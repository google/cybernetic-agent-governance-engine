# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
from pathlib import Path
from typing import Any

import yaml

from src.cage_finance.causal.synthetic_telemetry import generate_mock_telemetry
from src.gateway.governance.causal import gatekeeper
from src.gateway.governance.causal.gatekeeper import (
    CAUSAL_NORMALIZATION_SCALE,
    REASON_INSUFFICIENT_SAMPLES,
    REASON_NO_LIVE_TELEMETRY,
    CausalDecision,
    CausalGatekeeper,
)
from src.gateway.governance.contracts import (
    CausalSpec,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.schemas.thresholds import get_causal_min_samples
from src.gateway.governance.telemetry_provider import BaseTelemetryProvider

logger = logging.getLogger(__name__)

# Violation codes (decision D3): every causal failure is HARD. The bootstrap
# window (fewer than ``min_samples`` live rows) and a missing telemetry feed get
# their own codes so operators can tell "not enough history yet" from "feed
# down" from "world model refuted / risk too high".
CODE_INSUFFICIENT_SAMPLES = "CAUSAL_INSUFFICIENT_SAMPLES"
CODE_TELEMETRY_UNAVAILABLE = "CAUSAL_TELEMETRY_UNAVAILABLE"
CODE_CHECK_FAILED = "CAUSAL_CHECK_FAILED"

_REASON_CODES: dict[str, tuple[str, str]] = {
    REASON_INSUFFICIENT_SAMPLES: (
        CODE_INSUFFICIENT_SAMPLES,
        "Causal tier is in its bootstrap window: fewer live telemetry samples "
        "than causal.min_samples, so the world model cannot be validated.",
    ),
    REASON_NO_LIVE_TELEMETRY: (
        CODE_TELEMETRY_UNAVAILABLE,
        "No live telemetry is available to validate the causal world model "
        "(enforcing posture does not substitute synthetic data).",
    ),
}
_CHECK_FAILED_MESSAGE = (
    "World-model is untrustworthy or predicted risk exceeds safety boundary "
    "(DoWhy refutation failed)."
)

# Telemetry window requested from the provider: never fewer rows than the
# gatekeeper needs, and the provider's conventional default otherwise.
_DEFAULT_TELEMETRY_WINDOW = 500

_CAUSAL_GRAPH_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "causal_graph.yaml"
)
_DEFAULT_GATEKEEPER_CHECK = gatekeeper.causal_safety_check


def build_finance_causal_spec(path: Path = _CAUSAL_GRAPH_PATH) -> CausalSpec:
    """Build the finance domain :class:`CausalSpec` from ``causal_graph.yaml``."""
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    return CausalSpec(
        graph_dot=str(cfg.get("graph", "")).strip(),
        treatment_col=str(cfg.get("treatment", "trade_amount")),
        outcome_col=str(cfg.get("outcome", "risk_score")),
        treatment_extractor=lambda p: (
            float(p["amount"])
            if "amount" in p
            and p["amount"] is not None
            and not isinstance(p["amount"], bool)
            else None
        ),
        context_extractor=lambda p: str(p.get("market_regime", "unknown")),
        normalization_scale=CAUSAL_NORMALIZATION_SCALE,
        synthetic_telemetry_factory=generate_mock_telemetry,
    )


def build_finance_causal_gatekeeper() -> CausalGatekeeper:
    """Construct a :class:`CausalGatekeeper` configured for the finance domain."""
    return CausalGatekeeper(build_finance_causal_spec())


def causal_safety_check(params: dict[str, Any], current_telemetry: Any = None) -> bool:
    """Forwarding wrapper for causal safety check, supporting both module-level and gatekeeper patching."""
    if gatekeeper.causal_safety_check is not _DEFAULT_GATEKEEPER_CHECK:
        return gatekeeper.causal_safety_check(params, current_telemetry)
    return build_finance_causal_gatekeeper().causal_safety_check(
        params, current_telemetry
    )


class CausalTierPlugin(ReadOnlyTier):
    """Causal guard tier (phase 1, order 6).

    With a ``telemetry_provider`` the tier fetches live telemetry on every
    evaluation and hands it to the gatekeeper; without one it passes none, and
    the gatekeeper decides by posture (synthetic data in dev/test/ci, deny in
    enforcing postures). Production wiring always supplies a provider via
    :func:`src.cage_finance.create_finance_tiers`.
    """

    def __init__(
        self,
        causal_gatekeeper: CausalGatekeeper | None = None,
        telemetry_provider: BaseTelemetryProvider | None = None,
    ) -> None:
        self._gatekeeper = causal_gatekeeper
        self._telemetry_provider = telemetry_provider

    @property
    def tier_name(self) -> str:
        return "causal"

    @property
    def runtime_requirements(self) -> tuple[str, ...]:
        # The DoWhy causal gatekeeper: without it no causal world-model
        # validation happens, so enforcing postures refuse to start.
        return ("dowhy",)

    @property
    def order(self) -> int:
        return 6

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        try:
            telemetry = await self._fetch_telemetry()
        except Exception as exc:
            logger.error(
                "Causal tier: telemetry provider failed (%s) — failing closed.", exc
            )
            return [
                self._violation(
                    CODE_TELEMETRY_UNAVAILABLE, f"Telemetry provider failed: {exc}"
                )
            ]

        # Calling the module-level causal_safety_check function allows patching at either
        # src.cage_finance.tiers.causal_tier.causal_safety_check or
        # src.gateway.governance.causal.gatekeeper.causal_safety_check. A patched
        # check returns a bare bool, which maps to CAUSAL_CHECK_FAILED.
        if (
            gatekeeper.causal_safety_check is _DEFAULT_GATEKEEPER_CHECK
            and causal_safety_check is _DEFAULT_TIER_CHECK
        ):
            gk = self._gatekeeper or build_finance_causal_gatekeeper()
            decision = gk.evaluate(params, telemetry, action=action)
        else:
            decision = CausalDecision(bool(causal_safety_check(params, telemetry)), "")

        if decision.safe:
            return []
        code, message = _REASON_CODES.get(
            decision.reason, (CODE_CHECK_FAILED, _CHECK_FAILED_MESSAGE)
        )
        return [self._violation(code, message)]

    async def _fetch_telemetry(self) -> Any:
        """Fetch live telemetry off the event loop, or ``None`` without a provider."""
        if self._telemetry_provider is None:
            return None
        window = max(get_causal_min_samples(), _DEFAULT_TELEMETRY_WINDOW)
        return await asyncio.to_thread(self._telemetry_provider.get_latest_data, window)

    def _violation(self, code: str, message: str) -> Violation:
        return Violation(
            tier=self.tier_name,
            code=code,
            message=message,
            kind=ViolationKind.HARD,
        )


_DEFAULT_TIER_CHECK = causal_safety_check
