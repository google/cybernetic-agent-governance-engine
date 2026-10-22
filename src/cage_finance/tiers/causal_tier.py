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
from src.gateway.governance.causal.world_model_refresher import WorldModelRefresher
from src.gateway.governance.contracts import (
    CausalSpec,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
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

    On the request path, reads the latest precomputed :class:`WorldModelVerdict`
    from :class:`WorldModelRefresher` (zero network I/O and zero DoWhy
    refutations per request) and evaluates only the per-request marginal risk
    boundary on the injected :class:`CausalGatekeeper`. Until the refresher has
    produced a fresh verdict, or when the snapshot / telemetry watermark exceeds
    its TTL (`causal.cache_ttl_seconds` = 60 s / `telemetry.max_staleness_seconds`
    = 300 s), trades fail closed.
    """

    def __init__(
        self,
        causal_gatekeeper: CausalGatekeeper | None = None,
        telemetry_provider: BaseTelemetryProvider | None = None,
        *,
        world_model_refresher: WorldModelRefresher | None = None,
    ) -> None:
        self._gatekeeper = causal_gatekeeper
        if world_model_refresher is not None:
            self._refresher: WorldModelRefresher | None = world_model_refresher
            self._telemetry_provider = (
                telemetry_provider
                if telemetry_provider is not None
                else world_model_refresher.telemetry_provider
            )
            if self._gatekeeper is None:
                self._gatekeeper = world_model_refresher.gatekeeper
        else:
            self._telemetry_provider = telemetry_provider
            gk = self._gatekeeper
            if gk is None or isinstance(gk, CausalGatekeeper):
                resolved_gk = gk or build_finance_causal_gatekeeper()
                self._gatekeeper = resolved_gk
                self._refresher = WorldModelRefresher(
                    resolved_gk,
                    telemetry_provider,
                )
            else:
                self._refresher = None

    @property
    def refresher(self) -> WorldModelRefresher | None:
        return self._refresher

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
        # Calling the module-level causal_safety_check function allows patching at either
        # src.cage_finance.tiers.causal_tier.causal_safety_check or
        # src.gateway.governance.causal.gatekeeper.causal_safety_check. A patched
        # check returns a bare bool, which maps to CAUSAL_CHECK_FAILED.
        if (
            gatekeeper.causal_safety_check is not _DEFAULT_GATEKEEPER_CHECK
            or causal_safety_check is not _DEFAULT_TIER_CHECK
        ):
            decision = CausalDecision(bool(causal_safety_check(params, None)), "")
        elif self._refresher is None:
            # Custom non-CausalGatekeeper test double (e.g. RiskGatekeeper in e2e tests).
            assert self._gatekeeper is not None
            decision = self._gatekeeper.evaluate(params, None, action=action)
        else:
            assert self._gatekeeper is not None
            if (
                self._refresher.snapshot is None
                and self._gatekeeper._synthetic_telemetry_permitted()
            ):
                await self._refresher.refresh_once()
            verdict, provider_error = self._refresher.current_verdict()
            if provider_error is not None:
                return [
                    self._violation(
                        CODE_TELEMETRY_UNAVAILABLE,
                        f"Telemetry provider failed: {provider_error}",
                    )
                ]
            decision = self._gatekeeper.evaluate(
                params,
                action=action,
                verdict=verdict,
            )

        if decision.safe:
            return []
        code, message = _REASON_CODES.get(
            decision.reason, (CODE_CHECK_FAILED, _CHECK_FAILED_MESSAGE)
        )
        return [self._violation(code, message)]

    def _violation(self, code: str, message: str) -> Violation:
        return Violation(
            tier=self.tier_name,
            code=code,
            message=message,
            kind=ViolationKind.HARD,
        )


_DEFAULT_TIER_CHECK = causal_safety_check
