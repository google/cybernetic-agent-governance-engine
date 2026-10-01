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

from pathlib import Path
from typing import Any

import yaml

from src.cage_finance.causal.synthetic_telemetry import generate_mock_telemetry
from src.gateway.governance.causal import gatekeeper
from src.gateway.governance.causal.gatekeeper import (
    CAUSAL_NORMALIZATION_SCALE,
    CausalGatekeeper,
)
from src.gateway.governance.contracts import (
    CausalSpec,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)

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


def causal_safety_check(
    params: dict[str, Any], current_telemetry: Any = None
) -> bool:
    """Forwarding wrapper for causal safety check, supporting both module-level and gatekeeper patching."""
    if gatekeeper.causal_safety_check is not _DEFAULT_GATEKEEPER_CHECK:
        return gatekeeper.causal_safety_check(params, current_telemetry)
    return build_finance_causal_gatekeeper().causal_safety_check(
        params, current_telemetry
    )


class CausalTierPlugin(ReadOnlyTier):
    """Causal guard tier (phase 1, order 6)."""

    def __init__(self, causal_gatekeeper: CausalGatekeeper | None = None) -> None:
        self._gatekeeper = causal_gatekeeper

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
        # src.gateway.governance.causal.gatekeeper.causal_safety_check.
        if (
            self._gatekeeper is not None
            and gatekeeper.causal_safety_check is _DEFAULT_GATEKEEPER_CHECK
            and causal_safety_check is _DEFAULT_TIER_CHECK
        ):
            is_safe = self._gatekeeper.causal_safety_check(params)
        else:
            is_safe = causal_safety_check(params)
        if not is_safe:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CAUSAL_CHECK_FAILED",
                    message="World-model is untrustworthy or predicted risk exceeds safety boundary (DoWhy refutation failed).",
                    kind=ViolationKind.HARD,
                )
            ]
        return []

_DEFAULT_TIER_CHECK = causal_safety_check
