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

import math
from pathlib import Path
from typing import Any

from src.gateway.governance.consensus.engine import (
    ConsensusGate,
    ConsensusModelRegistry,
    extract_field_magnitude,
    load_critic_specs,
)
from src.gateway.governance.contracts import (
    ConsensusContribution,
    CriticSpec,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.schemas.thresholds import THRESHOLDS

_CRITICS_YAML_PATH = Path(__file__).resolve().parents[1] / "config" / "critics.yaml"


def load_finance_critics() -> tuple[CriticSpec, ...]:
    """Load finance critic specifications from ``src/cage_finance/config/critics.yaml``."""
    return load_critic_specs(_CRITICS_YAML_PATH)


def _resolve_default_consensus_threshold() -> float:
    """The configured finance consensus threshold (USD).

    Fail closed: a missing or non-positive threshold refuses to build the
    contribution rather than falling back to a value nobody configured. (The
    previous fallback read ``THRESHOLDS.consensus``, which does not exist, so
    it raised ``AttributeError`` anyway.)
    """
    val = THRESHOLDS.resolve("domains.finance.consensus.threshold_usd")
    if (
        isinstance(val, bool)
        or not isinstance(val, (int, float))
        or not math.isfinite(val)
        or val <= 0
    ):
        raise ValueError(
            f"domains.finance.consensus.threshold_usd must be a positive number, got {val!r}"
        )
    return float(val)


def build_finance_consensus_contribution(
    threshold: float | None = None,
) -> ConsensusContribution:
    """Build the finance domain's ``ConsensusContribution``."""
    resolved_threshold = (
        float(threshold)
        if threshold is not None
        else _resolve_default_consensus_threshold()
    )
    return ConsensusContribution(
        critics=load_finance_critics(),
        threshold=resolved_threshold,
        magnitude_extractor=extract_field_magnitude("amount"),
        high_stakes_actions=frozenset({"HIGH_VALUE_TRADE"}),
    )


def build_finance_consensus_gate(
    threshold: float | None = None,
    registry: ConsensusModelRegistry | None = None,
) -> ConsensusGate:
    """Build a ``ConsensusGate`` configured with the finance domain's critics and threshold."""
    return ConsensusGate.from_contribution(
        build_finance_consensus_contribution(threshold=threshold),
        registry=registry,
    )


class ConsensusTierPlugin(ReadOnlyTier):
    """Consensus guard tier (phase 1, order 5)."""

    def __init__(self, consensus: Any = None):
        if consensus is None or (
            isinstance(consensus, ConsensusGate) and not consensus.critics
        ):
            consensus = build_finance_consensus_gate()
        self.consensus = consensus

    @property
    def tier_name(self) -> str:
        return "consensus"

    @property
    def order(self) -> int:
        return 5

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        if self.consensus is None:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message="Consensus engine is not configured",
                    kind=ViolationKind.HARD,
                )
            ]
        raw_amount = params.get("amount", 0.0) if isinstance(params, dict) else None
        if isinstance(raw_amount, bool) or raw_amount is None:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message="Invalid trade amount for consensus evaluation",
                    kind=ViolationKind.HARD,
                )
            ]
        try:
            amount = float(raw_amount)
        except (TypeError, ValueError):
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message="Invalid trade amount for consensus evaluation",
                    kind=ViolationKind.HARD,
                )
            ]
        if not math.isfinite(amount) or amount < 0.0:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message="Non-finite or negative trade amount for consensus evaluation",
                    kind=ViolationKind.HARD,
                )
            ]

        result = await self.consensus.check_consensus(action, params, magnitude=amount)
        if not isinstance(result, dict):
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message="Invalid consensus result payload",
                    kind=ViolationKind.HARD,
                )
            ]
        status = result.get("status") if "status" in result else result.get("decision")
        reason = str(result.get("reason") or "Consensus check failed")

        if status in ("APPROVE", "APPROVED", "SKIPPED"):
            return []
        if status == "ESCALATE":
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_ESCALATED",
                    message=reason,
                    kind=ViolationKind.HITL,
                )
            ]
        return [
            Violation(
                tier=self.tier_name,
                code="CONSENSUS_REJECTED",
                message=reason,
                kind=ViolationKind.HARD,
            )
        ]
