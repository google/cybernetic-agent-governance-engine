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

from src.gateway.governance.consensus.engine import (
    ConsensusGate,
    ConsensusModelRegistry,
    load_critic_specs,
)
from src.gateway.governance.contracts import (
    CommitReceipt,
    ConsensusContribution,
    CriticSpec,
    GovernanceTierPlugin,
    Violation,
    ViolationKind,
)
from src.gateway.governance.schemas.thresholds import THRESHOLDS

_CRITICS_YAML_PATH = Path(__file__).resolve().parents[1] / "config" / "critics.yaml"


def load_finance_critics() -> tuple[CriticSpec, ...]:
    """Load finance critic specifications from ``src/cage_finance/config/critics.yaml``."""
    return load_critic_specs(_CRITICS_YAML_PATH)


def _resolve_default_consensus_threshold() -> float:
    try:
        val = THRESHOLDS.resolve("domains.finance.consensus.threshold_usd")
        if isinstance(val, (int, float)):
            return float(val)
    except Exception:
        pass
    return float(THRESHOLDS.consensus.threshold_usd)


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
        magnitude_extractor=lambda p: float(p.get("amount", 0.0) or 0.0),
        quorum=2,
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


class ConsensusTierPlugin(GovernanceTierPlugin):
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
    def phase(self) -> int:
        return 1

    @property
    def order(self) -> int:
        return 5

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        result = await self.consensus.check_consensus(action, params, magnitude=amount)
        if not isinstance(result, dict):
            return []
        status = result.get("status") or result.get("decision")
        reason = str(result.get("reason", "Consensus check failed"))

        if status in ("REJECT", "ERROR", "DENY"):
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message=reason,
                    kind=ViolationKind.HARD,
                )
            ]
        elif status == "ESCALATE":
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_ESCALATED",
                    message=reason,
                    kind=ViolationKind.HITL,
                )
            ]
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return [], None

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass

