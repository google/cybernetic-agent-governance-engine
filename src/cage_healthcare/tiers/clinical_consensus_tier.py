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

"""Clinical consensus tier — multi-critic agreement (phase 1, order 5)."""

from pathlib import Path
from typing import Any

from src.cage_healthcare.constants import HEALTHCARE_GOVERNED_ACTIONS
from src.gateway.governance.consensus import ConsensusGate, extract_field_magnitude, load_critic_specs
from src.gateway.governance.contracts import (
    CommitReceipt, ConsensusContribution, CriticSpec, GovernanceTierPlugin, Violation, ViolationKind,
)

_CRITICS_PATH = Path(__file__).resolve().parent.parent / "config" / "critics.yaml"
HIGH_STAKES_CLINICAL_ACTIONS: frozenset[str] = frozenset(
    {"administer_medication", "override_contraindication", "order_controlled_substance"}
)


def load_healthcare_critics(path: Path = _CRITICS_PATH) -> tuple[CriticSpec, ...]:
    return load_critic_specs(path)


def build_healthcare_consensus_contribution() -> ConsensusContribution:
    return ConsensusContribution(
        critics=load_healthcare_critics(),
        threshold=100.0,
        magnitude_extractor=extract_field_magnitude("dose_mg"),
        high_stakes_actions=HIGH_STAKES_CLINICAL_ACTIONS,
    )


def build_healthcare_consensus_gate() -> ConsensusGate:
    return ConsensusGate.from_contribution(build_healthcare_consensus_contribution())


class ClinicalConsensusTier(GovernanceTierPlugin):
    """Clinical consensus tier (phase 1, order 5)."""

    def __init__(self, consensus_engine: Any = None) -> None:
        if consensus_engine is None or (
            isinstance(consensus_engine, ConsensusGate) and not consensus_engine.critics
        ):
            consensus_engine = build_healthcare_consensus_gate()
        self.consensus_engine = consensus_engine

    @property
    def tier_name(self) -> str:
        return "clinical_consensus"

    @property
    def phase(self) -> int:
        return 1

    @property
    def order(self) -> int:
        return 5

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in HEALTHCARE_GOVERNED_ACTIONS or action in HIGH_STAKES_CLINICAL_ACTIONS

    def _reject(self, message: str, kind: ViolationKind = ViolationKind.HARD) -> list[Violation]:
        return [Violation(tier=self.tier_name, code="CLINICAL_CONSENSUS_REJECTED", message=message, kind=kind)]

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        if self.consensus_engine is None:
            return self._reject("Clinical consensus engine is not configured")
        result = await self.consensus_engine.check_consensus(action_type=action, params=params)
        if not isinstance(result, dict):
            return self._reject("Invalid clinical consensus result payload")
        status = result.get("status")
        if status in ("APPROVE", "APPROVED", "SKIPPED"):
            return []
        reason = str(result.get("reason") or "Multi-critic consensus not achieved")
        kind = ViolationKind.HITL if status == "ESCALATE" else ViolationKind.HARD
        return self._reject(reason, kind=kind)

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return [], None

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass

