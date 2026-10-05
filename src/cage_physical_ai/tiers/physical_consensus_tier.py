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

"""Physical safety consensus tier — multi-critic agreement for physical AI (phase 1, order 5)."""

from pathlib import Path
from typing import Any

from src.cage_physical_ai.constants import CTRL_PHYS_004, PHYSICAL_AI_GOVERNED_ACTIONS
from src.gateway.governance.consensus import (
    ConsensusGate,
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

_CRITICS_PATH = Path(__file__).resolve().parent.parent / "config" / "critics.yaml"
HIGH_STAKES_PHYSICAL_ACTIONS: frozenset[str] = frozenset(
    {
        "execute_high_speed_trajectory",
        "override_safety_envelope",
        "disengage_e_stop",
    }
)


def _format_ctrl_phys_004(reason: str) -> str:
    return reason if reason.startswith("[") else f"[{CTRL_PHYS_004}] {reason}"


def load_physical_critics(path: Path = _CRITICS_PATH) -> tuple[CriticSpec, ...]:
    return load_critic_specs(path)


def build_physical_consensus_contribution() -> ConsensusContribution:
    return ConsensusContribution(
        critics=load_physical_critics(),
        threshold=2.0,
        magnitude_extractor=extract_field_magnitude("velocity_m_s"),
        high_stakes_actions=HIGH_STAKES_PHYSICAL_ACTIONS,
    )


def build_physical_consensus_gate() -> ConsensusGate:
    return ConsensusGate.from_contribution(build_physical_consensus_contribution())


class PhysicalSafetyConsensusTier(ReadOnlyTier):
    """Physical safety consensus tier (phase 1, order 5).

    Requires multi-critic model consensus prior to issuing clearances for high-consequence
    physical actions (e.g. entering restricted zones or executing high-speed trajectories).
    """

    def __init__(self, consensus_engine: Any = None) -> None:
        if consensus_engine is None or (
            isinstance(consensus_engine, ConsensusGate) and not consensus_engine.critics
        ):
            consensus_engine = build_physical_consensus_gate()
        self.consensus_engine = consensus_engine

    @property
    def tier_name(self) -> str:
        return "physical_safety_consensus"

    @property
    def order(self) -> int:
        return 5

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return (
            action in PHYSICAL_AI_GOVERNED_ACTIONS
            or action in HIGH_STAKES_PHYSICAL_ACTIONS
        )

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        if self.consensus_engine is None:
            return [
                Violation(
                    tier=self.tier_name,
                    code="PHYSICAL_SAFETY_CONSENSUS_REJECTED",
                    message=_format_ctrl_phys_004(
                        "Physical safety consensus engine is not configured"
                    ),
                    kind=ViolationKind.HARD,
                )
            ]
        result = await self.consensus_engine.check_consensus(
            action_type=action, params=params
        )
        if not isinstance(result, dict):
            return [
                Violation(
                    tier=self.tier_name,
                    code="PHYSICAL_SAFETY_CONSENSUS_REJECTED",
                    message=_format_ctrl_phys_004(
                        "Invalid physical safety consensus result payload"
                    ),
                    kind=ViolationKind.HARD,
                )
            ]
        status = result.get("status")
        reason = str(result.get("reason") or "Consensus rejected physical action")
        if status in ("APPROVE", "APPROVED", "SKIPPED"):
            return []
        kind = ViolationKind.HITL if status == "ESCALATE" else ViolationKind.HARD
        return [
            Violation(
                tier=self.tier_name,
                code="PHYSICAL_SAFETY_CONSENSUS_REJECTED",
                message=_format_ctrl_phys_004(reason),
                kind=kind,
            )
        ]


PhysicalConsensusTier = PhysicalSafetyConsensusTier
