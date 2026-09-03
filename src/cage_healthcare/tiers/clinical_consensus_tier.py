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

from typing import Any

from src.cage_healthcare.constants import HEALTHCARE_GOVERNED_ACTIONS
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class ClinicalConsensusTier(GovernanceTierPlugin):
    """Clinical consensus tier (phase 1, order 5).

    Note what is absent: no consensus algorithm, no audit queue, no timeout
    budget, no ISO 42001 A.9.2 evidence emission. The kernel's ConsensusGate
    owns all of that. This tier only supplies the critic prompts (via YAML)
    and delegates to the engine.
    """

    def __init__(
        self, consensus_engine: Any
    ) -> None:  # consensus_engine: ConsensusGate
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
        return action in HEALTHCARE_GOVERNED_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 1: multi-critic consensus check
        result = await self.consensus_engine.check_consensus(
            action_type=action,
            params=params,
        )
        if result.get("status") != "APPROVED":
            return [
                Violation(
                    tier=self.tier_name,
                    code="CLINICAL_CONSENSUS_REJECTED",
                    message=result.get("reason", "Multi-critic consensus not achieved"),
                    recoverable=True,
                )
            ]
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 2: no mutation (consensus is read-only)
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        # Consensus tier has no state to roll back
        pass
