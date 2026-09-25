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

from typing import Any

from src.cage_physical_ai.constants import PHYSICAL_AI_GOVERNED_ACTIONS
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class PhysicalSafetyConsensusTier(GovernanceTierPlugin):
    """Physical safety consensus tier (phase 1, order 5).

    Requires multi-critic model consensus prior to issuing clearances for high-consequence
    physical actions (e.g. entering restricted zones or executing high-speed trajectories).
    """

    def __init__(self, consensus_engine: Any = None) -> None:
        self.consensus_engine = consensus_engine

    @property
    def tier_name(self) -> str:
        return "physical_safety_consensus"

    @property
    def phase(self) -> int:
        return 1

    @property
    def order(self) -> int:
        return 5

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in PHYSICAL_AI_GOVERNED_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        if self.consensus_engine is None:
            return []
        result = await self.consensus_engine.check_consensus(
            action_type=action, params=params
        )
        if result.get("status") != "APPROVED":
            return [
                Violation(
                    tier=self.tier_name,
                    code="PHYSICAL_SAFETY_CONSENSUS_REJECTED",
                    detail=result.get("reason", "Consensus rejected physical action"),
                )
            ]
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []
