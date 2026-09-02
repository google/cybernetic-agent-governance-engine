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

from typing import Any

from src.cage_finance.tiers import _TRADE_ACTIONS
from src.gateway.governance.consensus.engine import ConsensusGate
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class ConsensusTierPlugin(GovernanceTierPlugin):
    """Consensus guard tier (phase 1, order 5)."""

    def __init__(self, consensus: ConsensusGate):
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
        return action in _TRADE_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        result = await self.consensus.check_consensus(action, params, magnitude=amount)
        status = result.get("status")
        reason = result.get("reason", "Consensus check failed")

        if status in ("REJECT", "ERROR"):
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_REJECTED",
                    message=reason,
                    recoverable=True,
                )
            ]
        elif status == "ESCALATE":
            return [
                Violation(
                    tier=self.tier_name,
                    code="CONSENSUS_ESCALATED",
                    message=reason,
                    recoverable=True,
                    needs_human_review=True,
                )
            ]
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        pass
