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

import uuid
from typing import Any

from src.gateway.governance.safety.resource_guard import FiscalLimitGuard
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class FiscalTierPlugin(GovernanceTierPlugin):
    """Fiscal guard tier (phase 2, order 4)."""

    def __init__(self, guard: FiscalLimitGuard):
        self.guard = guard
        self._tokens = {}

    @property
    def tier_name(self) -> str:
        return "fiscal"

    @property
    def phase(self) -> int:
        return 2

    @property
    def order(self) -> int:
        return 4

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 2 tiers only implement commit and rollback.
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        agent_id = params.get("trader_id", "anonymous")
        transaction_id = params.get("transaction_id", str(uuid.uuid4()))

        token = await self.guard.reserve(agent_id=agent_id, amount_usd=amount)
        if token.rejected:
            return [
                Violation(
                    tier=self.tier_name,
                    code="FISCAL_LIMIT_EXCEEDED",
                    message=f"Daily fiscal limit exceeded for {agent_id}",
                    recoverable=True,
                )
            ]

        self._tokens[transaction_id] = token
        await self.guard.confirm(token)
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        transaction_id = params.get("transaction_id")
        token = self._tokens.get(transaction_id)
        if token:
            await self.guard.release(token)
