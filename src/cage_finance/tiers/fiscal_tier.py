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

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierPlugin,
    Violation,
    ViolationKind,
)
from src.gateway.governance.safety.resource_guard import FiscalLimitGuard


class FiscalTierPlugin(GovernanceTierPlugin):
    """Fiscal guard tier (phase 2, order 4).

    Stateless across requests: the ``ReservationToken`` from ``commit()`` is
    returned in the ``CommitReceipt`` and handed back to ``rollback()``.
    """

    def __init__(self, guard: FiscalLimitGuard):
        self.guard = guard

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
        """Read-only preview of commit() (DRY_RUN); reserves nothing."""
        amount = float(params.get("amount", 0.0))
        agent_id = params.get("agent_id") or params.get("trader_id") or "anonymous"
        if await self.guard.would_accept(amount_usd=amount):
            return []
        return [self._limit_violation(agent_id)]

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        amount = float(params.get("amount", 0.0))
        agent_id = params.get("agent_id") or params.get("trader_id") or "anonymous"

        token = await self.guard.reserve(agent_id=agent_id, amount_usd=amount)
        if token.rejected:
            return [self._limit_violation(agent_id)], None

        try:
            await self.guard.confirm(token)
        except BaseException:
            # A raising commit must leave nothing reserved: the caller gets no
            # receipt, so it could never release this token itself.
            await self.guard.release(token)
            raise
        return [], CommitReceipt(tier=self.tier_name, magnitude=token.amount_usd, token=token)

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        await self.guard.release(receipt.token)

    def _limit_violation(self, agent_id: str) -> Violation:
        return Violation(
            tier=self.tier_name,
            code="FISCAL_LIMIT_EXCEEDED",
            message=f"Daily fiscal limit exceeded for {agent_id}. Fiscal Limit Pre-Reservation REJECTED",
            kind=ViolationKind.NARROWABLE,
        )
