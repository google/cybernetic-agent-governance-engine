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

import logging
from typing import Any

from src.cage_finance.invariants import finance_cost_resolver
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.tiers.cbf_tier import CostResolver
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    Violation,
    ViolationKind,
    coerce_bound,
)

logger = logging.getLogger(__name__)


class FiscalTierPlugin(MutatingTier):
    """Fiscal guard tier (phase 2, order 4).

    Stateless across requests: the ``ReservationToken`` from ``commit()`` is
    returned in the ``CommitReceipt`` and handed back to ``confirm()`` or
    ``rollback()``.

    ``commit()`` only *reserves* (ADR-009): the spend becomes permanent in
    ``confirm()``, which the kernel calls once the sealed trade has actually
    executed (``SymbolicGovernor.settle(seal, executed=True)``).  A
    reservation that is never settled (crash between seal and actuation,
    or a sealed run nothing actuates) expires after the guard's TTL.

    Claims by cost (any action with a positive cash cost counts against the
    daily cap) and reserves that same cost.
    """

    def __init__(
        self,
        guard: FiscalLimitGuard,
        cost_resolver: CostResolver = finance_cost_resolver,
    ):
        self.guard = guard
        self._cost = cost_resolver

    @property
    def tier_name(self) -> str:
        return "fiscal"

    @property
    def order(self) -> int:
        return 4

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return self._cost(action, params) > 0

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Read-only preview of commit() (DRY_RUN); reserves nothing."""
        import math

        amount = self._cost(action, params)
        agent_id = params.get("agent_id") or params.get("trader_id") or "anonymous"
        shadow_spend = params.get("_shadow_daily_spend_usd")
        if (
            shadow_spend is not None
            and not isinstance(shadow_spend, bool)
            and isinstance(shadow_spend, (int, float))
            and math.isfinite(float(shadow_spend))
            and float(shadow_spend) >= 0.0
        ):
            cap_usd = float(getattr(self.guard, "_daily_cap_usd", 0.0))
            if float(shadow_spend) + amount <= cap_usd:
                return []
            headroom = max(0.0, cap_usd - float(shadow_spend))
            return [
                Violation(
                    tier=self.tier_name,
                    code="FISCAL_LIMIT_EXCEEDED",
                    message=(
                        f"Daily fiscal limit exceeded for {agent_id} "
                        f"(shadow spend {float(shadow_spend):.2f} + {amount:.2f} > {cap_usd:.2f}). "
                        "Fiscal Limit Pre-Reservation REJECTED"
                    ),
                    kind=ViolationKind.NARROWABLE,
                    bound=coerce_bound(headroom),
                )
            ]
        if await self.guard.would_accept(amount_usd=amount):
            return []
        return [await self._limit_violation(agent_id)]

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        amount = self._cost(action, params)
        agent_id = params.get("agent_id") or params.get("trader_id") or "anonymous"

        token = await self.guard.reserve(agent_id=agent_id, amount_usd=amount)
        if token.rejected:
            return [await self._limit_violation(agent_id)], None
        return [], CommitReceipt(
            tier=self.tier_name, magnitude=token.amount_usd, token=token
        )

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        await self.guard.release(receipt.token)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        """The trade executed: the reservation stops expiring and counts for good."""
        await self.guard.confirm(receipt.token)

    async def _limit_violation(self, agent_id: str) -> Violation:
        """NARROWABLE refusal whose ``bound`` is the headroom left in the cap.

        The headroom is read after the refusal, so it is a snapshot (``None``
        if the window is unreadable); the narrowed re-run re-checks it. A
        failed or malformed read leaves the refusal NARROWABLE with no bound.
        """
        try:
            bound = coerce_bound(await self.guard.headroom_usd())
        except Exception as exc:
            logger.warning("fiscal bound unavailable: %s", exc)
            bound = None
        return Violation(
            tier=self.tier_name,
            code="FISCAL_LIMIT_EXCEEDED",
            message=f"Daily fiscal limit exceeded for {agent_id}. Fiscal Limit Pre-Reservation REJECTED",
            kind=ViolationKind.NARROWABLE,
            bound=bound,
        )
