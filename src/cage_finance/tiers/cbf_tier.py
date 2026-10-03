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

from collections.abc import Callable
from typing import Any

from src.cage_finance.invariants import finance_cost_resolver
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    Violation,
)
from src.gateway.governance.safety.barrier_tier import (
    commit_barrier,
    confirm_barrier,
    preview_barrier,
    rollback_barrier,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

#: ``(action, params) -> cash cost``; raises on a malformed amount.
CostResolver = Callable[[str, dict[str, Any]], float]


class CBFTierPlugin(MutatingTier):
    """CBF guard tier (phase 2, order 3).

    Claims by cost, not by name: any action whose ``cost_resolver`` cost is
    positive spends cash and so must pass the barrier. A resolver that raises
    (negative or non-finite amount) propagates; the pipeline turns it into a
    HARD ``TIER_EXCEPTION`` (fail closed).
    """

    def __init__(
        self,
        cbf: ControlBarrierFunction,
        cost_resolver: CostResolver = finance_cost_resolver,
    ):
        self.cbf = cbf
        self._cost = cost_resolver

    @property
    def tier_name(self) -> str:
        return "cbf"

    @property
    def order(self) -> int:
        return 3

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return self._cost(action, params) > 0

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Read-only preview of commit() (DRY_RUN); spends no barrier headroom."""
        return await preview_barrier(
            self.cbf, tier=self.tier_name, code="CBF_BARRIER_VIOLATED", action=action, params=params
        )

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return await commit_barrier(
            self.cbf, tier=self.tier_name, code="CBF_BARRIER_VIOLATED", action=action, params=params
        )

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        await rollback_barrier(self.cbf, receipt)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        """The trade executed: the debit becomes settleable (ADR-010)."""
        await confirm_barrier(self.cbf, receipt)
