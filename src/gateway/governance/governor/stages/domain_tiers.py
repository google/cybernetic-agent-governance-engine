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

from collections.abc import Sequence

from src.gateway.governance.contracts import GovernanceTierPlugin
from src.gateway.governance.governor.pipeline import Stage, StageContext
from src.gateway.governance.contracts import Violation, ViolationKind


class DomainTierStage(Stage):
    """Wraps a GovernanceTierPlugin as a Stage."""

    def __init__(self, tier: GovernanceTierPlugin) -> None:
        self.tier = tier
        self.name = tier.tier_name
        self.mutating = (tier.phase == 2)

    def claims(self, ctx: StageContext) -> bool:
        try:
            return self.tier.claims_action(ctx.action, ctx.params)
        except Exception as exc:
            # An exception in claims_action: treat as claimed so that `run` fails closed
            self._claims_exception = exc
            return True

    async def run(self, ctx: StageContext) -> list[Violation]:
        if hasattr(self, "_claims_exception"):
            return [
                Violation(
                    tier=self.name,
                    code="TIER_EXCEPTION",
                    message=f"Exception in claims_action: {type(self._claims_exception).__name__}: {self._claims_exception}",
                    kind=ViolationKind.HARD,
                )
            ]

        try:
            if self.tier.phase == 1:
                return await self.tier.evaluate(ctx.action, ctx.params)
            else:
                return await self.tier.commit(ctx.action, ctx.params)
        except Exception as exc:
            return [
                Violation(
                    tier=self.name,
                    code="TIER_EXCEPTION",
                    message=f"Exception in tier execution: {type(exc).__name__}: {exc}",
                    kind=ViolationKind.HARD,
                )
            ]

    async def rollback(self, ctx: StageContext) -> None:
        # Phase-1 tiers are read-only: there is nothing to undo.
        if self.mutating:
            await self.tier.rollback(ctx.action, ctx.params)

def order_stages(tiers: Sequence[GovernanceTierPlugin]) -> tuple[DomainTierStage, ...]:
    """Validate, sort by (phase, order, tier_name) and wrap tiers as DomainTierStages.

    Duplicate ``tier_name`` registrations are rejected: a later tier must never
    silently shadow an earlier one's verdict or rollback.
    """
    seen: set[str] = set()
    for t in tiers:
        if t.tier_name in seen:
            raise ValueError(f"duplicate tier registration at construction: {t.tier_name}")
        seen.add(t.tier_name)
    sorted_tiers = sorted(tiers, key=lambda t: (t.phase, t.order, t.tier_name))
    return tuple(DomainTierStage(t) for t in sorted_tiers)
