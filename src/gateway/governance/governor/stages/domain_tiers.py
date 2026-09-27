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
from typing import Any

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierPlugin,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.pipeline import Stage, StageContext


class DomainTierStage(Stage):
    """Wraps a GovernanceTierPlugin as a Stage.

    ``run()`` and ``preview()`` call the tier's read-only ``evaluate()``.
    Phase-2 tiers are driven through ``commit()`` / ``rollback(receipt)``.

    Holds no per-request state: receipts go back to the pipeline, and a
    ``claims()`` exception propagates to the pipeline, which fails the stage
    closed for that request only.
    """

    def __init__(self, tier: GovernanceTierPlugin) -> None:
        self.tier = tier
        self.name = tier.tier_name
        self.mutating = (tier.phase == 2)

    def claims(self, ctx: StageContext) -> bool:
        """Delegate to the tier.  Exceptions propagate; ``run_pipeline`` fails closed."""
        return self.tier.claims_action(ctx.action, ctx.params)

    async def run(self, ctx: StageContext) -> list[Violation]:
        return await self._guarded(self.tier.evaluate, ctx)

    async def preview(self, ctx: StageContext) -> list[Violation]:
        """DRY_RUN stand-in for commit(): the tier's side-effect-free evaluate()."""
        return await self._guarded(self.tier.evaluate, ctx)

    async def commit(self, ctx: StageContext) -> tuple[list[Violation], CommitReceipt | None]:
        """Phase 2: commit the tier.  Fail-closed: a raise mutates nothing by contract."""
        try:
            result = await self.tier.commit(ctx.action, ctx.params)
        except Exception as exc:
            return [self._exception_violation("tier execution", exc)], None
        return self._checked_commit_result(result)

    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        await self.tier.rollback(ctx.action, ctx.params, receipt)

    def _checked_commit_result(self, result: Any) -> tuple[list[Violation], CommitReceipt | None]:
        """Enforce the ``(list[Violation], CommitReceipt | None)`` commit contract.

        A malformed result is a HARD violation.  A well-formed receipt found in
        a malformed result is kept so the pipeline still undoes its mutation.
        """
        pair = result if isinstance(result, tuple) and len(result) == 2 else (None, None)
        violations, receipt = pair
        receipt_ok = receipt is None or isinstance(receipt, CommitReceipt)
        if isinstance(violations, list) and receipt_ok:
            return violations, receipt
        return [
            Violation(
                tier=self.name,
                code="TIER_EXCEPTION",
                message=(
                    f"commit() returned {type(result).__name__}, not "
                    "(list[Violation], CommitReceipt | None)"
                ),
                kind=ViolationKind.HARD,
            )
        ], (receipt if isinstance(receipt, CommitReceipt) else None)

    async def _guarded(self, call, ctx: StageContext) -> list[Violation]:
        """Invoke a read-only tier hook; any exception becomes a HARD violation (fail-closed)."""
        try:
            return await call(ctx.action, ctx.params)
        except Exception as exc:
            return [self._exception_violation("tier execution", exc)]

    def _exception_violation(self, where: str, exc: BaseException) -> Violation:
        return Violation(
            tier=self.name,
            code="TIER_EXCEPTION",
            message=f"Exception in {where}: {type(exc).__name__}: {exc}",
            kind=ViolationKind.HARD,
        )

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
