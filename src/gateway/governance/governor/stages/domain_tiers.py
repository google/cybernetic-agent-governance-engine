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
from contextlib import AbstractContextManager
from typing import Any

from opentelemetry import trace

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierPlugin,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.pipeline import Stage, StageContext

tracer = trace.get_tracer(__name__)

# Span attribute keys. The span name itself is f"cage.tier.{tier_name}", so
# per-tier latency is observable without naming any tier in the kernel.
ATTR_PHASE = "cage.tier.phase"
ATTR_HOOK = "cage.tier.hook"
ATTR_VIOLATION_COUNT = "cage.tier.violation_count"
ATTR_EXCEPTION = "cage.tier.exception"


class DomainTierStage(Stage):
    """Wraps a GovernanceTierPlugin as a Stage.

    ``run()`` and ``preview()`` call the tier's read-only ``evaluate()``.
    Phase-2 tiers are driven through ``commit()`` / ``rollback(receipt)``.
    Every tier hook invocation (evaluate / commit / preview / rollback) runs
    inside exactly one OTel span named ``cage.tier.<tier_name>``.

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

    def _span(self, hook: str) -> AbstractContextManager[trace.Span]:
        return tracer.start_as_current_span(
            f"cage.tier.{self.name}",
            attributes={ATTR_PHASE: self.tier.phase, ATTR_HOOK: hook},
        )

    async def run(self, ctx: StageContext) -> list[Violation]:
        return await self._guarded(self.tier.evaluate, ctx, "evaluate")

    async def preview(self, ctx: StageContext) -> list[Violation]:
        """DRY_RUN stand-in for commit(): the tier's side-effect-free evaluate()."""
        return await self._guarded(self.tier.evaluate, ctx, "preview")

    async def commit(self, ctx: StageContext) -> tuple[list[Violation], CommitReceipt | None]:
        """Phase 2: commit the tier.  Fail-closed: a raise mutates nothing by contract."""
        with self._span("commit") as span:
            try:
                result = await self.tier.commit(ctx.action, ctx.params)
            except Exception as exc:
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                span.set_attribute(ATTR_VIOLATION_COUNT, 1)
                return [self._exception_violation("tier execution", exc)], None
            except BaseException as exc:
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                raise
            violations, receipt = self._checked_commit_result(result)
            span.set_attribute(ATTR_VIOLATION_COUNT, len(violations))
            return violations, receipt

    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        # Phase-1 tiers are read-only: there is nothing to undo.
        if not self.mutating:
            return
        with self._span("rollback") as span:
            try:
                await self.tier.rollback(ctx.action, ctx.params, receipt)
            except BaseException as exc:
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                raise
            span.set_attribute(ATTR_VIOLATION_COUNT, 0)

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

    async def _guarded(self, call, ctx: StageContext, hook: str) -> list[Violation]:
        """Invoke a read-only tier hook; any exception becomes a HARD violation (fail-closed)."""
        with self._span(hook) as span:
            try:
                violations = await call(ctx.action, ctx.params)
            except Exception as exc:
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                violations = [self._exception_violation("tier execution", exc)]
            except BaseException as exc:
                # Cancellation etc. propagates unchanged; the span still ends.
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                raise
            span.set_attribute(ATTR_VIOLATION_COUNT, len(violations))
            return violations

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
