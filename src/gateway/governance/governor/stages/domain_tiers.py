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

from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractContextManager
from typing import Any

from opentelemetry import trace

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTier,
    MutatingTier,
    ReadOnlyTier,
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


#: Hooks only a MutatingTier may define (ADR-009).
_MUTATING_HOOKS: tuple[str, ...] = ("commit", "rollback", "confirm")


def check_tier_kind(tier: object) -> bool:
    """Validate ``tier`` and return whether it mutates (ADR-009).

    A tier is a :class:`ReadOnlyTier` or a :class:`MutatingTier`, by
    subclassing. Anything else is refused, and so is a read-only tier that
    defines a mutating hook: it meant to reserve state, and running it as
    read-only would silently skip its commit.

    Raises:
        TypeError: ``tier`` is not exactly one of the two kinds, or a
            read-only tier defines ``commit`` / ``rollback`` / ``confirm``.
        ValueError: ``tier.phase`` contradicts its kind (a subclass overrode
            the derived ``phase``).
    """
    if not isinstance(tier, GovernanceTier):
        raise TypeError(
            f"{type(tier).__name__} is not a governance tier; subclass ReadOnlyTier or MutatingTier"
        )
    mutating = isinstance(tier, MutatingTier)
    if mutating == isinstance(tier, ReadOnlyTier):
        raise TypeError(
            f"tier {tier.tier_name!r} must be exactly one of ReadOnlyTier and MutatingTier"
        )
    if not mutating:
        stray = [hook for hook in _MUTATING_HOOKS if hasattr(tier, hook)]
        if stray:
            raise TypeError(
                f"read-only tier {tier.tier_name!r} defines {stray}; a tier that "
                "reserves state must subclass MutatingTier"
            )
    expected = 2 if mutating else 1
    if tier.phase != expected:
        raise ValueError(
            f"tier {tier.tier_name!r} reports phase {tier.phase}, but its kind is phase {expected}"
        )
    return mutating


class DomainTierStage(Stage):
    """Wraps a :class:`GovernanceTier` as a Stage.

    ``run()`` and ``preview()`` call the tier's read-only ``evaluate()``.
    Mutating tiers are driven through ``commit()`` / ``rollback(receipt)``
    and, after the sealed action, ``confirm(receipt)``. Every tier hook
    invocation runs inside exactly one OTel span named
    ``cage.tier.<tier_name>``.

    Holds no per-request state: receipts go back to the pipeline, and a
    ``claims()`` exception propagates to the pipeline, which fails the stage
    closed for that request only.
    """

    def __init__(self, tier: GovernanceTier) -> None:
        self.mutating = check_tier_kind(tier)
        self.tier = tier
        self.name = tier.tier_name

    def claims(self, ctx: StageContext) -> bool:
        """Delegate to the tier.  Exceptions propagate; ``run_pipeline`` fails closed."""
        return self.tier.claims_action(ctx.action, dict(ctx.params))

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

    async def commit(
        self, ctx: StageContext
    ) -> tuple[list[Violation], CommitReceipt | None]:
        """Phase 2: commit the tier.  Fail-closed: a raise mutates nothing by contract."""
        if not isinstance(
            self.tier, MutatingTier
        ):  # unreachable: the pipeline commits mutating stages only
            raise TypeError(f"read-only tier {self.name!r} cannot commit")
        with self._span("commit") as span:
            try:
                result = await self.tier.commit(ctx.action, dict(ctx.params))
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
        await self._settle_hook("rollback", ctx, receipt)

    async def confirm(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        """The sealed action was carried out: make the reservation permanent."""
        await self._settle_hook("confirm", ctx, receipt)

    async def _settle_hook(
        self, hook: str, ctx: StageContext, receipt: CommitReceipt
    ) -> None:
        if not isinstance(
            self.tier, MutatingTier
        ):  # unreachable: only commits issue receipts
            raise TypeError(
                f"read-only tier {self.name!r} holds no reservation to {hook}"
            )
        call = self.tier.rollback if hook == "rollback" else self.tier.confirm
        with self._span(hook) as span:
            try:
                await call(ctx.action, dict(ctx.params), receipt)
            except BaseException as exc:
                span.set_attribute(ATTR_EXCEPTION, type(exc).__name__)
                raise
            span.set_attribute(ATTR_VIOLATION_COUNT, 0)

    def _checked_commit_result(
        self, result: Any
    ) -> tuple[list[Violation], CommitReceipt | None]:
        """Enforce the ``(list[Violation], CommitReceipt | None)`` commit contract.

        A malformed result is a HARD violation.  A well-formed receipt found in
        a malformed result is kept so the pipeline still undoes its mutation.
        """
        pair = (
            result if isinstance(result, tuple) and len(result) == 2 else (None, None)
        )
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

    async def _guarded(
        self,
        call: Callable[[str, dict[str, Any]], Awaitable[list[Violation]]],
        ctx: StageContext,
        hook: str,
    ) -> list[Violation]:
        """Invoke a read-only tier hook; any exception becomes a HARD violation (fail-closed)."""
        with self._span(hook) as span:
            try:
                violations = await call(ctx.action, dict(ctx.params))
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


def order_stages(tiers: Sequence[GovernanceTier]) -> tuple[DomainTierStage, ...]:
    """Validate, sort by (phase, order, tier_name) and wrap tiers as DomainTierStages.

    Duplicate ``tier_name`` registrations are rejected: a later tier must never
    silently shadow an earlier one's verdict or rollback.
    """
    seen: set[str] = set()
    for t in tiers:
        if t.tier_name in seen:
            raise ValueError(
                f"duplicate tier registration at construction: {t.tier_name}"
            )
        seen.add(t.tier_name)
    sorted_tiers = sorted(tiers, key=lambda t: (t.phase, t.order, t.tier_name))
    return tuple(DomainTierStage(t) for t in sorted_tiers)
