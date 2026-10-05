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

"""Per-request ownership of phase-2 commits: hold them until sealed, else undo.

A governed request commits phase-2 stages (CBF headroom, fiscal reservations)
before the routing seal is issued.  ``ReservationScope`` owns those commits
for one request.  They stay in force only if the scope sees ``seal_issued()``;
any other exit (violations, a failing seal, cancellation, a plain return)
rolls every commit back, last-in first-out.
"""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import TYPE_CHECKING, Literal, NamedTuple

from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.governor.errors import GovernanceError

if TYPE_CHECKING:
    from src.gateway.governance.governor.pipeline import Stage, StageContext

logger = logging.getLogger(__name__)


class HeldCommit(NamedTuple):
    """One phase-2 commit: the stage, the context it ran under, its receipt."""

    stage: Stage
    ctx: StageContext
    receipt: CommitReceipt


SettleHook = Literal["confirm", "rollback"]


class ReservationScope:
    """Async context manager owning phase-2 commits for one request.

    Usage::

        async with ReservationScope() as scope:
            result = await run_pipeline(stages, ctx, profile=..., scope=scope)
            if not result.violations:
                scope.seal_issued(await issue_seal(...))

    Rules:

    * Exiting without ``seal_issued()`` rolls back every recorded commit (LIFO).
    * Rollback runs in a shielded task: cancelling the caller cannot interrupt
      it, and every rollback is attempted even if an earlier one fails.
    * Each receipt is rolled back at most once (``rollback()`` is idempotent).
    * ``__aexit__`` never suppresses an exception.  If rollback fails on exit,
      it raises ``GovernanceError("[ROLLBACK_FAILED] ...")`` chained to the
      original exception, so a failed rollback can never end in ALLOW.
      Cancellation (a non-``Exception`` ``BaseException``) keeps propagating
      unchanged; the rollback failure is logged and noted on it.

    A scope is single-use and per request.  Never share one across requests.
    """

    __slots__ = ("_commits", "_entered", "_exited", "_sealed")

    def __init__(self) -> None:
        self._commits: list[HeldCommit] = []
        self._entered = False
        self._exited = False
        self._sealed = False

    @property
    def commits(self) -> tuple[tuple[Stage, CommitReceipt], ...]:
        """Outstanding ``(stage, receipt)`` pairs, in commit order."""
        return tuple((stage, receipt) for stage, _, receipt in self._commits)

    @property
    def sealed(self) -> bool:
        return self._sealed

    async def __aenter__(self) -> ReservationScope:
        if self._entered:
            raise RuntimeError("ReservationScope is single-use")
        self._entered = True
        return self

    async def commit(self, stage: Stage, ctx: StageContext) -> list[Violation]:
        """Commit ``stage`` and record its receipt, if it returned one.

        A receipt is recorded even alongside violations: a commit that mutated
        state and then refused must still be undone.  A commit that raises an
        ``Exception`` becomes a HARD ``TIER_EXCEPTION`` and, by contract,
        mutated nothing.  Cancellation propagates; the scope's exit undoes the
        commits already recorded.
        """
        self._require_open("commit")
        try:
            violations, receipt = await stage.commit(ctx)
        except Exception as exc:
            logger.exception("stage %s commit raised", stage.name)
            return [
                Violation(
                    tier=stage.name,
                    code="TIER_EXCEPTION",
                    message=f"Exception in commit: {type(exc).__name__}: {exc}",
                    kind=ViolationKind.HARD,
                )
            ]
        if receipt is not None:
            self._commits.append(HeldCommit(stage, ctx, receipt))
        return list(violations)

    def seal_issued(self, seal: str) -> tuple[HeldCommit, ...]:
        """Disarm rollback: the recorded commits now back an issued seal.

        Returns those commits.  The scope no longer owns them: the caller
        hands them to a ``SettlementLedger``, which confirms or rolls them
        back once the sealed action has (or has not) run.
        """
        self._require_open("seal_issued")
        if not isinstance(seal, str) or not seal:
            raise ValueError(
                "seal_issued() requires the issued seal; rollback stays armed"
            )
        self._sealed = True
        return tuple(self._commits)

    async def rollback(self) -> list[Violation]:
        """Undo every outstanding commit, LIFO.  Idempotent.

        Returns one HARD ``ROLLBACK_FAILED`` violation per failed rollback.  A
        failed rollback is not retried: the action is denied and the resource
        needs manual reconciliation.  Raises only after every rollback has
        been attempted: ``CancelledError`` if the caller was cancelled
        meanwhile, or a non-``Exception`` ``BaseException`` a rollback raised.
        """
        if self._sealed:
            raise RuntimeError("cannot roll back commits that back an issued seal")
        pending, self._commits = self._commits, []
        if not pending:
            return []
        return await shielded_settle(tuple(pending), hook="rollback")

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        # Never suppresses: an exception inside the scope always propagates.
        self._exited = True
        if self._sealed:
            return False
        failures = await self.rollback()  # idempotent: a repeat exit is a no-op
        if not failures:
            return False
        detail = "; ".join(v.message for v in failures)
        if exc is None or isinstance(exc, Exception):
            raise GovernanceError(f"[ROLLBACK_FAILED] {detail}") from exc
        logger.critical(
            "rollback failed while %s propagated: %s", type(exc).__name__, detail
        )
        exc.add_note(f"[ROLLBACK_FAILED] {detail}")
        return False

    def _require_open(self, operation: str) -> None:
        if not self._entered or self._exited:
            raise RuntimeError(
                f"ReservationScope.{operation}() called outside 'async with'"
            )
        if self._sealed:
            raise RuntimeError(
                f"ReservationScope.{operation}() called after seal_issued()"
            )


async def shielded_settle(
    pending: tuple[HeldCommit, ...], *, hook: SettleHook
) -> list[Violation]:
    """Run ``hook`` for every commit in a shielded task and wait for all of them.

    ``rollback`` runs last in first out; ``confirm`` runs in commit order.
    If our caller is cancelled meanwhile, the hooks still run to completion
    before the ``CancelledError`` is re-raised.
    """
    task = asyncio.ensure_future(_settle_each(pending, hook))
    interrupted: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if task.cancelled():
                raise  # the rollback task itself was cancelled (e.g. loop shutdown)
            interrupted = exc  # our caller was cancelled: finish rolling back first
    failures, escaped = task.result()
    if escaped is not None:
        raise escaped
    if interrupted is not None:
        raise interrupted
    return failures


async def _settle_each(
    pending: tuple[HeldCommit, ...], hook: SettleHook
) -> tuple[list[Violation], BaseException | None]:
    """Attempt ``hook`` for every commit, catching ``BaseException`` per commit.

    D6: one faulty stage cannot strand reservations held by the others.
    """
    failures: list[Violation] = []
    escaped: BaseException | None = None
    ordered = reversed(pending) if hook == "rollback" else iter(pending)
    for stage, ctx, receipt in ordered:
        try:
            await getattr(stage, hook)(ctx, receipt)
        except BaseException as exc:
            logger.exception("stage %s %s FAILED", stage.name, hook)
            failures.append(
                Violation(
                    tier=stage.name,
                    code=f"{hook.upper()}_FAILED",
                    message=(
                        f"{hook} of {stage.name} failed: {type(exc).__name__} — "
                        "resource state may be inconsistent; manual reconciliation required"
                    ),
                    kind=ViolationKind.HARD,
                )
            )
            if escaped is None and not isinstance(exc, Exception):
                escaped = exc
    return failures, escaped
