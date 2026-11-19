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

"""Shared hooks for every CBF-backed domain tier (finance, healthcare, physical AI).

Phase-2 barrier tiers delegate all three tier hooks here:

* ``preview_barrier``  — ``evaluate()``: read-only preview used by DRY_RUN, so
  ``verify()`` reports the refusal live execution would produce without
  spending any barrier headroom.
* ``commit_barrier``   — ``commit()``: atomic verify-and-commit; the receipt
  records the magnitude the engine reports it deducted.
* ``rollback_barrier`` — ``rollback()``: restores exactly that magnitude.
* ``confirm_barrier``  — ``confirm()``: the action executed; the ledger entry
  becomes settleable, stamped with the confirm time (ADR-010).

Refusals carry ``Violation.bound`` (the engine's admissible cost) when the
engine is a :class:`BoundedBarrier`; otherwise, or if reading it fails, the
bound is ``None``. A barrier refusal is HARD, so the bound informs the
reviewer and the refusal receipt; it never authorizes anything.

Kept in the kernel so a fix to the fail-closed or receipt rules is applied once
for every domain.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from src.gateway.governance.contracts import (
    CommitReceipt,
    Violation,
    ViolationKind,
    coerce_bound,
)
from src.gateway.governance.seams.quarantine import QuarantineTriggerReason

logger = logging.getLogger(__name__)

SAFE = "SAFE"
CBF_RECONCILIATION_UNAVAILABLE_CODE = "CBF_RECONCILIATION_UNAVAILABLE"


class BarrierFailureKind(str, Enum):
    """Structured classification of why a barrier check or commit did not admit.

    Emitted by :class:`StructuredBarrierReader` / :class:`StructuredBarrierEngine`
    at the decision site so ``barrier_tier`` never parses human-readable messages.
    """

    BARRIER_BREACH = "BARRIER_BREACH"
    RECONCILIATION_DRIFT = "RECONCILIATION_DRIFT"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    RECONCILIATION_UNAVAILABLE = "RECONCILIATION_UNAVAILABLE"


@dataclass(frozen=True)
class BarrierCheckResult:
    """Typed verdict returned by ``StructuredBarrierReader.check_barrier()``."""

    safe: bool
    message: str
    failure_kind: BarrierFailureKind | None = None

    def __post_init__(self) -> None:
        if self.safe and self.failure_kind is not None:
            raise ValueError("safe BarrierCheckResult must not set failure_kind")
        if not self.safe and self.failure_kind is None:
            raise ValueError("unsafe BarrierCheckResult must set failure_kind")


@dataclass(frozen=True)
class BarrierCommitResult:
    """Typed outcome returned by ``StructuredBarrierEngine.commit_barrier_checked()``."""

    committed: bool
    message: str
    magnitude: float = 0.0
    failure_kind: BarrierFailureKind | None = None

    def __post_init__(self) -> None:
        if self.committed and self.failure_kind is not None:
            raise ValueError("committed BarrierCommitResult must not set failure_kind")
        if not self.committed and self.failure_kind is None:
            raise ValueError("uncommitted BarrierCommitResult must set failure_kind")


class BarrierReader(Protocol):
    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str: ...


class BarrierEngine(BarrierReader, Protocol):
    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
        *,
        debit_id: str | None = None,
    ) -> tuple[bool, str, float]: ...

    async def rollback_state(
        self,
        magnitude: float,
        governance_signature: str | None = None,
        *,
        debit_id: str | None = None,
    ) -> None: ...

    async def confirm_debit(self, debit_id: str) -> bool: ...


@runtime_checkable
class StructuredBarrierReader(Protocol):
    """A barrier reader that reports failure classifications structurally."""

    async def check_barrier(
        self, action_name: str, payload: dict[str, Any]
    ) -> BarrierCheckResult: ...


@runtime_checkable
class StructuredBarrierEngine(StructuredBarrierReader, Protocol):
    """A barrier engine that reports commit failures structurally."""

    async def commit_barrier_checked(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
        *,
        debit_id: str | None = None,
    ) -> BarrierCommitResult: ...


@runtime_checkable
class BoundedBarrier(Protocol):
    """An engine that can say how much cost it would still admit."""

    async def admissible_cost(self) -> float | None: ...


def _structured_method(obj: object, name: str) -> Any | None:
    """Return ``obj.<name>`` only when explicitly defined on the class or instance.

    Prevents synthesized ``MagicMock`` child attributes from shadowing a
    configured ``verify_action`` / ``atomic_verify_and_commit`` test double.
    """
    if name in getattr(obj, "__dict__", {}):
        fn = getattr(obj, name)
        return fn if callable(fn) else None
    if callable(getattr(type(obj), name, None)):
        return getattr(obj, name)
    return None


async def _admissible_bound(cbf: object) -> float | None:
    """The engine's admissible cost, or ``None`` if it cannot say (never a guess)."""
    if not isinstance(cbf, BoundedBarrier):
        return None
    try:
        return coerce_bound(await cbf.admissible_cost())
    except Exception as exc:
        logger.warning("barrier bound unavailable: %s", exc)
        return None


async def _refusal(
    cbf: object,
    *,
    tier: str,
    code: str,
    message: str,
    failure_kind: BarrierFailureKind = BarrierFailureKind.BARRIER_BREACH,
) -> Violation:
    if failure_kind in (
        BarrierFailureKind.STORE_UNAVAILABLE,
        BarrierFailureKind.RECONCILIATION_UNAVAILABLE,
    ):
        return Violation(
            tier=tier,
            code=CBF_RECONCILIATION_UNAVAILABLE_CODE,
            message=message,
            kind=ViolationKind.INFRASTRUCTURE,
            infra_dependency=tier,
            infra_error_code="governance_dependency_unavailable",
        )
    trigger = (
        QuarantineTriggerReason.RECONCILIATION_STATE_DRIFT
        if failure_kind is BarrierFailureKind.RECONCILIATION_DRIFT
        else QuarantineTriggerReason.CRITICAL_CBF_BREACH
    )
    return Violation(
        tier=tier,
        code=code,
        message=message,
        kind=ViolationKind.HARD,
        bound=await _admissible_bound(cbf),
        quarantine_trigger=trigger,
    )


async def preview_barrier(
    cbf: BarrierReader,
    *,
    tier: str,
    code: str,
    action: str,
    params: dict[str, Any],
) -> list[Violation]:
    """Evaluate the barrier against a state snapshot without committing.

    Fail-closed: structured readers classify unavailability vs. integrity/breach
    via :class:`BarrierFailureKind`; unstructured readers treat any verdict
    other than exactly ``"SAFE"`` as a HARD ``BARRIER_BREACH`` without parsing
    message strings. Exceptions propagate so the calling stage records
    ``TIER_EXCEPTION``.
    """
    check_fn = _structured_method(cbf, "check_barrier")
    if check_fn is not None:
        outcome = await check_fn(action, params)
        if not isinstance(outcome, BarrierCheckResult):
            raise TypeError(
                f"check_barrier() must return BarrierCheckResult, got {type(outcome).__name__}"
            )
        if outcome.safe:
            return []
        if outcome.failure_kind is None:
            raise ValueError("unsafe BarrierCheckResult must set failure_kind")
        return [
            await _refusal(
                cbf,
                tier=tier,
                code=code,
                message=outcome.message,
                failure_kind=outcome.failure_kind,
            )
        ]

    verdict = await cbf.verify_action(action, params)
    if verdict == SAFE:
        return []
    return [
        await _refusal(
            cbf,
            tier=tier,
            code=code,
            message=str(verdict),
            failure_kind=BarrierFailureKind.BARRIER_BREACH,
        )
    ]


async def commit_barrier(
    cbf: BarrierEngine,
    *,
    tier: str,
    code: str,
    action: str,
    params: dict[str, Any],
) -> tuple[list[Violation], CommitReceipt | None]:
    """Atomically verify and commit; return a receipt only if state was mutated.

    Structured engines classify unavailability vs. integrity/breach via
    :class:`BarrierFailureKind`; unstructured engines treat any uncommitted
    result as a HARD ``BARRIER_BREACH`` without parsing reason strings.
    Exceptions propagate so the calling stage records ``TIER_EXCEPTION``.
    """
    debit_id = uuid4().hex
    commit_fn = _structured_method(cbf, "commit_barrier_checked")
    if commit_fn is not None:
        outcome = await commit_fn(action, params, debit_id=debit_id)
        if not isinstance(outcome, BarrierCommitResult):
            raise TypeError(
                f"commit_barrier_checked() must return BarrierCommitResult, got {type(outcome).__name__}"
            )
        if not outcome.committed:
            if outcome.failure_kind is None:
                raise ValueError(
                    "uncommitted BarrierCommitResult must set failure_kind"
                )
            return [
                await _refusal(
                    cbf,
                    tier=tier,
                    code=code,
                    message=outcome.message,
                    failure_kind=outcome.failure_kind,
                )
            ], None
        return [], CommitReceipt(tier=tier, magnitude=outcome.magnitude, token=debit_id)

    committed, reason, magnitude = await cbf.atomic_verify_and_commit(
        action, params, debit_id=debit_id
    )
    if not committed:
        return [
            await _refusal(
                cbf,
                tier=tier,
                code=code,
                message=reason,
                failure_kind=BarrierFailureKind.BARRIER_BREACH,
            )
        ], None
    return [], CommitReceipt(tier=tier, magnitude=magnitude, token=debit_id)


async def rollback_barrier(cbf: BarrierEngine, receipt: CommitReceipt) -> None:
    """Retire exactly the debit recorded by ``commit_barrier``.

    The receipt's ``token`` is the ledger ``debit_id``; the engine restores
    the amount it ledgered under that id (falling back to ``magnitude`` only
    if the entry has already settled) and ignores a repeated rollback.
    """
    # A barrier commit always records its magnitude (commit_barrier); 0.0 is
    # only the restore amount if the ledger entry has already settled.
    magnitude = receipt.magnitude if receipt.magnitude is not None else 0.0
    await cbf.rollback_state(magnitude=magnitude, debit_id=receipt.token)


async def confirm_barrier(cbf: BarrierEngine, receipt: CommitReceipt) -> None:
    """Confirm exactly the debit recorded by ``commit_barrier`` (ADR-009/010).

    Until confirmed the debit is pending and the reconciler never settles it.
    A receipt without a ``debit_id`` token has nothing ledgered to confirm.
    """
    if isinstance(receipt.token, str) and receipt.token:
        await cbf.confirm_debit(receipt.token)
