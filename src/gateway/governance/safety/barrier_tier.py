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

Refusals carry ``Violation.bound`` (the engine's admissible cost) when the
engine is a :class:`BoundedBarrier`; otherwise, or if reading it fails, the
bound is ``None``. A barrier refusal is HARD, so the bound informs the
reviewer and the refusal receipt; it never authorizes anything.

Kept in the kernel so a fix to the fail-closed or receipt rules is applied once
for every domain.
"""

import logging
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from src.gateway.governance.contracts import (
    CommitReceipt,
    Violation,
    ViolationKind,
    coerce_bound,
)

logger = logging.getLogger(__name__)

SAFE = "SAFE"


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


@runtime_checkable
class BoundedBarrier(Protocol):
    """An engine that can say how much cost it would still admit."""

    async def admissible_cost(self) -> float | None: ...


async def _admissible_bound(cbf: object) -> float | None:
    """The engine's admissible cost, or ``None`` if it cannot say (never a guess)."""
    if not isinstance(cbf, BoundedBarrier):
        return None
    try:
        return coerce_bound(await cbf.admissible_cost())
    except Exception as exc:
        logger.warning("barrier bound unavailable: %s", exc)
        return None


async def _refusal(cbf: object, *, tier: str, code: str, message: str) -> Violation:
    return Violation(
        tier=tier,
        code=code,
        message=message,
        kind=ViolationKind.HARD,
        bound=await _admissible_bound(cbf),
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

    Fail-closed: any verdict other than exactly ``"SAFE"`` is a HARD violation.
    Exceptions propagate so the calling stage records ``TIER_EXCEPTION``.
    """
    verdict = await cbf.verify_action(action, params)
    if verdict == SAFE:
        return []
    return [await _refusal(cbf, tier=tier, code=code, message=str(verdict))]


async def commit_barrier(
    cbf: BarrierEngine,
    *,
    tier: str,
    code: str,
    action: str,
    params: dict[str, Any],
) -> tuple[list[Violation], CommitReceipt | None]:
    """Atomically verify and commit; return a receipt only if state was mutated.

    A refusal is a HARD violation with no receipt (the engine committed
    nothing).  Exceptions propagate so the calling stage records
    ``TIER_EXCEPTION``.
    """
    debit_id = uuid4().hex
    committed, reason, magnitude = await cbf.atomic_verify_and_commit(
        action, params, debit_id=debit_id
    )
    if not committed:
        return [await _refusal(cbf, tier=tier, code=code, message=reason)], None
    return [], CommitReceipt(tier=tier, magnitude=magnitude, token=debit_id)


async def rollback_barrier(cbf: BarrierEngine, receipt: CommitReceipt) -> None:
    """Retire exactly the debit recorded by ``commit_barrier``.

    The receipt's ``token`` is the ledger ``debit_id``; the engine restores
    the amount it ledgered under that id (falling back to ``magnitude`` only
    if the entry has already settled) and ignores a repeated rollback.
    """
    await cbf.rollback_state(magnitude=receipt.magnitude, debit_id=receipt.token)
