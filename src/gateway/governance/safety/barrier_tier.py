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

Kept in the kernel so a fix to the fail-closed or receipt rules is applied once
for every domain.
"""

from typing import Any, Protocol

from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind

SAFE = "SAFE"


class BarrierReader(Protocol):
    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str: ...


class BarrierEngine(BarrierReader, Protocol):
    async def atomic_verify_and_commit(
        self, action_name: str, payload: dict[str, Any], governance_signature: str = ""
    ) -> tuple[bool, str, float]: ...

    async def rollback_state(self, magnitude: float, governance_signature: str | None = None) -> None: ...


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
    return [Violation(tier=tier, code=code, message=str(verdict), kind=ViolationKind.HARD)]


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
    committed, reason, magnitude = await cbf.atomic_verify_and_commit(action, params)
    if not committed:
        return [Violation(tier=tier, code=code, message=reason, kind=ViolationKind.HARD)], None
    return [], CommitReceipt(tier=tier, magnitude=magnitude)


async def rollback_barrier(cbf: BarrierEngine, receipt: CommitReceipt) -> None:
    """Restore exactly the magnitude recorded by ``commit_barrier``."""
    await cbf.rollback_state(magnitude=receipt.magnitude)
