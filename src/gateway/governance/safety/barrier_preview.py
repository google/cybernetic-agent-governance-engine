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

"""Read-only barrier preview shared by every CBF-backed domain tier.

Phase-2 barrier tiers mutate state in ``commit()`` via
``atomic_verify_and_commit``.  Their ``evaluate()`` hook is the read-only
preview of that commit, used by DRY_RUN so ``verify()`` reports the refusal
live execution would produce without spending any barrier headroom.

Kept in the kernel so the fail-closed rule lives in one place for every
domain (finance, healthcare, physical AI).
"""

from typing import Any, Protocol

from src.gateway.governance.contracts import Violation, ViolationKind

SAFE = "SAFE"


class BarrierReader(Protocol):
    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str: ...


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
