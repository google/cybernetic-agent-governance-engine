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

"""A single-use in-memory approval for driving ``revalidate_post_hitl``.

Production approvals are ``DeferQueue`` tokens the gateway binds into a
:class:`PostHitlApproval` (``enforce_approved_governance``). Governor-level
tests that do not exercise the queue use :func:`granted_approval`, whose
``spend`` succeeds exactly once, like the queue's compare-and-swap.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.gateway.governance.governor.approval import PostHitlApproval


@dataclass
class SpendCounter:
    """How often an approval's ``spend`` was called and whether it succeeded."""

    calls: int = 0
    spent: bool = False
    results: list[bool] = field(default_factory=list)


def granted_approval(
    barrier_preview: str | None = None,
    *,
    approval_id: str = "approval-test",
    thread_id: str | None = None,
    counter: SpendCounter | None = None,
) -> PostHitlApproval:
    """An unspent approval given against ``barrier_preview``; spends once."""
    state = counter if counter is not None else SpendCounter()

    async def _spend() -> bool:
        state.calls += 1
        ok = not state.spent
        state.spent = True
        state.results.append(ok)
        return ok

    return PostHitlApproval(
        approval_id=approval_id,
        barrier_preview=barrier_preview,
        spend=_spend,
        thread_id=thread_id,
    )


__all__ = ["SpendCounter", "granted_approval"]
