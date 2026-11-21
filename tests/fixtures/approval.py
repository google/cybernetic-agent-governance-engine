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
``spend`` succeeds exactly once, like the queue's compare-and-swap, and only
for evaluated params its ``covers`` accepts (by default: all).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.governor.approval import PostHitlApproval


@dataclass
class SpendCounter:
    """How an approval's ``spend`` / ``covers`` were called and what they answered.

    ``params`` records the evaluated params handed to each ``spend`` call and
    ``covered`` those handed to each ``covers`` call, in order.
    """

    calls: int = 0
    spent: bool = False
    results: list[bool] = field(default_factory=list)
    params: list[dict[str, Any]] = field(default_factory=list)
    covered: list[dict[str, Any]] = field(default_factory=list)


def granted_approval(
    barrier_preview: str | None = None,
    *,
    approval_id: str = "approval-test",
    thread_id: str | None = None,
    counter: SpendCounter | None = None,
    approved_holds: frozenset[tuple[str, str]] = frozenset(),
    covers: Callable[[Mapping[str, Any]], bool] | None = None,
) -> PostHitlApproval:
    """An unspent approval given against ``barrier_preview`` and ``approved_holds``.

    ``covers`` decides which evaluated params the approval covers (default:
    every one). ``spend`` consumes it once, and only for covered params.
    """
    state = counter if counter is not None else SpendCounter()

    def _covers(evaluated: Mapping[str, Any]) -> bool:
        state.covered.append(dict(evaluated))
        return True if covers is None else bool(covers(evaluated))

    async def _spend(evaluated: Mapping[str, Any]) -> bool:
        state.calls += 1
        state.params.append(dict(evaluated))
        ok = not state.spent and (True if covers is None else bool(covers(evaluated)))
        if ok:
            state.spent = True
        state.results.append(ok)
        return ok

    return PostHitlApproval(
        approval_id=approval_id,
        barrier_preview=barrier_preview,
        spend=_spend,
        covers=_covers,
        thread_id=thread_id,
        approved_holds=approved_holds,
    )


__all__ = ["SpendCounter", "granted_approval"]
