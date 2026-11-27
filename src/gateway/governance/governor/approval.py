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

"""The human approval a post-approval committing run may spend.

``SymbolicGovernor.revalidate_post_hitl()`` is handed a
:class:`PostHitlApproval`, never a spent one. The run binds the request's
server inputs exactly once; the result (the evaluated params) is what every
stage evaluates, what the seal commits to and what the approval is checked
against. The governor decides first and spends second:

* **NOT COVERED** — before any stage runs, ``covers(evaluated)`` must hold:
  the approval was given for exactly these evaluated params (for example the
  same trader identity and an amount no larger than approved). Otherwise the
  run is refused ``[APPROVAL_NOT_REDEEMABLE]`` and the approval is **not**
  spent: it did not authorise this request.
* **ALLOW** — the POST_HITL run is clean. ``spend(evaluated)`` runs inside
  the run's ``ReservationScope``, after every stage and before the seal is
  minted. It is the atomic, single-use consumption
  (``DeferQueue.consume_approval()``: a ``RESOLVED -> CONSUMED``
  compare-and-swap that re-checks coverage of the same evaluated params), so
  of any number of concurrent redemptions at most one is sealed. A
  redemption that loses the race seals nothing and its phase-2 commits roll
  back.
* **DENY** — the approval is spent, then the run is refused. An approved
  request that no longer clears the barriers (or policy), or that now
  reports a human-review hold the approval was not given against
  (``approved_holds``), must be approved afresh.
* **DEFER** (a warranted norm became ineligible, and nothing else refuses) —
  the approval is **not** spent. A warrant failure is not the approver's to
  repair, and the approval did not authorise anything that ran; once the
  warrant is eligible again the same approval redeems, still single-use,
  still bound to the approved action and params, and still subject to its
  own expiry.

An approval is consumed only by a run that seals exactly the params it
covers. Coverage is evaluated against the evaluated (sealed) params, before
any stage runs and again inside the compare-and-swap that consumes the
approval. There is no second server-input lookup. (A refused run still burns
an approval through the same coverage-checked ``spend``, so only an approval
that covers its evaluated params; it never seals.)

The governor never opens a queue: the gateway binds ``covers`` and
``spend`` to the approval it verified (``enforce_approved_governance``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PostHitlApproval:
    """A verified, unspent human approval for one committing run.

    Attributes:
        approval_id: The approval token's id (``DeferToken.defer_id``). A
            post-approval deferral names it as the record that stays
            resolvable.
        barrier_preview: The phase-2 preview the approval was given against
            (``DeferToken.barrier_preview``): ``PASS``, ``FAIL`` or ``None``.
        spend: Atomically consume the approval iff it covers exactly the
            evaluated params it is given. Returns ``True`` iff this call
            consumed it; ``False`` if it was already spent, expired or does
            not cover those params. Must not raise for a refusal; an error
            is ``False`` (fail closed). An unreachable approval store may
            raise :class:`~.errors.ApprovalSpendUnavailableError`, which
            blocks the run without spending.
        covers: Side-effect-free check, made before any stage runs, that the
            approval covers the evaluated params it is given (compared with
            the approved snapshot). ``False`` refuses the run
            ``[APPROVAL_NOT_REDEEMABLE]`` without spending the approval. Must
            not raise; an error is ``False`` (fail closed).
        thread_id: The approval's thread, for trace correlation.
        approved_holds: ``(tier, code)`` of every human-review (HITL) hold
            the approval was given against (``DeferToken.hitl_holds``). The
            committing run treats a re-run read-only stage's HITL finding as
            answered only if it is one of these
            (``pipeline.answered_by_approval``). A hold the reviewer was never
            shown, e.g. an external authority escalating only after the
            request was parked, stands and refuses the run. Empty (the
            default) answers nothing: fail closed.
    """

    approval_id: str
    barrier_preview: str | None
    spend: Callable[[Mapping[str, Any]], Awaitable[bool]]
    covers: Callable[[Mapping[str, Any]], bool]
    thread_id: str | None = None
    approved_holds: frozenset[tuple[str, str]] = frozenset()


__all__ = ["PostHitlApproval"]
