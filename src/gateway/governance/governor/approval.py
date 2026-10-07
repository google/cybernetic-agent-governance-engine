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
:class:`PostHitlApproval`, never a spent one. The governor decides first and
spends second:

* **ALLOW** — the POST_HITL run is clean. ``spend()`` runs inside the run's
  ``ReservationScope``, after every stage and before the seal is minted. It
  is the atomic, single-use consumption (``DeferQueue.consume_approval()``:
  a ``RESOLVED -> CONSUMED`` compare-and-swap), so of any number of
  concurrent redemptions at most one is sealed. A redemption that loses the
  race seals nothing and its phase-2 commits roll back.
* **DENY** — the approval is spent, then the run is refused. An approved
  request that no longer clears the barriers (or policy) must be approved
  afresh.
* **DEFER** (a warranted norm became ineligible, and nothing else refuses) —
  the approval is **not** spent. A warrant failure is not the approver's to
  repair, and the approval did not authorise anything that ran; once the
  warrant is eligible again the same approval redeems, still single-use,
  still bound to the approved action and params, and still subject to its
  own expiry.

The governor never opens a queue: the gateway binds ``spend`` to the
approval it verified (``enforce_approved_governance``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PostHitlApproval:
    """A verified, unspent human approval for one committing run.

    Attributes:
        approval_id: The approval token's id (``DeferToken.defer_id``). A
            post-approval deferral names it as the record that stays
            resolvable.
        barrier_preview: The phase-2 preview the approval was given against
            (``DeferToken.barrier_preview``): ``PASS``, ``FAIL`` or ``None``.
        spend: Atomically consume the approval. Returns ``True`` iff this
            call consumed it; ``False`` if it was already spent, expired or
            no longer covers the request. Must not raise; an error is
            ``False`` (fail closed).
        thread_id: The approval's thread, for trace correlation.
    """

    approval_id: str
    barrier_preview: str | None
    spend: Callable[[], Awaitable[bool]]
    thread_id: str | None = None


__all__ = ["PostHitlApproval"]
