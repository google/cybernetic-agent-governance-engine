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

"""Settle the phase-2 commits behind a seal once the sealed action has run.

A clean committing run reserves phase-2 state (CBF headroom, a fiscal
reservation) and then mints a seal (:mod:`.sealing`).  The reservation is
made *before* the action runs, so it can only be made final *after*: the
caller reports the outcome with ``SymbolicGovernor.settle(seal, executed=...)``.

* ``executed=True`` calls each tier's ``confirm(receipt)`` in commit order.
* ``executed=False`` calls each tier's ``rollback(receipt)``, last in first out.

The ledger lives in the governor's process, because governance and actuation
share it (the seal is the identity carried between them).  It is not durable,
and does not need to be: if the process dies between seal and settlement,
nothing confirms, and a tier whose reservation must not outlive an unexecuted
action (fiscal) reclaims it on its own TTL.  A crash *after* the action but
*before* ``settle`` leaves the reservation to expire too, so that spend is
under-counted.  That trade-off is recorded in ADR-009.

Settlement is idempotent per seal: the first ``settle`` takes the commits,
and any later ``settle`` for the same seal finds nothing and does nothing.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from src.gateway.governance.contracts import Violation
from src.gateway.governance.governor.reservation import shielded_settle

if TYPE_CHECKING:
    from src.gateway.governance.governor.reservation import HeldCommit

logger = logging.getLogger(__name__)

#: Default seconds a held commit set stays settleable.  Longer than any tier
#: reservation TTL (the fiscal guard's default is 300 s), so a dropped entry's
#: reservation has already been reclaimed by its tier.
DEFAULT_HOLD_SECONDS = 600.0


class SettlementLedger:
    """In-process map from an issued seal to the commits that back it.

    Thread-safe; one per governor.  Entries older than ``hold_seconds`` are
    dropped on the next ``hold()``.  Dropping releases only the reference: it
    neither confirms nor rolls back, because the tier's own expiry is the
    backstop for an action that was never settled.
    """

    __slots__ = ("_clock", "_entries", "_hold_seconds", "_lock")

    def __init__(
        self,
        *,
        hold_seconds: float = DEFAULT_HOLD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if hold_seconds <= 0:
            raise ValueError("hold_seconds must be positive")
        self._hold_seconds = hold_seconds
        self._clock = clock
        self._entries: OrderedDict[str, tuple[float, tuple[HeldCommit, ...]]] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def hold(self, seal: str, commits: tuple[HeldCommit, ...]) -> None:
        """Bind ``commits`` to ``seal``.  A seal with no commits needs no entry."""
        if not commits:
            return
        now = self._clock()
        with self._lock:
            if seal in self._entries:
                raise ValueError("seal already holds commits; seals are single-use")
            self._prune(now)
            self._entries[seal] = (now, commits)

    def take(self, seal: str) -> tuple[HeldCommit, ...]:
        """Remove and return the commits behind ``seal`` (empty if none or expired)."""
        now = self._clock()
        with self._lock:
            self._prune(now)
            entry = self._entries.pop(seal, None)
        return entry[1] if entry is not None else ()

    def _prune(self, now: float) -> None:
        cutoff = now - self._hold_seconds
        while self._entries:
            seal, (held_at, commits) = next(iter(self._entries.items()))
            if held_at >= cutoff:
                break
            del self._entries[seal]
            logger.warning(
                "settlement for a seal expired unsettled; dropping %d commit(s) "
                "(%s); tier expiry reclaims any reservation",
                len(commits),
                ", ".join(c.stage.name for c in commits),
            )


async def settle(commits: tuple[HeldCommit, ...], *, executed: bool) -> list[Violation]:
    """Confirm (``executed``) or roll back every commit; return the failures.

    Every hook is attempted even if an earlier one fails, in a shielded task
    so a cancelled caller cannot strand half the commits.  A failure is a HARD
    ``CONFIRM_FAILED`` / ``ROLLBACK_FAILED`` violation that needs manual
    reconciliation; it is reported, not raised, because the action has
    already happened (or already failed) by the time we settle.
    """
    if not commits:
        return []
    return await shielded_settle(commits, hook="confirm" if executed else "rollback")
