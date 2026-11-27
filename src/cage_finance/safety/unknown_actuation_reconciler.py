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

"""Same-day reconciliation and reclamation for UNKNOWN fiscal reservations.

When an actuation ends with ``ActuationOutcome.UNKNOWN`` (broker timeout, 5xx,
or ambiguous status), :class:`FiscalLimitGuard.confirm` holds the trade amount
against ``fiscal:daily_limit:{YYYY-MM-DD}`` so daily capacity cannot be
over-spent. Without reconciliation, a broker non-fill holds capacity for the
remainder of the UTC day without a resolution path or alarm (POAM-2026-232
Stage 2).

This module queries the broker by ``idempotency_key`` (``client_order_id``):

* ``FILLED``        -> finalizes the spend (leaves daily counter intact, clears unverified entry, updates ledger ``EXECUTED``)
* ``NOT_EXECUTED``  -> reclaims the confirmed fiscal capacity cleanly and updates ledger ``BLOCKED``
* ``INDETERMINATE`` -> keeps the reservation held; if older than ``max_age_seconds``, reports it as aged unresolved and fires alerts
"""

from __future__ import annotations

import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from src.cage_finance.safety.broker_order_lookup import (
    BrokerOrderLookupResult,
    BrokerOrderStatus,
    lookup_broker_order_status,
)
from src.cage_finance.safety.fiscal_limit_guard import (
    FiscalLimitGuard,
    UnverifiedUnknownReservation,
)
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ExecutionLedger,
    ExecutionStatus,
)

logger = logging.getLogger(__name__)

DEFAULT_UNKNOWN_ACTUATION_MAX_AGE_SECONDS = 300.0

LookupFn = Callable[[str], Awaitable[BrokerOrderLookupResult]]
AgedAlertCallback = Callable[[list[UnverifiedUnknownReservation]], Awaitable[Any] | Any]


@dataclass(frozen=True)
class ReconcileUnknownReport:
    """Summary of one reconciliation pass over confirmed UNKNOWN reservations."""

    checked: int
    settled_executed: tuple[str, ...]
    settled_reclaimed: tuple[str, ...]
    still_indeterminate: tuple[str, ...]
    aged_unresolved: tuple[UnverifiedUnknownReservation, ...]


async def reconcile_unknown_actuations(
    fiscal_guard: FiscalLimitGuard,
    *,
    execution_ledger: ExecutionLedger | None = None,
    action: str = "execute_trade",
    caller_identity: str = SHARED_CALLER,
    lookup_fn: LookupFn = lookup_broker_order_status,
    max_age_seconds: float = DEFAULT_UNKNOWN_ACTUATION_MAX_AGE_SECONDS,
    governor_metrics: Any | None = None,
    on_aged_unresolved: AgedAlertCallback | None = None,
    now: float | None = None,
) -> ReconcileUnknownReport:
    """Reconcile all confirmed-but-unverified UNKNOWN fiscal reservations against broker lookup."""
    current_time = time.time() if now is None else float(now)
    pending = await fiscal_guard.list_unverified_unknown(now=current_time)

    settled_executed: list[str] = []
    settled_reclaimed: list[str] = []
    still_indeterminate: list[str] = []
    aged_unresolved: list[UnverifiedUnknownReservation] = []

    for entry in pending:
        try:
            lookup = await lookup_fn(entry.idempotency_key)
        except Exception as exc:
            logger.error(
                "[unknown_reconciler] Broker lookup error for %s (%s): %s",
                entry.idempotency_key,
                type(exc).__name__,
                exc,
            )
            lookup = BrokerOrderLookupResult(
                BrokerOrderStatus.INDETERMINATE,
                detail=f"{type(exc).__name__}: {exc}",
            )

        if lookup.status is BrokerOrderStatus.FILLED:
            await fiscal_guard.settle_unknown(entry.idempotency_key, executed=True)
            if execution_ledger is not None:
                await execution_ledger.resolve_unknown(
                    action,
                    caller_identity,
                    entry.idempotency_key,
                    status=ExecutionStatus.EXECUTED,
                    outcome=(
                        f"EXECUTED (reconciled): {entry.symbol} x {entry.amount_usd:.2f} "
                        f"({lookup.detail})"
                    ),
                )
            settled_executed.append(entry.idempotency_key)
            if governor_metrics is not None and hasattr(
                governor_metrics, "unknown_actuation_event"
            ):
                governor_metrics.unknown_actuation_event("settled_executed")
        elif lookup.status is BrokerOrderStatus.NOT_EXECUTED:
            await fiscal_guard.settle_unknown(entry.idempotency_key, executed=False)
            if execution_ledger is not None:
                await execution_ledger.resolve_unknown(
                    action,
                    caller_identity,
                    entry.idempotency_key,
                    status=ExecutionStatus.BLOCKED,
                    outcome=(
                        f"BLOCKED (reclaimed): {entry.symbol} x {entry.amount_usd:.2f} "
                        f"({lookup.detail})"
                    ),
                )
            settled_reclaimed.append(entry.idempotency_key)
            if governor_metrics is not None and hasattr(
                governor_metrics, "unknown_actuation_event"
            ):
                governor_metrics.unknown_actuation_event("settled_reclaimed")
        else:
            still_indeterminate.append(entry.idempotency_key)
            if governor_metrics is not None and hasattr(
                governor_metrics, "unknown_actuation_event"
            ):
                governor_metrics.unknown_actuation_event("indeterminate")
            age_s = current_time - entry.confirmed_at
            if age_s >= max_age_seconds:
                aged_unresolved.append(entry)
                logger.error(
                    "[unknown_reconciler] Aged unresolved UNKNOWN actuation tx=%s symbol=%s amount=%.2f age=%.1fs",
                    entry.idempotency_key,
                    entry.symbol,
                    entry.amount_usd,
                    age_s,
                )

    if governor_metrics is not None and hasattr(
        governor_metrics, "set_aged_unknown_actuations"
    ):
        governor_metrics.set_aged_unknown_actuations(len(aged_unresolved))

    if aged_unresolved and on_aged_unresolved is not None:
        callback_res = on_aged_unresolved(aged_unresolved)
        if inspect.isawaitable(callback_res):
            await callback_res

    return ReconcileUnknownReport(
        checked=len(pending),
        settled_executed=tuple(settled_executed),
        settled_reclaimed=tuple(settled_reclaimed),
        still_indeterminate=tuple(still_indeterminate),
        aged_unresolved=tuple(aged_unresolved),
    )
