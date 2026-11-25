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

"""Read-only broker order status lookup for UNKNOWN actuation reconciliation.

Kept separate from ``src.cage_finance.tools.trade_executor`` so reconcilers
never import the execution surface (POAM-2026-109 / POAM-2026-232 Stage 2).
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from enum import Enum

import httpx

from src.gateway.governance.execution_idempotency import is_valid_idempotency_key
from src.gateway.infrastructure.config_manager import config_manager

logger = logging.getLogger(__name__)


class BrokerOrderStatus(str, Enum):
    """Settled status returned by broker order lookup for UNKNOWN actuations."""

    FILLED = "FILLED"
    NOT_EXECUTED = "NOT_EXECUTED"
    INDETERMINATE = "INDETERMINATE"


class BrokerOrderLookupResult:
    """Outcome of querying the broker for an unsettled ``transaction_id``."""

    def __init__(
        self,
        status: BrokerOrderStatus,
        *,
        order_id: str | None = None,
        detail: str = "",
    ) -> None:
        self.status = status
        self.order_id = order_id
        self.detail = detail


_FILLED_ORDER_STATES: frozenset[str] = frozenset({"filled", "partially_filled"})
_UNFILLED_TERMINAL_ORDER_STATES: frozenset[str] = frozenset(
    {"canceled", "cancelled", "expired", "rejected", "done_for_day"}
)


def _is_mock_broker() -> bool:
    return os.getenv("USE_MOCK_BROKER", "false").lower() in ("true", "1", "yes")


async def lookup_broker_order_status(
    transaction_id: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> BrokerOrderLookupResult:
    """Query the broker by ``client_order_id`` (``transaction_id``) to settle an UNKNOWN hold.

    Fail-closed: only HTTP 404 (order absent) or a terminal zero-fill order state
    returns ``NOT_EXECUTED``; ambiguous, in-flight, error, or unconfigured states
    return ``INDETERMINATE`` so fiscal reservations are never prematurely released.
    """
    if not is_valid_idempotency_key(transaction_id):
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail=f"invalid transaction_id {transaction_id!r}",
        )

    if _is_mock_broker():
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail="mock broker mode has no authoritative order lookup",
        )

    api_key = config_manager.get("BROKER_API_KEY")
    api_secret = config_manager.get("BROKER_API_SECRET")
    base_url = str(
        config_manager.get("BROKER_API_URL", "https://paper-api.alpaca.markets") or ""
    ).rstrip("/")
    if not api_key or not api_secret:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail="missing broker credentials for order lookup",
        )

    parsed_url = urllib.parse.urlparse(base_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail=f"invalid BROKER_API_URL scheme or host ({parsed_url.scheme!r})",
        )

    headers = {"APCA-API-KEY-ID": api_key, "APCA-API-SECRET-KEY": api_secret}
    lookup_url = (
        f"{base_url}/v2/orders:by_client_order_id"
        f"?client_order_id={urllib.parse.quote(transaction_id.lower(), safe='')}"
    )
    try:
        if http_client is not None:
            resp = await http_client.get(lookup_url, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(lookup_url, headers=headers)
    except Exception as exc:
        logger.warning(
            "Broker order lookup failed for %s (%s): %s",
            transaction_id,
            type(exc).__name__,
            exc,
        )
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail=f"{type(exc).__name__}: {exc}",
        )

    if resp.status_code == 404:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.NOT_EXECUTED,
            detail="broker reported order not found (HTTP 404)",
        )

    if resp.status_code != 200:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail=f"broker lookup returned HTTP {resp.status_code}",
        )

    try:
        body = resp.json()
    except Exception as exc:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail=f"malformed lookup JSON: {exc}",
        )
    if not isinstance(body, dict):
        return BrokerOrderLookupResult(
            BrokerOrderStatus.INDETERMINATE,
            detail="non-object lookup response",
        )

    order_id_raw = body.get("id")
    order_id = order_id_raw if isinstance(order_id_raw, str) and order_id_raw else None
    raw_status = str(body.get("status", "")).strip().lower()
    raw_filled = body.get("filled_qty", 0)
    try:
        filled_qty = float(raw_filled or 0.0)
    except (TypeError, ValueError):
        filled_qty = -1.0

    if raw_status in _FILLED_ORDER_STATES or filled_qty > 0.0:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.FILLED,
            order_id=order_id,
            detail=f"broker order {raw_status or 'unknown'} (filled_qty={filled_qty})",
        )

    if raw_status in _UNFILLED_TERMINAL_ORDER_STATES and filled_qty == 0.0:
        return BrokerOrderLookupResult(
            BrokerOrderStatus.NOT_EXECUTED,
            order_id=order_id,
            detail=f"broker order {raw_status} with zero fills",
        )

    return BrokerOrderLookupResult(
        BrokerOrderStatus.INDETERMINATE,
        order_id=order_id,
        detail=f"broker order status={raw_status!r} still pending/ambiguous",
    )
