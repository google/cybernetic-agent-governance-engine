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

"""
Gateway Core: Real Trade Execution Logic (Optimistic Execution with Interrupt Check)
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import urllib.parse
from enum import Enum
from typing import Any

import httpx

from src.cage_finance.models.trade_order import TradeOrder
from src.gateway.infrastructure.config_manager import config_manager
from src.gateway.infrastructure.redis_client import redis_client

logger = logging.getLogger(__name__)

# Mock broker mode — set USE_MOCK_BROKER=true to bypass real Alpaca calls.
# Mirrors USE_MOCK_LLM for environments without broker credentials (CI, GKE load tests).
_USE_MOCK_BROKER: bool = os.getenv("USE_MOCK_BROKER", "false").lower() in (
    "true",
    "1",
    "yes",
)

# Only HTTP 400/401/403 prove pre-execution refusal across REST brokers.
# HTTP 422 (e.g. duplicate client_order_id on Alpaca when a prior order was
# already accepted) cannot rule out an existing fill and settles as UNKNOWN (F-35).
_PRE_EXECUTION_REJECTION_STATUSES: frozenset[int] = frozenset({400, 401, 403})
_ACCEPTED_ORDER_STATUSES: frozenset[int] = frozenset({200, 201})


class DispatchPhase(str, Enum):
    """Structural wire-dispatch state for broker order execution."""

    PRE_WIRE = "PRE_WIRE"
    IN_FLIGHT = "IN_FLIGHT"
    RESPONSE_RECEIVED = "RESPONSE_RECEIVED"


class BrokerExecutionError(RuntimeError):
    """Base typed exception for broker execution failures."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "EXECUTION_FAILED",
        retryable: bool = False,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.status_code = status_code


class PreWireRejectionError(BrokerExecutionError):
    """Deterministic failure proving no broker order was accepted or executed.

    Raised strictly BEFORE any HTTP order request bytes are transmitted on the
    wire (safety monitor interrupt, missing credentials, pre-send TCP/TLS
    connection failure) OR on deterministic HTTP 400/401/403 broker rejection
    where the order was explicitly refused without acceptance.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "PRE_WIRE_REJECTED",
        retryable: bool = False,
        status_code: int | None = None,
    ) -> None:
        super().__init__(
            message,
            code=code,
            retryable=retryable,
            status_code=status_code,
        )


class IndeterminateExecutionError(BrokerExecutionError):
    """Post-transmission failure where broker fill cannot be ruled out.

    Raised on ANY failure once HTTP request transmission begins: ReadTimeout,
    WriteTimeout, WriteError, ReadError, RemoteProtocolError, HTTP 5xx, HTTP 429,
    unexpected status codes, JSONDecodeError, or malformed 2xx response payload.
    Always non-retryable and settles as ActuationOutcome.UNKNOWN.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "INDETERMINATE_EXECUTION",
        status_code: int | None = None,
    ) -> None:
        super().__init__(
            message,
            code=code,
            retryable=False,
            status_code=status_code,
        )


def _is_mock_broker() -> bool:
    """Return True when mock broker mode is active via module flag or runtime env."""
    return _USE_MOCK_BROKER or os.getenv("USE_MOCK_BROKER", "false").lower() in (
        "true",
        "1",
        "yes",
    )


async def _redis_get(key: str) -> Any:
    """Compatibility wrapper: awaits redis_client.get() when it returns a coroutine,
    falls back to calling it synchronously (used by unit test mocks that return plain values)."""
    if redis_client is None:
        return None
    result = redis_client.get(key)
    if inspect.isawaitable(result):
        return await result
    return result


async def _check_safety_interrupt(*, late: bool = False) -> None:
    """Read Redis safety_violation flag strictly before wire transmission."""
    try:
        violation = await _redis_get("safety_violation")
    except Exception as exc:
        raise PreWireRejectionError(
            f"Safety monitor Redis pre-check unavailable: {exc}",
            code="SAFETY_CHECK_UNAVAILABLE",
            retryable=False,
        ) from exc

    if violation:
        if late:
            raise PreWireRejectionError(
                f"Trade INTERRUPTED immediately before HTTP call: {violation}",
                code="SAFETY_INTERRUPT",
                retryable=False,
            )
        logger.warning("🛑 Trade INTERRUPTED by Safety Monitor: %s", violation)
        raise PreWireRejectionError(
            f"Trade INTERRUPTED by Safety Monitor: {violation}",
            code="SAFETY_INTERRUPT",
            retryable=False,
        )


def _verify_execution_seal(
    order: TradeOrder,
    *,
    routing_seal: str,
    action: str = "execute_trade",
    seal_params: dict[str, Any] | None = None,
) -> None:
    """Enforce mandatory cryptographic seal verification before broker execution."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_seal,
    )

    if (
        not routing_seal
        or not isinstance(routing_seal, str)
        or not routing_seal.strip()
    ):
        raise SymbolicGovernorViolation(
            (
                "CRITICAL: Direct execution attempt rejected. execute_trade "
                "requires a governor routing seal, consumed via "
                "verify_and_consume_seal() and dispatched through ActuatorRegistry."
            ),
            action=action,
        )

    if seal_params is not None:
        if not verify_seal(routing_seal, action, seal_params):
            raise SymbolicGovernorViolation(
                "routing seal cryptographic verification returned False",
                action=action,
            )
        return

    full_params = order.model_dump(exclude_none=True)
    try:
        if verify_seal(routing_seal, action, full_params):
            return
    except SymbolicGovernorViolation as first_exc:
        if (
            "action mismatch" in first_exc.reason
            and "amount_minor" not in order.model_fields_set
        ):
            reduced_params = order.model_dump(
                exclude={"amount_minor"}, exclude_none=True
            )
            if verify_seal(routing_seal, action, reduced_params):
                return
        raise

    raise SymbolicGovernorViolation(
        "routing seal cryptographic verification returned False",
        action=action,
    )


async def _execute_trade(
    order: TradeOrder,
    *,
    routing_seal: str,
    action: str = "execute_trade",
    seal_params: dict[str, Any] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    """Private broker execution implementation with structural wire-phase tracking."""
    phase = DispatchPhase.PRE_WIRE

    _verify_execution_seal(
        order,
        routing_seal=routing_seal,
        action=action,
        seal_params=seal_params,
    )

    # C-01: Validate trade side before use — fail closed on invalid values.
    trade_side = order.side
    if trade_side not in {"buy", "sell"}:
        raise ValueError(f"Invalid trade side: {trade_side}")

    # --- INTERRUPT CHECK (Module 6 — Pre-Wire) ---
    await _check_safety_interrupt(late=False)

    # --- MOCK BROKER FAST-PATH ---
    if _is_mock_broker():
        mock_order_id = f"MOCK-{order.idempotency_key[:8].upper()}"
        logger.info(
            "🧪 Mock broker: EXECUTED %s x %s → %s",
            order.symbol,
            order.amount,
            mock_order_id,
        )
        return f"EXECUTED (mock): {order.symbol} x {order.amount} {order.side} (Order ID: {mock_order_id})"

    # Secure Config Loading (Pre-Wire)
    api_key = config_manager.get("BROKER_API_KEY")
    api_secret = config_manager.get("BROKER_API_SECRET")
    base_url = str(
        config_manager.get("BROKER_API_URL", "https://paper-api.alpaca.markets") or ""
    ).rstrip("/")

    if not api_key or not api_secret:
        error_msg = "Configuration Error: BROKER_API_KEY or BROKER_API_SECRET missing. Cannot execute trade."
        logger.error(error_msg)
        raise PreWireRejectionError(
            error_msg,
            code="MISSING_BROKER_CREDENTIALS",
            retryable=False,
        )

    parsed_url = urllib.parse.urlparse(base_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise PreWireRejectionError(
            f"Configuration Error: Invalid BROKER_API_URL scheme or host ({parsed_url.scheme!r}).",
            code="INVALID_BROKER_URL",
            retryable=False,
        )

    headers = {"APCA-API-KEY-ID": api_key, "APCA-API-SECRET-KEY": api_secret}
    payload = {
        "symbol": order.symbol,
        "notional": order.amount,
        "side": trade_side,
        "type": "market",
        "time_in_force": "day",
        "client_order_id": order.idempotency_key,
    }

    # --- LATE INTERRUPT CHECK (Strictly Pre-Wire) ---
    await _check_safety_interrupt(late=True)

    logger.info(
        "Executing Trade %s on %s (Confidence: %s)...",
        order.idempotency_key,
        base_url,
        order.confidence,
    )

    orders_url = f"{base_url}/v2/orders"
    phase = DispatchPhase.IN_FLIGHT
    try:
        if http_client is not None:
            resp = await http_client.post(orders_url, json=payload, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(orders_url, json=payload, headers=headers)
        phase = DispatchPhase.RESPONSE_RECEIVED
    except (
        httpx.ConnectTimeout,
        httpx.ConnectError,
        httpx.PoolTimeout,
        httpx.InvalidURL,
        httpx.UnsupportedProtocol,
        httpx.LocalProtocolError,
    ) as exc:
        logger.warning(
            "Broker pre-wire connection/protocol error (%s): %s",
            type(exc).__name__,
            exc,
        )
        raise PreWireRejectionError(
            f"Broker pre-wire connection error ({type(exc).__name__}): {exc}",
            code="BROKER_CONNECT_FAILED",
            retryable=False,
        ) from exc
    except (
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.WriteError,
        httpx.ReadError,
        httpx.RemoteProtocolError,
        httpx.CloseError,
        httpx.DecodingError,
        httpx.HTTPError,
    ) as exc:
        logger.error(
            "Broker post-dispatch transport error (phase=%s, %s): %s",
            phase.value,
            type(exc).__name__,
            exc,
        )
        raise IndeterminateExecutionError(
            f"Post-dispatch broker transport failure ({type(exc).__name__}): {exc}",
            code="BROKER_TRANSPORT_INDETERMINATE",
        ) from exc
    except Exception as exc:
        logger.error(
            "Unexpected broker error after dispatch began (phase=%s, %s): %s",
            phase.value,
            type(exc).__name__,
            exc,
        )
        raise IndeterminateExecutionError(
            f"Unexpected post-dispatch broker error ({type(exc).__name__}): {exc}",
            code="BROKER_EXECUTION_INDETERMINATE",
        ) from exc

    status_code = resp.status_code
    if status_code in _PRE_EXECUTION_REJECTION_STATUSES:
        logger.warning(
            "Broker deterministically rejected order %s with HTTP %d",
            order.idempotency_key,
            status_code,
        )
        raise PreWireRejectionError(
            f"Broker rejected order without acceptance (HTTP {status_code})",
            code=f"BROKER_HTTP_{status_code}",
            retryable=False,
            status_code=status_code,
        )

    if status_code not in _ACCEPTED_ORDER_STATUSES:
        logger.error(
            "Broker returned indeterminate status HTTP %d for order %s",
            status_code,
            order.idempotency_key,
        )
        raise IndeterminateExecutionError(
            f"Broker returned indeterminate HTTP status {status_code}",
            code=f"BROKER_HTTP_{status_code}",
            status_code=status_code,
        )

    try:
        result = resp.json()
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error(
            "Broker returned non-JSON body on HTTP %d for order %s: %s",
            status_code,
            order.idempotency_key,
            exc,
        )
        raise IndeterminateExecutionError(
            f"Broker returned malformed JSON on HTTP {status_code}: {exc}",
            code="MALFORMED_BROKER_JSON",
            status_code=status_code,
        ) from exc

    if not isinstance(result, dict):
        raise IndeterminateExecutionError(
            f"Broker returned non-object JSON payload ({type(result).__name__}) on HTTP {status_code}",
            code="MALFORMED_BROKER_RESPONSE",
            status_code=status_code,
        )

    order_id = result.get("id")
    if not isinstance(order_id, str) or not order_id.strip():
        raise IndeterminateExecutionError(
            f"Broker HTTP {status_code} response missing valid order 'id'",
            code="MALFORMED_BROKER_RESPONSE",
            status_code=status_code,
        )

    logger.info("Trade Executed: %s", order_id)
    return f"EXECUTED: {order.symbol} x {order.amount} (Order ID: {order_id})"


async def execute_trade(
    order: TradeOrder,
    *,
    routing_seal: str,
    action: str = "execute_trade",
    seal_params: dict[str, Any] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    """Execute a governed trade against a Broker API with mandatory cryptographic seal verification."""
    return await _execute_trade(
        order,
        routing_seal=routing_seal,
        action=action,
        seal_params=seal_params,
        http_client=http_client,
    )
