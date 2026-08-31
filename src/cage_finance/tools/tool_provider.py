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

import asyncio
import json
import logging
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import execute_trade
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.singletons import symbolic_governor
from src.gateway.server.governance_middleware import enforce_governance
from src.governed_financial_advisor.tools.market_data_tool import get_market_data

logger = logging.getLogger(__name__)


async def execute_trade_action(
    symbol: str,
    amount: float,
    currency: str,
    confidence: float = 0.0,
    transaction_id: str | None = None,
    trader_id: str = "agent_001",
    trader_role: str = "junior",
    dry_run: bool = False,
) -> str:
    """Execute a financial trade under strict governance.

    Gap 2 fix (No-Direct-Bind): ``enforce_governance()`` now returns a routing
    seal.  This function verifies the seal before executing the trade, ensuring
    that execution cannot proceed by ignoring the governance response.
    Satisfies: NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

    Args:
        symbol: Ticker symbol (e.g. "AAPL").
        amount: Trade quantity (positive float).
        currency: ISO 4217 currency code (e.g. "USD").
        confidence: Model confidence score [0.0, 1.0].  Callers MUST supply a
            real value — the governance pipeline enforces a minimum threshold
            (US_FED: 0.95).  Omitting this parameter leaves the default 0.0
            which will always fail the confidence gate.
        transaction_id: Optional idempotency key; auto-generated if absent.
        trader_id: Identifier of the requesting agent or user.
        trader_role: RBAC role used for fiscal-limit enforcement.
        dry_run: When True, governance checks run but no broker call is made.
    """
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_and_consume_seal,
    )

    logger.info(
        "Tool Call: execute_trade(%s, %s, confidence=%s)",
        symbol,
        amount,
        confidence,
    )
    if not transaction_id:
        transaction_id = str(uuid.uuid4())

    params = {
        "symbol": symbol,
        "amount": amount,
        "currency": currency,
        "confidence": confidence,
        "transaction_id": transaction_id,
        "trader_id": trader_id,
        "trader_role": trader_role,
        "dry_run": dry_run,
    }

    try:
        seal = await enforce_governance("execute_trade", params)
    except PermissionError as exc:
        return f"BLOCKED: {exc}"

    # Phase 3.2 NARROW Receipt Validation (CAGE-SEC-004 fix)
    # Check for NARROW verdict receipt using seal prefix before seal verification
    action_params = params  # Default: use original params

    if seal:
        from src.gateway.infrastructure.redis_client import redis_client

        # Generate receipt key from seal (first 32 hex chars = 128 bits)
        seal_prefix = seal[:32] if len(seal) >= 32 else seal
        receipt_key = f"narrow:receipt:{seal_prefix}"

        # Attempt to fetch NARROW receipt (fail-silent if not present)
        if redis_client is not None:
            try:
                receipt_data = await redis_client.get(receipt_key)
                if receipt_data:
                    # Delete receipt immediately (one-time use — fetch-and-burn pattern)
                    await redis_client.delete(receipt_key)

                    receipt_payload = json.loads(receipt_data)
                    narrowed_params = receipt_payload.get("narrowed_params", {})
                    receipt_signature = receipt_payload.get("original_signature", "")

                    # Verify original signature matches (prevents receipt forgery)
                    if receipt_signature != seal:
                        logger.error(
                            "🚫 execute_trade: NARROW receipt signature mismatch. "
                            "Receipt sig=%s, Seal=%s",
                            receipt_signature[:16],
                            seal[:16],
                        )
                        return "BLOCKED: Narrowing receipt signature mismatch — possible forgery attempt"

                    # Use narrowed params for trade execution
                    action_params = narrowed_params
                    logger.info(
                        "📐 execute_trade: NARROW receipt validated and consumed. "
                        "Using narrowed params: %s",
                        {
                            k: narrowed_params.get(k)
                            for k in ["symbol", "amount", "confidence"]
                        },
                    )
            except json.JSONDecodeError as exc:
                logger.error(
                    "🚫 execute_trade: NARROW receipt payload invalid JSON: %s",
                    exc,
                )
                return "BLOCKED: Narrowing receipt payload corrupted"
            except Exception as exc:
                # Only log errors, don't block — receipt may legitimately not exist
                logger.debug(
                    "execute_trade: NARROW receipt lookup failed (may be ALLOW verdict): %s",
                    exc,
                )

    # Gap 2 fix / CAGE-SEC-008: verify and atomically consume the routing seal before executing.
    # verify_and_consume_seal() burns the single-use nonce in Redis, preventing replay attacks.
    # Phase 3.2: Verify seal against the params that will actually be executed (narrowed or original)
    if seal:
        try:
            await verify_and_consume_seal(seal, "execute_trade", action_params)
        except SymbolicGovernorViolation as exc:
            logger.error(
                "🔒 execute_trade_action: routing seal verification FAILED — "
                "blocking execution (No-Direct-Bind invariant). Reason: %s",
                exc.reason,
            )
            return "BLOCKED: routing seal invalid, expired, or already consumed — governance authority unresolved."

    if dry_run:
        return "DRY_RUN: APPROVED by OPA, Safety, and Consensus."

    # Validate TradeOrder before actuation
    # Phase 3.2: Use action_params (either narrowed or original)
    try:
        order = TradeOrder(**action_params)  # type: ignore[arg-type]
    except Exception as exc:
        logger.error("TradeOrder validation failed before actuation: %s", exc)
        return f"ERROR: invalid trade parameters — {exc}"

    try:
        return await execute_trade(order)
    except Exception as exc:
        logger.error("Execution Error: %s", exc)
        if hasattr(symbolic_governor.safety_filter, "rollback_state"):
            raw_amt = action_params.get("amount")
            rollback_amt = (
                float(raw_amt)
                if isinstance(raw_amt, (int, float, str))
                else float(amount)
            )
            await symbolic_governor.safety_filter.rollback_state(rollback_amt)  # type: ignore[misc, func-returns-value]
        return f"ERROR: {exc}"


async def check_market_status(symbol: str) -> str:
    """Check current status of a market symbol."""
    return await asyncio.to_thread(get_market_data, symbol)


async def get_market_sentiment(symbol: str) -> str:
    """Retrieve current market sentiment for a symbol."""
    return await asyncio.to_thread(get_market_data, symbol)


class FinancialToolProvider(DomainToolProvider):
    def register_tools(self, server: FastMCP) -> None:
        server.tool()(execute_trade_action)
        server.tool()(check_market_status)
        server.tool()(get_market_sentiment)
