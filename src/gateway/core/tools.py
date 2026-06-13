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

import logging
import asyncio
import inspect
import os
from src.gateway.core.structs import TradeOrder
from src.governed_financial_advisor.infrastructure.redis_client import redis_client
from src.governed_financial_advisor.infrastructure.config_manager import config_manager

logger = logging.getLogger(__name__)

# Mock broker mode — set USE_MOCK_BROKER=true to bypass real Alpaca calls.
# Mirrors USE_MOCK_LLM for environments without broker credentials (CI, GKE load tests).
_USE_MOCK_BROKER: bool = os.getenv("USE_MOCK_BROKER", "false").lower() in ("true", "1", "yes")

async def _redis_get(key: str):
    """Compatibility wrapper: awaits redis_client.get() when it returns a coroutine,
    falls back to calling it synchronously (used by unit test mocks that return plain values)."""
    result = redis_client.get(key)
    if inspect.isawaitable(result):
        return await result
    return result


async def execute_trade(order: TradeOrder) -> str:
    """
    Executes a trade against a real Broker API (e.g. Alpaca).

    OPTIMISTIC EXECUTION: Checks 'safety_violation' in Redis before committing.
    CONFIG: Uses ConfigManager for secure key retrieval.
    """
    # C-01: Validate trade side before use — fail closed on invalid values.
    action = order.side
    assert action in {"buy", "sell"}, f"Invalid trade side: {action}"
    # --- INTERRUPT CHECK (Module 6) ---
    violation = await _redis_get("safety_violation")
    if violation:
        logger.warning(f"🛑 Trade INTERRUPTED by Safety Monitor: {violation}")
        raise RuntimeError(f"Trade INTERRUPTED by Safety Monitor: {violation}")

    # --- MOCK BROKER FAST-PATH ---
    # Activated by USE_MOCK_BROKER=true (env).  Skips real Alpaca HTTP call.
    # Still runs the interrupt checks above so the test remains representative.
    if _USE_MOCK_BROKER:
        mock_order_id = f"MOCK-{order.transaction_id[:8].upper()}"
        logger.info("🧪 Mock broker: EXECUTED %s x %s → %s", order.symbol, order.amount, mock_order_id)
        return f"EXECUTED (mock): {order.symbol} x {order.amount} {order.side} (Order ID: {mock_order_id})"

    # Secure Config Loading
    # Auto-mapping to 'broker-api-key' and 'broker-api-secret' via ConfigManager
    api_key = config_manager.get("BROKER_API_KEY")
    api_secret = config_manager.get("BROKER_API_SECRET")
    base_url = config_manager.get("BROKER_API_URL", "https://paper-api.alpaca.markets")

    if not api_key or not api_secret:
        # In Production, we fail safe if credentials are missing.
        error_msg = "Configuration Error: BROKER_API_KEY or BROKER_API_SECRET missing. Cannot execute trade."
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    logger.info(f"Executing Trade {order.transaction_id} on {base_url} (Confidence: {order.confidence})...")

    # Switch to httpx for native async I/O
    import httpx

    headers = {
        "APCA-API-KEY-ID": api_key,
        "APCA-API-SECRET-KEY": api_secret
    }

    payload = {
        "symbol": order.symbol,
        "qty": order.amount,
        "side": action,  # C-01: use validated trade side, not hardcoded "buy"
        "type": "market",
        "time_in_force": "day"
    }

    def _do_post():
        import requests
        resp = requests.post(f"{base_url}/v2/orders", json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    try:
        # --- LATE INTERRUPT CHECK (Just before HTTP call) ---
        latest_violation = await _redis_get("safety_violation")
        if latest_violation:
            raise RuntimeError(f"Trade INTERRUPTED immediately before HTTP call: {latest_violation}")

        result = await asyncio.to_thread(_do_post)

        logger.info(f"Trade Executed: {result.get('id')}")
        return f"EXECUTED: {order.symbol} x {order.amount} (Order ID: {result.get('id')})"

    except Exception as e:
        logger.error(f"Broker API Error: {e}")
        # Re-raise interrupt signals verbatim (preserves 'INTERRUPTED' sentinel)
        if "INTERRUPTED" in str(e):
            raise RuntimeError(str(e))
        raise RuntimeError(f"Broker Execution Failed: {e}")
