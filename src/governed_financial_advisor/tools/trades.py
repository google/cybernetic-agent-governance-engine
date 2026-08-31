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

import logging

from src.cage_finance.models.trade_order import TradeOrder
from src.governed_financial_advisor.graph.annotations import side_effect_node

logger = logging.getLogger(__name__)


def propose_trade(order: dict) -> str:
    """
    Proposes a trade strategy. This does NOT execute the trade.
    Args:
        order: A dictionary containing trade details.
    """
    # Handle dict input
    if isinstance(order, dict):
        try:
            order = TradeOrder(**order)  # type: ignore[assignment]
        except Exception as e:
            logger.error(f"Failed to parse TradeOrder dict: {e}")
            # Fallback to dict access if conversion fails (unlikely if Pydantic)
            symbol = order.get("symbol", "UNKNOWN")
            amount = order.get("amount", 0)
            currency = order.get("currency", "USD")
            tid = order.get("transaction_id", "N/A")
            return f"PROPOSAL LOGGED: {symbol} {amount} {currency}. Transaction ID: {tid}. Waiting for Verifier."

    # Simply log it locally. No governance needed for thinking.
    return f"PROPOSAL LOGGED: {order.symbol} {order.amount} {order.currency}. Transaction ID: {order.transaction_id}. Waiting for Verifier."  # type: ignore[attr-defined]


@side_effect_node(kind="api_call", external_system="gateway_mcp")
async def execute_trade(order: dict) -> str:
    """
    Executes a trade via the Agentic Gateway.
    The Gateway enforces all Policy (OPA), Safety, and Consensus checks.
    Args:
        order: A dictionary containing trade details (symbol, amount, currency, transaction_id, confidence).
    """
    # Handle dict input
    if isinstance(order, dict):
        # We need to keep it as dict for model_dump equivalent or just verify
        # but gateway expects dict params anyway.
        params = order
        tid = order.get("transaction_id", "UNKNOWN")
        conf = order.get("confidence", 0.0)
    else:
        # Fallback if somehow passed as object (though type hint says dict)
        params = order.model_dump()
        tid = order.transaction_id
        conf = order.confidence

    logger.info(f"Delegating trade execution to Gateway: {tid} (Confidence: {conf})")

    # Call Gateway via MCP
    from src.governed_financial_advisor.infrastructure.mcp_client import get_mcp_client

    # The MCP tool is named 'execute_trade_action' in hybrid_server.py
    result = await get_mcp_client().call_tool("execute_trade_action", params)

    return result
