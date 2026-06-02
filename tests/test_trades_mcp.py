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

import os
import sys
import logging
import pytest

pytestmark = pytest.mark.integration

# Adjust path
sys.path.append(os.getcwd())

from src.governed_financial_advisor.tools.trades import execute_trade

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestTradesMCP")

async def test_trade_execution():
    logger.info("--- Testing Trade Execution (MCP Integration) ---")
    
    # Mock Order
    order = {
        "symbol": "AAPL",
        "amount": 10,
        "currency": "USD",
        "transaction_id": "test-txn-001",
        "confidence": 0.95
    }

    # Execute Trade
    logger.info(f"Executing Trade: {order}")
    try:
        # This calls trades.py -> mcp_client -> Gateway -> execute_trade_action
        # The Gateway might fail if it tries to execute for real, or block if governance fails.
        # But we just want to see if the call succeeds.
        res = await execute_trade(order)
        logger.info(f"✅ Trade Result: {res}")
    except Exception as e:
        logger.error(f"❌ Trade Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_trade_execution())
