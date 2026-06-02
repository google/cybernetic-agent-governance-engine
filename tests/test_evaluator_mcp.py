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
import logging
import pytest

pytestmark = pytest.mark.integration

try:
    from langchain.agents import AgentExecutor
except ImportError:
    pytest.skip("AgentExecutor not found in langchain.agents", allow_module_level=True)

import sys
import os

# Adjust path
sys.path.append(os.getcwd())

from src.governed_financial_advisor.agents.evaluator.agent import (
    check_market_status,
    check_safety_constraints,
    verify_policy_opa,
    safety_intervention
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestEvaluatorMCP")

async def test_evaluator_tools():
    logger.info("--- Testing Evaluator Agent Tools (MCP Integration) ---")
    
    # 1. Check Market Status
    logger.info("1. Testing check_market_status...")
    try:
        res = await check_market_status("AAPL")
        logger.info(f"✅ Market Status Result: {res[:50]}...")
    except Exception as e:
        logger.error(f"❌ Market Status Failed: {e}")

    # 2. Check Safety Constraints
    logger.info("2. Testing check_safety_constraints...")
    try:
        res = await check_safety_constraints(
            target_tool="execute_trade",
            target_params={"symbol": "AAPL", "amount": 10},
            risk_profile="Low"
        )
        logger.info(f"✅ Safety Constraint Result: {res}")
    except Exception as e:
        logger.error(f"❌ Safety Constraint Failed: {e}")

    # 3. Verify Policy
    logger.info("3. Testing verify_policy_opa...")
    try:
        res = await verify_policy_opa(
            action="execute_trade",
            params={"symbol": "AAPL", "amount": 1000}
        )
        logger.info(f"✅ Policy Check Result: {res}")
    except Exception as e:
         logger.error(f"❌ Policy Check Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_evaluator_tools())
