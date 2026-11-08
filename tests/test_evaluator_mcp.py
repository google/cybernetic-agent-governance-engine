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
import os
import sys

import pytest

pytestmark = pytest.mark.integration

# Adjust path
sys.path.append(os.getcwd())

from src.governed_financial_advisor.agents.evaluator.agent import (
    check_market_status,
    simulate_governance_check,
)
from src.governed_financial_advisor.infrastructure.gateway_client import (
    GatewayClient,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestEvaluatorMCP")


@pytest.mark.asyncio
async def test_evaluator_tools():
    logger.info(
        "--- Testing Evaluator Agent Tools (MCP & Gateway Precheck Integration) ---"
    )

    # 1. Check Market Status
    logger.info("1. Testing check_market_status...")
    res = await check_market_status("AAPL")
    assert res is not None, "check_market_status returned None"
    logger.info(f"✅ Market Status Result: {res[:50]}...")

    # 2. Simulate Governance Check
    logger.info("2. Testing simulate_governance_check...")
    res = await simulate_governance_check(
        target_tool="execute_trade",
        target_params={"symbol": "AAPL", "amount": 10},
        risk_profile="Low",
    )
    assert res is not None, "simulate_governance_check returned None"
    logger.info(f"✅ Governance Check Result: {res}")

    # 3. Verify Policy Dry-Run via Gateway /governance/policy-precheck
    logger.info("3. Testing GatewayClient.evaluate_policy_dry_run...")
    decision = await GatewayClient().evaluate_policy_dry_run(
        "execute_trade", {"symbol": "AAPL", "amount": 1000, "currency": "USD"}
    )
    assert decision in {"ALLOW", "DENY", "MANUAL_REVIEW"}
    logger.info(f"✅ Policy Precheck Decision: {decision}")


if __name__ == "__main__":
    asyncio.run(test_evaluator_tools())
