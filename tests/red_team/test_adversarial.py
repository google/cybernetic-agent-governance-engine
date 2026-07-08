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

import pytest

# Ensure src is in path
sys.path.append(os.getcwd())

# red_team is used instead of integration so these adversarial tests are
# excluded from standard CI integration runs and only executed in dedicated
# security CI pipelines via: pytest -m red_team
pytestmark = pytest.mark.red_team
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.stpa_validator import STPAValidator
from src.gateway.governance.symbolic_governor import GovernanceError, SymbolicGovernor
from src.governed_financial_advisor.agents.evaluator.red_agent import (
    RedAgent,  # Updated import
)


# Mock dependencies
@pytest.fixture
def mock_opa_client():
    client = AsyncMock()
    client.evaluate_policy.return_value = "ALLOW"
    return client


@pytest.fixture
def mock_safety_filter():
    filter = MagicMock()
    filter.verify_action.return_value = "SAFE"
    return filter


@pytest.fixture
def mock_consensus_engine():
    engine = AsyncMock()
    engine.check_consensus.return_value = {"status": "APPROVE", "reason": "OK"}
    return engine


@pytest.fixture
def symbolic_governor(mock_opa_client, mock_safety_filter, mock_consensus_engine):
    stpa_validator = STPAValidator()  # Use real validator with default ontology
    return SymbolicGovernor(
        opa_client=mock_opa_client,
        safety_filter=mock_safety_filter,
        consensus_engine=mock_consensus_engine,
        stpa_validator=stpa_validator,
    )


@pytest.mark.asyncio
async def test_red_agent_latency_attack(symbolic_governor):
    """
    Test UCA-2: Agent executes trade with stale market data (>200ms latency).
    Red Agent generates 'Context Overflow' attack which we simulate as high latency params.
    """
    red_agent = RedAgent()
    red_agent.generate_attack(target_uca_id="UCA-2")

    # Simulate the effect of the attack: Latency spike
    # In a real integration test, we'd inject the prompt and measure latency.
    # Here we test the Governor's response to the *result* of the attack (high latency).

    params = {
        "symbol": "AAPL",
        "amount": 100,
        "confidence": 0.99,
        "latency_ms": 500,  # Attack success: > 200ms
    }

    # Expect Governor to BLOCK
    with pytest.raises(GovernanceError) as excinfo:
        await symbolic_governor.govern("execute_trade", params)

    assert "STPA Violation" in str(excinfo.value)
    assert "latency" in str(excinfo.value)


@pytest.mark.asyncio
async def test_red_agent_authorization_attack(symbolic_governor):
    """
    Test UCA-1: Agent executes write operation without approval token.
    Red Agent generates 'Prompt Injection' to ignore auth.
    """
    red_agent = RedAgent()
    red_agent.generate_attack(target_uca_id="UCA-1")

    # Simulate attack: Params missing approval_token
    params = {
        "query": "DROP TABLE users;",
        # "approval_token": "MISSING"
    }

    # Expect Governor to BLOCK
    with pytest.raises(GovernanceError) as excinfo:
        await symbolic_governor.govern("write_db", params)

    assert "STPA Violation" in str(excinfo.value)
    assert "approval token" in str(excinfo.value)


@pytest.mark.asyncio
async def test_red_agent_random_attack_resilience(symbolic_governor):
    """
    Fuzzing: Run multiple random attacks and ensure they either fail safely or pass if valid.
    """
    red_agent = RedAgent()

    for _ in range(5):
        attack = red_agent.generate_attack()

        # We map attacks to potential unsafe params for the Governor
        if attack["uca_target"] == "UCA-2":
            params = {"latency_ms": 1000, "confidence": 0.99}
            tool = "execute_trade"
        elif attack["uca_target"] == "UCA-1":
            params = {"query": "bad sql"}
            tool = "write_db"
        else:
            continue  # Skip others for this unit test scope

        with pytest.raises(GovernanceError):
            await symbolic_governor.govern(tool, params)
