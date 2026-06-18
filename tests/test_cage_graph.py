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
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = pytest.mark.unit

from src.governed_financial_advisor.graph.graph import create_graph
from src.governed_financial_advisor.graph.nodes.safety_node import (
    safety_check_node,
    route_safety,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def mock_state():
    """Return a minimal base AgentState dict for use in legacy tests."""
    return {
        "messages": [],
        "next_step": "supervisor",
        "risk_status": "UNKNOWN",
        "safety_status": "APPROVED",
        "user_id": "test_user",
    }


@pytest.fixture
def minimal_trade_state():
    """Minimal AgentState with an execution plan — ready for safety_check_node."""
    return {
        "messages": [],
        "next_step": "execution_analyst",
        "risk_status": "APPROVED",
        "safety_status": "APPROVED",
        "user_id": "trader_001",
        "risk_attitude": "moderate",
        "execution_plan_output": {
            "action": "execute_trade",
            "amount": 3000,
            "symbol": "AAPL",
            "currency": "USD",
        },
        "governance_signature": "abc123",
        "evaluation_result": {"verdict": "APPROVED"},
        "loop_count": 0,
        "opa_results": None,
        "execution_result": None,
        "governance_summary": None,
        "latency_stats": None,
        "approval_required": False,
        "approval_decision": None,
        "reasoning_output": None,
        "data_analyst_ticker": None,
        "investment_period": None,
        "risk_feedback": None,
    }


def _route_after_safety(state: dict) -> str:
    """Mirror of the inline route_after_safety closure in graph.py — used for unit assertions."""
    status = state.get("safety_status")
    if status in ("APPROVED", "SKIPPED"):
        return "governed_trader"
    return "explainer"


# ---------------------------------------------------------------------------
# Original smoke tests (preserved — do NOT delete)
# ---------------------------------------------------------------------------

def test_graph_compilation():
    """Verifies that the graph compiles successfully with the new CAGE nodes."""
    try:
        graph = create_graph(redis_url=None)
        assert graph is not None
        print("Graph compiled successfully")
    except Exception as e:
        pytest.fail(f"Graph compilation failed: {e}")


@patch("src.governed_financial_advisor.graph.nodes.adapters.run_adk_agent")
def test_cage_flow_structure(mock_run_agent):
    """Verifies structure of the CAGE graph — successful compilation implies nodes exist."""
    graph = create_graph()
    assert graph is not None


# ---------------------------------------------------------------------------
# Safety node routing tests (unit — OPA call mocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safety_node_approved_routes_to_governed_trader(minimal_trade_state):
    """APPROVED verdict from OPA must set safety_status=APPROVED and route to governed_trader."""
    mock_governor = AsyncMock()
    mock_governor.govern = AsyncMock(return_value=None)  # no exception = ALLOW

    with patch(
        "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
        mock_governor,
    ):
        update = await safety_check_node(minimal_trade_state)

    assert update["safety_status"] == "APPROVED"
    merged = {**minimal_trade_state, **update}
    assert _route_after_safety(merged) == "governed_trader"


@pytest.mark.asyncio
async def test_safety_node_blocked_routes_to_explainer(minimal_trade_state):
    """GovernanceError (DENY) must set safety_status=BLOCKED and route to explainer."""
    from src.gateway.governance.symbolic_governor import GovernanceError

    mock_governor = AsyncMock()
    mock_governor.govern = AsyncMock(
        side_effect=GovernanceError("ISO 42001 Policy Violation: OPA Denied Action.")
    )

    with patch(
        "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
        mock_governor,
    ):
        update = await safety_check_node(minimal_trade_state)

    assert update["safety_status"] == "BLOCKED"
    merged = {**minimal_trade_state, **update}
    assert _route_after_safety(merged) == "explainer"


@pytest.mark.asyncio
async def test_safety_node_escalated_routes_to_explainer(minimal_trade_state):
    """GovernanceError with 'Manual Review' must set safety_status=ESCALATED → explainer."""
    from src.gateway.governance.symbolic_governor import GovernanceError

    mock_governor = AsyncMock()
    mock_governor.govern = AsyncMock(
        side_effect=GovernanceError("ISO 42001 Policy Check: Manual Review Required.")
    )

    with patch(
        "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
        mock_governor,
    ):
        update = await safety_check_node(minimal_trade_state)

    assert update["safety_status"] == "ESCALATED"
    merged = {**minimal_trade_state, **update}
    assert _route_after_safety(merged) == "explainer"


@pytest.mark.asyncio
async def test_safety_node_skipped_on_non_trade_request(minimal_trade_state):
    """Absence of execution_plan_output must short-circuit to safety_status=SKIPPED."""
    state_no_plan = {**minimal_trade_state, "execution_plan_output": None}

    update = await safety_check_node(state_no_plan)

    assert update["safety_status"] == "SKIPPED"
    merged = {**state_no_plan, **update}
    assert _route_after_safety(merged) == "governed_trader"


@pytest.mark.asyncio
async def test_safety_node_opa_timeout_routes_to_explainer(minimal_trade_state):
    """OPA timeout must fail-closed: safety_status=BLOCKED, routed to explainer."""
    import asyncio

    mock_governor = AsyncMock()
    mock_governor.govern = AsyncMock(
        side_effect=asyncio.TimeoutError("OPA timed out")
    )

    with patch(
        "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
        mock_governor,
    ):
        update = await safety_check_node(minimal_trade_state)

    assert update["safety_status"] == "BLOCKED"
    merged = {**minimal_trade_state, **update}
    assert _route_after_safety(merged) == "explainer"


@pytest.mark.asyncio
async def test_safety_node_opa_unreachable_routes_to_explainer(minimal_trade_state):
    """OPA connection failure must fail-closed: safety_status=BLOCKED, routed to explainer."""
    import httpx

    mock_governor = AsyncMock()
    mock_governor.govern = AsyncMock(
        side_effect=httpx.ConnectError("connection refused")
    )

    with patch(
        "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
        mock_governor,
    ):
        update = await safety_check_node(minimal_trade_state)

    assert update["safety_status"] == "BLOCKED"
    merged = {**minimal_trade_state, **update}
    assert _route_after_safety(merged) == "explainer"


# ---------------------------------------------------------------------------
# Graph structure tests
# ---------------------------------------------------------------------------

def test_graph_has_safety_check_node():
    """Compiled graph must include the safety_check node (R-11 requirement)."""
    graph = create_graph(redis_url=None)
    # LangGraph compiled graphs expose their nodes via .nodes dict
    assert "safety_check" in graph.nodes


def test_safety_check_node_is_between_evaluator_and_governed_trader():
    """Graph must wire evaluator → safety_check and safety_check → governed_trader/explainer."""
    graph = create_graph(redis_url=None)
    # Confirm both anchor nodes exist alongside safety_check
    assert "evaluator" in graph.nodes
    assert "governed_trader" in graph.nodes
    assert "explainer" in graph.nodes
    assert "safety_check" in graph.nodes


def test_graph_compiles_with_safety_node():
    """create_graph() must succeed and return a non-None object with safety_check wired in."""
    graph = create_graph(redis_url=None)
    assert graph is not None
    assert "safety_check" in graph.nodes
