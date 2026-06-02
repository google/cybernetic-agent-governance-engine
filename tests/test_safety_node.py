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
Dedicated unit + integration tests for safety_check_node (R-20).

Unit tests mock all network I/O; integration tests are skipped unless
OPA_URL is set in the environment.

Refactored (P0): safety_check_node now calls symbolic_governor.govern()
directly — no MCP client involved.  Tests mock
``src.governed_financial_advisor.graph.nodes.safety_node.symbolic_governor``
instead of ``get_mcp_client``.
"""

import asyncio
import os
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests

pytestmark = pytest.mark.unit

from src.governed_financial_advisor.graph.nodes.safety_node import (
    route_safety,
    safety_check_node,
)
from src.gateway.governance.symbolic_governor import GovernanceError


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_trade_state() -> Dict[str, Any]:
    """Minimal AgentState with a structured execution plan for OPA validation."""
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
            "trader_role": "junior",
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


@pytest.fixture
def no_plan_state(minimal_trade_state) -> Dict[str, Any]:
    """AgentState with no execution plan — triggers SKIPPED path."""
    return {**minimal_trade_state, "execution_plan_output": None}


# ---------------------------------------------------------------------------
# Unit tests — all network I/O is mocked
# ---------------------------------------------------------------------------

class TestSafetyNodeUnit:
    """Unit tests for safety_check_node with all external calls mocked.

    OPA invocation is now via symbolic_governor.govern() (direct, native).
    Tests mock the module-level `symbolic_governor` singleton rather than
    `get_mcp_client` — no MCP client is involved.
    """

    @pytest.mark.asyncio
    async def test_trade_action_triggers_opa_check(self, minimal_trade_state):
        """A state with execution_plan_output must call govern() exactly once."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(return_value=None)  # no exception = ALLOW

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            await safety_check_node(minimal_trade_state)

        mock_governor.govern.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_trade_action_skips_opa(self, no_plan_state):
        """Absence of execution_plan_output must skip OPA and return SKIPPED immediately."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            update = await safety_check_node(no_plan_state)

        assert update["safety_status"] == "SKIPPED"
        mock_governor.govern.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_high_risk_score_triggers_escalation(self, minimal_trade_state):
        """GovernanceError with 'Manual Review' must produce safety_status=ESCALATED."""
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
        assert "error" in update

    @pytest.mark.asyncio
    async def test_approved_verdict_returns_approved_status(self, minimal_trade_state):
        """govern() returning None (no exception) must yield safety_status=APPROVED."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            update = await safety_check_node(minimal_trade_state)

        assert update["safety_status"] == "APPROVED"
        assert "error" not in update

    @pytest.mark.asyncio
    async def test_blocked_verdict_returns_blocked_status(self, minimal_trade_state):
        """GovernanceError without 'Manual Review' must yield safety_status=BLOCKED."""
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
        assert "error" in update

    @pytest.mark.asyncio
    async def test_opa_connection_error_returns_blocked_fail_closed(self, minimal_trade_state):
        """httpx.ConnectError during govern() must fail-closed with safety_status=BLOCKED."""
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

    @pytest.mark.asyncio
    async def test_opa_timeout_returns_blocked_fail_closed(self, minimal_trade_state):
        """asyncio.TimeoutError during govern() must fail-closed with safety_status=BLOCKED."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(
            side_effect=asyncio.TimeoutError("OPA timed out after 1s")
        )

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            update = await safety_check_node(minimal_trade_state)

        assert update["safety_status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_missing_governance_signature_returns_blocked(self, minimal_trade_state):
        """Unexpected exception from govern() must default to BLOCKED (fail-closed)."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(
            side_effect=RuntimeError("Unexpected governance error")
        )

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            update = await safety_check_node(minimal_trade_state)

        # Unexpected error → fail-closed → BLOCKED
        assert update["safety_status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_safety_status_field_always_set(self, minimal_trade_state):
        """safety_check_node must always include a safety_status key in its return dict."""
        mock_governor = AsyncMock()
        mock_governor.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_governor,
        ):
            update = await safety_check_node(minimal_trade_state)

        assert "safety_status" in update

    def test_route_safety_approved_goes_to_governed_trader(self):
        """route_safety must map APPROVED → governed_trader."""
        state = {"safety_status": "APPROVED"}
        assert route_safety(state) == "governed_trader"

    def test_route_safety_skipped_goes_to_governed_trader(self):
        """route_safety must map SKIPPED → governed_trader."""
        state = {"safety_status": "SKIPPED"}
        assert route_safety(state) == "governed_trader"

    def test_route_safety_blocked_goes_to_execution_analyst(self):
        """route_safety must map BLOCKED → execution_analyst (loop-back for replanning)."""
        state = {"safety_status": "BLOCKED"}
        assert route_safety(state) == "execution_analyst"

    def test_route_safety_escalated_goes_to_execution_analyst(self):
        """route_safety must map ESCALATED → execution_analyst (loop-back for replanning)."""
        state = {"safety_status": "ESCALATED"}
        assert route_safety(state) == "execution_analyst"


# ---------------------------------------------------------------------------
# Integration tests — require live OPA (skipped in CI without OPA_URL)
# ---------------------------------------------------------------------------

def _opa_reachable() -> bool:
    """Return True only when the OPA health endpoint is reachable."""
    opa_url = os.getenv("OPA_URL")
    if not opa_url:
        return False
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(opa_url)
        requests.get(f"{parsed.scheme}://{parsed.netloc}/health", timeout=2)
        return True
    except Exception:
        return False


@pytest.mark.integration
@pytest.mark.usefixtures("require_opa_reachable")
class TestSafetyNodeIntegration:
    """Integration tests that call a real OPA instance via symbolic_governor.govern()."""

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_junior_trade_above_5k_blocked_by_opa(self, minimal_trade_state):
        """Junior trader with $90k trade must be blocked by live OPA policy (R-12)."""
        state = {
            **minimal_trade_state,
            "execution_plan_output": {
                "action": "execute_trade",
                "amount": 90000,
                "symbol": "TSLA",
                "currency": "USD",
                "trader_role": "junior",
            },
        }
        with patch("src.gateway.governance.causal_gatekeeper.causal_safety_check", return_value=True):
            update = await safety_check_node(state)
        # $90k by junior trader must be BLOCKED or ESCALATED — never APPROVED
        assert update["safety_status"] in ("BLOCKED", "ESCALATED")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_senior_trade_below_500k_approved_by_opa(self, minimal_trade_state):
        """Senior trader with $200k trade must be approved (or escalated for human review
        when the SLM sidecar is unavailable and consensus splits).

        When the SLM sidecar is unreachable the SymbolicGovernor applies elevated
        confidence requirements, which can cause a split consensus vote
        (['APPROVE', 'ESCALATE']) that tips to ESCALATED instead of APPROVED.
        Both outcomes are correct governance behaviour: the trade is neither
        silently blocked nor silently executed — it is either approved or escalated
        for human review.  A BLOCKED outcome (outright denial) is the only failure
        mode this integration test guards against.
        """
        state = {
            **minimal_trade_state,
            "execution_plan_output": {
                "action": "execute_trade",
                "amount": 200000,
                "symbol": "MSFT",
                "currency": "USD",
                "trader_role": "senior",
            },
        }
        with patch("src.gateway.governance.causal_gatekeeper.causal_safety_check", return_value=True):
            update = await safety_check_node(state)
        # APPROVED: SLM available, OPA + consensus passed.
        # ESCALATED: SLM unavailable → elevated consensus → split vote → human review.
        # BLOCKED would indicate OPA denied the trade outright, which is wrong for a
        # valid senior trade under the $500k threshold.
        assert update["safety_status"] in ("APPROVED", "ESCALATED"), (
            f"Expected APPROVED or ESCALATED for a valid senior trade, "
            f"got {update['safety_status']!r}. "
            f"Full update: {update}"
        )
