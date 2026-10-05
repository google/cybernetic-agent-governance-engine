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
tests/test_hitl_toctou_revalidation.py — HITL TOCTOU Ghost-State Remediation
==============================================================================

Verifies the three new nodes that close the TOCTOU vulnerability in the
governed_trader subgraph:

  - post_hitl_rehydrate_node  : fetches fresh market data after HITL approval
  - post_hitl_revalidate_node : tests approved intent against live reality
  - drift_blocked_node        : fail-closed terminal node on market drift

Acceptance criteria (per implementation plan):
  1. Re-hydration populates rehydration_result with fresh price + drift_pct.
  2. Missing ticker degrades gracefully (status=SKIPPED, no exception).
  3. yfinance failure degrades gracefully (status=SKIPPED, no exception).
  4. Within slippage → PASSED + routing to "executor"; the node makes no
     gateway call (governance re-validation runs in the gateway when
     execute_trade_action consumes the deferred_id).
  5. Slippage exceeded → BLOCKED + routing to "drift_blocked".
  7. drift_blocked_node writes a human-readable message explaining the block.
  9. max_slippage_pct from resume payload propagates into approval_decision.
 10. /resume endpoint returns HTTP 410 when approval TTL has expired.

All tests are pure unit tests — no live Redis, no MCP, no network required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _revalidate(state: dict) -> dict:
    """Run post_hitl_revalidate_node with every outbound HTTP call forbidden."""
    from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
        post_hitl_revalidate_node,
    )

    forbidden = AsyncMock(
        side_effect=AssertionError("post-HITL node made a network call")
    )
    with patch.object(httpx.AsyncClient, "send", forbidden):
        return await post_hitl_revalidate_node(state)


def _make_plan_json(
    symbol: str = "AAPL",
    amount: float = 15000.0,
    price: float = 150.0,
    quantity: float = 100.0,
    confidence: float = 0.99,
) -> str:
    """Return a minimal execution_plan JSON string."""
    return json.dumps(
        {
            "strategy_name": "Test Buy",
            "steps": [
                {
                    "action": "execute_trade",
                    "symbol": symbol,
                    "amount": amount,
                    "price": price,
                    "quantity": quantity,
                    "confidence": confidence,
                    "currency": "USD",
                    "trader_role": "junior",
                }
            ],
        }
    )


def _base_state(
    ticker: str | None = "AAPL",
    plan: str | None = None,
    approval_decision: dict | None = None,
    rehydration_result: dict | None = None,
    post_hitl_safety_status: str | None = None,
) -> dict:
    """Build a minimal GovernedTraderState for testing."""
    return {
        "messages": [],
        "execution_plan": plan or _make_plan_json(),
        "evaluation_result": '{"verdict": "APPROVED", "risk_score": 0.3}',
        "deferred_id": "defer-1",
        "approval_decision": approval_decision
        or {
            "approved": True,
            "reviewer": "test@example.com",
            "rationale": "Test approval.",
            "max_slippage_pct": 2.0,
        },
        "data_analyst_ticker": ticker,
        "rehydration_result": rehydration_result,
        "post_hitl_safety_status": post_hitl_safety_status,
    }


# ---------------------------------------------------------------------------
# 1. post_hitl_rehydrate_node — fetches fresh price
# ---------------------------------------------------------------------------


class TestPostHitlRehydrateNode:
    """Unit tests for the state re-hydration node."""

    @pytest.mark.asyncio
    async def test_rehydrate_fetches_fresh_price(self):
        """Mocked yfinance returns a live quote; rehydration_result populated correctly."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 145.50}

        state = _base_state(ticker="AAPL", plan=_make_plan_json(price=150.0))

        with patch("yfinance.Ticker", return_value=mock_ticker):
            result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "OK"
        assert rh["ticker"] == "AAPL"
        assert rh["fresh_price"] == pytest.approx(145.50)
        assert rh["stale_price"] == pytest.approx(150.0)
        # drift_pct = |145.50 - 150.0| / 150.0 * 100 ≈ 3.0%
        assert rh["drift_pct"] == pytest.approx(3.0, rel=1e-3)
        assert "timestamp_utc" in rh

    @pytest.mark.asyncio
    async def test_rehydrate_extracts_ticker_from_plan_when_state_missing(self):
        """Falls back to parsing execution_plan JSON when data_analyst_ticker is None."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 200.0}

        state = _base_state(
            ticker=None, plan=_make_plan_json(symbol="MSFT", price=195.0)
        )

        with patch("yfinance.Ticker", return_value=mock_ticker) as mock_yf:
            result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "OK"
        assert rh["ticker"] == "MSFT"
        # yfinance was called with MSFT
        mock_yf.assert_called_once_with("MSFT")

    @pytest.mark.asyncio
    async def test_rehydrate_missing_ticker_degrades_gracefully(self):
        """No ticker anywhere → status=SKIPPED, no exception raised."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        state = _base_state(ticker=None, plan=json.dumps({"steps": []}))

        result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "SKIPPED"
        assert rh["reason"] == "no_ticker"
        assert rh["fresh_price"] is None
        assert rh["drift_pct"] is None

    @pytest.mark.asyncio
    async def test_rehydrate_yfinance_failure_degrades_gracefully(self):
        """yfinance raises an exception → status=SKIPPED, no exception propagated."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        state = _base_state(ticker="AAPL")

        with patch("yfinance.Ticker", side_effect=RuntimeError("network error")):
            result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "SKIPPED"
        assert "yfinance_error" in rh["reason"]
        assert rh["drift_pct"] is None


# ---------------------------------------------------------------------------
# 2. post_hitl_revalidate_node — reviewer slippage gate (no gateway call)
# ---------------------------------------------------------------------------


class TestPostHitlRevalidateNode:
    """The advisor applies only the reviewer's slippage tolerance after approval."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "drift", [0.0, 0.67, 2.0], ids=["zero", "within", "at_limit"]
    )
    async def test_within_slippage_passes_without_network(self, drift):
        state = _base_state(
            rehydration_result={"status": "OK", "ticker": "AAPL", "drift_pct": drift},
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )
        result = await _revalidate(state)
        assert result == {"post_hitl_safety_status": "PASSED"}

    @pytest.mark.asyncio
    async def test_slippage_exceeded_blocks_trade(self):
        state = _base_state(
            rehydration_result={"status": "OK", "ticker": "AAPL", "drift_pct": 4.0},
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )
        result = await _revalidate(state)
        assert result["post_hitl_safety_status"] == "BLOCKED"
        assert "4.00%" in result["rehydration_result"]["block_reason"]

    @pytest.mark.asyncio
    async def test_tighter_reviewer_tolerance_blocks(self):
        state = _base_state(
            rehydration_result={"status": "OK", "ticker": "AAPL", "drift_pct": 0.67},
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 0.5,
            },
        )
        result = await _revalidate(state)
        assert result["post_hitl_safety_status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_skipped_rehydration_passes_to_gateway_revalidation(self):
        """Unknown drift cannot be gated here; the gateway re-validates on execution."""
        state = _base_state(
            rehydration_result={
                "status": "SKIPPED",
                "reason": "no_ticker",
                "drift_pct": None,
            },
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )
        result = await _revalidate(state)
        assert result == {"post_hitl_safety_status": "PASSED"}

    def test_node_has_no_gateway_dependency(self):
        """The advisor has no post-HITL governance endpoint to call (POAM-2026-079)."""
        import inspect

        from src.governed_financial_advisor.graph.subgraphs import (
            governed_trader_graph as mod,
        )

        source = inspect.getsource(mod.post_hitl_revalidate_node)
        assert "GatewayClient" not in source
        assert "revalidate_post_hitl" not in source


# ---------------------------------------------------------------------------
# 3. drift_blocked_node — fail-closed terminal
# ---------------------------------------------------------------------------


class TestDriftBlockedNode:
    """Unit tests for the fail-closed terminal node."""

    def test_message_contains_drift_details(self):
        """Message surfaces ticker, drift_pct, and slippage tolerance."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            drift_blocked_node,
        )

        state = _base_state(
            rehydration_result={
                "status": "OK",
                "ticker": "AAPL",
                "fresh_price": 156.0,
                "stale_price": 150.0,
                "drift_pct": 4.0,
                "block_reason": "Market price of AAPL drifted 4.00% ...",
            },
            approval_decision={
                "approved": True,
                "reviewer": "carol@example.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )

        result = drift_blocked_node(state)

        messages = result["messages"]
        content = (
            messages[0][1] if isinstance(messages[0], tuple) else messages[0].content
        )
        assert "AAPL" in content
        assert "4.00%" in content
        assert "carol@example.com" in content or "carol" in content
        assert result["post_hitl_safety_status"] == "BLOCKED"

    def test_message_falls_back_to_block_reason_when_no_drift_pct(self):
        """When drift_pct is None, surfaces block_reason text directly."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            drift_blocked_node,
        )

        state = _base_state(
            rehydration_result={
                "status": "SKIPPED",
                "drift_pct": None,
                "block_reason": "CBF Violation: cash barrier breached.",
            },
            approval_decision={
                "approved": True,
                "reviewer": "dave@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )

        result = drift_blocked_node(state)
        content = result["messages"][0][1]
        assert "CBF Violation" in content


# ---------------------------------------------------------------------------
# 4. Graph topology — new nodes present
# ---------------------------------------------------------------------------


class TestGraphTopology:
    """Structural tests: verify the compiled graph contains the new nodes."""

    @pytest.fixture
    def governed_trader_graph(self):
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            build_governed_trader_graph,
        )

        return build_governed_trader_graph()

    def test_graph_contains_rehydrate_node(self, governed_trader_graph):
        assert "post_hitl_rehydrate" in governed_trader_graph.nodes

    def test_graph_contains_revalidate_node(self, governed_trader_graph):
        assert "post_hitl_revalidate" in governed_trader_graph.nodes

    def test_graph_contains_drift_blocked_node(self, governed_trader_graph):
        assert "drift_blocked" in governed_trader_graph.nodes

    def test_graph_still_contains_executor_and_approval_nodes(
        self, governed_trader_graph
    ):
        """Regression: original nodes must still be present."""
        for node in ("approval", "rejection", "executor", "tools"):
            assert node in governed_trader_graph.nodes, (
                f"Node '{node}' missing from graph"
            )


# ---------------------------------------------------------------------------
# 5. route_post_revalidation — routing edge
# ---------------------------------------------------------------------------


class TestRoutePostRevalidation:
    def test_blocked_routes_to_drift_blocked(self):
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_post_revalidation,
        )

        state = _base_state(post_hitl_safety_status="BLOCKED")
        assert route_post_revalidation(state) == "drift_blocked"

    def test_passed_routes_to_executor(self):
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_post_revalidation,
        )

        state = _base_state(post_hitl_safety_status="PASSED")
        assert route_post_revalidation(state) == "executor"

    def test_none_status_routes_to_executor(self):
        """None (skipped validation path) defaults to executor — fail-open semantics
        when post_hitl_safety_status was never set."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_post_revalidation,
        )

        state = _base_state(post_hitl_safety_status=None)
        assert route_post_revalidation(state) == "executor"


# ---------------------------------------------------------------------------
# 6. approval_node — max_slippage_pct + expires_at
# ---------------------------------------------------------------------------


class TestApprovalNodeSlippageAndTTL:
    """Verify the approval_node changes (slippage + TTL stamp) are correct."""

    def _call_node_with_decision(self, decision: dict) -> Command:
        from src.governed_financial_advisor.graph.nodes.approval_node import (
            approval_node,
        )

        with patch(
            "src.governed_financial_advisor.graph.nodes.approval_node.interrupt",
            return_value=decision,
        ):
            state = {
                "execution_plan": _make_plan_json(),
                "evaluation_result": '{"verdict": "APPROVED"}',
            }
            return approval_node(state)

    def test_max_slippage_pct_propagates_into_approval_decision(self):
        cmd = self._call_node_with_decision(
            {
                "approved": True,
                "reviewer": "alice@x.com",
                "rationale": "All good.",
                "max_slippage_pct": 1.5,
            }
        )
        assert cmd.update["approval_decision"]["max_slippage_pct"] == pytest.approx(1.5)

    def test_default_slippage_when_not_provided(self):
        cmd = self._call_node_with_decision(
            {
                "approved": True,
                "reviewer": "bob@x.com",
                "rationale": "Fine.",
                # max_slippage_pct absent — should default to 2.0
            }
        )
        assert cmd.update["approval_decision"]["max_slippage_pct"] == pytest.approx(2.0)

    def test_approved_routes_to_post_hitl_rehydrate(self):
        """CRITICAL: approved path must now route to post_hitl_rehydrate, not executor."""
        cmd = self._call_node_with_decision(
            {
                "approved": True,
                "reviewer": "carol@x.com",
                "rationale": "Within mandate.",
            }
        )
        assert cmd.goto == "post_hitl_rehydrate", (
            f"Expected goto='post_hitl_rehydrate', got goto='{cmd.goto}'. "
            "The TOCTOU routing fix may not have been applied."
        )

    def test_rejected_still_routes_to_rejection(self):
        """Regression: rejection path must be unchanged."""
        cmd = self._call_node_with_decision(
            {
                "approved": False,
                "reviewer": "dave@x.com",
                "rationale": "Exceeds drawdown limit.",
            }
        )
        assert cmd.goto == "rejection"

    def test_interrupt_payload_contains_expires_at(self):
        """expires_at must be stamped on the interrupt payload for TTL enforcement."""
        from src.governed_financial_advisor.graph.nodes.approval_node import (
            approval_node,
        )

        captured_payload = {}

        def mock_interrupt(payload):
            captured_payload.update(payload)
            return {"approved": True, "reviewer": "eve@x.com", "rationale": "ok"}

        with patch(
            "src.governed_financial_advisor.graph.nodes.approval_node.interrupt",
            side_effect=mock_interrupt,
        ):
            state = {"execution_plan": _make_plan_json(), "evaluation_result": ""}
            approval_node(state)

        assert "expires_at" in captured_payload, (
            "interrupt payload must include 'expires_at' for TTL enforcement"
        )
        expires_at = datetime.fromisoformat(captured_payload["expires_at"])
        now = datetime.now(timezone.utc)
        # expires_at should be ~300s (5 min) in the future
        delta = (expires_at - now).total_seconds()
        assert 0 < delta <= 305, f"expires_at delta={delta}s not in expected TTL range"


# ---------------------------------------------------------------------------
# 7. ApprovalResumeRequest — max_slippage_pct schema
# ---------------------------------------------------------------------------


class TestApprovalResumeRequestSchema:
    def _load(self):
        from src.governed_financial_advisor.graph.nodes.approval_contract import (
            ApprovalDecision as ApprovalResumeRequest,
        )

        return ApprovalResumeRequest

    def test_default_slippage_is_2_percent(self):
        Model = self._load()
        req = Model(approved=True, reviewer="t@x.com", rationale="ok")
        assert req.max_slippage_pct == pytest.approx(2.0)

    def test_custom_slippage_accepted(self):
        Model = self._load()
        req = Model(
            approved=True, reviewer="t@x.com", rationale="ok", max_slippage_pct=0.5
        )
        assert req.max_slippage_pct == pytest.approx(0.5)

    def test_existing_fields_unchanged(self):
        """Regression: rationale, reviewer, comment must still work as before."""
        Model = self._load()
        req = Model(
            approved=False,
            reviewer="bob@x.com",
            rationale="Exceeds mandate.",
            comment="Escalated to PM.",
        )
        assert req.rationale == "Exceeds mandate."
        assert req.comment == "Escalated to PM."
        assert req.approved is False


pytestmark = [pytest.mark.unit, pytest.mark.local]
