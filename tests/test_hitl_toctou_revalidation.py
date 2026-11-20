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
# Closure regression guard for: POAM-2026-045, POAM-2026-240

"""
tests/test_hitl_toctou_revalidation.py — HITL TOCTOU Ghost-State Remediation
==============================================================================

Verifies the post-HITL TOCTOU slippage enforcement pipeline in the
governed_financial_advisor graph (POAM-2026-045, POAM-2026-240):

  - data_analyst_node         : extracts validated ticker + check-time quote (never prose)
  - execution_analyst_node    : captures hitl_reference_quote at check time
  - governed_trader_node      : serializes ExecutionPlan dicts via json.dumps (never repr)
  - post_hitl_rehydrate_node  : resolves nested PlanStep.parameters + hitl_reference_quote
  - post_hitl_revalidate_node : fails closed on exceeded OR unverifiable drift (never false PASSED)
  - drift_blocked_node        : fail-closed terminal node clearing HITL tokens
  - route_post_revalidation   : routes to executor ONLY on explicit PASSED

All tests are pure unit tests — no live Redis, no MCP, no network required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _revalidate(state: dict[str, Any]) -> dict[str, Any]:
    """Run post_hitl_revalidate_node with every outbound HTTP call forbidden."""
    from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
        post_hitl_revalidate_node,
    )

    forbidden = AsyncMock(
        side_effect=AssertionError("post-HITL node made a network call")
    )
    with patch.object(httpx.AsyncClient, "send", forbidden):
        return await post_hitl_revalidate_node(state)


def _capture_spans() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _make_plan_json(
    symbol: str = "AAPL",
    amount: float = 15000.0,
    price: float = 150.0,
    quantity: float = 100.0,
    confidence: float = 0.99,
) -> str:
    """Return a legacy flat execution_plan JSON string."""
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


def _make_canonical_execution_plan_dict(
    symbol: str = "NVDA",
    amount: float = 15000.0,
    *,
    reference_price: float | None = None,
) -> dict[str, Any]:
    """Return a canonical ExecutionPlan.model_dump()-shaped dict with nested PlanStep.parameters."""
    params: dict[str, Any] = {
        "symbol": symbol,
        "amount": amount,
        "currency": "USD",
    }
    if reference_price is not None:
        params["reference_price"] = reference_price
    return {
        "plan_id": "plan-001",
        "strategy_name": f"Conservative Entry — {symbol}",
        "rationale": "The user profile supports a bounded equity allocation with strict slippage controls.",
        "risk_factors": ["market volatility"],
        "steps": [
            {
                "id": "s1",
                "action": "check_market_status",
                "description": f"Confirm {symbol} market is open",
                "parameters": {"symbol": symbol},
            },
            {
                "id": "s2",
                "action": "execute_trade",
                "description": f"Buy ${amount:.0f} of {symbol}",
                "parameters": params,
            },
        ],
        "user_risk_attitude": "Conservative",
        "user_investment_period": "Medium",
    }


def _base_state(
    ticker: str | None = "AAPL",
    plan: str | None = None,
    approval_decision: dict[str, Any] | None = None,
    rehydration_result: dict[str, Any] | None = None,
    post_hitl_safety_status: str | None = None,
    hitl_reference_quote: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal GovernedTraderState for testing."""
    return {
        "messages": [],
        "execution_plan": plan if plan is not None else _make_plan_json(),
        "evaluation_result": '{"verdict": "APPROVED", "risk_score": 0.3}',
        "deferred_id": "defer-1",
        "approval_decision": (
            approval_decision
            if approval_decision is not None
            else {
                "approved": True,
                "reviewer": "test@example.com",
                "rationale": "Test approval.",
                "max_slippage_pct": 2.0,
            }
        ),
        "data_analyst_ticker": ticker,
        "hitl_reference_quote": hitl_reference_quote,
        "rehydration_result": rehydration_result,
        "post_hitl_safety_status": post_hitl_safety_status,
    }


# ---------------------------------------------------------------------------
# 1. post_hitl_rehydrate_node — fetches fresh price & aligns ExecutionPlan schema
# ---------------------------------------------------------------------------


class TestPostHitlRehydrateNode:
    """Unit tests for the state re-hydration node (POAM-2026-240)."""

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
        mock_yf.assert_called_once_with("MSFT")

    @pytest.mark.asyncio
    async def test_rehydrate_supports_canonical_nested_parameters_and_hitl_reference_quote_poam_2026_240(
        self,
    ):
        """POAM-2026-240: Canonical ExecutionPlan nests symbol under PlanStep.parameters and relies on hitl_reference_quote."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 144.20}

        plan_json = json.dumps(_make_canonical_execution_plan_dict(symbol="NVDA"))
        state = _base_state(
            ticker=None,
            plan=plan_json,
            hitl_reference_quote={
                "ticker": "NVDA",
                "price": 140.0,
                "source": "get_market_data",
                "captured_at_utc": "2026-11-20T00:00:00+00:00",
            },
        )

        with patch("yfinance.Ticker", return_value=mock_ticker) as mock_yf:
            result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "OK"
        assert rh["ticker"] == "NVDA"
        assert rh["stale_price"] == pytest.approx(140.0)
        assert rh["fresh_price"] == pytest.approx(144.20)
        assert rh["drift_pct"] == pytest.approx(3.0, rel=1e-3)
        mock_yf.assert_called_once_with("NVDA")

    @pytest.mark.asyncio
    async def test_rehydrate_ignores_poisoned_prose_and_unknown_ticker_poam_2026_240(
        self,
    ):
        """POAM-2026-240: Multi-sentence reasoning prose or 'UNKNOWN' in data_analyst_ticker never reaches yfinance."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 202.0}

        plan_json = json.dumps(
            _make_canonical_execution_plan_dict(symbol="NVDA", reference_price=200.0)
        )
        for bad_ticker in (
            "UNKNOWN",
            "The user wants data for NVDA due to AI datacenter growth.",
        ):
            state = _base_state(ticker=bad_ticker, plan=plan_json)
            with patch("yfinance.Ticker", return_value=mock_ticker) as mock_yf:
                result = await post_hitl_rehydrate_node(state)
            rh = result["rehydration_result"]
            assert rh["status"] == "OK"
            assert rh["ticker"] == "NVDA"
            assert rh["drift_pct"] == pytest.approx(1.0, rel=1e-3)
            mock_yf.assert_called_once_with("NVDA")

    @pytest.mark.asyncio
    async def test_rehydrate_missing_reference_price_marks_skipped_poam_2026_240(self):
        """POAM-2026-240: Missing check-time reference price marks status=SKIPPED (never status=OK with drift_pct=None)."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            post_hitl_rehydrate_node,
        )

        plan_json = json.dumps(_make_canonical_execution_plan_dict(symbol="NVDA"))
        state = _base_state(ticker="NVDA", plan=plan_json, hitl_reference_quote=None)

        with patch("yfinance.Ticker") as mock_yf:
            result = await post_hitl_rehydrate_node(state)

        rh = result["rehydration_result"]
        assert rh["status"] == "SKIPPED"
        assert rh["reason"] == "missing_reference_price"
        assert rh["ticker"] == "NVDA"
        assert rh["drift_pct"] is None
        mock_yf.assert_not_called()

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
# 2. post_hitl_revalidate_node — fail-closed reviewer slippage gate
# ---------------------------------------------------------------------------


class TestPostHitlRevalidateNode:
    """The advisor applies the reviewer's slippage tolerance fail-closed (POAM-2026-240)."""

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
        provider, exporter = _capture_spans()
        state = _base_state(
            rehydration_result={"status": "OK", "ticker": "AAPL", "drift_pct": 4.0},
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )
        with patch(
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_tracer",
            side_effect=lambda: provider.get_tracer("test"),
        ):
            result = await _revalidate(state)

        assert result["post_hitl_safety_status"] == "BLOCKED"
        assert "4.00%" in result["rehydration_result"]["block_reason"]
        spans = exporter.get_finished_spans()
        assert spans[-1].attributes["toctou.revalidation.result"] == "BLOCKED"
        assert (
            spans[-1].attributes["toctou.revalidation.block_reason"]
            == "price_slippage_exceeded"
        )

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
    @pytest.mark.parametrize(
        "rehydration",
        [
            {"status": "SKIPPED", "reason": "no_ticker", "drift_pct": None},
            {
                "status": "SKIPPED",
                "reason": "missing_reference_price",
                "ticker": "NVDA",
                "drift_pct": None,
            },
            {
                "status": "SKIPPED",
                "reason": "yfinance_error: timeout",
                "ticker": "AAPL",
                "drift_pct": None,
            },
            {"status": "OK", "ticker": "AAPL", "drift_pct": None},
            {"status": "OK", "ticker": "AAPL", "drift_pct": float("nan")},
            {"status": "OK", "ticker": "AAPL", "drift_pct": float("inf")},
            {"status": "OK", "ticker": "AAPL", "drift_pct": -0.1},
            {"status": "OK", "ticker": "AAPL", "drift_pct": True},
            {
                "status": "OK",
                "ticker": "AAPL",
                "stale_price": None,
                "fresh_price": 150.0,
                "drift_pct": 0.0,
            },
        ],
        ids=[
            "skipped_no_ticker",
            "skipped_no_ref_price",
            "skipped_yfinance_error",
            "ok_none_drift",
            "ok_nan_drift",
            "ok_inf_drift",
            "ok_negative_drift",
            "ok_bool_drift",
            "ok_missing_stale_price",
        ],
    )
    async def test_unverifiable_drift_blocks_fail_closed_without_false_passed_poam_2026_240(
        self, rehydration
    ):
        """POAM-2026-240: post_hitl_revalidate_node is the sole max_slippage_pct gate and MUST block on unverifiable drift."""
        provider, exporter = _capture_spans()
        state = _base_state(
            rehydration_result=rehydration,
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": 2.0,
            },
        )
        with patch(
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_tracer",
            side_effect=lambda: provider.get_tracer("test"),
        ):
            result = await _revalidate(state)

        assert result["post_hitl_safety_status"] == "BLOCKED"
        assert (
            "Unable to verify post-HITL market drift"
            in (result["rehydration_result"]["block_reason"])
        )
        spans = exporter.get_finished_spans()
        assert spans[-1].attributes["toctou.revalidation.result"] == "BLOCKED"
        assert (
            spans[-1].attributes["toctou.revalidation.block_reason"]
            == "drift_unverifiable"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_slippage",
        [float("nan"), float("inf"), -0.5, 100.5, True, "not-a-float", None],
    )
    async def test_invalid_max_slippage_pct_blocks_fail_closed_poam_2026_240(
        self, bad_slippage
    ):
        """POAM-2026-240: Malformed or NaN max_slippage_pct blocks fail-closed instead of NaN comparison bypass."""
        provider, exporter = _capture_spans()
        state = _base_state(
            rehydration_result={"status": "OK", "ticker": "AAPL", "drift_pct": 0.1},
            approval_decision={
                "approved": True,
                "reviewer": "t@x.com",
                "rationale": "ok",
                "max_slippage_pct": bad_slippage,
            },
        )
        with patch(
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_tracer",
            side_effect=lambda: provider.get_tracer("test"),
        ):
            result = await _revalidate(state)

        assert result["post_hitl_safety_status"] == "BLOCKED"
        spans = exporter.get_finished_spans()
        assert spans[-1].attributes["toctou.revalidation.result"] == "BLOCKED"
        assert (
            spans[-1].attributes["toctou.revalidation.block_reason"]
            == "invalid_slippage_tolerance"
        )

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

    def test_message_contains_drift_details_and_clears_hitl_tokens(self):
        """Message surfaces ticker, drift_pct, and slippage tolerance and clears HITL state."""
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
            hitl_reference_quote={"ticker": "AAPL", "price": 150.0},
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
        assert result["deferred_id"] is None
        assert result["approval_decision"] is None
        assert result["hitl_reference_quote"] is None

    def test_message_falls_back_to_block_reason_when_no_drift_pct_or_bad_slippage(self):
        """When drift_pct is None or max_slippage_pct is malformed, surfaces block_reason without raising."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            drift_blocked_node,
        )

        state = _base_state(
            rehydration_result={
                "status": "SKIPPED",
                "drift_pct": None,
                "block_reason": "Unable to verify post-HITL market drift for NVDA.",
            },
            approval_decision={
                "approved": True,
                "reviewer": "dave@x.com",
                "rationale": "ok",
                "max_slippage_pct": "malformed",
            },
        )

        result = drift_blocked_node(state)
        content = result["messages"][0][1]
        assert "Unable to verify post-HITL market drift" in content
        assert result["post_hitl_safety_status"] == "BLOCKED"


# ---------------------------------------------------------------------------
# 4. Parent-graph producer & serialization contracts (POAM-2026-240)
# ---------------------------------------------------------------------------


class TestAdvisorProducerAndSerializationContractsPoam2026240:
    """POAM-2026-240: Verify data_analyst_node, execution_analyst_node, and governed_trader_node wiring."""

    @pytest.mark.asyncio
    async def test_data_analyst_node_extracts_real_ticker_and_quote_not_reasoning_prose(
        self,
    ):
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            data_analyst_node,
        )

        fake_messages = [
            HumanMessage(content="Analyze NVDA for a medium-term trade"),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "get_market_data",
                        "args": {"symbol": "NVDA"},
                        "id": "call-nvda-1",
                    }
                ],
            ),
            ToolMessage(
                tool_call_id="call-nvda-1",
                name="get_market_data",
                content=(
                    "# Market Data Report for NVDA\n"
                    "## Recent Price History (Last 1 Month)\n"
                    "\n**Latest Close:** 142.75\n"
                ),
            ),
            AIMessage(
                content="Data Analysis: NVDA closed at $142.75 with strong momentum."
            ),
        ]
        fake_subgraph_out = {
            "messages": fake_messages,
            "reasoning_output": (
                "The user wants market data for NVIDIA Corporation (NVDA) "
                "to evaluate semiconductor exposure over a medium horizon."
            ),
        }

        with patch(
            "src.governed_financial_advisor.graph.subgraphs.data_analyst_graph.data_analyst_graph.ainvoke",
            new=AsyncMock(return_value=fake_subgraph_out),
        ):
            out = await data_analyst_node({"messages": [fake_messages[0]]})

        assert out["data_analyst_ticker"] == "NVDA"
        assert out["hitl_reference_quote"]["ticker"] == "NVDA"
        assert out["hitl_reference_quote"]["price"] == pytest.approx(142.75)
        assert out["hitl_reference_quote"]["source"] == "get_market_data"

    @pytest.mark.asyncio
    async def test_data_analyst_node_returns_none_instead_of_unknown_when_no_ticker_found(
        self,
    ):
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            data_analyst_node,
        )

        fake_subgraph_out = {
            "messages": [HumanMessage(content="Hello")],
            "reasoning_output": "No stock ticker was mentioned by the user.",
        }
        with patch(
            "src.governed_financial_advisor.graph.subgraphs.data_analyst_graph.data_analyst_graph.ainvoke",
            new=AsyncMock(return_value=fake_subgraph_out),
        ):
            out = await data_analyst_node({"messages": [HumanMessage(content="Hello")]})

        assert out["data_analyst_ticker"] is None
        assert "hitl_reference_quote" not in out

    @pytest.mark.asyncio
    async def test_execution_analyst_node_captures_check_time_quote_when_analyst_skipped(
        self,
    ):
        from src.governed_financial_advisor.graph.nodes import agent_nodes

        plan_dict = _make_canonical_execution_plan_dict(symbol="MSFT", amount=20000.0)
        fake_chain = MagicMock()
        fake_chain.ainvoke = AsyncMock(
            return_value=AIMessage(content=json.dumps(plan_dict))
        )
        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 410.25}

        state = {
            "messages": [HumanMessage(content="Buy $20,000 of MSFT")],
            "risk_attitude": "Conservative",
            "investment_period": "Medium",
            "loop_count": 0,
        }
        with (
            patch.object(
                agent_nodes, "create_execution_analyst_agent", return_value=fake_chain
            ),
            patch("yfinance.Ticker", return_value=mock_ticker) as mock_yf,
        ):
            updates = await agent_nodes.execution_analyst_node(state)

        assert updates["data_analyst_ticker"] == "MSFT"
        assert updates["hitl_reference_quote"]["ticker"] == "MSFT"
        assert updates["hitl_reference_quote"]["price"] == pytest.approx(410.25)
        assert updates["hitl_reference_quote"]["source"] == "yfinance_check_time"
        mock_yf.assert_called_once_with("MSFT")

    @pytest.mark.asyncio
    async def test_governed_trader_node_serializes_dict_plan_as_json_and_blocks_excess_drift_end_to_end(
        self,
    ):
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            governed_trader_node,
        )
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            build_governed_trader_graph,
        )

        subgraph = build_governed_trader_graph()
        plan_dict = _make_canonical_execution_plan_dict(symbol="NVDA", amount=15000.0)
        parent_state = {
            "messages": [HumanMessage(content="Buy $15,000 of NVDA")],
            "execution_plan_output": plan_dict,  # Python dict (previously broken by str(dict))
            "evaluation_result": {"verdict": "APPROVED"},
            "data_analyst_ticker": "Reasoning essay that should be ignored because it is not a ticker.",
            "hitl_reference_quote": {
                "ticker": "NVDA",
                "price": 100.0,
                "source": "get_market_data",
            },
            "deferred_id": "defer-e2e-1",
            "approval_decision": {
                "approved": True,
                "reviewer": "approver@example.com",
                "rationale": "Approved within 1.0% slippage.",
                "max_slippage_pct": 1.0,
            },
        }

        mock_ticker = MagicMock()
        mock_ticker.fast_info = {"last_price": 103.5}  # +3.5% > 1.0% max_slippage_pct

        with (
            patch("yfinance.Ticker", return_value=mock_ticker) as mock_yf,
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_mcp_client"
            ) as mock_mcp,
        ):
            out = await governed_trader_node(parent_state, subgraph=subgraph)

        mock_yf.assert_called_once_with("NVDA")
        mock_mcp.assert_not_called()
        assert out["deferred_id"] is None
        assert out["approval_decision"] is None
        assert out["hitl_reference_quote"] is None
        last_msg = out["messages"][-1]
        text = last_msg[1] if isinstance(last_msg, tuple) else last_msg.content
        assert "NVDA" in text
        assert "3.50%" in text


# ---------------------------------------------------------------------------
# 5. Graph topology — new nodes present
# ---------------------------------------------------------------------------


class TestGraphTopology:
    """Structural tests: verify the compiled graph contains the TOCTOU nodes."""

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
# 6. route_post_revalidation — fail-closed routing edge
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

    @pytest.mark.parametrize("bad_status", [None, "", "SKIPPED", "UNKNOWN"])
    def test_non_passed_status_routes_fail_closed_to_drift_blocked_poam_2026_240(
        self, bad_status
    ):
        """POAM-2026-240: Any status other than explicit 'PASSED' routes fail-closed to drift_blocked."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_post_revalidation,
        )

        state = _base_state(post_hitl_safety_status=bad_status)
        assert route_post_revalidation(state) == "drift_blocked"

    def test_entry_with_preapproved_deferred_id_routes_to_rehydrate(self):
        """Parent-graph HITL resumption enters with deferred_id + approved=True and must run post_hitl_rehydrate."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_entry,
        )

        state = _base_state()
        assert route_entry(state) == "post_hitl_rehydrate"

    def test_entry_without_approval_routes_to_executor(self):
        """Normal entry (no deferred_id or unapproved) routes directly to executor."""
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_entry,
        )

        state = {**_base_state(), "deferred_id": None}
        assert route_entry(state) == "executor"
        unapproved = {**_base_state(), "approval_decision": {"approved": False}}
        assert route_entry(unapproved) == "executor"


# ---------------------------------------------------------------------------
# 7. approval_node — max_slippage_pct + expires_at
# ---------------------------------------------------------------------------


class TestApprovalNodeSlippageAndTTL:
    """Verify the approval_node changes (slippage + TTL stamp) are correct."""

    def _call_node_with_decision(self, decision: dict[str, Any]):
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
            }
        )
        assert cmd.update["approval_decision"]["max_slippage_pct"] == pytest.approx(2.0)

    def test_approved_routes_to_post_hitl_rehydrate(self):
        """CRITICAL: approved path must route to post_hitl_rehydrate, not executor."""
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

        captured_payload: dict[str, Any] = {}

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
        delta = (expires_at - now).total_seconds()
        assert 0 < delta <= 305, f"expires_at delta={delta}s not in expected TTL range"


# ---------------------------------------------------------------------------
# 8. ApprovalDecision — max_slippage_pct schema & bounds
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

    @pytest.mark.parametrize(
        "bad_slippage",
        [-0.1, 100.1, float("nan"), float("inf"), True, False, None, "abc"],
    )
    def test_invalid_slippage_rejected_poam_2026_240(self, bad_slippage):
        Model = self._load()
        with pytest.raises(ValidationError):
            Model(
                approved=True,
                reviewer="t@x.com",
                rationale="ok",
                max_slippage_pct=bad_slippage,
            )

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


class TestAllReachableHitlTradePathsPopulateReferenceQuote:
    """Verify every trade path reaching HITL populates a matching fresh reference quote."""

    @pytest.mark.asyncio
    async def test_multistep_safety_check_binds_quote_to_deferred_second_step(self):
        """Step 1 ALLOW (MSFT) + Step 2 REQUIRE_APPROVAL (NVDA) binds NVDA quote, not MSFT."""
        from langchain_core.messages import AIMessage

        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            governed_trader_node,
        )
        from src.governed_financial_advisor.graph.nodes.safety_node import (
            safety_check_node,
        )
        from src.governed_financial_advisor.graph.nodes.toctou_quote import (
            resolve_check_time_plan_quotes,
        )
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            build_governed_trader_graph,
        )

        plan = {
            "plan_id": "p-multi",
            "strategy_name": "Rebalance",
            "rationale": "Trim MSFT and initiate NVDA position within mandate.",
            "steps": [
                {
                    "id": "s1",
                    "action": "execute_trade",
                    "description": "Sell MSFT",
                    "parameters": {"symbol": "MSFT", "amount": 1000, "currency": "USD"},
                },
                {
                    "id": "s2",
                    "action": "execute_trade",
                    "description": "Buy NVDA",
                    "parameters": {
                        "symbol": "NVDA",
                        "amount": 75000,
                        "currency": "USD",
                    },
                },
            ],
        }

        async def _fake_quotes(sym: str, **_kwargs):
            return 410.0 if sym == "MSFT" else 140.0

        with patch(
            "src.governed_financial_advisor.graph.nodes.toctou_quote.fetch_live_yfinance_price",
            AsyncMock(side_effect=_fake_quotes),
        ):
            primary_ticker, plan_quotes = await resolve_check_time_plan_quotes({}, plan)

        assert primary_ticker == "MSFT"
        assert plan_quotes is not None
        assert plan_quotes["quotes_by_ticker"] == {"MSFT": 410.0, "NVDA": 140.0}

        initial_state = {
            "messages": [],
            "consecutive_denials": 0,
            "execution_plan_output": plan,
            "data_analyst_ticker": primary_ticker,
            "hitl_reference_quote": plan_quotes,
        }

        async def _fake_validate(action: str, params: dict):
            if params["symbol"] == "MSFT":
                return {
                    "verdict": "ALLOW",
                    "violations": [],
                    "signature": {"value": "sig-msft"},
                }
            return {
                "verdict": "REQUIRE_APPROVAL",
                "deferred_id": "def-nvda-2",
                "violations": [],
                "signature": {"value": "sig-nvda"},
            }

        with patch(
            "src.governed_financial_advisor.graph.nodes.safety_node.GatewayClient"
        ) as mock_gw_cls:
            mock_gw_cls.return_value.validate_action = AsyncMock(
                side_effect=_fake_validate
            )
            safety_out = await safety_check_node(initial_state)  # type: ignore[arg-type]

        assert safety_out["deferred_id"] == "def-nvda-2"
        assert safety_out["data_analyst_ticker"] == "NVDA"
        assert safety_out["hitl_reference_quote"]["ticker"] == "NVDA"
        assert safety_out["hitl_reference_quote"]["price"] == pytest.approx(140.0)

        # Resume after parent approval_node approves NVDA with live price 141.0 (0.71% <= 2.0%)
        resumed_parent_state = {
            **initial_state,
            **safety_out,
            "evaluation_result": {"verdict": "APPROVED"},
            "approval_decision": {
                "approved": True,
                "reviewer": "pm@firm.com",
                "rationale": "Approved rebalance.",
                "max_slippage_pct": 2.0,
            },
        }
        with (
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.fetch_live_yfinance_price",
                AsyncMock(return_value=141.0),
            ),
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.executor_node",
                AsyncMock(
                    return_value={"messages": [AIMessage(content="Executed NVDA.")]}
                ),
            ),
        ):
            subgraph_exec = build_governed_trader_graph()
            trader_out = await governed_trader_node(
                resumed_parent_state, subgraph=subgraph_exec
            )
        assert any("Executed NVDA." in str(m) for m in trader_out["messages"])

    @pytest.mark.asyncio
    async def test_subgraph_executor_overwrites_prior_turn_ticker_quote(self):
        """Turn 1 AAPL quote in state must be overwritten when Turn 2 executor emits NVDA."""
        from langchain_core.messages import AIMessage

        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            executor_node,
            post_hitl_rehydrate_node,
            post_hitl_revalidate_node,
        )

        fake_ai_call = AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call-nvda-1",
                    "name": "execute_trade_action",
                    "args": {"symbol": "NVDA", "amount": 75000, "currency": "USD"},
                }
            ],
        )
        fake_llm = MagicMock()
        fake_llm.bind_tools.return_value.ainvoke = AsyncMock(return_value=fake_ai_call)
        fake_mcp = MagicMock()
        fake_mcp.ensure_connected = AsyncMock()
        fake_tool = MagicMock()
        fake_tool.name = "execute_trade_action"
        fake_mcp.get_tools = AsyncMock(return_value=[fake_tool])

        prior_turn_state = {
            "messages": [],
            "execution_plan": "Buy $75,000 of NVDA at market.",
            "evaluation_result": "APPROVED",
            "data_analyst_ticker": "AAPL",
            "hitl_reference_quote": {
                "ticker": "AAPL",
                "price": 180.0,
                "source": "get_market_data",
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            "deferred_id": None,
            "approval_decision": None,
        }

        with (
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.chat_model",
                return_value=fake_llm,
            ),
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_mcp_client",
                return_value=fake_mcp,
            ),
            patch(
                "src.governed_financial_advisor.graph.nodes.toctou_quote.fetch_live_yfinance_price",
                AsyncMock(return_value=140.0),
            ),
        ):
            exec_out = await executor_node(prior_turn_state)  # type: ignore[arg-type]

        assert exec_out["data_analyst_ticker"] == "NVDA"
        assert exec_out["hitl_reference_quote"]["ticker"] == "NVDA"
        assert exec_out["hitl_reference_quote"]["price"] == pytest.approx(140.0)

        # Now resume post-HITL for NVDA at 141.0 (0.71% <= 2.0%) -> PASSED (not SKIPPED/BLOCKED)
        post_approval_state = {
            **prior_turn_state,
            **exec_out,
            "deferred_id": "def-sub-nvda",
            "approval_decision": {
                "approved": True,
                "reviewer": "pm@firm.com",
                "rationale": "Approved NVDA.",
                "max_slippage_pct": 2.0,
            },
        }
        with patch(
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.fetch_live_yfinance_price",
            AsyncMock(return_value=141.0),
        ):
            rehyd = await post_hitl_rehydrate_node(post_approval_state)  # type: ignore[arg-type]
        reval = await post_hitl_revalidate_node({**post_approval_state, **rehyd})  # type: ignore[arg-type]
        assert rehyd["rehydration_result"]["status"] == "OK"
        assert reval["post_hitl_safety_status"] == "PASSED"

    @pytest.mark.asyncio
    async def test_expired_prior_turn_quote_same_ticker_refreshed_at_check_time(self):
        """An hours-old Turn-1 AAPL quote is refreshed at Turn-2 check time, preventing false blocks."""
        from datetime import timedelta

        from src.governed_financial_advisor.graph.nodes.toctou_quote import (
            resolve_check_time_reference_quote,
        )

        three_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        state = {
            "hitl_reference_quote": {
                "ticker": "AAPL",
                "price": 180.0,
                "source": "get_market_data",
                "captured_at_utc": three_hours_ago,
            },
            "execution_plan_output": {
                "steps": [
                    {
                        "action": "execute_trade",
                        "description": "Buy AAPL",
                        "parameters": {"symbol": "AAPL", "amount": 75000},
                    }
                ]
            },
        }
        with patch(
            "src.governed_financial_advisor.graph.nodes.toctou_quote.fetch_live_yfinance_price",
            AsyncMock(return_value=200.0),
        ) as mock_live:
            refreshed = await resolve_check_time_reference_quote(state, ticker="AAPL")

        mock_live.assert_awaited_once_with("AAPL")
        assert refreshed is not None
        assert refreshed["ticker"] == "AAPL"
        assert refreshed["price"] == pytest.approx(200.0)
        assert refreshed["source"] == "yfinance_check_time"


pytestmark = [pytest.mark.unit, pytest.mark.local]
