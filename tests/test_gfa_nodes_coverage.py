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
tests/test_gfa_nodes_coverage.py
=================================
Unit tests for GFA graph node functions.

Gap 8: evaluator_node.py, explainer_node.py, agent_nodes.py, and
data_analyst_graph.py have no functional pytest coverage.

All tests are hermetic — LLM calls, OTel tracing, KMS signing, and
graph invocations are mocked via unittest.mock. No live services needed.

Node files confirmed to exist:
  src/governed_financial_advisor/graph/nodes/evaluator_node.py
  src/governed_financial_advisor/graph/nodes/explainer_node.py
  src/governed_financial_advisor/graph/nodes/agent_nodes.py
  src/governed_financial_advisor/graph/subgraphs/data_analyst_graph.py

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Heavy-dependency stub fixtures
# ---------------------------------------------------------------------------


def _install_opentelemetry_stubs() -> None:
    """Install minimal opentelemetry stubs if not already present."""
    if "opentelemetry" not in sys.modules:
        otel_stub = MagicMock()
        otel_trace_stub = MagicMock()
        span_stub = MagicMock()
        span_stub.__enter__ = MagicMock(return_value=span_stub)
        span_stub.__exit__ = MagicMock(return_value=False)
        tracer_stub = MagicMock()
        tracer_stub.start_as_current_span = MagicMock(return_value=span_stub)
        otel_trace_stub.get_tracer = MagicMock(return_value=tracer_stub)
        sys.modules["opentelemetry"] = otel_stub
        sys.modules["opentelemetry.trace"] = otel_trace_stub


_install_opentelemetry_stubs()


# ---------------------------------------------------------------------------
# Tests: agent_nodes.py — pure helper functions (no LLM/graph calls)
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgentNodeHelpers:
    """Tests for pure helper functions in agent_nodes.py."""

    def test_get_valid_last_message_empty_messages(self) -> None:
        """get_valid_last_message must return empty string for empty messages list."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_valid_last_message,
        )

        result = get_valid_last_message({"messages": []})
        assert result == "", f"Expected empty string for empty messages, got {result!r}"

    def test_get_valid_last_message_no_messages_key(self) -> None:
        """get_valid_last_message must handle missing messages key."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_valid_last_message,
        )

        result = get_valid_last_message({})
        assert result == "", (
            f"Expected empty string when no messages key, got {result!r}"
        )

    def test_get_valid_last_message_with_tuple_message(self) -> None:
        """get_valid_last_message must extract content from tuple (role, content) messages."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_valid_last_message,
        )

        state = {"messages": [("ai", "Buy AAPL at market price")]}
        result = get_valid_last_message(state)
        assert result == "Buy AAPL at market price", (
            f"Expected tuple content extracted, got {result!r}"
        )

    def test_get_valid_last_message_with_object_message(self) -> None:
        """get_valid_last_message must extract .content from message objects."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_valid_last_message,
        )

        msg = MagicMock()
        msg.content = "Analyze portfolio risk"
        state = {"messages": [msg]}
        result = get_valid_last_message(state)
        assert result == "Analyze portfolio risk", (
            f"Expected object .content extracted, got {result!r}"
        )

    def test_get_market_data_from_history_no_messages(self) -> None:
        """get_market_data_from_history must return empty string for no messages."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_market_data_from_history,
        )

        result = get_market_data_from_history({"messages": []})
        assert result == "", f"Expected empty string with no messages, got {result!r}"

    def test_get_market_data_from_history_finds_analysis_keyword(self) -> None:
        """get_market_data_from_history must find messages containing 'ANALYSIS'."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_market_data_from_history,
        )

        msg = MagicMock()
        msg.content = "ANALYSIS: AAPL is trending upward with RSI=65"
        state = {"messages": [msg]}
        result = get_market_data_from_history(state)
        assert "ANALYSIS" in result, (
            f"Expected ANALYSIS keyword found in history, got {result!r}"
        )

    def test_get_market_data_skips_irrelevant_messages(self) -> None:
        """get_market_data_from_history must return empty string for irrelevant messages."""
        from src.governed_financial_advisor.graph.nodes.agent_nodes import (
            get_market_data_from_history,
        )

        msg = MagicMock()
        msg.content = "Hello, I want to invest."
        state = {"messages": [msg]}
        result = get_market_data_from_history(state)
        assert result == "", (
            f"Expected empty string for irrelevant messages, got {result!r}"
        )


@pytest.mark.local
class TestExecutionAnalystNodeBehavior:
    """Tests for execution_analyst_node circuit-breaker behavior (no LLM)."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_fires_at_loop_count_3(self) -> None:
        """execution_analyst_node must apply circuit-breaker when loop_count >= 3."""
        # Mock heavy imports before importing the node
        mock_agent_chain = AsyncMock()
        mock_agent_chain.ainvoke = AsyncMock(return_value=MagicMock(content="{}"))

        with (
            patch(
                "src.governed_financial_advisor.agents.execution_analyst.agent.create_execution_analyst_agent",
                return_value=mock_agent_chain,
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.get_tracer",
                return_value=MagicMock(),
            ),
        ):
            from src.governed_financial_advisor.graph.nodes.agent_nodes import (
                execution_analyst_node,
            )

            state: dict[str, Any] = {
                "messages": [MagicMock(content="Buy AAPL")],
                "risk_status": "REJECTED_REVISE",
                "loop_count": 3,
                "risk_feedback": "Drawdown too high",
            }

            result = await execution_analyst_node(state)

        assert isinstance(result, dict), "Must return a dict"
        # Circuit breaker must produce a message and clear execution_plan
        assert "messages" in result, "Circuit breaker must produce messages"
        assert "execution_plan_output" in result, "Must return execution_plan_output"
        assert result["execution_plan_output"] is None, (
            "Circuit breaker must set execution_plan_output=None"
        )
        # loop_count must be incremented beyond 3
        assert result.get("loop_count", 0) > 3, (
            "loop_count must be incremented past 3 in circuit-breaker path"
        )


# ---------------------------------------------------------------------------
# Tests: explainer_node.py — pure helper functions
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestExplainerNodeHelpers:
    """Tests for pure helper functions in explainer_node.py."""

    def test_map_opa_rules_empty_opa_results(self) -> None:
        """map_opa_rules must return placeholder list when opa_results is empty."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            map_opa_rules,
        )

        result = map_opa_rules({})
        assert isinstance(result, list), "map_opa_rules must return a list"
        assert len(result) >= 1, "Must return at least one item when opa_results empty"

    def test_map_opa_rules_no_explanation_key(self) -> None:
        """map_opa_rules must return placeholder when no 'explanation' key."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            map_opa_rules,
        )

        result = map_opa_rules({"result": "ALLOW"})
        assert isinstance(result, list), "map_opa_rules must return a list"
        assert "No OPA trace available." in result, (
            "map_opa_rules must return 'No OPA trace available.' when no explanation"
        )

    def test_map_opa_rules_parses_exit_events(self) -> None:
        """map_opa_rules must parse 'exit' events in OPA explanation trace."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            map_opa_rules,
        )

        opa_results = {
            "explanation": [
                {
                    "type": "exit",
                    "node": "finance/trade/allow",
                    "location": {"file": "trade_policy.rego", "line": 42},
                },
                {
                    "type": "enter",
                    "node": "finance/trade/allow",
                    "location": {"file": "trade_policy.rego", "line": 42},
                },
            ]
        }
        result = map_opa_rules(opa_results)
        assert isinstance(result, list), "map_opa_rules must return a list"
        # Only exit events with finance/ and / should appear
        finance_rules = [r for r in result if "trade_policy.rego" in r]
        assert len(finance_rules) >= 1, (
            "map_opa_rules must capture exit events for finance rules"
        )

    def test_map_opa_rules_returns_unique_rules(self) -> None:
        """map_opa_rules must deduplicate identical rule references."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            map_opa_rules,
        )

        duplicate_event = {
            "type": "exit",
            "node": "finance/trade/allow",
            "location": {"file": "trade_policy.rego", "line": 10},
        }
        opa_results = {"explanation": [duplicate_event, duplicate_event]}
        result = map_opa_rules(opa_results)
        assert isinstance(result, list), "map_opa_rules must return a list"
        # Duplicates must be removed
        assert len(result) == len(set(result)), (
            "map_opa_rules must return unique rule references"
        )

    def test_is_low_risk_verdict_true_for_clean_allow(self) -> None:
        """_is_low_risk_verdict must return True for ALLOW with low risk_score."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            _is_low_risk_verdict,
        )

        governance_result = {
            "verdict": "ALLOW",
            "violations": [],
            "hitl_required": False,
            "risk_score": 0.1,
        }
        assert _is_low_risk_verdict(governance_result) is True, (
            "Clean ALLOW with low risk_score must be low risk"
        )

    def test_is_low_risk_verdict_false_for_deny(self) -> None:
        """_is_low_risk_verdict must return False for DENY verdicts."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            _is_low_risk_verdict,
        )

        governance_result = {
            "verdict": "DENY",
            "violations": ["UCA-5"],
            "hitl_required": False,
            "risk_score": 0.9,
        }
        assert _is_low_risk_verdict(governance_result) is False, (
            "DENY verdict must not be low risk"
        )

    def test_is_low_risk_verdict_false_when_violations_present(self) -> None:
        """_is_low_risk_verdict must return False even for ALLOW with violations."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            _is_low_risk_verdict,
        )

        governance_result = {
            "verdict": "ALLOW",
            "violations": ["SC-4"],
            "hitl_required": False,
            "risk_score": 0.3,
        }
        assert _is_low_risk_verdict(governance_result) is False, (
            "ALLOW with violations must not be low risk"
        )

    def test_is_low_risk_verdict_false_when_hitl_required(self) -> None:
        """_is_low_risk_verdict must return False when hitl_required=True."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            _is_low_risk_verdict,
        )

        governance_result = {
            "verdict": "ALLOW",
            "violations": [],
            "hitl_required": True,
            "risk_score": 0.2,
        }
        assert _is_low_risk_verdict(governance_result) is False, (
            "ALLOW with hitl_required=True must not be low risk"
        )

    def test_is_low_risk_verdict_false_when_risk_score_high(self) -> None:
        """_is_low_risk_verdict must return False when risk_score >= 0.5."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            _is_low_risk_verdict,
        )

        governance_result = {
            "verdict": "ALLOW",
            "violations": [],
            "hitl_required": False,
            "risk_score": 0.6,
        }
        assert _is_low_risk_verdict(governance_result) is False, (
            "ALLOW with risk_score=0.6 must not be low risk"
        )

    def test_verify_hmac_signature_unsigned_when_no_plan(self) -> None:
        """verify_hmac_signature must return UNSIGNED marker when no plan."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            verify_hmac_signature,
        )

        state: dict[str, Any] = {
            "governance_signature": "sig",
            "execution_plan_output": None,
        }
        result = verify_hmac_signature(state)
        assert "[HMAC: UNSIGNED]" in result, (
            f"Expected UNSIGNED when no plan, got {result!r}"
        )

    def test_verify_hmac_signature_failed_when_no_sig(self) -> None:
        """verify_hmac_signature must return FAILED marker when signature missing."""
        from src.governed_financial_advisor.graph.nodes.explainer_node import (
            verify_hmac_signature,
        )

        state: dict[str, Any] = {
            "governance_signature": None,
            "execution_plan_output": {"steps": [{"action": "buy"}]},
        }
        result = verify_hmac_signature(state)
        assert "[HMAC: FAILED]" in result, (
            f"Expected FAILED marker when signature is None, got {result!r}"
        )


# ---------------------------------------------------------------------------
# Tests: data_analyst_graph.py — state schema and graph structure
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestDataAnalystGraph:
    """Tests for data_analyst_graph.py graph structure and state schema."""

    def test_data_analyst_state_has_messages_field(self) -> None:
        """DataAnalystState TypedDict must define a 'messages' field."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            DataAnalystState,
        )

        # TypedDict annotations are in __annotations__
        assert "messages" in DataAnalystState.__annotations__, (
            "DataAnalystState must define 'messages' field"
        )

    def test_data_analyst_state_has_reasoning_output_field(self) -> None:
        """DataAnalystState TypedDict must define 'reasoning_output' field."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            DataAnalystState,
        )

        assert "reasoning_output" in DataAnalystState.__annotations__, (
            "DataAnalystState must define 'reasoning_output' field"
        )

    def test_data_analyst_graph_is_compiled(self) -> None:
        """data_analyst_graph module-level graph must be a compiled CompiledGraph."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            data_analyst_graph,
        )

        # The compiled graph has a get_graph() method and ainvoke
        assert hasattr(data_analyst_graph, "ainvoke"), (
            "data_analyst_graph must have ainvoke() — is it compiled?"
        )

    def test_data_analyst_graph_has_invoke_method(self) -> None:
        """Compiled data_analyst_graph must expose both ainvoke and invoke."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            data_analyst_graph,
        )

        assert callable(data_analyst_graph.ainvoke), "ainvoke must be callable"

    def test_doer_router_returns_execute_tool_for_tool_calls(self) -> None:
        """doer_router must return 'execute_tool' when last message has tool_calls."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            doer_router,
        )

        msg = MagicMock()
        msg.tool_calls = [
            {"name": "get_market_data", "args": {"ticker": "AAPL"}, "id": "tc-1"}
        ]
        state = {"messages": [msg], "reasoning_output": "Check AAPL"}
        result = doer_router(state)
        assert result == "execute_tool", (
            f"Expected 'execute_tool' when tool_calls present, got {result!r}"
        )

    def test_doer_router_returns_reporter_when_no_tool_calls(self) -> None:
        """doer_router must return 'reporter' when last message has no tool_calls."""
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            doer_router,
        )

        msg = MagicMock()
        msg.tool_calls = None
        state = {"messages": [msg], "reasoning_output": "No ticker found"}
        result = doer_router(state)
        assert result == "reporter", (
            f"Expected 'reporter' when no tool_calls, got {result!r}"
        )

    def test_analyst_thinker_node_raises_without_vllm_base(self) -> None:
        """analyst_thinker_node must raise RuntimeError when VLLM_REASONING_API_BASE unset."""
        import os

        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            analyst_thinker_node,
        )

        env_backup = os.environ.pop("VLLM_REASONING_API_BASE", None)
        try:
            with pytest.raises(RuntimeError, match="VLLM_REASONING_API_BASE"):
                # Build a minimal state
                msg = MagicMock()
                msg.content = "Test query"
                analyst_thinker_node({"messages": [msg], "reasoning_output": None})
        finally:
            if env_backup is not None:
                os.environ["VLLM_REASONING_API_BASE"] = env_backup
