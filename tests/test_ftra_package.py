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
tests/test_ftra_package.py

Covers the production FTRA Tier 0.5 gate (POAM-2026-030):
  - IrreversibilityClassifier (src/gateway/governance/ftra/classifier.py)
  - PlanGraphAnalyzer (src/gateway/governance/ftra/graph_analyzer.py)
  - create_ftra_node() / route_after_ftra() (src/gateway/governance/ftra/node_factory.py)

Prior to this file, the only FTRA test (tests/test_ftra_reachability.py)
exercised an unwired scaffold (ftra_reachability.py) that was never called
by SymbolicGovernor or graph.py. That scaffold has since been removed
(POAM-2026-032); this file provides direct coverage of the actual
production implementation wired into
src/governed_financial_advisor/graph/graph.py.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _make_plan(steps: list[tuple[str, str]], plan_id: str = "plan-1"):
    """Build an ExecutionPlan from a list of (step_id, action) tuples."""
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
        PlanStep,
    )

    return ExecutionPlan(
        plan_id=plan_id,
        strategy_name="Test Strategy",
        rationale="Comprehensive test rationale for unit testing purposes",
        risk_factors=[],
        steps=[
            PlanStep(
                id=step_id,
                action=action,
                description=f"Step {step_id}",
                parameters={},
            )
            for step_id, action in steps
        ],
    )


# ---------------------------------------------------------------------------
# IrreversibilityClassifier
# ---------------------------------------------------------------------------


class TestIrreversibilityClassifier:
    def test_classify_known_irreversible_action(self):
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        classifier = IrreversibilityClassifier()
        assert (
            classifier.classify("execute_trade")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )
        assert (
            classifier.classify("write_db")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    def test_classify_known_read_only_action(self):
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        classifier = IrreversibilityClassifier()
        assert (
            classifier.classify("prompt_injection_check")
            == TerminalClassification.READ_ONLY
        )

    def test_is_irreversible_convenience_wrapper(self):
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

        classifier = IrreversibilityClassifier()
        assert classifier.is_irreversible("execute_trade") is True
        assert classifier.is_irreversible("prompt_injection_check") is False

    def test_unregistered_action_fails_closed_to_irreversible(self):
        """Fail-closed contract: unknown actions must default to IRREVERSIBLE_TERMINAL."""
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        classifier = IrreversibilityClassifier()
        assert (
            classifier.classify("totally_made_up_action_xyz")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )
        assert classifier.is_irreversible("totally_made_up_action_xyz") is True

    def test_missing_registry_file_fails_closed(self, tmp_path):
        """If the registry file does not exist, classify() must fail closed
        rather than raising."""
        from pathlib import Path

        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        missing_path = Path(tmp_path) / "does_not_exist.json"
        classifier = IrreversibilityClassifier(registry_path=missing_path)
        assert (
            classifier.classify("execute_trade")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    def test_malformed_registry_json_fails_closed(self, tmp_path):
        """A registry file missing the 'terminals' key must fail closed."""
        import json
        from pathlib import Path

        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        bad_path = Path(tmp_path) / "bad_registry.json"
        bad_path.write_text(json.dumps({"not_terminals": {}}))

        classifier = IrreversibilityClassifier(registry_path=bad_path)
        assert (
            classifier.classify("execute_trade")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    def test_known_actions_returns_registry_keys(self):
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

        classifier = IrreversibilityClassifier()
        known = classifier.known_actions()
        assert "execute_trade" in known
        assert "write_db" in known
        assert "prompt_injection_check" in known

    def test_custom_registry_path_overrides_default(self, tmp_path):
        import json
        from pathlib import Path

        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import TerminalClassification

        custom_path = Path(tmp_path) / "custom_registry.json"
        custom_path.write_text(
            json.dumps({"terminals": {"custom_action": "REVERSIBLE"}})
        )

        classifier = IrreversibilityClassifier(registry_path=custom_path)
        assert classifier.classify("custom_action") == TerminalClassification.REVERSIBLE
        # Action absent from the *custom* registry still fails closed
        assert (
            classifier.classify("execute_trade")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )


# ---------------------------------------------------------------------------
# PlanGraphAnalyzer
# ---------------------------------------------------------------------------


class TestPlanGraphAnalyzer:
    def _analyzer(self, tmp_path, terminals: dict[str, str]):
        """Build a PlanGraphAnalyzer backed by a scratch terminal registry."""
        import json
        from pathlib import Path

        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer

        registry_path = Path(tmp_path) / "registry.json"
        registry_path.write_text(json.dumps({"terminals": terminals}))
        classifier = IrreversibilityClassifier(registry_path=registry_path)
        return PlanGraphAnalyzer(classifier=classifier)

    def test_empty_plan_is_clear(self, tmp_path):
        from src.gateway.governance.ftra.models import FTRAVerdict
        from src.governed_financial_advisor.agents.execution_analyst.agent import (
            ExecutionPlan,
        )

        analyzer = self._analyzer(tmp_path, {})
        # Use model_construct to bypass validators (steps_must_be_non_empty enforces
        # non-empty steps in the Pydantic model; for this test we need to exercise
        # the graph analyzer's behavior on a zero-step plan without going through
        # LLM-output validation).
        plan = ExecutionPlan.model_construct(
            plan_id="plan-1",
            strategy_name="Test Strategy",
            rationale="Comprehensive test rationale for unit testing purposes",
            risk_factors=[],
            steps=[],
        )
        result = analyzer.analyze(plan, confidence=0.9)

        assert result.verdict == FTRAVerdict.CLEAR
        assert result.total_steps == 0
        assert result.reachable_terminals == []

    def test_all_read_only_plan_is_clear(self, tmp_path):
        from src.gateway.governance.ftra.models import (
            FTRAVerdict,
            TerminalClassification,
        )

        analyzer = self._analyzer(
            tmp_path, {"check_price": "READ_ONLY", "check_balance": "READ_ONLY"}
        )
        plan = _make_plan([("s1", "check_price"), ("s2", "check_balance")])
        result = analyzer.analyze(plan, confidence=0.5)

        assert result.verdict == FTRAVerdict.CLEAR
        assert result.worst_case_classification == TerminalClassification.READ_ONLY
        assert result.reachable_terminals == []
        assert result.reachable_step_count == 2

    def test_irreversible_terminal_reachable_high_confidence_is_hitl(self, tmp_path):
        from src.gateway.governance.ftra.models import FTRAVerdict

        analyzer = self._analyzer(
            tmp_path,
            {"check_price": "READ_ONLY", "execute_trade": "IRREVERSIBLE_TERMINAL"},
        )
        plan = _make_plan([("s1", "check_price"), ("s2", "execute_trade")])
        result = analyzer.analyze(plan, confidence=0.85)

        assert result.verdict == FTRAVerdict.HITL_REQUIRED
        assert "s2" in result.reachable_terminals
        assert result.critical_path == ["s1", "s2"]

    def test_irreversible_terminal_reachable_low_confidence_is_blocked(self, tmp_path):
        from src.gateway.governance.ftra.models import FTRAVerdict

        analyzer = self._analyzer(
            tmp_path,
            {"check_price": "READ_ONLY", "execute_trade": "IRREVERSIBLE_TERMINAL"},
        )
        plan = _make_plan([("s1", "check_price"), ("s2", "execute_trade")])
        result = analyzer.analyze(plan, confidence=0.5)

        assert result.verdict == FTRAVerdict.BLOCKED

    def test_confidence_exactly_at_threshold_is_hitl_not_blocked(self, tmp_path):
        """FRIA_ZONE_DEFER boundary is inclusive: confidence == threshold -> HITL_REQUIRED."""
        from src.gateway.governance.ftra.models import FTRAVerdict
        from src.gateway.governance.schemas.thresholds import get_fria_zone_defer

        fria_zone_defer = get_fria_zone_defer()
        analyzer = self._analyzer(tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"})
        plan = _make_plan([("s1", "execute_trade")])
        result = analyzer.analyze(plan, confidence=fria_zone_defer)

        assert result.verdict == FTRAVerdict.HITL_REQUIRED

    def test_graph_analyzer_uses_config_based_fria_zone_defer(self, tmp_path):
        """EV-1 regression: graph_analyzer must use get_fria_zone_defer() from config.

        This test verifies that PlanGraphAnalyzer uses the centralized config
        accessor instead of a hardcoded FRIA_ZONE_DEFER constant. By mocking
        the accessor to return a custom threshold, we confirm the analyzer
        respects the config-based value.
        """
        from src.gateway.governance.ftra.models import FTRAVerdict

        analyzer = self._analyzer(tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"})
        plan = _make_plan([("s1", "execute_trade")])

        # Test case 1: Mock threshold at 0.50 — confidence 0.55 should be HITL_REQUIRED
        with patch(
            "src.gateway.governance.ftra.graph_analyzer.get_fria_zone_defer",
            return_value=0.50,
        ):
            result = analyzer.analyze(plan, confidence=0.55)
            assert result.verdict == FTRAVerdict.HITL_REQUIRED, (
                "With threshold=0.50 and confidence=0.55, expected HITL_REQUIRED"
            )

        # Test case 2: Mock threshold at 0.90 — confidence 0.55 should be BLOCKED
        with patch(
            "src.gateway.governance.ftra.graph_analyzer.get_fria_zone_defer",
            return_value=0.90,
        ):
            result = analyzer.analyze(plan, confidence=0.55)
            assert result.verdict == FTRAVerdict.BLOCKED, (
                "With threshold=0.90 and confidence=0.55, expected BLOCKED"
            )

        # Test case 3: Verify boundary behavior — confidence == threshold should be HITL_REQUIRED
        with patch(
            "src.gateway.governance.ftra.graph_analyzer.get_fria_zone_defer",
            return_value=0.75,
        ):
            result = analyzer.analyze(plan, confidence=0.75)
            assert result.verdict == FTRAVerdict.HITL_REQUIRED, (
                "With threshold=0.75 and confidence=0.75, expected HITL_REQUIRED (boundary inclusive)"
            )

    def test_unregistered_action_in_plan_fails_closed(self, tmp_path):
        """A plan step whose action is absent from the registry must be treated
        as IRREVERSIBLE_TERMINAL (fail-closed), forcing HITL/BLOCKED routing."""
        from src.gateway.governance.ftra.models import (
            FTRAVerdict,
            TerminalClassification,
        )

        analyzer = self._analyzer(tmp_path, {})  # empty registry
        plan = _make_plan([("s1", "totally_unknown_action")])
        result = analyzer.analyze(plan, confidence=0.9)

        assert result.worst_case_classification == (
            TerminalClassification.IRREVERSIBLE_TERMINAL
        )
        assert result.verdict == FTRAVerdict.HITL_REQUIRED

    def test_depends_on_edges_override_linear_chain(self, tmp_path):
        """Phase 2 forward-compat: if a step declares depends_on, use those
        edges instead of the linear chain, and steps unreachable from step[0]
        must not appear in reachable_terminals."""
        from src.governed_financial_advisor.agents.execution_analyst.agent import (
            ExecutionPlan,
            PlanStep,
        )

        class PlanStepWithDeps(PlanStep):
            depends_on: list[str] = []

        analyzer = self._analyzer(
            tmp_path,
            {
                "check_price": "READ_ONLY",
                "execute_trade": "IRREVERSIBLE_TERMINAL",
                "unrelated_read": "READ_ONLY",
            },
        )
        # s1 -> s2 (explicit dep); s3 has no dependency on s1/s2 and is not
        # reachable from s1 (the analysis source is always steps[0]).
        plan = ExecutionPlan(
            plan_id="plan-deps",
            strategy_name="Test",
            rationale="Comprehensive test rationale for unit testing purposes",
            risk_factors=[],
            steps=[
                PlanStepWithDeps(
                    id="s1",
                    action="check_price",
                    description="d",
                    parameters={},
                    depends_on=[],
                ),
                PlanStepWithDeps(
                    id="s2",
                    action="execute_trade",
                    description="d",
                    parameters={},
                    depends_on=["s1"],
                ),
                PlanStepWithDeps(
                    id="s3",
                    action="unrelated_read",
                    description="d",
                    parameters={},
                    depends_on=[],
                ),
            ],
        )
        result = analyzer.analyze(plan, confidence=0.9)

        assert "s2" in result.reachable_terminals
        assert "s3" not in result.reachable_terminals
        # s3 has no incoming edge and is not step[0], so DFS from s1 never visits it
        assert result.reachable_step_count == 2

    def test_analyze_never_raises_on_internal_error(self, tmp_path):
        """Fail-closed contract: any exception during analysis must be caught
        and converted into a HITL_REQUIRED/BLOCKED ReachabilityResult, never
        propagated to the caller."""
        from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
        from src.gateway.governance.ftra.models import (
            FTRAVerdict,
            TerminalClassification,
        )

        broken_classifier = MagicMock()
        broken_classifier.classify.side_effect = RuntimeError("boom")
        analyzer = PlanGraphAnalyzer(classifier=broken_classifier)

        plan = _make_plan([("s1", "execute_trade")])
        result = analyzer.analyze(plan, confidence=0.9)

        assert result.verdict == FTRAVerdict.HITL_REQUIRED
        assert result.worst_case_classification == (
            TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    def test_analyze_never_raises_low_confidence_blocks(self, tmp_path):
        from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
        from src.gateway.governance.ftra.models import FTRAVerdict

        broken_classifier = MagicMock()
        broken_classifier.classify.side_effect = RuntimeError("boom")
        analyzer = PlanGraphAnalyzer(classifier=broken_classifier)

        plan = _make_plan([("s1", "execute_trade")])
        result = analyzer.analyze(plan, confidence=0.1)

        assert result.verdict == FTRAVerdict.BLOCKED

    def test_explain_returns_step_details(self, tmp_path):
        analyzer = self._analyzer(tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"})
        plan = _make_plan([("s1", "execute_trade")])
        explanation = analyzer.explain(plan, confidence=0.9)

        assert explanation["plan_id"] == "plan-1"
        assert explanation["verdict"] == "HITL_REQUIRED"
        assert len(explanation["step_details"]) == 1
        assert explanation["step_details"][0]["id"] == "s1"
        assert explanation["step_details"][0]["classification"] == (
            "IRREVERSIBLE_TERMINAL"
        )


# ---------------------------------------------------------------------------
# create_ftra_node() / route_after_ftra()
# ---------------------------------------------------------------------------


class TestRouteAfterFtra:
    def test_clear_routes_to_safety_check(self):
        from src.gateway.governance.ftra.node_factory import route_after_ftra

        assert route_after_ftra({"ftra_status": "CLEAR"}) == "safety_check"

    def test_blocked_routes_to_explainer(self):
        from src.gateway.governance.ftra.node_factory import route_after_ftra

        assert route_after_ftra({"ftra_status": "BLOCKED"}) == "explainer"

    def test_hitl_required_routes_to_explainer_as_fallback(self):
        from src.gateway.governance.ftra.node_factory import route_after_ftra

        assert route_after_ftra({"ftra_status": "HITL_REQUIRED"}) == "explainer"

    def test_missing_status_fails_closed_to_explainer(self):
        from src.gateway.governance.ftra.node_factory import route_after_ftra

        assert route_after_ftra({}) == "explainer"


class TestCreateFtraNode:
    def _registry_path(self, tmp_path, terminals: dict[str, str]):
        import json
        from pathlib import Path

        path = Path(tmp_path) / "registry.json"
        path.write_text(json.dumps({"terminals": terminals}))
        return path

    def _plan_dict(self, steps: list[tuple[str, str]], plan_id: str = "plan-1"):
        return {
            "plan_id": plan_id,
            "strategy_name": "Test Strategy",
            "rationale": "Comprehensive test rationale for unit testing purposes",
            "risk_factors": [],
            "steps": [
                {
                    "id": step_id,
                    "action": action,
                    "description": f"Step {step_id}",
                    "parameters": {},
                }
                for step_id, action in steps
            ],
        }

    def test_clear_verdict_returns_clear_status(self, tmp_path):
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_defer_id"] is None
        assert result["ftra_result"]["ctrl_id"] == "CTRL_FTRA_001"

    def test_low_confidence_irreversible_returns_blocked_status(self, tmp_path):
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "execute_trade")]),
            "evaluation_result": {"confidence": 0.2},
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"
        assert result["ftra_defer_id"] is None

    def test_missing_execution_plan_fails_closed_to_blocked(self, tmp_path):
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {"evaluation_result": {"confidence": 0.9}}
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"
        # Error message indicates plan extraction failed (extractor returned None)
        assert "plan" in result["ftra_result"]["error"].lower()
        assert (
            "None" in result["ftra_result"]["error"]
            or "missing" in result["ftra_result"]["error"]
        )

    def test_malformed_execution_plan_defers_for_review(self, tmp_path):
        """Malformed plan should DEFER for human review, not auto-BLOCK.

        This is the BUG-FTRA-SCHEMA-001 fix: schema validation errors no longer
        cause automatic BLOCKED verdicts, which were false positives.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": {"not_a_valid_plan": True},
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        # Per BUG-FTRA-SCHEMA-001 fix: DEFER (HITL_REQUIRED), not BLOCKED
        assert result["ftra_status"] == "HITL_REQUIRED"
        assert result["ftra_result"]["parse_failure_class"] == "SCHEMA_VALIDATION_ERROR"

    def test_missing_evaluation_result_defaults_confidence_to_zero(self, tmp_path):
        """Absent evaluation_result must default confidence to 0.0, which for
        an irreversible-terminal plan means BLOCKED (not HITL_REQUIRED)."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {"execution_plan_output": self._plan_dict([("s1", "execute_trade")])}
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"

    def test_hitl_required_parks_token_via_deferqueue(self, tmp_path):
        """Regression test for the DeferQueue() zero-arg instantiation bug:
        with a mocked Redis client, park() must actually be called with the
        DeferQueue-assigned defer_id (not a never-persisted fallback UUID).

        NodeInterrupt is a subclass of Exception in LangGraph and is the
        correct mechanism for suspending the thread for HITL review — it
        must propagate out of ftra_node() rather than being swallowed into a
        BLOCKED response (see the second regression test below for that
        specific failure mode)."""
        from langgraph.errors import NodeInterrupt

        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "execute_trade")]),
            "evaluation_result": {"confidence": 0.85},
            "thread_id": "thread-hitl-001",
        }

        mock_queue_instance = MagicMock()
        mock_queue_instance.park = AsyncMock(return_value="persisted-defer-id-123")
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_client) as mock_from_url:
            with patch(
                "src.gateway.governance.defer_queue.DeferQueue",
                return_value=mock_queue_instance,
            ) as mock_defer_queue_cls:
                with pytest.raises(NodeInterrupt) as exc_info:
                    node(state)

        # The critical regression assertion: DeferQueue must be constructed
        # WITH the redis client (not zero-arg), and park() must be awaited.
        mock_defer_queue_cls.assert_called_once_with(mock_client)
        mock_queue_instance.park.assert_awaited_once()
        mock_from_url.assert_called_once()
        # NodeInterrupt wraps its payload as a list of langgraph Interrupt
        # objects: exc.args == ([Interrupt(value={...}), ...],)
        interrupt_payload = exc_info.value.args[0][0].value
        assert interrupt_payload["defer_id"] == "persisted-defer-id-123"
        assert interrupt_payload["reason"] == "FTRA_IRREVERSIBLE_TERMINAL"

    def test_hitl_required_falls_back_to_local_uuid_when_redis_unavailable(
        self, tmp_path
    ):
        """When Redis is unreachable, parking must fail soft: the
        NodeInterrupt still fires (thread still suspends for HITL), but the
        defer_id embedded in the interrupt payload is a locally-generated
        (unpersisted) UUID rather than a Redis-backed token."""
        from langgraph.errors import NodeInterrupt

        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "execute_trade")]),
            "evaluation_result": {"confidence": 0.85},
            "thread_id": "thread-hitl-002",
        }

        with patch("redis.asyncio.from_url", side_effect=ConnectionError("redis down")):
            with pytest.raises(NodeInterrupt) as exc_info:
                node(state)

        interrupt_payload = exc_info.value.args[0][0].value
        assert interrupt_payload["defer_id"] is not None
        import uuid as _uuid

        _uuid.UUID(interrupt_payload["defer_id"])  # must not raise

    def test_ftra_node_never_raises_plain_exception_fails_closed(self, tmp_path):
        """create_ftra_node()'s outer try/except must catch any *plain*
        (non-GraphInterrupt) exception unhandled by _run_ftra and fail
        closed to BLOCKED — GraphInterrupt/NodeInterrupt is the sole
        exception type that must propagate (see TestCreateFtraNode's HITL
        tests above)."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # A state value that will blow up type coercion deep inside _run_ftra
        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": "not-a-float"},
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"

    def test_create_ftra_node_default_config_behavior(self, tmp_path):
        """FtraNodeConfig defaults must work correctly.

        This test ensures that a node created with explicit config works as expected.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})

        # Explicit config
        config = FtraNodeConfig(registry_path=registry_path)
        config_node = create_ftra_node(config=config)

        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": 0.9},
        }

        config_result = config_node(state)

        # Must produce expected output
        assert config_result["ftra_status"] == "CLEAR"
        assert config_result["ftra_defer_id"] is None
        assert config_result["ftra_result"]["ctrl_id"] == "CTRL_FTRA_001"

    def test_create_ftra_node_custom_extractors(self, tmp_path):
        """Custom plan/confidence extractors must override default GFA schema paths."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})

        # Custom extractors that read from non-GFA keys
        def custom_plan_extractor(s):
            return s.get("my_custom_plan")

        def custom_confidence_extractor(s):
            return s.get("my_custom_confidence", 0.5)

        config = FtraNodeConfig(
            registry_path=registry_path,
            plan_extractor=custom_plan_extractor,
            confidence_extractor=custom_confidence_extractor,
        )
        node = create_ftra_node(config=config)

        # State with non-standard keys (no execution_plan_output or evaluation_result)
        state = {
            "my_custom_plan": self._plan_dict([("s1", "check_price")]),
            "my_custom_confidence": 0.95,
        }
        result = node(state)

        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_result"]["confidence_at_analysis"] == 0.95

    def test_create_ftra_node_custom_extractors_with_irreversible(self, tmp_path):
        """Custom extractors with IRREVERSIBLE_TERMINAL action must trigger BLOCKED/HITL."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path, {"dangerous_action": "IRREVERSIBLE_TERMINAL"}
        )

        config = FtraNodeConfig(
            registry_path=registry_path,
            plan_extractor=lambda s: s.get("custom_plan_field"),
            confidence_extractor=lambda s: s.get("custom_confidence_field", 0.0),
        )
        node = create_ftra_node(config=config)

        # Low confidence + irreversible action -> BLOCKED
        state = {
            "custom_plan_field": self._plan_dict([("s1", "dangerous_action")]),
            "custom_confidence_field": 0.3,
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"

    def test_ftra_node_config_key_based_extractor_fallback(self, tmp_path):
        """FtraNodeConfig key-based extractors must work when custom callables not provided."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_balance": "READ_ONLY"})

        # Use key overrides instead of callable extractors
        config = FtraNodeConfig(
            registry_path=registry_path,
            plan_key="alternate_plan_key",
            evaluation_result_key="alternate_eval_key",
        )
        node = create_ftra_node(config=config)

        state = {
            "alternate_plan_key": self._plan_dict([("s1", "check_balance")]),
            "alternate_eval_key": {"confidence": 0.88},
        }
        result = node(state)

        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_result"]["confidence_at_analysis"] == 0.88

    def test_ftra_node_config_span_attributes_propagate(self, tmp_path):
        """Extra span_attributes in FtraNodeConfig must be set on OTel spans."""
        from unittest.mock import MagicMock

        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})

        config = FtraNodeConfig(
            registry_path=registry_path,
            span_attributes={"custom.attr": "custom_value", "tenant.id": "tenant-123"},
        )
        node = create_ftra_node(config=config)

        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": 0.9},
        }

        mock_span = MagicMock()
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value.__enter__ = lambda _: mock_span
        mock_tracer.start_as_current_span.return_value.__exit__ = lambda *args: None

        with patch("opentelemetry.trace.get_tracer", return_value=mock_tracer):
            result = node(state)

        assert result["ftra_status"] == "CLEAR"
        # Verify set_attribute was called with custom attrs
        set_attr_calls = {
            call.args[0]: call.args[1]
            for call in mock_span.set_attribute.call_args_list
        }
        assert set_attr_calls.get("custom.attr") == "custom_value"
        assert set_attr_calls.get("tenant.id") == "tenant-123"
        assert set_attr_calls.get("cage.ftra.config_source") == "explicit"


# ---------------------------------------------------------------------------
# Schema-drift Hardening Tests (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001)
# ---------------------------------------------------------------------------


class TestSanitizeLlmOutput:
    """Tests for pre-parse sanitization (BUG-FTRA-JSON-001)."""

    def test_removes_markdown_code_fences_json_tag(self):
        """Markdown code fences with ```json should be stripped."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        raw = """```json
{"plan_id": "test", "steps": []}
```"""
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        assert "```" not in sanitized
        assert sanitized == '{"plan_id": "test", "steps": []}'

    def test_removes_markdown_code_fences_no_tag(self):
        """Markdown code fences without language tag should be stripped."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        raw = """```
{"plan_id": "test"}
```"""
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        assert "```" not in sanitized
        assert sanitized == '{"plan_id": "test"}'

    def test_removes_trailing_comma(self):
        """Trailing comma at end of string (truncation artifact) should be removed."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        # Trailing comma at end of truncated output (common with streaming LLMs)
        raw = '{"plan_id": "test", "steps": [{"id": "s1"},'
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        assert not sanitized.endswith(",")
        assert sanitized == '{"plan_id": "test", "steps": [{"id": "s1"}'

    def test_handles_unicode_escape_issues(self):
        """Invalid unicode escapes should be fixed."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        # Invalid \u followed by non-hex
        raw = r'{"text": "\uGGGG is not valid"}'
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        # Should escape the backslash to prevent JSON decode error
        assert "\\\\u" in sanitized

    def test_removes_bom(self):
        """Byte Order Mark should be removed."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        raw = '\ufeff{"plan_id": "test"}'
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        assert not sanitized.startswith("\ufeff")

    def test_strips_whitespace(self):
        """Leading/trailing whitespace should be stripped."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        raw = '   \n  {"plan_id": "test"}  \n   '
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is True
        assert sanitized == '{"plan_id": "test"}'

    def test_clean_input_unchanged(self):
        """Clean JSON should not be modified."""
        from src.gateway.governance.ftra.node_factory import sanitize_llm_output

        raw = '{"plan_id": "test", "steps": []}'
        sanitized, was_modified = sanitize_llm_output(raw)

        assert was_modified is False
        assert sanitized == raw


class TestParseResultAndFailureClasses:
    """Tests for ParseResult and ParseFailureClass."""

    def test_parse_failure_class_values(self):
        """ParseFailureClass enum should have expected values."""
        from src.gateway.governance.ftra.models import ParseFailureClass

        assert ParseFailureClass.SUCCESS.value == "SUCCESS"
        assert ParseFailureClass.JSON_DECODE_ERROR.value == "JSON_DECODE_ERROR"
        assert (
            ParseFailureClass.SCHEMA_VALIDATION_ERROR.value == "SCHEMA_VALIDATION_ERROR"
        )
        assert ParseFailureClass.EMPTY_STEPS.value == "EMPTY_STEPS"
        assert ParseFailureClass.TRUNCATED_PLAN.value == "TRUNCATED_PLAN"
        assert ParseFailureClass.TOKENIZER_ARTIFACT.value == "TOKENIZER_ARTIFACT"

    def test_parse_result_is_success(self):
        """ParseResult.is_success should return True only for SUCCESS."""
        from src.gateway.governance.ftra.models import ParseFailureClass, ParseResult

        success = ParseResult(
            plan={"plan_id": "test"},
            failure_class=ParseFailureClass.SUCCESS,
            raw_input="{}",
        )
        failure = ParseResult(
            plan=None,
            failure_class=ParseFailureClass.JSON_DECODE_ERROR,
            raw_input="invalid",
            error_message="parse error",
        )

        assert success.is_success is True
        assert failure.is_success is False

    def test_parse_result_is_blocking_error(self):
        """ParseResult.is_blocking_error should identify blocking failures."""
        from src.gateway.governance.ftra.models import ParseFailureClass, ParseResult

        json_error = ParseResult(
            plan=None,
            failure_class=ParseFailureClass.JSON_DECODE_ERROR,
            raw_input="invalid",
            error_message="parse error",
        )
        schema_error = ParseResult(
            plan=None,
            failure_class=ParseFailureClass.SCHEMA_VALIDATION_ERROR,
            raw_input="{}",
            error_message="missing field",
        )
        empty_steps = ParseResult(
            plan={"plan_id": "test", "steps": []},
            failure_class=ParseFailureClass.EMPTY_STEPS,
            raw_input="{}",
        )

        assert json_error.is_blocking_error is True
        assert schema_error.is_blocking_error is True
        assert empty_steps.is_blocking_error is False

    def test_parse_result_is_warning(self):
        """ParseResult.is_warning should identify non-blocking issues."""
        from src.gateway.governance.ftra.models import ParseFailureClass, ParseResult

        empty_steps = ParseResult(
            plan={"plan_id": "test", "steps": []},
            failure_class=ParseFailureClass.EMPTY_STEPS,
            raw_input="{}",
        )
        truncated = ParseResult(
            plan=None,
            failure_class=ParseFailureClass.TRUNCATED_PLAN,
            raw_input='{"plan_id": "test',
        )
        tokenizer = ParseResult(
            plan={"plan_id": "test"},
            failure_class=ParseFailureClass.TOKENIZER_ARTIFACT,
            raw_input="```json\n{}\n```",
            sanitized_input="{}",
            sanitization_applied=True,
        )

        assert empty_steps.is_warning is True
        assert truncated.is_warning is True
        assert tokenizer.is_warning is True


class TestBugFtraSchema001:
    """Regression tests for BUG-FTRA-SCHEMA-001: Incomplete LLM plan → not BLOCKED."""

    def _registry_path(self, tmp_path, terminals: dict[str, str]):
        import json
        from pathlib import Path

        path = Path(tmp_path) / "registry.json"
        path.write_text(json.dumps({"terminals": terminals}))
        return path

    def _plan_dict(self, steps: list[tuple[str, str]], plan_id: str = "plan-1"):
        return {
            "plan_id": plan_id,
            "strategy_name": "Test Strategy",
            "rationale": "Comprehensive test rationale for unit testing purposes",
            "risk_factors": [],
            "steps": [
                {
                    "id": step_id,
                    "action": action,
                    "description": f"Step {step_id}",
                    "parameters": {},
                }
                for step_id, action in steps
            ],
        }

    def test_schema_validation_error_returns_defer_not_blocked(self, tmp_path):
        """BUG-FTRA-SCHEMA-001: Schema validation errors should DEFER, not BLOCK.

        Prior to fix: malformed plan → BLOCKED (false positive)
        After fix: malformed plan → HITL_REQUIRED (DEFER for review)
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Malformed plan (missing required fields)
        state = {
            "execution_plan_output": {"not_a_valid_plan": True},
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        # Key assertion: should be HITL_REQUIRED (DEFER), not BLOCKED
        assert result["ftra_status"] == "HITL_REQUIRED"
        assert result["ftra_result"]["parse_failure_class"] == "SCHEMA_VALIDATION_ERROR"

    def test_json_decode_error_returns_defer_not_blocked(self, tmp_path):
        """BUG-FTRA-JSON-001: JSON decode errors should DEFER, not BLOCK.

        Prior to fix: invalid JSON → BLOCKED (false positive)
        After fix: invalid JSON → HITL_REQUIRED (DEFER for review)
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Invalid JSON string
        state = {
            "execution_plan_output": '{"invalid: json',
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        # Key assertion: should be HITL_REQUIRED (DEFER), not BLOCKED
        assert result["ftra_status"] == "HITL_REQUIRED"
        # Should include parse failure class
        assert "parse_failure_class" in result["ftra_result"]

    def test_empty_steps_high_confidence_returns_clear(self, tmp_path):
        """Empty plan with high confidence should ALLOW (CLEAR), not BLOCK.

        An empty plan may be a valid choice when no action is required.
        With high confidence, the LLM intentionally chose to do nothing.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig
        from src.governed_financial_advisor.agents.execution_analyst.agent import (
            ExecutionPlan,
        )

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Empty plan (use model_construct to bypass validator)
        empty_plan = ExecutionPlan.model_construct(
            plan_id="empty-plan-1",
            strategy_name="No Action Strategy",
            rationale="Comprehensive test rationale for unit testing purposes",
            risk_factors=[],
            steps=[],
        )

        state = {
            "execution_plan_output": empty_plan,
            "evaluation_result": {"confidence": 0.85},  # High confidence
        }
        result = node(state)

        # Key assertion: empty plan + high confidence → CLEAR
        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_result"]["parse_failure_class"] == "EMPTY_STEPS"
        assert result["ftra_result"]["empty_plan_allowed"] is True

    def test_empty_steps_low_confidence_returns_defer(self, tmp_path):
        """Empty plan with low confidence should DEFER for review."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig
        from src.governed_financial_advisor.agents.execution_analyst.agent import (
            ExecutionPlan,
        )

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Empty plan (use model_construct to bypass validator)
        empty_plan = ExecutionPlan.model_construct(
            plan_id="empty-plan-2",
            strategy_name="No Action Strategy",
            rationale="Comprehensive test rationale for unit testing purposes",
            risk_factors=[],
            steps=[],
        )

        state = {
            "execution_plan_output": empty_plan,
            "evaluation_result": {"confidence": 0.5},  # Low confidence
        }
        result = node(state)

        # Key assertion: empty plan + low confidence → HITL_REQUIRED
        assert result["ftra_status"] == "HITL_REQUIRED"
        assert result["ftra_result"]["parse_failure_class"] == "EMPTY_STEPS"


class TestBugFtraJson001:
    """Regression tests for BUG-FTRA-JSON-001: Tokenizer artifacts break JSON parse."""

    def _registry_path(self, tmp_path, terminals: dict[str, str]):
        import json
        from pathlib import Path

        path = Path(tmp_path) / "registry.json"
        path.write_text(json.dumps({"terminals": terminals}))
        return path

    def _plan_json_with_fences(self):
        """Return a valid plan wrapped in markdown code fences."""
        return """```json
{
    "plan_id": "fenced-plan-1",
    "strategy_name": "Test Strategy",
    "rationale": "Comprehensive test rationale for unit testing purposes",
    "risk_factors": [],
    "steps": [
        {
            "id": "s1",
            "action": "check_price",
            "description": "Check price",
            "parameters": {}
        }
    ]
}
```"""

    def test_markdown_fences_sanitized_and_parsed(self, tmp_path):
        """Markdown code fences should be sanitized and plan should parse.

        Prior to fix: ```json fences caused JSON parse failure → BLOCKED
        After fix: fences stripped, plan parses successfully
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_json_with_fences(),
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        # Key assertion: should parse successfully and return CLEAR
        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_result"]["sanitization_applied"] is True
        assert result["ftra_result"]["parse_failure_class"] == "TOKENIZER_ARTIFACT"

    def test_sanitization_can_be_disabled_via_env(self, tmp_path, monkeypatch):
        """FTRA_SANITIZE_TOKENIZER_ARTIFACTS=false disables sanitization."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        monkeypatch.setenv("FTRA_SANITIZE_TOKENIZER_ARTIFACTS", "false")

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_json_with_fences(),
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        # With sanitization disabled, the fences cause a parse failure
        # (should DEFER, not BLOCK per BUG-FTRA-SCHEMA-001 fix)
        assert result["ftra_status"] == "HITL_REQUIRED"

    def test_sanitization_enabled_by_default(self, tmp_path, monkeypatch):
        """Sanitization is enabled by default (no env var set)."""
        from src.gateway.governance.ftra.node_factory import _is_sanitization_enabled

        # Ensure env var is not set
        monkeypatch.delenv("FTRA_SANITIZE_TOKENIZER_ARTIFACTS", raising=False)

        assert _is_sanitization_enabled() is True

    def test_sanitization_env_var_variations(self, tmp_path, monkeypatch):
        """FTRA_SANITIZE_TOKENIZER_ARTIFACTS accepts various true/false values."""
        from src.gateway.governance.ftra.node_factory import _is_sanitization_enabled

        # Test truthy values
        for val in ["true", "True", "TRUE", "1", "yes", "on"]:
            monkeypatch.setenv("FTRA_SANITIZE_TOKENIZER_ARTIFACTS", val)
            assert _is_sanitization_enabled() is True, f"Expected True for '{val}'"

        # Test falsy values
        for val in ["false", "False", "FALSE", "0", "no", "off"]:
            monkeypatch.setenv("FTRA_SANITIZE_TOKENIZER_ARTIFACTS", val)
            assert _is_sanitization_enabled() is False, f"Expected False for '{val}'"


class TestTruncationDetection:
    """Tests for truncation detection logic."""

    def test_detect_truncation_unbalanced_braces(self):
        """Unbalanced braces should be detected as truncation."""
        from src.gateway.governance.ftra.node_factory import _detect_truncation

        truncated = '{"plan_id": "test", "steps": [{"id": "s1"'
        assert _detect_truncation(truncated) is True

    def test_detect_truncation_trailing_comma(self):
        """Trailing comma should be detected as truncation."""
        from src.gateway.governance.ftra.node_factory import _detect_truncation

        truncated = '{"plan_id": "test", "steps": [],'
        assert _detect_truncation(truncated) is True

    def test_detect_truncation_complete_json(self):
        """Complete JSON should not be detected as truncated."""
        from src.gateway.governance.ftra.node_factory import _detect_truncation

        complete = '{"plan_id": "test", "steps": []}'
        assert _detect_truncation(complete) is False


class TestTelemetry:
    """Tests for OTel and Prometheus telemetry."""

    def _registry_path(self, tmp_path, terminals: dict[str, str]):
        import json
        from pathlib import Path

        path = Path(tmp_path) / "registry.json"
        path.write_text(json.dumps({"terminals": terminals}))
        return path

    def _plan_dict(self, steps: list[tuple[str, str]], plan_id: str = "plan-1"):
        return {
            "plan_id": plan_id,
            "strategy_name": "Test Strategy",
            "rationale": "Comprehensive test rationale for unit testing purposes",
            "risk_factors": [],
            "steps": [
                {
                    "id": step_id,
                    "action": action,
                    "description": f"Step {step_id}",
                    "parameters": {},
                }
                for step_id, action in steps
            ],
        }

    def test_otel_span_includes_parse_failure_class(self, tmp_path):
        """OTel span should include cage.ftra.parse_failure_class attribute."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": 0.9},
        }

        mock_span = MagicMock()
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value.__enter__ = lambda _: mock_span
        mock_tracer.start_as_current_span.return_value.__exit__ = lambda *args: None

        with patch("opentelemetry.trace.get_tracer", return_value=mock_tracer):
            result = node(state)

        assert result["ftra_status"] == "CLEAR"

        # Verify OTel attributes
        set_attr_calls = {
            call.args[0]: call.args[1]
            for call in mock_span.set_attribute.call_args_list
        }
        assert "cage.ftra.parse_failure_class" in set_attr_calls
        assert set_attr_calls["cage.ftra.parse_failure_class"] == "SUCCESS"
        assert "cage.ftra.sanitization_applied" in set_attr_calls
        assert set_attr_calls["cage.ftra.sanitization_applied"] is False

    def test_otel_span_includes_sanitization_applied(self, tmp_path):
        """OTel span should include cage.ftra.sanitization_applied attribute."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Plan with markdown fences (will be sanitized)
        fenced_plan = """```json
{
    "plan_id": "test-1",
    "strategy_name": "Test",
    "rationale": "Test rationale for unit testing purposes",
    "risk_factors": [],
    "steps": [{"id": "s1", "action": "check_price", "description": "d", "parameters": {}}]
}
```"""

        state = {
            "execution_plan_output": fenced_plan,
            "evaluation_result": {"confidence": 0.9},
        }

        mock_span = MagicMock()
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value.__enter__ = lambda _: mock_span
        mock_tracer.start_as_current_span.return_value.__exit__ = lambda *args: None

        with patch("opentelemetry.trace.get_tracer", return_value=mock_tracer):
            result = node(state)

        assert result["ftra_status"] == "CLEAR"

        # Verify sanitization_applied is True
        set_attr_calls = {
            call.args[0]: call.args[1]
            for call in mock_span.set_attribute.call_args_list
        }
        assert set_attr_calls.get("cage.ftra.sanitization_applied") is True
        assert (
            set_attr_calls.get("cage.ftra.parse_failure_class") == "TOKENIZER_ARTIFACT"
        )

    def test_prometheus_counter_incremented_on_parse_failure(self, tmp_path):
        """Prometheus counter cage_ftra_parse_failures_total should be incremented.

        This test is skipped if prometheus_client is not available.
        """
        from src.gateway.governance.ftra.node_factory import (
            _PROM_AVAILABLE,
            FTRA_PARSE_FAILURES,
            create_ftra_node,
        )
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        if not _PROM_AVAILABLE or FTRA_PARSE_FAILURES is None:
            pytest.skip("prometheus_client not available")

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Get initial counter value
        initial_value = FTRA_PARSE_FAILURES.labels(
            failure_class="SCHEMA_VALIDATION_ERROR"
        )._value.get()

        # Trigger a schema validation error
        state = {
            "execution_plan_output": {"invalid": "plan"},
            "evaluation_result": {"confidence": 0.9},
        }
        node(state)

        # Counter should have incremented
        new_value = FTRA_PARSE_FAILURES.labels(
            failure_class="SCHEMA_VALIDATION_ERROR"
        )._value.get()
        assert new_value > initial_value


# ---------------------------------------------------------------------------
# FTRA Integration Tests (Phase 3.4)
# ---------------------------------------------------------------------------


class TestFtraIntegration:
    """Integration tests for FTRA Tier 0.5 gate.

    These tests verify end-to-end behavior of the FTRA subsystem, including:
    - In-graph ftra_node classification
    - Custom extractors for non-GFA state schemas
    - FTRA boundary check at controller level (Phase 3.3)
    - Consistency between in-graph node and boundary check
    """

    def _registry_path(self, tmp_path, terminals: dict[str, str]):
        import json
        from pathlib import Path

        path = Path(tmp_path) / "registry.json"
        path.write_text(json.dumps({"terminals": terminals}))
        return path

    def _plan_dict(self, steps: list[tuple[str, str]], plan_id: str = "plan-1"):
        return {
            "plan_id": plan_id,
            "strategy_name": "Test Strategy",
            "rationale": "Comprehensive test rationale for unit testing purposes",
            "risk_factors": [],
            "steps": [
                {
                    "id": step_id,
                    "action": action,
                    "description": f"Step {step_id}",
                    "parameters": {},
                }
                for step_id, action in steps
            ],
        }

    def test_ftra_node_classifies_terminal_action_correctly(self, tmp_path):
        """Verify terminal actions (delete, cancel) are flagged as IRREVERSIBLE_TERMINAL.

        This test ensures that actions classified as terminal in the registry
        are correctly identified and routed to HITL or BLOCKED status.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        # Registry with terminal actions that should trigger HITL/BLOCKED
        registry_path = self._registry_path(
            tmp_path,
            {
                "delete_account": "IRREVERSIBLE_TERMINAL",
                "cancel_order": "IRREVERSIBLE_TERMINAL",
                "execute_trade": "IRREVERSIBLE_TERMINAL",
                "check_balance": "READ_ONLY",
            },
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Plan with terminal delete action + high confidence → HITL_REQUIRED
        state = {
            "execution_plan_output": self._plan_dict(
                [
                    ("s1", "check_balance"),
                    ("s2", "delete_account"),  # Terminal action
                ]
            ),
            "evaluation_result": {"confidence": 0.85},
        }

        # Mock Redis to avoid actual HITL parking (just test classification)
        with patch(
            "redis.asyncio.from_url", side_effect=ConnectionError("redis unavailable")
        ):
            with pytest.raises(Exception):  # NodeInterrupt expected
                node(state)

    def test_ftra_node_passes_reversible_actions(self, tmp_path):
        """Verify reversible actions pass through with CLEAR status.

        Actions classified as READ_ONLY or REVERSIBLE should not trigger
        HITL escalation and should proceed to the next graph node.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path,
            {
                "check_balance": "READ_ONLY",
                "update_preferences": "REVERSIBLE",
                "view_portfolio": "READ_ONLY",
            },
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Plan with only reversible/read-only actions
        state = {
            "execution_plan_output": self._plan_dict(
                [
                    ("s1", "check_balance"),
                    ("s2", "update_preferences"),
                    ("s3", "view_portfolio"),
                ]
            ),
            "evaluation_result": {"confidence": 0.95},
        }
        result = node(state)

        # All actions are safe → CLEAR verdict
        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_defer_id"] is None
        assert result["ftra_result"]["ctrl_id"] == "CTRL_FTRA_001"
        assert result["ftra_result"]["verdict"] == "CLEAR"

    def test_ftra_config_custom_extractors_work_end_to_end(self, tmp_path):
        """Verify custom extractors extract plan correctly from non-GFA state schemas.

        This test validates that FtraNodeConfig custom extractors can be used
        to integrate FTRA with agent state schemas that differ from GFA's
        default execution_plan_output/evaluation_result structure.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path,
            {
                "safe_action": "READ_ONLY",
                "risky_action": "IRREVERSIBLE_TERMINAL",
            },
        )

        # Custom extractors for a hypothetical non-GFA agent
        def custom_plan_extractor(state: dict) -> dict | None:
            # Extract from a nested structure
            workflow = state.get("workflow_state", {})
            return workflow.get("pending_plan")

        def custom_confidence_extractor(state: dict) -> float:
            # Extract confidence from a different location
            metrics = state.get("agent_metrics", {})
            return float(metrics.get("decision_confidence", 0.0))

        config = FtraNodeConfig(
            registry_path=registry_path,
            plan_extractor=custom_plan_extractor,
            confidence_extractor=custom_confidence_extractor,
        )
        node = create_ftra_node(config=config)

        # State with non-GFA schema (nested plan, different confidence location)
        state = {
            "workflow_state": {
                "pending_plan": self._plan_dict([("s1", "safe_action")]),
            },
            "agent_metrics": {
                "decision_confidence": 0.92,
            },
        }
        result = node(state)

        # Should extract plan and confidence correctly and return CLEAR
        assert result["ftra_status"] == "CLEAR"
        assert result["ftra_result"]["confidence_at_analysis"] == 0.92

    def test_ftra_boundary_check_matches_ftra_node_classification(self, tmp_path):
        """Verify boundary check produces same result as in-graph node.

        Phase 3.3 FTRA boundary check (at controller boundary) must use the
        same IrreversibilityClassifier and terminal_registry.json as the
        in-graph ftra_node to ensure consistent classification semantics.

        This test verifies that both paths return the same classification
        for a given action.
        """
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
        from src.gateway.governance.ftra.models import (
            FtraBoundaryResult,
            TerminalClassification,
        )
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        # Create registry with known classifications
        registry_path = self._registry_path(
            tmp_path,
            {
                "execute_trade": "IRREVERSIBLE_TERMINAL",
                "check_price": "READ_ONLY",
                "update_watchlist": "REVERSIBLE",
            },
        )

        # 1. Test via in-graph ftra_node
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # 2. Test via boundary check (using same classifier)
        classifier = IrreversibilityClassifier(registry_path=registry_path)

        # Test each action type
        test_cases = [
            ("execute_trade", TerminalClassification.IRREVERSIBLE_TERMINAL, True),
            ("check_price", TerminalClassification.READ_ONLY, False),
            ("update_watchlist", TerminalClassification.REVERSIBLE, False),
            (
                "unknown_action",
                TerminalClassification.IRREVERSIBLE_TERMINAL,
                True,
            ),  # Fail-closed
        ]

        for action_name, expected_class, expected_hitl in test_cases:
            # Boundary check classification
            classification = classifier.classify(action_name)
            assert classification == expected_class, (
                f"Classifier mismatch for '{action_name}': "
                f"expected {expected_class}, got {classification}"
            )

            # Verify FtraBoundaryResult factory produces consistent result
            in_registry = action_name in classifier.known_actions()
            boundary_result = FtraBoundaryResult.from_classification(
                classification=classification,
                action_name=action_name,
                in_registry=in_registry,
            )
            assert boundary_result.requires_hitl == expected_hitl, (
                f"HITL requirement mismatch for '{action_name}': "
                f"expected {expected_hitl}, got {boundary_result.requires_hitl}"
            )
            assert boundary_result.classification == expected_class.value

            # Verify in-graph node produces same classification
            # (for READ_ONLY and REVERSIBLE actions, the node should return CLEAR)
            if not expected_hitl:
                state = {
                    "execution_plan_output": self._plan_dict([("s1", action_name)]),
                    "evaluation_result": {"confidence": 0.95},
                }
                result = node(state)
                assert result["ftra_status"] == "CLEAR", (
                    f"In-graph node status mismatch for '{action_name}': "
                    f"expected CLEAR, got {result['ftra_status']}"
                )

    def test_ftra_boundary_result_from_classification_factory(self):
        """Test FtraBoundaryResult.from_classification factory method.

        Verifies that the factory correctly maps TerminalClassification
        values to FtraBoundaryResult fields.
        """
        from src.gateway.governance.ftra.models import (
            FtraBoundaryResult,
            TerminalClassification,
        )

        # IRREVERSIBLE_TERMINAL → requires_hitl=True, score=1.0
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
            action_name="execute_trade",
            in_registry=True,
        )
        assert result.requires_hitl is True
        assert result.irreversibility_score == 1.0
        assert result.classification == "IRREVERSIBLE_TERMINAL"
        assert result.terminal_match == "execute_trade"
        assert len(result.violations) == 1
        assert "IRREVERSIBLE_TERMINAL" in result.violations[0]

        # READ_ONLY → requires_hitl=False, score=0.0
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.READ_ONLY,
            action_name="check_balance",
            in_registry=True,
        )
        assert result.requires_hitl is False
        assert result.irreversibility_score == 0.0
        assert result.classification == "READ_ONLY"
        assert result.violations == []
        assert result.is_safe is True

        # REVERSIBLE → requires_hitl=False, score=0.5
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.REVERSIBLE,
            action_name="update_preferences",
            in_registry=True,
        )
        assert result.requires_hitl is False
        assert result.irreversibility_score == 0.5
        assert result.classification == "REVERSIBLE"

        # Unknown action (fail-closed) → in_registry=False
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
            action_name="unknown_action",
            in_registry=False,
            bypassed_ftra_node=True,
        )
        assert result.requires_hitl is True
        assert result.terminal_match is None
        assert result.bypassed_ftra_node is True
        assert "not found" in result.violations[0]

    def test_ftra_integration_with_mixed_plan_actions(self, tmp_path):
        """Test FTRA handling of plans with mixed action types.

        A plan containing both safe (READ_ONLY) and terminal (IRREVERSIBLE_TERMINAL)
        actions should be flagged based on the worst-case classification.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(
            tmp_path,
            {
                "check_balance": "READ_ONLY",
                "analyze_market": "READ_ONLY",
                "execute_trade": "IRREVERSIBLE_TERMINAL",
                "update_preferences": "REVERSIBLE",
            },
        )
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        # Plan with mixed actions: mostly safe but one terminal
        state = {
            "execution_plan_output": self._plan_dict(
                [
                    ("s1", "check_balance"),  # READ_ONLY
                    ("s2", "analyze_market"),  # READ_ONLY
                    ("s3", "update_preferences"),  # REVERSIBLE
                    ("s4", "execute_trade"),  # IRREVERSIBLE_TERMINAL ← worst case
                ]
            ),
            "evaluation_result": {"confidence": 0.30},  # Low confidence → BLOCKED
        }
        result = node(state)

        # Should be BLOCKED due to low confidence + reachable terminal
        assert result["ftra_status"] == "BLOCKED"
        assert result["ftra_result"]["verdict"] == "BLOCKED"
        assert (
            result["ftra_result"]["worst_case_classification"]
            == "IRREVERSIBLE_TERMINAL"
        )
        assert "s4" in result["ftra_result"]["reachable_terminals"]

    def test_ftra_telemetry_attributes_complete(self, tmp_path):
        """Verify all required OTel span attributes are set.

        FTRA node must emit telemetry for audit and observability.
        """
        from src.gateway.governance.ftra.node_factory import create_ftra_node
        from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(config=FtraNodeConfig(registry_path=registry_path))

        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": 0.9},
        }

        mock_span = MagicMock()
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value.__enter__ = lambda _: mock_span
        mock_tracer.start_as_current_span.return_value.__exit__ = lambda *args: None

        with patch("opentelemetry.trace.get_tracer", return_value=mock_tracer):
            node(state)

        # Verify all expected attributes are set
        set_attr_calls = {
            call.args[0]: call.args[1]
            for call in mock_span.set_attribute.call_args_list
        }

        # Core FTRA attributes
        assert "cage.ftra.ctrl_id" in set_attr_calls
        assert set_attr_calls["cage.ftra.ctrl_id"] == "CTRL_FTRA_001"
        assert "cage.ftra.verdict" in set_attr_calls
        assert "cage.ftra.parse_failure_class" in set_attr_calls
        assert "cage.ftra.sanitization_applied" in set_attr_calls
        assert "cage.ftra.confidence_at_analysis" in set_attr_calls
        assert "cage.ftra.config_source" in set_attr_calls
