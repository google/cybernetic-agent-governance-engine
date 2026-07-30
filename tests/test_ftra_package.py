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
        rationale="Test rationale",
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

        analyzer = self._analyzer(tmp_path, {})
        plan = _make_plan([])
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
        """FRIA_ZONE_DEFER boundary is inclusive: confidence == 0.70 -> HITL_REQUIRED."""
        from src.gateway.governance.ftra.graph_analyzer import FRIA_ZONE_DEFER
        from src.gateway.governance.ftra.models import FTRAVerdict

        analyzer = self._analyzer(tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"})
        plan = _make_plan([("s1", "execute_trade")])
        result = analyzer.analyze(plan, confidence=FRIA_ZONE_DEFER)

        assert result.verdict == FTRAVerdict.HITL_REQUIRED

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
            rationale="Test",
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
            "rationale": "Test rationale",
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

        registry_path = self._registry_path(tmp_path, {"check_price": "READ_ONLY"})
        node = create_ftra_node(registry_path=registry_path)

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

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(registry_path=registry_path)

        state = {
            "execution_plan_output": self._plan_dict([("s1", "execute_trade")]),
            "evaluation_result": {"confidence": 0.2},
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"
        assert result["ftra_defer_id"] is None

    def test_missing_execution_plan_fails_closed_to_blocked(self, tmp_path):
        from src.gateway.governance.ftra.node_factory import create_ftra_node

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(registry_path=registry_path)

        state = {"evaluation_result": {"confidence": 0.9}}
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"
        assert "execution_plan_output missing" in result["ftra_result"]["error"]

    def test_malformed_execution_plan_fails_closed_to_blocked(self, tmp_path):
        from src.gateway.governance.ftra.node_factory import create_ftra_node

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(registry_path=registry_path)

        state = {
            "execution_plan_output": {"not_a_valid_plan": True},
            "evaluation_result": {"confidence": 0.9},
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"

    def test_missing_evaluation_result_defaults_confidence_to_zero(self, tmp_path):
        """Absent evaluation_result must default confidence to 0.0, which for
        an irreversible-terminal plan means BLOCKED (not HITL_REQUIRED)."""
        from src.gateway.governance.ftra.node_factory import create_ftra_node

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(registry_path=registry_path)

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

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(registry_path=registry_path)

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

        registry_path = self._registry_path(
            tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"}
        )
        node = create_ftra_node(registry_path=registry_path)

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

        registry_path = self._registry_path(tmp_path, {})
        node = create_ftra_node(registry_path=registry_path)

        # A state value that will blow up type coercion deep inside _run_ftra
        state = {
            "execution_plan_output": self._plan_dict([("s1", "check_price")]),
            "evaluation_result": {"confidence": "not-a-float"},
        }
        result = node(state)

        assert result["ftra_status"] == "BLOCKED"
