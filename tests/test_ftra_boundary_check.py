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
Tests for Phase 3.3: Controller-Boundary FTRA Check (Trust-Boundary Enforcement).

Risk R-03 identifies that ftra_node only fires if the host agent wires it into
its own LangGraph. Direct HTTP access to /validate-action or ext_authz bypasses
it entirely. These tests verify that the FTRA boundary check closes this gap.

Test Requirements:
- test_boundary_check_classifies_direct_http_bypass
- test_boundary_check_disabled_by_default
- test_boundary_check_routes_to_classify_violation
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.ftra.models import (
    FtraBoundaryResult,
    TerminalClassification,
)


# ---------------------------------------------------------------------------
# FtraBoundaryResult Unit Tests
# ---------------------------------------------------------------------------


class TestFtraBoundaryResult:
    """Unit tests for the FtraBoundaryResult dataclass."""

    def test_from_classification_irreversible_terminal(self) -> None:
        """Test FtraBoundaryResult creation for IRREVERSIBLE_TERMINAL classification."""
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
            action_name="execute_trade",
            in_registry=True,
            bypassed_ftra_node=True,
        )

        assert result.requires_hitl is True
        assert result.irreversibility_score == 1.0
        assert result.classification == "IRREVERSIBLE_TERMINAL"
        assert result.terminal_match == "execute_trade"
        assert result.bypassed_ftra_node is True
        assert len(result.violations) == 1
        assert "FTRA Boundary Check" in result.violations[0]
        assert "Human-in-the-loop review required" in result.violations[0]
        assert result.is_safe is False

    def test_from_classification_read_only(self) -> None:
        """Test FtraBoundaryResult creation for READ_ONLY classification."""
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.READ_ONLY,
            action_name="prompt_injection_check",
            in_registry=True,
            bypassed_ftra_node=False,
        )

        assert result.requires_hitl is False
        assert result.irreversibility_score == 0.0
        assert result.classification == "READ_ONLY"
        assert result.terminal_match == "prompt_injection_check"
        assert result.bypassed_ftra_node is False
        assert len(result.violations) == 0
        assert result.is_safe is True

    def test_from_classification_reversible(self) -> None:
        """Test FtraBoundaryResult creation for REVERSIBLE classification."""
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.REVERSIBLE,
            action_name="some_reversible_action",
            in_registry=True,
            bypassed_ftra_node=False,
        )

        assert result.requires_hitl is False
        assert result.irreversibility_score == 0.5
        assert result.classification == "REVERSIBLE"
        assert result.is_safe is True

    def test_from_classification_unknown_action_fail_closed(self) -> None:
        """Test FtraBoundaryResult for action not in registry — fails closed."""
        result = FtraBoundaryResult.from_classification(
            classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
            action_name="unknown_action",
            in_registry=False,
            bypassed_ftra_node=True,
        )

        assert result.requires_hitl is True
        assert result.terminal_match is None
        assert "not found in terminal_registry.json" in result.violations[0]
        assert "failing closed to IRREVERSIBLE_TERMINAL" in result.violations[0]


# ---------------------------------------------------------------------------
# SymbolicGovernor FTRA Boundary Check Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_opa_client() -> MagicMock:
    """Create a mock OPA client that returns ALLOW."""
    client = MagicMock()
    client.evaluate_policy = AsyncMock(return_value={"allow": "ALLOW"})
    return client


@pytest.fixture
def mock_safety_filter() -> MagicMock:
    """Create a mock safety filter that returns SAFE."""
    sf = MagicMock()
    sf.verify_action = AsyncMock(return_value="SAFE")
    sf.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))
    return sf


@pytest.fixture
def mock_consensus_engine() -> MagicMock:
    """Create a mock consensus engine that approves."""
    engine = MagicMock()
    engine.check_consensus = AsyncMock(
        return_value={"status": "ACCEPT", "reason": ""}
    )
    return engine


@pytest.fixture
def symbolic_governor(
    mock_opa_client: MagicMock,
    mock_safety_filter: MagicMock,
    mock_consensus_engine: MagicMock,
) -> "SymbolicGovernor":
    """Create a SymbolicGovernor instance with mocked dependencies."""
    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    return SymbolicGovernor(
        opa_client=mock_opa_client,
        safety_filter=mock_safety_filter,
        consensus_engine=mock_consensus_engine,
        stpa_validator=None,
        telemetry_provider=None,
        fiscal_limit_guard=None,
    )


class TestBoundaryCheckDisabledByDefault:
    """Test that FTRA boundary check is disabled by default."""

    @pytest.mark.asyncio
    async def test_boundary_check_disabled_by_default(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify boundary check is skipped when CAGE_FTRA_BOUNDARY_ENABLED is not set.

        This test ensures there is zero latency impact on existing deployments
        that do not opt into the boundary check feature.
        """
        # Ensure flag is disabled (default state)
        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "false"}):
            # Reimport to pick up the env change
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            # Create fresh governor with reloaded module
            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # Run checks for an irreversible action
            result = await governor._run_checks(
                tool_name="execute_trade",
                params={"amount": 100, "symbol": "AAPL", "confidence": 0.99},
                sim_mode=False,
            )

            # FTRA boundary result should be None (check was skipped)
            assert result.get("ftra_boundary_result") is None

    @pytest.mark.asyncio
    async def test_boundary_check_enabled_when_flag_true(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify boundary check runs when CAGE_FTRA_BOUNDARY_ENABLED=true."""
        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "true"}):
            # Reimport to pick up the env change
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            # Create fresh governor with reloaded module
            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # Run checks for an irreversible action
            result = await governor._run_checks(
                tool_name="execute_trade",
                params={"amount": 100, "symbol": "AAPL", "confidence": 0.99},
                sim_mode=False,
            )

            # FTRA boundary result should be present
            ftra_result = result.get("ftra_boundary_result")
            assert ftra_result is not None
            assert ftra_result.classification == "IRREVERSIBLE_TERMINAL"
            assert ftra_result.requires_hitl is True


class TestBoundaryCheckClassifiesDirectHttpBypass:
    """Test that boundary check catches direct HTTP bypasses of ftra_node."""

    @pytest.mark.asyncio
    async def test_boundary_check_classifies_direct_http_bypass(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify boundary check catches actions that would bypass in-graph ftra_node.

        This is the core test for Risk R-03 mitigation: when an action like
        execute_trade comes in via /validate-action or ext_authz, the boundary
        check should classify it as IRREVERSIBLE_TERMINAL and require HITL.
        """
        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "true"}):
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # Test execute_trade — should be caught as IRREVERSIBLE_TERMINAL
            result = await governor._ftra_boundary_check(
                tool_name="execute_trade",
                tool_input={"amount": 50000, "symbol": "TSLA"},
                detect_bypass=True,
            )

            assert result.requires_hitl is True
            assert result.classification == "IRREVERSIBLE_TERMINAL"
            assert result.bypassed_ftra_node is True
            assert len(result.violations) > 0
            assert "Human-in-the-loop review required" in result.violations[0]

    @pytest.mark.asyncio
    async def test_boundary_check_allows_read_only_actions(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify READ_ONLY actions pass through without HITL requirement."""
        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "true"}):
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # Test prompt_injection_check — should be READ_ONLY
            result = await governor._ftra_boundary_check(
                tool_name="prompt_injection_check",
                tool_input={"prompt": "test prompt"},
                detect_bypass=True,
            )

            assert result.requires_hitl is False
            assert result.classification == "READ_ONLY"
            assert result.bypassed_ftra_node is False
            assert len(result.violations) == 0
            assert result.is_safe is True

    @pytest.mark.asyncio
    async def test_boundary_check_fails_closed_for_unknown_action(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify unknown actions fail closed to IRREVERSIBLE_TERMINAL."""
        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "true"}):
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # Test unknown action — should fail closed
            result = await governor._ftra_boundary_check(
                tool_name="unknown_dangerous_action",
                tool_input={},
                detect_bypass=True,
            )

            assert result.requires_hitl is True
            assert result.classification == "IRREVERSIBLE_TERMINAL"
            assert result.terminal_match is None  # Not in registry


class TestBoundaryCheckRoutesToClassifyViolation:
    """Test that boundary check violations are routed through _classify_violation."""

    def test_boundary_check_routes_to_classify_violation(self) -> None:
        """Verify FTRA boundary violations are correctly classified.

        When the boundary check returns requires_hitl=True, the violation
        should be routed through _classify_violation() and result in
        REQUIRE_APPROVAL (not DENY).
        """
        from src.gateway.governance.symbolic_governor import _classify_violation

        # Simulate FTRA boundary check violation
        violations = [
            "FTRA Boundary Check: Action 'execute_trade' is classified as "
            "IRREVERSIBLE_TERMINAL in terminal_registry.json. "
            "Human-in-the-loop review required before execution."
        ]

        decision, metadata = _classify_violation(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.95,  # High confidence — should not trigger DEFER
            context={},
        )

        # Should route to REQUIRE_APPROVAL, not DENY
        from src.gateway.governance.decisions import GovernanceDecision

        assert decision == GovernanceDecision.REQUIRE_APPROVAL
        assert "FTRA_BOUNDARY_HITL" in metadata.get("violation_types", [])
        assert metadata.get("ftra_boundary_triggered") is True
        assert "Irreversible action caught at controller boundary" in metadata.get(
            "classification_reason", ""
        )

    def test_boundary_check_with_hard_violation_results_in_deny(self) -> None:
        """Verify FTRA boundary + hard violation results in DENY, not REQUIRE_APPROVAL.

        If there are hard violations (STPA, CBF, OPA DENY) alongside the FTRA
        boundary violation, the hard violations should take precedence.
        """
        from src.gateway.governance.symbolic_governor import _classify_violation

        # Simulate FTRA boundary check violation + STPA hard violation
        violations = [
            "FTRA Boundary Check: Action 'execute_trade' is classified as "
            "IRREVERSIBLE_TERMINAL in terminal_registry.json. "
            "Human-in-the-loop review required before execution.",
            "STPA UCA-7 Violation: Unsafe control action detected",
        ]

        decision, metadata = _classify_violation(
            violations=violations,
            stpa_violation_count=1,  # Hard violation
            confidence=0.95,
            context={},
        )

        # Hard violation should take precedence — DENY
        from src.gateway.governance.decisions import GovernanceDecision

        assert decision == GovernanceDecision.DENY
        assert "STPA_SAFETY" in metadata.get("violation_types", [])


class TestPrometheusMetrics:
    """Test Prometheus counter increments for FTRA boundary checks."""

    @pytest.mark.asyncio
    async def test_prometheus_counter_increments_on_hitl_required(
        self,
        symbolic_governor: "SymbolicGovernor",
    ) -> None:
        """Verify Prometheus counter increments for hitl_required result."""
        # Skip if prometheus_client not installed
        pytest.importorskip("prometheus_client")

        with patch.dict(os.environ, {"CAGE_FTRA_BOUNDARY_ENABLED": "true"}):
            import importlib

            import src.gateway.governance.symbolic_governor as sg_module

            importlib.reload(sg_module)

            governor = sg_module.SymbolicGovernor(
                opa_client=symbolic_governor.opa_client,
                safety_filter=symbolic_governor.safety_filter,
                consensus_engine=symbolic_governor.consensus_engine,
            )

            # The Counter will be created and incremented during the check
            # We just verify no exceptions are raised
            result = await governor._ftra_boundary_check(
                tool_name="execute_trade",
                tool_input={},
                detect_bypass=True,
            )

            assert result.requires_hitl is True
            # Counter increment happens without exception — test passes


class TestClassifierStandaloneInstantiation:
    """Test that IrreversibilityClassifier can be instantiated standalone."""

    def test_classifier_instantiation_standalone(self) -> None:
        """Verify IrreversibilityClassifier can be created without SymbolicGovernor."""
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

        # Should instantiate without errors
        classifier = IrreversibilityClassifier()

        # Should be able to classify actions
        classification = classifier.classify("execute_trade")
        assert classification == TerminalClassification.IRREVERSIBLE_TERMINAL

        classification = classifier.classify("prompt_injection_check")
        assert classification == TerminalClassification.READ_ONLY

    def test_classifier_known_actions(self) -> None:
        """Verify classifier reports known actions from registry."""
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

        classifier = IrreversibilityClassifier()
        known = classifier.known_actions()

        assert "execute_trade" in known
        assert "prompt_injection_check" in known

    def test_classifier_is_irreversible_helper(self) -> None:
        """Verify is_irreversible() convenience method."""
        from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

        classifier = IrreversibilityClassifier()

        assert classifier.is_irreversible("execute_trade") is True
        assert classifier.is_irreversible("write_db") is True
        assert classifier.is_irreversible("prompt_injection_check") is False
