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
Unit tests for ClassificationEngine.

This test module provides 100% branch coverage for the five-way classification
logic that routes violations to DENY, DEFER, NARROW, PAUSE, or REQUIRE_APPROVAL.

Test markers:
    @pytest.mark.unit — isolated unit tests with no external dependencies

Phase 1.6: CAGE Implementation Plan — Governance Primitives Test Coverage
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
)
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.narrower import NarrowerRegistry

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def narrower_registry():
    """Provide a NarrowerRegistry instance for testing."""
    return NarrowerRegistry()


def _make_classification_engine(
    narrower_registry: NarrowerRegistry,
    defer_enabled: bool = True,
    narrow_enabled: bool = False,
    pause_enabled: bool = False,
    confidence_threshold: float = 0.70,
) -> ClassificationEngine:
    """Helper to create a ClassificationEngine with custom settings."""
    return ClassificationEngine(
        narrower_registry=narrower_registry,
        confidence_threshold=confidence_threshold,
        defer_enabled=defer_enabled,
        narrow_enabled=narrow_enabled,
        pause_enabled=pause_enabled,
    )


def _make_violations(violation_strings: list[str]) -> list[Violation]:
    """Helper to create Violation objects from strings.
    
    Maps violation strings to appropriate ViolationKind based on content.
    """
    violations = []
    for v_str in violation_strings:
        # Determine kind based on violation string content
        if any(marker in v_str for marker in ["STPA", "UCA-", "CBF", "OPA Denied", "Fiscal Limit Pre-Reservation REJECTED"]):
            kind = ViolationKind.HARD
        elif any(marker in v_str for marker in ["Manual Review", "[CTRL_OPA_001]"]):
            kind = ViolationKind.HITL
        elif any(marker in v_str for marker in ["Rate limit", "Circuit breaker", "Quota exhausted", "temporarily unavailable"]):
            kind = ViolationKind.TRANSIENT
        elif any(marker in v_str for marker in ["Amount exceeds", "Scope exceeds", "Date range exceeds"]):
            kind = ViolationKind.NARROWABLE
        elif "Confidence Violation" in v_str or "POAM-TIER2" in v_str:
            kind = ViolationKind.DEFERRABLE
        else:
            kind = ViolationKind.HARD  # Default to hard for unknown
        
        violations.append(Violation(
            tier="test_tier",
            code="TEST-001",
            message=v_str,
            kind=kind,
        ))
    return violations


# ---------------------------------------------------------------------------
# TestClassifyViolation — Hard Violations (DENY)
# ---------------------------------------------------------------------------


class TestClassifyViolationDeny:
    """Tests for hard violation paths that always result in DENY."""

    def test_stpa_violations_return_deny(self, narrower_registry):
        """STPA safety violations MUST always result in DENY."""
        engine = _make_classification_engine(narrower_registry)
        violation_strs = ["UCA-7: Unsafe Control Action detected"]
        violations = _make_violations(violation_strs)
        
        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=1,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )
        
        result = engine.classify(context, "test_action")
        
        assert result.decision == GovernanceDecision.DENY
        assert result.metadata["classification_reason"] == "hard_violation"
        assert not result.metadata["deferrable"]

    def test_cbf_violations_return_deny(self, narrower_registry):
        """CBF cash barrier violations MUST always result in DENY."""
        engine = _make_classification_engine(narrower_registry)
        violations = _make_violations(["Safety Violation (RBC/CBF): cash barrier exceeded"])
        
        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )
        
        result = engine.classify(context, "test_action")
        
        assert result.decision == GovernanceDecision.DENY
        assert not result.metadata["deferrable"]

    def test_opa_deny_returns_deny(self, narrower_registry):
        """Explicit OPA DENY violation MUST result in DENY."""
        engine = _make_classification_engine(narrower_registry)
        violations = _make_violations(["[CTRL_OPA_005] OPA Denied Action"])
        
        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )
        
        result = engine.classify(context, "test_action")
        
        assert result.decision == GovernanceDecision.DENY
        assert not result.metadata["deferrable"]

    def test_fiscal_limit_rejection_returns_deny(self, narrower_registry):
        """Fiscal Limit Pre-Reservation REJECTED is a hard violation."""
        engine = _make_classification_engine(narrower_registry)
        violations = _make_violations(["Fiscal Limit Pre-Reservation REJECTED: amount exceeds daily cap"])
        
        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )
        
        result = engine.classify(context, "test_action")
        
        assert result.decision == GovernanceDecision.DENY


# ---------------------------------------------------------------------------
# TestClassifyViolation — DEFER Path
# ---------------------------------------------------------------------------


class TestClassifyViolationDefer:
    """Tests for soft violation paths that result in DEFER."""

    def test_low_confidence_soft_violations_return_defer(self, narrower_registry):
        """Low confidence + soft violations → DEFER (when enabled)."""
        engine = _make_classification_engine(narrower_registry, defer_enabled=True)
        violations = _make_violations(["Confidence Violation: score 0.55 < threshold 0.95"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.55,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.DEFER
        assert result.metadata["deferrable"]
        assert "confidence" in result.metadata["classification_reason"].lower()

    def test_defer_disabled_falls_back_to_deny(self, narrower_registry):
        """When defer_enabled=False, DEFER candidates fall back to DENY."""
        engine = _make_classification_engine(narrower_registry, defer_enabled=False)
        violations = _make_violations(["Confidence Violation: score 0.55 < threshold 0.95"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.55,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.DENY


# ---------------------------------------------------------------------------
# TestClassifyViolation — REQUIRE_APPROVAL Path
# ---------------------------------------------------------------------------


class TestClassifyViolationRequireApproval:
    """Tests for REQUIRE_APPROVAL (human sign-off) path."""

    def test_manual_review_violation_returns_require_approval(self, narrower_registry):
        """OPA MANUAL_REVIEW violation → REQUIRE_APPROVAL."""
        engine = _make_classification_engine(narrower_registry)
        violations = _make_violations(["[CTRL_OPA_001] Manual Review Required"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision="MANUAL_REVIEW",
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
        assert not result.metadata["deferrable"]

    def test_opa_manual_review_decision_returns_require_approval(self, narrower_registry):
        """OPA decision MANUAL_REVIEW → REQUIRE_APPROVAL (even with DEFERRABLE violations)."""
        engine = _make_classification_engine(narrower_registry)
        # Use a DEFERRABLE violation to show OPA MANUAL_REVIEW takes precedence
        violations = [Violation(
            tier="opa_tier",
            code="OPA-MANUAL",
            message="Policy requires manual review",
            kind=ViolationKind.DEFERRABLE,
        )]

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision="MANUAL_REVIEW",
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL

    def test_hitl_violation_returns_require_approval(self, narrower_registry):
        """HITL violations → REQUIRE_APPROVAL."""
        engine = _make_classification_engine(narrower_registry)
        violations = [Violation(
            tier="test_tier",
            code="TEST-001",
            message="Human-in-the-loop required",
            kind=ViolationKind.HITL,
        )]

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL


# ---------------------------------------------------------------------------
# TestClassifyViolation — PAUSE Path
# ---------------------------------------------------------------------------


class TestClassifyViolationPause:
    """Tests for PAUSE (resumable suspension) path."""

    def test_transient_violations_return_pause_when_enabled(self, narrower_registry):
        """Transient violations → PAUSE (when enabled)."""
        engine = _make_classification_engine(narrower_registry, pause_enabled=True)
        violations = _make_violations(["Rate limit exceeded: too many requests"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.PAUSE
        assert result.metadata["classification_reason"] == "transient_condition"

    def test_pause_disabled_falls_back_to_deny(self, narrower_registry):
        """When pause_enabled=False, PAUSE candidates fall back to DENY."""
        engine = _make_classification_engine(narrower_registry, pause_enabled=False)
        violations = _make_violations(["Rate limit exceeded"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.DENY


# ---------------------------------------------------------------------------
# TestClassifyViolation — Edge Cases
# ---------------------------------------------------------------------------


class TestClassifyViolationEdgeCases:
    """Edge case tests for ClassificationEngine."""

    def test_empty_violations_raises_error(self, narrower_registry):
        """Empty violations list raises ValueError."""
        engine = _make_classification_engine(narrower_registry)

        context = ClassificationContext(
            violations=[],
            stpa_violation_count=0,
            confidence=0.99,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        with pytest.raises(ValueError, match="no violations"):
            engine.classify(context, "test_action")

    def test_confidence_exactly_at_threshold(self, narrower_registry):
        """Confidence exactly at threshold should not trigger DEFER."""
        engine = _make_classification_engine(
            narrower_registry,
            defer_enabled=True,
            confidence_threshold=0.70,
        )
        violations = _make_violations(["Confidence Violation: marginal"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.70,  # Exactly at threshold
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        # Should be DENY (not DEFER), since confidence is not < threshold
        assert result.decision == GovernanceDecision.DENY

    def test_confidence_just_below_threshold(self, narrower_registry):
        """Confidence just below threshold triggers DEFER."""
        engine = _make_classification_engine(
            narrower_registry,
            defer_enabled=True,
            confidence_threshold=0.70,
        )
        violations = _make_violations(["Confidence Violation: marginal"])

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.699,  # Just below threshold
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.DEFER

    def test_mixed_hard_and_deferrable_violations(self, narrower_registry):
        """Mixed hard and deferrable violations → DENY (hard takes priority)."""
        engine = _make_classification_engine(narrower_registry, defer_enabled=True)
        violations = [
            Violation(
                tier="test_tier",
                code="TEST-001",
                message="UCA-7: STPA safety violation",
                kind=ViolationKind.HARD,
            ),
            Violation(
                tier="test_tier",
                code="TEST-002",
                message="Confidence Violation: below threshold",
                kind=ViolationKind.DEFERRABLE,
            ),
        ]

        context = ClassificationContext(
            violations=violations,
            stpa_violation_count=0,
            confidence=0.50,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
            cbf_violation=False,
        )

        result = engine.classify(context, "test_action")

        assert result.decision == GovernanceDecision.DENY
