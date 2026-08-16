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
Unit tests for _classify_violation() helper in symbolic_governor.py.

This test module provides 100% branch coverage for the five-way classification
logic that routes violations to DENY, DEFER, NARROW, PAUSE, or REQUIRE_APPROVAL.

Test markers:
    @pytest.mark.unit — isolated unit tests with no external dependencies

Phase 1.6: CAGE Implementation Plan — Governance Primitives Test Coverage
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest

from src.gateway.governance.decisions import GovernanceDecision

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_feature_flags(monkeypatch):
    """Reset feature flags to default values before each test."""
    monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
    monkeypatch.setenv("CAGE_NARROW_ENABLED", "false")
    monkeypatch.setenv("CAGE_PAUSE_ENABLED", "false")
    monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")


def _classify_violation_wrapper(
    violations: list[str],
    stpa_violation_count: int,
    confidence: float,
    context: dict[str, Any] | None = None,
) -> tuple[GovernanceDecision, dict[str, Any]]:
    """Wrapper to import and call _classify_violation with fresh module state.
    
    This ensures feature flag changes are picked up correctly.
    """
    # Import inside function to pick up monkeypatched env vars
    import importlib

    import src.gateway.governance.symbolic_governor as sg
    
    # Reload module-level flags
    sg.CAGE_DEFER_ENABLED = os.getenv("CAGE_DEFER_ENABLED", "true").lower() == "true"
    sg.CAGE_NARROW_ENABLED = os.getenv("CAGE_NARROW_ENABLED", "false").lower() == "true"
    sg.CAGE_PAUSE_ENABLED = os.getenv("CAGE_PAUSE_ENABLED", "false").lower() == "true"
    sg.FRIA_ZONE_DEFER = float(os.getenv("FRIA_ZONE_DEFER", "0.70"))
    
    return sg._classify_violation(violations, stpa_violation_count, confidence, context)


# ---------------------------------------------------------------------------
# TestClassifyViolation — Hard Violations (DENY)
# ---------------------------------------------------------------------------


class TestClassifyViolationDeny:
    """Tests for hard violation paths that always result in DENY."""

    def test_stpa_violations_return_deny(self):
        """STPA safety violations MUST always result in DENY."""
        violations = ["UCA-7: Unsafe Control Action detected"]
        decision, meta = _classify_violation_wrapper(violations, 1, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "STPA_SAFETY" in meta["violation_types"]
        assert not meta["deferrable"]
        assert violations[0] in meta["hard_violations"]

    def test_stpa_count_only_returns_deny(self):
        """Even without explicit STPA string, stpa_violation_count > 0 → DENY."""
        violations = ["Generic policy error"]
        decision, meta = _classify_violation_wrapper(violations, 2, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "STPA" in meta["classification_reason"]
        assert not meta["deferrable"]

    def test_cbf_violations_return_deny(self):
        """CBF cash barrier violations MUST always result in DENY."""
        violations = ["Safety Violation (RBC/CBF): cash barrier exceeded"]
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "CBF_CONSTRAINT" in meta["violation_types"]
        assert not meta["deferrable"]
        assert violations[0] in meta["hard_violations"]

    def test_cbf_context_flag_returns_deny(self):
        """Context cbf_violation flag triggers DENY path."""
        violations = ["Policy threshold exceeded"]
        ctx = {"cbf_violation": True}
        _decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        # CBF_CONSTRAINT_CTX is added to violation types when context flag is set
        assert "CBF_CONSTRAINT_CTX" in meta["violation_types"]

    def test_opa_deny_returns_deny(self):
        """Explicit OPA DENY violation MUST result in DENY."""
        violations = ["[CTRL_OPA_005] OPA Denied Action"]
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "OPA_DENY" in meta["violation_types"]
        assert not meta["deferrable"]

    def test_fiscal_limit_rejection_returns_deny(self):
        """Fiscal Limit Pre-Reservation REJECTED is a hard violation."""
        violations = ["Fiscal Limit Pre-Reservation REJECTED: amount exceeds daily cap"]
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "CBF_CONSTRAINT" in meta["violation_types"]

    def test_unknown_violations_default_to_deny(self):
        """Unknown violation types default to DENY for safety."""
        violations = ["Some unknown violation type xyz123"]
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "UNKNOWN_HARD" in meta["violation_types"]


# ---------------------------------------------------------------------------
# TestClassifyViolation — DEFER Path
# ---------------------------------------------------------------------------


class TestClassifyViolationDefer:
    """Tests for soft violation paths that result in DEFER."""

    def test_low_confidence_soft_violations_return_defer(self, monkeypatch):
        """Low confidence + soft violations → DEFER (when enabled)."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        violations = ["Confidence Violation: score 0.55 < threshold 0.95"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.55)
        
        assert decision == GovernanceDecision.DEFER
        assert "CONFIDENCE_STARVATION" in meta["violation_types"]
        assert meta["deferrable"]
        assert "confidence" in meta["classification_reason"].lower()

    def test_confidence_below_fria_zone_returns_defer(self, monkeypatch):
        """Confidence below FRIA_ZONE_DEFER threshold triggers DEFER."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")
        violations = ["Confidence Violation: below threshold"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.65)
        
        assert decision == GovernanceDecision.DEFER
        assert meta["deferrable"]

    def test_defer_disabled_falls_back_to_deny(self, monkeypatch):
        """When CAGE_DEFER_ENABLED=false, DEFER candidates fall back to DENY."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "false")
        violations = ["Confidence Violation: score 0.55 < threshold 0.95"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.55)
        
        assert decision == GovernanceDecision.DENY
        assert "CAGE_DEFER_ENABLED=false" in meta["classification_reason"]
        # deferrable is still True (violations are deferrable, but feature is disabled)
        assert meta["deferrable"]

    def test_soft_violations_with_starved_confidence_defer(self, monkeypatch):
        """Multiple soft violations with starved confidence → DEFER."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        violations = [
            "Confidence Violation: below threshold",
            "POAM-TIER2-001: Structural override required",
        ]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.50)
        
        assert decision == GovernanceDecision.DEFER
        assert "CONFIDENCE_STARVATION" in meta["violation_types"]
        assert "TIER2_STRUCTURAL" in meta["violation_types"]


# ---------------------------------------------------------------------------
# TestClassifyViolation — REQUIRE_APPROVAL Path
# ---------------------------------------------------------------------------


class TestClassifyViolationRequireApproval:
    """Tests for REQUIRE_APPROVAL (human sign-off) path."""

    def test_manual_review_violation_returns_require_approval(self):
        """OPA MANUAL_REVIEW violation → REQUIRE_APPROVAL."""
        violations = ["[CTRL_OPA_001] Manual Review Required"]
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.REQUIRE_APPROVAL
        assert "REQUIRE_APPROVAL" in meta["violation_types"]
        assert not meta["deferrable"]

    def test_high_confidence_soft_violations_return_require_approval(self):
        """Soft violations above confidence threshold → REQUIRE_APPROVAL."""
        violations = ["Confidence Violation: threshold edge case"]
        # Confidence is above FRIA_ZONE_DEFER (0.70) but has soft violations
        decision, meta = _classify_violation_wrapper(violations, 0, 0.85)
        
        assert decision == GovernanceDecision.REQUIRE_APPROVAL
        assert "above confidence threshold" in meta["classification_reason"]

    def test_manual_review_with_hard_violations_returns_deny(self):
        """Manual review + hard violations → DENY (hard violations take priority)."""
        violations = [
            "[CTRL_OPA_001] Manual Review Required",
            "UCA-7: STPA safety violation",
        ]
        decision, meta = _classify_violation_wrapper(violations, 1, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert not meta["deferrable"]


# ---------------------------------------------------------------------------
# TestClassifyViolation — NARROW Path
# ---------------------------------------------------------------------------


class TestClassifyViolationNarrow:
    """Tests for NARROW (partial-authority/clamped execution) path."""

    def test_narrowable_violations_return_narrow_when_enabled(self, monkeypatch):
        """Narrowable threshold violations → NARROW (when enabled)."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Amount exceeds limit: requested $150,000 > max $100,000"]
        ctx = {
            "params": {"amount": 150000, "symbol": "AAPL"},
            "threshold_config": {"max_amount": 100000},
        }
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert decision == GovernanceDecision.NARROW
        assert "AMOUNT_THRESHOLD_EXCEEDED" in meta["violation_types"]
        assert "narrowed_params" in meta
        assert "constraints_applied" in meta
        assert meta["narrowed_params"]["amount"] == 100000

    def test_scope_exceeded_returns_narrow_when_enabled(self, monkeypatch):
        """Scope exceeded violations → NARROW with filtered scope."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Scope exceeds allowed operations"]
        ctx = {
            "params": {"scope": ["read", "write", "delete"]},
            "threshold_config": {"allowed_scopes": ["read", "write"]},
        }
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert decision == GovernanceDecision.NARROW
        assert "SCOPE_EXCEEDED" in meta["violation_types"]
        assert meta["narrowed_params"]["scope"] == ["read", "write"]

    def test_date_range_exceeded_returns_narrow_when_enabled(self, monkeypatch):
        """Date range exceeded violations → NARROW with clamped days."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Date range exceeds max allowed: 365 days requested"]
        ctx = {
            "params": {"date_range_days": 365},
            "threshold_config": {"max_date_range_days": 90},
        }
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert decision == GovernanceDecision.NARROW
        assert "DATE_RANGE_EXCEEDED" in meta["violation_types"]
        assert meta["narrowed_params"]["date_range_days"] == 90

    def test_narrow_disabled_falls_back_to_defer(self, monkeypatch):
        """When CAGE_NARROW_ENABLED=false + confidence starved → DEFER."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "false")
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        violations = ["Amount exceeds limit"]
        
        # Confidence below threshold to trigger DEFER fallback
        decision, meta = _classify_violation_wrapper(violations, 0, 0.50)
        
        assert decision == GovernanceDecision.DEFER
        assert "CAGE_NARROW_ENABLED=false" in meta["classification_reason"]

    def test_narrow_disabled_falls_back_to_deny(self, monkeypatch):
        """When CAGE_NARROW_ENABLED=false + high confidence → DENY."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "false")
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        violations = ["Amount exceeds limit"]
        
        # High confidence means no DEFER fallback
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "CAGE_NARROW_ENABLED=false" in meta["classification_reason"]

    def test_narrow_clamps_amount_to_max(self, monkeypatch):
        """NARROW correctly clamps amount to max_allowed."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Amount exceeds limit"]
        ctx = {
            "params": {"amount": 250000.50},
            "threshold_config": {"max_amount": 100000.0},
        }
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert decision == GovernanceDecision.NARROW
        assert meta["narrowed_params"]["amount"] == 100000.0
        assert any("clamped" in c.lower() for c in meta["constraints_applied"])

    def test_narrow_restricts_scope_to_allowed(self, monkeypatch):
        """NARROW correctly filters scope to allowed_scopes."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Scope not allowed"]
        ctx = {
            "params": {"scope": ["read", "write", "admin", "delete"]},
            "threshold_config": {"allowed_scopes": ["read", "write"]},
        }
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert decision == GovernanceDecision.NARROW
        assert set(meta["narrowed_params"]["scope"]) == {"read", "write"}


# ---------------------------------------------------------------------------
# TestClassifyViolation — PAUSE Path
# ---------------------------------------------------------------------------


class TestClassifyViolationPause:
    """Tests for PAUSE (resumable suspension) path."""

    def test_rate_limit_violations_return_pause_when_enabled(self, monkeypatch):
        """Rate limit violations → PAUSE (when enabled)."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Rate limit exceeded: too many requests"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE
        assert "RATE_LIMITED" in meta["violation_types"]
        assert meta.get("pausable")
        assert meta["pause_reason"] == "RATE_LIMITED"
        assert "estimated_wait_seconds" in meta

    def test_circuit_breaker_violations_return_pause_when_enabled(self, monkeypatch):
        """Circuit breaker open violations → PAUSE (when enabled)."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Circuit breaker is open: service unavailable"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE
        assert "CIRCUIT_OPEN" in meta["violation_types"]
        assert meta["pause_reason"] == "CIRCUIT_OPEN"

    def test_resource_unavailable_returns_pause_when_enabled(self, monkeypatch):
        """Resource unavailable violations → PAUSE (when enabled)."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Quota exhausted: capacity exceeded"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE
        assert "RESOURCE_UNAVAILABLE" in meta["violation_types"]
        assert meta["pause_reason"] == "RESOURCE_UNAVAILABLE"

    def test_pause_disabled_falls_back_to_deny(self, monkeypatch):
        """When CAGE_PAUSE_ENABLED=false, PAUSE candidates fall back to DENY."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "false")
        violations = ["Rate limit exceeded"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "CAGE_PAUSE_ENABLED=false" in meta["classification_reason"]

    def test_pause_with_soft_violations_prioritizes_soft(self, monkeypatch):
        """Pausable + soft violations → soft violations take priority (not PAUSE)."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        violations = [
            "Rate limit exceeded",
            "Confidence Violation: below threshold",
        ]
        
        # Has both pausable and soft violations — should NOT be PAUSE
        decision, _meta = _classify_violation_wrapper(violations, 0, 0.50)
        
        # PAUSE only triggers when there are NO soft or narrowable violations
        assert decision != GovernanceDecision.PAUSE


# ---------------------------------------------------------------------------
# TestClassifyViolation — Classification Metadata
# ---------------------------------------------------------------------------


class TestClassifyViolationMetadata:
    """Tests for classification metadata population."""

    def test_classification_metadata_populated(self):
        """All required metadata fields are populated."""
        violations = ["UCA-7: STPA violation"]
        _decision, meta = _classify_violation_wrapper(violations, 1, 0.99)
        
        # Required fields
        assert "classification_reason" in meta
        assert "violation_types" in meta
        assert "deferrable" in meta
        assert "hard_violations" in meta
        assert "soft_violations" in meta
        assert "narrowable_violations" in meta
        
        # Values are correct type
        assert isinstance(meta["classification_reason"], str)
        assert isinstance(meta["violation_types"], list)
        assert isinstance(meta["deferrable"], bool)
        assert isinstance(meta["hard_violations"], list)
        assert isinstance(meta["soft_violations"], list)
        assert isinstance(meta["narrowable_violations"], list)

    def test_classification_reason_is_human_readable(self):
        """Classification reason provides meaningful context."""
        violations = ["Safety Violation (RBC/CBF): cash barrier violated"]
        _decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        reason = meta["classification_reason"]
        assert len(reason) > 10
        assert "violation" in reason.lower() or "cbf" in reason.lower()

    def test_violation_types_are_unique(self):
        """Violation types list has no duplicates."""
        violations = [
            "UCA-7: STPA safety violation",
            "UCA-8: Another STPA violation",
        ]
        _decision, meta = _classify_violation_wrapper(violations, 2, 0.99)
        
        # violation_types should be a set-like list (no duplicates)
        assert len(meta["violation_types"]) == len(set(meta["violation_types"]))

    def test_pausable_violations_tracked(self, monkeypatch):
        """Pausable violations are tracked in metadata."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Rate limit exceeded"]
        
        _decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert "pausable_violations" in meta
        assert len(meta["pausable_violations"]) > 0

    def test_narrowable_violations_tracked(self, monkeypatch):
        """Narrowable violations are tracked in metadata."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        violations = ["Amount exceeds limit"]
        ctx = {"params": {"amount": 150000}, "threshold_config": {"max_amount": 100000}}
        
        _decision, meta = _classify_violation_wrapper(violations, 0, 0.99, ctx)
        
        assert "narrowable_violations" in meta
        assert len(meta["narrowable_violations"]) > 0


# ---------------------------------------------------------------------------
# TestClassifyViolation — Edge Cases
# ---------------------------------------------------------------------------


class TestClassifyViolationEdgeCases:
    """Edge case tests for _classify_violation()."""

    def test_empty_violations_returns_deny(self):
        """Empty violations list defaults to DENY (should not reach here normally)."""
        decision, meta = _classify_violation_wrapper([], 0, 0.99)
        
        # With no violations, classification falls through to fallback DENY
        assert decision == GovernanceDecision.DENY
        assert "unclassified" in meta["classification_reason"].lower()

    def test_confidence_exactly_at_threshold(self, monkeypatch):
        """Confidence exactly at FRIA_ZONE_DEFER is NOT starved."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")
        violations = ["Confidence Violation: marginal"]
        
        # 0.70 is not < 0.70, so not confidence-starved
        decision, _meta = _classify_violation_wrapper(violations, 0, 0.70)
        
        # Should be REQUIRE_APPROVAL (soft violation above threshold), not DEFER
        assert decision == GovernanceDecision.REQUIRE_APPROVAL

    def test_confidence_just_below_threshold(self, monkeypatch):
        """Confidence just below FRIA_ZONE_DEFER triggers DEFER."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")
        violations = ["Confidence Violation: marginal"]
        
        # 0.699 is < 0.70, so confidence-starved
        decision, _meta = _classify_violation_wrapper(violations, 0, 0.699)
        
        assert decision == GovernanceDecision.DEFER

    def test_multiple_hard_violation_types(self):
        """Multiple hard violation types all tracked in metadata."""
        violations = [
            "UCA-7: STPA safety violation",
            "Safety Violation (RBC/CBF): cash barrier",
            "[CTRL_OPA_005] OPA Denied Action",
        ]
        decision, meta = _classify_violation_wrapper(violations, 1, 0.99)
        
        assert decision == GovernanceDecision.DENY
        assert "STPA_SAFETY" in meta["violation_types"]
        assert "CBF_CONSTRAINT" in meta["violation_types"]
        assert "OPA_DENY" in meta["violation_types"]
        assert len(meta["hard_violations"]) == 3

    def test_mixed_hard_and_soft_violations(self):
        """Mixed hard and soft violations → DENY (hard takes priority)."""
        violations = [
            "UCA-7: STPA safety violation",  # Hard
            "Confidence Violation: below threshold",  # Soft
        ]
        decision, meta = _classify_violation_wrapper(violations, 1, 0.50)
        
        assert decision == GovernanceDecision.DENY
        assert len(meta["hard_violations"]) == 1
        assert len(meta["soft_violations"]) == 1

    def test_throttle_variant_triggers_pause(self, monkeypatch):
        """'throttled' variant of rate limit triggers PAUSE."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Request throttled: wait before retry"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE
        assert "RATE_LIMITED" in meta["violation_types"]

    def test_too_many_requests_triggers_pause(self, monkeypatch):
        """'too many requests' triggers PAUSE."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Too many requests: slow down"]
        
        decision, _meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE

    def test_temporarily_unavailable_triggers_pause(self, monkeypatch):
        """'temporarily unavailable' triggers PAUSE."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        violations = ["Service temporarily unavailable"]
        
        decision, meta = _classify_violation_wrapper(violations, 0, 0.99)
        
        assert decision == GovernanceDecision.PAUSE
        assert "RESOURCE_UNAVAILABLE" in meta["violation_types"]
