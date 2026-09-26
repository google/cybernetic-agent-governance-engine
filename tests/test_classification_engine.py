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

"""Unit tests for ClassificationEngine decision routing logic.

Tests verify the 7-step classification decision tree:
1. Hard violations → DENY
2. OPA MANUAL_REVIEW → REQUIRE_APPROVAL
3. HITL violations → REQUIRE_APPROVAL
4. Transient violations → PAUSE (if enabled) or DENY
5. Narrowable violations → NARROW (if narrower available) or DENY
6. Deferrable violations → DEFER (if low confidence) or DENY
7. Default fallback → DENY
"""

import pytest

from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
)
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.narrower import NarrowerRegistry

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_hard_violation_returns_deny():
    """Hard violations always return DENY regardless of other factors."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test hard violation",
                kind=ViolationKind.HARD,
            )
        ],
        confidence=0.99,  # High confidence
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "hard_violation"
    assert result.metadata["deferrable"] is False


def test_opa_manual_review_returns_require_approval():
    """OPA MANUAL_REVIEW decision returns REQUIRE_APPROVAL."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test violation",
                kind=ViolationKind.DEFERRABLE,
            )
        ],
        confidence=0.85,
        opa_decision="MANUAL_REVIEW",
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
    assert result.metadata["classification_reason"] == "opa_manual_review"


def test_hitl_violation_returns_require_approval():
    """HITL violations return REQUIRE_APPROVAL."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test HITL violation",
                kind=ViolationKind.HITL,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
    assert result.metadata["classification_reason"] == "hitl_required"


def test_transient_with_pause_enabled_returns_pause():
    """Transient violations with pause_enabled=True return PAUSE."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
        pause_enabled=True,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test transient violation",
                kind=ViolationKind.TRANSIENT,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.PAUSE
    assert result.metadata["classification_reason"] == "transient_condition"


def test_transient_with_pause_disabled_returns_deny():
    """Transient violations with pause_enabled=False fall back to DENY."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
        pause_enabled=False,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test transient violation",
                kind=ViolationKind.TRANSIENT,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "transient_disabled_fallback"


def test_narrowable_with_narrower_available_returns_narrow():
    """Narrowable violations with registered narrower return NARROW."""
    from src.gateway.governance.narrower import NarrowingResult
    
    # Create a test narrower class
    class TestNarrower:
        def can_narrow(self, violation, action, params):
            return action == "test_action"
        
        def narrow(self, violation, action, params):
            return NarrowingResult(
                can_narrow=True,
                narrowed_params={"narrowed": True},
                constraints_applied=["test"],
                narrowing_reason="Test narrowing",
            )
    
    registry = NarrowerRegistry()
    registry.register(TestNarrower())

    engine = ClassificationEngine(
        narrower_registry=registry,
        confidence_threshold=0.70,
        narrow_enabled=True,  # Must enable narrowing
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test narrowable violation",
                kind=ViolationKind.NARROWABLE,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={"original": "value"},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.NARROW
    assert result.metadata["classification_reason"] == "narrowable_resolved"
    assert result.metadata["narrowed_params"] == {"narrowed": True}


def test_narrowable_without_narrower_returns_deny():
    """Narrowable violations without registered narrower fall back to DENY.
    
    When narrow_enabled=True but no narrower is registered, or when
    narrow_enabled=False, NARROWABLE violations fall through to default_deny.
    """
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),  # Empty registry
        confidence_threshold=0.70,
        narrow_enabled=True,  # Enable narrowing, but no narrower registered
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test narrowable violation",
                kind=ViolationKind.NARROWABLE,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "default_deny"


def test_deferrable_with_low_confidence_returns_defer():
    """Deferrable violations with confidence below threshold return DEFER."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test deferrable violation",
                kind=ViolationKind.DEFERRABLE,
            )
        ],
        confidence=0.65,  # Below threshold
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DEFER
    assert result.metadata["classification_reason"] == "confidence_below_threshold"
    assert result.metadata["deferrable"] is True


def test_deferrable_with_high_confidence_returns_deny():
    """Deferrable violations with confidence above threshold fall back to DENY.
    
    High-confidence deferrables don't trigger the DEFER path and fall through
    to the default DENY decision.
    """
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test deferrable violation",
                kind=ViolationKind.DEFERRABLE,
            )
        ],
        confidence=0.85,  # Above threshold
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "default_deny"
    assert result.metadata["deferrable"] is False


def test_default_fallback_returns_deny():
    """Violations that don't match specific routing rules fall back to DENY.
    
    When defer_enabled=False, even low-confidence DEFERRABLE violations
    will fall through to the default_deny path.
    """
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
        defer_enabled=False,  # Disable defer to reach default path
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST",
                message="Test deferrable violation",
                kind=ViolationKind.DEFERRABLE,
            )
        ],
        confidence=0.65,  # Below threshold, but defer disabled
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "default_deny"
    assert result.metadata["deferrable"] is False


def test_multiple_violations_prioritize_hard():
    """Multiple violations prioritize HARD over other kinds."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )

    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="TEST1",
                message="Deferrable violation",
                kind=ViolationKind.DEFERRABLE,
            ),
            Violation(
                tier="test",
                code="TEST2",
                message="Hard violation",
                kind=ViolationKind.HARD,
            ),
        ],
        confidence=0.65,  # Would trigger DEFER for deferrable
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )

    result = engine.classify(context, "test_action")

    # HARD should take precedence
    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "hard_violation"

def test_string_input_raises_typeerror():
    """Passing a string violation raises TypeError."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )
    context = ClassificationContext(
        violations=["this is a string violation"],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )
    import pytest
    with pytest.raises(TypeError, match="classify.. received string violation"):
        engine.classify(context, "test_action")

def test_adversarial_messages_do_not_override_hard_kind():
    """HARD violations whose message contains softer keywords still yield DENY."""
    engine = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=0.70,
    )
    # Give a HARD violation a message containing words that used to map to NARROW, TRANSIENT, HITL, DEFER
    context = ClassificationContext(
        violations=[
            Violation(
                tier="test",
                code="ADVERSARIAL",
                message="amount exceeds max rate limit Manual Review Required confidence",
                kind=ViolationKind.HARD,
            )
        ],
        confidence=0.85,
        opa_decision=None,
        policy_ambiguous=False,
        params={},
    )
    result = engine.classify(context, "test_action")
    assert result.decision == GovernanceDecision.DENY
    assert result.metadata["classification_reason"] == "hard_violation"
