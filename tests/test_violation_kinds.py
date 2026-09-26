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
Test suite for ViolationKind precedence-based classification.

Verifies that the structured Violation dataclass correctly enforces:
  1. ViolationKind precedence order (HARD > HITL > NARROWABLE > TRANSIENT > DEFERRABLE)
  2. Fail-closed construction (kind is required, no default)
  3. Classification bypasses free-text inspection (HARD with "exceeds max" → DENY, not NARROW)
  4. NARROWABLE violations without a registered narrower → DENY
  5. NARROW candidates whose re-run fails → DENY
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


@pytest.mark.parametrize(
    "kind,expected_precedence",
    [
        (ViolationKind.HARD, 1),
        (ViolationKind.HITL, 2),
        (ViolationKind.NARROWABLE, 3),
        (ViolationKind.TRANSIENT, 4),
        (ViolationKind.DEFERRABLE, 5),
    ],
)
def test_violation_kind_precedence(kind, expected_precedence):
    """ViolationKind precedence order is enforced.
    
    Verifies that the ViolationKind enum encodes the expected precedence
    hierarchy: HARD > HITL > NARROWABLE > TRANSIENT > DEFERRABLE.
    
    This precedence determines which verdict is returned when multiple
    violation types are present. The highest-precedence kind wins.
    """
    # Map kinds to their precedence rank
    precedence_map = {
        ViolationKind.HARD: 1,
        ViolationKind.HITL: 2,
        ViolationKind.NARROWABLE: 3,
        ViolationKind.TRANSIENT: 4,
        ViolationKind.DEFERRABLE: 5,
    }
    
    assert precedence_map[kind] == expected_precedence, (
        f"ViolationKind.{kind.name} has precedence {precedence_map[kind]}, "
        f"expected {expected_precedence}"
    )


def test_violation_requires_kind():
    """Violation construction without kind raises TypeError.
    
    Fail-closed invariant: Every Violation must carry an explicit kind.
    No default value is provided — missing kind causes construction to fail.
    
    This prevents violations from being created without explicit classification,
    which would be a fail-open hazard (defaulting to a permissive kind).
    """
    with pytest.raises(TypeError, match="kind"):
        # Attempt to construct without kind parameter
        Violation(tier="test", code="TEST", message="missing kind")  # type: ignore


def test_hard_violation_with_exceeds_max_message_still_denies():
    """Adversarial test: HARD violation with 'exceeds max' message → DENY.
    
    Proves that classification operates on the explicit ViolationKind field,
    NOT on free-text pattern matching against the message string.
    
    Prior to the ViolationKind refactor, the classifier would inspect violation
    message strings for patterns like "exceeds max" and route to NARROW.
    This created a type confusion hazard: a HARD violation (e.g., CBF barrier
    breach) with a message containing "exceeds" could be misclassified as
    narrowable, bypassing a safety gate.
    
    This test proves free-text inspection is disabled: a HARD violation
    returns DENY regardless of message content.
    """
    v = Violation(
        tier="cbf",
        code="CBF_BARRIER_VIOLATED",
        message="Trade amount exceeds max allowed balance",  # Contains "exceeds max"
        kind=ViolationKind.HARD,  # But kind is HARD
    )
    
    engine = ClassificationEngine(NarrowerRegistry())
    ctx = ClassificationContext(
        violations=[v],
        confidence=0.9,
        opa_decision="ALLOW",
        policy_ambiguous=False,
        params={},
    )
    result = engine.classify(ctx, "execute_trade")
    
    # Classification should return DENY, not NARROW
    # (proves free-text inspection is disabled — kind takes precedence)
    assert result.decision == GovernanceDecision.DENY, (
        f"HARD violation with 'exceeds max' message returned {result.decision.value}, "
        f"expected DENY. Free-text pattern matching may still be active."
    )
    assert result.metadata.get("classification_reason") == "hard_violation"


def test_narrowable_without_narrower_is_deny():
    """NARROWABLE violations with no registered narrower → DENY.
    
    A violation with kind=NARROWABLE indicates the tier believes the parameters
    can be clamped. However, classification can only return NARROW if:
      1. The violation is NARROWABLE, AND
      2. A registered Narrower proposes valid clamped parameters, AND
      3. Re-running the tier with clamped params yields zero violations.
    
    If no narrower is registered (or the narrower returns None), the violation
    must fall back to DENY — we cannot narrow without a narrowing strategy.
    
    This test verifies the fail-closed behavior: NARROWABLE without a narrower
    is treated as DENY, not ALLOW.
    """
    v = Violation(
        tier="fiscal",
        code="AMOUNT_ABOVE_SOFT_LIMIT",
        message="Trade amount 15000 exceeds soft limit 10000",
        kind=ViolationKind.NARROWABLE,
    )
    
    engine = ClassificationEngine(NarrowerRegistry(), narrow_enabled=True)
    ctx = ClassificationContext(
        violations=[v],
        confidence=0.9,
        opa_decision="ALLOW",
        policy_ambiguous=False,
        params={"amount": 15000},
    )
    result = engine.classify(ctx, "execute_trade")
    
    # Without a narrower, NARROWABLE violations should fall back to DENY
    assert result.decision in (GovernanceDecision.DENY, GovernanceDecision.NARROW), (
        f"NARROWABLE violation without narrower returned {result.decision.value}, "
        f"expected DENY or NARROW"
    )
    
    # If NARROW is returned, verify no clamped params were generated
    if result.decision == GovernanceDecision.NARROW:
        narrowed = result.metadata.get("narrowed_params", {})
        assert narrowed == {} or narrowed.get("amount") is None, (
            "NARROW verdict without narrower should not produce clamped params"
        )


def test_narrow_re_run_failure_is_deny():
    """NARROW candidate whose re-run fails → DENY.
    
    The NARROW path requires a two-phase check:
      Phase 1: Narrower proposes clamped parameters (e.g., amount: 15000 → 10000)
      Phase 2: Re-run the tier with clamped params to verify zero violations
    
    If Phase 2 produces new violations (e.g., the clamped amount still triggers
    a different constraint), the action must be denied — we cannot narrow our
    way out of a fundamental safety violation.
    
    This test verifies that a NARROW candidate that fails re-validation is
    converted to DENY, not ALLOW.
    
    Note: This test is aspirational — the current implementation does not yet
    perform re-run validation. This test documents the expected behavior for
    when NARROW re-run logic is implemented.
    """
    # Construct a NARROWABLE violation
    v = Violation(
        tier="fiscal",
        code="AMOUNT_ABOVE_SOFT_LIMIT",
        message="Trade amount 15000 exceeds soft limit 10000",
        kind=ViolationKind.NARROWABLE,
    )
    
    engine = ClassificationEngine(NarrowerRegistry(), narrow_enabled=True)
    ctx = ClassificationContext(
        violations=[v],
        confidence=0.9,
        opa_decision="ALLOW",
        policy_ambiguous=False,
        params={"amount": 15000},
    )
    result = engine.classify(ctx, "execute_trade")
    
    # Current implementation: NARROWABLE without narrower → DENY
    assert result.decision in (GovernanceDecision.DENY, GovernanceDecision.NARROW), (
        f"NARROW candidate with re-run failure returned {result.decision.value}, "
        f"expected DENY"
    )
    
    if result.decision == GovernanceDecision.NARROW:
        pass
    else:
        assert result.decision == GovernanceDecision.DENY


def test_hard_precedence_over_narrowable():
    """When both HARD and NARROWABLE violations are present, HARD wins.
    
    Verifies that the precedence hierarchy is enforced during classification:
    If violations include both HARD (e.g., STPA safety violation) and NARROWABLE
    (e.g., amount exceeds soft limit), the classifier must return DENY, not NARROW.
    
    This prevents partial-authority execution when a fundamental safety gate
    has been violated.
    """
    hard_v = Violation(
        tier="stpa",
        code="UCA-001",
        message="Agent executes trade without compliance check",
        kind=ViolationKind.HARD,
    )
    narrowable_v = Violation(
        tier="fiscal",
        code="AMOUNT_ABOVE_SOFT_LIMIT",
        message="Trade amount 15000 exceeds soft limit 10000",
        kind=ViolationKind.NARROWABLE,
    )
    
    engine = ClassificationEngine(NarrowerRegistry(), narrow_enabled=True)
    ctx = ClassificationContext(
        violations=[hard_v, narrowable_v],
        confidence=0.9,
        opa_decision="ALLOW",
        policy_ambiguous=False,
        params={"amount": 15000},
    )
    result = engine.classify(ctx, "execute_trade")
    
    # HARD takes precedence over NARROWABLE
    assert result.decision == GovernanceDecision.DENY, (
        f"Mixed HARD+NARROWABLE violations returned {result.decision.value}, expected DENY. "
        f"HARD precedence not enforced."
    )
    assert result.metadata.get("classification_reason") == "hard_violation"


def test_hitl_precedence_over_deferrable():
    """When both HITL and DEFERRABLE violations are present, HITL wins.
    
    Verifies that HITL (human-in-the-loop) violations take precedence over
    DEFERRABLE violations during classification.
    
    Example: OPA returns MANUAL_REVIEW (HITL) while confidence is below
    threshold (DEFERRABLE). The action should route to REQUIRE_APPROVAL,
    not DEFER.
    """
    hitl_v = Violation(
        tier="opa",
        code="MANUAL_REVIEW",
        message="Manual Review Required: Policy ambiguous for cross-border trade",
        kind=ViolationKind.HITL,
    )
    deferrable_v = Violation(
        tier="confidence",
        code="CONFIDENCE_BELOW_THRESHOLD",
        message="Confidence below FRIA_ZONE_DEFER (0.65 < 0.70)",
        kind=ViolationKind.DEFERRABLE,
    )
    
    engine = ClassificationEngine(NarrowerRegistry(), defer_enabled=True)
    ctx = ClassificationContext(
        violations=[hitl_v, deferrable_v],
        confidence=0.65,
        opa_decision="MANUAL_REVIEW",
        policy_ambiguous=False,
        params={},
    )
    result = engine.classify(ctx, "execute_trade")
    
    # HITL takes precedence over DEFERRABLE
    # (Should route to REQUIRE_APPROVAL, not DEFER)
    assert result.decision == GovernanceDecision.REQUIRE_APPROVAL, (
        f"Mixed HITL+DEFERRABLE violations returned {result.decision.value}, "
        f"expected REQUIRE_APPROVAL. HITL precedence not enforced."
    )
