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

Tests verify the 6-step classification decision tree:
1. Hard violations → DENY
2. OPA MANUAL_REVIEW → REQUIRE_APPROVAL
3. HITL violations → REQUIRE_APPROVAL
4. Narrowable violations → NARROW (if narrower available) or DENY
5. Deferrable violations → DEFER (if low confidence) or DENY
6. Default fallback → DENY

There is no PAUSE step: ``ViolationKind`` has no TRANSIENT member and the
engine accepts no ``pause_enabled`` knob.
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


def test_engine_has_no_pause_knob():
    """The PAUSE path is gone: ``pause_enabled`` is not a constructor argument
    and the decision enum has no PAUSE member for it to return."""
    with pytest.raises(TypeError):
        ClassificationEngine(
            narrower_registry=NarrowerRegistry(),
            confidence_threshold=0.70,
            pause_enabled=True,  # type: ignore[call-arg]
        )
    assert not hasattr(GovernanceDecision, "PAUSE")
    assert not hasattr(ViolationKind, "TRANSIENT")


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
    # Give a HARD violation a message containing words that used to map to NARROW, HITL, DEFER
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


# ---------------------------------------------------------------------------
# Phase 3: bound-aware narrowing and the REQUIRE_APPROVAL narrow hint
# ---------------------------------------------------------------------------


class _ClampToBound:
    """Records what it was asked; clamps ``amount`` to ``violation.bound``."""

    def __init__(self) -> None:
        self.asked: list[Violation] = []

    def can_narrow(self, violation, action, params):
        return violation.narrowable and violation.bound is not None

    def narrow(self, violation, action, params):
        from src.gateway.governance.contracts import NarrowingResult

        self.asked.append(violation)
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": violation.bound},
            constraints_applied=[f"amount <= {violation.bound}"],
            narrowing_reason=f"clamped to {violation.tier}",
        )


def _v(
    kind: ViolationKind, tier: str = "fiscal", bound: float | None = None
) -> Violation:
    return Violation(
        tier=tier, code=f"{tier.upper()}_X", message="", kind=kind, bound=bound
    )


def _ctx(violations, opa_decision=None):
    return ClassificationContext(
        violations=violations,
        confidence=0.99,
        opa_decision=opa_decision,
        policy_ambiguous=False,
        params={"amount": 50_000.0},
    )


def _engine(narrower, *, narrow_enabled=True):
    return ClassificationEngine(
        narrower_registry=NarrowerRegistry(narrowers=[narrower]),
        narrow_enabled=narrow_enabled,
    )


def test_narrow_resolves_the_tightest_bound_first():
    narrower = _ClampToBound()
    loose = _v(ViolationKind.NARROWABLE, "cap_a", bound=40_000.0)
    tight = _v(ViolationKind.NARROWABLE, "cap_b", bound=3_000.0)
    unbounded = _v(ViolationKind.NARROWABLE, "cap_c")

    result = _engine(narrower).classify(
        _ctx([unbounded, loose, tight]), "execute_trade"
    )

    assert result.decision == GovernanceDecision.NARROW
    assert result.metadata["narrowed_params"]["amount"] == 3_000.0
    assert narrower.asked == [tight]


def test_narrower_returning_none_falls_through_to_deny():
    class _Declines(_ClampToBound):
        def narrow(self, violation, action, params):
            return None

    result = _engine(_Declines()).classify(
        _ctx([_v(ViolationKind.NARROWABLE, bound=1.0)]), "execute_trade"
    )
    assert result.decision == GovernanceDecision.DENY


@pytest.mark.parametrize("opa_decision", [None, "MANUAL_REVIEW"])
def test_require_approval_carries_a_hint_when_the_rest_is_narrowable(opa_decision):
    violations = [
        _v(ViolationKind.HITL, "ftra"),
        _v(ViolationKind.NARROWABLE, bound=10_000.0),
    ]
    result = _engine(_ClampToBound()).classify(
        _ctx(violations, opa_decision), "execute_trade"
    )

    assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
    assert result.metadata["narrow_hint"]["narrowed_params"]["amount"] == 10_000.0


@pytest.mark.parametrize(
    "violations",
    [
        [_v(ViolationKind.HITL, "ftra")],  # nothing to narrow
        [
            _v(ViolationKind.HITL, "ftra"),
            _v(ViolationKind.NARROWABLE, bound=1.0),
            _v(ViolationKind.DEFERRABLE, "conf"),
        ],
    ],
    ids=["hitl-only", "mixed-non-narrowable"],
)
def test_require_approval_offers_no_hint_unless_every_other_finding_is_narrowable(
    violations,
):
    narrower = _ClampToBound()
    result = _engine(narrower).classify(_ctx(violations), "execute_trade")
    assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
    assert "narrow_hint" not in result.metadata
    assert narrower.asked == []


def test_require_approval_offers_no_hint_when_narrowing_is_disabled():
    narrower = _ClampToBound()
    violations = [
        _v(ViolationKind.HITL, "ftra"),
        _v(ViolationKind.NARROWABLE, bound=1.0),
    ]
    result = _engine(narrower, narrow_enabled=False).classify(
        _ctx(violations), "execute_trade"
    )
    assert "narrow_hint" not in result.metadata
    assert narrower.asked == []
