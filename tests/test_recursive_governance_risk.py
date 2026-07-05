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
Tests for Recursive Governance Risk Mitigation — AI 600-1 §2.1, §2.5.3
(POAM AI600-001 secondary).

The ConsensusEngine uses LLM inference to govern LLM outputs — creating a
recursive governance risk where confabulation in the governance layer
propagates to the governed system.  These tests verify that:

1. A governance LLM call with confidence < 0.95 triggers HITL escalation
   (via should_escalate_for_confidence).
2. A governance LLM call with confidence >= 0.95 proceeds normally (no
   escalation).
3. The governance confidence check is independent of the advisor confidence
   check — both thresholds are evaluated separately.
4. EscalationReason.GOVERNANCE_CONFIDENCE_LOW is the correct reason code
   for governance-layer low-confidence escalations.
5. The AGENTIC_SCOPE_STATEMENT.md documents the recursive governance risk.
"""

from __future__ import annotations

import pathlib

import pytest

pytest.importorskip("src", reason="src package required")

from src.gateway.governance.hitl_escalator import (
    EscalationReason,
    EscalationRequest,
    escalate_to_human,
    should_escalate_for_confidence,
)
from src.gateway.governance.confabulation_scorer import (
    is_confabulation_blocked,
    CONFIDENCE_THRESHOLD,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AI 600-1 §2.5.3 — governance layer confidence threshold
GOVERNANCE_CONFIDENCE_THRESHOLD = 0.95

# Advisor-layer confidence threshold (same value, independent check)
ADVISOR_CONFIDENCE_THRESHOLD = CONFIDENCE_THRESHOLD

SCOPE_STATEMENT_PATH = pathlib.Path("docs/governance/AGENTIC_SCOPE_STATEMENT.md")


# ---------------------------------------------------------------------------
# §7.3 — Governance layer confidence check
# ---------------------------------------------------------------------------

class TestGovernanceLayerConfidenceCheck:
    """Verify governance LLM confidence triggers HITL when below threshold."""

    def test_low_governance_confidence_triggers_escalation(self):
        """Governance LLM confidence < 0.95 must trigger HITL escalation."""
        governance_confidence = 0.80  # below threshold
        result = should_escalate_for_confidence(
            governance_confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is True, (
            f"Expected HITL escalation for governance confidence "
            f"{governance_confidence} < {GOVERNANCE_CONFIDENCE_THRESHOLD}"
        )

    def test_boundary_governance_confidence_triggers_escalation(self):
        """Governance confidence exactly at threshold boundary (0.949) must escalate."""
        governance_confidence = 0.949
        result = should_escalate_for_confidence(
            governance_confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is True, (
            f"Expected escalation at boundary confidence {governance_confidence}"
        )

    def test_high_governance_confidence_no_escalation(self):
        """Governance LLM confidence >= 0.95 must NOT trigger HITL escalation."""
        governance_confidence = 0.95  # at threshold — should not escalate
        result = should_escalate_for_confidence(
            governance_confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is False, (
            f"Expected no escalation for governance confidence "
            f"{governance_confidence} >= {GOVERNANCE_CONFIDENCE_THRESHOLD}"
        )

    def test_perfect_governance_confidence_no_escalation(self):
        """Governance LLM confidence = 1.0 must not trigger escalation."""
        result = should_escalate_for_confidence(
            1.0,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is False

    @pytest.mark.parametrize("confidence", [0.0, 0.10, 0.50, 0.80, 0.94])
    def test_various_low_confidences_trigger_escalation(self, confidence: float):
        """All confidence values below 0.95 must trigger escalation."""
        result = should_escalate_for_confidence(
            confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is True, (
            f"Expected escalation for governance confidence {confidence}"
        )

    @pytest.mark.parametrize("confidence", [0.95, 0.96, 0.99, 1.0])
    def test_various_high_confidences_no_escalation(self, confidence: float):
        """All confidence values >= 0.95 must not trigger escalation."""
        result = should_escalate_for_confidence(
            confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )
        assert result is False, (
            f"Expected no escalation for governance confidence {confidence}"
        )


# ---------------------------------------------------------------------------
# §7.3 — Governance confidence check is independent of advisor check
# ---------------------------------------------------------------------------

class TestGovernanceAdvisorIndependence:
    """Verify governance and advisor confidence checks are independent."""

    def test_high_advisor_low_governance_escalates(self):
        """High advisor confidence + low governance confidence must escalate."""
        advisor_confidence = 0.99   # advisor is fine
        governance_confidence = 0.70  # governance layer is uncertain

        advisor_escalates = should_escalate_for_confidence(
            advisor_confidence,
            threshold=ADVISOR_CONFIDENCE_THRESHOLD,
        )
        governance_escalates = should_escalate_for_confidence(
            governance_confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )

        assert advisor_escalates is False, (
            "Advisor with high confidence should not escalate"
        )
        assert governance_escalates is True, (
            "Governance layer with low confidence must escalate independently"
        )

    def test_low_advisor_high_governance_escalates_on_advisor(self):
        """Low advisor confidence + high governance confidence: advisor escalates."""
        advisor_confidence = 0.60   # advisor is uncertain
        governance_confidence = 0.98  # governance layer is confident

        advisor_escalates = should_escalate_for_confidence(
            advisor_confidence,
            threshold=ADVISOR_CONFIDENCE_THRESHOLD,
        )
        governance_escalates = should_escalate_for_confidence(
            governance_confidence,
            threshold=GOVERNANCE_CONFIDENCE_THRESHOLD,
        )

        assert advisor_escalates is True, (
            "Advisor with low confidence must escalate"
        )
        assert governance_escalates is False, (
            "Governance layer with high confidence should not escalate"
        )

    def test_both_low_confidence_both_escalate(self):
        """Both advisor and governance low confidence: both must escalate."""
        advisor_confidence = 0.50
        governance_confidence = 0.60

        assert should_escalate_for_confidence(
            advisor_confidence, threshold=ADVISOR_CONFIDENCE_THRESHOLD
        ) is True
        assert should_escalate_for_confidence(
            governance_confidence, threshold=GOVERNANCE_CONFIDENCE_THRESHOLD
        ) is True

    def test_both_high_confidence_neither_escalates(self):
        """Both advisor and governance high confidence: neither escalates."""
        advisor_confidence = 0.97
        governance_confidence = 0.99

        assert should_escalate_for_confidence(
            advisor_confidence, threshold=ADVISOR_CONFIDENCE_THRESHOLD
        ) is False
        assert should_escalate_for_confidence(
            governance_confidence, threshold=GOVERNANCE_CONFIDENCE_THRESHOLD
        ) is False

    def test_advisor_confabulation_block_independent_of_governance(self):
        """is_confabulation_blocked() for advisor is independent of governance check."""
        # Advisor blocked (confabulation risk)
        assert is_confabulation_blocked(0.50) is True
        # Governance layer at high confidence — independent check
        assert should_escalate_for_confidence(
            0.98, threshold=GOVERNANCE_CONFIDENCE_THRESHOLD
        ) is False


# ---------------------------------------------------------------------------
# §7.3 — EscalationReason.GOVERNANCE_CONFIDENCE_LOW
# ---------------------------------------------------------------------------

class TestGovernanceEscalationReason:
    """Verify GOVERNANCE_CONFIDENCE_LOW is the correct escalation reason code."""

    def test_governance_confidence_low_reason_exists(self):
        """EscalationReason.GOVERNANCE_CONFIDENCE_LOW must be defined."""
        assert hasattr(EscalationReason, "GOVERNANCE_CONFIDENCE_LOW"), (
            "EscalationReason.GOVERNANCE_CONFIDENCE_LOW not defined — "
            "add it to src/gateway/governance/hitl_escalator.py"
        )

    def test_governance_confidence_low_reason_value(self):
        """GOVERNANCE_CONFIDENCE_LOW must have the correct string value."""
        reason = EscalationReason.GOVERNANCE_CONFIDENCE_LOW
        assert reason.value == "governance_layer_confidence_below_threshold", (
            f"Unexpected value: {reason.value!r}"
        )

    def test_escalate_to_human_with_governance_reason(self):
        """escalate_to_human() must accept GOVERNANCE_CONFIDENCE_LOW reason."""
        request = EscalationRequest(
            trace_id="gov-risk-test-001",
            reason=EscalationReason.GOVERNANCE_CONFIDENCE_LOW,
            confidence=0.70,
        )
        record = escalate_to_human(request)

        assert record["trace_id"] == "gov-risk-test-001"
        assert record["reason"] == "governance_layer_confidence_below_threshold"
        assert record["status"] == "pending_review"

    def test_escalation_record_contains_confidence(self):
        """Escalation record for governance risk must include confidence value."""
        request = EscalationRequest(
            trace_id="gov-risk-test-002",
            reason=EscalationReason.GOVERNANCE_CONFIDENCE_LOW,
            confidence=0.65,
        )
        record = escalate_to_human(request)
        assert record.get("confidence") == 0.65, (
            "Escalation record must include the governance confidence value"
        )

    def test_escalation_record_has_timestamp(self):
        """Escalation record must include an ISO 8601 timestamp."""
        import re
        request = EscalationRequest(
            trace_id="gov-risk-test-003",
            reason=EscalationReason.GOVERNANCE_CONFIDENCE_LOW,
            confidence=0.72,
        )
        record = escalate_to_human(request)
        ts = record.get("escalated_at", "")
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts), (
            f"escalated_at is not ISO 8601: {ts!r}"
        )


# ---------------------------------------------------------------------------
# §7.3 — Agentic scope statement documents recursive governance risk
# ---------------------------------------------------------------------------

class TestRecursiveGovernanceRiskDocumented:
    """Verify docs/AGENTIC_SCOPE_STATEMENT.md documents recursive governance risk."""

    def test_scope_statement_exists(self):
        """docs/AGENTIC_SCOPE_STATEMENT.md must exist."""
        assert SCOPE_STATEMENT_PATH.exists(), (
            f"Agentic scope statement not found at {SCOPE_STATEMENT_PATH}"
        )

    def test_scope_statement_mentions_recursive_governance(self):
        """Scope statement must mention recursive governance risk."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        assert "recursive" in content.lower() or "Recursive" in content, (
            "docs/AGENTIC_SCOPE_STATEMENT.md does not document recursive governance risk"
        )

    def test_scope_statement_mentions_consensus_engine(self):
        """Scope statement must reference ConsensusEngine in governance risk context."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        assert "ConsensusEngine" in content or "consensus" in content.lower(), (
            "docs/AGENTIC_SCOPE_STATEMENT.md does not reference ConsensusEngine"
        )

    def test_scope_statement_mentions_ai600_section(self):
        """Scope statement must reference AI 600-1 §2.1 or §2.5."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        has_ref = (
            "AI 600-1" in content
            or "§2.1" in content
            or "§2.5" in content
            or "600-1" in content
        )
        assert has_ref, (
            "docs/AGENTIC_SCOPE_STATEMENT.md does not reference AI 600-1 §2.1/§2.5"
        )
