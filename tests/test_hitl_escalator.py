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

"""Tests for HITL escalator — AI 600-1 §2.5 (Human-AI Configuration).

POAM: AI600-004
Phase: 2 (core hardening)
"""

import re

from src.gateway.governance.hitl_escalator import (
    EscalationReason,
    EscalationRequest,
    escalate_to_human,
    get_hitl_regulatory_citation,
    get_hitl_sla_hours,
    hitl_override_audit_span,
    should_escalate_for_confidence,
    should_escalate_for_consensus,
)


class TestEscalateToHuman:
    """escalate_to_human must return correct escalation record schema."""

    def test_event_type_is_hitl_escalation(self):
        """escalate_to_human returns event='hitl_escalation'."""
        request = EscalationRequest(
            trace_id="trace-001",
            reason=EscalationReason.CONSENSUS_THRESHOLD,
            amount_usd=15000.0,
            confidence=None,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        assert record["event"] == "hitl_escalation"

    def test_trace_id_in_record(self):
        """escalate_to_human includes trace_id in the record."""
        request = EscalationRequest(
            trace_id="trace-xyz-789",
            reason=EscalationReason.CONFIDENCE_LOW,
            amount_usd=None,
            confidence=0.80,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        assert record["trace_id"] == "trace-xyz-789"

    def test_reason_is_string_value(self):
        """escalate_to_human serialises reason as the enum value string."""
        request = EscalationRequest(
            trace_id="trace-002",
            reason=EscalationReason.CONSENSUS_THRESHOLD,
            amount_usd=20000.0,
            confidence=None,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        assert record["reason"] == "consensus_threshold_exceeded"

    def test_status_is_pending_review(self):
        """escalate_to_human sets status='pending_review'."""
        request = EscalationRequest(
            trace_id="trace-003",
            reason=EscalationReason.MANUAL_REVIEW,
            amount_usd=None,
            confidence=None,
            reviewer_queue="security-review",
        )
        record = escalate_to_human(request)
        assert record["status"] == "pending_review"

    def test_amount_usd_in_record(self):
        """escalate_to_human includes amount_usd in the record."""
        request = EscalationRequest(
            trace_id="trace-004",
            reason=EscalationReason.CONSENSUS_THRESHOLD,
            amount_usd=15000.0,
            confidence=None,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        assert record["amount_usd"] == 15000.0

    def test_confidence_in_record(self):
        """escalate_to_human includes confidence in the record."""
        request = EscalationRequest(
            trace_id="trace-005",
            reason=EscalationReason.CONFIDENCE_LOW,
            amount_usd=None,
            confidence=0.75,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        assert record["confidence"] == 0.75

    def test_reviewer_queue_in_record(self):
        """escalate_to_human includes reviewer_queue in the record."""
        request = EscalationRequest(
            trace_id="trace-006",
            reason=EscalationReason.CAUSAL_BLOCK,
            amount_usd=None,
            confidence=None,
            reviewer_queue="security-review",
        )
        record = escalate_to_human(request)
        assert record["reviewer_queue"] == "security-review"

    def test_timestamp_is_iso8601_utc(self):
        """escalate_to_human timestamp is ISO 8601 UTC format ending with Z."""
        request = EscalationRequest(
            trace_id="trace-007",
            reason=EscalationReason.CONSENSUS_THRESHOLD,
            amount_usd=12000.0,
            confidence=None,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        timestamp = record["timestamp"]
        assert timestamp.endswith("Z"), f"Timestamp must end with Z: {timestamp!r}"
        iso8601_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
        assert iso8601_pattern.match(timestamp)

    def test_schema_has_all_required_fields(self):
        """escalate_to_human record has all required schema fields."""
        request = EscalationRequest(
            trace_id="trace-008",
            reason=EscalationReason.GOVERNANCE_CONFIDENCE_LOW,
            amount_usd=None,
            confidence=0.88,
            reviewer_queue="compliance-review",
        )
        record = escalate_to_human(request)
        required_fields = {
            "event",
            "trace_id",
            "reason",
            "amount_usd",
            "confidence",
            "reviewer_queue",
            "status",
            "timestamp",
        }
        assert required_fields.issubset(record.keys())


class TestShouldEscalateForConsensus:
    """should_escalate_for_consensus must correctly apply the USD threshold."""

    def test_escalates_above_threshold(self):
        """Escalation fires when amount > threshold."""
        assert should_escalate_for_consensus(15000.0, threshold_usd=10000.0) is True

    def test_does_not_escalate_at_threshold(self):
        """Escalation does NOT fire when amount == threshold."""
        assert should_escalate_for_consensus(10000.0, threshold_usd=10000.0) is False

    def test_does_not_escalate_below_threshold(self):
        """Escalation does NOT fire when amount < threshold."""
        assert should_escalate_for_consensus(9999.99, threshold_usd=10000.0) is False

    def test_escalates_for_large_amount(self):
        """Escalation fires for very large amounts."""
        assert should_escalate_for_consensus(1_000_000.0, threshold_usd=10000.0) is True

    def test_default_threshold_is_10000(self):
        """Default threshold is USD 10,000 (US_FED baseline)."""
        assert should_escalate_for_consensus(10001.0) is True
        assert should_escalate_for_consensus(9999.0) is False


class TestShouldEscalateForConfidence:
    """should_escalate_for_confidence must correctly apply the confidence threshold."""

    def test_escalates_below_threshold(self):
        """Escalation fires when confidence < threshold."""
        assert should_escalate_for_confidence(0.80, threshold=0.95) is True

    def test_does_not_escalate_at_threshold(self):
        """Escalation does NOT fire when confidence == threshold."""
        assert should_escalate_for_confidence(0.95, threshold=0.95) is False

    def test_does_not_escalate_above_threshold(self):
        """Escalation does NOT fire when confidence > threshold."""
        assert should_escalate_for_confidence(0.99, threshold=0.95) is False

    def test_default_threshold_is_0_95(self):
        """Default threshold is 0.95 (CTRL_AGT_001)."""
        assert should_escalate_for_confidence(0.94) is True
        assert should_escalate_for_confidence(0.95) is False


class TestGetHitlSlaHours:
    """FINDING-09 (MEDIUM): HITL SLA must be jurisdiction-aware.

    The module previously declared "Region: US_FED" in its docstring only,
    with no runtime CAGE_DEPLOYMENT_REGION check.
    """

    def test_us_fed_sla_is_4_hours(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        assert get_hitl_sla_hours() == 4.0

    def test_eu_ecb_sla_is_2_hours(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        assert get_hitl_sla_hours() == 2.0

    def test_apac_mas_sla_is_1_hour(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        assert get_hitl_sla_hours() == 1.0

    def test_unset_region_falls_back_to_4_hours(self, monkeypatch):
        monkeypatch.delenv("CAGE_DEPLOYMENT_REGION", raising=False)
        assert get_hitl_sla_hours() == 4.0

    def test_explicit_region_parameter_overrides_environment(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        assert get_hitl_sla_hours(region="APAC_MAS") == 1.0


class TestGetHitlRegulatoryCitation:
    """FINDING-09 (MEDIUM): HITL regulatory citation must be jurisdiction-aware."""

    def test_us_fed_cites_sr_26_2(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        citation = get_hitl_regulatory_citation()
        assert "SR 26-2" in citation

    def test_eu_ecb_cites_dora(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        citation = get_hitl_regulatory_citation()
        assert "DORA" in citation

    def test_apac_mas_cites_mas_feat(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        citation = get_hitl_regulatory_citation()
        assert "MAS FEAT" in citation

    def test_unset_region_falls_back_to_iso_42001(self, monkeypatch):
        monkeypatch.delenv("CAGE_DEPLOYMENT_REGION", raising=False)
        citation = get_hitl_regulatory_citation()
        assert "ISO 42001" in citation


class TestHitlOverrideAuditSpan:
    """hitl_override_audit_span() must produce a complete, jurisdiction-aware
    audit record (AI600-005 / ISO 42001 §A.8.4)."""

    def test_returns_all_required_attributes(self):
        attrs = hitl_override_audit_span(
            trace_id="trace-100",
            reviewer_id="reviewer-123",
            decision="OVERRIDE",
            original_escalation_reason=EscalationReason.CONSENSUS_THRESHOLD.value,
            reason="Verified with client via phone.",
        )
        required = {
            "hitl.reviewer_id",
            "hitl.decision",
            "hitl.reason",
            "hitl.original_escalation_reason",
            "hitl.override_ts",
            "hitl.trace_id",
            "hitl.regulatory_citation",
            "langfuse.trace.metadata.iso.control_id",
            "langfuse.trace.metadata.iso.requirement",
            "langfuse.trace.metadata.poam_ref",
        }
        assert required.issubset(attrs.keys())
        assert attrs["hitl.decision"] == "OVERRIDE"
        assert attrs["hitl.trace_id"] == "trace-100"
        assert attrs["langfuse.trace.metadata.poam_ref"] == "AI600-005"
        assert attrs["langfuse.trace.metadata.iso.control_id"] == "A.8.4"

    def test_reason_truncated_to_500_chars(self):
        long_reason = "x" * 1000
        attrs = hitl_override_audit_span(
            trace_id="trace-101",
            reviewer_id="reviewer-456",
            decision="UPHOLD",
            original_escalation_reason=EscalationReason.CAUSAL_BLOCK.value,
            reason=long_reason,
        )
        assert len(attrs["hitl.reason"]) == 500

    def test_citation_reflects_region(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        attrs = hitl_override_audit_span(
            trace_id="trace-102",
            reviewer_id="reviewer-789",
            decision="DEFER",
            original_escalation_reason=EscalationReason.MANUAL_REVIEW.value,
        )
        assert "DORA" in attrs["hitl.regulatory_citation"]


class TestEscalationReasonEnum:
    """EscalationReason enum must have all required values."""

    def test_consensus_threshold_reason(self):
        """CONSENSUS_THRESHOLD reason has correct value."""
        assert (
            EscalationReason.CONSENSUS_THRESHOLD.value == "consensus_threshold_exceeded"
        )

    def test_confidence_low_reason(self):
        """CONFIDENCE_LOW reason has correct value."""
        assert EscalationReason.CONFIDENCE_LOW.value == "confidence_below_threshold"

    def test_causal_block_reason(self):
        """CAUSAL_BLOCK reason has correct value."""
        assert EscalationReason.CAUSAL_BLOCK.value == "causal_gatekeeper_block"

    def test_manual_review_reason(self):
        """MANUAL_REVIEW reason has correct value."""
        assert EscalationReason.MANUAL_REVIEW.value == "manual_review_requested"

    def test_governance_confidence_low_reason(self):
        """GOVERNANCE_CONFIDENCE_LOW reason has correct value (recursive governance risk)."""
        assert (
            EscalationReason.GOVERNANCE_CONFIDENCE_LOW.value
            == "governance_layer_confidence_below_threshold"
        )
