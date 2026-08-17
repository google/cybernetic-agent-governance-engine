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

"""Tests for PII audit log — AI 600-1 §2.2 (Data Privacy).

POAM: AI600-002
Phase: 1 (quick wins)
"""

import re

import pytest

from src.gateway.governance.pii_sanitizer import pii_audit_log


class TestPiiAuditLog:
    """pii_audit_log must return correct schema and enforce invariants."""

    def test_returns_correct_event_type(self):
        """pii_audit_log returns event='pii_detected'."""
        record = pii_audit_log(
            trace_id="trace-001",
            entity_types=["PERSON", "EMAIL_ADDRESS"],
            redacted=True,
        )
        assert record["event"] == "pii_detected"

    def test_trace_id_in_record(self):
        """pii_audit_log includes the trace_id in the record."""
        record = pii_audit_log(
            trace_id="trace-xyz-456",
            entity_types=["PHONE_NUMBER"],
            redacted=True,
        )
        assert record["trace_id"] == "trace-xyz-456"

    def test_entity_types_preserved(self):
        """pii_audit_log preserves the entity_types list."""
        entity_types = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]
        record = pii_audit_log(
            trace_id="trace-002",
            entity_types=entity_types,
            redacted=True,
        )
        assert record["entity_types"] == entity_types

    def test_redacted_flag_true(self):
        """pii_audit_log records redacted=True correctly."""
        record = pii_audit_log(
            trace_id="trace-003",
            entity_types=["SSN"],
            redacted=True,
        )
        assert record["redacted"] is True

    def test_redacted_flag_false(self):
        """pii_audit_log records redacted=False correctly (detection without redaction)."""
        record = pii_audit_log(
            trace_id="trace-004",
            entity_types=["CREDIT_CARD"],
            redacted=False,
        )
        assert record["redacted"] is False

    def test_timestamp_is_iso8601_utc(self):
        """pii_audit_log timestamp is ISO 8601 UTC format ending with Z."""
        record = pii_audit_log(
            trace_id="trace-005",
            entity_types=["EMAIL_ADDRESS"],
            redacted=True,
        )
        timestamp = record["timestamp"]
        # Must end with Z (UTC indicator)
        assert timestamp.endswith("Z"), f"Timestamp must end with Z: {timestamp!r}"
        # Must be parseable as ISO 8601
        # Format: YYYY-MM-DDTHH:MM:SS.ffffffZ
        iso8601_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
        assert iso8601_pattern.match(timestamp), (
            f"Timestamp does not match ISO 8601 UTC format: {timestamp!r}"
        )

    def test_schema_has_all_required_fields(self):
        """pii_audit_log record has all required schema fields."""
        record = pii_audit_log(
            trace_id="trace-006",
            entity_types=["PERSON"],
            redacted=True,
        )
        required_fields = {"event", "trace_id", "entity_types", "redacted", "timestamp"}
        assert required_fields.issubset(record.keys())

    def test_entity_types_not_empty_when_redacted(self):
        """pii_audit_log raises ValueError when redacted=True but entity_types is empty."""
        with pytest.raises(ValueError, match="entity_types must not be empty"):
            pii_audit_log(
                trace_id="trace-007",
                entity_types=[],
                redacted=True,
            )

    def test_empty_entity_types_allowed_when_not_redacted(self):
        """pii_audit_log allows empty entity_types when redacted=False."""
        # This represents a scan that found no PII
        record = pii_audit_log(
            trace_id="trace-008",
            entity_types=[],
            redacted=False,
        )
        assert record["entity_types"] == []
        assert record["redacted"] is False

    def test_multiple_entity_types(self):
        """pii_audit_log handles multiple entity types correctly."""
        entity_types = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SSN", "CREDIT_CARD"]
        record = pii_audit_log(
            trace_id="trace-009",
            entity_types=entity_types,
            redacted=True,
        )
        assert len(record["entity_types"]) == 5
        assert "PERSON" in record["entity_types"]
        assert "SSN" in record["entity_types"]


class TestPiiAuditLogJurisdictionalRetentionAuthority:
    """FINDING-08 (MEDIUM): retention_authority citation must be jurisdiction-aware.

    pii_audit_log() previously cited "FISMA AU-11" unconditionally regardless
    of CAGE_DEPLOYMENT_REGION. These tests assert the correct regulatory
    citation is emitted per-region, with a universal ISO 42001 fallback.
    """

    def test_us_fed_cites_fisma_au11(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        record = pii_audit_log(trace_id="trace-us", entity_types=["SSN"], redacted=True)
        assert "FISMA AU-11" in record["retention_authority"]

    def test_eu_ecb_cites_gdpr(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        record = pii_audit_log(trace_id="trace-eu", entity_types=["SSN"], redacted=True)
        assert "GDPR" in record["retention_authority"]

    def test_apac_mas_cites_notice_655(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        record = pii_audit_log(
            trace_id="trace-apac", entity_types=["SSN"], redacted=True
        )
        assert "MAS Notice 655" in record["retention_authority"]

    def test_unset_region_falls_back_to_iso_42001(self, monkeypatch):
        monkeypatch.delenv("CAGE_DEPLOYMENT_REGION", raising=False)
        record = pii_audit_log(
            trace_id="trace-none", entity_types=["SSN"], redacted=True
        )
        assert "ISO 42001" in record["retention_authority"]

    def test_explicit_region_parameter_overrides_environment(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        record = pii_audit_log(
            trace_id="trace-explicit",
            entity_types=["SSN"],
            redacted=True,
            region="EU_ECB",
        )
        assert "GDPR" in record["retention_authority"]


pytestmark = [pytest.mark.unit, pytest.mark.local]
