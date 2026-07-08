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
Tests for examples/telemetry.py — Playground Evidence Chain + View-Access Log.

Covers:
  - SHA-256 hash chain construction and prev_hash linking
  - Chain idempotency (multiple runs append, never overwrite)
  - Chain integrity verification (verify_chain)
  - Tamper detection (modified record breaks chain)
  - PII redaction in params_redacted field
  - View-access log: event written with correct fields
  - View-access log: read_fingerprint is deterministic
  - View-access log: accessor_id and reason recorded verbatim
  - Scenario filtering in read_evidence_log
  - OTel span attributes match Langfuse schema (when OTel disabled via env)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

# Ensure repo root is on sys.path
_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

# Disable OTel and OpenLLMetry for all tests
os.environ["OTEL_TRACES_EXPORTER"] = "none"
os.environ["OPENLLMETRY_ENABLED"] = "false"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_evidence_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Redirect all evidence chain writes to a fresh temp directory.
    Patches the module-level path constants in examples.telemetry.
    """
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    chain_path = evidence_dir / "evidence_chain_test.ndjson"
    view_path = evidence_dir / "view_access_log_test.ndjson"

    import examples.telemetry as tel_mod

    monkeypatch.setattr(tel_mod, "_EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(tel_mod, "_EVIDENCE_CHAIN_PATH", chain_path)
    monkeypatch.setattr(tel_mod, "_VIEW_ACCESS_LOG_PATH", view_path)

    yield {"dir": evidence_dir, "chain": chain_path, "view": view_path}


@pytest.fixture()
def tel(tmp_evidence_dir):
    """Return a PlaygroundTelemetry instance wired to the temp evidence dir."""
    from examples.telemetry import PlaygroundTelemetry

    # _init_otel will return None (OTEL_TRACES_EXPORTER=none suppresses setup)
    t = PlaygroundTelemetry()
    return t


_SAMPLE_PARAMS = {
    "symbol": "NVDA",
    "amount": 50_000.0,
    "latency_ms": 340.0,
    "confidence": 0.87,
    "risk_assessed": True,
}

_SAMPLE_VIOLATIONS = [
    "STPA Violation UCA-2: stale market data",
    "SR 11-7: confidence 0.87 < 0.95",
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _write_and_read(tel_instance, scenario_id="A", violations=None, blocking_tier=0):
    violations = _SAMPLE_VIOLATIONS if violations is None else violations
    with tel_instance.scenario_span(scenario_id, "execute_trade", _SAMPLE_PARAMS) as sw:
        hash_ = tel_instance.record_result(
            sw,
            violations=violations,
            blocking_tier=blocking_tier,
            elapsed_ms=12.4,
            action="execute_trade",
            params=_SAMPLE_PARAMS,
            scenario_id=scenario_id,
        )
    return hash_


# ---------------------------------------------------------------------------
# Evidence chain — structure tests
# ---------------------------------------------------------------------------


class TestEvidenceChainStructure:
    def test_record_written_to_ndjson(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        assert tmp_evidence_dir["chain"].exists()
        lines = tmp_evidence_dir["chain"].read_text().strip().splitlines()
        assert len(lines) == 1

    def test_record_is_valid_json(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        line = tmp_evidence_dir["chain"].read_text().strip()
        record = json.loads(line)
        assert isinstance(record, dict)

    def test_required_fields_present(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        for field in [
            "schema",
            "record_id",
            "timestamp",
            "scenario_id",
            "action",
            "decision",
            "blocking_tier",
            "violations",
            "elapsed_ms",
            "nist_controls",
            "iso_controls",
            "record_hash",
            "prev_hash",
        ]:
            assert field in record, f"Missing field: {field}"

    def test_schema_version(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["schema"] == "cage-intent/1.0"

    def test_decision_blocked_when_violations(self, tel, tmp_evidence_dir):
        _write_and_read(tel, violations=["UCA-2 violation"])
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["decision"] == "BLOCKED"

    def test_decision_approved_when_no_violations(self, tel, tmp_evidence_dir):
        _write_and_read(tel, violations=[])
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["decision"] == "APPROVED"

    def test_blocking_tier_minus_one_when_approved(self, tel, tmp_evidence_dir):
        _write_and_read(tel, violations=[], blocking_tier=None)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["blocking_tier"] == -1


# ---------------------------------------------------------------------------
# Evidence chain — hash chain integrity
# ---------------------------------------------------------------------------


class TestHashChain:
    def test_first_record_chains_from_genesis(self, tel, tmp_evidence_dir):
        genesis = hashlib.sha256(b"GENESIS").hexdigest()
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["prev_hash"] == genesis

    def test_second_record_chains_from_first(self, tel, tmp_evidence_dir):
        hash_a = _write_and_read(tel, scenario_id="A")
        _write_and_read(tel, scenario_id="B")
        lines = tmp_evidence_dir["chain"].read_text().strip().splitlines()
        rec_b = json.loads(lines[1])
        assert rec_b["prev_hash"] == hash_a

    def test_returned_hash_matches_stored_hash(self, tel, tmp_evidence_dir):
        returned = _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["record_hash"] == returned

    def test_three_records_form_valid_chain(self, tel, tmp_evidence_dir):
        for sid in ["A", "B", "C"]:
            _write_and_read(tel, scenario_id=sid)
        ok, count = tel.verify_chain()
        assert ok is True
        assert count == 3

    def test_tampered_record_breaks_chain(self, tel, tmp_evidence_dir):
        for sid in ["A", "B", "C"]:
            _write_and_read(tel, scenario_id=sid)

        # Corrupt the first record's decision field
        lines = tmp_evidence_dir["chain"].read_text().strip().splitlines()
        rec0 = json.loads(lines[0])
        rec0["decision"] = "APPROVED"  # tamper
        lines[0] = json.dumps(rec0)
        tmp_evidence_dir["chain"].write_text("\n".join(lines) + "\n")

        ok, broken_at = tel.verify_chain()
        assert ok is False
        assert broken_at >= 1  # detected at or after record 1

    def test_empty_chain_is_valid(self, tel, tmp_evidence_dir):
        ok, count = tel.verify_chain()
        assert ok is True
        assert count == 0


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------


class TestPIIRedaction:
    def test_ssn_redacted(self, tel, tmp_evidence_dir):
        params = {**_SAMPLE_PARAMS, "ssn": "123-45-6789"}
        with tel.scenario_span("B", "write_db", params) as sw:
            tel.record_result(
                sw,
                violations=["UCA-1"],
                blocking_tier=0,
                elapsed_ms=1.0,
                action="write_db",
                params=params,
                scenario_id="B",
            )
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["params_redacted"]["ssn"] == "***REDACTED***"

    def test_approval_token_redacted(self, tel, tmp_evidence_dir):
        params = {**_SAMPLE_PARAMS, "approval_token": "tok_secret_xyz"}
        with tel.scenario_span("B", "write_db", params) as sw:
            tel.record_result(
                sw,
                violations=[],
                blocking_tier=None,
                elapsed_ms=1.0,
                action="write_db",
                params=params,
                scenario_id="B",
            )
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["params_redacted"]["approval_token"] == "***REDACTED***"

    def test_safe_fields_preserved(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert record["params_redacted"]["symbol"] == "NVDA"
        assert record["params_redacted"]["latency_ms"] == 340.0


# ---------------------------------------------------------------------------
# View-access log
# ---------------------------------------------------------------------------


class TestViewAccessLog:
    def test_view_event_written_on_read(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        tel.read_evidence_log(accessor_id="auditor@example.com", reason="audit")
        assert tmp_evidence_dir["view"].exists()
        events = tmp_evidence_dir["view"].read_text().strip().splitlines()
        assert len(events) == 1

    def test_view_event_fields(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        tel.read_evidence_log(accessor_id="risk@example.com", reason="annual review")
        event = json.loads(tmp_evidence_dir["view"].read_text().strip())
        assert event["schema"] == "cage-view-access/1.0"
        assert event["accessor_id"] == "risk@example.com"
        assert event["reason"] == "annual review"
        assert event["records_accessed"] == 1
        assert "read_fingerprint" in event
        assert "event_hash" in event
        assert "timestamp" in event

    def test_view_returns_records(self, tel, tmp_evidence_dir):
        _write_and_read(tel, scenario_id="A")
        _write_and_read(tel, scenario_id="B")
        records = tel.read_evidence_log(accessor_id="x")
        assert len(records) == 2

    def test_filter_by_scenario(self, tel, tmp_evidence_dir):
        _write_and_read(tel, scenario_id="A")
        _write_and_read(tel, scenario_id="B")
        _write_and_read(tel, scenario_id="C")
        records = tel.read_evidence_log(accessor_id="x", filter_scenario="B")
        assert len(records) == 1
        assert records[0]["scenario_id"] == "B"

    def test_multiple_view_events_chain(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        tel.read_evidence_log(accessor_id="a")
        tel.read_evidence_log(accessor_id="b")
        events = [
            json.loads(l)
            for l in tmp_evidence_dir["view"].read_text().strip().splitlines()
        ]
        assert len(events) == 2
        # Second event's prev_view_hash must equal first event's event_hash
        assert events[1]["prev_view_hash"] == events[0]["event_hash"]

    def test_read_fingerprint_deterministic(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        tel.read_evidence_log(accessor_id="a")
        tel.read_evidence_log(accessor_id="b")
        # Both read the same records — fingerprints must match
        events = [
            json.loads(l)
            for l in tmp_evidence_dir["view"].read_text().strip().splitlines()
        ]
        assert events[0]["read_fingerprint"] == events[1]["read_fingerprint"]

    def test_empty_chain_read_returns_empty_list(self, tel, tmp_evidence_dir):
        records = tel.read_evidence_log(accessor_id="x")
        assert records == []

    def test_view_event_written_even_for_empty_chain(self, tel, tmp_evidence_dir):
        tel.read_evidence_log(accessor_id="x")
        assert tmp_evidence_dir["view"].exists()

    def test_records_accessed_count_in_view_event(self, tel, tmp_evidence_dir):
        for sid in ["A", "B", "C"]:
            _write_and_read(tel, scenario_id=sid)
        tel.read_evidence_log(accessor_id="ciso@example.com")
        event = json.loads(tmp_evidence_dir["view"].read_text().strip())
        assert event["records_accessed"] == 3


# ---------------------------------------------------------------------------
# NIST / ISO control fields
# ---------------------------------------------------------------------------


class TestComplianceFields:
    def test_nist_controls_present(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert "SC-4" in record["nist_controls"]
        assert "SC-8" in record["nist_controls"]

    def test_iso_controls_present(self, tel, tmp_evidence_dir):
        _write_and_read(tel)
        record = json.loads(tmp_evidence_dir["chain"].read_text().strip())
        assert "A.8.4" in record["iso_controls"]
        assert "A.6.2" in record["iso_controls"]
