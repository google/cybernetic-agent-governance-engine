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
Tests for dual-schema evidence verification (v1.0 → v1.1 migration).

Phase 2.3: Validates schema migration support per Risk R-10 (backward incompatibility).
The dual-schema verifier must handle both v1.0 and v1.1 records seamlessly,
ensuring chain continuity during and after migration.

Test Coverage:
    - test_dual_schema_verify_record_handles_1_0_and_1_1
    - test_cutover_boundary_prev_hash_seeded_from_last_record_not_genesis
    - test_heterogeneous_schema_chain_verifies_end_to_end
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src.compliance_bridge.evidence_stream import (
    EvidenceRecord,
    VerifyResult,
    _detect_schema_version,
    _link_hash_versioned,
    _sha256,
    get_last_v1_0_hash,
    migrate_record_1_0_to_1_1,
    verify_record,
)


class TestEvidenceRecordDataclass:
    """Tests for the EvidenceRecord dataclass."""

    def test_evidence_record_default_schema_version_is_1_1(self) -> None:
        """New EvidenceRecord instances should default to schema v1.1."""
        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="ALLOW",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test_tool",
            control_id="A.5.3",
            prev_hash="abc123",
            record_hash="def456",
            payload={"key": "value"},
        )
        assert record.schema_version == "1.1"

    def test_evidence_record_v1_1_fields_default_to_none(self) -> None:
        """v1.1 metadata fields should default to None."""
        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="ALLOW",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test_tool",
            control_id="A.5.3",
            prev_hash="abc123",
            record_hash="def456",
            payload={},
        )
        assert record.classification_reason is None
        assert record.narrowing_applied is None
        assert record.pause_token is None

    def test_evidence_record_to_dict_sparse_representation(self) -> None:
        """to_dict() should only include v1.1 fields when they have values."""
        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="ALLOW",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test_tool",
            control_id="A.5.3",
            prev_hash="abc123",
            record_hash="def456",
            payload={},
        )
        record_dict = record.to_dict()
        assert "classification_reason" not in record_dict
        assert "narrowing_applied" not in record_dict
        assert "pause_token" not in record_dict

    def test_evidence_record_to_dict_includes_v1_1_fields_when_set(self) -> None:
        """to_dict() should include v1.1 fields when they have values."""
        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="DEFER",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test_tool",
            control_id="A.5.3",
            prev_hash="abc123",
            record_hash="def456",
            payload={},
            classification_reason="Requires human review",
            narrowing_applied={"max_tokens": 100},
            pause_token="pause-token-xyz",
        )
        record_dict = record.to_dict()
        assert record_dict["classification_reason"] == "Requires human review"
        assert record_dict["narrowing_applied"] == {"max_tokens": 100}
        assert record_dict["pause_token"] == "pause-token-xyz"

    def test_evidence_record_from_dict_detects_v1_0(self) -> None:
        """from_dict() should detect v1.0 records (no schema_version field)."""
        v1_0_dict = {
            "evidence_id": "evt-001",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "tool_name": "test_tool",
            "control_id": "A.5.3",
            "prev_hash": "abc123",
            "record_hash": "def456",
            "payload": {},
        }
        record = EvidenceRecord.from_dict(v1_0_dict)
        assert record.schema_version == "1.0"

    def test_evidence_record_from_dict_preserves_v1_1(self) -> None:
        """from_dict() should preserve explicit v1.1 schema version."""
        v1_1_dict = {
            "evidence_id": "evt-001",
            "decision": "DEFER",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "tool_name": "test_tool",
            "control_id": "A.5.3",
            "prev_hash": "abc123",
            "record_hash": "def456",
            "payload": {},
            "schema_version": "1.1",
            "classification_reason": "Human review required",
        }
        record = EvidenceRecord.from_dict(v1_1_dict)
        assert record.schema_version == "1.1"
        assert record.classification_reason == "Human review required"


class TestVerifyResult:
    """Tests for the VerifyResult dataclass."""

    def test_verify_result_is_frozen(self) -> None:
        """VerifyResult should be immutable."""
        result = VerifyResult(
            valid=True,
            schema_version="1.1",
            computed_hash="abc",
            expected_hash="abc",
        )
        with pytest.raises(AttributeError):
            result.valid = False  # type: ignore[misc]

    def test_verify_result_error_defaults_to_none(self) -> None:
        """VerifyResult.error should default to None."""
        result = VerifyResult(
            valid=True,
            schema_version="1.1",
            computed_hash="abc",
            expected_hash="abc",
        )
        assert result.error is None


class TestDualSchemaVerifyRecord:
    """Tests for the dual-schema verify_record() function."""

    def test_dual_schema_verify_record_handles_1_0_and_1_1(self) -> None:
        """verify_record() must correctly verify both v1.0 and v1.1 records.

        This is a key requirement for Risk R-10 (backward incompatibility):
        the system must be able to verify existing v1.0 records in Redis
        while also supporting new v1.1 records.
        """
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")

        # Create a v1.0 record
        v1_0_payload = {"type": "AUDIT_FINDING", "details": "test"}
        v1_0_payload_json = json.dumps(v1_0_payload, sort_keys=True, default=str)
        v1_0_hash = _link_hash_versioned(
            prev_hash=genesis_hash,
            sequence=0,
            event_type="AUDIT_FINDING",
            control_id="A.5.3",
            payload_json=v1_0_payload_json,
            schema_version="1.0",
        )
        v1_0_record = {
            "evidence_id": "evt-001",
            "decision": "AUDIT_FINDING",
            "event_type": "AUDIT_FINDING",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "tool_name": "test_tool",
            "control_id": "A.5.3",
            "prev_hash": genesis_hash,
            "record_hash": v1_0_hash,
            "payload": v1_0_payload,
            "sequence": 0,
            # No schema_version field (v1.0 indicator)
        }

        # Verify v1.0 record
        result_1_0 = verify_record(v1_0_record, genesis_hash)
        assert result_1_0.valid, f"v1.0 verification failed: {result_1_0.error}"
        assert result_1_0.schema_version == "1.0"

        # Create a v1.1 record chained from the v1.0 record
        v1_1_payload = {"type": "GOVERNANCE_DECISION", "decision": "DEFER"}
        v1_1_payload_json = json.dumps(v1_1_payload, sort_keys=True, default=str)
        v1_1_hash = _link_hash_versioned(
            prev_hash=v1_0_hash,
            sequence=1,
            event_type="GOVERNANCE_DECISION",
            control_id="A.5.3",
            payload_json=v1_1_payload_json,
            schema_version="1.1",
            classification_reason="Requires expert review",
        )
        v1_1_record = {
            "evidence_id": "evt-002",
            "decision": "GOVERNANCE_DECISION",
            "event_type": "GOVERNANCE_DECISION",
            "timestamp": "2026-01-01T00:01:00+00:00",
            "tool_name": "test_tool",
            "control_id": "A.5.3",
            "prev_hash": v1_0_hash,
            "record_hash": v1_1_hash,
            "payload": v1_1_payload,
            "sequence": 1,
            "schema_version": "1.1",
            "classification_reason": "Requires expert review",
        }

        # Verify v1.1 record
        result_1_1 = verify_record(v1_1_record, v1_0_hash)
        assert result_1_1.valid, f"v1.1 verification failed: {result_1_1.error}"
        assert result_1_1.schema_version == "1.1"

    def test_verify_record_detects_tampered_hash(self) -> None:
        """verify_record() must detect when record_hash has been tampered with."""
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")
        payload = {"type": "TEST"}
        payload_json = json.dumps(payload, sort_keys=True, default=str)

        correct_hash = _link_hash_versioned(
            prev_hash=genesis_hash,
            sequence=0,
            event_type="TEST",
            control_id="A.5.3",
            payload_json=payload_json,
            schema_version="1.1",
        )

        tampered_record = {
            "evidence_id": "evt-001",
            "event_type": "TEST",
            "control_id": "A.5.3",
            "prev_hash": genesis_hash,
            "record_hash": "tampered_hash_value",
            "payload": payload,
            "sequence": 0,
            "schema_version": "1.1",
        }

        result = verify_record(tampered_record, genesis_hash)
        assert not result.valid
        assert result.computed_hash == correct_hash
        assert result.expected_hash == "tampered_hash_value"
        assert "mismatch" in result.error.lower()

    def test_verify_record_detects_wrong_prev_hash(self) -> None:
        """verify_record() must fail when prev_hash doesn't match chain."""
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")
        wrong_prev_hash = _sha256("WRONG_GENESIS")

        payload = {"type": "TEST"}
        payload_json = json.dumps(payload, sort_keys=True, default=str)

        # Hash computed with wrong prev_hash
        record_hash = _link_hash_versioned(
            prev_hash=wrong_prev_hash,
            sequence=0,
            event_type="TEST",
            control_id="A.5.3",
            payload_json=payload_json,
            schema_version="1.1",
        )

        record = {
            "event_type": "TEST",
            "control_id": "A.5.3",
            "prev_hash": wrong_prev_hash,
            "record_hash": record_hash,
            "payload": payload,
            "sequence": 0,
            "schema_version": "1.1",
        }

        # Verify with correct genesis hash - should fail
        result = verify_record(record, genesis_hash)
        assert not result.valid

    def test_verify_record_missing_record_hash(self) -> None:
        """verify_record() must return error when record_hash is missing."""
        record = {
            "event_type": "TEST",
            "control_id": "A.5.3",
            "prev_hash": "abc",
            "payload": {},
            "sequence": 0,
        }
        result = verify_record(record, "abc")
        assert not result.valid
        assert "missing record_hash" in result.error.lower()

    def test_verify_record_with_evidence_record_dataclass(self) -> None:
        """verify_record() must accept EvidenceRecord dataclass instances."""
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")
        payload = {"type": "TEST"}
        payload_json = json.dumps(payload, sort_keys=True, default=str)

        record_hash = _link_hash_versioned(
            prev_hash=genesis_hash,
            sequence=0,
            event_type="ALLOW",
            control_id="A.5.3",
            payload_json=payload_json,
            schema_version="1.1",
        )

        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="ALLOW",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test_tool",
            control_id="A.5.3",
            prev_hash=genesis_hash,
            record_hash=record_hash,
            payload=payload,
            schema_version="1.1",
        )

        result = verify_record(record, genesis_hash)
        assert result.valid, f"Verification failed: {result.error}"


class TestCutoverBoundary:
    """Tests for schema cutover boundary handling."""

    def test_cutover_boundary_prev_hash_seeded_from_last_record_not_genesis(self) -> None:
        """On cutover, prev_hash MUST be seeded from last v1.0 record, NOT genesis.

        Per specs §4.1: Chain continuity requires the first v1.1 record to
        chain from the last v1.0 record's hash, not from a genesis sentinel.
        """
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")

        # Create a chain of v1.0 records
        v1_0_records = []
        prev_hash = genesis_hash

        for i in range(3):
            payload = {"type": "AUDIT", "seq": i}
            payload_json = json.dumps(payload, sort_keys=True, default=str)
            record_hash = _link_hash_versioned(
                prev_hash=prev_hash,
                sequence=i,
                event_type="AUDIT",
                control_id="A.5.3",
                payload_json=payload_json,
                schema_version="1.0",
            )
            record = {
                "evidence_id": f"evt-{i}",
                "event_type": "AUDIT",
                "control_id": "A.5.3",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload": payload,
                "sequence": i,
                # No schema_version (v1.0)
            }
            v1_0_records.append(record)
            prev_hash = record_hash

        # Get the last v1.0 hash using the helper function
        last_v1_0_hash = get_last_v1_0_hash(v1_0_records)

        # This MUST equal the last record's hash, NOT genesis
        assert last_v1_0_hash != genesis_hash
        assert last_v1_0_hash == v1_0_records[-1]["record_hash"]

        # Create the first v1.1 record, chained from last v1.0
        v1_1_payload = {"type": "DEFER", "reason": "cutover"}
        v1_1_payload_json = json.dumps(v1_1_payload, sort_keys=True, default=str)
        v1_1_hash = _link_hash_versioned(
            prev_hash=last_v1_0_hash,  # Seeded from last v1.0, NOT genesis
            sequence=3,
            event_type="DEFER",
            control_id="A.5.3",
            payload_json=v1_1_payload_json,
            schema_version="1.1",
            classification_reason="Schema cutover test",
        )
        v1_1_record = {
            "evidence_id": "evt-3",
            "event_type": "DEFER",
            "control_id": "A.5.3",
            "prev_hash": last_v1_0_hash,
            "record_hash": v1_1_hash,
            "payload": v1_1_payload,
            "sequence": 3,
            "schema_version": "1.1",
            "classification_reason": "Schema cutover test",
        }

        # Verify the v1.1 record chains correctly from the last v1.0 record
        result = verify_record(v1_1_record, last_v1_0_hash)
        assert result.valid, f"Cutover verification failed: {result.error}"

    def test_get_last_v1_0_hash_returns_genesis_when_no_v1_0_records(self) -> None:
        """get_last_v1_0_hash() should return genesis when no v1.0 records exist."""
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")

        # Empty list
        assert get_last_v1_0_hash([]) == genesis_hash

        # Only v1.1 records
        v1_1_records = [
            {"schema_version": "1.1", "record_hash": "hash1"},
            {"schema_version": "1.1", "record_hash": "hash2"},
        ]
        assert get_last_v1_0_hash(v1_1_records) == genesis_hash


class TestHeterogeneousSchemaChain:
    """Tests for chains containing mixed v1.0 and v1.1 records."""

    def test_heterogeneous_schema_chain_verifies_end_to_end(self) -> None:
        """A chain with mixed v1.0 and v1.1 records must verify completely.

        This tests the full migration scenario:
        1. Genesis → v1.0 records (legacy)
        2. v1.0 → v1.1 cutover (migration point)
        3. v1.1 records (new schema)

        Each link in the chain must verify correctly regardless of schema version.
        """
        genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")
        all_records = []
        prev_hash = genesis_hash

        # Phase 1: Create v1.0 records (legacy)
        for i in range(2):
            payload = {"type": "LEGACY", "index": i}
            payload_json = json.dumps(payload, sort_keys=True, default=str)
            record_hash = _link_hash_versioned(
                prev_hash=prev_hash,
                sequence=i,
                event_type="LEGACY",
                control_id="A.5.3",
                payload_json=payload_json,
                schema_version="1.0",
            )
            record = {
                "evidence_id": f"v1.0-{i}",
                "event_type": "LEGACY",
                "control_id": "A.5.3",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload": payload,
                "sequence": i,
                # No schema_version field (v1.0)
            }
            all_records.append(record)
            prev_hash = record_hash

        # Phase 2: Cutover to v1.1 (migration point)
        cutover_payload = {"type": "CUTOVER", "migration": True}
        cutover_payload_json = json.dumps(cutover_payload, sort_keys=True, default=str)
        cutover_hash = _link_hash_versioned(
            prev_hash=prev_hash,
            sequence=2,
            event_type="CUTOVER",
            control_id="A.5.3",
            payload_json=cutover_payload_json,
            schema_version="1.1",
            classification_reason="Schema migration cutover",
        )
        cutover_record = {
            "evidence_id": "v1.1-cutover",
            "event_type": "CUTOVER",
            "control_id": "A.5.3",
            "prev_hash": prev_hash,
            "record_hash": cutover_hash,
            "payload": cutover_payload,
            "sequence": 2,
            "schema_version": "1.1",
            "classification_reason": "Schema migration cutover",
        }
        all_records.append(cutover_record)
        prev_hash = cutover_hash

        # Phase 3: Create v1.1 records (new schema)
        for i in range(2):
            seq = 3 + i
            payload = {"type": "NEW_SCHEMA", "index": i}
            payload_json = json.dumps(payload, sort_keys=True, default=str)

            # Include different v1.1 fields for variety
            v1_1_kwargs = {}
            if i == 0:
                v1_1_kwargs["narrowing_applied"] = {"max_tokens": 500}
            else:
                v1_1_kwargs["pause_token"] = f"pause-{i}"

            record_hash = _link_hash_versioned(
                prev_hash=prev_hash,
                sequence=seq,
                event_type="NEW_SCHEMA",
                control_id="A.5.3",
                payload_json=payload_json,
                schema_version="1.1",
                **v1_1_kwargs,
            )
            record = {
                "evidence_id": f"v1.1-{i}",
                "event_type": "NEW_SCHEMA",
                "control_id": "A.5.3",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload": payload,
                "sequence": seq,
                "schema_version": "1.1",
                **v1_1_kwargs,
            }
            all_records.append(record)
            prev_hash = record_hash

        # Verify entire chain end-to-end
        verification_prev_hash = genesis_hash
        for idx, record in enumerate(all_records):
            result = verify_record(record, verification_prev_hash)
            assert result.valid, (
                f"Chain verification failed at record {idx} "
                f"(schema {result.schema_version}): {result.error}"
            )
            verification_prev_hash = record["record_hash"]

        # Confirm we verified a mixed chain
        versions = [_detect_schema_version(r) for r in all_records]
        assert "1.0" in versions, "Chain should contain v1.0 records"
        assert "1.1" in versions, "Chain should contain v1.1 records"


class TestMigrateRecord:
    """Tests for the migrate_record_1_0_to_1_1() function."""

    def test_migrate_preserves_all_v1_0_fields(self) -> None:
        """Migration must preserve all original v1.0 field values."""
        v1_0_record = {
            "evidence_id": "evt-legacy",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T12:00:00+00:00",
            "tool_name": "legacy_tool",
            "control_id": "A.5.3",
            "prev_hash": "prev_hash_value",
            "record_hash": "record_hash_value",
            "payload": {"legacy": "data"},
        }

        migrated = migrate_record_1_0_to_1_1(v1_0_record)

        assert migrated.evidence_id == "evt-legacy"
        assert migrated.decision == "ALLOW"
        assert migrated.tool_name == "legacy_tool"
        assert migrated.control_id == "A.5.3"
        assert migrated.prev_hash == "prev_hash_value"
        assert migrated.record_hash == "record_hash_value"
        assert migrated.payload == {"legacy": "data"}

    def test_migrate_sets_schema_version_to_1_1(self) -> None:
        """Migration must set schema_version to '1.1'."""
        v1_0_record = {
            "evidence_id": "evt-001",
            "decision": "ALLOW",
            "prev_hash": "abc",
            "record_hash": "def",
            "payload": {},
        }

        migrated = migrate_record_1_0_to_1_1(v1_0_record)
        assert migrated.schema_version == "1.1"

    def test_migrate_sets_v1_1_fields_to_none(self) -> None:
        """Migration must set new v1.1 fields to None (no defaults assumed)."""
        v1_0_record = {
            "evidence_id": "evt-001",
            "decision": "ALLOW",
            "prev_hash": "abc",
            "record_hash": "def",
            "payload": {},
        }

        migrated = migrate_record_1_0_to_1_1(v1_0_record)
        assert migrated.classification_reason is None
        assert migrated.narrowing_applied is None
        assert migrated.pause_token is None

    def test_migrate_handles_wire_format_payload_json(self) -> None:
        """Migration must handle wire format with payload_json string."""
        v1_0_wire = {
            "evidence_id": "evt-001",
            "event_type": "AUDIT",
            "prev_hash": "abc",
            "record_hash": "def",
            "payload_json": '{"wire": "format"}',
        }

        migrated = migrate_record_1_0_to_1_1(v1_0_wire)
        assert migrated.payload == {"wire": "format"}

    def test_migrate_handles_timestamp_parsing(self) -> None:
        """Migration must correctly parse ISO timestamp strings."""
        v1_0_record = {
            "evidence_id": "evt-001",
            "decision": "ALLOW",
            "timestamp": "2026-06-15T14:30:00Z",
            "prev_hash": "abc",
            "record_hash": "def",
            "payload": {},
        }

        migrated = migrate_record_1_0_to_1_1(v1_0_record)
        assert isinstance(migrated.timestamp, datetime)
        assert migrated.timestamp.year == 2026
        assert migrated.timestamp.month == 6
        assert migrated.timestamp.day == 15


class TestDetectSchemaVersion:
    """Tests for the _detect_schema_version() helper."""

    def test_detect_from_explicit_field(self) -> None:
        """Should use explicit schema_version field when present."""
        assert _detect_schema_version({"schema_version": "1.0"}) == "1.0"
        assert _detect_schema_version({"schema_version": "1.1"}) == "1.1"

    def test_detect_from_wire_schema_field(self) -> None:
        """Should detect version from wire format schema field."""
        assert _detect_schema_version({"schema": "cage-evidence-stream/1.1"}) == "1.1"
        assert _detect_schema_version({"schema": "cage-evidence-stream/1.0"}) == "1.0"

    def test_detect_defaults_to_1_0(self) -> None:
        """Should default to 1.0 for records without version markers."""
        assert _detect_schema_version({}) == "1.0"
        assert _detect_schema_version({"evidence_id": "evt-001"}) == "1.0"

    def test_detect_from_evidence_record_dataclass(self) -> None:
        """Should extract version from EvidenceRecord dataclass."""
        record = EvidenceRecord(
            evidence_id="evt-001",
            decision="ALLOW",
            timestamp=datetime.now(tz=timezone.utc),
            tool_name="test",
            control_id="A.5.3",
            prev_hash="abc",
            record_hash="def",
            payload={},
            schema_version="1.1",
        )
        assert _detect_schema_version(record) == "1.1"


class TestLinkHashVersioned:
    """Tests for the _link_hash_versioned() function."""

    def test_v1_0_hash_is_deterministic(self) -> None:
        """v1.0 hash computation must be deterministic."""
        params = {
            "prev_hash": "genesis",
            "sequence": 0,
            "event_type": "TEST",
            "control_id": "A.5.3",
            "payload_json": '{"test": true}',
            "schema_version": "1.0",
        }
        hash1 = _link_hash_versioned(**params)
        hash2 = _link_hash_versioned(**params)
        assert hash1 == hash2

    def test_v1_1_hash_is_deterministic(self) -> None:
        """v1.1 hash computation must be deterministic."""
        params = {
            "prev_hash": "genesis",
            "sequence": 0,
            "event_type": "TEST",
            "control_id": "A.5.3",
            "payload_json": '{"test": true}',
            "schema_version": "1.1",
            "classification_reason": "test reason",
        }
        hash1 = _link_hash_versioned(**params)
        hash2 = _link_hash_versioned(**params)
        assert hash1 == hash2

    def test_v1_0_and_v1_1_hashes_differ(self) -> None:
        """Same content with different schema versions must produce different hashes."""
        common_params = {
            "prev_hash": "genesis",
            "sequence": 0,
            "event_type": "TEST",
            "control_id": "A.5.3",
            "payload_json": '{"test": true}',
        }
        hash_1_0 = _link_hash_versioned(**common_params, schema_version="1.0")
        hash_1_1 = _link_hash_versioned(**common_params, schema_version="1.1")
        assert hash_1_0 != hash_1_1

    def test_v1_1_fields_affect_hash(self) -> None:
        """v1.1 metadata fields must be included in hash computation."""
        base_params = {
            "prev_hash": "genesis",
            "sequence": 0,
            "event_type": "TEST",
            "control_id": "A.5.3",
            "payload_json": '{"test": true}',
            "schema_version": "1.1",
        }

        hash_base = _link_hash_versioned(**base_params)
        hash_with_reason = _link_hash_versioned(
            **base_params, classification_reason="reason"
        )
        hash_with_narrowing = _link_hash_versioned(
            **base_params, narrowing_applied={"k": "v"}
        )
        hash_with_pause = _link_hash_versioned(**base_params, pause_token="token")

        # All hashes should be different
        all_hashes = [hash_base, hash_with_reason, hash_with_narrowing, hash_with_pause]
        assert len(set(all_hashes)) == 4, "All v1.1 field combinations should produce unique hashes"
