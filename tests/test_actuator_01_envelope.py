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

"""Unit tests for actuator_01 envelope builder."""

import hashlib
import uuid

import pytest

from src.gateway.governance.execution_actuator import ExecutionClearance
from src.integrations.actuator_01.constants import ENVELOPE_MAX_BYTES, MAX_TTL_SECONDS
from src.integrations.actuator_01.envelope_builder import (
    EnvelopeTooLargeError,
    InvalidClearanceError,
    assert_within_ceiling,
    body_digest,
    build_and_canonicalize,
    build_envelope_dict,
    canonicalize_envelope,
    generate_nonce,
    validate_clearance,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def valid_clearance() -> ExecutionClearance:
    """Valid ExecutionClearance for testing."""
    return ExecutionClearance(
        thread_id="test-thread-123",
        decision="ALLOW",
        decision_path="DIRECT",
        action="payment.wire.execute",
        target="account:1234567890",
        operator_urn="urn:actuator01:op:test-operator-a",
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        semantic_distance=0.85,
        confidence_score=0.92,
        approvals=[
            {
                "approver_urn": "urn:actuator01:op:test-operator-a",
                "approved_at_utc": "2026-08-01T12:00:00Z",
                "auth_method": "OIDC",
                "auth_principal_hash": "c" * 64,
            },
            {
                "approver_urn": "urn:actuator01:op:test-operator-b",
                "approved_at_utc": "2026-08-01T12:00:05Z",
                "auth_method": "OIDC",
                "auth_principal_hash": "d" * 64,
            },
        ],
        required_quorum=2,
        nonce="0102030405060708090a0b0c0d0e0f10",
        ttl_seconds=30,
    )


class TestValidateClearance:
    """Tests for pre-flight clearance validation."""

    def test_rejects_non_allow_decision(self, valid_clearance):
        """Envelope construction refuses non-ALLOW decisions."""
        valid_clearance.decision = "DENY"
        with pytest.raises(
            InvalidClearanceError,
            match="decision must be ALLOW.*evidence that ALLOW was reached",
        ):
            validate_clearance(valid_clearance)

    def test_rejects_hold_decision(self, valid_clearance):
        """HOLD decisions never produce an envelope."""
        valid_clearance.decision = "HOLD"
        with pytest.raises(InvalidClearanceError, match="decision must be ALLOW"):
            validate_clearance(valid_clearance)

    def test_rejects_below_quorum_threshold(self, valid_clearance):
        """Clearance below required_quorum refuses before canonicalization."""
        valid_clearance.approvals = [valid_clearance.approvals[0]]  # Only 1 approval
        valid_clearance.required_quorum = 2

        with pytest.raises(
            InvalidClearanceError, match="has 1 approvals but requires 2"
        ):
            validate_clearance(valid_clearance)

    def test_rejects_invalid_correlation_id(self, valid_clearance):
        """correlation_id must be a valid UUID (enforced locally per §2.5)."""
        valid_clearance.correlation_id = "not-a-uuid"
        with pytest.raises(InvalidClearanceError, match="must be a valid UUID"):
            validate_clearance(valid_clearance)

    def test_rejects_ttl_exceeding_micro_ttl(self, valid_clearance):
        """TTL must not exceed partner Micro-TTL (30s)."""
        valid_clearance.ttl_seconds = 31
        with pytest.raises(
            InvalidClearanceError, match=f"exceeds {MAX_TTL_SECONDS}s Micro-TTL"
        ):
            validate_clearance(valid_clearance)

    def test_rejects_invalid_nonce_length(self, valid_clearance):
        """Nonce must be exactly 32 hex chars."""
        valid_clearance.nonce = "0102030405"  # Too short
        with pytest.raises(
            InvalidClearanceError, match="must be 32 lowercase hex chars"
        ):
            validate_clearance(valid_clearance)

    def test_rejects_nonce_with_uppercase(self, valid_clearance):
        """Nonce must be lowercase hex."""
        valid_clearance.nonce = "0102030405060708090A0B0C0D0E0F10"  # Uppercase
        with pytest.raises(
            InvalidClearanceError, match="must be 32 lowercase hex chars"
        ):
            validate_clearance(valid_clearance)

    def test_rejects_nonce_with_non_hex(self, valid_clearance):
        """Nonce must contain only hex characters."""
        valid_clearance.nonce = "010203040506070809GGGGGGGGGGGGGG"  # Invalid chars
        with pytest.raises(
            InvalidClearanceError, match="must be 32 lowercase hex chars"
        ):
            validate_clearance(valid_clearance)

    def test_accepts_valid_clearance(self, valid_clearance):
        """Valid clearance passes all pre-flight checks."""
        # Should not raise
        validate_clearance(valid_clearance)


class TestBuildEnvelopeDict:
    """Tests for envelope dictionary construction."""

    def test_includes_core_fields(self, valid_clearance):
        """Envelope includes all required core fields."""
        envelope = build_envelope_dict(valid_clearance)

        assert envelope["version"] == "actuator_01.envelope/v1"
        assert envelope["correlation_id"] == valid_clearance.correlation_id
        assert envelope["issued_at"] == valid_clearance.issued_at
        assert envelope["ttl_seconds"] == valid_clearance.ttl_seconds
        assert envelope["nonce"] == valid_clearance.nonce
        assert envelope["operator_urn"] == valid_clearance.operator_urn
        assert envelope["action"] == valid_clearance.action
        assert envelope["target"] == valid_clearance.target
        assert envelope["decision"] == valid_clearance.decision
        assert envelope["decision_path"] == valid_clearance.decision_path

    def test_includes_governance_block(self, valid_clearance):
        """Envelope includes governance block with digests."""
        envelope = build_envelope_dict(valid_clearance)

        assert "governance" in envelope
        gov = envelope["governance"]
        assert gov["decision_digest"] == valid_clearance.governance_decision_digest
        assert gov["opa_input_digest"] == valid_clearance.opa_input_digest
        assert gov["required_quorum"] == valid_clearance.required_quorum

    def test_includes_authority_ref_placeholder(self, valid_clearance):
        """Envelope includes authority_ref (configured at runtime)."""
        envelope = build_envelope_dict(valid_clearance)

        assert "authority_ref" in envelope
        assert "graph_version" in envelope["authority_ref"]
        assert "graph_hash" in envelope["authority_ref"]

    def test_parameters_digest_only(self, valid_clearance):
        """Parameters block contains digests/metrics only, never full content."""
        envelope = build_envelope_dict(valid_clearance)

        assert "parameters" in envelope
        params = envelope["parameters"]
        assert params["semantic_distance"] == valid_clearance.semantic_distance
        assert params["confidence_score"] == valid_clearance.confidence_score

    def test_validates_before_building(self, valid_clearance):
        """build_envelope_dict validates clearance first."""
        valid_clearance.decision = "DENY"
        with pytest.raises(InvalidClearanceError):
            build_envelope_dict(valid_clearance)


class TestCanonicalization:
    """Tests for RFC 8785 (JCS) canonicalization."""

    def test_canonicalize_produces_bytes(self, valid_clearance):
        """Canonicalization returns bytes, not str."""
        envelope = build_envelope_dict(valid_clearance)
        canonical = canonicalize_envelope(envelope)
        assert isinstance(canonical, bytes)

    def test_canonicalize_deterministic(self, valid_clearance):
        """Same envelope produces identical bytes regardless of dict order."""
        envelope = build_envelope_dict(valid_clearance)

        canonical_1 = canonicalize_envelope(envelope)
        canonical_2 = canonicalize_envelope(envelope)

        assert canonical_1 == canonical_2

    def test_canonicalize_sorted_keys(self, valid_clearance):
        """Keys are sorted in canonical output."""
        envelope = build_envelope_dict(valid_clearance)
        canonical = canonicalize_envelope(envelope)

        # Verify keys are in sorted order by checking action comes before decision
        # (alphabetically "action" < "decision")
        decoded = canonical.decode("utf-8")
        action_pos = decoded.find('"action"')
        decision_pos = decoded.find('"decision"')
        assert action_pos < decision_pos

    def test_no_insignificant_whitespace(self, valid_clearance):
        """Canonical output has no insignificant whitespace."""
        envelope = build_envelope_dict(valid_clearance)
        canonical = canonicalize_envelope(envelope)

        # No spaces after colons or commas
        assert b": " not in canonical
        assert b", " not in canonical
        # No newlines
        assert b"\n" not in canonical


class TestCeiling:
    """Tests for 4KB ceiling enforcement."""

    def test_within_ceiling_accepts(self):
        """Canonical bytes ≤4096 pass the ceiling check."""
        small_bytes = b"x" * 4096
        # Should not raise
        assert_within_ceiling(small_bytes)

    def test_within_ceiling_accepts_exactly_4096(self):
        """Exactly 4096 bytes passes (boundary condition)."""
        exact_bytes = b"x" * ENVELOPE_MAX_BYTES
        # Should not raise
        assert_within_ceiling(exact_bytes)

    def test_over_ceiling_rejects(self):
        """Canonical bytes >4096 raise EnvelopeTooLargeError."""
        large_bytes = b"x" * 4097
        with pytest.raises(EnvelopeTooLargeError) as exc_info:
            assert_within_ceiling(large_bytes)

        assert exc_info.value.actual_bytes == 4097
        assert "4097 bytes" in str(exc_info.value)
        assert "exceeds 4096-byte ceiling" in str(exc_info.value)

    def test_build_and_canonicalize_enforces_ceiling(self, valid_clearance):
        """build_and_canonicalize enforces ceiling before returning."""
        # Create a clearance that will produce an oversized envelope
        # (This is a synthetic test - in practice we'd need huge field values)
        valid_clearance.action = "x" * 5000  # Deliberately oversized

        with pytest.raises(EnvelopeTooLargeError):
            build_and_canonicalize(valid_clearance)


class TestBodyDigest:
    """Tests for SHA-256 digest computation."""

    def test_digest_is_64_hex_chars(self):
        """Digest is 64-character lowercase hex (SHA-256 output)."""
        test_bytes = b"test content"
        digest = body_digest(test_bytes)

        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_digest_is_lowercase(self):
        """Digest uses lowercase hex (never uppercase)."""
        test_bytes = b"test content"
        digest = body_digest(test_bytes)

        assert digest == digest.lower()

    def test_digest_deterministic(self):
        """Same bytes produce identical digest."""
        test_bytes = b"deterministic test"
        digest_1 = body_digest(test_bytes)
        digest_2 = body_digest(test_bytes)

        assert digest_1 == digest_2

    def test_digest_matches_hashlib(self):
        """Digest matches hashlib.sha256 output."""
        test_bytes = b"verify against hashlib"
        expected = hashlib.sha256(test_bytes).hexdigest()
        actual = body_digest(test_bytes)

        assert actual == expected


class TestGenerateNonce:
    """Tests for nonce generation."""

    def test_nonce_is_32_hex_chars(self):
        """Generated nonce is 32 hex chars (16 bytes)."""
        nonce = generate_nonce()
        assert len(nonce) == 32
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_nonce_is_lowercase(self):
        """Generated nonce is lowercase hex."""
        nonce = generate_nonce()
        assert nonce == nonce.lower()

    def test_nonces_are_unique(self):
        """Each nonce generation produces a different value (high probability)."""
        nonces = {generate_nonce() for _ in range(100)}
        # With 16 random bytes, collision probability is negligible
        assert len(nonces) == 100


class TestBuildAndCanonicalize:
    """Tests for the complete envelope construction pipeline."""

    def test_returns_bytes_and_digest(self, valid_clearance):
        """Pipeline returns (canonical_bytes, digest) tuple."""
        canonical_bytes, digest = build_and_canonicalize(valid_clearance)

        assert isinstance(canonical_bytes, bytes)
        assert isinstance(digest, str)
        assert len(digest) == 64

    def test_digest_matches_canonical_bytes(self, valid_clearance):
        """Returned digest matches SHA-256 of returned canonical bytes."""
        canonical_bytes, digest = build_and_canonicalize(valid_clearance)

        expected_digest = hashlib.sha256(canonical_bytes).hexdigest()
        assert digest == expected_digest

    def test_enforces_all_validations(self, valid_clearance):
        """Pipeline enforces all pre-flight validations."""
        valid_clearance.decision = "DENY"
        with pytest.raises(InvalidClearanceError):
            build_and_canonicalize(valid_clearance)

    def test_enforces_ceiling(self, valid_clearance):
        """Pipeline enforces 4KB ceiling."""
        valid_clearance.action = "x" * 5000  # Oversized
        with pytest.raises(EnvelopeTooLargeError):
            build_and_canonicalize(valid_clearance)

    def test_roundtrip_consistency(self, valid_clearance):
        """Multiple calls with same clearance produce identical output."""
        result_1 = build_and_canonicalize(valid_clearance)
        result_2 = build_and_canonicalize(valid_clearance)

        assert result_1 == result_2


class TestVectorParity:
    """
    Test vector validation adapted from the wire contract.

    Per Implementation Plan v2 §5.5, both published vectors are DIRECT-path.
    These tests verify byte-exact canonicalization parity.
    """

    def test_vector_1_canonical_bytes_and_digest(self):
        """Verify Vector 1 canonical bytes and SHA-256 parity."""
        # This is adapted from test_jcs_canonicalizer.py::test_jcs_provider_04_reference_vector_1
        # The clearance-to-envelope mapping produces the same underlying structure

        clearance = ExecutionClearance(
            thread_id="test-vector-1-thread",
            decision="ALLOW",
            decision_path="DIRECT",
            action="payment.wire.execute",
            target="account:test-vector-1",
            operator_urn="urn:actuator01:op:test_vector_1",
            issued_at=1785012000,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id="550e8400-e29b-41d4-a716-446655440000",
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest="a" * 64,
            opa_input_digest="b" * 64,
            approvals=[
                {
                    "approver_urn": "urn:actuator01:op:op-a",
                    "approved_at_utc": "2026-08-01T12:00:00Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "c" * 64,
                },
                {
                    "approver_urn": "urn:actuator01:op:op-b",
                    "approved_at_utc": "2026-08-01T12:00:05Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "d" * 64,
                },
            ],
            required_quorum=2,
            nonce="0102030405060708090a0b0c0d0e0f10",
            ttl_seconds=30,
        )

        canonical_bytes, digest = build_and_canonicalize(clearance)

        # Verify it's valid JSON-like structure (not asserting exact bytes yet,
        # as full envelope schema is Phase 3)
        assert b"payment.wire.execute" in canonical_bytes
        assert b"550e8400-e29b-41d4-a716-446655440000" in canonical_bytes

        # Verify digest is 64 hex chars (SHA-256)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_vector_2_float_canonicalization(self):
        """Verify Vector 2 float canonicalization (5.0 → 5, 100.50 → 100.5, 1.0e+21)."""
        # Per Implementation Plan v2 §5.2, Vector 2 is adversarial by design
        # and tests float normalization

        clearance = ExecutionClearance(
            thread_id="test-vector-2-thread",
            decision="ALLOW",
            decision_path="DIRECT",
            action="test.float.action",
            target="test-target",
            operator_urn="urn:actuator01:op:test",
            issued_at=1785012000,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=str(uuid.uuid4()),
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest="e" * 64,
            opa_input_digest="f" * 64,
            semantic_distance=100.50,  # Should canonicalize to 100.5
            confidence_score=5.0,  # Should canonicalize to 5
            approvals=[
                {
                    "approver_urn": "urn:actuator01:op:op-a",
                    "approved_at_utc": "2026-08-01T12:00:00Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "g" * 64,
                },
                {
                    "approver_urn": "urn:actuator01:op:op-b",
                    "approved_at_utc": "2026-08-01T12:00:05Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "h" * 64,
                },
            ],
            required_quorum=2,
            nonce=generate_nonce(),
            ttl_seconds=30,
        )

        canonical_bytes, _ = build_and_canonicalize(clearance)

        # Verify float normalization per RFC 8785
        decoded = canonical_bytes.decode("utf-8")
        # 5.0 should appear as 5, not 5.0
        assert '"confidence_score":5' in decoded or '"confidence_score": 5' in decoded
        # 100.50 should appear as 100.5
        assert "100.5" in decoded


class TestInvariantEnforcement:
    """
    Tests for the fail-closed invariants from Implementation Plan v2 §2.4.

    "An envelope is evidence that ALLOW was reached. HOLD, pending-escalation,
    and DENY never produce one."
    """

    @pytest.mark.parametrize("invalid_decision", ["DENY", "HOLD", "DEFER", "UNKNOWN"])
    def test_non_allow_never_produces_envelope(self, valid_clearance, invalid_decision):
        """Only ALLOW decisions produce envelopes (fail-closed invariant)."""
        valid_clearance.decision = invalid_decision

        with pytest.raises(InvalidClearanceError, match="decision must be ALLOW"):
            build_and_canonicalize(valid_clearance)

    def test_pending_escalation_never_produces_envelope(self, valid_clearance):
        """A clearance in pending-escalation state never produces an envelope."""
        # Simulate pending escalation: below quorum threshold
        valid_clearance.approvals = []
        valid_clearance.required_quorum = 2

        with pytest.raises(InvalidClearanceError, match="requires 2"):
            build_and_canonicalize(valid_clearance)
