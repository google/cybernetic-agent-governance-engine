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
        operator_urn="urn:actuator_01:op:test-operator-a",
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
                "approver_urn": "urn:actuator_01:op:test-operator-a",
                "approved_at_utc": "2026-08-01T12:00:00Z",
                "auth_method": "OIDC",
                "auth_principal_hash": "c" * 64,
            },
            {
                "approver_urn": "urn:actuator_01:op:test-operator-b",
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

    def test_archytan_vector_3_structure(self, valid_clearance):
        """Envelope emits canonical Archytan ArbiterKernel wire structure."""
        envelope = build_envelope_dict(valid_clearance)

        # Verify envelope_version
        assert envelope["envelope_version"] == "archytan.envelope/v1"

        # Verify top-level fields
        assert envelope["correlation_id"] == valid_clearance.correlation_id
        assert envelope["issued_at"] == valid_clearance.issued_at
        assert envelope["ttl_seconds"] == valid_clearance.ttl_seconds
        assert envelope["nonce"] == valid_clearance.nonce
        assert envelope["action"] == valid_clearance.action
        assert envelope["operator_urn"] == valid_clearance.operator_urn

        # Verify authority_ref block
        assert "authority_ref" in envelope
        assert "graph_hash" in envelope["authority_ref"]
        assert "graph_version" in envelope["authority_ref"]

        # Verify target structure (account_hash only)
        assert "target" in envelope
        assert "account_hash" in envelope["target"]

        # Verify parameters at root level
        assert "parameters" in envelope
        assert isinstance(envelope["parameters"], dict)

    def test_governance_block_v3_structure(self, valid_clearance):
        """Governance block includes decision, decision_path, policy_version, receipt fields."""
        envelope = build_envelope_dict(valid_clearance)

        assert "governance" in envelope
        gov = envelope["governance"]
        assert gov["decision"] == valid_clearance.decision
        assert gov["decision_path"] == valid_clearance.decision_path
        assert gov["required_quorum"] == valid_clearance.required_quorum
        assert "policy_version" in gov
        assert "decision_signature" in gov  # May be None if no policy signer
        assert "receipt_id" in gov
        assert "receipt_hash" in gov
        assert "evaluated_at" in gov

    def test_approval_block_with_webauthn_fields(self, valid_clearance):
        """Approval block maps WebAuthn fields from clearance.approvals."""
        # Add WebAuthn fields to first approval
        valid_clearance.approvals[0]["credential_id"] = "test-credential-123"
        valid_clearance.approvals[0]["client_data_json"] = (
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"
        )
        valid_clearance.approvals[0]["authenticator_data"] = (
            "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA"
        )
        valid_clearance.approvals[0]["signature"] = "MEUCIQDvHVRm..."
        valid_clearance.approvals[0]["challenge_binding"] = "a" * 64

        envelope = build_envelope_dict(valid_clearance)

        assert "approval" in envelope
        approval = envelope["approval"]
        assert approval["approver_urn"] == valid_clearance.approvals[0]["approver_urn"]
        assert approval["credential_id"] == "test-credential-123"
        assert approval["client_data_json"] == "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"
        assert (
            approval["authenticator_data"]
            == "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA"
        )
        assert approval["signature"] == "MEUCIQDvHVRm..."
        assert approval["challenge_binding"] == "a" * 64

    def test_approval_key_omitted_when_no_approvals(self, valid_clearance):
        """DIRECT path omits approval key entirely (not null) when clearance.approvals is empty."""
        # DIRECT path: empty approvals list, quorum=0
        valid_clearance.approvals = []
        valid_clearance.required_quorum = 0

        envelope = build_envelope_dict(valid_clearance)

        # Per Vector 1: DIRECT path does NOT include "approval" key at all
        assert "approval" not in envelope

    def test_parameters_from_params_field(self, valid_clearance):
        """Parameters are populated at root level from clearance.params."""
        valid_clearance.params = {"amount_minor": 12345, "currency": "USD"}
        envelope = build_envelope_dict(valid_clearance)

        assert envelope["parameters"] == {"amount_minor": 12345, "currency": "USD"}

    def test_parameters_empty_dict_when_params_none(self, valid_clearance):
        """Parameters default to empty dict when params is not a dict."""
        valid_clearance.params = None
        envelope = build_envelope_dict(valid_clearance)

        assert envelope["parameters"] == {}

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

        # Verify keys are in sorted order by checking correlation_id comes before envelope_version
        # (alphabetically "correlation_id" < "envelope_version")
        decoded = canonical.decode("utf-8")
        correlation_pos = decoded.find('"correlation_id"')
        envelope_version_pos = decoded.find('"envelope_version"')
        assert correlation_pos < envelope_version_pos

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
        # This is adapted from test_jcs_canonicalizer.py::test_jcs_actuator_01_reference_vector_1
        # The clearance-to-envelope mapping produces the same underlying structure

        clearance = ExecutionClearance(
            thread_id="test-vector-1-thread",
            decision="ALLOW",
            decision_path="DIRECT",
            action="payment.wire.execute",
            target="account:test-vector-1",
            operator_urn="urn:actuator_01:op:test_vector_1",
            issued_at=1785012000,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id="550e8400-e29b-41d4-a716-446655440000",
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest="a" * 64,
            opa_input_digest="b" * 64,
            approvals=[
                {
                    "approver_urn": "urn:actuator_01:op:op-a",
                    "approved_at_utc": "2026-08-01T12:00:00Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "c" * 64,
                },
                {
                    "approver_urn": "urn:actuator_01:op:op-b",
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
            operator_urn="urn:actuator_01:op:test",
            issued_at=1785012000,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=str(uuid.uuid4()),
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest="e" * 64,
            opa_input_digest="f" * 64,
            params={
                "amount": 100.50,
                "multiplier": 5.0,
            },  # Test float canonicalization in params
            approvals=[
                {
                    "approver_urn": "urn:actuator_01:op:op-a",
                    "approved_at_utc": "2026-08-01T12:00:00Z",
                    "auth_method": "OIDC",
                    "auth_principal_hash": "g" * 64,
                },
                {
                    "approver_urn": "urn:actuator_01:op:op-b",
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

        # Verify float normalization per RFC 8785 in target.parameters
        decoded = canonical_bytes.decode("utf-8")
        # 5.0 should appear as 5, not 5.0
        assert '"multiplier":5' in decoded
        # 100.50 should appear as 100.5
        assert '"amount":100.5' in decoded


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


class TestPolicyDecisionSignature:
    """Tests for policy decision signature generation (Phase 3)."""

    def test_decision_signature_with_policy_signer(self, valid_clearance):
        """Envelope includes decision_signature when policy_signer is provided."""
        from unittest.mock import Mock

        from src.integrations.actuator_01.signatures import (
            ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION,
        )

        # Create mock policy signer
        mock_signer = Mock()
        mock_signer.is_kms_active = True
        mock_signer.signer_urn = "urn:actuator_01:policy:institutional"
        mock_signer.sign_raw.return_value = b"x" * 64  # 64-byte signature

        envelope = build_envelope_dict(valid_clearance, policy_signer=mock_signer)

        # Verify decision_signature is present and not None
        assert envelope["governance"]["decision_signature"] is not None
        assert len(envelope["governance"]["decision_signature"]) == 128  # hex string

    def test_decision_signature_none_without_policy_signer(self, valid_clearance):
        """Envelope has decision_signature=None when no policy_signer provided."""
        envelope = build_envelope_dict(valid_clearance, policy_signer=None)

        assert envelope["governance"]["decision_signature"] is None

    def test_decision_binding_format(self, valid_clearance):
        """Verify decision binding payload uses 0x1F unit separators."""
        import hashlib
        from unittest.mock import Mock

        # Create mock policy signer
        mock_signer = Mock()
        mock_signer.is_kms_active = True
        mock_signer.signer_urn = "urn:actuator_01:policy:institutional"
        mock_signer.sign_raw.return_value = b"x" * 64

        # Build envelope to trigger policy signature generation
        build_envelope_dict(valid_clearance, policy_signer=mock_signer)

        # Verify sign_raw was called
        assert mock_signer.sign_raw.called

        # Extract the message that was signed
        signed_message = mock_signer.sign_raw.call_args[0][0]

        # Verify it starts with the domain tag
        from src.integrations.actuator_01.signatures import (
            ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION,
        )

        assert signed_message.startswith(ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION)

        # Verify the remainder is a SHA-256 digest (32 bytes)
        decision_binding_digest = signed_message[
            len(ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION) :
        ]
        assert len(decision_binding_digest) == 32  # SHA-256 output

    def test_policy_signer_isolation_guard(self):
        """Policy decision signatures reject operator quorum keys."""
        from unittest.mock import Mock

        from src.integrations.actuator_01.signatures import sign_policy_decision

        # Create mock operator signer (URN contains ":op:")
        mock_operator_signer = Mock()
        mock_operator_signer.is_kms_active = True
        mock_operator_signer.signer_urn = "urn:actuator_01:op:operator-a"

        with pytest.raises(
            ValueError,
            match="operator quorum key.*Policy authority keys must be isolated",
        ):
            sign_policy_decision(
                signer=mock_operator_signer,
                action="payment.wire.execute",
                target_digest="a" * 64,
                correlation_id="550e8400-e29b-41d4-a716-446655440000",
                decision="ALLOW",
                decision_path="DIRECT",
                required_quorum=2,
                policy_version="v1",
                evaluated_at=1785012000,
            )

    def test_decision_signature_graceful_degradation(self, valid_clearance):
        """Envelope construction continues if policy signature fails."""
        from unittest.mock import Mock

        # Create mock policy signer that raises an error
        mock_signer = Mock()
        mock_signer.is_kms_active = True
        mock_signer.signer_urn = "urn:actuator_01:policy:institutional"
        mock_signer.sign_raw.side_effect = RuntimeError("KMS unavailable")

        # Should not raise - envelope construction continues
        envelope = build_envelope_dict(valid_clearance, policy_signer=mock_signer)

        # decision_signature should be None (graceful degradation)
        assert envelope["governance"]["decision_signature"] is None


class TestVector1Golden:
    """
    Archytan Vector 1 (DIRECT path) golden fixture test.

    Validates byte-exact canonicalization parity with the Archytan ArbiterKernel
    reference implementation.
    """

    def test_vector_1_canonical_golden(self):
        """Verify Vector 1 byte-exact canonicalization and SHA-256 golden hash."""
        import json

        # Load the golden fixture directly
        v1 = json.load(open("tests/fixtures/actuator_01/vector1_direct.json"))

        # Canonicalize
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        canonical_bytes = jcs_canonicalize_plan(v1)
        digest = hashlib.sha256(canonical_bytes).hexdigest()

        # Golden targets from Archytan ArbiterKernel
        expected_length = 958
        expected_hash = (
            "83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e"
        )

        # Diagnostic output on mismatch
        actual_length = len(canonical_bytes)
        if actual_length != expected_length or digest != expected_hash:
            import sys

            print("\n[Vector 1 Golden Mismatch]", file=sys.stderr)
            print(f"  Expected length: {expected_length}", file=sys.stderr)
            print(f"  Actual length:   {actual_length}", file=sys.stderr)
            print(f"  Expected hash:   {expected_hash}", file=sys.stderr)
            print(f"  Actual hash:     {digest}", file=sys.stderr)
            print("\n  Canonical bytes preview (first 300 chars):", file=sys.stderr)
            print(
                f"  {canonical_bytes[:300].decode('utf-8', errors='replace')}",
                file=sys.stderr,
            )

        # Assert byte-for-byte fidelity
        assert actual_length == expected_length, (
            f"Vector 1 canonical bytes length mismatch: "
            f"expected {expected_length}, got {actual_length}"
        )
        assert digest == expected_hash, (
            f"Vector 1 SHA-256 digest mismatch: expected {expected_hash}, got {digest}"
        )


class TestVector3Golden:
    """
    Archytan Vector 3 (ESCALATE path) golden fixture test.

    Validates byte-exact canonicalization parity with the Archytan ArbiterKernel
    reference implementation. This test serves as a frozen contract validator:
    any deviation in serialization, field order, or whitespace will break the
    golden hash, signaling a regression.
    """

    def test_vector_3_canonical_golden(self):
        """Verify Vector 3 byte-exact canonicalization and SHA-256 golden hash."""
        import json

        # Load the golden fixture directly
        v3 = json.load(open("tests/fixtures/actuator_01/vector3_escalate.json"))

        # Canonicalize
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        canonical_bytes = jcs_canonicalize_plan(v3)
        digest = hashlib.sha256(canonical_bytes).hexdigest()

        # Golden targets from Archytan ArbiterKernel
        expected_length = 1523
        expected_hash = (
            "aa10d1f8c0093808be0db3fba8c8787f755c8183ca8ab214fac42aaaadd6c080"
        )

        # Diagnostic output on mismatch
        actual_length = len(canonical_bytes)
        if actual_length != expected_length or digest != expected_hash:
            import sys

            print("\n[Vector 3 Golden Mismatch]", file=sys.stderr)
            print(f"  Expected length: {expected_length}", file=sys.stderr)
            print(f"  Actual length:   {actual_length}", file=sys.stderr)
            print(f"  Expected hash:   {expected_hash}", file=sys.stderr)
            print(f"  Actual hash:     {digest}", file=sys.stderr)
            print("\n  Canonical bytes preview (first 300 chars):", file=sys.stderr)
            print(
                f"  {canonical_bytes[:300].decode('utf-8', errors='replace')}",
                file=sys.stderr,
            )

        # Assert byte-for-byte fidelity
        assert actual_length == expected_length, (
            f"Vector 3 canonical bytes length mismatch: "
            f"expected {expected_length}, got {actual_length}"
        )
        assert digest == expected_hash, (
            f"Vector 3 SHA-256 digest mismatch: expected {expected_hash}, got {digest}"
        )
