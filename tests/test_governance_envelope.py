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

"""Unit tests for CAGE Governance Envelope Builder (v2.0 wire format).

This test module covers the de-branded GovernanceEnvelope and
GovernanceEnvelopeBuilder classes with the v2.0 wire format:
- envelope_version: "2.0"
- envelope_type values: "cage_*" prefix
- envelope_id prefix: "cage-"

For backward compatibility tests with the deprecated AGW* aliases,
see test_agw_envelope.py.
"""

import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ec_key_pair():
    """Generate an EC P-256 key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


@pytest.fixture
def sample_governance_result():
    """Sample governance result payload."""
    return {
        "verdict": "APPROVED",
        "tiers": {
            "stpa": {"status": "pass"},
            "cbf": {"status": "pass"},
            "opa": {"status": "pass"},
        },
        "confidence": 0.95,
    }


@pytest.fixture
def sample_params():
    """Sample action parameters."""
    return {
        "symbol": "AAPL",
        "amount": 1000.0,
        "order_type": "market",
    }


# ---------------------------------------------------------------------------
# Tests for GovernanceEnvelope dataclass
# ---------------------------------------------------------------------------


class TestGovernanceEnvelope:
    """Tests for the GovernanceEnvelope dataclass."""

    def test_envelope_to_dict(self, sample_governance_result, sample_params):
        """Test envelope serialization to dictionary."""
        from src.gateway.governance.governance_envelope import (
            GovernanceContext,
            GovernanceEnvelope,
            IssuerMetadata,
            SubjectMetadata,
        )

        envelope = GovernanceEnvelope(
            envelope_version="2.0",
            envelope_type="cage_governance_decision",
            envelope_id="cage-test123",
            issued_at="2026-08-21T12:00:00.000Z",
            expires_at="2026-08-21T12:05:00.000Z",
            issuer=IssuerMetadata(
                service="test-gateway",
                instance_id="test-instance",
                region="us-central1",
            ),
            subject=SubjectMetadata(
                action="execute_trade",
                action_hash="sha256:abc123",
                record_hash="sha256:def456",
                agent_id="advisor-v1",
            ),
            governance_context=GovernanceContext(
                policy_version="sha256:policy123",
                tiers_passed=["stpa", "cbf", "opa"],
                deployment_region="US_FED",
                controls_satisfied=["CTRL_OPA_001"],
            ),
            payload=sample_governance_result,
            signature=None,
        )

        result = envelope.to_dict()

        assert result["envelope_version"] == "2.0"
        assert result["envelope_type"] == "cage_governance_decision"
        assert result["envelope_id"] == "cage-test123"
        assert result["issuer"]["service"] == "test-gateway"
        assert result["subject"]["action"] == "execute_trade"
        assert result["governance_context"]["tiers_passed"] == ["stpa", "cbf", "opa"]
        assert result["payload"] == sample_governance_result
        assert "signature" not in result  # No signature attached

    def test_envelope_canonical_bytes(self, sample_governance_result):
        """Test envelope serialization to RFC 8785 canonical bytes."""
        from src.gateway.governance.governance_envelope import (
            GovernanceContext,
            GovernanceEnvelope,
            IssuerMetadata,
            SubjectMetadata,
        )

        envelope = GovernanceEnvelope(
            envelope_version="2.0",
            envelope_type="cage_governance_decision",
            envelope_id="cage-test123",
            issued_at="2026-08-21T12:00:00.000Z",
            expires_at="2026-08-21T12:05:00.000Z",
            issuer=IssuerMetadata(),
            subject=SubjectMetadata(action="test", action_hash="sha256:test"),
            governance_context=GovernanceContext(policy_version="sha256:test"),
            payload=sample_governance_result,
        )

        canonical = envelope.to_canonical_bytes()

        assert isinstance(canonical, bytes)
        # Verify it's valid JSON
        parsed = json.loads(canonical)
        assert parsed["envelope_version"] == "2.0"

    def test_envelope_digest_is_deterministic(self, sample_governance_result):
        """Test that envelope digest is deterministic."""
        from src.gateway.governance.governance_envelope import (
            GovernanceContext,
            GovernanceEnvelope,
            IssuerMetadata,
            SubjectMetadata,
        )

        envelope1 = GovernanceEnvelope(
            envelope_version="2.0",
            envelope_type="cage_governance_decision",
            envelope_id="cage-test123",
            issued_at="2026-08-21T12:00:00.000Z",
            expires_at="2026-08-21T12:05:00.000Z",
            issuer=IssuerMetadata(service="test", instance_id="test", region="test"),
            subject=SubjectMetadata(action="test", action_hash="sha256:test"),
            governance_context=GovernanceContext(policy_version="sha256:test"),
            payload=sample_governance_result,
        )

        envelope2 = GovernanceEnvelope(
            envelope_version="2.0",
            envelope_type="cage_governance_decision",
            envelope_id="cage-test123",
            issued_at="2026-08-21T12:00:00.000Z",
            expires_at="2026-08-21T12:05:00.000Z",
            issuer=IssuerMetadata(service="test", instance_id="test", region="test"),
            subject=SubjectMetadata(action="test", action_hash="sha256:test"),
            governance_context=GovernanceContext(policy_version="sha256:test"),
            payload=sample_governance_result,
        )

        assert envelope1.compute_digest() == envelope2.compute_digest()
        assert envelope1.compute_digest_hex() == envelope2.compute_digest_hex()


# ---------------------------------------------------------------------------
# Tests for GovernanceEnvelopeBuilder
# ---------------------------------------------------------------------------


class TestGovernanceEnvelopeBuilder:
    """Tests for the GovernanceEnvelopeBuilder class."""

    def test_build_unsigned_envelope(self, sample_governance_result, sample_params):
        """Test building an unsigned envelope."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
            record_hash="sha256:evidence123",
            agent_id="advisor-v1",
            tiers_passed=["stpa", "cbf", "opa"],
            controls_satisfied=["CTRL_OPA_001"],
        )

        assert envelope.envelope_version == "2.1"
        assert envelope.envelope_type == "cage_governance_decision"
        assert envelope.envelope_id.startswith("cage-")
        assert envelope.subject.action == "execute_trade"
        assert envelope.subject.action_hash.startswith("sha256:")
        assert envelope.subject.record_hash == "sha256:evidence123"
        assert envelope.subject.agent_id == "advisor-v1"
        assert envelope.governance_context.tiers_passed == ["stpa", "cbf", "opa"]
        assert envelope.payload == sample_governance_result
        assert envelope.signature is None

    def test_action_hash_is_deterministic(
        self, sample_governance_result, sample_params
    ):
        """Test that action hash is deterministic for same inputs."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()

        envelope1 = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        envelope2 = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        assert envelope1.subject.action_hash == envelope2.subject.action_hash

    def test_action_hash_changes_with_params(
        self, sample_governance_result, sample_params
    ):
        """Test that action hash changes when params change."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()

        envelope1 = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        modified_params = {**sample_params, "amount": 2000.0}
        envelope2 = builder.build_unsigned(
            action="execute_trade",
            params=modified_params,
            governance_result=sample_governance_result,
        )

        assert envelope1.subject.action_hash != envelope2.subject.action_hash

    def test_attach_signature(self, sample_governance_result, sample_params):
        """Test attaching a signature to an envelope."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        # Mock signature bytes
        signature_bytes = b"mock_signature_bytes_here"
        kid = "test-key-id"
        algorithm = "ES256"

        signed = builder.attach_signature(envelope, signature_bytes, kid, algorithm)

        assert signed.signature is not None
        assert signed.signature.kid == kid
        assert signed.signature.algorithm == algorithm
        # Signature should be base64url encoded
        decoded = base64.urlsafe_b64decode(signed.signature.value + "==")
        assert decoded == signature_bytes

    def test_envelope_ttl(self, sample_governance_result, sample_params):
        """Test that envelope TTL is applied correctly."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder(ttl_s=60)  # 60 seconds
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        # Parse timestamps
        issued = datetime.fromisoformat(envelope.issued_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(envelope.expires_at.replace("Z", "+00:00"))

        # TTL should be approximately 60 seconds
        delta = (expires - issued).total_seconds()
        assert 59 <= delta <= 61  # Allow 1 second tolerance

    def test_envelope_from_dict(self, sample_governance_result, sample_params):
        """Test reconstructing envelope from dictionary."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        original = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
            record_hash="sha256:test",
        )

        # Convert to dict and back
        original_dict = original.to_dict()
        reconstructed = builder._envelope_from_dict(original_dict)

        assert reconstructed.envelope_version == original.envelope_version
        assert reconstructed.envelope_id == original.envelope_id
        assert reconstructed.subject.action == original.subject.action
        assert reconstructed.subject.action_hash == original.subject.action_hash
        assert reconstructed.subject.record_hash == original.subject.record_hash


# ---------------------------------------------------------------------------
# Tests for envelope signing and verification
# ---------------------------------------------------------------------------


class TestEnvelopeSigningVerification:
    """Tests for envelope signing and verification with real keys."""

    def test_sign_and_verify_ec_key(
        self, ec_key_pair, sample_governance_result, sample_params
    ):
        """Test signing and verifying with EC key."""
        from cryptography.hazmat.primitives.asymmetric import utils

        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
        from src.gateway.governance.jwks import JWKSet, pem_to_jwk

        private_key, _, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        # Sign the envelope manually - use Prehashed since digest is already SHA256
        digest = envelope.compute_digest()
        signature_der = private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        # Get kid from JWK
        jwk = pem_to_jwk(public_pem)
        kid = jwk["kid"]

        signed = builder.attach_signature(envelope, signature_der, kid, "ES256")

        # Create a JWKSet with the public key
        jwks = JWKSet()
        jwks.add_key(public_pem)

        # Verify - patch at the source module where get_jwks is defined
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result = builder.verify(signed)

        assert result is True

    def test_verify_fails_with_wrong_key(
        self, ec_key_pair, sample_governance_result, sample_params
    ):
        """Test verification fails with wrong key."""
        from cryptography.hazmat.primitives.asymmetric import utils

        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
        from src.gateway.governance.jwks import JWKSet, pem_to_jwk

        private_key, _, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        # Sign with the correct key - use Prehashed since digest is already SHA256
        digest = envelope.compute_digest()
        signature_der = private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        jwk = pem_to_jwk(public_pem)
        kid = jwk["kid"]

        signed = builder.attach_signature(envelope, signature_der, kid, "ES256")

        # Create a JWKSet with a DIFFERENT key
        different_private = ec.generate_private_key(ec.SECP256R1())
        different_pem = different_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwks = JWKSet()
        jwks.add_key(different_pem, kid=kid)  # Same kid, different key

        # Verification should fail - patch at the source module
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result = builder.verify(signed)

        assert result is False

    def test_verify_fails_with_tampered_payload(
        self, ec_key_pair, sample_governance_result, sample_params
    ):
        """Test verification fails when payload is tampered."""
        from cryptography.hazmat.primitives.asymmetric import utils

        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
        from src.gateway.governance.jwks import JWKSet, pem_to_jwk

        private_key, _, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        # Sign the envelope - use Prehashed since digest is already SHA256
        digest = envelope.compute_digest()
        signature_der = private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        jwk = pem_to_jwk(public_pem)
        kid = jwk["kid"]

        signed = builder.attach_signature(envelope, signature_der, kid, "ES256")

        # Tamper with the payload
        signed.payload["verdict"] = "DENIED"

        # Create a JWKSet with the public key
        jwks = JWKSet()
        jwks.add_key(public_pem)

        # Verification should fail - patch at the source module
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result = builder.verify(signed)

        assert result is False

    def test_verify_unsigned_envelope(self, sample_governance_result, sample_params):
        """Test verification of unsigned envelope fails."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        result = builder.verify(envelope)

        assert result is False


# ---------------------------------------------------------------------------
# Tests for convenience functions
# ---------------------------------------------------------------------------


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_envelope_builder(self):
        """Test create_envelope_builder factory function."""
        from src.gateway.governance.governance_envelope import (
            IssuerMetadata,
            create_envelope_builder,
        )

        # Default builder
        builder1 = create_envelope_builder()
        assert builder1._ttl_s == 300  # Default TTL

        # Custom builder
        custom_issuer = IssuerMetadata(
            service="custom-gateway",
            instance_id="custom-instance",
            region="eu-west-1",
        )
        builder2 = create_envelope_builder(issuer=custom_issuer, ttl_s=600)
        assert builder2._issuer.service == "custom-gateway"
        assert builder2._ttl_s == 600

    @pytest.mark.asyncio
    async def test_build_governance_envelope_no_kms(
        self, sample_governance_result, sample_params
    ):
        """Test build_governance_envelope without KMS."""
        from src.gateway.governance.governance_envelope import build_governance_envelope

        # Mock KMS signer as inactive - patch at the source module
        mock_signer = MagicMock()
        mock_signer.kms_active = False

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ):
            envelope = await build_governance_envelope(
                action="execute_trade",
                params=sample_params,
                governance_result=sample_governance_result,
            )

        assert envelope.envelope_type == "cage_governance_decision"
        assert envelope.subject.action == "execute_trade"
        assert envelope.signature is None  # No signature without KMS


# ---------------------------------------------------------------------------
# Tests for envelope types
# ---------------------------------------------------------------------------


class TestEnvelopeTypes:
    """Tests for different envelope types."""

    def test_evidence_record_type(self, sample_governance_result, sample_params):
        """Test creating an evidence record envelope."""
        from src.gateway.governance.governance_envelope import (
            EnvelopeType,
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="store_evidence",
            params=sample_params,
            governance_result=sample_governance_result,
            envelope_type=EnvelopeType.EVIDENCE_RECORD,
        )

        assert envelope.envelope_type == "cage_evidence_record"

    def test_policy_attestation_type(self, sample_governance_result, sample_params):
        """Test creating a policy attestation envelope."""
        from src.gateway.governance.governance_envelope import (
            EnvelopeType,
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="attest_policy",
            params=sample_params,
            governance_result=sample_governance_result,
            envelope_type=EnvelopeType.POLICY_ATTESTATION,
        )

        assert envelope.envelope_type == "cage_policy_attestation"

    def test_audit_checkpoint_type(self, sample_governance_result, sample_params):
        """Test creating an audit checkpoint envelope."""
        from src.gateway.governance.governance_envelope import (
            EnvelopeType,
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="checkpoint",
            params=sample_params,
            governance_result=sample_governance_result,
            envelope_type=EnvelopeType.AUDIT_CHECKPOINT,
        )

        assert envelope.envelope_type == "cage_audit_checkpoint"


# ---------------------------------------------------------------------------
# Tests for v2.0 wire format changes
# ---------------------------------------------------------------------------


class TestWireFormatV2:
    """Tests verifying the v2.0 wire format changes."""

    def test_envelope_version_is_2_1(self, sample_governance_result, sample_params):
        """Verify envelope_version is now 2.1."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        assert envelope.envelope_version == "2.1"

    def test_envelope_type_uses_cage_prefix(
        self, sample_governance_result, sample_params
    ):
        """Verify envelope_type uses 'cage_' prefix instead of 'agw_'."""
        from src.gateway.governance.governance_envelope import (
            EnvelopeType,
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()

        # Test all envelope types have cage_ prefix
        for etype in EnvelopeType:
            envelope = builder.build_unsigned(
                action="test",
                params=sample_params,
                governance_result=sample_governance_result,
                envelope_type=etype,
            )
            assert envelope.envelope_type.startswith("cage_"), (
                f"Expected cage_ prefix for {etype}"
            )
            assert not envelope.envelope_type.startswith("agw_"), (
                f"Should not have agw_ prefix for {etype}"
            )

    def test_envelope_id_uses_cage_prefix(
        self, sample_governance_result, sample_params
    ):
        """Verify envelope_id uses 'cage-' prefix instead of 'agw-'."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        assert envelope.envelope_id.startswith("cage-"), (
            f"Expected cage- prefix, got {envelope.envelope_id}"
        )
        assert not envelope.envelope_id.startswith("agw-"), (
            "Should not have agw- prefix"
        )

    def test_enum_values_use_cage_prefix(self):
        """Verify EnvelopeType enum values use 'cage_' prefix."""
        from src.gateway.governance.governance_envelope import EnvelopeType

        assert EnvelopeType.GOVERNANCE_DECISION.value == "cage_governance_decision"
        assert EnvelopeType.EVIDENCE_RECORD.value == "cage_evidence_record"
        assert EnvelopeType.POLICY_ATTESTATION.value == "cage_policy_attestation"
        assert EnvelopeType.AUDIT_CHECKPOINT.value == "cage_audit_checkpoint"


# ---------------------------------------------------------------------------
# Tests for External Attestations (v2.1)
# ---------------------------------------------------------------------------


class TestExternalAttestations:
    """Tests verifying the external_attestations[] envelope extension."""

    def test_attestation_status_enum(self):
        """Verify AttestationStatus enum values."""
        from src.gateway.governance.governance_envelope import AttestationStatus

        assert AttestationStatus.VERIFIED.value == "VERIFIED"
        assert AttestationStatus.DENIED.value == "DENIED"
        assert AttestationStatus.STALE.value == "STALE"
        assert AttestationStatus.DRIFT_DETECTED.value == "DRIFT_DETECTED"
        assert AttestationStatus.ERROR.value == "ERROR"

    def test_external_attestation_to_dict(self):
        """Verify ExternalAttestation serializes properly with flattened metadata."""
        from src.gateway.governance.governance_envelope import (
            AttestationStatus,
            ExternalAttestation,
        )

        att = ExternalAttestation(
            attestation_type="BLUEPRINT",
            status=AttestationStatus.VERIFIED.value,
            receipt_id="veip-receipt-001",
            attested_at="2026-08-21T12:00:00.000Z",
            metadata={
                "threshold_id": "THR-FIN-006",
                "ao_signature_hash": "sha256:fedcba",
            },
        )

        d = att.to_dict()
        assert d["type"] == "BLUEPRINT"
        assert d["status"] == "VERIFIED"
        assert d["receipt_id"] == "veip-receipt-001"
        assert d["attested_at"] == "2026-08-21T12:00:00.000Z"
        assert d["threshold_id"] == "THR-FIN-006"
        assert d["ao_signature_hash"] == "sha256:fedcba"

    def test_envelope_to_dict_omits_empty_attestations(
        self, sample_governance_result, sample_params
    ):
        """Verify to_dict() omits external_attestations key when list is empty (backward compat)."""
        from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
        )

        d = envelope.to_dict()
        assert "external_attestations" not in d

    def test_envelope_to_dict_includes_populated_attestations(
        self, sample_governance_result, sample_params
    ):
        """Verify to_dict() includes external_attestations when present."""
        from src.gateway.governance.governance_envelope import (
            AttestationStatus,
            ExternalAttestation,
            GovernanceEnvelopeBuilder,
        )

        att = ExternalAttestation(
            attestation_type="KEY",
            status=AttestationStatus.VERIFIED.value,
            receipt_id="veip-key-123",
            attested_at="2026-08-21T12:00:00.000Z",
            metadata={"ca_fingerprint": "sha256:abcd"},
        )

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
            external_attestations=[att],
        )

        d = envelope.to_dict()
        assert "external_attestations" in d
        assert len(d["external_attestations"]) == 1
        assert d["external_attestations"][0]["type"] == "KEY"
        assert d["external_attestations"][0]["ca_fingerprint"] == "sha256:abcd"

    def test_attestations_participate_in_digest_and_tamper_evidence(
        self, sample_governance_result, sample_params
    ):
        """Verify mutating an attestation field changes the computed digest."""
        from src.gateway.governance.governance_envelope import (
            AttestationStatus,
            ExternalAttestation,
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()

        att1 = ExternalAttestation(
            attestation_type="BLUEPRINT",
            status=AttestationStatus.VERIFIED.value,
            receipt_id="receipt-1",
            attested_at="2026-08-21T12:00:00.000Z",
        )
        env1 = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
            external_attestations=[att1],
        )
        digest1 = env1.compute_digest()

        # Same envelope structure without attestations has different digest
        env_no_att = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
            external_attestations=[],
        )
        # Ensure identical IDs/timestamps for comparison
        env_no_att.envelope_id = env1.envelope_id
        env_no_att.issued_at = env1.issued_at
        env_no_att.expires_at = env1.expires_at
        assert env_no_att.compute_digest() != digest1

        # Mutated attestation receipt_id changes digest
        att2 = ExternalAttestation(
            attestation_type="BLUEPRINT",
            status=AttestationStatus.VERIFIED.value,
            receipt_id="receipt-TAMPERED",
            attested_at="2026-08-21T12:00:00.000Z",
        )
        env2 = builder.build_unsigned(
            action="test",
            params=sample_params,
            governance_result=sample_governance_result,
            external_attestations=[att2],
        )
        env2.envelope_id = env1.envelope_id
        env2.issued_at = env1.issued_at
        env2.expires_at = env1.expires_at
        assert env2.compute_digest() != digest1

    def test_envelope_from_dict_roundtrip_with_attestations(
        self, sample_governance_result, sample_params
    ):
        """Verify _envelope_from_dict deserializes external_attestations correctly."""
        from src.gateway.governance.governance_envelope import (
            AttestationStatus,
            ExternalAttestation,
            GovernanceEnvelopeBuilder,
        )

        att = ExternalAttestation(
            attestation_type="PHYSICS",
            status=AttestationStatus.VERIFIED.value,
            receipt_id="receipt-phys-99",
            attested_at="2026-08-21T12:00:00.000Z",
            metadata={"node_id": "gke-node-1", "freshness_seconds": 15},
        )

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_transfer",
            params=sample_params,
            governance_result=sample_governance_result,
            external_attestations=[att],
        )

        serialized = envelope.to_dict()
        reconstructed = builder._envelope_from_dict(serialized)

        assert reconstructed.envelope_version == "2.1"
        assert len(reconstructed.external_attestations) == 1
        recon_att = reconstructed.external_attestations[0]
        assert recon_att.attestation_type == "PHYSICS"
        assert recon_att.status == "VERIFIED"
        assert recon_att.receipt_id == "receipt-phys-99"
        assert recon_att.attested_at == "2026-08-21T12:00:00.000Z"
        assert recon_att.metadata["node_id"] == "gke-node-1"
        assert recon_att.metadata["freshness_seconds"] == 15
        assert reconstructed.compute_digest() == envelope.compute_digest()
