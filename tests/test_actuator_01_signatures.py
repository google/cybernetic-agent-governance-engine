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
test_actuator_01_signatures.py — Ed25519 Signature Construction Tests

Tests for the quorum signature construction per Phase 2, Stream C.
"""

import hashlib

import pytest

from src.gateway.governance.kms_signer import KMSGovernanceSigner
from src.integrations.actuator_01.signatures import (
    ACTUATOR_01_DOMAIN_TAG_QUORUM,
    Ed25519KeyPairSigner,
    SandboxSigningBundle,
    build_webauthn_approval,
    sign_for_quorum,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestQuorumSignatures:
    """Test quorum signature construction."""

    def test_sign_for_quorum_produces_lowercase_hex(self, monkeypatch):
        """Quorum signatures are lowercase hex (wire contract requirement)."""
        # Mock signer with test key
        mock_signature = b"a" * 64  # 64-byte Ed25519 signature

        class MockSigner:
            is_kms_active = True

            def sign_raw(self, message: bytes) -> bytes:
                return mock_signature

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        sig_hex = sign_for_quorum(signer, canonical_bytes)

        # Should be lowercase hex
        assert sig_hex == mock_signature.hex().lower()
        assert sig_hex == sig_hex.lower()  # No uppercase letters
        assert len(sig_hex) == 128  # 64 bytes = 128 hex chars

    def test_sign_for_quorum_uses_domain_tag(self, monkeypatch):
        """Quorum signatures use ACTUATOR_01_DOMAIN_TAG_QUORUM to prevent replay."""
        signed_message = None

        class MockSigner:
            is_kms_active = True

            def sign_raw(self, message: bytes) -> bytes:
                nonlocal signed_message
                signed_message = message
                return b"x" * 64

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        sign_for_quorum(signer, canonical_bytes)

        # Verify the signed message starts with domain tag
        assert signed_message is not None
        assert signed_message.startswith(ACTUATOR_01_DOMAIN_TAG_QUORUM)

        # Verify the digest is appended after the tag
        body_digest = hashlib.sha256(canonical_bytes).digest()
        expected_message = ACTUATOR_01_DOMAIN_TAG_QUORUM + body_digest
        assert signed_message == expected_message

    def test_sign_for_quorum_fails_when_kms_inactive(self):
        """sign_for_quorum raises RuntimeError if KMS is not active."""

        class MockSigner:
            is_kms_active = False

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        with pytest.raises(RuntimeError, match="KMS is not active"):
            sign_for_quorum(signer, canonical_bytes)

    def test_domain_tag_isolation(self):
        """ACTUATOR_01_DOMAIN_TAG_QUORUM is distinct and prevents cross-context replay."""
        tag = ACTUATOR_01_DOMAIN_TAG_QUORUM

        # Verify it's the wire-protocol value (ARCHYTAN_QUORUM_V1:)
        # The constant name is anonymized; the runtime value matches Archytan kernel contract.
        assert tag == b"ARCHYTAN_QUORUM_V1:"

        # Verify it's bytes (not string)
        assert isinstance(tag, bytes)


class TestSandboxSigningAndWebAuthn:
    """Tests for Ed25519KeyPairSigner, SandboxSigningBundle, and build_webauthn_approval."""

    def test_seed_signer_matches_archytan_vector_keys(self):
        """Ed25519KeyPairSigner.from_seed_hex reproduces Archytan golden public keys."""
        op1 = Ed25519KeyPairSigner.from_seed_hex(
            "01" * 32, "urn:archytan:op:test_vector_1"
        )
        policy = Ed25519KeyPairSigner.from_seed_hex(
            "07" * 32, "urn:archytan:cage:policy-authority"
        )
        assert (
            op1.public_key_hex
            == "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        )
        assert (
            policy.public_key_hex
            == "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        )

    def test_build_webauthn_approval_produces_verifiable_fido2_fields(self):
        """build_webauthn_approval produces valid 37-byte UV=1 auth_data and Ed25519 sig."""
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        approver = Ed25519KeyPairSigner.from_seed_hex(
            "04" * 32, "urn:archytan:op:test_vector_3_approver"
        )
        record = build_webauthn_approval(
            action="payment.wire.execute",
            target="account:1234",
            approver_urn="urn:archytan:op:test_vector_3_op1",
            webauthn_approver_urn=approver.signer_urn,
            decision="ALLOW",
            issued_at=1785012000,
            signer=approver,
        )
        assert len(record["challenge_binding"]) == 64

        def _b64u_dec(s: str) -> bytes:
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        auth_data = _b64u_dec(record["authenticator_data"])
        client_data = _b64u_dec(record["client_data_json"])
        sig = _b64u_dec(record["signature"])

        assert len(auth_data) == 37
        assert auth_data[32] == 0x05  # UP | UV required by Archytan kernel
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(approver.public_key_hex))
        pub.verify(sig, auth_data + hashlib.sha256(client_data).digest())

    def test_sandbox_signing_bundle_roundtrip(self, tmp_path):
        """SandboxSigningBundle loads generated keys and resolves per-operator signers."""
        from deployment.certs.actuator_01.generate_signing_keys import (
            generate_sandbox_keys,
        )

        manifest = generate_sandbox_keys(tmp_path, overwrite=True)
        bundle = SandboxSigningBundle.from_directory(tmp_path)

        assert (
            bundle.policy_signer.public_key_hex
            == manifest["keys"]["policy_authority"]["public_key_hex"]
        )
        assert len(bundle.operator_urns) == 2
        alice_signer = bundle.resolve_signer("urn:archytan:cage:operator:test-alice")
        bob_signer = bundle.resolve_signer("urn:archytan:cage:operator:test-bob")
        assert alice_signer is not bob_signer

        with pytest.raises(KeyError, match="Unknown operator URN"):
            bundle.resolve_signer("urn:archytan:cage:operator:unregistered")
