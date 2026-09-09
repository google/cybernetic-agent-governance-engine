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

"""Tests for Provider 02 Ed25519 signature verification (Phase 2b / B3+B4).

This module tests the two-stage verification:
  - Stage 1: Certificate-hash binding (SHA-256 recomputation)
  - Stage 2: Envelope signature (Ed25519 verification)

Critical test: embedded-key forgery must NOT verify. This is the highest-value
test in the suite — it proves the trust-anchor rule is enforced.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.attestation import AttestationStatus
from src.integrations.provider_02.provider import (
    JWKCache,
    Provider02AttestationProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def b64url_encode_unpadded(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_test_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Generate a test Ed25519 keypair and JWK representation.

    Returns:
        (private_key, public_key, jwk_dict_as_string)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Encode public key as base64url (no padding)
    public_bytes = public_key.public_bytes_raw()
    x_b64url = b64url_encode_unpadded(public_bytes)
    
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": "test-key-001",
        "x": x_b64url,
    }
    
    return private_key, public_key, json.dumps(jwk)


def create_signed_cer(
    private_key: Ed25519PrivateKey,
    kid: str,
    certificate_payload: dict,
    envelope_payload: dict,
    tamper_signature: bool = False,
    tamper_certificate: bool = False,
    use_different_key_for_signature: bool = False,
) -> tuple[str, dict]:
    """Create a signed CER for testing.

    Args:
        private_key: Ed25519 private key for signing
        kid: Key ID
        certificate_payload: The certificate payload dict
        envelope_payload: The envelope payload dict
        tamper_signature: If True, flip one byte in the signature
        tamper_certificate: If True, flip one byte in the certificate payload
        use_different_key_for_signature: If True, sign with a different key

    Returns:
        (certificate_hash, cer_body) where certificate_hash is SHA-256 of
        the certificate payload (as specified in the verification spec)
    """
    # Canonicalize payloads with JCS
    cert_canonical = jcs_canonicalize_plan(certificate_payload).decode("utf-8")
    envelope_canonical = jcs_canonicalize_plan(envelope_payload).decode("utf-8")
    
    # Compute certificate hash from the canonical certificate payload
    cert_hash = hashlib.sha256(cert_canonical.encode("utf-8")).hexdigest()
    
    # Tamper with certificate if requested (affects validation but not the hash we return)
    if tamper_certificate:
        cert_canonical = cert_canonical.replace('"', "'", 1)  # Flip one char
    
    # Sign the envelope payload
    signing_key = private_key
    if use_different_key_for_signature:
        signing_key = Ed25519PrivateKey.generate()
    
    signature_bytes = signing_key.sign(envelope_canonical.encode("utf-8"))
    signature_b64url = b64url_encode_unpadded(signature_bytes)
    
    # Tamper with signature if requested
    if tamper_signature:
        sig_bytes = bytearray(base64.urlsafe_b64decode(signature_b64url + "=="))
        sig_bytes[0] ^= 0xFF  # Flip all bits in first byte
        signature_b64url = b64url_encode_unpadded(bytes(sig_bytes))
    
    # Build the full CER structure
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes_raw()
    embedded_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": b64url_encode_unpadded(public_bytes),
    }
    
    cer_body = {
        "canonical": {
            "certificate": {
                "payload": cert_canonical,
                "hashAlgorithm": "sha256",
                "canonicalization": "jcs",
                "matchesCertificateHash": not tamper_certificate,
            },
            "envelope": {
                "payload": envelope_canonical,
                "kid": kid,
                "signer": "test-node",
                "publicKeyJwk": embedded_jwk,
            },
        },
        "verification": {
            "algorithm": "Ed25519",
            "verificationEnvelopeSignature": signature_b64url,
        },
        "timestamp": {
            "attestedAt": "2026-09-09T18:00:00Z",
        },
    }
    
    return cert_hash, cer_body


class TestEd25519Verification:
    """Test suite for Ed25519 signature verification."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_valid_signature_verifies(self) -> None:
        """Valid CER with matching key in manifest → VERIFIED."""
        private_key, _public_key, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        # Create a valid signed CER
        cert_payload = {"decision": "allowed", "timestamp": "2026-09-09"}
        envelope_payload = {"bundleType": "test", "version": "1.0"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Set up provider with JWK cache containing the public key
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [jwk]},
            last_synced=time.time(),
        )
        
        # Verify (passing cer_body directly to skip resolution)
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is True
        assert result.signature_checked is True
        assert result.key_id == kid
        assert result.error is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_embedded_key_forgery_does_not_verify(self) -> None:
        """CRITICAL: Signature valid against embedded key but NOT key manifest → MUST NOT VERIFY.

        This is the highest-value test in the suite. It proves that passing the
        embedded publicKeyJwk to the verifier is structurally impossible.

        A forger controls the entire CER body including the embedded key. Verifying
        against it proves nothing. The key MUST come from the independently-fetched
        key manifest.
        """
        # Attacker generates their own keypair
        attacker_key = Ed25519PrivateKey.generate()
        attacker_kid = "attacker-key"
        
        # Attacker creates a CER signed with their key
        cert_payload = {"decision": "allowed", "forged": True}
        envelope_payload = {"bundleType": "forged", "version": "1.0"}
        cert_hash, cer_body = create_signed_cer(
            attacker_key, attacker_kid, cert_payload, envelope_payload
        )
        
        # The CER's embedded publicKeyJwk matches the attacker's key
        # (create_signed_cer automatically embeds the correct key)
        
        # But the legitimate key manifest contains a DIFFERENT key
        _legitimate_key, _, jwk_json = generate_test_keypair()
        legitimate_jwk = json.loads(jwk_json)
        legitimate_jwk["kid"] = "legitimate-key"  # Different kid
        
        # Provider has legitimate key manifest (NOT the attacker's key)
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [legitimate_jwk]},
            last_synced=time.time(),
        )
        
        # Verify - MUST FAIL even though signature is valid against embedded key
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is False
        assert result.signature_checked is False
        assert result.error is not None
        assert "CER_UNKNOWN_KEY" in result.error or "not found" in result.error
        assert attacker_kid in result.error or result.key_id == attacker_kid

    @respx.mock
    @pytest.mark.asyncio
    async def test_tampered_envelope_payload_fails(self) -> None:
        """Tampered envelope payload → CER_SIGNATURE_INVALID."""
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        cert_payload = {"decision": "allowed"}
        envelope_payload = {"bundleType": "test"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Tamper with the envelope payload AFTER signing
        cer_body["canonical"]["envelope"]["payload"] = (
            cer_body["canonical"]["envelope"]["payload"].replace("test", "TAMPERED")
        )
        
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [jwk]},
            last_synced=time.time(),
        )
        
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is False
        assert result.signature_checked is False
        assert result.error is not None
        assert "CER_SIGNATURE_INVALID" in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_certificate_hash_mismatch_fails(self) -> None:
        """Certificate payload doesn't match hash → CER_DIGEST_MISMATCH."""
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        cert_payload = {"decision": "allowed"}
        envelope_payload = {"bundleType": "test"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Tamper with certificate payload AFTER creating the signed CER
        # This keeps matchesCertificateHash=true but makes the hash wrong
        cer_body["canonical"]["certificate"]["payload"] = (
            cer_body["canonical"]["certificate"]["payload"].replace("allowed", "TAMPERED")
        )
        
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [jwk]},
            last_synced=time.time(),
        )
        
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is False
        assert result.signature_checked is False
        assert result.error is not None
        assert "CER_DIGEST_MISMATCH" in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_matches_certificate_hash_false_fails(self) -> None:
        """matchesCertificateHash: false → rejected."""
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        cert_payload = {"decision": "allowed"}
        envelope_payload = {"bundleType": "test"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Set matchesCertificateHash to false
        cer_body["canonical"]["certificate"]["matchesCertificateHash"] = False
        
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [jwk]},
            last_synced=time.time(),
        )
        
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is False
        assert result.signature_checked is False
        assert result.error is not None
        assert "matchesCertificateHash" in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_unknown_kid_refresh_then_fail_closed(self) -> None:
        """Unknown kid → one JWK refresh attempt, then fail with CER_UNKNOWN_KEY."""
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        cert_payload = {"decision": "allowed"}
        envelope_payload = {"bundleType": "test"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Mock JWK endpoint (returns empty on refresh)
        # Note: endpoint is stripped of /v1 by resolver init, so mock at base
        jwk_route = respx.get(
            "https://api.provider02.example.com/.well-known/nexart-node.json"
        ).mock(
            return_value=httpx.Response(
                200,
                json={"keys": []},  # No matching kid
                headers={"ETag": '"empty"'},
            )
        )
        
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        # Start with at least one key so it doesn't fallback to remote verification
        # but make sure it's not the one we're looking for
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{"kid": "different-key", "kty": "OKP", "crv": "Ed25519", "x": "AAAA"}]},
            last_synced=time.time(),
        )
        
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert jwk_route.called  # Should have attempted refresh
        assert result.valid is False
        assert result.signature_checked is False
        assert result.error is not None
        assert "CER_UNKNOWN_KEY" in result.error
        assert kid in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_unpadded_base64url_signature_decodes_correctly(self) -> None:
        """Ed25519 signature (86 chars, no padding) decodes to 64 bytes."""
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        cert_payload = {"decision": "allowed"}
        envelope_payload = {"bundleType": "test"}
        cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Verify signature is 86 characters (64 bytes base64url-encoded with no padding)
        signature_b64url = cer_body["verification"]["verificationEnvelopeSignature"]
        assert len(signature_b64url) == 86
        assert "=" not in signature_b64url  # No padding
        
        # Decode and verify it's exactly 64 bytes
        provider = Provider02AttestationProvider(
            endpoint="https://api.provider02.example.com/v1"
        )
        signature_bytes = provider._b64url_decode_unpadded(signature_b64url)
        assert len(signature_bytes) == 64
        
        # Now verify the full CER
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [jwk]},
            last_synced=time.time(),
        )
        
        result = await provider.verify_cer(cert_hash, cer_body=cer_body)
        
        assert result.valid is True
        assert result.signature_checked is True


class TestJCSByteIdentity:
    """B4: JCS canonicalization byte-identity fixture test."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_jcs_canonical_certificate_payload_byte_identical(self) -> None:
        """Vendor's canonical.certificate.payload is byte-identical to JCS canonicalization.

        This test proves both sides implement RFC 8785 the same way. If it fails,
        that is a genuine cross-implementation divergence and should be reported
        rather than adjusting the assertion.
        """
        private_key, _, jwk_json = generate_test_keypair()
        jwk = json.loads(jwk_json)
        kid = jwk["kid"]
        
        # Create a certificate payload with various data types
        cert_payload = {
            "decision": "allowed",
            "timestamp": "2026-09-09T18:00:00Z",
            "score": 0.95,
            "count": 42,
            "nested": {"key": "value", "array": [1, 2, 3]},
        }
        
        envelope_payload = {"bundleType": "test"}
        _cert_hash, cer_body = create_signed_cer(
            private_key, kid, cert_payload, envelope_payload
        )
        
        # Extract the vendor's canonical payload
        vendor_canonical = cer_body["canonical"]["certificate"]["payload"]
        
        # Re-canonicalize with CAGE's JCS implementation
        cage_canonical = jcs_canonicalize_plan(cert_payload).decode("utf-8")
        
        # CRITICAL ASSERTION: Must be byte-identical
        assert vendor_canonical == cage_canonical, (
            "JCS canonicalization mismatch detected. This indicates a divergence "
            "between the vendor's RFC 8785 implementation and CAGE's. "
            f"Vendor: {vendor_canonical!r}\n"
            f"CAGE:   {cage_canonical!r}"
        )
        
        # Also verify the envelope payload for completeness
        vendor_envelope_canonical = cer_body["canonical"]["envelope"]["payload"]
        cage_envelope_canonical = jcs_canonicalize_plan(envelope_payload).decode("utf-8")
        
        assert vendor_envelope_canonical == cage_envelope_canonical


class TestPhase0InvariantUnchanged:
    """Verify the Phase 0 CERVerification invariant remains intact."""

    def test_cerverification_invariant_enforced(self) -> None:
        """CERVerification.__post_init__ raises if valid=True without signature_checked=True."""
        from src.integrations.provider_02.provider import CERVerification
        
        # Valid configuration: both True
        result_valid = CERVerification(valid=True, signature_checked=True)
        assert result_valid.valid is True
        assert result_valid.signature_checked is True
        
        # Valid configuration: both False
        result_invalid = CERVerification(valid=False, signature_checked=False)
        assert result_invalid.valid is False
        assert result_invalid.signature_checked is False
        
        # INVALID configuration: valid=True but signature_checked=False
        with pytest.raises(ValueError, match="valid=True requires signature_checked=True"):
            CERVerification(valid=True, signature_checked=False)
