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
test_provider_06_receipt_signature.py — Cryptographic Receipt Verification Tests
=================================================================================

Tests Ed25519 signature verification for Agent Integrity receipts following the
Trust Anchor Invariant: never verify against keys embedded in signed payloads.

Verification Flow Under Test:
1. Receipt digest verification (SHA-256 JCS)
2. Public key resolution from out-of-band JWKS manifest
3. Ed25519 signature verification over canonical payload
4. Expiration timestamp validation

All tests use deterministic test fixtures from test_key_pair.py (kid="test-key-1").
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.integrations.provider_06.adapter import Provider06AgentIntegrityAdapter
from src.integrations.provider_06.signature import (
    verify_receipt_digest,
    verify_receipt_signature,
)
from tests.integrations.provider_06.fixtures.test_key_pair import (
    TEST_KEY_ID,
    get_test_private_key,
    get_test_public_key_jwk,
)

# Hermetic: tests cryptographic verification with deterministic fixtures, no live services
pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


def create_test_receipt(
    verification_result: dict[str, Any] | None = None,
    envelope_digest: str = "test-envelope-digest-abc123",
    expires_in_days: int = 365,
) -> dict[str, Any]:
    """
    Create a cryptographically valid test receipt signed with test-key-1.

    Args:
        verification_result: IntegrityResult dict (defaults to PASS)
        envelope_digest: Envelope digest to embed
        expires_in_days: Days until receipt expires (negative = expired)

    Returns:
        Complete AlphaIntegrityReceipt with valid Ed25519 signature
    """
    if verification_result is None:
        verification_result = {
            "protocolVersion": "1-alpha",
            "status": "PASS",
            "findings": [],
        }

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=expires_in_days)

    # Build receipt payload (before signature)
    payload = {
        "protocolVersion": "1-alpha",
        "receiptVersion": "2-alpha",
        "engineVersion": "0.2.0-test",
        "issuer": "test-issuer",
        "audience": "cage-test",
        "purpose": "verification",
        "nonce": "test-nonce-12345",
        "runId": "test-run-001",
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "policyDigest": hashlib.sha256(b"test-policy").hexdigest(),
        "envelopeDigest": envelope_digest,
        "verification": verification_result,
    }

    # Canonicalize for signing (excludes signature and receiptDigest)
    payload_bytes = jcs_canonicalize_plan(payload)

    # Sign with test private key
    private_key = get_test_private_key()
    signature_bytes = private_key.sign(payload_bytes)
    signature_value = base64.urlsafe_b64encode(signature_bytes).decode("ascii").rstrip("=")

    # Compute receiptDigest
    receipt_digest = hashlib.sha256(payload_bytes).hexdigest()

    return {
        **payload,
        "signature": {
            "algorithm": "Ed25519",
            "keyId": TEST_KEY_ID,
            "value": signature_value,
        },
        "receiptDigest": receipt_digest,
    }


def create_jwks_manifest() -> dict[str, Any]:
    """Create JWKS manifest containing test-key-1."""
    return {"keys": [get_test_public_key_jwk()]}


# ---------------------------------------------------------------------------
# Receipt Digest Verification Tests
# ---------------------------------------------------------------------------


class TestReceiptDigestVerification:
    """Tests for receipt digest verification (SHA-256 JCS)."""

    def test_valid_receipt_digest_verifies_successfully(self) -> None:
        """Valid receipt with correct receiptDigest passes verification."""
        receipt = create_test_receipt()
        assert verify_receipt_digest(receipt) is True

    def test_tampered_receipt_body_fails_digest_verification(self) -> None:
        """Mutating receipt body (without updating digest) fails verification."""
        receipt = create_test_receipt()

        # Tamper with a field inside the canonical payload
        receipt["nonce"] = "TAMPERED-NONCE-67890"

        # Digest verification should fail (digest was computed over original nonce)
        assert verify_receipt_digest(receipt) is False

    def test_missing_receipt_digest_fails_closed(self) -> None:
        """Receipt missing receiptDigest field fails verification."""
        receipt = create_test_receipt()
        del receipt["receiptDigest"]

        assert verify_receipt_digest(receipt) is False

    def test_empty_receipt_digest_fails_closed(self) -> None:
        """Receipt with empty receiptDigest fails verification."""
        receipt = create_test_receipt()
        receipt["receiptDigest"] = ""

        assert verify_receipt_digest(receipt) is False


# ---------------------------------------------------------------------------
# Ed25519 Signature Verification Tests
# ---------------------------------------------------------------------------


class TestEd25519SignatureVerification:
    """Tests for Ed25519 signature verification over JCS canonical payload."""

    def test_valid_receipt_signature_verifies_successfully(self) -> None:
        """Valid receipt signed with test-key-1 passes signature verification."""
        receipt = create_test_receipt()
        public_key_jwk = get_test_public_key_jwk()

        # Decode public key from JWK
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        # Verify signature
        assert verify_receipt_signature(receipt, public_key) is True

    def test_tampered_signature_value_fails_closed(self) -> None:
        """Corrupted signature value fails verification (InvalidSignature)."""
        receipt = create_test_receipt()
        public_key_jwk = get_test_public_key_jwk()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        # Corrupt the signature bytes deterministically: decode the raw 64-byte
        # Ed25519 signature, XOR the first byte by 0xFF (always changes it), then
        # re-encode. Simply replacing "X" in the base64 string is non-deterministic
        # — when the original signature happens to start with "X", the tamper is a
        # no-op and verify() returns True.
        original_sig = receipt["signature"]["value"]
        sig_bytes = bytearray(base64.urlsafe_b64decode(original_sig + "=="))
        sig_bytes[0] ^= 0xFF  # guaranteed to differ from the original
        tampered_sig = base64.urlsafe_b64encode(bytes(sig_bytes)).decode("ascii").rstrip("=")
        assert tampered_sig != original_sig, "XOR tamper must produce a different signature"
        receipt["signature"]["value"] = tampered_sig

        # Signature verification should fail
        assert verify_receipt_signature(receipt, public_key) is False

    def test_tampered_receipt_body_fails_signature_verification(self) -> None:
        """Mutating receipt payload invalidates signature."""
        receipt = create_test_receipt()
        public_key_jwk = get_test_public_key_jwk()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        # Tamper with payload after signing
        receipt["envelopeDigest"] = "TAMPERED-ENVELOPE-DIGEST"

        # Signature verification should fail (digest mismatch)
        assert verify_receipt_signature(receipt, public_key) is False

    def test_missing_signature_block_fails_closed(self) -> None:
        """Receipt missing signature block fails verification."""
        receipt = create_test_receipt()
        public_key_jwk = get_test_public_key_jwk()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        del receipt["signature"]

        assert verify_receipt_signature(receipt, public_key) is False

    def test_missing_signature_value_fails_closed(self) -> None:
        """Receipt with signature block but no value fails verification."""
        receipt = create_test_receipt()
        public_key_jwk = get_test_public_key_jwk()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        receipt["signature"]["value"] = ""

        assert verify_receipt_signature(receipt, public_key) is False


# ---------------------------------------------------------------------------
# Adapter Integration Tests (End-to-End Verification)
# ---------------------------------------------------------------------------


class TestAdapterReceiptVerification:
    """Integration tests for adapter.submit_evidence() with cryptographic verification."""

    @pytest.mark.asyncio
    async def test_valid_receipt_signature_verifies_successfully(self) -> None:
        """Valid receipt from mock endpoint passes all cryptographic checks."""
        # Mock JWKS client to return test public key
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()

            # Decode public key from JWK
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key_jwk = get_test_public_key_jwk()
            public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            mock_client.get_key.return_value = public_key
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create a valid receipt
            receipt = create_test_receipt(envelope_digest="test-evidence-hash")

            # Mock HTTP response
            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                result = await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Should succeed (no error)
            assert result.error is None
            assert result.seal_hash == receipt["receiptDigest"]

    @pytest.mark.asyncio
    async def test_unknown_kid_fails_closed(self) -> None:
        """Receipt with unknown keyId produces cage.unknown_key error."""
        # Mock JWKS client to return None for unknown kid
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()
            mock_client.get_key.return_value = None  # Unknown kid
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create receipt with unknown keyId
            receipt = create_test_receipt()
            receipt["signature"]["keyId"] = "unknown-key-999"

            # Mock HTTP response
            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                result = await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Should fail with unknown key error
            assert result.error is not None
            assert "unknown key" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tampered_receipt_body_fails_closed(self) -> None:
        """Receipt with tampered body produces cage.receipt_digest_mismatch error."""
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key_jwk = get_test_public_key_jwk()
            public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            mock_client.get_key.return_value = public_key
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create valid receipt, then tamper with it
            receipt = create_test_receipt()
            receipt["nonce"] = "TAMPERED-NONCE"  # Mutate payload

            # Mock HTTP response
            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                result = await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Should fail (digest mismatch)
            assert result.error is not None
            assert "digest" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tampered_signature_value_fails_closed(self) -> None:
        """Receipt with corrupted signature produces cage.invalid_signature error."""
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key_jwk = get_test_public_key_jwk()
            public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            mock_client.get_key.return_value = public_key
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create valid receipt, then corrupt signature
            receipt = create_test_receipt()
            original_sig = receipt["signature"]["value"]
            receipt["signature"]["value"] = "X" + original_sig[1:]  # Flip first char

            # Mock HTTP response
            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                result = await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Should fail (signature verification failed)
            assert result.error is not None
            assert "signature" in result.error.lower()

    @pytest.mark.asyncio
    async def test_expired_receipt_fails_closed(self) -> None:
        """Receipt with expiresAt timestamp in the past produces cage.expired_receipt error."""
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key_jwk = get_test_public_key_jwk()
            public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            mock_client.get_key.return_value = public_key
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create receipt that expired 1 day ago
            receipt = create_test_receipt(expires_in_days=-1)

            # Mock HTTP response
            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                result = await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Should fail (receipt expired)
            assert result.error is not None
            assert "expired" in result.error.lower()


# ---------------------------------------------------------------------------
# Trust Anchor Invariant Tests
# ---------------------------------------------------------------------------


class TestTrustAnchorInvariant:
    """Tests enforcing the Trust Anchor Invariant: never parse keys from signed payloads."""

    @pytest.mark.asyncio
    async def test_public_key_resolved_from_independent_jwks_only(self) -> None:
        """Public keys are resolved from JWKS manifest, not from receipt payload."""
        with patch(
            "src.integrations.provider_06.adapter.Provider06KeyManifestClient"
        ) as MockJWKSClient:
            mock_client = AsyncMock()

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key_jwk = get_test_public_key_jwk()
            public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            mock_client.get_key.return_value = public_key
            MockJWKSClient.return_value = mock_client

            adapter = Provider06AgentIntegrityAdapter(
                endpoint="http://localhost:8090",
                key_manifest_url="file:///test/manifest.json",
            )

            # Create receipt (key resolution happens via JWKS client, not receipt)
            receipt = create_test_receipt()

            with patch("httpx.AsyncClient") as MockHTTPClient:
                client_instance = AsyncMock()
                from unittest.mock import MagicMock
                mock_response = MagicMock()
                mock_response.json.return_value = receipt
                client_instance.post.return_value = mock_response
                MockHTTPClient.return_value.__aenter__.return_value = client_instance

                await adapter.submit_evidence(
                    thread_id="test-thread",
                    evidence_hash="test-evidence-hash",
                )

            # Verify get_key was called with the kid from receipt
            mock_client.get_key.assert_called_once_with(TEST_KEY_ID)

    def test_receipt_never_contains_embedded_public_key(self) -> None:
        """Receipt structure does not include embedded public key (only keyId reference)."""
        receipt = create_test_receipt()

        # Assert signature block contains keyId but NOT a public key (x/y/n/e)
        signature_block = receipt["signature"]
        assert "keyId" in signature_block
        assert "x" not in signature_block  # Ed25519 JWK public key parameter
        assert "n" not in signature_block  # RSA public key parameter
        assert "publicKey" not in signature_block  # Generic embedded key
