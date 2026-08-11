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
tests/test_nexart_provider.py — Tests for the NexArt Attestation Provider.

Verification invariants:
  1. CER creation via certifyDecision returns CERReceipt.
  2. Fail-closed on timeout/error returns CERReceipt with error.
  3. JWK cache starts empty and populates on sync.
  4. JWK staleness detection works at TTL boundary.
  5. Local verification uses cached JWKs (no network call).
  6. Remote verification fallback when JWK cache is empty.
  7. Provider factory resolves "nexart" correctly.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.nexart.provider import (
    CERReceipt,
    JWKCache,
    NexArtAttestationProvider,
)

# ---------------------------------------------------------------------------
# Test 1: CER creation
# ---------------------------------------------------------------------------


class TestCERCreation:
    """Tests for certifyDecision CER creation."""

    @pytest.mark.asyncio
    async def test_certify_decision_returns_receipt(self):  # type: ignore[no-untyped-def]
        """Successful certifyDecision returns a valid CERReceipt."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "certificateHash": "abc123def456",
            "receiptUrl": "https://verify.nexart.io/cer/abc123def456",
            "signerKeyId": "key-001",
            "signedAt": "2026-05-29T14:00:00Z",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            provider = NexArtAttestationProvider(
                endpoint="https://api.nexart.io/v1",
                api_key="test-key",
            )
            cer = await provider.certify_decision({"test": True})

            assert cer.is_valid
            assert cer.certificate_hash == "abc123def456"
            assert cer.signer_key_id == "key-001"

    @pytest.mark.asyncio
    async def test_certify_decision_fails_closed_on_error(self):  # type: ignore[no-untyped-def]
        """Network error returns CERReceipt with error field."""
        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.side_effect = Exception("Connection refused")
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            provider = NexArtAttestationProvider(
                endpoint="https://api.nexart.io/v1",
            )
            cer = await provider.certify_decision({"test": True})

            assert not cer.is_valid
            assert "Connection refused" in cer.error  # type: ignore[operator]  # cer.error is str when is_valid=False; None only on success path


# ---------------------------------------------------------------------------
# Test 2: JWK caching
# ---------------------------------------------------------------------------


class TestJWKCache:
    """Tests for JWK cache behavior."""

    def test_empty_cache_has_no_keys(self):  # type: ignore[no-untyped-def]
        """Fresh JWK cache has no keys."""
        cache = JWKCache()
        assert not cache.has_keys
        assert cache.is_stale

    def test_populated_cache_has_keys(self):  # type: ignore[no-untyped-def]
        """Cache with keys reports has_keys=True."""
        cache = JWKCache(
            jwk_set={"keys": [{"kid": "key-001", "kty": "OKP", "crv": "Ed25519"}]},
            last_synced=time.time(),
        )
        assert cache.has_keys
        assert not cache.is_stale

    def test_staleness_at_ttl_boundary(self):  # type: ignore[no-untyped-def]
        """Cache becomes stale after TTL expires."""
        cache = JWKCache(
            jwk_set={"keys": [{"kid": "key-001"}]},
            last_synced=time.time() - (25 * 3600),  # 25 hours ago (TTL is 24h)
        )
        assert cache.is_stale

    @pytest.mark.asyncio
    async def test_sync_populates_cache(self):  # type: ignore[no-untyped-def]
        """JWK sync fetches keys and updates cache."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "keys": [
                {"kid": "nexart-ed25519-001", "kty": "OKP", "crv": "Ed25519"},
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"ETag": '"v1"'}

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            provider = NexArtAttestationProvider(
                endpoint="https://api.nexart.io/v1",
                jwk_endpoint="https://jwks.nexart.io/.well-known/jwks.json",
            )

            await provider._sync_jwks()

            assert provider.has_jwk_keys
            assert provider._jwk_cache.etag == '"v1"'


# ---------------------------------------------------------------------------
# Test 3: CER verification
# ---------------------------------------------------------------------------


class TestCERVerification:
    """Tests for CER verification."""

    @pytest.mark.asyncio
    async def test_local_verification_with_cached_keys(self):  # type: ignore[no-untyped-def]
        """With cached JWKs, verify_cer uses local verification."""
        provider = NexArtAttestationProvider(endpoint="https://api.nexart.io/v1")
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{"kid": "key-001", "kty": "OKP", "crv": "Ed25519"}]},
            last_synced=time.time(),
        )

        # Valid SHA-256 hash (64 hex chars)
        valid_hash = "a" * 64
        result = await provider.verify_cer(valid_hash)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_local_verification_rejects_invalid_hash(self):  # type: ignore[no-untyped-def]
        """Local verification rejects hash with wrong length."""
        provider = NexArtAttestationProvider(endpoint="https://api.nexart.io/v1")
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{"kid": "key-001"}]},
            last_synced=time.time(),
        )

        result = await provider.verify_cer("too_short")
        assert result.valid is False
        assert "length" in result.error  # type: ignore[operator]  # result.error is str when valid=False; None only on success path

    @pytest.mark.asyncio
    async def test_remote_fallback_when_cache_empty(self):  # type: ignore[no-untyped-def]
        """When JWK cache is empty, falls back to remote verification."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "valid": True,
            "signer": "nexart-node",
            "timestamp": "2026-05-29T14:00:00Z",
            "keyId": "key-001",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            provider = NexArtAttestationProvider(
                endpoint="https://api.nexart.io/v1",
            )
            # No JWK cache — should fall back to remote
            result = await provider.verify_cer("a" * 64)

            assert result.valid is True
            assert result.signer == "nexart-node"
            mock_instance.get.assert_called_once()


# ---------------------------------------------------------------------------
# Test 4: Provider factory
# ---------------------------------------------------------------------------


class TestProviderFactory:
    """Tests for normative_provider factory registration."""

    def test_nexart_provider_resolves(self):  # type: ignore[no-untyped-def]
        """get_normative_provider('nexart') returns NexArtAttestationProvider."""
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider("nexart")
        assert isinstance(provider, NexArtAttestationProvider)

    def test_invalid_provider_raises_with_nexart_in_list(self):  # type: ignore[no-untyped-def]
        """Invalid provider name includes 'nexart' in the error message."""
        from src.gateway.governance.normative_provider import get_normative_provider

        with pytest.raises(ValueError, match="nexart"):
            get_normative_provider("nonexistent")


# ---------------------------------------------------------------------------
# Test 5: CERReceipt data contract
# ---------------------------------------------------------------------------


class TestCERReceipt:
    """Tests for CERReceipt data contract."""

    def test_valid_receipt(self):  # type: ignore[no-untyped-def]
        receipt = CERReceipt(certificate_hash="abc123", receipt_url="https://...")
        assert receipt.is_valid

    def test_receipt_with_error(self):  # type: ignore[no-untyped-def]
        receipt = CERReceipt(error="Connection refused")
        assert not receipt.is_valid

    def test_empty_hash_is_invalid(self):  # type: ignore[no-untyped-def]
        receipt = CERReceipt(certificate_hash="")
        assert not receipt.is_valid


# ---------------------------------------------------------------------------
# Test 6: Provider lifecycle
# ---------------------------------------------------------------------------


class TestProviderLifecycle:
    """Tests for provider start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_stop_without_jwk_endpoint(self):  # type: ignore[no-untyped-def]
        """Provider starts and stops cleanly without JWK endpoint."""
        provider = NexArtAttestationProvider(
            endpoint="https://api.nexart.io/v1",
        )
        await provider.start()
        assert provider._running is True

        await provider.stop()
        assert provider._running is False

    def test_auth_headers(self):  # type: ignore[no-untyped-def]
        """Provider generates correct auth headers."""
        provider = NexArtAttestationProvider(
            endpoint="https://api.nexart.io/v1",
            api_key="test-key-123",
        )
        headers = provider._headers()
        assert headers["Authorization"] == "Bearer test-key-123"
        assert headers["Content-Type"] == "application/json"
