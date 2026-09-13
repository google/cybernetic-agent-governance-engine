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

"""Tests for Provider02CERResolver.

Verification invariants:
  1. 200 + ETag → resolved=True, status=UNVERIFIED (never VERIFIED)
  2. 304 revalidation → from_cache=True, cached body returned
  3. 404 → STALE, finding message says "unresolvable" (never "absent"/"invalid")
  4. 400 INVALID_HASH_FORMAT → CER_MALFORMED_REF
  5. Timeout → ENDPOINT_ERROR, retryable=True
  6. Digest mismatch → CER_DIGEST_MISMATCH, resolved=False
  7. UUID in hash position → rejected with zero network requests
  8. COMMITMENT-kind address → rejected with zero network requests
  9. Malformed string address → CER_MALFORMED_REF before network call
"""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
import respx

from src.gateway.governance.content_address import ContentAddress, ContentAddressKind
from src.gateway.governance.seams.attestation import AttestationStatus
from src.integrations.provider_02.resolver import Provider02CERResolver

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def resolver() -> Provider02CERResolver:
    """Fixture providing a CER resolver instance."""
    return Provider02CERResolver(
        base_url="https://resolver.provider02.example.com",
        timeout=5.0,
    )


@pytest.fixture
def sample_cer_body() -> dict:
    """Sample CER body with all expected fields."""
    return {
        "version": "1.0",
        "certificateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "decision": {"allowed": True},
        "links": {
            "self": "https://resolver.provider02.example.com/v1/resolve/cer/sha256%3Ae3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "keyManifest": "https://keys.provider02.example.com/manifest/v1",
            "verify": "https://verify.provider02.example.com/cer/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "humanVerifier": "https://verify.provider02.example.com/ui/cer/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "anchors": [
            {"logId": "transparency-log-001", "timestamp": "2026-09-09T12:00:00Z"}
        ],
        "timestamps": [{"tsa": "rfc3161-tsa", "value": "opaque-timestamp-data"}],
    }


@pytest.fixture
def valid_address() -> ContentAddress:
    """Fixture providing a valid sha256 content address."""
    # This is sha256 of empty string for test stability
    return ContentAddress(
        algorithm="sha256",
        hex_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        kind=ContentAddressKind.DIGEST,
    )


class TestSuccessfulResolution:
    """Tests for successful CER resolution with 200 OK."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_200_returns_unverified_never_verified(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sample_cer_body: dict,
    ) -> None:
        """A 200 response MUST map to UNVERIFIED status, never VERIFIED.

        This test would fail if someone changed the mapping to VERIFIED,
        which would be architecturally incorrect - only Phase 3 (signature
        verification) may promote to VERIFIED.
        """
        # Prepare response body with deterministic serialization
        body_bytes = json.dumps(sample_cer_body, separators=(",", ":")).encode("utf-8")
        computed_hash = hashlib.sha256(body_bytes).hexdigest()

        # Update the address to match the computed hash
        address = ContentAddress(
            algorithm="sha256", hex_digest=computed_hash, kind=ContentAddressKind.DIGEST
        )

        # Mock the endpoint - return the exact bytes we hashed
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=body_bytes,
                headers={"ETag": '"abc123"', "Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(address)

        # Verify request was made
        assert route.called

        # Critical assertion: 200 must yield UNVERIFIED, never VERIFIED
        assert result.status == AttestationStatus.UNVERIFIED.value
        assert result.status != AttestationStatus.VERIFIED.value

        # Verify structure
        assert result.resolved is True
        assert result.signature_checked is False
        assert result.etag == '"abc123"'
        assert result.from_cache is False
        assert result.evidence == sample_cer_body
        assert result.links == sample_cer_body["links"]
        assert result.anchors == sample_cer_body["anchors"]
        assert result.timestamps == sample_cer_body["timestamps"]
        assert len(result.findings) == 0

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_etag_caching_and_304_revalidation(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sample_cer_body: dict,
    ) -> None:
        """Second request with matching ETag returns cached data with from_cache=True."""
        # First request - populate cache
        body_bytes = json.dumps(sample_cer_body, separators=(",", ":")).encode("utf-8")
        computed_hash = hashlib.sha256(body_bytes).hexdigest()
        address = ContentAddress(
            algorithm="sha256", hex_digest=computed_hash, kind=ContentAddressKind.DIGEST
        )

        route_200 = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=body_bytes,
                headers={"ETag": '"cache-key-001"', "Content-Type": "application/json"},
            )
        )

        result1 = await resolver.resolve(address)
        assert route_200.called
        assert result1.resolved is True
        assert result1.from_cache is False
        assert result1.etag == '"cache-key-001"'

        # Second request - should send If-None-Match and get 304
        route_304 = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{address.url_encoded}"
        ).mock(return_value=httpx.Response(304))

        result2 = await resolver.resolve(address)
        assert route_304.called

        # Verify If-None-Match header was sent
        assert (
            route_304.calls.last.request.headers.get("If-None-Match")
            == '"cache-key-001"'
        )
        assert result2.resolved is True
        assert result2.from_cache is True
        assert result2.etag == '"cache-key-001"'
        assert result2.evidence == sample_cer_body
        assert result2.status == AttestationStatus.UNVERIFIED.value

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_accepts_string_address(
        self, resolver: Provider02CERResolver, sample_cer_body: dict
    ) -> None:
        """Resolver accepts string addresses and parses before network call."""
        body_bytes = json.dumps(sample_cer_body, separators=(",", ":")).encode("utf-8")
        computed_hash = hashlib.sha256(body_bytes).hexdigest()

        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/sha256%3A{computed_hash}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=body_bytes,
                headers={"ETag": '"test-etag"', "Content-Type": "application/json"},
            )
        )

        # Pass as string
        result = await resolver.resolve(f"sha256:{computed_hash}")

        assert route.called
        assert result.resolved is True
        assert result.status == AttestationStatus.UNVERIFIED.value

        await resolver.close()


class TestErrorHandling:
    """Tests for error conditions and fail-closed semantics."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_404_maps_to_stale_with_unresolvable_message(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """404 response maps to STALE with 'unresolvable' message.

        Critical: The message MUST say 'unresolvable', never 'absent', 'missing',
        or 'invalid'. The vendor returns identical 404 for unknown hashes and
        private receipts - CAGE must not accuse users of fabricating evidence
        that is merely private.
        """
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(404))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.STALE.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_UNRESOLVABLE"
        assert result.findings[0]["retryable"] is False

        # Critical assertion: must say "unresolvable", not "absent" or "invalid"
        message = result.findings[0]["message"].lower()
        assert "unresolvable" in message
        assert "absent" not in message
        assert "invalid" not in message
        assert "missing" not in message

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_invalid_hash_format(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """400 INVALID_HASH_FORMAT maps to CER_MALFORMED_REF."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(400, text="INVALID_HASH_FORMAT"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_endpoint_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Timeout maps to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(side_effect=httpx.TimeoutException("Connection timeout"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_5xx_server_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """5xx server errors map to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(503, text="Service Unavailable"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_transport_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Transport errors map to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(side_effect=httpx.TransportError("Connection reset"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()


class TestDigestVerification:
    """Tests for digest integrity verification."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_digest_mismatch_fails_closed(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Digest mismatch returns ERROR with CER_DIGEST_MISMATCH."""
        # Return a body that doesn't match the address
        wrong_body = {"data": "this will not match the hash"}

        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                json=wrong_body,
                headers={"ETag": '"mismatch-test"'},
            )
        )

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert result.findings[0]["retryable"] is False
        assert "mismatch" in result.findings[0]["message"].lower()

        await resolver.close()


class TestFailClosedBoundaries:
    """Tests for fail-closed rejection of invalid inputs."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_uuid_in_hash_position_rejected_zero_requests(
        self, resolver: Provider02CERResolver
    ) -> None:
        """UUID in digest position is rejected before any network call.

        Critical: respx mock MUST record zero calls. A UUID is never a valid
        hash digest and must be rejected at parse time.
        """
        uuid_string = "sha256:550e8400-e29b-41d4-a716-446655440000"

        # Set up a catch-all route that should never be called
        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(uuid_string)

        # Critical: zero network requests
        assert not route.called
        assert route.call_count == 0

        # Verify fail-closed
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_commitment_kind_rejected_zero_requests(
        self, resolver: Provider02CERResolver
    ) -> None:
        """COMMITMENT-kind addresses are rejected before any network call.

        Critical: respx mock MUST record zero calls. HMAC commitments are
        not dereferenceable public endpoints and must be rejected at the
        resolver boundary.
        """
        commitment = ContentAddress(
            algorithm="hmac-sha256",
            hex_digest="a" * 64,
            kind=ContentAddressKind.COMMITMENT,
        )

        # Set up a catch-all route that should never be called
        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(commitment)

        # Critical: zero network requests
        assert not route.called
        assert route.call_count == 0

        # Verify fail-closed
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False
        assert "COMMITMENT" in result.findings[0]["message"]
        assert "not dereferenceable" in result.findings[0]["message"]

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_malformed_string_rejected_before_network(
        self, resolver: Provider02CERResolver
    ) -> None:
        """Malformed string addresses are rejected before any network call."""
        malformed = "not-a-valid-address"

        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(malformed)

        # No network call should be made
        assert not route.called

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()
