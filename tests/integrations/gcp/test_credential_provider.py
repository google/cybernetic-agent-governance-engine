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
Tests for GCP OIDC Credential Provider.

Test Coverage:
    1. Token minting success (mock metadata server returns JWT)
    2. Token caching (same URL = cached token, no second request)
    3. Audience scoping (different URLs = different tokens)
    4. Cache expiry (expired token triggers fresh mint)
    5. Metadata server unreachable (raises RuntimeError, fail-closed)
    6. Manual integration test docstring (wrong-audience returns 403)
"""

from datetime import datetime, timedelta, timezone
import httpx
import pytest
import respx

from src.gateway.governance.seams.outbound_credential import BearerToken
from src.integrations.gcp.credential_provider import (
    DEFAULT_TOKEN_TTL_SECONDS,
    METADATA_SERVER_ENDPOINT,
    GcpOidcCredentialProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_jwt_token() -> str:
    """Return a synthetic JWT token for testing."""
    # Realistic JWT structure (header.payload.signature)
    return (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJhdWQiOiJodHRwczovL2Rvd25zdHJlYW0uZXhhbXBsZS5jb20iLCJleHAiOjE3MzAwMDAwMDAsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSJ9."
        "signature-placeholder"
    )


@pytest.fixture
def provider() -> GcpOidcCredentialProvider:
    """Return a fresh GcpOidcCredentialProvider instance."""
    return GcpOidcCredentialProvider.from_env()


@pytest.mark.asyncio
async def test_token_minting_success(provider: GcpOidcCredentialProvider, mock_jwt_token: str) -> None:
    """Test 1: Token minting succeeds when metadata server returns valid JWT."""
    target_url = "https://downstream.example.com"

    with respx.mock:
        # Mock metadata server response
        mock_route = respx.get(METADATA_SERVER_ENDPOINT).mock(
            return_value=httpx.Response(200, text=mock_jwt_token)
        )

        # Get token (should mint fresh)
        token = await provider.get_token(target_url)

        # Verify request was made with correct parameters
        assert mock_route.called
        request = mock_route.calls[0].request
        assert request.url.params["audience"] == target_url
        assert request.headers["Metadata-Flavor"] == "Google"

        # Verify token structure
        assert isinstance(token, BearerToken)
        assert token.token == mock_jwt_token
        assert token.audience == target_url
        assert not token.is_expired
        assert token.authorization_header == f"Bearer {mock_jwt_token}"

        # Verify expiry is ~55 minutes in the future
        expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_TOKEN_TTL_SECONDS)
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 5  # Allow 5-second tolerance


@pytest.mark.asyncio
async def test_token_caching(provider: GcpOidcCredentialProvider, mock_jwt_token: str) -> None:
    """Test 2: Same URL returns cached token without second metadata server request."""
    target_url = "https://downstream.example.com"

    with respx.mock:
        # Mock metadata server response (should only be called once)
        mock_route = respx.get(METADATA_SERVER_ENDPOINT).mock(
            return_value=httpx.Response(200, text=mock_jwt_token)
        )

        # First call: mints fresh token
        token1 = await provider.get_token(target_url)
        assert mock_route.call_count == 1

        # Second call: returns cached token (no second request)
        token2 = await provider.get_token(target_url)
        assert mock_route.call_count == 1  # Still 1, not 2

        # Verify both tokens are identical
        assert token1.token == token2.token
        assert token1.expires_at == token2.expires_at
        assert token1.audience == token2.audience


@pytest.mark.asyncio
async def test_audience_scoping(provider: GcpOidcCredentialProvider, mock_jwt_token: str) -> None:
    """Test 3: Different target URLs mint different tokens (audience-scoped)."""
    url1 = "https://service-a.example.com"
    url2 = "https://service-b.example.com"

    with respx.mock:
        # Mock metadata server to return different tokens for different audiences
        respx.get(METADATA_SERVER_ENDPOINT, params={"audience": url1}).mock(
            return_value=httpx.Response(200, text=f"{mock_jwt_token}-service-a")
        )
        respx.get(METADATA_SERVER_ENDPOINT, params={"audience": url2}).mock(
            return_value=httpx.Response(200, text=f"{mock_jwt_token}-service-b")
        )

        # Get tokens for both URLs
        token1 = await provider.get_token(url1)
        token2 = await provider.get_token(url2)

        # Verify tokens are different
        assert token1.token != token2.token
        assert token1.audience == url1
        assert token2.audience == url2
        assert token1.token.endswith("-service-a")
        assert token2.token.endswith("-service-b")


@pytest.mark.asyncio
async def test_cache_expiry_triggers_refresh(mock_jwt_token: str) -> None:
    """Test 4: Expired cached token triggers fresh mint from metadata server."""
    target_url = "https://downstream.example.com"
    
    # Use very short TTL (1 second) to test expiry behavior
    provider = GcpOidcCredentialProvider(token_ttl_seconds=1)

    with respx.mock:
        # First token mint
        mock_route = respx.get(METADATA_SERVER_ENDPOINT).mock(
            return_value=httpx.Response(200, text=f"{mock_jwt_token}-v1")
        )

        # Get initial token
        token1 = await provider.get_token(target_url)
        assert mock_route.call_count == 1
        assert token1.token.endswith("-v1")

        # Manually expire the token by updating cache entry
        expired_token = BearerToken(
            token=token1.token,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),  # 10 seconds ago
            audience=target_url,
        )
        provider._cache[target_url] = expired_token

        # Update mock to return different token
        mock_route.return_value = httpx.Response(200, text=f"{mock_jwt_token}-v2")

        # Get token again (should mint fresh because cached one is expired)
        token2 = await provider.get_token(target_url)
        assert mock_route.call_count == 2  # Second request made
        assert token2.token.endswith("-v2")
        assert not token2.is_expired


@pytest.mark.asyncio
async def test_metadata_server_unreachable(provider: GcpOidcCredentialProvider) -> None:
    """Test 5: Metadata server unreachable raises RuntimeError (fail-closed)."""
    target_url = "https://downstream.example.com"

    with respx.mock:
        # Simulate network error (connection refused)
        respx.get(METADATA_SERVER_ENDPOINT).mock(side_effect=httpx.ConnectError("Connection refused"))

        # Verify that get_token raises RuntimeError
        with pytest.raises(RuntimeError, match="Failed to reach GCP metadata server"):
            await provider.get_token(target_url)


@pytest.mark.asyncio
async def test_metadata_server_http_error(provider: GcpOidcCredentialProvider) -> None:
    """Test 5b: Metadata server HTTP error (4xx/5xx) raises RuntimeError."""
    target_url = "https://downstream.example.com"

    with respx.mock:
        # Simulate HTTP 500 error
        respx.get(METADATA_SERVER_ENDPOINT).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        # Verify that get_token raises RuntimeError
        with pytest.raises(RuntimeError, match="Failed to mint OIDC token.*HTTP 500"):
            await provider.get_token(target_url)


@pytest.mark.asyncio
async def test_metadata_server_empty_response(provider: GcpOidcCredentialProvider) -> None:
    """Test 5c: Metadata server returns empty token raises RuntimeError."""
    target_url = "https://downstream.example.com"

    with respx.mock:
        # Simulate empty response
        respx.get(METADATA_SERVER_ENDPOINT).mock(return_value=httpx.Response(200, text=""))

        # Verify that get_token raises RuntimeError
        with pytest.raises(RuntimeError, match="returned empty token"):
            await provider.get_token(target_url)


def test_manual_integration_test_docstring() -> None:
    """
    Test 6: Manual integration test instructions (wrong-audience verification).

    This test documents the manual verification procedure for OIDC audience
    claim validation. It is not an automated test, but a runbook for engineers.

    Manual Test Procedure (requires GCP Cloud Run environment):
    ==============================================================

    1. Deploy two Cloud Run services in the same project:
       - Service A (invoker): Makes HTTP requests with OIDC tokens
       - Service B (receiver): Validates incoming OIDC tokens

    2. Configure Service B to require authentication:
       ```bash
       gcloud run services add-iam-policy-binding service-b \\
         --member="serviceAccount:service-a@PROJECT.iam.gserviceaccount.com" \\
         --role="roles/run.invoker"
       ```

    3. From Service A, attempt to call Service B with wrong-audience token:
       ```python
       from src.integrations.gcp.credential_provider import GcpOidcCredentialProvider

       provider = GcpOidcCredentialProvider.from_env()
       
       # Mint token for WRONG audience
       token = await provider.get_token(target_url="https://wrong-service.run.app")
       
       # Attempt to call Service B with wrong token
       response = await httpx.get(
           "https://service-b.run.app/endpoint",
           headers={"Authorization": token.authorization_header}
       )
       ```

    4. Expected result: HTTP 403 Forbidden
       - Service B's IAM layer should reject the token because the audience
         claim does not match Service B's URL.

    5. Repeat with correct audience:
       ```python
       token = await provider.get_token(target_url="https://service-b.run.app")
       response = await httpx.get(
           "https://service-b.run.app/endpoint",
           headers={"Authorization": token.authorization_header}
       )
       ```

    6. Expected result: HTTP 200 OK (or 2xx, depending on endpoint logic)
       - Service B accepts the token because audience matches.

    This verifies that:
        - GCP Cloud Run enforces audience claim validation.
        - Wrong-audience tokens are rejected (fail-closed security boundary).
        - The credential provider correctly scopes tokens to target URLs.
    """
    # This is a documentation-only test; no assertions needed.
    pass


@pytest.mark.asyncio
async def test_bearer_token_is_expired_property() -> None:
    """Test BearerToken.is_expired property correctly detects expiry."""
    # Non-expired token (1 hour in future)
    future_token = BearerToken(
        token="test-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        audience="https://example.com",
    )
    assert not future_token.is_expired

    # Expired token (1 hour in past)
    past_token = BearerToken(
        token="test-token",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        audience="https://example.com",
    )
    assert past_token.is_expired

    # Edge case: exactly now (should be considered expired)
    now_token = BearerToken(
        token="test-token",
        expires_at=datetime.now(timezone.utc),
        audience="https://example.com",
    )
    assert now_token.is_expired


@pytest.mark.asyncio
async def test_bearer_token_authorization_header_format() -> None:
    """Test BearerToken.authorization_header returns correct format."""
    token = BearerToken(
        token="my-secret-token-12345",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        audience="https://example.com",
    )
    assert token.authorization_header == "Bearer my-secret-token-12345"
