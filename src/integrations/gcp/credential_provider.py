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
GCP OIDC Credential Provider — Layer 3 Cloud Run Metadata Server Adapter.

Acquires OIDC ID tokens from the GCP metadata server for inter-service
authentication between Cloud Run services.

Architecture:
    - Mints audience-scoped ID tokens via metadata server endpoint.
    - Caches tokens until TTL expiration (default 55 minutes, 5-minute safety margin).
    - Thread-safe with explicit locking for cache updates.
    - Fails closed on network errors (raises RuntimeError).

Metadata Server Protocol:
    - Endpoint: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
    - Query parameter: audience=<target_url>
    - Required header: Metadata-Flavor: Google
    - Response: Raw JWT string (not JSON-wrapped)

Usage:
    from src.integrations.gcp.credential_provider import GcpOidcCredentialProvider

    provider = GcpOidcCredentialProvider.from_env()
    token = await provider.get_token(target_url="https://downstream.example.com")
    headers = {"Authorization": token.authorization_header}
"""

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import ClassVar

import httpx

from src.gateway.governance.http_client_factory import create_async_client
from src.gateway.governance.seams.outbound_credential import BearerToken

logger = logging.getLogger(__name__)

# GCP metadata server endpoint for OIDC ID tokens
METADATA_SERVER_ENDPOINT = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)

# Default token TTL: 55 minutes (allowing 5-minute safety margin before 1-hour expiry)
DEFAULT_TOKEN_TTL_SECONDS = 3300


class GcpOidcCredentialProvider:
    """
    GCP Cloud Run OIDC ID token provider with TTL-aware caching.

    Thread-safe implementation with explicit locking around cache updates.
    """

    # Class-level client (shared across instances, lazy-initialized)
    _client: ClassVar[httpx.AsyncClient | None] = None
    _client_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> None:
        """
        Initialize GCP OIDC credential provider.

        Args:
            token_ttl_seconds: Token cache TTL in seconds (default 55 minutes).
        """
        self._token_ttl_seconds = token_ttl_seconds
        self._cache: dict[str, BearerToken] = {}
        self._cache_lock = threading.Lock()

    @classmethod
    def from_env(cls, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> "GcpOidcCredentialProvider":
        """
        Create provider from environment (no configuration needed for GCP metadata server).

        Args:
            token_ttl_seconds: Token cache TTL in seconds.

        Returns:
            Configured GcpOidcCredentialProvider instance.
        """
        return cls(token_ttl_seconds=token_ttl_seconds)

    @classmethod
    def _get_client(cls) -> httpx.AsyncClient:
        """
        Get or create shared async HTTP client (lazy initialization, thread-safe).

        Returns:
            Shared httpx.AsyncClient instance.
        """
        if cls._client is None:
            with cls._client_lock:
                if cls._client is None:
                    # Metadata server is local, use shorter timeout (5 seconds)
                    cls._client = create_async_client(timeout_seconds=5.0)
        return cls._client

    async def get_token(self, target_url: str) -> BearerToken:
        """
        Get OIDC ID token for target URL (cached if valid, minted if expired/missing).

        Args:
            target_url: Destination service URL (used as OIDC audience claim).

        Returns:
            BearerToken with valid (non-expired) token scoped to target_url.

        Raises:
            RuntimeError: If metadata server request fails or returns invalid response.
        """
        # Check cache first (fast path, read-only lock not needed for atomic dict reads)
        cached_token = self._cache.get(target_url)
        if cached_token is not None and not cached_token.is_expired:
            logger.debug("Using cached OIDC token for audience=%s", target_url)
            return cached_token

        # Cache miss or expired — mint fresh token (exclusive lock)
        with self._cache_lock:
            # Double-check cache after acquiring lock (another thread may have updated)
            cached_token = self._cache.get(target_url)
            if cached_token is not None and not cached_token.is_expired:
                logger.debug("Using cached OIDC token for audience=%s (cache hit after lock)", target_url)
                return cached_token

            # Mint fresh token from metadata server
            logger.info("Minting fresh OIDC token for audience=%s", target_url)
            fresh_token = await self._mint_token(audience=target_url)
            self._cache[target_url] = fresh_token
            return fresh_token

    async def _mint_token(self, audience: str) -> BearerToken:
        """
        Mint fresh OIDC ID token from GCP metadata server.

        Args:
            audience: Target service URL (OIDC audience claim).

        Returns:
            BearerToken with freshly minted token.

        Raises:
            RuntimeError: If metadata server request fails or returns non-200 status.
        """
        client = self._get_client()
        headers = {"Metadata-Flavor": "Google"}
        params = {"audience": audience}

        try:
            response = await client.get(
                METADATA_SERVER_ENDPOINT,
                headers=headers,
                params=params,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "GCP metadata server returned status %d for audience=%s: %s",
                exc.response.status_code,
                audience,
                exc.response.text,
            )
            raise RuntimeError(
                f"Failed to mint OIDC token for audience={audience}: "
                f"HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "GCP metadata server request failed for audience=%s: %s",
                audience,
                exc,
            )
            raise RuntimeError(
                f"Failed to reach GCP metadata server for audience={audience}: {exc}"
            ) from exc

        # Response is raw JWT string (not JSON-wrapped)
        token_string = response.text.strip()
        if not token_string:
            raise RuntimeError(f"GCP metadata server returned empty token for audience={audience}")

        # Calculate expiry (current time + TTL)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._token_ttl_seconds)

        logger.info(
            "Minted OIDC token for audience=%s (expires_at=%s)",
            audience,
            expires_at.isoformat(),
        )

        return BearerToken(
            token=token_string,
            expires_at=expires_at,
            audience=audience,
        )
