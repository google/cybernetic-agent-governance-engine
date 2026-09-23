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
JWKS Client for Out-of-Band Ed25519 Key Resolution (Provider 06).

Implements key resolution from a remote or local JWKS manifest with in-memory
caching and TTL-based expiration. Enforces the Trust Anchor Invariant: never
parse keys supplied inside signed message payloads.

Key Resolution Flow:
1. Check in-memory cache against TTL
2. On cache miss/expiry, fetch JWKS manifest via HTTP, HTTPS, or file://
3. Parse Ed25519 keys matching kty="OKP", crv="Ed25519"
4. Return None if kid is unknown (caller must fail closed)

Security Invariants:
- URL scheme validation (http/https/file only) for Bandit B310 compliance
- Independent key manifest (never embedded in signed payload)
- TTL-based cache invalidation to prevent stale key reuse
- Fail-closed on unknown kid (returns None, not exception)
"""

from __future__ import annotations

import base64
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("cage.provider_06.jwks_client")


class Provider06KeyManifestClient:
    """
    Out-of-band JWKS client for Ed25519 public key resolution.

    Fetches and caches Ed25519 public keys from a remote JWKS endpoint or
    local file. Keys are resolved by kid (Key Identifier) and cached in-memory
    with TTL.

    Attributes:
        manifest_url: URL of the JWKS manifest (http://, https://, or file://)
        cache_ttl_seconds: Time-to-live for cached keys (default: 3600)
        timeout_seconds: HTTP request timeout (default: 5.0)
    """

    def __init__(
        self,
        manifest_url: str,
        cache_ttl_seconds: int = 3600,
        timeout_seconds: float = 5.0,
    ) -> None:
        """
        Initialize JWKS client with URL validation and cache configuration.

        Args:
            manifest_url: JWKS manifest endpoint (http://, https://, or file://)
            cache_ttl_seconds: Cache TTL in seconds (default: 1 hour)
            timeout_seconds: HTTP request timeout (default: 5 seconds)

        Raises:
            ValueError: If manifest_url scheme is not http, https, or file
                       (Bandit B310 safe)
        """
        # Bandit B310: Validate URL scheme before httpx can use it
        parsed = urlparse(manifest_url)
        if parsed.scheme not in ("http", "https", "file"):
            raise ValueError(
                f"Invalid JWKS URL scheme: {parsed.scheme!r}. "
                f"Only 'http', 'https', and 'file' are allowed (Bandit B310 compliance)."
            )

        self._manifest_url = manifest_url
        self._cache_ttl_seconds = cache_ttl_seconds
        self._timeout_seconds = timeout_seconds
        self._key_cache: dict[str, Ed25519PublicKey] = {}
        self._cache_timestamp: float = 0.0

    async def get_key(self, kid: str) -> Ed25519PublicKey | None:
        """
        Resolve Ed25519 public key by Key Identifier (kid).

        Checks in-memory cache first. On cache miss or TTL expiry, fetches
        the JWKS manifest from the remote endpoint or local file and parses
        Ed25519 keys.

        Trust Anchor Invariant:
            Keys are ONLY resolved from the independently-fetched JWKS manifest.
            Never parse keys from the signed message payload itself.

        Args:
            kid: Key Identifier to resolve

        Returns:
            Ed25519PublicKey if kid is found in manifest, None otherwise
            (caller must fail closed on None)

        Raises:
            httpx.HTTPError: If JWKS fetch fails (network/HTTP errors)
            ValueError: If JWKS manifest is malformed
        """
        # Check cache validity
        current_time = time.time()
        cache_age = current_time - self._cache_timestamp

        # Cache miss or expired: refresh from remote
        if cache_age > self._cache_ttl_seconds or not self._key_cache:
            await self._refresh_keys()

        # Resolve key from cache
        key = self._key_cache.get(kid)
        if key is None:
            logger.warning(
                "provider_06: Unknown kid=%r in JWKS manifest (url=%s). "
                "Caller must fail closed.",
                kid,
                self._manifest_url,
            )
        return key

    async def _refresh_keys(self) -> None:
        """
        Fetch JWKS manifest and update in-memory cache.

        Parses Ed25519 keys matching:
            kty="OKP" (Octet Key Pair)
            crv="Ed25519" (Edwards-Curve Digital Signature Algorithm)
            x=<base64url public key bytes>

        Raises:
            httpx.HTTPError: If HTTP request fails
            ValueError: If JWKS JSON is malformed or keys are invalid
        """
        logger.info(
            "provider_06: Refreshing JWKS from %s (timeout=%.1fs)",
            self._manifest_url,
            self._timeout_seconds,
        )

        parsed = urlparse(self._manifest_url)

        # Handle file:// URLs
        if parsed.scheme == "file":
            import json

            file_path = Path(parsed.path)
            with open(file_path) as f:
                jwks_data = json.load(f)
        else:
            # HTTP/HTTPS fetch
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.get(self._manifest_url)
                response.raise_for_status()
                jwks_data = response.json()

        if not isinstance(jwks_data, dict) or "keys" not in jwks_data:
            raise ValueError(
                f"Invalid JWKS manifest: missing 'keys' array. Got: {jwks_data}"
            )

        new_cache: dict[str, Ed25519PublicKey] = {}
        for jwk in jwks_data["keys"]:
            if not isinstance(jwk, dict):
                continue

            # Filter Ed25519 keys only
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue

            kid = jwk.get("kid")
            x_b64 = jwk.get("x")

            if not kid or not x_b64:
                logger.warning(
                    "provider_06: Skipping JWK with missing kid or x: %s", jwk
                )
                continue

            try:
                # Decode base64url public key bytes (32 bytes for Ed25519)
                public_key_bytes = base64.urlsafe_b64decode(x_b64 + "==")
                public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                new_cache[kid] = public_key
                logger.debug("provider_06: Loaded Ed25519 key kid=%s", kid)
            except Exception as exc:
                logger.warning(
                    "provider_06: Failed to parse Ed25519 key kid=%s: %s", kid, exc
                )
                continue

        self._key_cache = new_cache
        self._cache_timestamp = time.time()
        logger.info(
            "provider_06: JWKS cache updated with %d keys (ttl=%ds)",
            len(new_cache),
            self._cache_ttl_seconds,
        )
