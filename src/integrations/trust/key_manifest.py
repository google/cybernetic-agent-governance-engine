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
Out-of-band Ed25519 key manifest client, resolved by ``kid``.

Shared by every partner adapter that verifies partner-signed artefacts
(receipts, attestations), so a fix to key resolution is applied once.

Trust Anchor Invariant:
    Keys are resolved ONLY from an independently fetched JWKS manifest, never
    from the signed document itself. An unknown ``kid`` returns ``None`` and the
    caller must fail closed.

Security properties:
- URL scheme allow-list (http/https/file) checked before any fetch (Bandit B310).
- Only ``kty=OKP, crv=Ed25519`` keys are loaded.
- TTL-bounded in-memory cache so rotated-out keys stop verifying.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("cage.integrations.trust.key_manifest")

_ALLOWED_SCHEMES = ("http", "https", "file")


class Ed25519KeyResolver(Protocol):
    """Anything that resolves an Ed25519 public key by ``kid`` (None if unknown)."""

    async def get_key(self, kid: str) -> Ed25519PublicKey | None: ...


class Ed25519KeyManifestClient:
    """Fetch and cache Ed25519 public keys from a JWKS manifest by ``kid``."""

    def __init__(
        self,
        manifest_url: str,
        cache_ttl_seconds: int = 3600,
        timeout_seconds: float = 5.0,
    ) -> None:
        """
        Args:
            manifest_url: JWKS manifest location (http://, https://, or file://).
            cache_ttl_seconds: Cache lifetime before the manifest is re-fetched.
            timeout_seconds: HTTP fetch timeout.

        Raises:
            ValueError: If the URL scheme is not allow-listed (Bandit B310).
        """
        parsed = urlparse(manifest_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
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
        """Resolve a public key by ``kid``; ``None`` if absent (fail closed).

        Raises:
            httpx.HTTPError: If the manifest fetch fails.
            ValueError: If the manifest is malformed.
        """
        cache_age = time.time() - self._cache_timestamp
        if cache_age > self._cache_ttl_seconds or not self._key_cache:
            await self._refresh_keys()

        key = self._key_cache.get(kid)
        if key is None:
            logger.warning(
                "Unknown kid=%r in key manifest (url=%s); caller must fail closed.",
                kid,
                self._manifest_url,
            )
        return key

    async def _refresh_keys(self) -> None:
        logger.info(
            "Refreshing key manifest from %s (timeout=%.1fs)",
            self._manifest_url,
            self._timeout_seconds,
        )
        parsed = urlparse(self._manifest_url)
        if parsed.scheme == "file":
            with open(Path(parsed.path)) as f:
                jwks_data = json.load(f)
        else:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.get(self._manifest_url)
                response.raise_for_status()
                jwks_data = response.json()

        if not isinstance(jwks_data, dict) or "keys" not in jwks_data:
            raise ValueError("Invalid JWKS manifest: missing 'keys' array")

        new_cache: dict[str, Ed25519PublicKey] = {}
        for jwk in jwks_data["keys"]:
            if not isinstance(jwk, dict):
                continue
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            kid = jwk.get("kid")
            x_b64 = jwk.get("x")
            if not kid or not x_b64:
                logger.warning("Skipping JWK with missing kid or x")
                continue
            try:
                public_key_bytes = base64.urlsafe_b64decode(x_b64 + "==")
                new_cache[kid] = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            except Exception as exc:
                logger.warning("Failed to parse Ed25519 key kid=%s: %s", kid, exc)

        self._key_cache = new_cache
        self._cache_timestamp = time.time()
        logger.info(
            "Key manifest cache updated with %d keys (ttl=%ds)",
            len(new_cache),
            self._cache_ttl_seconds,
        )
