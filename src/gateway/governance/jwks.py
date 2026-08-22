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
JWKS — JSON Web Key Set Management for Multi-Key Rotation Support.

This module provides:
1. JWK generation from PEM-encoded public keys (single key)
2. JWKSet management for multi-key rotation scenarios
3. Key caching with configurable TTL for performance
4. `kid` (Key ID) extraction from JWT headers for verification routing

Key rotation workflow:
    1. New signing key is provisioned in KMS
    2. Gateway fetches new public key and adds to JWKSet
    3. Old key remains in JWKSet for grace period (verifiers can still validate old signatures)
    4. After grace period, old key is removed from JWKSet

External verifiers fetch the JWKSet from /.well-known/jwks.json or /governance/jwks
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

logger = logging.getLogger("Gateway.Governance.JWKS")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How long to cache the JWKSet before refreshing from KMS (seconds)
_JWKS_CACHE_TTL_S: int = int(os.environ.get("CAGE_JWKS_CACHE_TTL_S", "300"))

# Maximum number of keys to keep in the JWKSet (oldest keys are rotated out)
_JWKS_MAX_KEYS: int = int(os.environ.get("CAGE_JWKS_MAX_KEYS", "3"))


def _to_base64url(b: bytes) -> str:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _compute_kid(pem_bytes: bytes) -> str:
    """Compute a stable kid by hashing the PEM content (first 16 bytes of SHA-256)."""
    return _to_base64url(hashlib.sha256(pem_bytes).digest()[:16])


def pem_to_jwk(pem_bytes: bytes, kid: str | None = None) -> dict[str, Any]:
    """Parse a PEM public key and format it as a JWK dictionary.

    Supports Ed25519, RSA, and Elliptic Curve (P-256, P-384, P-521) keys.
    Computes a stable `kid` by hashing the underlying PEM string if not provided.

    Args:
        pem_bytes: The public key in PEM format.
        kid: Optional Key ID. If not provided, computed from PEM hash.

    Returns:
        dict: The formatted JSON Web Key dictionary.

    Raises:
        ValueError: If the key type is unsupported.
    """
    pub = serialization.load_pem_public_key(pem_bytes)
    computed_kid = kid or _compute_kid(pem_bytes)

    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _to_base64url(raw),
            "kid": computed_kid,
            "use": "sig",
            "alg": "EdDSA",
        }

    elif isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        # Determine algorithm based on key size
        key_bits = pub.key_size
        alg = "RS256" if key_bits <= 2048 else "RS384" if key_bits <= 3072 else "RS512"
        return {
            "kty": "RSA",
            "n": _to_base64url(n_bytes),
            "e": _to_base64url(e_bytes),
            "kid": computed_kid,
            "use": "sig",
            "alg": alg,
        }

    elif isinstance(pub, ec.EllipticCurvePublicKey):
        ec_numbers = pub.public_numbers()
        curve_name = pub.curve.name
        crv_map = {
            "secp256r1": ("P-256", "ES256"),
            "secp384r1": ("P-384", "ES384"),
            "secp521r1": ("P-521", "ES512"),
        }
        crv, alg = crv_map.get(curve_name, (curve_name, "ES256"))
        key_size = (pub.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": crv,
            "x": _to_base64url(ec_numbers.x.to_bytes(key_size, "big")),
            "y": _to_base64url(ec_numbers.y.to_bytes(key_size, "big")),
            "kid": computed_kid,
            "use": "sig",
            "alg": alg,
        }

    raise ValueError(f"Unsupported key type: {type(pub)}")


# ---------------------------------------------------------------------------
# JWKSet — Multi-Key Management with Caching
# ---------------------------------------------------------------------------


@dataclass
class CachedKey:
    """A cached JWK with metadata for rotation management."""

    jwk: dict[str, Any]
    pem_bytes: bytes
    added_at: float = field(default_factory=time.time)
    expires_at: float | None = None  # None = no expiry (current active key)

    @property
    def kid(self) -> str:
        """Return the key ID."""
        return self.jwk["kid"]

    def is_expired(self, now: float | None = None) -> bool:
        """Return True if this key has expired and should be removed."""
        if self.expires_at is None:
            return False
        return (now or time.time()) > self.expires_at


class JWKSet:
    """Thread-safe JWK Set manager with caching and rotation support.

    Maintains a set of public keys for JWT verification, supporting:
    - Automatic key rotation with grace periods
    - Caching with configurable TTL
    - Thread-safe access for concurrent verification
    - Maximum key limit to bound memory usage

    Usage:
        jwks = JWKSet()
        jwks.add_key(pem_bytes)  # Add new signing key
        jwks_dict = jwks.to_dict()  # Get JWKSet for /jwks endpoint
        jwk = jwks.get_key("kid123")  # Get specific key by kid
    """

    def __init__(
        self,
        cache_ttl_s: int = _JWKS_CACHE_TTL_S,
        max_keys: int = _JWKS_MAX_KEYS,
    ):
        self._keys: dict[str, CachedKey] = {}
        self._lock = threading.RLock()
        self._cache_ttl_s = cache_ttl_s
        self._max_keys = max_keys
        self._last_refresh: float = 0.0

    def add_key(
        self,
        pem_bytes: bytes,
        kid: str | None = None,
        grace_period_s: float | None = None,
    ) -> str:
        """Add a new public key to the JWKSet.

        Args:
            pem_bytes: The public key in PEM format.
            kid: Optional Key ID. If not provided, computed from PEM hash.
            grace_period_s: If set, marks this key as expiring after this many seconds.
                           Used for old keys during rotation.

        Returns:
            The kid of the added key.
        """
        jwk = pem_to_jwk(pem_bytes, kid)
        computed_kid = jwk["kid"]

        expires_at = None
        if grace_period_s is not None:
            expires_at = time.time() + grace_period_s

        cached = CachedKey(
            jwk=jwk,
            pem_bytes=pem_bytes,
            expires_at=expires_at,
        )

        with self._lock:
            # If we're at max capacity and this is a new key, remove oldest
            if computed_kid not in self._keys and len(self._keys) >= self._max_keys:
                self._evict_oldest()

            self._keys[computed_kid] = cached
            logger.info(
                "🔑 Added key to JWKSet: kid=%s expires=%s",
                computed_kid,
                expires_at,
            )

        return computed_kid

    def get_key(self, kid: str) -> dict[str, Any] | None:
        """Get a JWK by its key ID.

        Args:
            kid: The key ID to look up.

        Returns:
            The JWK dictionary, or None if not found or expired.
        """
        with self._lock:
            cached = self._keys.get(kid)
            if cached is None:
                return None
            if cached.is_expired():
                del self._keys[kid]
                logger.info("🔑 Removed expired key from JWKSet: kid=%s", kid)
                return None
            return cached.jwk

    def get_pem(self, kid: str) -> bytes | None:
        """Get the PEM bytes for a key ID (used for JWT verification).

        Args:
            kid: The key ID to look up.

        Returns:
            The PEM bytes, or None if not found or expired.
        """
        with self._lock:
            cached = self._keys.get(kid)
            if cached is None:
                return None
            if cached.is_expired():
                del self._keys[kid]
                return None
            return cached.pem_bytes

    def remove_key(self, kid: str) -> bool:
        """Remove a key from the JWKSet.

        Args:
            kid: The key ID to remove.

        Returns:
            True if the key was removed, False if it wasn't found.
        """
        with self._lock:
            if kid in self._keys:
                del self._keys[kid]
                logger.info("🔑 Removed key from JWKSet: kid=%s", kid)
                return True
            return False

    def rotate_key(
        self,
        new_pem_bytes: bytes,
        grace_period_s: float = 3600.0,
    ) -> str:
        """Rotate to a new signing key while keeping the old key for a grace period.

        This marks all existing keys as expiring and adds the new key as the active key.

        Args:
            new_pem_bytes: The new public key in PEM format.
            grace_period_s: How long to keep old keys valid (default: 1 hour).

        Returns:
            The kid of the new active key.
        """
        with self._lock:
            now = time.time()
            # Mark all existing keys as expiring
            for cached in self._keys.values():
                if cached.expires_at is None:
                    cached.expires_at = now + grace_period_s

            # Add the new key (no expiry — it's the active key)
            return self.add_key(new_pem_bytes)

    def to_dict(self) -> dict[str, Any]:
        """Export the JWKSet as a dictionary for the /jwks endpoint.

        Automatically removes expired keys during export.

        Returns:
            JWKSet dictionary with "keys" array.
        """
        with self._lock:
            now = time.time()
            # Remove expired keys
            expired_kids = [
                kid for kid, cached in self._keys.items() if cached.is_expired(now)
            ]
            for kid in expired_kids:
                del self._keys[kid]
                logger.info("🔑 Removed expired key from JWKSet: kid=%s", kid)

            # Build the JWKSet
            return {
                "keys": [cached.jwk for cached in self._keys.values()],
            }

    def _evict_oldest(self) -> None:
        """Remove the oldest key to make room for a new one."""
        if not self._keys:
            return

        oldest_kid = min(self._keys.keys(), key=lambda k: self._keys[k].added_at)
        del self._keys[oldest_kid]
        logger.info("🔑 Evicted oldest key from JWKSet: kid=%s", oldest_kid)

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)


# ---------------------------------------------------------------------------
# Global JWKSet Singleton
# ---------------------------------------------------------------------------

_global_jwks: JWKSet | None = None
_global_jwks_lock = threading.Lock()


def get_jwks() -> JWKSet:
    """Get the global JWKSet singleton, initializing from KMS if needed."""
    global _global_jwks

    with _global_jwks_lock:
        if _global_jwks is None:
            _global_jwks = JWKSet()
            _initialize_jwks_from_kms(_global_jwks)
        return _global_jwks


def _initialize_jwks_from_kms(jwks: JWKSet) -> None:
    """Initialize the JWKSet from the KMS signer's public key(s)."""
    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        signer = get_governance_signer()
        if not signer.is_kms_active:
            logger.warning("⚠️ KMS not active — JWKSet will be empty")
            return

        # Get public key(s) from the signer
        if signer._provider:
            try:
                # Try multi-key method first
                pem_dict = signer._provider.get_public_keys_pem()
                for _key_id, pem_bytes in pem_dict.items():
                    jwks.add_key(pem_bytes)
                logger.info(
                    "✅ JWKSet initialized with %d key(s) from KMS", len(pem_dict)
                )
            except AttributeError:
                # Fallback to single-key method
                pem_bytes = signer._provider.get_public_key_pem()
                jwks.add_key(pem_bytes)
                logger.info("✅ JWKSet initialized with 1 key from KMS")
        elif signer._public_key_pem:
            jwks.add_key(signer._public_key_pem)
            logger.info("✅ JWKSet initialized with 1 key from local PEM")
    except Exception as e:
        logger.error("❌ Failed to initialize JWKSet from KMS: %s", e)


# ---------------------------------------------------------------------------
# JWT kid Extraction
# ---------------------------------------------------------------------------


def extract_kid_from_jwt(token: str) -> str | None:
    """Extract the `kid` (Key ID) from a JWT header without verifying the signature.

    This is used to route to the correct verification key before verification.

    Args:
        token: The JWT token string.

    Returns:
        The kid from the JWT header, or None if not present or invalid.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode header (first part)
        header_b64 = parts[0]
        # Add padding if needed
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        header_json = base64.urlsafe_b64decode(header_b64)
        import json

        header = json.loads(header_json)
        return header.get("kid")
    except Exception:
        return None


def get_verification_key_for_jwt(token: str) -> bytes | None:
    """Get the PEM-encoded public key for verifying a JWT.

    Extracts the kid from the JWT header and looks up the corresponding key
    in the global JWKSet.

    Args:
        token: The JWT token string.

    Returns:
        The PEM-encoded public key, or None if not found.
    """
    kid = extract_kid_from_jwt(token)
    if kid is None:
        # No kid in header — try to use the first (only) key
        jwks = get_jwks()
        jwks_dict = jwks.to_dict()
        if len(jwks_dict["keys"]) == 1:
            # Single key — use it
            return jwks.get_pem(jwks_dict["keys"][0]["kid"])
        logger.warning("⚠️ JWT has no kid header and JWKSet has multiple keys")
        return None

    return get_jwks().get_pem(kid)
