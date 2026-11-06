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

"""Out-of-band RFC 7517 JWKS parsing and bounded resolver for ``CageClient``.

Resolves gateway signing keys strictly by ``kid`` from an independently fetched
JWKS endpoint (``/governance/.well-known/jwks.json``) with single-flight
``asyncio.Lock`` refresh, bounded unknown-``kid`` refresh cooldown, HTTP ``304``
rejection, atomic key replacement on rotation/revocation, and fail-closed
eviction once ``max_jwks_staleness_s`` elapses during a JWKS outage.

Only the two key types the gateway signs with are admitted: EC P-256 (``ES256``)
and Ed25519 (``EdDSA``). A JWKS containing any other key type, curve, or ``alg``
is refused as a whole rather than partially used.
"""

from __future__ import annotations

import asyncio
import base64
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .exceptions import RoutingSealVerificationError

PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_PRIVATE_JWK_FIELDS: frozenset[str] = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
)
_P256_COORDINATE_BYTES = 32
_ED25519_KEY_BYTES = 32


def validate_http_url(url: str, *, field_name: str = "url") -> str:
    """Validate that ``url`` uses ``http://`` or ``https://`` with a non-empty host."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"{field_name} must be a non-empty HTTP(S) URL")
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"{field_name} must use http:// or https:// scheme with host, got {url!r}"
        )
    return cleaned


def b64url_decode(value: str, *, field_name: str = "base64url") -> bytes:
    """Strictly decode a base64url string without silently ignoring invalid chars."""
    if not isinstance(value, str) or not value or not _B64URL_RE.match(value):
        raise RoutingSealVerificationError(
            f"Invalid base64url encoding in {field_name}"
        )
    unpadded = value.rstrip("=")
    if not unpadded or len(unpadded) % 4 == 1:
        raise RoutingSealVerificationError(f"Invalid base64url length in {field_name}")
    padded = unpadded + ("=" * ((4 - len(unpadded) % 4) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise RoutingSealVerificationError(
            f"Failed to decode base64url in {field_name}: {exc}"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != unpadded:
        raise RoutingSealVerificationError(
            f"Non-canonical base64url padding bits in {field_name}"
        )
    return decoded


def _parse_p256_jwk(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    crv_name = jwk.get("crv")
    if crv_name != "P-256":
        raise ValueError(f"EC JWK crv={crv_name!r} is not accepted (only P-256)")
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != "ES256":
        raise ValueError(f"EC P-256 JWK alg={jwk_alg!r} is not ES256")
    x_raw = jwk.get("x")
    y_raw = jwk.get("y")
    if not isinstance(x_raw, str) or not isinstance(y_raw, str):
        raise ValueError("EC JWK missing string 'x' or 'y' coordinate")
    x_bytes = b64url_decode(x_raw, field_name="JWK.x")
    y_bytes = b64url_decode(y_raw, field_name="JWK.y")
    if len(x_bytes) != _P256_COORDINATE_BYTES or len(y_bytes) != _P256_COORDINATE_BYTES:
        raise ValueError(
            f"EC P-256 JWK coordinates must be {_P256_COORDINATE_BYTES} bytes"
        )
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_bytes, "big"),
        int.from_bytes(y_bytes, "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key()


def _parse_ed25519_jwk(jwk: Mapping[str, Any]) -> ed25519.Ed25519PublicKey:
    crv_name = jwk.get("crv")
    if crv_name != "Ed25519":
        raise ValueError(f"OKP JWK crv={crv_name!r} is not accepted (only Ed25519)")
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != "EdDSA":
        raise ValueError(f"Ed25519 JWK alg={jwk_alg!r} is not EdDSA")
    x_raw = jwk.get("x")
    if not isinstance(x_raw, str):
        raise ValueError("OKP JWK missing string 'x' coordinate")
    x_bytes = b64url_decode(x_raw, field_name="JWK.x")
    if len(x_bytes) != _ED25519_KEY_BYTES:
        raise ValueError(f"Ed25519 JWK 'x' must be {_ED25519_KEY_BYTES} bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)


def jwk_to_public_key(jwk: Mapping[str, Any]) -> tuple[str, PublicKey]:
    """Parse an RFC 7517 signing JWK entry into ``(kid, public_key)``.

    Only EC P-256 and OKP Ed25519 keys are admitted; any other ``kty`` or curve
    raises ``ValueError``.
    """
    if not isinstance(jwk, Mapping):
        raise ValueError("JWK entry must be a JSON object")
    if _PRIVATE_JWK_FIELDS.intersection(jwk.keys()):
        raise ValueError("Refusing JWK entry containing private/symmetric key fields")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise ValueError("JWK entry requires a non-empty string 'kid'")
    kid = kid.strip()
    use = jwk.get("use")
    if use not in (None, "sig"):
        raise ValueError(f"JWK kid={kid!r} has non-signing use={use!r}")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, list) or "verify" not in key_ops
    ):
        raise ValueError(f"JWK kid={kid!r} key_ops does not permit 'verify'")

    kty = jwk.get("kty")
    if kty == "EC":
        return kid, _parse_p256_jwk(jwk)
    if kty == "OKP":
        return kid, _parse_ed25519_jwk(jwk)
    raise ValueError(
        f"JWK kty={kty!r} for kid={kid!r} is not accepted "
        "(only EC P-256 and OKP Ed25519)"
    )


def parse_jwks_payload(payload: Any, *, max_keys: int = 64) -> dict[str, PublicKey]:
    """Validate and parse an RFC 7517 JWKS JSON document into ``{kid: PublicKey}``.

    Any entry that cannot be admitted refuses the whole document: a partially
    usable key set is never returned.
    """
    if not isinstance(payload, Mapping):
        raise RoutingSealVerificationError("JWKS response must be a JSON object")
    raw_keys = payload.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise RoutingSealVerificationError(
            "JWKS response must contain a non-empty 'keys' list"
        )
    if len(raw_keys) > max_keys:
        raise RoutingSealVerificationError(
            f"JWKS response exceeds bounded key limit ({len(raw_keys)} > {max_keys})"
        )
    parsed_keys: dict[str, PublicKey] = {}
    for entry in raw_keys:
        try:
            kid, pub_key = jwk_to_public_key(entry)
        except RoutingSealVerificationError:
            raise
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"Invalid JWK entry in JWKS payload: {exc}"
            ) from exc
        if kid in parsed_keys:
            raise RoutingSealVerificationError(f"Duplicate kid={kid!r} in JWKS payload")
        parsed_keys[kid] = pub_key
    return parsed_keys


class JwksKeyResolver:
    """Out-of-band JWKS trust-anchor resolver with bounded staleness and single-flight refresh.

    Enforces monotonic ``jwks_ttl_s`` refresh, rate-limits unknown-``kid`` refresh
    retries against forged-``kid`` floods, rejects HTTP ``304`` responses, replaces
    key maps atomically on rotation/revocation, and evicts cached keys fail-closed
    once ``max_jwks_staleness_s`` elapses during a JWKS endpoint outage.
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        ttl_s: float = 300.0,
        max_staleness_s: float = 3600.0,
        min_refresh_interval_s: float = 5.0,
        max_keys: int = 64,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.jwks_uri = validate_http_url(jwks_uri, field_name="jwks_uri")
        if not math.isfinite(ttl_s) or ttl_s <= 0:
            raise ValueError("jwks_ttl_s must be a finite number > 0")
        if not math.isfinite(max_staleness_s) or max_staleness_s < ttl_s:
            raise ValueError("max_jwks_staleness_s must be finite and >= jwks_ttl_s")
        if not math.isfinite(min_refresh_interval_s) or min_refresh_interval_s < 0:
            raise ValueError("min_refresh_interval_s must be a finite number >= 0")
        self._ttl_s = float(ttl_s)
        self._max_staleness_s = float(max_staleness_s)
        self._min_refresh_interval_s = min(float(min_refresh_interval_s), self._ttl_s)
        self._max_keys = max_keys
        self._clock = clock
        self._keys: dict[str, PublicKey] = {}
        self._fetched_at: float | None = None
        self._last_unknown_kid_refresh_at: float | None = None
        self._lock = asyncio.Lock()

    def _evict_if_beyond_max_staleness(self, now: float) -> bool:
        """Evict cached keys if ``max_jwks_staleness_s`` has elapsed. Returns True if evicted."""
        if (
            self._fetched_at is not None
            and (now - self._fetched_at) >= self._max_staleness_s
        ):
            self._keys.clear()
            self._fetched_at = None
            return True
        return False

    async def _fetch_jwks(self, http_client: httpx.AsyncClient) -> dict[str, PublicKey]:
        response = await http_client.get(
            self.jwks_uri, headers={"Accept": "application/json"}
        )
        if response.status_code == 304:
            raise RoutingSealVerificationError(
                "JWKS endpoint returned HTTP 304 Not Modified; refusing unverified cache extension"
            )
        if response.status_code != 200:
            raise RoutingSealVerificationError(
                f"JWKS endpoint returned HTTP {response.status_code}"
            )
        try:
            raw_json = response.json()
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"Invalid JSON from JWKS endpoint: {exc}"
            ) from exc
        return parse_jwks_payload(raw_json, max_keys=self._max_keys)

    async def resolve_key(self, kid: str, http_client: httpx.AsyncClient) -> PublicKey:
        """Resolve ``kid`` from the bounded JWKS cache, refreshing inline when needed."""
        now = self._clock()
        if (
            self._fetched_at is not None
            and (now - self._fetched_at) < self._ttl_s
            and kid in self._keys
        ):
            return self._keys[kid]

        fetched_before = self._fetched_at
        async with self._lock:
            now = self._clock()
            cache_fresh = (
                self._fetched_at is not None and (now - self._fetched_at) < self._ttl_s
            )
            if cache_fresh:
                if kid in self._keys:
                    return self._keys[kid]
                # Another coroutine already completed a single-flight refresh while we waited
                if self._fetched_at != fetched_before:
                    raise RoutingSealVerificationError(
                        f"GovernanceEnvelope signed by unknown kid={kid!r}"
                    )
                # Rate-limit unknown-kid refresh retries so forged-kid floods cannot hammer JWKS
                if (
                    self._last_unknown_kid_refresh_at is not None
                    and (now - self._last_unknown_kid_refresh_at)
                    < self._min_refresh_interval_s
                ):
                    raise RoutingSealVerificationError(
                        f"GovernanceEnvelope signed by unknown kid={kid!r} "
                        "(JWKS unknown-kid refresh cooldown active)"
                    )

            is_unknown_kid_retry = cache_fresh
            evicted_before_fetch = self._evict_if_beyond_max_staleness(now)
            try:
                fresh_keys = await self._fetch_jwks(http_client)
            except Exception as refresh_err:
                after_err = self._clock()
                if is_unknown_kid_retry:
                    self._last_unknown_kid_refresh_at = after_err
                evicted_after_err = self._evict_if_beyond_max_staleness(after_err)
                if (
                    evicted_before_fetch
                    or evicted_after_err
                    or self._fetched_at is None
                ):
                    raise RoutingSealVerificationError(
                        f"Unable to verify GovernanceEnvelope kid={kid!r}; "
                        f"JWKS refresh failed with no fresh cached trust anchor: {refresh_err}"
                    ) from refresh_err
                cached = self._keys.get(kid)
                if cached is None:
                    raise RoutingSealVerificationError(
                        f"GovernanceEnvelope signed by unknown kid={kid!r} "
                        f"and JWKS refresh failed: {refresh_err}"
                    ) from refresh_err
                return cached

            fetch_completed_at = self._clock()
            self._keys = fresh_keys
            self._fetched_at = fetch_completed_at
            resolved = self._keys.get(kid)
            if resolved is None:
                self._last_unknown_kid_refresh_at = fetch_completed_at
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope signed by unknown kid={kid!r}"
                )
            if is_unknown_kid_retry:
                self._last_unknown_kid_refresh_at = fetch_completed_at
            return resolved


JwksCache = JwksKeyResolver
