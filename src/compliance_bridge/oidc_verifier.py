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

"""Out-of-band ``kid``-resolved OIDC JWT verifier for ``compliance-bridge``.

Enforces CAGE trust-anchor invariants (``.agents/rules/security.md``):
  - Never trusts embedded key headers (``jwk``, ``jku``, ``x5c``, ``x5u``).
  - Restricts signatures to asymmetric algorithms (``RS256``, ``ES256``, ``EdDSA``)
    and rejects symmetric or private JWK material.
  - Resolves public keys strictly by ``kid`` from out-of-band JWKS sources
    (``CAGE_OPERATOR_JWKS_JSON``, ``CAGE_OPERATOR_JWKS_FILE``, or an ``https://``
    ``CAGE_OPERATOR_JWKS_URI``); fails closed on unknown ``kid``.
  - Validates ``iss``, ``aud``, ``exp``, ``nbf`` (when present), and non-empty ``sub``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt as pyjwt

from src.gateway.governance.env_posture import env_flag, is_enforcing

logger = logging.getLogger(__name__)

ALLOWED_OIDC_ALGS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
EMBEDDED_KEY_HEADERS: frozenset[str] = frozenset({"jwk", "jku", "x5c", "x5u"})
DEFAULT_OPERATOR_OIDC_AUDIENCE = "cage-compliance-bridge"

_JWKS_CACHE_TTL_SECONDS = 300.0
_JWKS_MIN_REFRESH_INTERVAL_SECONDS = 10.0
_JWKS_MAX_KEYS = 64
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})


def validate_jwks_uri(uri: str) -> str:
    """Validate an out-of-band JWKS URI and fail closed on unsafe schemes.

    Requires ``https://`` with a non-empty host and no embedded userinfo.
    Plain ``http://`` is permitted only for loopback hosts when NOT in an
    enforcing posture AND ``CAGE_ALLOW_INSECURE_LOOPBACK_JWKS=true`` is set
    for local hermetic testing.
    """
    candidate = uri.strip()
    if not candidate:
        raise ValueError("JWKS URI must not be empty")

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("JWKS URI must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("JWKS URI must not contain embedded credentials")

    if scheme == "https":
        return candidate

    if (
        scheme == "http"
        and hostname in _LOOPBACK_HOSTS
        and not is_enforcing()
        and env_flag("CAGE_ALLOW_INSECURE_LOOPBACK_JWKS", default=False)
    ):
        return candidate

    raise ValueError(
        f"JWKS URI must use https:// (got scheme={scheme!r}, host={hostname!r})"
    )


def parse_jwks_payload(raw_json: str) -> dict[str, Any]:
    """Parse an out-of-band JWKS JSON string or ``{kid: pem}`` map into public keys by ``kid``.

    Rejects symmetric keys (``oct``) and any entry carrying private key fields
    (``d``, ``k``, or ``PRIVATE KEY`` PEM blocks).
    """
    try:
        parsed = json.loads(raw_json)
    except ValueError as exc:
        logger.error("Malformed out-of-band JWKS JSON: %s", exc)
        return {}

    keys_by_kid: dict[str, Any] = {}
    if isinstance(parsed, dict) and isinstance(parsed.get("keys"), list):
        for jwk_entry in parsed["keys"][:_JWKS_MAX_KEYS]:
            if not isinstance(jwk_entry, dict):
                continue
            kid = str(jwk_entry.get("kid", "")).strip()
            if not kid:
                continue
            pem_val = jwk_entry.get("pem")
            if isinstance(pem_val, str) and pem_val.strip():
                if "PRIVATE KEY" in pem_val:
                    logger.error(
                        "Rejected JWK entry kid=%r containing private PEM material",
                        kid,
                    )
                    continue
                keys_by_kid[kid] = pem_val.strip()
                continue
            kty = str(jwk_entry.get("kty", "")).strip()
            if kty not in {"RSA", "EC", "OKP"}:
                logger.warning(
                    "Skipping JWK entry kid=%r with unsupported kty=%r", kid, kty
                )
                continue
            if "d" in jwk_entry or "k" in jwk_entry:
                logger.error(
                    "Rejected JWK entry kid=%r containing private/symmetric material",
                    kid,
                )
                continue
            try:
                keys_by_kid[kid] = pyjwt.PyJWK.from_dict(jwk_entry).key
            except Exception as exc:
                logger.error("Failed to parse JWK kid=%r: %s", kid, exc)
    elif isinstance(parsed, dict):
        for raw_kid, val in list(parsed.items())[:_JWKS_MAX_KEYS]:
            kid_str = str(raw_kid).strip()
            if not kid_str:
                continue
            if isinstance(val, str) and val.strip():
                if "PRIVATE KEY" in val:
                    logger.error(
                        "Rejected key map entry kid=%r containing private PEM material",
                        kid_str,
                    )
                    continue
                keys_by_kid[kid_str] = val.strip()
            elif isinstance(val, dict):
                kty = str(val.get("kty", "")).strip()
                if kty in {"RSA", "EC", "OKP"} and "d" not in val and "k" not in val:
                    try:
                        keys_by_kid[kid_str] = pyjwt.PyJWK.from_dict(val).key
                    except Exception as exc:
                        logger.error("Failed to parse JWK kid=%r: %s", kid_str, exc)

    return keys_by_kid


def load_static_operator_jwks() -> dict[str, Any]:
    """Load out-of-band operator verification keys from JSON or file env vars."""
    raw_json = (
        os.environ.get("CAGE_OPERATOR_JWKS_JSON", "").strip()
        or os.environ.get("CAGE_OIDC_JWKS_JSON", "").strip()
    )
    jwks_file = (
        os.environ.get("CAGE_OPERATOR_JWKS_FILE", "").strip()
        or os.environ.get("CAGE_OIDC_JWKS_FILE", "").strip()
    )
    if not raw_json and jwks_file:
        try:
            raw_json = Path(jwks_file).read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read JWKS file %r: %s", jwks_file, exc)
            return {}

    if not raw_json:
        return {}
    return parse_jwks_payload(raw_json)


class OidcVerifier:
    """Out-of-band ``kid``-resolved OIDC JWT verifier with bounded remote JWKS cache."""

    def __init__(
        self,
        *,
        issuer: str | None = None,
        audience: str | None = None,
        jwks_uri: str | None = None,
        jwks_cache: Mapping[str, Any] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        cache_ttl_seconds: float = _JWKS_CACHE_TTL_SECONDS,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._jwks_uri = jwks_uri
        self._static_cache: dict[str, Any] = dict(jwks_cache) if jwks_cache else {}
        self._remote_cache: dict[str, Any] = {}
        self._remote_cached_at: float = 0.0
        self._last_refresh_attempt: float = 0.0
        self._cache_ttl_seconds = cache_ttl_seconds
        self._http_transport = http_transport
        self._refresh_lock = asyncio.Lock()

    def _effective_issuer(self) -> str:
        if self._issuer is not None:
            return self._issuer.strip()
        return (
            os.environ.get("CAGE_OPERATOR_OIDC_ISSUER", "").strip()
            or os.environ.get("CAGE_OIDC_ISSUER", "").strip()
        )

    def _effective_audience(self) -> str:
        if self._audience is not None:
            return self._audience.strip()
        return (
            os.environ.get("CAGE_OPERATOR_OIDC_AUDIENCE", "").strip()
            or os.environ.get("CAGE_OIDC_AUDIENCE", "").strip()
            or DEFAULT_OPERATOR_OIDC_AUDIENCE
        )

    def _effective_jwks_uri(self) -> str:
        if self._jwks_uri is not None:
            return self._jwks_uri.strip()
        return (
            os.environ.get("CAGE_OPERATOR_JWKS_URI", "").strip()
            or os.environ.get("CAGE_OIDC_JWKS_URI", "").strip()
        )

    async def _fetch_remote_jwks(
        self, uri: str, *, force: bool = False
    ) -> dict[str, Any]:
        validated_uri = validate_jwks_uri(uri)
        now = time.monotonic()
        if (
            not force
            and self._remote_cache
            and (now - self._remote_cached_at) < self._cache_ttl_seconds
        ):
            return self._remote_cache

        async with self._refresh_lock:
            now = time.monotonic()
            if (
                not force
                and self._remote_cache
                and (now - self._remote_cached_at) < self._cache_ttl_seconds
            ):
                return self._remote_cache
            if (
                force
                and self._last_refresh_attempt > 0.0
                and (now - self._last_refresh_attempt)
                < _JWKS_MIN_REFRESH_INTERVAL_SECONDS
            ):
                return self._remote_cache

            self._last_refresh_attempt = now
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=2.0),
                follow_redirects=False,
                transport=self._http_transport,
            ) as client:
                response = await client.get(validated_uri)
                response.raise_for_status()
                parsed = parse_jwks_payload(response.text)
                if parsed:
                    self._remote_cache = parsed
                    self._remote_cached_at = time.monotonic()
                return self._remote_cache

    async def _resolve_key(
        self,
        kid: str,
        *,
        key_resolver: Callable[[str], Any] | None = None,
    ) -> tuple[Any | None, str]:
        if key_resolver is not None:
            resolved = key_resolver(kid)
            return (
                (resolved, "")
                if resolved is not None
                else (None, f"unknown kid {kid!r}")
            )

        if kid in self._static_cache:
            return self._static_cache[kid], ""

        env_keys = load_static_operator_jwks()
        if kid in env_keys:
            return env_keys[kid], ""

        jwks_uri = self._effective_jwks_uri()
        if jwks_uri:
            try:
                remote_keys = await self._fetch_remote_jwks(jwks_uri, force=False)
                if kid in remote_keys:
                    return remote_keys[kid], ""
                remote_keys = await self._fetch_remote_jwks(jwks_uri, force=True)
                if kid in remote_keys:
                    return remote_keys[kid], ""
            except ValueError as exc:
                logger.error("Rejected invalid JWKS URI: %s", exc)
                return None, str(exc)
            except Exception as exc:
                logger.error("Failed to fetch remote JWKS: %s", type(exc).__name__)
                return None, f"JWKS fetch failed ({type(exc).__name__})"

        return None, f"unknown kid {kid!r}"

    async def verify_token(
        self,
        token: str,
        *,
        key_resolver: Callable[[str], Any] | None = None,
    ) -> tuple[bool, dict[str, Any], str]:
        """Verify an OIDC JWT and return ``(is_valid, claims, error_reason)``."""
        if not token or not isinstance(token, str):
            return False, {}, "empty OIDC token"

        try:
            unverified_header = pyjwt.get_unverified_header(token)
        except Exception:
            return False, {}, "malformed JWS header"

        if not isinstance(unverified_header, dict):
            return False, {}, "malformed JWS header"

        if any(k in unverified_header for k in EMBEDDED_KEY_HEADERS):
            logger.warning("OIDC validation rejected: embedded key header present")
            return False, {}, "embedded key header is forbidden"

        alg = str(unverified_header.get("alg", "")).strip()
        if alg not in ALLOWED_OIDC_ALGS:
            logger.warning("OIDC validation rejected: disallowed alg=%r", alg)
            return False, {}, f"disallowed JWS algorithm {alg!r}"

        kid = str(unverified_header.get("kid", "")).strip()
        if not kid:
            logger.warning("OIDC validation rejected: missing kid in JWS header")
            return False, {}, "missing kid in JWS header"

        expected_issuer = self._effective_issuer()
        if not expected_issuer:
            return False, {}, "CAGE_OPERATOR_OIDC_ISSUER is not configured"

        expected_audience = self._effective_audience()
        if not expected_audience:
            return False, {}, "CAGE_OPERATOR_OIDC_AUDIENCE is not configured"

        pub_key, key_err = await self._resolve_key(kid, key_resolver=key_resolver)
        if pub_key is None:
            logger.warning("OIDC validation rejected: %s", key_err)
            return False, {}, key_err

        try:
            claims: dict[str, Any] = pyjwt.decode(
                token,
                pub_key,
                algorithms=list(ALLOWED_OIDC_ALGS),
                issuer=expected_issuer,
                audience=expected_audience,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except Exception as exc:
            logger.warning(
                "OIDC JWT signature/claim verification failed: %s", type(exc).__name__
            )
            return False, {}, f"JWT verification failed ({type(exc).__name__})"

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            return False, {}, "empty sub claim"

        claims["_verified_kid"] = kid
        return True, claims, ""


_default_verifier: OidcVerifier | None = None


def get_oidc_verifier() -> OidcVerifier:
    """Return the process-wide default ``OidcVerifier`` instance."""
    global _default_verifier
    if _default_verifier is None:
        _default_verifier = OidcVerifier()
    return _default_verifier


def reset_oidc_verifier() -> None:
    """Reset the process-wide ``OidcVerifier`` singleton (for tests)."""
    global _default_verifier
    _default_verifier = None


async def verify_operator_oidc_token(
    token: str,
    *,
    key_resolver: Callable[[str], Any] | None = None,
) -> tuple[bool, dict[str, Any], str]:
    """Verify an operator OIDC JWT using the process-wide ``OidcVerifier``."""
    return await get_oidc_verifier().verify_token(token, key_resolver=key_resolver)
