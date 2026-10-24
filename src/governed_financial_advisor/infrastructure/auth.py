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

"""Bearer token and end-user OIDC authentication for the Governed Financial Advisor API.

C-04: Authenticates API callers via ``CAGE_API_KEY`` using constant-time
comparison (or a verified end-user OIDC JWT when ``CAGE_USER_OIDC_ISSUER`` is
configured).

Issue #520: Binds the end-user principal to an authenticated identity via
out-of-band ``kid``-resolved OIDC JWT verification (:func:`verify_user_oidc_token`,
:func:`resolve_request_principal`):
  - Never verifies against a key embedded in the token header (``jwk``, ``jku``,
    ``x5c``, ``x5u``).
  - Resolves public keys strictly by ``kid`` from an out-of-band trust anchor
    manifest (``CAGE_USER_OIDC_JWKS_JSON`` or ``CAGE_USER_OIDC_TRUST_ANCHORS_FILE``).
  - Refuses mismatches between an authenticated token's principal and a
    caller-supplied ``QueryRequest.user_id`` with HTTP 403.
  - Under enforcing postures (or when ``CAGE_USER_OIDC_ISSUER`` /
    ``CAGE_REQUIRE_VERIFIED_PRINCIPAL`` is set, unless
    ``CAGE_ALLOW_ASSERTED_PRINCIPAL=true``), requests without a verified user
    OIDC token are refused with HTTP 401. Under permissive postures
    (``dev``/``test``/``ci``), unauthenticated requests carry ``verified=False``.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jwt as pyjwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.gateway.governance.env_posture import env_flag, is_enforcing
from src.governed_financial_advisor.models.principal import (
    PRINCIPAL_MAX_LEN,
    PRINCIPAL_PATTERN,
    PrincipalIdentity,
)

_bearer = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)

_ALLOWED_USER_OIDC_ALGS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
_EMBEDDED_KEY_HEADERS: frozenset[str] = frozenset({"jwk", "jku", "x5c", "x5u"})
USER_TOKEN_HEADERS: tuple[str, ...] = (
    "x-cage-user-token",
    "x-geap-user-assertion",
)


def _parse_unverified_jws_header(token: str) -> dict[str, Any] | None:
    """Decode the JWS header without trusting its contents."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        header = json.loads(raw.decode("utf-8"))
        return header if isinstance(header, dict) else None
    except Exception:
        return None


def _normalize_jwks_mapping(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a ``{kid: key}`` map or standard ``{"keys": [...]}`` JWKS object."""
    keys_list = raw.get("keys")
    if isinstance(keys_list, list):
        out: dict[str, Any] = {}
        for entry in keys_list:
            if isinstance(entry, Mapping):
                kid = entry.get("kid")
                if isinstance(kid, str) and kid.strip():
                    out[kid.strip()] = dict(entry)
        return out
    return {
        str(k).strip(): v
        for k, v in raw.items()
        if isinstance(k, str) and k.strip() and v is not None
    }


def _load_trust_anchors(
    jwks_cache: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Load out-of-band ``kid -> public_key`` trust anchors from override or environment."""
    if jwks_cache is not None:
        return _normalize_jwks_mapping(jwks_cache)

    anchors: dict[str, Any] = {}
    anchors_file = os.environ.get("CAGE_USER_OIDC_TRUST_ANCHORS_FILE", "").strip()
    if anchors_file:
        try:
            parsed_file = json.loads(Path(anchors_file).read_text(encoding="utf-8"))
            if isinstance(parsed_file, Mapping):
                anchors.update(_normalize_jwks_mapping(parsed_file))
        except Exception as exc:
            logger.warning(
                "Failed to load CAGE_USER_OIDC_TRUST_ANCHORS_FILE: %s",
                type(exc).__name__,
            )

    raw_json = os.environ.get("CAGE_USER_OIDC_JWKS_JSON", "").strip()
    if raw_json:
        try:
            parsed_json = json.loads(raw_json)
            if isinstance(parsed_json, Mapping):
                anchors.update(_normalize_jwks_mapping(parsed_json))
        except Exception as exc:
            logger.warning(
                "Failed to parse CAGE_USER_OIDC_JWKS_JSON: %s",
                type(exc).__name__,
            )

    return anchors


def _resolve_verification_key(raw_key: Any) -> Any:
    """Resolve a PEM string, JWK dict, or cryptography key into a PyJWT key."""
    if isinstance(raw_key, Mapping):
        pem_val = raw_key.get("pem") or raw_key.get("public_key")
        if isinstance(pem_val, str) and pem_val.strip():
            return pem_val.strip()
        return pyjwt.PyJWK.from_dict(dict(raw_key)).key
    return raw_key


def verify_user_oidc_token(
    token: str,
    *,
    jwks_cache: Mapping[str, Any] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> PrincipalIdentity:
    """Verify an end-user OIDC JWT against out-of-band ``kid`` trust anchors.

    Enforces CAGE Trust Anchor invariants:
      - Rejects any JWT header carrying embedded key material (``jwk``, ``jku``,
        ``x5c``, ``x5u``).
      - Requires ``alg`` in ``{"RS256", "ES256", "EdDSA"}`` and a non-empty ``kid``.
      - Resolves the verification key strictly by ``kid`` from ``jwks_cache``,
        ``CAGE_USER_OIDC_JWKS_JSON``, or ``CAGE_USER_OIDC_TRUST_ANCHORS_FILE``.
      - Verifies signature, ``exp``, ``iss``, and ``aud``, and validates the
        extracted principal against :data:`PRINCIPAL_PATTERN` and
        :data:`PRINCIPAL_MAX_LEN`.
    """
    expected_issuer = (
        issuer if issuer is not None else os.environ.get("CAGE_USER_OIDC_ISSUER", "")
    ).strip()
    expected_audience = (
        audience
        if audience is not None
        else os.environ.get("CAGE_USER_OIDC_AUDIENCE", "cage-advisor")
    ).strip() or "cage-advisor"

    if not expected_issuer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="CAGE_USER_OIDC_ISSUER is not configured for user OIDC verification",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing user OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    header = _parse_unverified_jws_header(token)
    if header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed user OIDC token header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if any(k in header for k in _EMBEDDED_KEY_HEADERS):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Embedded key headers (jwk/jku/x5c/x5u) are forbidden",
            headers={"WWW-Authenticate": "Bearer"},
        )

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _ALLOWED_USER_OIDC_ALGS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Disallowed OIDC signing algorithm: {alg!r}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing kid in user OIDC token header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    kid = kid.strip()

    anchors = _load_trust_anchors(jwks_cache)
    raw_key = anchors.get(kid)
    if raw_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unknown user OIDC key ID: {kid!r}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        pub_key = _resolve_verification_key(raw_key)
        claims: dict[str, Any] = pyjwt.decode(
            token,
            pub_key,
            algorithms=[alg],
            issuer=expected_issuer,
            audience=expected_audience,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User OIDC token verification failed: {type(exc).__name__}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    raw_principal = (
        claims.get("act_sub") or claims.get("user_sub") or claims.get("sub")
    )
    if (
        not isinstance(raw_principal, str)
        or not (1 <= len(raw_principal) <= PRINCIPAL_MAX_LEN)
        or re.fullmatch(PRINCIPAL_PATTERN, raw_principal) is None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid principal claim in OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return PrincipalIdentity(user_id=raw_principal, verified=True, issuer=expected_issuer, kid=kid)


def requires_verified_principal() -> bool:
    """Return True when the current posture requires a cryptographically verified principal."""
    if env_flag("CAGE_ALLOW_ASSERTED_PRINCIPAL", False):
        return False
    if bool(os.environ.get("CAGE_USER_OIDC_ISSUER", "").strip()):
        return True
    if env_flag("CAGE_REQUIRE_VERIFIED_PRINCIPAL", False):
        return True
    return is_enforcing()


def _extract_user_oidc_token(request: Any) -> str | None:
    """Extract an end-user OIDC token from ``request.headers`` when present."""
    headers = getattr(request, "headers", None)
    if headers is None or not hasattr(headers, "get"):
        return None

    for header_name in USER_TOKEN_HEADERS:
        raw_val = headers.get(header_name)
        if raw_val is None and hasattr(headers, "items"):
            for k, v in headers.items():
                if isinstance(k, str) and k.lower() == header_name:
                    raw_val = v
                    break
        if raw_val is not None:
            cleaned = str(raw_val).strip()
            if cleaned.lower().startswith("bearer "):
                cleaned = cleaned[7:].strip()
            return cleaned

    auth_val = headers.get("authorization") or headers.get("Authorization")
    if isinstance(auth_val, str) and auth_val.lower().startswith("bearer "):
        bearer_token = auth_val[7:].strip()
        api_key = os.environ.get("CAGE_API_KEY", "")
        if api_key and hmac.compare_digest(bearer_token.encode(), api_key.encode()):
            return None
        if os.environ.get("CAGE_USER_OIDC_ISSUER", "").strip() or (
            bearer_token.count(".") == 2
        ):
            return bearer_token

    return None


def resolve_request_principal(
    request: Any,
    asserted_user_id: str,
    *,
    jwks_cache: Mapping[str, Any] | None = None,
) -> PrincipalIdentity:
    """Resolve and verify the end-user principal for an advisor request.

    - When a user OIDC token is present, verifies it via :func:`verify_user_oidc_token`
      (failing closed with HTTP 401 on any invalid token) and rejects any mismatch
      with ``asserted_user_id`` with HTTP 403.
    - When no user OIDC token is present, refuses with HTTP 401 if
      :func:`requires_verified_principal` is True; otherwise returns an
      explicitly unverified :class:`PrincipalIdentity` in permissive postures.
    """
    token = _extract_user_oidc_token(request)
    if token is not None:
        verified_identity = verify_user_oidc_token(token, jwks_cache=jwks_cache)
        if asserted_user_id and asserted_user_id != verified_identity.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Asserted user_id does not match authenticated principal",
            )
        return verified_identity

    if requires_verified_principal():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Verified end-user principal required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return PrincipalIdentity(user_id=asserted_user_id, verified=False)


async def require_api_key(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    """Validate bearer token against CAGE_API_KEY or CAGE_USER_OIDC_ISSUER. Fail closed.

    Returns the validated token string on success.

    Raises:
        HTTPException(401): If credentials are missing or invalid.
    """
    api_key = os.environ.get("CAGE_API_KEY", "")
    oidc_issuer = os.environ.get("CAGE_USER_OIDC_ISSUER", "").strip()
    cage_env = os.environ.get(
        "CAGE_ENV", "prod"
    ).lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement

    # In dev with no API key or OIDC issuer configured, allow through with warning.
    # This preserves local development ergonomics without compromising prod.
    # Accept both "dev" and "development" — Kubernetes deployments commonly use
    # CAGE_ENV=development (the full word) while local scripts use CAGE_ENV=dev.
    if cage_env in ("dev", "development") and not api_key and not oidc_issuer:
        logger.warning("CAGE_API_KEY not set — authentication disabled in dev mode")
        return "dev-unauthenticated"

    if not credentials or (not api_key and not oidc_issuer):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided_str = credentials.credentials
    if api_key and hmac.compare_digest(provided_str.encode(), api_key.encode()):
        return provided_str

    if oidc_issuer:
        verify_user_oidc_token(provided_str)
        return provided_str

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
