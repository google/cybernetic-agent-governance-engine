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

C-04: Authenticates service callers via ``CAGE_API_KEY`` using constant-time
comparison (:func:`require_service_api_key`). Only ``POST /agent/query`` also
accepts a verified end-user OIDC JWT (:func:`require_api_key_or_user_token`).

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
  - Binds checkpointed conversation threads to the initiating principal via
    :func:`require_thread_owner`, refusing cross-principal access, default-thread
    pre-claiming, and ownerless populated checkpoints.
"""

from __future__ import annotations

import base64
import enum
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
from langgraph.checkpoint.base import BaseCheckpointSaver

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
USER_TOKEN_HEADERS: tuple[str, ...] = ("x-cage-user-token",)
ADVISOR_DEFAULT_THREAD_PREFIX: str = "advisor_session_"


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

    raw_principal = claims.get("act_sub") or claims.get("user_sub") or claims.get("sub")
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

    return PrincipalIdentity(
        user_id=raw_principal, verified=True, issuer=expected_issuer, kid=kid
    )


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


async def require_thread_owner(graph: Any, thread_id: str, user_id: str) -> None:
    """Refuse a turn on a conversation thread reserved for or owned by another principal.

    Enforces two fail-closed session-ownership invariants:
      1. Default-thread reservation: any ``thread_id`` starting with
         ``"advisor_session_"`` is reserved exclusively for
         ``f"advisor_session_{user_id}"``, rejecting pre-claiming / squatting
         even before any checkpoint exists.
      2. Checkpoint binding: when ``graph.checkpointer`` is a
         :class:`BaseCheckpointSaver`, any existing populated checkpoint
         (``snapshot is not None and bool(snapshot.values)``) must carry a
         non-empty ``user_id`` equal to ``user_id``; both another principal's
         checkpoint and ownerless pre-migration populated checkpoints fail
         closed.

    Raises:
        PermissionError: If ``user_id`` is empty, ``thread_id`` targets another
            principal's reserved ``advisor_session_`` prefix, or an existing
            populated checkpoint has a missing or different ``user_id``.
    """
    if not user_id:
        raise PermissionError("user_id is required to access a conversation thread")
    if (
        thread_id.startswith(ADVISOR_DEFAULT_THREAD_PREFIX)
        and thread_id != f"{ADVISOR_DEFAULT_THREAD_PREFIX}{user_id}"
    ):
        raise PermissionError(
            "advisor_session_ thread_id is reserved for the matching principal"
        )
    if not isinstance(getattr(graph, "checkpointer", None), BaseCheckpointSaver):
        return
    snapshot = await graph.aget_state({"configurable": {"thread_id": thread_id}})
    if snapshot is not None and bool(snapshot.values):
        owner = (
            snapshot.values.get("user_id")
            if isinstance(snapshot.values, Mapping)
            else None
        )
        if not isinstance(owner, str) or not owner or owner != user_id:
            raise PermissionError("thread_id belongs to another principal")


class CallerCredentialKind(str, enum.Enum):
    """Kind of bearer credential accepted by an advisor route dependency."""

    SERVICE_API_KEY = "service_api_key"
    USER_OIDC_TOKEN = "user_oidc_token"
    DEV_UNAUTHENTICATED = "dev_unauthenticated"


def _dev_auth_disabled(api_key: str, oidc_issuer: str) -> bool:
    """True in a dev posture that configures no credential at all.

    Preserves local development ergonomics without compromising prod. Accepts
    both ``dev`` and ``development``: Kubernetes deployments commonly use
    ``CAGE_ENV=development`` (the full word) while local scripts use
    ``CAGE_ENV=dev``. A missing ``CAGE_ENV`` reads as ``prod``, so it never
    disables authentication.
    """
    cage_env = os.environ.get("CAGE_ENV", "prod").lower()
    return cage_env in ("dev", "development") and not api_key and not oidc_issuer


def _is_service_api_key(provided: str, api_key: str) -> bool:
    """Constant-time check that ``provided`` is the configured ``CAGE_API_KEY``."""
    return bool(api_key) and hmac.compare_digest(provided.encode(), api_key.encode())


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_service_api_key(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> CallerCredentialKind:
    """Authenticate the calling service by ``CAGE_API_KEY``. Never an end-user token.

    Guards every advisor route that acts for the service or its operators
    rather than for the end user who calls ``POST /agent/query``. A verified
    end-user OIDC JWT is refused here even when ``CAGE_USER_OIDC_ISSUER`` is
    configured, and every request is refused when ``CAGE_API_KEY`` is unset,
    except in a dev posture that configures no credential at all.

    Raises:
        HTTPException(401): If the bearer token is missing or is not
            ``CAGE_API_KEY``.
    """
    api_key = os.environ.get("CAGE_API_KEY", "")
    oidc_issuer = os.environ.get("CAGE_USER_OIDC_ISSUER", "").strip()
    if _dev_auth_disabled(api_key, oidc_issuer):
        logger.warning("CAGE_API_KEY not set — authentication disabled in dev mode")
        return CallerCredentialKind.DEV_UNAUTHENTICATED
    if credentials is None or not _is_service_api_key(credentials.credentials, api_key):
        raise _unauthorized("Service credential required")
    return CallerCredentialKind.SERVICE_API_KEY


async def require_api_key_or_user_token(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> CallerCredentialKind:
    """Authenticate ``POST /agent/query`` by ``CAGE_API_KEY`` or an end-user OIDC JWT.

    The only advisor route an end user may call directly. A bearer token other
    than ``CAGE_API_KEY`` must verify as an end-user OIDC JWT
    (:func:`verify_user_oidc_token`) when ``CAGE_USER_OIDC_ISSUER`` is set;
    :func:`resolve_request_principal` then binds the request to that
    principal. Every other route depends on :func:`require_service_api_key`.
    Fail closed.

    Raises:
        HTTPException(401): If credentials are missing or invalid.
    """
    api_key = os.environ.get("CAGE_API_KEY", "")
    oidc_issuer = os.environ.get("CAGE_USER_OIDC_ISSUER", "").strip()
    if _dev_auth_disabled(api_key, oidc_issuer):
        logger.warning("CAGE_API_KEY not set — authentication disabled in dev mode")
        return CallerCredentialKind.DEV_UNAUTHENTICATED
    if credentials is None or (not api_key and not oidc_issuer):
        raise _unauthorized("Missing credentials")
    if _is_service_api_key(credentials.credentials, api_key):
        return CallerCredentialKind.SERVICE_API_KEY
    if oidc_issuer:
        verify_user_oidc_token(credentials.credentials)
        return CallerCredentialKind.USER_OIDC_TOKEN
    raise _unauthorized("Invalid credentials")
