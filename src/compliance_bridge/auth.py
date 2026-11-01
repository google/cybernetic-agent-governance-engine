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

"""Authentication and authorization helpers for compliance-bridge endpoints."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass
from typing import Literal

from fastapi import Header, HTTPException, Request

from src.gateway.server.workload_identity import is_pod_local_connection

logger = logging.getLogger(__name__)

_CAGE_ENV = os.environ.get("CAGE_ENV", "production")

# Strict SPIFFE ID grammar for transport-supplied operator SVIDs
# (request.attributes.source.principal): a lowercase trust domain followed by
# zero or more non-dot path segments, anchored end to end.
_SPIFFE_ID = re.compile(
    r"^spiffe://[a-z0-9][a-z0-9._-]{0,254}(?:/(?!\.\.?(?:/|\Z))[A-Za-z0-9._-]+)*\Z"
)

# Linkerd inbound proxy workload identity grammar (l5d-client-id):
# <service-account>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>
_LINKERD_IDENTITY = re.compile(
    r"^([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"  # group 1: service account
    r"\.([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"  # group 2: namespace
    r"\.serviceaccount\.identity\.linkerd\."
    r"([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\Z"  # group 3: trust domain
)


def _linkerd_client_id_header(request: Request) -> tuple[str | None, bool]:
    """Return ``(l5d_client_id, duplicate_detected)`` for ``l5d-client-id``.

    The Linkerd inbound proxy terminates mTLS and either sets ``l5d-client-id``
    from the verified peer certificate SAN or strips it when no verified peer
    certificate is present. That holds only for requests that came through the
    proxy, so :func:`require_operator_identity` also requires the connection to
    come from inside the pod (``is_pod_local_connection``). Multiple
    ``l5d-client-id`` headers indicate header smuggling and fail closed.

    Note (GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39): ``x-cage-source-principal``
    is a client-controllable HTTP header not managed by Linkerd and is never
    accepted as an operator identity source.
    """
    headers = request.headers
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = [v for v in getlist("l5d-client-id") if v]
    else:  # pragma: no cover - real requests always expose getlist
        single = headers.get("l5d-client-id") if hasattr(headers, "get") else None
        values = [single] if single else []
    if len(values) > 1:
        logger.warning(
            "Multiple l5d-client-id headers presented (%d) — rejecting",
            len(values),
        )
        return None, True
    if len(values) == 1:
        return values[0], False
    return None, False


def _linkerd_id_to_spiffe(l5d_id: str) -> str | None:
    """Convert a verified Linkerd ``l5d-client-id`` to its canonical ``spiffe://`` URN."""
    match = _LINKERD_IDENTITY.fullmatch(l5d_id)
    if not match:
        return None
    sa, namespace, trust_domain = match.group(1), match.group(2), match.group(3)
    return f"spiffe://{trust_domain}/ns/{namespace}/sa/{sa}"


def _trusted_operator_identities() -> frozenset[str]:
    """Return configured trusted operator identities (Linkerd DNS or spiffe:// URIs)."""
    raw = os.environ.get("CAGE_TRUSTED_OPERATOR_IDENTITIES", "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class OperatorPrincipal:
    """Verified operator identity from substrate-level transport or OIDC claims.

    Attributes:
        operator_urn: Canonical operator identity (SPIFFE ID or OIDC sub claim)
        channel_provenance: Source of identity verification
        auth_principal_hash: SHA-256 hash of the raw principal for audit correlation
    """

    operator_urn: str
    channel_provenance: Literal["SVID", "OIDC", "DEV_SYNTHETIC"]
    auth_principal_hash: str


async def require_internal_token(
    request: Request,
    x_cage_internal_token: str | None = Header(None, alias="X-Cage-Internal-Token"),
) -> str:
    """Verify the X-Cage-Internal-Token or Authorization header for internal-only endpoints.

    Fails closed by default (``CAGE_ENV`` defaults to ``production``).
    Unauthenticated dev access requires a dual-condition opt-in:
    ``CAGE_ENV`` in ``("dev", "development")`` AND
    ``CAGE_ALLOW_DEV_UNAUTHENTICATED=true`` (GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39).
    Accepts token from X-Cage-Internal-Token or Authorization: Bearer.
    Matches against CAGE_INTERNAL_TOKEN or COMPLIANCE_BRIDGE_INTERNAL_TOKEN.

    Args:
        request: The FastAPI request object
        x_cage_internal_token: The internal auth token from request headers

    Returns:
        The validated token value, or "dev-unauthenticated" under dual-condition dev opt-in

    Raises:
        HTTPException: 401 if token is missing or invalid
    """
    expected_token = os.environ.get("CAGE_INTERNAL_TOKEN") or os.environ.get(
        "COMPLIANCE_BRIDGE_INTERNAL_TOKEN"
    )

    token_val = x_cage_internal_token
    if not token_val:
        auth_header = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
        if auth_header and auth_header.startswith("Bearer "):
            token_val = auth_header[7:].strip()

    cage_env = os.environ.get("CAGE_ENV", _CAGE_ENV)
    allow_dev_unauth = (
        os.environ.get("CAGE_ALLOW_DEV_UNAUTHENTICATED", "false").lower() == "true"
    )
    # Dev-mode degradation requires dual-condition opt-in
    if cage_env in ("dev", "development") and allow_dev_unauth and not token_val:
        logger.warning(
            "⚠️  Internal token missing in dev mode (CAGE_ALLOW_DEV_UNAUTHENTICATED=true); allowing unauthenticated access"
        )
        return "dev-unauthenticated"

    # Token is mandatory unless dual-condition dev opt-in is active
    if not token_val:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Cage-Internal-Token or Authorization header",
        )

    if not expected_token:
        raise HTTPException(
            status_code=500,
            detail="CAGE_INTERNAL_TOKEN or COMPLIANCE_BRIDGE_INTERNAL_TOKEN not configured",
        )

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(token_val, expected_token):
        raise HTTPException(status_code=401, detail="Invalid internal token")

    return token_val


async def require_operator_identity(request: Request) -> OperatorPrincipal:
    """Extract verified operator identity from Linkerd mTLS SVID or OIDC claims.

    Identity precedence (fail-closed, evaluated not negotiated):
    1. **SPIFFE SVID / Linkerd mTLS** (primary): Extracted from Linkerd inbound
       proxy ``l5d-client-id`` header, accepted only on a connection from inside
       the pod, or transport-level ``request.attributes.source.principal``
       (never from client-controlled ``x-cage-source-principal`` headers;
       GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39).
    2. **OIDC JWT** (fallback): Only if ``CAGE_OPERATOR_IDENTITY_ALLOW_OIDC=true``.
    3. **Dev synthetic** (dev-only): If ``CAGE_ENV=dev`` AND
       ``CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC=true``.

    Args:
        request: FastAPI request carrying Linkerd ``l5d-client-id``, transport
                 ``.attributes.source.principal``, or OIDC ``Authorization``.

    Returns:
        OperatorPrincipal with verified identity and provenance channel

    Raises:
        HTTPException: 401 if no valid identity source exists, 403 if untrusted,
                       or 400 if dev-prefix used outside dev mode
    """
    if hasattr(request.headers, "get") and request.headers.get(
        "x-cage-source-principal"
    ):
        logger.warning(
            "Rejected unverified client-supplied x-cage-source-principal header "
            "(GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39)"
        )

    # Channel 1: Linkerd mTLS workload identity (l5d-client-id) or transport SVID
    l5d_id, duplicate_headers = _linkerd_client_id_header(request)
    if duplicate_headers:
        raise HTTPException(
            status_code=401,
            detail="Multiple l5d-client-id headers presented",
        )
    if l5d_id is not None and not is_pod_local_connection(
        getattr(request, "scope", {})
    ):
        # Only the pod's own Linkerd proxy writes this header. From any other
        # peer it names whichever operator the caller chose.
        client = getattr(request, "client", None)
        logger.warning(
            "Refused l5d-client-id from %s: it did not come through the pod's "
            "Linkerd proxy",
            getattr(client, "host", "<none>"),
        )
        raise HTTPException(
            status_code=401,
            detail="l5d-client-id did not come through the Linkerd proxy",
        )
    try:
        svid: str | None = None
        if isinstance(l5d_id, str):
            svid = _linkerd_id_to_spiffe(l5d_id)
            if svid is None:
                raise HTTPException(
                    status_code=401,
                    detail="Malformed l5d-client-id workload identity header",
                )
        else:
            attr_principal = getattr(
                getattr(request, "attributes", None), "source", {}
            ).get("principal")
            if isinstance(attr_principal, str) and _SPIFFE_ID.fullmatch(attr_principal):
                svid = attr_principal

        if isinstance(svid, str) and _SPIFFE_ID.fullmatch(svid):
            trusted = _trusted_operator_identities()
            if trusted and svid not in trusted and (l5d_id not in trusted):
                logger.warning(
                    "Operator SVID %s not in CAGE_TRUSTED_OPERATOR_IDENTITIES", svid
                )
                raise HTTPException(
                    status_code=403,
                    detail="Operator workload identity is not authorized",
                )
            principal_hash = hashlib.sha256(svid.encode()).hexdigest()
            logger.info(f"✅ Operator identity verified via SVID: {svid[:30]}...")
            return OperatorPrincipal(
                operator_urn=svid,
                channel_provenance="SVID",
                auth_principal_hash=principal_hash,
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"⚠️  SVID extraction failed: {e}")

    # Channel 2: OIDC JWT sub claim (gated fallback)
    allow_oidc = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "false").lower() == "true"
    )
    if allow_oidc:
        auth_header = (
            request.headers.get("authorization")
            if hasattr(request.headers, "get")
            else None
        )
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :].strip()
            try:
                jwt_sub: str | None = None
                state = getattr(request, "state", None)
                jwt_claims = getattr(state, "jwt_claims", None)
                if isinstance(jwt_claims, dict):
                    jwt_sub = jwt_claims.get("sub")
                elif token:
                    from src.gateway.governance.ingress.agw_adapter import (
                        get_agw_adapter,
                    )

                    valid, claims = await get_agw_adapter().validate_oidc_token(token)
                    if valid and isinstance(claims, dict):
                        jwt_sub = claims.get("sub")
                if isinstance(jwt_sub, str) and jwt_sub.strip():
                    trusted = _trusted_operator_identities()
                    if trusted and jwt_sub not in trusted:
                        logger.warning(
                            "Operator OIDC sub %s not in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                            jwt_sub,
                        )
                        raise HTTPException(
                            status_code=403,
                            detail="Operator OIDC identity is not authorized",
                        )
                    principal_hash = hashlib.sha256(jwt_sub.encode()).hexdigest()
                    logger.info(
                        f"✅ Operator identity verified via OIDC: {jwt_sub[:30]}..."
                    )
                    return OperatorPrincipal(
                        operator_urn=jwt_sub,
                        channel_provenance="OIDC",
                        auth_principal_hash=principal_hash,
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(f"⚠️  OIDC JWT extraction failed: {e}")

    # Channel 3: Dev-mode synthetic principal (dual-condition guard)
    allow_dev_synthetic = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "false").lower()
        == "true"
    )
    env_override = os.environ.get("CAGE_ENV", "").lower()
    is_dev_posture = _CAGE_ENV in ("dev", "development") and env_override not in (
        "prod",
        "production",
        "staging",
    )
    if is_dev_posture and allow_dev_synthetic:
        # Extract from custom dev header
        dev_principal = request.headers.get("x-cage-dev-operator-urn")
        if dev_principal:
            # Enforce reserved prefix
            if not dev_principal.startswith("urn:cage:dev:"):
                raise HTTPException(
                    status_code=400,
                    detail="Dev-mode operator URN must start with 'urn:cage:dev:' prefix",
                )
            principal_hash = hashlib.sha256(dev_principal.encode()).hexdigest()
            logger.warning(f"⚠️  DEV-MODE: Synthetic operator identity: {dev_principal}")
            return OperatorPrincipal(
                operator_urn=dev_principal,
                channel_provenance="DEV_SYNTHETIC",
                auth_principal_hash=principal_hash,
            )

    # No valid identity source found - fail closed
    logger.error("❌ No valid operator identity found in request")
    raise HTTPException(
        status_code=401,
        detail="No verified operator identity (SVID/OIDC/dev-synthetic)",
    )
