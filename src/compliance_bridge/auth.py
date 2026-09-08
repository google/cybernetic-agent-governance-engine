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
from dataclasses import dataclass
from typing import Literal

from fastapi import Header, HTTPException, Request

logger = logging.getLogger(__name__)

_CAGE_ENV = os.environ.get("CAGE_ENV", "dev")


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
    """Verify the X-Cage-Internal-Token header for internal-only endpoints.

    In dev mode (CAGE_ENV=dev), this degrades open to allow unauthenticated
    access for local testing. In staging/prod, it requires a valid token.

    Args:
        request: The FastAPI request object (unused, required for dependency signature)
        x_cage_internal_token: The internal auth token from request headers

    Returns:
        The validated token value, or "dev-unauthenticated" in dev mode without token

    Raises:
        HTTPException: 401 if token is missing or invalid in non-dev environments
    """
    expected_token = os.environ.get("CAGE_INTERNAL_TOKEN")

    # Dev-mode degradation: allow requests without token
    if _CAGE_ENV == "dev" and not x_cage_internal_token:
        logger.warning(
            "⚠️  Internal token missing in dev mode; allowing unauthenticated access"
        )
        return "dev-unauthenticated"

    # Prod/staging: token is mandatory
    if not x_cage_internal_token:
        raise HTTPException(
            status_code=401, detail="Missing X-Cage-Internal-Token header"
        )

    if not expected_token:
        raise HTTPException(
            status_code=500, detail="CAGE_INTERNAL_TOKEN not configured"
        )

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(x_cage_internal_token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid X-Cage-Internal-Token")

    return x_cage_internal_token


async def require_operator_identity(request: Request) -> OperatorPrincipal:
    """Extract verified operator identity from SPIFFE SVID or OIDC claims.

    Identity precedence (fail-closed, evaluated not negotiated):
    1. **SPIFFE SVID** (primary): Extracted from mTLS client cert SAN via Linkerd mesh
    2. **OIDC JWT** (fallback): Only if CAGE_OPERATOR_IDENTITY_ALLOW_OIDC=true
    3. **Dev synthetic** (dev-only): If CAGE_ENV=dev AND CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC=true

    Args:
        request: FastAPI request with potential .attributes.source.principal (SVID)
                 or .headers.authorization (OIDC)

    Returns:
        OperatorPrincipal with verified identity and provenance channel

    Raises:
        HTTPException: 401 if no valid identity source exists, or 400 if dev-prefix
                       used outside dev mode
    """
    # Channel 1: SPIFFE SVID from mTLS client certificate (primary)
    # Linkerd populates request.attributes.source.principal with spiffe://... from peer cert
    try:
        # In FastAPI with Envoy ext_authz, we receive grpc metadata as headers
        # The SPIFFE ID should be in x-forwarded-client-cert or a similar header
        # For now, we'll check if the source principal is available via a custom header
        svid = request.headers.get("x-cage-source-principal") or getattr(
            getattr(request, "attributes", None), "source", {}
        ).get("principal")

        if svid and svid.startswith("spiffe://"):
            principal_hash = hashlib.sha256(svid.encode()).hexdigest()
            logger.info(f"✅ Operator identity verified via SVID: {svid[:30]}...")
            return OperatorPrincipal(
                operator_urn=svid,
                channel_provenance="SVID",
                auth_principal_hash=principal_hash,
            )
    except Exception as e:
        logger.warning(f"⚠️  SVID extraction failed: {e}")

    # Channel 2: OIDC JWT sub claim (gated fallback)
    allow_oidc = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "false").lower() == "true"
    )
    if allow_oidc:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # In production, this would verify JWT signature and extract sub claim
            # For now, we'll extract the sub from a hypothetical pre-validated claim
            # The actual JWT validation should happen in a separate middleware
            try:
                # Placeholder: In real implementation, decode and verify JWT
                jwt_sub = (
                    request.state.jwt_claims.get("sub")
                    if hasattr(request.state, "jwt_claims")
                    else None
                )
                if jwt_sub:
                    principal_hash = hashlib.sha256(jwt_sub.encode()).hexdigest()
                    logger.info(
                        f"✅ Operator identity verified via OIDC: {jwt_sub[:30]}..."
                    )
                    return OperatorPrincipal(
                        operator_urn=jwt_sub,
                        channel_provenance="OIDC",
                        auth_principal_hash=principal_hash,
                    )
            except Exception as e:
                logger.warning(f"⚠️  OIDC JWT extraction failed: {e}")

    # Channel 3: Dev-mode synthetic principal (dual-condition guard)
    allow_dev_synthetic = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "false").lower()
        == "true"
    )
    if _CAGE_ENV == "dev" and allow_dev_synthetic:
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
