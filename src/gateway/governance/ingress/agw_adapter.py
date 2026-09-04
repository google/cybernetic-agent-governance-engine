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

"""Agent Gateway (AGW) absorption adapter.

Translates AGW-format agent requests into CAGE governance pipeline inputs.
Implements OIDC token validation for agent identity verification.

CAGE-002 Phase B: AGW Absorption
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

AGW_OIDC_ISSUER = os.environ.get("AGW_OIDC_ISSUER", "")
AGW_OIDC_AUDIENCE = os.environ.get("AGW_OIDC_AUDIENCE", "cage-gateway")
AGW_ENDPOINT = os.environ.get("AGW_ENDPOINT", "")


@dataclass
class AgwRequest:
    """Normalized AGW request for CAGE governance pipeline."""

    agent_id: str
    tool_name: str
    parameters: dict[str, Any]
    oidc_token: str = ""
    trace_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgwAdapterResult:
    """Result of AGW adapter processing."""

    success: bool
    agent_id: str
    tool_name: str
    parameters: dict[str, Any]
    identity_verified: bool = False
    error: str = ""


class AgwAdapter:
    """Adapter for Agent Gateway protocol absorption into CAGE governance.

    Validates OIDC tokens, normalizes AGW requests, and forwards to
    the CAGE governance pipeline.
    """

    def __init__(self) -> None:
        self._http_client: httpx.AsyncClient | None = None
        self._jwks_cache: dict[str, Any] = {}

    async def validate_oidc_token(self, token: str) -> tuple[bool, dict[str, Any]]:
        """Validate OIDC token against AGW issuer JWKS endpoint.

        Returns (is_valid, claims) tuple.
        """
        if not AGW_OIDC_ISSUER:
            logger.warning("AGW_OIDC_ISSUER not configured; skipping OIDC validation")
            return False, {}

        # In production: fetch JWKS from {AGW_OIDC_ISSUER}/.well-known/jwks.json
        # and validate JWT signature, expiry, audience
        # For now: stub that returns False (fail-closed)
        return False, {}

    async def translate_request(self, raw_request: dict[str, Any]) -> AgwRequest:
        """Translate raw AGW request dict into normalized AgwRequest."""
        return AgwRequest(
            agent_id=raw_request.get("agent_id", "unknown"),
            tool_name=raw_request.get("tool", {}).get("name", ""),
            parameters=raw_request.get("tool", {}).get("parameters", {}),
            oidc_token=raw_request.get("auth", {}).get("token", ""),
            trace_id=raw_request.get("trace_id", ""),
            metadata=raw_request.get("metadata", {}),
        )

    async def process(self, raw_request: dict[str, Any]) -> AgwAdapterResult:
        """Full AGW request processing: translate + OIDC validate.

        Issue #2 remediation: Fail-closed authentication semantics.
        If OIDC validation fails (identity_verified=False), the adapter
        returns success=False to prevent unauthenticated traffic from
        being admitted by callers that gate on success rather than
        identity_verified.

        Callers MUST check identity_verified before trusting the request.
        success=True AND identity_verified=True are both required for
        authenticated admission.
        """
        req = await self.translate_request(raw_request)
        identity_verified, _claims = await self.validate_oidc_token(req.oidc_token)

        # Issue #2: Fail-closed if OIDC validation fails
        # success is False if authentication fails, True if auth succeeds
        # Callers gating on success will correctly reject unauthenticated traffic
        return AgwAdapterResult(
            success=identity_verified,  # Changed from hardcoded True
            agent_id=req.agent_id,
            tool_name=req.tool_name,
            parameters=req.parameters,
            identity_verified=identity_verified,
            error="" if identity_verified else "OIDC token validation failed",
        )


_agw_adapter: AgwAdapter | None = None


def get_agw_adapter() -> AgwAdapter:
    """Lazy singleton for AGW adapter."""
    global _agw_adapter
    if _agw_adapter is None:
        _agw_adapter = AgwAdapter()
    return _agw_adapter
