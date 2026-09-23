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
Outbound Credential Protocol — Layer 1 Kernel (Gate G3 Compliant).

Defines the abstract protocol for acquiring bearer tokens to authenticate
outbound inter-service calls (e.g., Cloud Run → Cloud Run via OIDC ID tokens).

Architecture:
    - Layer 1 (this module): Protocol definitions only, zero vendor SDK imports.
    - Layer 3 (src/integrations/gcp/, src/integrations/aws/, etc.): Concrete
      implementations for GCP metadata server, AWS IRSA, Azure MSI.

Usage:
    from src.gateway.governance.seams.outbound_credential import (
        BearerToken,
        OutboundCredentialProvider,
    )
    from src.gateway.governance.outbound_credential_factory import (
        get_outbound_credential_provider,
    )

    provider = get_outbound_credential_provider()
    token = await provider.get_token(target_url="https://downstream.example.com")
    headers = {"Authorization": token.authorization_header}

Contract:
    - Tokens MUST include audience scoping (bound to target URL).
    - Providers MUST cache tokens until TTL expiration.
    - Expired tokens MUST trigger automatic refresh.
    - Network failures MUST fail-closed (raise, never return stale/invalid tokens).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


@dataclass(frozen=True)
class BearerToken:
    """
    Immutable bearer token with expiry metadata.

    Attributes:
        token: Raw token string (JWT for OIDC, opaque for OAuth2).
        expires_at: Absolute UTC timestamp when token becomes invalid.
        audience: Target URL or service identifier this token is scoped to.
    """

    token: str
    expires_at: datetime
    audience: str

    @property
    def is_expired(self) -> bool:
        """Check if token has expired based on current UTC time."""
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def authorization_header(self) -> str:
        """Return HTTP Authorization header value (Bearer scheme)."""
        return f"Bearer {self.token}"


class OutboundCredentialProvider(Protocol):
    """
    Protocol for acquiring outbound authentication tokens.

    Implementations MUST:
        - Cache tokens until TTL expiration (avoid redundant metadata calls).
        - Scope tokens to the requested target URL (audience claim).
        - Fail-closed on network errors (raise, never return invalid tokens).
        - Be thread-safe (multiple concurrent get_token calls allowed).
    """

    async def get_token(self, target_url: str) -> BearerToken:
        """
        Acquire or retrieve cached bearer token for the target URL.

        Args:
            target_url: Destination service URL (used as OIDC audience claim).

        Returns:
            BearerToken with valid (non-expired) token scoped to target_url.

        Raises:
            RuntimeError: If token minting fails (network, auth, platform errors).
        """
        ...
