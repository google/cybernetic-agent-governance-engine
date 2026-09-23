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
Outbound Credential Provider Factory — Layer 1 Kernel with Lazy Layer 3 Loading.

Auto-detects cloud platform (GCP/AWS/Azure) from environment variables and returns
the appropriate credential provider implementation via function-scope lazy imports.

Architecture:
    - Platform detection runs once at module initialization (fast env var reads).
    - Provider instantiation is deferred until first get_outbound_credential_provider() call.
    - Layer 3 adapter imports (src.integrations.gcp, etc.) occur at function scope only.

Platform Detection Strategy:
    - GCP Cloud Run: K_SERVICE environment variable present.
    - AWS ECS/Fargate: ECS_CONTAINER_METADATA_URI_V4 present.
    - Azure Container Apps: IDENTITY_ENDPOINT + IDENTITY_HEADER present.
    - Local/CI: None of the above → returns NullCredentialProvider (no-op).

Gate G3 Compliance:
    This module is allowlisted in INTEGRATIONS_FACTORY_ALLOWLIST
    (scripts/check_import_boundaries.py) to permit function-scope Layer 3 imports.
"""

import logging
import os
from datetime import datetime, timezone

from src.gateway.governance.seams.outbound_credential import (
    BearerToken,
    OutboundCredentialProvider,
)

logger = logging.getLogger(__name__)

# Platform detection (runs once at module load)
_DETECTED_PLATFORM: str | None = None


def _detect_platform() -> str | None:
    """
    Detect cloud platform from environment variables.

    Returns:
        "gcp" | "aws" | "azure" | None
    """
    if os.getenv("K_SERVICE"):
        return "gcp"
    if os.getenv("ECS_CONTAINER_METADATA_URI_V4"):
        return "aws"
    if os.getenv("IDENTITY_ENDPOINT") and os.getenv("IDENTITY_HEADER"):
        return "azure"
    return None


_DETECTED_PLATFORM = _detect_platform()


class NullCredentialProvider:
    """
    No-op credential provider for local/CI environments.

    Returns a synthetic token valid for 1 hour. Downstream services in local
    environments should disable token verification or accept this placeholder.
    """

    async def get_token(self, target_url: str) -> BearerToken:
        """Return synthetic token for local development."""
        logger.warning(
            "NullCredentialProvider: Returning synthetic token for target_url=%s. "
            "This is intended for local development only.",
            target_url,
        )
        return BearerToken(
            token="local-dev-token-no-verification",
            expires_at=datetime.now(timezone.utc).replace(
                hour=datetime.now(timezone.utc).hour + 1
            ),
            audience=target_url,
        )


def _load_provider(platform: str) -> OutboundCredentialProvider:
    """
    Lazy-load platform-specific credential provider (function-scope imports).

    Args:
        platform: "gcp" | "aws" | "azure"

    Returns:
        Concrete provider implementation from Layer 3 (src/integrations/).

    Raises:
        ImportError: If platform adapter not installed/implemented.
    """
    if platform == "gcp":
        from src.integrations.gcp.credential_provider import GcpOidcCredentialProvider

        return GcpOidcCredentialProvider.from_env()
    elif platform == "aws":
        # Future: AWS IRSA implementation
        raise NotImplementedError("AWS IRSA credential provider not yet implemented")
    elif platform == "azure":
        # Future: Azure MSI implementation
        raise NotImplementedError("Azure MSI credential provider not yet implemented")
    else:
        raise ValueError(f"Unknown platform: {platform}")


# Singleton instance
_PROVIDER_INSTANCE: OutboundCredentialProvider | None = None


def get_outbound_credential_provider() -> OutboundCredentialProvider:
    """
    Get singleton outbound credential provider (auto-detected platform).

    Returns:
        - GcpOidcCredentialProvider if running on GCP Cloud Run.
        - NullCredentialProvider if running locally/CI.
        - AWS/Azure providers when implemented.

    Thread-Safety:
        This function is not thread-safe during initial instantiation, but
        subsequent calls return the cached singleton. Call once during app
        startup to ensure thread-safe access.
    """
    global _PROVIDER_INSTANCE

    if _PROVIDER_INSTANCE is not None:
        return _PROVIDER_INSTANCE

    if _DETECTED_PLATFORM is None:
        logger.info(
            "No cloud platform detected (K_SERVICE, ECS_*, IDENTITY_ENDPOINT absent). "
            "Using NullCredentialProvider for local development."
        )
        _PROVIDER_INSTANCE = NullCredentialProvider()
    else:
        logger.info("Detected platform: %s. Loading credential provider.", _DETECTED_PLATFORM)
        _PROVIDER_INSTANCE = _load_provider(_DETECTED_PLATFORM)

    return _PROVIDER_INSTANCE
