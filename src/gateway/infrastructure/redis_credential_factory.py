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
Redis Credential Factory — Layer 1 Kernel Seam with Lazy Layer 3 Loading.

Provides Redis/Valkey credential providers for managed infrastructure authentication.
When IAM authentication is requested (e.g. Google Cloud Memorystore with IAM auth),
the factory loads the platform-specific adapter at function scope.

Gate G3 Compliance:
    This module is allowlisted in INTEGRATIONS_FACTORY_ALLOWLIST
    (scripts/check_import_boundaries.py) to permit function-scope Layer 3 imports.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redis.credentials import CredentialProvider

logger = logging.getLogger(__name__)


def is_redis_iam_auth_enabled() -> bool:
    """Return True if Redis IAM authentication is requested via configuration or environment."""
    auth_mode = os.environ.get("REDIS_AUTH_MODE", "").lower()
    if auth_mode == "iam":
        return True
    return os.environ.get("REDIS_IAM_AUTH", "").lower() in ("true", "1", "yes")


def get_redis_credential_provider(
    auth_mode: str | None = None,
) -> CredentialProvider | None:
    """
    Get a CredentialProvider instance for Redis/Valkey if IAM authentication is configured.

    Args:
        auth_mode: Optional explicit auth mode ('iam', 'password', 'none'). If omitted,
                   resolved from REDIS_AUTH_MODE and REDIS_IAM_AUTH environment variables.

    Returns:
        CredentialProvider implementation if IAM authentication is enabled, else None.
    """
    effective_iam = (
        auth_mode.lower() == "iam"
        if auth_mode is not None
        else is_redis_iam_auth_enabled()
    )

    if not effective_iam:
        return None

    # Function-scope lazy import of Layer 3 GCP integration (allowlisted under Gate G3)
    logger.info(
        "Initializing GCP IAM Credential Provider for Memorystore authentication"
    )
    from src.integrations.gcp.redis_credential_provider import (
        GcpRedisIamCredentialProvider,
    )

    return GcpRedisIamCredentialProvider()
