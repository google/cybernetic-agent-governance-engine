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
Internal service token authentication for the compliance bridge.

C-07: Adds authentication to the /v1/audit/ingest endpoint which previously
accepted audit results from any caller without authentication.

Uses a bearer token validated against the COMPLIANCE_BRIDGE_INTERNAL_TOKEN
environment variable with constant-time comparison to prevent timing attacks.

In dev mode with no token configured, requests are allowed through with a
warning so local development is not blocked.
"""

import hmac
import logging
import os

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)


async def require_internal_token(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    """Validate internal service token for compliance bridge endpoints.

    Returns the validated token string on success.

    Raises:
        HTTPException(401): If credentials are missing or invalid.
    """
    token = os.environ.get("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", "")
    cage_env = os.environ.get("CAGE_ENV", "prod").lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement

    # In dev with no token configured, allow through with warning.
    # This preserves local development ergonomics without compromising prod.
    if cage_env == "dev" and not token:
        logger.warning(
            "COMPLIANCE_BRIDGE_INTERNAL_TOKEN not set — auth disabled in dev"
        )
        return "dev-unauthenticated"

    if not credentials or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time comparison to prevent timing attacks.
    if not hmac.compare_digest(
        credentials.credentials.encode(), token.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
