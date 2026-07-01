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
Bearer token authentication dependency for the Governed Financial Advisor API.

C-04: Adds authentication to financial API endpoints that previously had none.
Validates the bearer token against the CAGE_API_KEY environment variable using
constant-time comparison to prevent timing attacks.

In dev mode with no CAGE_API_KEY configured, requests are allowed through with
a warning so local development is not blocked. In all other environments,
missing or invalid credentials return HTTP 401.
"""

import hmac
import logging
import os

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)


async def require_api_key(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    """Validate bearer token against CAGE_API_KEY env var. Fail closed.

    Returns the validated token string on success.

    Raises:
        HTTPException(401): If credentials are missing or invalid.
    """
    api_key = os.environ.get("CAGE_API_KEY", "")
    cage_env = os.environ.get("CAGE_ENV", "prod").lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement

    # In dev with no API key configured, allow through with warning.
    # This preserves local development ergonomics without compromising prod.
    if cage_env == "dev" and not api_key:
        logger.warning(
            "CAGE_API_KEY not set — authentication disabled in dev mode"
        )
        return "dev-unauthenticated"

    if not credentials or not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time comparison to prevent timing attacks.
    provided = credentials.credentials.encode()
    expected = api_key.encode()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
