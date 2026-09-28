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
GCP IAM Credential Provider for Redis / Valkey — Layer 3 Integration Adapter.

Provides dynamic OAuth2 access tokens for Google Cloud Memorystore (Valkey / Redis)
instances configured with authorization_mode = "IAM_AUTH".

Architecture:
    - Implements redis.credentials.CredentialProvider interface.
    - Resolves access tokens via GCP metadata server or Google Application Default Credentials.
    - Returns ("default", access_token) for Memorystore authentication.
    - Caches access tokens with TTL awareness and thread-safe locking.
    - Fails closed on network or token resolution errors.

Usage:
    from src.integrations.gcp.redis_credential_provider import GcpRedisIamCredentialProvider

    provider = GcpRedisIamCredentialProvider()
    username, password = provider.get_credentials()
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import ClassVar

import httpx
from redis.credentials import CredentialProvider

logger = logging.getLogger(__name__)

# GCP metadata server endpoint for OAuth2 access tokens
GCP_METADATA_TOKEN_ENDPOINT = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

# Safety margin before expiry (5 minutes in seconds)
TOKEN_EXPIRY_MARGIN_SECONDS = 300


class GcpRedisIamCredentialProvider(CredentialProvider):
    """
    CredentialProvider implementation yielding Google Cloud IAM OAuth2 access tokens.

    Memorystore instances running Valkey with IAM authentication require the client to
    authenticate using AUTH <username> <access_token>, where username is typically 'default'.
    """

    _cached_token: ClassVar[str | None] = None
    _cached_expiry: ClassVar[float] = 0.0
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self,
        username: str = "default",
        metadata_timeout: float = 3.0,
    ) -> None:
        self.username = username
        self.metadata_timeout = metadata_timeout

    def _fetch_token_from_metadata(self) -> tuple[str, float]:
        """Fetch access token from GCP metadata server."""
        try:
            with httpx.Client(timeout=self.metadata_timeout) as client:
                resp = client.get(
                    GCP_METADATA_TOKEN_ENDPOINT,
                    headers={"Metadata-Flavor": "Google"},
                )
                resp.raise_for_status()
                data = resp.json()
                token = data["access_token"]
                expires_in = float(data.get("expires_in", 3600))
                expiry = time.time() + expires_in
                return token, expiry
        except Exception as exc:
            logger.debug("GCP metadata server token fetch failed: %s", exc)
            raise RuntimeError(f"GCP metadata server token fetch failed: {exc}") from exc

    def _fetch_token_from_adc(self) -> tuple[str, float]:
        """Fetch access token from Application Default Credentials."""
        try:
            import google.auth
            from google.auth.transport.requests import Request

            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            credentials.refresh(Request())
            if not credentials.token:
                raise RuntimeError("ADC refreshed without token")
            expiry = (
                credentials.expiry.timestamp()
                if credentials.expiry
                else time.time() + 3600
            )
            return credentials.token, expiry
        except Exception as exc:
            logger.debug("GCP ADC token fetch failed: %s", exc)
            raise RuntimeError(f"GCP ADC token fetch failed: {exc}") from exc

    def _get_token(self) -> str:
        """Retrieve a valid access token, refreshing if necessary."""
        # Check explicit test/override environment variable
        override_token = os.environ.get("REDIS_IAM_TOKEN")
        if override_token:
            return override_token

        now = time.time()
        with self._lock:
            if (
                self._cached_token is not None
                and now < (self._cached_expiry - TOKEN_EXPIRY_MARGIN_SECONDS)
            ):
                return self._cached_token

            # Try metadata server first, then ADC
            token: str | None = None
            expiry: float = 0.0

            try:
                token, expiry = self._fetch_token_from_metadata()
            except RuntimeError:
                try:
                    token, expiry = self._fetch_token_from_adc()
                except RuntimeError as adc_exc:
                    cage_env = os.environ.get("CAGE_ENV", "").lower()
                    if cage_env in ("dev", "development", "test", "ci"):
                        logger.warning(
                            "GCP IAM credentials unavailable in %s environment; using simulated dev token",
                            cage_env,
                        )
                        token = "simulated-gcp-redis-iam-token"
                        expiry = now + 3600
                    else:
                        raise RuntimeError(
                            "Unable to obtain GCP IAM token for Memorystore authentication: "
                            "neither metadata server nor ADC succeeded."
                        ) from adc_exc

            self._cached_token = token
            self._cached_expiry = expiry
            return token

    def get_credentials(self) -> tuple[str, str]:
        """Return (username, access_token) for Redis/Valkey AUTH."""
        token = self._get_token()
        return self.username, token

    async def get_credentials_async(self) -> tuple[str, str]:
        """Asynchronously return (username, access_token) for Redis/Valkey AUTH."""
        return self.get_credentials()
