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
Lifecycle Management for Agent Integrity Sidecar.

Provides health check and daemon lifecycle utilities for the Agent Integrity
verification sidecar process. Supports both HTTP endpoint health probes and
subprocess management for test environments.

Usage:
    # Health check
    health = SidecarHealthCheck("http://localhost:8090")
    if await health.is_ready():
        # Proceed with verification requests
        ...

    # Test daemon management (for integration tests)
    # See tests/integrations/provider_06/conftest.py for usage examples
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("cage.provider_06.lifecycle")

# Default timeout from environment
_DEFAULT_TIMEOUT = float(os.environ.get("CAGE_AGENT_INTEGRITY_TIMEOUT", "10"))


class SidecarHealthCheck:
    """
    Health check client for Agent Integrity sidecar process.

    Probes HTTP endpoints to verify the sidecar is ready to accept
    verification requests. Supports bounded timeouts to prevent hanging
    during startup or failure scenarios.

    Attributes:
        endpoint: Base URL of the sidecar (e.g., "http://localhost:8090")
        timeout: Probe timeout in seconds (default from env or 10s)
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        """
        Initialize health check client.

        Args:
            endpoint: Base URL of Agent Integrity sidecar
            timeout: HTTP probe timeout in seconds
        """
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout

    async def is_ready(self) -> bool:
        """
        Check if sidecar is ready to accept requests.

        Probes the /health endpoint (or /status if /health is not available).
        Returns True if the endpoint responds with 2xx status code.

        Returns:
            True if sidecar is healthy, False otherwise

        Note:
            This method never raises exceptions. Network errors and HTTP
            failures are caught and mapped to False.
        """
        probe_endpoints = ["/health", "/status"]

        for path in probe_endpoints:
            url = f"{self._endpoint}{path}"
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(url)
                    if response.status_code == 200:
                        logger.debug(
                            "provider_06: Health check SUCCESS — %s", url
                        )
                        return True
            except httpx.TimeoutException:
                logger.warning(
                    "provider_06: Health check TIMEOUT — %s (%.1fs)",
                    url,
                    self._timeout,
                )
            except Exception as exc:
                logger.debug(
                    "provider_06: Health check FAILED — %s: %s",
                    url,
                    exc,
                )

        logger.warning(
            "provider_06: Sidecar not ready at %s (tried %s)",
            self._endpoint,
            probe_endpoints,
        )
        return False
