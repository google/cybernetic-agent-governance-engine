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
Lifecycle probes for the Agent Integrity verified-release sidecar.

The sidecar contract (Agent Integrity PR #11) defines two probes:

- ``GET /health/live``  — the process is up and answering.
- ``GET /health/ready`` — the sidecar can serve ``/verify`` (keys loaded,
  dependencies reachable). It fails closed: anything but HTTP 200 is
  "not ready".

There is deliberately no fallback to a legacy ``/health`` or ``/status``
path. A liveness-style endpoint answering 200 says nothing about readiness,
so falling back to one would let CAGE dispatch to a sidecar that cannot yet
sign receipts.

Usage:
    health = SidecarHealthCheck("http://localhost:8090")
    if await health.is_ready():
        ...  # dispatch /verify
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("cage.provider_06.lifecycle")

READY_PATH = "/health/ready"
LIVE_PATH = "/health/live"

# Default timeout from environment
_DEFAULT_TIMEOUT = float(os.environ.get("CAGE_AGENT_INTEGRITY_TIMEOUT", "10"))


class SidecarHealthCheck:
    """
    Probe client for the Agent Integrity sidecar.

    Both probes are bounded by ``timeout`` and never raise: transport errors,
    timeouts and non-200 responses all map to ``False`` (fail closed).

    Attributes:
        endpoint: Base URL of the sidecar (e.g., "http://localhost:8090")
        timeout: Probe timeout in seconds (default from env or 10s)
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = _DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Initialize the probe client.

        Args:
            endpoint: Base URL of the Agent Integrity sidecar.
            timeout: HTTP probe timeout in seconds.
            transport: Optional httpx transport (hermetic tests only).
        """
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    async def is_ready(self) -> bool:
        """True iff ``GET /health/ready`` answers HTTP 200."""
        return await self._probe(READY_PATH)

    async def is_live(self) -> bool:
        """True iff ``GET /health/live`` answers HTTP 200."""
        return await self._probe(LIVE_PATH)

    async def _probe(self, path: str) -> bool:
        url = f"{self._endpoint}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.get(url)
        except httpx.TimeoutException:
            logger.warning(
                "provider_06: probe TIMEOUT — %s (%.1fs)", url, self._timeout
            )
            return False
        except httpx.HTTPError as exc:
            logger.warning(
                "provider_06: probe FAILED — %s: %s", url, type(exc).__name__
            )
            return False

        if response.status_code != 200:
            logger.warning(
                "provider_06: probe NOT OK — %s (HTTP %d)", url, response.status_code
            )
            return False
        logger.debug("provider_06: probe OK — %s", url)
        return True
