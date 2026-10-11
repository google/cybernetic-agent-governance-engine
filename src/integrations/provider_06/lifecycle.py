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

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

logger = logging.getLogger("cage.provider_06.lifecycle")

READY_PATH = "/health/ready"
LIVE_PATH = "/health/live"

READINESS_REASONS = frozenset(
    {
        "CONFIGURATION",
        "KEYS",
        "ROOT_LEASE",
        "CAPACITY",
        "BUNDLE_ROOT",
        "SNAPSHOT_ROOT",
        "SOCKET",
        "RECOVERY_REQUIRED",
    }
)

# Default timeout from environment
_DEFAULT_TIMEOUT = float(os.environ.get("CAGE_AGENT_INTEGRITY_TIMEOUT", "10"))
_DEFAULT_SOCKET_PATH = os.environ.get("CAGE_AGENT_INTEGRITY_SOCKET_PATH", "")


@dataclass(frozen=True)
class ReadinessStatus:
    """Detailed readiness probe result from ``GET /health/ready``."""

    ready: bool
    reasons: tuple[str, ...] = ()
    status_code: int = 503
    retry_after: int | None = None


class SidecarHealthCheck:
    """
    Probe client for the Agent Integrity sidecar.

    Both probes are bounded by ``timeout`` and never raise: transport errors,
    timeouts and non-200 responses all map to ``False`` (fail closed).
    Supports both Unix domain sockets (``socket_path``) and HTTP endpoints.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost",
        timeout: float = _DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        socket_path: str | Path | None = None,
    ) -> None:
        """
        Initialize the probe client.

        Args:
            endpoint: Base URL of the Agent Integrity sidecar.
            timeout: HTTP probe timeout in seconds.
            transport: Optional httpx transport (hermetic tests only).
            socket_path: Optional Unix domain socket path for production UDS transport.
        """
        resolved_socket = (
            str(socket_path) if socket_path is not None else _DEFAULT_SOCKET_PATH
        )
        self._socket_path = resolved_socket or None
        self._endpoint = (endpoint or "http://localhost").rstrip("/")
        self._timeout = timeout
        self._transport = transport

    def _build_client(self) -> httpx.AsyncClient:
        transport = self._transport
        if transport is None and self._socket_path:
            transport = httpx.AsyncHTTPTransport(uds=self._socket_path)
        return httpx.AsyncClient(timeout=self._timeout, transport=transport)

    async def is_ready(self) -> bool:
        """True iff ``GET /health/ready`` answers HTTP 200 with ready state."""
        status = await self.check_readiness_detail()
        return status.ready

    async def is_live(self) -> bool:
        """True iff ``GET /health/live`` answers HTTP 200."""
        return await self._probe(LIVE_PATH)

    async def check_readiness_detail(self) -> ReadinessStatus:
        """Execute ``GET /health/ready`` and parse readiness reasons and Retry-After."""
        url = f"{self._endpoint}{READY_PATH}"
        try:
            async with self._build_client() as client:
                response = await client.get(url)
        except httpx.TimeoutException:
            logger.warning(
                "provider_06: probe TIMEOUT — %s (%.1fs)", url, self._timeout
            )
            return ReadinessStatus(ready=False, status_code=503)
        except httpx.HTTPError as exc:
            logger.warning(
                "provider_06: probe FAILED — %s: %s", url, type(exc).__name__
            )
            return ReadinessStatus(ready=False, status_code=503)

        retry_after: int | None = None
        raw_retry = response.headers.get("Retry-After")
        if raw_retry is not None and raw_retry.isdigit():
            retry_after = int(raw_retry)

        reasons: tuple[str, ...] = ()
        body_ready: bool | None = None
        if response.content:
            try:
                payload = json.loads(response.content.decode("utf-8"))
                if isinstance(payload, dict):
                    if isinstance(payload.get("ready"), bool):
                        body_ready = payload["ready"]
                    raw_reasons = payload.get("reasons")
                    if isinstance(raw_reasons, list) and all(
                        isinstance(r, str) for r in raw_reasons
                    ):
                        reasons = tuple(raw_reasons)
            except (UnicodeDecodeError, json.JSONDecodeError):
                body_ready = False

        if response.status_code != 200:
            logger.warning(
                "provider_06: probe NOT OK — %s (HTTP %d, reasons=%s)",
                url,
                response.status_code,
                reasons,
            )
            return ReadinessStatus(
                ready=False,
                reasons=reasons,
                status_code=response.status_code,
                retry_after=retry_after,
            )

        if body_ready is False or reasons:
            logger.warning(
                "provider_06: probe HTTP 200 but body reports not ready — %s",
                url,
            )
            return ReadinessStatus(
                ready=False,
                reasons=reasons,
                status_code=response.status_code,
                retry_after=retry_after,
            )

        logger.debug("provider_06: probe OK — %s", url)
        return ReadinessStatus(
            ready=True,
            reasons=(),
            status_code=200,
            retry_after=retry_after,
        )

    async def _probe(self, path: str) -> bool:
        url = f"{self._endpoint}{path}"
        try:
            async with self._build_client() as client:
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
