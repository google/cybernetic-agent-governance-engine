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
HTTP Client Factory — Centralized timeout enforcement for httpx clients.

This module addresses M-9 (MEDIUM): Async HTTP clients lack timeout enforcement.

Problem:
    httpx clients created without explicit timeout parameters can hang indefinitely
    on slow or unresponsive endpoints, causing request backlog and resource exhaustion.

Solution:
    Centralized factory functions with posture-aware default timeouts:
    - PRODUCTION/STAGING: 10 seconds (fail-fast for reliability)
    - DEV/TEST/LOCAL/CI: 30 seconds (allow slower local services)

Usage:
    from src.gateway.governance.http_client_factory import (
        create_async_client,
        create_sync_client,
    )

    # Create async client with default timeout
    async with create_async_client() as client:
        response = await client.get("https://api.example.com")

    # Create async client with custom timeout
    async with create_async_client(timeout_seconds=5.0) as client:
        response = await client.get("https://api.example.com")

    # Create sync client
    with create_sync_client() as client:
        response = client.get("https://api.example.com")

Architecture:
    All httpx client creation should go through these factory functions to ensure
    consistent timeout enforcement across the codebase. This prevents timeout
    configuration drift and makes timeout behavior auditable via a single module.

Security Rationale:
    Shorter timeouts in production reduce attack surface for slowloris-style DoS
    attacks where attackers send partial HTTP requests to exhaust connection pools.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.gateway.governance.env_posture import DeploymentPosture, resolve_posture

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Posture-aware timeout defaults
# ---------------------------------------------------------------------------

_PRODUCTION_TIMEOUT_S = 10.0  # Fail-fast in production
_DEV_TIMEOUT_S = 30.0  # Allow slower local services in dev


def _get_default_timeout(posture: DeploymentPosture | None = None) -> float:
    """
    Get the default HTTP client timeout for the current deployment posture.

    Args:
        posture: Deployment posture. If None, resolves from environment.

    Returns:
        Timeout in seconds (10.0 for production/staging, 30.0 for dev/test/local/ci).
    """
    if posture is None:
        posture = resolve_posture()

    if posture in (DeploymentPosture.PRODUCTION, DeploymentPosture.STAGING):
        return _PRODUCTION_TIMEOUT_S
    else:
        return _DEV_TIMEOUT_S


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def create_async_client(
    timeout_seconds: float | None = None,
    posture: DeploymentPosture | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """
    Create an httpx.AsyncClient with enforced timeout.

    M-9 fix: All async HTTP clients should be created via this factory to ensure
    timeouts are consistently enforced across the codebase.

    Args:
        timeout_seconds: Explicit timeout in seconds. If None, uses posture-aware default
            (PRODUCTION/STAGING=10s, DEV/TEST/LOCAL/CI=30s).
        posture: Deployment posture for default timeout selection. If None, auto-resolved.
        **kwargs: Additional arguments passed to httpx.AsyncClient constructor
            (e.g., limits, verify, headers, base_url).

    Returns:
        httpx.AsyncClient configured with the specified or default timeout.

    Examples:
        >>> # Use posture-aware default timeout
        >>> async with create_async_client() as client:
        ...     response = await client.get("https://api.example.com")

        >>> # Use explicit timeout
        >>> async with create_async_client(timeout_seconds=5.0) as client:
        ...     response = await client.get("https://api.example.com")

        >>> # Pass additional httpx.AsyncClient parameters
        >>> async with create_async_client(
        ...     timeout_seconds=15.0,
        ...     limits=httpx.Limits(max_connections=10),
        ...     verify=True,
        ... ) as client:
        ...     response = await client.get("https://api.example.com")
    """
    if timeout_seconds is None:
        timeout_seconds = _get_default_timeout(posture)

    # If caller already passed a 'timeout' kwarg, prefer the explicit timeout_seconds
    # to avoid confusion. Log a warning if both are provided.
    if "timeout" in kwargs:
        logger.warning(
            "create_async_client: both timeout_seconds=%s and timeout kwarg provided. "
            "Using timeout_seconds and ignoring timeout kwarg.",
            timeout_seconds,
        )
        kwargs.pop("timeout")

    logger.debug(
        "Creating httpx.AsyncClient with timeout=%.1fs (posture=%s)",
        timeout_seconds,
        posture.value if posture else resolve_posture().value,
    )

    return httpx.AsyncClient(timeout=timeout_seconds, **kwargs)


def create_sync_client(
    timeout_seconds: float | None = None,
    posture: DeploymentPosture | None = None,
    **kwargs: Any,
) -> httpx.Client:
    """
    Create an httpx.Client with enforced timeout.

    M-9 fix: All sync HTTP clients should be created via this factory to ensure
    timeouts are consistently enforced across the codebase.

    Args:
        timeout_seconds: Explicit timeout in seconds. If None, uses posture-aware default
            (PRODUCTION/STAGING=10s, DEV/TEST/LOCAL/CI=30s).
        posture: Deployment posture for default timeout selection. If None, auto-resolved.
        **kwargs: Additional arguments passed to httpx.Client constructor
            (e.g., limits, verify, headers, base_url).

    Returns:
        httpx.Client configured with the specified or default timeout.

    Examples:
        >>> # Use posture-aware default timeout
        >>> with create_sync_client() as client:
        ...     response = client.get("https://api.example.com")

        >>> # Use explicit timeout
        >>> with create_sync_client(timeout_seconds=5.0) as client:
        ...     response = client.get("https://api.example.com")

        >>> # Pass additional httpx.Client parameters
        >>> with create_sync_client(
        ...     timeout_seconds=15.0,
        ...     limits=httpx.Limits(max_connections=10),
        ...     verify=True,
        ... ) as client:
        ...     response = client.get("https://api.example.com")
    """
    if timeout_seconds is None:
        timeout_seconds = _get_default_timeout(posture)

    # If caller already passed a 'timeout' kwarg, prefer the explicit timeout_seconds
    # to avoid confusion. Log a warning if both are provided.
    if "timeout" in kwargs:
        logger.warning(
            "create_sync_client: both timeout_seconds=%s and timeout kwarg provided. "
            "Using timeout_seconds and ignoring timeout kwarg.",
            timeout_seconds,
        )
        kwargs.pop("timeout")

    logger.debug(
        "Creating httpx.Client with timeout=%.1fs (posture=%s)",
        timeout_seconds,
        posture.value if posture else resolve_posture().value,
    )

    return httpx.Client(timeout=timeout_seconds, **kwargs)
