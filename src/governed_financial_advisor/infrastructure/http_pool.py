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
HTTP Pool — Shared async httpx connection pool for governance infrastructure.

Provides a singleton pooled httpx.AsyncClient for reuse across requests.
Use _get_async_client() to get the shared client.
Call close_async_client() on application shutdown.
"""
import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_async_client: Optional[httpx.AsyncClient] = None
_async_client_lock: asyncio.Lock = asyncio.Lock()

# Connection pool configuration
_POOL_LIMITS = httpx.Limits(
    max_connections=50,
    max_keepalive_connections=20,
)

# Retry configuration
_MAX_RETRIES: int = 3
_BASE_DELAY_SECONDS: float = 1.0
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 503})


async def _get_async_client() -> httpx.AsyncClient:
    """Get or create the shared async HTTP client."""
    global _async_client
    if _async_client is not None and not _async_client.is_closed:
        return _async_client

    async with _async_client_lock:
        # Double-checked locking
        if _async_client is not None and not _async_client.is_closed:
            return _async_client
        logger.info(
            "http_pool: initialising pooled AsyncClient "
            "(max_connections=50, max_keepalive_connections=20)"
        )
        _async_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
        return _async_client


async def close_async_client() -> None:
    """Close the shared async HTTP client. Call on application shutdown."""
    global _async_client
    if _async_client is not None and not _async_client.is_closed:
        logger.info("http_pool: closing pooled AsyncClient")
        await _async_client.aclose()
    _async_client = None


async def _post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: dict,
    headers: dict,
) -> httpx.Response:
    """POST with exponential back-off for transient HTTP errors (429, 503).

    Raises the last exception if all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = await client.post(url, json=json, headers=headers)
            if response.status_code not in _RETRYABLE_STATUS_CODES:
                response.raise_for_status()
                return response
            # Transient error — back off and retry
            delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "http_pool: received %s (attempt %d/%d), retrying in %.1fs",
                response.status_code,
                attempt,
                _MAX_RETRIES,
                delay,
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(delay)
            last_exc = httpx.HTTPStatusError(
                f"HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as exc:
            delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "http_pool: network error on attempt %d/%d (%s), retrying in %.1fs",
                attempt,
                _MAX_RETRIES,
                exc,
                delay,
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(delay)
            last_exc = exc
    raise last_exc  # type: ignore[misc]
