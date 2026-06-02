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
Shared Redis client for the gateway package.

This is the canonical Redis client for all gateway-internal modules
(safety.py, symbolic_governor, etc.).  It wraps redis.asyncio to provide
convenience helpers used by ControlBarrierFunction.

Environment variables:
    REDIS_HOST  — default "localhost"
    REDIS_PORT  — default 6379
    REDIS_DB    — default 0
    REDIS_PASSWORD — optional
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("Gateway.Infrastructure.Redis")

try:
    import redis.asyncio as aioredis
    from urllib.parse import urlparse as _urlparse

    _REDIS_URL = os.environ.get("REDIS_URL", "")
    _REDIS_DB = int(os.environ.get("REDIS_DB", "0"))
    _REDIS_PASSWORD: Optional[str] = os.environ.get("REDIS_PASSWORD") or None

    # Parse defaults from REDIS_URL if present, then allow REDIS_HOST/REDIS_PORT overrides
    if _REDIS_URL:
        _parsed_url = _urlparse(_REDIS_URL)
        _url_host: str = _parsed_url.hostname or "localhost"
        _url_port: int = _parsed_url.port or 6379
    else:
        _url_host = "localhost"
        _url_port = 6379

    _REDIS_HOST = os.environ.get("REDIS_HOST", _url_host)
    _raw_port = os.environ.get("REDIS_PORT", "")
    if _raw_port:
        try:
            _REDIS_PORT = int(_raw_port)
        except ValueError:
            _REDIS_PORT = _url_port
    else:
        _REDIS_PORT = _url_port

    class _AsyncRedisClient:
        """Thin async Redis wrapper matching the interface expected by safety.py."""

        def __init__(self):
            self._client: Optional[aioredis.Redis] = None

        def _get(self) -> aioredis.Redis:
            if self._client is None:
                self._client = aioredis.Redis(
                    host=_REDIS_HOST,
                    port=_REDIS_PORT,
                    db=_REDIS_DB,
                    password=_REDIS_PASSWORD,
                    decode_responses=True,
                    socket_connect_timeout=3.0,
                    socket_timeout=3.0,
                )
            return self._client

        async def get(self, key: str) -> Optional[str]:
            return await self._get().get(key)

        async def set(self, key: str, value: str) -> None:
            await self._get().set(key, value)

        async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
            """Set *key* to *value* with an expiry of *ttl_seconds* seconds."""
            await self._get().setex(key, ttl_seconds, value)

        async def get_float(self, key: str, default: float = 0.0) -> float:
            raw = await self.get(key)
            if raw is None:
                return default
            try:
                return float(raw)
            except (ValueError, TypeError):
                return default

        def pipeline(self):
            """Return a raw redis.asyncio pipeline for WATCH/MULTI/EXEC."""
            return self._get().pipeline()

        def watch(self, *keys: str):
            """Return a pipeline in WATCH mode for optimistic locking."""
            return self._get().pipeline()

        async def close(self) -> None:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    redis_client = _AsyncRedisClient()
    logger.info(
        "✅ Gateway Redis client initialised (%s:%s db=%s)", _REDIS_HOST, _REDIS_PORT, _REDIS_DB
    )

except ImportError:
    logger.warning(
        "⚠️ redis.asyncio not installed — gateway Redis client unavailable. "
        "Install with: pip install redis[asyncio]"
    )
    redis_client = None  # type: ignore[assignment]
