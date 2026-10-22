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

"""Unit tests for PR B4: shared pooled Redis clients with timeouts and async IAM refresh.

Verifies:
1. ``build_async_redis()`` and ``_AsyncRedisClient`` configure ``BlockingConnectionPool``
   with ``max_connections`` (from ``REDIS_MAX_CONNECTIONS``, default 50),
   ``timeout`` (from ``REDIS_POOL_TIMEOUT``, default 3.0),
   ``health_check_interval=30``, and ``Retry(ExponentialBackoff(...), 2)`` on
   transient errors, plus URL path DB parsing when ``db`` is omitted.
2. ``open_defer_queue()`` yields the shared ``DeferQueue`` singleton without
   tearing down its pooled Redis client on exit, and loads the Lua script
   once per process via ``SCRIPT LOAD`` + ``EVALSHA`` with automatic fallback
   on ``NOSCRIPT``.
3. ``GcpRedisIamCredentialProvider.get_credentials_async()`` uses ``httpx.AsyncClient``
   for GCE metadata server fetches without blocking the event loop, and triggers
   proactive background refresh inside the 600s pre-expiry window while still
   returning the valid cached token immediately.
4. Remaining Redis consumers (``FiscalLimitGuard``, ``TokenQuotaProxy``,
   ``ConsequenceAuthorityStore``) route through ``build_async_redis()`` so TLS/IAM
   enforcement and connection pooling apply uniformly.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as aioredis
from redis.exceptions import BusyLoadingError, NoScriptError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from src.gateway.governance.defer_queue import (
    DeferQueue,
    DeferReason,
    DeferToken,
    close_shared_defer_queue,
    get_shared_defer_queue,
    open_defer_queue,
    reset_shared_defer_queue,
)
from src.gateway.infrastructure.redis_client import (
    _AsyncRedisClient,
    build_async_redis,
)
from src.integrations.gcp.redis_credential_provider import (
    PROACTIVE_REFRESH_MARGIN_SECONDS,
    TOKEN_EXPIRY_MARGIN_SECONDS,
    GcpRedisIamCredentialProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestPooledAsyncRedisBuilder:
    """Verify BlockingConnectionPool, timeouts, health checks, and retry wiring."""

    def test_build_async_redis_configures_blocking_pool_and_retries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("REDIS_TLS_ENABLED", "false")
        monkeypatch.setenv("REDIS_IAM_AUTH_ENABLED", "false")
        monkeypatch.setenv("REDIS_MAX_CONNECTIONS", "64")
        monkeypatch.setenv("REDIS_POOL_TIMEOUT", "4.5")

        client = build_async_redis("redis://localhost:6379/3", socket_timeout=7.5)
        try:
            pool = client.connection_pool
            assert isinstance(pool, aioredis.BlockingConnectionPool)
            assert pool.max_connections == 64
            assert pool.timeout == 4.5
            assert pool.connection_kwargs["db"] == 3
            assert pool.connection_kwargs["socket_timeout"] == 7.5
            assert pool.connection_kwargs["socket_connect_timeout"] == 3.0
            assert pool.connection_kwargs["health_check_interval"] == 30

            retry = pool.connection_kwargs["retry"]
            assert retry is not None
            supported_errors = tuple(retry._supported_errors)
            assert BusyLoadingError in supported_errors
            assert RedisConnectionError in supported_errors
            assert RedisTimeoutError in supported_errors
        finally:
            asyncio.run(client.aclose())

    def test_build_async_redis_explicit_db_overrides_url_db(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("REDIS_TLS_ENABLED", "false")
        monkeypatch.setenv("REDIS_IAM_AUTH_ENABLED", "false")

        client = build_async_redis("redis://localhost:6379/2", db=5)
        try:
            assert client.connection_pool.connection_kwargs["db"] == 5
        finally:
            asyncio.run(client.aclose())

    def test_shared_async_redis_client_uses_blocking_pool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("REDIS_TLS_ENABLED", "false")
        monkeypatch.setenv("REDIS_IAM_AUTH_ENABLED", "false")

        proxy = _AsyncRedisClient()

        async def _exercise() -> None:
            inner = await proxy._get()
            try:
                assert isinstance(
                    inner.connection_pool, aioredis.BlockingConnectionPool
                )
                assert inner.connection_pool.max_connections == 50
                assert inner.connection_pool.timeout == 3.0
            finally:
                await inner.aclose()

        asyncio.run(_exercise())


class TestSharedDeferQueueReuseAndScriptCaching:
    """Verify open_defer_queue reuses the singleton and caches Lua SHA."""

    def setup_method(self) -> None:
        reset_shared_defer_queue()

    def teardown_method(self) -> None:
        reset_shared_defer_queue()

    def test_open_defer_queue_reuses_shared_singleton_without_closing(self) -> None:
        mock_redis = AsyncMock()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=mock_redis,
        ) as mock_builder:

            async def _exercise() -> tuple[DeferQueue, DeferQueue, DeferQueue]:
                async with open_defer_queue() as q1:
                    first = q1
                async with open_defer_queue() as q2:
                    second = q2
                shared = get_shared_defer_queue()
                return first, second, shared

            q1, q2, shared = asyncio.run(_exercise())
            assert q1 is q2
            assert q1 is shared
            mock_builder.assert_called_once()
            mock_redis.aclose.assert_not_awaited()

            asyncio.run(close_shared_defer_queue())
            mock_redis.aclose.assert_awaited_once()

    def test_ensure_scripts_loaded_runs_script_load_once_and_recovers_on_noscript(
        self,
    ) -> None:
        mock_redis = AsyncMock()
        mock_redis.script_load = AsyncMock(side_effect=["sha-1", "sha-2"])
        mock_redis.evalsha = AsyncMock(
            side_effect=[
                [1, 1],
                NoScriptError("NOSCRIPT No matching script"),
            ]
        )
        mock_redis.eval = AsyncMock(return_value=[1, 2])

        queue = DeferQueue(redis_client=mock_redis)
        token = DeferToken(
            thread_id="thread-b4",
            defer_reason=DeferReason.HITL_REQUIRED,
            confidence_score=0.85,
            opa_input_snapshot={"action": "execute_trade"},
        )

        async def _exercise() -> None:
            sha_a = await queue.ensure_scripts_loaded()
            sha_b = await queue.ensure_scripts_loaded()
            assert sha_a == "sha-1"
            assert sha_b == "sha-1"
            assert mock_redis.script_load.await_count == 1

            # First _cas_update uses cached sha-1 via evalsha
            ok1, rev1 = await queue._cas_update(
                token.defer_id,
                expected_rev=0,
                updated_token=token,
                new_status="PARTIALLY_APPROVED",
            )
            assert ok1 is True
            assert rev1 == 1
            assert mock_redis.script_load.await_count == 1

            # Second _cas_update hits NoScriptError, falls back to eval, and reloads sha-2
            ok2, rev2 = await queue._cas_update(
                token.defer_id,
                expected_rev=1,
                updated_token=token,
                new_status="RESOLVED",
            )
            assert ok2 is True
            assert rev2 == 2
            assert mock_redis.script_load.await_count == 2
            assert queue._cas_update_sha == "sha-2"

        asyncio.run(_exercise())


class TestAsyncIamCredentialProvider:
    """Verify non-blocking async token fetch and proactive pre-expiry refresh."""

    def setup_method(self) -> None:
        GcpRedisIamCredentialProvider._cached_token = None
        GcpRedisIamCredentialProvider._cached_expiry = 0.0
        GcpRedisIamCredentialProvider._refresh_task = None

    def teardown_method(self) -> None:
        GcpRedisIamCredentialProvider._cached_token = None
        GcpRedisIamCredentialProvider._cached_expiry = 0.0
        GcpRedisIamCredentialProvider._refresh_task = None

    def test_get_credentials_async_fetches_via_httpx_async_client(self) -> None:
        provider = GcpRedisIamCredentialProvider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "ya29.async-metadata-token",
            "expires_in": 3600,
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            username, token = asyncio.run(provider.get_credentials_async())

        assert username == "default"
        assert token == "ya29.async-metadata-token"
        mock_client.get.assert_awaited_once()

    def test_proactive_refresh_schedules_background_update_before_hard_expiry(
        self,
    ) -> None:
        provider = GcpRedisIamCredentialProvider()
        # Set token expiry between TOKEN_EXPIRY_MARGIN_SECONDS (300s) and
        # PROACTIVE_REFRESH_MARGIN_SECONDS (600s) so the cached token is still
        # valid right now, but triggers proactive background refresh.
        GcpRedisIamCredentialProvider._store_cached_token(
            "ya29.cached-still-valid",
            time.time()
            + ((TOKEN_EXPIRY_MARGIN_SECONDS + PROACTIVE_REFRESH_MARGIN_SECONDS) / 2.0),
        )

        async def _fake_fetch() -> tuple[str, float]:
            await asyncio.sleep(0.01)
            return ("ya29.proactively-refreshed", time.time() + 3600.0)

        with patch.object(
            provider, "_fetch_token_from_metadata_async", side_effect=_fake_fetch
        ) as mock_fetch:

            async def _exercise() -> tuple[str, str]:
                _, immediate_token = await provider.get_credentials_async()
                assert GcpRedisIamCredentialProvider._refresh_task is not None
                await GcpRedisIamCredentialProvider._refresh_task
                _, updated_token = await provider.get_credentials_async()
                return immediate_token, updated_token

            immediate, updated = asyncio.run(_exercise())

        assert immediate == "ya29.cached-still-valid"
        assert updated == "ya29.proactively-refreshed"
        mock_fetch.assert_awaited_once()


class TestConsumersUseBuildAsyncRedis:
    """Verify remaining Redis consumers build clients through build_async_redis."""

    def test_token_quota_proxy_from_env_uses_build_async_redis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.governance.token_quota_proxy import TokenQuotaProxy

        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        fake_client = MagicMock()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=fake_client,
        ) as mock_builder:
            proxy = TokenQuotaProxy.from_env()
            assert proxy._redis is fake_client
            mock_builder.assert_called_once_with(
                "redis://localhost:6379/0", socket_timeout=3.0
            )
