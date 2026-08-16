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
tests/test_gateway_redis_client.py — Unit tests for Gateway Redis infrastructure client.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required")
import fakeredis.aioredis

from src.gateway.infrastructure.redis_client import (
    TransactionAbortedError,
    _AsyncRedisClient,
    _SyncRedisClient,
    get_redis_client,
)


@pytest.fixture
async def fake_async_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_async_redis_client_basic_ops(fake_async_redis):
    client_wrapper = _AsyncRedisClient()
    client_wrapper._client = fake_async_redis

    await client_wrapper.set("key1", "val1")
    assert await client_wrapper.get("key1") == "val1"

    await client_wrapper.setex("key2", 60, "123.45")
    val_f = await client_wrapper.get_float("key2")
    assert val_f == 123.45

    val_f_missing = await client_wrapper.get_float("nonexistent", default=9.9)
    assert val_f_missing == 9.9

    val_f_invalid = await client_wrapper.get_float("key1", default=5.5)
    assert val_f_invalid == 5.5

    assert client_wrapper.get_raw_client() is fake_async_redis
    assert client_wrapper.pipeline() is not None
    assert client_wrapper.watch("key1") is not None


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_async_redis_client_ping_ready(fake_async_redis):
    client_wrapper = _AsyncRedisClient()
    client_wrapper._client = fake_async_redis

    # Normal ping
    await client_wrapper.ping_ready()

    # Ping failure
    with patch.object(fake_async_redis, "ping", side_effect=RuntimeError("connection dropped")):
        with pytest.raises(RuntimeError):
            await client_wrapper.ping_ready()


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_async_redis_client_close(fake_async_redis):
    client_wrapper = _AsyncRedisClient()
    client_wrapper._client = fake_async_redis
    await client_wrapper.close()
    assert client_wrapper._client is None


@pytest.mark.local
@pytest.mark.unit
def test_sync_redis_client_ops():
    mock_sync_redis = MagicMock()
    mock_sync_redis.get.return_value = "sync_val"
    mock_sync_redis.ping.return_value = True

    client_wrapper = _SyncRedisClient()
    client_wrapper._client = mock_sync_redis

    assert client_wrapper.get("test_key") == "sync_val"
    client_wrapper.setex("test_key", 60, "test_val")
    mock_sync_redis.setex.assert_called_with("test_key", 60, "test_val")

    client_wrapper.ping_ready()

    client_wrapper.close()
    assert client_wrapper._client is None


@pytest.mark.local
@pytest.mark.unit
def test_get_redis_client_factory():
    client = get_redis_client()
    assert client is not None
