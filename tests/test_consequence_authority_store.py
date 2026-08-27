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
Unit tests for ConsequenceAuthorityStore — FlowSignal single-use consumption primitive.

Tests run against fakeredis (no live Redis required) and exercise:
  1. Happy path: first consume_once() → True
  2. Replay: second consume_once() with same binding → False
  3. Substitution: second consume_once() with different binding → False; get_binding() shows original
  4. TTL expiry: after ttl_seconds, key gone and consumption succeeds again
  5. Concurrency: asyncio.gather() of N concurrent consume_once() — exactly one succeeds
  6. Redis connection error → exception propagates (fail-closed, no silent success)
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for consequence_authority_store tests"
)

import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def redis_client() -> fakeredis.aioredis.FakeRedis:
    """A fresh in-memory async fakeredis instance per test."""
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def store(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> ConsequenceAuthorityStore:
    """ConsequenceAuthorityStore with default 90s TTL."""
    return ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)


# ---------------------------------------------------------------------------
# Test 1: Happy path — first consumption succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_consumption_succeeds(store: ConsequenceAuthorityStore) -> None:
    """First consume_once() call returns True (wins the race)."""
    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    result = await store.consume_once(
        authority_record_id="fs-token-001",
        binding=binding,
    )

    assert result is True, "First consumption should succeed"


# ---------------------------------------------------------------------------
# Test 2: Replay — second consumption with same binding fails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_same_binding_rejected(store: ConsequenceAuthorityStore) -> None:
    """Second consume_once() with same binding returns False (replay detected)."""
    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # First consumption
    result1 = await store.consume_once(
        authority_record_id="fs-token-002",
        binding=binding,
    )
    assert result1 is True

    # Replay attempt
    result2 = await store.consume_once(
        authority_record_id="fs-token-002",
        binding=binding,
    )
    assert result2 is False, "Replay with same binding should be rejected"


# ---------------------------------------------------------------------------
# Test 3: Substitution — second consumption with different binding fails,
#         get_binding() shows original value
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_substitution_different_binding_rejected(
    store: ConsequenceAuthorityStore,
) -> None:
    """Second consume_once() with different binding returns False (substitution attack).

    get_binding() returns the original binding value, enabling audit logs to
    distinguish SUBSTITUTION vs REPLAY.
    """
    binding1 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )
    binding2 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-beta",  # Different actor — substitution
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # First consumption with binding1
    result1 = await store.consume_once(
        authority_record_id="fs-token-003",
        binding=binding1,
    )
    assert result1 is True

    # Substitution attempt with binding2
    result2 = await store.consume_once(
        authority_record_id="fs-token-003",
        binding=binding2,
    )
    assert result2 is False, "Substitution with different binding should be rejected"

    # Verify stored binding is the original (binding1)
    stored = await store.get_binding("fs-token-003")
    assert stored == binding1, (
        "Stored binding should be original, not substituted value"
    )
    assert stored != binding2


# ---------------------------------------------------------------------------
# Test 4: TTL expiry — key expires, consumption succeeds again
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_expiry_allows_re_consumption(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """After TTL expiry, the key is gone and consumption succeeds again."""
    # Use a very short TTL for test speed
    store = ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=1)

    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # First consumption
    result1 = await store.consume_once(
        authority_record_id="fs-token-004",
        binding=binding,
    )
    assert result1 is True

    # Wait for TTL to expire (1s + margin)
    await asyncio.sleep(1.2)

    # Key should be gone
    key = "flowsignal:token:fs-token-004"
    exists = await redis_client.exists(key)
    assert exists == 0, "Key should be expired"

    # Consumption should succeed again
    result2 = await store.consume_once(
        authority_record_id="fs-token-004",
        binding=binding,
    )
    assert result2 is True, "Consumption should succeed after TTL expiry"


# ---------------------------------------------------------------------------
# Test 5: Concurrency — exactly one of N concurrent consume_once() succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_consumption_exactly_one_wins(
    store: ConsequenceAuthorityStore,
) -> None:
    """N concurrent consume_once() calls with same authority_record_id — exactly one returns True."""
    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # Launch 10 concurrent consumption attempts
    N = 10
    tasks = [
        store.consume_once(
            authority_record_id="fs-token-005",
            binding=binding,
        )
        for _ in range(N)
    ]

    results = await asyncio.gather(*tasks)

    # Exactly one should succeed
    success_count = sum(1 for r in results if r is True)
    failure_count = sum(1 for r in results if r is False)

    assert success_count == 1, (
        f"Exactly one consumption should succeed, got {success_count}"
    )
    assert failure_count == N - 1, f"Exactly {N - 1} should fail, got {failure_count}"


# ---------------------------------------------------------------------------
# Test 6: Redis connection error → exception propagates (fail-closed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_error_propagates_fail_closed(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Redis connection/timeout error propagates as exception (no silent success)."""
    store = ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)

    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # Simulate Redis connection error
    with patch.object(
        redis_client,
        "set",
        side_effect=ConnectionError("Redis connection refused"),
    ):
        with pytest.raises(ConnectionError, match="Redis connection refused"):
            await store.consume_once(
                authority_record_id="fs-token-006",
                binding=binding,
            )


@pytest.mark.asyncio
async def test_redis_timeout_propagates_fail_closed(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Redis timeout error propagates as exception."""
    store = ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)

    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # Simulate Redis timeout
    with patch.object(
        redis_client,
        "set",
        side_effect=TimeoutError("Redis operation timed out"),
    ):
        with pytest.raises(TimeoutError, match="Redis operation timed out"):
            await store.consume_once(
                authority_record_id="fs-token-007",
                binding=binding,
            )


# ---------------------------------------------------------------------------
# Test 7: binding_hash() produces consistent SHA-256 hashes
# ---------------------------------------------------------------------------


def test_binding_hash_consistent() -> None:
    """binding_hash() produces consistent SHA-256 hex digests."""
    binding1 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )
    binding2 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # Same inputs → same hash
    assert binding1 == binding2

    # Hash is 64 hex chars (SHA-256)
    assert len(binding1) == 64
    assert all(c in "0123456789abcdef" for c in binding1)


def test_binding_hash_different_inputs_different_hashes() -> None:
    """Different inputs produce different hashes."""
    binding1 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )
    binding2 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-2",  # Different thread
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    assert binding1 != binding2


def test_binding_hash_none_state_version_normalized() -> None:
    """state_version=None is normalized to empty string for consistent hashing."""
    binding1 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version=None,
    )
    binding2 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="",
    )

    # None and "" should produce the same hash
    assert binding1 == binding2


# ---------------------------------------------------------------------------
# Test 8: get_binding() returns None when key doesn't exist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_binding_nonexistent_key_returns_none(
    store: ConsequenceAuthorityStore,
) -> None:
    """get_binding() returns None when the key doesn't exist."""
    result = await store.get_binding("nonexistent-token-id")
    assert result is None


@pytest.mark.asyncio
async def test_get_binding_returns_stored_value(
    store: ConsequenceAuthorityStore,
) -> None:
    """get_binding() returns the stored binding value."""
    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    # Consume once
    await store.consume_once(
        authority_record_id="fs-token-008",
        binding=binding,
    )

    # get_binding should return the stored value
    stored = await store.get_binding("fs-token-008")
    assert stored == binding


@pytest.mark.asyncio
async def test_get_binding_redis_error_returns_none(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """get_binding() returns None on Redis error (diagnostic use, don't propagate)."""
    store = ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)

    # Simulate Redis error
    with patch.object(
        redis_client,
        "get",
        side_effect=ConnectionError("Redis down"),
    ):
        result = await store.get_binding("fs-token-009")
        assert result is None, "get_binding() should return None on Redis error"


# ---------------------------------------------------------------------------
# Test 9: from_env() factory method
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_from_env_uses_defaults() -> None:
    """from_env() uses default REDIS_URL and TTL when env vars not set."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client

            store = ConsequenceAuthorityStore.from_env()

            # Verify from_url was called with default redis://localhost:6379
            mock_from_url.assert_called_once_with(
                "redis://localhost:6379",
                decode_responses=True,
            )

            # Verify default TTL is 90s
            assert store._ttl_seconds == 90


@pytest.mark.local
def test_from_env_reads_custom_env_vars() -> None:
    """from_env() reads REDIS_URL and FLOWSIGNAL_CONSUMPTION_TTL_SECONDS env vars."""
    with patch.dict(
        os.environ,
        {
            "REDIS_URL": "redis://custom-host:6380/1",
            "FLOWSIGNAL_CONSUMPTION_TTL_SECONDS": "120",
        },
    ):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client

            store = ConsequenceAuthorityStore.from_env()

            # Verify from_url was called with custom URL
            mock_from_url.assert_called_once_with(
                "redis://custom-host:6380/1",
                decode_responses=True,
            )

            # Verify custom TTL
            assert store._ttl_seconds == 120


# ---------------------------------------------------------------------------
# Test 10: Key schema format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_schema_format(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Verify the Redis key schema is flowsignal:token:<authority_record_id>."""
    store = ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)

    binding = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread-1",
        actor_id="agent-alpha",
        action_digest="action-hash-xyz",
        state_version="v1",
    )

    authority_record_id = "test-record-uuid-123"
    await store.consume_once(
        authority_record_id=authority_record_id,
        binding=binding,
    )

    # Verify the key exists with the expected schema
    key = f"flowsignal:token:{authority_record_id}"
    exists = await redis_client.exists(key)
    assert exists == 1, f"Key {key} should exist in Redis"

    # Verify the stored value is the binding hash
    stored_value = await redis_client.get(key)
    assert stored_value == binding
