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
test_replay_evaluate_normative.py — Replay Evaluation Invariant Tests (ADR-008 Phase 5)

Regression tests to ensure all transitions out of PARKED state traverse
replay_evaluate() and that direct resolve() calls are blocked at the type boundary.

Test coverage:
  1. High-confidence external validation (>= 0.70) resolves tokens successfully
  2. Low-confidence external validation (< 0.70) fails closed and leaves tokens PARKED
  3. Static reflection confirms DeferQueue.resolve() is private (_resolve())
"""

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.defer_queue import (
    DEFER_CONFIDENCE_THRESHOLD,
    DeferQueue,
    DeferReason,
    DeferToken,
    ReplayResult,
    replay_evaluate,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# fakeredis fixture — async pipeline simulation
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis():
    """Minimal async Redis mock using an in-memory dict store."""
    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    # hset
    async def _hset(key: str, mapping: dict):
        store.setdefault(key, {}).update(mapping)

    # hget
    async def _hget(key: str, field: str):
        return store.get(key, {}).get(field)

    # expire (no-op in mock — TTL not enforced in unit tests)
    async def _expire(key: str, ttl: int):
        pass

    # zadd
    async def _zadd(zset_key: str, mapping: dict):
        zsets.setdefault(zset_key, {}).update(mapping)

    # zrangebyscore
    async def _zrangebyscore(zset_key: str, min_score, max_score, start=0, num=100):
        members = zsets.get(zset_key, {})
        result = []
        max_f = float("inf") if max_score == "+inf" else float(max_score)
        for member, score in sorted(members.items(), key=lambda x: x[1]):
            if score <= max_f:
                result.append(member)
        return result[start : start + num]

    # zrem
    async def _zrem(zset_key: str, member: str):
        zsets.get(zset_key, {}).pop(member, None)

    # Pipeline context manager
    class FakePipeline:
        def __init__(self):
            self._ops = []

        def hset(self, key, mapping):
            self._ops.append(("hset", key, mapping))
            return self

        def expire(self, key, ttl):
            self._ops.append(("expire", key, ttl))
            return self

        def zadd(self, zset_key, mapping):
            self._ops.append(("zadd", zset_key, mapping))
            return self

        def zrem(self, zset_key, member):
            self._ops.append(("zrem", zset_key, member))
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "hset":
                    await _hset(op[1], op[2])
                elif op[0] == "expire":
                    await _expire(op[1], op[2])
                elif op[0] == "zadd":
                    await _zadd(op[1], op[2])
                elif op[0] == "zrem":
                    await _zrem(op[1], op[2])
            return [None] * len(self._ops)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    def _pipeline(transaction=False):
        return FakePipeline()

    redis.hset = _hset
    redis.hget = _hget
    redis.expire = _expire
    redis.zadd = _zadd
    redis.zrangebyscore = _zrangebyscore
    redis.zrem = _zrem
    redis.pipeline = _pipeline

    # watch/unwatch for approval tests
    redis.watch = AsyncMock()
    redis.unwatch = AsyncMock()

    return redis


# ---------------------------------------------------------------------------
# Test 1: High-confidence replay succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_evaluate_high_confidence_admits_token(fake_redis):
    """Test that a deferred token with confidence >= 0.70 is resolved via replay_evaluate."""
    queue = DeferQueue(fake_redis)

    # Park a token with low initial confidence
    token = DeferToken(
        thread_id="thread-123",
        defer_reason=DeferReason.EXTERNAL_VALIDATION,
        confidence_score=0.65,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 50000},
    )
    defer_id = await queue.park(token)

    # Verify token is parked
    parked = await queue.get(defer_id)
    assert parked is not None
    assert parked.resolution is None

    # Replay with enriched context (confidence raised to 0.75 >= 0.70)
    enriched_context = {
        "confidence_score": 0.75,
        "external_validation": "ADMITTED",
        "provider_findings": [],
    }
    result = await replay_evaluate(queue, defer_id, enriched_context)

    # Assert: Token is admitted and resolved
    assert result == ReplayResult.ADMITTED

    # Verify token is resolved in Redis
    resolved = await queue.get(defer_id)
    assert resolved is not None
    assert resolved.resolution == "INJECTED"
    assert resolved.resolved_at_utc is not None


# ---------------------------------------------------------------------------
# Test 2: Low-confidence replay fails closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_evaluate_low_confidence_remains_parked(fake_redis):
    """Test that an admitted action with confidence < 0.70 fails closed and remains PARKED."""
    queue = DeferQueue(fake_redis)

    # Park a token with low initial confidence
    token = DeferToken(
        thread_id="thread-456",
        defer_reason=DeferReason.EXTERNAL_VALIDATION,
        confidence_score=0.55,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 75000},
    )
    defer_id = await queue.park(token)

    # Replay with enriched context (confidence raised to 0.65, still < 0.70)
    enriched_context = {
        "confidence_score": 0.65,
        "external_validation": "ADMITTED",
        "provider_findings": [],
    }
    result = await replay_evaluate(queue, defer_id, enriched_context)

    # Assert: Token remains PARKED
    assert result == ReplayResult.PARKED

    # Verify token is NOT resolved in Redis
    parked = await queue.get(defer_id)
    assert parked is not None
    assert parked.resolution is None
    assert parked.resolved_at_utc is None


# ---------------------------------------------------------------------------
# Test 3: Static reflection confirms resolve() is private
# ---------------------------------------------------------------------------


def test_defer_queue_resolve_is_private():
    """Assert via static reflection that DeferQueue does not expose a public resolve() method."""
    # Get all public methods of DeferQueue
    public_methods = [
        name
        for name, method in inspect.getmembers(DeferQueue, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]

    # Assert: resolve() is NOT in the public API
    assert "resolve" not in public_methods, (
        "DeferQueue.resolve() must be private (_resolve()) to enforce "
        "replay_evaluate() invariant (ADR-008 Phase 5)"
    )

    # Assert: _resolve() exists as a private method
    private_methods = [
        name
        for name, method in inspect.getmembers(DeferQueue, predicate=inspect.isfunction)
        if name.startswith("_") and not name.startswith("__")
    ]
    assert "_resolve" in private_methods, (
        "DeferQueue._resolve() must exist as the private resolution method"
    )


# ---------------------------------------------------------------------------
# Test 4: Boundary condition at exactly DEFER_CONFIDENCE_THRESHOLD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_evaluate_at_exact_threshold(fake_redis):
    """Test that confidence exactly at DEFER_CONFIDENCE_THRESHOLD (0.70) is admitted."""
    queue = DeferQueue(fake_redis)

    # Park a token with low initial confidence
    token = DeferToken(
        thread_id="thread-789",
        defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        confidence_score=0.60,
        opa_input_snapshot={"action": "approve_loan", "amount_usd": 100000},
    )
    defer_id = await queue.park(token)

    # Replay with enriched context (confidence raised to exactly 0.70)
    enriched_context = {
        "confidence_score": DEFER_CONFIDENCE_THRESHOLD,
        "external_validation": "ADMITTED",
        "provider_findings": [],
    }
    result = await replay_evaluate(queue, defer_id, enriched_context)

    # Assert: Token is admitted at the exact threshold
    assert result == ReplayResult.ADMITTED

    # Verify token is resolved
    resolved = await queue.get(defer_id)
    assert resolved is not None
    assert resolved.resolution == "INJECTED"


# ---------------------------------------------------------------------------
# Test 5: NOT_FOUND result for non-existent token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_evaluate_not_found(fake_redis):
    """Test that replay_evaluate returns NOT_FOUND for non-existent token."""
    queue = DeferQueue(fake_redis)

    # Attempt to replay a non-existent defer_id
    enriched_context = {
        "confidence_score": 0.85,
        "external_validation": "ADMITTED",
    }
    result = await replay_evaluate(queue, "nonexistent-defer-id", enriched_context)

    # Assert: NOT_FOUND result
    assert result == ReplayResult.NOT_FOUND
