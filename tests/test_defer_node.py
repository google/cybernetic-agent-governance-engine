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
tests/test_defer_node.py — Unit tests for the DeferNode LangGraph integration.

Verifies that defer_node correctly constructs DeferToken with the right field
names and calls DeferQueue.park(), using a fakeredis-backed queue (hermetic,
no live Redis required).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.defer_queue import DeferQueue, DeferToken


# ---------------------------------------------------------------------------
# fakeredis fixture — reused from test_defer_queue.py pattern
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis():
    """Minimal async Redis mock using an in-memory dict/zset store."""
    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    async def _hget(key: str, field: str):
        return store.get(key, {}).get(field)

    async def _zadd(zset_key: str, mapping: dict):
        zsets.setdefault(zset_key, {}).update(mapping)

    async def _zrangebyscore(zset_key: str, min_score, max_score, start=0, num=100):
        members = zsets.get(zset_key, {})
        result = []
        max_f = float("inf") if max_score == "+inf" else float(max_score)
        for member, score in sorted(members.items(), key=lambda x: x[1]):
            if score <= max_f:
                result.append(member)
        return result[start : start + num]

    async def _zrem(zset_key: str, member: str):
        zsets.get(zset_key, {}).pop(member, None)

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
                    store.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zadd":
                    zsets.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zrem":
                    zsets.get(op[1], {}).pop(op[2], None)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    redis.hget = _hget
    redis.zadd = _zadd
    redis.zrangebyscore = _zrangebyscore
    redis.zrem = _zrem
    redis.pipeline = lambda transaction=True: FakePipeline()

    return redis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(confidence: float = 0.82, thread_id: str = "thread-defer-test") -> dict:
    """Build a minimal AgentState dict for defer_node."""
    return {
        "thread_id": thread_id,
        "execution_plan_output": {
            "action": "execute_trade",
            "symbol": "TSLA",
            "confidence": confidence,
            "amount_usd": 15000,
        },
    }


# ---------------------------------------------------------------------------
# Test 1: defer_node parks token to Redis via DeferQueue.park()
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_defer_node_parks_token_to_redis(fake_redis):
    """When confidence is in [0.70, 0.95), defer_node parks a DeferToken in DeferQueue.

    Verifies:
    - DeferToken is constructed with correct field names (defer_reason, opa_input_snapshot)
    - DeferQueue.park() is called (token is retrievable via queue.get())
    - Returned state contains defer_id, defer_token dict, and safety_status="DEFERRED"
    """
    queue = DeferQueue(fake_redis)
    state = _make_state(confidence=0.82)

    # Patch the redis_client import inside defer_node and inject our fake queue
    with patch(
        "src.governed_financial_advisor.graph.nodes.defer_node.DeferQueue"
    ) as MockDeferQueue:
        mock_queue_instance = MagicMock()
        # Capture the token passed to park() so we can assert on it
        parked_tokens: list[DeferToken] = []

        async def _capture_park(token: DeferToken) -> str:
            parked_tokens.append(token)
            # Also park in the real fakeredis-backed queue for retrieval assertions
            return await queue.park(token)

        mock_queue_instance.park = _capture_park
        MockDeferQueue.return_value = mock_queue_instance

        # Also patch the redis_client import so the module-level import doesn't fail
        with patch(
            "src.governed_financial_advisor.graph.nodes.defer_node.redis_client",
            new=fake_redis,
            create=True,
        ):
            from src.governed_financial_advisor.graph.nodes.defer_node import defer_node

            result = await defer_node(state)

    # --- Assertions on the returned state ---
    assert result["safety_status"] == "DEFERRED"
    assert "defer_id" in result
    assert "defer_token" in result

    # --- Assertions on what was parked ---
    assert len(parked_tokens) == 1
    token = parked_tokens[0]

    # Field name correctness: must use defer_reason (not reason)
    assert hasattr(token, "defer_reason")
    assert token.defer_reason is not None

    # Field name correctness: must use opa_input_snapshot (not opa_input)
    assert hasattr(token, "opa_input_snapshot")
    assert isinstance(token.opa_input_snapshot, dict)

    # Token is persisted in Redis (retrievable via the real fakeredis-backed queue)
    retrieved = await queue.get(token.defer_id)
    assert retrieved is not None
    assert retrieved.thread_id == "thread-defer-test"
    assert retrieved.confidence_score == pytest.approx(0.82)


# ---------------------------------------------------------------------------
# Test 2: defer_node re-raises when DeferQueue.park() raises
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_defer_node_raises_on_queue_failure():
    """If DeferQueue.park() raises, defer_node must propagate the exception.

    Verifies the broad except-and-re-raise semantics introduced by the glue-layer
    fix — the exception must NOT be silently swallowed, ensuring the caller graph
    can detect and handle durable-queue failures.
    """
    state = _make_state(confidence=0.75)

    boom = RuntimeError("Redis connection refused")

    with patch(
        "src.governed_financial_advisor.graph.nodes.defer_node.DeferQueue"
    ) as MockDeferQueue:
        mock_queue_instance = MagicMock()
        mock_queue_instance.park = AsyncMock(side_effect=boom)
        MockDeferQueue.return_value = mock_queue_instance

        with patch(
            "src.governed_financial_advisor.graph.nodes.defer_node.redis_client",
            new=MagicMock(),
            create=True,
        ):
            from src.governed_financial_advisor.graph.nodes.defer_node import defer_node

            with pytest.raises(RuntimeError, match="Redis connection refused"):
                await defer_node(state)
