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

# tests/test_token_quota_proxy.py
# Unit tests for TokenQuotaProxy Redis Lua circuit breaker.
# Marker: @pytest.mark.local — CI-gated, no external dependencies.
# Run: uv run pytest tests/test_token_quota_proxy.py -m local -v

from unittest.mock import AsyncMock

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required")
import fakeredis.aioredis

from src.gateway.governance.token_quota_proxy import (
    QuotaExceededError,
    TokenQuotaProxy,
)


@pytest.fixture
async def redis_client():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def proxy(redis_client):
    return TokenQuotaProxy(
        redis_client=redis_client,
        step_quota_max=12,
        token_quota_max=100_000,
        session_ttl=3600,
    )


@pytest.mark.asyncio
@pytest.mark.local
async def test_step_limit_enforcement(proxy):
    """Steps 1-12 allowed; step 13 blocked with block_reason=step_count."""
    for i in range(12):
        result = await proxy.check_and_increment("agent-test", token_delta=100)
        assert result.allowed, f"Step {i + 1} should be allowed"
    result = await proxy.check_and_increment("agent-test", token_delta=100)
    assert not result.allowed
    assert result.block_reason == "step_count"
    assert result.step_count == 12


@pytest.mark.asyncio
@pytest.mark.local
async def test_token_limit_enforcement(proxy):
    """Single call with token_delta > quota_max is blocked."""
    result = await proxy.check_and_increment("agent-token", token_delta=100_001)
    assert not result.allowed
    assert result.block_reason == "token_count"


@pytest.mark.asyncio
@pytest.mark.local
async def test_rollback_decrements_counters(proxy):
    """rollback_step() decrements both step and token counters."""
    await proxy.check_and_increment("agent-rb", token_delta=500)
    await proxy.rollback_step("agent-rb", reserved_tokens=500)
    state = await proxy.get_session_state("agent-rb")
    assert state["steps"] == 0
    assert state["tokens"] == 0


@pytest.mark.asyncio
@pytest.mark.local
async def test_reconcile_adjusts_token_counter(proxy):
    """reconcile_actual_tokens() corrects over-allocation."""
    await proxy.check_and_increment("agent-rec", token_delta=1000)
    await proxy.reconcile_actual_tokens(
        "agent-rec", reserved_tokens=1000, actual_tokens_used=876
    )
    state = await proxy.get_session_state("agent-rec")
    assert state["tokens"] == 876


@pytest.mark.asyncio
@pytest.mark.local
async def test_fail_closed_redis_unavailable(redis_client):
    """Redis connection error raises QuotaExceededError (fail-CLOSED)."""
    proxy = TokenQuotaProxy(redis_client=redis_client, step_quota_max=12)
    proxy._redis.script_load = AsyncMock(
        side_effect=ConnectionError("Redis connection refused")
    )
    with pytest.raises(QuotaExceededError):
        await proxy.check_and_increment("agent-fail", token_delta=0)


@pytest.mark.asyncio
@pytest.mark.local
async def test_session_ttl_set(proxy, redis_client):
    """After check_and_increment, Redis keys have TTL set."""
    await proxy.check_and_increment("agent-ttl", token_delta=0)
    ttl = await redis_client.ttl("quota:session:agent-ttl:steps")
    assert 0 < ttl <= 3600


@pytest.mark.asyncio
@pytest.mark.local
async def test_reset_session_clears_keys(proxy):
    """reset_session() deletes all session keys."""
    await proxy.check_and_increment("agent-reset", token_delta=100)
    await proxy.reset_session("agent-reset")
    state = await proxy.get_session_state("agent-reset")
    assert state["steps"] == 0
    assert state["tokens"] == 0


@pytest.mark.asyncio
@pytest.mark.local
async def test_quota_check_result_fields(proxy):
    """QuotaCheckResult has all required fields populated."""
    result = await proxy.check_and_increment("agent-fields", token_delta=500)
    assert result.allowed is True
    assert result.agent_id == "agent-fields"
    assert result.step_count == 1
    assert result.accumulated_tokens == 500
    assert result.step_quota_max == 12
    assert result.token_quota_max == 100_000
    assert result.block_reason is None
    assert result.session_ttl == 3600
