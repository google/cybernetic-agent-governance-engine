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
Unit tests for src/gateway/governance/token_quota_proxy.py.

All tests are hermetic — no live Redis, no network.  An AsyncMock Redis
client is injected via the constructor.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.token_quota_proxy import (
    QuotaCheckResult,
    QuotaExceededError,
    TokenQuotaProxy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proxy(
    step_quota: int = 5,
    token_quota: int = 1000,
    session_ttl: int = 60,
) -> tuple[TokenQuotaProxy, AsyncMock]:
    """Return a proxy wired to an AsyncMock Redis client."""
    redis = AsyncMock()
    redis.script_load = AsyncMock(side_effect=["sha_check_xx", "sha_rollback_xx", "sha_reconcile_xx"])
    proxy = TokenQuotaProxy(
        redis_client=redis,
        step_quota_max=step_quota,
        token_quota_max=token_quota,
        session_ttl=session_ttl,
    )
    return proxy, redis


# ---------------------------------------------------------------------------
# 1. QuotaExceededError carries structured attributes
# ---------------------------------------------------------------------------

@pytest.mark.local
def test_quota_exceeded_error_attributes() -> None:
    """QuotaExceededError stores all fields and produces a readable message."""
    err = QuotaExceededError(
        agent_id="agent-42",
        reason="step_count",
        current_value=13,
        quota_max=12,
        session_key="quota:session:agent-42:steps",
    )
    assert err.agent_id == "agent-42"
    assert err.reason == "step_count"
    assert err.current_value == 13
    assert err.quota_max == 12
    assert "agent-42" in str(err)
    assert "step_count" in str(err)


# ---------------------------------------------------------------------------
# 2. _session_key builds the correct namespaced key
# ---------------------------------------------------------------------------

@pytest.mark.local
def test_session_key_format() -> None:
    """_session_key returns quota:session:<agent_id>:<suffix>."""
    proxy, _ = _make_proxy()
    assert proxy._session_key("abc-123", "steps") == "quota:session:abc-123:steps"
    assert proxy._session_key("abc-123", "tokens") == "quota:session:abc-123:tokens"


# ---------------------------------------------------------------------------
# 3. check_and_increment returns ALLOWED result on success
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_check_and_increment_allowed() -> None:
    """check_and_increment returns QuotaCheckResult with allowed=True when within quota."""
    proxy, redis = _make_proxy(step_quota=10, token_quota=5000)
    # Lua returns: [allowed_flag, steps, tokens, reason]
    redis.evalsha = AsyncMock(return_value=["1", "3", "200", ""])

    result = await proxy.check_and_increment("agent-007", token_delta=200)

    assert isinstance(result, QuotaCheckResult)
    assert result.allowed is True
    assert result.step_count == 3
    assert result.accumulated_tokens == 200
    assert result.block_reason is None


# ---------------------------------------------------------------------------
# 4. check_and_increment raises QuotaExceededError when Lua returns blocked
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_check_and_increment_blocked_returns_not_allowed() -> None:
    """check_and_increment returns allowed=False when Lua signals step_count block."""
    proxy, redis = _make_proxy(step_quota=5)
    redis.evalsha = AsyncMock(return_value=["0", "5", "0", "step_count"])

    result = await proxy.check_and_increment("agent-block")

    assert result.allowed is False
    assert result.block_reason == "step_count"


# ---------------------------------------------------------------------------
# 5. check_and_increment fails CLOSED when Redis evalsha raises
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_check_and_increment_redis_error_raises_quota_exceeded() -> None:
    """Redis evalsha failure causes check_and_increment to raise QuotaExceededError (fail-closed)."""
    proxy, redis = _make_proxy()
    redis.evalsha = AsyncMock(side_effect=ConnectionError("Redis down"))

    with pytest.raises(QuotaExceededError) as exc_info:
        await proxy.check_and_increment("agent-fail")

    assert exc_info.value.reason == "redis_unavailable"
    assert "agent-fail" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6. rollback_step decrements counters via Lua script
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_rollback_step_calls_evalsha() -> None:
    """rollback_step calls evalsha with the rollback script SHA and correct keys."""
    proxy, redis = _make_proxy()
    # Scripts already loaded via a prior check_and_increment — simulate that
    proxy._sha_check = "sha_check_xx"
    proxy._sha_rollback = "sha_rollback_xx"
    proxy._sha_reconcile = "sha_reconcile_xx"
    redis.evalsha = AsyncMock(return_value=None)

    await proxy.rollback_step("agent-rollback", reserved_tokens=50)

    redis.evalsha.assert_awaited_once()
    call_args = redis.evalsha.call_args
    assert "sha_rollback_xx" in call_args.args or call_args.args[0] == "sha_rollback_xx"


# ---------------------------------------------------------------------------
# 7. get_session_state returns zero-filled dict on Redis mget error
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_get_session_state_redis_error_returns_fallback() -> None:
    """get_session_state returns a zero-filled dict with an 'error' key on Redis failure."""
    proxy, redis = _make_proxy(step_quota=12, token_quota=100_000)
    redis.mget = AsyncMock(side_effect=ConnectionError("Redis unavailable"))

    state = await proxy.get_session_state("agent-error")

    assert state["agent_id"] == "agent-error"
    assert state["steps"] == 0
    assert state["tokens"] == 0
    assert "error" in state
    assert state["step_quota_max"] == 12
    assert state["token_quota_max"] == 100_000
