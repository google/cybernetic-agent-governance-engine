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
Unit tests for FiscalLimitGuard — multi-agent collision prevention.

Tests run against fakeredis (no live Redis required) and exercise:
  1. Single-agent happy-path reservation and confirmation
  2. Multi-agent race condition — second agent correctly rejected
  3. Release path (Saga rollback) — capacity restored atomically
  4. Unsettled reservation TTL — reclaimed after expiry, never a confirmed spend
  5. Redis failure — fail-closed behaviour
  6. Exactly-once settlement (double release / confirm / release-after-confirm)
  7. remaining_usd / current_spend_usd reporting
"""

from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for fiscal_limit_guard tests"
)

import fakeredis.aioredis  # type: ignore[import]

from src.cage_finance.safety.fiscal_limit_guard import (
    PENDING_KEY,
    RECLAIMED_KEY,
    FiscalLimitGuard,
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
async def guard(redis_client: fakeredis.aioredis.FakeRedis) -> FiscalLimitGuard:
    """FiscalLimitGuard with a $500k daily cap."""
    return FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
        window_seconds=86_400,
    )


# ---------------------------------------------------------------------------
# Test 1: Single-agent happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_agent_reservation_accepted(guard: FiscalLimitGuard) -> None:
    token = await guard.reserve(agent_id="trading-agent", amount_usd=100_000.0)
    assert not token.rejected
    assert token.amount_usd == 100_000.0
    assert token.running_total_usd == 100_000.0
    assert token.reservation_id


@pytest.mark.asyncio
async def test_confirm_is_idempotent(guard: FiscalLimitGuard) -> None:
    """confirm() should not raise and not change the spend total."""
    token = await guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    before = await guard.current_spend_usd()
    await guard.confirm(token)
    await guard.confirm(token)
    assert await guard.current_spend_usd() == before


@pytest.mark.asyncio
async def test_current_spend_and_remaining(guard: FiscalLimitGuard) -> None:
    await guard.reserve(agent_id="trading-agent", amount_usd=200_000.0)
    assert await guard.current_spend_usd() == pytest.approx(200_000.0, abs=0.01)
    assert await guard.remaining_usd() == pytest.approx(300_000.0, abs=0.01)


# ---------------------------------------------------------------------------
# Test 2: Multi-agent race condition — the core correctness test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_second_agent_rejected_when_limit_exceeded(
    guard: FiscalLimitGuard,
) -> None:
    """
    Simulates two agents simultaneously targeting $300k each against a $500k cap.
    The first must succeed; the second must be atomically rejected.
    """
    token_a = await guard.reserve(agent_id="trading-agent", amount_usd=300_000.0)
    token_b = await guard.reserve(agent_id="hedging-agent", amount_usd=300_000.0)

    assert not token_a.rejected, "Agent A should be accepted"
    assert token_b.rejected, "Agent B should be rejected — would exceed $500k cap"
    # Spend total should reflect only Agent A's reservation
    assert await guard.current_spend_usd() == pytest.approx(300_000.0, abs=0.01)


@pytest.mark.asyncio
async def test_three_agents_sequential_within_cap(guard: FiscalLimitGuard) -> None:
    """Three agents each reserving $150k should all pass against a $500k cap."""
    tokens = [
        await guard.reserve(agent_id=f"agent-{i}", amount_usd=150_000.0)
        for i in range(3)
    ]
    assert all(not t.rejected for t in tokens)
    assert await guard.current_spend_usd() == pytest.approx(450_000.0, abs=0.01)


@pytest.mark.asyncio
async def test_fourth_agent_rejected_after_three(guard: FiscalLimitGuard) -> None:
    """After 3 x $150k, the fourth $150k must be rejected (would hit $600k)."""
    for i in range(3):
        await guard.reserve(agent_id=f"agent-{i}", amount_usd=150_000.0)
    token = await guard.reserve(agent_id="agent-3", amount_usd=150_000.0)
    assert token.rejected


# ---------------------------------------------------------------------------
# Test 3: Release path (Saga rollback restores capacity)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_release_restores_capacity(guard: FiscalLimitGuard) -> None:
    """
    Agent A reserves $300k, trade fails, Saga compensating node calls release().
    Agent B should then succeed since capacity was restored.
    """
    token_a = await guard.reserve(agent_id="trading-agent", amount_usd=300_000.0)
    assert not token_a.rejected

    # Simulate Saga rollback
    new_total = await guard.release(token_a)
    assert new_total == pytest.approx(0.0, abs=0.01)

    # Agent B can now reserve
    token_b = await guard.reserve(agent_id="hedging-agent", amount_usd=300_000.0)
    assert not token_b.rejected


@pytest.mark.asyncio
async def test_release_of_rejected_token_is_noop(guard: FiscalLimitGuard) -> None:
    """Releasing a rejected token must not corrupt the spend counter."""
    # Fill the cap
    await guard.reserve(agent_id="agent-a", amount_usd=500_000.0)
    rejected_token = await guard.reserve(agent_id="agent-b", amount_usd=10_000.0)
    assert rejected_token.rejected

    before = await guard.current_spend_usd()
    await guard.release(rejected_token)  # must be a no-op
    assert await guard.current_spend_usd() == before


@pytest.mark.asyncio
async def test_double_release_does_not_go_negative(guard: FiscalLimitGuard) -> None:
    """Releasing the same token twice must floor at 0, not go negative."""
    token = await guard.reserve(agent_id="trading-agent", amount_usd=100_000.0)
    await guard.release(token)
    await guard.release(token)  # idempotent — must not underflow
    assert await guard.current_spend_usd() >= 0.0


# ---------------------------------------------------------------------------
# Test 4: Redis failure — fail-closed behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_failure_fails_closed(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """
    If Redis is unreachable during reserve(), the guard must fail CLOSED
    (return a rejected token) to prevent the agent from bypassing the limit.
    """
    broken_guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
    )
    # Simulate a connection error at the script layer
    broken_guard._eval = AsyncMock(
        side_effect=ConnectionError("Redis connection refused")
    )
    token = await broken_guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    assert token.rejected, "Redis failure must fail CLOSED (reservation rejected)"


@pytest.mark.asyncio
async def test_redis_release_failure_raises_and_leaves_reservation_reclaimable(
    guard: FiscalLimitGuard, redis_client: fakeredis.aioredis.FakeRedis
) -> None:
    """A failed release raises (the kernel records ROLLBACK_FAILED) and the
    reservation stays pending, so the TTL reclaimer still frees it."""
    token = await guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    with patch.object(redis_client, "eval", side_effect=ConnectionError("redis down")):
        with pytest.raises(ConnectionError):
            await guard.release(token)
    assert await redis_client.zscore(PENDING_KEY, token.member) is not None
    assert await guard.reclaim_expired(now=time.time() + 301) == 1
    assert await guard.current_spend_usd() == 0.0


# ---------------------------------------------------------------------------
# Test 5: Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_redis_returns_zero_spend(guard: FiscalLimitGuard) -> None:
    assert await guard.current_spend_usd() == 0.0
    assert await guard.remaining_usd() == pytest.approx(500_000.0, abs=0.01)


@pytest.mark.asyncio
async def test_exact_cap_reservation_accepted(guard: FiscalLimitGuard) -> None:
    """Reserving exactly the cap amount must succeed."""
    token = await guard.reserve(agent_id="trading-agent", amount_usd=500_000.0)
    assert not token.rejected
    assert await guard.remaining_usd() == pytest.approx(0.0, abs=0.01)


@pytest.mark.asyncio
async def test_one_cent_over_cap_rejected(guard: FiscalLimitGuard) -> None:
    """Reserving $500k + $0.01 must be rejected."""
    await guard.reserve(agent_id="trading-agent", amount_usd=500_000.0)
    token = await guard.reserve(agent_id="agent-b", amount_usd=0.01)
    assert token.rejected


@pytest.mark.asyncio
async def test_invalid_amount_raises(guard: FiscalLimitGuard) -> None:
    with pytest.raises(ValueError, match="amount_usd must be > 0"):
        await guard.reserve(agent_id="trading-agent", amount_usd=0.0)

    with pytest.raises(ValueError, match="amount_usd must be > 0"):
        await guard.reserve(agent_id="trading-agent", amount_usd=-100.0)


@pytest.mark.asyncio
async def test_reservation_token_fields(guard: FiscalLimitGuard) -> None:
    token = await guard.reserve(agent_id="liquidity-agent", amount_usd=75_000.0)
    assert token.agent_id == "liquidity-agent"
    assert token.cap_usd == 500_000.0
    assert token.window_key.startswith("fiscal:daily_limit:")
    assert token.ttl_seconds == 300
    assert not token.rejected


# ---------------------------------------------------------------------------
# Test 6: confirm() — properly awaited
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_awaitable_does_not_raise(guard: FiscalLimitGuard) -> None:
    """confirm() when properly awaited should not raise and not change the spend total."""
    token = await guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    before = await guard.current_spend_usd()
    await guard.confirm(token)  # properly awaited
    assert await guard.current_spend_usd() == before


@pytest.mark.asyncio
async def test_confirm_on_rejected_token_is_noop(guard: FiscalLimitGuard) -> None:
    """confirm() on a rejected token must be a no-op (no Redis writes)."""
    # Fill the cap
    await guard.reserve(agent_id="agent-a", amount_usd=500_000.0)
    rejected = await guard.reserve(agent_id="agent-b", amount_usd=10_000.0)
    assert rejected.rejected
    # confirm on a rejected token must not raise
    await guard.confirm(rejected)
    assert await guard.current_spend_usd() == pytest.approx(500_000.0, abs=0.01)


# ---------------------------------------------------------------------------
# Test 8: key schema
# ---------------------------------------------------------------------------


def test_window_key_format(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_window_key() returns a key starting with fiscal:daily_limit:."""
    guard = FiscalLimitGuard(redis_client=redis_client)
    key = guard._window_key()
    assert key.startswith("fiscal:daily_limit:")
    # Should contain a date string like 2026-08-09
    import re

    assert re.search(r"\d{4}-\d{2}-\d{2}$", key)


# ---------------------------------------------------------------------------
# Test 10: current_spend_usd Redis error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_current_spend_usd_redis_error_returns_zero(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """current_spend_usd() returns 0.0 when Redis raises an error (fail-safe)."""
    guard = FiscalLimitGuard(redis_client=redis_client)
    with patch.object(redis_client, "get", side_effect=ConnectionError("redis down")):
        result = await guard.current_spend_usd()
    assert result == 0.0


# ---------------------------------------------------------------------------
# Test 11: nan / inf input validation (CRIT-2 fix paths)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_infinite_amount_raises_value_error(guard: FiscalLimitGuard) -> None:
    """reserve() with float('inf') raises ValueError (CRIT-2 fix)."""
    with pytest.raises(ValueError, match="finite positive number"):
        await guard.reserve(agent_id="agent", amount_usd=float("inf"))


@pytest.mark.asyncio
async def test_nan_amount_raises_value_error(guard: FiscalLimitGuard) -> None:
    """reserve() with float('nan') raises ValueError (CRIT-2 fix)."""
    with pytest.raises(ValueError, match="finite positive number"):
        await guard.reserve(agent_id="agent", amount_usd=float("nan"))


@pytest.mark.asyncio
async def test_negative_infinity_raises_value_error(guard: FiscalLimitGuard) -> None:
    """reserve() with -float('inf') raises ValueError."""
    with pytest.raises(ValueError, match="finite positive number"):
        await guard.reserve(agent_id="agent", amount_usd=float("-inf"))


@pytest.mark.local
def test_fiscal_guard_from_env():
    with patch.dict(
        os.environ,
        {"REDIS_URL": "redis://localhost:6379/0", "FISCAL_DAILY_CAP_USD": "250000"},
    ):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client
            g = FiscalLimitGuard.from_env()
            assert g._daily_cap_usd == 250000.0


# ---------------------------------------------------------------------------
# Test 12: settlement lifecycle and the TTL reclaimer (ADR-009)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsettled_reservation_is_reclaimed_after_ttl(
    guard: FiscalLimitGuard, redis_client: fakeredis.aioredis.FakeRedis
) -> None:
    """Crash between seal and actuation: nobody settles, the TTL frees the cap."""
    token = await guard.reserve(agent_id="agent", amount_usd=200_000.0)
    assert await guard.reclaim_expired(now=time.time() + 10) == 0  # not yet expired
    assert await guard.current_spend_usd() == pytest.approx(200_000.0)

    assert await guard.reclaim_expired(now=time.time() + 301) == 1
    assert await guard.current_spend_usd() == 0.0
    assert await redis_client.zscore(PENDING_KEY, token.member) is None
    assert await redis_client.zscore(RECLAIMED_KEY, token.member) is not None


@pytest.mark.asyncio
async def test_reserve_reclaims_expired_reservations_lazily(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """A cap held by an abandoned reservation is freed by the next reserve()."""
    guard = FiscalLimitGuard(redis_client, daily_cap_usd=1_000.0, reservation_ttl=300)
    stale = await guard.reserve(agent_id="crashed", amount_usd=1_000.0)
    assert not stale.rejected
    assert (await guard.reserve(agent_id="b", amount_usd=1.0)).rejected
    # Age the abandoned reservation past its TTL.
    await redis_client.zadd(PENDING_KEY, {stale.member: time.time() - 1})
    assert await guard.would_accept(1_000.0)
    assert not (await guard.reserve(agent_id="b", amount_usd=1_000.0)).rejected


@pytest.mark.asyncio
async def test_preview_discounts_expired_reservations_without_writing(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """would_accept()/headroom_usd() agree with reserve() but never reclaim."""
    guard = FiscalLimitGuard(redis_client, daily_cap_usd=1_000.0, reservation_ttl=300)
    stale = await guard.reserve(agent_id="crashed", amount_usd=600.0)
    live = await guard.reserve(agent_id="live", amount_usd=300.0)
    await redis_client.zadd(PENDING_KEY, {stale.member: time.time() - 1})

    assert await guard.headroom_usd() == pytest.approx(700.0)
    assert await guard.would_accept(700.0)
    assert not await guard.would_accept(700.01)
    # Nothing was reclaimed: the stale reservation is still pending and counted.
    assert await redis_client.zscore(PENDING_KEY, stale.member) is not None
    assert await redis_client.zscore(RECLAIMED_KEY, stale.member) is None
    assert await guard.current_spend_usd() == pytest.approx(900.0)
    # The live reservation is not discounted.
    assert await redis_client.zscore(PENDING_KEY, live.member) is not None


@pytest.mark.asyncio
async def test_preview_fails_closed_when_pending_set_unreadable(
    redis_client: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = FiscalLimitGuard(redis_client, daily_cap_usd=1_000.0, reservation_ttl=300)
    await guard.reserve(agent_id="a", amount_usd=100.0)

    async def _boom(*_a, **_k):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_client, "zrangebyscore", _boom)
    assert await guard.would_accept(1.0) is False
    assert await guard.headroom_usd() is None


@pytest.mark.asyncio
async def test_confirmed_reservation_is_never_reclaimed(
    guard: FiscalLimitGuard,
) -> None:
    token = await guard.reserve(agent_id="agent", amount_usd=100_000.0)
    await guard.confirm(token)
    assert await guard.reclaim_expired(now=time.time() + 10_000) == 0
    assert await guard.current_spend_usd() == pytest.approx(100_000.0)


@pytest.mark.asyncio
async def test_release_after_confirm_is_a_noop(guard: FiscalLimitGuard) -> None:
    """A confirmed spend cannot be refunded by a late or replayed release."""
    token = await guard.reserve(agent_id="agent", amount_usd=100_000.0)
    await guard.confirm(token)
    assert await guard.release(token) == 0.0
    assert await guard.current_spend_usd() == pytest.approx(100_000.0)


@pytest.mark.asyncio
async def test_double_release_refunds_once(guard: FiscalLimitGuard) -> None:
    keep = await guard.reserve(agent_id="a", amount_usd=50_000.0)
    token = await guard.reserve(agent_id="b", amount_usd=100_000.0)
    await guard.release(token)
    await guard.release(token)
    assert not keep.rejected
    assert await guard.current_spend_usd() == pytest.approx(50_000.0)


@pytest.mark.asyncio
async def test_confirm_after_reclaim_recounts_the_spend(
    guard: FiscalLimitGuard,
) -> None:
    """The trade executed after its reservation expired: it still counts, once."""
    token = await guard.reserve(agent_id="agent", amount_usd=100_000.0)
    await guard.reclaim_expired(now=time.time() + 301)
    assert await guard.current_spend_usd() == 0.0
    await guard.confirm(token)
    await guard.confirm(token)
    assert await guard.current_spend_usd() == pytest.approx(100_000.0)


@pytest.mark.asyncio
async def test_release_after_reclaim_does_not_double_refund(
    guard: FiscalLimitGuard,
) -> None:
    keep = await guard.reserve(agent_id="a", amount_usd=50_000.0)
    token = await guard.reserve(agent_id="b", amount_usd=100_000.0)
    # Expire only ``token``.
    await guard._redis.zadd(PENDING_KEY, {token.member: time.time() - 1})
    assert await guard.reclaim_expired() == 1
    assert await guard.release(token) == 0.0
    assert not keep.rejected
    assert await guard.current_spend_usd() == pytest.approx(50_000.0)
    await guard.confirm(token)  # the release closed it: no re-count either
    assert await guard.current_spend_usd() == pytest.approx(50_000.0)


@pytest.mark.asyncio
async def test_reclaim_failure_keeps_reserve_fail_safe(
    guard: FiscalLimitGuard,
) -> None:
    """If the reclaimer cannot run, stale reservations stay counted (never freed early)."""
    original = guard.reclaim_expired
    guard.reclaim_expired = AsyncMock(side_effect=ConnectionError("down"))
    token = await guard.reserve(agent_id="a", amount_usd=10.0)
    assert not token.rejected
    guard.reclaim_expired = original


@pytest.mark.local
def test_sync_client_lifecycle() -> None:
    """The guard drives a synchronous redis client through the executor too."""
    import asyncio

    import fakeredis

    client = fakeredis.FakeRedis(decode_responses=True)
    guard = FiscalLimitGuard(client, daily_cap_usd=1_000.0)

    async def run() -> None:
        token = await guard.reserve(agent_id="a", amount_usd=600.0)
        assert not token.rejected
        assert (await guard.reserve(agent_id="b", amount_usd=600.0)).rejected
        assert await guard.release(token) == 0.0
        again = await guard.reserve(agent_id="b", amount_usd=600.0)
        await guard.confirm(again)
        assert await guard.current_spend_usd() == pytest.approx(600.0)

    asyncio.run(run())
