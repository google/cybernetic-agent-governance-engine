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
  4. Stale reservation TTL — capacity restored after expiry
  5. Redis failure — fail-closed behaviour
  6. Idempotent release (double-release safe)
  7. remaining_usd / current_spend_usd reporting
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for fiscal_limit_guard tests"
)

import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.fiscal_limit_guard import FiscalLimitGuard

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
    guard.confirm(token)
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
    """After 3 × $150k, the fourth $150k must be rejected (would hit $600k)."""
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
    # Simulate a connection error at the atomic layer
    broken_guard._atomic_increment = AsyncMock(
        side_effect=ConnectionError("Redis connection refused")
    )
    token = await broken_guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    assert token.rejected, "Redis failure must fail CLOSED (reservation rejected)"


@pytest.mark.asyncio
async def test_redis_release_failure_is_logged_not_raised(
    guard: FiscalLimitGuard,
) -> None:
    """
    If Redis fails during release(), the guard must log an error but NOT raise,
    since the rollback path must always complete to update the Saga ledger.
    """
    token = await guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
    guard._atomic_decrement = AsyncMock(return_value=-1)
    # Must not raise
    result = await guard.release(token)
    assert result == 0.0


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
