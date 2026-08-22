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

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for fiscal_limit_guard tests"
)

import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.fiscal_limit_guard import FiscalLimitGuard

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
# Test 7: rollback_state() — Saga compensating transaction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_state_decrements_spend(guard: FiscalLimitGuard) -> None:
    """rollback_state() decrements the aggregate spend counter."""
    await guard.reserve(agent_id="agent-a", amount_usd=200_000.0)
    assert await guard.current_spend_usd() == pytest.approx(200_000.0, abs=0.01)

    await guard.rollback_state(amount=100_000.0, audit_id="audit-123")
    assert await guard.current_spend_usd() == pytest.approx(100_000.0, abs=0.01)


@pytest.mark.asyncio
async def test_rollback_state_floors_at_zero(guard: FiscalLimitGuard) -> None:
    """rollback_state() never goes below zero (floor-at-zero)."""
    await guard.reserve(agent_id="agent-a", amount_usd=50_000.0)
    # Roll back more than spent
    await guard.rollback_state(amount=200_000.0, audit_id="audit-456")
    assert await guard.current_spend_usd() >= 0.0


@pytest.mark.asyncio
async def test_rollback_state_redis_error_re_raises(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """rollback_state() re-raises Redis errors (Saga error handling responsibility)."""
    guard = FiscalLimitGuard(redis_client=redis_client, daily_cap_usd=500_000.0)
    await guard.reserve(agent_id="agent-a", amount_usd=100_000.0)

    guard._atomic_decrement = AsyncMock(side_effect=RuntimeError("Redis gone"))
    with pytest.raises(RuntimeError, match="Redis gone"):
        await guard.rollback_state(amount=50_000.0, audit_id="audit-err")


# ---------------------------------------------------------------------------
# Test 8: _reservation_key helper
# ---------------------------------------------------------------------------


def test_reservation_key_format(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_reservation_key() returns the expected key schema."""
    guard = FiscalLimitGuard(redis_client=redis_client)
    key = guard._reservation_key("test-uuid-1234")
    assert key == "fiscal:reservation:test-uuid-1234"


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
# Test 9: _write_reservation_key and _delete_reservation_key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_reservation_key_success(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_write_reservation_key() stores a sentinel key with TTL."""
    guard = FiscalLimitGuard(redis_client=redis_client, reservation_ttl=60)
    await guard._write_reservation_key(
        "res-uuid", 5_000_00, "fiscal:daily_limit:2026-08-09"
    )

    key = "fiscal:reservation:res-uuid"
    val = await redis_client.get(key)
    assert val is not None
    assert "500000" in val  # amount_cents


@pytest.mark.asyncio
async def test_delete_reservation_key_removes_key(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_delete_reservation_key() removes the sentinel key."""
    guard = FiscalLimitGuard(redis_client=redis_client, reservation_ttl=60)
    await guard._write_reservation_key(
        "del-uuid", 100_00, "fiscal:daily_limit:2026-08-09"
    )

    key = "fiscal:reservation:del-uuid"
    assert await redis_client.get(key) is not None

    await guard._delete_reservation_key("del-uuid")
    assert await redis_client.get(key) is None


@pytest.mark.asyncio
async def test_write_reservation_key_failure_is_logged(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_write_reservation_key() failure is logged as warning, not raised."""
    guard = FiscalLimitGuard(redis_client=redis_client)
    # Patch redis.set to raise an error
    with patch.object(redis_client, "set", side_effect=ConnectionError("no redis")):
        # Must not raise
        await guard._write_reservation_key(
            "fail-uuid", 1000, "fiscal:daily_limit:2026-08-09"
        )


@pytest.mark.asyncio
async def test_delete_reservation_key_failure_is_logged(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """_delete_reservation_key() failure is logged as warning, not raised."""
    guard = FiscalLimitGuard(redis_client=redis_client)
    # Patch redis.delete to raise an error
    with patch.object(redis_client, "delete", side_effect=ConnectionError("no redis")):
        # Must not raise
        await guard._delete_reservation_key("fail-del-uuid")


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


@pytest.mark.local
def test_sync_increment_and_decrement():
    mock_pipe = MagicMock()
    mock_pipe.get.return_value = "1000"
    mock_pipe.execute.return_value = [2000]

    mock_sync_redis = MagicMock()
    mock_sync_redis.pipeline.return_value = mock_pipe

    guard = FiscalLimitGuard(redis_client=mock_sync_redis, daily_cap_usd=1000.0)

    # Test increment success
    res = guard._sync_atomic_increment("key", 1000, 50000)
    assert res == 2000

    # Test increment exceed cap
    mock_pipe.get.return_value = "60000"
    res_exceed = guard._sync_atomic_increment("key", 1000, 50000)
    assert res_exceed == -1

    # Test decrement
    mock_pipe.get.return_value = "3000"
    res_dec = guard._sync_atomic_decrement("key", 1000)
    assert res_dec == 2000


# ---------------------------------------------------------------------------
# Peer Review Fix Tests: Cross-window rollback handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_state_cross_window_skipped(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Rollback to a different window (e.g., after midnight) is skipped.

    This tests the cross-window expiry guard: if the target window_key
    differs from the current window, the rollback is treated as a no-op
    to prevent creating/modifying stale window keys.
    """
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
    )

    # Reserve in today's window
    token = await guard.reserve(agent_id="agent-1", amount_usd=50_000.0)
    assert not token.rejected

    # Simulate rollback with a different (stale) window key
    stale_window_key = "fiscal:daily_limit:1999-01-01"  # Obviously stale

    # Call rollback_state with the stale window_key
    # Should be a no-op (no error, no modification)
    await guard.rollback_state(
        amount=50_000.0,
        audit_id="test-audit-001",
        window_key=stale_window_key,
    )

    # Verify the current window's balance is unchanged
    current_spend = await guard.current_spend_usd()
    assert current_spend == 50_000.0, (
        "Balance should be unchanged after cross-window rollback"
    )


@pytest.mark.asyncio
async def test_rollback_state_expired_window_key_skipped(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Rollback to an expired/missing window key is skipped.

    If the target window_key no longer exists in Redis (TTL expired),
    the rollback is treated as a no-op — nothing to decrement.
    """
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
    )

    # Get the current window key
    current_window = guard._window_key()

    # Ensure the key does NOT exist (simulate expired)
    await redis_client.delete(current_window)

    # Call rollback_state — should be a no-op since key doesn't exist
    await guard.rollback_state(
        amount=10_000.0,
        audit_id="test-audit-002",
        window_key=current_window,
    )

    # Verify no key was created
    exists = await redis_client.exists(current_window)
    assert exists == 0, "Rollback should not create an expired/missing key"


@pytest.mark.asyncio
async def test_rollback_state_with_token_uses_token_window_key(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Rollback using ReservationToken.window_key correctly targets the token's window."""
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
    )

    # Reserve and get token
    token = await guard.reserve(agent_id="agent-1", amount_usd=75_000.0)
    assert not token.rejected
    assert token.window_key == guard._window_key()

    # Call rollback_state using the token parameter
    await guard.rollback_state(
        amount=75_000.0,
        audit_id="test-audit-003",
        token=token,
    )

    # Verify balance was decremented
    current_spend = await guard.current_spend_usd()
    assert current_spend == 0.0, "Rollback with token should decrement balance"


@pytest.mark.asyncio
async def test_rollback_state_legacy_no_window_key_uses_current(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Legacy rollback (no window_key/token) uses current window — backward compatible."""
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
    )

    # Reserve
    token = await guard.reserve(agent_id="agent-1", amount_usd=30_000.0)
    assert not token.rejected

    # Call rollback_state without window_key or token (legacy path)
    await guard.rollback_state(
        amount=30_000.0,
        audit_id="test-audit-004",
    )

    # Verify balance was decremented (backward compatible)
    current_spend = await guard.current_spend_usd()
    assert current_spend == 0.0, "Legacy rollback should work on current window"


@pytest.mark.asyncio
async def test_rollback_state_counter_floors_at_zero(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> None:
    """Rollback amount greater than balance floors at zero — no negative balance."""
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=500_000.0,
        reservation_ttl=300,
    )

    # Reserve a small amount
    await guard.reserve(agent_id="agent-1", amount_usd=5_000.0)

    # Rollback more than reserved (should floor at 0)
    await guard.rollback_state(
        amount=100_000.0,  # Way more than reserved
        audit_id="test-audit-005",
    )

    # Verify balance is 0, not negative
    current_spend = await guard.current_spend_usd()
    assert current_spend == 0.0, "Balance must floor at 0, never go negative"
