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
Tests for CBF atomicity: verifies that atomic_verify_and_commit() prevents
two concurrent execute_trade actions from jointly overdrawing the account.

Issue #6 in peer-review remediation: CBF TOCTOU race condition.
See CAGE_ARXIV.MD §5.1, §5.2 and POAM-TIER2-001 comments in symbolic_governor.py.

All tests run without live Redis (fakeredis) or live KMS (mocked).
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required for CBF atomicity tests")

import fakeredis.aioredis  # type: ignore[import]

from src.cage_finance.safety.cbf import ControlBarrierFunction

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The CBF min_cash_balance default threshold comes from THRESHOLDS.cbf.min_cash_balance.
# We use a balance that is exactly 1_000.00 above the default minimum (10_000.00),
# leaving room for exactly ONE trade of 900.00 to pass the barrier certificate.
# With gamma=0.05 (default), required_h_next = (1 - 0.05) * h(t):
#   h(11_000.00) = 11_000 - 10_000 = 1_000
#   After $900: h(10_100.00) = 10_100 - 10_000 = 100  >=  0.95 * 1_000 = 950? NO
# So we need a bigger gap. Use 100_000 balance and 90_000 trade:
#   h(100_000) = 100_000 - 10_000 = 90_000
#   After 90_000: h(10_000) = 0  >=  0.95 * 90_000 = 85_500? NO — still blocked.
# Use a trade that is just within limit for the first call but jointly overdrawing.
# Set balance = 12_000, trade = 1_800 each (2 concurrent):
#   h(12_000) = 12_000 - 10_000 = 2_000
#   After 1_800: h(10_200) = 200 >= 0.95 * 2_000 = 1_900? NO.
# Simplest: set min_cash_balance very low (100) and use a balance of 1_000, trade 900 each.
# h(1_000) = 900; after 900: h(100) = 0 >= 0.95 * 900 = 855? NO.
# Use gamma=0.0 effectively: h_next >= 0 only.
# With min_cash_balance=0: h(1000)=1000, trade=900 → h_next=100>=0. Trade 2: h(100)=100, 900>100 → blocked.

_INITIAL_BALANCE = 1000.0  # Total cash available
_TRADE_AMOUNT = 900.0  # Each trade requests 900 — only one can fit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cbf_with_fakeredis(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> ControlBarrierFunction:
    """Construct a ControlBarrierFunction whose Redis calls are served by fakeredis.

    Patches src.cage_finance.safety.cbf.redis_client so that get_raw_client()
    returns the caller-supplied fakeredis instance — matching the pattern used
    in test_cbf_reconciliation.py.
    """
    # skip_epoch_seed=True prevents the constructor from trying to fetch the epoch
    # from Redis before the monkeypatch is applied in the test
    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    # Override thresholds to make the test deterministic regardless of env config.
    # min_cash_balance=0 means the only constraint is h_next >= 0, i.e. balance > 0.
    cbf.min_cash_balance = 0.0
    cbf.gamma = 1.0  # No decay threshold: required_h_next = (1-1.0)*h_t = 0,
    # so constraint is h_next >= 0 only.
    # With balance=1000 and trade=900:
    #   Trade 1: h_next=100 >= 0 → COMMITTED ✓
    #   Trade 2: h_next=-800 < 0 → UNSAFE ✓
    cbf.tracer = None  # suppress OTel span creation in unit tests
    return cbf


async def _seed_balance(
    fake_redis: fakeredis.aioredis.FakeRedis, balance: float
) -> None:
    """Write the initial cash balance into the fakeredis instance."""
    await fake_redis.set("safety:current_cash", str(balance))


# ---------------------------------------------------------------------------
# Test 1: Sequential baseline — first call commits, second is blocked
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_sequential_atomic_verify_second_blocked() -> None:
    """First trade commits atomically; second trade is blocked because the new
    balance after the first deduction no longer satisfies the CBF envelope."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    await _seed_balance(fake_redis, _INITIAL_BALANCE)

    cbf = _make_cbf_with_fakeredis(fake_redis)

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client.return_value = fake_redis

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("src.cage_finance.safety.cbf.redis_client", mock_redis_module)

        committed1, reason1 = await cbf.atomic_verify_and_commit(
            action_name="execute_trade",
            payload={"amount": _TRADE_AMOUNT},
        )
        committed2, reason2 = await cbf.atomic_verify_and_commit(
            action_name="execute_trade",
            payload={"amount": _TRADE_AMOUNT},
        )

    assert committed1 is True, f"First trade should commit; got reason: {reason1}"
    assert committed2 is False, (
        f"Second trade should be blocked after first deduction; got: {reason2}"
    )
    assert "UNSAFE" in reason2, (
        f"Rejection reason must contain 'UNSAFE'; got: {reason2!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: Concurrent atomicity — TOCTOU property
#
# This is the primary regression test for Issue #6.  Two tasks call
# atomic_verify_and_commit() simultaneously via asyncio.gather().  Because the
# check and commit are collapsed into a single Redis Lua hop, only one of the
# two can win — the Lua script is single-threaded inside Redis, so the second
# call sees the already-debited balance and returns UNSAFE.
#
# Pre-fix failure mode: if verify_action() + update_state() were used instead,
# both coroutines could READ the same original balance before either WROTE back,
# allowing both to pass the barrier certificate check and jointly overdraw.
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_concurrent_atomic_verify_exactly_one_commits() -> None:
    """TOCTOU property: two concurrent atomic_verify_and_commit() calls for
    amounts that jointly exceed the balance must result in exactly one commit
    and one UNSAFE rejection — never both committed.

    This directly verifies the CBF Invariance Theorem atomicity premise
    described in CAGE_ARXIV.MD §5.1 and §5.2.
    """
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    await _seed_balance(fake_redis, _INITIAL_BALANCE)

    cbf = _make_cbf_with_fakeredis(fake_redis)

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client.return_value = fake_redis

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("src.cage_finance.safety.cbf.redis_client", mock_redis_module)

        results = await asyncio.gather(
            cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": _TRADE_AMOUNT},
            ),
            cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": _TRADE_AMOUNT},
            ),
            return_exceptions=True,
        )

    committed_results = [r for r in results if not isinstance(r, BaseException)]
    assert len(committed_results) == 2, (
        f"Both gather() tasks should return (bool, str) tuples; got: {results!r}"
    )

    commits = [r for r in committed_results if r[0] is True]
    blocks = [r for r in committed_results if r[0] is False]

    assert len(commits) == 1, (
        f"Exactly one trade should commit when only one fits in the balance; "
        f"got {len(commits)} commits. Pre-fix TOCTOU would allow both to pass."
    )
    assert len(blocks) == 1, (
        f"Exactly one trade should be blocked; got {len(blocks)} blocks."
    )
    assert "UNSAFE" in blocks[0][1], (
        f"Rejection reason must contain 'UNSAFE'; got: {blocks[0][1]!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: Non-trade actions are not debited by atomic_verify_and_commit
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_non_trade_action_not_debited() -> None:
    """atomic_verify_and_commit() passes cost=0 for non-execute_trade actions,
    so the balance is unchanged and the call always returns COMMITTED."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    await _seed_balance(fake_redis, _INITIAL_BALANCE)

    cbf = _make_cbf_with_fakeredis(fake_redis)

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client.return_value = fake_redis

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("src.cage_finance.safety.cbf.redis_client", mock_redis_module)

        committed, reason = await cbf.atomic_verify_and_commit(
            action_name="market_analysis",
            payload={"symbol": "AAPL"},
        )

    assert committed is True, (
        f"Non-trade action with zero cost must commit; got: {reason!r}"
    )
    assert reason == "COMMITTED"

    # Balance unchanged
    raw = await fake_redis.get("safety:current_cash")
    balance_after = float(raw)
    assert abs(balance_after - _INITIAL_BALANCE) < 0.01, (
        f"Balance must not change for non-trade action; got {balance_after}"
    )


# ---------------------------------------------------------------------------
# Test 4: Balance exactly at minimum is blocked
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_balance_at_minimum_blocks_any_trade() -> None:
    """When cash equals min_cash_balance, h(t)=0 and any positive trade must
    be blocked because h(t+1) < 0."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)

    cbf = _make_cbf_with_fakeredis(fake_redis)
    # Set balance exactly at min_cash_balance (0.0 in our override)
    await _seed_balance(fake_redis, cbf.min_cash_balance)

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client.return_value = fake_redis

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("src.cage_finance.safety.cbf.redis_client", mock_redis_module)

        committed, reason = await cbf.atomic_verify_and_commit(
            action_name="execute_trade",
            payload={"amount": 1.0},  # any positive trade
        )

    assert committed is False, (
        "A trade when balance == min_cash_balance must be blocked."
    )
    assert "UNSAFE" in reason
