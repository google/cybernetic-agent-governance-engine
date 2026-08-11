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

"""Negative-path unit tests for src/gateway/governance/cbf.py.

Covers all 5 branches of _read_cbf_state_atomic(), WATCH/MULTI/EXEC retry
paths in update_state() and rollback_state(), NOSCRIPT retry in
_evalsha_with_noscript_retry(), verify_action() edge cases, and the
_parse_lua_result() bytes/string handling.

All tests run without live Redis (fakeredis.aioredis) or live KMS (mocked).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required for CBF tests")

import fakeredis.aioredis  # type: ignore[import]

pytestmark = pytest.mark.local

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_BALANCE = 50_000.0
_MIN_CASH = 10_000.0
_GAMMA = 0.9


def _make_cbf(fake_redis: fakeredis.aioredis.FakeRedis) -> "ControlBarrierFunction":
    """Return a CBF wired to *fake_redis* with deterministic thresholds."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None  # suppress OTel span creation

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client = MagicMock(return_value=fake_redis)
    mock_redis_module.get = AsyncMock(
        side_effect=lambda key: fake_redis.get(key)
    )
    mock_redis_module.get_float = AsyncMock(
        side_effect=lambda key, default: asyncio.get_event_loop().run_until_complete(
            _async_get_float(fake_redis, key, default)
        )
        if False
        else None  # never used; real calls go through get_raw_client
    )
    mock_redis_module.set = AsyncMock(side_effect=lambda key, val: fake_redis.set(key, val))
    mock_redis_module.pipeline = fake_redis.pipeline

    return cbf, mock_redis_module


async def _async_get_float(
    r: fakeredis.aioredis.FakeRedis, key: str, default: float
) -> float:
    raw = await r.get(key)
    return float(raw) if raw is not None else default


async def _seed_balance(fake_redis: fakeredis.aioredis.FakeRedis, balance: float) -> None:
    await fake_redis.set("safety:current_cash", str(balance))


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 1: KMS-signed reconciled balance (valid sig)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_uses_reconciled_balance_when_kms_valid():
    """When reconciled balance has a valid KMS signature, source='reconciled'."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    # Build a mock verified balance with a valid KMS signature
    verified = MagicMock()
    verified.is_valid = True
    verified.signature = "sig-abc"
    verified.balance_usd = 88_000.0
    verified.source = "plaid"
    verified.verified_at = 1_700_000_000.0

    mock_signer = MagicMock()
    mock_signer.verify = MagicMock(return_value=True)

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "reconciled"
    assert state["current_cash"] == 88_000.0


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 2: KMS signature invalid → fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_falls_back_when_kms_sig_invalid():
    """When KMS signature is invalid, falls back to self-reported balance."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = "bad-sig"
    verified.balance_usd = 88_000.0
    verified.source = "plaid"
    verified.verified_at = 1_700_000_000.0

    mock_signer = MagicMock()
    mock_signer.verify = MagicMock(return_value=False)  # signature invalid

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported"
    assert state["current_cash"] == _SAFE_BALANCE


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 3: KMS verify raises → fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_falls_back_when_kms_verify_raises():
    """When KMS.verify() raises, falls back to self-reported balance."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = "some-sig"
    verified.balance_usd = 88_000.0
    verified.source = "plaid"
    verified.verified_at = 1_700_000_000.0

    mock_signer = MagicMock()
    mock_signer.verify = MagicMock(side_effect=RuntimeError("KMS network error"))

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported"


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 4: unsigned reconciled balance in dev mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_accepts_unsigned_balance_in_dev_mode():
    """In dev/ci mode, an unsigned reconciled balance is accepted."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = None  # no KMS signature
    verified.balance_usd = 77_000.0
    verified.source = "stub"
    verified.verified_at = 1_700_000_000.0

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch("src.gateway.governance.cbf._IS_PRODUCTION", False),  # dev mode
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "reconciled_unsigned"
    assert state["current_cash"] == 77_000.0


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 5: unsigned reconciled balance in production
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_rejects_unsigned_balance_in_production():
    """In production, an unsigned reconciled balance is rejected → self-reported."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = None  # no KMS signature
    verified.balance_usd = 77_000.0
    verified.source = "stub"
    verified.verified_at = 1_700_000_000.0

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch("src.gateway.governance.cbf._IS_PRODUCTION", True),  # production
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported"


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path: reconciliation read raises exception
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_falls_back_when_reconciliation_raises():
    """When asyncio.to_thread(read_verified_balance) raises, falls back to self-reported."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(side_effect=ConnectionError("Redis unavailable")),
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported"
    assert state["current_cash"] == _SAFE_BALANCE


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — redis_client is None raises RuntimeError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_raises_when_redis_unavailable():
    """_read_cbf_state_atomic raises RuntimeError when redis_client is None."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    with patch("src.gateway.governance.cbf.redis_client", None):
        with pytest.raises(RuntimeError, match="Redis client unavailable"):
            await cbf._read_cbf_state_atomic()


# ---------------------------------------------------------------------------
# verify_action — non-trade action always SAFE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_non_trade_action_is_always_safe():
    """Non-trade actions (cost=0) are always SAFE regardless of balance."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, 100.0)  # very low balance

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = 0.0
    cbf.gamma = 0.9
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=None),  # reconciliation absent
        ),
    ):
        result = await cbf.verify_action("market_analysis", {"symbol": "AAPL"})

    assert result == "SAFE"


# ---------------------------------------------------------------------------
# verify_action — drawdown violation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_drawdown_violation_returns_unsafe():
    """A drawdown_pct exceeding the threshold returns an UNSAFE message."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = 0.0
    cbf.gamma = 0.9
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    # Patch THRESHOLDS so drawdown limit is 5%
    mock_thresholds = MagicMock()
    mock_thresholds.drawdown.limit = 0.05

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch("src.gateway.governance.cbf.THRESHOLDS", mock_thresholds),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result = await cbf.verify_action(
            "execute_trade", {"amount": 100.0, "drawdown_pct": 10.0}  # 10% > 5% limit
        )

    assert "UNSAFE" in result
    assert "Drawdown" in result


# ---------------------------------------------------------------------------
# verify_action — trade that exactly hits barrier floor is SAFE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_trade_at_exact_floor_is_safe():
    """A trade that leaves balance exactly at min_cash_balance is SAFE.

    With gamma=1.0, required_h_next = (1-1.0)*h_t = 0, so h_next=0 is OK.
    """
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _MIN_CASH + 1000.0)  # 1000 above floor

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = 1.0  # required_h_next = 0
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result = await cbf.verify_action("execute_trade", {"amount": 1000.0})

    assert result == "SAFE"


# ---------------------------------------------------------------------------
# verify_action — trade that breaches barrier floor is UNSAFE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_trade_below_floor_returns_unsafe():
    """A trade that takes balance below min_cash_balance returns UNSAFE."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _MIN_CASH + 500.0)  # only 500 above floor

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = 1.0
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result = await cbf.verify_action("execute_trade", {"amount": 600.0})

    assert "UNSAFE" in result or "Violation" in result


# ---------------------------------------------------------------------------
# update_state — WatchError retries then succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_state_retries_on_watch_error():
    """update_state() retries on WatchError and succeeds on second attempt."""
    import warnings

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = _MIN_CASH
    cbf.gamma = _GAMMA
    cbf.tracer = None

    # Simulate a WatchError on the first attempt, then success
    attempt_count = 0

    class FakeWatchError(Exception):
        pass

    class FakePipe:
        def __init__(self):
            nonlocal attempt_count
            attempt_count += 1
            self._throw = attempt_count == 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def watch(self, key):
            pass

        async def get(self, key):
            return b"50000.0"

        def multi(self):
            pass

        def set(self, key, val):
            pass

        def rpush(self, key, val):
            pass

        async def execute(self):
            if self._throw:
                raise FakeWatchError("WatchError")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(side_effect=lambda: FakePipe())

    with patch("src.gateway.governance.cbf.redis_client", mock_redis_mod):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            await cbf.update_state(100.0)

    assert attempt_count == 2  # one retry needed


@pytest.mark.asyncio
async def test_update_state_raises_after_max_retries_exhausted():
    """update_state() raises RuntimeError after all WatchError retries fail."""
    import warnings

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    class FakeWatchError(Exception):
        pass

    class AlwaysWatchFails:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def watch(self, key):
            pass

        async def get(self, key):
            return b"50000.0"

        def multi(self):
            pass

        def set(self, key, val):
            pass

        async def execute(self):
            raise FakeWatchError("WatchError always")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=AlwaysWatchFails())

    with patch("src.gateway.governance.cbf.redis_client", mock_redis_mod):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(RuntimeError, match="retries"):
                await cbf.update_state(100.0)


@pytest.mark.asyncio
async def test_update_state_raises_when_redis_none():
    """update_state() raises RuntimeError immediately when redis_client is None."""
    import warnings

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()

    with patch("src.gateway.governance.cbf.redis_client", None):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(RuntimeError, match="Redis client unavailable"):
                await cbf.update_state(100.0)


# ---------------------------------------------------------------------------
# rollback_state — happy path and retry/exhaustion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_state_restores_balance():
    """rollback_state() adds back cost to the Redis balance."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    restored_values: list[str] = []

    class RecordingPipe:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def watch(self, key):
            pass

        async def get(self, key):
            return b"40000.0"

        def multi(self):
            pass

        def set(self, key, val):
            restored_values.append(val)

        async def execute(self):
            pass

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=RecordingPipe())

    with patch("src.gateway.governance.cbf.redis_client", mock_redis_mod):
        await cbf.rollback_state(1000.0)

    assert len(restored_values) == 1
    assert float(restored_values[0]) == pytest.approx(41_000.0)


@pytest.mark.asyncio
async def test_rollback_state_raises_when_redis_none():
    """rollback_state() raises RuntimeError when redis_client is None."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()

    with patch("src.gateway.governance.cbf.redis_client", None):
        with pytest.raises(RuntimeError, match="Redis client unavailable"):
            await cbf.rollback_state(100.0)


@pytest.mark.asyncio
async def test_rollback_state_raises_after_max_retries():
    """rollback_state() raises RuntimeError after all WatchError retries fail."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    class FakeWatchError(Exception):
        pass

    class AlwaysWatchFails:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def watch(self, key):
            pass

        async def get(self, key):
            return b"50000.0"

        def multi(self):
            pass

        def set(self, key, val):
            pass

        async def execute(self):
            raise FakeWatchError("WatchError always")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=AlwaysWatchFails())

    with patch("src.gateway.governance.cbf.redis_client", mock_redis_mod):
        with pytest.raises(RuntimeError, match="retries"):
            await cbf.rollback_state(100.0)


# ---------------------------------------------------------------------------
# _evalsha_with_noscript_retry — NOSCRIPT triggers reload and retry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evalsha_with_noscript_retry_reloads_on_noscript():
    """When evalsha raises NOSCRIPT, script is reloaded and retried once."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf._lua_sha = "some-sha"
    cbf.tracer = None

    call_count = 0

    async def _run_evalsha():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("NOSCRIPT No matching script")
        return [1, "COMMITTED", "49000.0"]

    reloaded = False

    async def _load_and_run():
        nonlocal reloaded
        reloaded = True
        return [1, "COMMITTED", "49000.0"]

    mock_client = MagicMock()
    mock_client.script_load = AsyncMock(return_value="new-sha")

    result = await cbf._evalsha_with_noscript_retry(
        mock_client, ["k1", "k2"], ["a1", "a2"], _run_evalsha, _load_and_run
    )

    assert reloaded is True
    assert result == [1, "COMMITTED", "49000.0"]


@pytest.mark.asyncio
async def test_evalsha_with_noscript_retry_reraises_non_noscript_error():
    """Non-NOSCRIPT errors from evalsha are re-raised immediately."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf._lua_sha = "some-sha"
    cbf.tracer = None

    async def _run_evalsha():
        raise RuntimeError("WRONGTYPE Operation against a key holding the wrong kind of value")

    mock_client = MagicMock()
    mock_client.script_load = AsyncMock(return_value="sha")

    with pytest.raises(RuntimeError, match="WRONGTYPE"):
        await cbf._evalsha_with_noscript_retry(
            mock_client, [], [], _run_evalsha, AsyncMock()
        )


# ---------------------------------------------------------------------------
# _parse_lua_result — bytes vs string variants
# ---------------------------------------------------------------------------


def test_parse_lua_result_committed_with_bytes():
    """_parse_lua_result handles bytes in result_list[1] and result_list[2]."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    committed, msg = cbf._parse_lua_result(
        [1, b"COMMITTED", b"49000.0"], None
    )

    assert committed is True
    assert msg == "COMMITTED"


def test_parse_lua_result_unsafe_with_strings():
    """_parse_lua_result handles plain strings and returns (False, reason)."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    committed, msg = cbf._parse_lua_result(
        [0, "UNSAFE: h_next=-500 < required=0", "50000.0"], None
    )

    assert committed is False
    assert "UNSAFE" in msg


# ---------------------------------------------------------------------------
# reset_local_debits — accumulator cleared to zero
# ---------------------------------------------------------------------------


def test_reset_local_debits_clears_accumulator():
    """reset_local_debits() sets _local_debits back to 0.0."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf._local_debits = 5000.0

    cbf.reset_local_debits()

    assert cbf._local_debits == 0.0


# ---------------------------------------------------------------------------
# get_h — barrier certificate value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "balance, min_cash, expected_h",
    [
        (50_000.0, 10_000.0, 40_000.0),
        (10_000.0, 10_000.0, 0.0),   # exactly at floor → h=0 (safe boundary)
        (9_999.0, 10_000.0, -1.0),   # below floor → h<0 (unsafe)
    ],
)
def test_get_h_returns_correct_barrier_value(balance, min_cash, expected_h):
    """get_h(x) = x - min_cash_balance."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = min_cash

    assert cbf.get_h(balance) == pytest.approx(expected_h)


# ---------------------------------------------------------------------------
# atomic_verify_and_commit — redis_client None raises RuntimeError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_atomic_verify_and_commit_raises_when_redis_none():
    """atomic_verify_and_commit raises RuntimeError when redis_client is None."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    with patch("src.gateway.governance.cbf.redis_client", None):
        with pytest.raises(RuntimeError, match="Redis client unavailable"):
            await cbf.atomic_verify_and_commit("execute_trade", {"amount": 100.0})


# ---------------------------------------------------------------------------
# local_debits accumulation — double-spend prevention within TTL window
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_accumulates_local_debits():
    """Approved trades accumulate in _local_debits for intra-window protection."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, 30_000.0)

    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction()
    cbf.min_cash_balance = 0.0
    cbf.gamma = 1.0  # required_h_next = 0
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.cbf.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.cbf.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result1 = await cbf.verify_action("execute_trade", {"amount": 10_000.0})
        assert result1 == "SAFE"
        assert cbf._local_debits == pytest.approx(10_000.0)

        result2 = await cbf.verify_action("execute_trade", {"amount": 10_000.0})
        assert result2 == "SAFE"
        assert cbf._local_debits == pytest.approx(20_000.0)
