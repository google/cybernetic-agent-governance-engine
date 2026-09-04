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
_MIN_CASH = 1_000.0
_GAMMA = 0.9


def _make_cbf(fake_redis: fakeredis.aioredis.FakeRedis):
    """Return a CBF wired to *fake_redis* with deterministic thresholds."""
    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # W1 (Post-v3): Mandatory invariant with custom gamma
    invariant = replace(CashBarrier(), gamma=_GAMMA)

    # B3a: Use skip_epoch_seed=True to avoid Redis seeding in tests
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    # Remove post-instantiation mutation - CBF is now immutable
    cbf.tracer = None  # suppress OTel span creation

    mock_redis_module = AsyncMock()
    mock_redis_module.get_raw_client = MagicMock(return_value=fake_redis)
    mock_redis_module.get = AsyncMock(side_effect=lambda key: fake_redis.get(key))
    mock_redis_module.get_float = AsyncMock(
        side_effect=lambda key, default: (
            asyncio.get_event_loop().run_until_complete(
                _async_get_float(fake_redis, key, default)
            )
            if False
            else None
        )  # never used; real calls go through get_raw_client
    )
    mock_redis_module.set = AsyncMock(
        side_effect=lambda key, val: fake_redis.set(key, val)
    )
    mock_redis_module.pipeline = fake_redis.pipeline

    return cbf, mock_redis_module


async def _async_get_float(
    r: fakeredis.aioredis.FakeRedis, key: str, default: float
) -> float:
    raw = await r.get(key)
    return float(raw) if raw is not None else default


async def _seed_balance(
    fake_redis: fakeredis.aioredis.FakeRedis, balance: float
) -> None:
    await fake_redis.set("safety:current_cash", str(balance))


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path 1: KMS-signed reconciled balance (valid sig)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_uses_reconciled_balance_when_kms_valid(make_cbf):
    """When reconciled balance has a valid KMS signature, source='reconciled'."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

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
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
async def test_read_cbf_state_falls_back_when_kms_sig_invalid(make_cbf):
    """When KMS signature is invalid, falls back to self-reported balance."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

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
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
async def test_read_cbf_state_falls_back_when_kms_verify_raises(make_cbf):
    """When KMS.verify() raises, falls back to self-reported balance."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

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
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
async def test_read_cbf_state_accepts_unsigned_balance_in_dev_mode(make_cbf):
    """In dev/ci mode, an unsigned reconciled balance is accepted."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = None  # no KMS signature
    verified.balance_usd = 77_000.0
    verified.source = "stub"
    verified.verified_at = 1_700_000_000.0

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", False
        ),  # dev mode
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
async def test_read_cbf_state_rejects_unsigned_balance_in_production(make_cbf):
    """In production, an unsigned reconciled balance is rejected → self-reported."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

    verified = MagicMock()
    verified.is_valid = True
    verified.signature = None  # no KMS signature
    verified.balance_usd = 77_000.0
    verified.source = "stub"
    verified.verified_at = 1_700_000_000.0

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True
        ),  # production
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported"


# ---------------------------------------------------------------------------
# _read_cbf_state_atomic — Path: reconciliation read raises exception
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_cbf_state_falls_back_when_reconciliation_raises(make_cbf):
    """When asyncio.to_thread(read_verified_balance) raises, falls back to self-reported."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, _SAFE_BALANCE)

    # Use make_cbf fixture factory
    cbf, _ = make_cbf(gamma=_GAMMA)

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
async def test_read_cbf_state_raises_when_redis_unavailable(make_cbf):
    """_read_cbf_state_atomic raises RuntimeError when redis_client is None."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", None):
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

    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Create CBF with gamma=0.9 immutably
    invariant = replace(CashBarrier(), gamma=0.9)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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

    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Create CBF with gamma=0.9 immutably
    invariant = replace(CashBarrier(), gamma=0.9)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    # Patch THRESHOLDS so drawdown limit is 5%
    mock_thresholds = MagicMock()
    mock_thresholds.drawdown.limit = 0.05

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch("src.gateway.governance.safety.cbf_engine.THRESHOLDS", mock_thresholds),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result = await cbf.verify_action(
            "execute_trade",
            {"amount": 100.0, "drawdown_pct": 10.0},  # 10% > 5% limit
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

    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Create CBF with gamma=1.0 immutably (required_h_next = 0)
    invariant = replace(CashBarrier(), gamma=1.0)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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

    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Create CBF with gamma=1.0 immutably
    invariant = replace(CashBarrier(), gamma=1.0)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
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
    from dataclasses import replace

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Create CBF with gamma immutably
    invariant = replace(CashBarrier(), gamma=_GAMMA)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
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

        def incr(self, key):
            pass

        def rpush(self, key, val):
            pass

        async def execute(self):
            if self._throw:
                raise FakeWatchError("WatchError")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(side_effect=lambda: FakePipe())

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            await cbf._update_state_unsafe(100.0)

    assert attempt_count == 2  # one retry needed


@pytest.mark.asyncio
async def test_update_state_raises_after_max_retries_exhausted(make_cbf):
    """update_state() raises RuntimeError after all WatchError retries fail."""
    import warnings

    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

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

        def incr(self, key):
            pass

        async def execute(self):
            raise FakeWatchError("WatchError always")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=AlwaysWatchFails())

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(RuntimeError, match="retries"):
                await cbf._update_state_unsafe(100.0)


@pytest.mark.asyncio
async def test_update_state_raises_when_redis_none(make_cbf):
    """update_state() raises RuntimeError immediately when redis_client is None."""
    import warnings

    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", None):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(RuntimeError, match="Redis client unavailable"):
                await cbf._update_state_unsafe(100.0)


# ---------------------------------------------------------------------------
# rollback_state — happy path and retry/exhaustion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_state_restores_balance(make_cbf):
    """rollback_state() adds back cost to the Redis balance."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

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

        def incr(self, key):
            pass

        async def execute(self):
            return [None, 1]  # [set result, incr result]

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=RecordingPipe())

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod):
        await cbf.rollback_state(1000.0)

    assert len(restored_values) == 1
    assert float(restored_values[0]) == pytest.approx(41_000.0)


@pytest.mark.asyncio
async def test_rollback_state_raises_when_redis_none(make_cbf):
    """rollback_state() raises RuntimeError when redis_client is None."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", None):
        with pytest.raises(RuntimeError, match="Redis client unavailable"):
            await cbf.rollback_state(100.0)


@pytest.mark.asyncio
async def test_rollback_state_raises_after_max_retries(make_cbf):
    """rollback_state() raises RuntimeError after all WatchError retries fail."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

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

        def incr(self, key):
            pass

        async def execute(self):
            raise FakeWatchError("WatchError always")

    mock_redis_mod = MagicMock()
    mock_redis_mod.pipeline = MagicMock(return_value=AlwaysWatchFails())

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod):
        with pytest.raises(RuntimeError, match="retries"):
            await cbf.rollback_state(100.0)


# ---------------------------------------------------------------------------
# _evalsha_with_noscript_retry — NOSCRIPT triggers reload and retry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evalsha_with_noscript_retry_reloads_on_noscript(make_cbf):
    """When evalsha raises NOSCRIPT, script is reloaded and retried once."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()
    cbf._lua_sha = "some-sha"

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
async def test_evalsha_with_noscript_retry_reraises_non_noscript_error(make_cbf):
    """Non-NOSCRIPT errors from evalsha are re-raised immediately."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()
    cbf._lua_sha = "some-sha"

    async def _run_evalsha():
        raise RuntimeError(
            "WRONGTYPE Operation against a key holding the wrong kind of value"
        )

    mock_client = MagicMock()
    mock_client.script_load = AsyncMock(return_value="sha")

    with pytest.raises(RuntimeError, match="WRONGTYPE"):
        await cbf._evalsha_with_noscript_retry(
            mock_client, [], [], _run_evalsha, AsyncMock()
        )


# ---------------------------------------------------------------------------
# _parse_lua_result — bytes vs string variants
# ---------------------------------------------------------------------------


def test_parse_lua_result_committed_with_bytes(make_cbf):
    """_parse_lua_result handles bytes in result_list[1] and result_list[2]."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

    committed, msg = cbf._parse_lua_result([1, b"COMMITTED", b"49000.0"], None)

    assert committed is True
    assert msg == "COMMITTED"


def test_parse_lua_result_unsafe_with_strings(make_cbf):
    """_parse_lua_result handles plain strings and returns (False, reason)."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

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
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf._local_debits = 5000.0

    cbf.reset_local_debits()

    assert cbf._local_debits == 0.0


# ---------------------------------------------------------------------------
# get_h — barrier certificate value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "balance, min_cash, expected_h",
    [
        (50_000.0, 1_000.0, 49_000.0),
        (1_000.0, 1_000.0, 0.0),  # exactly at floor → h=0 (safe boundary)
        (999.0, 1_000.0, -1.0),  # below floor → h<0 (unsafe)
    ],
)
def test_get_h_returns_correct_barrier_value(balance, min_cash, expected_h):
    """get_h(x) = x - min_cash_balance."""
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Note: This test validates the get_h() formula itself
    # The formula is get_h(x) = x - min_cash_balance
    # CBF is now immutable so we can't set min_cash_balance post-init
    # However, get_h() doesn't depend on the invariant's config, it just does the math
    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )

    # get_h(balance) with the CBF's current min_cash_balance (default 10000.0)
    # This test expects: get_h(balance) = balance - min_cash
    assert cbf.get_h(balance) == pytest.approx(balance - min_cash)


# ---------------------------------------------------------------------------
# atomic_verify_and_commit — redis_client None raises RuntimeError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_atomic_verify_and_commit_raises_when_redis_none(make_cbf):
    """atomic_verify_and_commit raises RuntimeError when redis_client is None."""
    # Use make_cbf fixture factory
    cbf, _ = make_cbf()

    with patch("src.gateway.governance.safety.cbf_engine.redis_client", None):
        with pytest.raises(RuntimeError, match="Redis client unavailable"):
            await cbf.atomic_verify_and_commit("execute_trade", {"amount": 100.0})


# ---------------------------------------------------------------------------
# local_debits accumulation — double-spend prevention within TTL window
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_action_accumulates_local_debits(make_cbf):
    """Approved trades accumulate in _local_debits for intra-window protection."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await _seed_balance(fake_redis, 30_000.0)

    # Use make_cbf fixture factory with gamma=1.0
    cbf, _ = make_cbf(gamma=1.0)

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        result1 = await cbf.verify_action("execute_trade", {"amount": 10_000.0})
        assert result1 == "SAFE"
        assert cbf._local_debits == pytest.approx(10_000.0)

        result2 = await cbf.verify_action("execute_trade", {"amount": 10_000.0})
        assert result2 == "SAFE"
        assert cbf._local_debits == pytest.approx(20_000.0)


# ---------------------------------------------------------------------------
# B3a: Fence epoch cold-start seeding — fail-closed tests
# ---------------------------------------------------------------------------


class TestFenceEpochColdStartFailClosed:
    """Tests for B3a: fail-closed behavior when Redis is unavailable at init."""

    def test_cbf_raises_initialization_error_when_redis_unavailable_in_production(self):
        """B3a: CBF must raise CBFInitializationError in production when Redis unavailable."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        with (
            patch("src.gateway.governance.safety.cbf_engine.sync_redis_client", None),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction(
                    invariant=CashBarrier(),
                    cost_resolver=finance_cost_resolver,
                )

        # Verify error message contains security context
        error_msg = str(exc_info.value)
        assert "sync Redis client unavailable" in error_msg
        assert "Failing closed" in error_msg

    def test_cbf_raises_initialization_error_on_redis_connection_error_in_production(
        self,
    ):
        """B3a: Redis connection errors in production raise CBFInitializationError."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(
            side_effect=ConnectionError("Connection refused to redis:6379")
        )

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                mock_sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction(
                    invariant=CashBarrier(),
                    cost_resolver=finance_cost_resolver,
                )

        error_msg = str(exc_info.value)
        assert "fence epoch unavailable from Redis" in error_msg
        assert "Connection refused" in error_msg

    def test_cbf_raises_initialization_error_on_redis_timeout_in_production(self):
        """B3a: Redis timeout errors in production raise CBFInitializationError."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(side_effect=TimeoutError("Redis read timeout"))

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                mock_sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction(
                    invariant=CashBarrier(),
                    cost_resolver=finance_cost_resolver,
                )

        error_msg = str(exc_info.value)
        assert "Redis read timeout" in error_msg

    def test_cbf_falls_back_gracefully_in_dev_mode(self):
        """B3a: In dev/test mode, Redis unavailability logs warning but proceeds."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(
            side_effect=ConnectionError("Redis not available")
        )

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                mock_sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", False),
            patch("src.gateway.governance.safety.cbf_engine.logger") as mock_logger,
        ):
            cbf = ControlBarrierFunction(
                invariant=CashBarrier(),
                cost_resolver=finance_cost_resolver,
            )

        # Should proceed with epoch=0
        assert cbf._last_seen_epoch == 0
        # Should log a warning
        mock_logger.warning.assert_called()

    def test_cbf_initialization_error_is_runtime_error_subclass(self):
        """B3a: CBFInitializationError is a RuntimeError subclass for clean propagation."""
        from src.gateway.governance.safety.cbf_engine import CBFInitializationError

        assert issubclass(CBFInitializationError, RuntimeError)

        exc = CBFInitializationError("test")
        assert isinstance(exc, RuntimeError)
        assert isinstance(exc, CBFInitializationError)

    def test_cbf_skip_epoch_seed_bypasses_all_redis_calls(self):
        """B3a: skip_epoch_seed=True completely bypasses Redis for testing."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock()

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                mock_sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True),
        ):
            from src.cage_finance.invariants import CashBarrier, finance_cost_resolver

            cbf = ControlBarrierFunction(
                invariant=CashBarrier(),
                cost_resolver=finance_cost_resolver,
                skip_epoch_seed=True,
            )

        # Should not have called Redis
        mock_sync_redis.get.assert_not_called()
        assert cbf._last_seen_epoch == 0

    def test_cbf_initialization_error_preserves_original_exception(self):
        """B3a: CBFInitializationError preserves the original exception chain."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        original_error = ConnectionError("Original network error")
        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(side_effect=original_error)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                mock_sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction(
                    invariant=CashBarrier(),
                    cost_resolver=finance_cost_resolver,
                )

        # Check that __cause__ is set (from the "from exc" clause)
        assert exc_info.value.__cause__ is original_error


# ---------------------------------------------------------------------------
# P0 Hardening: Strict Replication (WAIT fail-closed) tests
# ---------------------------------------------------------------------------


class TestStrictReplicationFailClosed:
    """P0 security hardening tests for CAGE_STRICT_REPLICATION=true behavior.

    When strict replication is enabled and the Redis WAIT command times out,
    the CBF must fail-closed by rolling back the committed state rather than
    allowing the action to proceed with unconfirmed replication.
    """

    @pytest.mark.asyncio
    async def test_wait_timeout_triggers_rollback_in_strict_mode(self):
        """P0: WAIT timeout with CAGE_STRICT_REPLICATION=true triggers rollback."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await _seed_balance(fake_redis, _SAFE_BALANCE)

        cbf, mock_redis_module = _make_cbf(fake_redis)

        # Mock _sync_to_replicas to return False (WAIT timeout)
        cbf._sync_to_replicas = AsyncMock(return_value=False)

        # Mock rollback_state to track calls
        cbf.rollback_state = AsyncMock()

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                mock_redis_module,
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True
            ),
        ):
            # Small trade that would normally succeed
            result = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": 1000, "asset": "AAPL"},
                governance_signature="test-sig",
            )

        # Should fail with REPLICATION_UNCONFIRMED
        assert result[0] is False
        assert "REPLICATION_UNCONFIRMED" in result[1]
        assert "Failed closed" in result[1]

        # Rollback should have been called
        cbf.rollback_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_wait_timeout_logs_warning_when_strict_mode_disabled(self):
        """P0: WAIT timeout without strict mode only logs warning, does not rollback."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await _seed_balance(fake_redis, _SAFE_BALANCE)

        cbf, mock_redis_module = _make_cbf(fake_redis)

        # Mock _sync_to_replicas to return False (WAIT timeout)
        cbf._sync_to_replicas = AsyncMock(return_value=False)

        # Mock rollback_state to track calls
        cbf.rollback_state = AsyncMock()

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                mock_redis_module,
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch(
                "src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", False
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True
            ),
            patch("src.gateway.governance.safety.cbf_engine.logger") as mock_logger,
        ):
            result = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": 1000, "asset": "AAPL"},
                governance_signature="test-sig",
            )

        # Should still succeed (legacy behavior)
        assert result[0] is True
        assert result[1] == "COMMITTED"

        # Rollback should NOT have been called
        cbf.rollback_state.assert_not_called()

        # Warning should have been logged
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_wait_success_does_not_trigger_rollback(self):
        """P0: Successful WAIT does not trigger rollback even in strict mode."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await _seed_balance(fake_redis, _SAFE_BALANCE)

        cbf, mock_redis_module = _make_cbf(fake_redis)

        # Mock _sync_to_replicas to return True (WAIT succeeded)
        cbf._sync_to_replicas = AsyncMock(return_value=True)

        # Mock rollback_state to track calls
        cbf.rollback_state = AsyncMock()

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                mock_redis_module,
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True
            ),
        ):
            result = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": 1000, "asset": "AAPL"},
                governance_signature="test-sig",
            )

        # Should succeed
        assert result[0] is True
        assert result[1] == "COMMITTED"

        # Rollback should NOT have been called
        cbf.rollback_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_strict_replication_requires_fence_epoch_enabled(self):
        """P0: Strict replication rollback only triggers when fence epoch is enabled."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await _seed_balance(fake_redis, _SAFE_BALANCE)

        cbf, mock_redis_module = _make_cbf(fake_redis)

        # Mock _sync_to_replicas to return False (WAIT timeout)
        cbf._sync_to_replicas = AsyncMock(return_value=False)

        # Mock rollback_state to track calls
        cbf.rollback_state = AsyncMock()

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                mock_redis_module,
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", False
            ),  # Disabled
        ):
            result = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": 1000, "asset": "AAPL"},
                governance_signature="test-sig",
            )

        # Should still succeed (fence epoch disabled = no strict replication)
        assert result[0] is True
        assert result[1] == "COMMITTED"

        # Rollback should NOT have been called
        cbf.rollback_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_wait_replicas_skips_replication_check(self):
        """P0: When CAGE_REDIS_WAIT_REPLICAS=0, no replication check occurs."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await _seed_balance(fake_redis, _SAFE_BALANCE)

        cbf, mock_redis_module = _make_cbf(fake_redis)

        # Mock _sync_to_replicas - should never be called
        cbf._sync_to_replicas = AsyncMock(return_value=False)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                mock_redis_module,
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0
            ),  # Disabled
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True
            ),
        ):
            result = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": 1000, "asset": "AAPL"},
                governance_signature="test-sig",
            )

        # Should succeed
        assert result[0] is True
        assert result[1] == "COMMITTED"

        # _sync_to_replicas should NOT have been called
        cbf._sync_to_replicas.assert_not_called()
