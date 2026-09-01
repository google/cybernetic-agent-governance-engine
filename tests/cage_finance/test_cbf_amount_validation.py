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
Regression tests: the CBF barrier must reject a non-finite or negative trade
``amount`` instead of treating it as SAFE.

A negative ``amount`` makes ``next_cash = current - cost`` larger than the
current balance, so the ``h_next >= (1-gamma)*h_t`` envelope check passes and
``atomic_verify_and_commit`` writes the inflated balance back to Redis; a NaN
``amount`` makes every comparison false, so the barrier also passes. Both let
attacker-supplied trade parameters defeat the cash barrier. FiscalLimitGuard.reserve
already applies the same finiteness/positive guard to reservations.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required for CBF state tests")

import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

_INVALID_AMOUNTS = [-1_000_000.0, float("nan"), float("inf"), float("-inf")]


@pytest.mark.local
@pytest.mark.asyncio
async def test_do_verify_action_rejects_invalid_amount() -> None:
    """The read-only barrier returns a non-SAFE result for negative / NaN / inf
    amounts, and still returns SAFE for a valid positive trade."""
    cbf = ControlBarrierFunction()

    for amount in _INVALID_AMOUNTS:
        result = await cbf._do_verify_action(
            "execute_trade",
            {"amount": amount},
            current_cash=100_000.0,
            balance_source="self_reported",
            span=None,
        )
        assert result != "SAFE", (
            f"amount={amount!r} must be rejected by the barrier; got SAFE "
            "(negative/NaN amount bypasses the CBF envelope check)"
        )

    ok = await cbf._do_verify_action(
        "execute_trade",
        {"amount": 1_000.0},
        current_cash=100_000.0,
        balance_source="self_reported",
        span=None,
    )
    assert ok == "SAFE", f"a valid positive trade must still pass; got {ok!r}"


@pytest.mark.local
@pytest.mark.asyncio
async def test_atomic_verify_rejects_invalid_amount_without_mutating_balance() -> None:
    """The atomic check+commit rejects an invalid amount and leaves the persisted
    cash balance untouched — a negative amount must not inflate it."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    await fake_redis.set("safety:current_cash", "100000.0")

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    mock_redis_module = MagicMock()
    mock_redis_module.get_raw_client.return_value = fake_redis

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(
            "src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_module
        )

        for amount in _INVALID_AMOUNTS:
            committed, reason = await cbf.atomic_verify_and_commit(
                action_name="execute_trade",
                payload={"amount": amount},
            )
            assert committed is False, (
                f"amount={amount!r} must not commit; got committed=True"
            )
            assert "UNSAFE" in reason, f"reason must flag UNSAFE; got {reason!r}"
            balance = (await fake_redis.get("safety:current_cash")).decode()
            assert float(balance) == 100_000.0, (
                f"balance must stay 100000.0 after rejecting amount={amount!r}; "
                f"got {balance} (negative amount inflated the persisted balance)"
            )

        # A valid trade still commits and debits the balance.
        committed, reason = await cbf.atomic_verify_and_commit(
            action_name="execute_trade",
            payload={"amount": 1_000.0},
        )
        assert committed is True, f"valid trade must commit; got reason={reason!r}"
        balance = (await fake_redis.get("safety:current_cash")).decode()
        assert float(balance) == 99_000.0, (
            f"balance must debit to 99000.0; got {balance}"
        )
