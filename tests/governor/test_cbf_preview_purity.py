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

"""PREVIEW_IS_PURE for the real CBF engine (plan F-8).

``preview()`` on a barrier tier calls ``ControlBarrierFunction.verify_action``.
It used to add every SAFE cost to an in-process ``_local_debits`` accumulator
that nothing ever reset, so a pending-approval preview drifted the barrier in
memory even though Redis stayed untouched. These tests run the real engine on
fakeredis (real Lua) and assert both halves: previews change nothing — not
the engine's attributes, not one Redis key — and one commit changes the
state exactly once.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

fakeredis = pytest.importorskip("fakeredis")
import fakeredis.aioredis  # noqa: E402  (after importorskip)

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver  # noqa: E402
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin  # noqa: E402
from src.gateway.governance.governor.pipeline import (  # noqa: E402
    BarrierPreview,
    Profile,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope  # noqa: E402
from src.gateway.governance.governor.stages.domain_tiers import order_stages  # noqa: E402
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CASH_KEY = "safety:current_cash"
_BALANCE = 30_000.0
_TRADE = {"amount": 10_000.0, "symbol": "AAPL", "agent_id": "agent-1"}
_PREVIEWS = 5  # an accumulating preview would refuse from the 3rd on ($30k / $10k)


def _engine() -> ControlBarrierFunction:
    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.threshold_value = 0.0
    cbf.gamma = 1.0  # constraint is h_next >= 0 only
    cbf.tracer = None
    return cbf


async def _redis_image(client: Any) -> dict[str, Any]:
    """Every key and its full value, so any write at all shows up as a diff."""
    image: dict[str, Any] = {}
    for key in sorted(await client.keys("*")):
        kind = await client.type(key)
        kind = kind.decode() if isinstance(kind, bytes) else kind
        if kind == "string":
            image[key] = await client.get(key)
        elif kind == "list":
            image[key] = await client.lrange(key, 0, -1)
        elif kind == "zset":
            image[key] = await client.zrange(key, 0, -1, withscores=True)
        elif kind == "hash":
            image[key] = await client.hgetall(key)
        elif kind == "set":
            image[key] = sorted(await client.smembers(key))
        else:  # pragma: no cover - unexpected type is itself a finding
            image[key] = f"<{kind}>"
    return image


@pytest.fixture
async def redis() -> Any:
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await client.set(_CASH_KEY, str(_BALANCE))
    module = MagicMock()
    module.get_raw_client = MagicMock(return_value=client)
    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", module),
        # No reconciled snapshot: the engine reads the self-reported balance.
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
            AsyncMock(return_value=None),
        ),
    ):
        yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_n_previews_leave_engine_and_redis_byte_identical(redis: Any) -> None:
    cbf = _engine()
    engine_before = dict(vars(cbf))
    redis_before = await _redis_image(redis)

    verdicts = [await cbf.verify_action("execute_trade", _TRADE) for _ in range(_PREVIEWS)]
    bound = await cbf.admissible_cost()

    assert verdicts == ["SAFE"] * _PREVIEWS
    assert bound == pytest.approx(_BALANCE)
    assert dict(vars(cbf)) == engine_before
    assert await _redis_image(redis) == redis_before


@pytest.mark.asyncio
async def test_one_commit_changes_state_exactly_once(redis: Any) -> None:
    cbf = _engine()
    for _ in range(_PREVIEWS):
        assert await cbf.verify_action("execute_trade", _TRADE) == "SAFE"

    committed, reason, magnitude = await cbf.atomic_verify_and_commit("execute_trade", _TRADE)

    assert (committed, magnitude) == (True, 10_000.0), reason
    assert float(await redis.get(_CASH_KEY)) == pytest.approx(_BALANCE - 10_000.0)
    # Previews after the commit see the committed balance, and only it.
    assert await cbf.admissible_cost() == pytest.approx(_BALANCE - 10_000.0)
    image = await _redis_image(redis)
    for _ in range(_PREVIEWS):
        assert await cbf.verify_action("execute_trade", _TRADE) == "SAFE"
    assert await _redis_image(redis) == image


@pytest.mark.asyncio
async def test_pending_approval_previews_through_the_pipeline_change_nothing(redis: Any) -> None:
    """The path a REQUIRE_APPROVAL takes: DRY_RUN previews of the cbf tier."""
    cbf = _engine()
    stages = order_stages([CBFTierPlugin(cbf)])
    engine_before = dict(vars(cbf))
    redis_before = await _redis_image(redis)

    for _ in range(_PREVIEWS):
        ctx = StageContext(action="execute_trade", params=_TRADE, profile=Profile.DRY_RUN)
        result = await run_pipeline(stages, ctx, profile=Profile.DRY_RUN)
        assert result.violations == ()
        assert result.barrier_preview is BarrierPreview.PASS

    assert dict(vars(cbf)) == engine_before
    assert await _redis_image(redis) == redis_before


@pytest.mark.asyncio
async def test_committing_run_still_debits_once_after_previews(redis: Any) -> None:
    """Guard against over-correction: the commit path must still spend headroom."""
    cbf = _engine()
    stages = order_stages([CBFTierPlugin(cbf)])
    for _ in range(_PREVIEWS):
        ctx = StageContext(action="execute_trade", params=_TRADE, profile=Profile.DRY_RUN)
        await run_pipeline(stages, ctx, profile=Profile.DRY_RUN)

    async with ReservationScope() as scope:
        ctx = StageContext(action="execute_trade", params=_TRADE, profile=Profile.FULL)
        result = await run_pipeline(stages, ctx, profile=Profile.FULL, scope=scope)
        scope.seal_issued("test-seal")

    assert result.committed_stages == ("cbf",)
    assert result.barrier_outcome is BarrierPreview.PASS
    assert float(await redis.get(_CASH_KEY)) == pytest.approx(_BALANCE - 10_000.0)
