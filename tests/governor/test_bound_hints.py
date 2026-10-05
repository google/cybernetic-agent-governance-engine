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

"""Phase-2 tiers say how much they would admit (``Violation.bound``).

The bound is a hint for narrowers and reviewers, never an authorization, so
the property that matters is that it is never *invented*: an unreadable
state yields ``None``, not a full cap. Each fail-closed path is observed.
"""

from typing import Any
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.safety.barrier_tier import commit_barrier, preview_barrier
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

pytestmark = [pytest.mark.unit, pytest.mark.local]

CAP = 1_000.0


# ── Fiscal: bound = remaining daily headroom ───────────────────────────────


async def _fiscal(spent: float = 0.0) -> tuple[FiscalTierPlugin, FiscalLimitGuard]:
    guard = FiscalLimitGuard(
        fakeredis.aioredis.FakeRedis(decode_responses=True), daily_cap_usd=CAP
    )
    if spent:
        await guard.reserve(agent_id="other-desk", amount_usd=spent)
    return FiscalTierPlugin(guard), guard


async def test_fiscal_preview_reports_the_remaining_headroom_as_bound() -> None:
    tier, _ = await _fiscal(spent=950.0)
    [violation] = await tier.evaluate("execute_trade", {"amount": 100.0})
    assert (violation.code, violation.kind, violation.bound) == (
        "FISCAL_LIMIT_EXCEEDED",
        ViolationKind.NARROWABLE,
        50.0,
    )


async def test_fiscal_commit_refusal_reports_the_same_bound_and_reserves_nothing() -> (
    None
):
    tier, guard = await _fiscal(spent=950.0)
    violations, receipt = await tier.commit("execute_trade", {"amount": 100.0})
    assert receipt is None
    assert [v.bound for v in violations] == [50.0]
    assert await guard.current_spend_usd() == 950.0


async def test_fiscal_bound_is_zero_when_the_cap_is_exhausted() -> None:
    tier, _ = await _fiscal(spent=CAP)
    [violation] = await tier.evaluate("execute_trade", {"amount": 1.0})
    assert violation.bound == 0.0


async def test_fiscal_bound_is_unknown_when_the_window_is_unreadable() -> None:
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    guard = FiscalLimitGuard(redis, daily_cap_usd=CAP)
    redis.get = AsyncMock(side_effect=ConnectionError("redis down"))  # type: ignore[method-assign]

    assert await guard.headroom_usd() is None
    assert await guard.remaining_usd() == CAP  # the reporting helper fails open...
    [violation] = await FiscalTierPlugin(guard).evaluate(
        "execute_trade", {"amount": 1.0}
    )
    assert violation.bound is None  # ...the bound never does


# ── Barrier tiers: bound = the engine's admissible cost ────────────────────


class _Engine:
    def __init__(self, verdict: str = "UNSAFE", bound: Any = 25.0) -> None:
        self.verdict, self.bound = verdict, bound

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        return self.verdict

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
        *,
        debit_id: str | None = None,
    ) -> tuple[bool, str, float]:
        return False, self.verdict, 0.0

    async def rollback_state(
        self,
        magnitude: float,
        governance_signature: str | None = None,
        *,
        debit_id: str | None = None,
    ) -> None:
        return None

    async def admissible_cost(self) -> Any:
        if isinstance(self.bound, Exception):
            raise self.bound
        return self.bound


class _UnboundedEngine(_Engine):
    admissible_cost = None  # type: ignore[assignment]  # an engine that cannot say


async def _refusals(engine: Any) -> list[Any]:
    preview = await preview_barrier(
        engine, tier="cbf", code="CBF_X", action="a", params={}
    )
    committed, _ = await commit_barrier(
        engine, tier="cbf", code="CBF_X", action="a", params={}
    )
    return [*preview, *committed]


async def test_barrier_refusals_carry_the_engine_bound_and_stay_hard() -> None:
    refusals = await _refusals(_Engine(bound=25.0))
    assert [(v.kind, v.bound) for v in refusals] == [(ViolationKind.HARD, 25.0)] * 2


@pytest.mark.parametrize(
    "engine",
    [
        _Engine(bound=ConnectionError("redis down")),
        _Engine(bound=None),
        _Engine(bound=float("nan")),
        _Engine(bound=-1.0),
        _Engine(bound=True),
        _Engine(bound="25"),
        _UnboundedEngine(),
    ],
    ids=["raises", "none", "nan", "negative", "bool", "str", "no-method"],
)
async def test_barrier_bound_is_never_guessed(engine: Any) -> None:
    refusals = await _refusals(engine)
    assert [(v.kind, v.bound) for v in refusals] == [(ViolationKind.HARD, None)] * 2


async def test_safe_barrier_reads_no_bound() -> None:
    engine = _Engine(verdict="SAFE", bound=ConnectionError("must not be read"))
    assert (
        await preview_barrier(engine, tier="cbf", code="CBF_X", action="a", params={})
        == []
    )


# ── Kernel CBF: admissible_cost is exactly verify_action's boundary ────────


def _cbf(
    monkeypatch: pytest.MonkeyPatch,
    cash: float | None,
    *,
    gamma: float,
    floor: float,
    source: str = "redis",
) -> ControlBarrierFunction:
    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.threshold_value = floor
    cbf.gamma = gamma
    state = {"current_cash": cash, "source": source, "fence_epoch": 0}
    monkeypatch.setattr(cbf, "_read_cbf_state_atomic", AsyncMock(return_value=state))
    return cbf


@pytest.mark.parametrize(
    ("gamma", "floor", "expected"), [(1.0, 0.0, 1_000.0), (0.5, 200.0, 400.0)]
)
async def test_admissible_cost_is_the_barrier_boundary(
    monkeypatch: pytest.MonkeyPatch, gamma: float, floor: float, expected: float
) -> None:
    cbf = _cbf(monkeypatch, 1_000.0, gamma=gamma, floor=floor)
    bound = await cbf.admissible_cost()
    assert bound == pytest.approx(expected)
    # One cent over is refused; exactly the bound is admitted (checked in that
    # order: a SAFE verify_action accrues a local debit).
    assert (
        await cbf.verify_action("execute_trade", {"amount": bound + 0.01})
    ) != "SAFE"
    assert (await cbf.verify_action("execute_trade", {"amount": bound})) == "SAFE"


async def test_admissible_cost_is_zero_below_the_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        await _cbf(monkeypatch, 100.0, gamma=0.5, floor=200.0).admissible_cost() == 0.0
    )


@pytest.mark.parametrize(
    ("cash", "source"), [(None, "redis"), (1_000.0, "epoch_regression")]
)
async def test_admissible_cost_is_unknown_without_trusted_state(
    monkeypatch: pytest.MonkeyPatch, cash: float | None, source: str
) -> None:
    assert (
        await _cbf(
            monkeypatch, cash, gamma=1.0, floor=0.0, source=source
        ).admissible_cost()
        is None
    )


async def test_cbf_tier_refusal_carries_the_kernel_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cbf = _cbf(monkeypatch, 1_000.0, gamma=1.0, floor=0.0)
    [violation] = await CBFTierPlugin(cbf).evaluate(
        "execute_trade", {"amount": 5_000.0}
    )
    assert (violation.code, violation.kind, violation.bound) == (
        "CBF_BARRIER_VIOLATED",
        ViolationKind.HARD,
        1_000.0,
    )


@pytest.mark.parametrize(
    "headroom",
    [
        AsyncMock(side_effect=RuntimeError("boom")),
        AsyncMock(return_value="lots"),
        AsyncMock(return_value=float("nan")),
    ],
    ids=["raises", "str", "nan"],
)
async def test_a_broken_headroom_read_leaves_the_refusal_narrowable_without_a_bound(
    headroom: AsyncMock,
) -> None:
    tier, guard = await _fiscal(spent=CAP)
    guard.headroom_usd = headroom  # type: ignore[method-assign]
    [violation] = await tier.evaluate("execute_trade", {"amount": 1.0})
    assert (violation.kind, violation.bound) == (ViolationKind.NARROWABLE, None)
