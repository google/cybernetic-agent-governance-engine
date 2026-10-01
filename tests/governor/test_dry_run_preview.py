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

"""DRY_RUN must predict live refusals without mutating any state.

``verify()`` is what agents and the /verify endpoint use to preview a
decision.  An optimistic ALLOW for an action live execution would DENY is a
fail-open prediction, so each test here asserts both halves: the refusal is
reported, and nothing is committed or reserved.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Profile, StageContext, run_pipeline
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard

pytestmark = [pytest.mark.unit, pytest.mark.local]

TRADE = {"amount": 100.0, "symbol": "AAPL", "agent_id": "agent-1"}


def _cbf(verdict: str) -> MagicMock:
    cbf = MagicMock()
    cbf.verify_action = AsyncMock(return_value=verdict)
    cbf.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE", 0.0))
    return cbf


async def _dry_run(tiers: list[Any], action: str = "execute_trade", params: dict | None = None):
    ctx = StageContext(action=action, params=params or TRADE, profile=Profile.DRY_RUN)
    return await run_pipeline(order_stages(tiers), ctx, profile=Profile.DRY_RUN)


@pytest.mark.asyncio
async def test_dry_run_reports_cbf_refusal_without_committing() -> None:
    cbf = _cbf("UNSAFE: projected cash below barrier")
    result = await _dry_run([CBFTierPlugin(cbf)])

    assert [(v.tier, v.code, v.kind) for v in result.violations] == [
        ("cbf", "CBF_BARRIER_VIOLATED", ViolationKind.HARD)
    ]
    assert result.violations[0].message == "UNSAFE: projected cash below barrier"
    cbf.verify_action.assert_awaited_once()
    cbf.atomic_verify_and_commit.assert_not_called()
    assert result.committed_stages == ()


@pytest.mark.asyncio
async def test_dry_run_allows_when_barrier_safe() -> None:
    cbf = _cbf("SAFE")
    result = await _dry_run([CBFTierPlugin(cbf)])
    assert result.violations == ()
    cbf.atomic_verify_and_commit.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["", "safe", "SAFE ", "UNKNOWN", "None"])
async def test_barrier_preview_fails_closed_on_non_safe_verdict(verdict: str) -> None:
    result = await _dry_run([CBFTierPlugin(_cbf(verdict))])
    assert [v.code for v in result.violations] == ["CBF_BARRIER_VIOLATED"]


@pytest.mark.asyncio
async def test_barrier_preview_exception_is_hard_violation() -> None:
    cbf = _cbf("SAFE")
    cbf.verify_action = AsyncMock(side_effect=ConnectionError("redis down"))
    result = await _dry_run([CBFTierPlugin(cbf)])
    assert [(v.code, v.kind) for v in result.violations] == [("TIER_EXCEPTION", ViolationKind.HARD)]
    assert "ConnectionError" in result.violations[0].message


@pytest.mark.asyncio
async def test_dry_run_reports_healthcare_dose_barrier_refusal() -> None:
    """The preview is kernel-level, so non-finance barrier tiers are covered too."""
    cbf = _cbf("UNSAFE: cumulative dose exceeds ceiling")
    result = await _dry_run([DoseBarrierTier(cbf)], action="administer_dose", params={"dose_mg": 10})
    assert [v.code for v in result.violations] == ["DOSE_BARRIER_VIOLATED"]
    cbf.atomic_verify_and_commit.assert_not_called()


# ── Fiscal ─────────────────────────────────────────────────────────────────


class _Redis:
    """Async-client stub; records every write so tests can assert none happened."""

    def __init__(self, spent_cents: int | None = 0, fail: bool = False) -> None:
        self.spent_cents, self.fail, self.writes = spent_cents, fail, []

    async def get(self, key: str) -> bytes | None:
        if self.fail:
            raise ConnectionError("redis down")
        return None if self.spent_cents is None else str(self.spent_cents).encode()

    def __getattr__(self, name: str):  # any write-path call is recorded
        async def _write(*args, **kwargs):
            self.writes.append(name)
        return _write


def _guard(redis: _Redis, cap: float = 1_000.0) -> FiscalLimitGuard:
    guard = FiscalLimitGuard(redis, daily_cap_usd=cap)
    guard._is_async_client = lambda: True  # type: ignore[method-assign]
    return guard


@pytest.mark.asyncio
async def test_dry_run_reports_fiscal_limit_without_reserving() -> None:
    redis = _Redis(spent_cents=95_000)  # $950 of $1000 spent; $100 trade exceeds
    result = await _dry_run([FiscalTierPlugin(_guard(redis))])
    assert [v.code for v in result.violations] == ["FISCAL_LIMIT_EXCEEDED"]
    assert redis.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("spent_cents", "amount", "accepted"),
    [(90_000, 100.0, True), (90_001, 100.0, False), (None, 1_000.0, True), (0, 1_000.01, False)],
)
async def test_would_accept_matches_reserve_cap_rule(spent_cents, amount, accepted) -> None:
    """Same boundary as reserve(): current + amount > cap rejects."""
    redis = _Redis(spent_cents=spent_cents)
    assert await _guard(redis).would_accept(amount) is accepted
    assert redis.writes == []


@pytest.mark.asyncio
async def test_would_accept_fails_closed_on_redis_error() -> None:
    """remaining_usd() reports full headroom on Redis error; would_accept must not."""
    assert await _guard(_Redis(fail=True)).would_accept(1.0) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [0.0, -5.0, float("nan"), float("inf")])
async def test_would_accept_rejects_invalid_amounts(amount: float) -> None:
    assert await _guard(_Redis()).would_accept(amount) is False


# ── Pipeline contract ──────────────────────────────────────────────────────


class _NoPreviewStage:
    name, mutating = "opaque_commit", True

    def claims(self, ctx: StageContext) -> bool:
        return True

    async def run(self, ctx: StageContext) -> list[Violation]:
        raise AssertionError("DRY_RUN must never call run() on a mutating stage")

    async def commit(self, ctx: StageContext) -> tuple[list[Violation], CommitReceipt | None]:
        raise AssertionError("DRY_RUN must never call commit()")

    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        raise AssertionError("nothing was committed")


@pytest.mark.asyncio
async def test_mutating_stage_without_preview_blocks_dry_run() -> None:
    """A commit that can't be previewed must not be reported as ALLOW."""
    ctx = StageContext(action="execute_trade", params=TRADE, profile=Profile.DRY_RUN)
    result = await run_pipeline([_NoPreviewStage()], ctx, profile=Profile.DRY_RUN)
    assert [(v.code, v.kind) for v in result.violations] == [("PREVIEW_UNAVAILABLE", ViolationKind.HARD)]


# ── PREVIEW_IS_PURE: real barriers on Redis, approval pending ──────────────
#
# With a HITL finding in phase 1 the committing profiles must preview the
# phase-2 barriers (phase2_mode → PREVIEW) and write nothing. Purity is
# observed on the real engines over fakeredis: the whole keyspace is
# snapshotted before and after, so a write through any path (pipelines, Lua,
# fence-epoch bookkeeping) shows up.

import fakeredis  # noqa: E402
import fakeredis.aioredis  # noqa: E402

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver  # noqa: E402
from src.cage_healthcare.invariants import SerumConcentrationBarrier, healthcare_cost_resolver  # noqa: E402
from src.cage_physical_ai.invariants import (  # noqa: E402
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
    spatial_cost_resolver,
    torque_cost_resolver,
    velocity_cost_resolver,
)
from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier  # noqa: E402
from src.gateway.governance.governor.pipeline import BarrierPreview  # noqa: E402
from src.gateway.governance.governor.reservation import ReservationScope  # noqa: E402
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction  # noqa: E402

_FISCAL_CAP = 10_000.0
_HEADROOM = 100_000.0  # every barrier state starts far from its threshold


class _Backends:
    def __init__(self) -> None:
        self.barrier = fakeredis.aioredis.FakeRedis(decode_responses=False)
        self.fiscal = fakeredis.aioredis.FakeRedis(decode_responses=True)

    async def snapshot(self) -> dict[str, dict[bytes, bytes | None]]:
        return {
            "barrier": {k: await self.barrier.dump(k) for k in sorted(await self.barrier.keys("*"))},
            "fiscal": {k: await self.fiscal.dump(k) for k in sorted(await self.fiscal.keys("*"))},
        }


@pytest.fixture
async def backends(monkeypatch: pytest.MonkeyPatch) -> _Backends:
    b = _Backends()
    raw = MagicMock()
    raw.get_raw_client.return_value = b.barrier
    monkeypatch.setattr("src.gateway.governance.safety.cbf_engine.redis_client", raw)
    monkeypatch.setattr(
        "src.gateway.governance.safety.cbf_engine.sync_redis_client",
        fakeredis.FakeRedis(decode_responses=True),
    )
    return b


def _engine(invariant: Any, cost_resolver: Any) -> ControlBarrierFunction:
    return ControlBarrierFunction(invariant=invariant, cost_resolver=cost_resolver, skip_epoch_seed=True)


async def _seeded(backends: _Backends, *engines: ControlBarrierFunction) -> None:
    for engine in engines:
        await backends.barrier.set(engine.redis_key, str(_HEADROOM))


#: Every phase-2 tier a plugin registers, with an action it claims and params
#: whose commit succeeds from a seeded state. (test_registered_phase2_tiers_are_all_covered
#: fails when a plugin adds a phase-2 tier missing here.)
async def _phase2_cases(backends: _Backends) -> list[tuple[Any, str, dict[str, Any]]]:
    cash = _engine(CashBarrier(), finance_cost_resolver)
    serum = _engine(SerumConcentrationBarrier(), healthcare_cost_resolver)
    kinematic = (
        _engine(SpatialSeparationBarrier(), spatial_cost_resolver),
        _engine(KinematicVelocityBarrier(), velocity_cost_resolver),
        _engine(TorqueSaturationBarrier(), torque_cost_resolver),
    )
    await _seeded(backends, cash, serum, *kinematic)
    fiscal = FiscalLimitGuard(backends.fiscal, daily_cap_usd=_FISCAL_CAP)
    trade = {"amount": 100.0, "symbol": "AAPL", "trader_id": "agent-1"}
    return [
        (CBFTierPlugin(cash), "execute_trade", trade),
        (FiscalTierPlugin(fiscal), "execute_trade", trade),
        (DoseBarrierTier(serum), "administer_medication", {"dose_mg": 1.0}),
        (
            KinematicBarrierTier(kinematic),
            "move_arm",
            {"approach_distance_mm": 1.0, "target_velocity_mm_s": 1.0, "target_torque_nm": 1.0},
        ),
    ]


class _PendingApproval:
    """Read-only stage reporting a HITL finding (named opa: runs under every profile)."""

    name, mutating = "opa", False

    async def run(self, ctx: StageContext) -> list[Violation]:
        return [Violation(tier="opa", code="OPA_MANUAL_REVIEW", message="review", kind=ViolationKind.HITL)]


def test_registered_phase2_tiers_are_all_covered() -> None:
    from src.cage_finance.plugin import get_plugin as finance
    from src.cage_healthcare.plugin import get_plugin as healthcare
    from src.cage_physical_ai.plugin import get_plugin as physical_ai

    registered = {
        tier.tier_name
        for plugin in (finance(), healthcare(), physical_ai())
        for tier in plugin.contribute().tiers
        if tier.phase == 2
    }
    assert registered == {"cbf", "fiscal", "dose_barrier", "kinematic_barrier"}


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", [Profile.FULL, Profile.POST_HITL])
@pytest.mark.parametrize("case", range(4), ids=["cbf", "fiscal", "dose_barrier", "kinematic_barrier"])
async def test_pending_approval_previews_barriers_and_writes_nothing(
    backends: _Backends, profile: Profile, case: int
) -> None:
    tier, action, params = (await _phase2_cases(backends))[case]
    before = await backends.snapshot()

    ctx = StageContext(action=action, params=params, profile=profile)
    async with ReservationScope() as scope:
        result = await run_pipeline([_PendingApproval(), *order_stages([tier])], ctx, profile=profile, scope=scope)

    assert result.barrier_preview == BarrierPreview.PASS
    assert result.commits == () and result.committed_stages == ()
    assert [v.code for v in result.violations] == ["OPA_MANUAL_REVIEW"]
    assert await backends.snapshot() == before


@pytest.mark.asyncio
async def test_pending_approval_preview_reports_a_breach_and_writes_nothing(backends: _Backends) -> None:
    fiscal = FiscalLimitGuard(backends.fiscal, daily_cap_usd=_FISCAL_CAP)
    await fiscal.reserve(agent_id="other-desk", amount_usd=_FISCAL_CAP - 50.0)
    before = await backends.snapshot()

    ctx = StageContext(action="execute_trade", params=TRADE, profile=Profile.FULL)
    async with ReservationScope() as scope:
        result = await run_pipeline(
            [_PendingApproval(), *order_stages([FiscalTierPlugin(fiscal)])], ctx, profile=Profile.FULL, scope=scope
        )

    assert result.barrier_preview == BarrierPreview.FAIL
    assert [v.code for v in result.preview_violations] == ["FISCAL_LIMIT_EXCEEDED"]
    assert result.commits == ()
    assert await backends.snapshot() == before


@pytest.mark.asyncio
async def test_hard_phase1_finding_skips_the_barriers_entirely() -> None:
    cbf = _cbf("SAFE")

    class _Refused:
        name, mutating = "opa", False

        async def run(self, ctx: StageContext) -> list[Violation]:
            return [Violation(tier="opa", code="OPA_DENY", message="deny", kind=ViolationKind.HARD)]

    ctx = StageContext(action="execute_trade", params=TRADE, profile=Profile.FULL)
    async with ReservationScope() as scope:
        result = await run_pipeline([_Refused(), *order_stages([CBFTierPlugin(cbf)])], ctx, profile=Profile.FULL, scope=scope)
    assert result.barrier_preview is None
    cbf.verify_action.assert_not_called()
    cbf.atomic_verify_and_commit.assert_not_called()


@pytest.mark.asyncio
async def test_preview_continues_past_a_narrowable_breach_to_a_hard_one() -> None:
    """A HARD barrier behind a NARROWABLE one still denies before a human is asked."""

    class _Narrowable:
        name, mutating = "fiscal_probe", True

        def claims(self, ctx: StageContext) -> bool:
            return True

        async def preview(self, ctx: StageContext) -> list[Violation]:
            return [Violation(tier=self.name, code="CAP", message="cap", kind=ViolationKind.NARROWABLE)]

    hard = _cbf("UNSAFE: barrier")
    ctx = StageContext(action="execute_trade", params=TRADE, profile=Profile.DRY_RUN)
    result = await run_pipeline(
        [_PendingApproval(), _Narrowable(), *order_stages([CBFTierPlugin(hard)])], ctx, profile=Profile.DRY_RUN
    )
    assert [v.code for v in result.preview_violations] == ["CAP", "CBF_BARRIER_VIOLATED"]


# ── Tier contract: evaluate() never mutates (contracts.GovernanceTierPlugin) ─


@pytest.mark.asyncio
@pytest.mark.parametrize("case", range(4), ids=["cbf", "fiscal", "dose_barrier", "kinematic_barrier"])
async def test_evaluate_after_commit_leaves_barrier_state_unchanged(backends: _Backends, case: int) -> None:
    tier, action, params = (await _phase2_cases(backends))[case]
    violations, receipt = await tier.commit(action, params)
    assert violations == [] and receipt is not None, violations

    committed = await backends.snapshot()
    for _ in range(3):
        assert await tier.evaluate(action, params) == []
    assert await backends.snapshot() == committed
