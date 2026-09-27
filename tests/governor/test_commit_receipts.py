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

"""Commit receipts: rollback undoes exactly what commit did.

Regression tests for:
  B1 (H5) CBF / dose-barrier rollback re-read the magnitude from params.
  B2      Fiscal tokens were kept on the tier, keyed by transaction_id.
  B3      KinematicBarrierTier committed to the CBF but had no rollback().
"""

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier
from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import (
    Profile,
    StageContext,
)
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    order_stages,
)
from src.cage_finance.safety.fiscal_limit_guard import ReservationToken
from tests.governor.scope_helpers import rollback_pairs, run_scoped

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _engine(applied: float) -> MagicMock:
    """CBF engine stub that reports ``applied`` as the magnitude it deducted."""
    engine = MagicMock()
    engine.atomic_verify_and_commit = AsyncMock(return_value=(True, "COMMITTED", applied))
    engine.rollback_state = AsyncMock()
    return engine


def _token(amount_usd: float, reservation_id: str, rejected: bool = False) -> ReservationToken:
    return ReservationToken(
        reservation_id=reservation_id,
        agent_id="agent",
        amount_usd=amount_usd,
        amount_cents=int(amount_usd * 100),
        window_key="w",
        cap_usd=1_000_000.0,
        running_total_usd=amount_usd,
        rejected=rejected,
        reserved_at=time.time(),
        ttl_seconds=300,
    )


def _fiscal_guard(*tokens: ReservationToken) -> MagicMock:
    guard = MagicMock()
    guard.reserve = AsyncMock(side_effect=list(tokens))
    guard.confirm = AsyncMock()
    guard.release = AsyncMock()
    return guard


class _Tier:
    """Phase-2 tier double whose commit result is fully scripted."""

    def __init__(self, name: str, order: int, result: tuple[list[Violation], CommitReceipt | None], log: list[str]):
        self._name, self._order, self._result, self.log = name, order, result, log

    tier_name = property(lambda self: self._name)
    phase = property(lambda self: 2)
    order = property(lambda self: self._order)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]):
        self.log.append(f"commit:{self._name}")
        return self._result

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        self.log.append(f"rollback:{self._name}:{receipt.magnitude}")


def _deny(tier: str) -> Violation:
    return Violation(tier=tier, code="DENY", message="denied", kind=ViolationKind.HARD)


# ── B1: CBF-backed rollback restores the committed magnitude ────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tier_cls", "action", "key"),
    [
        (CBFTierPlugin, "execute_trade", "amount"),
        (DoseBarrierTier, "administer_medication", "dose_mg"),
        (KinematicBarrierTier, "move_arm", "velocity"),
    ],
)
async def test_barrier_rollback_restores_committed_magnitude_not_params(tier_cls, action, key) -> None:
    engine = _engine(applied=100.0)
    tier = tier_cls(engine)
    params = {key: 100.0}

    violations, receipt = await tier.commit(action, params)
    assert violations == []
    assert receipt == CommitReceipt(tier=tier.tier_name, magnitude=100.0)

    params[key] = 5.0  # params drift after commit; rollback must not follow them
    await tier.rollback(action, params, receipt)

    engine.rollback_state.assert_awaited_once_with(magnitude=100.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("tier_cls", [CBFTierPlugin, DoseBarrierTier, KinematicBarrierTier])
async def test_barrier_refusal_issues_no_receipt(tier_cls) -> None:
    engine = MagicMock()
    engine.atomic_verify_and_commit = AsyncMock(return_value=(False, "UNSAFE: barrier", 0.0))
    violations, receipt = await tier_cls(engine).commit("any", {})
    assert receipt is None
    assert [v.kind for v in violations] == [ViolationKind.HARD]


@pytest.mark.asyncio
async def test_kinematic_without_engine_mutates_nothing() -> None:
    violations, receipt = await KinematicBarrierTier(cbf=None).commit("move_arm", {})
    assert receipt is None  # nothing mutated
    assert [v.code for v in violations] == ["KINEMATIC_BARRIER_UNCONFIGURED"]  # fail closed


@pytest.mark.asyncio
async def test_engine_reports_the_magnitude_it_deducted() -> None:
    """The receipt magnitude comes from the engine, and equals the balance delta."""
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    fake = fakeredis.FakeRedis(decode_responses=False)
    await fake.set("safety:current_cash", "1000.0")
    cbf = ControlBarrierFunction(invariant=CashBarrier(), cost_resolver=finance_cost_resolver, skip_epoch_seed=True)
    cbf.threshold_value, cbf.gamma, cbf.tracer = 0.0, 1.0, None
    redis_module = MagicMock()
    redis_module.get_raw_client.return_value = fake

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("src.gateway.governance.safety.cbf_engine.redis_client", redis_module)
        ok, _, applied = await cbf.atomic_verify_and_commit("execute_trade", {"amount": 250.0})
        refused, _, refused_applied = await cbf.atomic_verify_and_commit("execute_trade", {"amount": 5_000.0})

    balance = float(await fake.get("safety:current_cash"))
    assert ok is True and applied == 250.0 == 1000.0 - balance
    assert refused is False and refused_applied == 0.0


# ── B2: fiscal reservation travels in the receipt ───────────────────────────


@pytest.mark.asyncio
async def test_fiscal_rollback_without_transaction_id_releases_that_token() -> None:
    token = _token(100.0, "res-1")
    guard = _fiscal_guard(token)
    tier = FiscalTierPlugin(guard)

    violations, receipt = await tier.commit("execute_trade", {"amount": 100.0})
    assert violations == []
    assert receipt == CommitReceipt(tier="fiscal", magnitude=100.0, token=token)

    await tier.rollback("execute_trade", {}, receipt)
    guard.release.assert_awaited_once_with(token)


@pytest.mark.asyncio
async def test_fiscal_concurrent_same_transaction_id_each_release_own_token() -> None:
    t1, t2 = _token(10.0, "res-1"), _token(20.0, "res-2")
    guard = _fiscal_guard(t1, t2)
    tier = FiscalTierPlugin(guard)
    params = {"amount": 10.0, "transaction_id": "dup"}

    (_, r1), (_, r2) = await asyncio.gather(
        tier.commit("execute_trade", params), tier.commit("execute_trade", params)
    )
    await tier.rollback("execute_trade", params, r2)
    await tier.rollback("execute_trade", params, r1)

    assert [c.args[0] for c in guard.release.await_args_list] == [t2, t1]
    assert set(vars(tier)) == {"guard"}  # no per-request state on the shared tier


@pytest.mark.asyncio
async def test_fiscal_rejection_issues_no_receipt() -> None:
    guard = _fiscal_guard(_token(1e9, "res-x", rejected=True))
    violations, receipt = await FiscalTierPlugin(guard).commit("execute_trade", {"amount": 1e9})
    assert receipt is None
    assert violations[0].code == "FISCAL_LIMIT_EXCEEDED"
    guard.confirm.assert_not_awaited()


@pytest.mark.asyncio
async def test_fiscal_confirm_failure_releases_before_raising() -> None:
    """A raising commit must leave nothing reserved: the caller gets no receipt."""
    token = _token(50.0, "res-1")
    guard = _fiscal_guard(token)
    guard.confirm = AsyncMock(side_effect=ConnectionError("redis down"))

    with pytest.raises(ConnectionError):
        await FiscalTierPlugin(guard).commit("execute_trade", {"amount": 50.0})
    guard.release.assert_awaited_once_with(token)


# ── B3 + pipeline: receipts drive LIFO rollback ─────────────────────────────


@pytest.mark.asyncio
async def test_kinematic_rollback_has_no_rollback_failed() -> None:
    engine = _engine(applied=3.5)
    stage = DomainTierStage(KinematicBarrierTier(engine))
    ctx = StageContext(action="move_arm", params={"velocity": 3.5}, profile=Profile.FULL)

    _, receipt = await stage.commit(ctx)
    failures = await rollback_pairs([(stage, receipt)], ctx)

    assert failures == []
    engine.rollback_state.assert_awaited_once_with(magnitude=3.5)


@pytest.mark.asyncio
async def test_commit_with_violations_and_receipt_is_rolled_back() -> None:
    """A commit that mutated state and then refused must still be undone (LIFO)."""
    log: list[str] = []
    stages = order_stages([
        _Tier("m1", 1, ([], CommitReceipt(tier="m1", magnitude=1.0)), log),
        _Tier("m2", 2, ([_deny("m2")], CommitReceipt(tier="m2", magnitude=2.0)), log),
        _Tier("m3", 3, ([], CommitReceipt(tier="m3", magnitude=3.0)), log),
    ])
    result = await run_scoped(stages, StageContext("act", {}, Profile.FULL))

    assert log == ["commit:m1", "commit:m2", "rollback:m2:2.0", "rollback:m1:1.0"]
    assert [v.code for v in result.violations] == ["DENY"]
    assert result.commits == ()  # everything outstanding was undone
    assert result.committed_stages == ("m1",)


@pytest.mark.asyncio
async def test_receiptless_commit_is_not_rolled_back() -> None:
    log: list[str] = []
    stages = order_stages([
        _Tier("noop", 1, ([], None), log),
        _Tier("deny", 2, ([_deny("deny")], None), log),
    ])
    await run_scoped(stages, StageContext("act", {}, Profile.FULL))
    assert log == ["commit:noop", "commit:deny"]


@pytest.mark.asyncio
async def test_successful_pipeline_returns_outstanding_commits() -> None:
    log: list[str] = []
    r1, r2 = CommitReceipt(tier="a", magnitude=1.0), CommitReceipt(tier="b", token="tok")
    stages = order_stages([
        _Tier("a", 1, ([], r1), log),
        _Tier("b", 2, ([], r2), log),
    ])
    result = await run_scoped(stages, StageContext("act", {}, Profile.FULL))

    assert result.violations == ()
    assert [(s.name, r) for s, r in result.commits] == [("a", r1), ("b", r2)]
    assert result.committed_stages == ("a", "b")
