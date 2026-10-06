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

"""Settlement (ADR-009): a seal's phase-2 commits are confirmed after the action.

The committing run only *reserves*.  ``SymbolicGovernor.settle(seal, executed=...)``
confirms the reservations once the sealed action ran, or releases them when it
did not.  A seal that is never settled leaves each reservation to its tier's
own expiry; for the fiscal tier that is the guard's TTL reclaimer.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import CommitReceipt, MutatingTier, Violation
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.reservation import HeldCommit
from src.gateway.governance.governor.settlement import SettlementLedger
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _Tier(MutatingTier):
    """Phase-2 double recording commit / confirm / rollback."""

    def __init__(
        self,
        name: str,
        order: int,
        log: list[str],
        *,
        confirm_raises: BaseException | None = None,
        refuse: bool = False,
    ) -> None:
        self._name, self._order, self.log = name, order, log
        self._confirm_raises, self._refuse = confirm_raises, refuse

    tier_name = property(lambda self: self._name)
    order = property(lambda self: self._order)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]):
        self.log.append(f"commit:{self._name}")
        if self._refuse:
            from src.gateway.governance.contracts import ViolationKind

            return [
                Violation(
                    tier=self._name, code="NO", message="no", kind=ViolationKind.HARD
                )
            ], None
        return [], CommitReceipt(tier=self._name)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.log.append(f"confirm:{self._name}")
        if self._confirm_raises is not None:
            raise self._confirm_raises

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.log.append(f"rollback:{self._name}")


def _governor(tiers: list[MutatingTier], classifier: Any = None) -> SymbolicGovernor:
    return make_governor(
        core_stages=(), domain_tiers=tiers, classifier=classifier or MagicMock()
    )


@pytest.fixture
def seals(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    counter = iter(range(1_000_000))
    mock = AsyncMock(side_effect=lambda *a, **k: f"seal-{next(counter)}")
    monkeypatch.setattr(sealing_module, "issue_seal", mock)
    return mock


# --- governor.settle -------------------------------------------------------------


@pytest.mark.asyncio
async def test_executed_confirms_every_commit_in_order(seals: AsyncMock) -> None:
    log: list[str] = []
    gov = _governor([_Tier("cbf", 1, log), _Tier("fiscal", 2, log)])
    seal = await gov.govern("act", {})
    assert await gov.settle(seal, executed=True) == []
    assert log == ["commit:cbf", "commit:fiscal", "confirm:cbf", "confirm:fiscal"]


@pytest.mark.asyncio
async def test_not_executed_rolls_back_lifo(seals: AsyncMock) -> None:
    log: list[str] = []
    gov = _governor([_Tier("cbf", 1, log), _Tier("fiscal", 2, log)])
    seal = await gov.govern("act", {})
    assert await gov.settle(seal, executed=False) == []
    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
@pytest.mark.parametrize("second", [True, False])
async def test_settle_is_idempotent_per_seal(seals: AsyncMock, second: bool) -> None:
    """A replayed or double settle can neither confirm nor refund twice."""
    log: list[str] = []
    gov = _governor([_Tier("fiscal", 1, log)])
    seal = await gov.govern("act", {})
    await gov.settle(seal, executed=True)
    assert await gov.settle(seal, executed=second) == []
    assert log == ["commit:fiscal", "confirm:fiscal"]


@pytest.mark.asyncio
async def test_unknown_seal_settles_to_nothing(seals: AsyncMock) -> None:
    gov = _governor([_Tier("fiscal", 1, [])])
    assert await gov.settle("never-issued", executed=True) == []


@pytest.mark.asyncio
async def test_settlements_are_per_seal(seals: AsyncMock) -> None:
    log: list[str] = []
    gov = _governor([_Tier("fiscal", 1, log)])
    first = await gov.govern("act", {})
    second = await gov.govern("act", {})
    await gov.settle(second, executed=False)
    await gov.settle(first, executed=True)
    assert log == [
        "commit:fiscal",
        "commit:fiscal",
        "rollback:fiscal",
        "confirm:fiscal",
    ]


@pytest.mark.asyncio
async def test_confirm_failure_is_reported_and_others_still_confirm(
    seals: AsyncMock,
) -> None:
    log: list[str] = []
    gov = _governor(
        [
            _Tier("cbf", 1, log, confirm_raises=RuntimeError("redis down")),
            _Tier("fiscal", 2, log),
        ]
    )
    seal = await gov.govern("act", {})
    failures = await gov.settle(seal, executed=True)
    assert [(v.tier, v.code) for v in failures] == [("cbf", "CONFIRM_FAILED")]
    assert log[-2:] == ["confirm:cbf", "confirm:fiscal"]


@pytest.mark.asyncio
async def test_settle_completes_despite_caller_cancellation(seals: AsyncMock) -> None:
    """Shielded: cancelling the caller cannot strand half the reservations."""
    log: list[str] = []
    gate = asyncio.Event()

    class _Slow(_Tier):
        async def rollback(self, action, params, receipt):
            await gate.wait()
            await super().rollback(action, params, receipt)

    gov = _governor([_Tier("cbf", 1, log), _Slow("fiscal", 2, log)])
    seal = await gov.govern("act", {})
    task = asyncio.ensure_future(gov.settle(seal, executed=False))
    await asyncio.sleep(0)
    task.cancel()
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert log[-2:] == ["rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_refused_run_holds_nothing(seals: AsyncMock) -> None:
    from src.gateway.governance.governor.errors import GovernanceError

    log: list[str] = []
    classifier = MagicMock()
    classifier.classify.return_value = MagicMock(decision="DENY", metadata={})
    gov = _governor(
        [_Tier("cbf", 1, log), _Tier("fiscal", 2, log, refuse=True)], classifier
    )
    with pytest.raises(GovernanceError):
        await gov.govern("act", {})
    assert len(gov._settlements) == 0
    assert "rollback:cbf" in log


@pytest.mark.asyncio
async def test_read_only_runs_hold_nothing(seals: AsyncMock) -> None:
    """validate_action / verify never commit, so nothing awaits settlement."""
    log: list[str] = []
    gov = _governor([_Tier("fiscal", 1, log)])
    await gov.verify("act", {})
    assert len(gov._settlements) == 0
    assert log == []


# --- SettlementLedger -------------------------------------------------------------


def _held(name: str = "t") -> tuple[HeldCommit, ...]:
    stage = MagicMock()
    stage.name = name
    return (HeldCommit(stage, MagicMock(), CommitReceipt(tier=name)),)


def test_ledger_take_is_single_use() -> None:
    ledger = SettlementLedger()
    commits = _held()
    ledger.hold("s", commits)
    assert ledger.take("s") == commits
    assert ledger.take("s") == ()


def test_ledger_refuses_a_reused_seal() -> None:
    ledger = SettlementLedger()
    ledger.hold("s", _held())
    with pytest.raises(ValueError, match="single-use"):
        ledger.hold("s", _held())


def test_ledger_skips_empty_commit_sets() -> None:
    ledger = SettlementLedger()
    ledger.hold("s", ())
    assert len(ledger) == 0


def test_ledger_drops_entries_past_the_hold_window() -> None:
    now = [1000.0]
    ledger = SettlementLedger(hold_seconds=60, clock=lambda: now[0])
    ledger.hold("old", _held("old"))
    now[0] += 30
    ledger.hold("young", _held("young"))
    now[0] += 31  # "old" is 61 s old, "young" 31 s
    assert ledger.take("old") == ()
    assert ledger.take("young") != ()


def test_ledger_rejects_non_positive_hold() -> None:
    with pytest.raises(ValueError):
        SettlementLedger(hold_seconds=0)


# --- Fiscal end to end on a real guard -------------------------------------------


@pytest.fixture
async def fiscal() -> Any:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
    from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin

    guard = FiscalLimitGuard(
        fakeredis.FakeRedis(decode_responses=True),
        daily_cap_usd=1_000.0,
        reservation_ttl=300,
    )
    tier = FiscalTierPlugin(
        guard, cost_resolver=lambda action, params: float(params["amount"])
    )
    return guard, _governor([tier])


@pytest.mark.asyncio
async def test_fiscal_executed_trade_is_confirmed_and_never_reclaimed(
    seals, fiscal
) -> None:
    guard, gov = fiscal
    seal = await gov.govern("execute_trade", {"amount": 400})
    await gov.settle(seal, executed=True)
    assert await guard.reclaim_expired(now=time.time() + 10_000) == 0
    assert await guard.current_spend_usd() == pytest.approx(400)


@pytest.mark.asyncio
async def test_fiscal_failed_actuation_releases_the_reservation(seals, fiscal) -> None:
    guard, gov = fiscal
    seal = await gov.govern("execute_trade", {"amount": 400})
    assert await guard.current_spend_usd() == pytest.approx(400)
    await gov.settle(seal, executed=False)
    assert await guard.current_spend_usd() == 0.0


@pytest.mark.asyncio
async def test_fiscal_crash_between_seal_and_actuation_expires(seals, fiscal) -> None:
    """Nobody settles: the reservation is reclaimed after its TTL, never confirmed."""
    guard, gov = fiscal
    await gov.govern("execute_trade", {"amount": 1_000})
    # The abandoned reservation blocks the cap until it expires ...
    assert await guard.would_accept(1.0) is False
    # ... then the reclaimer frees it.
    assert await guard.reclaim_expired(now=time.time() + 301) == 1
    assert await guard.current_spend_usd() == 0.0
    seal = await gov.govern("execute_trade", {"amount": 1_000})
    assert seal


@pytest.mark.asyncio
async def test_fiscal_commit_only_reserves(seals, fiscal) -> None:
    """The committing run leaves the reservation pending (not yet confirmed)."""
    from src.cage_finance.safety.fiscal_limit_guard import PENDING_KEY

    guard, gov = fiscal
    await gov.govern("execute_trade", {"amount": 10})
    assert await guard._redis.zcard(PENDING_KEY) == 1
