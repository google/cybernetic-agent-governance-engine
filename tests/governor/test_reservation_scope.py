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

"""``ReservationScope``: phase-2 commits stay reserved until sealed, else roll back.

Before P3b the entry points called ``issue_seal()`` after ``run_pipeline()``
had committed.  A failing or cancelled seal leaked every commit (CBF
headroom, fiscal reservations).  Each test here observes a leak path close.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import (
    PipelineResult,
    Profile,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    order_stages,
)
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ENTRY_POINTS = ("validate_action", "govern", "revalidate_post_hitl")


class _Tier:
    """Phase-2 tier double recording commit/rollback order."""

    def __init__(
        self,
        name: str,
        order: int,
        log: list[str],
        *,
        commit_blocks: asyncio.Event | None = None,
        commit_raises: BaseException | None = None,
        rollback_raises: BaseException | None = None,
        rollback_delay: float = 0.0,
    ) -> None:
        self._name, self._order, self.log = name, order, log
        self._commit_blocks, self._commit_raises = commit_blocks, commit_raises
        self._rollback_raises, self._rollback_delay = rollback_raises, rollback_delay
        self.commit_started = asyncio.Event()

    tier_name = property(lambda self: self._name)
    phase = property(lambda self: 2)
    order = property(lambda self: self._order)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]):
        self.log.append(f"commit:{self._name}")
        self.commit_started.set()
        if self._commit_blocks is not None:
            await self._commit_blocks.wait()
        if self._commit_raises is not None:
            raise self._commit_raises
        return [], CommitReceipt(tier=self._name, magnitude=float(self._order))

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        assert receipt.tier == self._name
        if self._rollback_delay:
            await asyncio.sleep(self._rollback_delay)
        self.log.append(f"rollback:{self._name}")
        if self._rollback_raises is not None:
            raise self._rollback_raises


def _governor(tiers: list[_Tier]) -> SymbolicGovernor:
    """A governor whose only stages are ``tiers`` (so only the scope logic is under test)."""
    # The classifier is never reached: these runs have no violations.
    return make_governor(core_stages=(), domain_tiers=tiers, classifier=MagicMock())


def _two_tiers(log: list[str], **cbf_kwargs: Any) -> list[_Tier]:
    # Named "cbf"/"fiscal" so they also run under the POST_HITL profile.
    return [_Tier("cbf", 1, log, **cbf_kwargs), _Tier("fiscal", 2, log)]


def _ctx(profile: Profile = Profile.FULL) -> StageContext:
    return StageContext(action="act", params={}, profile=profile)


async def _call(gov: SymbolicGovernor, entry_point: str) -> Any:
    return await getattr(gov, entry_point)("act", {})


@pytest.fixture
def seal(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock(return_value="sealed")
    monkeypatch.setattr(sealing_module, "issue_seal", mock)
    return mock


# ── Entry points: the seal is issued inside the scope ─────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
async def test_seal_failure_rolls_back_every_commit_lifo(entry_point: str, seal: AsyncMock) -> None:
    log: list[str] = []
    seal.side_effect = RuntimeError("KMS unavailable")

    with pytest.raises(RuntimeError, match="KMS unavailable"):
        await _call(_governor(_two_tiers(log)), entry_point)

    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]
    seal.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
async def test_issued_seal_keeps_commits(entry_point: str, seal: AsyncMock) -> None:
    """Control for the test above: a sealed run is not rolled back."""
    log: list[str] = []
    result = await _call(_governor(_two_tiers(log)), entry_point)

    assert log == ["commit:cbf", "commit:fiscal"]
    sealed = result["seal"] if entry_point == "validate_action" else result
    assert sealed == "sealed"


@pytest.mark.asyncio
async def test_timeout_between_commit_and_seal_awaits_every_rollback(seal: AsyncMock) -> None:
    log: list[str] = []

    async def slow_seal(*args: Any, **kwargs: Any) -> str:
        await asyncio.sleep(10)
        return "never"

    seal.side_effect = slow_seal
    tiers = [_Tier("cbf", 1, log, rollback_delay=0.02), _Tier("fiscal", 2, log, rollback_delay=0.02)]

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(_governor(tiers).govern("act", {}), timeout=0.01)

    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_cancellation_during_seal_propagates_after_rollback(seal: AsyncMock) -> None:
    log: list[str] = []
    sealing = asyncio.Event()

    async def slow_seal(*args: Any, **kwargs: Any) -> str:
        sealing.set()
        await asyncio.sleep(10)
        return "never"

    seal.side_effect = slow_seal
    task = asyncio.create_task(_governor(_two_tiers(log)).validate_action("act", {}))
    await sealing.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_cancellation_during_second_of_three_commits_rolls_back_first(seal: AsyncMock) -> None:
    log: list[str] = []
    second = _Tier("b", 2, log, commit_blocks=asyncio.Event())
    gov = _governor([_Tier("a", 1, log), second, _Tier("c", 3, log)])

    task = asyncio.create_task(gov.govern("act", {}))
    await second.commit_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert log == ["commit:a", "commit:b", "rollback:a"]  # c never committed
    seal.assert_not_awaited()


@pytest.mark.asyncio
async def test_seal_failure_plus_rollback_failure_raises_governance_error(seal: AsyncMock) -> None:
    log: list[str] = []
    seal_error = RuntimeError("KMS unavailable")
    seal.side_effect = seal_error
    gov = _governor(_two_tiers(log, rollback_raises=ConnectionError("redis down")))

    with pytest.raises(GovernanceError, match=r"\[ROLLBACK_FAILED\].*cbf") as info:
        await gov.govern("act", {})

    assert info.value.__cause__ is seal_error
    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_refused_run_with_outstanding_commits_is_hard_and_rolled_back(
    seal: AsyncMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: commits are only made on a clean run.  A breach fails closed."""
    log: list[str] = []
    stage = DomainTierStage(_Tier("cbf", 1, log))

    async def leaky_pipeline(stages: Any, ctx: StageContext, *, profile: Profile, scope: ReservationScope):
        await scope.commit(stage, ctx)
        deny = Violation(tier="opa", code="DENY", message="denied", kind=ViolationKind.HARD)
        return PipelineResult((deny,), (), None, None, (), commits=scope.commits)

    monkeypatch.setattr(sealing_module, "run_pipeline", leaky_pipeline)
    with pytest.raises(GovernanceError, match=r"\[UNROLLED_COMMIT\] .*cbf"):
        await _governor([]).govern("act", {})

    assert log == ["commit:cbf", "rollback:cbf"]
    seal.assert_not_awaited()


@pytest.mark.asyncio
async def test_verify_creates_no_scope_and_never_commits(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_scope(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("verify() must not create a ReservationScope")

    monkeypatch.setattr(sealing_module, "ReservationScope", no_scope)
    log: list[str] = []
    result = await _governor(_two_tiers(log)).verify("act", {})

    assert result["violations"] == []
    assert log == []  # preview() only; commit() never awaited


# ── run_pipeline: scope requirements ───────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", [Profile.FULL, Profile.POST_HITL])
async def test_mutating_profile_without_scope_is_rejected(profile: Profile) -> None:
    log: list[str] = []
    with pytest.raises(ValueError, match="requires a ReservationScope"):
        await run_pipeline(order_stages(_two_tiers(log)), _ctx(profile), profile=profile)
    assert log == []


@pytest.mark.asyncio
async def test_dry_run_with_scope_is_rejected() -> None:
    log: list[str] = []
    async with ReservationScope() as scope:
        with pytest.raises(ValueError, match="DRY_RUN never commits"):
            await run_pipeline(
                order_stages(_two_tiers(log)), _ctx(Profile.DRY_RUN), profile=Profile.DRY_RUN, scope=scope
            )
    assert log == []


# ── ReservationScope unit behaviour ────────────────────────────────────────


async def _commit_all(scope: ReservationScope, tiers: list[_Tier]) -> None:
    for tier in tiers:
        await scope.commit(DomainTierStage(tier), _ctx())


@pytest.mark.asyncio
async def test_plain_exit_without_seal_rolls_back_lifo() -> None:
    log: list[str] = []
    async with ReservationScope() as scope:
        await _commit_all(scope, _two_tiers(log))
    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_one_failing_rollback_does_not_stop_the_others() -> None:
    log: list[str] = []
    tiers = [_Tier("a", 1, log), _Tier("b", 2, log, rollback_raises=RuntimeError("boom")), _Tier("c", 3, log)]
    async with ReservationScope() as scope:
        await _commit_all(scope, tiers)
        failures = await scope.rollback()

    assert log[3:] == ["rollback:c", "rollback:b", "rollback:a"]
    assert [(v.tier, v.code, v.kind) for v in failures] == [("b", "ROLLBACK_FAILED", ViolationKind.HARD)]


@pytest.mark.asyncio
async def test_rollback_failure_on_plain_exit_raises_governance_error() -> None:
    log: list[str] = []
    with pytest.raises(GovernanceError, match=r"\[ROLLBACK_FAILED\]"):
        async with ReservationScope() as scope:
            await _commit_all(scope, _two_tiers(log, rollback_raises=RuntimeError("boom")))


@pytest.mark.asyncio
async def test_rollback_failure_during_cancellation_keeps_cancellation() -> None:
    log: list[str] = []
    with pytest.raises(asyncio.CancelledError) as info:
        async with ReservationScope() as scope:
            await _commit_all(scope, _two_tiers(log, rollback_raises=RuntimeError("boom")))
            raise asyncio.CancelledError
    assert any("[ROLLBACK_FAILED]" in note for note in info.value.__notes__)
    assert log[2:] == ["rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_each_receipt_rolled_back_once() -> None:
    log: list[str] = []
    scope = ReservationScope()
    async with scope:
        await _commit_all(scope, _two_tiers(log))
        assert len(await scope.rollback()) == 0
        assert await scope.rollback() == []
    assert await scope.__aexit__(None, None, None) is False  # second exit

    assert log == ["commit:cbf", "commit:fiscal", "rollback:fiscal", "rollback:cbf"]
    assert scope.commits == ()


@pytest.mark.asyncio
async def test_seal_issued_disarms_rollback() -> None:
    log: list[str] = []
    scope = ReservationScope()
    async with scope:
        await _commit_all(scope, _two_tiers(log))
        scope.seal_issued("sealed")
    await scope.__aexit__(None, None, None)

    assert log == ["commit:cbf", "commit:fiscal"]
    assert scope.sealed


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_seal", ["", None])
async def test_empty_seal_does_not_disarm_rollback(bad_seal: Any) -> None:
    log: list[str] = []
    with pytest.raises(ValueError, match="rollback stays armed"):
        async with ReservationScope() as scope:
            await _commit_all(scope, _two_tiers(log))
            scope.seal_issued(bad_seal)
    assert log[2:] == ["rollback:fiscal", "rollback:cbf"]


@pytest.mark.asyncio
async def test_sealed_scope_refuses_further_commits_and_rollback() -> None:
    log: list[str] = []
    async with ReservationScope() as scope:
        scope.seal_issued("sealed")
        with pytest.raises(RuntimeError, match="after seal_issued"):
            await scope.commit(DomainTierStage(_Tier("late", 1, log)), _ctx())
        with pytest.raises(RuntimeError, match="issued seal"):
            await scope.rollback()
    assert log == []


@pytest.mark.asyncio
async def test_commit_outside_async_with_is_refused() -> None:
    log: list[str] = []
    scope = ReservationScope()
    with pytest.raises(RuntimeError, match="outside 'async with'"):
        await scope.commit(DomainTierStage(_Tier("a", 1, log)), _ctx())
    async with scope:
        pass
    with pytest.raises(RuntimeError, match="outside 'async with'"):
        await scope.commit(DomainTierStage(_Tier("a", 1, log)), _ctx())
    with pytest.raises(RuntimeError, match="single-use"):
        async with scope:
            pass
    assert log == []


class _RaisingStage:
    name, mutating = "kernel", True

    async def commit(self, ctx: StageContext):
        raise KeyError("exploded")

    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        raise AssertionError("a raising commit mutated nothing; never roll it back")


@pytest.mark.asyncio
async def test_raising_commit_is_hard_tier_exception_and_not_recorded() -> None:
    async with ReservationScope() as scope:
        violations = await scope.commit(_RaisingStage(), _ctx())
        assert scope.commits == ()
    assert [(v.tier, v.code, v.kind) for v in violations] == [("kernel", "TIER_EXCEPTION", ViolationKind.HARD)]
