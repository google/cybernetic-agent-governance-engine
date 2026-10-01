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

"""Cancellation safety of phase-2 rollback in the pipeline and its scope.

``asyncio.CancelledError`` is a ``BaseException``.  Before #280 a cancellation
mid-commit leaked every earlier commit, and a cancellation during rollback
aborted the remaining rollbacks.  ``ReservationScope`` now owns both paths;
governor-level cancellation between commit and seal is covered in
``test_reservation_scope.py``.
"""

import asyncio
from typing import Any

import pytest

from src.gateway.governance.contracts import CommitReceipt, MutatingTier, Violation
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    order_stages,
)
from tests.governor.scope_helpers import rollback_pairs, run_scoped

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _Escape(BaseException):
    """A non-Exception BaseException raised by a rollback."""


class _Tier(MutatingTier):
    """Phase-2 tier double with controllable commit/rollback timing."""

    def __init__(
        self,
        name: str,
        order: int,
        log: list[str],
        *,
        commit_blocks: asyncio.Event | None = None,
        rollback_delay: float = 0.0,
        rollback_raises: BaseException | None = None,
    ) -> None:
        self._name, self._order, self.log = name, order, log
        self._commit_blocks, self._rollback_delay = commit_blocks, rollback_delay
        self._rollback_raises = rollback_raises
        self.commit_started = asyncio.Event()

    tier_name = property(lambda self: self._name)
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
        return [], CommitReceipt(tier=self._name)

    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        self.log.append(f"confirm:{self._name}")

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        if self._rollback_delay:
            await asyncio.sleep(self._rollback_delay)
        self.log.append(f"rollback:{self._name}")
        if self._rollback_raises is not None:
            raise self._rollback_raises


def _ctx() -> StageContext:
    return StageContext(action="act", params={}, profile=Profile.FULL)


@pytest.mark.asyncio
async def test_cancel_during_second_commit_rolls_back_first() -> None:
    log: list[str] = []
    never = asyncio.Event()
    second = _Tier("m2", 2, log, commit_blocks=never)
    stages = order_stages([_Tier("m1", 1, log), second, _Tier("m3", 3, log)])

    task = asyncio.create_task(run_scoped(stages, _ctx()))
    await second.commit_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert log == ["commit:m1", "commit:m2", "rollback:m1"]  # m3 never committed


@pytest.mark.asyncio
async def test_cancel_during_rollback_still_completes_every_rollback() -> None:
    log: list[str] = []
    tiers = [_Tier(n, i, log, rollback_delay=0.02) for i, n in enumerate(["a", "b", "c"])]
    committed = [(DomainTierStage(t), CommitReceipt(tier=t.tier_name)) for t in tiers]

    task = asyncio.create_task(rollback_pairs(committed, _ctx()))
    await asyncio.sleep(0.01)  # first rollback in flight
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert log == ["rollback:c", "rollback:b", "rollback:a"]


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_abort_rollback() -> None:
    log: list[str] = []
    tiers = [_Tier(n, i, log, rollback_delay=0.02) for i, n in enumerate(["a", "b"])]
    committed = [(DomainTierStage(t), CommitReceipt(tier=t.tier_name)) for t in tiers]

    task = asyncio.create_task(rollback_pairs(committed, _ctx()))
    for _ in range(3):
        await asyncio.sleep(0.005)
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert log == ["rollback:b", "rollback:a"]


@pytest.mark.asyncio
@pytest.mark.parametrize("escape", [asyncio.CancelledError(), _Escape()], ids=["cancelled", "base"])
async def test_base_exception_in_one_rollback_does_not_stop_others(escape: BaseException) -> None:
    log: list[str] = []
    tiers = [
        _Tier("a", 1, log),
        _Tier("b", 2, log, rollback_raises=escape),
        _Tier("c", 3, log),
    ]
    committed = [(DomainTierStage(t), CommitReceipt(tier=t.tier_name)) for t in tiers]

    with pytest.raises(type(escape)):
        await rollback_pairs(committed, _ctx())

    assert log == ["rollback:c", "rollback:b", "rollback:a"]
