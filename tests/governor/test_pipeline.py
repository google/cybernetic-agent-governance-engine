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

"""Fail-closed contract tests for ``run_pipeline``.

Each test observes a blocking path actually block, not merely run.
"""

from typing import Any

import pytest

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import (
    Profile,
    StageContext,
    rollback_lifo,
    run_pipeline,
)
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    order_stages,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _Tier:
    """Minimal GovernanceTierPlugin with call recording."""

    def __init__(
        self,
        name: str,
        *,
        phase: int = 1,
        order: int = 0,
        deny: bool = False,
        rollback_raises: bool = False,
        log: list[str] | None = None,
    ) -> None:
        self._name, self._phase, self._order = name, phase, order
        self._deny, self._rollback_raises = deny, rollback_raises
        self.log = log if log is not None else []

    @property
    def tier_name(self) -> str:
        return self._name

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def order(self) -> int:
        return self._order

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    def _verdict(self) -> list[Violation]:
        if self._deny:
            return [Violation(tier=self._name, code="DENY", message="denied", kind=ViolationKind.HARD)]
        return []

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.log.append(f"evaluate:{self._name}")
        return self._verdict()

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.log.append(f"commit:{self._name}")
        return self._verdict()

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        self.log.append(f"rollback:{self._name}")
        if self._rollback_raises:
            raise RuntimeError("rollback exploded")


def _ctx(profile: Profile = Profile.FULL) -> StageContext:
    return StageContext(action="act", params={}, profile=profile)


@pytest.mark.asyncio
async def test_domain_tier_with_plugin_name_is_not_filtered_out() -> None:
    """A tier named outside PROFILE_STAGES (e.g. healthcare) must still deny."""
    stages = order_stages([_Tier("dose_barrier", deny=True)])
    result = await run_pipeline(stages, _ctx(), profile=Profile.FULL)
    assert [v.tier for v in result.violations] == ["dose_barrier"]


@pytest.mark.asyncio
async def test_post_hitl_keeps_its_narrow_scope() -> None:
    """POST_HITL re-checks only its named stages, not every domain tier."""
    log: list[str] = []
    stages = order_stages([_Tier("dose_barrier", deny=True, log=log)])
    result = await run_pipeline(stages, _ctx(Profile.POST_HITL), profile=Profile.POST_HITL)
    assert result.violations == ()
    assert log == []


@pytest.mark.asyncio
async def test_phase1_tiers_run_in_phase_order_then_name() -> None:
    log: list[str] = []
    stages = order_stages([
        _Tier("C", order=2, log=log),
        _Tier("B", order=1, log=log),
        _Tier("A", order=2, log=log),
    ])
    await run_pipeline(stages, _ctx(), profile=Profile.FULL)
    assert log == ["evaluate:B", "evaluate:A", "evaluate:C"]


def test_duplicate_tier_names_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate tier registration"):
        order_stages([_Tier("x"), _Tier("x", order=1)])


@pytest.mark.asyncio
async def test_failed_commit_rolls_back_lifo_and_records_rollback_failure() -> None:
    """A failing rollback must not stop later rollbacks and must add a HARD violation."""
    log: list[str] = []
    stages = order_stages([
        _Tier("m1", phase=2, order=1, log=log),
        _Tier("m2", phase=2, order=2, rollback_raises=True, log=log),
        _Tier("m3", phase=2, order=3, deny=True, log=log),
    ])
    result = await run_pipeline(stages, _ctx(), profile=Profile.FULL)

    assert log == ["commit:m1", "commit:m2", "commit:m3", "rollback:m2", "rollback:m1"]
    codes = [v.code for v in result.violations]
    assert codes == ["DENY", "ROLLBACK_FAILED"]
    assert all(v.kind == ViolationKind.HARD for v in result.violations)


@pytest.mark.asyncio
async def test_rollback_lifo_never_raises() -> None:
    stages = [DomainTierStage(_Tier("a", phase=2, rollback_raises=True))]
    failures = await rollback_lifo(stages, _ctx())
    assert [(v.tier, v.code) for v in failures] == [("a", "ROLLBACK_FAILED")]


@pytest.mark.asyncio
async def test_dry_run_never_commits() -> None:
    log: list[str] = []
    stages = order_stages([_Tier("m", phase=2, log=log)])
    await run_pipeline(stages, _ctx(Profile.DRY_RUN), profile=Profile.DRY_RUN)
    assert log == []


@pytest.mark.asyncio
async def test_read_only_violation_blocks_mutating_stages() -> None:
    log: list[str] = []
    stages = order_stages([_Tier("gate", deny=True, log=log), _Tier("m", phase=2, log=log)])
    result = await run_pipeline(stages, _ctx(), profile=Profile.FULL)
    assert "commit:m" not in log
    assert [v.tier for v in result.violations] == ["gate"]
