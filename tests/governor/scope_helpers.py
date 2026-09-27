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

"""Test helpers for driving the pipeline through a ``ReservationScope``."""

from collections.abc import Sequence

from src.gateway.governance.contracts import CommitReceipt, Violation
from src.gateway.governance.governor.pipeline import (
    PipelineResult,
    Profile,
    Stage,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope

TEST_SEAL = "test-seal"


async def run_scoped(
    stages: Sequence[Stage], ctx: StageContext, *, profile: Profile = Profile.FULL
) -> PipelineResult:
    """Run a mutating profile the way the governor does, sealing a clean run.

    A clean run keeps its commits (the scope is sealed); a refused run has
    already been rolled back by the pipeline.
    """
    async with ReservationScope() as scope:
        result = await run_pipeline(stages, ctx, profile=profile, scope=scope)
        if not result.violations:
            scope.seal_issued(TEST_SEAL)
        return result


class _Preset:
    """Stage adapter whose commit() hands back an already-known receipt."""

    mutating = True

    def __init__(self, stage: Stage, receipt: CommitReceipt) -> None:
        self._stage, self._receipt, self.name = stage, receipt, stage.name

    async def commit(self, ctx: StageContext) -> tuple[list[Violation], CommitReceipt]:
        return [], self._receipt

    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        await self._stage.rollback(ctx, receipt)


async def rollback_pairs(
    committed: Sequence[tuple[Stage, CommitReceipt]], ctx: StageContext
) -> list[Violation]:
    """Record ``committed`` in a fresh scope and roll it back explicitly."""
    async with ReservationScope() as scope:
        for stage, receipt in committed:
            await scope.commit(_Preset(stage, receipt), ctx)
        return await scope.rollback()
