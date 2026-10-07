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

"""Issue a routing seal only over a clean run, inside that run's ReservationScope.

Every seal the governor issues (ALLOW on each entry point, and NARROW over
re-verified params) goes through ``run_sealed``.  Phase-2 commits stay in
force only once the seal is issued; any other exit rolls them all back.
The commits behind an issued seal go to the governor's
:class:`~.settlement.SettlementLedger`, which confirms or releases them once
the caller reports whether the sealed action ran.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.pipeline import (
    PipelineResult,
    Stage,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope
from src.gateway.governance.governor.settlement import SettlementLedger
from src.gateway.governance.governor.verdicts import issue_seal


async def run_sealed(
    stages: Sequence[Stage],
    ctx: StageContext,
    params: dict[str, Any],
    *,
    path: str,
    settlements: SettlementLedger,
    on_seal: Callable[[str], Awaitable[None]] | None = None,
) -> tuple[PipelineResult, str | None]:
    """Run ``ctx.profile`` and seal ``params`` if the run is clean.

    Returns ``(result, None)`` when the run has violations (nothing stays
    committed).  A failing seal or a cancellation propagates after the scope
    has rolled every commit back.  ``on_seal(seal)`` runs inside the scope
    before the commits are kept: if it raises, they are rolled back and the
    error propagates, so a seal whose companion artefact (e.g. a NARROW
    receipt) could not be delivered never holds reserved headroom.  Once the
    seal is issued its commits are held in ``settlements`` under the seal.

    The seal's evidence record commits to the run's warrant reliance records
    (``PipelineResult.reliance``), so the seal proves which warrants grounded
    the decision it authorises.
    """
    async with ReservationScope() as scope:
        result = await run_pipeline(stages, ctx, profile=ctx.profile, scope=scope)
        if result.violations:
            assert_nothing_committed(result)
            return result, None
        # The clean run's reliance records go into the seal's evidence record.
        seal = await issue_seal(ctx.action, params, path=path, reliance=result.reliance)
        if on_seal is not None:
            await on_seal(seal)
        settlements.hold(seal, scope.seal_issued(seal))
        return result, seal


def assert_nothing_committed(result: PipelineResult) -> None:
    """A refused run must leave nothing committed; commits are made only when clean."""
    if result.commits:
        stages = ", ".join(stage.name for stage, _ in result.commits)
        raise GovernanceError(
            f"[UNROLLED_COMMIT] refused run left commits outstanding: {stages}"
        )
