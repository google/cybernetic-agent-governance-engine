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

"""Per-request facts never live on shared stage instances (plan §5b step 3).

Stages are built once by the composition root and shared by every concurrent
request. ``OpaStage`` used to park the decoded verdict on ``self`` and
``FtraStage`` its boundary result, for ``run_pipeline`` to read back. Both
now return a :class:`StageOutput`. These tests pin that:

* ``run()`` leaves the stage's ``vars()`` untouched (the old design wrote the
  verdict / boundary result onto the instance and fails this);
* two interleaved pipelines whose OPA answers arrive out of order each see
  their own verdict, in their ``PipelineResult`` and in the ``StageContext``
  handed to later stages.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.gateway.governance.ftra.models import FtraBoundaryResult
from src.gateway.governance.governor.pipeline import (
    OpaVerdict,
    Profile,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.stages.ftra import FtraStage
from src.gateway.governance.governor.stages.opa import OpaStage

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _OutOfOrderPolicy:
    """OPA client whose request "A" answers only after request "B" has."""

    def __init__(self) -> None:
        self.b_answered = asyncio.Event()

    async def evaluate_policy(self, input_data: dict, **_: Any) -> object:
        if input_data["req"] == "A":
            await self.b_answered.wait()
            return {"allow": True}
        self.b_answered.set()
        # Non-HARD, so B's later stages still run (a HARD stops phase 1).
        return "MANUAL_REVIEW"


class _RecordingStage:
    """Read-only domain tier that records the OPA verdict its context carried.

    It claims the action, so the pipeline treats the call as governed and runs
    it after OPA (ungoverned calls run only ftra/stpa/opa).
    """

    name = "recorder"
    mutating = False

    def __init__(self) -> None:
        self.seen: dict[str, OpaVerdict | None] = {}

    def claims(self, ctx: StageContext) -> bool:
        return True

    async def run(self, ctx: StageContext) -> list:
        # Test-only probe: deliberately keyed per request, so it is not shared state.
        self.seen[ctx.params["req"]] = ctx.opa_verdict
        return []


async def test_opa_stage_run_leaves_instance_state_untouched() -> None:
    stage = OpaStage(_OutOfOrderPolicy())
    before = dict(vars(stage))

    out = await stage.run(StageContext(action="x", params={"req": "B"}, profile=Profile.FULL))

    assert out.opa_verdict == OpaVerdict.MANUAL_REVIEW
    assert dict(vars(stage)) == before


async def test_ftra_stage_run_leaves_instance_state_untouched() -> None:
    def _result(classification: str) -> FtraBoundaryResult:
        return FtraBoundaryResult(
            requires_hitl=False,
            irreversibility_score=0.0,
            classification=classification,
            terminal_match=None,
            violations=[],
            bypassed_ftra_node=False,
        )

    results = {"A": _result("READ_ONLY"), "B": _result("REVERSIBLE")}

    class _Ftra(FtraStage):
        async def _ftra_boundary_check(self, tool_name, tool_input, *, detect_bypass=True):
            return results[tool_input["req"]]

    stage = _Ftra()
    before = dict(vars(stage))

    out_a, out_b = await asyncio.gather(
        stage.run(StageContext(action="x", params={"req": "A"}, profile=Profile.FULL)),
        stage.run(StageContext(action="x", params={"req": "B"}, profile=Profile.FULL)),
    )

    assert out_a.ftra is results["A"]
    assert out_b.ftra is results["B"]
    assert dict(vars(stage)) == before


async def test_interleaved_pipelines_never_observe_each_others_opa_verdict() -> None:
    opa = OpaStage(_OutOfOrderPolicy())
    recorder = _RecordingStage()
    stages = [opa, recorder]

    def _ctx(req: str) -> StageContext:
        return StageContext(action="execute_trade", params={"req": req}, profile=Profile.DRY_RUN)

    # A starts first but its OPA answer lands after B's has been decoded.
    result_a, result_b = await asyncio.gather(
        run_pipeline(stages, _ctx("A"), profile=Profile.DRY_RUN),
        run_pipeline(stages, _ctx("B"), profile=Profile.DRY_RUN),
    )

    assert result_a.opa_verdict == OpaVerdict.ALLOW
    assert result_b.opa_verdict == OpaVerdict.MANUAL_REVIEW
    assert [v.code for v in result_a.violations] == []
    assert [v.code for v in result_b.violations] == ["OPA_MANUAL_REVIEW"]
    # Later stages get the verdict of their own request.
    assert recorder.seen == {"A": OpaVerdict.ALLOW, "B": OpaVerdict.MANUAL_REVIEW}
