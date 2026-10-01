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

"""``ConfidenceStage`` never sees an STPA finding or an undecided OPA verdict.

The deleted POAM-TIER2-001 "structural corroboration" branch fired when STPA
had reported a finding or the OPA verdict was ``None``. Both are unreachable in
the assembled kernel order (ftra → stpa → opa → confidence): every STPA
finding is HARD (``StpaStage`` promotes any non-HARD kind) and every OPA path
that leaves the verdict undecided emits HARD, and ``run_pipeline`` stops at
the first HARD. These tests observe that, with a recording spy in place of
``ConfidenceStage``; the control cases prove the spy does run otherwise.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.assembly import kernel_stages
from src.gateway.governance.governor.pipeline import (
    OpaVerdict,
    Profile,
    Stage,
    StageContext,
    StageOutput,
    run_pipeline,
)
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.governor.stages.ftra import FtraStage
from tests.governor.scope_helpers import run_scoped

pytestmark = [pytest.mark.unit, pytest.mark.local]

_NON_HARD = [k for k in ViolationKind if k is not ViolationKind.HARD]


class _SpyConfidence(ConfidenceStage):
    """Records every context it is run with."""

    def __init__(self) -> None:
        self.seen: list[StageContext] = []

    async def run(self, ctx: StageContext) -> list[Violation]:
        self.seen.append(ctx)
        return await super().run(ctx)


class _NoopFtra:
    """Stands in for FTRA so the test needs no terminal registry."""

    name = "ftra"
    mutating = False

    async def run(self, ctx: StageContext) -> StageOutput:
        return StageOutput()


class _ClaimingTier:
    """A read-only domain stage that claims the action, so it is governed
    and ``confidence`` is in the selected stage set."""

    name = "claiming_tier"
    mutating = False

    def claims(self, ctx: StageContext) -> bool:
        return True

    async def run(self, ctx: StageContext) -> list[Violation]:
        return []


class _Opa:
    def __init__(self, result: Any) -> None:
        self._result = result

    async def evaluate_policy(self, input_data: dict[str, Any], **_: Any) -> Any:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _stpa(*violations: Violation) -> MagicMock:
    validator = MagicMock()
    validator.validate.return_value = list(violations)
    return validator


def _assembled(opa: Any, stpa: Any) -> tuple[list[Stage], _SpyConfidence]:
    """The kernel's own stage assembly, with FTRA stubbed and confidence spied.

    Returned in reverse so the order observed is the pipeline's, not the list's.
    """
    spy = _SpyConfidence()
    stages: list[Stage] = []
    for stage in kernel_stages(opa, stpa):
        if isinstance(stage, ConfidenceStage):
            stages.append(spy)
        elif isinstance(stage, FtraStage):
            stages.append(_NoopFtra())
        else:
            stages.append(stage)
    stages.append(_ClaimingTier())
    return list(reversed(stages)), spy


def _ctx(profile: Profile) -> StageContext:
    return StageContext(action="act", params={"confidence": 0.99}, profile=profile)


async def _run(stages: list[Stage], profile: Profile) -> Any:
    if profile == Profile.DRY_RUN:
        return await run_pipeline(stages, _ctx(profile), profile=profile)
    return await run_scoped(stages, _ctx(profile), profile=profile)


_PROFILES = pytest.mark.parametrize("profile", [Profile.FULL, Profile.DRY_RUN])


@pytest.mark.asyncio
@_PROFILES
@pytest.mark.parametrize("kind", _NON_HARD)
async def test_non_hard_stpa_finding_is_promoted_and_stops_before_confidence(
    profile: Profile, kind: ViolationKind
) -> None:
    """(a) A validator's non-HARD UCA becomes HARD; confidence never runs."""
    finding = Violation(tier="stpa", code="STPA_UCA_TEST", message="uca", kind=kind)
    stages, spy = _assembled(_Opa({"allow": True}), _stpa(finding))

    result = await _run(stages, profile)

    assert [(v.code, v.kind) for v in result.violations] == [
        ("STPA_UCA_TEST", ViolationKind.HARD)
    ]
    assert spy.seen == []


@pytest.mark.asyncio
@_PROFILES
async def test_opa_error_stops_before_confidence(profile: Profile) -> None:
    """(b) OPA raises → OPA_ERROR HARD, verdict None; confidence never runs."""
    stages, spy = _assembled(_Opa(ConnectionError("opa down")), _stpa())

    result = await _run(stages, profile)

    assert [(v.code, v.kind) for v in result.violations] == [("OPA_ERROR", ViolationKind.HARD)]
    assert result.opa_verdict is None
    assert spy.seen == []


@pytest.mark.asyncio
@_PROFILES
@pytest.mark.parametrize("raw", ["REJECT", {"unexpected": 1}, None, 1])
async def test_undecodable_opa_stops_before_confidence(profile: Profile, raw: Any) -> None:
    """(c) OPA answers something undecodable → HARD; confidence never runs."""
    stages, spy = _assembled(_Opa(raw), _stpa())

    result = await _run(stages, profile)

    assert [(v.code, v.kind) for v in result.violations] == [
        ("OPA_UNKNOWN_VERDICT", ViolationKind.HARD)
    ]
    assert result.opa_verdict is None
    assert spy.seen == []


@pytest.mark.asyncio
@_PROFILES
@pytest.mark.parametrize(
    ("raw", "verdict"),
    [({"allow": True}, OpaVerdict.ALLOW), ("MANUAL_REVIEW", OpaVerdict.MANUAL_REVIEW)],
)
async def test_confidence_runs_only_with_a_decided_verdict(
    profile: Profile, raw: Any, verdict: OpaVerdict
) -> None:
    """Control: with clean STPA and a decided verdict the spy does run, once,
    and only ever with that verdict in its context."""
    stages, spy = _assembled(_Opa(raw), _stpa())

    await _run(stages, profile)

    assert [ctx.opa_verdict for ctx in spy.seen] == [verdict]
