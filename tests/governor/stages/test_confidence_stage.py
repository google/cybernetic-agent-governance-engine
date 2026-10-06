import math
from unittest.mock import patch

import pytest

from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.governor.pipeline import OpaVerdict, Profile, StageContext
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.governor.verdicts import (
    reported_confidence as _reported_confidence,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.asyncio
@patch(
    "src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold",
    return_value=0.8,
)
async def test_confidence_stage_happy_path(mock_threshold):
    ctx = StageContext(
        action="test_action",
        params={"confidence": 0.9},
        profile=Profile.FULL,
        opa_verdict=OpaVerdict.ALLOW,
    )
    stage = ConfidenceStage()

    violations = await stage.run(ctx)
    assert violations == []


@pytest.mark.asyncio
@patch(
    "src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold",
    return_value=0.8,
)
@pytest.mark.parametrize(
    "invalid_val, expected_msg",
    [
        (None, "missing"),
        (True, "invalid type"),
        (False, "invalid type"),
        ("high", "invalid type"),
        (float("nan"), "NaN"),
        (float("inf"), "infinite"),
        (-0.1, "negative"),
        (1.1, "exceeds maximum 1.0"),
        (0.4, "< threshold"),  # 0.4 < 0.5 (confidence.defer_floor) -> DEFERRABLE
    ],
)
async def test_confidence_stage_fail_closed(mock_threshold, invalid_val, expected_msg):
    ctx = StageContext(
        action="test_action",
        params={"confidence": invalid_val},
        profile=Profile.FULL,
    )
    stage = ConfidenceStage()

    violations = await stage.run(ctx)
    assert len(violations) >= 1
    assert any(expected_msg in v.message for v in violations)
    if expected_msg == "< threshold":
        assert violations[0].kind == ViolationKind.DEFERRABLE


@pytest.mark.asyncio
@patch(
    "src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold",
    return_value=0.8,
)
@pytest.mark.parametrize("bool_val", [True, False])
async def test_confidence_stage_rejects_bool_confidence(mock_threshold, bool_val):
    ctx = StageContext(
        action="test_action",
        params={"confidence": bool_val},
        profile=Profile.FULL,
        opa_verdict=OpaVerdict.ALLOW,
    )
    stage = ConfidenceStage()

    violations = await stage.run(ctx)
    assert len(violations) == 1
    assert violations[0].code == "CONFIDENCE_INVALID"
    assert violations[0].kind == ViolationKind.HARD
    assert _reported_confidence({"confidence": bool_val}) == 0.0


@pytest.mark.asyncio
@patch(
    "src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold",
    return_value=0.8,
)
async def test_confidence_stage_judges_confidence_alone(mock_threshold):
    """No structural override: the stage reads only the agent's confidence.

    STPA findings and an undecided OPA verdict are HARD upstream, so
    run_pipeline never reaches this stage with either (see
    tests/governor/test_confidence_unreachable_after_hard.py).
    """
    ctx = StageContext(
        action="test_action",
        params={"confidence": 0.9},
        profile=Profile.FULL,
    )
    stage = ConfidenceStage()

    assert await stage.run(ctx) == []
