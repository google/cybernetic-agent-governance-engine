import pytest
import math
from unittest.mock import patch
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.governor.pipeline import StageContext, Profile, OpaVerdict
from src.gateway.governance.contracts import ViolationKind

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.asyncio
@patch("src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold", return_value=0.8)
async def test_confidence_stage_happy_path(mock_threshold):
    ctx = StageContext(action="test_action", params={"confidence": 0.9}, profile=Profile.FULL, stpa_violation_count=0, opa_verdict=OpaVerdict.ALLOW)
    stage = ConfidenceStage()
    
    violations = await stage.run(ctx)
    assert violations == []

@pytest.mark.asyncio
@patch("src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold", return_value=0.8)
@pytest.mark.parametrize("invalid_val, expected_msg", [
    (None, "missing"),
    ("high", "invalid type"),
    (float("nan"), "NaN"),
    (float("inf"), "infinite"),
    (-0.1, "negative"),
    (1.1, "exceeds maximum 1.0"),
    (0.4, "< threshold"), # 0.4 < 0.5 (FRIA_ZONE_DEFER) -> DEFERRABLE
])
async def test_confidence_stage_fail_closed(mock_threshold, invalid_val, expected_msg):
    ctx = StageContext(action="test_action", params={"confidence": invalid_val}, profile=Profile.FULL, stpa_violation_count=0)
    stage = ConfidenceStage()
    
    violations = await stage.run(ctx)
    assert len(violations) >= 1
    assert any(expected_msg in v.message for v in violations)
    if expected_msg == "< threshold":
        assert violations[0].kind == ViolationKind.DEFERRABLE

@pytest.mark.asyncio
@patch("src.gateway.governance.governor.stages.confidence.get_agent_confidence_threshold", return_value=0.8)
async def test_confidence_stage_structural_corroboration_override(mock_threshold):
    # Agent claims 0.9 confidence (>= 0.8), but STPA violations > 0
    ctx = StageContext(action="test_action", params={"confidence": 0.9}, profile=Profile.FULL, stpa_violation_count=1)
    stage = ConfidenceStage()
    
    violations = await stage.run(ctx)
    assert len(violations) == 1
    assert violations[0].code == "TIER2_STRUCTURAL_OVERRIDE"
    assert violations[0].kind == ViolationKind.HITL
