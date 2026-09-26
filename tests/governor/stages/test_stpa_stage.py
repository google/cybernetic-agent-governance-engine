import pytest
from unittest.mock import MagicMock
from src.gateway.governance.governor.stages.stpa import StpaStage
from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator as STPAValidator
from src.gateway.governance.governor.pipeline import StageContext, Profile
from src.gateway.governance.contracts import Violation, ViolationKind

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.asyncio
async def test_stpa_stage_happy_path():
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    validator = MagicMock()
    validator.validate.return_value = []
    stage = StpaStage(validator=validator)
    
    violations = await stage.run(ctx)
    assert violations == []

@pytest.mark.asyncio
async def test_stpa_stage_fail_closed_on_error():
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    validator = MagicMock()
    validator.validate.side_effect = Exception("STPA boom")
    stage = StpaStage(validator=validator)
    
    violations = await stage.run(ctx)
    assert len(violations) == 1
    assert violations[0].code == "STPA_ERROR"
    assert violations[0].kind == ViolationKind.HARD
    assert "STPA boom" in violations[0].message
