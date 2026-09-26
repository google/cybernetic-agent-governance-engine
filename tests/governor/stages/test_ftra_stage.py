import pytest
from unittest.mock import patch, MagicMock
from src.gateway.governance.governor.stages.ftra import FtraStage
from src.gateway.governance.governor.pipeline import StageContext, Profile
from src.gateway.governance.contracts import ViolationKind

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.asyncio
async def test_ftra_stage_happy_path():
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    stage = FtraStage()
    
    with patch.object(stage, "_ftra_boundary_check") as mock_check:
        mock_result = MagicMock()
        mock_result.violations = []
        mock_check.return_value = mock_result
        
        violations = await stage.run(ctx)
        
        assert violations == []
        mock_check.assert_called_once_with(tool_name="test_action", tool_input={}, detect_bypass=True)

@pytest.mark.asyncio
async def test_ftra_stage_fail_closed_on_error():
    # It says "each fail-closed path (classifier raises; ... ) observed blocking"
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    stage = FtraStage()
    
    # We want to test the actual exception handling in _ftra_boundary_check
    with patch("src.gateway.governance.governor.stages.ftra.validate_tool_input", side_effect=Exception("Boom")):
        violations = await stage.run(ctx)
        
        assert len(violations) == 1
        assert violations[0].code == "FTRA_ERROR"
        assert violations[0].kind == ViolationKind.HARD
        assert "Boom" in violations[0].message
