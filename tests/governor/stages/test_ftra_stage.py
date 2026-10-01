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
        
        out = await stage.run(ctx)
        violations = list(out.violations)
        
        assert violations == []
        mock_check.assert_called_once_with(tool_name="test_action", tool_input={}, detect_bypass=True)

@pytest.mark.asyncio
async def test_ftra_stage_fail_closed_on_error():
    # It says "each fail-closed path (classifier raises; ... ) observed blocking"
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    stage = FtraStage()
    
    # The real exception handling in _ftra_boundary_check: the classifier raises.
    with patch.object(stage, "_get_ftra_classifier", side_effect=Exception("Boom")):
        out = await stage.run(ctx)
        violations = list(out.violations)
        
        assert len(violations) == 1
        assert violations[0].code == "FTRA_ERROR"
        assert violations[0].kind == ViolationKind.HARD
        assert "Boom" in violations[0].message
        assert out.ftra is not None
        assert out.ftra.requires_hitl is True
        assert out.ftra.classification == "IRREVERSIBLE_TERMINAL"


@pytest.mark.asyncio
async def test_ftra_stage_fail_closed_when_classify_raises():
    """A classifier whose lookup raises fails closed to a HARD FTRA_ERROR."""
    ctx = StageContext(action="test_action", params={"amount": 1.0}, profile=Profile.FULL)
    stage = FtraStage(magnitude_extractor=lambda p: p["amount"])
    classifier = MagicMock()
    classifier.classify_with_provenance.side_effect = RuntimeError("registry lookup exploded")
    stage._ftra_classifier = classifier

    out = await stage.run(ctx)

    assert [(v.code, v.kind) for v in out.violations] == [("FTRA_ERROR", ViolationKind.HARD)]
    assert out.ftra is not None and out.ftra.auto_cleared is False
