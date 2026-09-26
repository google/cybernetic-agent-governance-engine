import pytest
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.contracts import PolicyClient, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import OpaVerdict
from src.gateway.governance.governor.stages.opa import OpaStage, decode_opa_verdict

pytestmark = [pytest.mark.unit, pytest.mark.local]

class MockPolicyClient:
    def __init__(self, result_to_return):
        self.result_to_return = result_to_return

    async def evaluate_policy(self, input_data: dict, **kwargs) -> object:
        if isinstance(self.result_to_return, Exception):
            raise self.result_to_return
        return self.result_to_return


@pytest.mark.parametrize("raw_input, expected_verdict", [
    # str exact matches
    ("ALLOW", OpaVerdict.ALLOW),
    (" ALLOW ", OpaVerdict.ALLOW),
    ("DENY", OpaVerdict.DENY),
    ("GOVERNANCE_VIOLATION", OpaVerdict.DENY),
    ("MANUAL_REVIEW", OpaVerdict.MANUAL_REVIEW),
    ("REJECT", None),
    ("ERROR", None),
    ("NONE", None),
    
    # dict matches
    ({"allow": True}, OpaVerdict.ALLOW),
    ({"allow": False}, OpaVerdict.DENY),
    ({"decision": "ALLOW"}, OpaVerdict.ALLOW),
    ({"decision": "DENY"}, OpaVerdict.DENY),
    ({"allow": True, "decision": "DENY"}, OpaVerdict.DENY),  # decision wins
    ({"allow": None}, None),
    ({}, None),
    
    # bool matches
    (True, OpaVerdict.ALLOW),
    (False, OpaVerdict.DENY),
    
    # invalid types
    (1, None),
    ([], None),
    (None, None),
])
def test_decode_opa_verdict(raw_input, expected_verdict):
    """Test the raw OPA response decoding logic."""
    assert decode_opa_verdict(raw_input) == expected_verdict


@pytest.mark.asyncio
async def test_opa_stage_returns_empty_list_for_allow():
    """OpaStage returns [] for ALLOW verdict."""
    client = MockPolicyClient({"allow": True})
    stage = OpaStage(client)
    
    violations = await stage.run("execute_trade", {"amount": 100})
    assert violations == []
    assert stage.decoded_verdict == OpaVerdict.ALLOW


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_for_deny():
    """OpaStage returns a HARD violation for DENY verdict."""
    client = MockPolicyClient("DENY")
    stage = OpaStage(client)
    
    violations = await stage.run("execute_trade", {"amount": 100})
    assert len(violations) == 1
    assert violations[0].code == "OPA_DENY"
    assert violations[0].kind == ViolationKind.HARD
    assert stage.decoded_verdict == OpaVerdict.DENY


@pytest.mark.asyncio
async def test_opa_stage_returns_hitl_violation_for_manual_review():
    """OpaStage returns a HITL violation for MANUAL_REVIEW verdict."""
    client = MockPolicyClient("MANUAL_REVIEW")
    stage = OpaStage(client)
    
    violations = await stage.run("execute_trade", {"amount": 100})
    assert len(violations) == 1
    assert violations[0].code == "OPA_MANUAL_REVIEW"
    assert violations[0].kind == ViolationKind.HITL
    assert stage.decoded_verdict == OpaVerdict.MANUAL_REVIEW


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_for_unknown():
    """OpaStage returns a HARD violation for unknown verdicts."""
    client = MockPolicyClient("SOMETHING_ELSE")
    stage = OpaStage(client)
    
    violations = await stage.run("execute_trade", {"amount": 100})
    assert len(violations) == 1
    assert violations[0].code == "OPA_UNKNOWN_VERDICT"
    assert violations[0].kind == ViolationKind.HARD
    assert stage.decoded_verdict is None


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_on_exception():
    """OpaStage returns a HARD violation when policy evaluation raises an exception."""
    client = MockPolicyClient(RuntimeError("Connection lost"))
    stage = OpaStage(client)
    
    violations = await stage.run("execute_trade", {"amount": 100})
    assert len(violations) == 1
    assert violations[0].code == "OPA_ERROR"
    assert violations[0].kind == ViolationKind.HARD
    assert "Connection lost" in violations[0].message
    assert stage.decoded_verdict is None

