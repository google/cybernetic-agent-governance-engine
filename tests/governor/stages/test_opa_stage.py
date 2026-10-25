from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import PolicyClient, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import OpaVerdict, Profile
from src.gateway.governance.governor.stages.opa import OpaStage, decode_opa_verdict

pytestmark = [pytest.mark.unit, pytest.mark.local]


class MockPolicyClient:
    def __init__(self, result_to_return):
        self.result_to_return = result_to_return

    async def evaluate_policy(self, input_data: dict, **kwargs) -> object:
        if isinstance(self.result_to_return, Exception):
            raise self.result_to_return
        return self.result_to_return


@pytest.mark.parametrize(
    "raw_input, expected_verdict",
    [
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
    ],
)
def test_decode_opa_verdict(raw_input, expected_verdict):
    """Test the raw OPA response decoding logic."""
    assert decode_opa_verdict(raw_input) == expected_verdict


@pytest.mark.asyncio
async def test_opa_stage_returns_empty_list_for_allow():
    """OpaStage returns no violations and the ALLOW verdict."""
    client = MockPolicyClient({"allow": True})
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert violations == []
    assert out.opa_verdict == OpaVerdict.ALLOW


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_for_deny():
    """OpaStage returns a HARD violation for DENY verdict."""
    client = MockPolicyClient("DENY")
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert len(violations) == 1
    assert violations[0].code == "OPA_DENY"
    assert violations[0].kind == ViolationKind.HARD
    assert out.opa_verdict == OpaVerdict.DENY


@pytest.mark.asyncio
async def test_opa_stage_returns_hitl_violation_for_manual_review():
    """OpaStage returns a HITL violation for MANUAL_REVIEW verdict."""
    client = MockPolicyClient("MANUAL_REVIEW")
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert len(violations) == 1
    assert violations[0].code == "OPA_MANUAL_REVIEW"
    assert violations[0].kind == ViolationKind.HITL
    assert out.opa_verdict == OpaVerdict.MANUAL_REVIEW


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_for_unknown():
    """OpaStage returns a HARD violation for unknown verdicts."""
    client = MockPolicyClient("SOMETHING_ELSE")
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert len(violations) == 1
    assert violations[0].code == "OPA_UNKNOWN_VERDICT"
    assert violations[0].kind == ViolationKind.HARD
    assert out.opa_verdict is None


@pytest.mark.asyncio
async def test_opa_stage_returns_hard_violation_on_exception():
    """OpaStage returns a HARD violation when policy evaluation raises an exception."""
    client = MockPolicyClient(RuntimeError("Connection lost"))
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert len(violations) == 1
    assert violations[0].code == "OPA_ERROR"
    assert violations[0].kind == ViolationKind.HARD
    assert "Connection lost" in violations[0].message
    assert out.opa_verdict is None


class RecordingPolicyClient:
    def __init__(self) -> None:
        self.inputs: list[dict] = []

    async def evaluate_policy(self, input_data: dict, **kwargs) -> object:
        self.inputs.append(input_data)
        return "ALLOW"


@pytest.mark.asyncio
async def test_opa_stage_sends_the_params_once_with_the_action():
    """The OPA input is the params plus the action; nothing is duplicated."""
    client = RecordingPolicyClient()
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade",
        params={"amount": 100, "symbol": "AAPL"},
        profile=Profile.FULL,
    )
    await stage.run(ctx)

    assert client.inputs == [
        {"amount": 100, "symbol": "AAPL", "action": "execute_trade"}
    ]


@pytest.mark.asyncio
async def test_opa_stage_clears_manual_review_in_post_hitl():
    """Under Profile.POST_HITL, MANUAL_REVIEW is satisfied by the human approval being redeemed."""
    client = MockPolicyClient("MANUAL_REVIEW")
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 7500}, profile=Profile.POST_HITL
    )
    out = await stage.run(ctx)
    assert list(out.violations) == []
    assert out.opa_verdict == OpaVerdict.MANUAL_REVIEW


@pytest.mark.asyncio
async def test_opa_stage_still_denies_on_deny_in_post_hitl():
    """Under Profile.POST_HITL, policy drift to DENY still emits a HARD violation."""
    client = MockPolicyClient("DENY")
    stage = OpaStage(client)

    from src.gateway.governance.governor.pipeline import StageContext

    ctx = StageContext(
        action="execute_trade", params={"amount": 15000}, profile=Profile.POST_HITL
    )
    out = await stage.run(ctx)
    violations = list(out.violations)
    assert len(violations) == 1
    assert violations[0].code == "OPA_DENY"
    assert violations[0].kind == ViolationKind.HARD
    assert out.opa_verdict == OpaVerdict.DENY
