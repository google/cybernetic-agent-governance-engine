import pytest
from unittest.mock import MagicMock
from src.cage_finance.plugin import FinanceCagePlugin
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.stpa import StpaStage
from src.gateway.governance.stpa_validator import STPAValidator, UcaRule

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


@pytest.mark.asyncio
async def test_stpa_stage_evaluates_contributed_finance_uca_rules():
    contrib = FinanceCagePlugin().contribute()
    assert len(contrib.uca_rules) >= 5
    stage = StpaStage(validator=STPAValidator(rules=contrib.uca_rules))

    # Defect A3: portfolio_drawdown_pct / current_drawdown > threshold triggers UCA-5
    ctx_breach = StageContext(
        action="execute_trade",
        params={
            "latency_ms": 10.0,
            "current_drawdown": 0.06,
            "risk_assessed": True,
            "compliance_checked": True,
        },
        profile=Profile.FULL,
    )
    violations = await stage.run(ctx_breach)
    assert any(v.code == "STPA_UCA_UCA_5" for v in violations)

    ctx_safe = StageContext(
        action="execute_trade",
        params={
            "latency_ms": 10.0,
            "current_drawdown": 0.02,
            "risk_assessed": True,
            "compliance_checked": True,
        },
        profile=Profile.FULL,
    )
    assert await stage.run(ctx_safe) == []


@pytest.mark.asyncio
async def test_stpa_validator_custom_uca_rule_fails_closed_on_predicate_error():
    def _broken_predicate(_params: dict) -> Violation | None:
        raise RuntimeError("predicate exploded")

    rule = UcaRule(
        uca_id="UCA-TEST-99",
        action_name="custom_action",
        description="Broken rule",
        predicate=_broken_predicate,
    )
    stage = StpaStage(validator=STPAValidator(rules=(rule,)))
    ctx = StageContext(action="custom_action", params={}, profile=Profile.FULL)
    violations = await stage.run(ctx)
    assert len(violations) == 1
    assert violations[0].code == "STPA_UCA_TEST_99"
    assert violations[0].kind == ViolationKind.HARD


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", [k for k in ViolationKind if k is not ViolationKind.HARD]
)
async def test_stpa_stage_promotes_non_hard_findings_to_hard(kind):
    """A UCA is never routable to a human: any non-HARD kind becomes HARD."""
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    finding = Violation(tier="stpa", code="STPA_UCA_X", message="uca", kind=kind, bound=5.0)
    validator = MagicMock()
    validator.validate.return_value = [finding]
    stage = StpaStage(validator=validator)

    violations = await stage.run(ctx)

    assert violations == [
        Violation(tier="stpa", code="STPA_UCA_X", message="uca", kind=ViolationKind.HARD, bound=5.0)
    ]


@pytest.mark.asyncio
async def test_stpa_stage_keeps_hard_findings_identical():
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    finding = Violation(tier="stpa", code="STPA_UCA_Y", message="uca", kind=ViolationKind.HARD)
    validator = MagicMock()
    validator.validate.return_value = [finding]
    stage = StpaStage(validator=validator)

    violations = await stage.run(ctx)

    assert len(violations) == 1 and violations[0] is finding
