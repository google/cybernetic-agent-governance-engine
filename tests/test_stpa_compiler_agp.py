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

"""Tests for generate_agp() in stpa_compiler.py — AGP NL output, budget guard, CBF omission."""

from __future__ import annotations

import pytest

from src.gateway.governance.stpa_compiler import (
    ConditionModel,
    ConstraintModel,
    ControlStructureModel,
    HazardModel,
    NemoRailModel,
    OpaRuleModel,
    RbacRoleModel,
    RbacRulesModel,
    SystemModel,
    UCAModel,
    generate_agp,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SYSTEM = SystemModel(
    name="Test System",
    version="1.0.0",
    description="Test",
    controller="TestController",
    controlled_process="TestProcess",
)

_HAZARD = HazardModel(id="H-1", description="Test hazard", severity="high")


def _make_cs(ucas: list[UCAModel], rbac_rules=None) -> ControlStructureModel:
    return ControlStructureModel(
        system=_SYSTEM,
        hazards=[_HAZARD],
        control_actions=[],
        unsafe_control_actions=ucas,
        safety_constraints=[
            ConstraintModel(
                id="SC-1",
                description="Test constraint",
                logic="always",
                scope=["all"],
            )
        ],
        rbac_rules=rbac_rules,
    )


def _make_uca(
    uca_id: str,
    action: str,
    operator: str | None = None,
    param: str | None = None,
    threshold: float | None = None,
    composite: str | None = None,
    enforcement: list[str] | None = None,
    nemo_rail: NemoRailModel | None = None,
    opa_rule: OpaRuleModel | None = None,
) -> UCAModel:
    condition = ConditionModel(
        operator=operator,
        param=param,
        threshold=threshold,
        composite=composite,
    )
    eff_enforcement = enforcement or ["python"]
    if "opa" in eff_enforcement and opa_rule is None:
        opa_rule = OpaRuleModel(decision="DENY", message=f"OPA deny for {uca_id}")
    if "nemo" in eff_enforcement and nemo_rail is None:
        nemo_rail = NemoRailModel(
            flow_name=f"flow_{uca_id.lower()}", message=f"nemo block {uca_id}"
        )
    return UCAModel(
        id=uca_id,
        action=action,
        uca_type="unsafe_action",
        hazard_refs=["H-1"],
        description=f"Test UCA {uca_id}",
        condition=condition,
        enforcement=eff_enforcement,
        opa_rule=opa_rule,
        nemo_rail=nemo_rail,
    )


# ---------------------------------------------------------------------------
# Operator mapping tests
# ---------------------------------------------------------------------------


class TestGenerateAGPOperatorMapping:
    def test_is_null_operator_produces_correct_nl(self):
        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert (
            'Do not execute "execute_trade" if "amount" is null or missing.' in output
        )

    def test_is_false_operator_produces_correct_nl(self):
        uca = _make_uca(
            "UCA-002", "execute_trade", operator="is_false", param="approved"
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert (
            'Do not execute "execute_trade" if "approved" is false or not set to true.'
            in output
        )

    def test_greater_than_operator_with_threshold_produces_correct_nl(self):
        uca = _make_uca(
            "UCA-003",
            "execute_trade",
            operator="greater_than",
            param="amount",
            threshold=500000.0,
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert 'Do not execute "execute_trade" if "amount" exceeds 500000.0.' in output

    def test_less_than_operator_with_threshold_produces_correct_nl(self):
        uca = _make_uca(
            "UCA-004",
            "execute_trade",
            operator="less_than",
            param="confidence",
            threshold=0.8,
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert 'Do not execute "execute_trade" if "confidence" is below 0.8.' in output

    def test_equals_operator_produces_correct_nl(self):
        uca = _make_uca(
            "UCA-005",
            "execute_trade",
            operator="equals",
            param="currency",
            threshold=0.0,
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert 'Do not execute "execute_trade" if "currency" equals' in output

    def test_composite_condition_produces_general_constraint(self):
        uca = _make_uca(
            "UCA-006", "execute_trade", composite="amount > 0 AND approved == True"
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert 'Do not execute "execute_trade" when:' in output
        assert "amount > 0 AND approved == True" in output

    def test_nemo_rail_message_produces_block_sentence(self):
        nemo_rail = NemoRailModel(
            flow_name="block_flow", message="contains CBRN content"
        )
        uca = _make_uca(
            "UCA-007",
            "generate_response",
            composite="cbrn_detected",
            enforcement=["nemo"],
            nemo_rail=nemo_rail,
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert "Block any request that contains CBRN content" in output

    def test_is_true_operator_produces_correct_nl(self):
        uca = _make_uca(
            "UCA-008", "execute_trade", operator="is_true", param="emergency_override"
        )
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert (
            'Do not execute "execute_trade" if "emergency_override" is true.' in output
        )


# ---------------------------------------------------------------------------
# CBF invariant omission test
# ---------------------------------------------------------------------------


class TestGenerateAGPCBFOmission:
    def test_cbf_invariant_not_in_output(self):
        """CBF invariants are not mappable to AGP NL — they must be omitted."""
        # CBF invariants are defined in safety_constraints, not UCAs.
        # The generate_agp() function only processes UCAs, so CBF constraints
        # are structurally omitted. Verify the output contains no CBF references.
        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        output = generate_agp(cs)
        # CBF-specific terms should not appear in AGP output
        assert "cbf" not in output.lower()
        assert "barrier" not in output.lower()


# ---------------------------------------------------------------------------
# Character budget tests
# ---------------------------------------------------------------------------


class TestGenerateAGPBudget:
    def test_output_within_5000_char_budget_for_small_cs(self):
        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert len(output) <= 5000

    def test_truncation_sentinel_added_when_budget_exceeded(self):
        """Generate a CS with enough UCAs to exceed the 5,000-char budget."""
        ucas = [
            _make_uca(
                f"UCA-{i:03d}",
                f"action_{i}",
                composite="very long composite condition that takes up space in the output "
                * 3,
            )
            for i in range(50)
        ]
        cs = _make_cs(ucas)
        output = generate_agp(cs)
        if len(output) > 5000 or "# TRUNCATED" in output:
            assert "# TRUNCATED" in output
            assert len(output) <= 5000 + 100  # Allow small overshoot for sentinel

    def test_output_is_string(self):
        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert isinstance(output, str)

    def test_output_contains_system_header(self):
        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        output = generate_agp(cs)
        assert "Test System" in output
        assert "1.0.0" in output


# ---------------------------------------------------------------------------
# RBAC rules tests
# ---------------------------------------------------------------------------


class TestGenerateAGPRBAC:
    def test_rbac_manual_review_produces_human_approval_sentence(self):
        role = RbacRoleModel(
            name="junior",
            allowed_actions=["execute_trade"],
            trade_limits={"allow_below": 5000, "manual_review_below": 500000},
        )
        rbac = RbacRulesModel(roles=[role])
        cs = _make_cs([], rbac_rules=rbac)
        output = generate_agp(cs)
        assert 'Require human approval for "execute_trade"' in output
        assert '"junior" role users' in output

    def test_rbac_currency_denylist_produces_deny_sentence(self):
        role = RbacRoleModel(
            name="junior",
            allowed_actions=["execute_trade"],
            trade_limits={"allow_below": 5000, "manual_review_below": 500000},
            restrictions=[{"currency_denylist": ["XAU", "XBT"]}],
        )
        rbac = RbacRulesModel(roles=[role])
        cs = _make_cs([], rbac_rules=rbac)
        output = generate_agp(cs)
        assert 'Deny "execute_trade" where "currency" is "XAU"' in output
        assert 'Deny "execute_trade" where "currency" is "XBT"' in output


# ---------------------------------------------------------------------------
# compile_control_structure agp target tests
# ---------------------------------------------------------------------------


class TestCompileControlStructureAGP:
    def test_agp_target_populates_agp_content(self):
        from src.gateway.governance.stpa_compiler import compile_control_structure

        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        result = compile_control_structure(cs, ["agp"])
        assert result.agp_content != ""
        assert result.errors == []

    def test_agp_not_in_all_target(self):
        """'all' target should NOT include agp (agp must be explicitly requested)."""
        from src.gateway.governance.stpa_compiler import compile_control_structure

        uca = _make_uca("UCA-001", "execute_trade", operator="is_null", param="amount")
        cs = _make_cs([uca])
        result = compile_control_structure(cs, ["all"])
        # 'all' expands to opa/nemo/python/langgraph — agp is separate
        assert result.agp_content == ""


pytestmark = [pytest.mark.unit, pytest.mark.local]
