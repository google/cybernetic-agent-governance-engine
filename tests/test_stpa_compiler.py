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

"""
Tests for the STPA-to-Policy Compiler (src/gateway/governance/stpa_compiler.py).

Covers:
  - Schema validation (valid and malformed YAML)
  - OPA Rego code generation
  - NeMo Colang rail generation
  - Python validator generation
  - CLI validate and compile commands (dry-run)
  - Enforcement dependency validation (missing opa_rule / nemo_rail)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    compile_control_structure,
    generate_nemo,
    generate_opa,
    generate_python,
    load_control_structure,
    main,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_YAML = """\
system:
  name: "Test System"
  version: "0.1"
  description: "Unit test system"
  controller: "Test Controller"
  controlled_process: "Test Process"

hazards:
  - id: H-1
    description: "Unauthorized action."
    severity: critical

control_actions:
  - name: do_thing
    description: "Perform a controlled action."
    params:
      - name: token
        type: string
        required: true

unsafe_control_actions:
  - id: UCA-1
    action: do_thing
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Action performed without a token."
    condition:
      param: token
      operator: is_null
    enforcement: [opa, python]
    opa_rule:
      decision: DENY
      message: "UCA-1: token is required."

safety_constraints:
  - id: SC-1
    uca_ref: UCA-1
    description: "Token must always be present."
    logic: "has_token == True"
    scope: [do_thing]
"""

_NEMO_YAML = """\
system:
  name: "NeMo Test System"
  version: "0.1"
  description: "NeMo rail test"
  controller: "Agent"
  controlled_process: "Market"

hazards:
  - id: H-1
    description: "PII leak."
    severity: high

control_actions:
  - name: respond
    description: "LLM response to user."
    params: []

unsafe_control_actions:
  - id: UCA-1
    action: respond
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Agent outputs PII."
    condition:
      semantic_pattern: output_contains_pii
    enforcement: [nemo]
    nemo_rail:
      flow_name: block_pii_output
      message: "I cannot share personal information."

safety_constraints: []
"""

_FULL_YAML_PATH = (
    Path(__file__).resolve().parents[1] / "config" / "stpa_control_structure.yaml"
)


@pytest.fixture
def minimal_cs() -> ControlStructureModel:
    raw = yaml.safe_load(_MINIMAL_YAML)
    return ControlStructureModel(**raw)


@pytest.fixture
def nemo_cs() -> ControlStructureModel:
    raw = yaml.safe_load(_NEMO_YAML)
    return ControlStructureModel(**raw)


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_minimal_yaml_parses(self, minimal_cs: ControlStructureModel) -> None:
        assert minimal_cs.system.name == "Test System"
        assert len(minimal_cs.hazards) == 1
        assert len(minimal_cs.unsafe_control_actions) == 1

    def test_duplicate_uca_ids_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        # Duplicate the UCA
        raw["unsafe_control_actions"].append(raw["unsafe_control_actions"][0].copy())
        with pytest.raises(Exception, match="Duplicate UCA IDs"):
            ControlStructureModel(**raw)

    def test_opa_enforcement_missing_rule_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0].pop("opa_rule", None)
        with pytest.raises(Exception, match="opa_rule is missing"):
            ControlStructureModel(**raw)

    def test_nemo_enforcement_missing_rail_rejected(self) -> None:
        raw = yaml.safe_load(_NEMO_YAML)
        raw["unsafe_control_actions"][0].pop("nemo_rail", None)
        with pytest.raises(Exception, match="nemo_rail is missing"):
            ControlStructureModel(**raw)

    def test_invalid_uca_type_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["uca_type"] = "invented_type"
        with pytest.raises(Exception):
            ControlStructureModel(**raw)

    def test_invalid_severity_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["hazards"][0]["severity"] = "catastrophic"
        with pytest.raises(Exception):
            ControlStructureModel(**raw)

    def test_full_production_yaml_valid(self) -> None:
        """The real stpa_control_structure.yaml must pass schema validation."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        assert len(cs.unsafe_control_actions) >= 7
        assert cs.system.name == "CAGE Financial Advisor"


# ---------------------------------------------------------------------------
# Generated-code injection guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGeneratedCodeInjection:
    """Control-structure string fields are compiled into the generated Python
    validator / saga nodes (imported at runtime) and the Rego / Colang policies.
    Fields carrying a quote, brace, or newline could break out of a generated
    literal or comment and inject code, so the schema rejects them at parse.
    """

    def test_threshold_ref_bare_code_injection_rejected(self) -> None:
        # threshold_ref lands in bare code (`threshold = THRESHOLDS.<ref>`); a
        # newline injects arbitrary statements into the generated validator.
        raw = yaml.safe_load(_MINIMAL_YAML)
        cond = raw["unsafe_control_actions"][0]["condition"]
        cond["operator"] = "greater_than"
        cond["threshold_ref"] = "drawdown\n    __import__('os').system('id')  #"
        with pytest.raises(Exception, match="threshold_ref"):
            ControlStructureModel(**raw)

    def test_param_non_identifier_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["condition"]["param"] = 'x") or exec("1'
        with pytest.raises(Exception, match="condition.param"):
            ControlStructureModel(**raw)

    def test_description_fstring_injection_rejected(self) -> None:
        # description is baked into a generated f-string; a brace is evaluated.
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["description"] = "{__import__('os').getpid()}"
        with pytest.raises(Exception, match="uca.description"):
            ControlStructureModel(**raw)

    def test_uca_action_non_identifier_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["action"] = 'do_thing"\n    import os  #'
        with pytest.raises(Exception, match="uca.action"):
            ControlStructureModel(**raw)

    def test_system_name_newline_rejected(self) -> None:
        # name/version reach the `# System: ...` header of every artifact.
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["system"]["name"] = "X\n_PWNED = 1"
        with pytest.raises(Exception, match="system field"):
            ControlStructureModel(**raw)

    def test_opa_rule_message_quote_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["opa_rule"]["message"] = 'a" ; allow := true #'
        with pytest.raises(Exception, match="opa_rule.message"):
            ControlStructureModel(**raw)

    def test_nemo_flow_name_non_identifier_rejected(self) -> None:
        raw = yaml.safe_load(_NEMO_YAML)
        raw["unsafe_control_actions"][0]["nemo_rail"]["flow_name"] = "bad name"
        with pytest.raises(Exception, match="nemo_rail.flow_name"):
            ControlStructureModel(**raw)

    def test_saga_action_non_identifier_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        uca = raw["unsafe_control_actions"][0]
        uca["enforcement"] = ["langgraph"]
        uca.pop("opa_rule", None)
        uca["langgraph_saga"] = {
            "forward_action": "execute_trade\n    import os  #",
            "compensating_action": "reverse_trade",
        }
        with pytest.raises(Exception, match="langgraph_saga action"):
            ControlStructureModel(**raw)

    def test_valid_fields_still_generate_clean_python(self) -> None:
        # Positive control: legitimate values compile and the generated Python
        # holds no injected import.
        raw = yaml.safe_load(_MINIMAL_YAML)
        cs = ControlStructureModel(**raw)
        gen = generate_python(cs)
        assert "GeneratedSTPAValidator" in gen
        assert "__import__" not in gen


# ---------------------------------------------------------------------------
# Python validator numeric-finiteness tests
# ---------------------------------------------------------------------------


_NUMERIC_YAML = """\
system:
  name: "Numeric Test System"
  version: "0.1"
  description: "greater_than threshold check"
  controller: "Agent"
  controlled_process: "Market"

hazards:
  - id: H-1
    description: "Stale data."
    severity: high

control_actions:
  - name: do_trade
    description: "Execute a trade."
    params:
      - name: latency_ms
        type: number
        required: true

unsafe_control_actions:
  - id: UCA-1
    action: do_trade
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Trade executed with stale data."
    condition:
      param: latency_ms
      operator: greater_than
      threshold: 100
    enforcement: [python]

safety_constraints: []
"""


class TestPythonGeneratedFiniteness:
    """A ``greater_than`` check compares ``float(val) > threshold``. ``float()``
    accepts ``NaN``/``inf``, and ``nan > threshold`` is False, so a non-finite
    param would otherwise slip through the Tier-0 STPA gate. The generated
    checks must fail closed on non-finite input.
    """

    @staticmethod
    def _load_generated(source: str):  # type: ignore[no-untyped-def]
        namespace: dict = {}
        exec(compile(source, "<generated_stpa_validator>", "exec"), namespace)
        return namespace["GeneratedSTPAValidator"]()

    def test_generated_source_guards_non_finite(self) -> None:
        cs = ControlStructureModel(**yaml.safe_load(_NUMERIC_YAML))
        gen = generate_python(cs)
        assert "import math" in gen
        assert "math.isfinite" in gen

    def test_literal_threshold_rejects_non_finite(self) -> None:
        validator = self._load_generated(
            generate_python(ControlStructureModel(**yaml.safe_load(_NUMERIC_YAML)))
        )
        # In-range value passes; over-threshold value violates (unchanged).
        assert validator.validate("do_trade", {"latency_ms": 10}) == []
        assert validator.validate("do_trade", {"latency_ms": 10**6})
        # Non-finite values fail closed instead of slipping through.
        assert validator.validate("do_trade", {"latency_ms": float("nan")})
        assert validator.validate("do_trade", {"latency_ms": float("inf")})

    def test_committed_validator_rejects_nan(self) -> None:
        from src.gateway.governance.generated_stpa_validator import (
            GeneratedSTPAValidator,
        )

        v = GeneratedSTPAValidator()
        # NaN on the latency (UCA-2) and drawdown (UCA-5) gates fails closed.
        assert v.validate(
            "execute_trade", {"latency_ms": float("nan"), "drawdown": 0.0}
        )
        assert v.validate(
            "execute_trade", {"latency_ms": 0.0, "drawdown": float("nan")}
        )
        # A valid in-range request stays non-violating.
        assert v.validate("execute_trade", {"latency_ms": 1, "drawdown": 0.0}) == []


# ---------------------------------------------------------------------------
# OPA generation tests
# ---------------------------------------------------------------------------


class TestOpaGeneration:
    def test_banner_present(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "AUTO-GENERATED by stpa_compiler" in rego

    def test_package_declaration(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "package stpa.generated" in rego

    def test_fail_closed_default(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "default stpa_allow = false" in rego

    def test_uca1_rule_generated(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "stpa_violation_uca_1" in rego
        assert "UCA-1: token is required." in rego

    def test_is_null_condition_renders(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "not input.token" in rego

    def test_aggregate_violation_rule(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "stpa_violations contains" in rego
        assert "msg := stpa_violation_uca_1" in rego

    def test_stpa_allow_rule(self, minimal_cs: ControlStructureModel) -> None:
        rego = generate_opa(minimal_cs)
        assert "stpa_allow if {" in rego
        assert "count(stpa_violations) == 0" in rego

    def test_full_yaml_opa_generation(self) -> None:
        """OPA generation from the real control structure should succeed."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        rego = generate_opa(cs)
        # All OPA-enforced UCAs must appear in the output
        opa_ucas = [
            u
            for u in cs.unsafe_control_actions
            if "opa" in u.enforcement or "all" in u.enforcement
        ]
        for uca in opa_ucas:
            rule_name = f"stpa_violation_{uca.id.lower().replace('-', '_')}"
            assert rule_name in rego, f"Expected rule {rule_name} in generated Rego"

    def test_rbac_rules_compiled(self) -> None:
        """RBAC rules from the YAML are included in the OPA output."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        rego = generate_opa(cs)
        assert "rbac_allow_junior_trade" in rego
        assert "rbac_allow_senior_trade" in rego


# ---------------------------------------------------------------------------
# NeMo generation tests
# ---------------------------------------------------------------------------


class TestNemoGeneration:
    def test_banner_present(self, nemo_cs: ControlStructureModel) -> None:
        colang = generate_nemo(nemo_cs)
        assert "AUTO-GENERATED by stpa_compiler" in colang

    def test_action_declaration_generated(self, nemo_cs: ControlStructureModel) -> None:
        colang = generate_nemo(nemo_cs)
        assert "action BlockPiiOutputCheckAction" in colang

    def test_flow_definition_generated(self, nemo_cs: ControlStructureModel) -> None:
        colang = generate_nemo(nemo_cs)
        assert "flow block_pii_output" in colang
        assert "I cannot share personal information." in colang

    def test_log_audit_action_present(self, nemo_cs: ControlStructureModel) -> None:
        colang = generate_nemo(nemo_cs)
        assert "await LogSafetyAuditAction" in colang

    def test_composite_guardrail_generated(
        self, nemo_cs: ControlStructureModel
    ) -> None:
        colang = generate_nemo(nemo_cs)
        assert "flow stpa_output_guardrail" in colang

    def test_no_nemo_ucas_produces_comment(
        self, minimal_cs: ControlStructureModel
    ) -> None:
        colang = generate_nemo(minimal_cs)
        assert "No NeMo rails defined" in colang

    def test_full_yaml_nemo_generation(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        colang = generate_nemo(cs)
        nemo_ucas = [
            u
            for u in cs.unsafe_control_actions
            if "nemo" in u.enforcement or "all" in u.enforcement
        ]
        for uca in nemo_ucas:
            assert uca.nemo_rail is not None
            assert uca.nemo_rail.flow_name in colang


# ---------------------------------------------------------------------------
# Python validator generation tests
# ---------------------------------------------------------------------------


class TestPythonGeneration:
    def test_banner_present(self, minimal_cs: ControlStructureModel) -> None:
        py = generate_python(minimal_cs)
        assert "AUTO-GENERATED by stpa_compiler" in py

    def test_class_defined(self, minimal_cs: ControlStructureModel) -> None:
        py = generate_python(minimal_cs)
        assert "class GeneratedSTPAValidator" in py

    def test_validate_generated_method(self, minimal_cs: ControlStructureModel) -> None:
        py = generate_python(minimal_cs)
        assert "def validate_generated" in py

    def test_uca_method_generated(self, minimal_cs: ControlStructureModel) -> None:
        py = generate_python(minimal_cs)
        assert "_check_uca_1" in py

    def test_is_null_check_in_python(self, minimal_cs: ControlStructureModel) -> None:
        py = generate_python(minimal_cs)
        assert 'params.get("token") is None' in py

    def test_full_yaml_python_generation(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        py = generate_python(cs)
        py_ucas = [
            u
            for u in cs.unsafe_control_actions
            if "python" in u.enforcement or "all" in u.enforcement
        ]
        for uca in py_ucas:
            method = f"_check_{uca.id.lower().replace('-', '_')}"
            assert method in py, f"Expected method {method} in generated Python"


# ---------------------------------------------------------------------------
# compile_control_structure orchestration tests
# ---------------------------------------------------------------------------


class TestCompileOrchestration:
    def test_compile_all_targets(self, minimal_cs: ControlStructureModel) -> None:
        result = compile_control_structure(minimal_cs, ["all"])
        assert result.opa_content
        assert result.nemo_content  # "No NeMo rails defined" comment
        assert result.python_content
        assert not result.errors

    def test_compile_opa_only(self, minimal_cs: ControlStructureModel) -> None:
        result = compile_control_structure(minimal_cs, ["opa"])
        assert result.opa_content
        assert result.nemo_content == ""
        assert result.python_content == ""

    def test_compile_nemo_only(self, nemo_cs: ControlStructureModel) -> None:
        result = compile_control_structure(nemo_cs, ["nemo"])
        assert result.nemo_content
        assert result.opa_content == ""

    def test_compile_python_only(self, minimal_cs: ControlStructureModel) -> None:
        result = compile_control_structure(minimal_cs, ["python"])
        assert result.python_content
        assert result.opa_content == ""
        assert result.nemo_content == ""


# ---------------------------------------------------------------------------
# CLI tests (using main() as entry point)
# ---------------------------------------------------------------------------


class TestCLI:
    def test_validate_command_success(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "cs.yaml"
        yaml_file.write_text(_MINIMAL_YAML)
        ret = main(["validate", "--input", str(yaml_file)])
        assert ret == 0

    def test_validate_command_invalid_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text(
            "system: {name: X}\nunsafe_control_actions: []\nhazards: []\ncontrol_actions: []\nsafety_constraints: []"
        )
        ret = main(["validate", "--input", str(yaml_file)])
        assert ret == 1

    def test_validate_missing_file(self, tmp_path: Path) -> None:
        ret = main(["validate", "--input", str(tmp_path / "nonexistent.yaml")])
        assert ret == 1

    def test_compile_dry_run_all(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        yaml_file = tmp_path / "cs.yaml"
        yaml_file.write_text(_MINIMAL_YAML)
        ret = main(["compile", "--input", str(yaml_file), "--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "package stpa.generated" in captured.out
        assert "GeneratedSTPAValidator" in captured.out

    def test_compile_writes_files(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "cs.yaml"
        yaml_file.write_text(_MINIMAL_YAML)
        opa_out = tmp_path / "out.rego"
        nemo_out = tmp_path / "out.co"
        py_out = tmp_path / "out.py"
        ret = main(
            [
                "compile",
                "--input",
                str(yaml_file),
                "--targets",
                "opa",
                "python",
                "--opa-out",
                str(opa_out),
                "--nemo-out",
                str(nemo_out),
                "--python-out",
                str(py_out),
            ]
        )
        assert ret == 0
        assert opa_out.exists()
        assert py_out.exists()
        assert "package stpa.generated" in opa_out.read_text()
        assert "GeneratedSTPAValidator" in py_out.read_text()

    def test_compile_production_yaml_dry_run(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Smoke test: compile the real YAML without writing files."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        ret = main(["compile", "--input", str(_FULL_YAML_PATH), "--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "UCA-5" in captured.out or "uca_5" in captured.out


pytestmark = [pytest.mark.unit, pytest.mark.local]
