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
    generate_langgraph,
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
_FINANCE_YAML_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "cage_finance"
    / "config"
    / "stpa"
    / "trade_hazards.yaml"
)


def _load_full_cs() -> ControlStructureModel:
    from src.gateway.governance.stpa_compiler import load_control_structures

    paths = [_FULL_YAML_PATH]
    if _FINANCE_YAML_PATH.exists():
        paths.append(_FINANCE_YAML_PATH)
    return load_control_structures(paths)


@pytest.fixture
def minimal_cs() -> ControlStructureModel:
    raw = yaml.safe_load(_MINIMAL_YAML)
    return ControlStructureModel(**raw)


def _finance_cs() -> ControlStructureModel:
    """The finance source set exactly as the STPA freshness check compiles it."""
    from src.gateway.governance.stpa_compiler import load_control_structures

    return load_control_structures(sorted(_FINANCE_YAML_PATH.parent.rglob("*.yaml")))


class TestSagaServerBoundParams:
    """A generated saga tool call never sends a ``server_bound`` param.

    GHSA-w39v-5v7h-fxg9: ``trader_role`` is required by the trade policy but
    bound by the gateway from the verified caller identity. A saga sends
    exactly its ``mcp_arguments``, and the control structure refuses one that
    names a server-bound param of the forward action.
    """

    @staticmethod
    def _raw() -> dict:
        return yaml.safe_load(_FINANCE_YAML_PATH.read_text())

    @staticmethod
    def _trade_saga(raw: dict) -> dict:
        (uca,) = [u for u in raw["unsafe_control_actions"] if u["id"] == "UCA-4"]
        return uca["langgraph_saga"]

    @staticmethod
    def _trader_role(raw: dict) -> dict:
        (trade,) = [
            ca for ca in raw["control_actions"] if ca["name"] == "execute_trade"
        ]
        (role,) = [p for p in trade["params"] if p["name"] == "trader_role"]
        return role

    def test_the_trade_saga_never_sends_the_trader_role(self) -> None:
        from src.gateway.governance.stpa_compiler import generate_langgraph

        generated = generate_langgraph(_finance_cs())

        assert 'name="execute_trade_action"' in generated
        assert '"trader_role"' not in generated

    def test_a_saga_sending_a_server_bound_param_is_refused(self) -> None:
        raw = self._raw()
        self._trade_saga(raw)["mcp_arguments"].append("trader_role")

        with pytest.raises(ValueError, match="server_bound"):
            ControlStructureModel(**raw)

    def test_the_flag_is_what_refuses_it(self) -> None:
        from src.gateway.governance.stpa_compiler import generate_langgraph

        raw = self._raw()
        self._trade_saga(raw)["mcp_arguments"].append("trader_role")
        role = self._trader_role(raw)
        assert role["required"] is True and role["server_bound"] is True
        role["server_bound"] = False

        assert '"trader_role"' in generate_langgraph(ControlStructureModel(**raw))

    def test_server_bound_must_be_a_boolean(self) -> None:
        raw = self._raw()
        self._trader_role(raw)["server_bound"] = "yes"

        with pytest.raises(ValueError, match="server_bound must be a boolean"):
            ControlStructureModel(**raw)


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
        """The real core + finance STPA YAMLs must pass schema validation."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = _load_full_cs()
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

    @staticmethod
    def _mcp_saga_raw(mcp_arguments: list[str] | None) -> dict:
        raw = yaml.safe_load(_MINIMAL_YAML)
        uca = raw["unsafe_control_actions"][0]
        uca["enforcement"] = ["langgraph"]
        uca.pop("opa_rule", None)
        saga = {
            "forward_action": "do_thing",
            "compensating_action": "undo_thing",
            "execution_type": "mcp_tool",
            "mcp_tool_name": "do_thing_tool",
        }
        if mcp_arguments is not None:
            saga["mcp_arguments"] = mcp_arguments
        uca["langgraph_saga"] = saga
        return raw

    @pytest.mark.parametrize("mcp_arguments", [None, [], ["token"]])
    def test_mcp_saga_without_transaction_id_argument_rejected(
        self, mcp_arguments: list[str] | None
    ) -> None:
        with pytest.raises(Exception, match="mcp_arguments must list"):
            ControlStructureModel(**self._mcp_saga_raw(mcp_arguments))

    def test_mcp_saga_argument_non_identifier_rejected(self) -> None:
        raw = self._mcp_saga_raw(["transaction_id", "token\n    import os  #"])
        with pytest.raises(Exception, match="langgraph_saga.mcp_arguments"):
            ControlStructureModel(**raw)

    def test_mcp_saga_duplicate_argument_rejected(self) -> None:
        raw = self._mcp_saga_raw(["transaction_id", "token", "token"])
        with pytest.raises(Exception, match="lists a key twice"):
            ControlStructureModel(**raw)

    def test_mcp_saga_forwards_only_declared_arguments(self) -> None:
        cs = ControlStructureModel(**self._mcp_saga_raw(["token", "transaction_id"]))
        gen = generate_langgraph(cs)
        assert 'if k in ("token", "transaction_id")' in gen
        assert "approval_token" not in gen
        assert "except MCPToolOutcomeUnknownError" in gen

    def test_valid_fields_still_generate_clean_python(self) -> None:
        # Positive control: legitimate values compile and the generated Python
        # holds no injected import.
        raw = yaml.safe_load(_MINIMAL_YAML)
        cs = ControlStructureModel(**raw)
        gen = generate_python(cs)
        assert "GeneratedSTPAValidator" in gen
        assert "__import__" not in gen


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
        cs = _load_full_cs()
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
        cs = _load_full_cs()
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
        cs = _load_full_cs()
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
        cs = _load_full_cs()
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
        assert "UCA-1" in captured.out or "uca_1" in captured.out

    def test_compile_domain_yaml_writes_domain_package(self, tmp_path: Path) -> None:
        """Per-domain compilation emits uca_rules.py, saga_nodes.py, and terminal_registry.json."""
        if not _FINANCE_YAML_PATH.exists():
            pytest.skip("Finance STPA YAML not found.")
        ret = main(
            [
                "compile",
                "--domain-yaml",
                str(_FINANCE_YAML_PATH),
                "--out-dir",
                str(tmp_path),
            ]
        )
        assert ret == 0
        assert (tmp_path / "uca_rules.py").exists()
        assert (tmp_path / "saga_nodes.py").exists()
        assert (tmp_path / "terminal_registry.json").exists()
        assert "UCA_RULES" in (tmp_path / "uca_rules.py").read_text()
        assert "SAGA_COMPENSATORS" in (tmp_path / "saga_nodes.py").read_text()


# ---------------------------------------------------------------------------
# less_than operator finiteness tests
# ---------------------------------------------------------------------------

_LESS_THAN_LITERAL_YAML = """\
system:
  name: "LT Test System"
  version: "0.1"
  description: "less_than literal test"
  controller: "Agent"
  controlled_process: "Market"

hazards:
  - id: H-1
    description: "Test hazard."
    severity: high

control_actions:
  - name: check_signal
    description: "Check a signal value."
    params:
      - name: signal_strength
        type: float
        required: false

unsafe_control_actions:
  - id: UCA-LT1
    action: check_signal
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Signal strength below minimum threshold."
    condition:
      param: signal_strength
      operator: less_than
      threshold: 0.5
    enforcement: [python]

safety_constraints: []
"""


class TestPythonGeneratedLessThanFiniteness:
    """less_than with literal threshold must reject NaN/inf via math.isfinite."""

    def _make_validator(self):
        raw = yaml.safe_load(_LESS_THAN_LITERAL_YAML)
        cs = ControlStructureModel(**raw)
        gen = generate_python(cs)
        ns: dict = {}
        exec(gen, ns)  # noqa: S102
        return ns["GeneratedSTPAValidator"]()

    def test_nan_yields_violation(self) -> None:
        v = self._make_validator()
        result = v.validate("check_signal", {"signal_strength": float("nan")})
        assert any(
            "Non-finite" in getattr(msg, "message", str(msg)) for msg in result
        ), f"Expected non-finite violation, got: {result}"

    def test_inf_yields_violation(self) -> None:
        v = self._make_validator()
        result = v.validate("check_signal", {"signal_strength": float("inf")})
        assert any(
            "Non-finite" in getattr(msg, "message", str(msg)) for msg in result
        ), f"Expected non-finite violation, got: {result}"

    def test_neg_inf_yields_violation(self) -> None:
        v = self._make_validator()
        result = v.validate("check_signal", {"signal_strength": float("-inf")})
        assert any(
            "Non-finite" in getattr(msg, "message", str(msg))
            or "UCA_LT1" in getattr(msg, "code", str(msg))
            or "UCA-LT1" in getattr(msg, "code", str(msg))
            for msg in result
        ), f"Expected violation, got: {result}"

    def test_valid_below_threshold_triggers(self) -> None:
        v = self._make_validator()
        result = v.validate("check_signal", {"signal_strength": 0.1})
        assert any(
            "UCA_LT1" in getattr(msg, "code", str(msg))
            or "UCA-LT1" in getattr(msg, "code", str(msg))
            for msg in result
        )

    def test_valid_above_threshold_passes(self) -> None:
        v = self._make_validator()
        result = v.validate("check_signal", {"signal_strength": 0.9})
        assert result == []

    def test_none_param_returns_no_violation(self) -> None:
        """Optional param: None means 'not provided', not a violation for literal threshold."""
        v = self._make_validator()
        result = v.validate("check_signal", {})
        assert result == []

    def test_import_math_in_generated_code(self) -> None:
        """Generated Python must include `import math` for isfinite calls."""
        raw = yaml.safe_load(_LESS_THAN_LITERAL_YAML)
        cs = ControlStructureModel(**raw)
        gen = generate_python(cs)
        assert "import math" in gen


class TestCompositeGrammar:
    """``composite`` is a closed grammar: one form, compiled by every generator.

    Any other expression used to compile to a comment (``pass`` in Python,
    ``false`` in Rego), i.e. a UCA that enforced nothing. It is now refused.
    """

    _SCALED = "order_size > threshold_ref(stpa.max_fraction) * daily_vol"

    def _cs(self, composite: str) -> ControlStructureModel:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["condition"] = {"composite": composite}
        return ControlStructureModel(**raw)

    @pytest.mark.parametrize(
        "expr",
        [
            "order_size > 0.01 * daily_vol",
            "a AND b",
            "always",
            "order_size >= threshold_ref(stpa.max_fraction) * daily_vol",
            "order_size > threshold_ref(stpa..x) * daily_vol",
            "order_size > threshold_ref(stpa.max_fraction) * daily_vol or True",
        ],
    )
    def test_any_other_expression_is_refused(self, expr: str) -> None:
        with pytest.raises(ValueError, match="condition.composite must have the form"):
            self._cs(expr)

    def test_scaled_threshold_form_is_accepted_and_stripped(self) -> None:
        cs = self._cs(f"  {self._SCALED}  ")
        assert cs.unsafe_control_actions[0].condition.composite == self._SCALED

    def test_opa_enforces_the_composite(self) -> None:
        rego = generate_opa(self._cs(self._SCALED))
        assert "input.daily_vol > 0" not in rego
        assert (
            "input.order_size > input._thresholds.stpa_max_fraction * input.daily_vol"
            in rego
        )
        assert "placeholder" not in rego and "    false" not in rego

    def test_python_enforces_the_composite(self) -> None:
        py = generate_python(self._cs(self._SCALED))
        assert 'params.get("order_size")' in py and 'params.get("daily_vol")' in py
        assert "* f_rhs:" in py
        assert "            pass" not in py

    def test_shipped_finance_composite_compiles(self) -> None:
        cs = load_control_structure(_FINANCE_YAML_PATH)
        composites = [
            u.condition.composite
            for u in cs.unsafe_control_actions
            if u.condition.composite
        ]
        assert composites, "UCA-6 should use the scaled-threshold composite"

    def test_composite_fails_closed_on_zero_negative_nan_or_missing_rhs(self) -> None:
        from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator

        v = GeneratedSTPAValidator()
        assert (
            v._check_uca_6("execute_trade", {"order_size": 100, "daily_vol": 0})
            is not None
        )
        assert (
            v._check_uca_6("execute_trade", {"order_size": 0, "daily_vol": -10})
            is not None
        )
        assert (
            v._check_uca_6(
                "execute_trade", {"order_size": float("nan"), "daily_vol": 1000}
            )
            is not None
        )
        assert v._check_uca_6("execute_trade", {"order_size": 100}) is not None
        assert (
            v._check_uca_6("execute_trade", {"order_size": 0, "daily_vol": 0}) is None
        )
        assert (
            v._check_uca_6("execute_trade", {"order_size": 10, "daily_vol": 10_000})
            is None
        )


class TestSandboxPolicyGeneration:
    """Tests for --targets sandbox / openshell and SandboxRuleModel input hardening."""

    def test_missing_sandbox_rule_when_sandbox_in_enforcement_raises(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["enforcement"] = ["opa", "sandbox"]
        with pytest.raises(ValueError, match="sandbox_rule is missing"):
            ControlStructureModel(**raw)

    def test_binary_path_traversal_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["enforcement"] = ["opa", "sandbox"]
        raw["unsafe_control_actions"][0]["sandbox_rule"] = {
            "allowed_binaries": ["/usr/bin/../bin/sh"],
        }
        with pytest.raises(ValueError, match="path traversal"):
            ControlStructureModel(**raw)

    def test_endpoint_injection_rejected(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["enforcement"] = ["opa", "sandbox"]
        raw["unsafe_control_actions"][0]["sandbox_rule"] = {
            "allowed_endpoints": ['https://evil.example.com/"\ninjected: true'],
        }
        with pytest.raises(ValueError):
            ControlStructureModel(**raw)

    def test_generate_sandbox_policy_emits_valid_yaml_and_precredentials_seal(
        self,
    ) -> None:
        from src.gateway.governance.stpa_compiler import generate_sandbox_policy

        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"][0]["enforcement"] = ["opa", "sandbox"]
        raw["unsafe_control_actions"][0]["terminal_classification"] = (
            "IRREVERSIBLE_TERMINAL"
        )
        raw["unsafe_control_actions"][0]["sandbox_rule"] = {
            "allowed_endpoints": [
                "https://cage-gateway.internal/v1/mcp/tools/call/do_thing"
            ],
            "allowed_http_verbs": ["POST"],
            "allowed_mcp_methods": ["tools/call:do_thing"],
            "allowed_binaries": ["/usr/bin/python3"],
            "require_routing_seal": True,
            "credential_placeholder": "CAGE_DO_THING_CREDENTIAL",
        }
        cs = ControlStructureModel(**raw)
        out = generate_sandbox_policy(cs)
        assert "# Generated:" in out
        doc = yaml.safe_load(out)
        assert doc["version"] == 1
        assert doc["metadata"]["require_cage_stera_seal"] is True
        assert "do_thing" in doc["network_policies"]
        pol = doc["network_policies"]["do_thing"]
        assert pol["require_routing_seal"] is True
        assert pol["terminal_classification"] == "IRREVERSIBLE_TERMINAL"
        assert doc["credential_broker_rules"][0]["phase"] == "PreCredentials"
        assert doc["credential_broker_rules"][0]["seal_header"] == "X-CAGE-Routing-Seal"
        assert (
            "CAGE_DO_THING_CREDENTIAL"
            in doc["credential_broker_rules"][0]["credential_placeholders"]
        )

    def test_compile_sandbox_target(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        cs = ControlStructureModel(**raw)
        res = compile_control_structure(cs, ["sandbox"])
        assert not res.errors
        assert res.sandbox_content
        assert "credential_broker_rules:" in res.sandbox_content


class TestEqualsOperatorAndTypeSafety:
    """Tests for `equals` operator in OPA/Python and non-numeric guards on threshold_ref."""

    def test_equals_literal_string_bool_numeric_opa_and_python(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["unsafe_control_actions"] = [
            {
                "id": "UCA-EQ-STR",
                "action": "do_thing",
                "uca_type": "unsafe_action",
                "hazard_refs": ["H-1"],
                "description": "Blocked status value.",
                "condition": {
                    "param": "status",
                    "operator": "equals",
                    "threshold": "SANCTIONED",
                },
                "enforcement": ["opa", "python"],
                "opa_rule": {"decision": "DENY", "message": "Sanctioned status."},
            },
            {
                "id": "UCA-EQ-BOOL",
                "action": "do_thing",
                "uca_type": "unsafe_action",
                "hazard_refs": ["H-1"],
                "description": "Blocked boolean flag.",
                "condition": {
                    "param": "bypass_flag",
                    "operator": "equals",
                    "threshold": True,
                },
                "enforcement": ["opa", "python"],
                "opa_rule": {"decision": "DENY", "message": "Bypass flag."},
            },
            {
                "id": "UCA-EQ-NUM",
                "action": "do_thing",
                "uca_type": "unsafe_action",
                "hazard_refs": ["H-1"],
                "description": "Blocked zero code.",
                "condition": {
                    "param": "code",
                    "operator": "equals",
                    "threshold": 0.0,
                },
                "enforcement": ["opa", "python"],
                "opa_rule": {"decision": "DENY", "message": "Zero code."},
            },
        ]
        cs = ControlStructureModel(**raw)
        rego = generate_opa(cs)
        assert 'input.status == "SANCTIONED"' in rego
        assert "input.bypass_flag == true" in rego
        assert "input.code == 0.0" in rego

        py = generate_python(cs)
        ns: dict = {}
        exec(py, ns)  # noqa: S102
        validator = ns["GeneratedSTPAValidator"]()

        # Matching literal triggers violation
        v_str = validator._check_uca_eq_str("do_thing", {"status": "SANCTIONED"})
        assert v_str is not None and v_str.code == "STPA_UCA_UCA_EQ_STR"
        assert validator._check_uca_eq_str("do_thing", {"status": "ACTIVE"}) is None

        # Missing required param fails closed
        v_missing = validator._check_uca_eq_str("do_thing", {})
        assert v_missing is not None and "Missing required param" in v_missing.message

        # Bool literal does not match integer 1, and numeric 0.0 does not match False
        assert (
            validator._check_uca_eq_bool("do_thing", {"bypass_flag": True}) is not None
        )
        assert validator._check_uca_eq_bool("do_thing", {"bypass_flag": 1}) is None
        assert validator._check_uca_eq_num("do_thing", {"code": 0}) is not None
        assert validator._check_uca_eq_num("do_thing", {"code": False}) is None

    def test_single_key_threshold_ref_rejects_boolean_and_non_numeric(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["system"]["domain"] = "finance"
        raw["unsafe_control_actions"] = [
            {
                "id": "UCA-GT-REF",
                "action": "do_thing",
                "uca_type": "unsafe_action",
                "hazard_refs": ["H-1"],
                "description": "Latency exceeds max.",
                "condition": {
                    "param": "latency_ms",
                    "operator": "greater_than",
                    "threshold_ref": "stpa.max_latency_ms",
                },
                "enforcement": ["python"],
            },
            {
                "id": "UCA-LT-REF",
                "action": "do_thing",
                "uca_type": "unsafe_action",
                "hazard_refs": ["H-1"],
                "description": "Latency below max.",
                "condition": {
                    "param": "latency_ms",
                    "operator": "less_than",
                    "threshold_ref": "stpa.max_latency_ms",
                },
                "enforcement": ["python"],
            },
        ]
        cs = ControlStructureModel(**raw)
        py = generate_python(cs)
        ns: dict = {}
        exec(py, ns)  # noqa: S102
        validator = ns["GeneratedSTPAValidator"]()

        # Boolean True would otherwise coerce to 1.0 <= max_latency_ms (500.0) and pass UCA-GT-REF!
        v_gt_bool = validator._check_uca_gt_ref("do_thing", {"latency_ms": True})
        assert (
            v_gt_bool is not None and "Invalid non-numeric param" in v_gt_bool.message
        )

        v_lt_bool = validator._check_uca_lt_ref("do_thing", {"latency_ms": False})
        assert (
            v_lt_bool is not None and "Invalid non-numeric param" in v_lt_bool.message
        )


pytestmark = [pytest.mark.unit, pytest.mark.local]
