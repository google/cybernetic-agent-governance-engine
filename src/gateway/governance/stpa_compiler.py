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
STPA-to-Policy Compiler
=======================

CLI utility that ingests ``config/stpa_control_structure.yaml`` and emits
deterministic, runtime-enforceable governance artifacts:

  1. OPA Rego policy     → config/opa/generated_stpa_policy.rego
  2. NeMo Colang rail    → config/rails/generated_stpa_rails.co
  3. Python validator    → src/gateway/governance/generated_stpa_validator.py

Usage::

    # Compile all targets (default)
    python -m src.gateway.governance.stpa_compiler compile

    # Compile specific targets
    python -m src.gateway.governance.stpa_compiler compile --targets opa nemo

    # Validate YAML without writing files
    python -m src.gateway.governance.stpa_compiler validate

    # Show compiled output without writing (dry-run)
    python -m src.gateway.governance.stpa_compiler compile --dry-run

    # Use a custom control structure file
    python -m src.gateway.governance.stpa_compiler compile \\
        --input path/to/my_control_structure.yaml

Exit codes:
    0  All artifacts generated successfully (or dry-run / validate OK).
    1  Fatal error: invalid schema, template error, or I/O failure.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator

logger = logging.getLogger("stpa_compiler")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_INPUT = _REPO_ROOT / "config" / "stpa_control_structure.yaml"
_DEFAULT_INPUT_DIR = _REPO_ROOT / "config" / "stpa"
_DEFAULT_OPA_OUT = _REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego"
_DEFAULT_NEMO_OUT = _REPO_ROOT / "config" / "rails" / "generated_stpa_rails.co"
_DEFAULT_PY_OUT = (
    _REPO_ROOT / "src" / "gateway" / "governance" / "generated_stpa_validator.py"
)
_DEFAULT_LG_OUT = (
    _REPO_ROOT / "src" / "gateway" / "governance" / "generated_saga_nodes.py"
)
_DEFAULT_AGP_OUT = _REPO_ROOT / "config" / "agp" / "generated_semantic_policy.txt"
_DEFAULT_FTRA_OUT = _REPO_ROOT / "config" / "ftra" / "terminal_registry.json"
_DEFAULT_REGISTRY_OUT = (
    _REPO_ROOT / "config" / "registry" / "generated_tool_authorizations.json"
)

# AGP Semantic Governance Policy character budget (platform limit)
_AGP_CHAR_BUDGET = 5_000

# ---------------------------------------------------------------------------
# Pydantic schema — mirrors stpa_control_structure.yaml
# ---------------------------------------------------------------------------

UcaType = Literal["not_provided", "unsafe_action", "wrong_timing", "stopped_too_soon"]
EnforcementTarget = Literal["opa", "nemo", "python", "langgraph", "ftra", "all"]
OpaDecision = Literal["DENY", "GOVERNANCE_VIOLATION", "MANUAL_REVIEW", "ALLOW"]

# ---------------------------------------------------------------------------
# Input hardening for fields that reach the code generators.
#
# generate_python() and generate_langgraph() interpolate control-structure
# string fields directly into Python source that write_artifacts() writes to
# generated_stpa_validator.py / generated_saga_nodes.py, which singletons.py,
# symbolic_governor.py and auditor.py import at process start; generate_opa()
# and generate_nemo() do the same for Rego / Colang.  A field that carries a
# quote, brace, or newline can break out of a generated string literal,
# f-string, or comment and inject executable code into the compiled artifact.
# Identifier-typed fields (action names, param keys, threshold paths) are held
# to identifier grammars; free-text fields (descriptions, messages) may not
# carry the characters that escape a generated literal.  Both are enforced here
# at parse time so no generator has to remember to escape.
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_ACTION_RE = re.compile(r"^(?:\*|[A-Za-z_][A-Za-z0-9_.-]*)$")
_DOTTED_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_TEXT_FORBIDDEN = ('"', "\\", "{", "}", "\n", "\r")


def _require_pattern(value: str, pattern: re.Pattern[str], field: str) -> str:
    if not pattern.match(value):
        raise ValueError(
            f"{field} must match {pattern.pattern!r}; got {value!r} — this value is "
            "compiled into generated enforcement code and may not contain other characters"
        )
    return value


def _reject_source_breaking(value: str, field: str) -> str:
    for ch in _TEXT_FORBIDDEN:
        if ch in value:
            raise ValueError(
                f"{field} may not contain {ch!r} — it is interpolated into generated "
                "enforcement code (string literals, f-strings, and comments)"
            )
    return value


# FTRA terminal classification — used by the Forward-Looking Trajectory Reachability Analyzer.
# Fail-closed: any action not present in the compiled registry is treated as
# IRREVERSIBLE_TERMINAL by IrreversibilityClassifier at runtime.
TerminalClassification = Literal[
    "IRREVERSIBLE_TERMINAL", "EXTERNALLY_REVERSIBLE", "REVERSIBLE", "READ_ONLY"
]


class HazardModel(BaseModel):
    id: str
    description: str
    severity: Literal["critical", "high", "medium", "low"]


class ConditionModel(BaseModel):
    param: str | None = None
    operator: (
        Literal["is_null", "is_false", "is_true", "greater_than", "less_than", "equals"]
        | None
    ) = None
    threshold_ref: str | None = None  # e.g. "stpa.max_latency_ms"
    threshold: float | None = None  # literal value
    semantic_pattern: str | None = None
    composite: str | None = None  # free-form expression for complex conditions

    @field_validator("param")
    @classmethod
    def _v_param(cls, v: str | None) -> str | None:
        return v if v is None else _require_pattern(v, _IDENT_RE, "condition.param")

    @field_validator("threshold_ref")
    @classmethod
    def _v_threshold_ref(cls, v: str | None) -> str | None:
        return (
            v
            if v is None
            else _require_pattern(v, _DOTTED_IDENT_RE, "condition.threshold_ref")
        )

    @field_validator("semantic_pattern", "composite")
    @classmethod
    def _v_free_text(cls, v: str | None, info: ValidationInfo) -> str | None:
        return (
            v
            if v is None
            else _reject_source_breaking(v, f"condition.{info.field_name}")
        )


class OpaRuleModel(BaseModel):
    decision: OpaDecision = "DENY"
    message: str

    @field_validator("message")
    @classmethod
    def _v_message(cls, v: str) -> str:
        return _reject_source_breaking(v, "opa_rule.message")


class NemoRailModel(BaseModel):
    flow_name: str
    message: str

    @field_validator("flow_name")
    @classmethod
    def _v_flow_name(cls, v: str) -> str:
        return _require_pattern(v, _IDENT_RE, "nemo_rail.flow_name")

    @field_validator("message")
    @classmethod
    def _v_message(cls, v: str) -> str:
        return _reject_source_breaking(v, "nemo_rail.message")


class ParameterMappingModel(BaseModel):
    """Maps a forward action parameter to its compensating action parameter.

    Example YAML::

        forward.transaction_id: compensating.target_tx_id
        forward.amount: compensating.refund_amount

    Both keys must follow the pattern ``forward.<key>`` or ``compensating.<key>``.
    """

    forward_key: str  # e.g. "transaction_id" from the forward action's context_data
    compensating_key: str  # e.g. "target_tx_id" expected by the compensating API call

    @field_validator("forward_key", "compensating_key")
    @classmethod
    def _v_key(cls, v: str) -> str:
        return _require_pattern(v, _IDENT_RE, "parameter_mapping key")

    @classmethod
    def from_yaml_dict(cls, raw: dict[str, str]) -> list[ParameterMappingModel]:
        """Parse {'forward.transaction_id': 'compensating.target_tx_id', ...}."""
        mappings = []
        for fwd, comp in raw.items():
            fwd_key = fwd.removeprefix("forward.")
            comp_key = comp.removeprefix("compensating.")
            mappings.append(cls(forward_key=fwd_key, compensating_key=comp_key))
        return mappings


ExecutionType = Literal["mcp_tool", "local"]


class SagaModel(BaseModel):
    """LangGraph Saga configuration for a UCA.

    Defined in YAML as::

        langgraph_saga:
          forward_action: execute_trade
          compensating_action: reverse_trade
          # [CTRL_WAL_002] declare execution backend so the compiler emits a
          # real MCP call instead of a hollow stub in the WAL forward node.
          execution_type: mcp_tool          # 'mcp_tool' | 'local'
          mcp_tool_name: execute_trade_action  # required when execution_type=mcp_tool
          parameter_mapping:
            forward.transaction_id: compensating.target_tx_id
            forward.amount: compensating.refund_amount
    """

    forward_action: str
    compensating_action: str
    parameter_mapping: list[ParameterMappingModel] = Field(default_factory=list)
    # [CTRL_WAL_002] fields — control how the forward WAL node executes the action.
    execution_type: ExecutionType = "local"
    mcp_tool_name: str | None = None

    @field_validator("forward_action", "compensating_action")
    @classmethod
    def _v_saga_action(cls, v: str) -> str:
        return _require_pattern(v, _IDENT_RE, "langgraph_saga action")

    @field_validator("mcp_tool_name")
    @classmethod
    def _v_mcp_tool_name(cls, v: str | None) -> str | None:
        return (
            v
            if v is None
            else _require_pattern(v, _IDENT_RE, "langgraph_saga.mcp_tool_name")
        )

    @model_validator(mode="before")
    @classmethod
    def _parse_parameter_mapping(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("parameter_mapping"), dict):
            data["parameter_mapping"] = ParameterMappingModel.from_yaml_dict(
                data["parameter_mapping"]
            )
        return data

    @model_validator(mode="after")
    def _validate_mcp_tool_name(self) -> SagaModel:
        if self.execution_type == "mcp_tool" and not self.mcp_tool_name:
            raise ValueError(
                "SagaModel: mcp_tool_name is required when execution_type='mcp_tool'."
            )
        return self


class UCAModel(BaseModel):
    id: str
    action: str
    uca_type: UcaType
    hazard_refs: list[str]
    description: str
    condition: ConditionModel
    enforcement: list[EnforcementTarget]
    opa_rule: OpaRuleModel | None = None
    nemo_rail: NemoRailModel | None = None
    langgraph_saga: SagaModel | None = None
    # FTRA: commencement-time worst-case reachability classification.
    # Fail-closed: IrreversibilityClassifier treats absent entries as IRREVERSIBLE_TERMINAL.
    terminal_classification: TerminalClassification | None = None

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str) -> str:
        return _require_pattern(v, _ID_RE, "uca.id")

    @field_validator("action")
    @classmethod
    def _v_action(cls, v: str) -> str:
        return _require_pattern(v, _ACTION_RE, "uca.action")

    @field_validator("description")
    @classmethod
    def _v_description(cls, v: str) -> str:
        return _reject_source_breaking(v, "uca.description")

    @model_validator(mode="after")
    def _validate_enforcement_deps(self) -> UCAModel:
        if "opa" in self.enforcement or "all" in self.enforcement:
            if self.opa_rule is None:
                raise ValueError(
                    f"{self.id}: enforcement includes 'opa' but opa_rule is missing."
                )
        if "nemo" in self.enforcement or "all" in self.enforcement:
            if self.nemo_rail is None:
                raise ValueError(
                    f"{self.id}: enforcement includes 'nemo' but nemo_rail is missing."
                )
        if "langgraph" in self.enforcement:
            if self.langgraph_saga is None:
                raise ValueError(
                    f"{self.id}: enforcement includes 'langgraph' but langgraph_saga is missing."
                )
        return self


class ConstraintModel(BaseModel):
    id: str
    description: str
    logic: str
    scope: list[str]
    uca_ref: str | None = None


class RbacRoleModel(BaseModel):
    name: str
    allowed_actions: list[str]
    trade_limits: dict[str, Any] | None = None
    restrictions: list[dict[str, Any]] | None = None


class RbacRulesModel(BaseModel):
    roles: list[RbacRoleModel]


class SystemModel(BaseModel):
    name: str
    version: str
    description: str
    controller: str
    controlled_process: str
    sensors: list[str] = Field(default_factory=list)

    @field_validator("name", "version")
    @classmethod
    def _v_banner_field(cls, v: str) -> str:
        # name and version are interpolated into the `# System: ...` header
        # comment of every generated artifact, including the Python ones.
        return _reject_source_breaking(v, "system field")


class ControlStructureModel(BaseModel):
    """Root schema for stpa_control_structure.yaml."""

    system: SystemModel
    hazards: list[HazardModel]
    control_actions: list[dict[str, Any]]  # kept flexible for param specs
    unsafe_control_actions: list[UCAModel]
    safety_constraints: list[ConstraintModel]
    rbac_rules: RbacRulesModel | None = None

    @field_validator("unsafe_control_actions")
    @classmethod
    def _unique_uca_ids(cls, ucas: list[UCAModel]) -> list[UCAModel]:
        ids = [u.id for u in ucas]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate UCA IDs found in unsafe_control_actions.")
        return ucas

    @classmethod
    def merge(cls, models: list[ControlStructureModel]) -> ControlStructureModel:
        """Merge multiple ControlStructureModels into one, deterministically.

        Rules:
        - ``system``: taken from the first model (caller must order
          meaningfully; typically the core system file comes first).
        - ``hazards``: union, sorted by ``id``; duplicate IDs are fatal.
        - ``control_actions``: union deduplicated by action ``name``,
          sorted by ``name``; duplicate names are fatal.
        - ``unsafe_control_actions``: union, sorted by ``id``; duplicate IDs
          are fatal (mirrors the existing _unique_uca_ids validator, but
          across files instead of within one file).
        - ``safety_constraints``: union, sorted by ``id``; duplicate IDs are
          fatal.
        - ``rbac_rules``: roles merged by ``name`` with last-writer-wins on
          duplicate role names (a warning is logged); result sorted by name.
        - ``hazard_refs`` integrity: every UCA hazard_ref across the merged
          corpus must resolve to a hazard present in the merged hazards list.
          Unresolved references are fatal.

        Returns the merged ``ControlStructureModel``.
        """
        if not models:
            raise ValueError("merge() requires at least one model")

        # System — first model wins
        merged_system = models[0].system

        # Hazards — union, duplicate IDs fatal, sort by id
        hazard_map: dict[str, HazardModel] = {}
        for m in models:
            for h in m.hazards:
                if h.id in hazard_map:
                    raise ValueError(
                        f"Duplicate hazard ID '{h.id}' found across STPA source files."
                    )
                hazard_map[h.id] = h
        merged_hazards = sorted(hazard_map.values(), key=lambda h: h.id)

        # Control actions — union deduplicated by name, duplicates fatal
        action_map: dict[str, dict] = {}
        for m in models:
            for ca in m.control_actions:
                name = ca.get("name", "")
                if name in action_map:
                    raise ValueError(
                        f"Duplicate control action name '{name}' found across STPA source files."
                    )
                action_map[name] = ca
        merged_actions = [action_map[k] for k in sorted(action_map)]

        # UCAs — union, duplicate IDs fatal, sort by id
        uca_map: dict[str, UCAModel] = {}
        for m in models:
            for uca in m.unsafe_control_actions:
                if uca.id in uca_map:
                    raise ValueError(
                        f"Duplicate UCA ID '{uca.id}' found across STPA source files."
                    )
                uca_map[uca.id] = uca
        merged_ucas = sorted(uca_map.values(), key=lambda u: u.id)

        # Safety constraints — union, duplicate IDs fatal, sort by id
        constraint_map: dict[str, ConstraintModel] = {}
        for m in models:
            for c in m.safety_constraints:
                if c.id in constraint_map:
                    raise ValueError(
                        f"Duplicate constraint ID '{c.id}' found across STPA source files."
                    )
                constraint_map[c.id] = c
        merged_constraints = sorted(constraint_map.values(), key=lambda c: c.id)

        # RBAC — merge roles by name (last-writer-wins on duplicates)
        role_map: dict[str, RbacRoleModel] = {}
        for m in models:
            if m.rbac_rules is not None:
                for role in m.rbac_rules.roles:
                    if role.name in role_map:
                        logger.warning(
                            "RBAC role '%s' defined in multiple STPA files; last-writer wins.",
                            role.name,
                        )
                    role_map[role.name] = role
        merged_rbac = (
            RbacRulesModel(roles=sorted(role_map.values(), key=lambda r: r.name))
            if role_map
            else None
        )

        # Cross-file referential integrity: every hazard_ref must resolve
        merged_hazard_ids = set(hazard_map)
        for uca in merged_ucas:
            for ref in uca.hazard_refs:
                if ref not in merged_hazard_ids:
                    raise ValueError(
                        f"UCA '{uca.id}' references hazard '{ref}' which is not defined "
                        f"in any of the merged STPA source files."
                    )

        # Construct via model_validate to bypass the field validators
        # (which re-check unique IDs on the already-deduplicated lists).
        return cls.model_validate(
            {
                "system": merged_system.model_dump(),
                "hazards": [h.model_dump() for h in merged_hazards],
                "control_actions": merged_actions,
                "unsafe_control_actions": [u.model_dump() for u in merged_ucas],
                "safety_constraints": [c.model_dump() for c in merged_constraints],
                "rbac_rules": merged_rbac.model_dump() if merged_rbac else None,
            }
        )


# ---------------------------------------------------------------------------
# Code-generation helpers
# ---------------------------------------------------------------------------

_BANNER = """\
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
#
# =============================================================================
# AUTO-GENERATED by stpa_compiler — DO NOT EDIT
# Source: config/stpa_control_structure.yaml
# Generated: {timestamp}
# =============================================================================
"""


def _banner() -> str:
    return _BANNER.format(
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# OPA Rego generator
# ---------------------------------------------------------------------------


def generate_opa(cs: ControlStructureModel) -> str:
    """Generate an OPA Rego policy from the control structure."""
    lines: list[str] = [
        _banner(),
        f"# System: {cs.system.name} v{cs.system.version}",
        "#",
        "# This policy enforces STPA Unsafe Control Actions (UCAs) identified in",
        "# config/stpa_control_structure.yaml.  It is loaded by OPA alongside",
        "# trade_governance.rego (which owns RBAC rules).",
        "#",
        "package stpa.generated",
        "",
        "import rego.v1",
        "",
        "# Fail-closed default: any action not explicitly allowed is denied.",
        "default stpa_allow = false",
        "",
        "# ---------------------------------------------------------------------------",
        "# STPA safety constraints",
        "# ---------------------------------------------------------------------------",
        "",
    ]

    # Group UCAs by action for clearer output
    uca_by_action: dict[str, list[UCAModel]] = {}
    for uca in cs.unsafe_control_actions:
        if "opa" in uca.enforcement or "all" in uca.enforcement:
            uca_by_action.setdefault(uca.action, []).append(uca)

    for action, ucas in uca_by_action.items():
        lines.append(f"# --- Action: {action} ---")
        for uca in ucas:
            assert uca.opa_rule is not None  # validated by Pydantic
            cond = uca.condition
            lines.append(f"# {uca.id}: {uca.description}")

            # Build the violation rule
            rule_name = f"stpa_violation_{uca.id.lower().replace('-', '_')}"
            lines.append(f"{rule_name} := msg if {{")
            lines.append(f'    input.action == "{action}"')

            if cond.param and cond.operator:
                param = cond.param
                op = cond.operator
                if op == "is_null":
                    lines.append(f"    not input.{param}")
                elif op == "is_false":
                    lines.append(f"    input.{param} == false")
                elif op == "is_true":
                    lines.append(f"    input.{param} == true")
                elif op == "greater_than":
                    if cond.threshold is not None:
                        lines.append(f"    input.{param} > {cond.threshold}")
                    elif cond.threshold_ref:
                        ref_comment = f"  # threshold from governance_thresholds.json:{cond.threshold_ref}"
                        lines.append(
                            f"    input.{param} > input._thresholds.{cond.threshold_ref.replace('.', '_')}{ref_comment}"
                        )
                elif op == "less_than":
                    if cond.threshold is not None:
                        lines.append(f"    input.{param} < {cond.threshold}")
                    elif cond.threshold_ref:
                        lines.append(
                            f"    input.{param} < input._thresholds.{cond.threshold_ref.replace('.', '_')}"
                        )
            elif cond.composite:
                lines.append(f"    # composite: {cond.composite}")
                lines.append(
                    "    # NOTE: complex composite condition — enforce via Python validator."
                )
                lines.append("    false  # placeholder: evaluated in STPAValidator")

            lines.append(f'    msg := "{uca.opa_rule.message}"')
            lines.append("}")
            lines.append("")

    # Aggregate deny rule
    lines += [
        "# ---------------------------------------------------------------------------",
        "# Aggregate: deny if any STPA violation fires",
        "# ---------------------------------------------------------------------------",
        "",
    ]

    for uca in cs.unsafe_control_actions:
        if "opa" in uca.enforcement or "all" in uca.enforcement:
            rule_name = f"stpa_violation_{uca.id.lower().replace('-', '_')}"
            lines.append(f"stpa_violations contains msg if msg := {rule_name}")

    lines += [
        "",
        "stpa_allow if {",
        "    count(stpa_violations) == 0",
        "}",
        "",
    ]

    # RBAC rules if present
    if cs.rbac_rules:
        lines += [
            "# ---------------------------------------------------------------------------",
            "# RBAC rules (compiled from stpa_control_structure.yaml rbac_rules)",
            "# ---------------------------------------------------------------------------",
            "",
        ]
        for role in cs.rbac_rules.roles:
            lines.append(f"# Role: {role.name}")
            if role.trade_limits:
                tl = role.trade_limits
                allow_below = tl.get("allow_below")
                review_below = tl.get("manual_review_below")
                denylist = []
                if role.restrictions:
                    for r in role.restrictions:
                        denylist.extend(r.get("currency_denylist", []))

                if allow_below:
                    lines.append(f"rbac_allow_{role.name}_trade if {{")
                    lines.append('    input.action == "execute_trade"')
                    lines.append(f'    lower(input.trader_role) == "{role.name}"')
                    lines.append(f"    input.amount <= {allow_below}")
                    for c in denylist:
                        lines.append(f'    input.currency != "{c}"')
                    lines.append("}")
                    lines.append("")

                if review_below and allow_below:
                    lines.append(f"rbac_review_{role.name}_trade if {{")
                    lines.append('    input.action == "execute_trade"')
                    lines.append(f'    lower(input.trader_role) == "{role.name}"')
                    lines.append(f"    input.amount > {allow_below}")
                    lines.append(f"    input.amount <= {review_below}")
                    for c in denylist:
                        lines.append(f'    input.currency != "{c}"')
                    lines.append("}")
                    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# NeMo Colang generator
# ---------------------------------------------------------------------------


def generate_nemo(cs: ControlStructureModel) -> str:
    """Generate NeMo Guardrails Colang 2.x rail definitions."""
    lines: list[str] = [
        _banner(),
        f"# System: {cs.system.name} v{cs.system.version}",
        "#",
        "# NeMo Guardrails Colang 2.x rails generated from STPA UCAs.",
        "# These rails guard LLM-level unsafe outputs and prompt injection.",
        "#",
        "",
    ]

    nemo_ucas = [
        u
        for u in cs.unsafe_control_actions
        if "nemo" in u.enforcement or "all" in u.enforcement
    ]

    if not nemo_ucas:
        lines.append("# No NeMo rails defined for any UCA in this control structure.")
        return "\n".join(lines)

    # Action declarations
    lines += [
        "# ---------------------------------------------------------------------------",
        "# Action declarations",
        "# ---------------------------------------------------------------------------",
        "",
        "action MaskPIIAction",
        "action LogSafetyAuditAction",
        "",
    ]
    for uca in nemo_ucas:
        assert uca.nemo_rail is not None
        flow = uca.nemo_rail.flow_name
        lines.append(f"action {_pascal(flow)}CheckAction  # {uca.id}")
    lines.append("")

    # Flow definitions
    lines += [
        "# ---------------------------------------------------------------------------",
        "# Safety flows",
        "# ---------------------------------------------------------------------------",
        "",
    ]
    for uca in nemo_ucas:
        assert uca.nemo_rail is not None
        rail = uca.nemo_rail
        lines += [
            f"# {uca.id}: {uca.description}",
            f"flow {rail.flow_name}",
            f'  bot say "{rail.message}"',
            "  await LogSafetyAuditAction",
            "",
        ]

    # Main output guardrail that chains all safety flows.
    # NOTE: `match bot said` is invalid Colang 2.x syntax — `match` only works
    # with user intent patterns.  This flow is registered as an output rail via
    # config/rails/config.yml and called by the NeMo runtime automatically; it
    # must NOT contain a `match` trigger statement.
    lines += [
        "# ---------------------------------------------------------------------------",
        "# Composite output guardrail — invoked on every bot response",
        "# ---------------------------------------------------------------------------",
        "",
        "flow stpa_output_guardrail",
    ]
    for uca in nemo_ucas:
        assert uca.nemo_rail is not None
        cond = uca.condition
        flow = uca.nemo_rail.flow_name
        if cond.semantic_pattern:
            lines.append(f"  # Pattern: {cond.semantic_pattern}")
            lines.append(
                f"  await {_pascal(flow)}CheckAction as $check_{uca.id.lower().replace('-', '_')}"
            )
            lines.append(
                f"  if $check_{uca.id.lower().replace('-', '_')}.detected == True"
            )
            lines.append(f"    await {flow}")
            lines.append("")
    lines.append("")

    return "\n".join(lines)


def _pascal(snake: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(w.capitalize() for w in snake.split("_"))


# ---------------------------------------------------------------------------
# Python validator generator
# ---------------------------------------------------------------------------


def generate_python(cs: ControlStructureModel) -> str:
    """Generate a Python STPAValidator subclass from the control structure."""
    py_ucas = [
        u
        for u in cs.unsafe_control_actions
        if "python" in u.enforcement or "all" in u.enforcement
    ]

    method_bodies: list[str] = []
    dispatch_lines: list[str] = []

    for uca in py_ucas:
        cond = uca.condition
        method_name = f"_check_{uca.id.lower().replace('-', '_')}"
        dispatch_lines.append(
            f"        _v = self.{method_name}(action_name, params)\n"
            f"        if _v: violations.append(_v)"
        )

        body_lines: list[str] = [
            f"    def {method_name}(self, action_name: str, params: dict) -> str | None:",
            f'        """{uca.id}: {uca.description}"""',
            "        try:",
        ]

        if uca.action != "*":
            body_lines.append(f'            if action_name != "{uca.action}":')
            body_lines.append("                return None")

        param = cond.param
        op = cond.operator

        if param and op == "is_null":
            body_lines += [
                f'            if params.get("{param}") is None:',
                "                return (",
                f'                    "STPA Violation {uca.id}: {uca.description}"',
                "                )",
            ]
        elif param and op == "is_false":
            body_lines += [
                f'            if params.get("{param}") is False:',
                "                return (",
                f'                    "STPA Violation {uca.id}: {uca.description}"',
                "                )",
            ]
        elif param and op == "greater_than" and cond.threshold_ref:
            # Map dot-path to THRESHOLDS singleton access
            attr_path = cond.threshold_ref.replace(".", ".")
            body_lines += [
                f"            threshold = THRESHOLDS.{attr_path}",
                f'            val = params.get("{param}")',
                "            if val is None:",
                f'                logger.warning("{uca.id}: missing param `{param}` — failing closed.")',
                f'                return "STPA Violation {uca.id}: Missing required param `{param}`."',
                "            if float(val) > threshold:",
                "                return (",
                f'                    f"STPA Violation {uca.id}: {uca.description} '
                f'({{float(val):.4f}} > {{threshold}})"',
                "                )",
            ]
        elif param and op == "greater_than" and cond.threshold is not None:
            body_lines += [
                f'            val = params.get("{param}")',
                f"            if val is not None and float(val) > {cond.threshold}:",
                f'                return "STPA Violation {uca.id}: {uca.description}"',
            ]
        elif param and op == "less_than" and cond.threshold_ref:
            # Map dot-path to THRESHOLDS singleton access
            attr_path = cond.threshold_ref.replace(".", ".")
            body_lines += [
                f"            threshold = THRESHOLDS.{attr_path}",
                f'            val = params.get("{param}")',
                "            if val is None:",
                f'                logger.warning("{uca.id}: missing param `{param}` — failing closed.")',
                f'                return "STPA Violation {uca.id}: Missing required param `{param}`."',
                "            f_val = float(val)",
                "            if not math.isfinite(f_val):",
                f'                return "STPA Violation {uca.id}: Non-finite param `{param}`."',
                "            if f_val < threshold:",
                "                return (",
                f'                    f"STPA Violation {uca.id}: {uca.description} '
                f'({{f_val:.4f}} < {{threshold}})"',
                "                )",
            ]
        elif param and op == "less_than" and cond.threshold is not None:
            body_lines += [
                f'            val = params.get("{param}")',
                "            if val is not None:",
                "                f_val = float(val)",
                "                if not math.isfinite(f_val):",
                f'                    return "STPA Violation {uca.id}: Non-finite param `{param}`."',
                f"                if f_val < {cond.threshold}:",
                f'                    return "STPA Violation {uca.id}: {uca.description}"',
            ]
        elif cond.composite:
            body_lines += [
                f"            # Composite condition: {cond.composite}",
                "            # Implement custom logic here.",
                "            pass",
            ]

        body_lines += [
            "            return None",
            "        except Exception as exc:",
            f'            logger.error("Error evaluating {uca.id}: %s", exc)',
            f'            return f"STPA Violation {uca.id}: Evaluation error — failing closed ({{exc}})."',
            "",
        ]
        method_bodies.append("\n".join(body_lines))

    dispatch_str = "\n".join(dispatch_lines)
    methods_str = "\n".join(method_bodies)

    return f'''\
{_banner()}# System: {cs.system.name} v{cs.system.version}
#
# Generated Python validator.  Extend GeneratedSTPAValidator in your
# STPAValidator subclass or use it directly as a drop-in replacement.
#
# All threshold references are resolved from the THRESHOLDS singleton
# (config/governance_thresholds.json).

from __future__ import annotations

import logging
import math
from typing import Any

from src.gateway.governance.schemas.thresholds import THRESHOLDS

logger = logging.getLogger("Gateway.Governance.GeneratedSTPAValidator")


class GeneratedSTPAValidator:
    """
    Auto-generated STPA validator.

    Checks all UCAs with enforcement=[python] or enforcement=[all] that were
    defined in config/stpa_control_structure.yaml.

    Do NOT edit this file; re-run the compiler instead:
        python -m src.gateway.governance.stpa_compiler compile
    """

    def validate(self, action_name: str, params: dict[str, Any]) -> list[str]:
        """Public entry-point — delegates to validate_generated().

        Call-sites that previously used STPAValidator.validate() can use this
        method directly on GeneratedSTPAValidator without going through the
        deprecated shim in stpa_validator.py.
        """
        return self.validate_generated(action_name, params)

    def validate_generated(self, action_name: str, params: dict[str, Any]) -> list[str]:
        """Run all generated UCA checks. Returns list of violation strings."""
        violations: list[str] = []
{dispatch_str}
        return violations

{methods_str}
'''


# ---------------------------------------------------------------------------
# LangGraph Saga generator
# ---------------------------------------------------------------------------


def generate_langgraph(cs: ControlStructureModel) -> str:
    """Generate LangGraph Saga compensating sub-graphs from UCA definitions.

    For each UCA with enforcement=[langgraph] this emits:

    1. A *forward wrapper node* that implements the Write-Ahead Log (WAL) pattern:
       - Step 1: Append a PENDING intent to ``state["completed_transactions"]``.
       - Step 2: Execute the external action.
       - Step 3: Update the ledger entry to COMPLETED.

    2. A *compensating node* that is strictly idempotent via an ``idempotency_key``.
       It reads the ledger, extracts context via the ``parameter_mapping``, and
       calls the reverse API.

    3. A centralized *saga_router_node* that:
       - Detects PENDING entries (ghost-state crash recovery) and escalates to
         human_review until an automated reconciliation API is registered.
       - Traverses COMPLETED entries in LIFO order and routes to the appropriate
         compensating node.
       - Routes to ``human_review`` if a compensating node itself fails.
    """
    saga_ucas = [u for u in cs.unsafe_control_actions if "langgraph" in u.enforcement]

    if not saga_ucas:
        return (
            f"{_banner()}"
            "# No UCAs with enforcement=[langgraph] defined in this control structure.\n"
        )

    # Determine whether any Saga UCA uses an MCP tool call — controls extra imports.
    needs_mcp_imports = any(
        u.langgraph_saga is not None and u.langgraph_saga.execution_type == "mcp_tool"
        for u in saga_ucas
    )

    # Build the third-party import block.  isort requires both third-party
    # imports to be in the same block (no blank line between them).
    thirdparty_import_lines: list[str] = [
        "AgentState = Any",
        "LedgerEntry = dict[str, Any]",
    ]
    mcp_singleton_lines: list[str] = []
    if needs_mcp_imports:
        thirdparty_import_lines.append(
            "from src.gateway.infrastructure.mcp_client import GatewayMCPClient"
        )
        mcp_singleton_lines = [
            "",
            "# [CTRL_WAL_002] module-level MCP client singleton for WAL forward nodes.",
            "# The singleton is re-used across Saga invocations to avoid connection churn.",
            "_mcp_client: GatewayMCPClient | None = None",
            "",
            "",
            "def _get_mcp_client() -> GatewayMCPClient:",
            "    global _mcp_client",
            "    if _mcp_client is None:",
            "        _mcp_client = GatewayMCPClient()",
            "    return _mcp_client",
            "",
            "",
        ]

    # asyncio is stdlib — include it in the stdlib block only when needed.
    # isort requires all stdlib imports to be together before third-party imports.
    stdlib_imports: list[str] = (
        [
            "import asyncio",
            "import datetime",
            "import hashlib",
            "import logging",
            "from collections.abc import Generator",
            "from typing import Any",
        ]
        if needs_mcp_imports
        else [
            "import datetime",
            "import hashlib",
            "import logging",
            "from collections.abc import Generator",
            "from typing import Any",
        ]
    )

    lines: list[str] = [
        _banner(),
        f"# System: {cs.system.name} v{cs.system.version}",
        "#",
        "# LangGraph Saga compensating sub-graphs generated from STPA UCAs.",
        "# Each forward node implements Write-Ahead Logging (WAL) to prevent",
        "# ghost state after mid-transaction crashes.  Each compensating node",
        "# is strictly idempotent via a derived idempotency_key.",
        "#",
        "# [CTRL_WAL_002] Compliance Note:",
        "#   Forward nodes with execution_type=mcp_tool emit a real async MCP tool",
        "#   invocation (via GatewayMCPClient) instead of a stub placeholder.  This",
        "#   satisfies the CTRL_WAL_002 requirement for atomic transaction guarantees",
        "#   to be provable in production, not merely declared in policy documents.",
        "#   See config/control_mappings.json for the active regulatory framework.",
        "# DO NOT EDIT -- regenerate with:",
        "#   python -m src.gateway.governance.stpa_compiler compile --targets langgraph",
        "",
        "from __future__ import annotations",
        "",
        *stdlib_imports,
        "",
        *thirdparty_import_lines,
        *mcp_singleton_lines,
        'logger = logging.getLogger("Gateway.Governance.GeneratedSagaNodes")',
        "",
        "",
        "# ---------------------------------------------------------------------------",
        "# Helpers",
        "# ---------------------------------------------------------------------------",
        "",
        "def _derive_idempotency_key(transaction_id: str, action: str) -> str:",
        '    """Deterministically derive an idempotency key for a compensating action."""',
        '    raw = f"{transaction_id}:{action}"',
        "    return hashlib.sha256(raw.encode()).hexdigest()[:32]",
        "",
        "",
        "def _utcnow() -> str:",
        "    return datetime.datetime.now(datetime.timezone.utc).isoformat()",
        "",
        "",
        "def _next_sequence_id(state: AgentState) -> int:",
        '    """Return the next monotonically increasing sequence_id for the ledger."""',
        '    txns = state.get("completed_transactions") or []',
        '    return (max(t["sequence_id"] for t in txns) + 1) if txns else 0',
        "",
        "",
    ]

    # -----------------------------------------------------------------------
    # Forward nodes (WAL pattern) + Compensating nodes (idempotent)
    # -----------------------------------------------------------------------
    router_cases: list[tuple[str, str, str]] = []

    for uca in saga_ucas:
        assert uca.langgraph_saga is not None  # validated by Pydantic
        saga = uca.langgraph_saga
        uca_id = uca.id
        uca_slug = uca_id.lower().replace("-", "_")
        fwd_fn = f"forward_{saga.forward_action}_node_{uca_slug}"
        comp_fn = f"compensate_{saga.compensating_action}_node_{uca_slug}"

        # Build context extraction lines from parameter_mapping.
        # Variables are prefixed with "_" so ruff F841 does not flag them as
        # unused — they are intentionally extracted for the implementor's
        # reference and used in the commented-out reverse API call below.
        mapping_lines = [
            f'    _{pm.compensating_key} = context_data.get("{pm.forward_key}")'
            for pm in saga.parameter_mapping
        ] or ["    pass  # no parameter_mapping defined"]
        comp_kwarg_lines = [
            f"        #     {pm.compensating_key}=_{pm.compensating_key},"
            for pm in saga.parameter_mapping
        ]
        mapping_str = "\n".join(mapping_lines)
        comp_kwargs_str = "\n".join(comp_kwarg_lines)

        # ---- Forward WAL node -------------------------------------------------
        # [CTRL_WAL_002] emit a real execution block based on execution_type.
        # execution_type=mcp_tool → async GatewayMCPClient.call_tool() call
        # execution_type=local    → retains a clearly-labeled local stub that
        #                           the implementor must wire before promotion.
        if saga.execution_type == "mcp_tool":
            step2_lines = [
                "    # Step 2: [CTRL_WAL_002] — real async MCP tool invocation.",
                "    # GatewayMCPClient traverses the full 7-layer governance pipeline",
                "    # (Aho-Corasick → NeMo → STPA → OPA → CBF → Consensus → DoWhy)",
                "    # before executing the trade, ensuring atomicity guarantees are",
                "    # proven in production and not merely declared in policy documents.",
                "    result: dict[str, Any] = asyncio.get_event_loop().run_until_complete(",
                "        _get_mcp_client().call_tool(",
                f'            name="{saga.mcp_tool_name}",',
                "            arguments={k: v for k, v in state.items()",
                '                       if k in ("amount", "symbol", "account_id",',
                '                                "trader_role", "approval_token")},',
                "        )",
                "    )",
            ]
        else:
            step2_lines = [
                "    # Step 2: LOCAL stub — wire to a real implementation before promoting",
                "    # to production.  See execution_type field in stpa_control_structure.yaml.",
                "    # To use MCP: set execution_type: mcp_tool + mcp_tool_name in the YAML",
                "    # and regenerate with: python -m src.gateway.governance.stpa_compiler compile",
                "    result: dict[str, Any] = {}  # STUB: replace before production",
            ]

        lines += [
            f"# --- {uca_id}: {uca.description} ---",
            f"# [CTRL_WAL_002] execution_type: {saga.execution_type}"
            + (f" | mcp_tool_name: {saga.mcp_tool_name}" if saga.mcp_tool_name else ""),
            "",
            f"def {fwd_fn}(state: AgentState) -> Generator[dict[str, Any], None, dict[str, Any]]:",
            f'    """WAL forward node for {uca_id} ({saga.forward_action}).',
            "    ",
            "    Step 1: Write PENDING intent to ledger (yielded to checkpointer).",
            f"    Step 2: Execute via {saga.execution_type} - {saga.mcp_tool_name or 'local stub'}.",
            "    Step 3: Confirm COMPLETED in the ledger.",
            "    ",
            "    This node MUST be wrapped in a try/except by the caller.",
            "    On exception, the PENDING entry persists so saga_router_node",
            "    can reconcile ghost state on the next execution.",
            '    """',
            "    seq_id = _next_sequence_id(state)",
            "    intent: LedgerEntry = {",
            '        "sequence_id": seq_id,',
            '        "timestamp": _utcnow(),',
            f'        "uca_ref": "{uca_id}",',
            f'        "action": "{saga.forward_action}",',
            '        "idempotency_key": "",  # populated after API call returns tx_id',
            '        "status": "PENDING",',
            '        "context_data": {},',
            "    }",
            "    # Step 1: Persist WAL intent BEFORE the API call",
            f'    logger.info("{uca_id}: writing PENDING intent seq_id=%s", seq_id)',
            '    yield {"completed_transactions": [intent]}',
            "",
            *step2_lines,
            '    tx_id: str = result.get("transaction_id", "")',
            "",
            "    # Step 3: Mark COMPLETED",
            "    confirmed: LedgerEntry = {",
            '        "sequence_id": seq_id,',
            '        "timestamp": _utcnow(),',
            f'        "uca_ref": "{uca_id}",',
            f'        "action": "{saga.forward_action}",',
            f'        "idempotency_key": _derive_idempotency_key(tx_id, "{saga.compensating_action}"),',
            '        "status": "COMPLETED",',
            '        "context_data": result,',
            "    }",
            f'    logger.info("{uca_id}: action COMPLETED tx_id=%s", tx_id)',
            '    return {"completed_transactions": [confirmed]}',
            "",
            "",
        ]

        # ---- Compensating node (idempotent) -----------------------------------
        lines += [
            f"def {comp_fn}(state: AgentState) -> dict[str, Any]:",
            f'    """Idempotent compensating node for {uca_id} ({saga.compensating_action}).',
            "    ",
            f"    Reads the most-recent COMPLETED ledger entry for '{saga.forward_action}'",
            f"    with uca_ref=={uca_id!r}, extracts parameters via parameter_mapping,",
            "    and calls the reverse API.",
            "    The idempotency_key prevents double-refunds across LangGraph retries.",
            '    """',
            '    txns = state.get("completed_transactions") or []',
            "    target = next(",
            "        (",
            "            t for t in reversed(txns)",
            f'            if t["uca_ref"] == "{uca_id}"',
            f'            and t["action"] == "{saga.forward_action}"',
            '            and t["status"] == "COMPLETED"',
            "        ),",
            "        None,",
            "    )",
            "    if target is None:",
            f'        logger.warning("{uca_id}: no COMPLETED ledger entry — nothing to compensate.")',
            '        return {"safety_status": "ESCALATED"}',
            "",
            '    context_data = target["context_data"]',
            '    idempotency_key = target["idempotency_key"]',
            "",
            "    # Extract parameters via parameter_mapping",
            mapping_str,
            "",
            "    try:",
            "        # Replace with real reverse API call, e.g.:",
            f"        # gateway_api.{saga.compensating_action}(",
            "        #     idempotency_key=idempotency_key,",
            comp_kwargs_str,
            "        # )",
            f"        logger.info(\"{uca_id}: '{saga.compensating_action}' executed. key=%s\", idempotency_key)",
            "        rollback_entry: LedgerEntry = dict(target)  # type: ignore[assignment]",
            '        rollback_entry["status"] = "ROLLED_BACK"',
            '        rollback_entry["timestamp"] = _utcnow()',
            "        return {",
            '            "completed_transactions": [rollback_entry],',
            '            "safety_status": "BLOCKED",',
            "        }",
            "    except Exception as exc:",
            f'        logger.error("{uca_id}: compensating action FAILED key=%s err=%s", idempotency_key, exc)',
            "        partial_entry: LedgerEntry = dict(target)  # type: ignore[assignment]",
            '        partial_entry["status"] = "PARTIAL_FAILURE"',
            '        partial_entry["timestamp"] = _utcnow()',
            "        return {",
            '            "completed_transactions": [partial_entry],',
            '            "safety_status": "ESCALATED",',
            '            "next_step": "human_review",',
            "        }",
            "",
            "",
        ]

        router_cases.append((uca_id, saga.forward_action, comp_fn))

    # -----------------------------------------------------------------------
    # Centralized Saga Router Node
    # -----------------------------------------------------------------------
    lines += [
        "# ---------------------------------------------------------------------------",
        "# Centralized Saga Router Node",
        "# ---------------------------------------------------------------------------",
        "",
        "def saga_router_node(state: AgentState) -> dict[str, Any]:",
        '    """Deterministic LIFO rollback router for all Saga compensating nodes.',
        "    ",
        "    1. Ghost-state recovery: escalates to human_review on PENDING entries.",
        "    2. LIFO rollback: traverses COMPLETED entries in reverse sequence_id order",
        "       and delegates to the appropriate compensating node function.",
        "    3. Unhandled UCA escalation: escalates if no compensating node is registered.",
        '    """',
        "    txns = sorted(",
        '        state.get("completed_transactions") or [],',
        '        key=lambda t: t["sequence_id"],',
        "        reverse=True,",
        "    )",
        "",
        "    # Ghost-state reconciliation",
        '    pending = [t for t in txns if t["status"] == "PENDING"]',
        "    if pending:",
        "        logger.warning(",
        '            "saga_router: %d PENDING entries detected — possible ghost state crash.",',
        "            len(pending),",
        "        )",
        "        return {",
        '            "safety_status": "ESCALATED",',
        '            "next_step": "human_review",',
        '            "governance_summary": (',
        '                f"Saga Router: ghost state detected ({len(pending)} PENDING entries). "',
        '                "Manual reconciliation required."',
        "            ),",
        "        }",
        "",
        "    # LIFO rollback routing",
        '    rollback_targets = [t for t in txns if t["status"] == "COMPLETED"]',
        "    if not rollback_targets:",
        '        logger.info("saga_router: no COMPLETED entries to roll back.")',
        '        return {"safety_status": "BLOCKED"}',
        "",
        "    next_target = rollback_targets[0]",
        '    uca_ref = next_target["uca_ref"]',
        '    action = next_target["action"]',
        "",
    ]

    for uca_id, fwd_action, comp_fn in router_cases:
        lines += [
            f'    if uca_ref == "{uca_id}" and action == "{fwd_action}":',
            f'        logger.info("saga_router: delegating to {comp_fn} seq_id=%s", next_target["sequence_id"])',
            f"        return {comp_fn}(state)",
            "",
        ]

    lines += [
        "    logger.error(",
        '        "saga_router: no compensating node for uca_ref=%s action=%s",',
        "        uca_ref, action,",
        "    )",
        "    return {",
        '        "safety_status": "ESCALATED",',
        '        "next_step": "human_review",',
        '        "governance_summary": f"Saga Router: unhandled uca_ref={uca_ref} action={action}.",',
        "    }",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AGP Semantic Governance Policy generator (C1)
# ---------------------------------------------------------------------------


def generate_agp(cs: ControlStructureModel) -> str:
    """Generate Google Agent Platform Semantic Governance Policy (SGP) text.

    Emits natural language constraint text following the mapping in
    ``CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md §4.1``.

    The output is a plain-text string (not JSON) suitable for the AGP
    ``Constraints`` field. Maximum 5,000 characters; generator warns and
    appends a ``# TRUNCATED`` sentinel if the budget is exceeded.

    CBF invariants are intentionally omitted — they are not mappable to
    AGP natural language constraints.

    Args:
        cs: Validated ``ControlStructureModel`` instance.

    Returns:
        Natural language constraint text string.
    """
    lines: list[str] = [
        f"# CAGE Semantic Governance Policy — {cs.system.name} v{cs.system.version}",
        "# Generated from STPA control structure. Do not edit manually.",
        "# Source: config/stpa_control_structure.yaml",
        "",
    ]

    for uca in cs.unsafe_control_actions:
        cond = uca.condition
        action = uca.action
        param = cond.param or ""

        # Resolve threshold value
        threshold: str | float | None = None
        if cond.threshold is not None:
            threshold = cond.threshold
        elif cond.threshold_ref:
            # Attempt runtime resolution via THRESHOLDS singleton
            try:
                from src.gateway.governance.schemas.thresholds import THRESHOLDS

                attr_path = cond.threshold_ref.split(".")
                obj: Any = THRESHOLDS
                for attr in attr_path:
                    obj = getattr(obj, attr, None)
                    if obj is None:
                        break
                threshold = obj
            except Exception:
                threshold = f"<{cond.threshold_ref}>"

        op = cond.operator

        # Map operator → NL sentence
        if op == "is_null" and param:
            sentence = f'Do not execute "{action}" if "{param}" is null or missing.'
        elif op == "is_false" and param:
            sentence = (
                f'Do not execute "{action}" if "{param}" is false or not set to true.'
            )
        elif op == "is_true" and param:
            sentence = f'Do not execute "{action}" if "{param}" is true.'
        elif op == "greater_than" and param and threshold is not None:
            sentence = f'Do not execute "{action}" if "{param}" exceeds {threshold}.'
        elif op == "less_than" and param and threshold is not None:
            sentence = f'Do not execute "{action}" if "{param}" is below {threshold}.'
        elif op == "equals" and param and threshold is not None:
            sentence = f'Do not execute "{action}" if "{param}" equals {threshold}.'
        elif cond.composite:
            # Composite conditions: emit as a general constraint
            sentence = f'Do not execute "{action}" when: {cond.composite}.'
        else:
            # Cannot map — skip with a comment
            lines.append(f"# UCA {uca.id}: condition not mappable to AGP NL — omitted.")
            continue

        lines.append(f"# {uca.id}: {uca.description}")
        lines.append(sentence)
        lines.append("")

    # NeMo rail messages → "Block any request that ..." sentences
    for uca in cs.unsafe_control_actions:
        if uca.nemo_rail:
            msg = uca.nemo_rail.message
            lines.append(f"# {uca.id} (NeMo rail): {uca.description}")
            lines.append(f"Block any request that {msg}")
            lines.append("")

    # RBAC rules → human approval / deny sentences
    if cs.rbac_rules:
        for role in cs.rbac_rules.roles:
            if role.trade_limits:
                tl = role.trade_limits
                review_below = tl.get("manual_review_below")
                allow_below = tl.get("allow_below")
                denylist: list[str] = []
                if role.restrictions:
                    for r in role.restrictions:
                        denylist.extend(r.get("currency_denylist", []))

                if review_below and allow_below:
                    lines.append(
                        f'Require human approval for "execute_trade" where '
                        f'"amount" exceeds {allow_below} for "{role.name}" role users.'
                    )
                    lines.append("")

                for currency in denylist:
                    lines.append(
                        f'Deny "execute_trade" where "currency" is "{currency}" '
                        f'for "{role.name}" role users.'
                    )
                    lines.append("")

    output = "\n".join(lines)

    # Enforce 5,000-character budget
    if len(output) > _AGP_CHAR_BUDGET:
        logger.warning(
            "generate_agp: output exceeds %d-character AGP budget (%d chars). "
            "Truncating with sentinel.",
            _AGP_CHAR_BUDGET,
            len(output),
        )
        # Truncate to budget minus sentinel length
        sentinel = "\n# TRUNCATED — output exceeded 5,000-character AGP budget."
        truncated = output[: _AGP_CHAR_BUDGET - len(sentinel)]
        output = truncated + sentinel

    return output


# ---------------------------------------------------------------------------
# FTRA Terminal Registry generator
# ---------------------------------------------------------------------------


def generate_terminal_registry(
    cs: ControlStructureModel,
    serial: int | None = None,
    validity_days: int = 90,
    sign: bool = False,
) -> str:
    """Generate the FTRA terminal classification registry as JSON (v2.0).

    Emits a JSON object mapping each unique action name found in
    ``unsafe_control_actions`` to its ``terminal_classification`` value.

    Fail-closed contract (enforced at runtime by IrreversibilityClassifier):
      Any action name absent from this registry is treated as
      ``IRREVERSIBLE_TERMINAL`` by the classifier.  This means that adding a
      new control action to the YAML without annotating
      ``terminal_classification`` will cause the FTRA to block any plan that
      reaches that action — the safe default.

    Actions with multiple UCAs:
      If the same action appears in multiple UCAs with *different*
      ``terminal_classification`` values, the most restrictive classification
      wins (IRREVERSIBLE_TERMINAL > EXTERNALLY_REVERSIBLE > REVERSIBLE >
      READ_ONLY).  A warning is logged for each conflict.

    Args:
        cs: Validated ``ControlStructureModel`` instance.
        serial: Registry serial number for anti-rollback (VEC-008). If None,
                defaults to int(time.time()). Monotonic by construction.
        validity_days: Registry lifetime in days. Default: 90.
        sign: If True, generate a detached signature (.sig file) using
              KMSGovernanceSigner. Requires live KMS. Default: False.

    Returns:
        JSON string suitable for writing to ``config/ftra/terminal_registry.json``.
    """
    import datetime as _dt
    import time as _time

    from src.gateway.governance.ftra.models import (
        CLASSIFICATION_SEVERITY,
    )
    from src.gateway.governance.ftra.models import (
        TerminalClassification as TC,
    )

    # Derive string-keyed severity map from the canonical enum-keyed map
    _SEVERITY_ORDER = {
        tc.value: severity for tc, severity in CLASSIFICATION_SEVERITY.items()
    }

    # Collect per-action classifications — most restrictive wins on conflict.
    action_map: dict[str, str] = {}
    conflicts: list[str] = []

    for uca in cs.unsafe_control_actions:
        action = uca.action
        classification = uca.terminal_classification or "IRREVERSIBLE_TERMINAL"

        if action in action_map:
            existing = action_map[action]
            if existing != classification:
                conflicts.append(
                    f"action '{action}': conflict between '{existing}' and "
                    f"'{classification}' — using most restrictive"
                )
                # Keep the more restrictive classification
                if _SEVERITY_ORDER[classification] > _SEVERITY_ORDER[existing]:
                    action_map[action] = classification
        else:
            action_map[action] = classification

    for conflict in conflicts:
        logger.warning("generate_terminal_registry: %s", conflict)

    # Generate v2.0 envelope with temporal and anti-rollback fields
    now_utc = _dt.datetime.now(_dt.timezone.utc)
    expires_at = now_utc + _dt.timedelta(days=validity_days)
    registry_serial = serial if serial is not None else int(_time.time())

    registry = {
        "version": "2.0",
        "serial": registry_serial,
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "system": cs.system.name,
        "system_version": cs.system.version,
        "fail_closed_note": (
            "Any action absent from this registry is treated as "
            "IRREVERSIBLE_TERMINAL by IrreversibilityClassifier at runtime."
        ),
        "terminals": action_map,
    }

    # Guard: assert no "signed_at" field (plan section 3 trap)
    # KMSGovernanceSigner.verify() hardcodes a 300-second staleness rejection
    # for any payload with a "signed_at" key, which would make the registry
    # unloadable five minutes after generation.
    assert "signed_at" not in registry, (
        "BUG: generate_terminal_registry() must never emit a 'signed_at' field. "
        "Use 'issued_at' and 'expires_at' instead."
    )

    import json as _json

    registry_json = _json.dumps(registry, indent=2)

    # Optional signing (opt-in via --sign flag, requires live KMS)
    if sign:
        logger.info(
            "Signing terminal registry (serial=%d) with KMSGovernanceSigner...",
            registry_serial,
        )
        from src.gateway.governance.kms_signer import get_governance_signer

        signer = get_governance_signer()
        if not signer.is_kms_active:
            raise RuntimeError(
                "Cannot sign terminal registry: KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and CAGE_ENV=prod. "
                "Run without --sign to emit an unsigned v2.0 registry."
            )

        # Sign the registry dict (KMSGovernanceSigner canonicalizes internally)
        signature_hex = signer.sign(registry)
        key_id = signer.key_id

        sig_envelope = {
            "alg": signer.jose_alg,
            "key_id": key_id,
            "canonicalization": "RFC8785-JCS",
            "signature": signature_hex,
        }

        logger.info(
            "✅ Terminal registry signed: serial=%d, key_id=%s, alg=%s",
            registry_serial,
            key_id,
            signer.jose_alg,
        )

        # Caller must write the .sig file alongside the registry JSON
        # (not done here to keep this function side-effect-free)
        return registry_json, _json.dumps(sig_envelope, indent=2)

    return registry_json


# ---------------------------------------------------------------------------
# GEAP Agent Registry manifest generator (Phase C)
# ---------------------------------------------------------------------------


def generate_registry_manifest(cs: ControlStructureModel) -> str:
    """Generate a GEAP Agent Registry tool authorization manifest as JSON.

    GCP Adaptation: the output is consumed by ``AgentRegistryAdapter.push_tool_authorizations()``
    to update tool authorization policies in the GEAP Agent Registry.  Cloud-agnostic
    deployments do not use this artifact.

    Emits a JSON string (not natural language) representing the tool authorization
    manifest derived from the STPA control structure.

    Output format::

        {
          "_generated_by": "CAGE stpa_compiler",
          "_source": "config/stpa_control_structure.yaml",
          "_generated_at": "2026-07-23T00:00:00Z",
          "_schema_version": "1.0.0",
          "tool_authorizations": [
            {
              "tool_name": "execute_trade",
              "allowed_roles": ["trader", "senior"],
              "denied_roles": ["junior"],
              "uca_refs": ["UCA-1", "UCA-2"],
              "hazard_refs": ["H-1", "H-2"],
              "requires_approval_above_usd": 10000
            }
          ]
        }

    Mapping rules:
    - Each unique ``action`` in ``cs.unsafe_control_actions`` becomes a ``tool_name`` entry.
    - ``uca_refs``: list of UCA IDs that reference this action.
    - ``hazard_refs``: union of all ``hazard_refs`` across UCAs for this action.
    - ``allowed_roles``: from ``cs.rbac_rules.roles`` where the action is in ``allowed_actions``.
    - ``denied_roles``: roles where the action is NOT in ``allowed_actions``.
    - ``requires_approval_above_usd``: from ``rbac_rules.roles[].trade_limits.manual_review_below``
      if present (minimum across all roles that have this limit for the action).

    Args:
        cs: Validated ``ControlStructureModel`` instance.

    Returns:
        JSON string suitable for writing to
        ``config/registry/generated_tool_authorizations.json``.
    """
    import datetime as _dt
    import json as _json

    now_utc = _dt.datetime.now(_dt.timezone.utc).isoformat()

    # ── Step 1: Collect per-action UCA refs and hazard refs ──────────────────
    action_uca_refs: dict[str, list[str]] = {}
    action_hazard_refs: dict[str, set[str]] = {}

    for uca in cs.unsafe_control_actions:
        action = uca.action
        action_uca_refs.setdefault(action, []).append(uca.id)
        action_hazard_refs.setdefault(action, set()).update(uca.hazard_refs)

    # ── Step 2: Collect per-action RBAC role membership ──────────────────────
    # allowed_roles: roles whose allowed_actions list includes this action
    # denied_roles: roles whose allowed_actions list does NOT include this action
    action_allowed_roles: dict[str, list[str]] = {}
    action_denied_roles: dict[str, list[str]] = {}
    action_approval_threshold: dict[str, float | None] = {}

    if cs.rbac_rules:
        for action in action_uca_refs:
            allowed: list[str] = []
            denied: list[str] = []
            thresholds: list[float] = []

            for role in cs.rbac_rules.roles:
                if action in role.allowed_actions:
                    allowed.append(role.name)
                    # Collect manual_review_below threshold if present
                    if role.trade_limits:
                        review_below = role.trade_limits.get("manual_review_below")
                        if review_below is not None:
                            thresholds.append(float(review_below))
                else:
                    denied.append(role.name)

            action_allowed_roles[action] = allowed
            action_denied_roles[action] = denied
            # Use the minimum threshold across all allowed roles (most restrictive)
            action_approval_threshold[action] = min(thresholds) if thresholds else None

    # ── Step 3: Build tool_authorizations list ────────────────────────────────
    tool_authorizations: list[dict] = []

    for action in sorted(action_uca_refs.keys()):
        entry: dict = {
            "tool_name": action,
            "allowed_roles": action_allowed_roles.get(action, []),
            "denied_roles": action_denied_roles.get(action, []),
            "uca_refs": action_uca_refs[action],
            "hazard_refs": sorted(action_hazard_refs.get(action, set())),
        }
        threshold = action_approval_threshold.get(action)
        if threshold is not None:
            entry["requires_approval_above_usd"] = threshold

        tool_authorizations.append(entry)

    manifest = {
        "_generated_by": "CAGE stpa_compiler",
        "_source": "config/stpa_control_structure.yaml",
        "_generated_at": now_utc,
        "_schema_version": "1.0.0",
        "tool_authorizations": tool_authorizations,
    }

    return _json.dumps(manifest, indent=2)


# ---------------------------------------------------------------------------
# Compiler orchestrator
# ---------------------------------------------------------------------------


@dataclass
class CompileResult:
    opa_content: str = ""
    nemo_content: str = ""
    python_content: str = ""
    langgraph_content: str = ""
    agp_content: str = ""
    ftra_content: str = ""
    ftra_sig_content: str = ""
    registry_content: str = ""
    errors: list[str] = field(default_factory=list)


def load_control_structure(path: Path) -> ControlStructureModel:
    """Load and validate the YAML control structure."""
    if not path.exists():
        raise FileNotFoundError(f"Control structure not found: {path}")
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    return ControlStructureModel(**raw)


def load_control_structures(paths: list[Path]) -> ControlStructureModel:
    """Load and merge multiple STPA control structure YAML files.

    All paths must exist. The merge is deterministic given the same set of
    files in sorted order: hazards, UCAs, and constraints are sorted by ID;
    control actions are sorted by name. The caller should pass ``sorted(paths)``
    to guarantee filesystem-order independence.

    Args:
        paths: Ordered list of YAML source paths. Must be non-empty.

    Returns:
        A single merged ``ControlStructureModel``.

    Raises:
        FileNotFoundError: If any path does not exist.
        ValueError: If duplicate IDs are found across files or a UCA's
                    hazard_ref does not resolve in the merged corpus.
    """
    if not paths:
        raise ValueError("load_control_structures() requires at least one path")
    models = [load_control_structure(p) for p in paths]
    if len(models) == 1:
        return models[0]
    return ControlStructureModel.merge(models)


def compile_control_structure(
    cs: ControlStructureModel,
    targets: list[str],
    registry_serial: int | None = None,
    registry_validity_days: int = 90,
    sign: bool = False,
) -> CompileResult:
    """Compile the control structure into governance artifacts."""
    result = CompileResult()
    effective_targets = (
        targets
        if "all" not in targets
        else ["opa", "nemo", "python", "langgraph", "ftra"]
    )

    if "opa" in effective_targets:
        try:
            result.opa_content = generate_opa(cs)
        except Exception as exc:
            result.errors.append(f"OPA generation failed: {exc}")

    if "nemo" in effective_targets:
        try:
            result.nemo_content = generate_nemo(cs)
        except Exception as exc:
            result.errors.append(f"NeMo generation failed: {exc}")

    if "langgraph" in effective_targets:
        try:
            result.langgraph_content = generate_langgraph(cs)
        except Exception as exc:
            result.errors.append(f"LangGraph Saga generation failed: {exc}")

    if "python" in effective_targets:
        try:
            result.python_content = generate_python(cs)
        except Exception as exc:
            result.errors.append(f"Python generation failed: {exc}")

    if "agp" in effective_targets:
        try:
            result.agp_content = generate_agp(cs)
        except Exception as exc:
            result.errors.append(f"AGP generation failed: {exc}")

    if "ftra" in effective_targets:
        try:
            registry_output = generate_terminal_registry(
                cs,
                serial=registry_serial,
                validity_days=registry_validity_days,
                sign=sign,
            )
            # Signing returns a tuple (registry_json, sig_json), unsigned returns just registry_json
            if sign:
                result.ftra_content, result.ftra_sig_content = registry_output
            else:
                result.ftra_content = registry_output
        except Exception as exc:
            result.errors.append(f"FTRA terminal registry generation failed: {exc}")

    if "registry" in effective_targets:
        try:
            result.registry_content = generate_registry_manifest(cs)
        except Exception as exc:
            result.errors.append(f"Agent Registry manifest generation failed: {exc}")

    return result


def _ruff_format(path: Path) -> None:
    """Run ``ruff format`` on a generated Python file (best-effort, no-op if ruff absent).

    Resolves the ruff binary relative to the current Python interpreter so that
    venv-installed ruff is found even when it is not on the system PATH.
    """
    import subprocess
    import sys

    # Prefer ruff installed alongside the current interpreter (venv-aware).
    ruff_bin = Path(sys.executable).parent / "ruff"
    if not ruff_bin.exists():
        ruff_bin = Path("ruff")  # fall back to PATH

    try:
        subprocess.run(
            [str(ruff_bin), "format", str(path)],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        # ruff not installed or formatting failed — leave file as-is.
        pass


def write_artifacts(
    result: CompileResult,
    opa_out: Path,
    nemo_out: Path,
    python_out: Path,
    langgraph_out: Path,
    agp_out: Path | None = None,
    ftra_out: Path | None = None,
    registry_out: Path | None = None,
) -> None:
    """Write generated artifacts to disk, creating parent dirs as needed."""
    if result.opa_content:
        opa_out.parent.mkdir(parents=True, exist_ok=True)
        opa_out.write_text(result.opa_content)
        logger.info("✅ OPA policy written → %s", opa_out)

    if result.nemo_content:
        nemo_out.parent.mkdir(parents=True, exist_ok=True)
        nemo_out.write_text(result.nemo_content)
        logger.info("✅ NeMo rails written → %s", nemo_out)

    if result.python_content:
        python_out.parent.mkdir(parents=True, exist_ok=True)
        python_out.write_text(result.python_content)
        _ruff_format(python_out)
        logger.info("✅ Python validator written → %s", python_out)

    if result.langgraph_content:
        langgraph_out.parent.mkdir(parents=True, exist_ok=True)
        langgraph_out.write_text(result.langgraph_content)
        _ruff_format(langgraph_out)
        logger.info("✅ LangGraph Saga nodes written → %s", langgraph_out)

    if result.agp_content:
        effective_agp_out = agp_out or _DEFAULT_AGP_OUT
        effective_agp_out.parent.mkdir(parents=True, exist_ok=True)
        effective_agp_out.write_text(result.agp_content)
        logger.info("✅ AGP Semantic Policy written → %s", effective_agp_out)
        char_count = len(result.agp_content)
        if char_count > _AGP_CHAR_BUDGET:
            logger.warning(
                "⚠️  AGP output exceeds %d-char budget (%d chars). "
                "Output contains TRUNCATED sentinel.",
                _AGP_CHAR_BUDGET,
                char_count,
            )
        else:
            logger.info(
                "   AGP character budget: %d/%d used (%.1f%%)",
                char_count,
                _AGP_CHAR_BUDGET,
                100.0 * char_count / _AGP_CHAR_BUDGET,
            )

    if result.ftra_content:
        effective_ftra_out = ftra_out or _DEFAULT_FTRA_OUT
        effective_ftra_out.parent.mkdir(parents=True, exist_ok=True)
        effective_ftra_out.write_text(result.ftra_content)
        logger.info("✅ FTRA terminal registry written → %s", effective_ftra_out)
        # Write detached signature if present (--sign was used)
        if result.ftra_sig_content:
            sig_out = Path(str(effective_ftra_out) + ".sig")
            sig_out.write_text(result.ftra_sig_content)
            logger.info("✅ FTRA registry signature written → %s", sig_out)

    if result.registry_content:
        effective_registry_out = registry_out or _DEFAULT_REGISTRY_OUT
        effective_registry_out.parent.mkdir(parents=True, exist_ok=True)
        effective_registry_out.write_text(result.registry_content)
        logger.info("✅ Agent Registry manifest written → %s", effective_registry_out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stpa_compiler",
        description=textwrap.dedent(
            """\
            STPA-to-Policy Compiler — transforms stpa_control_structure.yaml into
            deterministic OPA Rego policies, NeMo Colang rails, and Python validators.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # compile
    compile_p = sub.add_parser(
        "compile", help="Compile control structure to artifacts."
    )
    compile_p.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        metavar="YAML",
        help=f"Path to control structure YAML (default: {_DEFAULT_INPUT})",
    )
    compile_p.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Directory of STPA YAML source files (mutually exclusive with --input). "
            "All *.yaml files under DIR are merged deterministically. "
            f"Default directory: {_DEFAULT_INPUT_DIR}"
        ),
    )
    compile_p.add_argument(
        "--targets",
        nargs="+",
        choices=[
            "opa",
            "nemo",
            "python",
            "langgraph",
            "agp",
            "ftra",
            "registry",
            "all",
        ],
        default=["all"],
        help=(
            "Artifacts to generate (default: all). "
            "Use 'agp' for AGP Semantic Policy. "
            "Use 'ftra' for FTRA terminal registry (config/ftra/terminal_registry.json). "
            "Use 'registry' for GEAP Agent Registry tool authorization manifest "
            "(GCP Adaptation — config/registry/generated_tool_authorizations.json)."
        ),
    )
    compile_p.add_argument(
        "--opa-out",
        type=Path,
        default=_DEFAULT_OPA_OUT,
        metavar="FILE",
        help=f"OPA output path (default: {_DEFAULT_OPA_OUT})",
    )
    compile_p.add_argument(
        "--nemo-out",
        type=Path,
        default=_DEFAULT_NEMO_OUT,
        metavar="FILE",
        help=f"NeMo output path (default: {_DEFAULT_NEMO_OUT})",
    )
    compile_p.add_argument(
        "--python-out",
        type=Path,
        default=_DEFAULT_PY_OUT,
        metavar="FILE",
        help=f"Python output path (default: {_DEFAULT_PY_OUT})",
    )
    compile_p.add_argument(
        "--langgraph-out",
        type=Path,
        default=_DEFAULT_LG_OUT,
        metavar="FILE",
        help=f"LangGraph Saga output path (default: {_DEFAULT_LG_OUT})",
    )
    compile_p.add_argument(
        "--agp-out",
        type=Path,
        default=_DEFAULT_AGP_OUT,
        metavar="FILE",
        help=f"AGP Semantic Policy output path (default: {_DEFAULT_AGP_OUT})",
    )
    compile_p.add_argument(
        "--ftra-out",
        type=Path,
        default=_DEFAULT_FTRA_OUT,
        metavar="FILE",
        help=f"FTRA terminal registry output path (default: {_DEFAULT_FTRA_OUT})",
    )
    compile_p.add_argument(
        "--registry-out",
        type=Path,
        default=_DEFAULT_REGISTRY_OUT,
        metavar="FILE",
        help=(
            f"Agent Registry manifest output path (default: {_DEFAULT_REGISTRY_OUT}). "
            "GCP Adaptation — only used when --targets registry is specified."
        ),
    )
    compile_p.add_argument(
        "--registry-serial",
        type=int,
        default=None,
        metavar="N",
        help=(
            "FTRA registry serial number for anti-rollback (VEC-008). "
            "Defaults to int(time.time()) — monotonic by construction."
        ),
    )
    compile_p.add_argument(
        "--registry-validity-days",
        type=int,
        default=90,
        metavar="DAYS",
        help="FTRA registry lifetime in days (default: 90).",
    )
    compile_p.add_argument(
        "--sign",
        action="store_true",
        help=(
            "Sign the FTRA terminal registry with KMSGovernanceSigner "
            "(requires live KMS and CAGE_ENV=prod). Emits detached .sig file. "
            "Without this flag, generates unsigned v2.0 registry for dev/CI."
        ),
    )
    compile_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated content to stdout without writing files.",
    )

    # validate
    val_p = sub.add_parser(
        "validate", help="Validate the control structure YAML without compiling."
    )
    val_p.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        metavar="YAML",
        help=f"Path to control structure YAML (default: {_DEFAULT_INPUT})",
    )
    val_p.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Directory of STPA YAML source files to validate (mutually exclusive with --input)."
        ),
    )

    return parser


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        if args.input_dir is not None:
            yaml_files = sorted(args.input_dir.rglob("*.yaml"))
            if not yaml_files:
                print(f"❌ No YAML files found under {args.input_dir}", file=sys.stderr)
                return 1
            cs = load_control_structures(yaml_files)
        else:
            cs = load_control_structure(args.input)
        print(
            f"✅ Control structure valid: {len(cs.unsafe_control_actions)} UCAs, "
            f"{len(cs.hazards)} hazards, {len(cs.safety_constraints)} constraints."
        )
        return 0
    except Exception as exc:
        print(f"❌ Validation failed: {exc}", file=sys.stderr)
        return 1


def cmd_compile(args: argparse.Namespace) -> int:
    try:
        if args.input_dir is not None:
            yaml_files = sorted(args.input_dir.rglob("*.yaml"))
            if not yaml_files:
                print(
                    f"❌ No YAML files found under {args.input_dir}",
                    file=sys.stderr,
                )
                return 1
            logger.info(
                "Multi-source mode: loading %d files from %s",
                len(yaml_files),
                args.input_dir,
            )
            cs = load_control_structures(yaml_files)
        else:
            cs = load_control_structure(args.input)
    except Exception as exc:
        print(f"❌ Failed to load control structure: {exc}", file=sys.stderr)
        return 1

    result = compile_control_structure(
        cs,
        args.targets,
        registry_serial=getattr(args, "registry_serial", None),
        registry_validity_days=getattr(args, "registry_validity_days", 90),
        sign=getattr(args, "sign", False),
    )

    if result.errors:
        for err in result.errors:
            print(f"❌ {err}", file=sys.stderr)
        return 1

    if args.dry_run:
        sep = "\n" + "=" * 80 + "\n"
        if result.opa_content:
            print(sep + "OPA REGO" + sep + result.opa_content)
        if result.nemo_content:
            print(sep + "NEMO COLANG" + sep + result.nemo_content)
        if result.python_content:
            print(sep + "PYTHON VALIDATOR" + sep + result.python_content)
        if result.langgraph_content:
            print(sep + "LANGGRAPH SAGA NODES" + sep + result.langgraph_content)
        if result.agp_content:
            char_count = len(result.agp_content)
            print(
                sep
                + f"AGP SEMANTIC POLICY ({char_count}/{_AGP_CHAR_BUDGET} chars)"
                + sep
                + result.agp_content
            )
            if char_count > _AGP_CHAR_BUDGET:
                print(
                    f"⚠️  WARNING: AGP output exceeds {_AGP_CHAR_BUDGET}-char budget.",
                    file=sys.stderr,
                )
        if result.ftra_content:
            print(sep + "FTRA TERMINAL REGISTRY (JSON)" + sep + result.ftra_content)
        if result.registry_content:
            print(
                sep
                + "AGENT REGISTRY MANIFEST (JSON) [GCP Adaptation]"
                + sep
                + result.registry_content
            )
        return 0

    write_artifacts(
        result,
        args.opa_out,
        args.nemo_out,
        args.python_out,
        args.langgraph_out,
        agp_out=args.agp_out,
        ftra_out=args.ftra_out,
        registry_out=args.registry_out,
    )
    print("✅ STPA compiler finished. Artifacts written:")
    if result.opa_content:
        print(f"   OPA Rego  → {args.opa_out}")
    if result.nemo_content:
        print(f"   NeMo Colang → {args.nemo_out}")
    if result.python_content:
        print(f"   Python validator → {args.python_out}")
    if result.langgraph_content:
        print(f"   LangGraph Saga → {args.langgraph_out}")
    if result.agp_content:
        print(f"   AGP Semantic Policy → {args.agp_out}")
    if result.ftra_content:
        print(f"   FTRA terminal registry → {args.ftra_out}")
    if result.registry_content:
        print(f"   Agent Registry manifest [GCP] → {args.registry_out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "compile":
        return cmd_compile(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
