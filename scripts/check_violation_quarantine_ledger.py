#!/usr/bin/env python3
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
"""AST discovery & partition gate for Violation quarantine triggers (POAM-2026-233).

Walks every production Python file under ``src/**/*.py`` (excluding only
``__pycache__`` and embedded ``/tests/`` directories) to discover every
constructible ``Violation.code`` and ``Violation.kind`` from source AST, and
enforces a strict, zero-waiver disjoint partition between:

1. ``QUARANTINE_CODES`` — codes that trigger out-of-band workload quarantine
   when ``CAGE_ENABLE_AUTO_QUARANTINE=true`` (either via
   ``verdicts._QUARANTINE_TRIGGER_BY_CODE`` or structurally via
   ``barrier_tier._refusal``'s ``Violation.quarantine_trigger``).
2. ``EXPLICIT_NO_QUARANTINE_CODES`` — explicitly reviewed ``Violation.code``
   values that must NOT trigger workload quarantine.

Enforced invariants (floor + ceiling + infrastructure isolation):
- Zero unresolvable dynamic ``Violation(..., code=...)`` expressions in ``src/``.
- ``QUARANTINE_CODES & EXPLICIT_NO_QUARANTINE_CODES == set()``.
- ``discovered_codes - (QUARANTINE_CODES | EXPLICIT_NO_QUARANTINE_CODES) == set()``
  (any newly added ``Violation`` code anywhere in ``src/`` fails CI until
  explicitly classified).
- ``(QUARANTINE_CODES | EXPLICIT_NO_QUARANTINE_CODES) - (discovered_codes | seam_reserved_codes) == set()``
  (retired codes cannot linger in the ledger).
- ``verdicts._QUARANTINE_TRIGGER_BY_CODE`` keys match ``QUARANTINE_CODES``
  (minus barrier-tier codes that set ``Violation.quarantine_trigger`` directly
  in ``barrier_tier._refusal``).
- Zero ``ViolationKind.INFRASTRUCTURE`` codes appear in ``QUARANTINE_CODES``.
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Violation codes that trigger out-of-band workload quarantine on HARD refusal.
QUARANTINE_CODES: frozenset[str] = frozenset(
    {
        "CBF_BARRIER_VIOLATED",
        "DOSE_BARRIER_VIOLATED",
        "FTRA_UNCONTAINABLE_TERMINAL",
        "KINEMATIC_BARRIER_VIOLATED",
        "RECONCILIATION_DISCREPANCY_FENCE",
        "RECONCILIATION_STATE_DRIFT",
        "SANDBOX_ESCAPE_ATTEMPT",
    }
)

#: Explicitly reviewed Violation codes across src/ that do NOT trigger quarantine.
EXPLICIT_NO_QUARANTINE_CODES: frozenset[str] = frozenset(
    {
        # Kernel governor, approval, pipeline, settlement, and stage infrastructure/policy codes
        "APPROVAL_CONTEXT_DRIFT",
        "APPROVAL_NOT_REDEEMABLE",
        "CBF_RECONCILIATION_UNAVAILABLE",
        "CONFIDENCE_BELOW_THRESHOLD",
        "CONFIDENCE_INVALID",
        "CONFIRM_FAILED",
        "CONSENSUS_NO_INFERENCE_BACKEND",
        "DEFER_QUEUE_UNAVAILABLE",
        "EXECUTION_LEDGER_UNAVAILABLE",
        "FTRA_ERROR",
        "FTRA_REGISTERED_EXTERNALLY_REVERSIBLE",
        "FTRA_REGISTERED_IRREVERSIBLE",
        "FTRA_REGISTRY_ENTRY_INVALID",
        "FTRA_REGISTRY_UNAVAILABLE",
        "FTRA_UNREGISTERED_ACTION",
        "OPA_DENY",
        "OPA_MANUAL_REVIEW",
        "OPA_UNAVAILABLE",
        "PREVIEW_UNAVAILABLE",
        "RELIANCE_INELIGIBLE_AUTHENTICITY",
        "RELIANCE_INELIGIBLE_EXPIRED",
        "RELIANCE_INELIGIBLE_MISSING",
        "RELIANCE_INELIGIBLE_OUT_OF_SCOPE",
        "RELIANCE_INELIGIBLE_REVOKED",
        "RELIANCE_INELIGIBLE_STALE",
        "RELIANCE_INELIGIBLE_SUSPENDED",
        "RELIANCE_INELIGIBLE_UNRESOLVED",
        "RELIANCE_INELIGIBLE_VERSION_MISMATCH",
        "ROLLBACK_FAILED",
        "SERVER_INPUT_UNAVAILABLE",
        "STPA_ERROR",
        "STPA_UCA_1",
        "STPA_UCA_7",
        "TIER_EXCEPTION",
        "UNGOVERNED_POST_HITL",
        # Jurisdiction FRIA codes
        "FRIA_ASSESSMENT_STALE",
        "FRIA_EXTERNAL_HOLD",
        "FRIA_MAGNITUDE_INVALID",
        "FRIA_PROVIDER_UNAVAILABLE",
        "FRIA_REJECTED",
        # Domain STPA, bounding, fiscal, causal, consensus, confidence, and server-input codes
        "B10_ROLLBACK_WINDOW_CLOSED",
        "BOUNDING_B10_HARD_BLOCK",
        "BOUNDING_B1_HARD_BLOCK",
        "BOUNDING_B2_HARD_BLOCK",
        "BOUNDING_B3_HARD_BLOCK",
        "BOUNDING_B3_HITL_ESCALATE",
        "BOUNDING_B4_HARD_BLOCK",
        "BOUNDING_B5_HARD_BLOCK",
        "BOUNDING_B5_HITL_ESCALATE",
        "BOUNDING_B6_HITL_ESCALATE",
        "BOUNDING_B7_HARD_BLOCK",
        "BOUNDING_B8_HARD_BLOCK",
        "BOUNDING_B8_HITL_ESCALATE",
        "BOUNDING_B9_HARD_BLOCK",
        "CAUSAL_CHECK_FAILED",
        "CAUSAL_INSUFFICIENT_SAMPLES",
        "CAUSAL_TELEMETRY_UNAVAILABLE",
        "CLINICAL_CONSENSUS_REJECTED",
        "CONSENSUS_ESCALATED",
        "CONSENSUS_REJECTED",
        "DOSE_BARRIER_UNCONFIGURED",
        "FISCAL_LIMIT_EXCEEDED",
        "FISCAL_STORE_UNAVAILABLE",
        "INVALID_REQUEST_PARAMS",
        "KINEMATIC_BARRIER_UNCONFIGURED",
        "MARKET_DATA_UNAVAILABLE",
        "NOTIONAL_THRESHOLD_ESCALATION",
        "PHYSICAL_SAFETY_CONSENSUS_REJECTED",
        "PORTFOLIO_NAV_UNAVAILABLE",
        "STPA_UCA_10",
        "STPA_UCA_12",
        "STPA_UCA_13",
        "STPA_UCA_2",
        "STPA_UCA_3",
        "STPA_UCA_4",
        "STPA_UCA_5",
        "STPA_UCA_6",
        "STPA_UCA_8",
        "STPA_UCA_9",
        "STPA_UCA_UCA_10",
        "STPA_UCA_UCA_12",
        "STPA_UCA_UCA_13",
        "STPA_UCA_UCA_2",
        "STPA_UCA_UCA_3",
        "STPA_UCA_UCA_4",
        "STPA_UCA_UCA_5",
        "STPA_UCA_UCA_6",
        "STPA_UCA_UCA_8",
        "STPA_UCA_UCA_9",
        "TRADER_IDENTITY_UNAVAILABLE",
        "TRADE_CONFIDENCE_BELOW_FLOOR",
        "TRADE_CONFIDENCE_INVALID",
    }
)


@dataclass(frozen=True)
class LedgerReport:
    """Structured result of AST discovery and partition verification."""

    discovered_codes: frozenset[str]
    discovered_infra_codes: frozenset[str]
    barrier_refusal_codes: frozenset[str]
    seam_reserved_codes: frozenset[str]
    verdicts_map_codes: frozenset[str]
    unresolved_sites: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def _iter_prod_py_files(repo_root: Path) -> list[Path]:
    src_root = repo_root / "src"
    if not src_root.is_dir():
        raise RuntimeError(f"missing src/ directory under {repo_root}")
    files: list[Path] = []
    for path in sorted(src_root.rglob("*.py")):
        rel = path.relative_to(repo_root).as_posix()
        if "__pycache__" in rel or "/tests/" in f"/{rel}":
            continue
        files.append(path)
    return files


def _uca_id_to_code(uca_id: str) -> str:
    norm = uca_id.strip().upper().replace("-", "_")
    if norm.startswith("STPA_UCA_"):
        return norm
    if norm.startswith("UCA_"):
        return f"STPA_{norm}"
    return f"STPA_UCA_{norm}"


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _extract_code_and_kind_args(
    call: ast.Call,
) -> tuple[ast.expr | None, ast.expr | None]:
    code_expr: ast.expr | None = None
    kind_expr: ast.expr | None = None
    if len(call.args) >= 2:
        code_expr = call.args[1]
    if len(call.args) >= 4:
        kind_expr = call.args[3]
    for kw in call.keywords:
        if kw.arg == "code":
            code_expr = kw.value
        elif kw.arg == "kind":
            kind_expr = kw.value
    return code_expr, kind_expr


def _expr_mentions_infra_kind(expr: ast.expr | None) -> bool:
    if expr is None:
        return False
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Attribute) and sub.attr == "INFRASTRUCTURE":
            return True
    return False


def discover_and_check_ledger(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    quarantine_codes: Set[str] = QUARANTINE_CODES,
    non_quarantine_codes: Set[str] = EXPLICIT_NO_QUARANTINE_CODES,
) -> LedgerReport:
    """Discover all Violation codes across ``src/**/*.py`` and verify partition invariants."""
    files = _iter_prod_py_files(repo_root)
    trees: dict[str, ast.Module] = {}
    module_consts: dict[str, dict[str, str]] = {}
    module_dict_first_str: dict[str, dict[str, set[str]]] = {}
    global_consts: dict[str, set[str]] = {}
    enum_members: dict[str, dict[str, str]] = {}

    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        trees[rel] = tree
        consts: dict[str, str] = {}
        dict_first: dict[str, set[str]] = {}

        for stmt in tree.body:
            target_name: str | None = None
            val_node: ast.expr | None = None
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                target_name = stmt.targets[0].id
                val_node = stmt.value
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.value is not None
            ):
                target_name = stmt.target.id
                val_node = stmt.value
            elif isinstance(stmt, ast.ClassDef):
                members: dict[str, str] = {}
                for item in stmt.body:
                    if (
                        isinstance(item, ast.Assign)
                        and len(item.targets) == 1
                        and isinstance(item.targets[0], ast.Name)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                    ):
                        members[item.targets[0].id] = item.value.value
                if members:
                    enum_members[stmt.name] = members

            if target_name is not None and val_node is not None:
                if isinstance(val_node, ast.Constant) and isinstance(
                    val_node.value, str
                ):
                    consts[target_name] = val_node.value
                    global_consts.setdefault(target_name, set()).add(val_node.value)
                elif isinstance(val_node, ast.Dict):
                    vals: set[str] = set()
                    for v in val_node.values:
                        if isinstance(v, ast.Tuple) and v.elts:
                            e0 = v.elts[0]
                            if isinstance(e0, ast.Constant) and isinstance(
                                e0.value, str
                            ):
                                vals.add(e0.value)
                            elif isinstance(e0, ast.Name) and e0.id in consts:
                                vals.add(consts[e0.id])
                    if vals:
                        dict_first[target_name] = vals

        module_consts[rel] = consts
        module_dict_first_str[rel] = dict_first

    # Discover verdicts._QUARANTINE_TRIGGER_BY_CODE and seam-reserved quarantine codes.
    verdicts_map_codes: set[str] = set()
    verdicts_rel = "src/gateway/governance/governor/verdicts.py"
    if verdicts_rel in trees:
        for stmt in trees[verdicts_rel].body:
            val_node = None
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "_QUARANTINE_TRIGGER_BY_CODE"
            ):
                val_node = stmt.value
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "_QUARANTINE_TRIGGER_BY_CODE"
            ):
                val_node = stmt.value
            if isinstance(val_node, ast.Dict):
                for k in val_node.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        verdicts_map_codes.add(k.value)

    seam_reserved_codes: set[str] = set()
    for member_name, member_val in enum_members.get(
        "QuarantineTriggerReason", {}
    ).items():
        if member_name != "CRITICAL_CBF_BREACH":
            seam_reserved_codes.add(member_val)
    stream_consts = module_consts.get("src/gateway/governance/evidence/stream.py", {})
    for cname, cval in stream_consts.items():
        if cval == "RECONCILIATION_DISCREPANCY_FENCE" or cname.endswith(
            "DISCREPANCY_FENCE_EVENT_TYPE"
        ):
            seam_reserved_codes.add(cval)
    if "src/gateway/governance/evidence/stream.py" in trees:
        for node in ast.walk(trees["src/gateway/governance/evidence/stream.py"]):
            if (
                isinstance(node, ast.Constant)
                and node.value == "RECONCILIATION_DISCREPANCY_FENCE"
            ):
                seam_reserved_codes.add("RECONCILIATION_DISCREPANCY_FENCE")

    # Pre-pass across all src/**/*.py for structured domain/kernel inputs into Violation.code:
    # - ServerInputUnavailableError(failure_code=...)
    # - UcaRule(uca_id=...)
    # - ContractResult(contract_id=..., severity=..., code=...)
    # - consensus reason_code entries in src/gateway/governance/consensus/
    server_input_codes: set[str] = set()
    uca_codes: set[str] = set()
    bounding_codes: set[str] = set()
    consensus_reason_codes: set[str] = set()

    for rel, tree in trees.items():
        consts = module_consts[rel]
        if rel == "src/gateway/governance/contracts.py":
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ClassDef)
                    and node.name == "ServerInputUnavailableError"
                ):
                    for item in node.body:
                        if (
                            isinstance(item, ast.FunctionDef)
                            and item.name == "__init__"
                        ):
                            for default in item.args.kw_defaults:
                                if (
                                    isinstance(default, ast.Constant)
                                    and isinstance(default.value, str)
                                    and default.value.endswith("_UNAVAILABLE")
                                ):
                                    server_input_codes.add(default.value)

        scopes: list[ast.AST] = [tree] + [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for scope in scopes:
            local_str = dict(consts)
            if scope is not tree:
                for sub in ast.walk(scope):
                    if (
                        isinstance(sub, ast.Assign)
                        and len(sub.targets) == 1
                        and isinstance(sub.targets[0], ast.Name)
                        and isinstance(sub.value, ast.Constant)
                        and isinstance(sub.value.value, str)
                    ):
                        local_str[sub.targets[0].id] = sub.value.value

            iter_nodes = (
                [
                    sub
                    for stmt in tree.body
                    if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                    for sub in ast.walk(stmt)
                ]
                if scope is tree
                else list(ast.walk(scope))
            )
            for node in iter_nodes:
                if isinstance(node, ast.Call):
                    cname = _call_name(node)
                    if cname == "ServerInputUnavailableError":
                        for kw in node.keywords:
                            if kw.arg == "failure_code":
                                if isinstance(kw.value, ast.Constant) and isinstance(
                                    kw.value.value, str
                                ):
                                    server_input_codes.add(kw.value.value)
                                elif (
                                    isinstance(kw.value, ast.Name)
                                    and kw.value.id in local_str
                                ):
                                    server_input_codes.add(local_str[kw.value.id])
                    elif cname == "UcaRule":
                        uid_node: ast.expr | None = node.args[0] if node.args else None
                        for kw in node.keywords:
                            if kw.arg == "uca_id":
                                uid_node = kw.value
                        if isinstance(uid_node, ast.Constant) and isinstance(
                            uid_node.value, str
                        ):
                            uca_codes.add(_uca_id_to_code(uid_node.value))
                        elif (
                            isinstance(uid_node, ast.Name) and uid_node.id in local_str
                        ):
                            uca_codes.add(_uca_id_to_code(local_str[uid_node.id]))
                    elif cname == "ContractResult":
                        kw_map = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                        adm = kw_map.get("admitted")
                        if isinstance(adm, ast.Constant) and adm.value is True:
                            continue
                        c_node = kw_map.get("code")
                        if isinstance(c_node, ast.Constant) and isinstance(
                            c_node.value, str
                        ):
                            bounding_codes.add(c_node.value)
                            continue
                        if isinstance(c_node, ast.Name) and c_node.id in local_str:
                            bounding_codes.add(local_str[c_node.id])
                            continue
                        cid_node = kw_map.get("contract_id")
                        sev_node = kw_map.get("severity")
                        cid = (
                            cid_node.value
                            if isinstance(cid_node, ast.Constant)
                            and isinstance(cid_node.value, str)
                            else (
                                local_str.get(cid_node.id)
                                if isinstance(cid_node, ast.Name)
                                else None
                            )
                        )
                        sev = (
                            enum_members.get(sev_node.value.id, {}).get(sev_node.attr)
                            if isinstance(sev_node, ast.Attribute)
                            and isinstance(sev_node.value, ast.Name)
                            else None
                        )
                        if cid and sev:
                            bounding_codes.add(f"BOUNDING_{cid}_{sev}")
                elif isinstance(node, ast.Dict) and rel.startswith(
                    "src/gateway/governance/consensus/"
                ):
                    for k, v in zip(node.keys, node.values, strict=True):
                        if isinstance(k, ast.Constant) and k.value == "reason_code":
                            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                                consensus_reason_codes.add(v.value)
                            elif isinstance(v, ast.Name) and v.id in local_str:
                                consensus_reason_codes.add(local_str[v.id])

    discovered_codes: set[str] = set()
    discovered_infra_codes: set[str] = set()
    barrier_refusal_codes: set[str] = set()
    unresolved_sites: list[str] = []

    def resolve_code_expr(
        expr: ast.expr | None,
        *,
        rel: str,
        local_env: Mapping[str, set[str]],
        allow_param_names: Set[str] = frozenset(),
    ) -> set[str] | None:
        if expr is None:
            return None
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return {expr.value}
        if isinstance(expr, ast.Name):
            if expr.id in local_env:
                return set(local_env[expr.id])
            if expr.id in module_consts.get(rel, {}):
                return {module_consts[rel][expr.id]}
            if expr.id in global_consts and len(global_consts[expr.id]) == 1:
                return set(global_consts[expr.id])
            if expr.id in allow_param_names:
                return set()
            return None
        if (
            isinstance(expr, ast.Attribute)
            and isinstance(expr.value, ast.Name)
            and expr.attr == "failure_code"
        ):
            return set(server_input_codes) if server_input_codes else None
        if isinstance(expr, ast.Call):
            cname = _call_name(expr)
            if cname == "consensus_violation_code" and len(expr.args) >= 2:
                default_resolved = resolve_code_expr(
                    expr.args[1], rel=rel, local_env=local_env
                )
                if default_resolved is None:
                    return None
                return default_resolved | consensus_reason_codes
            if cname in ("_normalize_uca_code", "_uca_violation_code"):
                return set(uca_codes) if uca_codes else None
            return None
        if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):
            # e.g. result.code or f"BOUNDING_{result.contract_id}_{result.severity.value}"
            unparsed = ast.unparse(expr)
            if "BOUNDING_" in unparsed and "contract_id" in unparsed:
                return set(bounding_codes) if bounding_codes else None
            out: set[str] = set()
            for val in expr.values:
                sub = resolve_code_expr(val, rel=rel, local_env=local_env)
                if sub is None:
                    return None
                out |= sub
            return out
        if isinstance(expr, ast.JoinedStr):
            prefixes: set[str] = {""}
            for part in expr.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    prefixes = {p + part.value for p in prefixes}
                elif isinstance(part, ast.FormattedValue):
                    sub_vals: set[str] | None = None
                    fval = part.value
                    if (
                        isinstance(fval, ast.Call)
                        and isinstance(fval.func, ast.Attribute)
                        and fval.func.attr == "upper"
                        and isinstance(fval.func.value, ast.Name)
                        and fval.func.value.id == "hook"
                    ):
                        sub_vals = {"ROLLBACK", "CONFIRM"}
                    elif isinstance(fval, ast.Name) and fval.id == "status":
                        reliance_vals = {
                            v
                            for k, v in enum_members.get("RelianceStatus", {}).items()
                            if k != "ELIGIBLE"
                        }
                        sub_vals = reliance_vals or None
                    else:
                        sub_vals = resolve_code_expr(fval, rel=rel, local_env=local_env)
                    if not sub_vals:
                        return None
                    prefixes = {p + sv for p in prefixes for sv in sub_vals}
                else:
                    return None
            return prefixes or None
        return None

    # First collect intra-module helper functions that wrap Violation(..., code=<param>)
    # so call sites of those helpers resolve exact codes.
    helper_param_index: dict[tuple[str, str], tuple[int, str, set[str], bool]] = {}
    for rel, tree in trees.items():
        consts = module_consts[rel]
        for fn in [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            # Skip methods whose parameter is populated via external protocol calls
            # handled explicitly (preview_barrier/commit_barrier -> _refusal, STPAValidator._v).
            if fn.name in ("_refusal", "_v"):
                continue
            non_self_args = [a for a in fn.args.args if a.arg != "self"]
            defaults_map: dict[str, set[str]] = {}
            if fn.args.defaults:
                for arg_node, def_node in zip(
                    fn.args.args[-len(fn.args.defaults) :],
                    fn.args.defaults,
                    strict=True,
                ):
                    if isinstance(def_node, ast.Constant) and isinstance(
                        def_node.value, str
                    ):
                        defaults_map[arg_node.arg] = {def_node.value}
                    elif isinstance(def_node, ast.Name) and def_node.id in consts:
                        defaults_map[arg_node.arg] = {consts[def_node.id]}
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Call) and _call_name(sub) == "Violation":
                    c_expr, k_expr = _extract_code_and_kind_args(sub)
                    if isinstance(c_expr, ast.Name):
                        for idx, a in enumerate(non_self_args):
                            if a.arg == c_expr.id:
                                helper_param_index[(rel, fn.name)] = (
                                    idx,
                                    a.arg,
                                    defaults_map.get(a.arg, set()),
                                    _expr_mentions_infra_kind(k_expr),
                                )

    # Walk every file & scope to resolve all Violation, barrier, and helper calls.
    for rel, tree in trees.items():
        consts = module_consts[rel]
        dict_first = module_dict_first_str[rel]

        # Module-level (outside functions) Violation constructions
        top_env: dict[str, set[str]] = {k: {v} for k, v in consts.items()}
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Skip ClassDef method bodies here (visited below per function)
            if isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    for sub in ast.walk(item):
                        if isinstance(sub, ast.Call) and _call_name(sub) == "Violation":
                            c_expr, k_expr = _extract_code_and_kind_args(sub)
                            resolved = resolve_code_expr(
                                c_expr, rel=rel, local_env=top_env
                            )
                            if not resolved:
                                unresolved_sites.append(f"{rel}:{sub.lineno}")
                            else:
                                discovered_codes |= resolved
                                if _expr_mentions_infra_kind(k_expr):
                                    discovered_infra_codes |= resolved
                continue
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call) and _call_name(sub) == "Violation":
                    c_expr, k_expr = _extract_code_and_kind_args(sub)
                    resolved = resolve_code_expr(c_expr, rel=rel, local_env=top_env)
                    if not resolved:
                        unresolved_sites.append(f"{rel}:{sub.lineno}")
                    else:
                        discovered_codes |= resolved
                        if _expr_mentions_infra_kind(k_expr):
                            discovered_infra_codes |= resolved

        # Function / method scopes
        for fn in [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            local_env: dict[str, set[str]] = {k: {v} for k, v in consts.items()}
            # Collect local variable assignments within fn
            for stmt in ast.walk(fn):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    tgt = stmt.targets[0]
                    if isinstance(tgt, ast.Name):
                        res = resolve_code_expr(
                            stmt.value, rel=rel, local_env=local_env
                        )
                        if res:
                            local_env.setdefault(tgt.id, set()).update(res)
                        elif (
                            isinstance(stmt.value, ast.Call)
                            and _call_name(stmt.value) == "get"
                        ):
                            # e.g. code = {...}.get(classification) in ftra/models.py
                            if isinstance(
                                stmt.value.func, ast.Attribute
                            ) and isinstance(stmt.value.func.value, ast.Dict):
                                dvals: set[str] = set()
                                for dv in stmt.value.func.value.values:
                                    r = resolve_code_expr(
                                        dv, rel=rel, local_env=local_env
                                    )
                                    if r:
                                        dvals |= r
                                if dvals:
                                    local_env.setdefault(tgt.id, set()).update(dvals)
                    elif isinstance(tgt, ast.Tuple) and len(tgt.elts) == 2:
                        # e.g. code, message = _REASON_CODES.get(decision.reason, (CODE_CHECK_FAILED, ...))
                        e0 = tgt.elts[0]
                        if (
                            isinstance(e0, ast.Name)
                            and isinstance(stmt.value, ast.Call)
                            and isinstance(stmt.value.func, ast.Attribute)
                            and stmt.value.func.attr == "get"
                            and isinstance(stmt.value.func.value, ast.Name)
                        ):
                            dname = stmt.value.func.value.id
                            vals = set(dict_first.get(dname, set()))
                            if (
                                len(stmt.value.args) >= 2
                                and isinstance(stmt.value.args[1], ast.Tuple)
                                and stmt.value.args[1].elts
                            ):
                                def_res = resolve_code_expr(
                                    stmt.value.args[1].elts[0],
                                    rel=rel,
                                    local_env=local_env,
                                )
                                if def_res:
                                    vals |= def_res
                            if vals:
                                local_env.setdefault(e0.id, set()).update(vals)

            helper_meta = helper_param_index.get((rel, fn.name))
            for sub in ast.walk(fn):
                if not isinstance(sub, ast.Call):
                    continue
                cname = _call_name(sub)
                if cname == "Violation":
                    if fn.name in ("_refusal", "_v"):
                        c_expr, k_expr = _extract_code_and_kind_args(sub)
                        if isinstance(c_expr, ast.Name) and c_expr.id == "code":
                            continue
                    if helper_meta is not None:
                        c_expr, _k_expr = _extract_code_and_kind_args(sub)
                        if isinstance(c_expr, ast.Name) and c_expr.id == helper_meta[1]:
                            continue
                    c_expr, k_expr = _extract_code_and_kind_args(sub)
                    resolved = resolve_code_expr(c_expr, rel=rel, local_env=local_env)
                    if not resolved:
                        unresolved_sites.append(f"{rel}:{sub.lineno}")
                    else:
                        discovered_codes |= resolved
                        if _expr_mentions_infra_kind(k_expr):
                            discovered_infra_codes |= resolved
                elif cname in ("preview_barrier", "commit_barrier"):
                    if rel == "src/gateway/governance/safety/barrier_tier.py":
                        continue
                    kw_map = {kw.arg: kw.value for kw in sub.keywords if kw.arg}
                    c_expr = kw_map.get("code")
                    resolved = resolve_code_expr(c_expr, rel=rel, local_env=local_env)
                    if not resolved:
                        unresolved_sites.append(f"{rel}:{sub.lineno}")
                    else:
                        discovered_codes |= resolved
                        barrier_refusal_codes |= resolved
                elif cname is not None and (rel, cname) in helper_param_index:
                    p_idx, p_name, p_defaults, p_infra = helper_param_index[
                        (rel, cname)
                    ]
                    arg_expr: ast.expr | None = (
                        sub.args[p_idx] if len(sub.args) > p_idx else None
                    )
                    for kw in sub.keywords:
                        if kw.arg == p_name:
                            arg_expr = kw.value
                    if arg_expr is None and p_defaults:
                        discovered_codes |= p_defaults
                        if p_infra:
                            discovered_infra_codes |= p_defaults
                    else:
                        resolved = resolve_code_expr(
                            arg_expr, rel=rel, local_env=local_env
                        )
                        if not resolved:
                            unresolved_sites.append(f"{rel}:{sub.lineno}")
                        else:
                            discovered_codes |= resolved
                            if p_infra:
                                discovered_infra_codes |= resolved

    errors: list[str] = []
    q_set = set(quarantine_codes)
    nq_set = set(non_quarantine_codes)
    all_ledger = q_set | nq_set

    if unresolved_sites:
        errors.append(
            "Unresolvable dynamic Violation code expression(s) in src/: "
            + ", ".join(sorted(set(unresolved_sites)))
        )

    overlap = q_set & nq_set
    if overlap:
        errors.append(
            "Codes present in BOTH QUARANTINE_CODES and EXPLICIT_NO_QUARANTINE_CODES: "
            + ", ".join(sorted(overlap))
        )

    unclassified = discovered_codes - all_ledger
    if unclassified:
        errors.append(
            "Unclassified Violation code(s) discovered in src/ (missing from ledger): "
            + ", ".join(sorted(unclassified))
        )

    valid_ceiling = discovered_codes | seam_reserved_codes
    stale = all_ledger - valid_ceiling
    if stale:
        errors.append(
            "Stale code(s) in ledger not found in src/ or quarantine seam: "
            + ", ".join(sorted(stale))
        )

    unregistered_verdicts = verdicts_map_codes - q_set
    if unregistered_verdicts:
        errors.append(
            "verdicts._QUARANTINE_TRIGGER_BY_CODE contains code(s) absent from QUARANTINE_CODES: "
            + ", ".join(sorted(unregistered_verdicts))
        )

    unbacked_quarantine = q_set - (verdicts_map_codes | barrier_refusal_codes)
    if unbacked_quarantine:
        errors.append(
            "QUARANTINE_CODES entry has neither verdicts._QUARANTINE_TRIGGER_BY_CODE "
            "mapping nor barrier_tier._refusal quarantine_trigger: "
            + ", ".join(sorted(unbacked_quarantine))
        )

    infra_in_quarantine = discovered_infra_codes & q_set
    if infra_in_quarantine:
        errors.append(
            "ViolationKind.INFRASTRUCTURE code(s) forbidden in QUARANTINE_CODES: "
            + ", ".join(sorted(infra_in_quarantine))
        )

    return LedgerReport(
        discovered_codes=frozenset(discovered_codes),
        discovered_infra_codes=frozenset(discovered_infra_codes),
        barrier_refusal_codes=frozenset(barrier_refusal_codes),
        seam_reserved_codes=frozenset(seam_reserved_codes),
        verdicts_map_codes=frozenset(verdicts_map_codes),
        unresolved_sites=tuple(sorted(set(unresolved_sites))),
        errors=tuple(errors),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify exhaustive Violation quarantine trigger partition across src/."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory (default: parent of scripts/).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print discovered counts and partition summary.",
    )
    args = parser.parse_args(argv)

    report = discover_and_check_ledger(args.repo_root.resolve())
    if args.verbose or not report.ok:
        print(
            f"Violation quarantine ledger scan: "
            f"discovered={len(report.discovered_codes)} "
            f"quarantine={len(QUARANTINE_CODES)} "
            f"non_quarantine={len(EXPLICIT_NO_QUARANTINE_CODES)} "
            f"infra={len(report.discovered_infra_codes)} "
            f"barrier_refusal={sorted(report.barrier_refusal_codes)}"
        )
    if not report.ok:
        for err in report.errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1
    print("OK: Violation quarantine trigger ledger is exhaustive and disjoint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
