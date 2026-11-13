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
"""Gate 11: Producer/Consumer Dictionary-Key & Event-Type AST Parity Check.

Pure-stdlib AST gate verifying that cross-module evidence-stream and
governance-envelope consumers never read event types or dictionary keys that
no producer in ``src/`` ever emits.

Enforced Contracts (Zero Baseline / Zero Waivers):
1. **Stream Event-Type Parity**: Every uppercase event-type string referenced by
   stream consumers (``proof/stream_invariants.py``,
   ``packages/cage-conformance/src/cage_conformance/stream_invariants.py``, and
   ``src/compliance_bridge/``) in ``event_type`` comparisons or ``*_EVENT_TYPES``
   constants must be emitted as ``"type"`` / ``"event_type"`` by at least one
   evidence producer in ``src/``.
2. **Per-Event & Nested-Receipt Payload Key Parity**: Inside each ``event_type``
   branch of ``check_stream()`` (and transitively across helper functions called
   with ``payload``), every string key read from ``payload`` must be emitted by
   a producer of that ``event_type``, and every string key read from nested
   ``receipt`` / ``receipt_map`` containers must be emitted on the event or on
   ``RefusalReceipt``. General stream consumers in ``src/compliance_bridge/``
   may only read payload keys emitted by at least one stream producer (or wire
   header keys emitted by ``EvidenceStreamSink``).
3. **GovernanceEnvelope Sub-Block Key Parity**: Client SDK envelope consumers
   (``packages/cage-client/src/cage_client/``) may
   only declare ``GovernanceEnvelope`` model fields emitted by
   ``GovernanceEnvelope.to_dict()`` and may only read keys on ``issuer``,
   ``subject``, ``governance_context``, and ``signature`` emitted by the
   corresponding producer ``.to_dict()`` methods in
   ``src/gateway/governance/governance_envelope.py``.
4. **Non-Vacuous Corpus Floors**: Fails closed if AST extraction discovers fewer
   than the minimum expected number of produced event types, consumer files, or
   verified key reads.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]

# Non-vacuous floors when scanning the repository corpus.
MIN_PRODUCED_EVENT_TYPES = 12
MIN_STREAM_CONSUMER_FILES = 3
# envelope.py and core.py in packages/cage-client/, the SDK's only source tree
# since the src/gateway/client/ mirror was retired.
MIN_ENVELOPE_CONSUMER_FILES = 2
MIN_VERIFIED_KEY_READS = 40

EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")

# Wire-level Redis Stream / cage-audit/3.0 record header keys populated by
# EvidenceStreamSink (src/gateway/governance/evidence/stream.py).
WIRE_RECORD_HEADER_KEYS: frozenset[str] = frozenset(
    {
        "schema",
        "schema_version",
        "canonicalization",
        "hash_algorithm",
        "chain_id",
        "trace_id",
        "sequence",
        "prev_hash",
        "record_hash",
        "event_type",
        "control_id",
        "controlId",
        "payload_json",
        "payload",
        "narrowing_applied",
        "classification_reason",
        "pause_token",
        "timestamp_utc",
        "timestamp",
        "stream_id",
    }
)


@dataclass(frozen=True)
class ViolationRecord:
    """A single producer/consumer contract mismatch."""

    file: str
    line: int
    kind: str
    detail: str

    def format(self) -> str:
        return f"{self.file}:{self.line}: [{self.kind}] {self.detail}"


@dataclass
class ModuleIndex:
    """Parsed AST and top-level symbol table for one Python module."""

    path: Path
    rel_path: str
    module_name: str
    tree: ast.Module
    str_consts: dict[str, str] = field(default_factory=dict)
    str_sets: dict[str, set[str]] = field(default_factory=dict)
    dict_const_keys: dict[str, set[str]] = field(default_factory=dict)
    dict_const_str_values: dict[str, set[str]] = field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(
        default_factory=dict
    )
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)


@dataclass
class ProducerCatalog:
    """All producer schemas extracted from ``src/`` AST."""

    event_keys: dict[str, set[str]] = field(default_factory=dict)
    event_nested_keys: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    dataclass_fields: dict[str, set[str]] = field(default_factory=dict)
    to_dict_keys: dict[str, set[str]] = field(default_factory=dict)

    @property
    def all_stream_payload_keys(self) -> set[str]:
        out: set[str] = set()
        for keys in self.event_keys.values():
            out.update(keys)
        return out


def _module_name_for_path(repo_root: Path, path: Path) -> str:
    rel = path.relative_to(repo_root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _extract_literal_strings(node: ast.AST) -> set[str]:
    """Extract string constants from literals, tuples, lists, sets, frozensets, or Literal[...]."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out: set[str] = set()
        for elt in node.elts:
            out.update(_extract_literal_strings(elt))
        return out
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("frozenset", "set", "tuple", "list")
        and len(node.args) == 1
    ):
        return _extract_literal_strings(node.args[0])
    if isinstance(node, ast.Subscript):
        if (isinstance(node.value, ast.Name) and node.value.id == "Literal") or (
            isinstance(node.value, ast.Attribute) and node.value.attr == "Literal"
        ):
            return _extract_literal_strings(node.slice)
    if isinstance(node, ast.IfExp):
        return _extract_literal_strings(node.body) | _extract_literal_strings(
            node.orelse
        )
    return set()


def _record_import_from(stmt: ast.ImportFrom, idx: ModuleIndex, path: Path) -> None:
    if not stmt.module:
        return
    base_mod = stmt.module
    if stmt.level > 0:
        pkg_parts = idx.module_name.split(".")
        if path.name != "__init__.py":
            pkg_parts = pkg_parts[:-1]
        up = max(0, len(pkg_parts) - (stmt.level - 1))
        prefix = ".".join(pkg_parts[:up])
        base_mod = f"{prefix}.{stmt.module}" if prefix else stmt.module
    for alias in stmt.names:
        if alias.name == "*":
            continue
        local = alias.asname or alias.name
        idx.imports.setdefault(local, (base_mod, alias.name))


def _build_module_index(
    repo_root: Path, roots: Iterable[Path]
) -> dict[str, ModuleIndex]:
    modules: dict[str, ModuleIndex] = {}
    for root in roots:
        if not root.exists():
            continue
        paths = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for path in paths:
            if "__pycache__" in path.parts:
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError):
                continue
            rel_path = path.relative_to(repo_root).as_posix()
            mod_name = _module_name_for_path(repo_root, path)
            idx = ModuleIndex(
                path=path, rel_path=rel_path, module_name=mod_name, tree=tree
            )
            # Record top-level imports first, then function-scoped lazy imports
            for stmt in tree.body:
                if isinstance(stmt, ast.ImportFrom):
                    _record_import_from(stmt, idx, path)
                elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    )
                    value = stmt.value
                    if value is None:
                        continue
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                    if not names:
                        continue
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        for n in names:
                            idx.str_consts[n] = value.value
                    else:
                        lits = _extract_literal_strings(value)
                        if lits:
                            for n in names:
                                idx.str_sets[n] = lits
                    if isinstance(value, ast.Dict):
                        d_keys: set[str] = set()
                        d_vals: set[str] = set()
                        for k, v in zip(value.keys, value.values, strict=False):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                d_keys.add(k.value)
                            if v is not None:
                                d_vals.update(_extract_literal_strings(v))
                        for n in names:
                            if d_keys:
                                idx.dict_const_keys[n] = d_keys
                            if d_vals:
                                idx.dict_const_str_values[n] = d_vals
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    idx.functions[stmt.name] = stmt
                elif isinstance(stmt, ast.ClassDef):
                    idx.classes[stmt.name] = stmt
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    _record_import_from(node, idx, path)
            modules[mod_name] = idx
    return modules


def _resolve_str_symbol(
    mod: ModuleIndex,
    name: str,
    modules: dict[str, ModuleIndex],
    seen: set[tuple[str, str]] | None = None,
) -> set[str]:
    visited = seen if seen is not None else set()
    key = (mod.module_name, name)
    if key in visited:
        return set()
    visited.add(key)
    if name in mod.str_consts:
        return {mod.str_consts[name]}
    if name in mod.str_sets:
        return set(mod.str_sets[name])
    if name in mod.dict_const_str_values:
        return set(mod.dict_const_str_values[name])
    if name in mod.imports:
        target_mod_name, orig_name = mod.imports[name]
        target_mod = modules.get(target_mod_name)
        if target_mod is not None:
            return _resolve_str_symbol(target_mod, orig_name, modules, visited)
    return set()


def _resolve_dict_const_keys(
    mod: ModuleIndex,
    name: str,
    modules: dict[str, ModuleIndex],
    seen: set[tuple[str, str]] | None = None,
) -> set[str]:
    visited = seen if seen is not None else set()
    key = (mod.module_name, name)
    if key in visited:
        return set()
    visited.add(key)
    if name in mod.dict_const_keys:
        return set(mod.dict_const_keys[name])
    if name in mod.imports:
        target_mod_name, orig_name = mod.imports[name]
        target_mod = modules.get(target_mod_name)
        if target_mod is not None:
            return _resolve_dict_const_keys(target_mod, orig_name, modules, visited)
    return set()


def _resolve_expr_strings(
    expr: ast.AST,
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    local_vars: dict[str, set[str]] | None = None,
) -> set[str]:
    lits = _extract_literal_strings(expr)
    if lits:
        return lits
    if isinstance(expr, ast.Name):
        if local_vars and expr.id in local_vars:
            return set(local_vars[expr.id])
        return _resolve_str_symbol(mod, expr.id, modules)
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name):
        return _resolve_str_symbol(mod, expr.value.id, modules)
    if isinstance(expr, ast.IfExp):
        return _resolve_expr_strings(
            expr.body, mod, modules, local_vars
        ) | _resolve_expr_strings(expr.orelse, mod, modules, local_vars)
    return set()


def _extract_dict_keys_from_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
    depth: int = 0,
) -> set[str]:
    """Extract string keys returned as dicts by helper functions/methods."""
    if depth > 3:
        return set()
    keys: set[str] = set()
    local_dict_keys: dict[str, set[str]] = {}

    for node in ast.walk(fn):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            val = node.value
            if isinstance(target, ast.Name) and isinstance(val, ast.Dict):
                local_dict_keys.setdefault(target.id, set()).update(
                    _extract_dict_node_keys(
                        val, mod, modules, catalog, local_dict_keys, depth
                    )
                )
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id in local_dict_keys
            ):
                local_dict_keys[target.value.id].update(
                    _resolve_expr_strings(target.slice, mod, modules)
                )

    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Dict):
                keys.update(
                    _extract_dict_node_keys(
                        node.value, mod, modules, catalog, local_dict_keys, depth
                    )
                )
            elif isinstance(node.value, ast.Name) and node.value.id in local_dict_keys:
                keys.update(local_dict_keys[node.value.id])
    return keys


def _resolve_called_function(
    call: ast.Call,
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
) -> tuple[ModuleIndex, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if isinstance(call.func, ast.Name):
        fn_name = call.func.id
        if fn_name in mod.functions:
            return (mod, mod.functions[fn_name])
        if fn_name in mod.imports:
            t_mod_name, orig = mod.imports[fn_name]
            t_mod = modules.get(t_mod_name)
            if t_mod and orig in t_mod.functions:
                return (t_mod, t_mod.functions[orig])
    elif isinstance(call.func, ast.Attribute):
        method_name = call.func.attr
        for cand_mod in modules.values():
            for cls in cand_mod.classes.values():
                for item in cls.body:
                    if (
                        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name == method_name
                    ):
                        return (cand_mod, item)
    return None


def _extract_dict_node_keys(
    dict_node: ast.Dict,
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
    local_dict_keys: dict[str, set[str]] | None = None,
    depth: int = 0,
) -> set[str]:
    keys: set[str] = set()
    for k, v in zip(dict_node.keys, dict_node.values, strict=False):
        if k is not None:
            keys.update(_resolve_expr_strings(k, mod, modules))
        elif v is not None:
            if isinstance(v, ast.Name):
                if local_dict_keys and v.id in local_dict_keys:
                    keys.update(local_dict_keys[v.id])
                else:
                    keys.update(_resolve_dict_const_keys(mod, v.id, modules))
            elif isinstance(v, ast.Call):
                resolved = _resolve_called_function(v, mod, modules)
                if resolved is not None:
                    t_mod, t_fn = resolved
                    keys.update(
                        _extract_dict_keys_from_function(
                            t_fn, t_mod, modules, catalog, depth + 1
                        )
                    )
    return keys


def _extract_dataclass_and_to_dict_catalog(
    modules: dict[str, ModuleIndex], catalog: ProducerCatalog
) -> None:
    for mod in modules.values():
        if not mod.rel_path.startswith("src/"):
            continue
        for cls_name, cls_node in mod.classes.items():
            fields_set: set[str] = set()
            for item in cls_node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    if (
                        not item.target.id.startswith("_")
                        and item.target.id != "model_config"
                    ):
                        fields_set.add(item.target.id)
            if fields_set:
                catalog.dataclass_fields.setdefault(cls_name, set()).update(fields_set)
            for item in cls_node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == "to_dict"
                ):
                    td_keys = _extract_dict_keys_from_function(
                        item, mod, modules, catalog
                    )
                    if td_keys:
                        catalog.to_dict_keys.setdefault(cls_name, set()).update(td_keys)


def _scan_function_for_events(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
) -> None:
    local_str_vars: dict[str, set[str]] = {}
    local_dict_keys: dict[str, set[str]] = {}
    local_dict_types: dict[str, set[str]] = {}

    for stmt in ast.walk(fn):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            target = stmt.targets[0] if isinstance(stmt, ast.Assign) else stmt.target
            val = stmt.value
            if val is None:
                continue
            if isinstance(target, ast.Name):
                var_name = target.id
                strs = _resolve_expr_strings(val, mod, modules, local_str_vars)
                if strs:
                    local_str_vars.setdefault(var_name, set()).update(strs)
                if isinstance(val, ast.Dict):
                    d_keys = _extract_dict_node_keys(
                        val, mod, modules, catalog, local_dict_keys
                    )
                    local_dict_keys.setdefault(var_name, set()).update(d_keys)
                    for k, v in zip(val.keys, val.values, strict=False):
                        if (
                            isinstance(k, ast.Constant)
                            and k.value in ("type", "event_type")
                            and v is not None
                        ):
                            ev_types = _resolve_expr_strings(
                                v, mod, modules, local_str_vars
                            )
                            ev_types = {e for e in ev_types if EVENT_TYPE_RE.match(e)}
                            if ev_types:
                                local_dict_types.setdefault(var_name, set()).update(
                                    ev_types
                                )
                elif isinstance(val, ast.Call):
                    if (
                        isinstance(val.func, ast.Name)
                        and val.func.id == "_serialize_receipt"
                    ):
                        local_dict_keys.setdefault(var_name, set()).update(
                            catalog.dataclass_fields.get("RefusalReceipt", set())
                        )
                    else:
                        resolved = _resolve_called_function(val, mod, modules)
                        if resolved is not None:
                            t_mod, t_fn = resolved
                            local_dict_keys.setdefault(var_name, set()).update(
                                _extract_dict_keys_from_function(
                                    t_fn, t_mod, modules, catalog
                                )
                            )
                    if var_name == "decision_evidence":
                        sealing_mod = modules.get(
                            "src.gateway.governance.governor.sealing"
                        )
                        if (
                            sealing_mod
                            and "_build_decision_context" in sealing_mod.functions
                        ):
                            local_dict_keys.setdefault(var_name, set()).update(
                                _extract_dict_keys_from_function(
                                    sealing_mod.functions["_build_decision_context"],
                                    sealing_mod,
                                    modules,
                                    catalog,
                                )
                            )
            elif isinstance(target, ast.Subscript) and isinstance(
                target.value, ast.Name
            ):
                var_name = target.value.id
                assigned_keys = _resolve_expr_strings(
                    target.slice, mod, modules, local_str_vars
                )
                if assigned_keys:
                    local_dict_keys.setdefault(var_name, set()).update(assigned_keys)
                if any(k in ("type", "event_type") for k in assigned_keys):
                    ev_types = _resolve_expr_strings(val, mod, modules, local_str_vars)
                    ev_types = {e for e in ev_types if EVENT_TYPE_RE.match(e)}
                    if ev_types:
                        local_dict_types.setdefault(var_name, set()).update(ev_types)

    for var_name, ev_types in local_dict_types.items():
        d_keys = local_dict_keys.get(var_name, set())
        for et in ev_types:
            catalog.event_keys.setdefault(et, set()).update(d_keys)
            if et == "GOVERNANCE_REFUSAL" and "receipt" in d_keys:
                catalog.event_nested_keys.setdefault(
                    ("GOVERNANCE_REFUSAL", "receipt"), set()
                ).update(catalog.dataclass_fields.get("RefusalReceipt", set()))

    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            ev_types_inline: set[str] = set()
            for k, v in zip(node.keys, node.values, strict=False):
                if (
                    isinstance(k, ast.Constant)
                    and k.value in ("type", "event_type")
                    and v is not None
                ):
                    cand = _resolve_expr_strings(v, mod, modules, local_str_vars)
                    ev_types_inline.update(e for e in cand if EVENT_TYPE_RE.match(e))
            if ev_types_inline:
                d_keys = _extract_dict_node_keys(
                    node, mod, modules, catalog, local_dict_keys
                )
                for et in ev_types_inline:
                    catalog.event_keys.setdefault(et, set()).update(d_keys)
                    if et == "GOVERNANCE_REFUSAL" and "receipt" in d_keys:
                        catalog.event_nested_keys.setdefault(
                            ("GOVERNANCE_REFUSAL", "receipt"), set()
                        ).update(catalog.dataclass_fields.get("RefusalReceipt", set()))
        elif isinstance(node, ast.Call):
            call_ev_types: set[str] = set()
            call_payload_exprs: list[ast.expr] = []
            if node.args:
                call_payload_exprs.append(node.args[0])
            for kw in node.keywords:
                if kw.arg == "event_type":
                    cand = _resolve_expr_strings(kw.value, mod, modules, local_str_vars)
                    call_ev_types.update(e for e in cand if EVENT_TYPE_RE.match(e))
                elif kw.arg in ("payload", "record", "event"):
                    call_payload_exprs.append(kw.value)
            if call_ev_types:
                call_keys: set[str] = set()
                for p_expr in call_payload_exprs:
                    if isinstance(p_expr, ast.Dict):
                        call_keys.update(
                            _extract_dict_node_keys(
                                p_expr, mod, modules, catalog, local_dict_keys
                            )
                        )
                    elif isinstance(p_expr, ast.Name) and p_expr.id in local_dict_keys:
                        call_keys.update(local_dict_keys[p_expr.id])
                for et in call_ev_types:
                    catalog.event_keys.setdefault(et, set()).update(call_keys)


def collect_producers(
    repo_root: Path, modules: dict[str, ModuleIndex]
) -> ProducerCatalog:
    """Build the full ``ProducerCatalog`` from ``src/`` AST."""
    _ = repo_root
    catalog = ProducerCatalog()
    _extract_dataclass_and_to_dict_catalog(modules, catalog)

    for mod in modules.values():
        if not mod.rel_path.startswith("src/"):
            continue
        for cls in mod.classes.values():
            cls_fields: set[str] = set()
            cls_ev_types: set[str] = set()
            for item in cls.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    cls_fields.add(item.target.id)
                    if item.target.id == "event_type":
                        lits = _extract_literal_strings(item.annotation)
                        cls_ev_types.update(e for e in lits if EVENT_TYPE_RE.match(e))
            for et in cls_ev_types:
                catalog.event_keys.setdefault(et, set()).update(cls_fields)

        for fn in mod.functions.values():
            _scan_function_for_events(fn, mod, modules, catalog)
        for cls in mod.classes.values():
            for item in cls.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _scan_function_for_events(item, mod, modules, catalog)

    # Index INFRA stream producer keys from InfraEvent + InfraEvidenceChain.append_durable
    cb_main = modules.get("src.compliance_bridge.main")
    infra_mod = modules.get("src.compliance_bridge.infra_custody")
    if (
        cb_main is not None
        and infra_mod is not None
        and "InfraEvent" in cb_main.classes
        and "InfraEvidenceChain" in infra_mod.classes
    ):
        infra_ev_types: set[str] = set()
        for item in cb_main.classes["InfraEvent"].body:
            if (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id == "event_type"
            ):
                infra_ev_types.update(_extract_literal_strings(item.annotation))
        infra_keys: set[str] = set()
        for item in infra_mod.classes["InfraEvidenceChain"].body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "append_durable"
            ):
                for stmt in ast.walk(item):
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                        tgt = (
                            stmt.targets[0]
                            if isinstance(stmt, ast.Assign)
                            else stmt.target
                        )
                        val = stmt.value
                        if (
                            isinstance(tgt, ast.Name)
                            and tgt.id == "payload_dict"
                            and isinstance(val, ast.Dict)
                        ):
                            infra_keys.update(
                                _extract_dict_node_keys(
                                    val, infra_mod, modules, catalog
                                )
                            )
                        elif (
                            isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == "payload_dict"
                        ):
                            infra_keys.update(
                                _resolve_expr_strings(tgt.slice, infra_mod, modules)
                            )
        if infra_ev_types and infra_keys:
            for et in infra_ev_types:
                catalog.event_keys.setdefault(et, set()).update(infra_keys)

    return catalog


def _extract_condition_event_types(
    test: ast.expr, mod: ModuleIndex, modules: dict[str, ModuleIndex]
) -> set[str]:
    """Extract event_type string(s) guarded by ``if event_type == ...`` or ``if event_type in ...``."""
    out: set[str] = set()
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and len(test.comparators) == 1
    ):
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if isinstance(left, ast.Name) and left.id == "event_type":
            if isinstance(op, (ast.Eq, ast.In)):
                out.update(_resolve_expr_strings(right, mod, modules))
    elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        for val in test.values:
            out.update(_extract_condition_event_types(val, mod, modules))
    return {e for e in out if EVENT_TYPE_RE.match(e)}


def _collect_dict_reads_in_nodes(
    stmts: list[ast.stmt],
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    *,
    payload_names: set[str],
    receipt_names: set[str],
    visited_helpers: set[str],
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], int]:
    """Collect ``(lineno, key)`` reads on ``payload_names`` and ``receipt_names``."""
    payload_reads: list[tuple[int, str]] = []
    receipt_reads: list[tuple[int, str]] = []
    verified_count = 0

    local_loop_vars: dict[str, set[str]] = {}
    local_payload_aliases = set(payload_names)
    local_receipt_aliases = set(receipt_names)
    local_both_aliases: set[str] = set()

    def walk_block(block: list[ast.stmt]) -> None:
        nonlocal verified_count
        for stmt in block:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                tgt = stmt.targets[0]
                if isinstance(tgt, ast.Name):
                    if (
                        isinstance(stmt.value, ast.Call)
                        and isinstance(stmt.value.func, ast.Attribute)
                        and stmt.value.func.attr == "get"
                        and isinstance(stmt.value.func.value, ast.Name)
                        and stmt.value.func.value.id in local_payload_aliases
                        and stmt.value.args
                        and isinstance(stmt.value.args[0], ast.Constant)
                        and stmt.value.args[0].value == "receipt"
                    ):
                        local_receipt_aliases.add(tgt.id)
                    elif isinstance(stmt.value, ast.IfExp):
                        if (
                            isinstance(stmt.value.body, ast.Name)
                            and stmt.value.body.id in local_receipt_aliases
                        ):
                            local_receipt_aliases.add(tgt.id)
            if isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
                loop_var = stmt.target.id
                iter_strs = _resolve_expr_strings(stmt.iter, mod, modules)
                if iter_strs:
                    prev = local_loop_vars.get(loop_var)
                    local_loop_vars[loop_var] = iter_strs
                    walk_block(stmt.body)
                    if prev is None:
                        local_loop_vars.pop(loop_var, None)
                    else:
                        local_loop_vars[loop_var] = prev
                    continue
                if isinstance(stmt.iter, (ast.Tuple, ast.List)):
                    elt_names = {
                        e.id for e in stmt.iter.elts if isinstance(e, ast.Name)
                    }
                    if elt_names and elt_names <= (
                        local_payload_aliases | local_receipt_aliases
                    ):
                        local_both_aliases.add(loop_var)
                        walk_block(stmt.body)
                        local_both_aliases.discard(loop_var)
                        continue

            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "get"
                        and isinstance(node.func.value, ast.Name)
                        and node.args
                    ):
                        obj_name = node.func.value.id
                        read_keys = _resolve_expr_strings(
                            node.args[0], mod, modules, local_loop_vars
                        )
                        if read_keys:
                            if obj_name in local_payload_aliases:
                                for rk in sorted(read_keys):
                                    payload_reads.append((node.lineno, rk))
                                    verified_count += 1
                            elif obj_name in local_receipt_aliases:
                                for rk in sorted(read_keys):
                                    receipt_reads.append((node.lineno, rk))
                                    verified_count += 1
                            elif obj_name in local_both_aliases:
                                for rk in sorted(read_keys):
                                    payload_reads.append((node.lineno, rk))
                                    receipt_reads.append((node.lineno, rk))
                                    verified_count += 1
                    elif (
                        isinstance(node.func, ast.Name)
                        and node.func.id in mod.functions
                    ):
                        helper_name = node.func.id
                        helper_fn = mod.functions[helper_name]
                        if (
                            len(node.args) >= 2
                            and isinstance(node.args[0], ast.Name)
                            and node.args[0].id in local_payload_aliases
                        ):
                            second_keys = _resolve_expr_strings(
                                node.args[1], mod, modules, local_loop_vars
                            )
                            if second_keys and len(helper_fn.args.args) >= 2:
                                param2 = helper_fn.args.args[1].arg
                                if param2 in ("key", "field", "field_name"):
                                    for rk in sorted(second_keys):
                                        payload_reads.append((node.lineno, rk))
                                        verified_count += 1
                        if helper_name not in visited_helpers:
                            passed_payload_params: set[str] = set()
                            for pos, arg_expr in enumerate(node.args):
                                if (
                                    isinstance(arg_expr, ast.Name)
                                    and arg_expr.id in local_payload_aliases
                                    and pos < len(helper_fn.args.args)
                                ):
                                    passed_payload_params.add(
                                        helper_fn.args.args[pos].arg
                                    )
                            for kw in node.keywords:
                                if (
                                    kw.arg
                                    and isinstance(kw.value, ast.Name)
                                    and kw.value.id in local_payload_aliases
                                ):
                                    passed_payload_params.add(kw.arg)
                            if passed_payload_params:
                                visited_helpers.add(helper_name)
                                hp, hr, hc = _collect_dict_reads_in_nodes(
                                    helper_fn.body,
                                    mod,
                                    modules,
                                    payload_names=passed_payload_params,
                                    receipt_names=set(),
                                    visited_helpers=visited_helpers,
                                )
                                payload_reads.extend(hp)
                                receipt_reads.extend(hr)
                                verified_count += hc
                elif isinstance(node, ast.Subscript) and isinstance(
                    node.value, ast.Name
                ):
                    if isinstance(getattr(node, "ctx", None), ast.Load):
                        obj_name = node.value.id
                        read_keys = _resolve_expr_strings(
                            node.slice, mod, modules, local_loop_vars
                        )
                        if read_keys:
                            if obj_name in local_payload_aliases:
                                for rk in sorted(read_keys):
                                    payload_reads.append((node.lineno, rk))
                                    verified_count += 1
                            elif obj_name in local_receipt_aliases:
                                for rk in sorted(read_keys):
                                    receipt_reads.append((node.lineno, rk))
                                    verified_count += 1

    walk_block(stmts)
    return payload_reads, receipt_reads, verified_count


def check_stream_invariants_file(
    mod: ModuleIndex,
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
) -> tuple[list[ViolationRecord], int]:
    """Verify ``proof/stream_invariants.py`` (and conformance copy) against producers."""
    violations: list[ViolationRecord] = []
    verified_reads = 0

    for const_name, values in mod.str_sets.items():
        if const_name.endswith("EVENT_TYPES"):
            for ev in sorted(values):
                if EVENT_TYPE_RE.match(ev) and ev not in catalog.event_keys:
                    line = 1
                    for stmt in mod.tree.body:
                        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                            tgts = (
                                stmt.targets
                                if isinstance(stmt, ast.Assign)
                                else [stmt.target]
                            )
                            if any(
                                isinstance(t, ast.Name) and t.id == const_name
                                for t in tgts
                            ):
                                line = stmt.lineno
                                break
                    violations.append(
                        ViolationRecord(
                            file=mod.rel_path,
                            line=line,
                            kind="unproduced-event-type",
                            detail=(
                                f"{const_name} references event_type {ev!r}, "
                                "which is not emitted by any producer in src/"
                            ),
                        )
                    )

    check_fn = mod.functions.get("check_stream")
    if check_fn is None:
        return violations, verified_reads

    def walk_if_chain(if_node: ast.If) -> None:
        nonlocal verified_reads
        ev_types = _extract_condition_event_types(if_node.test, mod, modules)
        if ev_types:
            unknown_evs = sorted(ev for ev in ev_types if ev not in catalog.event_keys)
            for uev in unknown_evs:
                violations.append(
                    ViolationRecord(
                        file=mod.rel_path,
                        line=if_node.lineno,
                        kind="unproduced-event-type",
                        detail=(
                            f"check_stream() branches on event_type {uev!r}, "
                            "which is not emitted by any producer in src/"
                        ),
                    )
                )
            known_evs = [ev for ev in ev_types if ev in catalog.event_keys]
            if known_evs:
                allowed_payload_keys: set[str] = set()
                allowed_receipt_keys: set[str] = set()
                for kev in known_evs:
                    allowed_payload_keys.update(catalog.event_keys.get(kev, set()))
                    allowed_receipt_keys.update(
                        catalog.event_nested_keys.get((kev, "receipt"), set())
                    )
                if "GOVERNANCE_REFUSAL_RECEIPT" in known_evs:
                    allowed_receipt_keys.update(allowed_payload_keys)

                p_reads, r_reads, v_cnt = _collect_dict_reads_in_nodes(
                    if_node.body,
                    mod,
                    modules,
                    payload_names={"payload"},
                    receipt_names=set(),
                    visited_helpers=set(),
                )
                verified_reads += v_cnt
                for lineno, rk in p_reads:
                    if rk not in allowed_payload_keys:
                        violations.append(
                            ViolationRecord(
                                file=mod.rel_path,
                                line=lineno,
                                kind="unproduced-payload-key",
                                detail=(
                                    f"Consumer for {sorted(known_evs)} reads payload key {rk!r}, "
                                    f"not emitted by producer(s) (emitted: {sorted(allowed_payload_keys)})"
                                ),
                            )
                        )
                for lineno, rk in r_reads:
                    if rk not in (allowed_receipt_keys | allowed_payload_keys):
                        violations.append(
                            ViolationRecord(
                                file=mod.rel_path,
                                line=lineno,
                                kind="unproduced-receipt-key",
                                detail=(
                                    f"Consumer for {sorted(known_evs)} reads receipt key {rk!r}, "
                                    f"not emitted on RefusalReceipt or payload "
                                    f"(emitted: {sorted(allowed_receipt_keys | allowed_payload_keys)})"
                                ),
                            )
                        )

        for orelse_stmt in if_node.orelse:
            if isinstance(orelse_stmt, ast.If):
                walk_if_chain(orelse_stmt)

    for node in ast.walk(check_fn):
        if isinstance(node, ast.For):
            for body_stmt in node.body:
                if isinstance(body_stmt, ast.If):
                    walk_if_chain(body_stmt)

    return violations, verified_reads


def check_compliance_bridge_consumers(
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
) -> tuple[list[ViolationRecord], int, int]:
    """Check ``src/compliance_bridge/`` modules that consume ``cage:evidence:stream``."""
    violations: list[ViolationRecord] = []
    checked_files = 0
    verified_reads = 0
    allowed_any_payload = catalog.all_stream_payload_keys | WIRE_RECORD_HEADER_KEYS

    for mod in sorted(modules.values(), key=lambda m: m.rel_path):
        if not mod.rel_path.startswith("src/compliance_bridge/"):
            continue
        checked_files += 1
        consumes_evidence_stream = any(
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and (
                "cage:evidence:stream" in n.value
                or "EVIDENCE_STREAM" in n.value
                or "evidence_stream" in n.value
            )
            for n in ast.walk(mod.tree)
        )
        for const_name, values in mod.str_sets.items():
            if const_name.endswith("EVIDENCE_EVENT_TYPES") or (
                consumes_evidence_stream and const_name.endswith("EVENT_TYPES")
            ):
                for ev in sorted(values):
                    if EVENT_TYPE_RE.match(ev) and ev not in catalog.event_keys:
                        line = 1
                        for stmt in mod.tree.body:
                            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                                tgts = (
                                    stmt.targets
                                    if isinstance(stmt, ast.Assign)
                                    else [stmt.target]
                                )
                                if any(
                                    isinstance(t, ast.Name) and t.id == const_name
                                    for t in tgts
                                ):
                                    line = stmt.lineno
                                    break
                        violations.append(
                            ViolationRecord(
                                file=mod.rel_path,
                                line=line,
                                kind="unproduced-event-type",
                                detail=(
                                    f"{const_name} references event_type {ev!r}, "
                                    "which is not emitted by any producer in src/"
                                ),
                            )
                        )

        for fn in mod.functions.values():
            param_names = {a.arg for a in fn.args.args}
            uses_stream_payload = (
                consumes_evidence_stream
                and "payload" in param_names
                and "event_type" in param_names
            ) or any(
                isinstance(n, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id == "payload" for t in n.targets
                )
                and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Name)
                and n.value.func.id == "_parse_evidence_payload"
                for n in ast.walk(fn)
            )
            if not uses_stream_payload:
                continue
            p_reads, _, v_cnt = _collect_dict_reads_in_nodes(
                fn.body,
                mod,
                modules,
                payload_names={"payload"},
                receipt_names=set(),
                visited_helpers=set(),
            )
            verified_reads += v_cnt
            for lineno, rk in p_reads:
                if rk not in allowed_any_payload:
                    violations.append(
                        ViolationRecord(
                            file=mod.rel_path,
                            line=lineno,
                            kind="unproduced-stream-payload-key",
                            detail=(
                                f"{fn.name}() reads stream payload key {rk!r}, "
                                "which is never emitted by any stream producer in src/"
                            ),
                        )
                    )

    return violations, checked_files, verified_reads


def check_envelope_consumers(
    modules: dict[str, ModuleIndex],
    catalog: ProducerCatalog,
) -> tuple[list[ViolationRecord], int, int]:
    """Verify client SDK GovernanceEnvelope consumers against governance_envelope.py."""
    violations: list[ViolationRecord] = []
    checked_files = 0
    verified_reads = 0

    env_keys = catalog.to_dict_keys.get("GovernanceEnvelope", set())
    section_map = {
        "issuer": catalog.to_dict_keys.get("IssuerMetadata", set()),
        "subject": catalog.to_dict_keys.get("SubjectMetadata", set()),
        "governance_context": catalog.to_dict_keys.get("GovernanceContext", set()),
        "signature": catalog.to_dict_keys.get("SignatureBlock", set()),
    }
    exec_grant_keys = catalog.to_dict_keys.get("ExecutionGrant", set())

    target_prefixes = ("packages/cage-client/src/cage_client/",)

    for mod in sorted(modules.values(), key=lambda m: m.rel_path):
        if not mod.rel_path.startswith(target_prefixes):
            continue
        if not mod.rel_path.endswith(("envelope.py", "core.py")):
            continue
        checked_files += 1

        if "GovernanceEnvelope" in mod.classes and env_keys:
            cls = mod.classes["GovernanceEnvelope"]
            for item in cls.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    fname = item.target.id
                    if fname == "model_config" or fname.startswith("_"):
                        continue
                    verified_reads += 1
                    if fname not in env_keys:
                        violations.append(
                            ViolationRecord(
                                file=mod.rel_path,
                                line=item.lineno,
                                kind="unproduced-envelope-field",
                                detail=(
                                    f"GovernanceEnvelope consumer declares field {fname!r}, "
                                    f"not emitted by GovernanceEnvelope.to_dict() ({sorted(env_keys)})"
                                ),
                            )
                        )
        if "ExecutionGrant" in mod.classes and exec_grant_keys:
            cls = mod.classes["ExecutionGrant"]
            for item in cls.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    fname = item.target.id
                    if fname == "model_config" or fname.startswith("_"):
                        continue
                    verified_reads += 1
                    if fname not in exec_grant_keys:
                        violations.append(
                            ViolationRecord(
                                file=mod.rel_path,
                                line=item.lineno,
                                kind="unproduced-grant-field",
                                detail=(
                                    f"ExecutionGrant consumer declares field {fname!r}, "
                                    f"not emitted by ExecutionGrant.to_dict() ({sorted(exec_grant_keys)})"
                                ),
                            )
                        )

        all_fns: list[ast.FunctionDef | ast.AsyncFunctionDef] = list(
            mod.functions.values()
        )
        for cls in mod.classes.values():
            for item in cls.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    all_fns.append(item)

        for fn in all_fns:
            section_aliases: dict[str, str] = {}
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    tgt = node.targets[0]
                    if isinstance(tgt, ast.Name):
                        if (
                            isinstance(node.value, ast.Attribute)
                            and isinstance(node.value.value, ast.Name)
                            and node.value.value.id == "envelope"
                            and node.value.attr in section_map
                        ):
                            section_aliases[tgt.id] = node.value.attr
                        elif (
                            isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Attribute)
                            and node.value.func.attr == "get"
                            and node.value.args
                            and isinstance(node.value.args[0], ast.Constant)
                            and node.value.args[0].value in section_map
                        ):
                            section_aliases[tgt.id] = str(node.value.args[0].value)

            for node in ast.walk(fn):
                section_name: str | None = None
                key_expr: ast.AST | None = None
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and node.args
                ):
                    recv = node.func.value
                    if (
                        isinstance(recv, ast.Attribute)
                        and isinstance(recv.value, ast.Name)
                        and recv.value.id == "envelope"
                        and recv.attr in section_map
                    ):
                        section_name = recv.attr
                        key_expr = node.args[0]
                    elif isinstance(recv, ast.Name) and recv.id in section_aliases:
                        section_name = section_aliases[recv.id]
                        key_expr = node.args[0]
                elif isinstance(node, ast.Subscript) and isinstance(
                    getattr(node, "ctx", None), ast.Load
                ):
                    recv = node.value
                    if (
                        isinstance(recv, ast.Attribute)
                        and isinstance(recv.value, ast.Name)
                        and recv.value.id == "envelope"
                        and recv.attr in section_map
                    ):
                        section_name = recv.attr
                        key_expr = node.slice
                    elif isinstance(recv, ast.Name) and recv.id in section_aliases:
                        section_name = section_aliases[recv.id]
                        key_expr = node.slice

                if section_name is not None and key_expr is not None:
                    allowed = section_map[section_name]
                    for rk in sorted(_resolve_expr_strings(key_expr, mod, modules)):
                        verified_reads += 1
                        if rk not in allowed:
                            violations.append(
                                ViolationRecord(
                                    file=mod.rel_path,
                                    line=getattr(node, "lineno", 1),
                                    kind="unproduced-envelope-key",
                                    detail=(
                                        f"Envelope consumer reads {section_name}[{rk!r}], "
                                        f"not emitted by producer .to_dict() ({sorted(allowed)})"
                                    ),
                                )
                            )

    return violations, checked_files, verified_reads


def run_check(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    enforce_floors: bool = True,
    verbose: bool = False,
) -> tuple[list[ViolationRecord], dict[str, int]]:
    """Run all Gate 11 producer/consumer AST checks across ``repo_root``."""
    scan_roots = [
        repo_root / "src",
        repo_root / "proof" / "stream_invariants.py",
        repo_root
        / "packages"
        / "cage-conformance"
        / "src"
        / "cage_conformance"
        / "stream_invariants.py",
        repo_root / "packages" / "cage-client" / "src" / "cage_client",
    ]
    modules = _build_module_index(repo_root, scan_roots)
    catalog = collect_producers(repo_root, modules)

    violations: list[ViolationRecord] = []
    stream_consumer_files = 0
    verified_reads = 0

    for rel_target in (
        "proof/stream_invariants.py",
        "packages/cage-conformance/src/cage_conformance/stream_invariants.py",
    ):
        target_path = repo_root / rel_target
        if target_path.is_file():
            mod_name = _module_name_for_path(repo_root, target_path)
            mod = modules.get(mod_name)
            if mod is not None:
                stream_consumer_files += 1
                v_list, v_cnt = check_stream_invariants_file(mod, modules, catalog)
                violations.extend(v_list)
                verified_reads += v_cnt

    cb_violations, cb_files, cb_reads = check_compliance_bridge_consumers(
        modules, catalog
    )
    violations.extend(cb_violations)
    if cb_files > 0:
        stream_consumer_files += 1
    verified_reads += cb_reads

    env_violations, env_files, env_reads = check_envelope_consumers(modules, catalog)
    violations.extend(env_violations)
    verified_reads += env_reads

    stats = {
        "produced_event_types": len(catalog.event_keys),
        "stream_consumer_files": stream_consumer_files,
        "envelope_consumer_files": env_files,
        "verified_key_reads": verified_reads,
    }

    if enforce_floors:
        if stats["produced_event_types"] < MIN_PRODUCED_EVENT_TYPES:
            violations.append(
                ViolationRecord(
                    file="src/",
                    line=1,
                    kind="corpus-floor",
                    detail=(
                        f"Extracted only {stats['produced_event_types']} produced event types "
                        f"(< MIN_PRODUCED_EVENT_TYPES={MIN_PRODUCED_EVENT_TYPES})"
                    ),
                )
            )
        if stats["stream_consumer_files"] < MIN_STREAM_CONSUMER_FILES:
            violations.append(
                ViolationRecord(
                    file="proof/",
                    line=1,
                    kind="corpus-floor",
                    detail=(
                        f"Checked only {stats['stream_consumer_files']} stream consumer targets "
                        f"(< MIN_STREAM_CONSUMER_FILES={MIN_STREAM_CONSUMER_FILES})"
                    ),
                )
            )
        if stats["envelope_consumer_files"] < MIN_ENVELOPE_CONSUMER_FILES:
            violations.append(
                ViolationRecord(
                    file="packages/cage-client/",
                    line=1,
                    kind="corpus-floor",
                    detail=(
                        f"Checked only {stats['envelope_consumer_files']} envelope consumer files "
                        f"(< MIN_ENVELOPE_CONSUMER_FILES={MIN_ENVELOPE_CONSUMER_FILES})"
                    ),
                )
            )
        if stats["verified_key_reads"] < MIN_VERIFIED_KEY_READS:
            violations.append(
                ViolationRecord(
                    file="scripts/check_producer_consumer_keys.py",
                    line=1,
                    kind="corpus-floor",
                    detail=(
                        f"Verified only {stats['verified_key_reads']} consumer key reads "
                        f"(< MIN_VERIFIED_KEY_READS={MIN_VERIFIED_KEY_READS})"
                    ),
                )
            )

    if verbose:
        print(
            f"[Gate 11] Produced event types ({stats['produced_event_types']}): "
            f"{', '.join(sorted(catalog.event_keys))}"
        )
        print(
            f"[Gate 11] Checked {stats['stream_consumer_files']} stream consumer groups, "
            f"{stats['envelope_consumer_files']} envelope consumer files, "
            f"{stats['verified_key_reads']} key/field reads."
        )

    return violations, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gate 11: Verify producer/consumer dictionary-key & event-type AST parity."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory",
    )
    parser.add_argument(
        "--no-floors",
        action="store_true",
        help="Disable repository-wide minimum corpus floors (for isolated unit-test fixtures)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extracted producer event types and verification counts",
    )
    args = parser.parse_args(argv)

    violations, stats = run_check(
        args.repo_root.resolve(),
        enforce_floors=not args.no_floors,
        verbose=args.verbose,
    )
    if violations:
        for v in violations:
            print(f"FAIL: {v.format()}", file=sys.stderr)
        print(
            f"Gate 11 FAILED: {len(violations)} producer/consumer key mismatch(es) detected.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: Gate 11 passed — {stats['produced_event_types']} event types, "
        f"{stats['verified_key_reads']} consumer key/field reads verified (0 mismatches)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
