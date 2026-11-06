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

"""Daemon Lifespan Wiring Gate (AST Query #1).

Pure-stdlib static AST gate scanning ``src/`` for daemon / background-loop
classes defining concrete lifecycle loop entrypoints (``def start``,
``def run_forever``, ``def run_loop``) and verifying that every such daemon
class has at least one reachable start/wiring site in a service lifespan,
plugin contribution, or ``__main__`` entrypoint across ``src/``.

Structural daemon criteria (zero false positives on timers/spans/ABCs):
  1. Concrete method in ``("start", "run_forever", "run_loop")`` (excluding
     ``Protocol`` classes, ``@abstractmethod`` stubs, and ``...``/``pass``/
     ``raise`` stub bodies).
  2. Background loop/task/thread or lifecycle state inside the class:
     -For ``run_forever`` / ``run_loop``: contains a ``while`` wait loop,
      background task/thread spawn, or helper ``*loop*`` method.
     -For ``start``: spawns a background task/thread (``create_task``,
      ``ensure_future``, ``Thread``), defines a helper ``*loop*`` method,
      contains a ``while`` wait loop, or pairs a ``*_task`` / ``*_thread``
      handle attribute with teardown/running state (``stop``, ``close``,
      ``aclose``, ``shutdown``, ``_running``, ``_stopping``, ``_stop_event``).

Zero waivers are permitted: an unstarted daemon class must either be wired
into a reachable service lifespan/entrypoint or have its dead background loop
removed.

Usage:
    uv run python scripts/check_daemon_lifespans.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

LIFECYCLE_ENTRY_METHODS: tuple[str, ...] = ("start", "run_forever", "run_loop")

TEARDOWN_OR_STATE_NAMES: frozenset[str] = frozenset(
    {
        "stop",
        "close",
        "aclose",
        "shutdown",
        "_running",
        "_stopping",
        "_stop_event",
        "_closed",
    }
)
SPAWN_CALL_NAMES: frozenset[str] = frozenset({"create_task", "ensure_future", "Thread"})
LOOP_WAIT_CALL_NAMES: frozenset[str] = frozenset({"sleep", "wait", "wait_for"})
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {"__pycache__", "protos", ".pytest_cache", ".mypy_cache", "node_modules"}
)
ROOT_FUNCTION_NAMES: frozenset[str] = frozenset(
    {"lifespan", "main", "contribute", "startup", "on_startup"}
)
IGNORED_TYPE_TOKENS: frozenset[str] = frozenset(
    {"None", "Optional", "Union", "Any", "Callable", "Awaitable", "Coroutine"}
)
MIN_EXPECTED_REPO_FILES = 100
MIN_EXPECTED_REPO_DAEMONS = 4


@dataclass(frozen=True)
class DaemonClassInfo:
    """Discovered daemon/background-loop class metadata."""

    name: str
    module: str
    rel_path: str
    lineno: int
    entry_methods: tuple[str, ...]


@dataclass(frozen=True)
class LifespanAuditResult:
    """Result of scanning a ``src/`` tree for daemon lifespan wiring."""

    scanned_files: int
    daemons: tuple[DaemonClassInfo, ...]
    wired_locations: dict[str, tuple[str, ...]]
    unstarted: tuple[DaemonClassInfo, ...]


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """Return True if a function body is empty or only docstring/pass/.../raise."""
    stmts = list(body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return True
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Pass):
            return True
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis
        ):
            return True
        if isinstance(stmt, ast.Raise):
            return True
    return False


def _is_abstract_method(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if ``fn_node`` is an abstract method or stub."""
    for dec in fn_node.decorator_list:
        dec_name = (
            dec.id
            if isinstance(dec, ast.Name)
            else (dec.attr if isinstance(dec, ast.Attribute) else "")
        )
        if "abstractmethod" in dec_name:
            return True
    return _is_stub_body(fn_node.body)


def classify_daemon_class(cls_node: ast.ClassDef) -> tuple[bool, tuple[str, ...]]:
    """Determine whether ``cls_node`` is a daemon/lifecycle-loop class.

    Returns:
        ``(is_daemon, concrete_entry_methods)``.
    """
    for base in cls_node.bases:
        base_name = (
            base.id
            if isinstance(base, ast.Name)
            else (base.attr if isinstance(base, ast.Attribute) else "")
        )
        if base_name == "Protocol":
            return False, ()

    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        item.name: item
        for item in cls_node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    concrete_entries = tuple(
        name
        for name in LIFECYCLE_ENTRY_METHODS
        if name in methods and not _is_abstract_method(methods[name])
    )
    if not concrete_entries:
        return False, ()

    has_spawn = False
    has_while_wait = False
    has_loop_helper = any(
        "loop" in method_name and method_name not in LIFECYCLE_ENTRY_METHODS
        for method_name in methods
    )
    self_attrs: set[str] = set()

    for sub in ast.walk(cls_node):
        if isinstance(sub, ast.Call):
            call_name = (
                sub.func.id
                if isinstance(sub.func, ast.Name)
                else (sub.func.attr if isinstance(sub.func, ast.Attribute) else "")
            )
            if call_name in SPAWN_CALL_NAMES:
                has_spawn = True
        elif isinstance(sub, ast.While):
            for wsub in ast.walk(sub):
                if isinstance(wsub, ast.Call):
                    wait_name = (
                        wsub.func.id
                        if isinstance(wsub.func, ast.Name)
                        else (
                            wsub.func.attr
                            if isinstance(wsub.func, ast.Attribute)
                            else ""
                        )
                    )
                    if wait_name in LOOP_WAIT_CALL_NAMES:
                        has_while_wait = True
        elif (
            isinstance(sub, ast.Attribute)
            and isinstance(sub.value, ast.Name)
            and sub.value.id == "self"
        ):
            self_attrs.add(sub.attr)

    has_task_or_thread_attr = any(
        attr in {"_task", "_thread"}
        or attr.endswith("_task")
        or attr.endswith("_thread")
        for attr in self_attrs
    )
    has_teardown_or_state = bool((set(methods) | self_attrs) & TEARDOWN_OR_STATE_NAMES)

    if "run_forever" in concrete_entries or "run_loop" in concrete_entries:
        if has_while_wait or has_spawn or has_loop_helper:
            return True, concrete_entries
        return False, ()

    if (
        has_spawn
        or has_loop_helper
        or has_while_wait
        or (has_task_or_thread_attr and has_teardown_or_state)
    ):
        return True, concrete_entries
    return False, ()


def _unwrap_type_names(annotation: ast.AST | None) -> list[str]:
    """Extract candidate class names from a type annotation AST."""
    if annotation is None:
        return []
    names: list[str] = []
    for sub in ast.walk(annotation):
        if isinstance(sub, ast.Name) and sub.id not in IGNORED_TYPE_TOKENS:
            names.append(sub.id)
        elif isinstance(sub, ast.Attribute) and sub.attr not in IGNORED_TYPE_TOKENS:
            names.append(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            cleaned = (
                sub.value.replace("[", " ")
                .replace("]", " ")
                .replace("|", " ")
                .replace(",", " ")
            )
            for token in cleaned.split():
                short = token.split(".")[-1]
                if short and short not in IGNORED_TYPE_TOKENS:
                    names.append(short)
    return names


def _module_dotpath(py_file: Path, src_dir: Path) -> str:
    """Compute dotted module name for ``py_file`` (prefixed with ``src.`` when applicable)."""
    rel_parts = list(py_file.relative_to(src_dir).with_suffix("").parts)
    if rel_parts and rel_parts[-1] == "__init__":
        rel_parts = rel_parts[:-1]
    prefix = [src_dir.name] if src_dir.name == "src" else []
    full_parts = prefix + rel_parts
    return ".".join(full_parts) if full_parts else py_file.stem


def _resolve_import_module(
    current_module: str,
    node: ast.ImportFrom,
    *,
    is_package: bool = False,
) -> str:
    """Resolve ``ast.ImportFrom`` target module dotted path."""
    if node.level == 0:
        return node.module or ""
    pkg_parts = current_module.split(".")
    drop = node.level - 1 if is_package else node.level
    if drop == 0:
        base_parts = list(pkg_parts)
    elif len(pkg_parts) >= drop:
        base_parts = pkg_parts[:-drop]
    else:
        base_parts = []
    if node.module:
        base_parts.extend(node.module.split("."))
    return ".".join(base_parts)


def _collect_scope_imports(
    scope_node: ast.AST,
    current_module: str,
    *,
    is_package: bool = False,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Collect ``(symbol_aliases, qualified_symbol_targets)`` within ``scope_node``."""
    aliases: dict[str, str] = {}
    qualified: dict[str, tuple[str, str]] = {}
    for sub in ast.walk(scope_node):
        if isinstance(sub, ast.ImportFrom):
            target_mod = _resolve_import_module(
                current_module, sub, is_package=is_package
            )
            for alias in sub.names:
                orig = alias.name.split(".")[-1]
                local = alias.asname or orig
                aliases[local] = orig
                if target_mod:
                    qualified[local] = (target_mod, orig)
        elif isinstance(sub, ast.Import):
            for alias in sub.names:
                orig = alias.name.split(".")[-1]
                local = alias.asname or orig
                aliases[local] = orig
    return aliases, qualified


def _is_dunder_main_guard(test_expr: ast.AST) -> bool:
    """Return True if ``test_expr`` checks ``__name__ == '__main__'``."""
    if not isinstance(test_expr, ast.Compare) or len(test_expr.ops) != 1:
        return False
    if not isinstance(test_expr.ops[0], ast.Eq) or len(test_expr.comparators) != 1:
        return False
    left, right = test_expr.left, test_expr.comparators[0]
    if (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ):
        return True
    if (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    ):
        return True
    return False


def _is_type_checking_guard(test_expr: ast.AST) -> bool:
    """Return True if ``test_expr`` is ``if TYPE_CHECKING:``."""
    if isinstance(test_expr, ast.Name) and test_expr.id == "TYPE_CHECKING":
        return True
    if isinstance(test_expr, ast.Attribute) and test_expr.attr == "TYPE_CHECKING":
        return True
    return False


def _iter_module_classes(tree: ast.Module) -> list[ast.ClassDef]:
    """Collect class definitions in a module, skipping ``if TYPE_CHECKING:`` blocks."""
    classes: list[ast.ClassDef] = []

    def _visit_stmts(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.If) and _is_type_checking_guard(stmt.test):
                continue
            if isinstance(stmt, ast.ClassDef):
                classes.append(stmt)
                _visit_stmts(stmt.body)
            elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.AsyncWith)):
                for child_field in ("body", "orelse", "finalbody"):
                    child_stmts = getattr(stmt, child_field, None)
                    if isinstance(child_stmts, list):
                        _visit_stmts(child_stmts)
                if isinstance(stmt, ast.Try):
                    for handler in stmt.handlers:
                        _visit_stmts(handler.body)

    _visit_stmts(tree.body)
    return classes


def _normalize_module_key(mod_name: str, known_modules: set[str]) -> str:
    """Match ``mod_name`` against ``known_modules`` with or without ``src.`` prefix."""
    if mod_name in known_modules:
        return mod_name
    with_src = f"src.{mod_name}"
    if with_src in known_modules:
        return with_src
    if mod_name.startswith("src.") and mod_name[4:] in known_modules:
        return mod_name[4:]
    return mod_name


def audit_daemon_lifespans(
    src_dir: Path,
    repo_root: Path | None = None,
) -> LifespanAuditResult:
    """Scan ``src_dir`` for daemon classes and verify reachable lifespan wiring."""
    resolved_src = src_dir.resolve()
    resolved_root = (
        repo_root.resolve() if repo_root is not None else resolved_src.parent.resolve()
    )

    py_files = [
        p
        for p in sorted(resolved_src.rglob("*.py"))
        if not any(part in EXCLUDED_DIRS for part in p.relative_to(resolved_src).parts)
    ]

    parsed: list[tuple[Path, str, str, ast.Module]] = []
    daemons_by_name: dict[str, DaemonClassInfo] = {}
    known_modules: set[str] = set()

    for py_file in py_files:
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
        mod_name = _module_dotpath(py_file, resolved_src)
        known_modules.add(mod_name)
        try:
            rel_str = str(py_file.relative_to(resolved_root))
        except ValueError:
            rel_str = str(py_file)
        parsed.append((py_file, mod_name, rel_str, tree))

        for cls_node in _iter_module_classes(tree):
            is_daemon, entry_methods = classify_daemon_class(cls_node)
            if is_daemon:
                daemons_by_name[cls_node.name] = DaemonClassInfo(
                    name=cls_node.name,
                    module=mod_name,
                    rel_path=rel_str,
                    lineno=cls_node.lineno,
                    entry_methods=entry_methods,
                )

    # Pass A: discover factory functions & class properties/attributes returning daemons
    factory_returns: dict[tuple[str, str], str] = {}
    unqualified_factories: dict[str, set[str]] = {}
    class_attr_daemon: dict[tuple[str, str], str] = {}

    for py_file, mod_name, _rel_str, tree in parsed:
        is_pkg = py_file.name == "__init__.py"
        mod_aliases, _ = _collect_scope_imports(tree, mod_name, is_package=is_pkg)
        mod_globals: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                for tname in _unwrap_type_names(node.annotation):
                    orig = mod_aliases.get(tname, tname)
                    if orig in daemons_by_name:
                        mod_globals[node.target.id] = orig

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                resolved_daemon: str | None = None
                for tname in _unwrap_type_names(node.returns):
                    orig = mod_aliases.get(tname, tname)
                    if orig in daemons_by_name:
                        resolved_daemon = orig
                        break
                if resolved_daemon is None:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Return) and sub.value is not None:
                            if isinstance(sub.value, ast.Call):
                                fn = sub.value.func
                                if isinstance(fn, ast.Name):
                                    orig = mod_aliases.get(fn.id, fn.id)
                                    if orig in daemons_by_name:
                                        resolved_daemon = orig
                                elif isinstance(fn, ast.Attribute) and isinstance(
                                    fn.value, ast.Name
                                ):
                                    orig = mod_aliases.get(fn.value.id, fn.value.id)
                                    if orig in daemons_by_name:
                                        resolved_daemon = orig
                            elif (
                                isinstance(sub.value, ast.Name)
                                and sub.value.id in mod_globals
                            ):
                                resolved_daemon = mod_globals[sub.value.id]
                if resolved_daemon is not None:
                    factory_returns[(mod_name, node.name)] = resolved_daemon
                    unqualified_factories.setdefault(node.name, set()).add(
                        resolved_daemon
                    )
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for tname in _unwrap_type_names(item.returns):
                            orig = mod_aliases.get(tname, tname)
                            if orig in daemons_by_name:
                                class_attr_daemon[(node.name, item.name)] = orig
                        if item.name == "__init__":
                            for sub in ast.walk(item):
                                if (
                                    isinstance(sub, ast.AnnAssign)
                                    and isinstance(sub.target, ast.Attribute)
                                    and isinstance(sub.target.value, ast.Name)
                                    and sub.target.value.id == "self"
                                ):
                                    for tname in _unwrap_type_names(sub.annotation):
                                        orig = mod_aliases.get(tname, tname)
                                        if orig in daemons_by_name:
                                            class_attr_daemon[
                                                (node.name, sub.target.attr)
                                            ] = orig
                                elif isinstance(sub, ast.Assign) and isinstance(
                                    sub.value, ast.Call
                                ):
                                    fn = sub.value.func
                                    cand = (
                                        mod_aliases.get(fn.id, fn.id)
                                        if isinstance(fn, ast.Name)
                                        else (
                                            mod_aliases.get(fn.value.id, fn.value.id)
                                            if isinstance(fn, ast.Attribute)
                                            and isinstance(fn.value, ast.Name)
                                            else ""
                                        )
                                    )
                                    if cand in daemons_by_name:
                                        for tgt in sub.targets:
                                            if (
                                                isinstance(tgt, ast.Attribute)
                                                and isinstance(tgt.value, ast.Name)
                                                and tgt.value.id == "self"
                                            ):
                                                class_attr_daemon[
                                                    (node.name, tgt.attr)
                                                ] = cand

    # Pass B: build module-qualified function call graph from root entrypoints
    defined_funcs: set[tuple[str, str]] = set()
    for _py_file, mod_name, _rel_str, tree in parsed:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined_funcs.add((mod_name, node.name))
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        defined_funcs.add((mod_name, f"{node.name}.{item.name}"))

    def _resolve_callee(
        callee_local: str,
        current_mod: str,
        qual_imports: dict[str, tuple[str, str]],
        aliases: dict[str, str],
    ) -> list[tuple[str, str]]:
        targets: list[tuple[str, str]] = []
        if callee_local in qual_imports:
            raw_mod, orig_sym = qual_imports[callee_local]
            norm_mod = _normalize_module_key(raw_mod, known_modules)
            if (norm_mod, orig_sym) in defined_funcs:
                targets.append((norm_mod, orig_sym))
        orig_name = aliases.get(callee_local, callee_local)
        if (current_mod, orig_name) in defined_funcs:
            targets.append((current_mod, orig_name))
        return targets

    func_calls: dict[tuple[str, str], set[tuple[str, str]]] = {}
    root_funcs: set[tuple[str, str]] = set()

    for py_file, mod_name, _rel_str, tree in parsed:
        is_pkg = py_file.name == "__init__.py"
        mod_aliases, mod_qual = _collect_scope_imports(
            tree, mod_name, is_package=is_pkg
        )
        for node in tree.body:
            if isinstance(node, ast.If) and _is_dunder_main_guard(node.test):
                local_aliases, local_qual = _collect_scope_imports(
                    node, mod_name, is_package=is_pkg
                )
                merged_aliases = {**mod_aliases, **local_aliases}
                merged_qual = {**mod_qual, **local_qual}
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        for resolved in _resolve_callee(
                            sub.func.id, mod_name, merged_qual, merged_aliases
                        ):
                            root_funcs.add(resolved)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_key = (mod_name, node.name)
                if node.name in ROOT_FUNCTION_NAMES:
                    root_funcs.add(fn_key)
                for dec in node.decorator_list:
                    dec_name = (
                        dec.id
                        if isinstance(dec, ast.Name)
                        else (
                            dec.attr
                            if isinstance(dec, ast.Attribute)
                            else (
                                dec.func.attr
                                if isinstance(dec, ast.Call)
                                and isinstance(dec.func, ast.Attribute)
                                else ""
                            )
                        )
                    )
                    if dec_name in {"on_event", "asynccontextmanager"} and (
                        "lifespan" in node.name or "startup" in node.name
                    ):
                        root_funcs.add(fn_key)
                local_aliases, local_qual = _collect_scope_imports(
                    node, mod_name, is_package=is_pkg
                )
                merged_aliases = {**mod_aliases, **local_aliases}
                merged_qual = {**mod_qual, **local_qual}
                callees: set[tuple[str, str]] = set()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        callees.update(
                            _resolve_callee(
                                sub.func.id, mod_name, merged_qual, merged_aliases
                            )
                        )
                func_calls[fn_key] = callees
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_key = (mod_name, f"{node.name}.{item.name}")
                        if item.name in ROOT_FUNCTION_NAMES:
                            root_funcs.add(method_key)
                        local_aliases, local_qual = _collect_scope_imports(
                            item, mod_name, is_package=is_pkg
                        )
                        merged_aliases = {**mod_aliases, **local_aliases}
                        merged_qual = {**mod_qual, **local_qual}
                        callees = set()
                        for sub in ast.walk(item):
                            if isinstance(sub, ast.Call) and isinstance(
                                sub.func, ast.Name
                            ):
                                callees.update(
                                    _resolve_callee(
                                        sub.func.id,
                                        mod_name,
                                        merged_qual,
                                        merged_aliases,
                                    )
                                )
                        func_calls[method_key] = callees

    reachable_funcs: set[tuple[str, str]] = set(root_funcs)
    frontier = list(root_funcs)
    while frontier:
        current = frontier.pop()
        for nxt in func_calls.get(current, ()):
            if nxt not in reachable_funcs:
                reachable_funcs.add(nxt)
                frontier.append(nxt)

    # Pass C: resolve daemon start/wiring sites in reachable scopes
    def _resolve_factory_daemon(
        local_fn_name: str,
        current_mod: str,
        qual_imports: dict[str, tuple[str, str]],
        aliases: dict[str, str],
    ) -> str | None:
        if local_fn_name in qual_imports:
            raw_mod, orig_sym = qual_imports[local_fn_name]
            norm_mod = _normalize_module_key(raw_mod, known_modules)
            if (norm_mod, orig_sym) in factory_returns:
                return factory_returns[(norm_mod, orig_sym)]
        orig_name = aliases.get(local_fn_name, local_fn_name)
        if (current_mod, orig_name) in factory_returns:
            return factory_returns[(current_mod, orig_name)]
        cands = unqualified_factories.get(orig_name)
        if cands and len(cands) == 1:
            return next(iter(cands))
        return None

    def _resolve_expr_type(
        expr: ast.AST,
        var_types: dict[str, str],
        current_mod: str,
        qual_imports: dict[str, tuple[str, str]],
        aliases: dict[str, str],
    ) -> str | None:
        if isinstance(expr, ast.Name):
            return var_types.get(expr.id)
        if isinstance(expr, ast.Call):
            fn = expr.func
            if isinstance(fn, ast.Name):
                orig = aliases.get(fn.id, fn.id)
                if orig in daemons_by_name:
                    return orig
                fac_daemon = _resolve_factory_daemon(
                    fn.id, current_mod, qual_imports, aliases
                )
                if fac_daemon is not None:
                    return fac_daemon
                return orig
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                orig = aliases.get(fn.value.id, fn.value.id)
                if orig in daemons_by_name:
                    return orig
                return orig
        if isinstance(expr, ast.BoolOp):
            for val in expr.values:
                resolved = _resolve_expr_type(
                    val, var_types, current_mod, qual_imports, aliases
                )
                if resolved in daemons_by_name:
                    return resolved
        if isinstance(expr, ast.Attribute):
            base_type = _resolve_expr_type(
                expr.value, var_types, current_mod, qual_imports, aliases
            )
            if base_type and (base_type, expr.attr) in class_attr_daemon:
                return class_attr_daemon[(base_type, expr.attr)]
        return None

    def _scan_reachable_scope(
        scope_node: ast.AST,
        owner_class: str | None,
        current_mod: str,
        mod_aliases: dict[str, str],
        mod_qual: dict[str, tuple[str, str]],
        rel_path: str,
        *,
        is_package: bool = False,
    ) -> dict[str, list[str]]:
        local_aliases, local_qual = _collect_scope_imports(
            scope_node, current_mod, is_package=is_package
        )
        aliases = {**mod_aliases, **local_aliases}
        qual_imports = {**mod_qual, **local_qual}
        var_types: dict[str, str] = (
            {"self": owner_class} if owner_class is not None else {}
        )

        if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in scope_node.args.args + scope_node.args.kwonlyargs:
                for tname in _unwrap_type_names(arg.annotation):
                    var_types[arg.arg] = aliases.get(tname, tname)
                    break

        for sub in ast.walk(scope_node):
            if isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                for tname in _unwrap_type_names(sub.annotation):
                    var_types[sub.target.id] = aliases.get(tname, tname)
                    break
                if sub.value is not None:
                    rhs_type = _resolve_expr_type(
                        sub.value, var_types, current_mod, qual_imports, aliases
                    )
                    if rhs_type in daemons_by_name:
                        var_types[sub.target.id] = rhs_type
            elif isinstance(sub, ast.Assign):
                rhs_type = _resolve_expr_type(
                    sub.value, var_types, current_mod, qual_imports, aliases
                )
                if rhs_type:
                    for tgt in sub.targets:
                        if isinstance(tgt, ast.Name):
                            var_types[tgt.id] = rhs_type
            elif isinstance(sub, ast.Call):
                if (
                    isinstance(sub.func, ast.Name)
                    and sub.func.id == "isinstance"
                    and len(sub.args) == 2
                    and isinstance(sub.args[0], ast.Name)
                ):
                    for tname in _unwrap_type_names(sub.args[1]):
                        var_types[sub.args[0].id] = aliases.get(tname, tname)

        hits: dict[str, list[str]] = {}
        for sub in ast.walk(scope_node):
            if (
                isinstance(sub, ast.Attribute)
                and isinstance(sub.ctx, ast.Load)
                and sub.attr in LIFECYCLE_ENTRY_METHODS
            ):
                target_type = _resolve_expr_type(
                    sub.value, var_types, current_mod, qual_imports, aliases
                )
                if target_type in daemons_by_name and target_type != owner_class:
                    if sub.attr in daemons_by_name[target_type].entry_methods:
                        loc = f"{rel_path}:{sub.lineno}"
                        locs = hits.setdefault(target_type, [])
                        if loc not in locs:
                            locs.append(loc)
        return hits

    wired_raw: dict[str, list[str]] = {}
    for py_file, mod_name, rel_str, tree in parsed:
        is_pkg = py_file.name == "__init__.py"
        mod_aliases, mod_qual = _collect_scope_imports(
            tree, mod_name, is_package=is_pkg
        )
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (mod_name, node.name) in reachable_funcs:
                    scope_hits = _scan_reachable_scope(
                        node,
                        None,
                        mod_name,
                        mod_aliases,
                        mod_qual,
                        rel_str,
                        is_package=is_pkg,
                    )
                    for d_name, locs in scope_hits.items():
                        for loc in locs:
                            if loc not in wired_raw.setdefault(d_name, []):
                                wired_raw[d_name].append(loc)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if (mod_name, f"{node.name}.{item.name}") in reachable_funcs:
                            scope_hits = _scan_reachable_scope(
                                item,
                                node.name,
                                mod_name,
                                mod_aliases,
                                mod_qual,
                                rel_str,
                                is_package=is_pkg,
                            )
                            for d_name, locs in scope_hits.items():
                                for loc in locs:
                                    if loc not in wired_raw.setdefault(d_name, []):
                                        wired_raw[d_name].append(loc)
            elif isinstance(node, ast.If) and _is_dunder_main_guard(node.test):
                scope_hits = _scan_reachable_scope(
                    node,
                    None,
                    mod_name,
                    mod_aliases,
                    mod_qual,
                    rel_str,
                    is_package=is_pkg,
                )
                for d_name, locs in scope_hits.items():
                    for loc in locs:
                        if loc not in wired_raw.setdefault(d_name, []):
                            wired_raw[d_name].append(loc)

    ordered_daemons = tuple(
        daemons_by_name[name] for name in sorted(daemons_by_name.keys())
    )
    wired_locations = {
        info.name: tuple(wired_raw.get(info.name, ())) for info in ordered_daemons
    }
    unstarted = tuple(
        info for info in ordered_daemons if not wired_locations[info.name]
    )

    return LifespanAuditResult(
        scanned_files=len(py_files),
        daemons=ordered_daemons,
        wired_locations=wired_locations,
        unstarted=unstarted,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for the daemon lifespan AST gate."""
    parser = argparse.ArgumentParser(
        description=(
            "Verify every daemon/lifecycle-loop class in src/ has a reachable "
            "lifespan or entrypoint start site."
        )
    )
    parser.add_argument(
        "--src-dir",
        type=Path,
        default=None,
        help="Optional override path to src/ directory (defaults to <repo>/src).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every discovered daemon class and its resolved start site(s).",
    )
    parser.add_argument(
        "--min-files",
        type=int,
        default=None,
        help="Minimum Python files expected in scanned corpus.",
    )
    parser.add_argument(
        "--min-daemons",
        type=int,
        default=None,
        help="Minimum daemon classes expected in scanned corpus.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    default_repo_scan = args.src_dir is None
    src_dir = args.src_dir.resolve() if not default_repo_scan else repo_root / "src"
    min_files = (
        args.min_files
        if args.min_files is not None
        else (MIN_EXPECTED_REPO_FILES if default_repo_scan else 1)
    )
    min_daemons = (
        args.min_daemons
        if args.min_daemons is not None
        else (MIN_EXPECTED_REPO_DAEMONS if default_repo_scan else 1)
    )

    if not src_dir.is_dir():
        print(f"ERROR: src directory not found: {src_dir}", file=sys.stderr)
        return 1

    result = audit_daemon_lifespans(src_dir, repo_root=repo_root)

    if args.verbose:
        print(
            f"Scanned {result.scanned_files} Python files in {src_dir}; "
            f"discovered {len(result.daemons)} daemon class(es):"
        )
        for info in result.daemons:
            locs = result.wired_locations.get(info.name, ())
            methods_str = ", ".join(info.entry_methods)
            if locs:
                print(
                    f"  [WIRED]     {info.name} ({info.rel_path}:{info.lineno}, "
                    f"entry: {methods_str}) -> {', '.join(locs)}"
                )
            else:
                print(
                    f"  [UNSTARTED] {info.name} ({info.rel_path}:{info.lineno}, "
                    f"entry: {methods_str}) -> NO REACHABLE START SITE"
                )

    corpus_failures: list[str] = []
    if result.scanned_files < min_files:
        corpus_failures.append(
            f"scanned Python files {result.scanned_files} < minimum expected {min_files}"
        )
    if len(result.daemons) < min_daemons:
        corpus_failures.append(
            f"recognized daemon classes {len(result.daemons)} < minimum expected {min_daemons}"
        )
    if corpus_failures:
        print(
            "Daemon lifespan check FAILED: vacuous/blind corpus floor not met:",
            file=sys.stderr,
        )
        for failure in corpus_failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    if result.unstarted:
        print()
        print(
            "Daemon lifespan check FAILED: found daemon/background-loop class(es) "
            "with no reachable start site in src/:"
        )
        for info in result.unstarted:
            methods_str = ", ".join(info.entry_methods)
            print(
                f"  - {info.name} ({info.rel_path}:{info.lineno}) "
                f"defines [{methods_str}] but is never started from any "
                "lifespan, plugin contribution, or __main__ entrypoint."
            )
        print()
        print(
            "Remediation: wire the daemon into its owning service lifespan "
            "(with shutdown cancellation) or delete dead background loop methods."
        )
        return 1

    print(
        f"Daemon lifespan check PASSED: {len(result.daemons)}/{len(result.daemons)} "
        f"daemon class(es) wired across {result.scanned_files} files."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
