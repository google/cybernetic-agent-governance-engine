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

"""Posture Guard Integrity Check — AST Gate (F-112).

Enforces that posture-gated startup guards and factories across ``src/`` fail
closed across their full declared enforcing scope without caller-side defeat.

Zero waivers or allowlists are permitted in this gate.

Rules Enforced
--------------
- **Rule A (Query #3 — Swallowed posture-gated raise):**
  1. Indexes all public posture-gated raising functions and methods in ``src/``
     (functions/methods that contain ``raise`` and reference posture/environment
     signals: ``is_enforcing``, ``resolve_posture``, ``get_posture``,
     ``DeploymentPosture``, ``Posture``, ``CAGE_ENV``, ``ENVIRONMENT``,
     ``CAGE_POSTURE``, ``DEPLOYMENT_POSTURE``), plus ``ClassName.__init__``
     constructors, transitive ``ClassName.from_env`` factories (where
     ``ClassName.from_env`` or ``ClassName.__init__`` invokes a posture-gated
     raising target), and module-level ``_get_*`` singleton accessors that
     delegate to a posture-gated raising factory.
  2. Flags any ``try`` statement in ``src/`` whose body invokes a posture-gated
     factory or guard and has at least one broad ``except`` handler
     (``Exception``, ``BaseException``, ``RuntimeError``, ``ValueError``, or
     bare ``except:``) that does not re-raise on every execution path (or
     explicitly re-raise whenever ``is_enforcing(...)`` holds). Handlers that
     catch strictly ``ImportError`` / ``ModuleNotFoundError`` for optional
     dependencies are permitted.

- **Rule B (Query #4 — Caller narrowing a posture guard below its declared scope):**
  1. Indexes all guard functions and methods (``assert_*``, ``validate_*``,
     ``verify_*``, ``enforce_*``, ``check_*``, ``require_*``, plus posture-gated
     raising functions/methods) whose internal body applies across all enforcing
     or non-development environments (for example ``is_enforcing(...)``,
     ``.enforces_controls``, or early-return / ``not in`` checks over permissive
     development postures such as ``("development", "test", "dev", "ci")``).
  2. Walks enclosing ``ast.If`` statements around call sites in ``src/`` and
     flags any call site gated by an ``if`` condition that narrows the posture
     to production-only values (such as ``env == "prod"``,
     ``env in ("prod", "production")``, or
     ``posture == DeploymentPosture.PRODUCTION``), which silently disables the
     guard in ``staging`` and other enforcing postures.

Static Scope Boundaries of Rule B
---------------------------------
Rule B inspects lexical ``ast.If`` guards enclosing direct call sites. The
following patterns lie outside Rule B's static AST scope and require code
review / behavioral posture tests:
- **Indirect conditional callers**: Caller ``f()`` is gated on ``env == "prod"``
  and calls helper ``g()``, which unconditionally calls ``guard()``.
- **Early-return narrowing**: Caller executes ``if env != "prod": return``
  prior to a top-level ``guard()`` call in the same function body rather than
  wrapping ``guard()`` inside an ``ast.If`` block.
- **Argument narrowing**: Caller passes a narrowed boolean or overridden
  environment string as an argument (e.g. ``guard(strict=(env == "prod"))``)
  instead of branching at the call site.

Usage:
    python scripts/check_posture_guard_integrity.py
    python scripts/check_posture_guard_integrity.py --verbose

Exit codes:
    0 - No posture guard integrity violations detected
    1 - One or more Rule A or Rule B violations detected
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

SRC_ROOT = Path("src")

POSTURE_SYMBOLS: frozenset[str] = frozenset(
    {
        "is_enforcing",
        "resolve_posture",
        "get_posture",
        "DeploymentPosture",
        "Posture",
    }
)

POSTURE_ENV_VARS: frozenset[str] = frozenset(
    {
        "CAGE_ENV",
        "ENVIRONMENT",
        "CAGE_POSTURE",
        "DEPLOYMENT_POSTURE",
    }
)

GUARD_PREFIXES: tuple[str, ...] = (
    "assert_",
    "validate_",
    "verify_",
    "enforce_",
    "check_",
    "require_",
)

BROAD_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "Exception",
        "BaseException",
        "RuntimeError",
        "ValueError",
    }
)

IMPORT_ONLY_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "ImportError",
        "ModuleNotFoundError",
    }
)

PERMISSIVE_ENV_LITERALS: frozenset[str] = frozenset(
    {
        "dev",
        "development",
        "test",
        "testing",
        "ci",
        "continuous-integration",
    }
)

PROD_ONLY_LITERALS: frozenset[str] = frozenset(
    {
        "prod",
        "production",
    }
)

PROD_ONLY_ENUM_ATTRS: frozenset[str] = frozenset({"PRODUCTION"})


@dataclass(frozen=True)
class PostureGuardViolation:
    """A single Rule A or Rule B AST violation."""

    rule: str
    file_path: str
    line_number: int
    end_line_number: int
    target: str
    detail: str

    def format_line_span(self) -> str:
        if self.end_line_number > self.line_number:
            return f"{self.file_path}:{self.line_number}-{self.end_line_number}"
        return f"{self.file_path}:{self.line_number}"


def _iter_scope_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Yield AST descendants within the current function/class scope."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield child
        yield from _iter_scope_nodes(child)


def _iter_try_body_nodes(stmts: Sequence[ast.stmt]) -> Iterator[ast.AST]:
    """Yield nodes inside a ``try`` body that raise directly to this ``try``'s handlers.

    Skips nested function/class definitions and nested ``try`` blocks that have
    their own ``except`` handlers (those inner ``try`` blocks are audited
    independently when walked). A ``try ... finally`` with no ``except``
    handlers still propagates exceptions to the outer ``try``.
    """
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Try):
            if not stmt.handlers:
                yield from _iter_try_body_nodes(stmt.body)
            yield from _iter_try_body_nodes(stmt.orelse)
            yield from _iter_try_body_nodes(stmt.finalbody)
            continue
        yield stmt
        for child in _iter_scope_nodes(stmt):
            if isinstance(child, ast.Try):
                continue
            yield child


def _has_posture_signal(node: ast.AST) -> bool:
    """Return True if ``node`` references a posture symbol or posture env var."""
    for sub in _iter_scope_nodes(node):
        if isinstance(sub, ast.Name) and sub.id in POSTURE_SYMBOLS:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr in POSTURE_SYMBOLS:
            return True
        if (
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and sub.value in POSTURE_ENV_VARS
        ):
            return True
    return False


def _has_raise(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if ``fn_node`` contains a ``raise`` statement in its own scope."""
    return any(isinstance(sub, ast.Raise) for sub in _iter_scope_nodes(fn_node))


def _is_direct_enforcing_check(expr: ast.expr) -> bool:
    """Return True when ``expr`` directly tests ``is_enforcing(...)`` or ``.enforces_controls``."""
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name) and expr.func.id == "is_enforcing":
            return True
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "is_enforcing":
            return True
    if isinstance(expr, ast.Attribute) and expr.attr == "enforces_controls":
        return True
    return False


def _is_broad_enforcing_guard_body(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return True if ``fn_node`` applies across all enforcing / non-dev postures."""
    for sub in _iter_scope_nodes(fn_node):
        if isinstance(sub, ast.Name) and sub.id == "is_enforcing":
            return True
        if isinstance(sub, ast.Attribute) and sub.attr in (
            "is_enforcing",
            "enforces_controls",
        ):
            return True
        if isinstance(sub, ast.If):
            for cmp_node in ast.walk(sub.test):
                if not isinstance(cmp_node, ast.Compare):
                    continue
                str_lits = _extract_compared_strings(cmp_node)
                if str_lits and str_lits <= PERMISSIVE_ENV_LITERALS:
                    has_early_return = any(isinstance(s, ast.Return) for s in sub.body)
                    is_negated_cmp = any(
                        isinstance(op, (ast.NotIn, ast.NotEq)) for op in cmp_node.ops
                    )
                    if has_early_return or is_negated_cmp:
                        return True
                enum_attrs = _extract_posture_enum_attrs(cmp_node)
                if {"PRODUCTION", "STAGING"} <= enum_attrs:
                    return True
    return False


def _extract_compared_strings(cmp_node: ast.Compare) -> set[str]:
    """Collect lowercase string literals appearing as operands of ``cmp_node``."""
    out: set[str] = set()
    for part in (cmp_node.left, *cmp_node.comparators):
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            out.add(part.value.lower())
        elif isinstance(part, (ast.Tuple, ast.List, ast.Set)):
            for elt in part.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    out.add(elt.value.lower())
    return out


def _extract_posture_enum_attrs(cmp_node: ast.Compare) -> set[str]:
    """Collect ``DeploymentPosture.<MEMBER>`` / ``Posture.<MEMBER>`` names in ``cmp_node``."""
    out: set[str] = set()
    for part in (cmp_node.left, *cmp_node.comparators):
        candidates = (
            part.elts if isinstance(part, (ast.Tuple, ast.List, ast.Set)) else [part]
        )
        for item in candidates:
            if (
                isinstance(item, ast.Attribute)
                and isinstance(item.value, ast.Name)
                and item.value.id in ("DeploymentPosture", "Posture")
            ):
                out.add(item.attr)
    return out


def _contains_non_raising_exit(node: ast.AST) -> bool:
    """Return True if ``node`` can exit via ``return`` / ``break`` / ``continue``."""
    return any(
        isinstance(sub, (ast.Return, ast.Break, ast.Continue))
        for sub in _iter_scope_nodes(node)
    )


def _stmts_always_reraise(stmts: Sequence[ast.stmt]) -> bool:
    """Return True if ``stmts`` re-raises on every enforcing execution path."""
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, (ast.Return, ast.Break, ast.Continue)):
            return False
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _stmts_always_reraise(stmt.body)
                and _stmts_always_reraise(stmt.orelse)
            ):
                return True
            if _is_direct_enforcing_check(stmt.test) and _stmts_always_reraise(
                stmt.body
            ):
                return True
            if _contains_non_raising_exit(stmt):
                return False
        elif _contains_non_raising_exit(stmt):
            return False
    return False


def _handler_exception_names(handler: ast.ExceptHandler) -> set[str] | None:
    """Return caught exception type names, or ``None`` for bare ``except:``."""
    if handler.type is None:
        return None
    names: set[str] = set()
    elts = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for elt in elts:
        if isinstance(elt, ast.Name):
            names.add(elt.id)
        elif isinstance(elt, ast.Attribute):
            names.add(elt.attr)
    return names


def _build_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local ``import ... as alias`` names in ``tree`` back to their symbol."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name.split(".")[-1]
    return aliases


def _calls_in_function(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    cls_name: str | None,
    alias_map: dict[str, str],
) -> set[str]:
    """Return candidate target keys invoked inside ``fn_node``'s own scope."""
    called: set[str] = set()
    for sub in _iter_scope_nodes(fn_node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if isinstance(func, ast.Name):
            orig = alias_map.get(func.id, func.id)
            called.add(orig)
            called.add(f"{orig}.__init__")
            if cls_name and func.id == "cls":
                called.add(f"{cls_name}.__init__")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if cls_name and func.value.id in ("cls", "self"):
                called.add(f"{cls_name}.{func.attr}")
            else:
                base = alias_map.get(func.value.id, func.value.id)
                called.add(f"{base}.{func.attr}")
    return called


def _resolve_call_candidates(
    call: ast.Call,
    alias_map: dict[str, str],
    enclosing_cls: str | None,
    top_level_funcs: set[str],
) -> list[tuple[str, str]]:
    """Return ``(lookup_key, display_name)`` candidates for ``call``."""
    candidates: list[tuple[str, str]] = []
    func = call.func
    if isinstance(func, ast.Name):
        orig = alias_map.get(func.id, func.id)
        candidates.append((orig, f"{orig}()"))
        candidates.append((f"{orig}.__init__", f"{orig}()"))
    elif isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            if enclosing_cls and func.value.id in ("self", "cls"):
                key = f"{enclosing_cls}.{func.attr}"
                candidates.append((key, f"{key}()"))
            else:
                base = alias_map.get(func.value.id, func.value.id)
                candidates.append((f"{base}.{func.attr}", f"{base}.{func.attr}()"))
                if func.attr in top_level_funcs:
                    candidates.append((func.attr, f"{func.value.id}.{func.attr}()"))
        candidates.append((f".{func.attr}", f"{func.attr}()"))
    return candidates


def _is_narrowing_if_condition(
    test: ast.expr,
    env_vars_in_scope: frozenset[str],
    *,
    in_orelse: bool = False,
) -> bool:
    """Return True if ``test`` narrows execution to prod-only posture."""
    for cmp_node in ast.walk(test):
        if not isinstance(cmp_node, ast.Compare):
            continue
        if in_orelse:
            valid_ops = all(
                isinstance(op, (ast.NotEq, ast.NotIn, ast.IsNot)) for op in cmp_node.ops
            )
        else:
            valid_ops = all(
                isinstance(op, (ast.Eq, ast.In, ast.Is)) for op in cmp_node.ops
            )
        if not valid_ops:
            continue

        str_lits = _extract_compared_strings(cmp_node)
        enum_attrs = _extract_posture_enum_attrs(cmp_node)
        if not (
            (str_lits and str_lits <= PROD_ONLY_LITERALS)
            or (enum_attrs and enum_attrs <= PROD_ONLY_ENUM_ATTRS)
        ):
            continue

        references_posture_or_env = False
        for part in (cmp_node.left, *cmp_node.comparators):
            for sub in ast.walk(part):
                if (
                    isinstance(sub, ast.Constant)
                    and isinstance(sub.value, str)
                    and sub.value in POSTURE_ENV_VARS
                ):
                    references_posture_or_env = True
                elif isinstance(sub, ast.Name) and (
                    sub.id in env_vars_in_scope
                    or sub.id in POSTURE_SYMBOLS
                    or "env" in sub.id.lower()
                    or "posture" in sub.id.lower()
                ):
                    references_posture_or_env = True
                elif isinstance(sub, ast.Attribute) and sub.attr in POSTURE_SYMBOLS:
                    references_posture_or_env = True

        if references_posture_or_env:
            return True
    return False


def _walk_rule_a(
    node: ast.AST,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    posture_raising_targets: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
    cls_name: str | None = None,
) -> None:
    """Audit ``node`` recursively for Rule A (swallowed posture-gated raises)."""
    for child in ast.iter_child_nodes(node):
        next_cls = child.name if isinstance(child, ast.ClassDef) else cls_name
        if isinstance(child, ast.Try):
            matched_calls: list[str] = []
            for sub in _iter_try_body_nodes(child.body):
                if not isinstance(sub, ast.Call):
                    continue
                for key, display in _resolve_call_candidates(
                    sub, alias_map, cls_name, top_func_names
                ):
                    if key in posture_raising_targets:
                        if display not in matched_calls:
                            matched_calls.append(display)
                        break
            if matched_calls:
                for handler in child.handlers:
                    exc_names = _handler_exception_names(handler)
                    if (
                        exc_names is not None
                        and exc_names
                        and exc_names <= IMPORT_ONLY_EXCEPTIONS
                    ):
                        continue
                    is_broad = exc_names is None or bool(exc_names & BROAD_EXCEPTIONS)
                    if is_broad and not _stmts_always_reraise(handler.body):
                        caught_desc = (
                            "bare except:"
                            if exc_names is None
                            else f"except ({', '.join(sorted(exc_names))})"
                        )
                        target_str = ", ".join(matched_calls)
                        v = PostureGuardViolation(
                            rule="Rule A (swallowed posture-gated raise)",
                            file_path=file_label,
                            line_number=handler.lineno,
                            end_line_number=handler.lineno,
                            target=target_str,
                            detail=(
                                f"{caught_desc} swallows posture-gated raise "
                                f"from {target_str} without re-raising"
                            ),
                        )
                        violations.append(v)
                        if verbose:
                            print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")
        _walk_rule_a(
            child,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            posture_raising_targets=posture_raising_targets,
            violations=violations,
            verbose=verbose,
            cls_name=next_cls,
        )


def _walk_rule_b(
    node: ast.AST,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
    cls_name: str | None = None,
    enclosing_ifs: tuple[tuple[ast.If, bool], ...] = (),
    env_vars: frozenset[str] = frozenset(),
) -> None:
    """Audit ``node`` recursively for Rule B (caller-narrowed posture guards)."""
    local_env_vars = set(env_vars)
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Assign) and _has_posture_signal(
            ast.Module(body=[child], type_ignores=[])
        ):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    local_env_vars.add(target.id)
        elif (
            isinstance(child, ast.AnnAssign)
            and child.value is not None
            and isinstance(child.target, ast.Name)
            and _has_posture_signal(ast.Module(body=[child], type_ignores=[]))
        ):
            local_env_vars.add(child.target.id)
    frozen_vars = frozenset(local_env_vars)

    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.ClassDef):
            _walk_rule_b(
                child,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=child.name,
                enclosing_ifs=(),
                env_vars=frozen_vars,
            )
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _walk_rule_b(
                child,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=(),
                env_vars=frozen_vars,
            )
        elif isinstance(child, ast.If):
            _walk_rule_b(
                child.test,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=enclosing_ifs,
                env_vars=frozen_vars,
            )
            body_wrapper = ast.Module(body=list(child.body), type_ignores=[])
            _walk_rule_b(
                body_wrapper,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=(*enclosing_ifs, (child, False)),
                env_vars=frozen_vars,
            )
            if child.orelse:
                orelse_wrapper = ast.Module(body=list(child.orelse), type_ignores=[])
                _walk_rule_b(
                    orelse_wrapper,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=(*enclosing_ifs, (child, True)),
                    env_vars=frozen_vars,
                )
        else:
            if isinstance(child, ast.Call):
                matched_display: str | None = None
                for key, display in _resolve_call_candidates(
                    child, alias_map, cls_name, top_func_names
                ):
                    if key in broad_enforcing_guards:
                        matched_display = display
                        break
                if matched_display is not None:
                    for if_node, in_orelse in enclosing_ifs:
                        if _is_narrowing_if_condition(
                            if_node.test, frozen_vars, in_orelse=in_orelse
                        ):
                            v = PostureGuardViolation(
                                rule="Rule B (caller-narrowed posture guard)",
                                file_path=file_label,
                                line_number=if_node.lineno,
                                end_line_number=child.lineno,
                                target=matched_display,
                                detail=(
                                    f"enclosing if-condition at line {if_node.lineno} "
                                    f"narrows {matched_display} to production-only posture"
                                ),
                            )
                            violations.append(v)
                            if verbose:
                                print(
                                    f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}"
                                )
                            break
            _walk_rule_b(
                child,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=enclosing_ifs,
                env_vars=frozen_vars,
            )


def _analyze_parsed_modules(
    parsed_modules: Sequence[tuple[str, ast.Module]],
    *,
    verbose: bool = False,
) -> list[PostureGuardViolation]:
    """Run two-pass Rule A and Rule B analysis over ``parsed_modules``."""
    posture_raising_targets: set[str] = set()
    broad_enforcing_guards: set[str] = set()
    top_level_funcs: dict[
        str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    class_methods: dict[
        tuple[str, str], list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    module_aliases: dict[str, dict[str, str]] = {}

    # Pass 1: Index posture-gated raising functions/methods and broad enforcing guards.
    for file_label, tree in parsed_modules:
        module_aliases[file_label] = _build_import_aliases(tree)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                top_level_funcs.setdefault(node.name, []).append((file_label, node))
                is_public = not node.name.startswith("_")
                if is_public and _has_raise(node) and _has_posture_signal(node):
                    posture_raising_targets.add(node.name)
                    if _is_broad_enforcing_guard_body(node):
                        broad_enforcing_guards.add(node.name)
                elif node.name.startswith(
                    GUARD_PREFIXES
                ) and _is_broad_enforcing_guard_body(node):
                    broad_enforcing_guards.add(node.name)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    class_methods.setdefault((node.name, item.name), []).append(
                        (file_label, item)
                    )
                    key = f"{node.name}.{item.name}"
                    is_public_or_init = (
                        not item.name.startswith("_") or item.name == "__init__"
                    )
                    if (
                        is_public_or_init
                        and _has_raise(item)
                        and _has_posture_signal(item)
                    ):
                        posture_raising_targets.add(key)
                        if _is_broad_enforcing_guard_body(item):
                            broad_enforcing_guards.add(key)
                            if item.name.startswith(GUARD_PREFIXES):
                                broad_enforcing_guards.add(f".{item.name}")
                    elif item.name.startswith(
                        GUARD_PREFIXES
                    ) and _is_broad_enforcing_guard_body(item):
                        broad_enforcing_guards.add(key)
                        broad_enforcing_guards.add(f".{item.name}")

    # Fixed-point propagation:
    # - ClassName.from_env where ClassName.from_env or ClassName.__init__ invokes a
    #   posture-gated raising target (e.g. KMSGovernanceSigner.from_env).
    # - Module-level _get_* singleton getters that wrap a posture-gated factory.
    changed = True
    while changed:
        changed = False
        for (cls_name, method_name), defs in class_methods.items():
            if method_name not in ("from_env", "__init__"):
                continue
            from_env_key = f"{cls_name}.from_env"
            if from_env_key in posture_raising_targets:
                continue
            if (cls_name, "from_env") not in class_methods:
                continue
            for file_label, fn_node in defs:
                called = _calls_in_function(
                    fn_node, cls_name, module_aliases[file_label]
                )
                if called & posture_raising_targets:
                    posture_raising_targets.add(from_env_key)
                    changed = True
                    break

        for fn_name, defs in top_level_funcs.items():
            if not fn_name.startswith("_get_") or fn_name in posture_raising_targets:
                continue
            for file_label, fn_node in defs:
                called = _calls_in_function(fn_node, None, module_aliases[file_label])
                if called & posture_raising_targets:
                    posture_raising_targets.add(fn_name)
                    changed = True
                    break

    if verbose:
        print(
            f"📊 Indexed {len(posture_raising_targets)} posture-gated raising targets "
            f"and {len(broad_enforcing_guards)} broad enforcing guard keys "
            f"across {len(parsed_modules)} files."
        )

    top_func_names = set(top_level_funcs)
    violations: list[PostureGuardViolation] = []

    # Pass 2: Audit all call sites in each module for Rule A and Rule B.
    for file_label, tree in parsed_modules:
        alias_map = module_aliases[file_label]
        _walk_rule_a(
            tree,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            posture_raising_targets=posture_raising_targets,
            violations=violations,
            verbose=verbose,
        )
        _walk_rule_b(
            tree,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
        )

    return violations


def scan_tree(
    root: Path = SRC_ROOT,
    *,
    verbose: bool = False,
) -> list[PostureGuardViolation]:
    """Scan all ``*.py`` files under ``root`` for Rule A and Rule B violations."""
    py_files = sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    parsed: list[tuple[str, ast.Module]] = []
    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        parsed.append((py_file.as_posix(), tree))
    return _analyze_parsed_modules(parsed, verbose=verbose)


def scan_source(
    source: str,
    *,
    filename: str = "<synthetic>",
    verbose: bool = False,
) -> list[PostureGuardViolation]:
    """Scan a synthetic Python source snippet for Rule A and Rule B violations."""
    tree = ast.parse(source, filename=filename)
    return _analyze_parsed_modules([(filename, tree)], verbose=verbose)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify posture-gated startup guards are neither swallowed nor narrowed."
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed index counts and per-site violation diagnostics.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=SRC_ROOT,
        help="Root directory of Python sources to scan (default: src).",
    )
    args = parser.parse_args(argv)

    print("🔍 Checking posture guard integrity (Rule A + Rule B)...")
    if not args.root.exists():
        print(f"❌ Source root not found: {args.root}")
        return 1

    violations = scan_tree(args.root, verbose=args.verbose)
    if violations:
        print(
            f"\n❌ POSTURE GUARD INTEGRITY VIOLATIONS DETECTED ({len(violations)}):\n"
        )
        for v in violations:
            print(f"  {v.format_line_span()} [{v.rule}]")
            print(f"    └─ {v.detail}\n")
        return 1

    print("✅ All posture guards fail closed across their full enforcing scope.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
