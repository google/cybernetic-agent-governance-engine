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

"""Posture & Middleware Guard Integrity Check — AST Gate (F-112).

Enforces that posture-gated startup guards/factories and request-path middleware
security guards across ``src/`` fail closed across their full declared scope
without caller-side swallowing, early-return posture narrowing, or size/bound
threshold fallthrough into downstream ASGI/HTTP dispatch.

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
  2. Audits both enclosing ``ast.If`` conditions **and** preceding non-raising
     early-exit guard clauses (``if env != "prod": return`` / ``continue`` /
     ``break``, ``if not (env == "prod"): return``, ``if env == "staging": return``,
     and ``if env == "prod": pass; else: return``) with De Morgan negation
     propagation, flagging any call site narrowed to production-only posture or
     excluding ``staging``.

- **Rule C (Middleware threshold/bound guard fallthrough to downstream dispatch):**
  1. Recognizes ASGI middleware ``__call__(self, scope, receive, send)``,
     Starlette ``BaseHTTPMiddleware`` ``dispatch(self, request, call_next)``,
     and ``@app.middleware(...)`` handlers across ``src/``, enforcing both a
     non-vacuous corpus floor (``MIN_EXPECTED_MIDDLEWARE_HANDLERS``) and a
     two-ways-of-counting cross-check against every in-tree ``*Middleware`` /
     ``BaseHTTPMiddleware`` class, ``add_middleware(...)`` registration, and
     ``@*.middleware(...)`` decorator so newly added middleware with an
     unrecognized signature fails closed rather than silently escaping audit.
  2. Flags any security guard call (``assert_*``, ``validate_*``, ``verify_*``,
     ``enforce_*``, ``check_*``, ``require_*``, or indexed posture guard) gated
     by a size/length/count bound comparison (``<``, ``<=``, ``>``, ``>=`` — on
     an enclosing ``if`` or preceding bounded ``while`` loop) whose complement
     path reaches downstream ``self.app(...)`` / ``call_next(...)`` without
     failing closed (returning an error response or raising), as well as
     bound-gated early dispatch that returns ``self.app(...)`` / ``call_next(...)``
     ahead of a security guard.

Static Scope Boundaries
-----------------------
- **Indirect cross-function conditional callers**: Caller ``f()`` narrows on
  ``env == "prod"`` and calls non-guard helper ``g()``, which calls ``guard()``.
- **Argument narrowing**: Caller passes a narrowed boolean expression as an
  argument (e.g. ``guard(strict=(env == "prod"))``) instead of branching.

Usage:
    python scripts/check_posture_guard_integrity.py
    python scripts/check_posture_guard_integrity.py --verbose

Exit codes:
    0 - No posture or middleware guard integrity violations detected
    1 - One or more Rule A, Rule B, Rule C, or corpus-floor violations detected
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"

MIN_EXPECTED_REPO_FILES = 100
MIN_EXPECTED_RAISING_TARGETS = 10
MIN_EXPECTED_BROAD_GUARDS = 5
MIN_EXPECTED_MIDDLEWARE_HANDLERS = 2

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
STAGING_LITERALS: frozenset[str] = frozenset({"staging"})
STAGING_ENUM_ATTRS: frozenset[str] = frozenset({"STAGING"})

BOUND_COMPARE_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
DEFAULT_ASGI_APP_ATTRS: frozenset[str] = frozenset(
    {"app", "_app", "inner", "inner_app", "next_app"}
)
IGNORED_BOUND_IDENTIFIERS: frozenset[str] = frozenset(
    {"len", "int", "float", "max", "min", "abs", "sum"}
)


@dataclass(frozen=True)
class PostureGuardViolation:
    """A single Rule A, Rule B, or Rule C AST violation."""

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


def _compare_references_posture(
    cmp_node: ast.Compare,
    env_vars_in_scope: frozenset[str],
) -> bool:
    """Return True if ``cmp_node`` inspects a posture symbol or environment variable."""
    for part in (cmp_node.left, *cmp_node.comparators):
        for sub in ast.walk(part):
            if (
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and sub.value in POSTURE_ENV_VARS
            ):
                return True
            if isinstance(sub, ast.Name) and (
                sub.id in env_vars_in_scope
                or sub.id in POSTURE_SYMBOLS
                or "env" in sub.id.lower()
                or "posture" in sub.id.lower()
            ):
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in POSTURE_SYMBOLS:
                return True
    return False


def _cmp_narrows_posture(
    cmp_node: ast.Compare,
    env_vars_in_scope: frozenset[str],
    *,
    negated: bool,
) -> bool:
    """Return True if ``cmp_node`` (under ``negated`` polarity) narrows below staging+prod."""
    if not _compare_references_posture(cmp_node, env_vars_in_scope):
        return False

    is_pos_op = all(isinstance(op, (ast.Eq, ast.In, ast.Is)) for op in cmp_node.ops)
    is_neg_op = all(
        isinstance(op, (ast.NotEq, ast.NotIn, ast.IsNot)) for op in cmp_node.ops
    )
    if not (is_pos_op or is_neg_op):
        return False

    effective_pos = (is_pos_op and not negated) or (is_neg_op and negated)
    effective_neg = (is_neg_op and not negated) or (is_pos_op and negated)

    str_lits = _extract_compared_strings(cmp_node)
    enum_attrs = _extract_posture_enum_attrs(cmp_node)

    if effective_pos and (
        (str_lits and str_lits <= PROD_ONLY_LITERALS)
        or (enum_attrs and enum_attrs <= PROD_ONLY_ENUM_ATTRS)
    ):
        return True

    if (
        effective_neg
        and (bool(str_lits & STAGING_LITERALS) or bool(enum_attrs & STAGING_ENUM_ATTRS))
        and not (
            bool(str_lits & PROD_ONLY_LITERALS)
            or bool(enum_attrs & PROD_ONLY_ENUM_ATTRS)
        )
    ):
        return True

    return False


def _expr_admits_staging(
    expr: ast.expr,
    env_vars_in_scope: frozenset[str],
    *,
    negated: bool,
) -> bool:
    """Return True if ``expr`` (under ``negated`` polarity) explicitly admits ``staging``."""
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return _expr_admits_staging(
            expr.operand, env_vars_in_scope, negated=not negated
        )
    if _is_direct_enforcing_check(expr):
        return not negated
    if isinstance(expr, ast.Compare):
        if not _compare_references_posture(expr, env_vars_in_scope):
            return False
        is_pos_op = all(isinstance(op, (ast.Eq, ast.In, ast.Is)) for op in expr.ops)
        is_neg_op = all(
            isinstance(op, (ast.NotEq, ast.NotIn, ast.IsNot)) for op in expr.ops
        )
        effective_pos = (is_pos_op and not negated) or (is_neg_op and negated)
        if not effective_pos:
            return False
        str_lits = _extract_compared_strings(expr)
        enum_attrs = _extract_posture_enum_attrs(expr)
        return bool(str_lits & STAGING_LITERALS) or bool(
            enum_attrs & STAGING_ENUM_ATTRS
        )
    if isinstance(expr, ast.BoolOp):
        is_effective_or = (isinstance(expr.op, ast.Or) and not negated) or (
            isinstance(expr.op, ast.And) and negated
        )
        if is_effective_or:
            return any(
                _expr_admits_staging(v, env_vars_in_scope, negated=negated)
                for v in expr.values
            )
        return all(
            _expr_admits_staging(v, env_vars_in_scope, negated=negated)
            for v in expr.values
        )
    return False


def _expr_narrows_posture(
    expr: ast.expr,
    env_vars_in_scope: frozenset[str],
    *,
    negated: bool = False,
) -> bool:
    """Evaluate whether ``expr`` (under De Morgan ``negated`` polarity) narrows posture."""
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return _expr_narrows_posture(
            expr.operand, env_vars_in_scope, negated=not negated
        )
    if isinstance(expr, ast.BoolOp):
        is_effective_and = (isinstance(expr.op, ast.And) and not negated) or (
            isinstance(expr.op, ast.Or) and negated
        )
        if is_effective_and:
            return any(
                _expr_narrows_posture(v, env_vars_in_scope, negated=negated)
                for v in expr.values
            )
        return any(
            _expr_narrows_posture(v, env_vars_in_scope, negated=negated)
            for v in expr.values
        ) and not any(
            _expr_admits_staging(v, env_vars_in_scope, negated=negated)
            for v in expr.values
        )
    if isinstance(expr, ast.Compare):
        return _cmp_narrows_posture(expr, env_vars_in_scope, negated=negated)
    return any(
        _expr_narrows_posture(child, env_vars_in_scope, negated=negated)
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.expr)
    )


def _is_narrowing_if_condition(
    test: ast.expr,
    env_vars_in_scope: frozenset[str],
    *,
    in_orelse: bool = False,
) -> bool:
    """Return True if ``test`` (or ``not test`` when ``in_orelse``) narrows to prod-only."""
    return _expr_narrows_posture(test, env_vars_in_scope, negated=in_orelse)


def _stmts_always_exit_non_raising(stmts: Sequence[ast.stmt]) -> bool:
    """Return True if every path through ``stmts`` exits via return/break/continue (not raise)."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Break, ast.Continue)):
            return True
        if isinstance(stmt, ast.Raise):
            return False
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _stmts_always_exit_non_raising(stmt.body)
                and _stmts_always_exit_non_raising(stmt.orelse)
            ):
                return True
            if any(isinstance(sub, ast.Raise) for sub in _iter_scope_nodes(stmt)):
                return False
    return False


def _stmts_always_exit(stmts: Sequence[ast.stmt]) -> bool:
    """Return True if every path through ``stmts`` exits via return/break/continue/raise."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Break, ast.Continue, ast.Raise)):
            return True
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _stmts_always_exit(stmt.body)
                and _stmts_always_exit(stmt.orelse)
            ):
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


def _audit_rule_b_expr(
    expr: ast.AST,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
    cls_name: str | None,
    enclosing_ifs: tuple[tuple[ast.If | ast.IfExp, bool, bool], ...],
    env_vars: frozenset[str],
) -> None:
    """Audit calls inside an expression for Rule B (including inline ``IfExp``)."""
    if isinstance(expr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    if isinstance(expr, ast.IfExp):
        _audit_rule_b_expr(
            expr.test,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
            cls_name=cls_name,
            enclosing_ifs=enclosing_ifs,
            env_vars=env_vars,
        )
        _audit_rule_b_expr(
            expr.body,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
            cls_name=cls_name,
            enclosing_ifs=(*enclosing_ifs, (expr, False, False)),
            env_vars=env_vars,
        )
        _audit_rule_b_expr(
            expr.orelse,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
            cls_name=cls_name,
            enclosing_ifs=(*enclosing_ifs, (expr, True, False)),
            env_vars=env_vars,
        )
        return

    if isinstance(expr, ast.Call):
        matched_display: str | None = None
        for key, display in _resolve_call_candidates(
            expr, alias_map, cls_name, top_func_names
        ):
            if key in broad_enforcing_guards:
                matched_display = display
                break
        if matched_display is not None:
            for if_node, in_orelse, is_early_exit in enclosing_ifs:
                if _is_narrowing_if_condition(
                    if_node.test, env_vars, in_orelse=in_orelse
                ):
                    kind = (
                        "early-exit guard"
                        if is_early_exit
                        else "enclosing if-condition"
                    )
                    v = PostureGuardViolation(
                        rule="Rule B (caller-narrowed posture guard)",
                        file_path=file_label,
                        line_number=if_node.lineno,
                        end_line_number=expr.lineno,
                        target=matched_display,
                        detail=(
                            f"{kind} at line {if_node.lineno} "
                            f"narrows {matched_display} below full enforcing posture scope"
                        ),
                    )
                    violations.append(v)
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")
                    break

    for child in ast.iter_child_nodes(expr):
        _audit_rule_b_expr(
            child,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
            cls_name=cls_name,
            enclosing_ifs=enclosing_ifs,
            env_vars=env_vars,
        )


def _walk_rule_b_stmts(
    stmts: Sequence[ast.stmt],
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
    cls_name: str | None = None,
    enclosing_ifs: tuple[tuple[ast.If | ast.IfExp, bool, bool], ...] = (),
    env_vars: frozenset[str] = frozenset(),
) -> None:
    """Audit an ordered statement block for Rule B, propagating early-exit guards."""
    local_env_vars = set(env_vars)
    for stmt in stmts:
        if isinstance(stmt, ast.Assign) and _has_posture_signal(
            ast.Module(body=[stmt], type_ignores=[])
        ):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    local_env_vars.add(target.id)
        elif (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and isinstance(stmt.target, ast.Name)
            and _has_posture_signal(ast.Module(body=[stmt], type_ignores=[]))
        ):
            local_env_vars.add(stmt.target.id)

    active_ifs: list[tuple[ast.If | ast.IfExp, bool, bool]] = list(enclosing_ifs)

    for stmt in stmts:
        frozen_vars = frozenset(local_env_vars)
        current_ifs = tuple(active_ifs)

        if isinstance(stmt, ast.ClassDef):
            for dec in stmt.decorator_list:
                _audit_rule_b_expr(
                    dec,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )
            _walk_rule_b_stmts(
                stmt.body,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=stmt.name,
                enclosing_ifs=(),
                env_vars=frozen_vars,
            )
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in stmt.decorator_list:
                _audit_rule_b_expr(
                    dec,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )
            _walk_rule_b_stmts(
                stmt.body,
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
        elif isinstance(stmt, ast.If):
            _audit_rule_b_expr(
                stmt.test,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=current_ifs,
                env_vars=frozen_vars,
            )
            _walk_rule_b_stmts(
                stmt.body,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=(*current_ifs, (stmt, False, False)),
                env_vars=frozen_vars,
            )
            if stmt.orelse:
                _walk_rule_b_stmts(
                    stmt.orelse,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=(*current_ifs, (stmt, True, False)),
                    env_vars=frozen_vars,
                )
            if _stmts_always_exit_non_raising(stmt.body) and not _stmts_always_exit(
                stmt.orelse
            ):
                active_ifs.append((stmt, True, True))
            elif (
                stmt.orelse
                and _stmts_always_exit_non_raising(stmt.orelse)
                and not _stmts_always_exit(stmt.body)
            ):
                active_ifs.append((stmt, False, True))
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            _audit_rule_b_expr(
                stmt.iter,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=current_ifs,
                env_vars=frozen_vars,
            )
            for block in (stmt.body, stmt.orelse):
                if block:
                    _walk_rule_b_stmts(
                        block,
                        file_label=file_label,
                        alias_map=alias_map,
                        top_func_names=top_func_names,
                        broad_enforcing_guards=broad_enforcing_guards,
                        violations=violations,
                        verbose=verbose,
                        cls_name=cls_name,
                        enclosing_ifs=current_ifs,
                        env_vars=frozen_vars,
                    )
        elif isinstance(stmt, ast.While):
            _audit_rule_b_expr(
                stmt.test,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=current_ifs,
                env_vars=frozen_vars,
            )
            for block in (stmt.body, stmt.orelse):
                if block:
                    _walk_rule_b_stmts(
                        block,
                        file_label=file_label,
                        alias_map=alias_map,
                        top_func_names=top_func_names,
                        broad_enforcing_guards=broad_enforcing_guards,
                        violations=violations,
                        verbose=verbose,
                        cls_name=cls_name,
                        enclosing_ifs=current_ifs,
                        env_vars=frozen_vars,
                    )
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                _audit_rule_b_expr(
                    item.context_expr,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )
            _walk_rule_b_stmts(
                stmt.body,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=current_ifs,
                env_vars=frozen_vars,
            )
        elif isinstance(stmt, ast.Try):
            for block in (stmt.body, stmt.orelse, stmt.finalbody):
                if block:
                    _walk_rule_b_stmts(
                        block,
                        file_label=file_label,
                        alias_map=alias_map,
                        top_func_names=top_func_names,
                        broad_enforcing_guards=broad_enforcing_guards,
                        violations=violations,
                        verbose=verbose,
                        cls_name=cls_name,
                        enclosing_ifs=current_ifs,
                        env_vars=frozen_vars,
                    )
            for handler in stmt.handlers:
                _walk_rule_b_stmts(
                    handler.body,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )
        elif isinstance(stmt, ast.Match):
            _audit_rule_b_expr(
                stmt.subject,
                file_label=file_label,
                alias_map=alias_map,
                top_func_names=top_func_names,
                broad_enforcing_guards=broad_enforcing_guards,
                violations=violations,
                verbose=verbose,
                cls_name=cls_name,
                enclosing_ifs=current_ifs,
                env_vars=frozen_vars,
            )
            for case in stmt.cases:
                _walk_rule_b_stmts(
                    case.body,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )
        else:
            for child in ast.iter_child_nodes(stmt):
                _audit_rule_b_expr(
                    child,
                    file_label=file_label,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    broad_enforcing_guards=broad_enforcing_guards,
                    violations=violations,
                    verbose=verbose,
                    cls_name=cls_name,
                    enclosing_ifs=current_ifs,
                    env_vars=frozen_vars,
                )


def _walk_rule_b(
    tree: ast.Module,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
) -> None:
    """Audit ``tree`` for Rule B (enclosing and early-return posture narrowing)."""
    _walk_rule_b_stmts(
        tree.body,
        file_label=file_label,
        alias_map=alias_map,
        top_func_names=top_func_names,
        broad_enforcing_guards=broad_enforcing_guards,
        violations=violations,
        verbose=verbose,
    )


# ---------------------------------------------------------------------------
# Rule C: Middleware threshold/bound guard fallthrough to downstream dispatch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _MiddlewareSpec:
    """Recognized ASGI or HTTP middleware entrypoint and its downstream targets."""

    cls_name: str | None
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef
    self_param: str | None
    asgi_app_attrs: frozenset[str]
    call_next_param: str | None


def _extract_init_app_attrs(cls_node: ast.ClassDef) -> set[str]:
    """Extract ``self.<attr>`` names assigned from ``__init__``'s first argument."""
    attrs: set[str] = set()
    for item in cls_node.body:
        if (
            not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            or item.name != "__init__"
        ):
            continue
        params = [a.arg for a in (*item.args.posonlyargs, *item.args.args)]
        if len(params) < 2:
            continue
        self_name, app_param = params[0], params[1]
        for sub in _iter_scope_nodes(item):
            if (
                isinstance(sub, ast.Assign)
                and isinstance(sub.value, ast.Name)
                and sub.value.id == app_param
            ):
                for target in sub.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == self_name
                    ):
                        attrs.add(target.attr)
    return attrs


def _iter_middleware_specs(tree: ast.Module) -> Iterator[_MiddlewareSpec]:
    """Yield all recognized ASGI and HTTP middleware handlers in ``tree``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            init_attrs = _extract_init_app_attrs(node)
            has_middleware_base = any(
                "Middleware" in ast.unparse(base) for base in node.bases
            )
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = [
                    a.arg
                    for a in (
                        *item.args.posonlyargs,
                        *item.args.args,
                        *item.args.kwonlyargs,
                    )
                ]
                if item.name == "__call__" and {"scope", "receive", "send"} <= set(
                    params
                ):
                    self_param = params[0] if params else "self"
                    yield _MiddlewareSpec(
                        cls_name=node.name,
                        fn_node=item,
                        self_param=self_param,
                        asgi_app_attrs=frozenset(DEFAULT_ASGI_APP_ATTRS | init_attrs),
                        call_next_param=None,
                    )
                elif (
                    item.name == "dispatch"
                    and len(params) >= 3
                    and (
                        has_middleware_base
                        or params[2] in ("call_next", "next_handler")
                    )
                ):
                    yield _MiddlewareSpec(
                        cls_name=node.name,
                        fn_node=item,
                        self_param=params[0],
                        asgi_app_attrs=frozenset(),
                        call_next_param=params[2],
                    )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_http_mw_decorator = any(
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "middleware"
                for dec in node.decorator_list
            )
            params = [a.arg for a in (*node.args.posonlyargs, *node.args.args)]
            if is_http_mw_decorator and len(params) >= 2:
                yield _MiddlewareSpec(
                    cls_name=None,
                    fn_node=node,
                    self_param=None,
                    asgi_app_attrs=frozenset(),
                    call_next_param=params[1],
                )


def _is_downstream_dispatch_call(call: ast.Call, spec: _MiddlewareSpec) -> bool:
    """Return True when ``call`` invokes downstream ``self.app(...)`` / ``call_next(...)``."""
    func = call.func
    if (
        spec.self_param is not None
        and spec.asgi_app_attrs
        and isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == spec.self_param
        and func.attr in spec.asgi_app_attrs
    ):
        return True
    if (
        spec.call_next_param is not None
        and isinstance(func, ast.Name)
        and func.id == spec.call_next_param
    ):
        return True
    return False


def _stmts_contain_downstream(
    stmts: Sequence[ast.stmt],
    spec: _MiddlewareSpec,
) -> bool:
    """Return True if ``stmts`` contain a downstream middleware dispatch call."""
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Call) and _is_downstream_dispatch_call(stmt, spec):
            return True
        for sub in _iter_scope_nodes(stmt):
            if isinstance(sub, ast.Call) and _is_downstream_dispatch_call(sub, spec):
                return True
    return False


def _stmts_terminate_request_without_downstream(
    stmts: Sequence[ast.stmt],
    spec: _MiddlewareSpec,
) -> bool:
    """Return True if ``stmts`` always exit the handler (return/raise) without calling downstream."""
    if not stmts or _stmts_contain_downstream(stmts, spec):
        return False
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return True
        if isinstance(stmt, (ast.Break, ast.Continue)):
            return False
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _stmts_terminate_request_without_downstream(stmt.body, spec)
                and _stmts_terminate_request_without_downstream(stmt.orelse, spec)
            ):
                return True
    return False


def _extract_bound_comparisons(expr: ast.expr) -> list[ast.Compare]:
    """Return ``ast.Compare`` nodes in ``expr`` that use ``<``, ``<=``, ``>``, or ``>=``."""
    return [
        sub
        for sub in ast.walk(expr)
        if isinstance(sub, ast.Compare)
        and any(isinstance(op, BOUND_COMPARE_OPS) for op in sub.ops)
    ]


def _expr_identifiers(expr: ast.AST) -> set[str]:
    """Extract variable and attribute identifiers referenced in ``expr``."""
    ids: set[str] = set()
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Name) and sub.id not in IGNORED_BOUND_IDENTIFIERS:
            ids.add(sub.id)
        elif (
            isinstance(sub, ast.Attribute) and sub.attr not in IGNORED_BOUND_IDENTIFIERS
        ):
            ids.add(sub.attr)
    return ids


def _find_middleware_guard_calls(
    stmts: Sequence[ast.stmt],
    *,
    spec: _MiddlewareSpec,
    alias_map: dict[str, str],
    top_func_names: set[str],
    posture_raising_targets: set[str],
    broad_enforcing_guards: set[str],
) -> list[tuple[ast.Call, str]]:
    """Return ``(call_node, display_name)`` for security guard calls in ``stmts``."""
    found: list[tuple[ast.Call, str]] = []
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nodes = [stmt, *_iter_scope_nodes(stmt)]
        for sub in nodes:
            if not isinstance(sub, ast.Call) or _is_downstream_dispatch_call(sub, spec):
                continue
            raw_name: str | None = None
            if isinstance(sub.func, ast.Name):
                raw_name = alias_map.get(sub.func.id, sub.func.id)
            elif isinstance(sub.func, ast.Attribute):
                raw_name = sub.func.attr

            matched_display: str | None = None
            for key, display in _resolve_call_candidates(
                sub, alias_map, spec.cls_name, top_func_names
            ):
                if key in posture_raising_targets or key in broad_enforcing_guards:
                    matched_display = display
                    break
            if (
                matched_display is None
                and raw_name is not None
                and raw_name.startswith(GUARD_PREFIXES)
            ):
                matched_display = f"{raw_name}()"
            if matched_display is not None:
                found.append((sub, matched_display))
    return found


def _collect_request_terminating_if_ids(
    stmts: Sequence[ast.stmt],
    spec: _MiddlewareSpec,
) -> set[str]:
    """Collect identifiers tested by ``if`` guards in ``stmts`` that return/raise without downstream."""
    rejected: set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for sub in [stmt, *_iter_scope_nodes(stmt)]:
            if not isinstance(sub, ast.If):
                continue
            if _stmts_terminate_request_without_downstream(
                sub.body, spec
            ) and not _stmts_always_exit(sub.orelse):
                rejected |= _expr_identifiers(sub.test)
            elif (
                sub.orelse
                and _stmts_terminate_request_without_downstream(sub.orelse, spec)
                and not _stmts_always_exit(sub.body)
            ):
                rejected |= _expr_identifiers(sub.test)
    return rejected


def _audit_middleware_spec(
    spec: _MiddlewareSpec,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    posture_raising_targets: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    verbose: bool,
) -> None:
    """Audit a single middleware handler for Rule C bound-gated guard fallthrough."""
    stmts = spec.fn_node.body
    if not _stmts_contain_downstream(stmts, spec):
        return

    rejected_ids: set[str] = set()
    flagged_if_nodes: set[int] = set()

    for idx, stmt in enumerate(stmts):
        later_stmts = stmts[idx + 1 :]

        if isinstance(stmt, ast.If):
            bound_cmps = _extract_bound_comparisons(stmt.test)
            if bound_cmps:
                body_guards = _find_middleware_guard_calls(
                    stmt.body,
                    spec=spec,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    posture_raising_targets=posture_raising_targets,
                    broad_enforcing_guards=broad_enforcing_guards,
                )
                orelse_guards = _find_middleware_guard_calls(
                    stmt.orelse,
                    spec=spec,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    posture_raising_targets=posture_raising_targets,
                    broad_enforcing_guards=broad_enforcing_guards,
                )
                later_guards = _find_middleware_guard_calls(
                    later_stmts,
                    spec=spec,
                    alias_map=alias_map,
                    top_func_names=top_func_names,
                    posture_raising_targets=posture_raising_targets,
                    broad_enforcing_guards=broad_enforcing_guards,
                )

                # Shape C3: Bound-gated early dispatch (`if size > MAX: return await call_next(...)`)
                # ahead of a security guard in the complement or subsequent statements.
                if _stmts_contain_downstream(stmt.body, spec) and (
                    orelse_guards or later_guards
                ):
                    guard_call, guard_display = (orelse_guards or later_guards)[0]
                    v = PostureGuardViolation(
                        rule="Rule C (middleware bound-gated guard fallthrough)",
                        file_path=file_label,
                        line_number=stmt.lineno,
                        end_line_number=max(stmt.lineno, guard_call.lineno),
                        target=guard_display,
                        detail=(
                            f"threshold condition at line {stmt.lineno} dispatches to "
                            f"downstream handler bypassing {guard_display}"
                        ),
                    )
                    violations.append(v)
                    flagged_if_nodes.add(id(stmt))
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")
                elif (
                    stmt.orelse
                    and _stmts_contain_downstream(stmt.orelse, spec)
                    and (body_guards or later_guards)
                ):
                    guard_call, guard_display = (body_guards or later_guards)[0]
                    v = PostureGuardViolation(
                        rule="Rule C (middleware bound-gated guard fallthrough)",
                        file_path=file_label,
                        line_number=stmt.lineno,
                        end_line_number=max(stmt.lineno, guard_call.lineno),
                        target=guard_display,
                        detail=(
                            f"threshold else-branch at line {stmt.lineno} dispatches to "
                            f"downstream handler bypassing {guard_display}"
                        ),
                    )
                    violations.append(v)
                    flagged_if_nodes.add(id(stmt))
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")

                # Shape C1: Bound-gated `if` wrapping a security guard whose complement
                # falls through to downstream dispatch without failing closed.
                elif (
                    body_guards
                    and _stmts_contain_downstream(later_stmts, spec)
                    and not _stmts_terminate_request_without_downstream(
                        stmt.orelse, spec
                    )
                ):
                    unrejected = any(
                        not (_expr_identifiers(cmp_node) <= rejected_ids)
                        for cmp_node in bound_cmps
                    )
                    if unrejected:
                        guard_call, guard_display = body_guards[0]
                        v = PostureGuardViolation(
                            rule="Rule C (middleware bound-gated guard fallthrough)",
                            file_path=file_label,
                            line_number=stmt.lineno,
                            end_line_number=guard_call.lineno,
                            target=guard_display,
                            detail=(
                                f"threshold condition at line {stmt.lineno} gates "
                                f"{guard_display} without failing closed when bound is "
                                f"exceeded before downstream dispatch"
                            ),
                        )
                        violations.append(v)
                        flagged_if_nodes.add(id(stmt))
                        if verbose:
                            print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")
                elif (
                    orelse_guards
                    and _stmts_contain_downstream(later_stmts, spec)
                    and not _stmts_terminate_request_without_downstream(stmt.body, spec)
                ):
                    unrejected = any(
                        not (_expr_identifiers(cmp_node) <= rejected_ids)
                        for cmp_node in bound_cmps
                    )
                    if unrejected:
                        guard_call, guard_display = orelse_guards[0]
                        v = PostureGuardViolation(
                            rule="Rule C (middleware bound-gated guard fallthrough)",
                            file_path=file_label,
                            line_number=stmt.lineno,
                            end_line_number=guard_call.lineno,
                            target=guard_display,
                            detail=(
                                f"threshold condition at line {stmt.lineno} skips "
                                f"{guard_display} without failing closed before "
                                f"downstream dispatch"
                            ),
                        )
                        violations.append(v)
                        flagged_if_nodes.add(id(stmt))
                        if verbose:
                            print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")

            rejected_ids |= _collect_request_terminating_if_ids([stmt], spec)

        elif isinstance(stmt, ast.While):
            rejected_ids |= _collect_request_terminating_if_ids(stmt.body, spec)
            loop_bound_cmps = _extract_bound_comparisons(stmt.test)
            if not loop_bound_cmps:
                continue

            loop_assigned_names: set[str] = set()
            loop_bool_flags: set[str] = set()
            for sub in _iter_scope_nodes(stmt):
                if isinstance(sub, ast.Assign):
                    is_bool_const = isinstance(sub.value, ast.Constant) and isinstance(
                        sub.value.value, bool
                    )
                    for t in sub.targets:
                        if isinstance(t, ast.Name):
                            loop_assigned_names.add(t.id)
                            if is_bool_const:
                                loop_bool_flags.add(t.id)
                elif isinstance(sub, ast.AugAssign) and isinstance(
                    sub.target, ast.Name
                ):
                    loop_assigned_names.add(sub.target.id)

            # Shape C2: Bounded `while` buffering loop preceding a conditional guard
            # that reaches downstream dispatch without rejecting over-bound inputs.
            post_loop_rejected = set(rejected_ids)
            for offset, next_stmt in enumerate(later_stmts):
                remaining = later_stmts[offset + 1 :]
                if isinstance(next_stmt, ast.If):
                    next_guards = _find_middleware_guard_calls(
                        next_stmt.body,
                        spec=spec,
                        alias_map=alias_map,
                        top_func_names=top_func_names,
                        posture_raising_targets=posture_raising_targets,
                        broad_enforcing_guards=broad_enforcing_guards,
                    )
                    if (
                        next_guards
                        and _stmts_contain_downstream(remaining, spec)
                        and not _stmts_terminate_request_without_downstream(
                            next_stmt.orelse, spec
                        )
                    ):
                        # Defer to Shape C1 if next_stmt itself carries the unrejected bound.
                        next_has_own_unrejected_bound = any(
                            not (_expr_identifiers(c) <= post_loop_rejected)
                            for c in _extract_bound_comparisons(next_stmt.test)
                        )
                        tested_loop_flags = (
                            _expr_identifiers(next_stmt.test) & loop_assigned_names
                        )
                        bound_covered = (
                            all(
                                _expr_identifiers(c) <= post_loop_rejected
                                for c in loop_bound_cmps
                            )
                            or bool(tested_loop_flags & post_loop_rejected)
                            or bool(loop_bool_flags & post_loop_rejected)
                        )
                        if (
                            not bound_covered
                            and not next_has_own_unrejected_bound
                            and id(next_stmt) not in flagged_if_nodes
                        ):
                            guard_call, guard_display = next_guards[0]
                            v = PostureGuardViolation(
                                rule="Rule C (middleware bound-gated guard fallthrough)",
                                file_path=file_label,
                                line_number=stmt.lineno,
                                end_line_number=guard_call.lineno,
                                target=guard_display,
                                detail=(
                                    f"bounded while-loop at line {stmt.lineno} feeds "
                                    f"conditional guard {guard_display} without failing "
                                    f"closed when bound is exceeded before downstream dispatch"
                                ),
                            )
                            violations.append(v)
                            flagged_if_nodes.add(id(next_stmt))
                            if verbose:
                                print(
                                    f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}"
                                )
                        break
                    post_loop_rejected |= _collect_request_terminating_if_ids(
                        [next_stmt], spec
                    )
        else:
            rejected_ids |= _collect_request_terminating_if_ids([stmt], spec)


THIRD_PARTY_MIDDLEWARE_PACKAGES: frozenset[str] = frozenset(
    {"fastapi", "starlette", "uvicorn", "opentelemetry", "asgi_correlation_id"}
)


def _collect_third_party_middleware_imports(tree: ast.Module) -> set[str]:
    """Return imported symbol/module names originating from external ASGI frameworks."""
    external: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top_pkg = node.module.split(".", 1)[0]
            if top_pkg in THIRD_PARTY_MIDDLEWARE_PACKAGES:
                for alias in node.names:
                    external.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top_pkg = alias.name.split(".", 1)[0]
                if top_pkg in THIRD_PARTY_MIDDLEWARE_PACKAGES:
                    external.add(alias.asname or top_pkg)
    return external


def _walk_rule_c(
    tree: ast.Module,
    *,
    file_label: str,
    alias_map: dict[str, str],
    top_func_names: set[str],
    posture_raising_targets: set[str],
    broad_enforcing_guards: set[str],
    violations: list[PostureGuardViolation],
    recognized_classes: set[str],
    recognized_funcs: set[tuple[str, str, int]],
    verbose: bool,
) -> int:
    """Audit middleware handlers in ``tree`` for Rule C and record recognized targets."""
    count = 0
    for spec in _iter_middleware_specs(tree):
        count += 1
        if spec.cls_name is not None:
            recognized_classes.add(spec.cls_name)
        else:
            recognized_funcs.add((file_label, spec.fn_node.name, spec.fn_node.lineno))
        _audit_middleware_spec(
            spec,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            posture_raising_targets=posture_raising_targets,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            verbose=verbose,
        )
    return count


def _cross_check_middleware_inventory(
    parsed_modules: Sequence[tuple[str, ast.Module]],
    *,
    module_aliases: dict[str, dict[str, str]],
    corpus_defined_classes: set[str],
    recognized_classes: set[str],
    recognized_funcs: set[tuple[str, str, int]],
    violations: list[PostureGuardViolation],
    verbose: bool,
) -> None:
    """Cross-check Rule C handler detection against independent middleware declarations/registrations.

    Ensures a newly added ``*Middleware`` / ``BaseHTTPMiddleware`` class,
    in-tree ``add_middleware(...)`` target, or ``@*.middleware(...)`` function
    whose signature is missed by ``_iter_middleware_specs`` fails closed instead
    of escaping audit while existing handlers satisfy the numeric floor.
    """
    flagged_class_defs: set[tuple[str, str]] = set()
    for file_label, tree in parsed_modules:
        alias_map = module_aliases[file_label]
        third_party_imports = _collect_third_party_middleware_imports(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                is_named_or_subclassed_mw = node.name.endswith("Middleware") or any(
                    "Middleware" in ast.unparse(base) for base in node.bases
                )
                if (
                    is_named_or_subclassed_mw
                    and node.name not in recognized_classes
                    and (file_label, node.name) not in flagged_class_defs
                ):
                    flagged_class_defs.add((file_label, node.name))
                    v = PostureGuardViolation(
                        rule="Rule C (unrecognized middleware registration)",
                        file_path=file_label,
                        line_number=node.lineno,
                        end_line_number=node.lineno,
                        target=node.name,
                        detail=(
                            f"middleware class {node.name} at line {node.lineno} was "
                            f"not matched by Rule C handler signature detector"
                        ),
                    )
                    violations.append(v)
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")

            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_middleware"
                and node.args
            ):
                arg0 = node.args[0]
                raw_name: str | None = None
                is_external = False
                if isinstance(arg0, ast.Name):
                    raw_name = alias_map.get(arg0.id, arg0.id)
                    if (
                        raw_name not in corpus_defined_classes
                        and arg0.id in third_party_imports
                    ):
                        is_external = True
                elif isinstance(arg0, ast.Attribute):
                    raw_name = arg0.attr
                    if (
                        raw_name not in corpus_defined_classes
                        and isinstance(arg0.value, ast.Name)
                        and arg0.value.id in third_party_imports
                    ):
                        is_external = True
                if (
                    raw_name is not None
                    and not is_external
                    and raw_name not in recognized_classes
                ):
                    v = PostureGuardViolation(
                        rule="Rule C (unrecognized middleware registration)",
                        file_path=file_label,
                        line_number=node.lineno,
                        end_line_number=node.lineno,
                        target=f"add_middleware({raw_name})",
                        detail=(
                            f"add_middleware({raw_name}) at line {node.lineno} registers "
                            f"a class not matched by Rule C handler signature detector"
                        ),
                    )
                    violations.append(v)
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_mw_decorated = any(
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "middleware"
                    for dec in node.decorator_list
                )
                if (
                    is_mw_decorated
                    and (file_label, node.name, node.lineno) not in recognized_funcs
                ):
                    v = PostureGuardViolation(
                        rule="Rule C (unrecognized middleware registration)",
                        file_path=file_label,
                        line_number=node.lineno,
                        end_line_number=node.lineno,
                        target=f"{node.name}()",
                        detail=(
                            f"@middleware function {node.name}() at line {node.lineno} "
                            f"was not matched by Rule C handler signature detector"
                        ),
                    )
                    violations.append(v)
                    if verbose:
                        print(f"❌ {v.format_line_span()} [{v.rule}]: {v.detail}")


def _analyze_parsed_modules(
    parsed_modules: Sequence[tuple[str, ast.Module]],
    *,
    verbose: bool = False,
) -> tuple[list[PostureGuardViolation], int, int, int, int]:
    """Run two-pass Rule A, Rule B, and Rule C analysis over ``parsed_modules``."""
    posture_raising_targets: set[str] = set()
    broad_enforcing_guards: set[str] = set()
    top_level_funcs: dict[
        str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    class_methods: dict[
        tuple[str, str], list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    module_aliases: dict[str, dict[str, str]] = {}
    corpus_defined_classes: set[str] = set()

    # Pass 1: Index posture-gated raising functions/methods, broad enforcing guards,
    # and all in-tree class definitions across the scanned corpus.
    for file_label, tree in parsed_modules:
        module_aliases[file_label] = _build_import_aliases(tree)
        for walked in ast.walk(tree):
            if isinstance(walked, ast.ClassDef):
                corpus_defined_classes.add(walked.name)
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

    top_func_names = set(top_level_funcs)
    violations: list[PostureGuardViolation] = []
    recognized_mw_classes: set[str] = set()
    recognized_mw_funcs: set[tuple[str, str, int]] = set()
    middleware_count = 0

    # Pass 2: Audit all call sites and middleware handlers for Rules A, B, and C.
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
        middleware_count += _walk_rule_c(
            tree,
            file_label=file_label,
            alias_map=alias_map,
            top_func_names=top_func_names,
            posture_raising_targets=posture_raising_targets,
            broad_enforcing_guards=broad_enforcing_guards,
            violations=violations,
            recognized_classes=recognized_mw_classes,
            recognized_funcs=recognized_mw_funcs,
            verbose=verbose,
        )

    _cross_check_middleware_inventory(
        parsed_modules,
        module_aliases=module_aliases,
        corpus_defined_classes=corpus_defined_classes,
        recognized_classes=recognized_mw_classes,
        recognized_funcs=recognized_mw_funcs,
        violations=violations,
        verbose=verbose,
    )

    if verbose:
        print(
            f"📊 Indexed {len(posture_raising_targets)} posture-gated raising targets, "
            f"{len(broad_enforcing_guards)} broad enforcing guard keys, and "
            f"{middleware_count} middleware handlers across {len(parsed_modules)} files."
        )

    return (
        violations,
        len(parsed_modules),
        len(posture_raising_targets),
        len(broad_enforcing_guards),
        middleware_count,
    )


def scan_tree_with_stats(
    root: Path = SRC_ROOT,
    *,
    verbose: bool = False,
) -> tuple[list[PostureGuardViolation], int, int, int, int]:
    """Scan ``*.py`` files under ``root`` and return violations plus corpus counts."""
    py_files = sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    parsed: list[tuple[str, ast.Module]] = []
    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        parsed.append((py_file.as_posix(), tree))
    return _analyze_parsed_modules(parsed, verbose=verbose)


def scan_tree(
    root: Path = SRC_ROOT,
    *,
    verbose: bool = False,
) -> list[PostureGuardViolation]:
    """Scan all ``*.py`` files under ``root`` for Rule A, Rule B, and Rule C violations."""
    violations, _, _, _, _ = scan_tree_with_stats(root, verbose=verbose)
    return violations


def scan_source(
    source: str,
    *,
    filename: str = "<synthetic>",
    verbose: bool = False,
) -> list[PostureGuardViolation]:
    """Scan a synthetic Python source snippet for Rule A, Rule B, and Rule C violations."""
    tree = ast.parse(source, filename=filename)
    violations, _, _, _, _ = _analyze_parsed_modules(
        [(filename, tree)], verbose=verbose
    )
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify posture-gated startup guards and middleware security guards "
            "fail closed across their full declared scope."
        )
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
        default=None,
        help="Root directory of Python sources to scan (default: <repo>/src).",
    )
    parser.add_argument(
        "--min-files",
        type=int,
        default=None,
        help="Minimum Python files expected in scanned corpus.",
    )
    parser.add_argument(
        "--min-raising-targets",
        type=int,
        default=None,
        help="Minimum posture-gated raising targets expected in scanned corpus.",
    )
    parser.add_argument(
        "--min-broad-guards",
        type=int,
        default=None,
        help="Minimum broad enforcing guards expected in scanned corpus.",
    )
    parser.add_argument(
        "--min-middleware-handlers",
        type=int,
        default=None,
        help="Minimum ASGI/HTTP middleware handlers expected in scanned corpus.",
    )
    args = parser.parse_args(argv)

    default_repo_scan = args.root is None
    scan_root = SRC_ROOT if default_repo_scan else args.root
    min_files = (
        args.min_files
        if args.min_files is not None
        else (MIN_EXPECTED_REPO_FILES if default_repo_scan else 1)
    )
    min_raising = (
        args.min_raising_targets
        if args.min_raising_targets is not None
        else (MIN_EXPECTED_RAISING_TARGETS if default_repo_scan else 0)
    )
    min_broad = (
        args.min_broad_guards
        if args.min_broad_guards is not None
        else (MIN_EXPECTED_BROAD_GUARDS if default_repo_scan else 0)
    )
    min_middleware = (
        args.min_middleware_handlers
        if args.min_middleware_handlers is not None
        else (MIN_EXPECTED_MIDDLEWARE_HANDLERS if default_repo_scan else 0)
    )

    print(
        "🔍 Checking posture & middleware guard integrity (Rule A + Rule B + Rule C)..."
    )
    if not scan_root.exists():
        print(f"❌ Source root not found: {scan_root}")
        return 1

    violations, file_count, raising_count, broad_count, middleware_count = (
        scan_tree_with_stats(scan_root, verbose=args.verbose)
    )
    corpus_failures: list[str] = []
    if file_count < min_files:
        corpus_failures.append(
            f"scanned Python files {file_count} < minimum expected {min_files}"
        )
    if raising_count < min_raising:
        corpus_failures.append(
            f"recognized posture-raising targets {raising_count} < minimum expected {min_raising}"
        )
    if broad_count < min_broad:
        corpus_failures.append(
            f"recognized broad enforcing guards {broad_count} < minimum expected {min_broad}"
        )
    if middleware_count < min_middleware:
        corpus_failures.append(
            f"recognized middleware handlers {middleware_count} < minimum expected {min_middleware}"
        )
    if corpus_failures:
        print("\n❌ POSTURE GUARD CORPUS FLOOR FAILURE (vacuous/blind parser check):")
        for failure in corpus_failures:
            print(f"  - {failure}")
        return 1

    if violations:
        print(
            f"\n❌ POSTURE GUARD INTEGRITY VIOLATIONS DETECTED ({len(violations)}):\n"
        )
        for v in violations:
            print(f"  {v.format_line_span()} [{v.rule}]")
            print(f"    └─ {v.detail}\n")
        return 1

    print(
        "✅ All posture and middleware security guards fail closed across their full scope."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
