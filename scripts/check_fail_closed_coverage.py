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

"""Scoped fail-closed test reachability gate (``@pytest.mark.covers``).

Prevents short-circuited false-passing fail-closed tests — where an upstream
error or omitted fixture satisfies an assertion (e.g. HTTP ``503`` or a refusal
code) before the named code path executes — from passing silently under
aggregate line/branch coverage.

Two complementary checks run together:

1. **Static discovery & target resolution (default / ``--mode discover``):**
   Pure-stdlib AST pass intended for ``pre-commit`` and ``ci.yml::lint``.

   * Computes the in-scope fail-closed candidate pool dynamically from
     ``compliance/oscal/evidence_claim_census.jsonl`` ``read_back`` citations
     and/or HTTP ``503`` assertions under ``tests/`` (no hand-maintained waiver
     table that drifts).
   * Requires every in-scope candidate test to carry either
     ``@pytest.mark.covers("module:qualname[#anchor]", ...)`` **or**
     ``@pytest.mark.covers_exempt(reason="<category>: <explanation>")``
     (mutually exclusive).
   * Validates **every** ``@pytest.mark.covers`` target across the entire
     ``tests/`` tree against live source AST: rejects missing modules,
     deleted/renamed functions/methods, ambiguous/missing ``#anchor`` strings,
     and non-literal dynamic marker expressions.
   * Rejects stale ``@pytest.mark.covers_exempt`` markers whose reason omits an
     approved category prefix, lacks substance, or sits on a non-candidate test.
   * Finds outcome-normalizing ``except`` fallthrough pairs under ``src/``
     (ordered handlers on the same ``try`` whose tail statements produce
     identical ``return`` / ``raise`` / HTTP ``status_code`` / fallthrough
     outcomes) and enforces a monotonically-decreasing integer baseline
     (``tests/.shadow-except-baseline``). Each uncovered pair should be resolved
     via one of four paths rather than adding exemptions to a table:
     (1) collapse identical-outcome handlers into one ``except`` tuple,
     (2) fold pure-logging differences before identical fallbacks,
     (3) pin security-distinct earlier handlers with an explicit inner-line
     ``@pytest.mark.covers("module:qualname#anchor")`` mark, or
     (4) assert the observable side effect (e.g. ``bundle.errors`` vs
     ``bundle.warnings``) when both branches return the same sentinel.

   .. note::
      The name-token AST scan is a **candidate finder requiring reconciliation,
      not a semantic definition** of "all fail-closed tests". Repository naming
      varies widely (e.g. ``fail_closed`` vs ``fails_closed``, ``refuses`` vs
      ``refusal`` / ``refused``, ``blocked`` vs ``blocks``). The
      ``--reconciliation-report`` output always surfaces unannotated repo-wide
      counts across every token variant so uncovered tests remain visible.

2. **Runtime per-test context verification (``--verify-coverage <path>``):**
   Reads the SQLite ``.coverage`` database written by ``pytest --cov-context=test``
   using **exact string equality** (``WHERE c.context = ?``). It deliberately
   avoids ``coverage.CoverageData.set_query_contexts([raw])``, which treats
   inputs as regular expressions so an unescaped ``|`` in ``nodeid|run`` acts
   as regex alternation and matches every ``|run`` context across the database.

   Supports both ``arc`` tables (``branch = true``) and ``line_bits`` bitmap
   tables (``branch = false``). Only ``|run`` contexts are consulted (never
   ``|setup``, ``|teardown``, or import-time ``""``).
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sqlite3
import sys
import tokenize
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

REPO_ROOT_DEFAULT: Final[Path] = Path(__file__).resolve().parent.parent
CENSUS_REL_PATH: Final[Path] = Path("compliance/oscal/evidence_claim_census.jsonl")
TESTS_REL_DIR: Final[Path] = Path("tests")
SRC_REL_DIR: Final[Path] = Path("src")
SHADOW_EXCEPT_BASELINE_REL_PATH: Final[Path] = Path("tests/.shadow-except-baseline")

# Discovery name tokens (lowercased substring match against test function name).
# Treated as a *candidate finder requiring reconciliation*, never a closed definition.
CANDIDATE_TOKENS: Final[tuple[str, ...]] = (
    "fail_closed",
    "fails_closed",
    "failclosed",
    "refuses",
    "blocked",
    "unavailable",
    "outage",
)

# Broader reconciliation-only tokens surfaced in advisory reports so spelling
# variants remain visible even when outside the active mandatory token set.
RECONCILIATION_TOKENS: Final[tuple[str, ...]] = (
    "fail_closed",
    "fails_closed",
    "failclosed",
    "fail_close",
    "refuses",
    "refusal",
    "refused",
    "blocked",
    "blocks",
    "unavailable",
    "outage",
    "rejects",
    "rejected",
    "denies",
    "denied",
)

APPROVED_EXEMPT_CATEGORIES: Final[tuple[str, ...]] = (
    "non-src-target",
    "subprocess-target",
    "non-hermetic",
    "negative-control",
    "pure-model",
    "omitted-source",
)
MIN_EXEMPT_EXPLANATION_LEN: Final[int] = 12

HERMETIC_MARKERS: Final[frozenset[str]] = frozenset({"local", "unit"})
NON_HERMETIC_MARKERS: Final[frozenset[str]] = frozenset(
    {"integration", "partner_integration", "live_external", "e2e", "chaos", "load"}
)

VALID_SCOPES: Final[tuple[str, ...]] = (
    "holds",
    "holds-and-503",
    "readback",
    "readback-and-503",
    "all",
)
VALID_PARAM_SCOPES: Final[frozenset[str]] = frozenset({"all_params", "any_param"})

TEST_PATH_RE: Final[re.Pattern[str]] = re.compile(r"tests/[A-Za-z0-9_./-]+\.py")

# Base directories searched when mapping a dotted Python module target to a file.
_PACKAGE_ROOTS: Final[tuple[tuple[str, Path], ...]] = (
    ("src.", Path("")),
    ("scripts.", Path("")),
    ("cage_client.", Path("packages/cage-client/src")),
    ("cage_conformance.", Path("packages/cage-conformance/src")),
)


@dataclass(frozen=True)
class CoversTargetSpec:
    """One parsed ``@pytest.mark.covers(...)`` target string."""

    raw: str
    module: str
    qualname: str
    anchor: str | None
    scope: str = "all_params"  # "all_params" | "any_param"
    param_id: str | None = None  # Non-None when attached to pytest.param(..., id=...)


@dataclass(frozen=True)
class ResolvedTarget:
    """Resolved source file and executable line set for a ``CoversTargetSpec``."""

    spec: CoversTargetSpec
    rel_path: Path
    target_lines: frozenset[int]
    resolution_kind: str  # "function_body" | "statement_anchor" | "branch_body_anchor"


@dataclass(frozen=True)
class ExemptAnnotation:
    """Parsed ``@pytest.mark.covers_exempt(reason=...)`` marker."""

    reason: str
    lineno: int


@dataclass
class DiscoveredTest:
    """AST metadata for one collected test function inside ``tests/``."""

    rel_path: str
    class_name: str | None
    func_name: str
    lineno: int
    asserts_503: bool
    matched_tokens: tuple[str, ...]
    selection_markers: frozenset[str]
    is_skipped: bool
    covers_specs: list[CoversTargetSpec] = field(default_factory=list)
    exemptions: list[ExemptAnnotation] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def nodeid(self) -> str:
        if self.class_name:
            return f"{self.rel_path}::{self.class_name}::{self.func_name}"
        return f"{self.rel_path}::{self.func_name}"

    @property
    def is_hermetic(self) -> bool:
        return bool(self.selection_markers & HERMETIC_MARKERS)


@dataclass(frozen=True)
class Violation:
    """One deterministic gate failure."""

    code: str
    nodeid: str
    message: str

    def format_line(self) -> str:
        return f"[{self.code}] {self.nodeid}: {self.message}"


@dataclass(frozen=True)
class ShadowExceptPair:
    """Two ordered ``except`` handlers in the same ``try`` with matching outcomes."""

    rel_path: str
    qualname: str
    earlier_lineno: int
    earlier_end_lineno: int
    earlier_body_lines: frozenset[int]
    earlier_type: str
    later_lineno: int
    later_end_lineno: int
    later_type: str
    outcome: str
    covered_by: tuple[str, ...] = ()

    @property
    def is_covered(self) -> bool:
        return bool(self.covered_by)

    @property
    def location(self) -> str:
        return f"{self.rel_path}:L{self.earlier_lineno}-L{self.later_lineno}"


# ---------------------------------------------------------------------------
# Coverage bitmap decoding (pure stdlib equivalent of coverage.numbits)
# ---------------------------------------------------------------------------


def decode_numbits(blob: bytes) -> set[int]:
    """Decode a ``coverage.py`` little-endian ``line_bits.numbits`` bitmap."""
    lines: set[int] = set()
    for byte_idx, byte_val in enumerate(blob):
        if not byte_val:
            continue
        base = byte_idx * 8
        for bit in range(8):
            if byte_val & (1 << bit):
                lines.add(base + bit)
    return lines


# ---------------------------------------------------------------------------
# OSCAL census ``read_back`` discovery
# ---------------------------------------------------------------------------


def load_census_readback_files(
    repo_root: Path,
    *,
    census_path: Path | None = None,
    verdicts: frozenset[str] | None = None,
) -> set[str]:
    """Extract unique repo-relative ``tests/.../*.py`` paths cited in ``read_back``.

    Fails closed (``FileNotFoundError`` / ``ValueError``) if the census file is
    missing, empty, or contains malformed JSONL so the discovery floor cannot
    silently collapse to zero.
    """
    path = census_path if census_path is not None else (repo_root / CENSUS_REL_PATH)
    if not path.is_file():
        raise FileNotFoundError(
            f"OSCAL evidence claim census missing: {path}. "
            "Cannot compute read_back candidate scope."
        )
    raw_lines = [
        ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    if not raw_lines:
        raise ValueError(f"OSCAL evidence claim census is empty: {path}")

    files: set[str] = set()
    for idx, line in enumerate(raw_lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSONL at {path}:{idx}: {exc}") from exc
        if not isinstance(row, dict):
            continue
        if verdicts is not None and row.get("verdict") not in verdicts:
            continue
        rb = row.get("read_back")
        if rb is None:
            continue
        rb_text = rb if isinstance(rb, str) else json.dumps(rb, sort_keys=True)
        for hit in TEST_PATH_RE.findall(rb_text):
            files.add(hit)
    if not files:
        raise ValueError(
            f"Zero test files found in `read_back` field of {path} (verdicts={verdicts})"
        )
    return files


# ---------------------------------------------------------------------------
# Module + AST target parsing and line-set resolution
# ---------------------------------------------------------------------------


def parse_target_string(
    raw: str,
    *,
    scope: str = "all_params",
    param_id: str | None = None,
) -> CoversTargetSpec:
    """Parse ``"module:qualname"`` or ``"module:qualname#anchor"``."""
    stripped = raw.strip()
    if not stripped or ":" not in stripped:
        raise ValueError(
            f"Invalid covers target {raw!r}: expected 'module:qualname' or 'module:qualname#anchor'"
        )
    module_part, rest = stripped.split(":", 1)
    if not module_part or not rest:
        raise ValueError(
            f"Invalid covers target {raw!r}: module and qualname must both be non-empty"
        )
    if "#" in rest:
        qualname, anchor = rest.split("#", 1)
        if not anchor:
            raise ValueError(f"Invalid covers target {raw!r}: empty anchor after '#'")
    else:
        qualname, anchor = rest, None
    if not qualname or not all(seg.isidentifier() for seg in qualname.split(".")):
        raise ValueError(f"Invalid qualname {qualname!r} in covers target {raw!r}")
    if not all(seg.isidentifier() for seg in module_part.split(".")):
        raise ValueError(
            f"Invalid module name {module_part!r} in covers target {raw!r}"
        )
    if scope not in VALID_PARAM_SCOPES:
        raise ValueError(
            f"Invalid covers scope {scope!r}; expected one of {sorted(VALID_PARAM_SCOPES)}"
        )
    return CoversTargetSpec(
        raw=stripped,
        module=module_part,
        qualname=qualname,
        anchor=anchor,
        scope=scope,
        param_id=param_id,
    )


def resolve_module_path(repo_root: Path, module: str) -> Path:
    """Resolve a dotted module path to a repo-relative ``.py`` file."""
    base_dir = Path("")
    matched_prefix = False
    for prefix, pkg_root in _PACKAGE_ROOTS:
        if module == prefix.rstrip(".") or module.startswith(prefix):
            base_dir = pkg_root
            matched_prefix = True
            break
    if not matched_prefix:
        # Allow any top-level dotted module resolving inside repo_root.
        base_dir = Path("")

    rel_parts = Path(*module.split("."))
    candidates = [
        base_dir / rel_parts.with_suffix(".py"),
        base_dir / rel_parts / "__init__.py",
    ]
    for cand in candidates:
        full = repo_root / cand
        if full.is_file():
            return cand
    raise FileNotFoundError(
        f"Module {module!r} could not be resolved to any file under {repo_root} "
        f"(checked {[str(c) for c in candidates]})"
    )


def _strip_docstring_node(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return ``body`` omitting a leading literal string docstring, if present."""
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _find_qualname_node(
    tree: ast.Module, qualname: str
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Walk nested scopes inside ``tree`` to find the unique function/method."""
    parts = qualname.split(".")
    cur_body: list[ast.stmt] = tree.body
    found: ast.AST | None = None
    for idx, part in enumerate(parts):
        is_last = idx == len(parts) - 1
        matches: list[ast.stmt] = []
        for stmt in cur_body:
            if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name == part:
                    matches.append(stmt)
        if not matches:
            raise LookupError(f"Symbol {part!r} not found while resolving {qualname!r}")
        if len(matches) > 1:
            # Handle @property getter + setter/deleter or @overload stubs cleanly
            # only by filtering out typing.overload stubs; duplicate real defs fail closed.
            non_overload = [
                m
                for m in matches
                if not any(
                    (isinstance(d, ast.Name) and d.id == "overload")
                    or (isinstance(d, ast.Attribute) and d.attr == "overload")
                    for d in getattr(m, "decorator_list", ())
                )
            ]
            matches = non_overload or matches
        if len(matches) > 1:
            raise LookupError(
                f"Ambiguous symbol {part!r} ({len(matches)} definitions) in {qualname!r}"
            )
        node = matches[0]
        if is_last:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                raise LookupError(
                    f"Target {qualname!r} resolved to {type(node).__name__}, expected function/method"
                )
            found = node
        else:
            if not isinstance(
                node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                raise LookupError(f"Cannot descend into {part!r} in {qualname!r}")
            cur_body = node.body
    assert isinstance(found, (ast.FunctionDef, ast.AsyncFunctionDef))
    return found


def _executable_lines_of_stmts(
    stmts: list[ast.stmt], *, exclude_nested_defs: bool = True
) -> set[int]:
    """Return all source line numbers covered by simple statements inside ``stmts``.

    Recursively includes branches inside compound statements, excluding nested
    ``def``/``async def``/``class`` bodies when ``exclude_nested_defs`` is true
    so defining an uncalled closure does not mask execution of its enclosing body.
    """
    out: set[int] = set()

    def walk_block(block: list[ast.stmt]) -> None:
        for stmt in block:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if exclude_nested_defs:
                    continue
                if stmt.lineno is not None and stmt.end_lineno is not None:
                    out.update(range(stmt.lineno, stmt.end_lineno + 1))
                continue
            if isinstance(stmt, ast.If):
                out.update(
                    range(
                        stmt.test.lineno, (stmt.test.end_lineno or stmt.test.lineno) + 1
                    )
                )
                walk_block(stmt.body)
                walk_block(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                out.update(
                    range(stmt.lineno, (stmt.iter.end_lineno or stmt.lineno) + 1)
                )
                walk_block(stmt.body)
                walk_block(stmt.orelse)
            elif isinstance(stmt, ast.While):
                out.update(
                    range(
                        stmt.test.lineno, (stmt.test.end_lineno or stmt.test.lineno) + 1
                    )
                )
                walk_block(stmt.body)
                walk_block(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                last_item_line = stmt.lineno
                for item in stmt.items:
                    end = getattr(item.context_expr, "end_lineno", None) or stmt.lineno
                    last_item_line = max(last_item_line, end)
                out.update(range(stmt.lineno, last_item_line + 1))
                walk_block(stmt.body)
            elif isinstance(stmt, ast.Try):
                walk_block(stmt.body)
                for h in stmt.handlers:
                    walk_block(h.body)
                walk_block(stmt.orelse)
                walk_block(stmt.finalbody)
            elif hasattr(ast, "TryStar") and isinstance(
                stmt, ast.TryStar
            ):  # Python 3.11+
                walk_block(stmt.body)
                for h in stmt.handlers:
                    walk_block(h.body)
                walk_block(stmt.orelse)
                walk_block(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                out.update(
                    range(
                        stmt.subject.lineno,
                        (stmt.subject.end_lineno or stmt.subject.lineno) + 1,
                    )
                )
                for case in stmt.cases:
                    walk_block(case.body)
            else:
                end = stmt.end_lineno or stmt.lineno
                out.update(range(stmt.lineno, end + 1))

    walk_block(stmts)
    return out


def _code_lines_without_comments(source: str) -> dict[int, str]:
    """Reconstruct per-line source strings with comments blanked via ``tokenize``."""
    lines = source.splitlines()
    masked: dict[int, list[str]] = {i: list(ln) for i, ln in enumerate(lines, start=1)}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                lineno, start_col = tok.start
                _, end_col = tok.end
                if lineno in masked:
                    row = masked[lineno]
                    for col in range(start_col, min(end_col, len(row))):
                        row[col] = " "
    except tokenize.TokenError:
        pass
    return {lineno: "".join(chars) for lineno, chars in masked.items()}


def _docstring_lines(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    """Line numbers occupied by a function's leading docstring (if any)."""
    body = func_node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        end = body[0].end_lineno or body[0].lineno
        return set(range(body[0].lineno, end + 1))
    return set()


def _resolve_line_to_statement(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    line: int,
) -> tuple[tuple[int, int, str], frozenset[int], str]:
    """Map a matched anchor line inside ``func_node`` to its innermost target lines.

    If the anchor sits on a compound header (``if``, ``elif``, ``for``, ``while``,
    ``with``, ``except``), return the **branch body lines** instead of the header
    line so the branch must actually be *entered*, not merely evaluated.
    """
    best_simple: ast.stmt | None = None
    best_compound: tuple[tuple[int, int, str], list[ast.stmt], int] | None = None

    def inspect_block(stmts: list[ast.stmt]) -> None:
        nonlocal best_simple, best_compound
        for stmt in stmts:
            start = stmt.lineno
            end = stmt.end_lineno or start
            if not (start <= line <= end):
                continue
            if isinstance(stmt, ast.If):
                test_end = stmt.test.end_lineno or stmt.lineno
                if stmt.lineno <= line <= test_end:
                    key = (stmt.lineno, test_end, "if_body")
                    best_compound = (key, stmt.body, test_end - stmt.lineno)
                inspect_block(stmt.body)
                inspect_block(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                hdr_end = stmt.iter.end_lineno or stmt.lineno
                if stmt.lineno <= line <= hdr_end:
                    key = (stmt.lineno, hdr_end, "loop_body")
                    best_compound = (key, stmt.body, hdr_end - stmt.lineno)
                inspect_block(stmt.body)
                inspect_block(stmt.orelse)
            elif isinstance(stmt, ast.While):
                hdr_end = stmt.test.end_lineno or stmt.lineno
                if stmt.lineno <= line <= hdr_end:
                    key = (stmt.lineno, hdr_end, "while_body")
                    best_compound = (key, stmt.body, hdr_end - stmt.lineno)
                inspect_block(stmt.body)
                inspect_block(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                hdr_end = stmt.lineno
                for item in stmt.items:
                    hdr_end = max(hdr_end, item.context_expr.end_lineno or stmt.lineno)
                if stmt.lineno <= line <= hdr_end:
                    key = (stmt.lineno, hdr_end, "with_body")
                    best_compound = (key, stmt.body, hdr_end - stmt.lineno)
                inspect_block(stmt.body)
            elif isinstance(stmt, ast.Try) or (
                hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)
            ):
                inspect_block(stmt.body)
                for handler in stmt.handlers:
                    h_start = handler.lineno
                    h_end = handler.end_lineno or h_start
                    if h_start <= line <= h_end:
                        type_end = (
                            (handler.type.end_lineno or h_start)
                            if handler.type is not None
                            else h_start
                        )
                        if h_start <= line <= type_end:
                            key = (h_start, type_end, "except_body")
                            best_compound = (key, handler.body, type_end - h_start)
                        inspect_block(handler.body)
                inspect_block(stmt.orelse)
                inspect_block(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    inspect_block(case.body)
            elif isinstance(
                stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                raise LookupError(
                    f"Anchor line {line} falls inside nested {type(stmt).__name__} "
                    f"{stmt.name!r}; target the nested symbol explicitly using "
                    f"'{func_node.name}.{stmt.name}#<anchor>' so its `def` line cannot "
                    "mask an uncalled body."
                )
            else:
                span_len = end - start
                if best_simple is None or span_len <= (
                    (best_simple.end_lineno or best_simple.lineno) - best_simple.lineno
                ):
                    best_simple = stmt

    inspect_block(_strip_docstring_node(func_node.body))

    if best_simple is not None:
        s_end = best_simple.end_lineno or best_simple.lineno
        return (
            (best_simple.lineno, s_end, type(best_simple).__name__),
            frozenset(range(best_simple.lineno, s_end + 1)),
            "statement_anchor",
        )
    if best_compound is not None:
        key, body_stmts, _ = best_compound
        body_lines = _executable_lines_of_stmts(_strip_docstring_node(body_stmts))
        if not body_lines:
            # Body contained only a nested def or docstring; fall back to direct body line span
            body_lines = {s.lineno for s in body_stmts}
        return key, frozenset(body_lines), "branch_body_anchor"
    raise LookupError(
        f"Anchor line {line} inside {func_node.name!r} sits on a non-executable line "
        "(signature/else/finally/try keyword) rather than an executable statement or branch header"
    )


class TargetResolver:
    """Cached AST resolver mapping ``CoversTargetSpec`` -> ``ResolvedTarget``."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self._trees: dict[Path, tuple[str, ast.Module, dict[int, str]]] = {}

    def _load(self, rel_path: Path) -> tuple[str, ast.Module, dict[int, str]]:
        cached = self._trees.get(rel_path)
        if cached is not None:
            return cached
        source = (self.repo_root / rel_path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(rel_path))
        code_lines = _code_lines_without_comments(source)
        entry = (source, tree, code_lines)
        self._trees[rel_path] = entry
        return entry

    def resolve(self, spec: CoversTargetSpec) -> ResolvedTarget:
        rel_path = resolve_module_path(self.repo_root, spec.module)
        _, tree, code_lines = self._load(rel_path)
        func_node = _find_qualname_node(tree, spec.qualname)
        body_stmts = _strip_docstring_node(func_node.body)

        if spec.anchor is None:
            lines = _executable_lines_of_stmts(body_stmts, exclude_nested_defs=True)
            if not lines:
                # Fallback: e.g. function whose body is solely a nested def + return
                lines = _executable_lines_of_stmts(
                    body_stmts, exclude_nested_defs=False
                )
            if not lines:
                raise LookupError(
                    f"Target {spec.raw!r} resolved to function with zero executable body lines"
                )
            return ResolvedTarget(
                spec=spec,
                rel_path=rel_path,
                target_lines=frozenset(lines),
                resolution_kind="function_body",
            )

        body_start = body_stmts[0].lineno if body_stmts else func_node.lineno
        func_end = func_node.end_lineno or func_node.lineno
        doc_lines = _docstring_lines(func_node)

        matching_lines: list[int] = []
        for lineno in range(body_start, func_end + 1):
            if lineno in doc_lines:
                continue
            line_text = code_lines.get(lineno, "")
            if spec.anchor in line_text:
                matching_lines.append(lineno)

        if not matching_lines:
            raise LookupError(
                f"Anchor {spec.anchor!r} not found in non-comment, non-docstring lines of "
                f"{spec.module}:{spec.qualname} ({rel_path}:L{body_start}-L{func_end})"
            )

        resolved_stmts: dict[tuple[int, int, str], tuple[frozenset[int], str]] = {}
        for ln in matching_lines:
            key, tgt_lines, kind = _resolve_line_to_statement(func_node, ln)
            resolved_stmts[key] = (tgt_lines, kind)

        if len(resolved_stmts) > 1:
            stmt_summary = ", ".join(
                f"L{k[0]}-L{k[1]} ({k[2]})" for k in sorted(resolved_stmts)
            )
            raise LookupError(
                f"Anchor {spec.anchor!r} inside {spec.module}:{spec.qualname} is ambiguous "
                f"(matched {len(resolved_stmts)} distinct statements: {stmt_summary}). "
                "Use a more specific anchor substring."
            )

        tgt_lines, kind = next(iter(resolved_stmts.values()))
        return ResolvedTarget(
            spec=spec,
            rel_path=rel_path,
            target_lines=tgt_lines,
            resolution_kind=kind,
        )


# ---------------------------------------------------------------------------
# Test file AST scanner (candidate discovery + marker extraction)
# ---------------------------------------------------------------------------


def _asserts_503(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when the function body contains an ``assert`` referencing ``503`` or ``SERVICE_UNAVAILABLE``."""
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            for sub in ast.walk(child.test):
                if (
                    isinstance(sub, ast.Constant)
                    and type(sub.value) is int
                    and sub.value == 503
                ):
                    return True
                if isinstance(sub, ast.Attribute) and sub.attr == "SERVICE_UNAVAILABLE":
                    return True
    return False


def _marker_attr_name(expr: ast.AST) -> str | None:
    """Return marker name if ``expr`` looks like ``pytest.mark.<name>(...)`` or ``pytest.mark.<name>``."""
    target = expr.func if isinstance(expr, ast.Call) else expr
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Attribute)
        and target.value.attr == "mark"
        and isinstance(target.value.value, ast.Name)
        and target.value.value.id == "pytest"
    ):
        return target.attr
    return None


def _extract_markers_from_expr(
    expr: ast.expr,
    *,
    param_id: str | None = None,
) -> tuple[set[str], list[CoversTargetSpec], list[ExemptAnnotation], list[str], bool]:
    """Extract selection/skip/covers/covers_exempt metadata from one marker AST expression."""
    sel_markers: set[str] = set()
    covers: list[CoversTargetSpec] = []
    exempts: list[ExemptAnnotation] = []
    errors: list[str] = []
    is_skipped = False

    def handle_one(node: ast.expr) -> None:
        nonlocal is_skipped
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                handle_one(elt)
            return
        mname = _marker_attr_name(node)
        if mname is None:
            return
        if mname in HERMETIC_MARKERS or mname in NON_HERMETIC_MARKERS:
            sel_markers.add(mname)
        elif mname == "skip":
            is_skipped = True
        elif mname == "covers":
            if not isinstance(node, ast.Call):
                errors.append(
                    f"L{node.lineno}: @pytest.mark.covers must be called with target strings"
                )
                return
            scope = "all_params"
            for kw in node.keywords:
                if kw.arg == "scope":
                    if isinstance(kw.value, ast.Constant) and isinstance(
                        kw.value.value, str
                    ):
                        scope = kw.value.value
                    else:
                        errors.append(
                            f"L{node.lineno}: @pytest.mark.covers scope= must be a string literal"
                        )
                        return
                else:
                    errors.append(
                        f"L{node.lineno}: unsupported keyword argument {kw.arg!r} in @pytest.mark.covers"
                    )
                    return
            if not node.args:
                errors.append(
                    f"L{node.lineno}: @pytest.mark.covers requires at least one target string"
                )
                return
            for arg in node.args:
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    errors.append(
                        f"L{node.lineno}: @pytest.mark.covers argument must be a string literal"
                    )
                    continue
                try:
                    covers.append(
                        parse_target_string(arg.value, scope=scope, param_id=param_id)
                    )
                except ValueError as exc:
                    errors.append(f"L{node.lineno}: {exc}")
        elif mname == "covers_exempt":
            if not isinstance(node, ast.Call):
                errors.append(
                    f"L{node.lineno}: @pytest.mark.covers_exempt requires reason='<category>: <explanation>'"
                )
                return
            reason_val: str | None = None
            if node.args and len(node.args) == 1 and not node.keywords:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    reason_val = arg.value
            else:
                for kw in node.keywords:
                    if kw.arg == "reason":
                        if isinstance(kw.value, ast.Constant) and isinstance(
                            kw.value.value, str
                        ):
                            reason_val = kw.value.value
            if reason_val is None:
                errors.append(
                    f"L{node.lineno}: @pytest.mark.covers_exempt must pass a string literal reason='<category>: <explanation>'"
                )
                return
            exempts.append(ExemptAnnotation(reason=reason_val, lineno=node.lineno))

    handle_one(expr)
    return sel_markers, covers, exempts, errors, is_skipped


def _extract_parametrize_param_covers(
    decorator: ast.AST,
) -> tuple[list[CoversTargetSpec], list[str]]:
    """Extract ``pytest.param(..., id='x', marks=pytest.mark.covers(...))`` specs."""
    specs: list[CoversTargetSpec] = []
    errors: list[str] = []
    if _marker_attr_name(decorator) != "parametrize" or not isinstance(
        decorator, ast.Call
    ):
        return specs, errors
    for sub in ast.walk(decorator):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "param"
            and isinstance(func.value, ast.Name)
            and func.value.id == "pytest"
        ):
            continue
        marks_expr: ast.expr | None = None
        param_id: str | None = None
        for kw in sub.keywords:
            if kw.arg == "marks":
                marks_expr = kw.value
            elif (
                kw.arg == "id"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                param_id = kw.value.value
        if marks_expr is None:
            continue
        _, found_covers, found_exempts, found_errs, _ = _extract_markers_from_expr(
            marks_expr, param_id=param_id
        )
        if found_covers and param_id is None:
            errors.append(
                f"L{sub.lineno}: pytest.param(..., marks=pytest.mark.covers(...)) must include an explicit string id='...'"
            )
            continue
        if found_exempts:
            errors.append(
                f"L{sub.lineno}: @pytest.mark.covers_exempt is supported at function/class level, not inside pytest.param"
            )
        specs.extend(found_covers)
        errors.extend(found_errs)
    return specs, errors


def _is_test_class(cls: ast.ClassDef) -> bool:
    if cls.name.startswith("Test"):
        return True
    for base in cls.bases:
        if isinstance(base, ast.Name) and base.id.endswith("TestCase"):
            return True
        if isinstance(base, ast.Attribute) and base.attr.endswith("TestCase"):
            return True
    return False


def scan_test_file(repo_root: Path, path: Path) -> list[DiscoveredTest]:
    """AST-scan a single ``test_*.py`` file for collected tests and markers."""
    rel_path = path.relative_to(repo_root).as_posix()
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=rel_path)

    mod_sel: set[str] = set()
    mod_covers: list[CoversTargetSpec] = []
    mod_exempts: list[ExemptAnnotation] = []
    mod_errors: list[str] = []
    mod_skipped = False

    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "pytestmark":
                    s, c, e, errs, sk = _extract_markers_from_expr(stmt.value)
                    mod_sel |= s
                    mod_covers.extend(c)
                    mod_exempts.extend(e)
                    mod_errors.extend(errs)
                    mod_skipped = mod_skipped or sk

    discovered: list[DiscoveredTest] = []

    def process_fn(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        cls_name: str | None,
        cls_sel: set[str],
        cls_covers: list[CoversTargetSpec],
        cls_exempts: list[ExemptAnnotation],
        cls_errors: list[str],
        cls_skipped: bool,
    ) -> None:
        sel = set(mod_sel) | set(cls_sel)
        cov = list(mod_covers) + list(cls_covers)
        ex = list(mod_exempts) + list(cls_exempts)
        errs = list(mod_errors) + list(cls_errors)
        skipped = mod_skipped or cls_skipped
        for dec in fn.decorator_list:
            s, c, e, er, sk = _extract_markers_from_expr(dec)
            sel |= s
            cov.extend(c)
            ex.extend(e)
            errs.extend(er)
            skipped = skipped or sk
            pc, perr = _extract_parametrize_param_covers(dec)
            cov.extend(pc)
            errs.extend(perr)

        lower = fn.name.lower()
        matched_toks = tuple(t for t in CANDIDATE_TOKENS if t in lower)
        discovered.append(
            DiscoveredTest(
                rel_path=rel_path,
                class_name=cls_name,
                func_name=fn.name,
                lineno=fn.lineno,
                asserts_503=_asserts_503(fn),
                matched_tokens=matched_toks,
                selection_markers=frozenset(sel),
                is_skipped=skipped,
                covers_specs=cov,
                exemptions=ex,
                parse_errors=errs,
            )
        )

    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef) and _is_test_class(stmt):
            cls_sel: set[str] = set()
            cls_cov: list[CoversTargetSpec] = []
            cls_ex: list[ExemptAnnotation] = []
            cls_err: list[str] = []
            cls_sk = False
            for dec in stmt.decorator_list:
                s, c, e, er, sk = _extract_markers_from_expr(dec)
                cls_sel |= s
                cls_cov.extend(c)
                cls_ex.extend(e)
                cls_err.extend(er)
                cls_sk = cls_sk or sk
            for member in stmt.body:
                if isinstance(
                    member, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and member.name.startswith("test_"):
                    process_fn(
                        member, stmt.name, cls_sel, cls_cov, cls_ex, cls_err, cls_sk
                    )
        elif isinstance(
            stmt, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and stmt.name.startswith("test_"):
            process_fn(stmt, None, set(), [], [], [], False)

    return discovered


def scan_all_tests(
    repo_root: Path, tests_dir: Path | None = None
) -> list[DiscoveredTest]:
    root = tests_dir if tests_dir is not None else (repo_root / TESTS_REL_DIR)
    all_tests: list[DiscoveredTest] = []
    for path in sorted(root.rglob("test_*.py")):
        all_tests.extend(scan_test_file(repo_root, path))
    return all_tests


def compute_scope_candidates(
    all_tests: list[DiscoveredTest],
    *,
    scope: str,
    repo_root: Path,
    census_path: Path | None = None,
) -> tuple[set[str], dict[str, str]]:
    """Return ``(candidate_nodeids, reason_by_nodeid)`` for ``scope``."""
    if scope not in VALID_SCOPES:
        raise ValueError(f"Unsupported scope {scope!r}; choose from {VALID_SCOPES}")

    readback_files: set[str] = set()
    if scope in ("holds", "holds-and-503"):
        readback_files = load_census_readback_files(
            repo_root, census_path=census_path, verdicts=frozenset({"HOLDS"})
        )
    elif scope in ("readback", "readback-and-503"):
        readback_files = load_census_readback_files(
            repo_root, census_path=census_path, verdicts=None
        )

    include_global_503 = scope in ("holds-and-503", "readback-and-503", "all")

    candidates: set[str] = set()
    reasons: dict[str, str] = {}
    for t in all_tests:
        has_token = bool(t.matched_tokens)
        in_readback = scope == "all" or t.rel_path in readback_files
        parts: list[str] = []
        if t.asserts_503 and (include_global_503 or in_readback):
            parts.append("asserts_503")
        if in_readback and has_token:
            parts.append(f"name_token({','.join(t.matched_tokens)})")
        if parts:
            src_tag = (
                "census:read_back"
                if (scope != "all" and t.rel_path in readback_files)
                else ("global:503" if t.asserts_503 else "repo:all")
            )
            candidates.add(t.nodeid)
            reasons[t.nodeid] = f"{src_tag}:{'+'.join(parts)}"
    return candidates, reasons


def validate_exempt_reason(reason: str) -> str | None:
    """Return an error string if ``reason`` violates the exemption format, else ``None``."""
    stripped = reason.strip()
    if ":" not in stripped:
        return (
            f"covers_exempt reason {reason!r} must start with '<category>: <explanation>' "
            f"(categories: {', '.join(APPROVED_EXEMPT_CATEGORIES)})"
        )
    prefix, detail = stripped.split(":", 1)
    cat = prefix.strip().lower()
    if cat not in APPROVED_EXEMPT_CATEGORIES:
        return (
            f"covers_exempt category {cat!r} is not allowed; "
            f"choose from {', '.join(APPROVED_EXEMPT_CATEGORIES)}"
        )
    if len(detail.strip()) < MIN_EXEMPT_EXPLANATION_LEN:
        return (
            f"covers_exempt explanation after '{cat}:' must be at least "
            f"{MIN_EXEMPT_EXPLANATION_LEN} characters (got {len(detail.strip())})"
        )
    return None


# ---------------------------------------------------------------------------
# Outcome-normalizing except fallthrough finder & baseline ratchet
# ---------------------------------------------------------------------------


_TRY_NODES: Final[tuple[type[ast.AST], ...]] = (
    (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
)


def _call_tail_name(node: ast.expr) -> str | None:
    """Return bare identifier or attribute tail of a callee expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _status_code_kw(call: ast.Call) -> object | None:
    """Return constant ``status_code`` (keyword or positional on ``HTTPException``)."""
    for kw in call.keywords:
        if kw.arg == "status_code" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    if (
        _call_tail_name(call.func) == "HTTPException"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, int)
    ):
        return call.args[0].value
    return None


def _except_tail_outcome(handler: ast.ExceptHandler) -> tuple[str, str]:
    """Summarize the control-flow tail outcome of an ``except`` handler body."""
    if not handler.body:
        return ("fallthrough", "fallthrough")
    last = handler.body[-1]
    if isinstance(last, ast.Return):
        if last.value is None:
            return ("return_const", "return None")
        if isinstance(last.value, ast.Constant):
            return ("return_const", f"return {last.value.value!r}")
        return ("return_expr", f"return {ast.unparse(last.value)}")
    if isinstance(last, ast.Raise):
        if last.exc is None:
            return ("raise", "reraise")
        if isinstance(last.exc, ast.Call):
            fn = _call_tail_name(last.exc.func) or ast.unparse(last.exc.func)
            sc = _status_code_kw(last.exc)
            detail = f"{fn}:{sc}" if sc is not None else fn
            return ("raise_call", f"raise {detail}")
        return ("raise_expr", f"raise {ast.unparse(last.exc)}")
    if isinstance(last, ast.Break):
        return ("break", "break")
    if isinstance(last, ast.Continue):
        return ("continue", "continue")
    return ("fallthrough", "fallthrough")


def _body_line_span(stmts: list[ast.stmt]) -> frozenset[int]:
    """Collect all source line numbers spanned by statements in ``stmts``."""
    lines: set[int] = set()
    for stmt in stmts:
        end = stmt.end_lineno if stmt.end_lineno is not None else stmt.lineno
        lines.update(range(stmt.lineno, end + 1))
    return frozenset(lines)


class _ShadowExceptVisitor(ast.NodeVisitor):
    """AST visitor collecting ordered outcome-normalizing ``except`` pairs."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self._qual_parts: list[str] = []
        self.pairs: list[ShadowExceptPair] = []

    def _visit_named(self, node: ast.AST, name: str) -> None:
        self._qual_parts.append(name)
        try:
            self.generic_visit(node)
        finally:
            self._qual_parts.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_named(node, node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_named(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_named(node, node.name)

    def _visit_try_node(self, node: ast.AST) -> None:
        handlers: list[ast.ExceptHandler] = getattr(node, "handlers", [])
        qualname = ".".join(self._qual_parts) if self._qual_parts else "<module>"
        if len(handlers) >= 2:
            summarized = [(_except_tail_outcome(h), h) for h in handlers]
            for i in range(len(summarized)):
                out_i, h_i = summarized[i]
                for j in range(i + 1, len(summarized)):
                    out_j, h_j = summarized[j]
                    if out_i != out_j:
                        continue
                    self.pairs.append(
                        ShadowExceptPair(
                            rel_path=self.rel_path,
                            qualname=qualname,
                            earlier_lineno=h_i.lineno,
                            earlier_end_lineno=h_i.end_lineno or h_i.lineno,
                            earlier_body_lines=_body_line_span(h_i.body),
                            earlier_type=(
                                ast.unparse(h_i.type)
                                if h_i.type is not None
                                else "bare"
                            ),
                            later_lineno=h_j.lineno,
                            later_end_lineno=h_j.end_lineno or h_j.lineno,
                            later_type=(
                                ast.unparse(h_j.type)
                                if h_j.type is not None
                                else "bare"
                            ),
                            outcome=out_i[1],
                        )
                    )
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try_node(node)

    def visit_TryStar(self, node: ast.AST) -> None:
        self._visit_try_node(node)


def find_outcome_normalizing_except_pairs(
    repo_root: Path,
    *,
    src_dir: Path | None = None,
) -> list[ShadowExceptPair]:
    """Scan Python modules under ``src/`` for outcome-normalizing ``except`` pairs."""
    search_dir = src_dir if src_dir is not None else (repo_root / SRC_REL_DIR)
    if not search_dir.is_dir():
        return []
    pairs: list[ShadowExceptPair] = []
    for py_path in sorted(search_dir.rglob("*.py")):
        rel_path = _normalize_posix(str(py_path.relative_to(repo_root)))
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel_path)
        visitor = _ShadowExceptVisitor(rel_path)
        visitor.visit(tree)
        pairs.extend(visitor.pairs)
    return pairs


def evaluate_shadow_except_pairs(
    repo_root: Path,
    resolved_by_nodeid: dict[str, list[ResolvedTarget]],
    *,
    src_dir: Path | None = None,
) -> tuple[list[ShadowExceptPair], list[ShadowExceptPair]]:
    """Classify each outcome-normalizing ``except`` pair as covered or uncovered.

    A pair is covered when at least one anchored ``@pytest.mark.covers`` target
    (``statement_anchor`` or ``branch_body_anchor`` — never coarse
    ``function_body``) resolves inside the earlier handler's body without
    touching the later handler's line span.
    """
    raw_pairs = find_outcome_normalizing_except_pairs(repo_root, src_dir=src_dir)
    if not raw_pairs:
        return [], []

    anchored_by_file: dict[str, list[tuple[str, ResolvedTarget]]] = {}
    for nodeid, targets in resolved_by_nodeid.items():
        for tgt in targets:
            if tgt.resolution_kind == "function_body":
                continue
            key = _normalize_posix(str(tgt.rel_path))
            anchored_by_file.setdefault(key, []).append((nodeid, tgt))

    evaluated: list[ShadowExceptPair] = []
    uncovered: list[ShadowExceptPair] = []
    for pair in raw_pairs:
        later_span = frozenset(range(pair.later_lineno, pair.later_end_lineno + 1))
        hits = sorted(
            {
                nodeid
                for nodeid, tgt in anchored_by_file.get(pair.rel_path, ())
                if (tgt.target_lines & pair.earlier_body_lines)
                and not (tgt.target_lines & later_span)
            }
        )
        updated = ShadowExceptPair(
            rel_path=pair.rel_path,
            qualname=pair.qualname,
            earlier_lineno=pair.earlier_lineno,
            earlier_end_lineno=pair.earlier_end_lineno,
            earlier_body_lines=pair.earlier_body_lines,
            earlier_type=pair.earlier_type,
            later_lineno=pair.later_lineno,
            later_end_lineno=pair.later_end_lineno,
            later_type=pair.later_type,
            outcome=pair.outcome,
            covered_by=tuple(hits),
        )
        evaluated.append(updated)
        if not updated.is_covered:
            uncovered.append(updated)
    return evaluated, uncovered


def resolve_shadow_baseline_path(
    repo_root: Path,
    shadow_baseline_path: Path | None = None,
) -> Path:
    """Resolve the path to ``tests/.shadow-except-baseline``."""
    return (
        shadow_baseline_path
        if shadow_baseline_path is not None
        else (repo_root / SHADOW_EXCEPT_BASELINE_REL_PATH)
    )


def read_shadow_except_baseline(baseline_path: Path) -> tuple[int | None, str | None]:
    """Read a non-negative integer baseline from ``baseline_path``."""
    if not baseline_path.is_file():
        return None, f"missing shadow-except baseline file {baseline_path}"
    raw = baseline_path.read_text(encoding="utf-8").strip()
    try:
        value = int(raw)
    except ValueError:
        return (
            None,
            f"invalid integer {raw!r} in shadow-except baseline {baseline_path}",
        )
    if value < 0:
        return None, f"negative baseline {value} in {baseline_path}"
    return value, None


def write_shadow_except_baseline(count: int, baseline_path: Path) -> None:
    """Write ``count`` as a single-line monotonic ratchet baseline."""
    if count < 0:
        raise ValueError(f"baseline count must be >= 0, got {count}")
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(f"{count}\n", encoding="utf-8")


def check_shadow_except_baseline(
    repo_root: Path,
    resolved_by_nodeid: dict[str, list[ResolvedTarget]],
    *,
    shadow_baseline_path: Path | None = None,
    src_dir: Path | None = None,
    enforce: bool = True,
) -> tuple[list[ShadowExceptPair], list[ShadowExceptPair], int | None, list[Violation]]:
    """Audit outcome-normalizing ``except`` pairs against the monotonic baseline."""
    evaluated, uncovered = evaluate_shadow_except_pairs(
        repo_root, resolved_by_nodeid, src_dir=src_dir
    )
    baseline_file = resolve_shadow_baseline_path(repo_root, shadow_baseline_path)
    violations: list[Violation] = []

    if not evaluated and not baseline_file.is_file() and shadow_baseline_path is None:
        return evaluated, uncovered, None, violations

    baseline_val: int | None = None
    if baseline_file.is_file():
        baseline_val, err = read_shadow_except_baseline(baseline_file)
        if err is not None and enforce:
            violations.append(
                Violation("SHADOW_EXCEPT_BASELINE_INVALID", str(baseline_file), err)
            )
            return evaluated, uncovered, None, violations
    elif enforce and uncovered:
        violations.append(
            Violation(
                "SHADOW_EXCEPT_BASELINE_EXCEEDED",
                str(baseline_file),
                f"found {len(uncovered)} uncovered outcome-normalizing except pair(s) "
                f"with no {SHADOW_EXCEPT_BASELINE_REL_PATH} baseline file",
            )
        )
        return evaluated, uncovered, None, violations

    if enforce and baseline_val is not None and len(uncovered) > baseline_val:
        sample = "; ".join(
            f"{p.location} ({p.earlier_type} vs {p.later_type} -> {p.outcome})"
            for p in uncovered[:5]
        )
        violations.append(
            Violation(
                "SHADOW_EXCEPT_BASELINE_EXCEEDED",
                SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
                f"uncovered outcome-normalizing except pairs increased from baseline "
                f"{baseline_val} to {len(uncovered)} (sample: {sample}). Resolve via "
                "one of the 4 documented paths or pin the earlier handler with an "
                "anchored @pytest.mark.covers('module:qualname#anchor').",
            )
        )
    return evaluated, uncovered, baseline_val, violations


def verify_static(
    repo_root: Path,
    *,
    scope: str,
    census_path: Path | None = None,
    tests_dir: Path | None = None,
    require_candidates_marked: bool = True,
    shadow_baseline_path: Path | None = None,
    enforce_shadow_baseline: bool = True,
) -> tuple[
    list[DiscoveredTest],
    set[str],
    dict[str, str],
    dict[str, list[ResolvedTarget]],
    list[Violation],
]:
    """Run static discovery, exemption hygiene, target resolution, and shadow-except ratchet."""
    all_tests = scan_all_tests(repo_root, tests_dir=tests_dir)
    candidates, reasons = compute_scope_candidates(
        all_tests, scope=scope, repo_root=repo_root, census_path=census_path
    )
    resolver = TargetResolver(repo_root)
    resolved_by_nodeid: dict[str, list[ResolvedTarget]] = {}
    violations: list[Violation] = []

    for t in all_tests:
        for err in t.parse_errors:
            violations.append(Violation("MARKER_SYNTAX", t.nodeid, err))

        has_covers = bool(t.covers_specs)
        has_exempt = bool(t.exemptions)

        if has_covers and has_exempt:
            violations.append(
                Violation(
                    "MUTUALLY_EXCLUSIVE",
                    t.nodeid,
                    "cannot carry both @pytest.mark.covers and @pytest.mark.covers_exempt",
                )
            )

        if has_exempt:
            for ex in t.exemptions:
                err_msg = validate_exempt_reason(ex.reason)
                if err_msg is not None:
                    violations.append(
                        Violation(
                            "INVALID_EXEMPTION", t.nodeid, f"L{ex.lineno}: {err_msg}"
                        )
                    )
            if t.nodeid not in candidates:
                violations.append(
                    Violation(
                        "STALE_EXEMPTION",
                        t.nodeid,
                        f"carries @pytest.mark.covers_exempt but is not a candidate in scope {scope!r}",
                    )
                )

        if has_covers:
            resolved_list: list[ResolvedTarget] = []
            for spec in t.covers_specs:
                try:
                    resolved_list.append(resolver.resolve(spec))
                except (FileNotFoundError, LookupError, SyntaxError, ValueError) as exc:
                    violations.append(
                        Violation("UNRESOLVED_TARGET", t.nodeid, f"{spec.raw!r}: {exc}")
                    )
            if resolved_list:
                resolved_by_nodeid[t.nodeid] = resolved_list

        if (
            require_candidates_marked
            and t.nodeid in candidates
            and not has_covers
            and not has_exempt
            and not t.parse_errors
        ):
            violations.append(
                Violation(
                    "UNMARKED_CANDIDATE",
                    t.nodeid,
                    f"matches fail-closed discovery ({reasons[t.nodeid]}) at L{t.lineno} "
                    "without @pytest.mark.covers(...) or @pytest.mark.covers_exempt(reason=...).",
                )
            )

    if enforce_shadow_baseline:
        _, _, _, shadow_violations = check_shadow_except_baseline(
            repo_root,
            resolved_by_nodeid,
            shadow_baseline_path=shadow_baseline_path,
            enforce=True,
        )
        violations.extend(shadow_violations)

    return all_tests, candidates, reasons, resolved_by_nodeid, violations


# ---------------------------------------------------------------------------
# Exact SQLite coverage database reader (immune to regex '|' alternation)
# ---------------------------------------------------------------------------


def _normalize_posix(path: str) -> str:
    return path.replace("\\", "/")


def _match_coverage_file_id(
    rel_path: Path,
    db_files: dict[int, str],
) -> tuple[int | None, str | None]:
    """Match a repo-relative target path to a unique ``file.id`` in ``.coverage``."""
    target_rel = _normalize_posix(str(rel_path))
    suffixes = [f"/{target_rel}"]
    # Editable/wheel fallback for workspace packages (e.g. packages/cage-client/src/cage_client/...)
    if target_rel.startswith("packages/"):
        parts = target_rel.split("/")
        if len(parts) >= 4 and parts[2] == "src":
            pkg_rel = "/".join(parts[3:])
            suffixes.append(f"/{pkg_rel}")

    for sfx in suffixes:
        hits = [
            (fid, fpath)
            for fid, fpath in db_files.items()
            if fpath == target_rel or fpath.endswith(sfx)
        ]
        if len(hits) == 1:
            return hits[0][0], None
        if len(hits) > 1:
            sample = ", ".join(p for _, p in hits[:5])
            return None, f"ambiguous coverage file rows for {target_rel!r}: {sample}"
    return None, (
        f"file {target_rel!r} is absent from the coverage database "
        "(either never executed/imported or excluded by .coveragerc omit / --cov= scope)"
    )


class CoverageContextDB:
    """Read-only exact-equality query reader for a ``coverage.py`` SQLite DB."""

    def __init__(self, db_path: Path) -> None:
        if not db_path.is_file():
            raise FileNotFoundError(f"Coverage database not found: {db_path}")
        resolved = db_path.resolve()
        encoded = urllib.parse.quote(str(resolved), safe="/:")
        uri = f"file:{encoded}?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True)
        try:
            self.has_arcs = self._detect_has_arcs()
            self.files: dict[int, str] = self._load_files()
            self.contexts: dict[str, int] = self._load_contexts()
            self._validate_dynamic_contexts()
        except Exception:
            self._conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CoverageContextDB:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _detect_has_arcs(self) -> bool:
        tables = {
            row[0]
            for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required = {"file", "context"}
        if not required.issubset(tables):
            raise ValueError(
                f"Database does not look like a coverage.py SQLite file (tables={sorted(tables)})"
            )
        if "meta" in tables:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", ("has_arcs",)
            ).fetchone()
            if row is not None:
                return str(row[0]) == "1"
        if "arc" in tables:
            cnt = self._conn.execute("SELECT COUNT(*) FROM arc LIMIT 1").fetchone()[0]
            if cnt > 0:
                return True
        if "line_bits" in tables:
            return False
        raise ValueError(
            "Coverage database contains neither 'arc' nor 'line_bits' table"
        )

    def _load_files(self) -> dict[int, str]:
        return {
            int(fid): _normalize_posix(str(path))
            for fid, path in self._conn.execute("SELECT id, path FROM file").fetchall()
        }

    def _load_contexts(self) -> dict[str, int]:
        return {
            str(ctx): int(cid)
            for cid, ctx in self._conn.execute(
                "SELECT id, context FROM context"
            ).fetchall()
        }

    def _validate_dynamic_contexts(self) -> None:
        run_contexts = [c for c in self.contexts if c.endswith("|run")]
        if not run_contexts:
            raise ValueError(
                "Coverage database contains zero per-test '|run' dynamic contexts "
                f"(found {len(self.contexts)} contexts total). "
                "Re-run pytest with --cov-context=test."
            )

    def run_contexts_for_test(
        self, nodeid: str, *, param_id: str | None = None
    ) -> list[str]:
        """Exact non-regex lookup of all ``|run`` contexts for a test ``nodeid``."""
        if param_id is not None:
            # Handle explicit pytest.param(..., id=...) and multi-dim param ids (e.g. [a-x]).
            exact = f"{nodeid}[{param_id}]|run"
            if exact in self.contexts:
                return [exact]
            prefix = f"{nodeid}["
            matched = [
                c
                for c in self.contexts
                if c.startswith(prefix)
                and c.endswith("]|run")
                and param_id in c[len(prefix) : -len("]|run")].split("-")
            ]
            return sorted(matched)

        unparam = f"{nodeid}|run"
        prefix = f"{nodeid}["
        found: list[str] = []
        if unparam in self.contexts:
            found.append(unparam)
        found.extend(
            c for c in self.contexts if c.startswith(prefix) and c.endswith("]|run")
        )
        return sorted(found)

    def executed_lines(self, file_id: int, context_name: str) -> frozenset[int]:
        """Return executed source line numbers for the exact literal ``context_name``."""
        ctx_id = self.contexts.get(context_name)
        if ctx_id is None:
            return frozenset()
        lines: set[int] = set()
        if self.has_arcs:
            rows = self._conn.execute(
                "SELECT fromno, tono FROM arc WHERE file_id = ? AND context_id = ?",
                (file_id, ctx_id),
            ).fetchall()
            for fromno, tono in rows:
                if fromno > 0:
                    lines.add(int(fromno))
                if tono > 0:
                    lines.add(int(tono))
        else:
            rows = self._conn.execute(
                "SELECT numbits FROM line_bits WHERE file_id = ? AND context_id = ?",
                (file_id, ctx_id),
            ).fetchall()
            for (blob,) in rows:
                lines.update(decode_numbits(bytes(blob)))
        return frozenset(lines)


def verify_coverage_reachability(
    all_tests: list[DiscoveredTest],
    resolved_by_nodeid: dict[str, list[ResolvedTarget]],
    coverage_db: Path,
    *,
    partial: bool = False,
) -> tuple[int, int, list[Violation]]:
    """Check every ``@pytest.mark.covers`` target against ``coverage_db``.

    Returns ``(checks_evaluated, contexts_matched, violations)``.
    """
    violations: list[Violation] = []
    tests_by_nodeid = {t.nodeid: t for t in all_tests}
    checks_evaluated = 0
    contexts_matched = 0

    with CoverageContextDB(coverage_db) as db:
        file_id_cache: dict[Path, tuple[int | None, str | None]] = {}
        for nodeid in sorted(resolved_by_nodeid):
            test = tests_by_nodeid[nodeid]
            targets = resolved_by_nodeid[nodeid]
            if not test.is_hermetic and not partial:
                # Non-hermetic integration/live/e2e tests are not executed in the local suite.
                continue
            if test.is_skipped:
                continue

            for target in targets:
                ctxs = db.run_contexts_for_test(nodeid, param_id=target.spec.param_id)
                if not ctxs:
                    if partial:
                        continue
                    suffix = (
                        f" (param id={target.spec.param_id!r})"
                        if target.spec.param_id is not None
                        else ""
                    )
                    violations.append(
                        Violation(
                            "MISSING_CONTEXT",
                            nodeid,
                            f"no '|run' coverage context recorded for target {target.spec.raw!r}{suffix}. "
                            "Test was skipped, unselected, or renamed without executing.",
                        )
                    )
                    continue

                file_entry = file_id_cache.get(target.rel_path)
                if file_entry is None:
                    file_entry = _match_coverage_file_id(target.rel_path, db.files)
                    file_id_cache[target.rel_path] = file_entry
                fid, fid_err = file_entry
                if fid is None:
                    violations.append(
                        Violation(
                            "TARGET_FILE_NOT_MEASURED",
                            nodeid,
                            f"{target.spec.raw!r}: {fid_err}",
                        )
                    )
                    continue

                checks_evaluated += 1
                contexts_matched += len(ctxs)

                if target.spec.scope == "any_param":
                    hit_any = False
                    for ctx in ctxs:
                        exec_lines = db.executed_lines(fid, ctx)
                        if exec_lines & target.target_lines:
                            hit_any = True
                            break
                    if not hit_any:
                        t_min = min(target.target_lines)
                        t_max = max(target.target_lines)
                        violations.append(
                            Violation(
                                "TARGET_NOT_REACHED",
                                nodeid,
                                f"{target.spec.raw!r} ({target.resolution_kind}, "
                                f"{target.rel_path}:L{t_min}-L{t_max}) never executed in any of "
                                f"{len(ctxs)} parametrized '|run' context(s).",
                            )
                        )
                else:
                    for ctx in ctxs:
                        exec_lines = db.executed_lines(fid, ctx)
                        if not (exec_lines & target.target_lines):
                            t_min = min(target.target_lines)
                            t_max = max(target.target_lines)
                            violations.append(
                                Violation(
                                    "TARGET_NOT_REACHED",
                                    ctx,
                                    f"{target.spec.raw!r} ({target.resolution_kind}, "
                                    f"{target.rel_path}:L{t_min}-L{t_max}) executed 0 target lines "
                                    "(possible upstream short-circuit before reaching the tested branch).",
                                )
                            )

    return checks_evaluated, contexts_matched, violations


# ---------------------------------------------------------------------------
# Reconciliation report (repo-wide heuristic counts across naming variants)
# ---------------------------------------------------------------------------


def build_reconciliation_report(all_tests: list[DiscoveredTest]) -> dict[str, int]:
    """Count tests matching each spelling variant across the entire ``tests/`` tree."""
    counts: dict[str, int] = dict.fromkeys(RECONCILIATION_TOKENS, 0)
    counts["asserts_503"] = 0
    counts["total_tests"] = len(all_tests)
    counts["marked_covers"] = 0
    counts["marked_exempt"] = 0
    for t in all_tests:
        lower = t.func_name.lower()
        for tok in RECONCILIATION_TOKENS:
            if tok in lower:
                counts[tok] += 1
        if t.asserts_503:
            counts["asserts_503"] += 1
        if t.covers_specs:
            counts["marked_covers"] += 1
        if t.exemptions:
            counts["marked_exempt"] += 1
    return counts


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate @pytest.mark.covers fail-closed reachability annotations "
            "and (optionally) verify per-test execution in a .coverage database."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT_DEFAULT,
        help="Repository root directory (default: script parent).",
    )
    parser.add_argument(
        "--scope",
        choices=VALID_SCOPES,
        default="readback-and-503",
        help=(
            "Active mandatory discovery tier: 'holds', 'holds-and-503', "
            "'readback', 'readback-and-503' (default), or 'all'."
        ),
    )
    parser.add_argument(
        "--census-path",
        type=Path,
        default=None,
        help="Override path to evidence_claim_census.jsonl.",
    )
    parser.add_argument(
        "--verify-coverage",
        type=Path,
        default=None,
        help="Path to SQLite .coverage database generated with --cov-context=test.",
    )
    parser.add_argument(
        "--partial",
        action="store_true",
        help=(
            "With --verify-coverage, skip tests that have no '|run' context in the "
            "database (use for scoped single-file/subset runs)."
        ),
    )
    parser.add_argument(
        "--list-candidates",
        action="store_true",
        help="Print candidate nodeids for the selected --scope and exit 0.",
    )
    parser.add_argument(
        "--list-unmarked",
        action="store_true",
        help="Print only currently unmarked candidate nodeids for --scope and exit 0.",
    )
    parser.add_argument(
        "--list-shadow-excepts",
        action="store_true",
        help="Print outcome-normalizing except pairs under src/ with cover status and exit 0.",
    )
    parser.add_argument(
        "--shadow-baseline",
        type=Path,
        default=None,
        help="Override path to tests/.shadow-except-baseline.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help=(
            "Write current uncovered shadow-except count to tests/.shadow-except-baseline "
            "(monotonic ratchet: fails if count exceeds existing baseline)."
        ),
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Validate existing markers only without failing on unmarked candidates.",
    )
    parser.add_argument(
        "--reconciliation-report",
        action="store_true",
        help="Print full repo-wide token counts (candidate-finder reconciliation notice).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print summary details including reconciliation counts.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root: Path = args.repo_root.resolve()

    if args.list_candidates or args.list_unmarked:
        all_tests = scan_all_tests(repo_root)
        candidates, reasons = compute_scope_candidates(
            all_tests,
            scope=args.scope,
            repo_root=repo_root,
            census_path=args.census_path,
        )
        by_id = {t.nodeid: t for t in all_tests}
        for nid in sorted(candidates):
            t = by_id[nid]
            if args.list_unmarked and (t.covers_specs or t.exemptions):
                continue
            marker = (
                "COVERS"
                if t.covers_specs
                else ("EXEMPT" if t.exemptions else "UNMARKED")
            )
            print(f"{marker}\t{nid}\t{reasons[nid]}")
        return 0

    try:
        all_tests, candidates, _reasons, resolved, violations = verify_static(
            repo_root,
            scope=args.scope,
            census_path=args.census_path,
            require_candidates_marked=not args.skip_discovery,
            shadow_baseline_path=args.shadow_baseline,
            enforce_shadow_baseline=not (
                args.list_shadow_excepts or args.update_baseline
            ),
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.list_shadow_excepts:
        evaluated, uncovered = evaluate_shadow_except_pairs(repo_root, resolved)
        for pair in evaluated:
            status = "COVERED" if pair.is_covered else "UNCOVERED"
            covers = ",".join(pair.covered_by) if pair.covered_by else "-"
            print(
                f"{status}\t{pair.location}\t{pair.qualname}\t"
                f"{pair.earlier_type}\t{pair.later_type}\t{pair.outcome}\t{covers}"
            )
        print(
            f"# total_pairs={len(evaluated)} uncovered={len(uncovered)} "
            f"covered={len(evaluated) - len(uncovered)}",
            file=sys.stderr,
        )
        return 0

    if args.update_baseline:
        if violations:
            print(
                f"FAIL: refusing --update-baseline with {len(violations)} static violation(s):",
                file=sys.stderr,
            )
            for v in violations:
                print(f"  {v.format_line()}", file=sys.stderr)
            return 1
        evaluated, uncovered = evaluate_shadow_except_pairs(repo_root, resolved)
        baseline_file = resolve_shadow_baseline_path(repo_root, args.shadow_baseline)
        if baseline_file.is_file():
            existing, err = read_shadow_except_baseline(baseline_file)
            if err is not None:
                print(f"FAIL: {err}", file=sys.stderr)
                return 1
            if existing is not None and len(uncovered) > existing:
                print(
                    f"FAIL: refusing to raise shadow-except baseline from "
                    f"{existing} to {len(uncovered)} (monotonic ratchet).",
                    file=sys.stderr,
                )
                return 1
        write_shadow_except_baseline(len(uncovered), baseline_file)
        print(
            f"UPDATED: {baseline_file} = {len(uncovered)} "
            f"(total_pairs={len(evaluated)}, covered={len(evaluated) - len(uncovered)})"
        )
        return 0

    checks_eval = 0
    ctx_matched = 0
    if args.verify_coverage is not None:
        if not resolved:
            print(
                "ERROR: zero @pytest.mark.covers targets found to verify against coverage DB.",
                file=sys.stderr,
            )
            return 2
        try:
            checks_eval, ctx_matched, cov_violations = verify_coverage_reachability(
                all_tests,
                resolved,
                args.verify_coverage,
                partial=args.partial,
            )
        except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
            print(
                f"ERROR reading coverage database {args.verify_coverage}: {exc}",
                file=sys.stderr,
            )
            return 2
        violations.extend(cov_violations)

    if args.reconciliation_report or args.verbose:
        rec = build_reconciliation_report(all_tests)
        shadow_all, shadow_uncovered, shadow_base, _ = check_shadow_except_baseline(
            repo_root,
            resolved,
            shadow_baseline_path=args.shadow_baseline,
            enforce=False,
        )
        print(
            "Reconciliation report (AST name scan is a candidate finder requiring "
            "reconciliation, not a semantic definition of all fail-closed tests):"
        )
        print(
            f"  total_tests={rec['total_tests']} "
            f"in_scope[{args.scope}]={len(candidates)} "
            f"marked_covers={rec['marked_covers']} "
            f"marked_exempt={rec['marked_exempt']} "
            f"shadow_except_pairs={len(shadow_all)} "
            f"shadow_except_uncovered={len(shadow_uncovered)} "
            f"shadow_except_baseline={shadow_base}"
        )
        tok_line = ", ".join(
            f"{tok}={rec[tok]}" for tok in ("asserts_503", *RECONCILIATION_TOKENS)
        )
        print(f"  repo_wide_tokens: {tok_line}")

    if violations:
        print(
            f"FAIL: {len(violations)} fail-closed coverage violation(s) "
            f"(scope={args.scope}, candidates={len(candidates)}, "
            f"covers_targets={sum(len(v) for v in resolved.values())}):",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v.format_line()}", file=sys.stderr)
        return 1

    runtime_note = (
        f", verified_targets={checks_eval} across {ctx_matched} '|run' context(s)"
        if args.verify_coverage is not None
        else ""
    )
    print(
        f"OK: scope={args.scope}, candidates={len(candidates)}, "
        f"marked_tests={len(resolved)}, "
        f"covers_targets={sum(len(v) for v in resolved.values())}"
        f"{runtime_note}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
