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
   * Finds outcome-normalizing ``except`` fallthrough pairs under ``src/`` and
     ``packages/*/src/`` (ordered shadowing handlers on the same ``try`` whose
     branch-aware terminal statements produce equivalent ``return`` / ``raise`` /
     HTTP ``status_code`` / fallthrough outcomes, binding bare ``raise`` to the
     caught exception type and excluding provably disjoint sibling handlers) and
     enforces a detector-bound monotonic ratchet (``tests/.shadow-except-baseline``).
     ``--update-baseline`` can only lower the ceiling under an unchanged
     ``detector_sha256``; ``--recompute-baseline --reason "..."`` is permitted
     **only** when ``detector_sha256`` changes and records before/after counts
     and the reason in an append-only history chain.

     **Standing-debt policy & remediation classes:** The tracked ceiling is
     standing historical debt governed by a non-regression ratchet (preventing
     new shadow-except pairs rather than committing to clear all historical
     items). Optional burn-down prioritizes ``oscal_claim_cited`` pairs — source
     modules cited on ``read_back``-backed claims in
     ``compliance/oscal/evidence_claim_census.jsonl``, where a dead narrow
     handler propagates into a published OSCAL claim. Uncovered pairs split into
     two remediation classes recorded separately in the baseline:

     - ``collapse_or_covers_pin``: identical return/raise/fallthrough or
       ``reraise-vs-wrap`` outcomes — resolve by (1) collapsing identical
       handlers into one ``except`` tuple, (2) folding pure-logging differences,
       (3) pinning security-distinct earlier handlers with an anchored
       ``@pytest.mark.covers("module:qualname#anchor")``, or (4) asserting the
       observable side effect when both branches return the same sentinel.
     - ``needs_structured_discriminator``: handlers whose ``return`` expressions
       differ **only** by free-text prose (``message`` / ``error`` /
       ``advisor_error``) — a ``@pytest.mark.covers`` pin does **not** clear
       these; add a structured discriminator (``code`` / ``failure_kind`` /
       ``reason_code``) or collapse the handlers.

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
import copy
import hashlib
import io
import json
import re
import sqlite3
import sys
import tokenize
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

REPO_ROOT_DEFAULT: Final[Path] = Path(__file__).resolve().parent.parent
CENSUS_REL_PATH: Final[Path] = Path("compliance/oscal/evidence_claim_census.jsonl")
TESTS_REL_DIR: Final[Path] = Path("tests")
SRC_REL_DIR: Final[Path] = Path("src")
PACKAGES_REL_DIR: Final[Path] = Path("packages")
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
SOURCE_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![0-9a-f]{8}:)((?:src|packages)/[A-Za-z0-9_./-]+\.py)"
)

REMEDIATION_COLLAPSE_OR_PIN: Final[str] = "collapse_or_covers_pin"
REMEDIATION_STRUCTURED_DISCRIMINATOR: Final[str] = "needs_structured_discriminator"
VALID_REMEDIATION_CLASSES: Final[frozenset[str]] = frozenset(
    {REMEDIATION_COLLAPSE_OR_PIN, REMEDIATION_STRUCTURED_DISCRIMINATOR}
)

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
    remediation_class: str = REMEDIATION_COLLAPSE_OR_PIN
    oscal_claim_cited: bool = False
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


def load_census_claim_source_files(
    repo_root: Path,
    *,
    census_path: Path | None = None,
) -> set[str]:
    """Extract live ``src/`` and ``packages/`` Python files cited on ``read_back`` OSCAL claims."""
    path = census_path if census_path is not None else (repo_root / CENSUS_REL_PATH)
    if not path.is_file():
        return set()
    files: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not row.get("read_back"):
            continue
        for field_val in (row.get("cites"), row.get("read_back")):
            if field_val is None:
                continue
            text = (
                field_val
                if isinstance(field_val, str)
                else json.dumps(field_val, sort_keys=True)
            )
            files.update(SOURCE_PATH_RE.findall(text))
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
# Outcome-normalizing except fallthrough finder & detector-bound ratchet
# ---------------------------------------------------------------------------

# BEGIN SHADOW_EXCEPT_DETECTOR
SHADOW_VENDOR_PREFIXES: Final[tuple[str, ...]] = (
    "src/gateway/governance/vendor/",
    "packages/cage-client/src/cage_client/_jcs/",
)

_BASE_ONLY_EXCEPTIONS: Final[frozenset[str]] = frozenset(
    {
        "BaseException",
        "SystemExit",
        "KeyboardInterrupt",
        "GeneratorExit",
        "CancelledError",
    }
)
_PROSE_RETURN_KWARGS: Final[frozenset[str]] = frozenset(
    {"message", "error", "advisor_error"}
)
_PROSE_RETURN_DICT_KEYS: Final[frozenset[str]] = frozenset({"message", "advisor_error"})

_KNOWN_EXCEPTION_PARENTS: Final[dict[str, tuple[str, ...]]] = {
    "BaseException": (),
    "SystemExit": ("BaseException",),
    "KeyboardInterrupt": ("BaseException",),
    "GeneratorExit": ("BaseException",),
    "CancelledError": ("BaseException",),
    "Exception": ("BaseException",),
    "ArithmeticError": ("Exception",),
    "ZeroDivisionError": ("ArithmeticError",),
    "LookupError": ("Exception",),
    "IndexError": ("LookupError",),
    "KeyError": ("LookupError",),
    "OSError": ("Exception",),
    "IOError": ("OSError",),
    "FileNotFoundError": ("OSError",),
    "PermissionError": ("OSError",),
    "ConnectionError": ("OSError",),
    "TimeoutError": ("OSError",),
    "ImportError": ("Exception",),
    "ModuleNotFoundError": ("ImportError",),
    "RuntimeError": ("Exception",),
    "ValueError": ("Exception",),
    "UnicodeError": ("ValueError",),
    "UnicodeDecodeError": ("UnicodeError",),
    "UnicodeEncodeError": ("UnicodeError",),
    "JSONDecodeError": ("ValueError",),
    "ValidationError": ("ValueError",),
    "TypeError": ("Exception",),
    "AttributeError": ("Exception",),
    "HTTPError": ("Exception",),
    "RequestError": ("HTTPError",),
    "HTTPStatusError": ("HTTPError",),
    "TransportError": ("RequestError",),
    "TimeoutException": ("TransportError",),
    "ConnectTimeout": ("TimeoutException",),
    "ReadTimeout": ("TimeoutException",),
    "WriteTimeout": ("TimeoutException",),
    "PoolTimeout": ("TimeoutException",),
    "NetworkError": ("TransportError",),
    "ConnectError": ("NetworkError",),
    "ReadError": ("NetworkError",),
    "WriteError": ("NetworkError",),
    "CloseError": ("NetworkError",),
    "ProtocolError": ("TransportError",),
    "LocalProtocolError": ("ProtocolError",),
    "RemoteProtocolError": ("ProtocolError",),
    "ProxyError": ("TransportError",),
    "UnsupportedProtocol": ("TransportError",),
    "DecodingError": ("RequestError",),
    "TooManyRedirects": ("RequestError",),
    "PyJWTError": ("Exception",),
    "InvalidTokenError": ("PyJWTError",),
    "DecodeError": ("InvalidTokenError",),
    "InvalidSignatureError": ("DecodeError",),
    "ExpiredSignatureError": ("InvalidTokenError",),
    "ImmatureSignatureError": ("InvalidTokenError",),
    "InvalidAudienceError": ("InvalidTokenError",),
    "InvalidIssuerError": ("InvalidTokenError",),
    "InvalidAlgorithmError": ("InvalidTokenError",),
}

_OutcomeToken = tuple[str, str, str | None, str | None]


def _call_tail_name(node: ast.expr) -> str | None:
    """Return bare identifier or attribute tail of a callee/type expression."""
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


class _ProseFieldNormalizer(ast.NodeTransformer):
    """Scrub free-text message kwargs/dict values while keeping structured codes intact."""

    def visit_keyword(self, node: ast.keyword) -> ast.keyword:
        visited = self.generic_visit(node)
        assert isinstance(visited, ast.keyword)
        if visited.arg in _PROSE_RETURN_KWARGS:
            return ast.keyword(arg=visited.arg, value=ast.Constant(value="<prose>"))
        return visited

    def visit_Dict(self, node: ast.Dict) -> ast.Dict:
        new_keys: list[ast.expr | None] = []
        new_vals: list[ast.expr] = []
        for key, val in zip(node.keys, node.values, strict=True):
            new_keys.append(key)
            if (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value in _PROSE_RETURN_DICT_KEYS
            ):
                new_vals.append(ast.Constant(value="<prose>"))
            else:
                visited_val = self.visit(val)
                assert isinstance(visited_val, ast.expr)
                new_vals.append(visited_val)
        return ast.Dict(keys=new_keys, values=new_vals)


def _resolve_shadow_scan_dirs(repo_root: Path, src_dir: Path | None) -> list[Path]:
    """Return existing Python source roots to audit (`src/` + `packages/*/src/`)."""
    if src_dir is not None:
        return [src_dir] if src_dir.is_dir() else []
    candidates: list[Path] = [repo_root / SRC_REL_DIR]
    pkgs_dir = repo_root / PACKAGES_REL_DIR
    if pkgs_dir.is_dir():
        candidates.extend(sorted(pkgs_dir.glob("*/src")))
    return [d for d in candidates if d.is_dir()]


def _collect_shadow_python_files(
    repo_root: Path,
    scan_dirs: Sequence[Path],
) -> list[tuple[str, ast.Module]]:
    """Parse non-vendored Python modules across ``scan_dirs``."""
    parsed: list[tuple[str, ast.Module]] = []
    for search_dir in scan_dirs:
        for py_path in sorted(search_dir.rglob("*.py")):
            try:
                rel_path = _normalize_posix(str(py_path.relative_to(repo_root)))
            except ValueError:
                rel_path = _normalize_posix(str(py_path))
            if rel_path.startswith(SHADOW_VENDOR_PREFIXES):
                continue
            source = py_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel_path)
            parsed.append((rel_path, tree))
    return parsed


def _build_exception_parents(
    parsed_files: Sequence[tuple[str, ast.Module]],
) -> dict[str, set[str]]:
    """Combine known stdlib/library exception hierarchy with AST class definitions."""
    parents: dict[str, set[str]] = {
        cls_name: set(bases) for cls_name, bases in _KNOWN_EXCEPTION_PARENTS.items()
    }
    for _, tree in parsed_files:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                base_name = _call_tail_name(base)
                if base_name and base_name != node.name:
                    parents.setdefault(node.name, set()).add(base_name)
    return parents


def _exception_ancestors(
    name: str,
    parents: dict[str, set[str]],
) -> set[str]:
    """Return all transitive base class names for ``name``."""
    seen: set[str] = set()
    stack = list(parents.get(name, ()))
    while stack:
        cur = stack.pop()
        if cur not in seen:
            seen.add(cur)
            stack.extend(parents.get(cur, ()))
    return seen


def _handler_type_names(htype: ast.expr | None) -> tuple[list[str], bool]:
    """Extract caught exception class names and whether a dynamic tuple var is used."""
    if htype is None:
        return ["BaseException"], False
    elts = list(htype.elts) if isinstance(htype, ast.Tuple) else [htype]
    names: list[str] = []
    has_dynamic = False
    for elt in elts:
        nm = _call_tail_name(elt)
        if nm is None:
            has_dynamic = True
        else:
            names.append(nm)
            if not nm[0].isupper() and not nm.startswith("_"):
                has_dynamic = True
    return names, has_dynamic


def _can_shadow(
    h_earlier: ast.ExceptHandler,
    h_later: ast.ExceptHandler,
    parents: dict[str, set[str]],
) -> bool:
    """True when ``h_later`` can catch an exception targeted by ``h_earlier``."""
    e_names, _ = _handler_type_names(h_earlier.type)
    l_names, l_dynamic = _handler_type_names(h_later.type)
    if h_later.type is None or "BaseException" in l_names:
        return True
    if "Exception" in l_names:
        return not (bool(e_names) and set(e_names).issubset(_BASE_ONLY_EXCEPTIONS))
    if l_dynamic:
        return True
    for e_name in e_names:
        anc = _exception_ancestors(e_name, parents)
        for l_name in l_names:
            if e_name == l_name or l_name in anc:
                return True
    return False


def _single_caught_name(htype: ast.expr | None) -> str | None:
    """Return single caught exception class name when ``htype`` is not a tuple/bare."""
    if htype is None or isinstance(htype, ast.Tuple):
        return None
    nm = _call_tail_name(htype)
    if nm and (nm[0].isupper() or nm.startswith("_")):
        return nm
    return None


def _summarize_return_outcome(stmt: ast.Return) -> _OutcomeToken:
    if stmt.value is None:
        return ("return_const", "return None", None, None)
    if isinstance(stmt.value, ast.Constant):
        return ("return_const", f"return {stmt.value.value!r}", None, None)
    raw_expr = ast.unparse(stmt.value)
    normalized = _ProseFieldNormalizer().visit(copy.deepcopy(stmt.value))
    return ("return_expr", f"return {ast.unparse(normalized)}", None, raw_expr)


def _summarize_raise_outcome(
    stmt: ast.Raise,
    caught_name: str | None,
) -> set[_OutcomeToken]:
    if stmt.exc is None:
        if caught_name and caught_name not in (
            "Exception",
            "BaseException",
            "HTTPException",
        ):
            return {
                ("reraise_typed", f"raise {caught_name}", caught_name, None),
                ("raise", "reraise", None, None),
            }
        return {("raise", "reraise", None, None)}
    if isinstance(stmt.exc, ast.Call):
        fn = _call_tail_name(stmt.exc.func) or ast.unparse(stmt.exc.func)
        sc = _status_code_kw(stmt.exc)
        detail = f"{fn}:{sc}" if sc is not None else fn
        return {("raise_call", f"raise {detail}", fn if sc is None else None, None)}
    return {("raise_expr", f"raise {ast.unparse(stmt.exc)}", None, None)}


def _handler_outcomes(
    stmts: list[ast.stmt],
    caught_name: str | None,
) -> set[_OutcomeToken]:
    """Collect terminal control-flow outcomes across compound ``if``/``with`` tails."""
    if not stmts:
        return {("fallthrough", "fallthrough", None, None)}
    last = stmts[-1]
    if isinstance(last, ast.Return):
        return {_summarize_return_outcome(last)}
    if isinstance(last, ast.Raise):
        return _summarize_raise_outcome(last, caught_name)
    if isinstance(last, ast.Break):
        return {("break", "break", None, None)}
    if isinstance(last, ast.Continue):
        return {("continue", "continue", None, None)}
    if isinstance(last, ast.If):
        then_out = _handler_outcomes(last.body, caught_name)
        else_out = (
            _handler_outcomes(last.orelse, caught_name)
            if last.orelse
            else {("fallthrough", "fallthrough", None, None)}
        )
        return then_out | else_out
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _handler_outcomes(last.body, caught_name)
    return {("fallthrough", "fallthrough", None, None)}


def _pair_token_match(
    tok_i: _OutcomeToken,
    tok_j: _OutcomeToken,
    parents: dict[str, set[str]],
) -> tuple[str, str] | None:
    k_i, lbl_i, cls_i, raw_i = tok_i
    k_j, lbl_j, cls_j, raw_j = tok_j
    if k_i == "fallthrough" or k_j == "fallthrough":
        return None
    if k_i == k_j and lbl_i == lbl_j:
        if k_i == "return_expr" and raw_i != raw_j:
            return (lbl_i, REMEDIATION_STRUCTURED_DISCRIMINATOR)
        return (lbl_i, REMEDIATION_COLLAPSE_OR_PIN)
    if k_i == "reraise_typed" and k_j == "raise_call" and cls_i and cls_j:
        if cls_i == cls_j or cls_i in _exception_ancestors(cls_j, parents):
            return (lbl_j, REMEDIATION_COLLAPSE_OR_PIN)
    if k_i == "raise_call" and k_j == "reraise_typed" and cls_i and cls_j:
        if cls_i == cls_j or cls_j in _exception_ancestors(cls_i, parents):
            return (lbl_i, REMEDIATION_COLLAPSE_OR_PIN)
    return None


def _matching_shadow_outcome(
    h_earlier: ast.ExceptHandler,
    h_later: ast.ExceptHandler,
    parents: dict[str, set[str]],
) -> tuple[str, str] | None:
    """Return ``(outcome, remediation_class)`` if ``h_later`` normalizes ``h_earlier``."""
    out_i = _handler_outcomes(h_earlier.body, _single_caught_name(h_earlier.type))
    out_j = _handler_outcomes(h_later.body, _single_caught_name(h_later.type))
    matched: list[tuple[str, str]] = []
    for tok_i in out_i:
        for tok_j in out_j:
            hit = _pair_token_match(tok_i, tok_j, parents)
            if hit is not None:
                matched.append(hit)
    if matched:
        ordered = sorted(
            set(matched),
            key=lambda item: (
                item[0] == "reraise",
                item[1] != REMEDIATION_COLLAPSE_OR_PIN,
                item[0],
            ),
        )
        return ordered[0]
    pure_fallthrough = {("fallthrough", "fallthrough", None, None)}
    if out_i == pure_fallthrough and out_j == pure_fallthrough:
        return ("fallthrough", REMEDIATION_COLLAPSE_OR_PIN)
    return None


def _body_line_span(stmts: list[ast.stmt]) -> frozenset[int]:
    """Collect all source line numbers spanned by statements in ``stmts``."""
    lines: set[int] = set()
    for stmt in stmts:
        end = stmt.end_lineno if stmt.end_lineno is not None else stmt.lineno
        lines.update(range(stmt.lineno, end + 1))
    return frozenset(lines)


class _ShadowExceptVisitor(ast.NodeVisitor):
    """AST visitor collecting ordered outcome-normalizing ``except`` pairs."""

    def __init__(
        self,
        rel_path: str,
        parents: dict[str, set[str]],
        *,
        oscal_claim_cited: bool = False,
    ) -> None:
        self.rel_path = rel_path
        self._parents = parents
        self._oscal_claim_cited = oscal_claim_cited
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
        for i, h_i in enumerate(handlers):
            for h_j in handlers[i + 1 :]:
                if not _can_shadow(h_i, h_j, self._parents):
                    continue
                match = _matching_shadow_outcome(h_i, h_j, self._parents)
                if match is None:
                    continue
                outcome, rem_cls = match
                self.pairs.append(
                    ShadowExceptPair(
                        rel_path=self.rel_path,
                        qualname=qualname,
                        earlier_lineno=h_i.lineno,
                        earlier_end_lineno=h_i.end_lineno or h_i.lineno,
                        earlier_body_lines=_body_line_span(h_i.body),
                        earlier_type=(
                            ast.unparse(h_i.type) if h_i.type is not None else "bare"
                        ),
                        later_lineno=h_j.lineno,
                        later_end_lineno=h_j.end_lineno or h_j.lineno,
                        later_type=(
                            ast.unparse(h_j.type) if h_j.type is not None else "bare"
                        ),
                        outcome=outcome,
                        remediation_class=rem_cls,
                        oscal_claim_cited=self._oscal_claim_cited,
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
    census_path: Path | None = None,
) -> list[ShadowExceptPair]:
    """Scan Python modules under ``src/`` and ``packages/*/src/`` for shadow-except pairs."""
    scan_dirs = _resolve_shadow_scan_dirs(repo_root, src_dir)
    if not scan_dirs:
        return []
    claim_files = load_census_claim_source_files(repo_root, census_path=census_path)
    parsed_files = _collect_shadow_python_files(repo_root, scan_dirs)
    parents = _build_exception_parents(parsed_files)
    pairs: list[ShadowExceptPair] = []
    for rel_path, tree in parsed_files:
        visitor = _ShadowExceptVisitor(
            rel_path,
            parents,
            oscal_claim_cited=(rel_path in claim_files),
        )
        visitor.visit(tree)
        pairs.extend(visitor.pairs)
    return pairs


def evaluate_shadow_except_pairs(
    repo_root: Path,
    resolved_by_nodeid: dict[str, list[ResolvedTarget]],
    *,
    src_dir: Path | None = None,
    census_path: Path | None = None,
) -> tuple[list[ShadowExceptPair], list[ShadowExceptPair]]:
    """Classify each outcome-normalizing ``except`` pair as covered or uncovered.

    A ``collapse_or_covers_pin`` pair is covered when at least one anchored
    ``@pytest.mark.covers`` target (``statement_anchor`` or
    ``branch_body_anchor`` — never coarse ``function_body``) resolves inside the
    earlier handler's body without touching the later handler's line span.
    Pairs in ``needs_structured_discriminator`` (differentiated only by
    free-text prose) are **never** cleared by a ``@pytest.mark.covers`` pin:
    they require adding a structured ``code``/``failure_kind`` discriminator or
    collapsing the handlers.
    """
    raw_pairs = find_outcome_normalizing_except_pairs(
        repo_root, src_dir=src_dir, census_path=census_path
    )
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
        hits: list[str] = []
        if pair.remediation_class != REMEDIATION_STRUCTURED_DISCRIMINATOR:
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
            remediation_class=pair.remediation_class,
            oscal_claim_cited=pair.oscal_claim_cited,
            covered_by=tuple(hits),
        )
        evaluated.append(updated)
        if not updated.is_covered:
            uncovered.append(updated)
    return evaluated, uncovered


# END SHADOW_EXCEPT_DETECTOR

SHADOW_BASELINE_SCHEMA_VERSION: Final[int] = 1
MIN_RECOMPUTE_REASON_LEN: Final[int] = 24
_DETECTOR_BEGIN_SENTINEL: Final[str] = "# BEGIN " + "SHADOW_EXCEPT_DETECTOR\n"
_DETECTOR_END_SENTINEL: Final[str] = "# END " + "SHADOW_EXCEPT_DETECTOR"

STANDING_DEBT_POLICY_DEFAULT: Final[str] = (
    "Non-regression ratchet over standing historical debt: prevents new shadow-except "
    "pairs rather than committing to clear all historical items. Optional burn-down "
    "prioritizes oscal_claim_cited pairs (modules cited on read_back-backed claims in "
    "compliance/oscal/evidence_claim_census.jsonl, where a dead narrow handler affects "
    "a published OSCAL claim). Pairs in needs_structured_discriminator differ only by "
    "free-text message/error prose and cannot be cleared by @pytest.mark.covers pins "
    "— add a structured code/failure_kind discriminator or collapse the handlers."
)


@dataclass(frozen=True)
class ShadowBaselineState:
    """Validated detector-bound baseline state and append-only audit history."""

    baseline: int
    detector_sha256: str
    uncovered_breakdown: dict[str, int]
    standing_debt_policy: str
    history: tuple[dict[str, object], ...]


def summarize_shadow_uncovered_breakdown(
    uncovered: Sequence[ShadowExceptPair],
) -> dict[str, int]:
    """Partition uncovered shadow pairs by remediation class and OSCAL claim citation."""
    prose_only = sum(
        1
        for p in uncovered
        if p.remediation_class == REMEDIATION_STRUCTURED_DISCRIMINATOR
    )
    collapse_or_pin = len(uncovered) - prose_only
    oscal_cited = sum(1 for p in uncovered if p.oscal_claim_cited)
    return {
        REMEDIATION_COLLAPSE_OR_PIN: collapse_or_pin,
        REMEDIATION_STRUCTURED_DISCRIMINATOR: prose_only,
        "oscal_claim_cited": oscal_cited,
    }


def _docstring_spans(tree: ast.Module) -> tuple[set[tuple[int, int]], set[int]]:
    """Return docstring ``(lineno, col_offset)`` starts and ``end_lineno`` lines."""
    starts: set[tuple[int, int]] = set()
    end_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_val = body[0].value
                starts.add((doc_val.lineno, doc_val.col_offset))
                end_lines.add(doc_val.end_lineno or doc_val.lineno)
    return starts, end_lines


def compute_shadow_detector_fingerprint(script_path: Path | None = None) -> str:
    """Compute a Python-version-portable SHA-256 over the shadow-except detector tokens.

    Hashes logical code tokens (including block ``INDENT``/``DEDENT`` and
    ``NEWLINE`` boundaries while ignoring comments, non-logical line-wrapping
    ``NL`` whitespace, and docstrings) between the detector sentinels. Any
    change to detector logic, constants, or scanned roots alters this digest.
    """
    path = script_path if script_path is not None else Path(__file__).resolve()
    source = path.read_text(encoding="utf-8")
    start_idx = source.find(_DETECTOR_BEGIN_SENTINEL)
    end_idx = source.find(_DETECTOR_END_SENTINEL)
    if start_idx < 0 or end_idx <= start_idx:
        raise RuntimeError(
            f"Missing shadow-except detector sentinels in {path}; cannot compute detector_sha256"
        )
    section = source[start_idx + len(_DETECTOR_BEGIN_SENTINEL) : end_idx]
    doc_starts, doc_end_lines = _docstring_spans(ast.parse(section))
    digest = hashlib.sha256()
    skip_types = {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
    }
    for tok in tokenize.generate_tokens(io.StringIO(section).readline):
        if tok.type in skip_types:
            continue
        if tok.type == tokenize.STRING and tok.start in doc_starts:
            continue
        if tok.type == tokenize.NEWLINE and tok.start[0] in doc_end_lines:
            continue
        if tok.type == tokenize.INDENT:
            payload = "INDENT"
        elif tok.type == tokenize.DEDENT:
            payload = "DEDENT"
        elif tok.type == tokenize.NEWLINE:
            payload = "NEWLINE"
        else:
            payload = f"{tok.type}:{tok.string}"
        digest.update(payload.encode("utf-8") + b"\0")
    return digest.hexdigest()


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


def _is_non_neg_int(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val >= 0


def _validate_uncovered_breakdown(
    raw_bd: object,
    expected_total: int,
) -> tuple[dict[str, int] | None, str | None]:
    if not isinstance(raw_bd, dict):
        return None, "uncovered_breakdown must be a JSON object"
    cp = raw_bd.get(REMEDIATION_COLLAPSE_OR_PIN)
    ns = raw_bd.get(REMEDIATION_STRUCTURED_DISCRIMINATOR)
    oc = raw_bd.get("oscal_claim_cited")
    if not (_is_non_neg_int(cp) and _is_non_neg_int(ns) and _is_non_neg_int(oc)):
        return (
            None,
            "uncovered_breakdown requires non-negative integer "
            "collapse_or_covers_pin, needs_structured_discriminator, and oscal_claim_cited",
        )
    assert isinstance(cp, int) and isinstance(ns, int) and isinstance(oc, int)
    if cp + ns != expected_total:
        return (
            None,
            f"uncovered_breakdown remediation sum ({cp} + {ns}) != baseline ({expected_total})",
        )
    if oc > expected_total:
        return (
            None,
            f"uncovered_breakdown.oscal_claim_cited ({oc}) > baseline ({expected_total})",
        )
    return {
        REMEDIATION_COLLAPSE_OR_PIN: cp,
        REMEDIATION_STRUCTURED_DISCRIMINATOR: ns,
        "oscal_claim_cited": oc,
    }, None


def _validate_history_counts(idx: int, entry: dict[str, object]) -> str | None:
    after_base = entry.get("after_baseline")
    after_cov = entry.get("after_covered")
    after_tot = entry.get("after_total")
    if not (
        _is_non_neg_int(after_base)
        and _is_non_neg_int(after_cov)
        and _is_non_neg_int(after_tot)
    ):
        return f"history[{idx}] requires non-negative integer after_baseline/after_covered/after_total"
    assert (
        isinstance(after_base, int)
        and isinstance(after_cov, int)
        and isinstance(after_tot, int)
    )
    if after_base + after_cov != after_tot:
        return (
            f"history[{idx}] count mismatch: after_baseline ({after_base}) + "
            f"after_covered ({after_cov}) != after_total ({after_tot})"
        )
    return None


def _validate_history_transition(
    idx: int,
    event: str,
    entry: dict[str, object],
    prev: dict[str, object],
) -> str | None:
    before_base = entry.get("before_baseline")
    before_sha = entry.get("before_detector_sha256")
    det_sha = entry.get("detector_sha256")
    after_base = entry.get("after_baseline")
    reason = str(entry.get("reason", "")).strip()
    if before_base != prev.get("after_baseline"):
        return (
            f"history[{idx}].before_baseline ({before_base!r}) does not match "
            f"history[{idx - 1}].after_baseline ({prev.get('after_baseline')!r})"
        )
    if before_sha != prev.get("detector_sha256"):
        return (
            f"history[{idx}].before_detector_sha256 ({before_sha!r}) does not match "
            f"history[{idx - 1}].detector_sha256 ({prev.get('detector_sha256')!r})"
        )
    if event == "update":
        if det_sha != before_sha:
            return f"history[{idx}] ('update') cannot change detector_sha256; use 'recompute'"
        assert isinstance(after_base, int) and isinstance(before_base, int)
        if after_base > before_base:
            return (
                f"history[{idx}] ('update') raised baseline from "
                f"{before_base} to {after_base} (monotonic violation)"
            )
        return None
    if det_sha == before_sha:
        return (
            f"history[{idx}] ('recompute') has unchanged detector_sha256 ({det_sha!r}); "
            "recomputation is permitted only when the detector changes"
        )
    if len(reason) < MIN_RECOMPUTE_REASON_LEN:
        return (
            f"history[{idx}] ('recompute') reason must be at least "
            f"{MIN_RECOMPUTE_REASON_LEN} chars (got {len(reason)})"
        )
    return None


def _validate_history_entry(
    idx: int,
    entry: object,
    prev: dict[str, object] | None,
) -> str | None:
    if not isinstance(entry, dict):
        return f"history[{idx}] must be a JSON object"
    event = entry.get("event")
    det_sha = entry.get("detector_sha256")
    reason = entry.get("reason")
    if not isinstance(det_sha, str) or not det_sha.strip():
        return f"history[{idx}].detector_sha256 must be a non-empty string"
    if not isinstance(reason, str) or not reason.strip():
        return f"history[{idx}].reason must be a non-empty string"
    cnt_err = _validate_history_counts(idx, entry)
    if cnt_err is not None:
        return cnt_err
    if idx == 0:
        if event != "initial_baseline":
            return f"history[0].event must be 'initial_baseline', got {event!r}"
        if (
            entry.get("before_baseline") is not None
            or entry.get("before_detector_sha256") is not None
        ):
            return (
                "history[0] must set before_baseline and before_detector_sha256 to null"
            )
        return None
    if event not in ("update", "recompute"):
        return f"history[{idx}].event must be 'update' or 'recompute', got {event!r}"
    assert prev is not None
    return _validate_history_transition(idx, event, entry, prev)


def _parse_baseline_json(
    baseline_path: Path,
) -> tuple[dict[str, object] | None, str | None]:
    if not baseline_path.is_file():
        return None, f"missing shadow-except baseline file {baseline_path}"
    raw = baseline_path.read_text(encoding="utf-8").strip()
    if not raw:
        return None, f"empty shadow-except baseline file {baseline_path}"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in shadow-except baseline {baseline_path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"shadow-except baseline {baseline_path} must be a JSON object"
    if payload.get("schema_version") != SHADOW_BASELINE_SCHEMA_VERSION:
        return (
            None,
            f"unsupported schema_version {payload.get('schema_version')!r} in {baseline_path}",
        )
    return payload, None


def read_shadow_except_baseline(
    baseline_path: Path,
) -> tuple[ShadowBaselineState | None, str | None]:
    """Read and validate the detector-bound baseline JSON and history chain."""
    payload, parse_err = _parse_baseline_json(baseline_path)
    if parse_err is not None or payload is None:
        return None, parse_err
    baseline = payload.get("baseline")
    det_sha = payload.get("detector_sha256")
    policy = payload.get("standing_debt_policy")
    history = payload.get("history")
    if not _is_non_neg_int(baseline):
        return None, f"invalid baseline {baseline!r} in {baseline_path}"
    assert isinstance(baseline, int)
    if not isinstance(det_sha, str) or not det_sha.strip():
        return None, f"invalid detector_sha256 {det_sha!r} in {baseline_path}"
    if not isinstance(policy, str) or not policy.strip():
        return None, f"missing standing_debt_policy in {baseline_path}"
    breakdown, bd_err = _validate_uncovered_breakdown(
        payload.get("uncovered_breakdown"), baseline
    )
    if bd_err is not None or breakdown is None:
        return None, f"{baseline_path}: {bd_err}"
    if not isinstance(history, list) or not history:
        return None, f"history must be a non-empty list in {baseline_path}"
    prev_entry: dict[str, object] | None = None
    typed_history: list[dict[str, object]] = []
    for idx, item in enumerate(history):
        err = _validate_history_entry(idx, item, prev_entry)
        if err is not None:
            return None, f"{baseline_path}: {err}"
        assert isinstance(item, dict)
        typed_history.append(item)
        prev_entry = item
    last = typed_history[-1]
    if baseline != last["after_baseline"] or det_sha != last["detector_sha256"]:
        return (
            None,
            f"{baseline_path}: top-level baseline/detector_sha256 disagrees with history[-1]",
        )
    return (
        ShadowBaselineState(
            baseline=baseline,
            detector_sha256=det_sha,
            uncovered_breakdown=breakdown,
            standing_debt_policy=policy,
            history=tuple(typed_history),
        ),
        None,
    )


def write_shadow_except_baseline_state(
    state: ShadowBaselineState,
    baseline_path: Path,
) -> None:
    """Serialize a validated ``ShadowBaselineState`` to ``baseline_path``."""
    doc = {
        "schema_version": SHADOW_BASELINE_SCHEMA_VERSION,
        "baseline": state.baseline,
        "detector_sha256": state.detector_sha256,
        "standing_debt_policy": state.standing_debt_policy,
        "uncovered_breakdown": state.uncovered_breakdown,
        "history": list(state.history),
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _, err = read_shadow_except_baseline(baseline_path)
    if err is not None:
        raise ValueError(f"Refusing to write invalid baseline state: {err}")


def write_initial_shadow_except_baseline(
    count: int,
    baseline_path: Path,
    *,
    covered: int = 0,
    detector_sha256: str | None = None,
    uncovered_breakdown: dict[str, int] | None = None,
    standing_debt_policy: str = STANDING_DEBT_POLICY_DEFAULT,
    reason: str = "Initial shadow-except baseline.",
) -> ShadowBaselineState:
    """Initialize a fresh ``schema_version=1`` shadow-except baseline file."""
    if count < 0 or covered < 0:
        raise ValueError(f"counts must be >= 0 (count={count}, covered={covered})")
    sha = (
        detector_sha256
        if detector_sha256 is not None
        else compute_shadow_detector_fingerprint()
    )
    breakdown = (
        dict(uncovered_breakdown)
        if uncovered_breakdown is not None
        else {
            REMEDIATION_COLLAPSE_OR_PIN: count,
            REMEDIATION_STRUCTURED_DISCRIMINATOR: 0,
            "oscal_claim_cited": 0,
        }
    )
    entry: dict[str, object] = {
        "event": "initial_baseline",
        "before_baseline": None,
        "after_baseline": count,
        "after_covered": covered,
        "after_total": count + covered,
        "before_detector_sha256": None,
        "detector_sha256": sha,
        "uncovered_breakdown": breakdown,
        "reason": reason,
    }
    state = ShadowBaselineState(
        baseline=count,
        detector_sha256=sha,
        uncovered_breakdown=breakdown,
        standing_debt_policy=standing_debt_policy,
        history=(entry,),
    )
    write_shadow_except_baseline_state(state, baseline_path)
    return state


def _check_shadow_counts(
    uncovered: Sequence[ShadowExceptPair],
    state: ShadowBaselineState,
    *,
    allow_slack: bool = False,
) -> Violation | None:
    if len(uncovered) > state.baseline:
        sample = "; ".join(
            f"{p.location} [{p.remediation_class}] ({p.earlier_type} vs {p.later_type} -> {p.outcome})"
            for p in uncovered[:5]
        )
        return Violation(
            "SHADOW_EXCEPT_BASELINE_EXCEEDED",
            SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
            f"uncovered outcome-normalizing except pairs increased from baseline "
            f"{state.baseline} to {len(uncovered)} (sample: {sample}). Collapse "
            "redundant handlers, add a structured discriminator (required for "
            "needs_structured_discriminator), or pin collapse_or_covers_pin "
            "handlers with @pytest.mark.covers('module:qualname#anchor').",
        )
    live_bd = summarize_shadow_uncovered_breakdown(uncovered)
    max_prose = state.uncovered_breakdown[REMEDIATION_STRUCTURED_DISCRIMINATOR]
    live_prose = live_bd[REMEDIATION_STRUCTURED_DISCRIMINATOR]
    if live_prose > max_prose:
        return Violation(
            "SHADOW_EXCEPT_BASELINE_EXCEEDED",
            SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
            f"needs_structured_discriminator shadow-except pairs increased from "
            f"{max_prose} to {live_prose}; prose-only handler pairs cannot be "
            "offset by @pytest.mark.covers pins — add a structured "
            "code/failure_kind discriminator or collapse the handlers.",
        )
    if not allow_slack:
        if len(uncovered) < state.baseline:
            return Violation(
                "SHADOW_EXCEPT_BASELINE_SLACK",
                SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
                f"uncovered outcome-normalizing except pairs dropped below baseline "
                f"({state.baseline} -> {len(uncovered)}); run --update-baseline to "
                "tighten tests/.shadow-except-baseline.",
            )
        if live_prose < max_prose:
            return Violation(
                "SHADOW_EXCEPT_BASELINE_SLACK",
                SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
                f"needs_structured_discriminator shadow-except pairs dropped below "
                f"recorded breakdown ({max_prose} -> {live_prose}); run "
                "--update-baseline to tighten tests/.shadow-except-baseline.",
            )
    return None


def check_shadow_except_baseline(
    repo_root: Path,
    resolved_by_nodeid: dict[str, list[ResolvedTarget]],
    *,
    shadow_baseline_path: Path | None = None,
    src_dir: Path | None = None,
    census_path: Path | None = None,
    enforce: bool = True,
    expected_detector_sha256: str | None = None,
) -> tuple[list[ShadowExceptPair], list[ShadowExceptPair], int | None, list[Violation]]:
    """Audit outcome-normalizing ``except`` pairs against the detector-bound baseline."""
    evaluated, uncovered = evaluate_shadow_except_pairs(
        repo_root,
        resolved_by_nodeid,
        src_dir=src_dir,
        census_path=census_path,
    )
    baseline_file = resolve_shadow_baseline_path(repo_root, shadow_baseline_path)
    violations: list[Violation] = []

    if not evaluated and not baseline_file.is_file() and shadow_baseline_path is None:
        return evaluated, uncovered, None, violations

    state: ShadowBaselineState | None = None
    if baseline_file.is_file():
        state, err = read_shadow_except_baseline(baseline_file)
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

    if state is None:
        return evaluated, uncovered, None, violations

    live_sha = (
        expected_detector_sha256
        if expected_detector_sha256 is not None
        else compute_shadow_detector_fingerprint()
    )
    if enforce and state.detector_sha256 != live_sha:
        violations.append(
            Violation(
                "SHADOW_EXCEPT_DETECTOR_DRIFT",
                SHADOW_EXCEPT_BASELINE_REL_PATH.as_posix(),
                f"shadow-except detector fingerprint drifted from recorded "
                f"{state.detector_sha256[:12]} to {live_sha[:12]}; run "
                "--recompute-baseline --reason '<why detector changed>' to "
                "explicitly re-derive and record before/after counts.",
            )
        )
        return evaluated, uncovered, state.baseline, violations

    if enforce:
        count_violation = _check_shadow_counts(uncovered, state)
        if count_violation is not None:
            violations.append(count_violation)
    return evaluated, uncovered, state.baseline, violations


def verify_static(
    repo_root: Path,
    *,
    scope: str,
    census_path: Path | None = None,
    tests_dir: Path | None = None,
    require_candidates_marked: bool = True,
    shadow_baseline_path: Path | None = None,
    enforce_shadow_baseline: bool = True,
    expected_detector_sha256: str | None = None,
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
            census_path=census_path,
            enforce=True,
            expected_detector_sha256=expected_detector_sha256,
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
        help=(
            "Print outcome-normalizing except pairs under src/ and packages/*/src/ "
            "with remediation class, OSCAL claim tag, and cover status, then exit 0."
        ),
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
            "Lower tests/.shadow-except-baseline to the current uncovered count "
            "(monotonic ratchet: fails if count exceeds baseline or detector changed)."
        ),
    )
    parser.add_argument(
        "--recompute-baseline",
        action="store_true",
        help=(
            "Re-derive tests/.shadow-except-baseline when the shadow-except detector "
            "changes (requires --reason; fails if detector_sha256 is unchanged)."
        ),
    )
    parser.add_argument(
        "--reason",
        type=str,
        default=None,
        help=(
            "Mandatory explanation for --recompute-baseline (>= 24 chars), or "
            "optional note for --update-baseline."
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


def _run_list_candidates(
    repo_root: Path,
    *,
    scope: str,
    census_path: Path | None,
    unmarked_only: bool,
) -> int:
    all_tests = scan_all_tests(repo_root)
    candidates, reasons = compute_scope_candidates(
        all_tests,
        scope=scope,
        repo_root=repo_root,
        census_path=census_path,
    )
    by_id = {t.nodeid: t for t in all_tests}
    for nid in sorted(candidates):
        t = by_id[nid]
        if unmarked_only and (t.covers_specs or t.exemptions):
            continue
        marker = (
            "COVERS" if t.covers_specs else ("EXEMPT" if t.exemptions else "UNMARKED")
        )
        print(f"{marker}\t{nid}\t{reasons[nid]}")
    return 0


def _run_list_shadow_excepts(
    repo_root: Path,
    resolved: dict[str, list[ResolvedTarget]],
    *,
    census_path: Path | None = None,
) -> int:
    evaluated, uncovered = evaluate_shadow_except_pairs(
        repo_root, resolved, census_path=census_path
    )
    for pair in evaluated:
        status = "COVERED" if pair.is_covered else "UNCOVERED"
        oscal_tag = "oscal_claim" if pair.oscal_claim_cited else "-"
        covers = ",".join(pair.covered_by) if pair.covered_by else "-"
        print(
            f"{status}\t{pair.location}\t{pair.qualname}\t"
            f"{pair.earlier_type}\t{pair.later_type}\t{pair.outcome}\t"
            f"{pair.remediation_class}\t{oscal_tag}\t{covers}"
        )
    bd = summarize_shadow_uncovered_breakdown(uncovered)
    print(
        f"# total_pairs={len(evaluated)} uncovered={len(uncovered)} "
        f"covered={len(evaluated) - len(uncovered)} "
        f"collapse_or_covers_pin={bd[REMEDIATION_COLLAPSE_OR_PIN]} "
        f"needs_structured_discriminator={bd[REMEDIATION_STRUCTURED_DISCRIMINATOR]} "
        f"oscal_claim_cited={bd['oscal_claim_cited']}",
        file=sys.stderr,
    )
    return 0


def _print_static_refusal(flag_name: str, violations: Sequence[Violation]) -> int:
    print(
        f"FAIL: refusing {flag_name} with {len(violations)} static violation(s):",
        file=sys.stderr,
    )
    for v in violations:
        print(f"  {v.format_line()}", file=sys.stderr)
    return 1


def _run_update_baseline(
    repo_root: Path,
    resolved: dict[str, list[ResolvedTarget]],
    violations: Sequence[Violation],
    *,
    shadow_baseline: Path | None,
    census_path: Path | None = None,
    reason: str | None,
    expected_detector_sha256: str | None = None,
) -> int:
    if violations:
        return _print_static_refusal("--update-baseline", violations)
    baseline_file = resolve_shadow_baseline_path(repo_root, shadow_baseline)
    if not baseline_file.is_file():
        print(
            f"FAIL: missing {baseline_file}; initialize via "
            "--recompute-baseline --reason '<explanation>'.",
            file=sys.stderr,
        )
        return 1
    existing, err = read_shadow_except_baseline(baseline_file)
    if err is not None or existing is None:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    live_sha = (
        expected_detector_sha256
        if expected_detector_sha256 is not None
        else compute_shadow_detector_fingerprint()
    )
    if existing.detector_sha256 != live_sha:
        print(
            f"FAIL: shadow-except detector fingerprint changed "
            f"({existing.detector_sha256[:12]} -> {live_sha[:12]}); "
            "--update-baseline cannot absorb detector changes. "
            "Use --recompute-baseline --reason '<why detector changed>'.",
            file=sys.stderr,
        )
        return 1
    evaluated, uncovered = evaluate_shadow_except_pairs(
        repo_root, resolved, census_path=census_path
    )
    covered_count = len(evaluated) - len(uncovered)
    breakdown = summarize_shadow_uncovered_breakdown(uncovered)
    count_err = _check_shadow_counts(uncovered, existing, allow_slack=True)
    if count_err is not None:
        print(
            f"FAIL: refusing to raise shadow-except baseline (monotonic ratchet): "
            f"{count_err.message}",
            file=sys.stderr,
        )
        return 1
    if (
        len(uncovered) == existing.baseline
        and breakdown == existing.uncovered_breakdown
    ):
        print(
            f"UNCHANGED: {baseline_file} = {len(uncovered)} "
            f"(total_pairs={len(evaluated)}, covered={covered_count})"
        )
        return 0
    note = (
        reason.strip()
        if reason and reason.strip()
        else "Monotonic ratchet reduction via resolved or covered shadow-except pairs."
    )
    entry: dict[str, object] = {
        "event": "update",
        "before_baseline": existing.baseline,
        "after_baseline": len(uncovered),
        "after_covered": covered_count,
        "after_total": len(evaluated),
        "before_detector_sha256": existing.detector_sha256,
        "detector_sha256": live_sha,
        "uncovered_breakdown": breakdown,
        "reason": note,
    }
    updated = ShadowBaselineState(
        baseline=len(uncovered),
        detector_sha256=live_sha,
        uncovered_breakdown=breakdown,
        standing_debt_policy=existing.standing_debt_policy,
        history=(*existing.history, entry),
    )
    write_shadow_except_baseline_state(updated, baseline_file)
    print(
        f"UPDATED: {baseline_file}: {existing.baseline} -> {len(uncovered)} "
        f"(total_pairs={len(evaluated)}, covered={covered_count})"
    )
    return 0


def _run_recompute_baseline(
    repo_root: Path,
    resolved: dict[str, list[ResolvedTarget]],
    violations: Sequence[Violation],
    *,
    shadow_baseline: Path | None,
    census_path: Path | None = None,
    reason: str | None,
    expected_detector_sha256: str | None = None,
) -> int:
    if violations:
        return _print_static_refusal("--recompute-baseline", violations)
    reason_text = (reason or "").strip()
    if len(reason_text) < MIN_RECOMPUTE_REASON_LEN:
        print(
            f"FAIL: --recompute-baseline requires --reason of at least "
            f"{MIN_RECOMPUTE_REASON_LEN} characters explaining the detector change.",
            file=sys.stderr,
        )
        return 1
    live_sha = (
        expected_detector_sha256
        if expected_detector_sha256 is not None
        else compute_shadow_detector_fingerprint()
    )
    evaluated, uncovered = evaluate_shadow_except_pairs(
        repo_root, resolved, census_path=census_path
    )
    covered_count = len(evaluated) - len(uncovered)
    breakdown = summarize_shadow_uncovered_breakdown(uncovered)
    baseline_file = resolve_shadow_baseline_path(repo_root, shadow_baseline)
    if not baseline_file.is_file():
        write_initial_shadow_except_baseline(
            len(uncovered),
            baseline_file,
            covered=covered_count,
            detector_sha256=live_sha,
            uncovered_breakdown=breakdown,
            reason=reason_text,
        )
        print(
            f"INITIALIZED: {baseline_file} = {len(uncovered)} "
            f"(total_pairs={len(evaluated)}, covered={covered_count}, "
            f"detector={live_sha[:12]})"
        )
        return 0
    existing, err = read_shadow_except_baseline(baseline_file)
    if err is not None or existing is None:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    if existing.detector_sha256 == live_sha:
        print(
            f"FAIL: refusing --recompute-baseline because detector_sha256 is "
            f"unchanged ({live_sha[:12]}). Recomputation is permitted only when "
            "the shadow-except detector changes; resolve uncovered pairs or use "
            "--update-baseline to lower the ceiling.",
            file=sys.stderr,
        )
        return 1
    entry: dict[str, object] = {
        "event": "recompute",
        "before_baseline": existing.baseline,
        "after_baseline": len(uncovered),
        "after_covered": covered_count,
        "after_total": len(evaluated),
        "before_detector_sha256": existing.detector_sha256,
        "detector_sha256": live_sha,
        "uncovered_breakdown": breakdown,
        "reason": reason_text,
    }
    recomputed = ShadowBaselineState(
        baseline=len(uncovered),
        detector_sha256=live_sha,
        uncovered_breakdown=breakdown,
        standing_debt_policy=existing.standing_debt_policy,
        history=(*existing.history, entry),
    )
    write_shadow_except_baseline_state(recomputed, baseline_file)
    print(
        f"RECOMPUTED: {baseline_file}: {existing.baseline} -> {len(uncovered)} "
        f"(total_pairs={len(evaluated)}, covered={covered_count}, "
        f"detector={existing.detector_sha256[:12]}->{live_sha[:12]})"
    )
    return 0


def _print_reconciliation_summary(
    repo_root: Path,
    all_tests: list[DiscoveredTest],
    candidates: set[str],
    resolved: dict[str, list[ResolvedTarget]],
    *,
    scope: str,
    shadow_baseline: Path | None,
    census_path: Path | None = None,
) -> None:
    rec = build_reconciliation_report(all_tests)
    shadow_all, shadow_uncovered, shadow_base, _ = check_shadow_except_baseline(
        repo_root,
        resolved,
        shadow_baseline_path=shadow_baseline,
        census_path=census_path,
        enforce=False,
    )
    bd = summarize_shadow_uncovered_breakdown(shadow_uncovered)
    print(
        "Reconciliation report (AST name scan is a candidate finder requiring "
        "reconciliation, not a semantic definition of all fail-closed tests):"
    )
    print(
        f"  total_tests={rec['total_tests']} "
        f"in_scope[{scope}]={len(candidates)} "
        f"marked_covers={rec['marked_covers']} "
        f"marked_exempt={rec['marked_exempt']} "
        f"shadow_except_pairs={len(shadow_all)} "
        f"shadow_except_uncovered={len(shadow_uncovered)} "
        f"shadow_except_prose_only={bd[REMEDIATION_STRUCTURED_DISCRIMINATOR]} "
        f"shadow_except_oscal_claim={bd['oscal_claim_cited']} "
        f"shadow_except_baseline={shadow_base}"
    )
    tok_line = ", ".join(
        f"{tok}={rec[tok]}" for tok in ("asserts_503", *RECONCILIATION_TOKENS)
    )
    print(f"  repo_wide_tokens: {tok_line}")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.update_baseline and args.recompute_baseline:
        print(
            "ERROR: --update-baseline and --recompute-baseline are mutually exclusive.",
            file=sys.stderr,
        )
        return 2
    repo_root: Path = args.repo_root.resolve()

    if args.list_candidates or args.list_unmarked:
        return _run_list_candidates(
            repo_root,
            scope=args.scope,
            census_path=args.census_path,
            unmarked_only=args.list_unmarked,
        )

    skip_shadow_enforce = (
        args.list_shadow_excepts or args.update_baseline or args.recompute_baseline
    )
    try:
        all_tests, candidates, _reasons, resolved, violations = verify_static(
            repo_root,
            scope=args.scope,
            census_path=args.census_path,
            require_candidates_marked=not args.skip_discovery,
            shadow_baseline_path=args.shadow_baseline,
            enforce_shadow_baseline=not skip_shadow_enforce,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.list_shadow_excepts:
        return _run_list_shadow_excepts(
            repo_root, resolved, census_path=args.census_path
        )
    if args.update_baseline:
        return _run_update_baseline(
            repo_root,
            resolved,
            violations,
            shadow_baseline=args.shadow_baseline,
            census_path=args.census_path,
            reason=args.reason,
        )
    if args.recompute_baseline:
        return _run_recompute_baseline(
            repo_root,
            resolved,
            violations,
            shadow_baseline=args.shadow_baseline,
            census_path=args.census_path,
            reason=args.reason,
        )

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
        _print_reconciliation_summary(
            repo_root,
            all_tests,
            candidates,
            resolved,
            scope=args.scope,
            shadow_baseline=args.shadow_baseline,
            census_path=args.census_path,
        )

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
