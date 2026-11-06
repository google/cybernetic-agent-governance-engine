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

"""scripts/check_write_only_state.py

Pure-stdlib AST gate verifying that every ``*.state.<attr>`` attribute written
anywhere under ``src/`` has at least one reader in ``src/`` (POAM-2026-169 #6).

Zero waivers and zero suffix exemptions are permitted.

Usage::

    python scripts/check_write_only_state.py [--root <dir>] [--verbose]
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "tests",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".git",
        ".venv",
    }
)

STATE_PARAM_NAMES: frozenset[str] = frozenset({"state", "app_state", "req_state"})


@dataclass(frozen=True)
class StateWrite:
    """Single ``<expr>.state.<attr>`` write site."""

    filepath: Path
    lineno: int
    attr: str


def _is_getattr_state_call(node: ast.AST) -> bool:
    """Return True if ``node`` is ``getattr(<expr>, "state", ...)``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "state"
    )


def _is_state_source_expr(node: ast.AST, local_aliases: set[str]) -> bool:
    """Return True if ``node`` evaluates to a ``.state`` object."""
    if isinstance(node, ast.Attribute) and node.attr == "state":
        return True
    if _is_getattr_state_call(node):
        return True
    if isinstance(node, ast.Name) and node.id in local_aliases:
        return True
    if isinstance(node, ast.IfExp):
        return _is_state_source_expr(node.body, local_aliases) or _is_state_source_expr(
            node.orelse, local_aliases
        )
    return False


def _is_state_getattr_target(node: ast.AST, local_aliases: set[str]) -> bool:
    """Return True if ``node`` is a valid ``getattr``/``hasattr`` first argument for state."""
    if _is_state_source_expr(node, local_aliases):
        return True
    if isinstance(node, ast.Name) and node.id in STATE_PARAM_NAMES:
        return True
    return False


class _StateAccessVisitor(ast.NodeVisitor):
    """Collect ``*.state.<attr>`` writes and reads from a module AST."""

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.writes: list[StateWrite] = []
        self.reads: set[str] = set()
        self._alias_stack: list[set[str]] = [set()]

    @property
    def _aliases(self) -> set[str]:
        return self._alias_stack[-1]

    def _visit_scope(self, body: list[ast.stmt]) -> None:
        self._alias_stack.append(set())
        try:
            for stmt in body:
                self.visit(stmt)
        finally:
            self._alias_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for kw_default in node.args.kw_defaults:
            if kw_default is not None:
                self.visit(kw_default)
        self._visit_scope(node.body)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for kw_default in node.args.kw_defaults:
            if kw_default is not None:
                self.visit(kw_default)
        self._visit_scope(node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)
        self._visit_scope(node.body)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        is_state_rhs = _is_state_source_expr(node.value, self._aliases)
        for target in node.targets:
            self.visit(target)
            if isinstance(target, ast.Name):
                if is_state_rhs:
                    self._aliases.add(target.id)
                else:
                    self._aliases.discard(target.id)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        is_state_rhs = False
        if node.value is not None:
            self.visit(node.value)
            is_state_rhs = _is_state_source_expr(node.value, self._aliases)
        self.visit(node.target)
        self.visit(node.annotation)
        if isinstance(node.target, ast.Name) and node.value is not None:
            if is_state_rhs:
                self._aliases.add(node.target.id)
            else:
                self._aliases.discard(node.target.id)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        is_state_rhs = _is_state_source_expr(node.value, self._aliases)
        self.visit(node.target)
        if isinstance(node.target, ast.Name):
            if is_state_rhs:
                self._aliases.add(node.target.id)
            else:
                self._aliases.discard(node.target.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        is_direct_state = (
            isinstance(node.value, ast.Attribute) and node.value.attr == "state"
        )
        is_alias_state = (
            isinstance(node.value, ast.Name) and node.value.id in self._aliases
        )

        if isinstance(node.ctx, ast.Store):
            if is_direct_state or is_alias_state:
                self.writes.append(
                    StateWrite(
                        filepath=self.filepath,
                        lineno=node.lineno,
                        attr=node.attr,
                    )
                )
        elif isinstance(node.ctx, ast.Load):
            if is_direct_state or is_alias_state:
                self.reads.add(node.attr)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "hasattr")
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and _is_state_getattr_target(node.args[0], self._aliases)
        ):
            self.reads.add(node.args[1].value)

        self.generic_visit(node)


def iter_python_files(scan_dir: Path) -> list[Path]:
    """Return sorted non-test Python files under ``scan_dir``."""
    files: list[Path] = []
    for path in sorted(scan_dir.rglob("*.py")):
        rel_parts = path.relative_to(scan_dir).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts[:-1]):
            continue
        if path.name.startswith("test_"):
            continue
        files.append(path)
    return files


def find_write_only_state(
    root: Path,
) -> tuple[list[StateWrite], list[str]]:
    """Scan ``root`` and return ``(write_only_sites, parse_errors)``."""
    scan_dir = root / "src" if (root / "src").is_dir() else root
    all_writes: list[StateWrite] = []
    all_reads: set[str] = set()
    parse_errors: list[str] = []

    for filepath in iter_python_files(scan_dir):
        try:
            source = filepath.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            parse_errors.append(f"{filepath}: failed to parse Python source: {exc}")
            continue

        visitor = _StateAccessVisitor(filepath)
        visitor.visit(tree)
        all_writes.extend(visitor.writes)
        all_reads.update(visitor.reads)

    violations = [w for w in all_writes if w.attr not in all_reads]
    return violations, parse_errors


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Fail if any *.state.<attr> written in src/ has zero readers in src/."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Directory to scan (defaults to repository src/).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print summary when clean.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    if args.root is None:
        scan_target = repo_root / "src"
        display_base = repo_root
    else:
        scan_target = args.root.resolve()
        display_base = scan_target

    if not scan_target.exists():
        print(f"Error: scan root does not exist: {scan_target}", file=sys.stderr)
        return 1

    violations, parse_errors = find_write_only_state(scan_target)
    if parse_errors:
        for err in parse_errors:
            print(err, file=sys.stderr)
        return 1

    if violations:
        for v in violations:
            try:
                rel = v.filepath.relative_to(display_base)
            except ValueError:
                rel = v.filepath
            print(
                f"{rel}:{v.lineno}: write-only state attribute "
                f"'state.{v.attr}' has 0 readers in src/"
            )
        return 1

    if args.verbose:
        print("OK: every *.state.<attr> written in src/ has at least one reader.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
