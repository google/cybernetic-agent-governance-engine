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

"""Gate G7: Telemetry Vendor Literal Enforcement.

Scans Python files under ``src/`` (and ``config/rails/actions.py``) for raw
``"langfuse."`` attribute literals in executable code.

Excludes:
  - Docstrings and comments (illustrative examples and documentation are legitimate)
  - src/gateway/observability/attributes.py (canonical declaration of telemetry constants)
  - Non-executable cache and build directories

Design Rationale (Wave 1, Task W1.6 / AW-6):
  Vendor namespace strings must not be hardcoded in application or governance logic.
  All attribute keys must be imported from ``src.gateway.observability.attributes``
  to allow single-point remapping across OTLP backends.

Exit 0 on clean code; Exit 1 on any executable-code violation.

Usage:
    python scripts/check_telemetry_literals.py [--verbose]
    uv run python scripts/check_telemetry_literals.py [--verbose]
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

# Files permitted to define the vendor namespace
EXCLUDED_FILES = {
    "attributes.py",
}

# Directories excluded from scanning
EXCLUDED_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".git",
}

# Pattern matching raw telemetry vendor attribute prefixes
FORBIDDEN_PATTERN = re.compile(r"^langfuse\.|ai\.webhook\.langfuse\.")


class TelemetryLiteralChecker(ast.NodeVisitor):
    """AST visitor collecting raw telemetry vendor string literals outside docstrings."""

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.violations: list[tuple[int, str]] = []
        self._docstring_nodes: set[ast.AST] = set()

    def visit_Module(self, node: ast.Module) -> None:
        """Track module docstring."""
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function docstring."""
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function docstring."""
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class docstring."""
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Check string constants outside docstrings."""
        if isinstance(node.value, str) and node not in self._docstring_nodes:
            val = node.value.strip()
            if val.startswith("langfuse.") or val.startswith("ai.webhook.langfuse."):
                self.violations.append((node.lineno, val))
        self.generic_visit(node)


def check_file(filepath: Path) -> list[tuple[int, str]]:
    """Parse a Python file and return any telemetry literal violations."""
    try:
        content = filepath.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(filepath))
        checker = TelemetryLiteralChecker(filepath)
        checker.visit(tree)
        return checker.violations
    except SyntaxError as e:
        print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Warning: error reading {filepath}: {e}", file=sys.stderr)
        return []


def scan_directory(
    root_dir: Path, verbose: bool = False
) -> dict[Path, list[tuple[int, str]]]:
    """Scan root_dir for telemetry literal violations."""
    all_violations: dict[Path, list[tuple[int, str]]] = {}

    for path in sorted(root_dir.rglob("*.py")):
        # Skip excluded dirs
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        # Skip excluded files
        if path.name in EXCLUDED_FILES:
            if verbose:
                print(f"Skipping excluded file: {path}")
            continue

        violations = check_file(path)
        if violations:
            all_violations[path] = violations
        elif verbose:
            print(f"Clean: {path}")

    return all_violations


def main() -> int:
    """Main entry point for Gate G7 check."""
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"

    if not src_dir.exists():
        print(f"Error: {src_dir} does not exist", file=sys.stderr)
        return 1

    print("Running Gate G7: Telemetry Vendor Literal Enforcement...")
    violations = scan_directory(src_dir, verbose=verbose)

    # Also scan config/rails/actions.py if present
    rails_actions = repo_root / "config" / "rails" / "actions.py"
    if rails_actions.exists():
        rails_violations = check_file(rails_actions)
        if rails_violations:
            violations[rails_actions] = rails_violations

    if violations:
        total = sum(len(v) for v in violations.values())
        print(
            f"\n❌ Gate G7 FAILED: Found {total} raw telemetry literal violation(s) "
            f"across {len(violations)} file(s):\n",
            file=sys.stderr,
        )
        for filepath, file_violations in sorted(violations.items()):
            rel_path = filepath.relative_to(repo_root)
            for lineno, literal in file_violations:
                print(
                    f"  {rel_path}:{lineno}: Forbidden telemetry literal '{literal}'",
                    file=sys.stderr,
                )
        print(
            "\nImport constants from 'src.gateway.observability.attributes' instead.",
            file=sys.stderr,
        )
        return 1

    print("✅ Gate G7 PASSED: No raw telemetry vendor literals in executable code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
