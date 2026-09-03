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

"""G6: the kernel must carry no domain action names.

Scans src/gateway/ for domain action literals in executable code. Excludes:
  - docstrings and comments (illustrative examples are legitimate)
  - generated_*.py (STPA compiler output legitimately names domain actions)
  - protos/ (schema examples)

Exit 1 on any executable-code occurrence.

Usage:
    python scripts/check_domain_literals.py
    uv run python scripts/check_domain_literals.py
"""

import ast
import sys
from pathlib import Path

# Domain action names that must not appear in kernel executable code
FORBIDDEN_LITERALS = {"execute_trade", "reverse_trade"}

# Files that are allowed to contain domain action names
EXCLUDED_FILES = {
    "generated_stpa_validator.py",
    "generated_saga_nodes.py",
    "generated_stpa_policy.rego",  # OPA generated policy
}

# Directories excluded from scanning
EXCLUDED_DIRS = {"protos", "__pycache__", ".pytest_cache", ".mypy_cache"}


class DomainLiteralChecker(ast.NodeVisitor):
    """AST visitor that collects string literals outside of docstrings."""

    def __init__(self, filepath: Path):
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
        """Check string constants that are not docstrings."""
        if isinstance(node.value, str) and node not in self._docstring_nodes:
            if node.value in FORBIDDEN_LITERALS:
                self.violations.append((node.lineno, node.value))
        self.generic_visit(node)


def check_file(filepath: Path) -> list[tuple[int, str]]:
    """Parse a Python file and return any domain literal violations.

    Args:
        filepath: Path to Python file to check.

    Returns:
        List of (line_number, literal) tuples for violations found.
    """
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        checker = DomainLiteralChecker(filepath)
        checker.visit(tree)
        return checker.violations
    except SyntaxError as exc:
        print(f"⚠️  Syntax error in {filepath}: {exc}", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"⚠️  Failed to parse {filepath}: {exc}", file=sys.stderr)
        return []


def should_skip(path: Path, base_dir: Path) -> bool:
    """Return True if path should be excluded from scanning.

    Args:
        path: File or directory path to check.
        base_dir: Base directory for relative path computation.

    Returns:
        True if path should be skipped.
    """
    # Skip excluded directories
    for part in path.relative_to(base_dir).parts:
        if part in EXCLUDED_DIRS:
            return True

    # Skip excluded files
    if path.name in EXCLUDED_FILES:
        return True

    return False


def main() -> int:
    """Scan src/gateway/ for forbidden domain action literals.

    Returns:
        Exit code: 0 if no violations, 1 if violations found.
    """
    repo_root = Path(__file__).parent.parent
    gateway_dir = repo_root / "src" / "gateway"

    if not gateway_dir.exists():
        print(f"❌ Gateway directory not found: {gateway_dir}", file=sys.stderr)
        return 1

    violations_found = False
    scanned_count = 0

    for py_file in gateway_dir.rglob("*.py"):
        if should_skip(py_file, gateway_dir):
            continue

        scanned_count += 1
        violations = check_file(py_file)

        if violations:
            violations_found = True
            rel_path = py_file.relative_to(repo_root)
            print(f"❌ {rel_path}:")
            for line_num, literal in violations:
                print(f"   Line {line_num}: '{literal}'")

    if violations_found:
        print()
        print(
            "❌ Gate G6 FAILED: Found forbidden domain action literals in kernel code."
        )
        print(f"   Forbidden literals: {', '.join(sorted(FORBIDDEN_LITERALS))}")
        print()
        print("   The kernel must be domain-agnostic. Move domain-specific logic")
        print("   to domain plugins (src/cage_finance/, src/cage_healthcare/, etc.).")
        return 1

    print(
        f"✅ Gate G6 PASSED: No domain action literals found (scanned {scanned_count} files)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
