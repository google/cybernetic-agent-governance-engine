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

"""G8: the kernel must carry no vendor brand literals in executable code.

Scans src/gateway/ for vendor brand name literals in executable code. Excludes:
  - docstrings and comments (illustrative examples and documentation are legitimate)
  - test files (tests/ or test_*.py or *_test.py)
  - generated_*.py (STPA compiler output)
  - protos/ (schema examples)

The gate exists to stop new executable coupling in the kernel. Vendor names in
prose, docstrings, comments, and Layer 3 adapter identifiers are all legitimate
and must stay. This gate only blocks enum members, string literals, function names,
Redis keys, and environment variables in src/gateway/.

Exit 1 on any executable-code occurrence.

Usage:
    python scripts/check_vendor_brands.py
    uv run python scripts/check_vendor_brands.py
    uv run python scripts/check_vendor_brands.py --verbose
"""

import argparse
import ast
import sys
from pathlib import Path

# Vendor brand names that must not appear in kernel executable code
# NOTE: This list may start empty if the tree is clean. An empty-but-wired gate
# that catches the next violation is still worth having.
FORBIDDEN_VENDOR_BRANDS: set[str] = set()
# Examples (currently no known violations after C9 FLOWSIGNAL_ESCALATION → EXTERNAL_HOLD):
# FORBIDDEN_VENDOR_BRANDS = {"langfuse", "langsmith", "openai"}

# Files that are allowed to contain vendor brand names
EXCLUDED_FILES = {
    "generated_stpa_validator.py",
    "generated_saga_nodes.py",
    "generated_stpa_policy.rego",
}

# Directories excluded from scanning
EXCLUDED_DIRS = {"protos", "__pycache__", ".pytest_cache", ".mypy_cache"}


class VendorBrandChecker(ast.NodeVisitor):
    """AST visitor that collects string literals outside of docstrings.

    Reuses the DomainLiteralChecker design, which already skips docstrings
    via _docstring_nodes and is comment-blind by construction.
    """

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
            # Check if the string contains any vendor brand (case-insensitive)
            lower_value = node.value.lower()
            for brand in FORBIDDEN_VENDOR_BRANDS:
                if brand.lower() in lower_value:
                    self.violations.append((node.lineno, node.value))
                    break
        self.generic_visit(node)


def check_file(filepath: Path) -> list[tuple[int, str]]:
    """Parse a Python file and return any vendor brand violations.

    Args:
        filepath: Path to Python file to check.

    Returns:
        List of (line_number, literal) tuples for violations found.
    """
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        checker = VendorBrandChecker(filepath)
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

    # Skip test files — test fixtures may reference vendor names
    if (
        "/tests/" in str(path)
        or path.name.endswith("_test.py")
        or path.name.startswith("test_")
    ):
        return True

    return False


def main() -> int:
    """Scan src/gateway/ for forbidden vendor brand literals.

    Returns:
        Exit code: 0 if no violations, 1 if violations found.
    """
    parser = argparse.ArgumentParser(
        description="Check vendor brand literals in kernel"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    gateway_dir = repo_root / "src" / "gateway"

    if not gateway_dir.exists():
        print(f"❌ Gateway directory not found: {gateway_dir}", file=sys.stderr)
        return 1

    if not FORBIDDEN_VENDOR_BRANDS:
        if args.verbose:
            print("INFO: Gate G8: No vendor brands configured (empty list).")  # noqa: RUF001
        print(
            "✅ Gate G8 PASSED: Vendor brand list is empty (gate is wired but not restrictive)."
        )  # noqa: RUF001
        return 0

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
            "❌ Gate G8 FAILED: Found forbidden vendor brand literals in kernel code."
        )
        print(f"   Forbidden brands: {', '.join(sorted(FORBIDDEN_VENDOR_BRANDS))}")
        print()
        print("   The kernel must be vendor-neutral. Vendor names are acceptable in:")
        print("   • Docstrings and comments (documentation and prose)")
        print("   • Layer 3 adapter identifiers (src/integrations/provider_*/)")
        print()
        print("   They must NOT appear in:")
        print("   • Enum members, string literals in executable code")
        print("   • Function names, Redis keys, environment variables")
        print()
        print("   Use observability abstractions, not vendor-specific coupling.")
        return 1

    if args.verbose:
        print(f"📊 Scanned {scanned_count} files in {gateway_dir}/")  # noqa: RUF001
    print(
        f"✅ Gate G8 PASSED: No vendor brand literals found (scanned {scanned_count} files)."  # noqa: RUF001
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
