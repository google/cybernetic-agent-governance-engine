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

"""G6: the kernel and operational scripts must carry no domain-specific literals.

Scans src/gateway/, src/integrations/, and scripts/ for domain action, package,
and policy literals in executable code. Excludes:
  - docstrings and comments (illustrative examples are legitimate)
  - protos/ (schema examples)
  - documented meta-checkers / paper benchmark harnesses in SCRIPTS_EXCLUDED_FILES

Exit 1 on any executable-code occurrence.

Usage:
    python scripts/check_domain_literals.py
    uv run python scripts/check_domain_literals.py
"""

import ast
import sys
from pathlib import Path

# Domain action, field, threshold, role, plugin, and OPA policy literals that
# must not appear in kernel (src/gateway/) or operational script executable code.
FORBIDDEN_LITERALS = {
    "execute_trade",
    "reverse_trade",
    "wire_transfer",
    "place_order",
    "trade_amount",
    "market_regime",
    "min_cash_balance",
    "portfolio_drawdown",
    "portfolio_drawdown_pct",
    "threshold_usd",
    "min_trade_confidence",
    "HIGH_VALUE_TRADE",
    "Risk Manager",
    "Execution Quant",
    "administer_medication",
    "move_effector",
    "cage_finance",
    "cage_healthcare",
    "cage_physical_ai",
    "trade_governance",
    "dosing_governance",
    "trade.governance",
    "dosing.governance",
}

# Domain literals forbidden in Layer 3 integrations
INTEGRATIONS_FORBIDDEN_LITERALS = {
    "execute_trade",
    "reverse_trade",
    "cage_finance",
    "cage_healthcare",
    "cage_physical_ai",
    "trade_governance",
    "dosing_governance",
    "trade.governance",
    "dosing.governance",
}

# Kernel/integration file exclusions (empty: generated STPA modules live under src/cage_<domain>/stpa/).
EXCLUDED_FILES: set[str] = set()

# Scripts whose sole purpose is defining domain-boundary/symbol tables or running
# explicit finance-domain paper benchmarks (§6.5). Every operational/CI gate
# script outside this map is scanned against FORBIDDEN_LITERALS.
SCRIPTS_EXCLUDED_FILES: dict[str, str] = {
    "check_domain_literals.py": "Gate G6 itself defines FORBIDDEN_LITERALS.",
    "check_import_boundaries.py": "Gate G3 AST boundary checker defines FORBIDDEN_DOMAIN_LITERALS.",
    "check_doc_references.py": "Gate G9 Markdown symbol resolver maps src/cage_* package names.",
    "measure_paper_metrics.py": "Paper evaluation harness explicitly benchmarks FinanceCagePlugin.",
    "measure_reconciliation_metrics.py": "Paper §6.5 reconciliation benchmark explicitly exercises CashBarrier.",
}

# Directories excluded from scanning
EXCLUDED_DIRS = {"protos", "__pycache__", ".pytest_cache", ".mypy_cache"}


class DomainLiteralChecker(ast.NodeVisitor):
    """AST visitor that collects string literals outside of docstrings."""

    def __init__(
        self,
        filepath: Path,
        forbidden_literals: set[str] | frozenset[str] = FORBIDDEN_LITERALS,
    ):
        self.filepath = filepath
        self.forbidden_literals = forbidden_literals
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
            if node.value in self.forbidden_literals:
                self.violations.append((node.lineno, node.value))
        self.generic_visit(node)


def check_file(
    filepath: Path,
    forbidden_literals: set[str] | frozenset[str] | None = None,
) -> list[tuple[int, str]]:
    """Parse a Python file and return any domain literal violations."""
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        checker = DomainLiteralChecker(
            filepath,
            forbidden_literals=forbidden_literals
            if forbidden_literals is not None
            else FORBIDDEN_LITERALS,
        )
        checker.visit(tree)
        return checker.violations
    except SyntaxError as exc:
        print(f"⚠️  Syntax error in {filepath}: {exc}", file=sys.stderr)
        return [(1, f"<unparseable: {exc}>")]
    except Exception as exc:
        print(f"⚠️  Failed to parse {filepath}: {exc}", file=sys.stderr)
        return [(1, f"<unparseable: {exc}>")]


def should_skip(
    path: Path,
    base_dir: Path,
    *,
    extra_excluded_files: set[str] | frozenset[str] = frozenset(),
) -> bool:
    """Return True if path should be excluded from scanning."""
    for part in path.relative_to(base_dir).parts:
        if part in EXCLUDED_DIRS:
            return True

    if path.name in EXCLUDED_FILES or path.name in extra_excluded_files:
        return True

    if (
        "/tests/" in str(path)
        or path.name.endswith("_test.py")
        or path.name.startswith("test_")
    ):
        return True

    return False


def main() -> int:
    """Scan src/gateway/, src/integrations/, and scripts/ for forbidden domain literals."""
    repo_root = Path(__file__).parent.parent
    gateway_dir = repo_root / "src" / "gateway"
    integrations_dir = repo_root / "src" / "integrations"
    scripts_dir = repo_root / "scripts"

    if not gateway_dir.exists():
        print(f"❌ Gateway directory not found: {gateway_dir}", file=sys.stderr)
        return 1

    violations_found = False
    scanned_count = 0

    scan_targets: list[tuple[Path, set[str] | frozenset[str], frozenset[str]]] = [
        (gateway_dir, FORBIDDEN_LITERALS, frozenset()),
        (integrations_dir, INTEGRATIONS_FORBIDDEN_LITERALS, frozenset()),
        (scripts_dir, FORBIDDEN_LITERALS, frozenset(SCRIPTS_EXCLUDED_FILES)),
    ]

    for target_dir, literals, extra_excluded in scan_targets:
        if not target_dir.exists():
            continue
        for py_file in sorted(target_dir.rglob("*.py")):
            if should_skip(py_file, target_dir, extra_excluded_files=extra_excluded):
                continue

            scanned_count += 1
            violations = check_file(py_file, forbidden_literals=literals)

            if violations:
                violations_found = True
                rel_path = py_file.relative_to(repo_root)
                print(f"❌ {rel_path}:")
                for line_num, literal in violations:
                    print(f"   Line {line_num}: '{literal}'")

    if violations_found:
        print()
        print(
            "❌ Gate G6 FAILED: Found forbidden domain literals in kernel/integration/scripts code."
        )
        print(f"   Forbidden literals: {', '.join(sorted(FORBIDDEN_LITERALS))}")
        print()
        print(
            "   Kernel, integrations, and operational scripts must be domain-agnostic."
        )
        return 1

    print(
        f"✅ Gate G6 PASSED: No domain action literals found (scanned {scanned_count} files)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
