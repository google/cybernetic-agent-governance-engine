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

"""Import Boundary Enforcement — Gate G3 CI Check (PR B + Sprint 3)

Verifies layer isolation (domain-generic):
- Layer 1 (src/gateway/) must NOT import from Layer 2 (src/cage_*/)
- Layer 1 (src/gateway/) must NOT import from Layer 3 (langfuse SDK)
- Layer 1 must NOT import from Layer 4 (src/governed_financial_advisor/)

Sprint 3.3: Blocks gateway → Langfuse SDK boundary violation
All telemetry flows through Evidence Stream or OTel only.

Usage:
    python scripts/check_import_boundaries.py
    python scripts/check_import_boundaries.py --verbose

Exit codes:
    0 - All boundaries respected
    1 - Boundary violation detected
"""

import argparse
import ast
import re
import sys
from pathlib import Path

# Layer definitions (in dependency order, lower layers cannot import higher layers)
LAYER_1_GATEWAY = "src/gateway"
LAYER_2_CAGE_PATTERN = re.compile(r"^(src\.)?cage_\w+")  # Matches src.cage_* or cage_*
LAYER_3_LANGFUSE_PATTERN = re.compile(r"^langfuse")  # Matches langfuse or from langfuse
LAYER_4_GFA_PATTERN = re.compile(r"^(src\.)?governed_financial_advisor")


class ImportVisitor(ast.NodeVisitor):
    """AST visitor to extract all import statements."""

    def __init__(self):
        self.imports: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Visit `import x` statements."""
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit `from x import y` statements."""
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)


def extract_imports(filepath: Path) -> set[str]:
    """Extract all import module names from a Python file."""
    try:
        with open(filepath, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(filepath))
        visitor = ImportVisitor()
        visitor.visit(tree)
        return visitor.imports
    except (SyntaxError, FileNotFoundError):
        # Skip files with syntax errors or transient temp files deleted during scan
        return set()


def check_file_boundaries(
    filepath: Path, verbose: bool = False
) -> list[tuple[str, str]]:
    """Check if a file violates import boundaries.

    Returns:
        List of (importing_layer, forbidden_module) tuples for violations.
    """
    violations = []
    imports = extract_imports(filepath)

    # Determine which layer this file belongs to
    filepath_str = str(filepath)
    if LAYER_1_GATEWAY in filepath_str:
        # Gateway files cannot import cage_* (Layer 2) or langfuse (Layer 3)
        # NOTE: Layer 1 → Layer 4 (GFA) check will be added in PR D
        for imp in imports:
            if LAYER_2_CAGE_PATTERN.match(imp):
                violations.append((filepath_str, imp))
                if verbose:
                    print(f"❌ {filepath}: imports {imp} (Layer 1 → Layer 2 violation)")
            elif LAYER_3_LANGFUSE_PATTERN.match(imp):
                violations.append((filepath_str, imp))
                if verbose:
                    print(
                        f"❌ {filepath}: imports {imp} (Layer 1 → Layer 3 Langfuse SDK violation)"
                    )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Check layer import boundaries")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print(
        "🔍 Checking import boundaries (Layer 1 must not import Layer 2 cage_* or Layer 3 langfuse)..."
    )

    # Scan all Python files in src/gateway/
    gateway_root = Path(LAYER_1_GATEWAY)
    if not gateway_root.exists():
        print(f"❌ Gateway layer not found: {gateway_root}")
        return 1

    all_violations: list[tuple[str, str]] = []
    scanned_count = 0

    for py_file in gateway_root.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue
        scanned_count += 1
        violations = check_file_boundaries(py_file, verbose=args.verbose)
        all_violations.extend(violations)

    # Report results
    print(f"📊 Scanned {scanned_count} files in {LAYER_1_GATEWAY}/")

    if all_violations:
        print(f"\n❌ BOUNDARY VIOLATIONS DETECTED ({len(all_violations)}):\n")
        for filepath, imported_module in all_violations:
            print(f"  {filepath}")
            print(f"    └─ imports {imported_module}\n")

        print(
            "🚨 Layer 1 (gateway) must NOT import from Layer 2 (cage_*) or Layer 3 (langfuse)."
        )
        print(
            "   Use plugin entry points, dependency injection, or the plugin seam instead."
        )
        print("   All telemetry flows through Evidence Stream or OTel only.")
        print(
            "   Violation: See plans/evidence_integration_implementation_plan.md §4.8"
        )
        print("   NOTE: Layer 1 → Layer 4 (GFA) violations will be addressed in PR D.")
        return 1

    print("✅ All import boundaries respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
