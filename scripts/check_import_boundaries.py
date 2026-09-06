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

"""Import Boundary Enforcement — Gate G3 CI Check

Verifies layer isolation (clean architecture):
- Layer 1 (src/gateway/) must NOT import from Layer 2 (src/cage_*/)
- Layer 1 must NOT import from Layer 3 (src/compliance_bridge/)
- Layer 1 must NOT import from Layer 4 (src/governed_financial_advisor/)
- Evidence kernel (src/gateway/governance/evidence/) must NOT import vendor SDKs:
  (google.cloud, boto3, botocore, azure, langfuse)

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
from dataclasses import dataclass
from pathlib import Path

# Layer definitions
LAYER_1_GATEWAY = Path("src/gateway")
EVIDENCE_DIR = Path("src/gateway/governance/evidence")

# Forbidden import patterns for Layer 1
LAYER_2_CAGE_PATTERN = re.compile(r"^(src\.)?cage_\w+")
LAYER_3_BRIDGE_PATTERN = re.compile(r"^(src\.)?compliance_bridge")
LAYER_4_GFA_PATTERN = re.compile(r"^(src\.)?governed_financial_advisor")

# Forbidden vendor SDKs for Evidence Kernel
FORBIDDEN_VENDOR_SDKS = ("google.cloud", "boto3", "botocore", "azure", "langfuse")


@dataclass(frozen=True)
class BoundaryViolation:
    file_path: str
    line_number: int
    imported_module: str
    rule_violated: str


class ImportVisitor(ast.NodeVisitor):
    """AST visitor to extract all import statements with line numbers."""

    def __init__(self) -> None:
        self.imports: list[tuple[str, int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        """Visit `import x` statements."""
        for alias in node.names:
            self.imports.append((alias.name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit `from x import y` statements."""
        if node.module:
            self.imports.append((node.module, node.lineno))
        self.generic_visit(node)


def extract_imports(filepath: Path) -> list[tuple[str, int]]:
    """Extract all (import_module_name, line_number) tuples from a Python file."""
    try:
        with open(filepath, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(filepath))
        visitor = ImportVisitor()
        visitor.visit(tree)
        return visitor.imports
    except (SyntaxError, FileNotFoundError):
        return []


def check_file_boundaries(
    filepath: Path, verbose: bool = False
) -> list[BoundaryViolation]:
    """Check if a file violates import boundaries.

    Returns:
        List of BoundaryViolation instances.
    """
    violations: list[BoundaryViolation] = []
    imports = extract_imports(filepath)
    filepath_str = str(filepath)

    is_layer1 = False
    try:
        if filepath.is_relative_to(
            LAYER_1_GATEWAY
        ) or filepath.resolve().is_relative_to(LAYER_1_GATEWAY.resolve()):
            is_layer1 = True
    except (ValueError, FileNotFoundError):
        pass

    if not is_layer1:
        parts = filepath.parts
        for i in range(len(parts) - 1):
            if parts[i] == "src" and parts[i + 1] == "gateway":
                is_layer1 = True
                break

    if not is_layer1:
        return violations

    is_evidence_kernel = False
    try:
        if filepath.is_relative_to(EVIDENCE_DIR) or filepath.resolve().is_relative_to(
            EVIDENCE_DIR.resolve()
        ):
            is_evidence_kernel = True
    except (ValueError, FileNotFoundError):
        pass

    if not is_evidence_kernel:
        parts = filepath.parts
        for i in range(len(parts) - 3):
            if parts[i : i + 4] == ("src", "gateway", "governance", "evidence"):
                is_evidence_kernel = True
                break

    for imp, lineno in imports:
        # Check Layer 1 -> Layer 2
        if LAYER_2_CAGE_PATTERN.match(imp):
            v = BoundaryViolation(
                file_path=filepath_str,
                line_number=lineno,
                imported_module=imp,
                rule_violated="Layer 1 → Layer 2 (gateway must not import cage_*)",
            )
            violations.append(v)
            if verbose:
                print(f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})")

        # Check Layer 1 -> Layer 3
        if LAYER_3_BRIDGE_PATTERN.match(imp):
            v = BoundaryViolation(
                file_path=filepath_str,
                line_number=lineno,
                imported_module=imp,
                rule_violated="Layer 1 → Layer 3 (gateway must not import compliance_bridge)",
            )
            violations.append(v)
            if verbose:
                print(f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})")

        # Check Layer 1 -> Layer 4
        if LAYER_4_GFA_PATTERN.match(imp):
            v = BoundaryViolation(
                file_path=filepath_str,
                line_number=lineno,
                imported_module=imp,
                rule_violated="Layer 1 → Layer 4 (gateway must not import governed_financial_advisor)",
            )
            violations.append(v)
            if verbose:
                print(f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})")

        # Check evidence kernel vendor neutrality
        if is_evidence_kernel:
            for vendor_sdk in FORBIDDEN_VENDOR_SDKS:
                if imp == vendor_sdk or imp.startswith(f"{vendor_sdk}."):
                    v = BoundaryViolation(
                        file_path=filepath_str,
                        line_number=lineno,
                        imported_module=imp,
                        rule_violated=f"Evidence kernel vendor neutrality (forbidden vendor SDK: {vendor_sdk})",
                    )
                    violations.append(v)
                    if verbose:
                        print(
                            f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})"
                        )
                    break

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Check layer import boundaries")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print("🔍 Checking import boundaries (Gate G3)...")

    gateway_root = Path(LAYER_1_GATEWAY)
    if not gateway_root.exists():
        print(f"❌ Gateway layer not found: {gateway_root}")
        return 1

    all_violations: list[BoundaryViolation] = []
    scanned_count = 0

    for py_file in gateway_root.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue
        scanned_count += 1
        violations = check_file_boundaries(py_file, verbose=args.verbose)
        all_violations.extend(violations)

    print(f"📊 Scanned {scanned_count} files in {LAYER_1_GATEWAY}/")

    if all_violations:
        print(f"\n❌ BOUNDARY VIOLATIONS DETECTED ({len(all_violations)}):\n")
        for v in all_violations:
            print(f"  {v.file_path}:{v.line_number}")
            print(f"    └─ imports {v.imported_module} [{v.rule_violated}]\n")

        print("🚨 Layer 1 (gateway) must NOT import from Layer 2, Layer 3, or Layer 4.")
        print("🚨 Evidence kernel must NOT import proprietary vendor SDKs.")
        print("   Use dependency injection, canonical interfaces, or external plugins.")
        return 1

    print("✅ All import boundaries respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
