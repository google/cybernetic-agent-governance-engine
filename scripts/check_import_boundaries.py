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
- Layer 1 must NOT import from Layer 3 integrations (src/integrations/) at module scope
  (function-scope lazy imports are permitted only in allowlisted factory modules)
- Layer 1 must NOT import from Layer 4 (src/governed_financial_advisor/)
- Evidence kernel (src/gateway/governance/evidence/) must NOT import vendor SDKs:
  (google.cloud, boto3, botocore, azure, langfuse)

Forward compatibility note:
    src/gateway/governance/execution_actuator.py is the expected next allowlist entry
    when ActuatorRegistry lands (will instantiate actuator_01 via lazy factory pattern).

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
LAYER_3_INTEGRATIONS = Path("src/integrations")
EVIDENCE_DIR = Path("src/gateway/governance/evidence")

# Forbidden import patterns for Layer 1
LAYER_2_CAGE_PATTERN = re.compile(r"^(src\.)?cage_\w+")
LAYER_3_BRIDGE_PATTERN = re.compile(r"^(src\.)?compliance_bridge")
LAYER_3_INTEGRATIONS_PATTERN = re.compile(r"^(src\.)?integrations\b")
LAYER_4_GFA_PATTERN = re.compile(r"^(src\.)?governed_financial_advisor")

# Forbidden vendor SDKs for Evidence Kernel
FORBIDDEN_VENDOR_SDKS = ("google.cloud", "boto3", "botocore", "azure", "langfuse")

# Allowlist for function-scope lazy imports of src.integrations in Layer 1
# These factory modules may lazy-load vendor adapters at instantiation time.
# Adding an entry requires deliberate architectural review — keep this small.
INTEGRATIONS_FACTORY_ALLOWLIST = frozenset(
    [
        "src/gateway/governance/normative_provider.py",  # lazy-loads provider_01/03/06
        "src/gateway/governance/evidence/factory.py",  # lazy-loads storage_gcs/storage_s3
        "src/compliance_bridge/main.py",  # lazy-loads provider_02.cer_index (B6 CER wiring)
    ]
)


@dataclass(frozen=True)
class BoundaryViolation:
    file_path: str
    line_number: int
    imported_module: str
    rule_violated: str


class ImportVisitor(ast.NodeVisitor):
    """AST visitor to extract all import statements with scope information.

    Emits (module_name, line_number, is_module_scope) triples.
    Class-body imports are treated as module-scope for this rule.
    """

    def __init__(self) -> None:
        self.imports: list[tuple[str, int, bool]] = []
        self._scope_depth: int = 0

    def visit_Import(self, node: ast.Import) -> None:
        """Visit `import x` statements."""
        is_module_scope = self._scope_depth == 0
        for alias in node.names:
            self.imports.append((alias.name, node.lineno, is_module_scope))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit `from x import y` statements."""
        is_module_scope = self._scope_depth == 0
        if node.module:
            self.imports.append((node.module, node.lineno, is_module_scope))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track entry/exit of function scope."""
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track entry/exit of async function scope."""
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track entry/exit of class scope.

        Note: class-body imports are NOT considered function-scope for this rule.
        """
        # Do NOT increment scope_depth — class-body imports are module-scope
        self.generic_visit(node)


def extract_imports(filepath: Path) -> list[tuple[str, int, bool]]:
    """Extract all (import_module_name, line_number, is_module_scope) triples from a Python file."""
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

    # Check if file is in the integrations factory allowlist
    is_in_factory_allowlist = any(
        filepath_str.endswith(allowed_path) or allowed_path in filepath_str
        for allowed_path in INTEGRATIONS_FACTORY_ALLOWLIST
    )

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

    for imp, lineno, is_module_scope in imports:
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

        # Check Layer 1 -> Layer 3 integrations (scope-aware)
        if LAYER_3_INTEGRATIONS_PATTERN.match(imp):
            if is_module_scope:
                # Module-scope integrations imports are ALWAYS forbidden
                v = BoundaryViolation(
                    file_path=filepath_str,
                    line_number=lineno,
                    imported_module=imp,
                    rule_violated="Layer 1 → Layer 3 (module-scope src.integrations import forbidden; use a function-scope lazy factory import)",
                )
                violations.append(v)
                if verbose:
                    print(
                        f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})"
                    )
            elif not is_in_factory_allowlist:
                # Function-scope import but file not in allowlist
                v = BoundaryViolation(
                    file_path=filepath_str,
                    line_number=lineno,
                    imported_module=imp,
                    rule_violated="Layer 1 → Layer 3 (src.integrations import outside the factory allowlist)",
                )
                violations.append(v)
                if verbose:
                    print(
                        f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})"
                    )
            # else: function-scope AND in allowlist → permitted (no violation)

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


# Allowlist for specific Layer 3 integrations files that have justified cross-layer dependencies.
# Each entry requires explicit architectural justification — keep this minimal.
INTEGRATIONS_BOUNDARY_ALLOWLIST = frozenset(
    [
        # provider_02/cer_index.py implements the CERIndex Protocol defined in compliance_bridge
        # and is dependency-injected into compliance_bridge at FastAPI startup (B6 integration).
        # Importing Disclosure enum from the protocol it implements is legitimate coupling.
        "src/integrations/provider_02/cer_index.py",
    ]
)


def check_integrations_boundaries(
    filepath: Path, verbose: bool = False
) -> list[BoundaryViolation]:
    """Check if a Layer 3 integrations file imports from Layer 2/4.

    Layer 3 (src/integrations/) must NOT import from:
    - Layer 2 (src/cage_*) — except test files importing domain test fixtures
    - Layer 3 compliance_bridge (src/compliance_bridge/) — except allowlisted protocol implementations
    - Layer 4 (src/governed_financial_advisor/)

    Returns:
        List of BoundaryViolation instances.
    """
    violations: list[BoundaryViolation] = []
    imports = extract_imports(filepath)
    filepath_str = str(filepath)

    # Check if file is in the integrations boundary allowlist
    is_in_boundary_allowlist = any(
        filepath_str.endswith(allowed_path) or allowed_path in filepath_str
        for allowed_path in INTEGRATIONS_BOUNDARY_ALLOWLIST
    )

    # Check if this is a test file (tests may import domain fixtures)
    is_test_file = "/tests/" in filepath_str or filepath_str.endswith("_test.py")

    for imp, lineno, _is_module_scope in imports:
        # Check Layer 3 integrations -> Layer 2 cage_*
        if LAYER_2_CAGE_PATTERN.match(imp):
            # Test files may import domain fixtures
            if not is_test_file:
                v = BoundaryViolation(
                    file_path=filepath_str,
                    line_number=lineno,
                    imported_module=imp,
                    rule_violated="Layer 3 integrations → Layer 2 (integrations must not import cage_*)",
                )
                violations.append(v)
                if verbose:
                    print(
                        f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})"
                    )

        # Check Layer 3 integrations -> Layer 3 compliance_bridge
        if LAYER_3_BRIDGE_PATTERN.match(imp):
            # Allowlisted protocol implementations may import from compliance_bridge
            if not is_in_boundary_allowlist:
                v = BoundaryViolation(
                    file_path=filepath_str,
                    line_number=lineno,
                    imported_module=imp,
                    rule_violated="Layer 3 integrations → Layer 3 compliance_bridge (cross-Layer-3 coupling forbidden)",
                )
                violations.append(v)
                if verbose:
                    print(
                        f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})"
                    )

        # Check Layer 3 integrations -> Layer 4
        if LAYER_4_GFA_PATTERN.match(imp):
            v = BoundaryViolation(
                file_path=filepath_str,
                line_number=lineno,
                imported_module=imp,
                rule_violated="Layer 3 integrations → Layer 4 (integrations must not import governed_financial_advisor)",
            )
            violations.append(v)
            if verbose:
                print(f"❌ {filepath_str}:{lineno}: imports {imp} ({v.rule_violated})")

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

    # Forward scan: Layer 1 (gateway) must not import from Layer 2/3/4
    for py_file in gateway_root.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue
        scanned_count += 1
        violations = check_file_boundaries(py_file, verbose=args.verbose)
        all_violations.extend(violations)

    print(f"📊 Forward scan: {scanned_count} files in {LAYER_1_GATEWAY}/")

    # Reverse scan: Layer 3 (integrations) must not import from Layer 2/4
    integrations_root = Path(LAYER_3_INTEGRATIONS)
    if integrations_root.exists():
        integrations_count = 0
        for py_file in integrations_root.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            integrations_count += 1
            violations = check_integrations_boundaries(py_file, verbose=args.verbose)
            all_violations.extend(violations)
        print(f"📊 Reverse scan: {integrations_count} files in {LAYER_3_INTEGRATIONS}/")

    if all_violations:
        print(f"\n❌ BOUNDARY VIOLATIONS DETECTED ({len(all_violations)}):\n")
        for v in all_violations:
            print(f"  {v.file_path}:{v.line_number}")
            print(f"    └─ imports {v.imported_module} [{v.rule_violated}]\n")

        print("🚨 Layer 1 (gateway) must NOT import from Layer 2, Layer 3, or Layer 4.")
        print("🚨 Layer 1 module-scope imports of src.integrations are FORBIDDEN.")
        print(
            "🚨 Function-scope lazy imports of src.integrations require explicit allowlist entry."
        )
        print(
            "🚨 Layer 3 (integrations) must NOT import from Layer 2 (cage_*) or Layer 4."
        )
        print(
            "🚨 Layer 3 cross-coupling (integrations ↔ compliance_bridge) is forbidden."
        )
        print("🚨 Evidence kernel must NOT import proprietary vendor SDKs.")
        print()
        print("   Remediation:")
        print("   • Use dependency injection or canonical interfaces (Layer 2/4)")
        print("   • For vendor adapters: use function-scope lazy factory imports")
        print(
            "   • Adding to INTEGRATIONS_FACTORY_ALLOWLIST requires architectural review"
        )
        print(
            "   • Integrations must use kernel seams (NormativeProvider, AttestationProvider)"
        )
        return 1

    print("✅ All import boundaries respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
