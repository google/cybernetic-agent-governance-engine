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

"""Gate G8: Vendor and partner brand anonymity enforcement across code, paths, and tests.

Scope (all 5 code/test trees):
  1. ``src/gateway/`` (Layer 1 kernel)
  2. ``packages/cage-conformance/src/`` (published conformance CLI)
  3. ``src/integrations/`` (Layer 3 adapters)
  4. ``scripts/`` (operational and verification scripts)
  5. ``tests/`` (unit, integration, and conformance tests)

What is checked:
  - File and directory paths across all 5 trees (catches branded filenames such as
    ``verify_flowsignal_wire_and_hostile.py`` or ``flowsignal_v02.json``).
  - Python AST symbol and identifier names (``ClassDef``, ``FunctionDef``,
    ``AsyncFunctionDef``, ``Name``, ``Attribute``, ``arg``) across all 5 trees
    (catches ``FlowSignalNormativeProvider``, ``_map_flowsignal_decision``, etc.).
  - Python AST string and bytes literals (``ast.Constant``) outside of docstrings.

Layer 3 External Wire-Protocol Boundary & Provenance Ceiling:
  CAGE-owned paths, class/function/variable identifiers, CLI choices, environment
  variable names, log messages, and test fixtures must use anonymized identifiers
  (``provider_01``..``provider_08``, ``actuator_01``) across all 5 trees.
  At the Layer 3 wire boundary, only external wire-protocol constants fixed by a
  partner's cryptographic signing preimage, HTTP header contract, discovery path,
  or signed JWS test vector payload may retain the wire-level string/bytes value.
  Every such constant must be registered in ``LAYER3_WIRE_PROTOCOL_PROVENANCE``
  mapping the literal to the committed non-Python partner specification or
  received test vector artifact (``.md`` or ``.json``) that defines it. Gate G8
  mechanically verifies both directions:
    1. Provenance floor: every allowlisted literal must appear in its cited
       non-Python specification or vector artifact on disk.
    2. Ceiling (no dead/speculative entries): every allowlisted literal must be
       referenced in the scanned Python trees; unused entries fail Gate G8.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# External normative and actuation partner brand names. Forbidden in paths,
# Python identifiers, and non-wire string/bytes literals across all 5 scanned trees.
PARTNER_VENDOR_BRANDS: set[str] = {
    "flowsignal",
    "flow_signal",
    "archytan",
    "nexart",
    "primust",
    "thoughtbox",
    "thoughtproof",
    "ackagent",
    "infertheta",
    "verdict_systems",
}

# Full set of vendor brands forbidden in Layer 1 kernel (src/gateway/) and
# published conformance package (packages/cage-conformance/src/).
FORBIDDEN_VENDOR_BRANDS: set[str] = PARTNER_VENDOR_BRANDS | {
    "langsmith",
    "langfuse",
    "openai",
}

# Allowed artifact extensions for LAYER3_WIRE_PROTOCOL_PROVENANCE citations.
# Python (.py) files are forbidden as provenance sources so an author cannot
# self-justify a literal by pointing at the code or test that introduced it.
ALLOWED_PROVENANCE_SUFFIXES: frozenset[str] = frozenset({".md", ".json"})

# Explicit Layer 3 external wire-protocol constants mapped to the committed
# partner specification or received vector artifact where the wire value is defined.
LAYER3_WIRE_PROTOCOL_PROVENANCE: dict[str, str] = {
    # actuator_01 cryptographic domain-separation prefixes & HTTP wire headers
    "ARCHYTAN_ASSERTION_V1:": "src/integrations/actuator_01/README.md",
    "ARCHYTAN_QUORUM_V1:": "src/integrations/actuator_01/README.md",
    "ARCHYTAN_POLICY_DECISION_V1:": "docs/operations/ARCHYTAN_VECTOR_ALIGNMENT.md",
    "ARCHYTAN_RECEIPT_V1:": "src/integrations/actuator_01/README.md",
    "X-Archytan-Signatures": "src/integrations/actuator_01/README.md",
    "x-archytan-signatures": "src/integrations/actuator_01/README.md",
    "archytan.envelope/v1": "tests/fixtures/actuator_01/vector1_direct.json",
    "archytan.local": "docs/operations/ARCHYTAN_VECTOR_ALIGNMENT.md",
    "https://archytan.local": "docs/operations/ARCHYTAN_VECTOR_ALIGNMENT.md",
    "archytan-sandbox-receipt-2026-01": "src/integrations/actuator_01/README.md",
    "urn:archytan:op:test_vector_1": "tests/fixtures/actuator_01/vector1_direct.json",
    "urn:archytan:op:test_vector_3_approver": "tests/fixtures/actuator_01/vector3_escalate.json",
    "urn:archytan:op:test_vector_3_op1": "tests/fixtures/actuator_01/vector3_escalate.json",
    "urn:archytan:cage:policy-authority": "deployment/certs/actuator_01/sandbox_public_keys.json",
    "urn:archytan:cage:operator:test-alice": "deployment/certs/actuator_01/sandbox_public_keys.json",
    "urn:archytan:cage:operator:test-bob": "deployment/certs/actuator_01/sandbox_public_keys.json",
    # provider_02 discovery endpoint & protected-set schema identifier
    "/.well-known/nexart-node.json": "tests/fixtures/provider_02_native/attest_exchange_k1.json",
    "nexart.governed.execution.v1.protected-set.v1": "tests/fixtures/provider_02_native/attest_exchange_k1.json",
    # provider_07 signed JWS receipt kids and authority_record_ids in wire vectors
    "infertheta-provider07-2026-01": "src/integrations/provider_07/README.md",
    "infertheta-provider07-prod-2026-01": "docs/partners/provider_07/INFERTHETA_CANONICAL_SCHEMA.md",
    "infertheta-ar-09b99a87-66ff-4791-9f31-f453841d2e8a": "src/integrations/provider_07/README.md",
    "infertheta-ar-": "src/integrations/provider_07/README.md",
}

LAYER3_WIRE_PROTOCOL_LITERALS: frozenset[str] = frozenset(
    LAYER3_WIRE_PROTOCOL_PROVENANCE
)

# Documentation-governance scripts and gate unit tests that inspect markdown docs
# under docs/partners/ or test Gate G8 itself.
DOC_GOVERNANCE_FILES: frozenset[str] = frozenset(
    {
        "scripts/check_vendor_brands.py",
        "scripts/check_partner_headers.py",
        "scripts/check_doc_references.py",
        "scripts/check_poam_lula_divergence.py",
        "scripts/package_provider_02_handoff.py",
        "tests/test_check_partner_headers.py",
        "tests/test_layer_boundary_gates.py",
    }
)

# Auto-generated files excluded from AST scanning
EXCLUDED_FILES: set[str] = {
    "generated_stpa_validator.py",
    "generated_saga_nodes.py",
}

# Directories excluded from scanning
EXCLUDED_DIRS: set[str] = {"protos", "__pycache__", ".pytest_cache", ".mypy_cache"}


class VendorBrandChecker(ast.NodeVisitor):
    """AST visitor that checks identifiers and non-docstring string/bytes literals."""

    def __init__(
        self,
        filepath: Path,
        brands: set[str],
        *,
        allow_wire_literals: bool = False,
    ) -> None:
        self.filepath = filepath
        self.brands = {b.lower() for b in brands}
        self.allow_wire_literals = allow_wire_literals
        self.violations: list[tuple[int, str]] = []
        self.matched_wire_literals: set[str] = set()
        self._docstring_nodes: set[ast.AST] = set()

    def _check_identifier(self, lineno: int, kind: str, name: str) -> None:
        lower_name = name.lower()
        for brand in self.brands:
            if brand in lower_name:
                self.violations.append((lineno, f"{kind}:{name}"))
                break

    def visit_Module(self, node: ast.Module) -> None:
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_identifier(node.lineno, "def", node.name)
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_identifier(node.lineno, "async def", node.name)
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._check_identifier(node.lineno, "class", node.name)
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self._check_identifier(node.lineno, "id", node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_identifier(node.lineno, "attr", node.attr)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        self._check_identifier(node.lineno, "arg", node.arg)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if node not in self._docstring_nodes:
            text: str | None = None
            if isinstance(node.value, str):
                text = node.value
            elif isinstance(node.value, bytes):
                text = node.value.decode("utf-8", errors="replace")

            if text is not None:
                stripped = text.strip()
                if (
                    self.allow_wire_literals
                    and stripped in LAYER3_WIRE_PROTOCOL_LITERALS
                ):
                    self.matched_wire_literals.add(stripped)
                    self.generic_visit(node)
                    return

                lower_value = text.lower()
                for brand in self.brands:
                    if brand in lower_value:
                        self.violations.append((node.lineno, text))
                        break
        self.generic_visit(node)


def check_wire_literal_provenance(
    repo_root: Path,
    provenance: dict[str, str] | None = None,
) -> list[str]:
    """Verify every allowlisted Layer 3 wire literal exists in its cited spec/vector artifact."""
    active_provenance = (
        LAYER3_WIRE_PROTOCOL_PROVENANCE if provenance is None else provenance
    )
    errors: list[str] = []
    content_cache: dict[Path, str] = {}

    for literal, rel_artifact in sorted(active_provenance.items()):
        if not literal or not rel_artifact:
            errors.append(
                f"'{literal}' -> '{rel_artifact}': empty literal or provenance path"
            )
            continue

        artifact_path = repo_root / rel_artifact
        if artifact_path.suffix not in ALLOWED_PROVENANCE_SUFFIXES:
            errors.append(
                f"'{literal}' -> '{rel_artifact}': provenance must be a non-Python "
                f"spec or vector artifact ({sorted(ALLOWED_PROVENANCE_SUFFIXES)}), not '{artifact_path.suffix}'"
            )
            continue

        if not artifact_path.is_file():
            errors.append(
                f"'{literal}' -> '{rel_artifact}': provenance artifact does not exist"
            )
            continue

        if artifact_path not in content_cache:
            content_cache[artifact_path] = artifact_path.read_text(encoding="utf-8")

        text = content_cache[artifact_path]
        if literal not in text and literal.lower() not in text.lower():
            errors.append(
                f"'{literal}' -> '{rel_artifact}': literal not found in cited provenance artifact"
            )

    return errors


def check_path(
    filepath: Path,
    repo_root: Path,
    brands: set[str] | None = None,
) -> list[str]:
    """Return any forbidden partner brand names present in ``filepath`` relative to ``repo_root``."""
    active_brands = PARTNER_VENDOR_BRANDS if brands is None else brands
    try:
        rel_str = filepath.relative_to(repo_root).as_posix().lower()
    except ValueError:
        rel_str = filepath.name.lower()
    return sorted(brand for brand in active_brands if brand.lower() in rel_str)


def check_file(
    filepath: Path,
    brands: set[str] | None = None,
    *,
    allow_wire_literals: bool = False,
    matched_wire_literals: set[str] | None = None,
) -> list[tuple[int, str]]:
    """Parse ``filepath`` and return ``(lineno, offending_token)`` violations."""
    active_brands = FORBIDDEN_VENDOR_BRANDS if brands is None else brands
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        checker = VendorBrandChecker(
            filepath,
            active_brands,
            allow_wire_literals=allow_wire_literals,
        )
        checker.visit(tree)
        if matched_wire_literals is not None:
            matched_wire_literals.update(checker.matched_wire_literals)
        return checker.violations
    except SyntaxError as exc:
        print(f"⚠️  Syntax error in {filepath}: {exc}", file=sys.stderr)
        return [(1, f"<unparseable: {exc}>")]
    except Exception as exc:
        print(f"⚠️  Failed to parse {filepath}: {exc}", file=sys.stderr)
        return [(1, f"<unparseable: {exc}>")]


def should_skip_path(path: Path, base_dir: Path) -> bool:
    for part in path.relative_to(base_dir).parts:
        if part in EXCLUDED_DIRS:
            return True
    if path.name in EXCLUDED_FILES:
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check vendor and partner brand names in paths, AST identifiers, and "
            "executable literals across src/gateway/, packages/cage-conformance/src/, "
            "src/integrations/, scripts/, and tests/."
        )
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    gateway_dir = repo_root / "src" / "gateway"
    conformance_dir = repo_root / "packages" / "cage-conformance" / "src"
    integrations_dir = repo_root / "src" / "integrations"
    scripts_dir = repo_root / "scripts"
    tests_dir = repo_root / "tests"

    if not gateway_dir.exists():
        print(f"❌ Gateway directory not found: {gateway_dir}", file=sys.stderr)
        return 1

    if not FORBIDDEN_VENDOR_BRANDS or not PARTNER_VENDOR_BRANDS:
        print(
            "❌ Gate G8 FAILED: Brand sets must not be empty.",
            file=sys.stderr,
        )
        return 1

    provenance_errors = check_wire_literal_provenance(repo_root)
    if provenance_errors:
        print(
            "❌ Gate G8 FAILED: LAYER3_WIRE_PROTOCOL_PROVENANCE contains unverified entries:"
        )
        for err in provenance_errors:
            print(f"   • {err}")
        return 1

    # (directory, brands_to_enforce, allow_layer3_wire_literals)
    scan_targets: list[tuple[Path, set[str], bool]] = [
        (gateway_dir, FORBIDDEN_VENDOR_BRANDS, False),
        (conformance_dir, FORBIDDEN_VENDOR_BRANDS, True),
        (integrations_dir, PARTNER_VENDOR_BRANDS, True),
        (scripts_dir, PARTNER_VENDOR_BRANDS, True),
        (tests_dir, PARTNER_VENDOR_BRANDS, True),
    ]

    violations_found = False
    scanned_files = 0
    scanned_paths = 0
    matched_wire_literals: set[str] = set()

    for scan_dir, brands, allow_wire_literals in scan_targets:
        if not scan_dir.exists():
            continue

        for entry in sorted(scan_dir.rglob("*")):
            if should_skip_path(entry, scan_dir):
                continue

            scanned_paths += 1
            path_hits = check_path(entry, repo_root, PARTNER_VENDOR_BRANDS)
            if path_hits:
                violations_found = True
                rel_path = entry.relative_to(repo_root).as_posix()
                print(
                    f"❌ {rel_path}: path contains forbidden brand(s): {', '.join(path_hits)}"
                )

            if not entry.is_file() or entry.suffix != ".py":
                continue

            rel_posix = entry.relative_to(repo_root).as_posix()
            if rel_posix in DOC_GOVERNANCE_FILES:
                continue

            scanned_files += 1
            violations = check_file(
                entry,
                brands,
                allow_wire_literals=allow_wire_literals,
                matched_wire_literals=matched_wire_literals,
            )
            if violations:
                violations_found = True
                print(f"❌ {rel_posix}:")
                for line_num, literal in violations:
                    print(f"   Line {line_num}: '{literal}'")

    unused_wire_literals = sorted(LAYER3_WIRE_PROTOCOL_LITERALS - matched_wire_literals)
    if unused_wire_literals:
        violations_found = True
        print(
            "❌ LAYER3_WIRE_PROTOCOL_PROVENANCE contains unused allowlist entries (ceiling check):"
        )
        for unused in unused_wire_literals:
            print(
                f"   • '{unused}' (cited in {LAYER3_WIRE_PROTOCOL_PROVENANCE[unused]})"
            )

    if violations_found:
        print()
        print(
            "❌ Gate G8 FAILED: Found forbidden vendor/partner brands in paths, identifiers, or literals."
        )
        print(
            f"   Kernel forbidden brands: {', '.join(sorted(FORBIDDEN_VENDOR_BRANDS))}"
        )
        print(
            f"   Partner forbidden brands: {', '.join(sorted(PARTNER_VENDOR_BRANDS))}"
        )
        print()
        print("   Partner and vendor brand rules across all 5 scanned trees:")
        print(
            "   • File and directory paths must use anonymized IDs (provider_01, actuator_01)"
        )
        print(
            "   • Python class, function, variable, attribute, and arg names must be anonymized"
        )
        print("   • Docstrings and comments may name partners in prose")
        print(
            "   • Only external wire-protocol constants in LAYER3_WIRE_PROTOCOL_PROVENANCE "
            "(each verified against its cited .md/.json partner spec or vector artifact, with "
            "zero unused entries) are permitted"
        )
        return 1

    if args.verbose:
        print(
            f"📊 Scanned {scanned_files} Python files and {scanned_paths} paths across "
            f"{', '.join(str(t[0].relative_to(repo_root)) for t in scan_targets if t[0].exists())} "
            f"({len(matched_wire_literals)}/{len(LAYER3_WIRE_PROTOCOL_LITERALS)} provenance-verified wire literals active)"
        )
    print(
        f"✅ Gate G8 PASSED: No forbidden vendor brands in {scanned_files} Python files or {scanned_paths} paths "
        f"({len(LAYER3_WIRE_PROTOCOL_LITERALS)} provenance-verified wire literals)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
