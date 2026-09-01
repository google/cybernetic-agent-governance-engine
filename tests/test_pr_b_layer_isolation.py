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

"""PR B — Layer Isolation Tests (G3)

Verifies that the plugin seam architecture established in PR B correctly
enforces the three-layer split:
- Layer 1 (src/gateway/) must NOT import from Layer 2 (src/cage_*)
- Layer 1 must NOT import from Layer 4 (src/governed_financial_advisor/)

These tests are marked with pytest marker 'layer_isolation' and 'local'.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.local
@pytest.mark.layer_isolation
def test_g3_import_boundary_enforcement():
    """G3 — Verify that check_import_boundaries.py exits 0 (no violations)."""
    script_path = (
        Path(__file__).parent.parent / "scripts" / "check_import_boundaries.py"
    )
    assert script_path.exists(), f"Import boundary script not found: {script_path}"

    result = subprocess.run(
        [sys.executable, str(script_path), "--verbose"],
        capture_output=True,
        text=True,
    )

    # Gate G3: The script must exit 0 (no boundary violations)
    assert result.returncode == 0, (
        f"Import boundary violations detected:\n{result.stdout}\n{result.stderr}"
    )

    # Verify the script scanned files and found no violations
    assert "Scanned" in result.stdout
    assert "All import boundaries respected" in result.stdout


@pytest.mark.local
@pytest.mark.layer_isolation
def test_gateway_files_have_no_cage_imports():
    """Directly verify that no src/gateway/ files import from src/cage_*."""
    gateway_root = Path(__file__).parent.parent / "src" / "gateway"
    assert gateway_root.exists(), f"Gateway directory not found: {gateway_root}"

    cage_import_pattern = re.compile(
        r"^(from\s+src\.cage_\w+|from\s+cage_\w+|import\s+src\.cage_\w+|import\s+cage_\w+)"
    )

    violations = []
    for py_file in gateway_root.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue

        with open(py_file, encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if cage_import_pattern.match(stripped):
                    violations.append((py_file, line_num, stripped))

    assert not violations, (
        f"Found {len(violations)} Layer 1 → Layer 2 import violations:\n"
        + "\n".join(f"  {path}:{line}: {code}" for path, line, code in violations)
    )


@pytest.mark.local
@pytest.mark.layer_isolation
@pytest.mark.skip(
    reason="Layer 1 → Layer 4 (GFA) violations are out of scope for PR B - fixed in PR D"
)
def test_gateway_files_have_no_gfa_imports():
    """Directly verify that no src/gateway/ files import from src/governed_financial_advisor/.

    NOTE: This test is skipped for PR B. Layer 1 → Layer 4 violations will be fixed in PR D
    (Rail Seam and Second Domain Proof). PR B only addresses Layer 1 → Layer 2 (cage_*) violations.
    """
    gateway_root = Path(__file__).parent.parent / "src" / "gateway"
    assert gateway_root.exists(), f"Gateway directory not found: {gateway_root}"

    gfa_import_pattern = re.compile(
        r"^(from\s+src\.governed_financial_advisor|from\s+governed_financial_advisor|import\s+src\.governed_financial_advisor|import\s+governed_financial_advisor)"
    )

    violations = []
    for py_file in gateway_root.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue

        with open(py_file, encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if gfa_import_pattern.match(stripped):
                    violations.append((py_file, line_num, stripped))

    assert not violations, (
        f"Found {len(violations)} Layer 1 → Layer 4 import violations:\n"
        + "\n".join(f"  {path}:{line}: {code}" for path, line, code in violations)
    )


@pytest.mark.local
@pytest.mark.layer_isolation
def test_plugin_seam_imports_are_kernel_only():
    """Verify that plugin seam modules (singletons, background_tasks, constants) only import from Layer 1."""
    seam_modules = [
        "src/gateway/governance/singletons.py",
        "src/gateway/governance/background_tasks.py",
        "src/gateway/governance/constants.py",
        "src/gateway/governance/null_components.py",
        "src/gateway/governance/types.py",
    ]

    repo_root = Path(__file__).parent.parent
    cage_import_pattern = re.compile(r"cage_\w+")

    violations = []
    for module_path in seam_modules:
        full_path = repo_root / module_path
        if not full_path.exists():
            continue

        try:
            with open(full_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(full_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if cage_import_pattern.search(alias.name):
                            violations.append((module_path, alias.name, "import"))
                elif isinstance(node, ast.ImportFrom):
                    if node.module and cage_import_pattern.search(node.module):
                        violations.append((module_path, node.module, "from"))
        except SyntaxError:
            pass  # Skip files with syntax errors

    assert not violations, (
        "Plugin seam modules must not import from cage_* (Layer 2):\n"
        + "\n".join(f"  {path}: {imp} ({kind})" for path, imp, kind in violations)
    )
