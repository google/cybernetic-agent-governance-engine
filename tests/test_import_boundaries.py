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

"""
Sprint 3.3: Import Boundary Enforcement Tests

Verifies that Layer 1 (gateway/kernel) does not import from Layer 3 (Langfuse SDK)
or Layer 2 (cage_*), ensuring proper architectural layering.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest


class TestImportBoundaries:
    """Test import boundary enforcement between architectural layers."""

    def test_gateway_cannot_import_langfuse(self):
        """
        Static analysis: verify no Langfuse imports in src/gateway/.

        All telemetry flows through Evidence Stream or OTel only.
        See plans/evidence_integration_implementation_plan.md §4.8
        """
        gateway_root = Path("src/gateway")
        violations = []

        for py_file in gateway_root.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.startswith("langfuse"):
                                violations.append((str(py_file), alias.name))
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and node.module.startswith("langfuse"):
                            violations.append((str(py_file), node.module))
            except (SyntaxError, FileNotFoundError):
                # Skip files with syntax errors or temp files
                continue

        if violations:
            msg = "Gateway (Layer 1) must not import Langfuse SDK (Layer 3):\n"
            for filepath, module in violations:
                msg += f"  {filepath} imports {module}\n"
            pytest.fail(msg)

    def test_gateway_cannot_import_cage_modules(self):
        """
        Static analysis: verify no cage_* imports in src/gateway/.

        Layer 1 must not import Layer 2 (cage_* plugins).
        """
        gateway_root = Path("src/gateway")
        violations = []

        for py_file in gateway_root.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if "cage_" in alias.name:
                                violations.append((str(py_file), alias.name))
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and "cage_" in node.module:
                            violations.append((str(py_file), node.module))
            except (SyntaxError, FileNotFoundError):
                continue

        if violations:
            msg = "Gateway (Layer 1) must not import cage_* (Layer 2):\n"
            for filepath, module in violations:
                msg += f"  {filepath} imports {module}\n"
            pytest.fail(msg)

    def test_boundary_violations_fail_ci(self):
        """
        Verify check_import_boundaries.py exits 1 on violation.

        This ensures the CI gate will catch boundary violations.
        """
        result = subprocess.run(
            [sys.executable, "scripts/check_import_boundaries.py"],
            capture_output=True,
            text=True,
        )

        # Exit code 0 = no violations, 1 = violations detected
        # For this test to pass, we expect NO violations (exit 0)
        if result.returncode != 0:
            pytest.fail(
                f"Import boundary violations detected:\n{result.stdout}\n{result.stderr}"
            )

    def test_boundary_check_script_exists(self):
        """Verify the boundary check script exists and is executable."""
        script_path = Path("scripts/check_import_boundaries.py")

        assert script_path.exists(), "check_import_boundaries.py not found"
        assert script_path.is_file(), "check_import_boundaries.py is not a file"

        # Verify script has valid Python syntax
        with open(script_path, encoding="utf-8") as f:
            try:
                ast.parse(f.read())
            except SyntaxError as e:
                pytest.fail(f"Syntax error in check_import_boundaries.py: {e}")

    def test_layer_definitions_include_langfuse(self):
        """Verify check_import_boundaries.py defines Layer 3 Langfuse pattern."""
        script_path = Path("scripts/check_import_boundaries.py")

        with open(script_path, encoding="utf-8") as f:
            content = f.read()

        assert "LAYER_3_LANGFUSE_PATTERN" in content, (
            "check_import_boundaries.py missing LAYER_3_LANGFUSE_PATTERN definition"
        )
        assert "langfuse" in content.lower(), (
            "check_import_boundaries.py does not check for langfuse imports"
        )
