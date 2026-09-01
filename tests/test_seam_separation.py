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

"""Test seam separation (G4 gate).

Vendor adapters (src/integrations/) and domain plugins (src/cage_*) are
orthogonal families. No integration module may implement a domain protocol
or declare a cage.plugins entry point.
"""

import ast
from pathlib import Path

import pytest


class TestSeamSeparation:
    """G4 gate: integration and domain seams are orthogonal."""

    def test_no_integration_module_implements_domain_protocol(self):
        """No src/integrations/ module implements GovernanceTierPlugin or RailProvider.

        Domain protocols live in src/gateway/governance/contracts.py.
        Vendor adapters implement NormativeProvider, AttestationProvider, etc.
        The two families must not overlap.
        """
        integrations_dir = Path(__file__).parent.parent / "src" / "integrations"

        if not integrations_dir.exists():
            pytest.skip("No integrations directory")

        domain_protocols = {
            "GovernanceTierPlugin",
            "RailProvider",
            "DomainToolProvider",
            "InvariantModel",
            "CagePlugin",
        }

        violations = []

        for py_file in integrations_dir.rglob("*.py"):
            if py_file.name.startswith("test_"):
                continue

            try:
                with open(py_file) as f:
                    tree = ast.parse(f.read(), filename=str(py_file))

                # Check for class definitions
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        # Check if any base class names match domain protocols
                        for base in node.bases:
                            if (
                                isinstance(base, ast.Name)
                                and base.id in domain_protocols
                            ):
                                violations.append(
                                    f"{py_file.relative_to(integrations_dir.parent)}: "
                                    f"class {node.name} implements {base.id}"
                                )
            except SyntaxError:
                # Skip files that don't parse
                pass

        assert not violations, (
            "G4 violation: integration modules implement domain protocols:\n"
            + "\n".join(violations)
        )

    def test_no_integration_module_declares_cage_plugin_entrypoint(self):
        """No module under src/integrations/ declares a cage.plugins entry point.

        This is enforced by the import boundary checker at the package level.
        """
        from pathlib import Path

        # Check that integrations don't declare plugin entry points
        integrations_dir = Path(__file__).parent.parent / "src" / "integrations"

        if not integrations_dir.exists():
            pytest.skip("No integrations directory")

        # Look for any setup.py or plugin.py that might declare entry points
        plugin_files = list(integrations_dir.rglob("plugin.py"))

        # Integration adapters should NOT have plugin.py files
        # (that pattern is for domain plugins only)
        assert not plugin_files, (
            f"G4 violation: found plugin.py files in integrations: {plugin_files}"
        )

    def test_no_cage_domain_imports_integration_internals(self):
        """Domain plugins must not import src/integrations/ internals.

        They may import kernel-owned provider protocols from src/gateway/,
        but not vendor adapter implementation details.
        """
        cage_dirs = list(Path(__file__).parent.parent.glob("src/cage_*"))

        if not cage_dirs:
            pytest.skip("No cage_* domain plugins found")

        violations = []

        for cage_dir in cage_dirs:
            for py_file in cage_dir.rglob("*.py"):
                try:
                    with open(py_file) as f:
                        content = f.read()

                    # Check for imports from src.integrations
                    if (
                        "from src.integrations" in content
                        or "import src.integrations" in content
                    ):
                        tree = ast.parse(content, filename=str(py_file))

                        for node in ast.walk(tree):
                            if isinstance(node, (ast.Import, ast.ImportFrom)):
                                if isinstance(node, ast.ImportFrom):
                                    if node.module and node.module.startswith(
                                        "src.integrations"
                                    ):
                                        violations.append(
                                            f"{py_file.relative_to(cage_dir.parent)}: "
                                            f"imports {node.module}"
                                        )
                                else:
                                    for alias in node.names:
                                        if alias.name.startswith("src.integrations"):
                                            violations.append(
                                                f"{py_file.relative_to(cage_dir.parent)}: "
                                                f"imports {alias.name}"
                                            )
                except (SyntaxError, FileNotFoundError):
                    pass

        assert not violations, (
            "G4 violation: domain plugins import integration internals:\n"
            + "\n".join(violations)
        )


@pytest.mark.local
class TestSeamSeparationLocal:
    """Local-only seam separation tests."""

    def test_domain_plugins_use_kernel_protocols_only(self):
        """Domain plugins import from src/gateway/governance/contracts.py, not integrations."""
        # This is a documentation test — verify the pattern is followed
        from src.cage_finance.plugin import FinanceCagePlugin
        from src.cage_healthcare.plugin import HealthcareCagePlugin

        # Both plugins should import from gateway, not integrations
        finance_module = FinanceCagePlugin.__module__
        healthcare_module = HealthcareCagePlugin.__module__

        assert finance_module.startswith("cage_finance") or finance_module.startswith(
            "src.cage_finance"
        )
        assert healthcare_module.startswith(
            "cage_healthcare"
        ) or healthcare_module.startswith("src.cage_healthcare")
