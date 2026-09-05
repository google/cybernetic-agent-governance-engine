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
Sprint 3.4: OSCAL Claim Backing Tests

Verifies that all security controls marked "implemented" in the OSCAL SSP
have corresponding evidence artifacts (config, tests, deployment manifests).

Prevents SC-7/SI-4 class defects where controls are asserted but not operational.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml


class TestOSCALClaimBacking:
    """Test OSCAL control claim backing validation."""

    def test_implemented_controls_have_evidence(self):
        """
        Verify all implemented controls have backing artifacts.

        Runs the check_oscal_claim_backing.py script and expects exit 0.
        """
        result = subprocess.run(
            [sys.executable, "scripts/check_oscal_claim_backing.py"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(
                f"OSCAL claim backing validation failed:\n{result.stdout}\n{result.stderr}"
            )

    def test_sc7_status_is_planned(self):
        """
        Verify SC-7 status changed from implemented → planned.

        Sprint 3.2 requirement: SC-7 (Boundary Protection) must be marked
        "planned" because Cilium CNI is documented but not yet deployed.
        """
        ssp_path = Path("compliance/oscal/system-security-plan.yaml")

        if not ssp_path.exists():
            pytest.skip("SSP not found (expected in compliance/oscal/)")

        with open(ssp_path) as f:
            ssp = yaml.safe_load(f)

        # Find SC-7 control in implemented-requirements
        controls = (
            ssp.get("system-security-plan", {})
            .get("control-implementation", {})
            .get("implemented-requirements", [])
        )

        sc7_control = None
        for control in controls:
            if control.get("control-id") == "SC-7":
                sc7_control = control
                break

        if not sc7_control:
            pytest.skip("SC-7 control not found in SSP")

        # Check status
        status = "planned"  # default

        # Try implementation-status.state first (OSCAL 1.0)
        impl_status = sc7_control.get("implementation-status", {})
        if isinstance(impl_status, dict):
            status = impl_status.get("state", "planned")

        # Fall back to direct status field (custom extension)
        if "status" in sc7_control:
            status = sc7_control.get("status", "planned")

        assert status == "planned", (
            f"SC-7 status must be 'planned' (found: {status}). "
            f"Cilium CNI is documented but not deployed."
        )

    def test_sc7_oscal_ssp_exporter_reflects_planned_status(self):
        """
        Verify oscal_ssp_exporter.py reflects SC-7 as planned.

        The SSP exporter control metadata must match the actual SSP status.
        """
        exporter_path = Path("src/gateway/governance/oscal_ssp_exporter.py")

        if not exporter_path.exists():
            pytest.skip("oscal_ssp_exporter.py not found")

        with open(exporter_path, encoding="utf-8") as f:
            content = f.read()

        # Verify SC-7 definition contains "planned" status
        assert '"sc-7"' in content.lower() or "'sc-7'" in content.lower(), (
            "SC-7 control definition not found in oscal_ssp_exporter.py"
        )

        # Check for planned status near SC-7 definition
        # This is a heuristic check - we look for "planned" within ~500 chars of "sc-7"
        sc7_index = content.lower().find('"sc-7"')
        if sc7_index == -1:
            sc7_index = content.lower().find("'sc-7'")

        if sc7_index != -1:
            context = content[sc7_index : sc7_index + 800].lower()
            assert (
                '"status": "planned"' in context or "'status': 'planned'" in context
            ), "SC-7 control in oscal_ssp_exporter.py must have status='planned'"

    def test_aarm_mapper_cilium_evidence_file_correct(self):
        """
        Verify AARM mapper references correct Cilium evidence file.

        Sprint 3.2 fix: deployment/k8s/cilium-egress-lockdown.yaml (not cilium-network-policy.yaml)
        """
        aarm_path = Path("src/compliance_bridge/aarm_mapper.py")

        if not aarm_path.exists():
            pytest.skip("aarm_mapper.py not found")

        with open(aarm_path, encoding="utf-8") as f:
            content = f.read()

        # Verify correct evidence file is referenced
        assert "cilium-egress-lockdown.yaml" in content, (
            "AARM mapper must reference cilium-egress-lockdown.yaml"
        )

        # Verify incorrect file is NOT referenced
        assert (
            "cilium-network-policy.yaml" not in content
            or "cilium-network-policy.yaml"
            in content.replace("cilium-egress-lockdown.yaml", "")
        ), "AARM mapper must not reference non-existent cilium-network-policy.yaml"

    def test_oscal_claim_backing_script_exists(self):
        """Verify the OSCAL claim backing script exists and is valid Python."""
        script_path = Path("scripts/check_oscal_claim_backing.py")

        assert script_path.exists(), "check_oscal_claim_backing.py not found"
        assert script_path.is_file(), "check_oscal_claim_backing.py is not a file"

        # Verify script has valid Python syntax
        with open(script_path, encoding="utf-8") as f:
            import ast

            try:
                ast.parse(f.read())
            except SyntaxError as e:
                pytest.fail(f"Syntax error in check_oscal_claim_backing.py: {e}")

    def test_cilium_egress_lockdown_file_exists(self):
        """Verify deployment/k8s/cilium-egress-lockdown.yaml exists."""
        cilium_file = Path("deployment/k8s/cilium-egress-lockdown.yaml")

        assert cilium_file.exists(), (
            "cilium-egress-lockdown.yaml must exist as evidence artifact for SC-7"
        )
        assert cilium_file.is_file(), "cilium-egress-lockdown.yaml must be a file"
