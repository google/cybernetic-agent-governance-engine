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

"""
OSCAL Claim Backing Validator (Sprint 3.4)

Asserts that every security control marked "implemented" in the OSCAL SSP
has a corresponding evidence artifact (config file, test, or deployment manifest).

Prevents SC-7/SI-4 class defects where controls are asserted but not operational.

Exit codes:
  0 - All implemented controls have backing evidence
  1 - One or more controls lack evidence
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


def load_oscal_ssp(path: Path) -> dict | None:
    """Load OSCAL SSP YAML.

    Returns:
        dict: OSCAL SSP content or None if file not found
    """
    if not path.exists():
        return None

    with open(path) as f:
        return yaml.safe_load(f)


def check_control_evidence(control_id: str, status: str, remarks: str) -> bool:
    """
    Verify control has backing evidence.

    Args:
        control_id: NIST SP 800-53 control ID (e.g., "SC-7", "IA-3")
        status: Control implementation status
        remarks: Control narrative/remarks

    Returns:
        True if evidence exists, False otherwise.
    """
    if status != "implemented":
        # Only check implemented controls
        return True

    # Evidence patterns to check
    control_slug = control_id.lower().replace("-", "_")
    evidence_patterns = [
        f"deployment/k8s/*{control_slug}*.yaml",
        f"deployment/k8s/*{control_id.lower()}*.yaml",
        f"compliance/lula/lula-validation-{control_id.lower()}.yaml",
        f"compliance/lula/lula-validation-{control_slug}.yaml",
        f"tests/test_{control_slug}_*.py",
        f"tests/test_*{control_slug}*.py",
        f"config/opa/*{control_slug}*.rego",
        f"config/opa/*{control_id.lower()}*.rego",
    ]

    for pattern in evidence_patterns:
        matches = list(Path(".").glob(pattern))
        if matches:
            print(f"✓ {control_id}: Evidence found at {matches[0]}")
            return True

    print(f"✗ {control_id}: No evidence found (status: {status})")
    return False


def main() -> int:
    """Main entry point."""
    ssp_path = Path("compliance/oscal/system-security-plan.yaml")

    if not ssp_path.exists():
        print(f"Error: SSP not found at {ssp_path}")
        sys.exit(1)

    ssp = load_oscal_ssp(ssp_path)
    if not ssp:
        print(f"Error: Failed to parse SSP at {ssp_path}")
        sys.exit(1)

    # Extract controls from SSP
    # OSCAL SSP structure: system-security-plan.control-implementation.implemented-requirements
    try:
        controls = (
            ssp.get("system-security-plan", {})
            .get("control-implementation", {})
            .get("implemented-requirements", [])
        )
    except (AttributeError, TypeError):
        print("Error: SSP structure invalid (missing control-implementation)")
        sys.exit(1)

    if not controls:
        print("Warning: No controls found in SSP")
        sys.exit(0)

    failed: list[str] = []
    checked_count = 0

    for control in controls:
        control_id = control.get("control-id")
        if not control_id:
            continue

        # Check for status in multiple possible locations
        status = "planned"  # default

        # Try implementation-status.state first (OSCAL 1.0)
        impl_status = control.get("implementation-status", {})
        if isinstance(impl_status, dict):
            status = impl_status.get("state", "planned")

        # Fall back to direct status field (custom extension)
        if "status" in control:
            status = control.get("status", "planned")

        remarks = control.get("remarks", "")

        checked_count += 1
        if not check_control_evidence(control_id, status, remarks):
            failed.append(control_id)

    if failed:
        print(f"\n❌ {len(failed)} controls lack evidence:")
        for control_id in failed:
            print(f"   - {control_id}")
        print("\nEither:")
        print("  1. Add evidence artifact (deployment manifest, test, Lula validation)")
        print("  2. Change status from 'implemented' → 'planned' in SSP")
        print("\nSee AGENTS.md §Compliance Artifact Obligations for details.")
        sys.exit(1)

    print(f"\n✅ All {checked_count} controls have backing evidence")
    sys.exit(0)


if __name__ == "__main__":
    main()
