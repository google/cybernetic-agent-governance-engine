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

"""Kernel controls resolve from the kernel baselines, in every domain.

Layer 1 code that resolves a control with the strict
``ControlRegistry.get_mapping(GovernanceControl.X)`` raises ``KeyError`` when
the active profile lacks it. A control the kernel cites must therefore live in
every ``config/compliance/<REGION>_BASELINE.json``, not in a domain overlay:
otherwise a domain that does not ship the overlay (healthcare did not ship
``CTRL_MRM_004``) turns a CBF rejection into an exception. The finance
session fixture in ``tests/conftest.py`` registers the finance overlays, so
the second test isolates the registry to the healthcare overlay alone.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from src.gateway.governance import constants
from src.gateway.governance.constants import (
    SUPPORTED_REGIONS,
    ControlRegistry,
    GovernanceControl,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]
_KERNEL = _REPO / "src" / "gateway"
_BASELINES = _REPO / "config" / "compliance"
_HEALTHCARE_OVERLAYS = _REPO / "src" / "cage_healthcare" / "config" / "compliance"


def _strictly_resolved_kernel_controls() -> set[GovernanceControl]:
    """Every ``get_mapping(GovernanceControl.X)`` call site under src/gateway/."""
    found: set[GovernanceControl] = set()
    for path in _KERNEL.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get_mapping"
                and node.args
            ):
                continue
            arg = node.args[0]
            if (
                isinstance(arg, ast.Attribute)
                and isinstance(arg.value, ast.Name)
                and arg.value.id == "GovernanceControl"
            ):
                found.add(GovernanceControl[arg.attr])
    return found


def test_scan_finds_the_cbf_control() -> None:
    # Guards the scanner itself: an AST shape change must not empty the set.
    assert (
        GovernanceControl.TRADITIONAL_MRM_VALIDATION
        in _strictly_resolved_kernel_controls()
    )


@pytest.mark.parametrize("region", sorted(SUPPORTED_REGIONS))
def test_every_strict_kernel_control_is_in_the_baseline(region: str) -> None:
    baseline = json.loads((_BASELINES / f"{region}_BASELINE.json").read_text())
    missing = sorted(
        c.value for c in _strictly_resolved_kernel_controls() if c.value not in baseline
    )
    assert not missing, (
        f"{region}_BASELINE.json lacks controls the kernel resolves strictly: {missing}. "
        "Define them in the baseline, or use get_mapping_safe() for region-specific ones."
    )


@pytest.mark.parametrize("region", sorted(SUPPORTED_REGIONS))
def test_kernel_controls_resolve_with_only_the_healthcare_overlay(
    region: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [_HEALTHCARE_OVERLAYS.resolve()])
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    ControlRegistry._drop_loaded_instance()
    try:
        registry = ControlRegistry()
        assert registry.active_region == region
        for control in _strictly_resolved_kernel_controls():
            assert registry.get_mapping(control)["primary_framework"]
    finally:
        # The next test reloads with the session's real overlays and region.
        ControlRegistry._drop_loaded_instance()
