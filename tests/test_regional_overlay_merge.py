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

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.gateway.governance import constants
from src.gateway.governance.constants import (
    ControlOverlayCollisionError,
    ControlRegistry,
    GovernanceControl,
)

pytestmark = [pytest.mark.local, pytest.mark.unit]


@pytest.mark.parametrize("region", ["US_FED", "EU_ECB", "APAC_MAS"])
def test_regional_overlay_merge_hash(region: str):
    """Verify ControlRegistry loads deterministically across all three regions."""
    ControlRegistry.reconfigure(region)
    registry = ControlRegistry()

    assert len(registry.active_hash) == 64, (
        f"Expected SHA256 hash (64 chars), got {len(registry.active_hash)} chars"
    )
    assert all(c in "0123456789abcdef" for c in registry.active_hash), (
        f"Hash contains non-hex characters: {registry.active_hash}"
    )

    mapping = registry.get_mapping(GovernanceControl.AGENT_CONFIDENCE_THRESHOLD)
    assert mapping is not None
    assert "primary_framework" in mapping

    first_hash = registry.active_hash
    ControlRegistry.reconfigure(region)
    registry_second = ControlRegistry()
    assert registry_second.active_hash == first_hash, (
        f"Hash not deterministic for {region}: {first_hash} != {registry_second.active_hash}"
    )


def test_overlay_collision_on_kernel_control_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Undeclared plugin overlay redefinition of a kernel control fails closed (POAM-2026-123)."""
    overlay_dir = tmp_path / "colliding_plugin"
    overlay_dir.mkdir()
    (overlay_dir / "US_FED_OVERLAY.json").write_text(
        json.dumps(
            {
                "CTRL_FTRA_001": {
                    "internal_id": "THR-FTRA-OVERRIDE",
                    "primary_framework": "OVERWRITTEN",
                    "co_frameworks": [],
                    "legacy_citation": "OVERWRITTEN",
                    "scope": "agentic",
                    "description": "Unauthorized override",
                }
            }
        )
    )

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [overlay_dir])
    ControlRegistry.reset_for_testing()
    try:
        with pytest.raises(ControlOverlayCollisionError, match="CTRL_FTRA_001"):
            ControlRegistry.reconfigure("US_FED")
    finally:
        ControlRegistry.reset_for_testing()


def test_overlay_collision_between_plugins_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Later plugin redefining an earlier plugin's control fails closed."""
    plugin_a = tmp_path / "plugin_a"
    plugin_b = tmp_path / "plugin_b"
    plugin_a.mkdir()
    plugin_b.mkdir()
    entry = {
        "CTRL_CUSTOM_001": {
            "internal_id": "THR-CUSTOM-001",
            "primary_framework": "Custom Standard",
            "co_frameworks": [],
            "legacy_citation": "Custom Standard",
            "scope": "agentic",
            "description": "Custom control",
        }
    }
    (plugin_a / "US_FED_OVERLAY.json").write_text(json.dumps(entry))
    (plugin_b / "US_FED_OVERLAY.json").write_text(json.dumps(entry))

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [plugin_a, plugin_b])
    ControlRegistry.reset_for_testing()
    try:
        with pytest.raises(ControlOverlayCollisionError, match="CTRL_CUSTOM_001"):
            ControlRegistry.reconfigure("US_FED")
    finally:
        ControlRegistry.reset_for_testing()


def test_overlay_cannot_overwrite_kernel_meta_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Plugin overlays cannot alter kernel metadata blocks such as '_hitl'."""
    overlay_dir = tmp_path / "meta_override"
    overlay_dir.mkdir()
    (overlay_dir / "US_FED_OVERLAY.json").write_text(
        json.dumps({"_hitl": {"sla_hours": 999.0}})
    )

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [overlay_dir])
    ControlRegistry.reset_for_testing()
    try:
        with pytest.raises(ControlOverlayCollisionError, match="_hitl"):
            ControlRegistry.reconfigure("US_FED")
    finally:
        ControlRegistry.reset_for_testing()


def test_declared_extension_cannot_overwrite_protected_or_assessment_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Even a declared extension cannot inject CTRL_FRIA_006.assessments or replace primary_framework."""
    overlay_dir = tmp_path / "fria_spoof"
    overlay_dir.mkdir()
    (overlay_dir / "EU_ECB_OVERLAY.json").write_text(
        json.dumps(
            {
                "_declared_extensions": ["CTRL_FRIA_006"],
                "CTRL_FRIA_006": {
                    "assessments": [{"assessed_at": "2099-01-01T00:00:00Z"}]
                },
            }
        )
    )

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [overlay_dir])
    ControlRegistry.reset_for_testing()
    try:
        with pytest.raises(ControlOverlayCollisionError, match="assessments"):
            ControlRegistry.reconfigure("EU_ECB")
    finally:
        ControlRegistry.reset_for_testing()


def test_declared_extension_is_applied_and_recorded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Explicit additive extensions merge cleanly, preserve kernel fields, and record provenance."""
    ControlRegistry.reconfigure("US_FED")
    baseline_hash = ControlRegistry().active_hash

    overlay_dir = tmp_path / "declared_ext"
    overlay_dir.mkdir()
    (overlay_dir / "US_FED_OVERLAY.json").write_text(
        json.dumps(
            {
                "_declared_extensions": ["CTRL_FTRA_001"],
                "CTRL_FTRA_001": {
                    "co_frameworks": ["SR 26-2 §IV.B - Pre-Trade Risk Controls"],
                    "domain_extensions": {"finance_note": "Required for execute_trade"},
                },
            }
        )
    )

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [overlay_dir])
    ControlRegistry.reset_for_testing()
    try:
        with caplog.at_level(logging.INFO, logger="Gateway.Governance.Constants"):
            ControlRegistry.reconfigure("US_FED")
            reg = ControlRegistry()
            ftra = reg.get_mapping(GovernanceControl.FTRA_REACHABILITY_GATE)
            assert ftra["internal_id"] == "CTRL_FTRA_001"
            assert ftra["primary_framework"] == "ISO 42001 A.8.4"
            assert "SR 26-2 §IV.B - Pre-Trade Risk Controls" in ftra["co_frameworks"]
            assert ftra["domain_extensions"] == {
                "finance_note": "Required for execute_trade"
            }
            assert len(reg.declared_extensions) == 1
            assert reg.declared_extensions[0]["control_id"] == "CTRL_FTRA_001"
            assert reg.active_hash != baseline_hash
            assert any("CTRL_FTRA_001" in rec.message for rec in caplog.records)
    finally:
        ControlRegistry.reset_for_testing()


@pytest.mark.parametrize("region", ["US_FED", "EU_ECB", "APAC_MAS"])
def test_real_plugin_overlays_compose_across_all_regions_without_collision(
    monkeypatch: pytest.MonkeyPatch, region: str
) -> None:
    """All shipped domain plugin overlays load together across every region with zero collisions."""
    from src.cage_finance.plugin import FinanceCagePlugin
    from src.cage_healthcare.plugin import HealthcareCagePlugin
    from src.cage_physical_ai.plugin import PhysicalAICagePlugin

    overlay_dirs = [
        d
        for plugin_cls in (
            FinanceCagePlugin,
            HealthcareCagePlugin,
            PhysicalAICagePlugin,
        )
        for d in plugin_cls().contribute().compliance_overlay_dirs
    ]
    monkeypatch.setattr(constants, "_OVERLAY_DIRS", list(overlay_dirs))
    ControlRegistry.reset_for_testing()
    try:
        ControlRegistry.reconfigure(region)
        reg = ControlRegistry()
        ftra = reg.get_mapping(GovernanceControl.FTRA_REACHABILITY_GATE)
        assert ftra["internal_id"] == "CTRL_FTRA_001"
        assert ftra["primary_framework"] == "ISO 42001 A.8.4"
        assert reg.declared_extensions == ()
    finally:
        ControlRegistry.reset_for_testing()


def test_validation_report_withdrawal_and_regional_posture_triggers() -> None:
    """POAM-2026-121: Report withdraws independent-composition claims, drops stale hashes, and workflow watches plugin overlays."""
    import yaml

    repo_root = Path(__file__).resolve().parents[1]
    report = (
        repo_root / "docs" / "compliance" / "REGIONAL_POSTURE_VALIDATION_REPORT.md"
    ).read_text(encoding="utf-8")
    assert "POAM-2026-121" in report
    assert "§3 Independence Claim Withdrawn" in report
    assert "489f444aca7b" not in report
    assert "6dbefdbbb607" not in report
    assert "cage_iso42001.json" not in report
    assert "config/oscal/framework_mappings/ISO_42001.json" in report
    assert "compliance/oscal/component-definition.yaml" in report

    workflow = yaml.safe_load(
        (repo_root / ".github" / "workflows" / "regional-posture.yml").read_text(
            encoding="utf-8"
        )
    )
    on_block = workflow.get("on") or workflow.get(True)
    push_paths = set(on_block["push"]["paths"])
    assert "src/cage_*/config/compliance/**" in push_paths
    assert "src/cage_*/config/thresholds/**" in push_paths
    for job in workflow["jobs"].values():
        assert job.get("continue-on-error") is not True
        for step in job.get("steps", []):
            assert step.get("continue-on-error") is not True
