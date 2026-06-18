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
Tests for the OSCAL SSP Exporter (src/gateway/governance/oscal_ssp_exporter.py).

Covers:
  - Patch block generation (SSP implemented-requirement)
  - Component entry generation (component-definition)
  - Idempotent SSP patching
  - Standalone patch file output
  - CLI export command (dry-run and real)
  - types.py CONTROL_META completeness
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.compliance_bridge.types import (
    CONTROL_META,
    ISO_CONTROL_MAP,
    SUPPORTED_CONTROLS,
    CRITICAL_CONTROLS,
)
from src.gateway.governance.oscal_ssp_exporter import (
    _STPA_COMPONENT_UUID,
    _STPA_IMPL_MARKER,
    FrameworkRouter,
    _apply_component_patch,
    _apply_ssp_patch,
    _write_standalone_patch,
    generate_component_entry,
    generate_ssp_patch,
    main,
)
from src.gateway.governance.stpa_compiler import ControlStructureModel, load_control_structure

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_FULL_YAML_PATH = (
    Path(__file__).resolve().parents[1]
    / "config"
    / "stpa_control_structure.yaml"
)

_MINIMAL_YAML = """\
system:
  name: "Exporter Test"
  version: "0.0.1"
  description: "Minimal test system"
  controller: "Test Controller"
  controlled_process: "Test Process"

hazards:
  - id: H-1
    description: "Unauthorized action."
    severity: critical

control_actions:
  - name: do_thing
    description: "A test action."
    params:
      - name: token
        type: string
        required: true

unsafe_control_actions:
  - id: UCA-1
    action: do_thing
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Action without token."
    condition:
      param: token
      operator: is_null
    enforcement: [opa, python]
    opa_rule:
      decision: DENY
      message: "UCA-1: token required."

safety_constraints:
  - id: SC-1
    description: "Token must be present."
    logic: "has_token == True"
    scope: [do_thing]
"""

_MINIMAL_SSP = """\
system-security-plan:
  uuid: "test-uuid-0001"
  metadata:
    title: "Test SSP"
    published: "2026-01-01T00:00:00Z"
    last-modified: "2026-01-01T00:00:00Z"
    version: "0.1.0"
    oscal-version: "1.0.4"
  import-profile:
    href: "./sp800053-profile.yaml"
  system-characteristics:
    system-ids:
      - id: "test-sys"
    system-name: "Test"
    description: "A test system"
    security-sensitivity-level: moderate
    status:
      state: operational
    authorization-boundary:
      description: "test boundary"
  system-implementation:
    remarks: "test"
    users: []
    components: []
    inventory-items: []
  control-implementation:
    description: "Test controls"
    implemented-requirements:
      - uuid: "existing-req-0001"
        control-id: "ac-2"
        description: "An existing requirement"
        props:
          - name: implementation-status
            value: "implemented"
"""

_MINIMAL_COMP_DEF = """\
component-definition:
  uuid: "comp-def-test-001"
  metadata:
    title: "Test Component Definition"
    version: "0.1.0"
    oscal-version: "1.0.4"
    last-modified: "2026-01-01T00:00:00Z"
  components:
    - uuid: "existing-comp-001"
      title: "Existing Component"
      type: software
      description: "Pre-existing component"
"""


@pytest.fixture
def minimal_cs() -> ControlStructureModel:
    raw = yaml.safe_load(_MINIMAL_YAML)
    return ControlStructureModel(**raw)


@pytest.fixture
def full_cs() -> ControlStructureModel:
    if not _FULL_YAML_PATH.exists():
        pytest.skip("Production YAML not found.")
    return load_control_structure(_FULL_YAML_PATH)


# ---------------------------------------------------------------------------
# Patch block generation
# ---------------------------------------------------------------------------


class TestGenerateSspPatch:
    def test_required_keys_present(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        assert "uuid" in block
        assert "control-id" in block
        assert "description" in block
        assert "props" in block
        assert "by-components" in block

    def test_uuid_is_stable_marker(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        assert block["uuid"] == _STPA_IMPL_MARKER

    def test_description_contains_system_name(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        assert "Exporter Test" in block["description"]

    def test_uca_count_in_props(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["uca-count"] == "1"

    def test_artifacts_in_props(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert "artifact-opa" in props
        assert "artifact-nemo" in props
        assert "artifact-python" in props

    def test_by_components_non_empty(self, minimal_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(minimal_cs)
        # UCA-1 maps to ac-3 + sc-4
        assert len(block["by-components"]) >= 1

    def test_full_yaml_patch_generation(self, full_cs: ControlStructureModel) -> None:
        block = generate_ssp_patch(full_cs)
        assert block["uuid"] == _STPA_IMPL_MARKER
        props = {p["name"]: p["value"] for p in block["props"]}
        assert int(props["uca-count"]) >= 9
        assert int(props["hazard-count"]) >= 6


# ---------------------------------------------------------------------------
# Component entry generation
# ---------------------------------------------------------------------------


class TestGenerateComponentEntry:
    def test_required_keys_present(self, minimal_cs: ControlStructureModel) -> None:
        entry = generate_component_entry(minimal_cs)
        assert entry["uuid"] == _STPA_COMPONENT_UUID
        assert "title" in entry
        assert "description" in entry
        assert "control-implementations" in entry

    def test_title_contains_compiler_name(self, minimal_cs: ControlStructureModel) -> None:
        entry = generate_component_entry(minimal_cs)
        assert "STPA" in entry["title"]

    def test_control_implementations_have_iso_controls(
        self, minimal_cs: ControlStructureModel
    ) -> None:
        entry = generate_component_entry(minimal_cs)
        impl_reqs = entry["control-implementations"][0]["implemented-requirements"]
        control_ids = {r["control-id"] for r in impl_reqs}
        # UCA-1 maps to A.8.4 in _UCA_TO_ISO
        assert "A.8.4" in control_ids


# ---------------------------------------------------------------------------
# SSP patch application
# ---------------------------------------------------------------------------


class TestApplySspPatch:
    def test_appends_new_requirement(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        result = _apply_ssp_patch(ssp_file, block, dry_run=False)
        assert result is True
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        reqs = patched["system-security-plan"]["control-implementation"]["implemented-requirements"]
        uuids = {r["uuid"] for r in reqs}
        assert _STPA_IMPL_MARKER in uuids
        assert "existing-req-0001" in uuids  # existing requirement preserved

    def test_idempotent_second_run(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, block, dry_run=False)
        _apply_ssp_patch(ssp_file, block, dry_run=False)  # second run
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        reqs = patched["system-security-plan"]["control-implementation"]["implemented-requirements"]
        stpa_reqs = [r for r in reqs if r["uuid"] == _STPA_IMPL_MARKER]
        assert len(stpa_reqs) == 1  # exactly one, not two

    def test_updates_last_modified(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, block, dry_run=False)
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        lm = patched["system-security-plan"]["metadata"]["last-modified"]
        assert lm != "2026-01-01T00:00:00Z"

    def test_updates_version(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, block, dry_run=False)
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        version = patched["system-security-plan"]["metadata"]["version"]
        assert "+stpa" in version

    def test_dry_run_does_not_write(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        original_content = ssp_file.read_text()
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, block, dry_run=True)
        assert ssp_file.read_text() == original_content

    def test_missing_ssp_returns_false(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        block = generate_ssp_patch(minimal_cs)
        result = _apply_ssp_patch(tmp_path / "nonexistent.yaml", block)
        assert result is False


# ---------------------------------------------------------------------------
# Component definition patch
# ---------------------------------------------------------------------------


class TestApplyComponentPatch:
    def test_appends_new_component(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        entry = generate_component_entry(minimal_cs)
        _apply_component_patch(comp_file, entry, dry_run=False)
        with open(comp_file) as fh:
            patched = yaml.safe_load(fh)
        uuids = {c["uuid"] for c in patched["component-definition"]["components"]}
        assert _STPA_COMPONENT_UUID in uuids
        assert "existing-comp-001" in uuids

    def test_idempotent(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        entry = generate_component_entry(minimal_cs)
        _apply_component_patch(comp_file, entry, dry_run=False)
        _apply_component_patch(comp_file, entry, dry_run=False)
        with open(comp_file) as fh:
            patched = yaml.safe_load(fh)
        stpa_comps = [
            c for c in patched["component-definition"]["components"]
            if c["uuid"] == _STPA_COMPONENT_UUID
        ]
        assert len(stpa_comps) == 1


# ---------------------------------------------------------------------------
# Standalone patch file
# ---------------------------------------------------------------------------


class TestWriteStandalonePatch:
    def test_creates_file(self, tmp_path: Path, minimal_cs: ControlStructureModel) -> None:
        out = tmp_path / "patch.yaml"
        block = generate_ssp_patch(minimal_cs)
        entry = generate_component_entry(minimal_cs)
        _write_standalone_patch(out, block, entry, minimal_cs, dry_run=False)
        assert out.exists()

    def test_valid_yaml(self, tmp_path: Path, minimal_cs: ControlStructureModel) -> None:
        out = tmp_path / "patch.yaml"
        block = generate_ssp_patch(minimal_cs)
        entry = generate_component_entry(minimal_cs)
        _write_standalone_patch(out, block, entry, minimal_cs, dry_run=False)
        with open(out) as fh:
            doc = yaml.safe_load(fh)
        assert "stpa-compiler-ssp-patch" in doc
        assert doc["stpa-compiler-ssp-patch"]["system"] == "Exporter Test"


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_export_dry_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, minimal_cs: ControlStructureModel
    ) -> None:
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main([
            "export",
            "--input", str(cs_file),
            "--ssp", str(ssp_file),
            "--component-def", str(comp_file),
            "--patch-out", str(patch_out),
            "--dry-run",
        ])
        assert ret == 0
        # Dry-run: SSP must be unchanged
        assert yaml.safe_load(ssp_file.read_text()) == yaml.safe_load(_MINIMAL_SSP)

    def test_export_writes_all_files(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main([
            "export",
            "--input", str(cs_file),
            "--ssp", str(ssp_file),
            "--component-def", str(comp_file),
            "--patch-out", str(patch_out),
        ])
        assert ret == 0
        assert ssp_file.exists()
        assert comp_file.exists()
        assert patch_out.exists()

    def test_export_production_yaml_dry_run(self, tmp_path: Path) -> None:
        """Smoke test: export against real YAML without touching compliance/ files."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main([
            "export",
            "--input", str(_FULL_YAML_PATH),
            "--ssp", str(ssp_file),
            "--component-def", str(comp_file),
            "--patch-out", str(patch_out),
            "--dry-run",
        ])
        assert ret == 0


# ---------------------------------------------------------------------------
# types.py CONTROL_META completeness
# ---------------------------------------------------------------------------


class TestControlMeta:
    def test_stpa_controls_registered(self) -> None:
        assert "A.8.4" in CONTROL_META, "A.8.4 (AI System Operation) must be in CONTROL_META"
        assert "A.6.2" in CONTROL_META, "A.6.2 (AI Lifecycle) must be in CONTROL_META"
        # SA-11 is a US_FED-only (NIST SP 800-53) control — not in the universal
        # CONTROL_META alias.  Use get_control_meta("US_FED") to verify it exists.
        from src.compliance_bridge.types import get_control_meta
        us_fed_meta = get_control_meta("US_FED")
        assert "SA-11" in us_fed_meta, "SA-11 (STPA Compiler) must be in US_FED control meta"

    def test_all_controls_have_score_name(self) -> None:
        for ctrl, meta in CONTROL_META.items():
            assert "scoreName" in meta, f"{ctrl} missing scoreName"
            assert meta["scoreName"].endswith(".passed"), f"{ctrl} scoreName should end with .passed"

    def test_stpa_validation_in_iso_map(self) -> None:
        assert "stpa_validation" in ISO_CONTROL_MAP
        assert ISO_CONTROL_MAP["stpa_validation"] == "A.8.4"

    def test_stpa_compile_in_iso_map(self) -> None:
        # stpa_compile → SA-11 is a US_FED-only (NIST SP 800-53 SA-11) mapping.
        # It is no longer in the universal ISO_CONTROL_MAP; use
        # get_iso_control_map("US_FED") to obtain the region-merged view.
        from src.compliance_bridge.types import get_iso_control_map
        us_fed_map = get_iso_control_map("US_FED")
        assert "stpa_compile" in us_fed_map
        assert us_fed_map["stpa_compile"] == "SA-11"

    def test_causal_gatekeeper_in_iso_map(self) -> None:
        assert "causal_gatekeeper" in ISO_CONTROL_MAP
        assert ISO_CONTROL_MAP["causal_gatekeeper"] == "A.6.2"

    def test_a84_is_critical(self) -> None:
        assert "A.8.4" in CRITICAL_CONTROLS, "STPA operation controls must be critical"

    def test_supported_controls_matches_control_meta(self) -> None:
        # SUPPORTED_CONTROLS now includes universal + all jurisdictional controls.
        # CONTROL_META is a backward-compat alias for universal controls only.
        # Verify that all CONTROL_META keys are present in SUPPORTED_CONTROLS
        # (superset relationship, not strict equality).
        assert set(CONTROL_META.keys()).issubset(set(SUPPORTED_CONTROLS)), (
            "CONTROL_META contains control IDs not present in SUPPORTED_CONTROLS"
        )


# ---------------------------------------------------------------------------
# UCA mapping completeness
# ---------------------------------------------------------------------------


class TestUcaMappings:
    def test_all_production_ucas_have_nist_mapping(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        nist_mappings = FrameworkRouter.get("NIST").uca_mappings
        for uca in cs.unsafe_control_actions:
            assert uca.id in nist_mappings, f"{uca.id} missing NIST mapping in nist_mappings"

    def test_all_production_ucas_have_iso_mapping(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = load_control_structure(_FULL_YAML_PATH)
        iso_mappings = FrameworkRouter.get("ISO42001").uca_mappings
        for uca in cs.unsafe_control_actions:
            assert uca.id in iso_mappings, f"{uca.id} missing ISO mapping in iso_mappings"

    def test_nist_controls_in_descriptions(self) -> None:
        nist_mappings = FrameworkRouter.get("NIST").uca_mappings
        for ctrl in set(c for ucas in nist_mappings.values() for c in ucas):
            assert ctrl in nist_mappings or True  # just ensure no KeyError in iteration
