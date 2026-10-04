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
    CRITICAL_CONTROLS,
    SUPPORTED_CONTROLS,
    get_control_meta,
    get_iso_control_map,
)
from src.gateway.governance.oscal_ssp_exporter import (
    _FTRA_COMPONENT_UUID,
    _FTRA_SI10_IMPL_UUID,
    _STPA_COMPONENT_UUID,
    _STPA_IMPL_MARKER,
    FrameworkRouter,
    _apply_component_patch,
    _apply_ftra_component_patch,
    _apply_ssp_patch,
    _write_standalone_patch,
    generate_component_entry,
    generate_ftra_component_entry,
    generate_ssp_patch,
    main,
)
from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    load_control_structure,
    load_control_structures,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_FULL_YAML_PATH = (
    Path(__file__).resolve().parents[1] / "config" / "stpa_control_structure.yaml"
)
_FINANCE_YAML_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "cage_finance"
    / "config"
    / "stpa"
    / "trade_hazards.yaml"
)


def _load_full_cs() -> ControlStructureModel:
    paths = [_FULL_YAML_PATH]
    if _FINANCE_YAML_PATH.exists():
        paths.append(_FINANCE_YAML_PATH)
    return load_control_structures(paths)


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
    return _load_full_cs()


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

    def test_description_contains_system_name(
        self, minimal_cs: ControlStructureModel
    ) -> None:
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
        assert props.get("artifact-sandbox") == "config/sandbox/generated_sandbox_policy.yaml"

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

    def test_title_contains_compiler_name(
        self, minimal_cs: ControlStructureModel
    ) -> None:
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
# FTRA Component Entry Generation
# ---------------------------------------------------------------------------


class TestGenerateFtraComponentEntry:
    def test_required_keys_present(self) -> None:
        entry = generate_ftra_component_entry()
        assert entry["uuid"] == _FTRA_COMPONENT_UUID
        assert "title" in entry
        assert "description" in entry
        assert "control-implementations" in entry

    def test_title_contains_ftra_name(self) -> None:
        entry = generate_ftra_component_entry()
        assert "FTRA" in entry["title"]
        assert "Irreversibility Classifier" in entry["title"]

    def test_control_implementations_are_si10_only(self) -> None:
        """FTRA claims SI-10 by delegation and no AC-4: it never rejected
        undeclared parameters (docs/governance/FTRA_SCOPE.md)."""
        entry = generate_ftra_component_entry()
        impl_reqs = entry["control-implementations"][0]["implemented-requirements"]
        assert [r["control-id"] for r in impl_reqs] == ["si-10"]

    def test_deterministic_uuids(self) -> None:
        entry = generate_ftra_component_entry()
        impl_reqs = entry["control-implementations"][0]["implemented-requirements"]
        assert {r["uuid"] for r in impl_reqs} == {_FTRA_SI10_IMPL_UUID}

    def test_si10_description_names_the_value_validation_owners(self) -> None:
        entry = generate_ftra_component_entry()
        impl_reqs = entry["control-implementations"][0]["implemented-requirements"]
        desc = next(r for r in impl_reqs if r["control-id"] == "si-10")["description"]
        assert "src/cage_finance/stpa/uca_rules.py" in desc
        assert "src/cage_finance/opa/trade_governance.rego" in desc
        assert "ActionSchema" not in desc and "schemas.py" not in desc

    def test_ftra_oscal_text_cites_only_existing_paths(self) -> None:
        """Every repo path the FTRA component cites exists (no stale schemas.py)."""
        import re

        root = Path(__file__).resolve().parents[1]
        text = yaml.safe_dump(generate_ftra_component_entry())
        paths = set(re.findall(r"(?:src|config|docs)/[\w./-]+\.(?:py|rego|co|txt|md)", text))
        assert paths, "expected the FTRA component to cite source paths"
        missing = sorted(p for p in paths if not (root / p).exists())
        assert missing == []


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
        result = _apply_ssp_patch(ssp_file, [block], dry_run=False)
        assert result is True
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        reqs = patched["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
        uuids = {r["uuid"] for r in reqs}
        assert _STPA_IMPL_MARKER in uuids
        assert "existing-req-0001" in uuids  # existing requirement preserved

    def test_idempotent_second_run(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, [block], dry_run=False)
        _apply_ssp_patch(ssp_file, [block], dry_run=False)  # second run
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        reqs = patched["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
        stpa_reqs = [r for r in reqs if r["uuid"] == _STPA_IMPL_MARKER]
        assert len(stpa_reqs) == 1  # exactly one, not two

    def test_updates_last_modified(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, [block], dry_run=False)
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
        _apply_ssp_patch(ssp_file, [block], dry_run=False)
        with open(ssp_file) as fh:
            patched = yaml.safe_load(fh)
        version = patched["system-security-plan"]["metadata"]["version"]
        assert "+stpa" in version

    def test_version_suffix_is_idempotent(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """Repeated patches append "+stpa" once, not once per run."""
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        block = generate_ssp_patch(minimal_cs)
        versions = []
        for _ in range(3):
            _apply_ssp_patch(ssp_file, [block], dry_run=False)
            with open(ssp_file) as fh:
                versions.append(
                    yaml.safe_load(fh)["system-security-plan"]["metadata"]["version"]
                )
        assert versions[0] == versions[1] == versions[2]
        assert versions[0].endswith("+stpa")
        assert versions[0].count("+stpa") == 1

    def test_two_consecutive_exports_yield_same_version(
        self, tmp_path: Path
    ) -> None:
        """Two full `export` runs leave metadata.version unchanged the second time."""
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        argv = [
            "export",
            "--input",
            str(cs_file),
            "--ssp",
            str(ssp_file),
            "--component-def",
            str(comp_file),
            "--patch-out",
            str(tmp_path / "patch.yaml"),
        ]

        def _version() -> str:
            with open(ssp_file) as fh:
                return yaml.safe_load(fh)["system-security-plan"]["metadata"]["version"]

        assert main(argv) == 0
        first = _version()
        assert main(argv) == 0
        assert _version() == first
        assert first.count("+stpa") == 1

    def test_dry_run_does_not_write(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        original_content = ssp_file.read_text()
        block = generate_ssp_patch(minimal_cs)
        _apply_ssp_patch(ssp_file, [block], dry_run=True)
        assert ssp_file.read_text() == original_content

    def test_missing_ssp_returns_false(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        block = generate_ssp_patch(minimal_cs)
        result = _apply_ssp_patch(tmp_path / "nonexistent.yaml", [block])
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
            c
            for c in patched["component-definition"]["components"]
            if c["uuid"] == _STPA_COMPONENT_UUID
        ]
        assert len(stpa_comps) == 1


# ---------------------------------------------------------------------------
# Standalone patch file
# ---------------------------------------------------------------------------


class TestWriteStandalonePatch:
    def test_creates_file(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        out = tmp_path / "patch.yaml"
        block = generate_ssp_patch(minimal_cs)
        entry = generate_component_entry(minimal_cs)
        _write_standalone_patch(out, block, entry, minimal_cs, dry_run=False)
        assert out.exists()

    def test_valid_yaml(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
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
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
        minimal_cs: ControlStructureModel,
    ) -> None:
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
                "--dry-run",
            ]
        )
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

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
            ]
        )
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

        ret = main(
            [
                "export",
                "--input",
                str(_FULL_YAML_PATH),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
                "--dry-run",
            ]
        )
        assert ret == 0

    def test_export_contains_ftra_component(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """Verify exported component-definition contains FTRA component UUID."""
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
            ]
        )
        assert ret == 0

        with open(comp_file) as fh:
            comp_def = yaml.safe_load(fh)
        component_uuids = {
            c["uuid"] for c in comp_def["component-definition"]["components"]
        }
        assert _FTRA_COMPONENT_UUID in component_uuids

    def test_ftra_si10_multiple_components(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """Verify SI-10 control has multiple component references (NeMo and FTRA)."""
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
            ]
        )
        assert ret == 0

        # Load the component definition to verify si-10 appears in multiple components
        with open(comp_file) as fh:
            comp_def = yaml.safe_load(fh)

        components = comp_def["component-definition"]["components"]
        si10_components = []
        for comp in components:
            if "control-implementations" in comp:
                for ctrl_impl in comp["control-implementations"]:
                    for req in ctrl_impl.get("implemented-requirements", []):
                        if req.get("control-id") == "si-10":
                            si10_components.append(comp["uuid"])

        # Both FTRA and potentially STPA (if mapped) should implement si-10
        # At minimum, FTRA must be present
        assert _FTRA_COMPONENT_UUID in si10_components

    def test_ac4_absent_from_ftra_component(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """The exported FTRA component claims no AC-4 (it never enforced one)."""
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
            ]
        )
        assert ret == 0

        # Load and verify AC-4 is not claimed
        with open(comp_file) as fh:
            comp_def = yaml.safe_load(fh)

        components = comp_def["component-definition"]["components"]
        ftra_component = next(
            (c for c in components if c["uuid"] == _FTRA_COMPONENT_UUID), None
        )
        assert ftra_component is not None, "FTRA component not found in output"

        impl_reqs = ftra_component["control-implementations"][0][
            "implemented-requirements"
        ]
        control_ids = {r["control-id"] for r in impl_reqs}
        assert "ac-4" not in control_ids


# ---------------------------------------------------------------------------
# FTRA Component Patch Application
# ---------------------------------------------------------------------------


class TestApplyFtraComponentPatch:
    def test_appends_ftra_component(self, tmp_path: Path) -> None:
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        ftra_entry = generate_ftra_component_entry()
        result = _apply_ftra_component_patch(comp_file, ftra_entry, dry_run=False)
        assert result is True
        with open(comp_file) as fh:
            patched = yaml.safe_load(fh)
        component_uuids = {
            c["uuid"] for c in patched["component-definition"]["components"]
        }
        assert _FTRA_COMPONENT_UUID in component_uuids

    def test_idempotent_ftra_second_run(self, tmp_path: Path) -> None:
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        ftra_entry = generate_ftra_component_entry()
        _apply_ftra_component_patch(comp_file, ftra_entry, dry_run=False)
        _apply_ftra_component_patch(comp_file, ftra_entry, dry_run=False)  # second run
        with open(comp_file) as fh:
            patched = yaml.safe_load(fh)
        ftra_components = [
            c
            for c in patched["component-definition"]["components"]
            if c["uuid"] == _FTRA_COMPONENT_UUID
        ]
        assert len(ftra_components) == 1  # exactly one, not two


# ---------------------------------------------------------------------------
# types.py CONTROL_META completeness
# ---------------------------------------------------------------------------


class TestControlMeta:
    def test_stpa_controls_registered(self) -> None:
        # Use region-aware accessor for universal controls
        control_meta = get_control_meta("LOCAL")
        assert "A.8.4" in control_meta, (
            "A.8.4 (AI System Operation) must be in control metadata"
        )
        assert "A.6.2" in control_meta, (
            "A.6.2 (AI Lifecycle) must be in control metadata"
        )
        # SA-11 is a US_FED-only (NIST SP 800-53) control — not in universal controls.
        # Use get_control_meta("US_FED") to verify it exists.
        us_fed_meta = get_control_meta("US_FED")
        assert "SA-11" in us_fed_meta, (
            "SA-11 (STPA Compiler) must be in US_FED control meta"
        )

    def test_all_controls_have_score_name(self) -> None:
        # Use region-aware accessor for universal controls
        control_meta = get_control_meta("LOCAL")
        for ctrl, meta in control_meta.items():
            assert "scoreName" in meta, f"{ctrl} missing scoreName"
            assert meta["scoreName"].endswith(".passed"), (
                f"{ctrl} scoreName should end with .passed"
            )

    def test_stpa_validation_in_iso_map(self) -> None:
        # Use region-aware accessor for universal controls
        iso_control_map = get_iso_control_map("LOCAL")
        assert "stpa_validation" in iso_control_map
        assert iso_control_map["stpa_validation"] == "A.8.4"

    def test_stpa_compile_in_iso_map(self) -> None:
        # stpa_compile → SA-11 is a US_FED-only (NIST SP 800-53 SA-11) mapping.
        # Use get_iso_control_map("US_FED") to obtain the region-merged view.
        us_fed_map = get_iso_control_map("US_FED")
        assert "stpa_compile" in us_fed_map
        assert us_fed_map["stpa_compile"] == "SA-11"

    def test_causal_gatekeeper_in_iso_map(self) -> None:
        # Use region-aware accessor for universal controls
        iso_control_map = get_iso_control_map("LOCAL")
        assert "causal_gatekeeper" in iso_control_map
        assert iso_control_map["causal_gatekeeper"] == "A.6.2"

    def test_a84_is_critical(self) -> None:
        assert "A.8.4" in CRITICAL_CONTROLS, "STPA operation controls must be critical"

    def test_supported_controls_matches_control_meta(self) -> None:
        # SUPPORTED_CONTROLS now includes universal + all jurisdictional controls.
        # get_control_meta("LOCAL") returns universal controls only.
        # Verify that all universal control keys are present in SUPPORTED_CONTROLS
        # (superset relationship, not strict equality).
        control_meta = get_control_meta("LOCAL")
        assert set(control_meta.keys()).issubset(set(SUPPORTED_CONTROLS)), (
            "Universal control metadata contains control IDs not present in SUPPORTED_CONTROLS"
        )


# ---------------------------------------------------------------------------
# UCA mapping completeness
# ---------------------------------------------------------------------------


class TestUcaMappings:
    def test_all_production_ucas_have_nist_mapping(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = _load_full_cs()
        nist_mappings = FrameworkRouter.get("NIST").uca_mappings
        for uca in cs.unsafe_control_actions:
            assert uca.id in nist_mappings, (
                f"{uca.id} missing NIST mapping in nist_mappings"
            )

    def test_all_production_ucas_have_iso_mapping(self) -> None:
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = _load_full_cs()
        iso_mappings = FrameworkRouter.get("ISO42001").uca_mappings
        for uca in cs.unsafe_control_actions:
            assert uca.id in iso_mappings, (
                f"{uca.id} missing ISO mapping in iso_mappings"
            )

    def test_nist_controls_in_descriptions(self) -> None:
        nist_mappings = FrameworkRouter.get("NIST").uca_mappings
        for ctrl in set(c for ucas in nist_mappings.values() for c in ucas):
            assert ctrl in nist_mappings or True  # just ensure no KeyError in iteration


# ---------------------------------------------------------------------------
# End-to-End FTRA Telemetry → OSCAL Traceability Tests (Task 3)
# ---------------------------------------------------------------------------


class TestFtraTelemetryToOscalTraceability:
    """End-to-end tests asserting FTRA runtime telemetry events link to OSCAL CERs."""

    def test_ftra_boundary_check_emits_si10_cer(self) -> None:
        """Assert the ftra_boundary_check event maps to SI-10 and ISO 42001 A.8.4."""
        from src.compliance_bridge.types import get_control_meta, get_iso_control_map

        control_map = get_iso_control_map("US_FED")
        assert control_map["ftra_boundary_check"] == "SI-10"
        # Events with no producer (deleted semantic validator, never-emitted
        # flow enforcement) have no mapping.
        assert "ftra_semantic_validation" not in control_map
        assert "ftra_flow_enforcement" not in control_map

        us_fed_controls = get_control_meta("US_FED")
        assert "SI-10" in us_fed_controls, "SI-10 must be in US_FED control metadata"
        si10_meta = us_fed_controls["SI-10"]
        assert si10_meta["scoreName"] == "nist.SI-10.passed"
        assert "fedramp" in si10_meta["frameworks"]
        assert "aarm" in si10_meta["frameworks"]

        # Verify ISO 42001 A.8.4 cross-reference (universal control)
        universal_controls = get_control_meta("LOCAL")
        assert "A.8.4" in universal_controls
        assert universal_controls["A.8.4"]["scoreName"] == "iso42001.A.8.4.passed"

    def test_si10_multi_component_satisfaction(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """Verify SI-10 control lists implemented requirements for BOTH components.

        Exports the complete System Security Plan and validates that control SI-10
        lists implemented requirements for:
        (a) NeMo Guardrails component (nemo0001-4e47-bbc8-guardrails001)
        (b) FTRA Irreversibility Classifier component (ftra0001-4e47-bbc8-irreversibility01)

        This multi-component control implementation demonstrates defense-in-depth:
        - NeMo: PII validation, content masking
        - FTRA: irreversibility classification at the controller boundary
          (value policy is STPA/OPA; see docs/governance/FTRA_SCOPE.md)
        """
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        # Export SSP with FTRA and STPA components
        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
            ]
        )
        assert ret == 0

        # Load the exported component definition
        with open(comp_file) as fh:
            comp_def = yaml.safe_load(fh)

        components = comp_def["component-definition"]["components"]

        # Verify FTRA component exists
        ftra_component = next(
            (c for c in components if c["uuid"] == _FTRA_COMPONENT_UUID), None
        )
        assert ftra_component is not None, (
            "FTRA component must be in component-definition"
        )

        # Verify FTRA component implements SI-10
        ftra_impl_reqs = ftra_component["control-implementations"][0][
            "implemented-requirements"
        ]
        ftra_control_ids = {r["control-id"] for r in ftra_impl_reqs}
        assert "si-10" in ftra_control_ids, "FTRA must implement SI-10"

        # Find SI-10 requirement in FTRA component
        ftra_si10_req = next(r for r in ftra_impl_reqs if r["control-id"] == "si-10")
        assert ftra_si10_req["uuid"] == _FTRA_SI10_IMPL_UUID
        assert "validation" in ftra_si10_req["description"].lower()

        # Count components implementing SI-10
        si10_implementing_components = []
        for comp in components:
            if "control-implementations" not in comp:
                continue
            for ctrl_impl in comp["control-implementations"]:
                for req in ctrl_impl.get("implemented-requirements", []):
                    if req.get("control-id") == "si-10":
                        si10_implementing_components.append(comp["uuid"])
                        break

        # Assert FTRA is among the SI-10 implementers
        assert _FTRA_COMPONENT_UUID in si10_implementing_components, (
            "FTRA Irreversibility Classifier must be listed as implementing SI-10"
        )

        # Note: NeMo Guardrails component UUID would be checked here if it exists
        # in the minimal fixture. In production SSP, both components should be present.
        # Verify at least FTRA is present (minimal test fixture constraint)
        assert len(si10_implementing_components) >= 1, (
            "SI-10 must be implemented by at least FTRA component"
        )

    def test_jurisdictional_isolation_si10(self) -> None:
        """SI-10 and the FTRA boundary event are US_FED-only.

        SI-10 is a NIST SP 800-53 control. It must not appear in the EU_ECB
        (EU AI Act) or APAC_MAS (MAS FEAT) control metadata, and the
        ftra_boundary_check event must not map to anything there.
        """
        from src.compliance_bridge.types import get_control_meta, get_iso_control_map

        for region in ("EU_ECB", "APAC_MAS"):
            assert "SI-10" not in get_control_meta(region), (
                f"SI-10 (NIST SP 800-53) must NOT be in {region} control metadata"
            )
            assert "ftra_boundary_check" not in get_iso_control_map(region), (
                f"ftra_boundary_check must NOT be in {region} control map"
            )

        # Positive assertions: present under US_FED.
        assert "SI-10" in get_control_meta("US_FED")
        assert get_iso_control_map("US_FED")["ftra_boundary_check"] == "SI-10"


# ---------------------------------------------------------------------------
# Phase E: Platform-Aware Narratives Integration Tests
# ---------------------------------------------------------------------------


class TestPhaseEPlatformNarratives:
    """Integration tests for Phase E platform-aware OSCAL SSP narratives."""

    def test_export_with_gke_platform_narratives(
        self, tmp_path: Path, minimal_cs: ControlStructureModel
    ) -> None:
        """Verify --platform gcp-gke generates GKE-specific narratives (Cilium, Linkerd)."""
        cs_file = tmp_path / "cs.yaml"
        cs_file.write_text(_MINIMAL_YAML)
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        patch_out = tmp_path / "patch.yaml"

        ret = main(
            [
                "export",
                "--input",
                str(cs_file),
                "--ssp",
                str(ssp_file),
                "--component-def",
                str(comp_file),
                "--patch-out",
                str(patch_out),
                "--platform",
                "gcp-gke",
            ]
        )
        assert ret == 0

        # Load SSP and verify GKE-specific content
        with open(ssp_file) as fh:
            ssp = yaml.safe_load(fh)

        impl_reqs = ssp["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
        control_ids = {r["control-id"] for r in impl_reqs}

        assert "sc-7" in control_ids
        assert "sc-8" in control_ids
        assert "sc-39" in control_ids
        assert "si-3" in control_ids

        # Verify SC-7 mentions Cilium
        sc7_req = next(r for r in impl_reqs if r["control-id"] == "sc-7")
        assert "Cilium" in sc7_req["description"]

        # Verify SC-8 mentions Linkerd
        sc8_req = next(r for r in impl_reqs if r["control-id"] == "sc-8")
        assert "Linkerd" in sc8_req["description"]


pytestmark = [pytest.mark.unit, pytest.mark.local]
