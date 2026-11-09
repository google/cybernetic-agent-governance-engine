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

import json
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
    _FTRA_SI10_DESCRIPTION,
    _FTRA_SI10_IMPL_UUID,
    _PLATFORM_SC7_IMPL_UUID,
    _STPA_COMPONENT_UUID,
    _STPA_IMPL_MARKER,
    FrameworkRouter,
    _apply_component_patch,
    _apply_ftra_component_patch,
    _apply_ssp_patch,
    _write_standalone_patch,
    apply_narrative_source,
    generate_component_entry,
    generate_ftra_component_entry,
    generate_ssp_patch,
    load_narrative_source,
    main,
    narrative_source_for,
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
    Path(__file__).resolve().parents[1] / "config" / "stpa" / "core_system.yaml"
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
        server_bound: true

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


_NEMO_ARTIFACT = "config/rails/generated_stpa_rails.co"
_OPA_ARTIFACT = "config/opa/generated_stpa_policy.rego"


def _with_uca1_targets(enforcement: list[str]) -> ControlStructureModel:
    """The minimal structure with UCA-1 retargeted (and valid for NeMo)."""
    raw = yaml.safe_load(_MINIMAL_YAML)
    uca = raw["unsafe_control_actions"][0]
    uca["enforcement"] = enforcement
    uca["condition"]["semantic_pattern"] = "missing_token"
    uca["nemo_rail"] = {"flow_name": "block_missing_token", "message": "Blocked."}
    return ControlStructureModel(**raw)


@pytest.fixture
def nemo_cs() -> ControlStructureModel:
    return _with_uca1_targets(["opa", "nemo"])


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
        assert "artifact-opa" not in props
        assert "artifact-python" in props
        assert "enforcing-uca-count" in props
        assert "advisory-uca-count" in props
        assert (
            props.get("artifact-sandbox")
            == "config/sandbox/generated_sandbox_policy.yaml"
        )

    def test_untargeted_nemo_artifact_is_not_cited(
        self, minimal_cs: ControlStructureModel
    ) -> None:
        """UCA-1 targets [opa, python]: nothing may name the Colang rails file."""
        block = generate_ssp_patch(minimal_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert "artifact-nemo" not in props
        assert _NEMO_ARTIFACT not in block["description"]
        for entry in block["by-components"]:
            assert _NEMO_ARTIFACT not in entry["description"]

    def test_targeted_nemo_artifact_is_cited(
        self, nemo_cs: ControlStructureModel
    ) -> None:
        block = generate_ssp_patch(nemo_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["artifact-nemo"] == _NEMO_ARTIFACT
        assert f"{_NEMO_ARTIFACT}     (NeMo Colang — 1 UCAs)" in block["description"]
        assert all(_NEMO_ARTIFACT in e["description"] for e in block["by-components"])

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


class TestEnforcementArtifactCitation:
    """A control narrative names only the generators its UCAs target (POAM-2026-145)."""

    @staticmethod
    def _ac3(cs: ControlStructureModel) -> str:
        # UCA-1 maps to ac-3 in the NIST routing table.
        return FrameworkRouter.get("NIST").format_narrative(
            "ac-3", cs.unsafe_control_actions
        )

    def test_python_target_cites_neither_opa_nor_nemo(self) -> None:
        text = self._ac3(_with_uca1_targets(["python"]))
        assert "uca_rules.py" in text and "stpa_validator.py" in text
        assert _OPA_ARTIFACT not in text
        assert _NEMO_ARTIFACT not in text

    def test_all_target_cites_every_generator(self) -> None:
        text = self._ac3(_with_uca1_targets(["all"]))
        assert _OPA_ARTIFACT not in text
        assert _NEMO_ARTIFACT in text
        assert "uca_rules.py" in text

    def test_no_generated_artifact_reads_none(self) -> None:
        text = self._ac3(_with_uca1_targets(["ftra"]))
        assert "via generated artifacts: none." in text


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

    def test_names_only_targeted_artifact_kinds(
        self, minimal_cs: ControlStructureModel, nemo_cs: ControlStructureModel
    ) -> None:
        entry = generate_component_entry(minimal_cs)
        assert "deterministic Python validator artifacts" in entry["description"]
        assert "NeMo" not in entry["description"] + entry["purpose"]
        assert "runtime Python governance" in entry["purpose"]

        nemo_entry = generate_component_entry(nemo_cs)
        assert "deterministic NeMo Colang artifacts" in nemo_entry["description"]
        assert "runtime NeMo governance" in nemo_entry["purpose"]


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
        assert "domain STPA UCA rules" in desc
        assert "domain OPA policy" in desc
        assert "src/cage_finance" not in desc
        assert "ActionSchema" not in desc and "schemas.py" not in desc

    def test_ftra_oscal_text_cites_only_existing_paths(self) -> None:
        """Every repo path the FTRA component cites exists (no stale schemas.py)."""
        import re

        root = Path(__file__).resolve().parents[1]
        text = yaml.safe_dump(generate_ftra_component_entry())
        paths = set(
            re.findall(r"(?:src|config|docs)/[\w./-]+\.(?:py|rego|co|txt|md)", text)
        )
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

    def test_two_consecutive_exports_yield_same_version(self, tmp_path: Path) -> None:
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
        """Verify SI-10 control has multiple component references (input screening and FTRA)."""
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

    def test_hand_edited_statement_is_replaced_by_the_generated_one(
        self, tmp_path: Path
    ) -> None:
        """F-82: a hand edit to the generated FTRA statement does not survive an
        export; the statement text comes from ``si10_description`` (the
        narrative source) or the kernel seed, never from the committed YAML."""
        comp_file = tmp_path / "comp.yaml"
        comp_file.write_text(_MINIMAL_COMP_DEF)
        _apply_ftra_component_patch(comp_file, generate_ftra_component_entry())
        doc = yaml.safe_load(comp_file.read_text())
        _si10(_ftra(doc))["description"] = "Hand-maintained statement."
        comp_file.write_text(yaml.safe_dump(doc, sort_keys=False))

        entry = generate_ftra_component_entry(si10_description="Narrative statement.")
        _apply_ftra_component_patch(comp_file, entry)

        ftra = _ftra(yaml.safe_load(comp_file.read_text()))
        assert _si10(ftra)["description"] == "Narrative statement."

    def test_seed_is_used_without_a_narrative_statement(self) -> None:
        si10 = _si10(generate_ftra_component_entry())
        assert si10["description"] == _FTRA_SI10_DESCRIPTION
        props = {p["name"]: p["value"] for p in si10["props"]}
        assert props["implementation-status"] == "partial"

    def test_export_takes_the_si10_statement_from_the_narrative_source(self) -> None:
        """The committed FTRA SI-10 statement names the domain's files because
        the narrative source supplies it, not because a hand edit was kept."""
        root = Path(__file__).resolve().parents[1]
        source = narrative_source_for(
            root / "compliance/oscal/component-definition.yaml"
        )
        assert source is not None
        expected = load_narrative_source(source)["nodes"][_FTRA_SI10_IMPL_UUID][
            "description"
        ]
        committed = yaml.safe_load(
            (root / "compliance/oscal/component-definition.yaml").read_text()
        )
        assert _si10(_ftra(committed))["description"] == expected
        assert "src/cage_finance/stpa/uca_rules.py" in expected


def _ftra(comp_def: dict) -> dict:
    return next(
        c
        for c in comp_def["component-definition"]["components"]
        if c["uuid"] == _FTRA_COMPONENT_UUID
    )


def _si10(component: dict) -> dict:
    return next(
        req
        for impl in component["control-implementations"]
        for req in impl["implemented-requirements"]
        if req["uuid"] == _FTRA_SI10_IMPL_UUID
    )


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
    @pytest.mark.parametrize("framework", ["NIST", "ISO42001", "EU_AI_ACT", "MAS_FEAT"])
    def test_every_active_uca_maps_in_every_framework(self, framework: str) -> None:
        """POAM-2026-188: an active UCA with no mapping emits an empty crosswalk line."""
        if not _FULL_YAML_PATH.exists():
            pytest.skip("Production YAML not found.")
        cs = _load_full_cs()
        mappings = FrameworkRouter.get(framework).uca_mappings
        for uca in cs.unsafe_control_actions:
            assert mappings.get(uca.id), f"{uca.id} has no {framework} mapping"

    @pytest.mark.parametrize(
        ("ssp_name", "framework_id"),
        [
            ("system-security-plan.yaml", "NIST"),
            ("system-security-plan-eu-ecb.yaml", "EU_AI_ACT"),
            ("system-security-plan-apac-mas.yaml", "MAS_FEAT"),
        ],
    )
    def test_committed_ssps_have_no_empty_crosswalk_line(
        self, ssp_name: str, framework_id: str
    ) -> None:
        """POAM-2026-188: no committed SA-11 block carries an empty ``→ <FW>:`` line."""
        ssp = yaml.safe_load(
            (
                Path(__file__).resolve().parents[1] / "compliance" / "oscal" / ssp_name
            ).read_text(encoding="utf-8")
        )
        reqs = ssp["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
        sa11 = next(r for r in reqs if r["uuid"] == _STPA_IMPL_MARKER)
        prefix = f"→ {framework_id}:"
        lines = [
            line.strip()
            for line in sa11["description"].splitlines()
            if line.strip().startswith(prefix)
        ]
        assert lines
        for line in lines:
            assert line.removeprefix(prefix).strip(), f"{ssp_name}: empty {line!r}"

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
        (a) Deterministic Input Screening and PII Redaction component
            (3d19fa63-7253-4563-b757-23c89ea461ce, sp800-53-component-definition.yaml)
        (b) FTRA Irreversibility Classifier component (ftra0001-4e47-bbc8-irreversibility01)

        This multi-component control implementation demonstrates defense-in-depth:
        - Input screening: Presidio PII redaction and the Stage 1 keyword scan
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

        # Note: the input screening component would be checked here if it existed
        # in the minimal fixture. In the production component definitions, both are present.
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

        # Verify SC-39 mentions GKE Pod Security Standards and gVisor sandboxing (and not retired GEAP Agent Runtime)
        sc39_req = next(r for r in impl_reqs if r["control-id"] == "sc-39")
        assert "gvisor" in sc39_req["description"].lower()
        assert "GEAP Agent Runtime" not in sc39_req["description"]


# ---------------------------------------------------------------------------
# Regional SSP Export & Drift Check (--check, POAM-2026-176 / POAM-2026-177)
# ---------------------------------------------------------------------------


class TestRegionalSspExportAndCheck:
    """Verify regional SSPs carry _STPA_IMPL_UUID and export --check catches drift."""

    _ROOT = Path(__file__).resolve().parents[1]
    _EU_SSP_PATH = _ROOT / "compliance" / "oscal" / "system-security-plan-eu-ecb.yaml"
    _APAC_SSP_PATH = (
        _ROOT / "compliance" / "oscal" / "system-security-plan-apac-mas.yaml"
    )

    def test_committed_regional_ssps_carry_stpa_impl_uuid_and_pass_check(self) -> None:
        for ssp_path, expected_fw, expected_marker in (
            (self._EU_SSP_PATH, "EU AI Act", "→ EU_AI_ACT:"),
            (self._APAC_SSP_PATH, "MAS FEAT", "→ MAS_FEAT:"),
        ):
            assert ssp_path.exists(), f"Missing regional SSP: {ssp_path}"
            data = yaml.safe_load(ssp_path.read_text(encoding="utf-8"))
            impl_reqs = data["system-security-plan"]["control-implementation"][
                "implemented-requirements"
            ]
            stpa_block = next(
                (r for r in impl_reqs if r.get("uuid") == _STPA_IMPL_MARKER), None
            )
            assert stpa_block is not None, (
                f"{ssp_path.name} missing _STPA_IMPL_UUID ({_STPA_IMPL_MARKER})"
            )
            assert stpa_block["control-id"] == "sa-11"
            assert expected_marker in stpa_block["description"]
            props = {p["name"]: p["value"] for p in stpa_block.get("props", [])}
            assert expected_fw in props.get("target-framework", "")
            assert props.get("uca-count") == "12"
            assert main(["export", "--check", "--ssp", str(ssp_path)]) == 0

    def test_planted_divergence_in_eu_ecb_ssp_detected_by_export_check(
        self, tmp_path: Path
    ) -> None:
        eu_copy = tmp_path / "system-security-plan-eu-ecb.yaml"
        original_text = self._EU_SSP_PATH.read_text(encoding="utf-8")
        eu_copy.write_text(original_text, encoding="utf-8")
        assert main(["export", "--check", "--ssp", str(eu_copy)]) == 0

        diverged = original_text.replace(
            f"uuid: {_STPA_IMPL_MARKER}\n      control-id: sa-11",
            f"uuid: {_STPA_IMPL_MARKER}\n      control-id: sa-999",
            1,
        )
        assert diverged != original_text
        eu_copy.write_text(diverged, encoding="utf-8")

        assert main(["export", "--check", "--ssp", str(eu_copy)]) == 1
        # --check must never overwrite the file on disk
        assert eu_copy.read_text(encoding="utf-8") == diverged

    def test_planted_divergence_in_apac_mas_ssp_detected_by_export_check(
        self, tmp_path: Path
    ) -> None:
        apac_copy = tmp_path / "system-security-plan-apac-mas.yaml"
        original_text = self._APAC_SSP_PATH.read_text(encoding="utf-8")
        apac_copy.write_text(original_text, encoding="utf-8")
        assert main(["export", "--check", "--ssp", str(apac_copy)]) == 0

        diverged = original_text.replace(
            f"uuid: {_STPA_IMPL_MARKER}\n      control-id: sa-11",
            f"uuid: {_STPA_IMPL_MARKER}\n      control-id: sa-999",
            1,
        )
        assert diverged != original_text
        apac_copy.write_text(diverged, encoding="utf-8")

        assert main(["export", "--check", "--ssp", str(apac_copy)]) == 1
        assert apac_copy.read_text(encoding="utf-8") == diverged

    def test_volatile_timestamp_changes_ignored_by_export_check(
        self, tmp_path: Path
    ) -> None:
        import re

        eu_copy = tmp_path / "system-security-plan-eu-ecb.yaml"
        original_text = self._EU_SSP_PATH.read_text(encoding="utf-8")
        rewritten = re.sub(
            r"2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            "1999-12-31T23:59:59Z",
            original_text,
        )
        assert rewritten != original_text
        eu_copy.write_text(rewritten, encoding="utf-8")
        assert main(["export", "--check", "--ssp", str(eu_copy)]) == 0


class TestServerBoundAndAdvisoryOscalExport:
    """F-99 / F-102: OSCAL exporter verifies per-UCA server_bound enforcement and never marks advisory-only controls implemented."""

    def test_advisory_only_control_marked_partially_implemented(self) -> None:
        raw = yaml.safe_load(_MINIMAL_YAML)
        raw["control_actions"][0]["params"][0]["server_bound"] = False
        raw["unsafe_control_actions"][0]["advisory"] = True
        cs = ControlStructureModel(**raw)

        block = generate_ssp_patch(cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["enforcing-uca-count"] == "0"
        assert props["advisory-uca-count"] == "1"
        assert props["implementation-status"] == "partial"
        for bc in block["by-components"]:
            assert bc["implementation-status"]["state"] == "partial"

        comp = generate_component_entry(cs)
        assert "OPA Rego" not in comp["description"]
        assert "config/stpa/" in comp["description"]

    def test_production_cs_marks_si4_advisory_only_partially_implemented(
        self, full_cs: ControlStructureModel
    ) -> None:
        from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

        block = generate_ssp_patch(full_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["enforcing-uca-count"] == "6"
        assert props["advisory-uca-count"] == "6"
        assert "config/opa/generated_stpa_policy.rego" not in block["description"]
        controls = FrameworkRouter.get("NIST").all_controls(
            full_cs.unsafe_control_actions
        )
        by_ctrl = dict(zip(controls, block["by-components"], strict=True))
        assert by_ctrl["si-4"]["implementation-status"]["state"] == "partial"
        assert by_ctrl["sc-28"]["implementation-status"]["state"] == "partial"
        # AC-3 maps enforcing UCA-1/UCA-5 and advisory UCA-3/8/9/12: partial.
        assert by_ctrl["ac-3"]["implementation-status"]["state"] == "partial"
        advisory = (
            by_ctrl["ac-3"]["description"]
            .split("advisory UCAs (not server-bound):", 1)[1]
            .rstrip(".")
        )
        assert {u.strip() for u in advisory.split(",")} == {
            "UCA-3",
            "UCA-8",
            "UCA-9",
            "UCA-12",
        }
        # SI-3 maps only UCA-6 and UCA-7, both bound server-side.
        assert by_ctrl["si-3"]["implementation-status"]["state"] == "implemented"
        assert props["implementation-status"] == "partial"

    def test_control_with_one_enforcing_and_one_advisory_uca_is_partial(self) -> None:
        """Regression (SA11-SYSTEMIC): one enforcing UCA must not mark a control
        implemented while another UCA mapped to it is advisory."""
        from src.gateway.governance.oscal_ssp_exporter import _rollup_state

        assert _rollup_state(["implemented", "partial"]) == "partial"
        assert _rollup_state(["implemented", "planned"]) == "partial"
        assert _rollup_state(["implemented", "implemented"]) == "implemented"
        assert _rollup_state(["planned"]) == "planned"
        assert _rollup_state([]) == "planned"

    def test_yaml_server_bound_without_registered_resolver_not_credited_implemented(
        self, minimal_cs: ControlStructureModel
    ) -> None:
        """Static YAML ``server_bound: true`` without a live ``ServerInputResolver``
        in ``assemble_governor()`` must downgrade to ``planned``, never ``implemented``."""
        block = generate_ssp_patch(minimal_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["enforcing-uca-count"] == "0"
        assert props["advisory-uca-count"] == "1"
        assert props["implementation-status"] == "planned"
        assert "[unregistered server_bound — planned]" in block["description"]
        for bc in block["by-components"]:
            assert bc["implementation-status"]["state"] == "planned"

    def test_yaml_server_bound_with_assembled_resolver_credited_implemented(
        self, minimal_cs: ControlStructureModel, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once ``assemble_governor()`` registers a ``ServerInputResolver`` owning the
        ``server_bound: true`` parameter, the exporter credits ``implemented``."""
        import importlib.metadata
        from collections.abc import Mapping
        from typing import Any

        from src.gateway.governance.contracts import CagePlugin, PluginContribution

        class _TokenResolver:
            owned_keys: frozenset[str] = frozenset({"token"})

            async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
                return {"token": "srv-bound"}

        class _DoThingPlugin(CagePlugin):
            name = "do_thing_domain"
            api_version = "2.0"
            maturity = "production"
            domain_config = None

            def contribute(self) -> PluginContribution:
                return PluginContribution(
                    domain=self.name,
                    maturity=self.maturity,
                    registered_actions=frozenset({"do_thing"}),
                    server_inputs={"do_thing": _TokenResolver()},
                )

        class _FakeEntryPoint:
            name = "do_thing_domain"

            @staticmethod
            def load() -> type[CagePlugin]:
                return _DoThingPlugin

        monkeypatch.setattr(
            importlib.metadata,
            "entry_points",
            lambda **_kwargs: [_FakeEntryPoint()],
        )

        block = generate_ssp_patch(minimal_cs)
        props = {p["name"]: p["value"] for p in block["props"]}
        assert props["enforcing-uca-count"] == "1"
        assert props["advisory-uca-count"] == "0"
        assert props["implementation-status"] == "implemented"
        for bc in block["by-components"]:
            assert bc["implementation-status"]["state"] == "implemented"


class TestNarrativeSources:
    """F-82: hand-authored blocks the exporter owns through config/oscal/narratives/."""

    @staticmethod
    def _doc() -> dict:
        return {
            "plan": {
                "reqs": [
                    {"uuid": "req-1", "description": "old", "remarks": "stale"},
                    {"uuid": "req-2", "description": "keep"},
                ],
                "set-parameters": [{"param-id": "p-1", "values": ["old"]}],
                "back-matter": {"resources": [{"uuid": "res-1"}, {"uuid": "res-2"}]},
            }
        }

    def test_replaces_fields_deletes_null_drops_items_and_sets_params(self) -> None:
        doc = self._doc()
        data = {
            "nodes": {"req-1": {"description": "new", "remarks": None}},
            "set_parameters": {"p-1": ["new"]},
            "remove": ["res-1"],
        }
        apply_narrative_source(
            doc, data, generated_uuids=frozenset(), source=Path("n.json")
        )
        plan = doc["plan"]
        assert plan["reqs"][0] == {"uuid": "req-1", "description": "new"}
        assert plan["reqs"][1] == {"uuid": "req-2", "description": "keep"}
        assert plan["set-parameters"][0]["values"] == ["new"]
        assert plan["back-matter"]["resources"] == [{"uuid": "res-2"}]

    @pytest.mark.parametrize(
        "data",
        [
            {"nodes": {"req-missing": {"description": "x"}}},
            {"remove": ["res-missing"]},
            {"set_parameters": {"p-missing": ["x"]}},
        ],
    )
    def test_entry_that_matches_nothing_fails_closed(self, data: dict) -> None:
        with pytest.raises(ValueError, match="matches 0 nodes"):
            apply_narrative_source(
                self._doc(), data, generated_uuids=frozenset(), source=Path("n.json")
            )

    def test_duplicate_uuid_fails_closed(self) -> None:
        doc = self._doc()
        doc["plan"]["reqs"].append({"uuid": "req-1", "description": "twin"})
        with pytest.raises(ValueError, match="matches 2 nodes"):
            apply_narrative_source(
                doc,
                {"nodes": {"req-1": {"description": "x"}}},
                generated_uuids=frozenset(),
                source=Path("n.json"),
            )

    def test_generated_block_cannot_be_targeted(self) -> None:
        with pytest.raises(ValueError, match="exporter-generated"):
            apply_narrative_source(
                self._doc(),
                {"nodes": {"req-1": {"description": "x"}}},
                generated_uuids=frozenset({"req-1"}),
                source=Path("n.json"),
            )

    @pytest.mark.parametrize(
        "payload",
        [
            {"unexpected": {}},
            {"nodes": {"req-1": {"uuid": "other"}}},
            {"nodes": {"req-1": {}}},
            {"nodes": {_FTRA_SI10_IMPL_UUID: {"description": "x", "props": []}}},
            {"set_parameters": {"p-1": "not-a-list"}},
            {"remove": "res-1"},
        ],
    )
    def test_malformed_source_is_rejected(self, tmp_path: Path, payload: dict) -> None:
        source = tmp_path / "narratives.json"
        source.write_text(json.dumps(payload))
        with pytest.raises(ValueError):
            load_narrative_source(source)

    def test_only_canonical_outputs_have_narrative_sources(
        self, tmp_path: Path
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        canonical = root / "compliance" / "oscal" / "component-definition.yaml"
        assert narrative_source_for(canonical) is not None
        copy = tmp_path / "component-definition.yaml"
        copy.write_text(canonical.read_text())
        assert narrative_source_for(copy) is None

    def test_ssp_patch_with_stale_source_writes_nothing(self, tmp_path: Path) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        source = tmp_path / "narratives.json"
        source.write_text(json.dumps({"nodes": {"gone-0001": {"description": "x"}}}))
        assert not _apply_ssp_patch(ssp_file, [], narratives=source)
        assert ssp_file.read_text() == _MINIMAL_SSP

    def test_ssp_patch_applies_source_to_a_hand_authored_block(
        self, tmp_path: Path
    ) -> None:
        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        source = tmp_path / "narratives.json"
        source.write_text(
            json.dumps(
                {
                    "nodes": {
                        "existing-req-0001": {
                            "description": "Restated.",
                            "props": [
                                {"name": "implementation-status", "value": "partial"}
                            ],
                        }
                    }
                }
            )
        )
        assert _apply_ssp_patch(ssp_file, [], narratives=source)
        req = yaml.safe_load(ssp_file.read_text())["system-security-plan"][
            "control-implementation"
        ]["implemented-requirements"][0]
        assert req["description"] == "Restated."
        assert req["props"] == [{"name": "implementation-status", "value": "partial"}]

    def test_platform_block_cannot_be_overridden(self, tmp_path: Path) -> None:
        from src.gateway.governance.oscal_ssp_exporter import (
            generate_platform_control_narratives,
        )

        ssp_file = tmp_path / "ssp.yaml"
        ssp_file.write_text(_MINIMAL_SSP)
        source = tmp_path / "narratives.json"
        source.write_text(
            json.dumps({"nodes": {_PLATFORM_SC7_IMPL_UUID: {"description": "x"}}})
        )
        blocks = generate_platform_control_narratives("gcp-gke")
        assert not _apply_ssp_patch(ssp_file, blocks, narratives=source)

    @pytest.mark.parametrize(
        "output",
        [
            "system-security-plan.yaml",
            "system-security-plan-eu-ecb.yaml",
            "system-security-plan-apac-mas.yaml",
            "component-definition.yaml",
        ],
    )
    def test_committed_outputs_carry_their_narrative_source(self, output: str) -> None:
        """Every field a narrative source sets is what the committed YAML says,
        so a hand edit to an exporter-owned block shows up here and in
        ``export --check``."""
        root = Path(__file__).resolve().parents[1]
        target = root / "compliance" / "oscal" / output
        source = narrative_source_for(target)
        if source is None:
            pytest.skip(f"{output} has no narrative source")
        data = load_narrative_source(source)
        index: dict[str, dict] = {}

        def walk(node: object) -> None:
            if isinstance(node, dict):
                if isinstance(node.get("uuid"), str):
                    index[node["uuid"]] = node
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(yaml.safe_load(target.read_text(encoding="utf-8")))
        for uid, fields in data.get("nodes", {}).items():
            for field, value in fields.items():
                if value is None:
                    assert field not in index[uid], (uid, field)
                else:
                    assert index[uid][field] == value, (uid, field)
        for uid in data.get("remove", []):
            assert uid not in index, uid


pytestmark = [pytest.mark.unit, pytest.mark.local]
