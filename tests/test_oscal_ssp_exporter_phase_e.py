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
Phase E: OSCAL SSP Platform Narrative Tests

Tests platform-aware OSCAL SSP control narratives for GKE deployment
(SC-7, SC-8, SC-39, SI-3).

Coverage:
  - Platform detection logic (_detect_deployment_platform)
  - Platform narrative generation (generate_platform_control_narratives)
  - Narrative content validation
  - UUID stability and deterministic generation
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from src.gateway.governance.oscal_ssp_exporter import (
    _PLATFORM_SC7_IMPL_UUID,
    _PLATFORM_SC8_IMPL_UUID,
    _PLATFORM_SC39_IMPL_UUID,
    _PLATFORM_SI3_IMPL_UUID,
    PLATFORM_CONTROL_NARRATIVES,
    _detect_deployment_platform,
    generate_platform_control_narratives,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_PATH_RE = re.compile(
    r"(?<![\w./-])((?:src|infra|tests|compliance|deployment|scripts|config|docs|\.github)/"
    r"[\w./-]+\.(?:py|tf|hcl|yaml|yml|json|md|sh))"
)
_POAM_ID_RE = re.compile(r"\bPOAM-(?:\d{4}-)?\d{3}\b")


# ---------------------------------------------------------------------------
# Platform Detection Tests
# ---------------------------------------------------------------------------


class TestPlatformDetection:
    """Test _detect_deployment_platform() environment variable logic."""

    def test_detects_gcp_gke_from_kubernetes_service_host(self) -> None:
        """GKE sets KUBERNETES_SERVICE_HOST environment variable."""
        with patch.dict(
            os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, clear=True
        ):
            assert _detect_deployment_platform() == "gcp-gke"

    def test_detects_aws_ecs_from_metadata_uri(self) -> None:
        """ECS sets ECS_CONTAINER_METADATA_URI_V4 environment variable."""
        with patch.dict(
            os.environ,
            {"ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/abc123"},
            clear=True,
        ):
            assert _detect_deployment_platform() == "aws-ecs"

    def test_detects_azure_containerapp_from_identity_vars(self) -> None:
        """Azure Container Apps set IDENTITY_ENDPOINT and IDENTITY_HEADER."""
        with patch.dict(
            os.environ,
            {
                "IDENTITY_ENDPOINT": "http://localhost:8081/msi/token",
                "IDENTITY_HEADER": "secret-header-value",
            },
            clear=True,
        ):
            assert _detect_deployment_platform() == "azure-containerapp"

    def test_returns_agnostic_for_local_environment(self) -> None:
        """Local/dev environment with no platform markers returns 'agnostic'."""
        with patch.dict(os.environ, {}, clear=True):
            assert _detect_deployment_platform() == "agnostic"


# ---------------------------------------------------------------------------
# Platform Narrative Generation Tests
# ---------------------------------------------------------------------------


class TestPlatformNarrativeGeneration:
    """Test generate_platform_control_narratives() block generation."""

    def test_generates_four_controls_for_gke(self) -> None:
        """GKE generates narratives for SC-7, SC-8, SC-39, SI-3."""
        narratives = generate_platform_control_narratives("gcp-gke")
        assert len(narratives) == 4
        control_ids = {n["control-id"] for n in narratives}
        assert control_ids == {"sc-7", "sc-8", "sc-39", "si-3"}

    def test_returns_empty_list_for_agnostic_platform(self) -> None:
        """Agnostic/local platform returns empty list (no platform narratives)."""
        narratives = generate_platform_control_narratives("agnostic")
        assert narratives == []

    def test_returns_empty_list_for_unknown_platform(self) -> None:
        """Unknown platform identifier returns empty list."""
        narratives = generate_platform_control_narratives("unknown-platform")
        assert narratives == []

    def test_auto_detects_platform_when_none_supplied(self) -> None:
        """generate_platform_control_narratives(None) auto-detects via environment."""
        with patch.dict(
            os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, clear=True
        ):
            narratives = generate_platform_control_narratives(platform=None)
            assert len(narratives) == 4

    def test_each_narrative_has_required_oscal_keys(self) -> None:
        """Each generated narrative block has uuid, control-id, description, props."""
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            assert "uuid" in narrative
            assert "control-id" in narrative
            assert "description" in narrative
            assert "props" in narrative
            assert "responsible-roles" in narrative

    def test_props_include_implementation_status(self) -> None:
        """Each GKE narrative is partial and names the gap that keeps it so.

        The SC-7, SC-8, SC-39 and SI-3 narratives describe what the gcp-gke
        Terraform deploys today; every one still has an open gap (internal
        segmentation, mesh authorization, GKE Sandbox, read-only root
        filesystem), so none may claim ``implemented``.
        """
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert props["implementation-status"] == "partial"
            assert "Open gap" in narrative["description"], narrative["control-id"]

    def test_props_include_deployment_platform(self) -> None:
        """Each narrative props include deployment-platform tag."""
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert props["deployment-platform"] == "gcp-gke"

    def test_props_include_evidence_file(self) -> None:
        """Each narrative props include evidence-file reference."""
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert "evidence-file" in props
            assert len(props["evidence-file"]) > 0

    def test_poam_refs_name_only_existing_poam_items(self) -> None:
        """POA&M ids in a narrative or its ``poam-refs`` prop exist in the registers.

        A narrative with no POA&M item for its gap carries no ``poam-refs``
        prop rather than an invented one.
        """
        registers = (_REPO_ROOT / "docs" / "POAM.md").read_text(encoding="utf-8") + (
            _REPO_ROOT / "docs" / "compliance" / "us_fed" / "POAM_US_FED.md"
        ).read_text(encoding="utf-8")
        cited = 0
        for narrative in generate_platform_control_narratives("gcp-gke"):
            props = {p["name"]: p["value"] for p in narrative["props"]}
            refs = _POAM_ID_RE.findall(props.get("poam-refs", ""))
            assert "poam-refs" not in props or refs, narrative["control-id"]
            for poam_id in refs + _POAM_ID_RE.findall(narrative["description"]):
                assert f"| {poam_id} |" in registers, poam_id
                cited += 1
        assert cited

    def test_narratives_cite_only_existing_paths(self) -> None:
        """Every repository path a narrative or its evidence prop names exists."""
        for narrative in generate_platform_control_narratives("gcp-gke"):
            props = {p["name"]: p["value"] for p in narrative["props"]}
            text = narrative["description"] + " " + props["evidence-file"]
            paths = _REPO_PATH_RE.findall(text)
            assert paths, narrative["control-id"]
            missing = [p for p in paths if not (_REPO_ROOT / p).exists()]
            assert not missing, (narrative["control-id"], missing)


# ---------------------------------------------------------------------------
# Narrative Content Validation Tests
# ---------------------------------------------------------------------------


class TestNarrativeContent:
    """Test GKE narrative text references Kubernetes manifests and Linkerd mTLS."""

    def test_gke_narratives_reference_kubernetes_resources(self) -> None:
        """GKE narratives reference Kubernetes manifests and enforcement mechanisms."""
        narratives = generate_platform_control_narratives("gcp-gke")
        sc7 = next(n for n in narratives if n["control-id"] == "sc-7")
        sc8 = next(n for n in narratives if n["control-id"] == "sc-8")
        sc39 = next(n for n in narratives if n["control-id"] == "sc-39")
        si3 = next(n for n in narratives if n["control-id"] == "si-3")

        assert "Cilium" in sc7["description"]
        assert "network_policy.tf" in sc7["description"]
        assert "Linkerd" in sc8["description"]
        assert "governed_advisor" in sc39["description"]
        assert "GEAP Agent Runtime" not in sc39["description"]
        assert "Binary Authorization" in si3["description"]

    def test_gke_narratives_disclose_the_gaps_terraform_leaves(self) -> None:
        """Each narrative states the deployed gap instead of claiming the control.

        Regression: the SSP claimed per-workload egress isolation, TLS on both
        Memorystore instances, gVisor sandboxing and read-only root filesystems
        on every container, none of which infra/ deploys.
        """
        narratives = generate_platform_control_narratives("gcp-gke")
        by_ctrl = {
            n["control-id"]: " ".join(n["description"].split()) for n in narratives
        }
        assert "POAM-2026-195" in by_ctrl["sc-7"]
        assert "POAM-2026-191" in by_ctrl["sc-7"]
        assert "memorystore_app" in by_ctrl["sc-8"]
        assert "transit encryption and authentication disabled" in by_ctrl["sc-8"]
        assert "GKE Sandbox (gVisor) is not enabled" in by_ctrl["sc-39"]
        assert "readOnlyRootFilesystem: true" not in by_ctrl["si-3"]
        assert "read_only_root_filesystem = true is set only by" in by_ctrl["si-3"]


# ---------------------------------------------------------------------------
# UUID Stability Tests
# ---------------------------------------------------------------------------


class TestUUIDStability:
    """Test deterministic UUID generation for platform narratives."""

    def test_uuids_are_stable_across_invocations(self) -> None:
        """Platform narrative UUIDs are deterministic (no random generation)."""
        narratives_1 = generate_platform_control_narratives("gcp-gke")
        narratives_2 = generate_platform_control_narratives("gcp-gke")

        uuids_1 = {n["uuid"] for n in narratives_1}
        uuids_2 = {n["uuid"] for n in narratives_2}

        assert uuids_1 == uuids_2

    def test_platform_control_uuids_match_constants(self) -> None:
        """Generated UUIDs match the module-level constants."""
        narratives = generate_platform_control_narratives("gcp-gke")

        sc7 = next(n for n in narratives if n["control-id"] == "sc-7")
        sc8 = next(n for n in narratives if n["control-id"] == "sc-8")
        sc39 = next(n for n in narratives if n["control-id"] == "sc-39")
        si3 = next(n for n in narratives if n["control-id"] == "si-3")

        assert sc7["uuid"] == _PLATFORM_SC7_IMPL_UUID
        assert sc8["uuid"] == _PLATFORM_SC8_IMPL_UUID
        assert sc39["uuid"] == _PLATFORM_SC39_IMPL_UUID
        assert si3["uuid"] == _PLATFORM_SI3_IMPL_UUID


# ---------------------------------------------------------------------------
# Platform Control Narratives Dictionary Structure Tests
# ---------------------------------------------------------------------------


class TestPlatformControlNarrativesDictionary:
    """Test PLATFORM_CONTROL_NARRATIVES dictionary structure."""

    def test_dictionary_has_gcp_gke_only(self) -> None:
        """PLATFORM_CONTROL_NARRATIVES includes gcp-gke as the hardened target."""
        assert list(PLATFORM_CONTROL_NARRATIVES.keys()) == ["gcp-gke"]

    def test_all_platforms_have_four_controls(self) -> None:
        """Each platform in the dictionary defines SC-7, SC-8, SC-39, SI-3."""
        for _platform, controls in PLATFORM_CONTROL_NARRATIVES.items():
            assert "sc-7" in controls
            assert "sc-8" in controls
            assert "sc-39" in controls
            assert "si-3" in controls

    def test_all_control_entries_have_required_keys(self) -> None:
        """Each control entry has uuid, control-id, title, status, narrative, evidence, poam_refs."""
        for platform, controls in PLATFORM_CONTROL_NARRATIVES.items():
            for control_id, meta in controls.items():
                assert "uuid" in meta, f"{platform}/{control_id} missing uuid"
                assert "control-id" in meta, (
                    f"{platform}/{control_id} missing control-id"
                )
                assert "title" in meta, f"{platform}/{control_id} missing title"
                assert "status" in meta, f"{platform}/{control_id} missing status"
                assert "narrative" in meta, f"{platform}/{control_id} missing narrative"
                assert "evidence" in meta, f"{platform}/{control_id} missing evidence"
                assert "poam_refs" in meta, f"{platform}/{control_id} missing poam_refs"
