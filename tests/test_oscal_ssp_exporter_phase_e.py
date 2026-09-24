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
Phase E: Cloud Run OSCAL SSP Platform Narrative Tests

Tests platform-aware OSCAL SSP control narratives for GKE vs. Cloud Run
deployment differences (SC-7, SC-8, SC-39, SI-3).

Coverage:
  - Platform detection logic (_detect_deployment_platform)
  - Platform narrative generation (generate_platform_control_narratives)
  - Narrative content validation (compensating/superior/conditional labels)
  - UUID stability and deterministic generation
"""

from __future__ import annotations

import os
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


# ---------------------------------------------------------------------------
# Platform Detection Tests
# ---------------------------------------------------------------------------


class TestPlatformDetection:
    """Test _detect_deployment_platform() environment variable logic."""

    def test_detects_gcp_cloudrun_from_k_service(self) -> None:
        """Cloud Run sets K_SERVICE environment variable."""
        with patch.dict(os.environ, {"K_SERVICE": "my-service"}, clear=True):
            assert _detect_deployment_platform() == "gcp-cloudrun"

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

    def test_gcp_cloudrun_takes_precedence_over_gke(self) -> None:
        """Cloud Run detection (K_SERVICE) takes precedence over GKE markers."""
        with patch.dict(
            os.environ,
            {"K_SERVICE": "my-service", "KUBERNETES_SERVICE_HOST": "10.0.0.1"},
            clear=True,
        ):
            # Cloud Run check is first in detection order
            assert _detect_deployment_platform() == "gcp-cloudrun"


# ---------------------------------------------------------------------------
# Platform Narrative Generation Tests
# ---------------------------------------------------------------------------


class TestPlatformNarrativeGeneration:
    """Test generate_platform_control_narratives() block generation."""

    def test_generates_four_controls_for_cloudrun(self) -> None:
        """Cloud Run generates narratives for SC-7, SC-8, SC-39, SI-3."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        assert len(narratives) == 4
        control_ids = {n["control-id"] for n in narratives}
        assert control_ids == {"sc-7", "sc-8", "sc-39", "si-3"}

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
        with patch.dict(os.environ, {"K_SERVICE": "my-service"}, clear=True):
            narratives = generate_platform_control_narratives(platform=None)
            assert len(narratives) == 4

    def test_each_narrative_has_required_oscal_keys(self) -> None:
        """Each generated narrative block has uuid, control-id, description, props."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        for narrative in narratives:
            assert "uuid" in narrative
            assert "control-id" in narrative
            assert "description" in narrative
            assert "props" in narrative
            assert "responsible-roles" in narrative

    def test_props_include_implementation_status(self) -> None:
        """Each narrative props include implementation-status = implemented."""
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert props["implementation-status"] == "implemented"

    def test_props_include_deployment_platform(self) -> None:
        """Each narrative props include deployment-platform tag."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert props["deployment-platform"] == "gcp-cloudrun"

    def test_props_include_evidence_file(self) -> None:
        """Each narrative props include evidence-file reference."""
        narratives = generate_platform_control_narratives("gcp-gke")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert "evidence-file" in props
            assert len(props["evidence-file"]) > 0

    def test_props_include_poam_refs(self) -> None:
        """Each narrative props include POAM references."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        for narrative in narratives:
            props = {p["name"]: p["value"] for p in narrative["props"]}
            assert "poam-refs" in props


# ---------------------------------------------------------------------------
# Narrative Content Validation Tests
# ---------------------------------------------------------------------------


class TestNarrativeContent:
    """Test narrative text contains required compensating/superior/conditional labels."""

    def test_cloudrun_sc7_is_compensating_control(self) -> None:
        """Cloud Run SC-7 narrative explicitly labeled as compensating control."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        sc7 = next(n for n in narratives if n["control-id"] == "sc-7")
        description = sc7["description"]
        assert "**Compensating Control Disclosure:**" in description
        assert "not equivalent" in description.lower()

    def test_cloudrun_sc8_is_superior_control(self) -> None:
        """Cloud Run SC-8 narrative labeled as superior to GKE mTLS."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        sc8 = next(n for n in narratives if n["control-id"] == "sc-8")
        description = sc8["description"]
        assert "**Superior Control Implementation:**" in description
        assert "superior" in description.lower()
        assert "TLS 1.3" in description
        assert "Google Front End (GFE)" in description
        assert "IAM-issued OIDC" in description

    def test_cloudrun_sc39_is_conditional(self) -> None:
        """Cloud Run SC-39 narrative states execution-environment dependent."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        sc39 = next(n for n in narratives if n["control-id"] == "sc-39")
        description = sc39["description"]
        assert "execution-environment dependent" in description.lower()
        assert "Gen1" in description
        assert "Gen2" in description
        assert "gVisor" in description
        assert "microVM" in description

    def test_cloudrun_si3_is_compensating_not_equivalent(self) -> None:
        """Cloud Run SI-3 narrative labeled as compensating and explicitly not equivalent."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        si3 = next(n for n in narratives if n["control-id"] == "si-3")
        description = si3["description"]
        assert "**Compensating Control Disclosure:**" in description
        assert "not equivalent" in description
        assert "writable root filesystem" in description.lower()
        assert "readOnlyRootFilesystem: true" in description  # Mentioned as what GKE has, not Cloud Run

    def test_gke_narratives_reference_kubernetes_resources(self) -> None:
        """GKE narratives reference Kubernetes manifests and enforcement mechanisms."""
        narratives = generate_platform_control_narratives("gcp-gke")
        sc7 = next(n for n in narratives if n["control-id"] == "sc-7")
        si3 = next(n for n in narratives if n["control-id"] == "si-3")
        
        # SC-7 should reference Cilium
        assert "Cilium" in sc7["description"]
        
        # SI-3 should reference readOnlyRootFilesystem
        assert "readOnlyRootFilesystem: true" in si3["description"]


# ---------------------------------------------------------------------------
# UUID Stability Tests
# ---------------------------------------------------------------------------


class TestUUIDStability:
    """Test deterministic UUID generation for platform narratives."""

    def test_uuids_are_stable_across_invocations(self) -> None:
        """Platform narrative UUIDs are deterministic (no random generation)."""
        narratives_1 = generate_platform_control_narratives("gcp-cloudrun")
        narratives_2 = generate_platform_control_narratives("gcp-cloudrun")
        
        uuids_1 = {n["uuid"] for n in narratives_1}
        uuids_2 = {n["uuid"] for n in narratives_2}
        
        assert uuids_1 == uuids_2

    def test_platform_control_uuids_match_constants(self) -> None:
        """Generated UUIDs match the module-level constants."""
        narratives = generate_platform_control_narratives("gcp-cloudrun")
        
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

    def test_dictionary_has_gcp_cloudrun_and_gcp_gke(self) -> None:
        """PLATFORM_CONTROL_NARRATIVES includes both gcp-cloudrun and gcp-gke."""
        assert "gcp-cloudrun" in PLATFORM_CONTROL_NARRATIVES
        assert "gcp-gke" in PLATFORM_CONTROL_NARRATIVES

    def test_all_platforms_have_four_controls(self) -> None:
        """Each platform in the dictionary defines SC-7, SC-8, SC-39, SI-3."""
        for platform, controls in PLATFORM_CONTROL_NARRATIVES.items():
            assert "sc-7" in controls
            assert "sc-8" in controls
            assert "sc-39" in controls
            assert "si-3" in controls

    def test_all_control_entries_have_required_keys(self) -> None:
        """Each control entry has uuid, control-id, title, status, narrative, evidence, poam_refs."""
        for platform, controls in PLATFORM_CONTROL_NARRATIVES.items():
            for control_id, meta in controls.items():
                assert "uuid" in meta, f"{platform}/{control_id} missing uuid"
                assert "control-id" in meta, f"{platform}/{control_id} missing control-id"
                assert "title" in meta, f"{platform}/{control_id} missing title"
                assert "status" in meta, f"{platform}/{control_id} missing status"
                assert "narrative" in meta, f"{platform}/{control_id} missing narrative"
                assert "evidence" in meta, f"{platform}/{control_id} missing evidence"
                assert "poam_refs" in meta, f"{platform}/{control_id} missing poam_refs"
