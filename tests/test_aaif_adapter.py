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

"""Tests for src/gateway/governance/ingress/aaif_adapter.py — AAIF → pipeline stage mapping."""

from __future__ import annotations

import pytest

from src.gateway.governance.ingress.aaif_adapter import (
    aaif_to_control_structure_patch,
    translate_aaif,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_AAIF_SPEC = {
    "governedRunLoop": {
        "name": "Test Agent Run Loop",
        "stages": [
            {
                "name": "input_validation",
                "governanceHooks": [
                    {
                        "id": "AAIF-IV-001",
                        "action": "validate_input",
                        "description": "Validate all inputs before processing",
                        "ucaType": "unsafe_action",
                        "hazardRefs": ["H-AAIF-1"],
                        "enforcement": ["python"],
                        "constraints": [
                            {"type": "required", "parameter": "user_input"}
                        ],
                    }
                ],
            }
        ],
    }
}

_MULTI_STAGE_AAIF_SPEC = {
    "governedRunLoop": {
        "name": "Multi-Stage Agent",
        "stages": [
            {"name": "input_validation", "governanceHooks": []},
            {"name": "policy_check", "governanceHooks": []},
            {"name": "access_control", "governanceHooks": []},
        ],
    }
}

_UNKNOWN_STAGE_AAIF_SPEC = {
    "governedRunLoop": {
        "stages": [
            {
                "name": "custom_stage",
                "governanceHooks": [
                    {
                        "id": "AAIF-CUSTOM-001",
                        "action": "custom_action",
                        "description": "Custom governance hook",
                    }
                ],
            }
        ]
    }
}


# ---------------------------------------------------------------------------
# translate_aaif tests
# ---------------------------------------------------------------------------


class TestTranslateAAIF:
    def test_missing_governed_run_loop_raises(self):
        with pytest.raises(ValueError, match="governedRunLoop"):
            translate_aaif({"notGovernedRunLoop": {}})

    def test_minimal_spec_returns_stage_map_and_ucas(self):
        stage_map, ucas = translate_aaif(_MINIMAL_AAIF_SPEC)
        assert isinstance(stage_map, dict)
        assert isinstance(ucas, list)

    def test_known_stage_maps_to_correct_tier(self):
        stage_map, _ = translate_aaif(_MINIMAL_AAIF_SPEC)
        assert "input_validation" in stage_map
        assert stage_map["input_validation"]["tier"] == 0

    def test_policy_check_maps_to_tier_2(self):
        stage_map, _ = translate_aaif(_MULTI_STAGE_AAIF_SPEC)
        assert stage_map["policy_check"]["tier"] == 2

    def test_access_control_maps_to_tier_3(self):
        stage_map, _ = translate_aaif(_MULTI_STAGE_AAIF_SPEC)
        assert stage_map["access_control"]["tier"] == 3

    def test_governance_hook_produces_uca(self):
        _, ucas = translate_aaif(_MINIMAL_AAIF_SPEC)
        assert len(ucas) == 1
        assert ucas[0]["id"] == "AAIF-IV-001"

    def test_uca_action_preserved(self):
        _, ucas = translate_aaif(_MINIMAL_AAIF_SPEC)
        assert ucas[0]["action"] == "validate_input"

    def test_uca_has_aaif_stage_metadata(self):
        _, ucas = translate_aaif(_MINIMAL_AAIF_SPEC)
        assert ucas[0]["_aaif_stage"] == "input_validation"
        assert ucas[0]["_aaif_tier"] == 0

    def test_unknown_stage_gets_tier_minus_one(self):
        stage_map, _ = translate_aaif(_UNKNOWN_STAGE_AAIF_SPEC)
        assert stage_map["custom_stage"]["tier"] == -1

    def test_empty_stages_produces_empty_results(self):
        spec = {"governedRunLoop": {"stages": []}}
        stage_map, ucas = translate_aaif(spec)
        assert stage_map == {}
        assert ucas == []

    def test_stage_with_constraints_but_no_hooks_creates_synthetic_uca(self):
        spec = {
            "governedRunLoop": {
                "stages": [
                    {
                        "name": "rate_limiting",
                        "constraints": [
                            {
                                "type": "max",
                                "parameter": "requests_per_second",
                                "value": 100,
                            }
                        ],
                    }
                ]
            }
        }
        _, ucas = translate_aaif(spec)
        assert len(ucas) == 1
        assert "SYNTHETIC" in ucas[0]["id"]

    def test_uca_type_omission_maps_to_not_provided(self):
        spec = {
            "governedRunLoop": {
                "stages": [
                    {
                        "name": "input_validation",
                        "governanceHooks": [
                            {
                                "id": "AAIF-TEST",
                                "action": "test_action",
                                "ucaType": "omission",
                            }
                        ],
                    }
                ]
            }
        }
        _, ucas = translate_aaif(spec)
        assert ucas[0]["uca_type"] == "not_provided"


# ---------------------------------------------------------------------------
# aaif_to_control_structure_patch tests
# ---------------------------------------------------------------------------


class TestAAIFToControlStructurePatch:
    def test_patch_has_system_key(self):
        patch = aaif_to_control_structure_patch(_MINIMAL_AAIF_SPEC)
        assert "system" in patch

    def test_patch_system_name_from_run_loop(self):
        patch = aaif_to_control_structure_patch(_MINIMAL_AAIF_SPEC)
        assert patch["system"]["name"] == "Test Agent Run Loop"

    def test_patch_has_control_actions_from_stages(self):
        patch = aaif_to_control_structure_patch(_MULTI_STAGE_AAIF_SPEC)
        assert len(patch["control_actions"]) == 3

    def test_patch_has_aaif_stage_map(self):
        patch = aaif_to_control_structure_patch(_MINIMAL_AAIF_SPEC)
        assert "_aaif_stage_map" in patch

    def test_patch_has_unsafe_control_actions(self):
        patch = aaif_to_control_structure_patch(_MINIMAL_AAIF_SPEC)
        assert "unsafe_control_actions" in patch
