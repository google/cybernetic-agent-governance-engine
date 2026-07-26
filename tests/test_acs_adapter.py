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

"""Tests for src/gateway/governance/ingress/acs_adapter.py — ACS → UCA YAML round-trip."""

from __future__ import annotations

import pytest

from src.gateway.governance.ingress.acs_adapter import (
    acs_to_control_structure_patch,
    translate_acs,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_ACS_SPEC = {
    "behaviorDeclarations": [
        {
            "id": "ACS-001",
            "action": "execute_trade",
            "description": "Do not execute trade if amount is null",
            "ucaType": "unsafe_action",
            "hazardRefs": ["H-1"],
            "enforcement": ["python"],
            "constraints": [
                {
                    "type": "null_check",
                    "parameter": "amount",
                }
            ],
        }
    ]
}

_MULTI_CONSTRAINT_ACS_SPEC = {
    "behaviorDeclarations": [
        {
            "id": "ACS-002",
            "action": "execute_trade",
            "description": "Trade amount must be within limits",
            "ucaType": "unsafe_action",
            "hazardRefs": ["H-2"],
            "enforcement": ["opa", "python"],
            "constraints": [
                {"type": "greater_than", "parameter": "amount", "value": 500000},
                {"type": "equals", "parameter": "currency", "value": "XAU"},
            ],
        }
    ]
}

_NO_CONSTRAINTS_ACS_SPEC = {
    "behaviorDeclarations": [
        {
            "id": "ACS-003",
            "action": "market_analysis",
            "description": "Always governed",
            "ucaType": "not_provided",
            "hazardRefs": ["H-3"],
            "enforcement": ["python"],
        }
    ]
}


# ---------------------------------------------------------------------------
# translate_acs tests
# ---------------------------------------------------------------------------


class TestTranslateACS:
    def test_minimal_spec_produces_one_uca(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert len(ucas) == 1

    def test_uca_id_preserved(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert ucas[0]["id"] == "ACS-001"

    def test_uca_action_preserved(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert ucas[0]["action"] == "execute_trade"

    def test_uca_description_preserved(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert "null" in ucas[0]["description"].lower()

    def test_uca_type_mapped(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert ucas[0]["uca_type"] == "unsafe_action"

    def test_hazard_refs_preserved(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert ucas[0]["hazard_refs"] == ["H-1"]

    def test_enforcement_preserved(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        assert ucas[0]["enforcement"] == ["python"]

    def test_null_check_constraint_maps_to_is_null(self):
        ucas = translate_acs(_MINIMAL_ACS_SPEC)
        condition = ucas[0]["condition"]
        assert condition.get("operator") == "is_null"
        assert condition.get("param") == "amount"

    def test_greater_than_constraint_maps_correctly(self):
        ucas = translate_acs(_MULTI_CONSTRAINT_ACS_SPEC)
        # Multiple constraints → composite
        condition = ucas[0]["condition"]
        assert "composite" in condition

    def test_no_constraints_produces_composite_condition(self):
        ucas = translate_acs(_NO_CONSTRAINTS_ACS_SPEC)
        condition = ucas[0]["condition"]
        assert "composite" in condition

    def test_missing_behavior_declarations_raises(self):
        with pytest.raises(ValueError, match="behaviorDeclarations"):
            translate_acs({"notBehaviorDeclarations": []})

    def test_non_list_behavior_declarations_raises(self):
        with pytest.raises(ValueError):
            translate_acs({"behaviorDeclarations": "not-a-list"})

    def test_behavior_without_action_is_skipped(self):
        spec = {
            "behaviorDeclarations": [
                {"id": "ACS-NO-ACTION", "description": "no action"},
            ]
        }
        ucas = translate_acs(spec)
        assert len(ucas) == 0

    def test_auto_generated_id_when_missing(self):
        spec = {
            "behaviorDeclarations": [
                {"action": "some_action", "description": "test"},
            ]
        }
        ucas = translate_acs(spec)
        assert len(ucas) == 1
        assert ucas[0]["id"].startswith("ACS-UCA-")

    def test_aaif_uca_type_omission_maps_to_not_provided(self):
        spec = {
            "behaviorDeclarations": [
                {
                    "id": "ACS-004",
                    "action": "get_portfolio",
                    "ucaType": "omission",
                    "hazardRefs": ["H-4"],
                    "enforcement": ["python"],
                }
            ]
        }
        ucas = translate_acs(spec)
        assert ucas[0]["uca_type"] == "not_provided"

    def test_multiple_behaviors_all_translated(self):
        spec = {
            "behaviorDeclarations": [
                {
                    "id": f"ACS-{i:03d}",
                    "action": f"action_{i}",
                    "description": f"desc {i}",
                }
                for i in range(5)
            ]
        }
        ucas = translate_acs(spec)
        assert len(ucas) == 5


# ---------------------------------------------------------------------------
# acs_to_control_structure_patch tests
# ---------------------------------------------------------------------------


class TestACSToControlStructurePatch:
    def test_patch_has_system_key(self):
        patch = acs_to_control_structure_patch(_MINIMAL_ACS_SPEC)
        assert "system" in patch

    def test_patch_has_unsafe_control_actions(self):
        patch = acs_to_control_structure_patch(_MINIMAL_ACS_SPEC)
        assert "unsafe_control_actions" in patch
        assert len(patch["unsafe_control_actions"]) == 1

    def test_patch_has_hazards_from_refs(self):
        patch = acs_to_control_structure_patch(_MINIMAL_ACS_SPEC)
        hazard_ids = [h["id"] for h in patch["hazards"]]
        assert "H-1" in hazard_ids

    def test_system_name_from_metadata(self):
        spec = {
            "metadata": {"name": "My ACS System", "version": "2.0.0"},
            "behaviorDeclarations": [
                {"id": "ACS-001", "action": "act", "description": "d"}
            ],
        }
        patch = acs_to_control_structure_patch(spec)
        assert patch["system"]["name"] == "My ACS System"
        assert patch["system"]["version"] == "2.0.0"
