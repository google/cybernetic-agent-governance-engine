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

"""Tests for src/gateway/governance/ingress/oscal_adapter.py — OSCAL → UCA YAML round-trip."""

from __future__ import annotations

import pytest

from src.gateway.governance.ingress.oscal_adapter import (
    oscal_to_control_structure_patch,
    translate_oscal,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_OSCAL_DOC = {
    "oscal-version": "1.1.2",
    "component-definition": {
        "metadata": {
            "title": "Test Component",
            "version": "1.0.0",
            "oscal-version": "1.1.2",
        },
        "components": [
            {
                "uuid": "comp-001",
                "title": "Governance Gateway",
                "type": "software",
                "control-implementations": [
                    {
                        "uuid": "impl-001",
                        "source": "https://csrc.nist.gov/",
                        "implemented-requirements": [
                            {
                                "uuid": "req-001-abcd",
                                "control-id": "ac-3",
                                "description": "Access enforcement via OPA RBAC",
                                "props": [
                                    {
                                        "name": "implementation-status",
                                        "value": "implemented",
                                    },
                                    {
                                        "name": "enforcement-target",
                                        "value": "opa,python",
                                    },
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
    },
}

_PLANNED_STATUS_OSCAL_DOC = {
    "oscal-version": "1.1.2",
    "component-definition": {
        "metadata": {"title": "Test", "oscal-version": "1.1.2"},
        "components": [
            {
                "title": "Test Component",
                "control-implementations": [
                    {
                        "implemented-requirements": [
                            {
                                "uuid": "req-002-efgh",
                                "control-id": "si-10",
                                "description": "Input validation planned",
                                "props": [
                                    {
                                        "name": "implementation-status",
                                        "value": "planned",
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        ],
    },
}

_OSCAL_WITH_STATEMENTS = {
    "oscal-version": "1.1.2",
    "component-definition": {
        "metadata": {"title": "Test", "oscal-version": "1.1.2"},
        "components": [
            {
                "title": "Test Component",
                "control-implementations": [
                    {
                        "implemented-requirements": [
                            {
                                "uuid": "req-003-ijkl",
                                "control-id": "au-12",
                                "description": "Audit record generation",
                                "statements": [
                                    {"description": "All API calls are logged"},
                                    {"description": "Logs include user identity"},
                                ],
                            }
                        ]
                    }
                ],
            }
        ],
    },
}

_NO_OSCAL_VERSION_DOC = {
    "component-definition": {
        "metadata": {"title": "No version"},
        "components": [],
    }
}

_MISSING_ENFORCEMENT_TARGET_DOC = {
    "oscal-version": "1.1.2",
    "component-definition": {
        "metadata": {"title": "Test", "oscal-version": "1.1.2"},
        "components": [
            {
                "title": "Test Component",
                "control-implementations": [
                    {
                        "implemented-requirements": [
                            {
                                "uuid": "req-004-mnop",
                                "control-id": "sc-8",
                                "description": "Transmission confidentiality",
                                # No enforcement-target prop
                            }
                        ]
                    }
                ],
            }
        ],
    },
}


# ---------------------------------------------------------------------------
# translate_oscal tests
# ---------------------------------------------------------------------------


class TestTranslateOSCAL:
    def test_missing_oscal_version_raises(self):
        with pytest.raises(ValueError, match="oscal-version"):
            translate_oscal(_NO_OSCAL_VERSION_DOC)

    def test_minimal_doc_produces_one_uca(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        assert len(ucas) == 1

    def test_uca_id_contains_control_id(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        assert "AC_3" in ucas[0]["id"]

    def test_uca_action_maps_from_control_id(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        assert ucas[0]["action"] == "access_enforcement"

    def test_implemented_status_maps_to_unsafe_action(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        assert ucas[0]["uca_type"] == "unsafe_action"

    def test_planned_status_maps_to_not_provided(self):
        ucas = translate_oscal(_PLANNED_STATUS_OSCAL_DOC)
        assert ucas[0]["uca_type"] == "not_provided"

    def test_enforcement_target_prop_parsed(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        enforcement = ucas[0]["enforcement"]
        assert "opa" in enforcement
        assert "python" in enforcement

    def test_missing_enforcement_target_defaults_to_python(self):
        ucas = translate_oscal(_MISSING_ENFORCEMENT_TARGET_DOC)
        assert ucas[0]["enforcement"] == ["python"]

    def test_hazard_refs_contain_control_id(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        assert "AC_3" in ucas[0]["hazard_refs"]

    def test_statements_joined_into_composite_condition(self):
        ucas = translate_oscal(_OSCAL_WITH_STATEMENTS)
        condition = ucas[0]["condition"]
        assert "composite" in condition
        assert "All API calls are logged" in condition["composite"]

    def test_description_used_as_condition_when_no_statements(self):
        ucas = translate_oscal(_MINIMAL_OSCAL_DOC)
        condition = ucas[0]["condition"]
        assert "composite" in condition

    def test_unknown_control_id_still_produces_uca(self):
        doc = {
            "oscal-version": "1.1.2",
            "component-definition": {
                "metadata": {"title": "Test", "oscal-version": "1.1.2"},
                "components": [
                    {
                        "title": "Test",
                        "control-implementations": [
                            {
                                "implemented-requirements": [
                                    {
                                        "uuid": "req-unknown",
                                        "control-id": "zz-999",
                                        "description": "Unknown control",
                                    }
                                ]
                            }
                        ],
                    }
                ],
            },
        }
        ucas = translate_oscal(doc)
        # Unknown control-id should still produce a UCA (logged as warning, not hard failure)
        assert len(ucas) == 1
        assert "ZZ_999" in ucas[0]["hazard_refs"]

    def test_requirement_without_control_id_is_skipped(self):
        doc = {
            "oscal-version": "1.1.2",
            "component-definition": {
                "metadata": {"title": "Test", "oscal-version": "1.1.2"},
                "components": [
                    {
                        "title": "Test",
                        "control-implementations": [
                            {
                                "implemented-requirements": [
                                    {
                                        "uuid": "req-no-ctrl",
                                        "description": "No control-id",
                                    }
                                ]
                            }
                        ],
                    }
                ],
            },
        }
        ucas = translate_oscal(doc)
        assert len(ucas) == 0


# ---------------------------------------------------------------------------
# oscal_to_control_structure_patch tests
# ---------------------------------------------------------------------------


class TestOSCALToControlStructurePatch:
    def test_patch_has_system_key(self):
        patch = oscal_to_control_structure_patch(_MINIMAL_OSCAL_DOC)
        assert "system" in patch

    def test_patch_system_name_from_metadata_title(self):
        patch = oscal_to_control_structure_patch(_MINIMAL_OSCAL_DOC)
        assert patch["system"]["name"] == "Test Component"

    def test_patch_has_hazards(self):
        patch = oscal_to_control_structure_patch(_MINIMAL_OSCAL_DOC)
        assert len(patch["hazards"]) >= 1

    def test_patch_has_oscal_version(self):
        patch = oscal_to_control_structure_patch(_MINIMAL_OSCAL_DOC)
        assert patch["_oscal_version"] == "1.1.2"
