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

"""Contract tests for the provider_09 decision-point response schema.

The JSON Schema is the partner-facing copy of the EstateProvider seam. These
tests stop it drifting from the authoritative dataclasses in
``src/gateway/governance/seams/estate.py`` and check every response fixture
under ``tests/fixtures/provider_09/``.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import Path

import jsonschema
import pytest

from src.gateway.governance.seams import estate

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "schemas" / "provider_09" / "estate_decision_response.schema.json"
_FIXTURES = sorted((_ROOT / "tests" / "fixtures" / "provider_09").glob("*.json"))

_SEAM_TYPES = (
    estate.CloudOpsResourcePredicate,
    estate.BlastRadiusEstimate,
    estate.TopologySnapshot,
)


@pytest.fixture(scope="module")
def schema() -> dict:
    loaded = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(loaded)
    return loaded


@pytest.mark.parametrize("seam_type", _SEAM_TYPES, ids=lambda t: t.__name__)
def test_schema_properties_match_seam_dataclass(schema: dict, seam_type: type) -> None:
    definition = schema["$defs"][seam_type.__name__]
    fields = dataclasses.fields(seam_type)
    required = {
        f.name
        for f in fields
        if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
    }
    assert set(definition["properties"]) == {f.name for f in fields}
    assert set(definition["required"]) == required


@pytest.mark.parametrize(
    ("enum_type", "def_name", "prop"),
    [
        (estate.EnvironmentTier, "CloudOpsResourcePredicate", "environment_tier"),
        (estate.CriticalityTier, "CloudOpsResourcePredicate", "criticality_tier"),
        (estate.IaCDriftStatus, "CloudOpsResourcePredicate", "iac_drift_status"),
        (estate.CloudOpsReversibility, "CloudOpsResourcePredicate", "reversibility_tier"),
    ],
)
def test_schema_enums_match_seam(
    schema: dict, enum_type: type[Enum], def_name: str, prop: str
) -> None:
    assert schema["$defs"][def_name]["properties"][prop]["enum"] == [
        m.value for m in enum_type
    ]


def test_status_enum_matches_seam(schema: dict) -> None:
    assert schema["$defs"]["status"]["enum"] == [m.value for m in estate.EstateQueryStatus]


def test_fixtures_present() -> None:
    assert _FIXTURES, "expected at least one provider_09 response fixture"


@pytest.mark.parametrize("path", _FIXTURES, ids=lambda p: p.name)
def test_fixture_validates_and_hydrates(schema: dict, path: Path) -> None:
    doc = json.loads(path.read_text())
    jsonschema.Draft202012Validator(schema).validate(doc)

    by_name = {t.__name__: t for t in _SEAM_TYPES}
    method_to_type = {
        "get_resource_predicate": by_name["CloudOpsResourcePredicate"],
        "query_blast_radius": by_name["BlastRadiusEstimate"],
        "get_topology_snapshot": by_name["TopologySnapshot"],
    }
    for answer in doc["answers"]:
        seam_type = method_to_type[answer["method"]]
        # Construction proves the payload maps onto the seam with no extra keys.
        seam_type(**answer["result"])


def test_schema_rejects_unknown_field(schema: dict) -> None:
    doc = json.loads(_FIXTURES[0].read_text())
    doc["answers"][0]["result"]["confidence_vibes"] = "high"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(doc)
