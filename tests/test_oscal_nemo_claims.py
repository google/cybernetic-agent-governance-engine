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

"""The compliance artifacts credit NeMo with nothing the default posture lacks.

POAM-2026-145. NeMo Colang rails are opt-in (``CAGE_NEMO_ENABLED``, default
false). The OSCAL artifacts and the AARM report card had credited them with PII
redaction (ISO 42001 A.9.2, NIST PT-2/PT-3, SI-10), injection screening (SI-3,
AARM-V2/V5/V10) and enforcement from ``config/rails/generated_stpa_rails.co``,
a file that defines no rails while no UCA targets ``nemo``. Those controls are
deterministic and in-process. These tests read the committed artifacts, which
is what an assessor reads, so a regenerated or hand-edited artifact that puts
a claim back fails here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from src.compliance_bridge.aarm_mapper import AARM_THREAT_VECTORS
from src.gateway.governance.oscal_ssp_exporter import (
    _FTRA_SI10_DESCRIPTION,
    _FTRA_SI10_IMPL_UUID,
    _enforcement_targets,
)
from src.gateway.governance.stpa_compiler import load_control_structures

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[1]
OSCAL = REPO_ROOT / "compliance" / "oscal"
NEMO_RAILS = "config/rails/generated_stpa_rails.co"
NEMO_SSP_COMPONENT = "e5000002-0000-4000-8000-000000000002"
PII_SSP_COMPONENT = "e5000008-0000-4000-8000-000000000008"

#: Controls the deterministic in-process path implements.
DETERMINISTIC_CONTROLS = frozenset({"a.9.2", "pt-2", "pt-3", "si-10", "si-3"})

#: The qualifier every remaining NeMo mention must carry.
NEMO_QUALIFIER = "CAGE_NEMO_ENABLED=true"

COMPONENT_DEFINITIONS = (
    "component-definition.yaml",
    "sp800-53-component-definition.yaml",
)
OSCAL_ARTIFACTS = (
    "system-security-plan.yaml",
    "stpa_compiler_ssp_patch.yaml",
    *COMPONENT_DEFINITIONS,
)


def _load(name: str) -> dict[str, Any]:
    return yaml.safe_load((OSCAL / name).read_text(encoding="utf-8"))


def _flat(text: str) -> str:
    return " ".join(text.split())


def _production_targets() -> set[str]:
    """Enforcement targets of the control structure the exporter exports by default."""
    paths = [
        REPO_ROOT / "config" / "stpa_control_structure.yaml",
        *sorted((REPO_ROOT / "src").glob("cage_*/config/stpa/*.yaml")),
    ]
    return _enforcement_targets(load_control_structures(paths).unsafe_control_actions)


def _requirements(component: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        req
        for impl in component.get("control-implementations") or []
        for req in impl.get("implemented-requirements") or []
    ]


@pytest.mark.parametrize("artifact", OSCAL_ARTIFACTS)
def test_rails_file_is_cited_only_while_a_uca_targets_nemo(artifact: str) -> None:
    text = (OSCAL / artifact).read_text(encoding="utf-8")
    assert "nemo" in _production_targets() or NEMO_RAILS not in text


def test_ssp_credits_pii_controls_to_in_process_redaction_not_nemo() -> None:
    ssp = _load("system-security-plan.yaml")["system-security-plan"]
    components = {c["uuid"]: c for c in ssp["system-implementation"]["components"]}

    nemo = components[NEMO_SSP_COMPONENT]
    assert nemo["status"]["state"] != "operational"
    assert not {"A.9.2", "PT-2", "PT-3"} & set(
        nemo["purpose"].replace("/", " ").split()
    )

    pii = components[PII_SSP_COMPONENT]
    assert pii["status"]["state"] == "operational"
    assert "A.9.2" in pii["purpose"] and "PT-2/PT-3" in pii["purpose"]
    assert "nemo" not in pii["title"].lower()


def _poam_is_open(poam_id: str) -> bool:
    """True while *poam_id* has a row in the POA&M's Open Findings tables."""
    text = (REPO_ROOT / "docs" / "POAM.md").read_text(encoding="utf-8")
    open_findings = text.split("## Open Findings", 1)[1].split("## Closed Findings", 1)[
        0
    ]
    return f"| {poam_id} |" in open_findings


@pytest.mark.parametrize("poam_id", ["POAM-2026-146", "POAM-2026-147"])
def test_pii_component_discloses_its_open_poams(poam_id: str) -> None:
    """The A.9.2 component is operational, so its open defects ride with the claim.

    An assessor who reads the POA&M and the SSP together must find each open
    item against this component on the component itself. Closing the POAM is
    what releases the caveat.
    """
    if not _poam_is_open(poam_id):
        pytest.skip(f"{poam_id} is closed")
    ssp = _load("system-security-plan.yaml")["system-security-plan"]
    pii = next(
        c
        for c in ssp["system-implementation"]["components"]
        if c["uuid"] == PII_SSP_COMPONENT
    )
    assert poam_id in {
        p["value"] for p in pii["props"] if p["name"].startswith("poam-gap")
    }
    assert poam_id in pii["purpose"]

    if poam_id == "POAM-2026-147":
        # The fail-open qualifies the fail-closed claim wherever it is made.
        assert poam_id in pii["status"].get("remarks", "")
        assert poam_id in pii["description"]
        claims = [
            (artifact, _flat(req["description"]))
            for artifact in COMPONENT_DEFINITIONS
            for component in _load(artifact)["component-definition"]["components"]
            for req in _requirements(component)
            if "Presidio" in req["description"]
            and (
                "fails closed" in _flat(req["description"])
                or "failing closed" in _flat(req["description"])
            )
        ]
        assert claims, "no statement makes the Presidio fail-closed claim"
        for artifact, text in claims:
            assert poam_id in text, f"{artifact}: fail-closed claim without {poam_id}"


@pytest.mark.parametrize("artifact", COMPONENT_DEFINITIONS)
def test_deterministic_controls_are_not_credited_to_nemo(artifact: str) -> None:
    for component in _load(artifact)["component-definition"]["components"]:
        for req in _requirements(component):
            if req["control-id"].lower() not in DETERMINISTIC_CONTROLS:
                continue
            where = f"{component['title']} / {req['control-id']}"
            assert "nemo" not in component["title"].lower(), where
            text = _flat(req["description"] + " " + req.get("remarks", ""))
            assert "NeMo" not in text or NEMO_QUALIFIER in text, where


def _committed_ftra_si10(artifact: str) -> str:
    for component in _load(artifact)["component-definition"]["components"]:
        for req in _requirements(component):
            if req.get("uuid") == _FTRA_SI10_IMPL_UUID:
                return str(req["description"])
    raise AssertionError(f"FTRA SI-10 statement not found in {artifact}")


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(_FTRA_SI10_DESCRIPTION, id="exporter-seed"),
        pytest.param(
            _committed_ftra_si10(COMPONENT_DEFINITIONS[0]), id="component-definition"
        ),
        pytest.param(_committed_ftra_si10(COMPONENT_DEFINITIONS[1]), id="sp800-53"),
    ],
)
def test_ftra_si10_says_uca7_compiles_only_to_opa(statement: str) -> None:
    text = _flat(statement)
    assert NEMO_RAILS not in text
    assert "generated_semantic_policy.txt" not in text
    assert "UCA-7 compiles only to OPA" in text
    assert "NeMo" not in text or NEMO_QUALIFIER in text


@pytest.mark.parametrize("vector_id", sorted(AARM_THREAT_VECTORS))
def test_aarm_vectors_cite_default_path_code(vector_id: str) -> None:
    vector = AARM_THREAT_VECTORS[vector_id]
    optional = [
        path
        for path in vector.implementation_files
        if path.startswith(("src/integrations/nemo/", "config/rails/"))
    ]
    assert not optional, f"{vector_id} cites optional NeMo code: {optional}"
    assert "NeMo" not in vector.notes or NEMO_QUALIFIER in vector.notes
