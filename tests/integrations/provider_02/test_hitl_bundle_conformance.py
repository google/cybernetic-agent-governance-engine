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

"""Hermetic conformance for the Provider 02 HITL approval-path bundle.

Checks both the bundle the adapter emits at runtime and the committed
``06_hitl_approval.json`` fixture against the vendored Provider 02 schema and
the three HITL interop invariants agreed with the partner (stateHash format,
topology membership, causal parentage). The over-the-wire counterpart is
``test_tc06_hitl_approval`` in ``test_staging_e2e.py``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, RefResolver

from tests.integrations.provider_02.hitl_bundle import (
    FIXTURE_PATH,
    build_hitl_approval_bundle,
    hitl_invariant_violations,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

SCHEMAS_DIR = Path(__file__).resolve().parents[3] / "schemas" / "provider_02"


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(
        (SCHEMAS_DIR / "attestation_bundle.schema.json").read_text(encoding="utf-8")
    )
    step_schema = json.loads(
        (SCHEMAS_DIR / "project_bundle_step.schema.json").read_text(encoding="utf-8")
    )
    resolver = RefResolver.from_schema(
        schema, store={"urn:cage:governance:v1:step-entry": step_schema}
    )
    return Draft202012Validator(
        schema, resolver=resolver, format_checker=Draft202012Validator.FORMAT_CHECKER
    )


def _bundles() -> dict[str, dict[str, Any]]:
    return {
        "runtime": build_hitl_approval_bundle(),
        "fixture": json.loads(FIXTURE_PATH.read_text(encoding="utf-8")),
    }


@pytest.mark.parametrize("source", ["runtime", "fixture"])
def test_hitl_bundle_validates_against_schema(
    source: str, validator: Draft202012Validator
) -> None:
    errors = [e.message for e in validator.iter_errors(_bundles()[source])]
    assert not errors, f"{source} HITL bundle failed schema validation: {errors}"


@pytest.mark.parametrize("source", ["runtime", "fixture"])
def test_hitl_bundle_satisfies_interop_invariants(source: str) -> None:
    violations = hitl_invariant_violations(_bundles()[source])
    assert not violations, f"{source} HITL bundle violations: {violations}"


def test_invariant_check_rejects_uppercase_state_hash() -> None:
    """The checker itself must fail closed on the pre-fix stateHash defect."""
    bundle = copy.deepcopy(build_hitl_approval_bundle())
    hitl = next(s for s in bundle["steps"] if s["nodeName"] == "hitl_interrupt")
    hitl["stateHash"] = hitl["stateHash"].upper()
    assert any("stateHash" in v for v in hitl_invariant_violations(bundle))


def test_invariant_check_rejects_trader_bypassing_hitl() -> None:
    """governed_trader parented directly on safety_check is the pre-fix lineage."""
    bundle = copy.deepcopy(build_hitl_approval_bundle())
    by_node = {s["nodeName"]: s for s in bundle["steps"]}
    by_node["governed_trader"]["parentStepIds"] = [by_node["safety_check"]["stepId"]]
    assert any("governed_trader" in v for v in hitl_invariant_violations(bundle))
