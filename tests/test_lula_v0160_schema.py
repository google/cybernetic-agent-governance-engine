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

"""Unit tests for Lula v0.16.0 validation schema, Rego invariants, and verdict enforcement (R-12, F-98, F-106)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml

from scripts.verify_lula_assessment_results import (
    main as verify_lula_cli_main,
)
from scripts.verify_lula_assessment_results import (
    verify_assessment_results_data,
    verify_assessment_results_file,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parent.parent
LULA_DIR = REPO_ROOT / "compliance" / "lula"
SCHEMA_PATH = LULA_DIR / "schemas" / "lula_v0160_validation.schema.json"


def _all_lula_files() -> list[Path]:
    return sorted(LULA_DIR.glob("lula-validation-*.yaml"))


def test_all_33_lula_validation_manifests_exist() -> None:
    files = _all_lula_files()
    assert len(files) == 33, f"Expected 33 Lula validation files, found {len(files)}"


@pytest.mark.parametrize(
    "lula_path",
    _all_lula_files(),
    ids=lambda p: p.name,
)
def test_lula_manifest_conforms_to_v0160_schema_and_rego_invariants(
    lula_path: Path,
) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)

    doc = yaml.safe_load(lula_path.read_text(encoding="utf-8"))
    assert "component-definition" in doc, (
        f"{lula_path.name} missing component-definition"
    )
    resources = doc["component-definition"]["back-matter"]["resources"]
    assert len(resources) >= 1, f"{lula_path.name} has no back-matter resources"

    for res in resources:
        res_uuid = res["uuid"]
        payload = yaml.safe_load(res["description"])
        errors = list(validator.iter_errors(payload))
        assert not errors, (
            f"{lula_path.name} ({res_uuid}) failed Lula v0.16.0 schema validation: "
            + "; ".join(e.message for e in errors)
        )

        # Verify domain resource names
        dom = payload["domain"]
        if dom["type"] == "kubernetes":
            k8s_resources = dom["kubernetes-spec"]["resources"]
            assert len(k8s_resources) >= 1, (
                f"{lula_path.name} ({res_uuid}) must declare at least 1 kubernetes resource"
            )
            resource_names = []
            for kr in k8s_resources:
                resource_names.append(kr["name"])
                rule = kr["resource-rule"]
                assert "namespaces" in rule and len(rule["namespaces"]) >= 1, (
                    f"{lula_path.name} ({res_uuid}) resource {kr['name']} missing explicit namespaces in resource-rule"
                )
        elif dom["type"] == "api":
            api_requests = dom["api-spec"]["requests"]
            assert len(api_requests) >= 1, (
                f"{lula_path.name} ({res_uuid}) must declare at least 1 api request"
            )
            resource_names = [req["name"] for req in api_requests]
        else:
            pytest.fail(f"Unexpected domain type {dom['type']} in {lula_path.name}")

        # Verify Rego invariants:
        # 1. Exactly one `validate if {` rule (no multiple `validate if` rules which act as OR)
        # 2. No bare `validate := true` stub
        # 3. Every declared resource input has `count(input...) > 0`
        rego = payload["provider"]["opa-spec"]["rego"]
        non_comment_lines = [
            line
            for line in rego.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        clean_rego = "\n".join(non_comment_lines)

        validate_heads = re.findall(r"^\s*validate\b", clean_rego, flags=re.MULTILINE)
        assert len(validate_heads) == 1, (
            f"{lula_path.name} ({res_uuid}) must define exactly 1 `validate` rule "
            f"(found {len(validate_heads)})"
        )
        assert re.search(r"^\s*validate\s+if\s*\{", clean_rego, flags=re.MULTILINE), (
            f"{lula_path.name} ({res_uuid}) must use `validate if {{ ... }}`"
        )

        for rname in resource_names:
            pattern_dot = f"count(input.{rname}) > 0"
            pattern_bracket = f'count(input["{rname}"]) > 0'
            assert pattern_dot in clean_rego or pattern_bracket in clean_rego, (
                f"{lula_path.name} ({res_uuid}) must assert non-empty input via "
                f"`{pattern_dot}` or `{pattern_bracket}`"
            )


def test_ac3_and_sc4_target_in_state_opa_resources_not_deleted_configmap() -> None:
    for fname in ("lula-validation-ac3.yaml", "lula-validation-sc4.yaml"):
        raw = (LULA_DIR / fname).read_text(encoding="utf-8")
        doc = yaml.safe_load(raw)
        desc = doc["component-definition"]["back-matter"]["resources"][0]["description"]
        assert "opa-compliance-status" not in desc, (
            f"{fname} must not target deleted ConfigMap/opa-compliance-status"
        )
        assert "opa-service" in desc
        assert "opa-policies" in desc


def test_assessment_results_verdict_parser_rejects_not_satisfied_and_zero_observations(
    tmp_path: Path,
) -> None:
    # 1. Satisfied fixture passes
    satisfied_doc = {
        "assessment-results": {
            "results": [
                {
                    "findings": [
                        {
                            "uuid": "f-1",
                            "target": {
                                "target-id": "ac-2",
                                "status": {"state": "satisfied"},
                            },
                        }
                    ],
                    "observations": [
                        {
                            "uuid": "obs-1",
                            "relevant-evidence": [
                                {"description": "Result: satisfied\n"}
                            ],
                        }
                    ],
                }
            ]
        }
    }
    ok, errors = verify_assessment_results_data(satisfied_doc)
    assert ok is True, errors

    satisfied_file = tmp_path / "satisfied.yaml"
    satisfied_file.write_text(yaml.safe_dump(satisfied_doc), encoding="utf-8")
    assert verify_lula_cli_main([str(satisfied_file)]) == 0

    # 2. not-satisfied finding fails closed
    not_satisfied_doc = {
        "assessment-results": {
            "results": [
                {
                    "findings": [
                        {
                            "uuid": "f-2",
                            "target": {
                                "target-id": "ac-3",
                                "status": {"state": "not-satisfied"},
                            },
                        }
                    ],
                    "observations": [
                        {
                            "uuid": "obs-2",
                            "relevant-evidence": [
                                {"description": "Result: not-satisfied\n"}
                            ],
                        }
                    ],
                }
            ]
        }
    }
    ok, errors = verify_assessment_results_data(not_satisfied_doc)
    assert ok is False
    assert any("not-satisfied" in e for e in errors)

    not_satisfied_file = tmp_path / "not-satisfied.yaml"
    not_satisfied_file.write_text(yaml.safe_dump(not_satisfied_doc), encoding="utf-8")
    assert verify_lula_cli_main([str(not_satisfied_file)]) == 1

    # 3. lula-validation-error observation fails closed
    error_doc = {
        "assessment-results": {
            "results": [
                {
                    "findings": [
                        {
                            "uuid": "f-3",
                            "target": {
                                "target-id": "sc-8",
                                "status": {"state": "lula-validation-error"},
                            },
                        }
                    ],
                    "observations": [
                        {
                            "uuid": "obs-3",
                            "remarks": "lula-validation-error: schema mismatch",
                        }
                    ],
                }
            ]
        }
    }
    ok, errors = verify_assessment_results_data(error_doc)
    assert ok is False
    assert any("lula-validation-error" in e for e in errors)

    # 4. Zero observations fails closed
    zero_obs_doc = {
        "assessment-results": {
            "results": [
                {
                    "findings": [],
                    "observations": [],
                }
            ]
        }
    }
    ok, errors = verify_assessment_results_data(zero_obs_doc)
    assert ok is False
    assert any("0 observations" in e for e in errors)

    # 5. Committed compliance/lula/assessment-results.yaml (which contains historical
    # not-satisfied entries) is rejected by the verifier
    committed_ar = LULA_DIR / "assessment-results.yaml"
    if committed_ar.is_file():
        ok_committed, errs_committed = verify_assessment_results_file(committed_ar)
        assert ok_committed is False
        assert any("not-satisfied" in e for e in errs_committed)


def test_ra5_never_targets_hollow_network_policy_shell() -> None:
    """F-109 regression guard: RA-5 must assert an active scanner CronJob, never an orphan NetworkPolicy."""
    ra5_raw = (LULA_DIR / "lula-validation-ra5.yaml").read_text(encoding="utf-8")
    assert "# cage-status: planned" in ra5_raw
    doc = yaml.safe_load(ra5_raw)
    desc = doc["component-definition"]["back-matter"]["resources"][0]["description"]
    assert "trivy-scanner-dns-egress" not in desc
    assert "networkpolicies" not in desc
    assert "cronjobs" in desc

    netpol_tf = (
        REPO_ROOT / "infra" / "targets" / "gcp-gke" / "network_policy.tf"
    ).read_text(encoding="utf-8")
    assert "trivy_scanner_dns_egress" not in netpol_tf
    assert "trivy_scanner_egress_fqdn" not in netpol_tf


def test_au12_asserts_blocking_evidence_custody_not_langfuse() -> None:
    """R-2 / F-84 regression guard: AU-12 Lula check must assert blocking hash-chain + WORM cold-store, never Langfuse."""
    au12_raw = (LULA_DIR / "lula-validation-au12.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(au12_raw)
    resources = doc["component-definition"]["back-matter"]["resources"]
    assert len(resources) == 1
    desc = resources[0]["description"]
    assert "langfuse" not in desc.lower()
    assert '"EVIDENCE_CHAIN_BLOCKING", "true"' in desc
    assert "EVIDENCE_COLD_STORE" in desc
