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
"""Unit and planted-drift tests for scripts/check_mechanism_references.py (POAM-2026-222)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_mechanism_references import (
    MechanismReferenceError,
    check_mechanism_references,
    main,
    verify_mechanism_references,
)
from scripts.measurement_inventory import CorpusFloorError

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _build_valid_synth_repo(root: Path) -> Path:
    """Create a self-consistent synthetic repository tree passing all four mechanism checks."""
    # 1. Domain package directory (must NOT be misclassified as a Prometheus metric)
    (root / "src" / "cage_finance").mkdir(parents=True)
    (root / "src" / "cage_finance" / "__init__.py").write_text("", encoding="utf-8")

    # 2. Gateway Prometheus collector registrations
    gw_metrics = root / "src" / "gateway" / "metrics.py"
    gw_metrics.parent.mkdir(parents=True)
    gw_metrics.write_text(
        "from prometheus_client import Counter, Histogram\n"
        "GATED_REQ = Counter('cage_gateway_gated_requests_total', 'doc', ['outcome'])\n"
        "LOOP_LAG = Histogram('cage_event_loop_lag_seconds', 'doc')\n",
        encoding="utf-8",
    )

    # 3. Compliance-bridge FastAPI route + Pydantic score model
    cb_main = root / "src" / "compliance_bridge" / "main.py"
    cb_main.parent.mkdir(parents=True)
    cb_main.write_text(
        "from fastapi import FastAPI\n"
        "from pydantic import BaseModel\n"
        "app = FastAPI()\n"
        "class ComplianceMetrics(BaseModel):\n"
        "    safety_rate: float | None = None\n"
        "    total_traces: int = 0\n"
        "    evidence_age_seconds: float = 0.0\n"
        "@app.get('/v1/metrics/{control_id}', response_model=ComplianceMetrics)\n"
        "async def get_metrics(control_id: str) -> ComplianceMetrics:\n"
        "    return ComplianceMetrics()\n",
        encoding="utf-8",
    )

    # 4. Terraform Cloud Monitoring alert policy
    tf_alerts = root / "infra" / "targets" / "gcp-gke" / "metrics_alerting.tf"
    tf_alerts.parent.mkdir(parents=True)
    tf_alerts.write_text(
        'variable "cage_deployment_region" {\n'
        "  type = string\n"
        "}\n"
        'resource "google_monitoring_alert_policy" "gateway_sustained_refusal_ratio" {\n'
        '  display_name          = "Sustained Refusal Ratio"\n'
        "  notification_channels = var.channels\n"
        "  conditions {\n"
        "    condition_prometheus_query_language {\n"
        '      query = "rate(cage_gateway_gated_requests_total{outcome=\\"blocked\\"}[5m]) > 0.95"\n'
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # 5. Lula validation manifests
    lula_dir = root / "compliance" / "lula"
    lula_dir.mkdir(parents=True)
    (lula_dir / "lula-validation-a52.yaml").write_text(
        "domain:\n"
        "  type: api\n"
        "  api-spec:\n"
        "    requests:\n"
        "      - name: langfuse_metrics_a52\n"
        "        url: http://compliance-bridge.governance-stack.svc.cluster.local/v1/metrics/A.5.2\n"
        "provider:\n"
        "  type: opa\n"
        "  opa-spec:\n"
        "    rego: |\n"
        "      package lula\n"
        '      metrics_doc := object.get(input.langfuse_metrics_a52, "response", input.langfuse_metrics_a52)\n'
        "      validate if {\n"
        "        metrics_doc.safety_rate >= 0.99\n"
        "        metrics_doc.evidence_age_seconds < 172800\n"
        "      }\n",
        encoding="utf-8",
    )
    (lula_dir / "lula-validation-cm6.yaml").write_text(
        "domain:\n  type: kubernetes\nprovider:\n  type: opa\n",
        encoding="utf-8",
    )

    # 6. OSCAL YAML & in-scope architecture documentation
    oscal_file = root / "compliance" / "oscal" / "sp800-53-component-definition.yaml"
    oscal_file.parent.mkdir(parents=True)
    oscal_file.write_text(
        "component-definition:\n"
        "  remarks: >-\n"
        "    Monitored via google_monitoring_alert_policy.gateway_sustained_refusal_ratio\n"
        "    over cage_gateway_gated_requests_total and cage_event_loop_lag_seconds_count\n"
        "    for domain package cage_finance.\n",
        encoding="utf-8",
    )

    arch_doc = root / "docs" / "architecture" / "GATEWAY_ARCHITECTURE.md"
    arch_doc.parent.mkdir(parents=True)
    arch_doc.write_text(
        "# Gateway Architecture\n\n"
        "Domain plugin `cage_finance` runs under `var.cage_deployment_region`.\n"
        "Alert `google_monitoring_alert_policy.gateway_sustained_refusal_ratio` watches\n"
        "`cage_gateway_gated_requests_total{outcome}`.\n",
        encoding="utf-8",
    )

    # 7. docs/POAM.md & THRESHOLD_TRACEABILITY_MATRIX.md (Open signing hold)
    poam_doc = root / "docs" / "POAM.md"
    poam_doc.write_text(
        "# POA&M\n\n"
        "## Open Items\n\n"
        "| ID | Control | Weakness | Risk | Target |\n"
        "|---|---|---|---|---|\n"
        "| POAM-2026-222 | CA-7 | TTM monitoring column cites un-emitted telemetry | Moderate | 2026-12-31 |\n\n"
        "### POAM-2026-222: Threshold Traceability Matrix Monitoring Column\n\n"
        "**Status:** Open\n",
        encoding="utf-8",
    )

    ttm_doc = (
        root / "compliance" / "risk_acceptance" / "THRESHOLD_TRACEABILITY_MATRIX.md"
    )
    ttm_doc.parent.mkdir(parents=True)
    ttm_doc.write_text(
        "# CAGE Threshold Traceability Matrix\n\n"
        "> **⚠️ Evidence Withdrawal and Signing Hold (2026-11-15, `POAM-2026-222`):**\n"
        "> Withdrawn pending per-row disposition.\n"
        ">\n"
        "> **Signing hold:** RA-001 through RA-004 and §6 must not be signed under `POAM-2026-222`.\n\n"
        "## 1. Document Purpose and Scope\n\n"
        "### 2.1 Full Threshold Registry Table\n\n"
        "| Threshold ID | Threshold Name | Lula Validation | Langfuse Metric |\n"
        "|---|---|---|---|\n"
        "| **THR-FIN-003** | Max Sell Fraction | `lula-validation-cm6.yaml` | `cage.stpa.fin1_violations` (counter) |\n\n"
        "## 5. Threshold Risk Acceptance Register\n\n"
        "### 5.1 RA-001: Sample\n"
        "| Field | Value |\n|---|---|\n"
        "| **Who Accepted** | Authorizing Official (AO) — [SIGNATURE PENDING] |\n"
        "| **Acceptance Date** | Pending AO signature |\n\n"
        "### 5.2 RA-002: Consensus\n"
        "| Field | Value |\n|---|---|\n"
        "| **Who Accepted** | Authorizing Official (AO) — [SIGNATURE PENDING] |\n"
        "| **Acceptance Date** | Pending AO signature |\n\n"
        "### 5.3 RA-003: SBOM\n"
        "| Field | Value |\n|---|---|\n"
        "| **Who Accepted** | Authorizing Official (AO) — [SIGNATURE PENDING] |\n"
        "| **Acceptance Date** | Pending AO signature |\n\n"
        "### 5.4 RA-004: Single-Node OPA\n"
        "| Field | Value |\n|---|---|\n"
        "| **Who Accepted** | ISSO (interim acceptance) — AO review required for ATO |\n"
        "| **Acceptance Date** | 2026-03-06 (interim) |\n\n"
        "## 6. Approval Block\n\n"
        "> **Signing hold:** Held under `POAM-2026-222`.\n\n"
        "```\n"
        "Date: 2026-03-06\n"
        "[SIGNATURE REQUIRED — PENDING AO APPROVAL]\n"
        "│ Name:    _______________________________  Date: ___________________________  │\n"
        "│ Signature: _____________________________                                     │\n"
        "│ This acceptance expires: _________________________                           │\n"
        "```\n\n"
        "## Appendix B: Langfuse Metric Naming Convention\n\n"
        "- All `cage.stpa.*` metrics\n",
        encoding="utf-8",
    )
    return root


def test_live_repository_passes_mechanism_reference_gate_with_zero_waivers() -> None:
    """Live repository passes check_mechanism_references with exit code 0 and zero waivers."""
    snapshot = verify_mechanism_references()
    assert len(snapshot.prometheus_metrics) >= 42
    assert main(["--verbose"]) == 0


def test_clean_synthetic_repo_passes_with_no_floors(tmp_path: Path) -> None:
    """Baseline synthetic repository passes all mechanism checks when floors are disabled."""
    synth = _build_valid_synth_repo(tmp_path)
    assert check_mechanism_references(synth, enforce_floors=False) == []
    assert main(["--repo-root", str(synth), "--no-floors"]) == 0


def test_negative_a_corpus_floor_drop_fails_closed(tmp_path: Path) -> None:
    """(a) Synthetic repository below corpus floors fails closed when floors are enforced."""
    synth = _build_valid_synth_repo(tmp_path)
    with pytest.raises(CorpusFloorError, match="corpus floor breach"):
        verify_mechanism_references(synth, enforce_floors=True)
    assert main(["--repo-root", str(synth)]) == 1


def test_negative_b_alert_policy_and_dashboard_phantom_metric_fails_closed(
    tmp_path: Path,
) -> None:
    """(b) Alert policy or infra dashboard referencing `cage_phantom_requests_total` fails closed."""
    synth = _build_valid_synth_repo(tmp_path)
    tf_alerts = synth / "infra" / "targets" / "gcp-gke" / "metrics_alerting.tf"
    tf_alerts.write_text(
        tf_alerts.read_text(encoding="utf-8")
        + '\nresource "google_monitoring_alert_policy" "phantom_alert" {\n'
        '  display_name = "Phantom"\n'
        "  conditions {\n"
        "    condition_prometheus_query_language {\n"
        '      query = "rate(cage_phantom_requests_total[5m]) > 0"\n'
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    with pytest.raises(MechanismReferenceError, match="cage_phantom_requests_total"):
        verify_mechanism_references(synth, enforce_floors=False)
    assert main(["--repo-root", str(synth), "--no-floors"]) == 1

    # Also verify JSON dashboard detection in infra/
    dashboard = synth / "infra" / "dashboards" / "overview.json"
    dashboard.parent.mkdir(parents=True)
    dashboard.write_text(
        '{"widgets": [{"promqlQuery": {"query": "sum(cage_phantom_dashboard_total)"}}]}',
        encoding="utf-8",
    )
    violations = check_mechanism_references(synth, enforce_floors=False)
    assert any("cage_phantom_dashboard_total" in v.detail for v in violations)


def test_negative_c_lula_manifest_nonexistent_bridge_field_fails_closed(
    tmp_path: Path,
) -> None:
    """(c) Lula manifest asserting on a nonexistent compliance-bridge JSON field fails closed."""
    synth = _build_valid_synth_repo(tmp_path)
    lula_a52 = synth / "compliance" / "lula" / "lula-validation-a52.yaml"
    lula_a52.write_text(
        lula_a52.read_text(encoding="utf-8").replace(
            "metrics_doc.safety_rate >= 0.99",
            "metrics_doc.nonexistent_bridge_score >= 0.99",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MechanismReferenceError, match="nonexistent_bridge_score"):
        verify_mechanism_references(synth, enforce_floors=False)
    assert main(["--repo-root", str(synth), "--no-floors"]) == 1


def test_negative_d_oscal_and_doc_nonexistent_metric_or_alert_policy_fails_closed(
    tmp_path: Path,
) -> None:
    """(d) OSCAL or in-scope Markdown citing phantom `cage_*` metric or alert policy fails closed."""
    # Case d1: OSCAL cites phantom metric and phantom alert policy
    synth_oscal = _build_valid_synth_repo(tmp_path / "oscal_case")
    oscal_file = (
        synth_oscal / "compliance" / "oscal" / "sp800-53-component-definition.yaml"
    )
    oscal_file.write_text(
        "component-definition:\n"
        "  remarks: >-\n"
        "    Cites cage_phantom_refusals_total and google_monitoring_alert_policy.nonexistent.\n",
        encoding="utf-8",
    )
    violations_oscal = check_mechanism_references(synth_oscal, enforce_floors=False)
    details_oscal = "\n".join(v.detail for v in violations_oscal)
    assert "cage_phantom_refusals_total" in details_oscal
    assert "google_monitoring_alert_policy.nonexistent" in details_oscal

    # Case d2: In-scope Markdown doc cites phantom counter and phantom alert policy
    synth_doc = _build_valid_synth_repo(tmp_path / "doc_case")
    arch_doc = synth_doc / "docs" / "architecture" / "GATEWAY_ARCHITECTURE.md"
    arch_doc.write_text(
        "# Gateway\n\n"
        "Tracks `cage_phantom_refusals_total` and `google_monitoring_alert_policy.nonexistent`.\n",
        encoding="utf-8",
    )
    violations_doc = check_mechanism_references(synth_doc, enforce_floors=False)
    details_doc = "\n".join(v.detail for v in violations_doc)
    assert "cage_phantom_refusals_total" in details_doc
    assert "google_monitoring_alert_policy.nonexistent" in details_doc


def test_negative_e_ra001_or_approval_block_signed_while_poam_222_open_fails_closed(
    tmp_path: Path,
) -> None:
    """(e) Signing RA-001 (or §6 Approval Block) while POAM-2026-222 is Open fails closed."""
    synth = _build_valid_synth_repo(tmp_path / "ra001_signed")
    ttm = synth / "compliance" / "risk_acceptance" / "THRESHOLD_TRACEABILITY_MATRIX.md"
    ttm.write_text(
        ttm.read_text(encoding="utf-8").replace(
            "| **Who Accepted** | Authorizing Official (AO) — [SIGNATURE PENDING] |",
            "| **Who Accepted** | Authorizing Official (AO) — J. Smith (Signed) |",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(MechanismReferenceError, match="RA-001 appears signed"):
        verify_mechanism_references(synth, enforce_floors=False)
    assert main(["--repo-root", str(synth), "--no-floors"]) == 1

    # Also verify §6 signature blank fill-in fails closed while POAM-2026-222 is Open
    synth_sec6 = _build_valid_synth_repo(tmp_path / "sec6_signed")
    ttm_sec6 = (
        synth_sec6
        / "compliance"
        / "risk_acceptance"
        / "THRESHOLD_TRACEABILITY_MATRIX.md"
    )
    ttm_sec6.write_text(
        ttm_sec6.read_text(encoding="utf-8").replace(
            "Signature: _____________________________",
            "Signature: Jane_Doe_AO_2026",
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        MechanismReferenceError, match="§6 Approval Block field is populated"
    ):
        verify_mechanism_references(synth_sec6, enforce_floors=False)


def test_negative_f_closing_poam_222_with_dot_metrics_remaining_fails_closed(
    tmp_path: Path,
) -> None:
    """(f) Marking POAM-2026-222 Closed while `cage.stpa.fin1_violations` remains in TTM fails closed."""
    synth = _build_valid_synth_repo(tmp_path)
    poam = synth / "docs" / "POAM.md"
    poam.write_text(
        "# POA&M\n\n"
        "## Closed Items\n\n"
        "| ID | Control | Weakness | Closed |\n"
        "|---|---|---|---|\n"
        "| POAM-2026-222 | CA-7 | Remediated | 2026-11-17 |\n\n"
        "### POAM-2026-222: Threshold Traceability Matrix Monitoring Column\n\n"
        "**Status:** Closed\n",
        encoding="utf-8",
    )

    with pytest.raises(MechanismReferenceError) as exc_info:
        verify_mechanism_references(synth, enforce_floors=False)
    msg = str(exc_info.value)
    assert "cage.stpa.fin1_violations" in msg
    assert "cage.stpa.*" in msg
    assert main(["--repo-root", str(synth), "--no-floors"]) == 1

    # Once §2.1 is re-pointed to an emitted Prometheus series and Appendix B is cleaned up, closure passes!
    ttm = synth / "compliance" / "risk_acceptance" / "THRESHOLD_TRACEABILITY_MATRIX.md"
    ttm.write_text(
        ttm.read_text(encoding="utf-8")
        .replace(
            "`cage.stpa.fin1_violations` (counter)",
            "`cage_gateway_gated_requests_total{outcome}`",
        )
        .replace(
            "- All `cage.stpa.*` metrics\n", "- Emitted `cage_*` Prometheus series.\n"
        ),
        encoding="utf-8",
    )
    verify_mechanism_references(synth, enforce_floors=False)
    assert main(["--repo-root", str(synth), "--no-floors"]) == 0


# Regression coverage binding: POAM-2026-222
