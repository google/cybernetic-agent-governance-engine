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
"""Unit tests for the shared measurement-inventory discovery layer (POAM-2026-222 & POAM-2026-234)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from scripts.measurement_inventory import (
    MIN_ALERT_POLICIES,
    MIN_BRIDGE_SCORES,
    MIN_LULA_BRIDGE_SPECS,
    MIN_PROMETHEUS_METRICS,
    CorpusFloorError,
    PrometheusMetric,
    discover_alert_policies,
    discover_bridge_scores,
    discover_inventory,
    discover_lula_bridge_specs,
    discover_prometheus_metrics,
    enforce_corpus_floors,
    main,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_live_repository_inventory_meets_all_corpus_floors_and_discovers_known_surfaces() -> (
    None
):
    """Live repository snapshot passes all four corpus floors and finds concrete known surfaces."""
    snapshot = discover_inventory()
    enforce_corpus_floors(snapshot)

    assert len(snapshot.prometheus_metrics) >= MIN_PROMETHEUS_METRICS
    assert len(snapshot.alert_policies) >= MIN_ALERT_POLICIES
    assert len(snapshot.lula_bridge_specs) >= MIN_LULA_BRIDGE_SPECS
    assert len(snapshot.bridge_scores) >= MIN_BRIDGE_SCORES

    # 1. Prometheus metrics (direct, fixed-helper, and class-factory registrations)
    prom_by_name = {m.name: m for m in snapshot.prometheus_metrics}
    assert prom_by_name["cage_gateway_gated_requests_total"].metric_type == "counter"
    assert prom_by_name["cage_gateway_gated_requests_total"].labels == ("outcome",)
    assert prom_by_name["cage_event_loop_lag_seconds"].metric_type == "histogram"
    assert (
        "cage_event_loop_lag_seconds_count"
        in prom_by_name["cage_event_loop_lag_seconds"].exposed_series_names()
    )
    assert prom_by_name["cage_cbf_wait_latency_seconds"].metric_type == "histogram"
    assert prom_by_name["cage_evidence_custody_batches_total"].labels == ("outcome",)
    assert prom_by_name["cage_lula_audit_not_satisfied_controls"].metric_type == "gauge"

    # 2. Cloud Monitoring alert policies (including transitive local.* PromQL expansion)
    alerts_by_label = {a.resource_label: a for a in snapshot.alert_policies}
    expected_labels = {
        "prometheus_metrics_scrape_liveness",
        "gateway_sustained_refusal_ratio",
        "gateway_zero_permitted_requests",
        "gateway_canary_probe_absent",
        "gateway_canary_pod_health",
        "gateway_evidence_append_reconciliation",
        "lula_audit_failure",
        "lula_audit_pod_restart",
    }
    assert expected_labels.issubset(alerts_by_label.keys())
    assert (
        "cage_event_loop_lag_seconds_count"
        in alerts_by_label["prometheus_metrics_scrape_liveness"].referenced_metrics
    )
    assert (
        "cage_lula_audit_deadman_breaches_total"
        in alerts_by_label["lula_audit_failure"].referenced_metrics
    )

    # 3. Evaluated Lula compliance-bridge specs (excluding planned/not-applicable templates)
    lula_by_path = {s.rel_path: s for s in snapshot.lula_bridge_specs}
    assert set(lula_by_path.keys()) >= {
        "compliance/lula/lula-validation-a52.yaml",
        "compliance/lula/lula-validation-a53.yaml",
        "compliance/lula/lula-validation-a92.yaml",
        "compliance/lula/lula-validation-aarm-vectors.yaml",
    }
    assert "compliance/lula/lula-validation-dora-art10.yaml" not in lula_by_path
    assert "compliance/lula/lula-validation-gdpr-art22.yaml" not in lula_by_path
    assert set(
        lula_by_path["compliance/lula/lula-validation-a52.yaml"].referenced_fields
    ) == {
        "evidence_age_seconds",
        "min_sample_size",
        "safety_rate",
        "startup_grace_active",
        "total_traces",
    }

    # 4. Compliance-bridge models, endpoints, stream schemas, and evaluators (for POAM-2026-234)
    by_kind_and_name = {(b.surface_kind, b.name): b for b in snapshot.bridge_scores}
    assert ("model", "ComplianceMetrics") in by_kind_and_name
    assert "safety_rate" in by_kind_and_name[("model", "ComplianceMetrics")].fields
    assert ("model", "AARMConformanceReport") in by_kind_and_name
    assert ("stream_record", "lula_audit_infra_event") in by_kind_and_name
    assert ("endpoint", "get_metrics") in by_kind_and_name
    assert (
        by_kind_and_name[("endpoint", "get_metrics")].endpoint
        == "GET /v1/metrics/{control_id}"
    )

    for required_evaluator in (
        "_is_control_effective_record",
        "_fetch_from_evidence_stream_sync",
        "get_last_passing_lula_audit_age_seconds",
        "_check_sla_once",
        "_check_lula_audit_deadman",
        "_get_grace_status",
    ):
        assert ("evaluator", required_evaluator) in by_kind_and_name, (
            f"Expected evaluator {required_evaluator!r} in BridgeScoreSurface inventory"
        )


def test_prometheus_metric_exposed_series_names_matches_prometheus_client_semantics() -> (
    None
):
    """Counter handles names with or without `_total`; Histogram/Summary expose `_bucket`/`_count`/`_sum`."""
    c_with_total = PrometheusMetric(
        name="cage_requests_total",
        metric_type="counter",
        labels=("outcome",),
        rel_path="src/foo.py",
        line=10,
    )
    c_without_total = PrometheusMetric(
        name="cage_requests",
        metric_type="counter",
        labels=(),
        rel_path="src/foo.py",
        line=11,
    )
    assert c_with_total.exposed_series_names() == (
        "cage_requests_created",
        "cage_requests_total",
    )
    assert c_without_total.exposed_series_names() == (
        "cage_requests_created",
        "cage_requests_total",
    )
    assert c_with_total.base_family_name() == "cage_requests"

    gauge = PrometheusMetric(
        name="cage_active_workers",
        metric_type="gauge",
        labels=(),
        rel_path="src/foo.py",
        line=12,
    )
    assert gauge.exposed_series_names() == ("cage_active_workers",)

    hist = PrometheusMetric(
        name="cage_latency_seconds",
        metric_type="histogram",
        labels=(),
        rel_path="src/foo.py",
        line=13,
    )
    assert hist.exposed_series_names() == (
        "cage_latency_seconds",
        "cage_latency_seconds_bucket",
        "cage_latency_seconds_count",
        "cage_latency_seconds_created",
        "cage_latency_seconds_sum",
    )

    summary = PrometheusMetric(
        name="cage_payload_bytes",
        metric_type="summary",
        labels=(),
        rel_path="src/foo.py",
        line=14,
    )
    assert summary.exposed_series_names() == (
        "cage_payload_bytes",
        "cage_payload_bytes_count",
        "cage_payload_bytes_created",
        "cage_payload_bytes_sum",
    )


def test_corpus_floor_drop_fails_closed_for_each_of_four_classes() -> None:
    """Dropping below the floor in any of the four measurement classes raises CorpusFloorError."""
    live = discover_inventory()

    dropped_prom = dataclasses.replace(
        live, prometheus_metrics=live.prometheus_metrics[: MIN_PROMETHEUS_METRICS - 1]
    )
    with pytest.raises(CorpusFloorError, match="prometheus_metrics="):
        enforce_corpus_floors(dropped_prom)

    dropped_alerts = dataclasses.replace(
        live, alert_policies=live.alert_policies[: MIN_ALERT_POLICIES - 1]
    )
    with pytest.raises(CorpusFloorError, match="alert_policies="):
        enforce_corpus_floors(dropped_alerts)

    dropped_lula = dataclasses.replace(
        live, lula_bridge_specs=live.lula_bridge_specs[: MIN_LULA_BRIDGE_SPECS - 1]
    )
    with pytest.raises(CorpusFloorError, match="lula_bridge_specs="):
        enforce_corpus_floors(dropped_lula)

    dropped_scores = dataclasses.replace(
        live, bridge_scores=live.bridge_scores[: MIN_BRIDGE_SCORES - 1]
    )
    with pytest.raises(CorpusFloorError, match="bridge_scores="):
        enforce_corpus_floors(dropped_scores)


def test_synthetic_tree_discovery_across_all_four_classes_and_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Discovery functions work hermetically on synthetic `tmp_path` trees without touching live repo."""
    # 1. Synthetic src/ collectors (verifies collections.Counter is ignored)
    src_mod = tmp_path / "src" / "gateway" / "metrics_sample.py"
    src_mod.parent.mkdir(parents=True)
    src_mod.write_text(
        "from collections import Counter as StdCounter\n"
        "from prometheus_client import Counter as _PromCounter, Gauge, Summary\n"
        "bag = StdCounter(['not_a_metric'])\n"
        "def _mk_counter(name: str, doc: str, labels: list[str] | None = None):\n"
        "    return _PromCounter(name, doc, labels or [])\n"
        "REQ_TOTAL = _mk_counter('cage_synth_requests', 'doc', ['route'])\n"
        "QUEUE_DEPTH = Gauge('cage_synth_queue_depth', 'doc')\n"
        "BATCH_BYTES = Summary('cage_synth_batch_bytes', 'doc')\n",
        encoding="utf-8",
    )

    # 2. Synthetic infra/ alert policy with empty notification_channels = []
    tf_file = tmp_path / "infra" / "alerts.tf"
    tf_file.parent.mkdir(parents=True)
    tf_file.write_text(
        "locals {\n"
        '  synth_promql = "rate(cage_synth_requests_total[5m]) > 0"\n'
        "}\n"
        'resource "google_monitoring_alert_policy" "synth_alert" {\n'
        '  display_name = "Synthetic Alert"\n'
        "  notification_channels = []\n"
        "  conditions {\n"
        "    condition_prometheus_query_language {\n"
        "      query = local.synth_promql\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # 3. Synthetic Lula manifest
    lula_file = tmp_path / "compliance" / "lula" / "lula-validation-synth.yaml"
    lula_file.parent.mkdir(parents=True)
    lula_file.write_text(
        "domain:\n"
        "  type: api\n"
        "  api-spec:\n"
        "    requests:\n"
        "      - name: synth_status\n"
        "        url: http://compliance-bridge.local/v1/metrics/A.5.2\n"
        "provider:\n"
        "  type: opa\n"
        "  opa-spec:\n"
        "    rego: |\n"
        "      package lula\n"
        "      validate if {\n"
        "        input.synth_status.safety_rate >= 0.99\n"
        "      }\n",
        encoding="utf-8",
    )

    # 4. Synthetic compliance_bridge model & SLA evaluator
    cb_file = tmp_path / "src" / "compliance_bridge" / "metrics.py"
    cb_file.parent.mkdir(parents=True)
    cb_file.write_text(
        "from pydantic import BaseModel\n"
        "class ControlMetrics(BaseModel):\n"
        "    safety_rate: float\n"
        "    evidence_age_seconds: float\n"
        "def _check_sla_once() -> list[str]:\n"
        "    return []\n",
        encoding="utf-8",
    )

    prom = discover_prometheus_metrics(tmp_path)
    assert [m.name for m in prom] == [
        "cage_synth_batch_bytes",
        "cage_synth_queue_depth",
        "cage_synth_requests",
    ]
    alerts = discover_alert_policies(tmp_path)
    assert len(alerts) == 1
    assert alerts[0].resource_label == "synth_alert"
    assert alerts[0].has_notification_channels_expr is False
    assert alerts[0].referenced_metrics == ("cage_synth_requests_total",)

    lula_specs = discover_lula_bridge_specs(tmp_path)
    assert len(lula_specs) == 1
    assert lula_specs[0].endpoints == ("/v1/metrics/A.5.2",)
    assert lula_specs[0].referenced_fields == ("safety_rate",)

    scores = discover_bridge_scores(tmp_path)
    assert {s.name for s in scores} == {"ControlMetrics", "_check_sla_once"}

    # CLI fails closed without --no-floors on small synthetic tree, succeeds with --no-floors --json
    assert main(["--repo-root", str(tmp_path)]) == 1
    capsys.readouterr()
    assert main(["--repo-root", str(tmp_path), "--no-floors", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["counts"] == {
        "prometheus_metrics": 3,
        "alert_policies": 1,
        "lula_bridge_specs": 1,
        "bridge_scores": 2,
    }


# Regression coverage binding: POAM-2026-222, POAM-2026-234
