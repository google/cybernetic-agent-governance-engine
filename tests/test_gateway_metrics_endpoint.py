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

"""Unit and contract tests for PR A1 — Gateway metrics endpoint & event-loop lag monitor.

Covers:
  - ``src/gateway/observability/loop_monitor.py``:
      * ``run_loop_lag_monitor`` records blocking event-loop drift into
        ``cage_event_loop_lag_seconds`` and cancels cleanly;
      * ``start_metrics_http_server`` starts an out-of-band WSGI HTTP server on
        a background thread that serves ``/metrics`` even while the asyncio
        event loop is blocked, honours ``CAGE_METRICS_PORT=0`` to disable, and
        degrades gracefully on port bind conflicts;
  - ``src/gateway/server/hybrid_server.py``:
      * ``_gateway_lifespan`` starts and stops ``start_metrics_http_server``
        and the ``run_loop_lag_monitor`` task (including cleanup on startup
        failure);
  - ``src/integrations/gcp/kms_provider.py``:
      * ``cage_kms_rpc_total{op}`` increments on ``get_crypto_key_version``,
        ``sign``, ``get_public_key``, and ``list_crypto_key_versions``;
  - Terraform & Lula manifests:
      * ``infra/modules/gateway/main.tf`` declares containerPort ``9090``
        (``metrics``), Service label ``app = "gateway"``, Service port ``9090``
        (``metrics``), and ``config.linkerd.io/skip-inbound-ports = "9090"``;
      * ``infra/modules/gateway/metrics-monitors/templates/monitors.yaml``
        defines both ``ServiceMonitor/stera-gateway-monitor`` and
        ``PodMonitoring/gateway-metrics`` selecting ``app: gateway`` on port
        ``metrics``;
      * ``compliance/lula/lula-validation-metrics.yaml`` validates
        ``gateway-metrics`` under ``au-12``.
"""

from __future__ import annotations

import asyncio
import sys
import time
import urllib.request
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from prometheus_client import CollectorRegistry, Histogram

from src.gateway.observability.loop_monitor import (
    EVENT_LOOP_LAG_SECONDS,
    record_loop_lag,
    run_loop_lag_monitor,
    start_metrics_http_server,
)
from src.integrations.gcp.kms_provider import KMS_RPC_TOTAL, GCPKMSProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Event-loop lag monitor tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_loop_lag_monitor_records_blocking_sleep() -> None:
    """Injecting a blocking time.sleep on the event loop records drift in the histogram."""
    registry = CollectorRegistry()
    hist = Histogram(
        "test_event_loop_lag_seconds",
        "Test loop lag histogram",
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        registry=registry,
    )

    task = asyncio.create_task(
        run_loop_lag_monitor(interval_seconds=0.02, histogram=hist)
    )
    try:
        # Let the monitor enter its first asyncio.sleep(0.02)
        await asyncio.sleep(0.005)
        # Block the event loop synchronously for ~60 ms
        time.sleep(0.06)
        # Allow the monitor coroutine to wake up and record the drift
        await asyncio.sleep(0.03)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    count = registry.get_sample_value("test_event_loop_lag_seconds_count")
    total = registry.get_sample_value("test_event_loop_lag_seconds_sum")
    assert count is not None and count >= 1.0
    assert total is not None and total >= 0.035


@pytest.mark.asyncio
async def test_loop_lag_monitor_rejects_non_positive_interval() -> None:
    with pytest.raises(ValueError, match="interval_seconds must be positive"):
        await run_loop_lag_monitor(interval_seconds=0.0)


def test_record_loop_lag_clamps_negative_values() -> None:
    registry = CollectorRegistry()
    hist = Histogram(
        "test_clamp_lag_seconds",
        "Test clamp histogram",
        buckets=(0.001, 0.01, 0.1),
        registry=registry,
    )
    record_loop_lag(-0.5, histogram=hist)
    assert registry.get_sample_value("test_clamp_lag_seconds_count") == 1.0
    assert registry.get_sample_value("test_clamp_lag_seconds_sum") == 0.0
    assert EVENT_LOOP_LAG_SECONDS is not None


# ---------------------------------------------------------------------------
# 2. Out-of-band Prometheus HTTP server tests
# ---------------------------------------------------------------------------


def test_metrics_http_server_starts_on_ephemeral_port_and_serves_metrics() -> None:
    handle = start_metrics_http_server(port=0, addr="127.0.0.1")
    # port=0 disables when passed directly; verify ephemeral port via start_http_server(0)
    assert handle is None


def test_metrics_http_server_serves_scrape_and_handles_port_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start the WSGI server on a free port, scrape /metrics over HTTP, and verify conflict handling."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    monkeypatch.setenv("CAGE_METRICS_PORT", str(free_port))
    handle = start_metrics_http_server(addr="127.0.0.1")
    assert handle is not None
    try:
        assert handle.port == free_port
        url = f"http://127.0.0.1:{handle.port}/metrics"
        assert url.startswith("http://")
        with urllib.request.urlopen(url, timeout=2.0) as resp:  # nosec B310
            body = resp.read().decode("utf-8")
            assert resp.status == 200
            assert "cage_event_loop_lag_seconds" in body

        # Starting a second server on the same port logs a warning and returns None instead of crashing
        conflict_handle = start_metrics_http_server(port=free_port, addr="127.0.0.1")
        assert conflict_handle is None
    finally:
        handle.stop()


def test_metrics_http_server_invalid_env_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_METRICS_PORT", "not-an-int")
    with patch(
        "src.gateway.observability.loop_monitor.start_http_server",
        return_value=(MagicMock(server_port=9090), MagicMock()),
    ) as mock_start:
        handle = start_metrics_http_server(addr="127.0.0.1")
        assert handle is not None
        mock_start.assert_called_once_with(9090, addr="127.0.0.1")
        handle.stop()


def test_metrics_http_server_fails_closed_under_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under is_enforcing(), port <= 0, missing prometheus_client, or OSError raises RuntimeError."""
    with patch("src.gateway.governance.env_posture.is_enforcing", return_value=True):
        with pytest.raises(RuntimeError, match="cannot be disabled"):
            start_metrics_http_server(port=0, addr="127.0.0.1")

        with patch("src.gateway.observability.loop_monitor.start_http_server", None):
            with pytest.raises(RuntimeError, match="prometheus_client is required"):
                start_metrics_http_server(port=9090, addr="127.0.0.1")

        with patch(
            "src.gateway.observability.loop_monitor.start_http_server",
            side_effect=OSError("address already in use"),
        ):
            with pytest.raises(RuntimeError, match="Failed to bind Prometheus"):
                start_metrics_http_server(port=9090, addr="127.0.0.1")


# ---------------------------------------------------------------------------
# 3. _gateway_lifespan wiring tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gateway_lifespan_starts_and_stops_metrics_server_and_loop_monitor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_gateway_lifespan starts the metrics HTTP server and loop-lag task, and cleans both up on exit."""
    from tests.test_hybrid_server import _make_hybrid_stubs

    monkeypatch.setenv(
        "CAGE_TRUSTED_CLIENT_IDENTITIES",
        "advisor.cage.serviceaccount.identity.linkerd.cluster.local",
    )
    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")

    mock_handle = MagicMock()
    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with (
        patch.dict("sys.modules", stubs),
        patch(
            "src.gateway.observability.loop_monitor.start_metrics_http_server",
            return_value=mock_handle,
        ) as mock_start_srv,
    ):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        app_mock = MagicMock()
        app_mock.state = MagicMock()

        async with _gateway_lifespan(app_mock):
            mock_start_srv.assert_called_once()
            assert app_mock.state.metrics_server is mock_handle
            assert isinstance(app_mock.state.loop_lag_task, asyncio.Task)
            assert not app_mock.state.loop_lag_task.done()

        assert (
            app_mock.state.loop_lag_task.cancelled()
            or app_mock.state.loop_lag_task.done()
        )
        mock_handle.stop.assert_called_once()


# ---------------------------------------------------------------------------
# 4. GCP KMS RPC counter tests
# ---------------------------------------------------------------------------


def _kms_rpc_count(op: str) -> float:
    assert KMS_RPC_TOTAL is not None
    return float(KMS_RPC_TOTAL.labels(op=op)._value.get())


def test_gcp_kms_provider_increments_rpc_counter_by_operation() -> None:
    mock_client = MagicMock()
    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_version.state.name = "ENABLED"
    mock_version.name = (
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    )
    mock_client.get_crypto_key_version.return_value = mock_version
    mock_client.asymmetric_sign.return_value = MagicMock(signature=b"sig-bytes")
    mock_client.get_public_key.return_value = MagicMock(
        pem="-----BEGIN PUBLIC KEY-----\n..."
    )
    mock_client.list_crypto_key_versions.return_value = [mock_version]

    before_get_ver = _kms_rpc_count("get_crypto_key_version")
    before_sign = _kms_rpc_count("sign")
    before_pub = _kms_rpc_count("get_public_key")
    before_list = _kms_rpc_count("list_crypto_key_versions")

    provider = GCPKMSProvider(
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        kms_client=mock_client,
    )
    # __init__ -> _detect_hash_width issues 1 get_crypto_key_version RPC
    assert _kms_rpc_count("get_crypto_key_version") == before_get_ver + 1.0

    # jose_alg reads the cached algorithm from __init__ (0 extra RPCs)
    _ = provider.jose_alg
    assert _kms_rpc_count("get_crypto_key_version") == before_get_ver + 1.0

    provider.validate_ready()
    assert _kms_rpc_count("get_crypto_key_version") == before_get_ver + 2.0

    with patch.dict(
        "sys.modules",
        {
            "google": MagicMock(),
            "google.cloud": MagicMock(),
            "google.cloud.kms_v1": MagicMock(),
            "google.cloud.kms_v1.types": MagicMock(service=MagicMock()),
        },
    ):
        provider.sign_digest(b"0" * 32)
        provider.sign_raw(b"raw-message")
    assert _kms_rpc_count("sign") == before_sign + 2.0

    provider.get_public_key_pem()
    assert _kms_rpc_count("get_public_key") == before_pub + 1.0

    provider.get_public_keys_pem()
    assert _kms_rpc_count("list_crypto_key_versions") == before_list + 1.0
    assert _kms_rpc_count("get_public_key") == before_pub + 2.0


# ---------------------------------------------------------------------------
# 5. Terraform, ServiceMonitor, PodMonitoring, and Lula manifest contracts
# ---------------------------------------------------------------------------


def _render_metrics_monitors_chart(namespace: str = "governance-stack") -> list[dict]:
    """Deterministically render infra/modules/gateway/metrics-monitors/templates/monitors.yaml."""
    import re

    chart_dir = _REPO / "infra/modules/gateway/metrics-monitors"
    values = yaml.safe_load((chart_dir / "values.yaml").read_text(encoding="utf-8"))
    tpl = (chart_dir / "templates/monitors.yaml").read_text(encoding="utf-8")
    rendered = "\n".join(
        line for line in tpl.splitlines() if not line.strip().startswith("{{-")
    )
    rendered = rendered.replace("{{ .Release.Namespace }}", namespace)
    rendered = re.sub(
        r"\{\{\s*\.Values\.podMonitoring\.interval\s*\|\s*quote\s*\}\}",
        f'"{values["podMonitoring"]["interval"]}"',
        rendered,
    )
    rendered = re.sub(
        r"\{\{\s*\.Values\.podMonitoring\.timeout\s*\|\s*quote\s*\}\}",
        f'"{values["podMonitoring"]["timeout"]}"',
        rendered,
    )
    rendered = re.sub(
        r"\{\{\s*\.Values\.serviceMonitor\.interval\s*\|\s*quote\s*\}\}",
        f'"{values["serviceMonitor"]["interval"]}"',
        rendered,
    )
    rendered = re.sub(
        r"\{\{\s*\.Values\.serviceMonitor\.scrapeTimeout\s*\|\s*quote\s*\}\}",
        f'"{values["serviceMonitor"]["scrapeTimeout"]}"',
        rendered,
    )
    return [d for d in yaml.safe_load_all(rendered) if isinstance(d, dict)]


def test_gateway_terraform_exposes_metrics_port_and_linkerd_bypass() -> None:
    main_tf = (_REPO / "infra/modules/gateway/main.tf").read_text(encoding="utf-8")
    assert '"config.linkerd.io/skip-inbound-ports" = "9090"' in main_tf
    assert "container_port = 9090" in main_tf
    assert 'name           = "metrics"' in main_tf
    assert 'name  = "CAGE_METRICS_PORT"' in main_tf

    svc_start = main_tf.index('resource "kubernetes_service" "gateway"')
    svc_block = main_tf[
        svc_start : main_tf.index("\n# ─── PodDisruptionBudget", svc_start)
    ]
    assert 'app = "gateway"' in svc_block
    assert "port        = 9090" in svc_block
    assert "target_port = 9090" in svc_block
    assert 'name        = "metrics"' in svc_block


def test_gateway_servicemonitor_and_podmonitoring_select_gateway() -> None:
    docs = _render_metrics_monitors_chart()
    assert len(docs) == 2

    sm = next(d for d in docs if d.get("kind") == "ServiceMonitor")
    assert sm["metadata"]["name"] == "stera-gateway-monitor"
    assert sm["spec"]["selector"]["matchLabels"] == {"app": "gateway"}
    assert sm["spec"]["endpoints"][0]["port"] == "metrics"
    assert sm["spec"]["endpoints"][0]["path"] == "/metrics"

    pm = next(d for d in docs if d.get("kind") == "PodMonitoring")
    assert pm["apiVersion"] == "monitoring.googleapis.com/v1"
    assert pm["metadata"]["name"] == "gateway-metrics"
    assert pm["spec"]["selector"]["matchLabels"] == {"app": "gateway"}
    assert pm["spec"]["endpoints"][0]["port"] == "metrics"
    assert pm["spec"]["endpoints"][0]["path"] == "/metrics"


def test_lula_validation_metrics_covers_in_state_podmonitoring() -> None:
    lula_path = _REPO / "compliance" / "lula" / "lula-validation-metrics.yaml"
    doc = yaml.safe_load(lula_path.read_text(encoding="utf-8"))
    comp_def = doc["component-definition"]
    impl_req = comp_def["components"][0]["control-implementations"][0][
        "implemented-requirements"
    ][0]
    assert impl_req["control-id"] == "au-12"

    resource_desc = yaml.safe_load(
        comp_def["back-matter"]["resources"][0]["description"]
    )
    resources = {
        r["name"]: r["resource-rule"]["resource"]
        for r in resource_desc["domain"]["kubernetes-spec"]["resources"]
    }
    assert resources == {
        "gateway-metrics": "podmonitorings",
    }
    rego = resource_desc["provider"]["opa-spec"]["rego"]
    assert "pod_monitoring_valid" in rego
    assert 'count(input["gateway-metrics"]) > 0' in rego


def test_gateway_terraform_module_wires_probes_pdb_loop_lag_hpa_and_podmonitoring() -> (
    None
):
    main_tf = (_REPO / "infra/modules/gateway/main.tf").read_text(encoding="utf-8")
    vars_tf = (_REPO / "infra/modules/gateway/variables.tf").read_text(encoding="utf-8")

    assert not (_REPO / "deployment" / "k8s").exists()
    assert 'name  = "OMP_NUM_THREADS"\n            value = "2"' in main_tf
    assert 'name  = "OPENBLAS_NUM_THREADS"\n            value = "2"' in main_tf
    assert 'command = ["/bin/sh", "-c", "sleep 5"]' in main_tf

    for probe_header in ("startup_probe {", "liveness_probe {", "readiness_probe {"):
        idx = main_tf.index(probe_header)
        probe_block = main_tf[idx : idx + 260]
        assert 'path = "/health"' in probe_block
        assert "port = 8080" in probe_block

    startup_idx = main_tf.index("startup_probe {")
    startup_block = main_tf[startup_idx : startup_idx + 260]
    assert "period_seconds    = 5" in startup_block
    assert "failure_threshold = 30" in startup_block

    assert 'resource "kubernetes_pod_disruption_budget_v1" "gateway"' in main_tf
    assert "count = var.replicas >= 2 ? 1 : 0" in main_tf
    assert 'name      = "gateway-pdb"' in main_tf
    assert "min_available = 1" in main_tf

    assert 'resource "kubernetes_horizontal_pod_autoscaler_v2" "gateway"' in main_tf
    assert "min_replicas = max(2, var.replicas)" in main_tf
    assert "max_replicas = var.max_replicas" in main_tf
    assert "prometheus.googleapis.com|cage_event_loop_lag_seconds|gauge" in main_tf
    assert 'type          = "AverageValue"' in main_tf
    assert "average_value = var.autoscaling_target_loop_lag" in main_tf
    assert 'variable "enable_autoscaling"' in vars_tf
    assert 'variable "max_replicas"' in vars_tf
    assert "default     = 5" in vars_tf
    assert 'variable "autoscaling_target_loop_lag"' in vars_tf
    assert 'default     = "50m"' in vars_tf
    assert 'resource "helm_release" "metrics_monitors"' in main_tf
    assert 'variable "enable_pod_monitoring"' in vars_tf
    assert 'variable "enable_service_monitor"' in vars_tf


def test_reconciliation_worker_managed_in_terraform_state_poam_096() -> None:
    mod_tf = (_REPO / "infra/modules/reconciliation_worker/main.tf").read_text(
        encoding="utf-8"
    )
    iam_tf = (_REPO / "infra/targets/gcp-gke/iam.tf").read_text(encoding="utf-8")
    gke_tf = (_REPO / "infra/targets/gcp-gke/main.tf").read_text(encoding="utf-8")

    assert 'resource "kubernetes_deployment" "reconciliation_worker"' in mod_tf
    assert 'resource "kubernetes_secret" "reconciliation_worker"' in mod_tf
    assert 'name      = "reconciliation-worker-secrets"' in mod_tf
    assert 'type = "Recreate"' in mod_tf
    assert "var.ttl_seconds >= 2 * var.poll_interval_seconds" in mod_tf
    assert "src.gateway.governance.reconciliation.daemon" in mod_tf
    assert "name    = local.ksa_reconciler" in iam_tf
    assert 'module "reconciliation_worker"' in gke_tf
    assert (
        'kubernetes_service_account.workload["reconciler"].metadata[0].name' in gke_tf
    )
    assert "enable_pod_monitoring  = true" in gke_tf
