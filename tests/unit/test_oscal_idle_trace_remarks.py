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

"""Unit tests for Option 1 idle-cluster Lula OSCAL remarks and POAM-2026-215 remediation.

Covers:
  - POAM-2026-215: `findings_from_metrics_dict()`, `GET /v1/oscal/assessment-results`,
    and `GET /v1/aarm/conformance-report` must never emit `not-applicable` (or vacuous
    `satisfied` / `SECURE`) when `total_traces == 0` (`safety_rate is None`). Instead
    they emit `state: not-satisfied` (`result: INSUFFICIENT_EVIDENCE`) with explicit
    OSCAL `remarks` and `props` (`assessment_status=insufficient_traffic`, `total_traces=0`).
  - Native Lula v0.16.0 `opa-spec.output.observations: [lula.assessment_remark]` across
    `lula-validation-a52.yaml`, `lula-validation-a53.yaml`, and `lula-validation-a92.yaml`:
    strict `not-satisfied` verdict on `total_traces == 0` outside startup grace with
    self-describing `assessment_status=insufficient_traffic` remarks, distinguished from
    `threshold_violation`, `stale_evidence`, `startup_grace`, and `satisfied`.
  - Three-state routing in `run_lula_audit.sh`, `POST /v1/infra/events`, `metrics.py`,
    and `sla_monitor.py`: idle clusters route `a52`/`a53`/`a92` `insufficient_traffic`
    into `cage_lula_audit_insufficient_traffic_controls` (`not_satisfied_controls == 0`)
    without contaminating `A.5.3` `total_traces` or tripping the 1800s dead-man's switch,
    while rejecting spoofed non-statistical controls fail-closed and preserving Gate W's
    strict 26/26 seeded requirement.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
import yaml
from fastapi.testclient import TestClient

import src.compliance_bridge.main as bridge_main
import src.compliance_bridge.sla_monitor as sla_mod
from scripts.verify_lula_assessment_results import verify_assessment_results_data
from src.compliance_bridge.aarm_mapper import build_aarm_conformance_report
from src.compliance_bridge.infra_custody import InfraEvidenceChain
from src.compliance_bridge.main import InfraEvent, app
from src.compliance_bridge.metrics import (
    _fetch_from_evidence_stream_sync,
    _is_passing_evidence_record,
    get_last_passing_lula_audit_age_seconds,
    invalidate_compliance_metrics_cache,
)
from src.compliance_bridge.oscal_exporter import (
    build_oscal_assessment_results,
    findings_from_metrics_dict,
)
from src.compliance_bridge.oscal_parser import parse_oscal_yaml
from src.compliance_bridge.types import ComplianceMetrics
from src.gateway.governance.evidence.stream import verify_record

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LULA_DIR = REPO_ROOT / "compliance" / "lula"
RUN_SCRIPT = REPO_ROOT / "infra" / "modules" / "lula_cron" / "run_lula_audit.sh"
STAGING_LIFECYCLE = REPO_ROOT / "scripts" / "staging_lifecycle.sh"

POD_IP = "10.24.1.19"
CAGE_LULA_SA_L5D = (
    "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


def _metric_value(metric: Any, **labels: str) -> float:
    assert metric is not None, "prometheus_client collector must be registered"
    target = metric.labels(**labels) if labels else metric
    return float(target._value.get())


def _zero_trace_metrics(control_id: str) -> ComplianceMetrics:
    return ComplianceMetrics(
        control_id=control_id,
        safety_rate=None,
        total_traces=0,
        blocked_traces=0,
        passed_traces=0,
        window_hours=24.0,
        last_event_utc="2026-11-14T08:00:00+00:00",
        evidence_age_seconds=0.0,
        startup_grace_active=False,
        startup_grace_remaining_hours=0.0,
    )


@pytest.fixture(autouse=True)
def _reset_bridge_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
    monkeypatch.setenv("POD_IP", POD_IP)
    monkeypatch.delenv("LULA_AUDIT_MIN_MANIFESTS", raising=False)
    monkeypatch.delenv("LULA_AUDIT_MAX_AGE_SECONDS", raising=False)
    monkeypatch.delenv("LULA_AUDIT_DEADMAN_DISABLED", raising=False)
    monkeypatch.delenv("CAGE_TRUSTED_INFRA_PRODUCERS", raising=False)
    invalidate_compliance_metrics_cache()
    for attr in (
        "infra_evidence_chain",
        "infra_evidence_custodian",
        "infra_custody_flusher",
    ):
        if hasattr(app.state, attr):
            delattr(app.state, attr)
    yield
    invalidate_compliance_metrics_cache()
    for attr in (
        "infra_evidence_chain",
        "infra_evidence_custodian",
        "infra_custody_flusher",
    ):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


# ---------------------------------------------------------------------------
# Suite 1: POAM-2026-215 — Correct false `not-applicable` compliance claim
# ---------------------------------------------------------------------------


class TestPoam2026215FalseNotApplicableClaimRemediation:
    """POAM-2026-215: zero traces (`safety_rate is None`) must never emit `not-applicable`."""

    def test_poam_2026_215_zero_trace_metrics_emit_not_satisfied_with_insufficient_traffic_remarks(
        self,
    ) -> None:
        data = {
            cid: _zero_trace_metrics(cid).model_dump()
            for cid in ("A.5.2", "A.5.3", "A.9.2", "SC-4")
        }
        findings = findings_from_metrics_dict(data, "poam-2026-215-unit")
        assert len(findings) == 4

        for finding in findings:
            assert finding.result != "NOT_APPLICABLE", (
                f"POAM-2026-215: {finding.control_id} with total_traces=0 must never "
                "claim NOT_APPLICABLE (out of scope)"
            )
            assert finding.result != "PASS", (
                f"POAM-2026-215: {finding.control_id} with total_traces=0 must never "
                "emit a vacuous PASS"
            )
            assert finding.result == "INSUFFICIENT_EVIDENCE"
            assert finding.remarks is not None
            assert "assessment_status=insufficient_traffic" in finding.remarks
            assert f"control_id={finding.control_id}" in finding.remarks
            assert "total_traces=0" in finding.remarks
            assert "safety_rate=null" in finding.remarks

        doc = build_oscal_assessment_results(
            findings=findings,
            audit_id="poam-2026-215-unit",
            window_hours=24,
        )
        exported_findings = doc["assessment-results"]["results"][0]["findings"]
        assert len(exported_findings) == 4

        for entry in exported_findings:
            state = entry["target"]["status"]["state"]
            assert state == "not-satisfied", (
                f"POAM-2026-215: expected OSCAL state 'not-satisfied' on zero traces, got {state!r}"
            )
            status_remarks = entry["target"]["status"].get("remarks", "")
            assert "assessment_status=insufficient_traffic" in status_remarks
            assert "assessment_status=insufficient_traffic" in entry.get("remarks", "")
            assert "assessment_status=insufficient_traffic" in entry.get(
                "description", ""
            )
            props = {p["name"]: p["value"] for p in entry["props"]}
            assert props.get("assessment_status") == "insufficient_traffic"
            assert props.get("total_traces") == "0"

    def test_poam_2026_215_live_endpoints_idle_cluster_never_claim_not_applicable_or_secure(
        self,
    ) -> None:
        async def _idle_metrics(control_id: str, window_hours: int = 24):
            return _zero_trace_metrics(control_id)

        client = TestClient(
            app,
            client=(POD_IP, 50000),
            base_url=f"http://{POD_IP}:3001",
        )
        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.get_compliance_metrics",
                new=AsyncMock(side_effect=_idle_metrics),
            ),
            client as c,
        ):
            json_resp = c.get("/v1/oscal/assessment-results?audit_id=poam-215-idle")
            yaml_resp = c.get(
                "/v1/oscal/assessment-results?format=yaml&audit_id=poam-215-idle"
            )
            aarm_resp = c.get("/v1/aarm/conformance-report?audit_id=poam-215-idle")

        assert json_resp.status_code == 200, json_resp.text
        oscal_findings = json_resp.json()["document"]["assessment-results"]["results"][
            0
        ]["findings"]
        assert len(oscal_findings) >= 3
        by_cid = {f["target"]["target-id"]: f for f in oscal_findings}
        for cid in ("A.5.2", "A.5.3", "A.9.2"):
            assert cid in by_cid
            assert by_cid[cid]["target"]["status"]["state"] == "not-satisfied"
            assert "assessment_status=insufficient_traffic" in by_cid[cid]["remarks"]
        assert all(
            f["target"]["status"]["state"] == "not-satisfied" for f in oscal_findings
        )

        assert yaml_resp.status_code == 200, yaml_resp.text
        parsed_back = parse_oscal_yaml(yaml_resp.json()["yaml"])
        assert len(parsed_back) == len(oscal_findings)
        assert all(f.result == "INSUFFICIENT_EVIDENCE" for f in parsed_back)
        assert all(
            "assessment_status=insufficient_traffic" in (f.remarks or "")
            for f in parsed_back
        )

        assert aarm_resp.status_code == 200, aarm_resp.text
        report = aarm_resp.json()["report"]
        assert report["exposed"] == 0
        assert report["neutralized"] == 0
        assert report["unknown"] == 11
        assert report["overall_posture"] == "DEGRADED", (
            "POAM-2026-215: AARM conformance report must not claim SECURE when "
            "all 11 vectors are UNKNOWN due to zero traces"
        )

        direct_report = build_aarm_conformance_report(parsed_back, "poam-215-direct")
        assert direct_report.overall_posture == "DEGRADED"


# ---------------------------------------------------------------------------
# Suite 2: Lula v0.16.0 native `output.observations` across a52 / a53 / a92
# ---------------------------------------------------------------------------


def _find_lula_binary() -> str | None:
    found = shutil.which("lula")
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / "lula"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


class TestLulaNativeObservationsStatisticalSpecs:
    """Verify native `output.observations: [lula.assessment_remark]` in a52, a53, and a92."""

    @pytest.mark.parametrize(
        ("filename", "control_id", "threshold_str"),
        [
            ("lula-validation-a52.yaml", "A.5.2", "0.99"),
            ("lula-validation-a53.yaml", "A.5.3", "0.98"),
            ("lula-validation-a92.yaml", "A.9.2", "1.0"),
        ],
    )
    def test_statistical_lula_manifests_declare_native_observations_output(
        self, filename: str, control_id: str, threshold_str: str
    ) -> None:
        raw = yaml.safe_load((LULA_DIR / filename).read_text(encoding="utf-8"))
        desc = yaml.safe_load(
            raw["component-definition"]["back-matter"]["resources"][0]["description"]
        )
        opa_spec = desc["provider"]["opa-spec"]
        assert opa_spec["output"]["validation"] == "lula.validate"
        assert opa_spec["output"]["observations"] == ["lula.assessment_remark"]
        rego = opa_spec["rego"]
        assert f"control_id={control_id}" in rego
        assert f"threshold={threshold_str}" in rego
        for status_token in (
            "insufficient_traffic",
            "threshold_violation",
            "stale_evidence",
            "startup_grace",
            "satisfied",
        ):
            assert status_token in rego
        assert "not-satisfied" not in rego
        assert "lula-validation-error" not in rego

    def test_lula_binary_evaluates_all_five_states_with_self_describing_remarks(
        self, tmp_path: Path
    ) -> None:
        lula_bin = _find_lula_binary()
        if lula_bin is None:
            pytest.skip("lula binary not installed in this environment")

        current_payload: dict[str, Any] = {}

        class _MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(current_payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = HTTPServer(("127.0.0.1", port), _MetricsHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            for filename, cid, pass_rate, fail_rate in (
                ("lula-validation-a52.yaml", "A.5.2", 0.995, 0.90),
                ("lula-validation-a53.yaml", "A.5.3", 0.985, 0.85),
                ("lula-validation-a92.yaml", "A.9.2", 1.0, 0.95),
            ):
                spec_text = (LULA_DIR / filename).read_text(encoding="utf-8")
                patched_spec = spec_text.replace(
                    f"http://compliance-bridge.governance-stack.svc.cluster.local/v1/metrics/{cid}",
                    f"http://127.0.0.1:{port}/v1/metrics/{cid}",
                )
                spec_file = tmp_path / filename
                spec_file.write_text(patched_spec, encoding="utf-8")

                scenarios = [
                    (
                        "insufficient_traffic",
                        {
                            "control_id": cid,
                            "safety_rate": None,
                            "total_traces": 0,
                            "evidence_age_seconds": 0.0,
                            "startup_grace_active": False,
                        },
                        "not-satisfied",
                        False,
                    ),
                    (
                        "threshold_violation",
                        {
                            "control_id": cid,
                            "safety_rate": fail_rate,
                            "total_traces": 20,
                            "evidence_age_seconds": 120.0,
                            "startup_grace_active": False,
                        },
                        "not-satisfied",
                        False,
                    ),
                    (
                        "stale_evidence",
                        {
                            "control_id": cid,
                            "safety_rate": pass_rate,
                            "total_traces": 20,
                            "evidence_age_seconds": 200000.0,
                            "startup_grace_active": False,
                        },
                        "not-satisfied",
                        False,
                    ),
                    (
                        "startup_grace",
                        {
                            "control_id": cid,
                            "safety_rate": None,
                            "total_traces": 0,
                            "evidence_age_seconds": 0.0,
                            "startup_grace_active": True,
                        },
                        "satisfied",
                        True,
                    ),
                    (
                        "satisfied",
                        {
                            "control_id": cid,
                            "safety_rate": pass_rate,
                            "total_traces": 25,
                            "evidence_age_seconds": 45.0,
                            "startup_grace_active": False,
                        },
                        "satisfied",
                        True,
                    ),
                ]

                for (
                    expected_status,
                    payload_data,
                    expected_state,
                    expect_ok,
                ) in scenarios:
                    current_payload.clear()
                    current_payload.update(payload_data)
                    out_file = tmp_path / f"out-{cid}-{expected_status}.yaml"
                    proc = subprocess.run(
                        [
                            lula_bin,
                            "validate",
                            "-f",
                            str(spec_file),
                            "-o",
                            str(out_file),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    assert proc.returncode == 0, proc.stderr
                    ar_doc = yaml.safe_load(out_file.read_text(encoding="utf-8"))
                    res0 = ar_doc["assessment-results"]["results"][0]
                    assert (
                        res0["findings"][0]["target"]["status"]["state"]
                        == expected_state
                    )
                    ev_remarks = res0["observations"][0]["relevant-evidence"][0][
                        "remarks"
                    ]
                    assert (
                        f"lula.assessment_remark: assessment_status={expected_status};"
                        in ev_remarks
                    )
                    assert f"control_id={cid}" in ev_remarks
                    ok, _ = verify_assessment_results_data(ar_doc)
                    assert ok is expect_ok
        finally:
            server.shutdown()
            server.server_close()


# ---------------------------------------------------------------------------
# Suite 3: Three-state runner + bridge consumer + idle-night custody loop
# ---------------------------------------------------------------------------


class TestThreeStateLulaAuditPipeline:
    """Verify idle-cluster `insufficient_traffic` routing, spoof rejection, and Gate W safety."""

    def _build_client(
        self, fake_server: fakeredis.FakeServer
    ) -> tuple[InfraEvidenceChain, TestClient]:
        chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key="cage:test:infra:lula-three-state",
        )
        app.state.infra_evidence_chain = chain
        client = TestClient(
            app,
            client=(POD_IP, 50000),
            base_url=f"http://{POD_IP}:3001",
            raise_server_exceptions=False,
        )
        return chain, client

    def test_run_lula_audit_script_idle_cluster_exits_zero_and_gate_w_regex_still_rejects_unseeded_logs(
        self, tmp_path: Path
    ) -> None:
        bin_dir = tmp_path / "bin"
        specs_dir = tmp_path / "specs"
        out_dir = tmp_path / "out"
        log_file = tmp_path / "curl.log"
        bin_dir.mkdir()
        specs_dir.mkdir()
        out_dir.mkdir()

        lula_sh = bin_dir / "lula"
        lula_sh.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'spec=""\n'
            'out=""\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  case "$1" in\n'
            '    -f) spec="$2"; shift 2 ;;\n'
            '    -o) out="$2"; shift 2 ;;\n'
            "    *) shift 1 ;;\n"
            "  esac\n"
            "done\n"
            'case "$spec" in\n'
            "  *a52*|*a53*|*a92*)\n"
            "    cat <<'EOF' > \"$out\"\n"
            "observations:\n"
            "  - relevant-evidence:\n"
            "      - description: |\n"
            "          Result: not-satisfied\n"
            "        remarks: |\n"
            "          lula.assessment_remark: assessment_status=insufficient_traffic; total_traces=0; safety_rate=null\n"
            "findings:\n"
            "  - target:\n"
            "      status:\n"
            "        state: not-satisfied\n"
            "EOF\n"
            "    ;;\n"
            "  *)\n"
            "    printf 'observations:\\n  - state: satisfied\\n' > \"$out\"\n"
            "    ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        lula_sh.chmod(lula_sh.stat().st_mode | stat.S_IXUSR)

        curl_sh = bin_dir / "curl"
        curl_sh.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'url=""\n'
            'body=""\n'
            'prev=""\n'
            'for arg in "$@"; do\n'
            '  if [ "$prev" = "-d" ]; then body="$arg"; fi\n'
            '  case "$arg" in http://*|https://*) url="$arg" ;; esac\n'
            '  prev="$arg"\n'
            "done\n"
            f'printf \'%s|%s\\n\' "$url" "$body" >> "{log_file}"\n'
            'case "$url" in\n'
            '  */v1/infra/events) printf \'{"status":"INGESTED","record_hash":"%064d"}\' 0 ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        curl_sh.chmod(curl_sh.stat().st_mode | stat.S_IXUSR)

        for spec_name in (
            "lula-validation-a52.yaml",
            "lula-validation-a53.yaml",
            "lula-validation-a92.yaml",
            "lula-validation-ac3.yaml",
            "lula-validation-ia3.yaml",
        ):
            (specs_dir / spec_name).write_text("x: 1\n", encoding="utf-8")

        env = dict(os.environ)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '/usr/bin:/bin')}"
        env["LULA_BIN"] = str(lula_sh)
        env["LULA_SPECS_DIR"] = str(specs_dir)
        env["LULA_OUT_DIR"] = str(out_dir)
        env["LULA_SKIP_LINKERD_WAIT"] = "true"
        env["COMPLIANCE_BRIDGE_EVENTS_URL"] = "http://127.0.0.1:8085/v1/infra/events"

        proc = subprocess.run(
            ["/bin/sh", "-ec", RUN_SCRIPT.read_text(encoding="utf-8")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        # Steady-state CronJob exits 0 when failed == 0 so pods do not CrashLoop/BackOff
        assert proc.returncode == 0, proc.stderr

        post_line = next(
            line
            for line in log_file.read_text(encoding="utf-8").splitlines()
            if "/v1/infra/events" in line
        )
        posted = json.loads(post_line.split("|", 1)[1])
        assert posted["evaluated_count"] == 5
        assert posted["satisfied_count"] == 2
        assert posted["failed_count"] == 0
        assert posted["insufficient_traffic_count"] == 3
        assert posted["failed_controls"] == []
        assert posted["insufficient_traffic_controls"] == [
            "lula-validation-a52",
            "lula-validation-a53",
            "lula-validation-a92",
        ]
        assert posted["summary"].startswith("lula_audit INSUFFICIENT_TRAFFIC:")
        validated = InfraEvent.model_validate(posted)
        assert validated.insufficient_traffic_count == 3

        # Gate W Phase 3 log check (`staging_lifecycle.sh`) MUST still reject unseeded
        # runs where Job/lula-gate-w emits non-zero not-satisfied controls!
        lifecycle_src = STAGING_LIFECYCLE.read_text(encoding="utf-8")
        assert (
            r"\bnot[-_]satisfied\s*[:=]\s*[1-9]\d*|\b[1-9]\d*\s+not[-_]satisfied\b"
            in lifecycle_src
        )
        assert re.search(
            r"\bnot[-_]satisfied\s*[:=]\s*[1-9]\d*|\b[1-9]\d*\s+not[-_]satisfied\b",
            proc.stdout,
            re.IGNORECASE,
        ), (
            f"Expected Gate W non-zero not-satisfied guard to match stdout: {proc.stdout!r}"
        )

    @pytest.mark.asyncio
    async def test_idle_night_multi_cycle_seals_worm_sets_insufficient_gauge_without_alerting_or_poisoning_a53(
        self,
    ) -> None:
        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        before_insuff = _metric_value(
            bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="insufficient_traffic"
        )
        before_fails = _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")
        if bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS is not None:
            bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS.set(4.0)

        idle_specs = [
            "lula-validation-a52",
            "lula-validation-a53",
            "lula-validation-a92",
        ]
        now = datetime.now(tz=timezone.utc)
        ts_str = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")

        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.create_notifier",
                return_value=mock_notifier,
            ),
            client_ctx as client,
        ):
            resp = client.post(
                "/v1/infra/events",
                headers={
                    "l5d-client-id": CAGE_LULA_SA_L5D,
                    "Idempotency-Key": "lula-idle-23-of-26",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": ts_str,
                    "summary": (
                        "lula_audit INSUFFICIENT_TRAFFIC: 23/26 satisfied "
                        f"(3 not-satisfied [insufficient_traffic]: {','.join(idle_specs)})"
                    ),
                    "control_hint": "A.5.3",
                    "evaluated_count": 26,
                    "satisfied_count": 23,
                    "failed_count": 0,
                    "insufficient_traffic_count": 3,
                    "failed_controls": [],
                    "insufficient_traffic_controls": idle_specs,
                },
            )
            metrics_resp = client.get("/metrics")

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "INGESTED"
        mock_notifier.send_critical_alert.assert_not_called()

        assert (
            _metric_value(
                bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="insufficient_traffic"
            )
            == before_insuff + 1.0
        )
        assert (
            _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")
            == before_fails
        )
        assert _metric_value(bridge_main.LULA_AUDIT_EVALUATED_MANIFESTS) == 26.0
        assert _metric_value(bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS) == 0.0
        assert (
            _metric_value(bridge_main.LULA_AUDIT_INSUFFICIENT_TRAFFIC_CONTROLS) == 3.0
        )
        assert "cage_lula_audit_insufficient_traffic_controls" in metrics_resp.text

        # Verify sealed INFRA record passes JCS hash verification
        sync_redis = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
        entries = sync_redis.xrange("cage:test:infra:lula-three-state")
        assert len(entries) == 1
        _, sealed_entry = entries[0]
        verdict = verify_record(sealed_entry, "")
        assert verdict.valid, verdict.error

        # It is NOT a clean 26/26 PASS record:
        assert _is_passing_evidence_record(sealed_entry) is False

        # T+15m check: sealed idle lula_audit record must NOT contaminate A.5.3
        # total_traces (neither safety_rate=1.0 nor safety_rate=0.0)!
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[sealed_entry],
        ):
            a53_metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)
            assert a53_metrics.total_traces == 0
            assert a53_metrics.safety_rate is None

            # Yet the 1800s dead-man's switch recognizes the healthy 26-manifest
            # 0-failure execution so idle nights do not page after 30 minutes!
            age_s, last_iso = get_last_passing_lula_audit_age_seconds(window_hours=24)
            assert age_s is not None and age_s < 600.0
            assert last_iso is not None

        live_metrics = MagicMock()
        live_metrics.startup_grace_active = False
        live_metrics.evidence_age_seconds = 0.0
        before_deadman = _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)
        with (
            patch(
                "src.compliance_bridge.sla_monitor._active_sla_seconds",
                return_value={"A.5.3": 14400},
            ),
            patch(
                "src.compliance_bridge.sla_monitor.get_compliance_metrics",
                AsyncMock(return_value=live_metrics),
            ),
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=[sealed_entry],
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
        ):
            await sla_mod._check_sla_once()

        mock_notifier.send_critical_alert.assert_not_called()
        assert (
            _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL) == before_deadman
        )

    def test_non_statistical_control_claiming_insufficient_traffic_fails_closed_and_pages(
        self,
    ) -> None:
        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        before_fails = _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")

        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.create_notifier",
                return_value=mock_notifier,
            ),
            client_ctx as client,
        ):
            resp = client.post(
                "/v1/infra/events",
                headers={
                    "l5d-client-id": CAGE_LULA_SA_L5D,
                    "Idempotency-Key": "lula-spoofed-ac3-insuff",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-14T03:00:00Z",
                    "summary": (
                        "lula_audit INSUFFICIENT_TRAFFIC: 25/26 satisfied "
                        "(1 not-satisfied [insufficient_traffic]: lula-validation-ac3)"
                    ),
                    "control_hint": "A.5.3",
                    "evaluated_count": 26,
                    "satisfied_count": 25,
                    "failed_count": 0,
                    "insufficient_traffic_count": 1,
                    "failed_controls": [],
                    "insufficient_traffic_controls": ["lula-validation-ac3"],
                },
            )

        assert resp.status_code == 200, resp.text
        mock_notifier.send_critical_alert.assert_awaited_once()
        assert (
            _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")
            == before_fails + 1.0
        )
        assert _metric_value(bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS) >= 1.0
        assert (
            _metric_value(bridge_main.LULA_AUDIT_INSUFFICIENT_TRAFFIC_CONTROLS) == 0.0
        )
