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

"""Unit tests for PR-W0c: Lula A.5.3 metric-poisoning fix, fail-closed consumer alerting, and 2x-schedule dead-man's switch."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

import src.compliance_bridge.main as bridge_main
import src.compliance_bridge.sla_monitor as sla_mod
from src.compliance_bridge.infra_custody import InfraEvidenceChain
from src.compliance_bridge.main import InfraEvent, app
from src.compliance_bridge.metrics import (
    _fetch_from_evidence_stream_sync,
    _is_passing_evidence_record,
    get_last_passing_lula_audit_age_seconds,
    invalidate_compliance_metrics_cache,
)
from src.gateway.governance.evidence.stream import verify_record

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "infra" / "modules" / "lula_cron" / "run_lula_audit.sh"

POD_IP = "10.24.1.9"
CAGE_LULA_SA_L5D = (
    "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


def _make_lula_record(
    timestamp: datetime,
    *,
    summary: str,
    evaluated_count: int | None = None,
    satisfied_count: int | None = None,
    failed_count: int | None = None,
    not_satisfied_count: int | None = None,
    failed_controls: list[str] | None = None,
    sequence: int = 1,
    record_hash: str | None = None,
) -> dict[str, Any]:
    """Construct a wire-shaped INFRA `lula_audit` custody record for A.5.3."""
    payload: dict[str, Any] = {
        "control_hint": "A.5.3",
        "control_id": "A.5.3",
        "event_type": "lula_audit",
        "namespace": "governance-stack",
        "pod_name": None,
        "pod_name_verified": False,
        "producer_id": CAGE_LULA_SA_L5D,
        "producer_svid": "spiffe://cluster.local/ns/governance-stack/sa/cage-lula-sa",
        "producer_timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "received_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "source": "cage-lula-sa",
        "summary": summary,
    }
    if evaluated_count is not None:
        payload["evaluated_count"] = evaluated_count
    if satisfied_count is not None:
        payload["satisfied_count"] = satisfied_count
    if failed_count is not None:
        payload["failed_count"] = failed_count
    if not_satisfied_count is not None:
        payload["not_satisfied_count"] = not_satisfied_count
    if failed_controls is not None:
        payload["failed_controls"] = failed_controls

    return {
        "schema": "cage-audit/3.0",
        "chain_id": "00000000-0000-4000-8000-000000000099",
        "sequence": str(sequence),
        "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "event_type": "lula_audit",
        "control_id": "A.5.3",
        "trace_id": f"trace-{sequence}",
        "evidence_class": "INFRA",
        "prev_hash": "0" * 64,
        "record_hash": record_hash or (f"{sequence:064x}"),
        "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
    }


def _metric_value(metric: Any, **labels: str) -> float:
    """Read current value from a `prometheus_client` Counter or Gauge."""
    assert metric is not None, "prometheus_client collector must be registered"
    target = metric.labels(**labels) if labels else metric
    return float(target._value.get())


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
# Test 1: A.5.3 metric poisoning fix in `_is_passing_evidence_record()`
# ---------------------------------------------------------------------------


class TestLulaAuditMetricPoisoningFix:
    """Verify `lula_audit` failures never poison A.5.3 `safety_rate` or age."""

    def test_lula_audit_fail_22_of_26_is_blocking_and_lowers_a53_safety_rate(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        older_pass_ts = now - timedelta(hours=2)
        recent_fail_ts = now - timedelta(minutes=2)

        fail_rec = _make_lula_record(
            recent_fail_ts,
            summary=(
                "lula_audit FAIL: 22/26 satisfied "
                "(4 failed: lula-validation-a53,lula-validation-sc7,"
                "lula-validation-ac2,lula-validation-si7)"
            ),
            evaluated_count=26,
            satisfied_count=22,
            failed_controls=[
                "lula-validation-a53",
                "lula-validation-sc7",
                "lula-validation-ac2",
                "lula-validation-si7",
            ],
            sequence=2,
        )
        assert _is_passing_evidence_record(fail_rec) is False

        # Summary-only legacy record (no structured counts) must also fail closed
        legacy_fail_rec = _make_lula_record(
            recent_fail_ts,
            summary="lula_audit FAIL: 22/26 satisfied (4 failed: lula-validation-a53)",
            sequence=3,
        )
        assert _is_passing_evidence_record(legacy_fail_rec) is False

        # Structured failure indicators override a spoofed PASS summary
        for bad_kwargs in (
            {"failed_count": 1},
            {"not_satisfied_count": 2},
            {"failed_controls": ["lula-validation-sc7"]},
            {"evaluated_count": 0, "satisfied_count": 0},
        ):
            spoofed = _make_lula_record(
                recent_fail_ts,
                summary="lula_audit PASS: 26/26 active validations satisfied",
                sequence=4,
                **bad_kwargs,  # type: ignore[arg-type]
            )
            assert _is_passing_evidence_record(spoofed) is False

        # Non-zero `not-satisfied` or missing `lula_audit PASS:` prefix fails closed
        assert (
            _is_passing_evidence_record(
                _make_lula_record(
                    recent_fail_ts,
                    summary="lula_audit PASS: 26/26 active validations satisfied (1 not-satisfied)",
                    sequence=5,
                )
            )
            is False
        )
        assert (
            _is_passing_evidence_record(
                _make_lula_record(
                    recent_fail_ts,
                    summary="26/26 active validations satisfied",
                    evaluated_count=26,
                    satisfied_count=26,
                    sequence=6,
                )
            )
            is False
        )

        # Aggregation over 1 older pass + 1 recent fail lowers safety_rate to 0.5
        # AND preserves older_pass_ts rather than resetting A.5.3 evidence age!
        pass_rec = _make_lula_record(
            older_pass_ts,
            summary="lula_audit PASS: 26/26 active validations satisfied",
            evaluated_count=26,
            satisfied_count=26,
            failed_controls=[],
            sequence=1,
        )
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[fail_rec, pass_rec],
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)

        assert metrics.total_traces == 2
        assert metrics.passed_traces == 1
        assert metrics.blocked_traces == 1
        assert metrics.safety_rate == 0.5
        assert metrics.evidence_age_seconds >= 7000


# ---------------------------------------------------------------------------
# Test 2, 3, 4: `POST /v1/infra/events` pass, fail, corpus floor & script JSON
# ---------------------------------------------------------------------------


class TestComplianceBridgeLulaAuditConsumer:
    """Verify WORM sealing, Prometheus gauges/counters, and critical alerting."""

    def _build_client(
        self, fake_server: fakeredis.FakeServer
    ) -> tuple[InfraEvidenceChain, TestClient]:
        chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key="cage:test:infra:lula-alerting",
        )
        app.state.infra_evidence_chain = chain
        client = TestClient(
            app,
            client=(POD_IP, 50000),
            base_url=f"http://{POD_IP}:3001",
            raise_server_exceptions=False,
        )
        return chain, client

    def test_clean_pass_26_of_26_updates_pass_timestamp_without_alerting(self) -> None:
        now = datetime.now(tz=timezone.utc)
        pass_rec = _make_lula_record(
            now,
            summary="lula_audit PASS: 26/26 active validations satisfied (0 not-satisfied)",
            evaluated_count=26,
            satisfied_count=26,
            failed_controls=[],
        )
        assert _is_passing_evidence_record(pass_rec) is True

        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        before_passes = _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="pass")
        if bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS is not None:
            bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS.set(0.0)

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
                    "Idempotency-Key": "lula-pass-26-of-26",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-09T12:00:00Z",
                    "summary": "lula_audit PASS: 26/26 active validations satisfied",
                    "control_hint": "A.5.3",
                    "evaluated_count": 26,
                    "satisfied_count": 26,
                    "failed_controls": [],
                },
            )
            metrics_resp = client.get("/metrics")

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "INGESTED"
        mock_notifier.send_critical_alert.assert_not_called()

        assert (
            _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="pass")
            == before_passes + 1.0
        )
        assert _metric_value(bridge_main.LULA_AUDIT_EVALUATED_MANIFESTS) == 26.0
        assert _metric_value(bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS) == 0.0
        assert _metric_value(bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS) > 0.0
        assert metrics_resp.status_code == 200
        assert "cage_lula_audit_not_satisfied_controls" in metrics_resp.text

    def test_lula_audit_fail_seals_worm_receipt_and_dispatches_critical_alert(
        self,
    ) -> None:
        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        if bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS is not None:
            bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS.set(12345.0)
        before_fails = _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")

        failed_specs = [
            "lula-validation-a53",
            "lula-validation-sc7",
            "lula-validation-ac2",
            "lula-validation-si7",
        ]
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
                    "Idempotency-Key": "lula-fail-22-of-26",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-09T12:15:00Z",
                    "summary": (
                        "lula_audit FAIL: 22/26 satisfied "
                        f"(4 failed: {','.join(failed_specs)})"
                    ),
                    "control_hint": "A.5.3",
                    "evaluated_count": 26,
                    "satisfied_count": 22,
                    "failed_controls": failed_specs,
                },
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "INGESTED"
        assert len(body["record_hash"]) == 64

        # Verify sealed INFRA record passes JCS self-verification with structured fields
        sync_redis = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
        entries = sync_redis.xrange("cage:test:infra:lula-alerting")
        assert len(entries) == 1
        _, sealed_entry = entries[0]
        verdict = verify_record(sealed_entry, "")
        assert verdict.valid, verdict.error
        sealed_payload = json.loads(sealed_entry["payload_json"])
        assert sealed_payload["evaluated_count"] == 26
        assert sealed_payload["satisfied_count"] == 22
        assert sealed_payload["failed_controls"] == failed_specs

        # Verify loud critical alert includes A.5.3 + each failed control
        mock_notifier.send_critical_alert.assert_awaited_once()
        findings, audit_id = mock_notifier.send_critical_alert.call_args.args
        assert audit_id.startswith("lula-audit-")
        control_ids = [f.control_id for f in findings]
        assert control_ids == ["A.5.3", *failed_specs]
        assert all(f.result == "FAIL" for f in findings)

        # Verify Prometheus metrics reflect failure and do NOT advance last_pass_timestamp
        assert (
            _metric_value(bridge_main.LULA_AUDIT_RUNS_TOTAL, outcome="fail")
            == before_fails + 1.0
        )
        assert _metric_value(bridge_main.LULA_AUDIT_EVALUATED_MANIFESTS) == 26.0
        assert _metric_value(bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS) == 4.0
        assert (
            _metric_value(bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS) == 12345.0
        )

    @pytest.mark.parametrize(
        ("evaluated", "satisfied", "idem"),
        [
            (0, 0, "lula-floor-0-of-0"),
            (12, 12, "lula-floor-12-of-12"),
        ],
    )
    def test_corpus_floor_breach_fails_closed_and_alerts(
        self, evaluated: int, satisfied: int, idem: str
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        rec = _make_lula_record(
            now,
            summary=f"lula_audit PASS: {satisfied}/{evaluated} active validations satisfied",
            evaluated_count=evaluated,
            satisfied_count=satisfied,
            failed_controls=[],
        )
        assert _is_passing_evidence_record(rec) is False

        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        if bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS is not None:
            bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS.set(999.0)

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
                    "Idempotency-Key": idem,
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-09T12:30:00Z",
                    "summary": (
                        f"lula_audit PASS: {satisfied}/{evaluated} "
                        "active validations satisfied"
                    ),
                    "control_hint": "A.5.3",
                    "evaluated_count": evaluated,
                    "satisfied_count": satisfied,
                    "failed_controls": [],
                },
            )

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "INGESTED"
        mock_notifier.send_critical_alert.assert_awaited_once()
        findings, _ = mock_notifier.send_critical_alert.call_args.args
        assert findings[0].control_id == "A.5.3"
        assert findings[0].result == "FAIL"
        assert "corpus-floor breach" in (findings[0].remarks or "")
        assert _metric_value(bridge_main.LULA_AUDIT_NOT_SATISFIED_CONTROLS) >= float(
            26 - evaluated
        )
        assert (
            _metric_value(bridge_main.LULA_AUDIT_LAST_PASS_TIMESTAMP_SECONDS) == 999.0
        )

    def test_notifier_transport_error_does_not_drop_worm_receipt(self) -> None:
        fake_server = fakeredis.FakeServer()
        _, client_ctx = self._build_client(fake_server)
        broken_notifier = MagicMock()
        broken_notifier.send_critical_alert = AsyncMock(
            side_effect=RuntimeError("webhook unreachable")
        )

        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.create_notifier",
                return_value=broken_notifier,
            ),
            client_ctx as client,
        ):
            resp = client.post(
                "/v1/infra/events",
                headers={"l5d-client-id": CAGE_LULA_SA_L5D},
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-09T12:45:00Z",
                    "summary": "lula_audit FAIL: 25/26 satisfied (1 failed: lula-validation-ac2)",
                    "control_hint": "A.5.3",
                    "evaluated_count": 26,
                    "satisfied_count": 25,
                    "failed_controls": ["lula-validation-ac2"],
                },
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "INGESTED"
        broken_notifier.send_critical_alert.assert_awaited_once()

    def test_run_lula_audit_script_emits_structured_counts_and_keeps_sealed_stdout(
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
            "  *ac2*) printf 'observations:\\n  - state: not-satisfied\\n' > \"$out\" ;;\n"
            "  *) printf 'observations:\\n  - state: satisfied\\n' > \"$out\" ;;\n"
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

        (specs_dir / "lula-validation-ac2.yaml").write_text("x: 1\n", encoding="utf-8")
        (specs_dir / "lula-validation-si7.yaml").write_text("x: 1\n", encoding="utf-8")

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
        assert proc.returncode == 1
        assert (
            f"Sealed lula_audit assessment-results via /v1/infra/events: "
            f"status=INGESTED record_hash={'0' * 64} (1/2 satisfied, 1 not-satisfied)"
            in proc.stdout
        )
        post_line = next(
            line
            for line in log_file.read_text(encoding="utf-8").splitlines()
            if "/v1/infra/events" in line
        )
        posted = json.loads(post_line.split("|", 1)[1])
        assert posted["evaluated_count"] == 2
        assert posted["satisfied_count"] == 1
        assert posted["failed_controls"] == ["lula-validation-ac2"]
        validated = InfraEvent.model_validate(posted)
        assert validated.failed_controls == ["lula-validation-ac2"]


# ---------------------------------------------------------------------------
# Test 5: `2 x schedule` Dead-Man's Switch in `sla_monitor.py`
# ---------------------------------------------------------------------------


class TestLulaAuditDeadManSwitch:
    """Verify `2 x schedule` dead-man's switch catches missing/stale/failing runs."""

    @pytest.mark.asyncio
    async def test_deadman_alerts_when_only_failing_lula_audit_events_exist(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        only_fails = [
            _make_lula_record(
                now - timedelta(minutes=3),
                summary="lula_audit FAIL: 22/26 satisfied (4 failed: lula-validation-a53)",
                evaluated_count=26,
                satisfied_count=22,
                failed_controls=["lula-validation-a53"],
                sequence=1,
            )
        ]

        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=only_fails,
        ):
            age, ts = get_last_passing_lula_audit_age_seconds(window_hours=24)
            assert age is None
            assert ts is None

        mock_metrics = MagicMock()
        mock_metrics.startup_grace_active = False
        mock_metrics.evidence_age_seconds = 120.0

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        before_deadman = _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)

        with (
            patch(
                "src.compliance_bridge.sla_monitor._active_sla_seconds",
                return_value={"A.5.3": 14400},
            ),
            patch(
                "src.compliance_bridge.sla_monitor.get_compliance_metrics",
                AsyncMock(return_value=mock_metrics),
            ),
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=only_fails,
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
        ):
            breached = await sla_mod._check_sla_once()

        # General 4h A.5.3 SLA did not breach, yet dead-man's switch caught the failing-only loop!
        assert breached == []
        mock_notifier.send_critical_alert.assert_awaited_once()
        findings, audit_id = mock_notifier.send_critical_alert.call_args.args
        assert audit_id.startswith("lula-audit-deadman-")
        assert len(findings) == 1
        assert findings[0].control_id == "A.5.3"
        assert findings[0].result == "FAIL"
        assert findings[0].finding_id.startswith("lula-audit-deadman-")
        assert (
            _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)
            == before_deadman + 1.0
        )

    @pytest.mark.asyncio
    async def test_deadman_alerts_when_last_pass_exceeds_max_age_seconds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LULA_AUDIT_MAX_AGE_SECONDS", "1800")
        now = datetime.now(tz=timezone.utc)
        stale_pass = [
            _make_lula_record(
                now - timedelta(seconds=2400),
                summary="lula_audit PASS: 26/26 active validations satisfied",
                evaluated_count=26,
                satisfied_count=26,
                failed_controls=[],
                sequence=1,
            )
        ]

        mock_metrics = MagicMock()
        mock_metrics.startup_grace_active = False
        mock_metrics.evidence_age_seconds = 2400.0

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        before_deadman = _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)

        with (
            patch(
                "src.compliance_bridge.sla_monitor._active_sla_seconds",
                return_value={"A.5.3": 14400},
            ),
            patch(
                "src.compliance_bridge.sla_monitor.get_compliance_metrics",
                AsyncMock(return_value=mock_metrics),
            ),
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=stale_pass,
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
        ):
            await sla_mod._check_sla_once()

        mock_notifier.send_critical_alert.assert_awaited_once()
        assert (
            _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)
            == before_deadman + 1.0
        )

    @pytest.mark.asyncio
    async def test_deadman_stays_quiet_during_startup_grace_and_on_fresh_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        fresh_pass = [
            _make_lula_record(
                now - timedelta(seconds=300),
                summary="lula_audit PASS: 26/26 active validations satisfied",
                evaluated_count=26,
                satisfied_count=26,
                failed_controls=[],
                sequence=1,
            )
        ]

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        before_deadman = _metric_value(sla_mod.LULA_AUDIT_DEADMAN_BREACHES_TOTAL)

        # 1. Startup grace active (even when zero records exist) -> silent
        grace_metrics = MagicMock()
        grace_metrics.startup_grace_active = True
        grace_metrics.startup_grace_remaining_hours = 4.0

        with (
            patch(
                "src.compliance_bridge.sla_monitor._active_sla_seconds",
                return_value={"A.5.3": 14400},
            ),
            patch(
                "src.compliance_bridge.sla_monitor.get_compliance_metrics",
                AsyncMock(return_value=grace_metrics),
            ),
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=[],
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
        ):
            await sla_mod._check_sla_once()

        mock_notifier.send_critical_alert.assert_not_called()

        # 2. Grace inactive, fresh 26/26 pass (300s <= 1800s) -> silent
        live_metrics = MagicMock()
        live_metrics.startup_grace_active = False
        live_metrics.evidence_age_seconds = 300.0

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
                return_value=fresh_pass,
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

        # 3. Opt-out via LULA_AUDIT_DEADMAN_DISABLED=1 -> silent
        monkeypatch.setenv("LULA_AUDIT_DEADMAN_DISABLED", "1")
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
                return_value=[],
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
        ):
            await sla_mod._check_sla_once()

        mock_notifier.send_critical_alert.assert_not_called()


def test_compliance_bridge_gmp_podmonitoring_and_promql_alert_policy_wiring() -> None:
    """compliance-bridge exposes :9090 metrics with GMP PodMonitoring and PromQL disable_metric_validation."""
    import base64
    import re
    from pathlib import Path

    import yaml

    repo = Path(__file__).resolve().parents[2]
    cb_tf = (repo / "infra/modules/compliance_bridge/main.tf").read_text(
        encoding="utf-8"
    )
    assert "skip-inbound-ports" not in cb_tf
    assert "container_port = 9090" in cb_tf
    assert 'name  = "CAGE_METRICS_PORT"' in cb_tf
    assert 'name            = "compliance-bridge-metrics-monitors"' in cb_tf
    cb_mesh = (
        repo / "infra/modules/compliance_bridge/mesh-policy/templates/policy.yaml"
    ).read_text(encoding="utf-8")
    assert "name: compliance-bridge-metrics" in cb_mesh
    assert "name: compliance-bridge-metrics-scrape" in cb_mesh

    chart_dir = repo / "infra/modules/compliance_bridge/metrics-monitors"
    values = yaml.safe_load((chart_dir / "values.yaml").read_text(encoding="utf-8"))
    tpl = (chart_dir / "templates/monitors.yaml").read_text(encoding="utf-8")
    rendered = re.sub(r"\{\{-?\s*if\s+[^}]+\}\}\n?", "", tpl)
    rendered = re.sub(r"\{\{-?\s*end\s*\}\}\n?", "", rendered)
    rendered = re.sub(
        r"\{\{\s*\.Release\.Namespace\s*\}\}", "governance-stack", rendered
    )
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
    pm = yaml.safe_load(rendered)
    assert pm["kind"] == "PodMonitoring"
    assert pm["metadata"]["name"] == "compliance-bridge-metrics"
    assert pm["spec"]["selector"]["matchLabels"] == {"app": "compliance-bridge"}
    assert pm["spec"]["endpoints"][0]["port"] == "metrics"
    assert pm["spec"]["endpoints"][0]["path"] == "/metrics"

    netpol_tf = (repo / "infra/targets/gcp-gke/network_policy.tf").read_text(
        encoding="utf-8"
    )
    cb_ing_start = netpol_tf.index(
        'resource "kubernetes_network_policy_v1" "compliance_bridge_ingress"'
    )
    cb_ing_end = netpol_tf.index(
        'resource "kubernetes_network_policy_v1" "compliance_bridge_egress_l3_l4"',
        cb_ing_start,
    )
    cb_ing = netpol_tf[cb_ing_start:cb_ing_end]
    assert '"gmp-system"' in cb_ing
    assert 'port     = "9090"' in cb_ing

    alert_tf = (repo / "infra/targets/gcp-gke/lula_alerting.tf").read_text(
        encoding="utf-8"
    )
    assert alert_tf.count("condition_prometheus_query_language {") == 1
    assert alert_tf.count("disable_metric_validation = true") == 1
    assert (
        'resource "google_monitoring_alert_policy" "lula_audit_pod_restart"' in alert_tf
    )

    lifecycle_sh = (repo / "scripts/staging_lifecycle.sh").read_text(encoding="utf-8")
    assert '"google_storage_bucket.langfuse_event_upload"' in lifecycle_sh
    assert '"random_id.bucket_suffix"' in lifecycle_sh
    assert "langfuse-event-upload-${PROJECT_ID}-[0-9a-f]{8}" in lifecycle_sh

    bootstrap_sh = (repo / "scripts/bootstrap_gcp_project.sh").read_text(
        encoding="utf-8"
    )
    assert '"random_id.bucket_suffix"' in bootstrap_sh
    assert '"google_storage_bucket.langfuse_event_upload"' in bootstrap_sh
    # Verify exact HashiCorp random_id base64url import encoding (live state: fe82cebc -> _oLOvA):
    assert (
        base64.urlsafe_b64encode(bytes.fromhex("fe82cebc")).decode("ascii").rstrip("=")
        == "_oLOvA"
    )
