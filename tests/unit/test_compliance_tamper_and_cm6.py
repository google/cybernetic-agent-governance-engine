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

"""Unit tests for Track B Slice 1 (`IAB-03`, `IAB-04`, and `CSC-04` CM-6 repointing).

Covers:
1. `IAB-03`:
   - `GOVERNANCE_INFRASTRUCTURE_BLOCK` partitioned into `infrastructure_blocks`
     without entering `total_traces`, `passed_traces`, `blocked_traces`,
     `safety_rate`, or `last_event_date` / `evidence_age_seconds`.
   - `SANDBOX_OCSF_TELEMETRY` classified in `_is_passing_evidence_record()` and
     `_is_control_effective_record()` using `ocsf_disposition`, `ocsf_action`,
     `ocsf_severity_id`, and `governance_decision_digest`.
2. `IAB-04`:
   - `EvidenceCustodyIntegrityError` and `NonEvidentiaryAttestationError`
     propagated from `_query_cage_evidence_records()`, returning HTTP `503`
     (`custody_integrity_error`) on `GET /v1/metrics/summary` and
     `GET /v1/metrics/{control_id}`, and firing consolidated CRITICAL tamper
     alerts in `_check_sla_once()`.
   - Per-control `TimeoutError` and fetch errors recorded in `errored_controls`
     and `failing_controls` (never counted in `passing_controls`) and alerted
     as SLA check failures in `_check_sla_once()`.
3. `CSC-04` (`POAM-2026-151` Option 2 Step 2):
   - `GET /v1/compliance/cm6` and `GET /v1/config/cm6` evaluating
     `GOVERNANCE_THRESHOLDS_LOADED` (`thresholds_digest`, `region`,
     `schema_version`, `domain_sections`) and `GOVERNANCE_DECISION` digest drift.
   - `compliance/lula/lula-validation-cm6.yaml` API-domain contract.
"""

# Regression coverage binding: POAM-2026-151, POAM-2026-233, POAM-2026-234

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from fastapi.testclient import TestClient

from src.compliance_bridge.evidence_custodian import (
    EvidenceCustodyIntegrityError,
    NonEvidentiaryAttestationError,
)
from src.compliance_bridge.metrics import (
    _fetch_from_evidence_stream_sync,
    _is_control_effective_record,
    _is_passing_evidence_record,
    _query_cage_evidence_records,
    evaluate_cm6_thresholds_records,
    invalidate_compliance_metrics_cache,
)
from src.compliance_bridge.types import ComplianceMetrics

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_stream_record(
    ts: datetime,
    *,
    control_id: str = "A.5.3",
    event_type: str = "GOVERNANCE_DECISION",
    sequence: int = 1,
    stream_id: str | None = None,
    payload_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": event_type,
        "controlId": control_id,
        "timestamp_utc": ts.isoformat(),
    }
    if payload_extra:
        payload.update(payload_extra)
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    chain_id = "00000000-0000-4000-8000-000000000099"
    record_hash = hashlib.sha256(
        f"{chain_id}:{sequence}:{payload_json}".encode()
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "chain_id": chain_id,
        "sequence": str(sequence),
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "control_id": control_id,
        "trace_id": f"trace-{sequence}",
        "payload": payload_json,
        "prev_hash": "0" * 64,
        "record_hash": record_hash,
        "stream_id": stream_id or f"{int(ts.timestamp() * 1000)}-{sequence}",
    }


@pytest.fixture
def bridge_client() -> Any:
    with patch("src.compliance_bridge.main.Langfuse") as mock_lf:
        mock_lf.return_value = MagicMock()
        from src.compliance_bridge.auth import require_internal_token
        from src.compliance_bridge.main import app

        app.dependency_overrides[require_internal_token] = lambda: "test-token"
        try:
            with TestClient(app, raise_server_exceptions=False) as c:
                yield c
        finally:
            app.dependency_overrides.pop(require_internal_token, None)


class TestIab03InfrastructureBlocksAndOcsf:
    """IAB-03: Partition infra outages from safety_rate/freshness & classify OCSF."""

    @pytest.mark.covers(
        "src.compliance_bridge.metrics:_fetch_from_evidence_stream_sync#infrastructure_blocks += 1"
    )
    def test_infrastructure_block_only_stream_leaves_traces_and_freshness_untouched(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_stream_record(
                now - timedelta(seconds=30),
                control_id="A.5.3",
                event_type="GOVERNANCE_INFRASTRUCTURE_BLOCK",
                sequence=1,
                payload_extra={"verdict": "INFRASTRUCTURE_UNAVAILABLE"},
            ),
            _make_stream_record(
                now - timedelta(seconds=10),
                control_id="A.5.3",
                event_type="GOVERNANCE_INFRASTRUCTURE_BLOCK",
                sequence=2,
                payload_extra={"verdict": "INFRASTRUCTURE_UNAVAILABLE"},
            ),
        ]
        with (
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=records,
            ),
            patch(
                "src.compliance_bridge.metrics._get_grace_status",
                return_value={"active": False, "remaining_hours": 0.0},
            ),
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)

        assert metrics.infrastructure_blocks == 2
        assert metrics.total_traces == 0
        assert metrics.passed_traces == 0
        assert metrics.blocked_traces == 0
        assert metrics.safety_rate is None
        assert metrics.evidence_age_seconds == 0.0

    @pytest.mark.covers(
        "src.compliance_bridge.metrics:_fetch_from_evidence_stream_sync#infrastructure_blocks += 1"
    )
    def test_infrastructure_blocks_do_not_depress_safety_rate_or_advance_last_event(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        two_hours_ago = now - timedelta(hours=2)
        ten_seconds_ago = now - timedelta(seconds=10)
        records = [
            _make_stream_record(
                two_hours_ago,
                control_id="A.5.3",
                event_type="GOVERNANCE_DECISION",
                sequence=1,
                payload_extra={"verdict": "ALLOW"},
            ),
            _make_stream_record(
                ten_seconds_ago,
                control_id="A.5.3",
                event_type="GOVERNANCE_INFRASTRUCTURE_BLOCK",
                sequence=2,
                payload_extra={"verdict": "INFRASTRUCTURE_UNAVAILABLE"},
            ),
        ]
        with (
            patch(
                "src.compliance_bridge.metrics._query_cage_evidence_records",
                return_value=records,
            ),
            patch(
                "src.compliance_bridge.metrics._get_grace_status",
                return_value={"active": False, "remaining_hours": 0.0},
            ),
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)

        assert metrics.infrastructure_blocks == 1
        assert metrics.total_traces == 1
        assert metrics.passed_traces == 1
        assert metrics.blocked_traces == 0
        assert metrics.safety_rate == 1.0
        assert metrics.last_event_utc == two_hours_ago.isoformat()
        assert metrics.evidence_age_seconds >= 7100.0

    @pytest.mark.covers(
        "src.compliance_bridge.metrics:_classify_sandbox_ocsf_telemetry"
    )
    def test_sandbox_ocsf_telemetry_classifies_allow_containment_and_violation(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        valid_digest = "a" * 64

        allowed_rec = _make_stream_record(
            now,
            control_id="SC-7",
            event_type="SANDBOX_OCSF_TELEMETRY",
            sequence=1,
            payload_extra={
                "ocsf_disposition": "Allowed",
                "ocsf_action": "Allowed",
                "ocsf_severity_id": 1,
                "governance_decision_digest": valid_digest,
            },
        )
        assert _is_passing_evidence_record(allowed_rec) is True
        assert _is_control_effective_record(allowed_rec) is True

        contained_rec = _make_stream_record(
            now,
            control_id="SC-7",
            event_type="SANDBOX_OCSF_TELEMETRY",
            sequence=2,
            payload_extra={
                "ocsf_disposition": "Blocked",
                "ocsf_action": "Denied",
                "ocsf_severity_id": 3,
                "governance_decision_digest": valid_digest,
            },
        )
        assert _is_passing_evidence_record(contained_rec) is False
        assert _is_control_effective_record(contained_rec) is True

        violation_rec = _make_stream_record(
            now,
            control_id="SC-7",
            event_type="SANDBOX_OCSF_TELEMETRY",
            sequence=3,
            payload_extra={
                "ocsf_disposition": "Alert",
                "ocsf_action": "Observed",
                "ocsf_severity_id": 5,
                "governance_decision_digest": None,
            },
        )
        assert _is_passing_evidence_record(violation_rec) is False
        assert _is_control_effective_record(violation_rec) is False

        high_sev_unsealed_allow = _make_stream_record(
            now,
            control_id="SC-7",
            event_type="SANDBOX_OCSF_TELEMETRY",
            sequence=4,
            payload_extra={
                "ocsf_disposition": "Allowed",
                "ocsf_action": "Allowed",
                "ocsf_severity_id": 4,
                "governance_decision_digest": None,
            },
        )
        assert _is_passing_evidence_record(high_sev_unsealed_allow) is False
        assert _is_control_effective_record(high_sev_unsealed_allow) is False


class TestIab04CustodyTamperAndSummaryAccounting:
    """IAB-04: Propagate WORM tamper (503 + critical SLA alert) & strict summary pass rate."""

    @pytest.mark.covers(
        "src.compliance_bridge.metrics:_query_cage_evidence_records#_read_cold_store_records_async"
    )
    def test_query_cage_evidence_records_propagates_custody_tamper_in_all_postures(
        self,
    ) -> None:
        invalidate_compliance_metrics_cache()
        fake_store = MagicMock()
        fake_store._bucket_name = "tampered-worm-bucket"
        with (
            patch.dict(os.environ, {"CAGE_ENV": "test"}, clear=False),
            patch(
                "src.compliance_bridge.metrics._resolve_metrics_cold_store",
                return_value=fake_store,
            ),
            patch(
                "src.compliance_bridge.metrics._read_cold_store_records_async",
                new=AsyncMock(
                    side_effect=EvidenceCustodyIntegrityError("WORM hash chain broken")
                ),
            ),
        ):
            with pytest.raises(
                EvidenceCustodyIntegrityError, match="WORM hash chain broken"
            ):
                _query_cage_evidence_records("A.5.2", window_hours=24)

    @pytest.mark.covers(
        "src.compliance_bridge.main:get_metrics_summary#custody_integrity_error"
    )
    def test_metrics_summary_fails_closed_503_on_custody_integrity_error(
        self, bridge_client: TestClient
    ) -> None:
        async def _tampered(
            control_id: str, window_hours: int = 24
        ) -> ComplianceMetrics:
            if control_id == "A.9.2":
                raise EvidenceCustodyIntegrityError("batch signature invalid")
            return ComplianceMetrics(
                control_id=control_id,
                safety_rate=1.0,
                total_traces=5,
                blocked_traces=0,
                passed_traces=5,
                window_hours=float(window_hours),
                last_event_utc=datetime.now(tz=timezone.utc).isoformat(),
                evidence_age_seconds=5.0,
                startup_grace_active=False,
                startup_grace_remaining_hours=0.0,
            )

        with patch(
            "src.compliance_bridge.main.get_compliance_metrics",
            new=AsyncMock(side_effect=_tampered),
        ):
            resp = bridge_client.get("/v1/metrics/summary")

        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "custody_integrity_error"
        assert "batch signature invalid" in body["detail"]["message"]

    @pytest.mark.covers(
        "src.compliance_bridge.main:get_metrics#custody_integrity_error"
    )
    def test_single_control_metrics_fails_closed_503_on_non_evidentiary_attestation(
        self, bridge_client: TestClient
    ) -> None:
        with patch(
            "src.compliance_bridge.main.get_compliance_metrics",
            new=AsyncMock(
                side_effect=NonEvidentiaryAttestationError("unsigned batch in WORM")
            ),
        ):
            resp = bridge_client.get("/v1/metrics/A.5.2")

        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "custody_integrity_error"
        assert "unsigned batch in WORM" in body["detail"]["message"]

    def test_metrics_summary_never_counts_timed_out_or_errored_controls_as_passing(
        self, bridge_client: TestClient
    ) -> None:
        async def _all_timeout(
            control_id: str, window_hours: int = 24
        ) -> ComplianceMetrics:
            raise asyncio.TimeoutError()

        with patch(
            "src.compliance_bridge.main.get_compliance_metrics",
            new=AsyncMock(side_effect=_all_timeout),
        ):
            resp = bridge_client.get("/v1/metrics/summary")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total_controls"] > 0
        assert data["passing_controls"] == 0
        assert data["overall_pass_rate"] == 0.0
        assert set(data["errored_controls"]) == set(data["controls"].keys())
        assert set(data["failing_controls"]) == set(data["controls"].keys())
        assert "A.9.2" in data["critical_fails"]

    def test_metrics_summary_marks_stale_control_failing_outside_grace(
        self, bridge_client: TestClient
    ) -> None:
        async def _stale_a92(
            control_id: str, window_hours: int = 24
        ) -> ComplianceMetrics:
            age = 9_000.0 if control_id == "A.9.2" else 10.0
            return ComplianceMetrics(
                control_id=control_id,
                safety_rate=1.0,
                total_traces=10,
                blocked_traces=0,
                passed_traces=10,
                window_hours=float(window_hours),
                last_event_utc=datetime.now(tz=timezone.utc).isoformat(),
                evidence_age_seconds=age,
                startup_grace_active=False,
                startup_grace_remaining_hours=0.0,
            )

        with patch(
            "src.compliance_bridge.main.get_compliance_metrics",
            new=AsyncMock(side_effect=_stale_a92),
        ):
            data = bridge_client.get("/v1/metrics/summary").json()

        assert "A.9.2" in data["failing_controls"]
        assert "A.9.2" in data["critical_fails"]
        assert data["passing_controls"] == data["total_controls"] - 1

    @pytest.mark.asyncio
    @pytest.mark.covers(
        "src.compliance_bridge.sla_monitor:_check_sla_once#EvidenceCustodyIntegrityError"
    )
    async def test_sla_monitor_dispatches_critical_alert_on_custody_tamper_and_fetch_error(
        self,
    ) -> None:
        from src.compliance_bridge.sla_monitor import _check_sla_once

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        async def _mixed_failures(
            control_id: str, window_hours: int = 24
        ) -> ComplianceMetrics:
            if control_id == "A.9.2":
                raise EvidenceCustodyIntegrityError("prev_hash mismatch in WORM")
            if control_id == "A.5.3":
                raise TimeoutError("valkey read timed out")
            return ComplianceMetrics(
                control_id=control_id,
                safety_rate=1.0,
                total_traces=4,
                blocked_traces=0,
                passed_traces=4,
                window_hours=float(window_hours),
                last_event_utc=datetime.now(tz=timezone.utc).isoformat(),
                evidence_age_seconds=15.0,
                startup_grace_active=False,
                startup_grace_remaining_hours=0.0,
            )

        with (
            patch(
                "src.compliance_bridge.sla_monitor.get_compliance_metrics",
                new=AsyncMock(side_effect=_mixed_failures),
            ),
            patch(
                "src.compliance_bridge.sla_monitor.create_notifier",
                return_value=mock_notifier,
            ),
            patch(
                "src.compliance_bridge.sla_monitor._check_lula_audit_deadman",
                new=AsyncMock(),
            ),
        ):
            breached = await _check_sla_once()

        assert "A.9.2" in breached
        assert "A.5.3" in breached
        assert mock_notifier.send_critical_alert.await_count == 2

        dispatched_batches = [
            call.args[0] for call in mock_notifier.send_critical_alert.await_args_list
        ]
        tamper_batch = next(
            b
            for b in dispatched_batches
            if any(f.assessment_status == "custody_integrity_error" for f in b)
        )
        fetch_err_batch = next(
            b
            for b in dispatched_batches
            if any(f.assessment_status == "sla_fetch_error" for f in b)
        )
        assert tamper_batch[0].control_id == "A.9.2"
        assert tamper_batch[0].result == "FAIL"
        assert "prev_hash mismatch" in (tamper_batch[0].remarks or "")
        assert fetch_err_batch[0].control_id == "A.5.3"
        assert fetch_err_batch[0].result == "ERROR"


class TestCsc04Cm6EndpointsAndLulaManifest:
    """CSC-04 (`POAM-2026-151` Option 2 Step 2): CM-6 posture endpoints & Lula API spec."""

    def test_evaluate_cm6_thresholds_records_satisfied_and_drift_cases(self) -> None:
        now = datetime.now(tz=timezone.utc)
        digest_a = "1" * 64
        digest_b = "2" * 64

        empty_posture = evaluate_cm6_thresholds_records([], active_region="US_FED")
        assert empty_posture.assessment_status == "not_satisfied"
        assert empty_posture.decisions_checked == 0

        records_ok = [
            _make_stream_record(
                now - timedelta(minutes=30),
                control_id="SC-4",
                event_type="GOVERNANCE_DECISION",
                sequence=1,
                payload_extra={"verdict": "ALLOW", "thresholds_digest": digest_a},
            ),
            _make_stream_record(
                now - timedelta(minutes=20),
                control_id="CM-6",
                event_type="GOVERNANCE_THRESHOLDS_LOADED",
                sequence=2,
                payload_extra={
                    "schema_version": 1,
                    "region": "US_FED",
                    "thresholds_digest": digest_b,
                    "domain_sections": ["finance"],
                },
            ),
            _make_stream_record(
                now - timedelta(minutes=10),
                control_id="SC-4",
                event_type="GOVERNANCE_DECISION",
                sequence=3,
                payload_extra={"verdict": "ALLOW", "thresholds_digest": digest_b},
            ),
            _make_stream_record(
                now - timedelta(minutes=5),
                control_id="SC-4",
                event_type="GOVERNANCE_DECISION",
                sequence=4,
                payload_extra={"verdict": "DENY", "thresholds_digest": digest_b},
            ),
        ]
        ok_posture = evaluate_cm6_thresholds_records(records_ok, active_region="US_FED")
        assert ok_posture.assessment_status == "satisfied"
        assert ok_posture.thresholds_digest == digest_b
        assert ok_posture.region == "US_FED"
        assert ok_posture.schema_version == 1
        assert ok_posture.domain_sections == ["finance"]
        assert ok_posture.decisions_checked == 2
        assert ok_posture.digest_mismatches == 0

        mismatch_region = evaluate_cm6_thresholds_records(
            records_ok, active_region="EU_ECB"
        )
        assert mismatch_region.assessment_status == "not_satisfied"

        records_drift = [
            *records_ok,
            _make_stream_record(
                now - timedelta(minutes=1),
                control_id="SC-4",
                event_type="GOVERNANCE_DECISION",
                sequence=5,
                payload_extra={"verdict": "ALLOW", "thresholds_digest": digest_a},
            ),
        ]
        drifted = evaluate_cm6_thresholds_records(records_drift, active_region="US_FED")
        assert drifted.assessment_status == "not_satisfied"
        assert drifted.decisions_checked == 3
        assert drifted.digest_mismatches == 1

    def test_cm6_canonical_and_alias_routes_return_identical_posture(
        self, bridge_client: TestClient
    ) -> None:
        invalidate_compliance_metrics_cache()
        now = datetime.now(tz=timezone.utc)
        digest = "c" * 64
        records = [
            _make_stream_record(
                now - timedelta(minutes=5),
                control_id="CM-6",
                event_type="GOVERNANCE_THRESHOLDS_LOADED",
                sequence=1,
                payload_extra={
                    "schema_version": 1,
                    "region": "US_FED",
                    "thresholds_digest": digest,
                    "domain_sections": ["finance", "healthcare"],
                },
            ),
            _make_stream_record(
                now - timedelta(minutes=1),
                control_id="SC-4",
                event_type="GOVERNANCE_DECISION",
                sequence=2,
                payload_extra={"verdict": "ALLOW", "thresholds_digest": digest},
            ),
        ]
        with (
            patch.dict(os.environ, {"CAGE_DEPLOYMENT_REGION": "US_FED"}, clear=False),
            patch(
                "src.compliance_bridge.metrics._query_cm6_stream_records",
                return_value=records,
            ),
        ):
            r_canonical = bridge_client.get("/v1/compliance/cm6")
            r_alias = bridge_client.get("/v1/config/cm6")

        assert r_canonical.status_code == 200
        assert r_alias.status_code == 200
        assert r_canonical.json() == r_alias.json()
        payload = r_canonical.json()
        assert payload["assessment_status"] == "satisfied"
        assert payload["thresholds_digest"] == digest
        assert payload["decisions_checked"] == 1
        assert payload["digest_mismatches"] == 0

    @pytest.mark.covers(
        "src.compliance_bridge.metrics:_query_cm6_stream_records#_read_cold_store_records_async",
        "src.compliance_bridge.main:_resolve_cm6_posture#custody_integrity_error",
    )
    def test_cm6_endpoint_fails_closed_503_on_custody_tamper(
        self, bridge_client: TestClient
    ) -> None:
        invalidate_compliance_metrics_cache()
        fake_store = MagicMock()
        fake_store._bucket_name = "tampered-cm6-worm"
        with (
            patch(
                "src.compliance_bridge.metrics._resolve_metrics_cold_store",
                return_value=fake_store,
            ),
            patch(
                "src.compliance_bridge.metrics._read_cold_store_records_async",
                new=AsyncMock(
                    side_effect=EvidenceCustodyIntegrityError(
                        "CM-6 cold batch tampered"
                    )
                ),
            ),
        ):
            resp = bridge_client.get("/v1/compliance/cm6")

        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "custody_integrity_error"
        assert "CM-6 cold batch tampered" in resp.json()["detail"]["message"]

    @pytest.mark.covers(
        "src.compliance_bridge.main:_resolve_cm6_posture#cm6_custody_unavailable"
    )
    def test_cm6_endpoint_fails_closed_503_when_stream_unavailable(
        self, bridge_client: TestClient
    ) -> None:
        with patch(
            "src.compliance_bridge.main.get_cm6_thresholds_posture",
            new=AsyncMock(side_effect=ConnectionError("redis connection refused")),
        ):
            resp = bridge_client.get("/v1/config/cm6")

        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "cm6_custody_unavailable"

    def test_lula_validation_cm6_manifest_eliminates_cage_deployment_vacuity(
        self,
    ) -> None:
        cm6_path = REPO_ROOT / "compliance" / "lula" / "lula-validation-cm6.yaml"
        doc = yaml.safe_load(cm6_path.read_text(encoding="utf-8"))
        desc = yaml.safe_load(
            doc["component-definition"]["back-matter"]["resources"][0]["description"]
        )
        assert desc["domain"]["type"] == "api"
        requests = desc["domain"]["api-spec"]["requests"]
        assert requests == [
            {
                "name": "cm6_thresholds_posture",
                "url": "http://compliance-bridge.governance-stack.svc.cluster.local/v1/compliance/cm6",
                "method": "GET",
            }
        ]
        assert desc["provider"]["opa-spec"]["output"]["observations"] == [
            "lula.assessment_remark"
        ]
        rego = desc["provider"]["opa-spec"]["rego"]
        assert "cage-deployment" not in rego
        assert "governance-thresholds-config" not in rego
        assert "thresholds_loaded_valid" in rego
        assert "digest_mismatches == 0" in rego
