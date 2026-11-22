# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Focused unit tests for POAM-2026-201 / POAM-2026-244 / cold-store hardening.

Verifies:
1. Generalized anti-latch rule (POAM-2026-201): no control's own evaluation
   output (`lula_audit`, `control_assessment`, `assessment_result`,
   `record_role="control_evaluation"`, or explicit `evaluated_control` match)
   may enter that control's own input denominator, across *every* control ID,
   while genuine governed-subject failures remain counted fail-closed.
2. Minimum sample size guard (POAM-2026-244): statistical assessments with
   `0 < total_traces < min_sample_size` report `assessment_status=insufficient_sample`
   (`not-satisfied` / `INSUFFICIENT_EVIDENCE`), except zero-tolerance
   `threshold == 1.0` controls (`A.9.2`) where any `safety_rate < 1.0` fails
   immediately as `threshold_violation`. Neither `insufficient_traffic` nor
   `insufficient_sample` resets the Lula dead-man timer (`POAM-2026-234` item 4).
3. Bounded cold-store scaling (`POAM-2026-244`): process-scoped cold-store client
   reuse, verified immutable WORM batch caching, fail-closed tamper refusal
   (never cached), and `GcsColdStore` keep-alive connection pool sizing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

from src.compliance_bridge import main as bridge_main
from src.compliance_bridge.evidence_custodian import EvidenceCustodyIntegrityError
from src.compliance_bridge.infra_custody import InfraEvidenceChain
from src.compliance_bridge.metrics import (
    _fetch_from_evidence_stream_sync,
    _is_self_evaluation_record,
    _read_cold_store_records_async,
    _resolve_metrics_cold_store,
    _resolve_min_sample_size,
    get_last_passing_lula_audit_age_seconds,
    invalidate_compliance_metrics_cache,
)
from src.compliance_bridge.oscal_exporter import (
    build_oscal_assessment_results,
    findings_from_metrics_dict,
)
from src.compliance_bridge.oscal_parser import parse_oscal_yaml
from src.compliance_bridge.types import ComplianceMetrics
from src.gateway.governance.env_posture import DeploymentPosture
from src.integrations.storage_gcs.cold_store import GcsColdStore

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from verify_lula_assessment_results import verify_assessment_results_data  # noqa: E402


def _iso_ago(seconds: float) -> str:
    return (
        (datetime.now(tz=timezone.utc) - timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _gov_pass_record(
    control_id: str,
    *,
    seq: int,
    age_s: float = 30.0,
    event_type: str = "GOVERNANCE_DECISION",
    verdict: str = "ALLOW",
) -> dict[str, Any]:
    return {
        "chain_id": "test-chain-201",
        "sequence": str(seq),
        "timestamp": _iso_ago(age_s),
        "control_id": control_id,
        "event_type": event_type,
        "record_hash": hashlib.sha256(
            f"{control_id}:{seq}:{verdict}".encode()
        ).hexdigest(),
        "payload": json.dumps(
            {
                "control_id": control_id,
                "verdict": verdict,
                "outcome": verdict,
                "action": "market_analysis",
            }
        ),
    }


def _lula_audit_record(
    summary: str,
    *,
    seq: int,
    age_s: float = 30.0,
    evaluated_count: int = 26,
    satisfied_count: int = 26,
    failed_controls: list[str] | None = None,
    insufficient_traffic_controls: list[str] | None = None,
    insufficient_sample_controls: list[str] | None = None,
) -> dict[str, Any]:
    failed = list(failed_controls or [])
    insuff_traffic = list(insufficient_traffic_controls or [])
    insuff_sample = list(insufficient_sample_controls or [])
    return {
        "chain_id": "test-infra-chain",
        "sequence": str(seq),
        "timestamp": _iso_ago(age_s),
        "event_type": "lula_audit",
        "control_id": "A.5.3",
        "record_hash": hashlib.sha256(f"lula:{seq}:{summary}".encode()).hexdigest(),
        "payload": json.dumps(
            {
                "event_type": "lula_audit",
                "summary": summary,
                "evaluated_count": evaluated_count,
                "satisfied_count": satisfied_count,
                "failed_count": len(failed),
                "failed_controls": failed,
                "insufficient_traffic_count": len(insuff_traffic),
                "insufficient_traffic_controls": insuff_traffic,
                "insufficient_sample_count": len(insuff_sample),
                "insufficient_sample_controls": insuff_sample,
            }
        ),
    }


# ---------------------------------------------------------------------------
# 1. Generalized Anti-Latch Rule (POAM-2026-201)
# ---------------------------------------------------------------------------


class TestGeneralizedAntiLatchRule:
    """No control evaluation output for control X may enter X's own input."""

    @pytest.mark.parametrize(
        ("control_id", "event_type"),
        [
            ("A.5.3", "lula_audit"),
            ("A.5.2", "control_assessment"),
            ("A.9.2", "assessment_result"),
            ("SC-4", "lula_validation"),
            ("SC-7", "lula_audit"),
            ("CM-6", "control_assessment"),
        ],
    )
    def test_evaluation_output_targeting_same_control_is_excluded(
        self, control_id: str, event_type: str
    ) -> None:
        rec = {
            "event_type": event_type,
            "control_id": control_id,
            "timestamp": _iso_ago(10),
            "payload": json.dumps(
                {
                    "event_type": event_type,
                    "evaluated_control_id": control_id,
                    "outcome": "FAIL",
                }
            ),
        }
        assert _is_self_evaluation_record(rec, control_id) is True

    def test_evaluation_output_for_different_control_is_not_excluded(self) -> None:
        """An assessment output targeting A.9.2 does not self-evaluate A.5.2."""
        rec = {
            "event_type": "control_assessment",
            "control_id": "A.9.2",
            "payload": json.dumps({"evaluated_control_id": "A.9.2", "outcome": "FAIL"}),
        }
        assert _is_self_evaluation_record(rec, "A.5.2") is False
        assert _is_self_evaluation_record(rec, "A.9.2") is True

    def test_record_role_control_evaluation_excluded_for_explicit_target_list(
        self,
    ) -> None:
        rec = {
            "event_type": "custom_audit_check",
            "payload": json.dumps(
                {
                    "record_role": "control_evaluation",
                    "evaluated_controls": ["A.5.2", "SC-4"],
                    "outcome": "FAIL",
                }
            ),
        }
        assert _is_self_evaluation_record(rec, "A.5.2") is True
        assert _is_self_evaluation_record(rec, "SC-4") is True
        assert _is_self_evaluation_record(rec, "A.5.3") is False

    def test_genuine_runtime_failures_are_never_excluded(self) -> None:
        """Real governed-subject failures must continue lowering safety_rate."""
        for ev in (
            "CBF_ROLLBACK",
            "GOVERNANCE_VIOLATION",
            "cilium_flow_denied",
            "ACTUATION_REFUSAL_RECEIPT",
        ):
            rec = {
                "event_type": ev,
                "control_id": "A.5.3",
                "payload": json.dumps({"event_type": ev, "outcome": "FAIL"}),
            }
            assert _is_self_evaluation_record(rec, "A.5.3") is False

    def test_a53_recovers_immediately_after_lula_audit_fail_burst_without_24h_wait(
        self,
    ) -> None:
        """Simulates the live 2026-11-22 staging failure (5 lula_audit FAILs + 30 healthy traces)."""
        fail_burst = [
            _lula_audit_record(
                "lula_audit FAIL: 23/26 satisfied (3 failed: lula-validation-a53)",
                seq=734 + i,
                age_s=60.0 + i * 3600,
                satisfied_count=23,
                failed_controls=["lula-validation-a53"],
            )
            for i in range(5)
        ]
        healthy_traces = [
            _gov_pass_record("A.5.3", seq=100 + i, age_s=30.0 + i) for i in range(30)
        ]
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=fail_burst + healthy_traces,
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)

        assert metrics.total_traces == 30
        assert metrics.passed_traces == 30
        assert metrics.blocked_traces == 0
        assert metrics.safety_rate == 1.0
        assert metrics.self_evaluation_records_excluded == 5

    def test_non_a53_control_also_excludes_its_own_control_assessment_output(
        self,
    ) -> None:
        self_eval_fail = {
            "chain_id": "test-infra",
            "sequence": "900",
            "timestamp": _iso_ago(20),
            "control_id": "A.5.2",
            "event_type": "control_assessment",
            "payload": json.dumps(
                {
                    "event_type": "control_assessment",
                    "evaluated_control": "A.5.2",
                    "outcome": "FAIL",
                }
            ),
        }
        healthy_traces = [
            _gov_pass_record("A.5.2", seq=i, age_s=10 + i) for i in range(32)
        ]
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[self_eval_fail, *healthy_traces],
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.2", 24)

        assert metrics.total_traces == 32
        assert metrics.safety_rate == 1.0
        assert metrics.self_evaluation_records_excluded == 1

    def test_genuine_cbf_rollback_still_lowers_a53_safety_rate(self) -> None:
        healthy_traces = [
            _gov_pass_record("A.5.3", seq=i, age_s=30 + i) for i in range(29)
        ]
        failure = {
            "chain_id": "test-chain-201",
            "sequence": "999",
            "timestamp": _iso_ago(15),
            "control_id": "A.5.3",
            "event_type": "CBF_ROLLBACK",
            "payload": json.dumps({"event_type": "CBF_ROLLBACK", "outcome": "FAIL"}),
        }
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[*healthy_traces, failure],
        ):
            metrics = _fetch_from_evidence_stream_sync("A.5.3", 24)

        assert metrics.total_traces == 30
        assert metrics.passed_traces == 29
        assert metrics.blocked_traces == 1
        assert metrics.self_evaluation_records_excluded == 0
        assert metrics.safety_rate == pytest.approx(29 / 30, rel=1e-4)


# ---------------------------------------------------------------------------
# 2. Minimum Sample Size & `insufficient_sample` (POAM-2026-244 / 234 #4)
# ---------------------------------------------------------------------------


class TestMinimumSampleSizeFloor:
    """Verify minimum population floor across metrics, OSCAL, verifier, and bridge."""

    def test_resolve_min_sample_size_env_parsing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("COMPLIANCE_MIN_SAMPLE_SIZE", raising=False)
        assert _resolve_min_sample_size() == 30
        monkeypatch.setenv("COMPLIANCE_MIN_SAMPLE_SIZE", "50")
        assert _resolve_min_sample_size() == 50
        monkeypatch.setenv("COMPLIANCE_MIN_SAMPLE_SIZE", "0")
        assert _resolve_min_sample_size() == 1
        monkeypatch.setenv("COMPLIANCE_MIN_SAMPLE_SIZE", "not-a-number")
        assert _resolve_min_sample_size() == 30

    def test_oscal_exporter_and_parser_insufficient_sample_vs_zero_tolerance(
        self,
    ) -> None:
        now_iso = _iso_ago(60)
        # A.5.3 with 12 traces (below 30) and 1.0 -> insufficient_sample
        m_a53_low_pass = ComplianceMetrics(
            control_id="A.5.3",
            safety_rate=1.0,
            total_traces=12,
            passed_traces=12,
            blocked_traces=0,
            min_sample_size=30,
            window_hours=24.0,
            evidence_age_seconds=60.0,
            last_event_utc=now_iso,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        m_a52_low_rate = ComplianceMetrics(
            control_id="A.5.2",
            safety_rate=0.75,
            total_traces=20,
            passed_traces=15,
            blocked_traces=5,
            min_sample_size=30,
            window_hours=24.0,
            evidence_age_seconds=60.0,
            last_event_utc=now_iso,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        # Zero-tolerance A.9.2 (threshold == 1.0): a single violation MUST fail
        # immediately as threshold_violation even when total_traces < min_sample_size!
        m_a92_single_violation = ComplianceMetrics(
            control_id="A.9.2",
            safety_rate=0.5,
            total_traces=2,
            passed_traces=1,
            blocked_traces=1,
            min_sample_size=30,
            window_hours=24.0,
            evidence_age_seconds=60.0,
            last_event_utc=now_iso,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        findings_in = findings_from_metrics_dict(
            {
                "A.5.3": m_a53_low_pass.model_dump(),
                "A.5.2": m_a52_low_rate.model_dump(),
                "A.9.2": m_a92_single_violation.model_dump(),
            },
            "poam-244-sample-floor",
        )
        doc = build_oscal_assessment_results(
            findings=findings_in,
            audit_id="poam-244-sample-floor",
        )
        findings = {
            f["target"]["target-id"]: f
            for f in doc["assessment-results"]["results"][0]["findings"]
        }
        assert findings["A.5.3"]["target"]["status"]["state"] == "not-satisfied"
        assert "assessment_status=insufficient_sample" in findings["A.5.3"]["remarks"]
        assert findings["A.5.2"]["target"]["status"]["state"] == "not-satisfied"
        assert "assessment_status=insufficient_sample" in findings["A.5.2"]["remarks"]
        assert findings["A.9.2"]["target"]["status"]["state"] == "not-satisfied"
        a92_props = {p["name"]: p["value"] for p in findings["A.9.2"]["props"]}
        assert a92_props["assessment_status"] == "threshold_violation"

        # Round-trip through OSCAL YAML parser
        import yaml

        parsed = {f.control_id: f for f in parse_oscal_yaml(yaml.safe_dump(doc))}
        assert parsed["A.5.3"].result == "INSUFFICIENT_EVIDENCE"
        assert parsed["A.5.2"].result == "INSUFFICIENT_EVIDENCE"
        assert parsed["A.9.2"].result == "FAIL"

        # Zero-tolerance A.9.2 with 1.0 rate but < 30 traces stays insufficient_sample
        m_a92_small_clean = ComplianceMetrics(
            control_id="A.9.2",
            safety_rate=1.0,
            total_traces=10,
            passed_traces=10,
            blocked_traces=0,
            min_sample_size=30,
            window_hours=24.0,
            evidence_age_seconds=60.0,
            last_event_utc=now_iso,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        doc_clean = build_oscal_assessment_results(
            findings=findings_from_metrics_dict(
                {"A.9.2": m_a92_small_clean.model_dump()},
                "poam-244-a92-small-clean",
            ),
            audit_id="poam-244-a92-small-clean",
        )
        f_a92 = doc_clean["assessment-results"]["results"][0]["findings"][0]
        assert f_a92["target"]["status"]["state"] == "not-satisfied"
        assert "assessment_status=insufficient_sample" in f_a92["remarks"]

    def test_verify_lula_assessment_results_fails_closed_on_insufficient_sample(
        self,
    ) -> None:
        doc = {
            "assessment-results": {
                "results": [
                    {
                        "title": "a53",
                        "observations": [
                            {
                                "uuid": "obs-1",
                                "description": "A.5.3",
                                "relevant-evidence": [
                                    {
                                        "remarks": (
                                            "lula.assessment_remark: "
                                            "assessment_status=insufficient_sample; "
                                            "control_id=A.5.3; total_traces=15; "
                                            "min_sample_size=30"
                                        )
                                    }
                                ],
                            }
                        ],
                        "findings": [
                            {
                                "uuid": "f-1",
                                "target": {
                                    "target-id": "A.5.3",
                                    "status": {"state": "not-satisfied"},
                                },
                                "remarks": (
                                    "assessment_status=insufficient_sample; "
                                    "total_traces=15; min_sample_size=30"
                                ),
                            }
                        ],
                    }
                ]
            }
        }
        ok, errors = verify_assessment_results_data(doc)
        assert ok is False
        assert any("not-satisfied" in e for e in errors)

    def test_deadman_rejects_both_insufficient_traffic_and_insufficient_sample(
        self,
    ) -> None:
        """POAM-2026-234 item 4: dead-man resets strictly on clean PASS runs."""
        older_pass = _lula_audit_record(
            "lula_audit PASS: 26/26 active validations satisfied",
            seq=1,
            age_s=10_000.0,
        )
        newer_insuff_traffic = _lula_audit_record(
            "lula_audit INSUFFICIENT_TRAFFIC: 23/26 satisfied (3 insufficient_traffic, 0 failed)",
            seq=2,
            age_s=60.0,
            satisfied_count=23,
            insufficient_traffic_controls=[
                "lula-validation-a52",
                "lula-validation-a53",
                "lula-validation-a92",
            ],
        )
        newer_insuff_sample = _lula_audit_record(
            "lula_audit INSUFFICIENT_SAMPLE: 25/26 satisfied (1 insufficient_sample, 0 failed)",
            seq=3,
            age_s=10.0,
            satisfied_count=25,
            insufficient_sample_controls=["lula-validation-a53"],
        )

        # Without a clean PASS, dead-man returns (None, None)
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[newer_insuff_sample, newer_insuff_traffic],
        ):
            age_s, ts = get_last_passing_lula_audit_age_seconds(window_hours=24)
        assert age_s is None and ts is None

        # With an older clean PASS, neither newer record advances the timestamp
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[newer_insuff_sample, newer_insuff_traffic, older_pass],
        ):
            age_s, ts = get_last_passing_lula_audit_age_seconds(window_hours=24)
        assert age_s is not None and age_s >= 9900.0
        assert ts is not None

    def test_infra_events_records_insufficient_sample_and_fails_closed_on_non_statistical(
        self,
    ) -> None:
        fake_server = fakeredis.FakeServer()
        chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key="cage:test:infra:sample-floor",
        )
        bridge_main.app.state.infra_evidence_chain = chain
        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()
        l5d_client = "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
        pod_ip = "10.0.0.42"
        client_ctx = TestClient(
            bridge_main.app,
            client=(pod_ip, 50000),
            base_url=f"http://{pod_ip}:3001",
            raise_server_exceptions=False,
        )

        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.create_notifier",
                return_value=mock_notifier,
            ),
            client_ctx as client,
        ):
            ok_resp = client.post(
                "/v1/infra/events",
                headers={
                    "l5d-client-id": l5d_client,
                    "Idempotency-Key": "sample-floor-ok",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-22T10:00:00Z",
                    "control_hint": "A.5.3",
                    "summary": (
                        "lula_audit INSUFFICIENT_SAMPLE: 25/26 satisfied "
                        "(1 not-satisfied [insufficient_sample]: lula-validation-a53)"
                    ),
                    "evaluated_count": 26,
                    "satisfied_count": 25,
                    "failed_controls": [],
                    "insufficient_traffic_controls": [],
                    "insufficient_sample_controls": ["lula-validation-a53"],
                },
            )
            assert ok_resp.status_code == 200, ok_resp.text
            mock_notifier.send_critical_alert.assert_not_called()
            assert (
                bridge_main.LULA_AUDIT_INSUFFICIENT_SAMPLE_CONTROLS._value.get() == 1.0
            )

            # Non-statistical spec claiming insufficient_sample MUST fail closed and page
            bad_resp = client.post(
                "/v1/infra/events",
                headers={
                    "l5d-client-id": l5d_client,
                    "Idempotency-Key": "sample-floor-spoofed",
                },
                json={
                    "event_type": "lula_audit",
                    "timestamp_utc": "2026-11-22T10:05:00Z",
                    "control_hint": "A.5.3",
                    "summary": (
                        "lula_audit INSUFFICIENT_SAMPLE: 25/26 satisfied "
                        "(1 not-satisfied [insufficient_sample]: lula-validation-sc7)"
                    ),
                    "evaluated_count": 26,
                    "satisfied_count": 25,
                    "failed_controls": [],
                    "insufficient_sample_controls": ["lula-validation-sc7"],
                },
            )
            assert bad_resp.status_code == 200, bad_resp.text
            mock_notifier.send_critical_alert.assert_called_once()


# ---------------------------------------------------------------------------
# 3. Cold-Store Caching, Process Reuse, & Pool Sizing (POAM-2026-244)
# ---------------------------------------------------------------------------


class _FakeWormColdStore:
    """In-memory cold store recording `get()` calls for batch-cache verification."""

    def __init__(self, objects: dict[str, bytes], bucket: str = "unit-worm") -> None:
        self._objects = dict(objects)
        self._bucket_name = bucket
        self.list_calls = 0
        self.get_calls: list[str] = []

    async def list_keys(self, prefix: str) -> list[str]:
        self.list_calls += 1
        return sorted(k for k in self._objects if k.startswith(prefix))

    async def get(self, key: str) -> bytes:
        self.get_calls.append(key)
        return self._objects[key]


def _signed_v2_attestation(content_sha256: str) -> bytes:
    return json.dumps(
        {
            "schema": "cage-evidence-batch/2",
            "signature_status": "SIGNED",
            "evidentiary": True,
            "deployment_posture": "staging",
            "content_sha256": content_sha256,
            "signature": {
                "algorithm": "EC_SIGN_P256_SHA256",
                "key_id": "projects/test/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "value": "dGVzdC1zaWduYXR1cmU=",
            },
        }
    ).encode("utf-8")


class TestColdStoreReadCachingAndPooling:
    """Verify verified-batch caching, fail-closed tamper refusal, and client reuse."""

    def teardown_method(self) -> None:
        invalidate_compliance_metrics_cache(None)

    def test_verified_batch_cache_avoids_re_downloading_immutable_signed_batches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        invalidate_compliance_metrics_cache(None)
        monkeypatch.setenv("CAGE_DEPLOYMENT_POSTURE", "enforcing_staging")
        now = datetime.now(tz=timezone.utc)
        day_prefix = f"evidence-stream/{now.strftime('%Y/%m/%d')}/chain-1"
        rec_line = json.dumps(_gov_pass_record("A.5.3", seq=1, age_s=120.0)).encode(
            "utf-8"
        )
        ndjson_key = f"{day_prefix}/000000000001-000000000001.ndjson"
        att_key = f"{day_prefix}/000000000001-000000000001.attestation.json"
        att_bytes = _signed_v2_attestation(hashlib.sha256(rec_line).hexdigest())
        store = _FakeWormColdStore({ndjson_key: rec_line, att_key: att_bytes})

        with patch(
            "src.compliance_bridge.metrics.resolve_posture",
            return_value=DeploymentPosture.DEV,
        ):
            r1 = asyncio.run(
                _read_cold_store_records_async(
                    store,  # type: ignore[arg-type]
                    now - timedelta(hours=1),
                    now,
                )
            )
            first_gets = len(store.get_calls)
            r2 = asyncio.run(
                _read_cold_store_records_async(
                    store,  # type: ignore[arg-type]
                    now - timedelta(hours=1),
                    now,
                )
            )
        assert len(r1) == 1
        assert len(r2) == 1
        assert first_gets == 2  # ndjson + attestation fetched once
        assert len(store.get_calls) == first_gets  # 0 extra GETs on warm batch cache

    def test_tampered_batch_raises_integrity_error_and_is_never_cached(self) -> None:
        invalidate_compliance_metrics_cache(None)
        now = datetime.now(tz=timezone.utc)
        day_prefix = f"evidence-stream/{now.strftime('%Y/%m/%d')}/chain-tamper"
        rec_line = json.dumps(_gov_pass_record("A.5.3", seq=2)).encode("utf-8")
        ndjson_key = f"{day_prefix}/000000000002-000000000002.ndjson"
        att_key = f"{day_prefix}/000000000002-000000000002.attestation.json"
        bad_att = _signed_v2_attestation("0" * 64)
        store = _FakeWormColdStore({ndjson_key: rec_line, att_key: bad_att})

        with pytest.raises(EvidenceCustodyIntegrityError):
            asyncio.run(
                _read_cold_store_records_async(
                    store,  # type: ignore[arg-type]
                    now - timedelta(hours=1),
                    now,
                )
            )
        # Re-read MUST still fail closed (never poisoned cache entry)
        with pytest.raises(EvidenceCustodyIntegrityError):
            asyncio.run(
                _read_cold_store_records_async(
                    store,  # type: ignore[arg-type]
                    now - timedelta(hours=1),
                    now,
                )
            )
        assert len(store.get_calls) == 4

    def test_resolve_metrics_cold_store_reuses_client_and_updates_on_bucket_change(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        invalidate_compliance_metrics_cache(None)
        created: list[tuple[str | None, str | None]] = []

        def _fake_factory(
            *, backend: str | None = None, bucket: str | None = None
        ) -> object:
            created.append((backend, bucket))
            return object()

        monkeypatch.setenv("EVIDENCE_COLD_STORE", "gcs")
        monkeypatch.setenv("EVIDENCE_ARCHIVE_BUCKET", "bucket-a")
        with patch(
            "src.compliance_bridge.metrics.get_cold_store",
            side_effect=_fake_factory,
        ):
            # Replace module attr on fake so it behaves like production factory
            pass

        with patch.object(
            sys.modules["src.compliance_bridge.metrics"],
            "get_cold_store",
            _fake_factory,
        ):
            s1 = _resolve_metrics_cold_store()
            s2 = _resolve_metrics_cold_store()
            assert s1 is s2
            assert created == [("gcs", "bucket-a")]

            monkeypatch.setenv("EVIDENCE_ARCHIVE_BUCKET", "bucket-b")
            s3 = _resolve_metrics_cold_store()
            assert s3 is not s1
            assert created == [("gcs", "bucket-a"), ("gcs", "bucket-b")]

    def test_gcs_cold_store_mounts_keepalive_http_adapter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mounted: list[tuple[str, Any]] = []

        class _FakeSession:
            def mount(self, prefix: str, adapter: Any) -> None:
                mounted.append((prefix, adapter))

        class _FakeClient:
            def __init__(self, project: str | None = None) -> None:
                self._http = _FakeSession()

            def bucket(self, name: str) -> str:
                return f"bucket:{name}"

        fake_storage = MagicMock()
        fake_storage.Client = _FakeClient
        monkeypatch.setenv("EVIDENCE_COLD_STORE_POOL_SIZE", "48")

        store = GcsColdStore(bucket_name="test-worm-bucket")
        fake_google_cloud = MagicMock(storage=fake_storage)
        with patch.dict(
            sys.modules,
            {
                "google.cloud": fake_google_cloud,
                "google.cloud.storage": fake_storage,
            },
        ):
            client = store._get_client()

        assert isinstance(client, _FakeClient)
        prefixes = {p for p, _ in mounted}
        assert "https://" in prefixes
        adapter = dict(mounted)["https://"]
        assert adapter._pool_maxsize == 48
        assert adapter._pool_connections == 48
