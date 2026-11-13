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

"""Dedicated unit tests for custody-chain `src/compliance_bridge/metrics.py`."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _ensure_stubs() -> None:
    """Install minimal cachetools stub when running in bare environments."""
    if "cachetools" not in sys.modules:
        cachetools_stub = MagicMock()

        class _TTLCache(dict):  # type: ignore[type-arg]
            def __init__(self, maxsize: int = 128, ttl: int = 300) -> None:
                super().__init__()
                self._maxsize = maxsize
                self._ttl = ttl

        cachetools_stub.TTLCache = _TTLCache
        sys.modules["cachetools"] = cachetools_stub


_ensure_stubs()


class _FakeColdStore:
    """In-memory async `EvidenceColdStore` double for WORM custody tests."""

    def __init__(self, objects: dict[str, bytes], backend_id: str = "gcs") -> None:
        self._objects = dict(objects)
        self.backend_id = backend_id

    async def list_keys(self, prefix: str) -> list[str]:
        return sorted(k for k in self._objects if k.startswith(prefix))

    async def get(self, key: str) -> bytes:
        return self._objects[key]


def _make_evidence_record(
    timestamp: datetime,
    *,
    control_id: str = "A.5.2",
    event_type: str = "GOVERNANCE_DECISION",
    verdict: str | None = "ALLOW",
    trace_id: str = "trace-1",
    record_hash: str | None = None,
    sequence: int = 1,
    chain_id: str = "00000000-0000-4000-8000-000000000001",
    stream_id: str = "1700000000000-0",
    extra_payload: dict[str, Any] | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical wire-shaped `cage_evidence` record."""
    payload: dict[str, Any] = {
        "type": event_type,
        "controlId": control_id,
        "timestamp_utc": timestamp.isoformat(),
    }
    if verdict is not None:
        payload["verdict"] = verdict
    if extra_payload:
        payload.update(extra_payload)

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    computed_hash = (
        record_hash
        or hashlib.sha256(f"{chain_id}:{sequence}:{payload_json}".encode()).hexdigest()
    )

    rec: dict[str, Any] = {
        "schema_version": "1.0",
        "chain_id": chain_id,
        "sequence": str(sequence),
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "control_id": control_id,
        "trace_id": trace_id,
        "payload": payload_json,
        "prev_hash": "0" * 64,
        "record_hash": computed_hash,
        "stream_id": stream_id,
    }
    if extra_fields:
        rec.update(extra_fields)
    return rec


def _make_signed_attestation_bytes(data_key: str, ndjson_bytes: bytes) -> bytes:
    """Build a citable signed custody attestation companion for `data_key`."""
    from src.compliance_bridge.evidence_custodian import ATTESTATION_SCHEMA, SIGNED

    attestation = {
        "schema": ATTESTATION_SCHEMA,
        "chain_id": "00000000-0000-4000-8000-000000000001",
        "stream_key": "cage:evidence:stream",
        "first_sequence": 1,
        "last_sequence": 1,
        "first_stream_id": "1700000000000-0",
        "last_stream_id": "1700000000000-0",
        "first_prev_hash": "0" * 64,
        "last_record_hash": "a" * 64,
        "entries_count": 1,
        "content_sha256": hashlib.sha256(ndjson_bytes).hexdigest(),
        "data_key": data_key,
        "gap": {"detected": False},
        "signature_status": SIGNED,
        "evidentiary": True,
        "signature": {
            "algorithm": "ECDSA_P256_SHA256",
            "key_id": "gcp-kms://projects/<PROJECT_ID>-evidence/locations/us-central1/keyRings/cage/cryptoKeys/evidence/cryptoKeyVersions/1",
            "value": "base64-sig-placeholder",
        },
    }
    return json.dumps(attestation, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


class TestGraceStatus:
    """Tests for deployment cold-start grace period logic."""

    def test_grace_active_within_window(self) -> None:
        now = datetime.now(tz=timezone.utc)
        import src.compliance_bridge.metrics as metrics_mod

        original_start = metrics_mod._DEPLOYMENT_START
        original_grace = metrics_mod._STARTUP_GRACE_HOURS
        metrics_mod._DEPLOYMENT_START = now
        metrics_mod._STARTUP_GRACE_HOURS = 6
        try:
            status = metrics_mod._get_grace_status()
            assert status["active"] is True
            assert float(status["remaining_hours"]) > 0.0
        finally:
            metrics_mod._DEPLOYMENT_START = original_start
            metrics_mod._STARTUP_GRACE_HOURS = original_grace

    def test_grace_inactive_after_window(self) -> None:
        old_start = datetime.now(tz=timezone.utc) - timedelta(hours=48)
        import src.compliance_bridge.metrics as metrics_mod

        original_start = metrics_mod._DEPLOYMENT_START
        original_grace = metrics_mod._STARTUP_GRACE_HOURS
        metrics_mod._DEPLOYMENT_START = old_start
        metrics_mod._STARTUP_GRACE_HOURS = 6
        try:
            status = metrics_mod._get_grace_status()
            assert status["active"] is False
            assert status["remaining_hours"] == 0.0
        finally:
            metrics_mod._DEPLOYMENT_START = original_start
            metrics_mod._STARTUP_GRACE_HOURS = original_grace

    def test_parse_deployment_start_returns_now_when_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DEPLOYMENT_START_UTC", raising=False)
        from src.compliance_bridge.metrics import _parse_deployment_start

        result = _parse_deployment_start()
        assert isinstance(result, datetime)
        assert abs((datetime.now(tz=timezone.utc) - result).total_seconds()) < 5

    def test_parse_deployment_start_parses_z_suffix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DEPLOYMENT_START_UTC", "2026-01-15T08:00:00Z")
        from src.compliance_bridge.metrics import _parse_deployment_start

        result = _parse_deployment_start()
        assert result.tzinfo is not None
        assert result.year == 2026


class TestCanonicalProducerClassification:
    """Verify real gateway/actuator producer event shapes classify accurately."""

    def test_governance_decision_allow_and_narrow_pass_while_deny_blocks(self) -> None:
        from src.compliance_bridge.metrics import _is_passing_evidence_record

        now = datetime.now(tz=timezone.utc)
        allow_rec = _make_evidence_record(
            now, event_type="GOVERNANCE_DECISION", verdict="ALLOW"
        )
        narrow_rec = _make_evidence_record(
            now,
            event_type="GOVERNANCE_DECISION",
            verdict="NARROW",
            extra_payload={"seal_present": True, "clamped_params_valid": True},
        )
        deny_rec = _make_evidence_record(
            now, event_type="GOVERNANCE_DECISION", verdict="DENY"
        )

        assert _is_passing_evidence_record(allow_rec) is True
        assert _is_passing_evidence_record(narrow_rec) is True
        assert _is_passing_evidence_record(deny_rec) is False

    def test_governance_seal_consumed_without_verdict_is_passing(self) -> None:
        """`GOVERNANCE_SEAL_CONSUMED` carries no `verdict` field and must pass."""
        from src.compliance_bridge.metrics import _is_passing_evidence_record

        now = datetime.now(tz=timezone.utc)
        seal_consumed = _make_evidence_record(
            now,
            control_id="A.8.4",
            event_type="GOVERNANCE_SEAL_CONSUMED",
            verdict=None,
            extra_payload={
                "action": "execute_trade",
                "phase": "EXECUTED",
                "seal_present": True,
                "seal_ref": "a" * 64,
            },
        )
        assert _is_passing_evidence_record(seal_consumed) is True

    def test_actuation_receipt_accepted_passes_and_non_accepted_blocks(self) -> None:
        """`ACTUATION_RECEIPT` passes iff `outcome == 'ACCEPTED'`."""
        from src.compliance_bridge.metrics import _is_passing_evidence_record

        now = datetime.now(tz=timezone.utc)
        accepted_rec = _make_evidence_record(
            now,
            control_id="AC-3",
            event_type="ACTUATION_RECEIPT",
            verdict=None,
            extra_payload={"accepted": True, "outcome": "ACCEPTED"},
        )
        rejected_rec = _make_evidence_record(
            now,
            control_id="AC-3",
            event_type="ACTUATION_RECEIPT",
            verdict=None,
            extra_payload={"accepted": False, "outcome": "REJECTED"},
        )
        refusal_receipt = _make_evidence_record(
            now,
            control_id="AC-3",
            event_type="ACTUATION_REFUSAL_RECEIPT",
            verdict=None,
            extra_payload={"accepted": False, "outcome": "REJECTED"},
        )
        indeterminate_receipt = _make_evidence_record(
            now,
            control_id="AC-3",
            event_type="ACTUATION_INDETERMINATE_RECEIPT",
            verdict=None,
            extra_payload={"accepted": False, "outcome": "UNKNOWN"},
        )

        assert _is_passing_evidence_record(accepted_rec) is True
        assert _is_passing_evidence_record(rejected_rec) is False
        assert _is_passing_evidence_record(refusal_receipt) is False
        assert _is_passing_evidence_record(indeterminate_receipt) is False

    def test_refusal_deferral_rollback_and_discrepancy_fence_are_blocking(self) -> None:
        from src.compliance_bridge.metrics import _is_passing_evidence_record

        now = datetime.now(tz=timezone.utc)
        from src.compliance_bridge.metrics import _record_matches_control

        for ev_type, extra in (
            (
                "GOVERNANCE_REFUSAL",
                {
                    "violated_rule": "OPA_LIMIT",
                    "receipt": {
                        "control_id": "AC-3",
                        "violated_rule": "Multiple violations",
                        "tier_failures": [
                            {"control_id": "AC-3"},
                            {"control_id": "SC-4"},
                        ],
                    },
                },
            ),
            (
                "GOVERNANCE_DEFERRAL",
                {"defer_id": "def-1", "defer_reason": "HIGH_RISK", "reason": "HITL"},
            ),
            ("CBF_ROLLBACK", {"status": "ROLLED_BACK"}),
            ("RECONCILIATION_DISCREPANCY_FENCE", {"reason": "ledger drift"}),
        ):
            rec = _make_evidence_record(
                now,
                control_id="AC-3",
                event_type=ev_type,
                verdict="ALLOW",  # Even a spoofed ALLOW inside payload must not pass
                extra_payload=extra,
            )
            assert _is_passing_evidence_record(rec) is False, f"{ev_type} must block"
            if ev_type == "GOVERNANCE_REFUSAL":
                assert _record_matches_control(rec, "SC-4") is True

    def test_settlement_confirmed_passes_and_rolled_back_blocks(self) -> None:
        from src.compliance_bridge.metrics import _is_passing_evidence_record

        now = datetime.now(tz=timezone.utc)
        confirmed = _make_evidence_record(
            now,
            control_id="A.8.4",
            event_type="GOVERNANCE_SETTLEMENT",
            verdict=None,
            extra_payload={"executed": True, "status": "CONFIRMED"},
        )
        rolled_back = _make_evidence_record(
            now,
            control_id="A.8.4",
            event_type="GOVERNANCE_SETTLEMENT",
            verdict=None,
            extra_payload={"executed": False, "status": "ROLLED_BACK"},
        )
        assert _is_passing_evidence_record(confirmed) is True
        assert _is_passing_evidence_record(rolled_back) is False


class TestFetchFromEvidenceStreamSync:
    """Tests for `_fetch_from_evidence_stream_sync()` metric aggregation."""

    def _run_fetch(
        self,
        records: list[dict[str, Any]],
        control_id: str = "A.5.2",
        window_hours: int = 24,
    ) -> Any:
        from src.compliance_bridge.metrics import _fetch_from_evidence_stream_sync

        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=records,
        ):
            return _fetch_from_evidence_stream_sync(control_id, window_hours)

    def test_safety_rate_is_none_when_no_records(self) -> None:
        result = self._run_fetch(records=[])
        assert result.safety_rate is None
        assert result.total_traces == 0
        assert result.evidence_age_seconds == 0.0

    def test_mixed_canonical_events_aggregate_accurately(self) -> None:
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="GOVERNANCE_DECISION",
                verdict="ALLOW",
                sequence=1,
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="GOVERNANCE_SEAL_CONSUMED",
                verdict=None,
                extra_payload={"phase": "EXECUTED", "seal_present": True},
                sequence=2,
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="GOVERNANCE_REFUSAL",
                verdict="DENY",
                sequence=3,
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="CBF_ROLLBACK",
                verdict="ROLLED_BACK",
                sequence=4,
            ),
        ]
        result = self._run_fetch(records=records, control_id="A.5.2")
        assert result.total_traces == 4
        assert result.passed_traces == 3
        assert result.blocked_traces == 1
        assert result.safety_rate == 0.75

    def test_preventive_deny_and_defer_count_as_effective_control_execution(
        self,
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_evidence_record(
                now,
                control_id="agentic_scope_statement",
                event_type="GOVERNANCE_DECISION",
                verdict="ALLOW",
                sequence=1,
            ),
            _make_evidence_record(
                now,
                control_id="CTRL_OPA_005",
                event_type="GOVERNANCE_REFUSAL",
                verdict="DENY",
                sequence=2,
            ),
            _make_evidence_record(
                now,
                control_id="CTRL_OPA_005",
                event_type="GOVERNANCE_DEFERRAL",
                verdict="REQUIRE_APPROVAL",
                sequence=3,
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="INFERENCE_PROXY_BLOCK",
                verdict="DENY",
                sequence=4,
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="INFERENCE_PROXY_STAGE1_PASS",
                verdict="PASS",
                sequence=5,
            ),
        ]
        a53 = self._run_fetch(records=records, control_id="A.5.3")
        assert a53.total_traces == 3
        assert a53.passed_traces == 3
        assert a53.blocked_traces == 0
        assert a53.safety_rate == 1.0

        a52 = self._run_fetch(records=records, control_id="A.5.2")
        assert a52.total_traces == 2
        assert a52.passed_traces == 2
        assert a52.safety_rate == 1.0

    def test_safety_rate_rounds_to_four_decimals(self) -> None:
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_evidence_record(now, verdict="ALLOW", sequence=1),
            _make_evidence_record(now, verdict="ALLOW", sequence=2),
            _make_evidence_record(
                now, event_type="GOVERNANCE_VIOLATION", verdict="VIOLATION", sequence=3
            ),
        ]
        result = self._run_fetch(records=records)
        assert result.safety_rate == 0.6667

    def test_control_id_substring_collision_excluded(self) -> None:
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_evidence_record(now, control_id="A.5.2", verdict="ALLOW", sequence=1),
            _make_evidence_record(
                now, control_id="A.5.20", verdict="ALLOW", sequence=2
            ),
        ]
        result = self._run_fetch(records=records, control_id="A.5.2")
        assert result.total_traces == 1
        assert result.passed_traces == 1

    def test_backward_compat_alias_points_to_evidence_stream(self) -> None:
        from src.compliance_bridge.metrics import (
            _fetch_from_evidence_stream_sync,
            _fetch_from_langfuse_sync,
        )

        assert _fetch_from_langfuse_sync is _fetch_from_evidence_stream_sync


class TestCustodyChainStoreDeduplication:
    """Tests for Redis DB 1 + GCS WORM `.ndjson` custody chain reading & dedup."""

    def test_merges_and_deduplicates_worm_archive_and_redis_db1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.compliance_bridge.metrics as metrics_mod

        now = datetime.now(tz=timezone.utc)
        day_path = now.strftime("%Y/%m/%d")
        chain_id = "00000000-0000-4000-8000-000000000001"

        rec_archived_only = _make_evidence_record(
            now - timedelta(hours=2),
            control_id="A.5.2",
            event_type="GOVERNANCE_DECISION",
            verdict="ALLOW",
            sequence=1,
            stream_id="1700000000001-0",
            record_hash="1" * 64,
        )
        rec_overlapping = _make_evidence_record(
            now - timedelta(hours=1),
            control_id="A.5.2",
            event_type="GOVERNANCE_SEAL_CONSUMED",
            verdict=None,
            extra_payload={"phase": "EXECUTED", "seal_present": True},
            sequence=2,
            stream_id="1700000000002-0",
            record_hash="2" * 64,
        )
        rec_hot_only = _make_evidence_record(
            now - timedelta(minutes=5),
            control_id="A.5.2",
            event_type="GOVERNANCE_REFUSAL",
            verdict="DENY",
            sequence=3,
            stream_id="1700000000003-0",
            record_hash="3" * 64,
        )
        rec_expired = _make_evidence_record(
            now - timedelta(hours=30),
            control_id="A.5.2",
            event_type="GOVERNANCE_DECISION",
            verdict="ALLOW",
            sequence=0,
            stream_id="1699990000000-0",
            record_hash="9" * 64,
        )

        data_key = (
            f"evidence-stream/{day_path}/{chain_id}/000000000001-000000000002.ndjson"
        )
        att_key = f"evidence-stream/{day_path}/{chain_id}/000000000001-000000000002.attestation.json"
        ndjson_bytes = (
            "\n".join(
                json.dumps(r, sort_keys=True)
                for r in (rec_expired, rec_archived_only, rec_overlapping)
            )
            + "\n"
        ).encode("utf-8")
        fake_store = _FakeColdStore(
            {
                data_key: ndjson_bytes,
                att_key: _make_signed_attestation_bytes(data_key, ndjson_bytes),
            }
        )

        mock_redis = MagicMock()

        def _fake_xrevrange(
            stream_key: str, _max_id: str, _min_id: str, count: int = 1000
        ) -> list[tuple[str, dict[str, Any]]]:
            if stream_key == "cage:evidence:stream":
                return [
                    (rec_hot_only["stream_id"], rec_hot_only),
                    (rec_overlapping["stream_id"], rec_overlapping),
                ]
            return []

        mock_redis.xrevrange.side_effect = _fake_xrevrange

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "gcs")
        monkeypatch.setenv("EVIDENCE_ARCHIVE_BUCKET", "cage-worm-archive")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "rediss://redis.internal:6379")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_DB", "1")

        with (
            patch(
                "src.compliance_bridge.metrics.get_cold_store",
                return_value=fake_store,
            ),
            patch(
                "src.compliance_bridge.metrics._build_evidence_sync_redis",
                return_value=mock_redis,
            ),
        ):
            recs = metrics_mod._query_cage_evidence_records("A.5.2", window_hours=24)

        # Expect exactly 3 unique in-window records (seq 1, 2, 3), newest-first;
        # overlapping seq 2 is counted once and 30h-old seq 0 is excluded.
        assert [r["record_hash"] for r in recs] == ["3" * 64, "2" * 64, "1" * 64]
        mock_redis.close.assert_called_once()

    def test_enforcing_posture_rejects_unsigned_worm_batch_and_missing_stores(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.compliance_bridge.metrics as metrics_mod
        from src.compliance_bridge.evidence_custodian import (
            NonEvidentiaryAttestationError,
        )

        monkeypatch.setenv("CAGE_ENV", "prod")
        monkeypatch.delenv("EVIDENCE_COLD_STORE", raising=False)
        monkeypatch.delenv("EVIDENCE_ARCHIVE_BUCKET", raising=False)
        monkeypatch.delenv("EVIDENCE_STREAM_REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_URL", raising=False)

        with pytest.raises(RuntimeError, match="No authoritative custody-chain store"):
            metrics_mod._query_cage_evidence_records("A.5.2", window_hours=24)

        now = datetime.now(tz=timezone.utc)
        day_path = now.strftime("%Y/%m/%d")
        data_key = f"evidence-stream/{day_path}/chain/000000000001-000000000001.ndjson"
        unsigned_key = f"evidence-stream/{day_path}/chain/000000000001-000000000001.attestation.unsigned.json"
        fake_store = _FakeColdStore(
            {
                data_key: b"{}\n",
                unsigned_key: b'{"signature_status":"UNSIGNED","evidentiary":false}',
            }
        )
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "gcs")
        monkeypatch.setenv("EVIDENCE_ARCHIVE_BUCKET", "cage-worm-archive")

        with (
            patch(
                "src.compliance_bridge.metrics.get_cold_store",
                return_value=fake_store,
            ),
            pytest.raises(NonEvidentiaryAttestationError),
        ):
            metrics_mod._query_cage_evidence_records("A.5.2", window_hours=24)


class TestGetComplianceMetricsAndAuditWorkflow:
    """Tests for async `get_compliance_metrics()` and Step 5 custody-chain context."""

    @pytest.mark.asyncio
    async def test_returns_compliance_metrics_on_cache_miss(self) -> None:
        from src.compliance_bridge.types import ComplianceMetrics

        now = datetime.now(tz=timezone.utc)
        import src.compliance_bridge.metrics as metrics_mod

        metrics_mod._metrics_cache.clear()
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=[
                _make_evidence_record(now, control_id="A.5.2", verdict="ALLOW")
            ],
        ):
            result = await metrics_mod.get_compliance_metrics("A.5.2", window_hours=24)

        assert isinstance(result, ComplianceMetrics)
        assert result.control_id == "A.5.2"
        assert result.total_traces == 1
        assert result.safety_rate == 1.0

    @pytest.mark.asyncio
    async def test_cache_hit_skips_store_query_and_updates_evidence_age(self) -> None:
        from src.compliance_bridge.types import ComplianceMetrics

        last_event = datetime.now(tz=timezone.utc) - timedelta(seconds=60)
        cached_result = ComplianceMetrics(
            control_id="A.5.3",
            safety_rate=0.95,
            total_traces=20,
            blocked_traces=1,
            passed_traces=19,
            window_hours=24.0,
            last_event_utc=last_event.isoformat(),
            evidence_age_seconds=0.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )

        import src.compliance_bridge.metrics as metrics_mod

        metrics_mod._metrics_cache["A.5.3:24"] = cached_result
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            side_effect=AssertionError("Cache hit must not query custody store"),
        ) as mock_query:
            result = await metrics_mod.get_compliance_metrics("A.5.3", window_hours=24)

        mock_query.assert_not_called()
        assert result.passed_traces == 19
        assert result.evidence_age_seconds >= 55

    @pytest.mark.asyncio
    async def test_audit_workflow_step5_uses_custody_records_and_generic_domain_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        now = datetime.now(tz=timezone.utc)
        records = [
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="GOVERNANCE_SEAL_CONSUMED",
                verdict=None,
                trace_id="trace-seal",
                extra_payload={"phase": "EXECUTED", "seal_present": True},
            ),
            _make_evidence_record(
                now,
                control_id="A.5.2",
                event_type="GOVERNANCE_REFUSAL",
                verdict="DENY",
                trace_id="trace-deny",
                record_hash="f" * 64,
                extra_payload={
                    "action": "submit_order",
                    "refusal_reason": "OPA stage guardrail violation",
                },
            ),
        ]

        import src.compliance_bridge.audit_workflow as aw
        from src.compliance_bridge.types import OscalFinding

        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            return_value=records,
        ):
            failing = await aw._fetch_failing_traces("A.5.2", limit=5)

        assert len(failing) == 1
        assert failing[0]["id"] == "trace-deny"
        assert failing[0]["event_type"] == "GOVERNANCE_REFUSAL"
        assert failing[0]["record_hash"] == "f" * 64
        assert "OPA stage guardrail violation" in failing[0]["output"]

        prompt = aw._build_remediation_prompt(
            OscalFinding(
                control_id="A.5.2",
                result="FAIL",
                finding_id="f-1",
                safety_rate=0.5,
                evidence_age_s=10.0,
            ),
            "Content Safety",
            failing,
        )
        assert "src/cage_<domain>/opa/" in prompt
        assert "trade_governance.rego" not in prompt
        assert "trade_policy.rego" not in prompt

    @pytest.mark.asyncio
    async def test_empty_window_is_not_cached_across_cold_start_seeding(self) -> None:
        now = datetime.now(tz=timezone.utc)
        import src.compliance_bridge.metrics as metrics_mod

        metrics_mod._metrics_cache.clear()
        with patch(
            "src.compliance_bridge.metrics._query_cage_evidence_records",
            side_effect=[
                [],
                [_make_evidence_record(now, control_id="A.5.3", verdict="ALLOW")],
            ],
        ) as mock_query:
            cold = await metrics_mod.get_compliance_metrics("A.5.3", window_hours=24)
            seeded = await metrics_mod.get_compliance_metrics("A.5.3", window_hours=24)

        assert cold.total_traces == 0
        assert cold.safety_rate is None
        assert seeded.total_traces == 1
        assert seeded.safety_rate == 1.0
        assert mock_query.call_count == 2


# Regression coverage binding: POAM-2026-146
