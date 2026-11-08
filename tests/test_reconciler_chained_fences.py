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

"""Unit tests for §11b (R-7, F-86): Chained Reconciliation Discrepancy Records.

Verifies that:
1. ``GroundTruthReconciler`` emits a hash-chained ``RECONCILIATION_DISCREPANCY_FENCE``
   record (``control_id="CA-7"``) into ``cage:evidence:stream`` every time it
   fences the gateway on a custodian discrepancy spike or barrier-floor breach,
   passing a structured ``dict[str, Any]`` to ``signer.sign_decision(plan)``.
2. Under enforcing postures (``STAGING``, ``PRODUCTION``), KMS signing failures
   fail closed (log at ``ERROR``, increment ``evidence_publish_failures``, keep
   Redis DB 0 fenced, emit zero unsigned records to DB 1, and re-raise).
3. ``GroundTruthReconciler.from_env()`` connects operational state/fences to
   Redis DB 0 while wiring ``EvidenceStreamClient.from_env()`` to Redis DB 1
   (``EVIDENCE_STREAM_REDIS_DB``, default ``1``).
4. ``cbf_engine.py`` stamps ``RECONCILIATION_FENCE_ACTIVE (fence_id=..., fence_epoch=...)``
   when refusing under an active reconciliation fence, ``RefusalReceipt.to_dict()``
   serializes real receipt fields, and ``proof/stream_invariants.py`` +
   ``packages/cage-conformance`` enforce Check 8b against real ``GOVERNANCE_REFUSAL``
   and ``GOVERNANCE_REFUSAL_RECEIPT`` payloads.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE_SRC = _REPO_ROOT / "packages" / "cage-conformance" / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

import cage_conformance as cc  # noqa: E402
from cage_conformance.stream_invariants import (  # noqa: E402
    check_stream as pkg_check_stream,
)
from cage_conformance.stream_invariants import (
    compute_cage_audit_hash,
    jcs_bytes,
)

from proof.stream_invariants import check_stream as repo_check_stream  # noqa: E402
from src.cage_finance.ground_truth import SimulatedCashLedgerProvider  # noqa: E402
from src.cage_finance.invariants import (  # noqa: E402
    CashBarrier,
    finance_cost_resolver,
)
from src.gateway.governance.constants import GovernanceControl  # noqa: E402
from src.gateway.governance.contracts import (  # noqa: E402
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.evidence.stream import (  # noqa: E402
    RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE,
    EvidenceStreamClient,
    append_evidence_record_sync,
    verify_record,
)
from src.gateway.governance.governor.verdicts import (  # noqa: E402
    build_refusal_receipt,
)
from src.gateway.governance.kms_signer import (  # noqa: E402
    KMSGovernanceSigner,
    SignedRecord,
    SoftwareEd25519Provider,
)
from src.gateway.governance.reconciliation.daemon import (  # noqa: E402
    FENCE_EPOCH_KEY,
    GroundTruthReconciler,
    active_fence_key,
    reconciled_state_key,
)
from src.gateway.governance.reconciliation.trust import (  # noqa: E402
    build_reconciler_verifier,
    reset_reconciler_trust,
)
from src.gateway.governance.safety.barrier_tier import (  # noqa: E402
    commit_barrier,
    preview_barrier,
)
from src.gateway.governance.safety.cbf_engine import (  # noqa: E402
    ControlBarrierFunction,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_STREAM_KEY = "cage:evidence:stream"
_TRACE_ID = "0123456789abcdef0123456789abcdef"
_CHAIN_ID = "11111111-2222-3333-4444-555555555555"


class _HardwareEd25519TestProvider(SoftwareEd25519Provider):
    """Asymmetric Ed25519 KMS test provider emulating hardware-backed KMS in enforcing postures."""

    @property
    def provider_name(self) -> str:
        return "GCP_KMS_ED25519"

    @property
    def is_software_fallback(self) -> bool:
        return False


class _StrictTypedDecisionSigner:
    """Real typed signer enforcing ``isinstance(plan, dict)`` as ``KMSGovernanceSigner.sign_decision`` does."""

    def __init__(self, inner: KMSGovernanceSigner) -> None:
        self._inner = inner
        self.observed_plans: list[dict[str, Any]] = []

    @property
    def is_kms_active(self) -> bool:
        return self._inner.is_kms_active

    def sign_decision(self, plan: dict[str, Any]) -> SignedRecord:
        if not isinstance(plan, dict):
            raise TypeError(
                f"sign_decision expected dict[str, Any], got {type(plan).__name__}"
            )
        self.observed_plans.append(dict(plan))
        return self._inner.sign_decision(plan)


def _read_stream_entries(r: Any, stream_key: str = _STREAM_KEY) -> list[dict[str, str]]:
    raw = r.xrange(stream_key, min="-", max="+")
    return [
        {
            (k.decode() if isinstance(k, bytes) else str(k)): (
                v.decode() if isinstance(v, bytes) else str(v)
            )
            for k, v in fields.items()
        }
        for _entry_id, fields in raw
    ]


def _make_chained_records(payloads: list[dict[str, Any]]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    prev_hash = ""
    for seq, payload in enumerate(payloads):
        payload_json = jcs_bytes(payload).decode("utf-8")
        event_type = str(payload.get("type", "UNKNOWN"))
        control_id = str(
            payload.get("controlId") or payload.get("control_id") or "CA-7"
        )
        rec_hash = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=seq,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=_CHAIN_ID,
            trace_id=_TRACE_ID,
        )
        records.append(
            {
                "schema": "cage-audit/3.0",
                "chain_id": _CHAIN_ID,
                "sequence": str(seq),
                "timestamp_utc": "2026-11-05T15:00:00+00:00",
                "event_type": event_type,
                "control_id": control_id,
                "trace_id": _TRACE_ID,
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "GOVERNANCE",
                "prev_hash": prev_hash,
                "record_hash": rec_hash,
                "payload_json": payload_json,
            }
        )
        prev_hash = rec_hash
    return records


def _valid_discrepancy_fence_payload(
    *,
    fence_epoch: int = 1,
    invariant_id: str = "finance.cash_balance",
    fence_id: str | None = None,
) -> dict[str, Any]:
    resolved_fence_id = fence_id or f"{invariant_id}:epoch:{fence_epoch}"
    return {
        "type": RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE,
        "event_type": RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE,
        "schema_version": 1,
        "controlId": "CA-7",
        "control_id": "CA-7",
        "fence_epoch": fence_epoch,
        "fence_id": resolved_fence_id,
        "fence_trigger": "custodian_discrepancy_spike",
        "invariant_id": invariant_id,
        "account_id": "default",
        "source": "simulated:finance_cash_ledger",
        "sequence": 1,
        "state_scalar": 50000,
        "discrepancy_delta": 50000,
        "effective_threshold": 1000,
        "discrepancy_count": 1,
        "reasons": ["discrepancy_delta=50000.00 exceeds effective_threshold=1000.00"],
        "discrepancy_digests": ["a" * 64],
        "custodian_snapshot_digest": "b" * 64,
        "timestamp_utc": "2026-11-05T15:00:00+00:00",
        "signed_at": 1762354800.0,
    }


def _build_real_refusal_event(
    *,
    violations: list[Violation],
    action: str = "execute_trade",
    params: dict[str, Any] | None = None,
    governing_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_params = dict(params or {"thread_id": "tx-11b-001", "amount": 250.0})
    tier_failures = [
        GovernanceTierFailure(
            tier=v.tier,
            control_id=v.code,
            rule_description=v.message,
            governing_state=dict(governing_state or {}),
            protected_consequence="prevent_unverified_balance_mutation",
        )
        for v in violations
    ]
    receipt = build_refusal_receipt(
        action=action,
        params=resolved_params,
        violations=violations,
        tier_failures=tier_failures,
    )
    assert receipt.verify_proof_hash() is True
    receipt_dict = receipt.to_dict()
    assert isinstance(receipt_dict["tier_failures"], list)
    assert all(isinstance(tf, dict) for tf in receipt_dict["tier_failures"])
    return {
        "type": "GOVERNANCE_REFUSAL",
        "controlId": receipt.control_id
        or GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
        "receipt": receipt_dict,
    }


class TestReconcilerChainedDiscrepancyFenceEmission:
    """Verify GroundTruthReconciler emits KMS-signed, hash-chained RECONCILIATION_DISCREPANCY_FENCE records."""

    def test_discrepancy_spike_emits_hash_chained_fence_record(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        r = fakeredis.FakeRedis(decode_responses=True)
        r.set("safety:current_cash", "100000.0")

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r,
            discrepancy_threshold=1_000.0,
        )

        result = reconciler.reconcile()

        assert not result.is_valid
        assert result.discrepancy_detected is True
        assert result.fence_epoch == 1
        assert result.evidence_error is None
        assert result.evidence_sequence == 0
        assert (
            isinstance(result.evidence_record_hash, str)
            and len(result.evidence_record_hash) == 64
        )
        assert r.get(FENCE_EPOCH_KEY) == "1"
        assert r.get(reconciled_state_key("finance.cash_balance")) is None
        active_marker = json.loads(
            str(r.get(active_fence_key("finance.cash_balance")) or "{}")
        )
        assert active_marker["fence_epoch"] == 1
        assert active_marker["fence_id"] == "finance.cash_balance:epoch:1"

        entries = _read_stream_entries(r)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["event_type"] == RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE
        assert entry["control_id"] == "CA-7"
        assert entry["sequence"] == "0"
        assert entry["prev_hash"] == ""
        assert entry["record_hash"] == result.evidence_record_hash
        assert verify_record(entry, "").valid is True

        payload = json.loads(entry["payload_json"])
        assert payload["type"] == RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE
        assert payload["fence_epoch"] == 1
        assert payload["fence_id"] == "finance.cash_balance:epoch:1"
        assert payload["invariant_id"] == "finance.cash_balance"
        assert payload["discrepancy_count"] == 1
        assert len(payload["reasons"]) == 1
        assert len(payload["discrepancy_digests"]) == 1
        assert len(payload["custodian_snapshot_digest"]) == 64

        assert repo_check_stream(entries, expected_fence_epochs=(1,)) == []
        assert pkg_check_stream(entries, expected_fence_epochs=(1,)) == []

    def test_barrier_floor_breach_and_subsequent_spike_chain_together(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        r = fakeredis.FakeRedis(decode_responses=True)
        r.set("safety:current_cash", "100000.0")

        provider = SimulatedCashLedgerProvider(initial_scalar=5_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r,
            discrepancy_threshold=1_000.0,
        )
        res1 = reconciler.reconcile()
        assert not res1.is_valid
        assert res1.fence_epoch == 1
        assert res1.evidence_sequence == 0

        provider.reset(scalar=40_000.0)
        res2 = reconciler.reconcile()
        assert not res2.is_valid
        assert res2.fence_epoch == 2
        assert res2.evidence_sequence == 1

        entries = _read_stream_entries(r)
        assert len(entries) == 2
        assert entries[0]["sequence"] == "0"
        assert entries[0]["prev_hash"] == ""
        assert entries[1]["sequence"] == "1"
        assert entries[1]["prev_hash"] == entries[0]["record_hash"]
        assert verify_record(entries[0], "").valid is True
        assert verify_record(entries[1], entries[0]["record_hash"]).valid is True

        p1 = json.loads(entries[0]["payload_json"])
        p2 = json.loads(entries[1]["payload_json"])
        assert p1["fence_trigger"] == "barrier_floor_breach"
        assert p1["fence_epoch"] == 1
        assert p2["fence_trigger"] == "custodian_discrepancy_spike"
        assert p2["fence_epoch"] == 2

        assert repo_check_stream(entries, expected_fence_epochs=(1, 2)) == []

    @pytest.mark.parametrize("posture_env", ["development", "staging", "production"])
    def test_real_kms_governance_signer_receives_dict_and_verifies_signature(
        self, monkeypatch: pytest.MonkeyPatch, posture_env: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", posture_env)
        r_db0 = fakeredis.FakeRedis(decode_responses=True)
        r_db1 = fakeredis.FakeRedis(decode_responses=True)
        r_db0.set("safety:current_cash", "100000.0")

        hw_provider = _HardwareEd25519TestProvider(
            key_id="projects/p/locations/us/keyRings/r/cryptoKeys/reconciler/cryptoKeyVersions/1"
        )
        kms_signer = KMSGovernanceSigner(provider=hw_provider)
        typed_signer = _StrictTypedDecisionSigner(kms_signer)
        sink = EvidenceStreamClient(r_db1, redis_db=1)

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r_db0,
            signer=typed_signer,
            evidence_sink=sink,
            discrepancy_threshold=1_000.0,
        )

        res = reconciler.reconcile()
        assert not res.is_valid
        assert res.evidence_error is None
        assert len(typed_signer.observed_plans) == 1
        observed_plan = typed_signer.observed_plans[0]
        assert isinstance(observed_plan, dict)
        assert isinstance(observed_plan.get("signed_at"), float)
        assert observed_plan["fence_epoch"] == 1
        assert observed_plan["fence_id"] == "finance.cash_balance:epoch:1"

        assert _read_stream_entries(r_db0) == []
        entries = _read_stream_entries(r_db1)
        assert len(entries) == 1
        payload = json.loads(entries[0]["payload_json"])
        assert isinstance(payload["signature"], str) and len(payload["signature"]) >= 64
        assert payload["kms_key_id"] == hw_provider.key_id
        assert payload["signing_algorithm"] == "GCP_KMS_ED25519"

        unsigned_payload = {
            k: v
            for k, v in payload.items()
            if k not in ("signature", "kms_key_id", "signing_algorithm")
        }
        verifier = build_reconciler_verifier(
            trust_anchors={hw_provider.key_id: hw_provider.get_public_key_pem()}
        )
        assert (
            verifier.verify_decision(
                unsigned_payload,
                payload["signature"],
                kid=payload["kms_key_id"],
                algorithm=payload["signing_algorithm"],
            )
            is True
        )

    @pytest.mark.parametrize("posture_env", ["staging", "production"])
    def test_signing_exception_in_enforcing_posture_raises_and_emits_no_unsigned_record(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        posture_env: str,
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", posture_env)
        r_db0 = fakeredis.FakeRedis(decode_responses=True)
        r_db1 = fakeredis.FakeRedis(decode_responses=True)
        r_db0.set("safety:current_cash", "100000.0")
        r_db0.set(
            reconciled_state_key("finance.cash_balance"),
            '{"state_scalar":100000}',
        )

        failing_signer = MagicMock()
        failing_signer.is_kms_active = True
        failing_signer.sign_decision.side_effect = RuntimeError("KMS HSM unavailable")

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r_db0,
            signer=failing_signer,
            evidence_sink=EvidenceStreamClient(r_db1, redis_db=1),
            discrepancy_threshold=1_000.0,
        )

        with caplog.at_level(logging.ERROR):
            with pytest.raises(
                RuntimeError,
                match="Discrepancy fence KMS signing failed in enforcing posture",
            ):
                reconciler.reconcile()

        # Gateway operational state MUST still be fenced (fail-closed)
        assert r_db0.get(FENCE_EPOCH_KEY) == "1"
        assert r_db0.get(reconciled_state_key("finance.cash_balance")) is None
        # Zero unsigned records may be emitted to the evidence stream
        assert _read_stream_entries(r_db1) == []
        assert _read_stream_entries(r_db0) == []
        assert reconciler.evidence_publish_failures == 1
        assert any(rec.levelno >= logging.ERROR for rec in caplog.records)

    @pytest.mark.parametrize("posture_env", ["staging", "production"])
    def test_unconfigured_or_fallback_signer_in_enforcing_posture_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch, posture_env: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", posture_env)
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        r_db0 = fakeredis.FakeRedis(decode_responses=True)
        r_db1 = fakeredis.FakeRedis(decode_responses=True)
        r_db0.set("safety:current_cash", "100000.0")

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r_db0,
            evidence_sink=EvidenceStreamClient(r_db1, redis_db=1),
            discrepancy_threshold=1_000.0,
        )

        with pytest.raises(
            RuntimeError,
            match="Discrepancy fence KMS signing failed in enforcing posture",
        ):
            reconciler.reconcile()

        assert r_db0.get(FENCE_EPOCH_KEY) == "1"
        assert _read_stream_entries(r_db1) == []
        assert reconciler.evidence_publish_failures == 1

    def test_evidence_append_failure_remains_fail_closed_and_surfaces_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        r = fakeredis.FakeRedis(decode_responses=True)
        r.set("safety:current_cash", "100000.0")
        r.set(
            reconciled_state_key("finance.cash_balance"),
            '{"state_scalar":100000}',
        )

        failing_sink = MagicMock()
        failing_sink._redis = None
        failing_sink.ingest_sync.side_effect = RuntimeError("Redis stream offline")

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r,
            evidence_sink=failing_sink,
            discrepancy_threshold=1_000.0,
        )

        res = reconciler.reconcile()

        assert not res.is_valid
        assert res.discrepancy_detected is True
        assert res.fence_epoch == 1
        assert r.get(FENCE_EPOCH_KEY) == "1"
        assert r.get(reconciled_state_key("finance.cash_balance")) is None

        assert reconciler.evidence_publish_failures == 1
        assert res.evidence_error is not None
        assert "Redis stream offline" in res.evidence_error
        assert "evidence_append_failed" in (res.error or "")

        findings = repo_check_stream(
            [], publish_failures=reconciler.evidence_publish_failures
        )
        assert [f.rule for f in findings] == ["evidence_loss"]


class TestGroundTruthReconcilerFromEnvDatabaseIsolation:
    """Verify GroundTruthReconciler.from_env() wires operational Redis to DB 0 and evidence to DB 1."""

    def test_from_env_wires_operational_db0_and_evidence_sink_db1_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("REDIS_TLS", "false")
        monkeypatch.delenv("REDIS_AUTH_MODE", raising=False)
        monkeypatch.delenv("EVIDENCE_STREAM_REDIS_URL", raising=False)
        monkeypatch.delenv("EVIDENCE_STREAM_REDIS_DB", raising=False)
        monkeypatch.delenv("EVIDENCE_STREAM_KEY", raising=False)

        reconciler = GroundTruthReconciler.from_env()

        op_kwargs = reconciler._redis.connection_pool.connection_kwargs
        assert op_kwargs["db"] == 0

        from src.gateway.governance.evidence.stream import (
            EvidenceStreamClient as _CurrentEvidenceStreamClient,
        )

        sink = reconciler._evidence_sink
        assert isinstance(sink, _CurrentEvidenceStreamClient)
        assert sink.redis_db == 1
        assert sink.stream_key == "cage:evidence:stream"
        ev_kwargs = sink._redis.connection_pool.connection_kwargs
        assert ev_kwargs["db"] == 1

    def test_from_env_respects_evidence_stream_redis_db_and_routes_fences_to_db1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_DB", "1")
        monkeypatch.setenv("EVIDENCE_STREAM_KEY", "cage:evidence:stream")
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        shared_server = fakeredis.FakeServer()
        fake_db0 = fakeredis.FakeRedis(
            server=shared_server, db=0, decode_responses=True
        )
        fake_db1 = fakeredis.FakeRedis(
            server=shared_server, db=1, decode_responses=True
        )

        monkeypatch.setattr(
            "redis.from_url",
            lambda _url, decode_responses=True: fake_db0,
        )
        monkeypatch.setattr(
            "src.gateway.infrastructure.redis_client.build_sync_redis",
            lambda _url, *, db=None, socket_timeout=3.0: (
                fake_db1 if db == 1 else fake_db0
            ),
        )

        reconciler = GroundTruthReconciler.from_env()
        reconciler._discrepancy_threshold = 1_000.0
        # Seed baseline at 250,000 while default simulated provider reports 100,000
        fake_db0.set("safety:current_cash", "250000.0")

        res = reconciler.reconcile()
        assert not res.is_valid
        assert res.discrepancy_detected is True
        assert res.fence_epoch == 1
        assert res.evidence_error is None

        # Operational state & fence epoch live on DB 0; evidence stream on DB 0 MUST be empty
        assert fake_db0.get(FENCE_EPOCH_KEY) == "1"
        assert _read_stream_entries(fake_db0) == []

        # Authoritative evidence chain on DB 1 MUST carry the discrepancy fence record
        db1_entries = _read_stream_entries(fake_db1)
        assert len(db1_entries) == 1
        assert (
            db1_entries[0]["event_type"] == RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE
        )
        assert verify_record(db1_entries[0], "").valid is True
        assert repo_check_stream(db1_entries, expected_fence_epochs=(1,)) == []


class TestReconciliationFenceStreamInvariants:
    """Verify cbf_engine.py, RefusalReceipt.to_dict(), stream_invariants.py, and cage-conformance Check 8b."""

    def test_end_to_end_reconciler_fence_and_cbf_refusal_receipt_conform(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.delenv("RECONCILER_KMS_KEY", raising=False)
        reset_reconciler_trust()

        shared_server = fakeredis.FakeServer()
        r_db0_sync = fakeredis.FakeRedis(
            server=shared_server, db=0, decode_responses=True
        )
        r_db0_async = fakeredis.aioredis.FakeRedis(
            server=shared_server, db=0, decode_responses=True
        )
        r_db1_sync = fakeredis.FakeRedis(
            server=shared_server, db=1, decode_responses=True
        )
        r_db0_sync.set("safety:current_cash", "100000.0")

        hw_provider = _HardwareEd25519TestProvider(key_id="reconciler-kms-key-1")
        kms_signer = KMSGovernanceSigner(provider=hw_provider)

        provider = SimulatedCashLedgerProvider(initial_scalar=50_000.0)
        reconciler = GroundTruthReconciler(
            provider=provider,
            redis_client=r_db0_sync,
            signer=kms_signer,
            evidence_sink=EvidenceStreamClient(r_db1_sync, redis_db=1),
            discrepancy_threshold=1_000.0,
        )
        res = reconciler.reconcile()
        assert res.fence_epoch == 1
        assert res.evidence_error is None

        cbf = ControlBarrierFunction(
            invariant=CashBarrier(gamma=0.5),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )
        cbf.tracer = None

        async def _mock_get(key: str) -> Any:
            return await r_db0_async.get(key)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                new=MagicMock(
                    get_raw_client=MagicMock(return_value=r_db0_async),
                    get=MagicMock(side_effect=_mock_get),
                ),
            ),
            patch(
                "src.gateway.governance.reconciliation.daemon.read_verified_balance",
                return_value=None,
            ),
            patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
        ):
            preview_violations = asyncio.run(
                preview_barrier(
                    cbf,
                    tier="CBF",
                    code=GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                    action="execute_trade",
                    params={"amount": 250.0, "thread_id": "tx-preview-1"},
                )
            )
            commit_violations, commit_rcpt = asyncio.run(
                commit_barrier(
                    cbf,
                    tier="CBF",
                    code=GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                    action="execute_trade",
                    params={"amount": 250.0, "thread_id": "tx-commit-1"},
                )
            )

        assert commit_rcpt is None
        assert len(preview_violations) == 1
        assert len(commit_violations) == 1
        for v in (preview_violations[0], commit_violations[0]):
            assert "RECONCILIATION_FENCE_ACTIVE" in v.message
            assert "fence_id=finance.cash_balance:epoch:1" in v.message
            assert "fence_epoch=1" in v.message

        refusal_event_preview = _build_real_refusal_event(
            violations=preview_violations,
            params={"amount": 250.0, "thread_id": "tx-preview-1"},
        )
        refusal_event_commit = _build_real_refusal_event(
            violations=commit_violations,
            params={"amount": 250.0, "thread_id": "tx-commit-1"},
        )
        append_evidence_record_sync(r_db1_sync, refusal_event_preview)
        append_evidence_record_sync(r_db1_sync, refusal_event_commit)

        entries = _read_stream_entries(r_db1_sync)
        assert len(entries) == 3
        assert repo_check_stream(entries, expected_fence_epochs=(1,)) == []
        assert pkg_check_stream(entries, expected_fence_epochs=(1,)) == []

        provenance = cc.build_provenance(
            cc.AdapterUnderTest(
                provider_id="cage-kernel",
                adapter_author_org="Google LLC",
                counterparty_org="Example Deployer",
                adapter_version="5.0.0",
                adapter_commit="385e502e",
                contract_profile=cc.MODE_PROFILES["stream"],
            ),
            cc.RunnerProvenance(
                runner_org="Google LLC",
                runner_identity="ci@example.com",
                cage_conformance_version=cc.__version__,
                timestamp_utc="2026-11-05T15:00:00+00:00",
            ),
        )
        inputs = (cc.InputDigest.of_bytes("stream.jsonl", jcs_bytes(entries)),)
        report = cc.verify_stream(entries, provenance=provenance, inputs=inputs)
        assert report.conformant, [a for a in report.assertions if not a.passed]
        fence_assertions = [
            a for a in report.assertions if a.assertion_id == "reconciliation_fence"
        ]
        assert len(fence_assertions) == 1
        assert fence_assertions[0].passed is True

        # Subsequent valid reconciliation clears the active fence marker on DB 0
        provider.reset(scalar=100_000.0)
        recovered = reconciler.reconcile()
        assert recovered.is_valid
        assert r_db0_sync.get(active_fence_key("finance.cash_balance")) is None

    def test_uncaused_real_refusal_receipt_citing_fence_fails_conformance(self) -> None:
        v = Violation(
            tier="CBF",
            code=GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
            kind=ViolationKind.HARD,
            message=(
                "[CAGE-CTRL-004] SR 11-7 Violation: Ground truth verification failed "
                "(self_reported): unverified self_reported balance in strict mode; "
                "RECONCILIATION_FENCE_ACTIVE (fence_id=finance.cash_balance:epoch:1, fence_epoch=1). Fail-closed."
            ),
        )
        uncaused_refusal = _build_real_refusal_event(violations=[v])
        records = _make_chained_records([uncaused_refusal])
        findings = repo_check_stream(records)
        assert {f.rule for f in findings} == {"reconciliation_fence"}
        assert any(
            "fence_id 'finance.cash_balance:epoch:1'" in f.detail for f in findings
        )
        assert any("fence_epoch 1" in f.detail for f in findings)
        assert [(f.index, f.rule, f.detail) for f in pkg_check_stream(records)] == [
            (f.index, f.rule, f.detail) for f in findings
        ]

    def test_mismatched_fence_epoch_in_real_refusal_receipt_fails_conformance(
        self,
    ) -> None:
        cause = _valid_discrepancy_fence_payload(fence_epoch=1)
        v = Violation(
            tier="CBF",
            code=GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
            kind=ViolationKind.HARD,
            message=(
                "RECONCILIATION_UNAVAILABLE: CBF strict mode: reconciliation unavailable; "
                "RECONCILIATION_FENCE_ACTIVE (fence_id=finance.cash_balance:epoch:2, fence_epoch=2)"
            ),
        )
        stale_refusal = _build_real_refusal_event(violations=[v])
        receipt_dict = stale_refusal["receipt"]
        summary_refusal = {
            "type": "GOVERNANCE_REFUSAL_RECEIPT",
            "control_id": receipt_dict["control_id"],
            "proof_hash": receipt_dict["proof_hash"],
            "violated_rule": receipt_dict["violated_rule"],
            "refusal_reason": receipt_dict["violated_rule"],
            "tier_failures": receipt_dict["tier_failures"],
            "standing_snapshot": receipt_dict["standing_snapshot"],
        }
        records = _make_chained_records([cause, stale_refusal, summary_refusal])
        findings = repo_check_stream(records)
        assert {f.rule for f in findings} == {"reconciliation_fence"}
        assert any(f.index == 1 and "fence_epoch 2" in f.detail for f in findings)
        assert any(f.index == 2 and "fence_epoch 2" in f.detail for f in findings)

    def test_ordinary_cbf_overspend_refusal_does_not_require_discrepancy_fence(
        self,
    ) -> None:
        v = Violation(
            tier="CBF",
            code=GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
            kind=ViolationKind.HARD,
            message=(
                "[CAGE-CTRL-004] SR 11-7 Violation: Action cost 95000.00 violates "
                "Control Barrier Function headroom (h_next=5000.00 < required=45000.00)."
            ),
        )
        normal_refusal = _build_real_refusal_event(
            violations=[v],
            governing_state={"balance": 100_000.0, "fence_epoch": 3},
        )
        records = _make_chained_records([normal_refusal])
        assert repo_check_stream(records) == []
        assert pkg_check_stream(records) == []

    @pytest.mark.parametrize(
        ("override", "expected_substring"),
        [
            ({"controlId": "AU-2", "control_id": "AU-2"}, "control_id"),
            ({"fence_epoch": 0}, "invalid fence_epoch"),
            ({"fence_id": ""}, "missing/invalid fence_id"),
            ({"invariant_id": ""}, "missing/invalid invariant_id"),
            ({"discrepancy_count": 0}, "invalid discrepancy_count"),
            ({"reasons": []}, "missing/invalid reasons"),
            ({"discrepancy_digests": ["not-a-hex-digest"]}, "discrepancy_digests"),
            (
                {"custodian_snapshot_digest": "short"},
                "custodian_snapshot_digest",
            ),
            ({"timestamp_utc": ""}, "timestamp_utc"),
        ],
    )
    def test_malformed_discrepancy_fence_record_fails_conformance(
        self, override: dict[str, Any], expected_substring: str
    ) -> None:
        bad = _valid_discrepancy_fence_payload() | override
        records = _make_chained_records([bad])
        findings = repo_check_stream(records)
        fence_findings = [f for f in findings if f.rule == "reconciliation_fence"]
        assert fence_findings, f"Expected reconciliation_fence finding for {override}"
        assert any(expected_substring in f.detail for f in fence_findings)

    def test_non_monotonic_fence_epoch_for_same_invariant_fails(self) -> None:
        first = _valid_discrepancy_fence_payload(
            fence_epoch=2, fence_id="finance.cash_balance:epoch:2"
        )
        second = _valid_discrepancy_fence_payload(
            fence_epoch=2, fence_id="finance.cash_balance:epoch:2-dup"
        )
        records = _make_chained_records([first, second])
        findings = repo_check_stream(records)
        assert [f.rule for f in findings] == ["reconciliation_fence"]
        assert "non-monotonic" in findings[0].detail
