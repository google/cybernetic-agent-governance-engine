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

"""Tests for src/compliance_bridge/evidence_verifier.py.

Hermetic end to end: the real ``EvidenceStreamSink`` produces into fakeredis,
the real ``EvidenceCustodian`` signs with a real asymmetric key
(``SoftwareEd25519Provider``, permitted only in test posture) and writes to
the real ``NullColdStore``. The verifier then reads the archive back. Most
tests tamper with the archive and observe the verifier refusing it.
"""

from __future__ import annotations

import hashlib
import json

import fakeredis
import pytest

from src.compliance_bridge import evidence_verifier as ev
from src.compliance_bridge.evidence_custodian import EvidenceCustodian
from src.compliance_bridge.evidence_verifier import (
    CustodyVerificationReport,
    CustodyVerifier,
    VerificationFailure,
    build_attestation_verifier,
    load_evidence_trust_anchors,
)
from src.gateway.governance.evidence.cold_store import ColdStoreError
from src.gateway.governance.evidence.null_cold_store import NullColdStore
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

STREAM_KEY = "cage:evidence:verifier-test"
KID = "projects/p/locations/l/keyRings/r/cryptoKeys/compliance-evidence/cryptoKeyVersions/1"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_key_env(monkeypatch):
    for var in (
        "EVIDENCE_KMS_KEY",
        "KMS_GOVERNANCE_KEY",
        "RECONCILER_KMS_KEY",
        "EVIDENCE_TRUST_ANCHORS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def server():
    return fakeredis.FakeServer()


@pytest.fixture
def provider():
    return SoftwareEd25519Provider(key_id=KID)


@pytest.fixture
def signer(provider):
    return KMSGovernanceSigner(provider=provider)


@pytest.fixture
def store():
    return NullColdStore()


def _redis(server):
    return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)


async def _sink(server, *, max_len: int = 10_000) -> EvidenceStreamSink:
    sink = EvidenceStreamSink(stream_key=STREAM_KEY, max_len=max_len)
    sink._redis = _redis(server)
    return sink


async def _ingest(sink, n: int, start: int = 0) -> None:
    for i in range(n):
        await sink.ingest(
            {"type": "GOVERNANCE_DECISION", "controlId": "AU-9", "n": start + i}
        )


def _custodian(server, store, signer, *, require_signature=True):
    return EvidenceCustodian(
        _redis(server),
        store,
        signer,
        stream_key=STREAM_KEY,
        batch_size=100,
        require_signature=require_signature,
        interval_s=0.01,
    )


async def _custody_batches(server, store, signer, sizes: list[int]):
    """Produce and custody one batch per entry in ``sizes``; return outcomes."""
    sink = await _sink(server)
    custodian = _custodian(server, store, signer)
    outcomes, produced = [], 0
    for size in sizes:
        await _ingest(sink, size, start=produced)
        produced += size
        outcomes.append(await custodian.flush_once())
    return outcomes


def _verifier(store, provider, anchors=None):
    anchors = {KID: provider.get_public_key_pem()} if anchors is None else anchors
    return CustodyVerifier(store, build_attestation_verifier(anchors))


def _reasons(report: CustodyVerificationReport) -> str:
    return " | ".join(f.reason for f in report.failures)


def _resign(store, signer, att_key: str, att: dict) -> None:
    body = {k: v for k, v in att.items() if k != "signature"}
    att = {
        **body,
        "signature": {
            "algorithm": signer.signing_algorithm,
            "key_id": signer.key_id,
            "value": signer.sign(body),
        },
    }
    store._entries[att_key] = json.dumps(
        att, sort_keys=True, separators=(",", ":")
    ).encode()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestVerifiesCustodiedArchive:
    @pytest.mark.asyncio
    async def test_signed_chain_verifies(self, server, store, signer, provider):
        outcomes = await _custody_batches(server, store, signer, [3, 2, 4])
        report = await _verifier(store, provider).verify_all()

        assert report.ok, _reasons(report)
        assert [b.attestation_key for b in report.verified] == sorted(
            o.attestation_key for o in outcomes
        )
        assert [(b.first_sequence, b.last_sequence) for b in report.verified] == [
            (0, 2),
            (3, 4),
            (5, 8),
        ]
        assert all(b.key_id == KID for b in report.verified)
        assert report.declared_gaps == [] and report.non_evidentiary == []

    @pytest.mark.asyncio
    async def test_declared_trim_gap_is_reported_not_failed(
        self, server, store, signer, provider
    ):
        sink = await _sink(server, max_len=3)
        custodian = _custodian(server, store, signer)
        await _ingest(sink, 2)
        await custodian.flush_once()  # 0..1
        await _ingest(sink, 5, start=2)  # stream keeps 4..6 only
        await custodian.flush_once()

        report = await _verifier(store, provider).verify_all()
        assert report.ok, _reasons(report)
        assert len(report.verified) == 2
        [gap] = report.declared_gaps
        assert (gap.missing_from, gap.missing_to) == (2, 3)

    @pytest.mark.asyncio
    async def test_unsigned_attestations_are_never_verified(
        self, server, store, provider
    ):
        sink = await _sink(server)
        await _ingest(sink, 3)
        await _custodian(server, store, None, require_signature=False).flush_once()

        report = await _verifier(store, provider).verify_all()
        assert report.verified == []
        assert len(report.non_evidentiary) == 1
        assert report.non_evidentiary[0].endswith(".attestation.unsigned.json")


# ---------------------------------------------------------------------------
# Signature and trust anchors (fail closed)
# ---------------------------------------------------------------------------


class TestSignatureFailsClosed:
    @pytest.mark.asyncio
    async def test_unknown_kid_fails(self, server, store, signer, provider):
        await _custody_batches(server, store, signer, [2])
        report = await _verifier(store, provider, anchors={}).verify_all()
        assert not report.ok
        assert "does not verify" in _reasons(report)

    @pytest.mark.asyncio
    async def test_wrong_public_key_for_kid_fails(
        self, server, store, signer, provider
    ):
        await _custody_batches(server, store, signer, [2])
        other = SoftwareEd25519Provider(key_id=KID).get_public_key_pem()
        report = await _verifier(store, provider, anchors={KID: other}).verify_all()
        assert not report.ok
        assert "does not verify" in _reasons(report)

    @pytest.mark.asyncio
    async def test_gateway_seal_kid_is_rejected(
        self, server, store, signer, provider, monkeypatch
    ):
        await _custody_batches(server, store, signer, [2])
        monkeypatch.setenv("KMS_GOVERNANCE_KEY", KID)
        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "non-evidence key" in _reasons(report)

    @pytest.mark.asyncio
    async def test_tampered_attestation_body_fails(
        self, server, store, signer, provider
    ):
        [outcome] = await _custody_batches(server, store, signer, [3])
        att = json.loads(store._entries[outcome.attestation_key])
        att["last_record_hash"] = "0" * 64
        store._entries[outcome.attestation_key] = json.dumps(att).encode()

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "does not verify" in _reasons(report)

    @pytest.mark.asyncio
    async def test_unsigned_body_under_signed_key_fails(
        self, server, store, signer, provider
    ):
        [outcome] = await _custody_batches(server, store, signer, [2])
        att = json.loads(store._entries[outcome.attestation_key])
        att["signature_status"] = "UNSIGNED"
        store._entries[outcome.attestation_key] = json.dumps(att).encode()

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "UNSIGNED" in _reasons(report)


# ---------------------------------------------------------------------------
# Data object and records (fail closed)
# ---------------------------------------------------------------------------


class TestDataFailsClosed:
    @pytest.mark.asyncio
    async def test_tampered_data_object_fails(self, server, store, signer, provider):
        [outcome] = await _custody_batches(server, store, signer, [3])
        store._entries[outcome.data_key] = store._entries[outcome.data_key].replace(
            b"AU-9", b"AU-8", 1
        )
        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "SHA-256" in _reasons(report)

    @pytest.mark.asyncio
    async def test_missing_data_object_fails(self, server, store, signer, provider):
        [outcome] = await _custody_batches(server, store, signer, [2])
        del store._entries[outcome.data_key]
        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "data object is missing" in _reasons(report)

    @pytest.mark.asyncio
    async def test_signed_but_forged_record_fails(
        self, server, store, signer, provider
    ):
        """Even a validly signed attestation cannot vouch for a broken record."""
        [outcome] = await _custody_batches(server, store, signer, [3])
        lines = store._entries[outcome.data_key].decode().splitlines()
        forged = json.loads(lines[1])
        forged["payload_json"] = forged["payload_json"].replace("AU-9", "AU-8")
        lines[1] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
        content = ("\n".join(lines) + "\n").encode()
        store._entries[outcome.data_key] = content

        att = json.loads(store._entries[outcome.attestation_key])
        att["content_sha256"] = hashlib.sha256(content).hexdigest()
        _resign(store, signer, outcome.attestation_key, att)

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "sequence 1" in _reasons(report)

    @pytest.mark.asyncio
    async def test_attestation_moved_to_another_key_fails(
        self, server, store, signer, provider
    ):
        [outcome] = await _custody_batches(server, store, signer, [2])
        moved = outcome.attestation_key.replace("000000000001", "000000000009")
        store._entries[moved] = store._entries.pop(outcome.attestation_key)

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        reasons = _reasons(report)
        assert "does not belong to data_key" in reasons
        assert "data object has no attestation" in reasons

    @pytest.mark.asyncio
    async def test_orphan_data_object_fails(self, server, store, signer, provider):
        [outcome] = await _custody_batches(server, store, signer, [2])
        del store._entries[outcome.attestation_key]
        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert report.failures == [
            VerificationFailure(outcome.data_key, "data object has no attestation")
        ]

    @pytest.mark.asyncio
    async def test_unexpected_object_fails(self, server, store, signer, provider):
        await _custody_batches(server, store, signer, [2])
        await store.put_batch("evidence-stream/notes.txt", b"hello")
        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "unexpected object" in _reasons(report)


# ---------------------------------------------------------------------------
# Cross-batch continuity (fail closed)
# ---------------------------------------------------------------------------


class TestContinuityFailsClosed:
    @pytest.mark.asyncio
    async def test_deleted_middle_batch_fails(self, server, store, signer, provider):
        outcomes = await _custody_batches(server, store, signer, [2, 2, 2])
        del store._entries[outcomes[1].data_key]
        del store._entries[outcomes[1].attestation_key]

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "missing sequences 2..3" in _reasons(report)
        assert report.declared_gaps == []

    @pytest.mark.asyncio
    async def test_deleted_chain_head_fails(self, server, store, signer, provider):
        outcomes = await _custody_batches(server, store, signer, [2, 2])
        del store._entries[outcomes[0].data_key]
        del store._entries[outcomes[0].attestation_key]

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "missing sequences 0..1" in _reasons(report)

    @pytest.mark.asyncio
    async def test_unsigned_batch_inside_signed_chain_fails(
        self, server, store, signer, provider
    ):
        sink = await _sink(server)
        await _ingest(sink, 2)
        await _custodian(server, store, signer).flush_once()
        await _ingest(sink, 2, start=2)
        await _custodian(server, store, None, require_signature=False).flush_once()
        await _ingest(sink, 2, start=4)
        await _custodian(server, store, signer).flush_once()

        report = await _verifier(store, provider).verify_all()
        assert not report.ok
        assert "missing sequences 2..3" in _reasons(report)
        assert len(report.non_evidentiary) == 1


# ---------------------------------------------------------------------------
# Backend errors, trust-anchor loading, CLI
# ---------------------------------------------------------------------------


class _BrokenStore(NullColdStore):
    async def list_keys(self, prefix: str) -> list[str]:
        raise ColdStoreError("backend down", backend_id="null")


class TestBackendAndAnchors:
    @pytest.mark.asyncio
    async def test_backend_error_is_not_a_verdict(self, provider):
        with pytest.raises(ColdStoreError):
            await _verifier(_BrokenStore(), provider).verify_all()

    def test_no_configuration_loads_no_anchors(self):
        assert load_evidence_trust_anchors() == {}

    def test_manifest_anchors_are_loaded(self, tmp_path, monkeypatch, provider):
        manifest = tmp_path / "anchors.json"
        manifest.write_text(json.dumps({KID: provider.get_public_key_pem().decode()}))
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        assert load_evidence_trust_anchors() == {KID: provider.get_public_key_pem()}

    def test_manifest_with_gateway_kid_is_rejected(
        self, tmp_path, monkeypatch, provider
    ):
        manifest = tmp_path / "anchors.json"
        manifest.write_text(json.dumps({KID: provider.get_public_key_pem().decode()}))
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        monkeypatch.setenv("KMS_GOVERNANCE_KEY", KID)
        with pytest.raises(ValueError, match="gateway or reconciler"):
            load_evidence_trust_anchors()

    def test_manifest_with_other_crypto_key_is_rejected(
        self, tmp_path, monkeypatch, provider
    ):
        other_kid = KID.replace("compliance-evidence", "something-else")
        manifest = tmp_path / "anchors.json"
        manifest.write_text(
            json.dumps({other_kid: provider.get_public_key_pem().decode()})
        )
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        monkeypatch.setattr(
            "src.compliance_bridge.kms_batch_signer.build_evidence_signer",
            lambda: KMSGovernanceSigner(provider=provider),
        )
        monkeypatch.setenv("EVIDENCE_KMS_KEY", KID)
        with pytest.raises(ValueError, match="not a version of EVIDENCE_KMS_KEY"):
            load_evidence_trust_anchors()

    def test_malformed_manifest_is_rejected(self, tmp_path, monkeypatch):
        manifest = tmp_path / "anchors.json"
        manifest.write_text(json.dumps(["not", "a", "map"]))
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        with pytest.raises(ValueError, match="kid -> PEM"):
            load_evidence_trust_anchors()


class TestCli:
    def test_exit_status_reflects_failures(self, monkeypatch, capsys):
        failing = CustodyVerificationReport(
            prefix="evidence-stream/",
            failures=[VerificationFailure("k", "broken")],
        )

        async def fake_run(prefix):
            return failing

        monkeypatch.setattr(ev, "_run", fake_run)
        assert ev.main([]) == 1
        assert "FAIL k: broken" in capsys.readouterr().out

        async def fake_ok(prefix):
            return CustodyVerificationReport(prefix=prefix)

        monkeypatch.setattr(ev, "_run", fake_ok)
        assert ev.main(["--json"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

    def test_require_citable_rejects_empty_ok_report(self, monkeypatch, capsys):
        async def fake_empty(prefix):
            return CustodyVerificationReport(prefix=prefix)

        monkeypatch.setattr(ev, "_run", fake_empty)
        assert ev.main(["--require-citable"]) == 1
        assert "NOT CITABLE" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Citation gate & OSCAL export provenance
# ---------------------------------------------------------------------------


class TestCitabilityAndOscalExport:
    @pytest.mark.asyncio
    async def test_signed_chain_is_citable_and_populates_oscal_provenance(
        self, server, store, signer, provider
    ):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        from src.compliance_bridge.types import OscalFinding

        outcomes = await _custody_batches(server, store, signer, [2, 3])
        verifier = _verifier(store, provider)
        report = await verifier.verify_for_citation()

        assert report.ok is True
        assert report.citable is True
        assert report.to_dict()["citable"] is True
        assert len(report.assert_citable()) == 2

        finding = OscalFinding(
            control_id="AU-10",
            result="PASS",
            finding_id="finding-au10",
            safety_rate=1.0,
            evidence_age_s=10,
            remarks=None,
        )
        doc = build_oscal_assessment_results(
            findings=[finding],
            audit_id="audit-custody-1",
            custody_report=report,
        )
        result_entry = doc["assessment-results"]["results"][0]
        props = {p["name"]: p["value"] for p in result_entry["props"]}
        assert props["evidence-custody-verified-batches"] == "2"
        assert (
            props["evidence-custody-chain-head"] == report.verified[-1].last_record_hash
        )
        assert props["evidence-custody-key-id"] == KID
        links = result_entry["links"]
        assert [lnk["href"] for lnk in links] == [
            f"urn:cage:evidence-attestation:{o.attestation_key}" for o in outcomes
        ]
        assert all(lnk["rel"] == "evidence-attestation" for lnk in links)

    @pytest.mark.asyncio
    async def test_empty_archive_is_not_citable(self, store, provider):
        from src.compliance_bridge.evidence_verifier import EvidenceVerificationError
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results

        verifier = _verifier(store, provider)
        report = await verifier.verify_all()
        assert report.ok is True
        assert report.citable is False
        with pytest.raises(
            EvidenceVerificationError,
            match="contains no signed, verified evidence batches",
        ):
            report.assert_citable()
        with pytest.raises(EvidenceVerificationError):
            await verifier.verify_for_citation()
        with pytest.raises(EvidenceVerificationError):
            build_oscal_assessment_results(
                findings=[],
                audit_id="audit-empty",
                custody_report=report,
            )

    @pytest.mark.asyncio
    async def test_unsigned_only_archive_is_not_citable(self, server, store, provider):
        from src.compliance_bridge.evidence_verifier import EvidenceVerificationError
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results

        sink = await _sink(server)
        await _ingest(sink, 2)
        await _custodian(server, store, None, require_signature=False).flush_once()

        report = await _verifier(store, provider).verify_all()
        assert report.ok is True
        assert report.citable is False
        with pytest.raises(
            EvidenceVerificationError,
            match="unsigned non-evidentiary batch",
        ):
            report.assert_citable()
        with pytest.raises(EvidenceVerificationError):
            build_oscal_assessment_results(
                findings=[],
                audit_id="audit-unsigned",
                custody_report=report,
            )

    @pytest.mark.asyncio
    async def test_declared_gap_blocks_citation_unless_explicitly_allowed(
        self, server, store, signer, provider
    ):
        from src.compliance_bridge.evidence_verifier import EvidenceVerificationError

        sink = await _sink(server, max_len=2)
        await _ingest(sink, 5)
        await _custodian(server, store, signer).flush_once()

        report = await _verifier(store, provider).verify_all()
        assert report.ok is True
        assert report.citable is False
        with pytest.raises(
            EvidenceVerificationError,
            match="declared stream-trim gap",
        ):
            report.assert_citable()
        batches = report.assert_citable(allow_declared_gaps=True)
        assert len(batches) == 1

    @pytest.mark.asyncio
    async def test_tampered_archive_blocks_oscal_export(
        self, server, store, signer, provider
    ):
        from src.compliance_bridge.evidence_verifier import EvidenceVerificationError
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results

        [outcome] = await _custody_batches(server, store, signer, [2])
        store._entries[outcome.data_key] = b'{"tampered": true}\n'
        report = await _verifier(store, provider).verify_all()
        assert report.ok is False
        assert report.citable is False
        with pytest.raises(EvidenceVerificationError, match="SHA-256"):
            build_oscal_assessment_results(
                findings=[],
                audit_id="audit-tampered",
                custody_report=report,
            )


# ---------------------------------------------------------------------------
# from_env, run_forever scheduler, and Prometheus metrics
# ---------------------------------------------------------------------------


class _NonNullStore(NullColdStore):
    @property
    def backend_id(self) -> str:
        return "gcs"


class TestFromEnvAndScheduler:
    def test_enforcing_rejects_null_cold_store(self, monkeypatch):
        from src.compliance_bridge.evidence_custodian import EvidenceCustodyConfigError

        monkeypatch.setenv("CAGE_ENV", "production")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "null")
        with pytest.raises(EvidenceCustodyConfigError, match="null"):
            CustodyVerifier.from_env()

    def test_enforcing_rejects_empty_trust_anchors(self, monkeypatch):
        from src.compliance_bridge.evidence_custodian import EvidenceCustodyConfigError

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setattr(
            "src.gateway.governance.evidence.factory.get_cold_store",
            _NonNullStore,
        )
        with pytest.raises(EvidenceCustodyConfigError, match="trust anchor"):
            CustodyVerifier.from_env()

    def test_enforcing_rejects_malformed_manifest(self, tmp_path, monkeypatch):
        from src.compliance_bridge.evidence_custodian import EvidenceCustodyConfigError

        manifest = tmp_path / "bad.json"
        manifest.write_text("not-json")
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        monkeypatch.setattr(
            "src.gateway.governance.evidence.factory.get_cold_store",
            _NonNullStore,
        )
        with pytest.raises(EvidenceCustodyConfigError):
            CustodyVerifier.from_env()

    def test_permissive_builds_from_env_and_respects_interval_and_prefix(
        self, tmp_path, monkeypatch, provider
    ):
        manifest = tmp_path / "anchors.json"
        manifest.write_text(json.dumps({KID: provider.get_public_key_pem().decode()}))
        monkeypatch.setenv("CAGE_ENV", "test")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "null")
        monkeypatch.setenv("EVIDENCE_TRUST_ANCHORS_FILE", str(manifest))
        monkeypatch.setenv("EVIDENCE_VERIFY_PREFIX", "custom-prefix/")
        monkeypatch.setenv("EVIDENCE_VERIFY_INTERVAL_S", "42.5")
        verifier = CustodyVerifier.from_env()
        assert verifier._prefix == "custom-prefix/"
        assert verifier._interval_s == 42.5

    def test_invalid_interval_raises_value_error(self, store, provider):
        with pytest.raises(ValueError, match="interval_s must be > 0"):
            CustodyVerifier(
                store,
                build_attestation_verifier({KID: provider.get_public_key_pem()}),
                interval_s=0,
            )

    @pytest.mark.asyncio
    async def test_run_forever_updates_last_report_and_prometheus_metrics(
        self, server, store, signer, provider
    ):
        import asyncio

        await _custody_batches(server, store, signer, [2, 1])
        verifier = CustodyVerifier(
            store,
            build_attestation_verifier({KID: provider.get_public_key_pem()}),
            interval_s=0.02,
        )
        before_ok = ev.VERIFICATION_RUNS_TOTAL.labels(outcome="ok")._value.get()
        task = asyncio.create_task(verifier.run_forever())
        try:
            for _ in range(50):
                if verifier.last_report is not None:
                    break
                await asyncio.sleep(0.01)
            assert verifier.last_report is not None
            assert verifier.last_report.citable is True
            assert (
                ev.VERIFICATION_RUNS_TOTAL.labels(outcome="ok")._value.get() > before_ok
            )
            assert ev.VERIFIED_BATCHES._value.get() == 2.0
            assert ev.VERIFICATION_FAILURES._value.get() == 0.0
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


# ---------------------------------------------------------------------------
# FastAPI endpoints (/v1/evidence/verify & /v1/oscal/assessment-results)
# ---------------------------------------------------------------------------


class TestComplianceBridgeEndpoints:
    @pytest.mark.asyncio
    async def test_verify_endpoint_200_and_409_and_503(
        self, server, store, signer, provider, monkeypatch
    ):
        from unittest.mock import MagicMock, patch

        from fastapi.testclient import TestClient

        from src.compliance_bridge.main import app

        [outcome] = await _custody_batches(server, store, signer, [2])
        verifier = _verifier(store, provider)

        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(app) as client:
                app.state.evidence_verifier = verifier
                resp = client.get("/v1/evidence/verify?require_citable=true")
                assert resp.status_code == 200
                body = resp.json()
                assert body["ok"] is True
                assert body["citable"] is True
                assert len(body["verified"]) == 1

                # Tamper with data object -> 409
                store._entries[outcome.data_key] = b'{"forged": 1}\n'
                resp_bad = client.get("/v1/evidence/verify")
                assert resp_bad.status_code == 409
                assert resp_bad.json()["ok"] is False

                # Empty archive with require_citable=true -> 409
                empty_verifier = _verifier(NullColdStore(), provider)
                app.state.evidence_verifier = empty_verifier
                resp_empty = client.get("/v1/evidence/verify?require_citable=true")
                assert resp_empty.status_code == 409
                assert resp_empty.json()["ok"] is True
                assert resp_empty.json()["citable"] is False
                assert (
                    "no signed, verified evidence"
                    in resp_empty.json()["citation_error"]
                )

                # ColdStoreError -> 503
                app.state.evidence_verifier = _verifier(_BrokenStore(), provider)
                resp_503 = client.get("/v1/evidence/verify")
                assert resp_503.status_code == 503
                assert (
                    resp_503.json()["detail"]["error"] == "EVIDENCE_STORE_UNAVAILABLE"
                )

    @pytest.mark.asyncio
    async def test_oscal_endpoint_verify_custody_passes_and_fails_closed(
        self, server, store, signer, provider, monkeypatch
    ):
        from unittest.mock import AsyncMock, MagicMock, patch

        from fastapi.testclient import TestClient

        from src.compliance_bridge.main import app

        await _custody_batches(server, store, signer, [2])
        verifier = _verifier(store, provider)

        fake_metric = MagicMock()
        fake_metric.model_dump.return_value = {
            "safety_rate": 1.0,
            "evidence_age_seconds": 5,
        }

        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.get_compliance_metrics",
                new=AsyncMock(return_value=fake_metric),
            ),
        ):
            with TestClient(app) as client:
                # 1. Verified chain passes and attaches custody provenance
                app.state.evidence_verifier = verifier
                resp = client.get(
                    "/v1/oscal/assessment-results?verify_custody=true&audit_id=test-ok"
                )
                assert resp.status_code == 200
                result_entry = resp.json()["document"]["assessment-results"]["results"][
                    0
                ]
                props = {p["name"]: p["value"] for p in result_entry["props"]}
                assert props["evidence-custody-verified-batches"] == "1"
                assert props["evidence-custody-key-id"] == KID
                assert result_entry["links"][0]["rel"] == "evidence-attestation"

                # 2. Empty archive fails closed with 409
                app.state.evidence_verifier = _verifier(NullColdStore(), provider)
                resp_empty = client.get(
                    "/v1/oscal/assessment-results?verify_custody=true"
                )
                assert resp_empty.status_code == 409
                assert (
                    resp_empty.json()["detail"]["error"]
                    == "EVIDENCE_CUSTODY_UNVERIFIED"
                )

                # 3. OSCAL_REQUIRE_VERIFIED_CUSTODY=true enforces gate even without query param
                monkeypatch.setenv("OSCAL_REQUIRE_VERIFIED_CUSTODY", "true")
                resp_env = client.get("/v1/oscal/assessment-results")
                assert resp_env.status_code == 409
                assert (
                    resp_env.json()["detail"]["error"] == "EVIDENCE_CUSTODY_UNVERIFIED"
                )

                # 4. ColdStoreError fails closed with 503
                app.state.evidence_verifier = _verifier(_BrokenStore(), provider)
                resp_503 = client.get(
                    "/v1/oscal/assessment-results?verify_custody=true"
                )
                assert resp_503.status_code == 503
                assert (
                    resp_503.json()["detail"]["error"] == "EVIDENCE_STORE_UNAVAILABLE"
                )

    def test_lifespan_enforcing_fails_closed_when_verifier_unconfigured(
        self, monkeypatch
    ):
        from unittest.mock import AsyncMock, MagicMock, patch

        from fastapi.testclient import TestClient

        from src.compliance_bridge.main import app

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
        monkeypatch.setattr(
            "src.gateway.governance.evidence.factory.get_cold_store",
            _NonNullStore,
        )
        custodian = MagicMock()
        custodian.run_forever = AsyncMock(return_value=None)
        custodian.aclose = AsyncMock(return_value=None)
        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.evidence_custodian.EvidenceCustodian.from_env",
                return_value=custodian,
            ),
            pytest.raises(RuntimeError, match="trust anchor"),
        ):
            with TestClient(app):
                pass
