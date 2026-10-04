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

"""Tests for src/compliance_bridge/evidence_custodian.py.

The custodian is the only path by which gateway evidence reaches WORM storage,
so most tests here observe a fail-closed path: a failed write, a failed
signature or a tampered record must leave the cursor where it was.

Hermetic: records are produced by the real ``EvidenceStreamSink`` into
fakeredis (with Lua); the cold store and signer are in-memory fakes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import fakeredis
import pytest

from src.compliance_bridge.evidence_custodian import (
    ATTESTATION_SCHEMA,
    CustodyStatus,
    EvidenceCustodian,
    EvidenceCustodyConfigError,
    EvidenceCustodyIntegrityError,
    NonEvidentiaryAttestationError,
    assert_citable,
)
from src.gateway.governance.evidence.cold_store import ColdStoreError, ColdStoreReceipt
from src.gateway.governance.evidence.stream import EvidenceStreamSink

pytestmark = [pytest.mark.unit, pytest.mark.local]

STREAM_KEY = "cage:evidence:custody-test"
CURSOR_KEY = f"{STREAM_KEY}:custody"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeColdStore:
    """In-memory WORM store: ``put_if_absent`` never overwrites."""

    backend_id = "fake"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_on: set[str] = set()  # key suffixes that raise
        self.put_calls: list[str] = []
        self.metadata: dict[str, dict] = {}

    async def put_if_absent(self, key, content, metadata=None):
        self.put_calls.append(key)
        if any(key.endswith(suffix) for suffix in self.fail_on):
            raise ColdStoreError(f"injected failure for {key}", backend_id="fake")
        created = key not in self.objects
        if created:
            self.objects[key] = content
            self.metadata[key] = dict(metadata or {})
        receipt = ColdStoreReceipt(
            uri=f"fake://{key}",
            key=key,
            content_sha256=hashlib.sha256(content).hexdigest(),
            backend_id="fake",
            written_at=datetime.now(timezone.utc),
        )
        return receipt, created

    async def get(self, key):
        if key not in self.objects:
            raise ColdStoreError(f"missing {key}", backend_id="fake")
        return self.objects[key]

    def data_keys(self) -> list[str]:
        return sorted(k for k in self.objects if k.endswith(".ndjson"))


class FakeSigner:
    def __init__(self, *, active: bool = True, fail: bool = False) -> None:
        self._active = active
        self.fail = fail
        self.signed: list[dict] = []

    @property
    def is_kms_active(self) -> bool:
        return self._active

    @property
    def key_id(self) -> str:
        return "projects/p/locations/l/keyRings/r/cryptoKeys/compliance-evidence/cryptoKeyVersions/1"

    @property
    def signing_algorithm(self) -> str:
        return "EC_SIGN_P256_SHA256"

    def sign(self, plan: dict) -> str:
        if self.fail:
            raise RuntimeError("KMS unavailable")
        self.signed.append(plan)
        return hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def server():
    return fakeredis.FakeServer()


def _redis(server):
    return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)


async def _produce(server, n: int, *, max_len: int = 10_000) -> EvidenceStreamSink:
    sink = EvidenceStreamSink(stream_key=STREAM_KEY, max_len=max_len)
    sink._redis = _redis(server)
    for i in range(n):
        await sink.ingest({"type": "GOVERNANCE_DECISION", "controlId": "AU-9", "n": i})
    return sink


def _custodian(server, store, signer=None, *, require_signature=True, batch_size=100):
    return EvidenceCustodian(
        _redis(server),
        store,
        signer if signer is not None else FakeSigner(),
        stream_key=STREAM_KEY,
        batch_size=batch_size,
        require_signature=require_signature,
        interval_s=0.01,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestCustodyHappyPath:
    @pytest.mark.asyncio
    async def test_idle_when_stream_empty(self, server):
        outcome = await _custodian(server, FakeColdStore()).flush_once()
        assert outcome.status is CustodyStatus.IDLE

    @pytest.mark.asyncio
    async def test_writes_batch_and_signed_attestation(self, server):
        sink = await _produce(server, 3)
        store, signer = FakeColdStore(), FakeSigner()
        outcome = await _custodian(server, store, signer).flush_once()

        assert outcome.status is CustodyStatus.WRITTEN
        assert (outcome.first_sequence, outcome.last_sequence) == (0, 2)
        assert outcome.data_key.endswith(
            f"/{sink.chain_id}/000000000000-000000000002.ndjson"
        )

        lines = store.objects[outcome.data_key].decode().splitlines()
        assert [json.loads(line)["sequence"] for line in lines] == ["0", "1", "2"]

        att = json.loads(store.objects[outcome.attestation_key])
        assert att["schema"] == ATTESTATION_SCHEMA
        assert att["chain_id"] == sink.chain_id
        assert att["entries_count"] == 3
        assert att["first_prev_hash"] == ""
        assert att["last_record_hash"] == sink.chain_root
        assert (
            att["content_sha256"]
            == hashlib.sha256(store.objects[outcome.data_key]).hexdigest()
        )
        assert att["gap"] == {"detected": False}
        assert att["signature"]["key_id"] == signer.key_id
        assert att["signature"]["algorithm"] == "EC_SIGN_P256_SHA256"
        # The signature covers the attestation body, not per-record payloads.
        assert signer.signed == [{k: v for k, v in att.items() if k != "signature"}]

    @pytest.mark.asyncio
    async def test_cursor_advances_and_next_batch_continues(self, server):
        sink = await _produce(server, 2)
        store = FakeColdStore()
        custodian = _custodian(server, store)
        await custodian.flush_once()

        for i in range(2):
            await sink.ingest({"type": "X", "n": 10 + i})
        second = await custodian.flush_once()

        assert (second.first_sequence, second.last_sequence) == (2, 3)
        assert not second.gap
        cursor = await _redis(server).hgetall(CURSOR_KEY)
        assert cursor["last_sequence"] == "3"
        assert cursor["last_record_hash"] == sink.chain_root
        assert "pending_end_id" not in cursor

    @pytest.mark.asyncio
    async def test_batch_size_bounds_each_cycle(self, server):
        await _produce(server, 5)
        store = FakeColdStore()
        custodian = _custodian(server, store, batch_size=2)
        seqs = []
        while (o := await custodian.flush_once()).status is CustodyStatus.WRITTEN:
            seqs.append((o.first_sequence, o.last_sequence))
        assert seqs == [(0, 1), (2, 3), (4, 4)]


# ---------------------------------------------------------------------------
# Fail-closed paths
# ---------------------------------------------------------------------------


class TestCustodyFailClosed:
    @pytest.mark.asyncio
    async def test_cold_store_failure_does_not_advance_and_retry_reuses_key(
        self, server
    ):
        await _produce(server, 3)
        store = FakeColdStore()
        store.fail_on = {".attestation.json"}  # data lands, attestation fails
        custodian = _custodian(server, store)

        with pytest.raises(ColdStoreError):
            await custodian.flush_once()

        cursor = await _redis(server).hgetall(CURSOR_KEY)
        assert "last_id" not in cursor
        assert cursor["pending_end_id"]
        (data_key,) = store.data_keys()
        first_bytes = store.objects[data_key]

        store.fail_on = set()
        outcome = await custodian.flush_once()
        assert outcome.data_key == data_key
        assert store.objects[data_key] == first_bytes
        assert outcome.attestation_key in store.objects
        assert store.data_keys() == [data_key]

    @pytest.mark.asyncio
    async def test_retry_is_bounded_to_pending_range(self, server):
        """New records arriving between failure and retry go in the next batch."""
        sink = await _produce(server, 2)
        store = FakeColdStore()
        store.fail_on = {".ndjson"}
        custodian = _custodian(server, store)
        with pytest.raises(ColdStoreError):
            await custodian.flush_once()

        await sink.ingest({"type": "late"})
        store.fail_on = set()
        retry = await custodian.flush_once()
        nxt = await custodian.flush_once()
        assert (retry.first_sequence, retry.last_sequence) == (0, 1)
        assert (nxt.first_sequence, nxt.last_sequence) == (2, 2)

    @pytest.mark.asyncio
    async def test_signing_failure_writes_nothing_when_enforcing(self, server):
        await _produce(server, 2)
        store = FakeColdStore()
        custodian = _custodian(server, store, FakeSigner(fail=True))

        with pytest.raises(RuntimeError, match="signing failed"):
            await custodian.flush_once()

        assert store.objects == {}
        assert await _redis(server).hgetall(CURSOR_KEY) == {}

    @pytest.mark.asyncio
    async def test_signing_failure_writes_unsigned_when_permissive(self, server):
        await _produce(server, 1)
        store = FakeColdStore()
        custodian = _custodian(
            server, store, FakeSigner(fail=True), require_signature=False
        )
        outcome = await custodian.flush_once()
        assert json.loads(store.objects[outcome.attestation_key])["signature"] is None

    def test_enforcing_requires_active_signer(self, server):
        with pytest.raises(EvidenceCustodyConfigError):
            _custodian(server, FakeColdStore(), FakeSigner(active=False))

    @pytest.mark.asyncio
    async def test_tampered_payload_halts_custody(self, server):
        await _produce(server, 3)
        redis = _redis(server)
        entries = await redis.xrange(STREAM_KEY)
        # Rewrite record 1 in place with a different payload (same hash fields).
        await redis.delete(STREAM_KEY)
        for i, (sid, fields) in enumerate(entries):
            if i == 1:
                fields = dict(fields, payload_json='{"n":999}')
            await redis.xadd(STREAM_KEY, fields, id=sid)

        store = FakeColdStore()
        custodian = _custodian(server, store)
        with pytest.raises(EvidenceCustodyIntegrityError):
            await custodian.flush_once()
        assert store.objects == {}
        assert await redis.hgetall(CURSOR_KEY) == {}

        # It stays stuck: a second cycle refuses again.
        with pytest.raises(EvidenceCustodyIntegrityError):
            await custodian.flush_once()

    @pytest.mark.asyncio
    async def test_broken_link_halts_custody(self, server):
        await _produce(server, 3)
        redis = _redis(server)
        entries = await redis.xrange(STREAM_KEY)
        await redis.xdel(STREAM_KEY, entries[1][0])  # hole inside the batch

        store = FakeColdStore()
        with pytest.raises(EvidenceCustodyIntegrityError):
            await _custodian(server, store).flush_once()
        assert store.objects == {}

    @pytest.mark.asyncio
    async def test_relinked_head_after_cursor_is_refused(self, server):
        """Same sequence as expected but a different prev_hash is tampering."""
        sink = await _produce(server, 1)
        custodian = _custodian(server, FakeColdStore())
        await custodian.flush_once()
        await sink.ingest({"type": "next"})
        await _redis(server).hset(CURSOR_KEY, mapping={"last_record_hash": "0" * 64})

        with pytest.raises(EvidenceCustodyIntegrityError, match="prev_hash"):
            await custodian.flush_once()


# ---------------------------------------------------------------------------
# Gaps, restarts, rotation
# ---------------------------------------------------------------------------


class TestCustodyContinuity:
    @pytest.mark.asyncio
    async def test_maxlen_trim_is_recorded_as_gap(self, server):
        sink = await _produce(server, 2, max_len=3)
        store = FakeColdStore()
        custodian = _custodian(server, store)
        await custodian.flush_once()  # custodies 0..1

        for i in range(5):  # stream keeps only the newest 3: seq 4,5,6
            await sink.ingest({"type": "burst", "n": i})
        outcome = await custodian.flush_once()

        assert outcome.gap is True
        assert outcome.first_sequence == 4
        att = json.loads(store.objects[outcome.attestation_key])
        assert att["gap"]["detected"] is True
        assert att["gap"]["expected_sequence"] == 2

    @pytest.mark.asyncio
    async def test_first_run_on_trimmed_stream_is_gap(self, server):
        await _produce(server, 5, max_len=2)
        outcome = await _custodian(server, FakeColdStore()).flush_once()
        assert outcome.gap is True
        assert outcome.first_sequence == 3

    @pytest.mark.asyncio
    async def test_restart_produces_no_duplicates(self, server):
        sink = await _produce(server, 3)
        store = FakeColdStore()
        await _custodian(server, store).flush_once()

        await sink.ingest({"type": "after-restart"})
        restarted = _custodian(server, store)  # fresh process, same cursor
        outcome = await restarted.flush_once()

        assert (outcome.first_sequence, outcome.last_sequence) == (3, 3)
        records = [
            json.loads(line)["sequence"]
            for key in store.data_keys()
            for line in store.objects[key].decode().splitlines()
        ]
        assert records == ["0", "1", "2", "3"]

    @pytest.mark.asyncio
    async def test_chain_rotation_at_genesis_is_accepted(self, server):
        old = await _produce(server, 2)
        store = FakeColdStore()
        custodian = _custodian(server, store)
        await custodian.flush_once()

        await _redis(server).delete(STREAM_KEY)  # stream lost; new chain starts
        new = EvidenceStreamSink(stream_key=STREAM_KEY)
        new._redis = _redis(server)
        await new.ingest({"type": "fresh"})
        assert new.chain_id != old.chain_id

        outcome = await custodian.flush_once()
        assert outcome.status is CustodyStatus.WRITTEN
        assert outcome.gap is False
        assert f"/{new.chain_id}/000000000000-000000000000.ndjson" in outcome.data_key


# ---------------------------------------------------------------------------
# from_env preconditions
# ---------------------------------------------------------------------------


class TestReadBackVerification:
    """A pre-existing WORM object must be the same evidence (GCS digest quirk)."""

    @pytest.mark.asyncio
    async def test_conflicting_existing_data_object_halts_custody(self, server):
        await _produce(server, 2)
        store = FakeColdStore()
        probe = _custodian(server, FakeColdStore())
        expected_key = (await probe.flush_once()).data_key
        store.objects[expected_key] = b"forged batch\n"  # squatted key
        await _redis(server).delete(CURSOR_KEY)  # the probe advanced it

        custodian = _custodian(server, store)
        with pytest.raises(EvidenceCustodyIntegrityError, match="different content"):
            await custodian.flush_once()
        cursor = await _redis(server).hgetall(CURSOR_KEY)
        assert "last_id" not in cursor  # not advanced past the conflict

    @pytest.mark.asyncio
    async def test_identical_existing_objects_are_accepted(self, server):
        await _produce(server, 2)
        store = FakeColdStore()
        store.fail_on = {".attestation.json"}
        custodian = _custodian(server, store)
        with pytest.raises(ColdStoreError):
            await custodian.flush_once()
        store.fail_on = set()
        outcome = await custodian.flush_once()  # data object re-put: same bytes
        assert outcome.status is CustodyStatus.WRITTEN

    @pytest.mark.asyncio
    async def test_resigned_identical_attestation_is_accepted(self, server):
        """A randomized re-signature over the same body is the same evidence."""
        await _produce(server, 2)
        store = FakeColdStore()
        first = await _custodian(server, store).flush_once()
        stored = json.loads(store.objects[first.attestation_key])
        stored["signature"]["value"] = "a-different-randomized-signature"
        store.objects[first.attestation_key] = json.dumps(stored).encode()
        await _redis(server).delete(CURSOR_KEY)  # replay the same batch

        outcome = await _custodian(server, store).flush_once()
        assert outcome.attestation_key == first.attestation_key

    @pytest.mark.asyncio
    async def test_conflicting_attestation_body_halts_custody(self, server):
        await _produce(server, 2)
        store = FakeColdStore()
        first = await _custodian(server, store).flush_once()
        stored = json.loads(store.objects[first.attestation_key])
        stored["entries_count"] = 999
        store.objects[first.attestation_key] = json.dumps(stored).encode()
        await _redis(server).delete(CURSOR_KEY)  # replay the same batch

        with pytest.raises(EvidenceCustodyIntegrityError):
            await _custodian(server, store).flush_once()

    @pytest.mark.asyncio
    async def test_objects_carry_data_classification(self, server):
        await _produce(server, 1)
        store = FakeColdStore()
        outcome = await _custodian(server, store).flush_once()
        for key in (outcome.data_key, outcome.attestation_key):
            assert store.metadata[key]["x-data-classification"] == (
                "internal-pii-sanitized"
            )


class TestNullColdStorePosture:
    class _NullStore(FakeColdStore):
        backend_id = "null"

    @pytest.mark.parametrize("env", ["production", "staging"])
    def test_constructor_refuses_null_store_when_enforcing(
        self, server, monkeypatch, env
    ):
        monkeypatch.setenv("CAGE_ENV", env)
        with pytest.raises(EvidenceCustodyConfigError, match="null"):
            _custodian(server, self._NullStore())

    def test_constructor_allows_null_store_when_permissive(self, server, monkeypatch):
        monkeypatch.setenv("CAGE_ENV", "dev")
        assert _custodian(server, self._NullStore()) is not None

    def test_enforcing_rejects_unset_cold_store(self, monkeypatch):
        """EVIDENCE_COLD_STORE unset defaults to null and is refused."""
        monkeypatch.setenv("CAGE_ENV", "production")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379")
        monkeypatch.delenv("EVIDENCE_COLD_STORE", raising=False)
        with pytest.raises(EvidenceCustodyConfigError, match="null"):
            EvidenceCustodian.from_env()


class TestFromEnv:
    def test_enforcing_rejects_null_cold_store(self, monkeypatch):
        monkeypatch.setenv("CAGE_ENV", "production")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "null")
        with pytest.raises(EvidenceCustodyConfigError, match="null"):
            EvidenceCustodian.from_env()

    def test_missing_redis_url_is_config_error(self, monkeypatch):
        monkeypatch.setenv("CAGE_ENV", "test")
        monkeypatch.delenv("EVIDENCE_STREAM_REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_URL", raising=False)
        with pytest.raises(EvidenceCustodyConfigError, match="REDIS_URL"):
            EvidenceCustodian.from_env()

    def test_permissive_builds_with_null_store_and_hmac_signer(self, monkeypatch):
        monkeypatch.setenv("CAGE_ENV", "test")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "null")
        monkeypatch.delenv("EVIDENCE_KMS_KEY", raising=False)
        monkeypatch.delenv("KMS_PROVIDER", raising=False)
        custodian = EvidenceCustodian.from_env()
        assert custodian._require_signature is False


# ---------------------------------------------------------------------------
# Unsigned attestations are never evidence
# ---------------------------------------------------------------------------


class TestNonEvidentiaryAttestations:
    @pytest.mark.asyncio
    async def test_signed_attestation_is_evidentiary_and_citable(self, server):
        await _produce(server, 2)
        store, signer = FakeColdStore(), FakeSigner()
        outcome = await _custodian(server, store, signer).flush_once()

        assert outcome.evidentiary is True
        assert outcome.attestation_key.endswith(".attestation.json")
        att = json.loads(store.objects[outcome.attestation_key])
        assert (att["signature_status"], att["evidentiary"]) == ("SIGNED", True)
        # The evidentiary claim is inside the signed body.
        assert signer.signed[0]["evidentiary"] is True
        assert store.metadata[outcome.attestation_key]["evidentiary"] == "true"
        assert store.metadata[outcome.data_key]["evidentiary"] == "true"
        assert_citable(att)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "signer",
        [None, FakeSigner(active=False), FakeSigner(fail=True)],
        ids=["no-signer", "inactive-signer", "signing-failure"],
    )
    async def test_unsigned_attestation_is_marked_and_segregated(self, server, signer):
        await _produce(server, 2)
        store = FakeColdStore()
        custodian = EvidenceCustodian(
            _redis(server),
            store,
            signer,
            stream_key=STREAM_KEY,
            require_signature=False,
        )
        outcome = await custodian.flush_once()

        assert outcome.status is CustodyStatus.WRITTEN
        assert outcome.evidentiary is False
        assert outcome.attestation_key.endswith(".attestation.unsigned.json")
        assert not any(k.endswith(".attestation.json") for k in store.objects)
        att = json.loads(store.objects[outcome.attestation_key])
        assert att["signature"] is None
        assert (att["signature_status"], att["evidentiary"]) == ("UNSIGNED", False)
        assert store.metadata[outcome.attestation_key]["evidentiary"] == "false"
        assert store.metadata[outcome.data_key]["evidentiary"] == "false"
        with pytest.raises(NonEvidentiaryAttestationError, match="UNSIGNED"):
            assert_citable(att)


class TestAssertCitable:
    def _signed(self) -> dict:
        return {
            "schema": ATTESTATION_SCHEMA,
            "signature_status": "SIGNED",
            "evidentiary": True,
            "signature": {
                "algorithm": "EC_SIGN_P256_SHA256",
                "key_id": "k/1",
                "value": "sig",
            },
        }

    def test_accepts_signed(self):
        assert_citable(self._signed())

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda a: a.update(schema="cage-evidence-batch/0"),
            lambda a: a.update(signature_status="UNSIGNED"),
            lambda a: a.pop("signature_status"),
            lambda a: a.update(evidentiary=False),
            lambda a: a.update(evidentiary="true"),
            lambda a: a.update(signature=None),
            lambda a: a["signature"].update(value=""),
            lambda a: a["signature"].pop("key_id"),
        ],
        ids=[
            "wrong-schema",
            "unsigned-status",
            "missing-status",
            "non-evidentiary",
            "string-flag",
            "null-signature",
            "empty-value",
            "missing-kid",
        ],
    )
    def test_rejects_non_evidentiary(self, mutate):
        att = self._signed()
        mutate(att)
        with pytest.raises(NonEvidentiaryAttestationError):
            assert_citable(att)
