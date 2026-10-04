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

"""Kernel state-commitment service: sanitize → JCS → SHA-256 → evidence chain.

Hermetic: the real ``EvidenceStreamSink`` over Lua-capable fakeredis, the real
``PIISanitizer`` and the real JCS canonicalizer. No network, no cold store.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import fakeredis
import pytest

from src.gateway.governance.evidence.state_commitment import (
    MAX_PREIMAGE_BYTES,
    StateCommitmentService,
    build_state_commitment_service,
    canonicalize_state,
    linkage_digest,
    verify_state_commitment,
)
from src.gateway.governance.evidence.stream import (
    ConfigurationError,
    EvidenceStreamSink,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.state_commitment import (
    STATE_COMMITMENT_METHOD,
    InvalidStateSnapshotError,
    StateCommitmentError,
    StateCommitmentLinkage,
    StateCommitmentReceipt,
    StateCommitter,
    StateSnapshotTooLargeError,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

STREAM_KEY = "cage:evidence:test-state-commitment"
CALLER = "advisor.cage.serviceaccount.identity.linkerd.cluster.local"

#: PII markers covered by the sanitizer, keyed by where they appear.
PII_MARKERS = {
    "email": "jane.doe@example.com",
    "phone": "+1 (415) 555-0134",
    "ssn": "123-45-6789",
    "card": "4111 1111 1111 1111",
    "iban": "DE89370400440532013000",
    "bearer": "Bearer abcdefghijklmnop",
}


def _linkage(**overrides: str) -> StateCommitmentLinkage:
    fields = {
        "namespace": "provider_02",
        "bundle_id": "bundle-1",
        "step_id": "step-1",
        "thread_id": "thread-1",
        "label": "safety_check",
    }
    fields.update(overrides)
    return StateCommitmentLinkage(**fields)


def _pii_snapshot() -> dict[str, Any]:
    return {
        "user_id": "u-48151623",
        "loop_count": 2,
        "messages": [
            {"type": "human", "content": f"email me at {PII_MARKERS['email']}"},
            {"type": "human", "content": f"or call {PII_MARKERS['phone']}"},
        ],
        "profile": {"ssn": PII_MARKERS["ssn"], "card": PII_MARKERS["card"]},
        "table": [["iban", PII_MARKERS["iban"]]],  # nested list
        "auth": PII_MARKERS["bearer"],
        "token": "opaque-session-value",  # key-denylisted
    }


def _sink(redis: Any) -> EvidenceStreamSink:
    sink = EvidenceStreamSink(
        redis_url="redis://localhost:6379", redis_db=1, stream_key=STREAM_KEY
    )
    sink._redis = redis
    sink._running = True
    return sink


def _fake_redis() -> Any:
    return fakeredis.FakeAsyncRedis(
        server=fakeredis.FakeServer(), decode_responses=True
    )


class TestCanonicalizeState:
    def test_preimage_is_pii_free_and_hash_binds_it(self) -> None:
        state, preimage, state_hash = canonicalize_state(_pii_snapshot())

        text = preimage.decode("utf-8")
        for marker in PII_MARKERS.values():
            assert marker not in text, marker
        assert "opaque-session-value" not in text
        assert state_hash == hashlib.sha256(preimage).hexdigest()
        assert preimage == jcs_canonicalize_plan(state)

    def test_documented_gap_opaque_ids_and_names_are_retained(self) -> None:
        """The regex sanitizer does not pseudonymize opaque ids or free-text names.

        ``user_id`` is retained deliberately (pseudonymous subject linkage for
        attribution); names in free text are a known gap. See
        docs/architecture/EVIDENCE_CHAIN.md "State commitments".
        """
        snapshot = {"user_id": "u-48151623", "note": "Client Jane Doe called"}
        _, preimage, _ = canonicalize_state(snapshot)
        assert b"u-48151623" in preimage
        assert b"Jane Doe" in preimage

    def test_tuples_and_decimals_normalize_like_the_evidence_chain(self) -> None:
        from decimal import Decimal

        state, _, _ = canonicalize_state({"t": (1, 2), "amount": Decimal("1.50")})
        assert state == {"t": [1, 2], "amount": "1.50"}

    @pytest.mark.parametrize(
        "snapshot",
        [{1: "non-string key"}, {"nested": {2: "x"}}, {"x": float("nan")}],
    )
    def test_uncanonicalizable_snapshots_are_refused(self, snapshot: Any) -> None:
        with pytest.raises(InvalidStateSnapshotError):
            canonicalize_state(snapshot)

    def test_non_mapping_is_refused(self) -> None:
        with pytest.raises(InvalidStateSnapshotError):
            canonicalize_state(["not", "an", "object"])  # type: ignore[arg-type]

    def test_twelve_digit_groups_are_not_visa(self) -> None:
        """uuid4 segments like ``4365-4282-8412`` must not be redacted as cards."""
        uid = "426550a5-4365-4282-8412-21a96f4af749"
        state, _, _ = canonicalize_state({"thread": uid})
        assert state == {"thread": uid}

    def test_oversized_preimage_is_refused(self) -> None:
        with pytest.raises(StateSnapshotTooLargeError):
            canonicalize_state({"blob": "x" * (MAX_PREIMAGE_BYTES + 1)})


class TestStateCommitmentService:
    @pytest.mark.asyncio
    async def test_commit_round_trips_through_the_real_evidence_sink(self) -> None:
        redis = _fake_redis()
        service = StateCommitmentService(_sink(redis))
        assert isinstance(service, object)

        receipt = await service.commit_state(
            _pii_snapshot(), linkage=_linkage(), caller_identity=CALLER
        )

        assert dict(receipt.method) == dict(STATE_COMMITMENT_METHOD)
        entries = await redis.xrange(STREAM_KEY)
        assert len(entries) == 1
        stream_id, fields = entries[0]
        assert stream_id == receipt.evidence_id
        assert fields["record_hash"] == receipt.evidence_record_hash
        payload = json.loads(fields["payload_json"])
        assert payload["type"] == "STATE_COMMITMENT"
        assert payload["stateHash"] == receipt.state_hash
        assert payload["callerIdentity"] == CALLER
        assert payload["linkage"]["stepId"] == "step-1"
        for key, value in STATE_COMMITMENT_METHOD.items():
            assert payload[key] == value
        for marker in PII_MARKERS.values():
            assert marker not in fields["payload_json"]
        # The stored state is exactly the hashed preimage.
        assert (
            hashlib.sha256(jcs_canonicalize_plan(payload["state"])).hexdigest()
            == receipt.state_hash
        )
        assert verify_state_commitment(receipt.state_hash, fields["payload_json"])

    @pytest.mark.asyncio
    async def test_verification_fails_on_tampered_state(self) -> None:
        redis = _fake_redis()
        receipt = await StateCommitmentService(_sink(redis)).commit_state(
            {"loop_count": 1}, linkage=_linkage()
        )
        ((_sid, fields),) = await redis.xrange(STREAM_KEY)
        payload = json.loads(fields["payload_json"])
        payload["state"]["loop_count"] = 2
        assert not verify_state_commitment(receipt.state_hash, payload)
        assert not verify_state_commitment("0" * 64, fields["payload_json"])
        assert not verify_state_commitment(receipt.state_hash, "not json")

    @pytest.mark.asyncio
    async def test_chain_outage_fails_closed(self) -> None:
        sink = _sink(None)  # Redis never connected
        with pytest.raises(StateCommitmentError) as excinfo:
            await StateCommitmentService(sink).commit_state(
                {"a": 1}, linkage=_linkage()
            )
        assert not isinstance(excinfo.value, InvalidStateSnapshotError)

    @pytest.mark.asyncio
    async def test_missing_sink_fails_closed(self) -> None:
        with pytest.raises(StateCommitmentError):
            await StateCommitmentService(None).commit_state(
                {"a": 1}, linkage=_linkage()
            )

    @pytest.mark.asyncio
    async def test_uuid_that_trips_card_regex_still_binds_via_linkage_digest(
        self,
    ) -> None:
        """uuid4 values whose 8-4-4 groups are all digits match the card regex.

        The informational ``linkage`` object is sanitized like any field, but
        ``linkageDigest`` survives and binds the record to the exact step.
        """
        colliding = "44845531-3164-4232-a812-73c6e3dfa067"
        linkage = _linkage(step_id=colliding)
        redis = _fake_redis()
        receipt = await StateCommitmentService(_sink(redis)).commit_state(
            {"loop_count": 1}, linkage=linkage
        )
        ((_sid, fields),) = await redis.xrange(STREAM_KEY)
        payload = json.loads(fields["payload_json"])
        assert payload["linkage"]["stepId"] != colliding  # sanitized in transit
        assert payload["linkageDigest"] == linkage_digest(linkage)
        assert verify_state_commitment(receipt.state_hash, payload, linkage=linkage)
        assert not verify_state_commitment(
            receipt.state_hash, payload, linkage=_linkage(step_id="other")
        )


class TestLinkageAndReceipt:
    @pytest.mark.parametrize("bad", ["", "a/b", "x" * 129, "white space"])
    def test_linkage_ids_are_constrained(self, bad: str) -> None:
        with pytest.raises(InvalidStateSnapshotError):
            _linkage(step_id=bad)

    def test_linkage_round_trips(self) -> None:
        linkage = _linkage()
        assert StateCommitmentLinkage.from_dict(linkage.to_dict()) == linkage

    def test_linkage_missing_field_is_refused(self) -> None:
        with pytest.raises(InvalidStateSnapshotError):
            StateCommitmentLinkage.from_dict({"namespace": "x"})

    def test_receipt_rejects_wrong_method(self) -> None:
        wire = {
            "stateHash": "a" * 64,
            "evidenceId": "1-0",
            "evidenceRecordHash": "b" * 64,
            "sequence": 0,
            "method": {**STATE_COMMITMENT_METHOD, "stateHashScope": "agentstate/v0"},
        }
        with pytest.raises(StateCommitmentError):
            StateCommitmentReceipt.from_dict(wire)

    def test_receipt_rejects_malformed_digest(self) -> None:
        wire = {
            "stateHash": "A" * 64,
            "evidenceId": "1-0",
            "evidenceRecordHash": "b" * 64,
            "sequence": 0,
            "method": dict(STATE_COMMITMENT_METHOD),
        }
        with pytest.raises(StateCommitmentError):
            StateCommitmentReceipt.from_dict(wire)

    def test_method_constants(self) -> None:
        assert dict(STATE_COMMITMENT_METHOD) == {
            "stateHashAlg": "sha256",
            "stateHashCanon": "RFC8785-JCS",
            "stateHashScope": "agentstate-pii-sanitized/v1",
        }


class TestPostureGuard:
    @pytest.mark.parametrize("env", ["production", "staging"])
    def test_enforcing_posture_refuses_missing_sink(
        self, monkeypatch: pytest.MonkeyPatch, env: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", env)
        with pytest.raises(ConfigurationError):
            build_state_commitment_service(None)

    def test_enforcing_posture_refuses_disconnected_sink(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "production")
        sink = _sink(None)
        sink._running = False
        with pytest.raises(ConfigurationError):
            build_state_commitment_service(sink)

    def test_enforcing_posture_accepts_running_sink(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "production")
        service = build_state_commitment_service(_sink(_fake_redis()))
        assert isinstance(service, StateCommitmentService)

    @pytest.mark.parametrize("env", ["dev", "test", "ci"])
    def test_permissive_posture_allows_missing_sink(
        self, monkeypatch: pytest.MonkeyPatch, env: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", env)
        assert isinstance(build_state_commitment_service(None), StateCommitmentService)


def test_gateway_client_satisfies_the_committer_protocol() -> None:
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )

    assert isinstance(GatewayClient(), StateCommitter)
