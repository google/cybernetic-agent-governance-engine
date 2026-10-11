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

"""Hermetic unit tests for src/integrations/actuator_02/ (OpenShell Supervisor)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.routing_seal import SEAL_CANON, compute_action_hash
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.credential_broker import CredentialAccessDenied
from src.integrations.actuator_02.adapter import Actuator02Adapter
from src.integrations.actuator_02.constants import (
    RECEIPT_SIGNATURE_DOMAIN_TAG,
    SEAL_PROFILE,
)
from src.integrations.actuator_02.ocsf_ingestor import OcsfEvidenceIngestor
from src.integrations.actuator_02.policy_advisor_bridge import (
    PolicyAdvisorBridge,
    PolicyAdvisorProposal,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _StubSigner:
    @property
    def is_kms_active(self) -> bool:
        return False  # software stub, never a KMS key

    def sign_raw(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest() * 2


class _StubKeyResolver:
    def __init__(self, keys: dict[str, Any]) -> None:
        self._keys = keys

    async def get_key(self, kid: str) -> Any | None:
        return self._keys.get(kid)


class _StubCredentialBroker:
    def __init__(self, fail: bool = False) -> None:
        self._fail = fail
        self.calls: list[tuple[str, str, str | None]] = []

    async def fetch_credential(
        self, agent_svid: str, tool_name: str, scope: str | None = None
    ) -> dict[str, str]:
        self.calls.append((agent_svid, tool_name, scope))
        if self._fail:
            raise CredentialAccessDenied("SVID not authorized for tool")
        return {"X-Brokered-Token": "ephemeral-scoped-token"}


# Shape-valid compact JWS; tests that need a verifiable seal mint one below.
_STUB_SEAL = "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4ifQ.c2lnbmF0dXJl"


def _make_clearance(**overrides: Any) -> ExecutionClearance:
    defaults: dict[str, Any] = {
        "thread_id": "thread-02",
        "decision": "ALLOW",
        "decision_path": "DIRECT",
        "action": "write_db",
        "target": "db-primary",
        "operator_urn": "spiffe://cage.local/ns/default/sa/agent",
        "issued_at": 1700000000,
        "issued_at_provenance": "CONSTRUCTION_TIME",
        "correlation_id": "corr-02",
        "correlation_id_source": "INGRESS_MINTED",
        "governance_decision_digest": "a" * 64,
        "opa_input_digest": "b" * 64,
        "nonce": "c" * 32,
        "params": {"table": "audit"},
        "executor_id": "actuator_02",
        "routing_seal": _STUB_SEAL,
    }
    defaults.update(overrides)
    return ExecutionClearance(**defaults)


class TestActuator02Adapter:
    """Tests for Actuator02Adapter seal-bound brokerage and receipt verification."""

    @pytest.mark.asyncio
    async def test_verified_receipt_and_precredentials_brokerage(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        resolver = _StubKeyResolver({"openshell-kid-1": pub})
        broker = _StubCredentialBroker()
        captured_headers: dict[str, str] = {}

        def _handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            env_digest = request.headers["x-cage-envelope-digest"]
            unsigned_body = {
                "receipt_id": "rcpt-os-001",
                "session_uuid": "sess-os-001",
                "status": "ACCEPTED",
                "envelope_digest": env_digest,
            }
            sig = priv.sign(
                RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(unsigned_body)
            )
            body = {
                **unsigned_body,
                "signature": {
                    "alg": "EdDSA",
                    "kid": "openshell-kid-1",
                    "value": base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="),
                },
            }
            return httpx.Response(200, json=body)

        client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443",
            signer=_StubSigner(),
            http_client=client,
            credential_broker=broker,
            receipt_key_resolver=resolver,
            require_signed_receipts=True,
        )
        receipt = await adapter.actuate(_make_clearance())
        assert receipt.accepted is True
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.VERIFIED
        assert captured_headers.get("x-cage-routing-seal") == _STUB_SEAL
        assert captured_headers.get("x-cage-seal-profile") == SEAL_PROFILE
        assert captured_headers.get("x-brokered-token") == "ephemeral-scoped-token"
        assert len(broker.calls) == 1

    @pytest.mark.asyncio
    async def test_credential_broker_denial_fails_closed_before_wire(self) -> None:
        broker = _StubCredentialBroker(fail=True)
        wire_called = False

        def _handler(_request: httpx.Request) -> httpx.Response:
            nonlocal wire_called
            wire_called = True
            return httpx.Response(200, json={})

        client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443",
            signer=_StubSigner(),
            http_client=client,
            credential_broker=broker,
        )
        receipt = await adapter.actuate(_make_clearance())
        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert wire_called is False
        assert any(f["code"] == "CREDENTIAL_BROKER_FAILED" for f in receipt.findings)

    @pytest.mark.asyncio
    async def test_unknown_kid_produces_invalid_verification_and_unknown_outcome(
        self,
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        resolver = _StubKeyResolver({})

        def _handler(request: httpx.Request) -> httpx.Response:
            env_digest = request.headers["x-cage-envelope-digest"]
            unsigned_body = {
                "receipt_id": "rcpt-os-002",
                "session_uuid": "sess-os-002",
                "status": "ACCEPTED",
                "envelope_digest": env_digest,
            }
            sig = priv.sign(
                RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(unsigned_body)
            )
            return httpx.Response(
                200,
                json={
                    **unsigned_body,
                    "signature": {
                        "alg": "EdDSA",
                        "kid": "unknown-kid",
                        "value": base64.urlsafe_b64encode(sig).decode("ascii"),
                    },
                },
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443",
            signer=_StubSigner(),
            http_client=client,
            receipt_key_resolver=resolver,
            require_signed_receipts=True,
        )
        receipt = await adapter.actuate(_make_clearance())
        assert receipt.accepted is False
        assert receipt.verification is ReceiptVerification.INVALID
        assert receipt.outcome is ActuationOutcome.UNKNOWN


class TestOcsfEvidenceIngestor:
    """Tests for OcsfEvidenceIngestor schema validation and secret redaction."""

    @pytest.mark.asyncio
    async def test_ingests_valid_ocsf_and_redacts_secrets(self) -> None:
        events: list[dict[str, Any]] = []

        class _StubSink:
            async def ingest(self, record: dict[str, Any]) -> str:
                events.append(record)
                return "msg-ocsf-1"

        ingestor = OcsfEvidenceIngestor(sink=_StubSink())
        msg_id = await ingestor.ingest_ocsf_event(
            {
                "class_uid": 4001,
                "disposition": "Blocked",
                "sandbox_id": "sbx-1",
                "thread_id": "thread-1",
                "governance_decision_digest": "d" * 64,
                "metadata": {
                    "dst_endpoint": "api.external.example",
                    "api_key": "should-not-appear",
                },
            }
        )
        assert msg_id == "msg-ocsf-1"
        assert len(events) == 1
        assert events[0]["type"] == "SANDBOX_OCSF_TELEMETRY"
        assert events[0]["controlId"] == "AC-3"
        assert events[0]["metadata"]["api_key"] == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_rejects_unsupported_ocsf_class_uid(self) -> None:
        ingestor = OcsfEvidenceIngestor()
        with pytest.raises(ValueError, match="Unsupported OCSF class_uid"):
            await ingestor.ingest_ocsf_event(
                {
                    "class_uid": 9999,
                    "sandbox_id": "sbx-1",
                    "thread_id": "thread-1",
                    "governance_decision_digest": "d" * 64,
                }
            )


class TestPolicyAdvisorBridge:
    """Tests for PolicyAdvisorBridge DRY_RUN evaluation and DeferQueue parking."""

    @pytest.mark.asyncio
    async def test_parks_require_approval_proposal_in_defer_queue(self) -> None:
        @dataclass
        class _Verdict:
            decision: GovernanceDecision
            reason: str

        class _StubGovernor:
            async def validate_action(self, **_kwargs: Any) -> _Verdict:
                return _Verdict(
                    decision=GovernanceDecision.REQUIRE_APPROVAL,
                    reason="Terminal action requires HITL",
                )

        parked: list[Any] = []

        class _StubDeferQueue:
            async def park(self, token: Any) -> str:
                parked.append(token)
                return token.defer_id

        bridge = PolicyAdvisorBridge(
            governor=_StubGovernor(),
            defer_queue=_StubDeferQueue(),  # type: ignore[arg-type]
        )
        outcome = await bridge.evaluate_proposal(
            PolicyAdvisorProposal(
                sandbox_id="sbx-1",
                thread_id="thread-1",
                action="write_db",
                requested_endpoint="https://db.internal/write",
            )
        )
        assert outcome.status == "PARKED_FOR_HITL"
        assert outcome.defer_id is not None
        assert len(parked) == 1
        assert parked[0].opa_input_snapshot["action"] == "write_db"

    @pytest.mark.asyncio
    async def test_rejects_hard_stpa_violation_without_parking(self) -> None:
        @dataclass
        class _Verdict:
            decision: GovernanceDecision
            reason: str

        class _StubGovernor:
            async def validate_action(self, **_kwargs: Any) -> _Verdict:
                return _Verdict(
                    decision=GovernanceDecision.DENY,
                    reason="UCA-1 hard violation",
                )

        bridge = PolicyAdvisorBridge(governor=_StubGovernor(), defer_queue=None)
        outcome = await bridge.evaluate_proposal(
            PolicyAdvisorProposal(
                sandbox_id="sbx-1",
                thread_id="thread-1",
                action="write_db",
                requested_endpoint="https://db.internal/write",
            )
        )
        assert outcome.status == "REJECTED"
        assert outcome.defer_id is None


def _wire_recorder() -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"receipt_id": "r", "status": "ACCEPTED"})

    return httpx.AsyncClient(transport=httpx.MockTransport(_handler)), seen


class TestSealProfile:
    """cage-seal/1: the seal is mandatory, partner-verifiable and out of band."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("seal", "code"),
        [
            (None, "ROUTING_SEAL_MISSING"),
            ("", "ROUTING_SEAL_MISSING"),
            (
                "65f0a1b2.execute-trade." + "a" * 64 + "." + "b" * 64,
                "ROUTING_SEAL_NOT_JWS",
            ),
            ("not a jws", "ROUTING_SEAL_NOT_JWS"),
            ("a.b.c\nX-Injected: 1", "ROUTING_SEAL_NOT_JWS"),
        ],
    )
    async def test_missing_or_unverifiable_seal_refused_before_wire(
        self, seal: str | None, code: str
    ) -> None:
        client, seen = _wire_recorder()
        broker = _StubCredentialBroker()
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443",
            signer=_StubSigner(),
            http_client=client,
            credential_broker=broker,
        )
        receipt = await adapter.actuate(_make_clearance(routing_seal=seal))
        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert [f["code"] for f in receipt.findings] == [code]
        assert seen == []
        assert broker.calls == [], "no credential is brokered for an unsealed clearance"

    @pytest.mark.asyncio
    async def test_seal_stays_out_of_the_envelope(self) -> None:
        client, seen = _wire_recorder()
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443", signer=_StubSigner(), http_client=client
        )
        clearance = _make_clearance()
        await adapter.actuate(clearance)
        (request,) = seen
        assert _STUB_SEAL.encode() not in request.content
        assert "routing_seal" not in clearance.to_dict()
        assert _STUB_SEAL not in repr(clearance)
        assert (
            request.headers["x-cage-envelope-digest"]
            == hashlib.sha256(jcs_canonicalize_plan(clearance.to_dict())).hexdigest()
        )

    @pytest.mark.asyncio
    async def test_brokered_headers_cannot_shadow_cage_headers(self) -> None:
        class _HostileBroker(_StubCredentialBroker):
            async def fetch_credential(self, *a: Any, **k: Any) -> dict[str, str]:
                return {
                    "x-cage-routing-seal": "attacker.seal.value",
                    "X-CAGE-Seal-Profile": "none",
                    "X-Brokered-Token": "ok",
                }

        client, seen = _wire_recorder()
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443",
            signer=_StubSigner(),
            http_client=client,
            credential_broker=_HostileBroker(),
        )
        await adapter.actuate(_make_clearance())
        (request,) = seen
        assert request.headers.get_list("x-cage-routing-seal") == [_STUB_SEAL]
        assert request.headers.get_list("x-cage-seal-profile") == [SEAL_PROFILE]
        assert request.headers["x-brokered-token"] == "ok"

    @pytest.mark.asyncio
    async def test_supervisor_can_verify_seal_from_wire_bytes_alone(self) -> None:
        """The Supervisor's checks (profile doc section 4) pass on exactly what it receives."""
        gateway_key = ec.generate_private_key(ec.SECP256R1())
        params = {"table": "audit", "rows": [1, 2], "meta": {"k": None}}
        seal = pyjwt.encode(
            {
                "action_hash": compute_action_hash("write_db", params),
                "canon": SEAL_CANON,
                "record_hash": "e" * 64,
                "nonce": "n-1",
                "iat": int(time.time()),
                "exp": int(time.time()) + 30,
                "iss": "cage-gateway",
                "aud": "cage-actuator:write_db",
            },
            gateway_key,
            algorithm="ES256",
            headers={"kid": "gw-1"},
        )
        client, seen = _wire_recorder()
        adapter = Actuator02Adapter(
            endpoint="https://127.0.0.1:8443", signer=_StubSigner(), http_client=client
        )
        await adapter.actuate(_make_clearance(params=params, routing_seal=seal))
        (request,) = seen

        envelope = json.loads(request.content)
        claims = pyjwt.decode(
            request.headers["x-cage-routing-seal"],
            gateway_key.public_key(),
            algorithms=["ES256", "EdDSA"],
            audience=f"cage-actuator:{envelope['action']}",
            issuer="cage-gateway",
            options={"require": ["exp", "aud", "nonce", "action_hash", "canon"]},
        )
        assert request.headers["x-cage-seal-profile"] == SEAL_PROFILE
        assert claims["canon"] == SEAL_CANON
        recomputed = hashlib.sha256(
            jcs_canonicalize_plan(
                {"action": envelope["action"], "params": envelope["params"]}
            )
        ).hexdigest()
        assert recomputed == claims["action_hash"]

        # A tampered envelope would not match the sealed hash.
        tampered = {**envelope["params"], "rows": "[1, 2]"}
        assert (
            hashlib.sha256(
                jcs_canonicalize_plan(
                    {"action": envelope["action"], "params": tampered}
                )
            ).hexdigest()
            != claims["action_hash"]
        )

    def test_ocsf_metadata_exceeding_cap_rejected(self) -> None:
        """Issue #405: OcsfEventModel caps metadata at MAX_OCSF_METADATA_BYTES (64 KB)."""
        from pydantic import ValidationError

        from src.integrations.actuator_02.ocsf_ingestor import (
            MAX_OCSF_METADATA_BYTES,
            OcsfEventModel,
        )

        with pytest.raises(ValidationError, match="OCSF metadata is .* bytes; limit"):
            OcsfEventModel(
                class_uid=1007,
                activity_id=1,
                severity_id=4,
                status_id=2,
                sandbox_id="sbx-1",
                thread_id="thread-1",
                governance_decision_digest="d" * 64,
                message="syscall blocked",
                metadata={"blob": "A" * (MAX_OCSF_METADATA_BYTES + 1)},
            )
