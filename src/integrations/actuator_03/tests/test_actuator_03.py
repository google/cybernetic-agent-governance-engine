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

"""Unit tests for Layer 3 actuator_03 and Layer 1 QuarantineActuator seam."""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.verdicts import handle_deny
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    InferenceProxySvidQuarantineActuator,
    SimulatedQuarantineActuator,
    clear_local_quarantine_state,
    dispatch_quarantine,
    is_workload_quarantined,
    load_quarantine_actuator_from_env,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineTriggerReason,
)
from src.integrations.actuator_03.adapter import Actuator03Adapter
from src.integrations.actuator_03.constants import QUARANTINE_RECEIPT_DOMAIN_TAG

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


class _StubEvidenceSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def ingest(self, event: dict[str, Any]) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def _reset_quarantine_state() -> Any:
    clear_local_quarantine_state()
    yield
    clear_local_quarantine_state()


def _make_directive(
    *,
    thread_id: str = "thread-q-01",
    agent_svid: str = "spiffe://cluster.local/ns/cage/sa/advisor-agent",
    sandbox_id: str = "sbx-01",
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id,
        agent_svid=agent_svid,
        sandbox_id=sandbox_id,
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_SAFETY_BARRIER_BREACH",),
        issued_at=1710000000,
        correlation_id="corr-q-001",
        governance_decision_digest="digest-abc-123",
        nonce="nonce-q-001",
        ttl_seconds=900,
    )


def _sign_quarantine_receipt(
    priv_key: Ed25519PrivateKey,
    *,
    kid: str,
    rule_id: str,
    quarantined: bool,
    envelope_digest: str,
) -> dict[str, Any]:
    unsigned_body: dict[str, Any] = {
        "quarantined": quarantined,
        "rule_id": rule_id,
        "envelope_digest": envelope_digest,
    }
    msg = QUARANTINE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(unsigned_body)
    sig_bytes = priv_key.sign(msg)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    return {
        **unsigned_body,
        "signature": {
            "alg": "EdDSA",
            "kid": kid,
            "value": sig_b64,
        },
    }


class TestActuator03Adapter:
    """Tests for Actuator03Adapter out-of-band DPU quarantine."""

    @pytest.mark.asyncio
    async def test_quarantine_workload_verifies_ed25519_receipt(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        directive = _make_directive()
        expected_digest = hashlib.sha256(
            jcs_canonicalize_plan(directive.to_dict())
        ).hexdigest()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["X-CAGE-Envelope-Digest"] == expected_digest
            assert request.headers["X-CAGE-Quarantine-Assertion"]
            body = _sign_quarantine_receipt(
                priv,
                kid="dpu-key-01",
                rule_id="doca-flow-rule-99",
                quarantined=True,
                envelope_digest=expected_digest,
            )
            return httpx.Response(200, json=body)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        adapter = Actuator03Adapter(
            endpoint="https://dpu-sentry.internal:9443",
            signer=_StubSigner(),
            http_client=client,
            receipt_key_resolver=_StubKeyResolver({"dpu-key-01": pub}),
            require_signed_receipts=True,
        )
        receipt = await adapter.quarantine_workload(directive)
        assert receipt.quarantined is True
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.VERIFIED
        assert receipt.rule_id == "doca-flow-rule-99"
        assert receipt.enforcement_plane == "IN_SILICON_DPU"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_quarantine_fails_closed_on_unknown_kid_ignoring_embedded_key(
        self,
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        directive = _make_directive()
        expected_digest = hashlib.sha256(
            jcs_canonicalize_plan(directive.to_dict())
        ).hexdigest()

        def handler(_request: httpx.Request) -> httpx.Response:
            body = _sign_quarantine_receipt(
                priv,
                kid="unknown-dpu-kid",
                rule_id="doca-flow-rule-99",
                quarantined=True,
                envelope_digest=expected_digest,
            )
            body["embedded_public_key"] = "ignored"
            return httpx.Response(200, json=body)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        adapter = Actuator03Adapter(
            endpoint="https://dpu-sentry.internal:9443",
            signer=_StubSigner(),
            http_client=client,
            receipt_key_resolver=_StubKeyResolver({"dpu-key-01": pub}),
            require_signed_receipts=True,
        )
        receipt = await adapter.quarantine_workload(directive)
        assert receipt.quarantined is False
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.INVALID
        assert any(f["code"] == "RECEIPT_UNKNOWN_KID" for f in receipt.findings)
        await client.aclose()


class TestLayer1QuarantineBackends:
    """Tests for InferenceProxySvidQuarantineActuator, SimulatedQuarantineActuator, and handle_deny."""

    @pytest.mark.asyncio
    async def test_svid_proxy_quarantine_blocks_workload_and_records_evidence(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sink = _StubEvidenceSink()
        monkeypatch.setattr(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            lambda: sink,
        )
        actuator = InferenceProxySvidQuarantineActuator()
        svid = "spiffe://cluster.local/ns/cage/sa/rogue-agent"
        directive = _make_directive(thread_id="thread-rogue-1", agent_svid=svid)

        assert (
            await is_workload_quarantined(thread_id="thread-rogue-1", agent_svid=svid)
            is False
        )
        receipt = await dispatch_quarantine(directive, actuator=actuator)
        assert receipt.quarantined is True
        assert receipt.enforcement_plane == "CAGE_INFERENCE_PROXY_SVID"
        assert (
            await is_workload_quarantined(thread_id="thread-rogue-1", agent_svid=svid)
            is True
        )
        assert len(sink.events) == 1
        assert sink.events[0]["type"] == "WORKLOAD_QUARANTINE_RECEIPT"
        assert sink.events[0]["controlId"] == "SC-7"

    @pytest.mark.asyncio
    async def test_simulated_quarantine_fault_injection_and_prod_guard(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        directive = _make_directive()

        sim_reject = SimulatedQuarantineActuator(fault_mode="REJECT")
        r_reject = await sim_reject.quarantine_workload(directive)
        assert r_reject.quarantined is False
        assert r_reject.outcome is ActuationOutcome.REJECTED

        sim_timeout = SimulatedQuarantineActuator(fault_mode="TIMEOUT")
        r_timeout = await sim_timeout.quarantine_workload(directive)
        assert r_timeout.quarantined is False
        assert r_timeout.outcome is ActuationOutcome.UNKNOWN

        sim_ok = SimulatedQuarantineActuator()
        r_ok = await sim_ok.quarantine_workload(directive)
        assert r_ok.quarantined is True
        assert r_ok.outcome is ActuationOutcome.ACCEPTED

        # Simulated backend must refuse in production posture
        monkeypatch.setenv("CAGE_ENV", "prod")
        monkeypatch.setenv("CAGE_QUARANTINE_ACTUATOR", "simulated")
        with pytest.raises(
            RuntimeError, match="SimulatedQuarantineActuator is forbidden"
        ):
            load_quarantine_actuator_from_env()

    @pytest.mark.asyncio
    async def test_handle_deny_triggers_quarantine_when_enabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sink = _StubEvidenceSink()
        monkeypatch.setattr(
            "src.gateway.governance.governor.verdicts.publish_refusal",
            AsyncMock(),
        )
        monkeypatch.setattr(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            lambda: sink,
        )
        monkeypatch.setenv("CAGE_QUARANTINE_ACTUATOR", "cage_svid")

        svid = "spiffe://cluster.local/ns/cage/sa/breach-agent"
        with pytest.raises(GovernanceError) as exc_info:
            await handle_deny(
                action="transfer_funds",
                params={
                    "_caller_principal": svid,
                    "thread_id": "thread-breach-99",
                    "_quarantine_on_breach": True,
                },
                violations=[
                    Violation(
                        tier="CBF",
                        code="CBF_BARRIER_VIOLATION",
                        message="Barrier breached",
                        kind=ViolationKind.HARD,
                    )
                ],
                tier_failures=[],
            )

        err = exc_info.value
        assert err.payload.get("quarantined") is True
        assert (
            err.payload.get("quarantine_enforcement_plane")
            == "CAGE_INFERENCE_PROXY_SVID"
        )
        assert (
            await is_workload_quarantined(thread_id="thread-breach-99", agent_svid=svid)
            is True
        )
