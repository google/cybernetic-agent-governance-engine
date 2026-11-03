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

"""Unit tests for quarantine actuator, monotonic epoch advancement, and host-kernel actuator_04."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.gateway.governance.arm_containment_ring import (
    ArmContainmentRing,
    ArmRole,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    InferenceProxySvidQuarantineActuator,
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineReleaseDirective,
    QuarantineReleaseReceipt,
    QuarantineTriggerReason,
    advance_workload_epoch,
    clear_local_quarantine_state,
    dispatch_quarantine,
    dispatch_quarantine_release,
    get_workload_min_epoch,
    is_workload_quarantined,
    unquarantine_workload,
)
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.gateway.governance.seams.actuation import ActuationOutcome, ReceiptVerification
from src.gateway.governance.seams.attestation import AttestationStatus
from src.gateway.governance.seams.normative import FindingStatus
from src.integrations.actuator_04.adapter import (
    Actuator04Adapter,
    verify_substrate_receipt_signature,
)
from src.integrations.actuator_04.attestation import Actuator04AttestationProvider
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ATTESTATION_RECEIPT_DOMAIN_TAG,
    OCSF_EVENT_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)
from src.integrations.actuator_04.normative import Actuator04NormativeProvider
from src.integrations.actuator_04.ocsf_bridge import Actuator04OcsfIngestor

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Helpers & Mock Classes
# ---------------------------------------------------------------------------

class StubKeyResolver:
    """In-memory key resolver for tests."""

    def __init__(self, keys: dict[str, ed25519.Ed25519PublicKey]) -> None:
        self.keys = keys

    async def get_key(self, kid: str) -> ed25519.Ed25519PublicKey | None:
        return self.keys.get(kid)


class StubSigner:
    """Mock RawMessageSigner implementing asymmetric signing."""

    def __init__(self, key_id: str = "cage-gov-kms-key-1") -> None:
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def is_kms_active(self) -> bool:
        return True

    def sign_raw(self, message: bytes) -> bytes:
        return b"m" * 64

    async def sign_raw_async(self, message: bytes) -> bytes:
        return b"m" * 64


def _generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


# ---------------------------------------------------------------------------
# Quarantine Release Directive & Receipt RFC 8785 Canonical JCS
# ---------------------------------------------------------------------------

def test_quarantine_release_directive_canonical_jcs():
    directive = QuarantineReleaseDirective(
        thread_id="thread-rel-42",
        agent_svid="spiffe://cluster.local/ns/agents/sa/agent-alpha",
        sandbox_id="sandbox-node-7",
        expected_min_epoch=3,
        quorum_approval_digest="a" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="corr-rel-999",
        nonce="nonce-release-1234",
        reason="incident_remediated",
    )
    jcs_bytes = directive.to_canonical_jcs()
    assert isinstance(jcs_bytes, bytes)
    decoded = json.loads(jcs_bytes.decode("utf-8"))
    assert decoded["agent_svid"] == "spiffe://cluster.local/ns/agents/sa/agent-alpha"
    assert decoded["expected_min_epoch"] == 3
    assert decoded["quorum_count"] == 2


def test_quarantine_release_receipt_serialization():
    receipt = QuarantineReleaseReceipt(
        released=True,
        enforcement_plane="HOST_OS_KERNEL",
        epoch_before=2,
        epoch_after=3,
        outcome=ActuationOutcome.ACCEPTED,
        verification=ReceiptVerification.VERIFIED,
        findings=[{"code": "SUCCESS", "detail": "Quarantine lifted"}],
    )
    data = receipt.to_dict()
    assert data["released"] is True
    assert data["enforcement_plane"] == "HOST_OS_KERNEL"
    assert data["epoch_before"] == 2
    assert data["epoch_after"] == 3
    assert data["outcome"] == "ACCEPTED"


# ---------------------------------------------------------------------------
# Workload Epoch Tracking & Monotonicity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_monotonic_workload_epoch_advancement():
    clear_local_quarantine_state()
    agent_svid = "spiffe://cluster.local/ns/agents/sa/test-agent-epoch"

    # Initial epoch is 0
    assert await get_workload_min_epoch(agent_svid) == 0

    # Advance to 1
    new_epoch = await advance_workload_epoch(agent_svid, 1)
    assert new_epoch == 1
    assert await get_workload_min_epoch(agent_svid) == 1

    # Advancing to a higher epoch succeeds
    new_epoch = await advance_workload_epoch(agent_svid, 4)
    assert new_epoch == 4
    assert await get_workload_min_epoch(agent_svid) == 4

    # Attempting to rewind to epoch 2 does NOT decrease monotonic epoch
    new_epoch = await advance_workload_epoch(agent_svid, 2)
    assert new_epoch == 4
    assert await get_workload_min_epoch(agent_svid) == 4


@pytest.mark.asyncio
async def test_monotonic_workload_epoch_in_redis():
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    agent_svid = "spiffe://cluster.local/ns/agents/sa/redis-agent"

    assert await get_workload_min_epoch(agent_svid, redis_client=redis_client) == 0

    await advance_workload_epoch(agent_svid, 5, redis_client=redis_client)
    assert await get_workload_min_epoch(agent_svid, redis_client=redis_client) == 5

    # Cannot rewind
    await advance_workload_epoch(agent_svid, 3, redis_client=redis_client)
    assert await get_workload_min_epoch(agent_svid, redis_client=redis_client) == 5


# ---------------------------------------------------------------------------
# Arm Containment Ring (Containment Invariants)
# ---------------------------------------------------------------------------

def test_arm_containment_ring_hmac_and_epoch_verification():
    master_seed = b"01234567890123456789012345678901"  # 32 bytes
    ring = ArmContainmentRing(master_seed)
    arm_id = "arm-worker-1"
    ring.register_arm(arm_id, ArmRole.WORKER, initial_epoch=1)
    assert ring.get_epoch(arm_id) == 1

    message = b"privileged-command-payload"
    sig = ring.sign_message(arm_id, 1, ArmRole.WORKER, message)

    # Valid message verification with matching epoch
    assert ring.verify_message(arm_id, 1, ArmRole.WORKER, message, sig) is True

    # Stale epoch signature is rejected
    ring.advance_epoch(arm_id)
    assert ring.get_epoch(arm_id) == 2
    assert ring.verify_message(arm_id, 1, ArmRole.WORKER, message, sig) is False

    # New signature with epoch 2 verifies
    sig2 = ring.sign_message(arm_id, 2, ArmRole.WORKER, message)
    assert ring.verify_message(arm_id, 2, ArmRole.WORKER, message, sig2) is True


def test_arm_containment_ring_lateral_sink_isolation():
    master_seed = b"01234567890123456789012345678901"
    ring = ArmContainmentRing(master_seed)
    ring.register_arm("fuzzing-arm", ArmRole.FUZZING)
    ring.register_arm("admin-arm", ArmRole.COORDINATOR)

    # Fuzzing role is blocked from high-privilege sinks (case-insensitive)
    assert ring.can_access_sink("fuzzing-arm", "AccountingLedgerWrite") is False
    assert ring.can_access_sink("fuzzing-arm", "accountingledgerwrite") is False
    assert ring.can_access_sink("fuzzing-arm", "fundtransfer") is False
    assert ring.can_access_sink("fuzzing-arm", "normal_audit_query") is True

    # Coordinator role can access high-privilege sinks
    assert ring.can_access_sink("admin-arm", "AccountingLedgerWrite") is True


# ---------------------------------------------------------------------------
# Actuator_04 Detached Signature Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_substrate_receipt_signature_success():
    priv, pub = _generate_ed25519_keypair()
    resolver = StubKeyResolver({"node-1": pub})

    receipt_body = {
        "quarantined": True,
        "rule_id": "blackhole-101",
        "latency_us": 120,
        "kid": "node-1",
        "envelope_digest": "env-digest-1234",
    }
    # JCS canonical bytes without signature
    jcs_body = jcs_canonicalize_plan(receipt_body)
    data_to_sign = QUARANTINE_RECEIPT_DOMAIN_TAG + jcs_body
    raw_sig = priv.sign(data_to_sign)
    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode("ascii")
    receipt_body["signature"] = sig_b64

    verification, finding = await verify_substrate_receipt_signature(
        receipt_body,
        domain_tag=QUARANTINE_RECEIPT_DOMAIN_TAG,
        expected_envelope_digest="env-digest-1234",
        key_resolver=resolver,
    )
    assert verification == ReceiptVerification.VERIFIED
    assert finding is None


@pytest.mark.asyncio
async def test_verify_substrate_receipt_signature_unknown_kid_fails_closed():
    priv, pub = _generate_ed25519_keypair()
    # Empty resolver - unknown kid
    resolver = StubKeyResolver({})

    receipt_body = {
        "quarantined": True,
        "kid": "unknown-node",
        "signature": base64.urlsafe_b64encode(b"d" * 64).decode("ascii"),
    }
    verification, finding = await verify_substrate_receipt_signature(
        receipt_body,
        domain_tag=QUARANTINE_RECEIPT_DOMAIN_TAG,
        expected_envelope_digest="",
        key_resolver=resolver,
    )
    assert verification == ReceiptVerification.INVALID
    assert finding is not None
    assert finding["code"] == "RECEIPT_UNKNOWN_KID"


# ---------------------------------------------------------------------------
# Actuator_04 Adapter Quarantine and Release Execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_actuator_04_adapter_quarantine_workload():
    priv, pub = _generate_ed25519_keypair()
    resolver = StubKeyResolver({"daemon-node-0": pub})
    signer = StubSigner()

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["http://daemon:3030"]

    directive = QuarantineDirective(
        thread_id="t-001",
        agent_svid="spiffe://cluster.local/ns/agents/sa/quarantine-test",
        sandbox_id="sb-001",
        reason=QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT,
        violation_codes=["MEM_ESCAPE_01"],
        issued_at=int(time.time()),
        correlation_id="c-001",
        nonce="nonce-quarantine-123",
        governance_decision_digest="0" * 64,
        ttl_seconds=300,
    )

    canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
    expected_env = hashlib.sha256(canonical_bytes).hexdigest()

    resp_payload = {
        "quarantined": True,
        "rule_id": "wfp-rule-100",
        "latency_us": 320,
        "kid": "daemon-node-0",
        "envelope_digest": expected_env,
    }
    jcs_body = jcs_canonicalize_plan(resp_payload)
    sig = priv.sign(QUARANTINE_RECEIPT_DOMAIN_TAG + jcs_body)
    resp_payload["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = resp_payload
    mock_transport.post_to_endpoints.return_value = [mock_resp]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED
    assert receipt.enforcement_plane == "HOST_OS_KERNEL"


@pytest.mark.asyncio
async def test_actuator_04_adapter_release_workload():
    priv, pub = _generate_ed25519_keypair()
    resolver = StubKeyResolver({"daemon-node-0": pub})
    signer = StubSigner()

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["http://daemon:3030"]

    release_directive = QuarantineReleaseDirective(
        thread_id="t-001",
        agent_svid="spiffe://cluster.local/ns/agents/sa/quarantine-test",
        sandbox_id="sb-001",
        expected_min_epoch=1,
        quorum_approval_digest="f" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="c-002",
        nonce="nonce-release-456",
    )

    canonical_bytes = jcs_canonicalize_plan(release_directive.to_dict())
    expected_env = hashlib.sha256(canonical_bytes).hexdigest()

    resp_payload = {
        "released": True,
        "epoch_before": 1,
        "epoch_after": 2,
        "kid": "daemon-node-0",
        "envelope_digest": expected_env,
    }
    jcs_body = jcs_canonicalize_plan(resp_payload)
    sig = priv.sign(QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG + jcs_body)
    resp_payload["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = resp_payload
    mock_transport.post_to_endpoints.return_value = [mock_resp]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.release_workload(release_directive)
    assert receipt.released is True
    assert receipt.epoch_after == 2
    assert receipt.verification == ReceiptVerification.VERIFIED


# ---------------------------------------------------------------------------
# Actuator_04 Normative Provider & Attestation Provider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_actuator_04_normative_provider():
    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["http://daemon:3030"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "profile": {"conformal_threshold": 0.95},
        "signature": "mock-baseline-sig",
        "etag": "etag-123",
    }
    mock_transport.get_from_endpoints.return_value = [mock_resp]

    provider = Actuator04NormativeProvider(transport=mock_transport, default_alpha=0.05)
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.profile["conformal_threshold"] == 0.95


@pytest.mark.asyncio
async def test_actuator_04_attestation_provider():
    priv, pub = _generate_ed25519_keypair()
    resolver = StubKeyResolver({"node-attest-0": pub})

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["http://daemon:3030"]

    resp_payload = {
        "status": "VALID",
        "tpm_pcr_quote": "expected-pcr-quote-hex",
        "envelope_digest": "expected-pcr-quote-hex",
        "kid": "node-attest-0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    jcs_body = jcs_canonicalize_plan(resp_payload)
    sig = priv.sign(ATTESTATION_RECEIPT_DOMAIN_TAG + jcs_body)
    resp_payload["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = resp_payload
    mock_transport.get_from_endpoints.return_value = [mock_resp]

    provider = Actuator04AttestationProvider(
        transport=mock_transport,
        expected_pcr_quote="expected-pcr-quote-hex",
        receipt_key_resolver=resolver,
    )
    attestations = await provider.fetch_attestations({})
    assert len(attestations) == 1
    assert attestations[0].receipt_id == "node-attest-0"
    assert attestations[0].status == AttestationStatus.VERIFIED.value

    # Verify stale attestation quote (> 300s) is rejected with ERROR
    resp_payload_stale = dict(resp_payload)
    resp_payload_stale["timestamp_utc"] = "2020-01-01T00:00:00Z"
    stale_body = jcs_canonicalize_plan(resp_payload_stale)
    resp_payload_stale["signature"] = base64.urlsafe_b64encode(
        priv.sign(ATTESTATION_RECEIPT_DOMAIN_TAG + stale_body)
    ).decode("ascii")
    mock_resp.json.return_value = resp_payload_stale
    stale_attestations = await provider.fetch_attestations({})
    assert len(stale_attestations) == 1
    assert stale_attestations[0].status == AttestationStatus.ERROR.value
    assert stale_attestations[0].metadata["code"] == "ATTESTATION_TIMESTAMP_STALE"


# ---------------------------------------------------------------------------
# Actuator_04 OCSF Bridge (Automated Quarantine Trigger)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_actuator_04_ocsf_ingestor_triggers_quarantine_on_severity_4():
    priv, pub = _generate_ed25519_keypair()
    resolver = StubKeyResolver({"node-ocsf": pub})

    raw_event = {
        "class_uid": 1007,
        "category_uid": 1,
        "severity_id": 4,  # High severity breach
        "activity_id": 1,
        "action": "sandbox_escape_detected",
        "disposition": "Blocked",
        "sandbox_id": "sandbox-1",
        "thread_id": "thread-breakout-99",
        "agent_svid": "spiffe://cluster.local/ns/agents/sa/rogue-agent",
        "governance_decision_digest": "b" * 64,
        "envelope_digest": "b" * 64,
        "kid": "node-ocsf",
        "metadata": {
            "threat": "kernel_exploit",
        },
    }
    jcs_body = jcs_canonicalize_plan(raw_event)
    sig = priv.sign(OCSF_EVENT_DOMAIN_TAG + jcs_body)
    raw_event["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")

    mock_sink = AsyncMock()
    mock_sink.ingest.return_value = "receipt-ocsf-001"
    ingestor = Actuator04OcsfIngestor(sink=mock_sink, key_resolver=resolver)

    with patch("src.gateway.governance.quarantine_actuator.dispatch_quarantine") as mock_dispatch:
        mock_dispatch.return_value = QuarantineReceipt(
            quarantined=True,
            enforcement_plane="HOST_OS_KERNEL",
            rule_id="ocsf-auto-quarantine",
            latency_us=100,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
            findings=[],
        )
        receipt_id = await ingestor.ingest_ocsf_event(raw_event)
        assert receipt_id is not None
        assert mock_dispatch.called is True
        call_directive = mock_dispatch.call_args[0][0]
        assert call_directive.agent_svid == "spiffe://cluster.local/ns/agents/sa/rogue-agent"
        assert call_directive.reason == QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT
