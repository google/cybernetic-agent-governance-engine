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

"""Empirical stress test suite for monotonic epoch autotomy and quarantine ingress.

Challenges:
1. advance_workload_epoch() in ArmContainmentRing and quarantine_actuator.py:
   - Stale epoch token replay attacks
   - Concurrent release race conditions
   - Monotonicity preservation & epoch rollback resistance
   - Cross-arm and cross-role replay resistance
2. Ingress quarantine enforcement on /governance/validate-action, /mcp, and /tools/execute:
   - Fail-closed 403 rejection for quarantined SVIDs and threads
   - Stale epoch 403 rejection
   - Header casing and param fallback resiliency
3. Quorum release authorization:
   - quorum_count < 2 fail-closed validation
   - Receipt epoch_after > epoch_before invariant enforcement
   - Substrate receipt cryptographic signature verification
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from src.gateway.governance.arm_containment_ring import (
    ArmContainmentRing,
    ArmRole,
    advance_workload_epoch,
    get_workload_min_epoch,
)
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineReleaseDirective,
    QuarantineReleaseReceipt,
    QuarantineTriggerReason,
    clear_local_quarantine_state,
    dispatch_quarantine,
    dispatch_quarantine_release,
    is_workload_quarantined,
    unquarantine_workload,
)
from src.gateway.governance.seams.actuation import ActuationOutcome, ReceiptVerification
from src.integrations.actuator_04.adapter import (
    Actuator04Adapter,
    verify_substrate_receipt_signature,
)
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Helpers & Stubs
# ---------------------------------------------------------------------------

class StubKeyResolver:
    """In-memory key resolver for tests."""

    def __init__(self, keys: dict[str, ed25519.Ed25519PublicKey]) -> None:
        self.keys = keys

    async def get_key(self, kid: str) -> ed25519.Ed25519PublicKey | None:
        return self.keys.get(kid)


class StubSigner:
    """Mock RawMessageSigner."""

    @property
    def key_id(self) -> str:
        return "cage-gov-kms-key-stress"

    @property
    def is_kms_active(self) -> bool:
        return True

    def sign_raw(self, message: bytes) -> bytes:
        return b"s" * 64

    async def sign_raw_async(self, message: bytes) -> bytes:
        return b"s" * 64


# ===========================================================================
# 1. ArmContainmentRing & advance_workload_epoch Stress Tests
# ===========================================================================

def test_arm_containment_ring_stale_epoch_replay_attack():
    """Verify that stale epoch messages cannot be replayed after epoch advancement."""
    seed = b"k" * 32
    ring = ArmContainmentRing(seed)
    arm_id = "agent-arm-01"
    ring.register_arm(arm_id, ArmRole.WORKER, initial_epoch=1)

    msg = b"execute_critical_operation_payload"
    sig_epoch_1 = ring.sign_message(arm_id, 1, ArmRole.WORKER, msg)
    assert ring.verify_message(arm_id, 1, ArmRole.WORKER, msg, sig_epoch_1) is True

    # Advance epoch multiple times
    for _ in range(5):
        ring.advance_epoch(arm_id)
    assert ring.get_epoch(arm_id) == 6

    # Replay of epoch 1 signature MUST be rejected
    assert ring.verify_message(arm_id, 1, ArmRole.WORKER, msg, sig_epoch_1) is False

    # Intermediate stale epochs (2..5) must also be rejected
    for stale_epoch in range(1, 6):
        sig_stale = ring.sign_message(arm_id, stale_epoch, ArmRole.WORKER, msg)
        assert ring.verify_message(arm_id, stale_epoch, ArmRole.WORKER, msg, sig_stale) is False

    # Current epoch 6 signature MUST be accepted
    sig_epoch_6 = ring.sign_message(arm_id, 6, ArmRole.WORKER, msg)
    assert ring.verify_message(arm_id, 6, ArmRole.WORKER, msg, sig_epoch_6) is True


def test_arm_containment_ring_cross_arm_and_cross_role_replay():
    """Verify that signatures cannot be transferred across different arms or roles."""
    seed = b"m" * 32
    ring = ArmContainmentRing(seed)
    arm_a = "arm-alpha"
    arm_b = "arm-beta"
    ring.register_arm(arm_a, ArmRole.WORKER, initial_epoch=1)
    ring.register_arm(arm_b, ArmRole.COORDINATOR, initial_epoch=1)

    msg = b"transfer_authority_token"
    sig_a = ring.sign_message(arm_a, 1, ArmRole.WORKER, msg)

    # Replaying Arm A's signature as Arm B must fail
    assert ring.verify_message(arm_b, 1, ArmRole.COORDINATOR, msg, sig_a) is False

    # Replaying Arm A's signature with a different role on Arm A must fail
    assert ring.verify_message(arm_a, 1, ArmRole.COORDINATOR, msg, sig_a) is False


@pytest.mark.asyncio
async def test_advance_workload_epoch_concurrent_release_races_local():
    """Stress test concurrent calls to advance_workload_epoch in-memory."""
    clear_local_quarantine_state()
    agent_svid = "spiffe://cluster.local/ns/agents/sa/stress-agent-local"

    # Spawn 50 concurrent tasks with random epochs in [1..100]
    epochs_to_set = [random.randint(1, 100) for _ in range(50)]
    max_expected = max(epochs_to_set)

    async def _worker(epoch: int) -> int:
        await asyncio.sleep(random.uniform(0.001, 0.01))
        return await advance_workload_epoch(agent_svid, epoch)

    results = await asyncio.gather(*[_worker(ep) for ep in epochs_to_set])
    final_epoch = await get_workload_min_epoch(agent_svid)

    assert final_epoch == max_expected, f"Expected final epoch {max_expected}, got {final_epoch}"
    # Every return value must be >= the epoch requested
    for req_ep, res_ep in zip(epochs_to_set, results):
        assert res_ep >= req_ep


@pytest.mark.asyncio
async def test_advance_workload_epoch_concurrent_release_races_redis():
    """Stress test concurrent calls to advance_workload_epoch with Redis backend (Lua CAS)."""
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    agent_svid = "spiffe://cluster.local/ns/agents/sa/stress-agent-redis"

    epochs_to_set = [random.randint(1, 200) for _ in range(50)]
    max_expected = max(epochs_to_set)

    async def _worker(epoch: int) -> int:
        await asyncio.sleep(random.uniform(0.001, 0.01))
        return await advance_workload_epoch(agent_svid, epoch, redis_client=redis_client)

    results = await asyncio.gather(*[_worker(ep) for ep in epochs_to_set])
    final_epoch = await get_workload_min_epoch(agent_svid, redis_client=redis_client)

    assert final_epoch == max_expected, f"Expected final epoch {max_expected}, got {final_epoch}"
    for req_ep, res_ep in zip(epochs_to_set, results):
        assert res_ep >= req_ep


@pytest.mark.asyncio
async def test_advance_workload_epoch_rollback_attempts():
    """Verify that attempting to rewind epoch (lower, negative, zero) is strictly rejected."""
    clear_local_quarantine_state()
    agent_svid = "spiffe://cluster.local/ns/agents/sa/rollback-agent"

    # Set to 10
    assert await advance_workload_epoch(agent_svid, 10) == 10

    # Attempts to rewind
    assert await advance_workload_epoch(agent_svid, 9) == 10
    assert await advance_workload_epoch(agent_svid, 0) == 10
    assert await advance_workload_epoch(agent_svid, -5) == 10
    assert await get_workload_min_epoch(agent_svid) == 10

    # Redis backend test
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    assert await advance_workload_epoch(agent_svid, 50, redis_client=redis_client) == 50
    assert await advance_workload_epoch(agent_svid, 20, redis_client=redis_client) == 50
    assert await advance_workload_epoch(agent_svid, 0, redis_client=redis_client) == 50
    assert await get_workload_min_epoch(agent_svid, redis_client=redis_client) == 50


# ===========================================================================
# 2. Ingress Quarantine Enforcement Stress Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_ingress_quarantine_governance_validate_action():
    """Verify /governance/validate-action rejects quarantined workloads and stale epochs."""
    clear_local_quarantine_state()
    from src.gateway.server.governance_middleware import governance_app

    # Mount mock governor on governance_app.state to allow non-quarantined evaluation
    mock_gov = MagicMock(spec=SymbolicGovernor)
    mock_gov.profile = MagicMock()
    mock_gov.validate_action = AsyncMock()
    governance_app.state.governor = mock_gov

    client = TestClient(governance_app)
    svid = "spiffe://cluster.local/ns/agents/sa/validate-action-agent"
    thread_id = "thread-val-1"

    payload = {
        "action": "READ_DATA",
        "params": {
            "agent_svid": svid,
            "thread_id": thread_id,
        },
    }

    # 1. Quarantine the SVID
    directive = QuarantineDirective(
        thread_id=thread_id,
        agent_svid=svid,
        sandbox_id="sb-test",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="c-val-1",
        nonce="nonce-val-1",
        governance_decision_digest="0" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive)
    assert await is_workload_quarantined(thread_id=thread_id, agent_svid=svid) is True

    # 2. Request from quarantined SVID must be rejected fail-closed with HTTP 403
    resp_quarantined = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-thread-id": thread_id},
    )
    assert resp_quarantined.status_code == 403
    data = resp_quarantined.json()
    assert data["error"] == "workload_quarantined"
    assert data["agent_id"] == svid

    # 3. Lift quarantine and advance epoch to 5
    await unquarantine_workload(thread_id=thread_id, agent_svid=svid)
    await advance_workload_epoch(svid, 5)

    # 4. Request with stale epoch (3 < 5) must be rejected with HTTP 403 stale_workload_epoch
    resp_stale = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "3"},
    )
    assert resp_stale.status_code == 403
    stale_data = resp_stale.json()
    assert stale_data["error"] == "stale_workload_epoch"
    assert stale_data["min_epoch"] == 5

    # 5. Request with fresh epoch (5 >= 5) passes quarantine & epoch checks
    resp_fresh = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "5"},
    )
    # Passed quarantine gate (did not return 403 workload_quarantined or stale_workload_epoch)
    assert resp_fresh.status_code != 403 or resp_fresh.json().get("error") not in (
        "workload_quarantined",
        "stale_workload_epoch",
    )


@pytest.mark.asyncio
async def test_ingress_quarantine_mcp_middleware():
    """Verify McpQuarantineMiddleware rejects quarantined SVID/thread and stale epochs on /mcp."""
    clear_local_quarantine_state()
    from src.gateway.server.mcp_tool_server import McpQuarantineMiddleware

    # Mock inner ASGI app
    inner_app_called = False

    async def dummy_app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal inner_app_called
        inner_app_called = True
        body = b'{"status": "ok"}'
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    middleware = McpQuarantineMiddleware(dummy_app)
    svid = "spiffe://cluster.local/ns/agents/sa/mcp-agent"
    thread_id = "thread-mcp-99"

    # Quarantine the workload
    directive = QuarantineDirective(
        thread_id=thread_id,
        agent_svid=svid,
        sandbox_id="sb-mcp",
        reason=QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT,
        violation_codes=["ESCAPE_01"],
        issued_at=int(time.time()),
        correlation_id="c-mcp-1",
        nonce="nonce-mcp-1",
        governance_decision_digest="1" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive)

    # Dispatch ASGI request with quarantined headers
    scope = {
        "type": "http",
        "headers": [
            (b"x-cage-agent-svid", svid.encode("utf-8")),
            (b"x-cage-thread-id", thread_id.encode("utf-8")),
        ],
    }

    responses: list[dict[str, Any]] = []

    async def mock_send(msg: dict[str, Any]) -> None:
        responses.append(msg)

    async def mock_receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    await middleware(scope, mock_receive, mock_send)
    assert inner_app_called is False
    assert len(responses) == 2
    assert responses[0]["status"] == 403
    body_data = json.loads(responses[1]["body"].decode("utf-8"))
    assert body_data["error"] == "workload_quarantined"

    # Test stale epoch rejection
    await unquarantine_workload(thread_id=thread_id, agent_svid=svid)
    await advance_workload_epoch(svid, 10)

    stale_scope = {
        "type": "http",
        "headers": [
            (b"x-cage-agent-svid", svid.encode("utf-8")),
            (b"x-cage-epoch", b"8"),
        ],
    }
    responses.clear()
    await middleware(stale_scope, mock_receive, mock_send)
    assert responses[0]["status"] == 403
    stale_body = json.loads(responses[1]["body"].decode("utf-8"))
    assert stale_body["error"] == "stale_workload_epoch"
    assert stale_body["min_epoch"] == 10


@pytest.mark.asyncio
async def test_ingress_quarantine_tools_execute_fail_closed():
    """Verify /tools/execute rejects quarantined workload with HTTP 403."""
    clear_local_quarantine_state()
    from src.gateway.server.mcp_tool_server import ToolExecutionRequest, execute_tool_endpoint

    svid = "spiffe://cluster.local/ns/agents/sa/tools-agent"
    thread_id = "thread-tools-1"

    # Quarantine the agent
    directive = QuarantineDirective(
        thread_id=thread_id,
        agent_svid=svid,
        sandbox_id="sb-tools",
        reason=QuarantineTriggerReason.FTRA_UNCONTAINABLE_TERMINAL,
        violation_codes=["FTRA_01"],
        issued_at=int(time.time()),
        correlation_id="c-tools-1",
        nonce="nonce-tools-1",
        governance_decision_digest="2" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive)

    # Construct request with verified identity policy mock
    mock_request = MagicMock()
    mock_request.scope = {
        "headers": [(b"l5d-client-id", svid.encode("latin-1"))],
        "client": ("127.0.0.1", 50000),
    }
    mock_request.headers.get.side_effect = lambda h, default=None: (
        thread_id if h.lower() == "x-cage-thread-id" else default
    )
    mock_request.app.state.redis = None

    req_body = ToolExecutionRequest(
        tool_name="trigger_safety_intervention",
        params={"reason": "lockout", "thread_id": thread_id},
    )

    with patch("src.gateway.server.workload_identity.extract_client_identity", return_value=svid), \
         patch("src.gateway.server.workload_identity.load_identity_policy") as mock_policy:
        mock_policy.return_value.trusted = {svid}
        resp = await execute_tool_endpoint(req_body, mock_request)
        assert resp.status_code == 403
        data = json.loads(resp.body.decode("utf-8"))
        assert data["error"] == "workload_quarantined"
        assert data["agent_id"] == svid


# ===========================================================================
# 3. Quorum Release Authorization Stress Tests
# ===========================================================================

def test_quorum_release_directive_insufficient_quorum_fails_closed():
    """Verify that quorum_count < 2 strictly raises ValueError (fail-closed)."""
    valid_digest = "e" * 64

    # quorum_count = 1 MUST raise
    with pytest.raises(ValueError, match="quorum_count >= 2; got 1"):
        QuarantineReleaseDirective(
            thread_id="t-q1",
            agent_svid="spiffe://cluster.local/ns/agents/sa/q-agent",
            sandbox_id="sb-q",
            quorum_approval_digest=valid_digest,
            quorum_count=1,
            issued_at=int(time.time()),
            correlation_id="c-q1",
            nonce="nonce-q1",
        )

    # quorum_count = 0 MUST raise
    with pytest.raises(ValueError, match="quorum_count >= 2; got 0"):
        QuarantineReleaseDirective(
            thread_id="t-q0",
            agent_svid="spiffe://cluster.local/ns/agents/sa/q-agent",
            sandbox_id="sb-q",
            quorum_approval_digest=valid_digest,
            quorum_count=0,
            issued_at=int(time.time()),
            correlation_id="c-q0",
            nonce="nonce-q0",
        )

    # quorum_count = -5 MUST raise
    with pytest.raises(ValueError, match="quorum_count >= 2"):
        QuarantineReleaseDirective(
            thread_id="t-qneg",
            agent_svid="spiffe://cluster.local/ns/agents/sa/q-agent",
            sandbox_id="sb-q",
            quorum_approval_digest=valid_digest,
            quorum_count=-5,
            issued_at=int(time.time()),
            correlation_id="c-qneg",
            nonce="nonce-qneg",
        )


def test_quorum_release_directive_invalid_digest_fails_closed():
    """Verify that malformed or non-sha256 quorum_approval_digest fails closed."""
    for bad_digest in ["not-a-hash", "e" * 63, "E" * 64, ""]:
        with pytest.raises(ValueError):
            QuarantineReleaseDirective(
                thread_id="t-bad-hash",
                agent_svid="spiffe://cluster.local/ns/agents/sa/q-agent",
                sandbox_id="sb-q",
                quorum_approval_digest=bad_digest,
                quorum_count=2,
                issued_at=int(time.time()),
                correlation_id="c-bad",
                nonce="nonce-bad",
            )


def test_quorum_release_receipt_monotonic_epoch_invariant():
    """Verify that QuarantineReleaseReceipt enforces epoch_after > epoch_before when released=True."""
    # epoch_after == epoch_before MUST raise ValueError
    with pytest.raises(ValueError, match="epoch_after.*must be > epoch_before"):
        QuarantineReleaseReceipt(
            released=True,
            enforcement_plane="HOST_OS_KERNEL",
            epoch_before=2,
            epoch_after=2,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
        )

    # epoch_after < epoch_before MUST raise ValueError
    with pytest.raises(ValueError, match="epoch_after.*must be > epoch_before"):
        QuarantineReleaseReceipt(
            released=True,
            enforcement_plane="HOST_OS_KERNEL",
            epoch_before=5,
            epoch_after=4,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
        )

    # released=False does NOT require epoch advancement
    receipt_unreleased = QuarantineReleaseReceipt(
        released=False,
        enforcement_plane="HOST_OS_KERNEL",
        epoch_before=3,
        epoch_after=3,
        outcome=ActuationOutcome.REJECTED,
        verification=ReceiptVerification.UNVERIFIED,
    )
    assert receipt_unreleased.released is False


@pytest.mark.asyncio
async def test_actuator_04_adapter_forged_release_signature_fails_closed():
    """Verify that an invalid Ed25519 signature on a release receipt is rejected."""
    priv, pub = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate().public_key()
    resolver = StubKeyResolver({"daemon-0": pub})
    signer = StubSigner()

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["http://daemon:3030"]

    directive = QuarantineReleaseDirective(
        thread_id="t-rel-forge",
        agent_svid="spiffe://cluster.local/ns/agents/sa/forged-agent",
        sandbox_id="sb-forge",
        expected_min_epoch=1,
        quorum_approval_digest="d" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="c-forge",
        nonce="nonce-forge",
    )
    canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
    expected_env = hashlib.sha256(canonical_bytes).hexdigest()

    # Case A: 64-byte forged signature that fails cryptographic verification
    forged_resp = {
        "released": True,
        "epoch_before": 1,
        "epoch_after": 2,
        "kid": "daemon-0",
        "envelope_digest": expected_env,
        "signature": base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii"),
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = forged_resp
    mock_transport.post_to_endpoints.return_value = [mock_resp]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.release_workload(directive)
    assert receipt.released is False
    assert receipt.outcome == ActuationOutcome.UNKNOWN
    assert receipt.verification == ReceiptVerification.INVALID
    assert any(f["code"] == "RECEIPT_SIGNATURE_INVALID" for f in receipt.findings)

    # Case B: Malformed signature length fails closed
    forged_resp["signature"] = base64.urlsafe_b64encode(b"short").decode("ascii")
    receipt_short = await adapter.release_workload(directive)
    assert receipt_short.released is False
    assert receipt_short.outcome == ActuationOutcome.UNKNOWN
    assert receipt_short.verification == ReceiptVerification.INVALID
    assert any(f["code"] == "RECEIPT_SIGNATURE_LENGTH" for f in receipt_short.findings)

    # Case C: Unknown KID fails closed
    forged_resp["kid"] = "unknown-node"
    forged_resp["signature"] = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii")
    receipt_unknown = await adapter.release_workload(directive)
    assert receipt_unknown.released is False
    assert receipt_unknown.outcome == ActuationOutcome.UNKNOWN
    assert receipt_unknown.verification == ReceiptVerification.INVALID
    assert any(f["code"] == "RECEIPT_UNKNOWN_KID" for f in receipt_unknown.findings)


# ===========================================================================
# 4. Adversarial Findings: Gap Demonstrations & Edge Cases
# ===========================================================================

@pytest.mark.asyncio
async def test_quarantine_svid_case_sensitivity_gap(monkeypatch):
    """Verify that quarantine_actuator normalizes SVID casing with .strip().lower().

    When an agent is quarantined under mixed-case SVID, requests using lowercase
    SVID are correctly blocked.
    """
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    svid_upper = "spiffe://cluster.local/ns/agents/sa/Rogue-Agent-Alpha"
    svid_lower = "spiffe://cluster.local/ns/agents/sa/rogue-agent-alpha"

    directive = QuarantineDirective(
        thread_id="t-case-1",
        agent_svid=svid_upper,
        sandbox_id="sb-case",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="c-case",
        nonce="nonce-case",
        governance_decision_digest="9" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive, redis_client=redis_client)

    # Upper case matches
    assert await is_workload_quarantined(agent_svid=svid_upper, redis_client=redis_client) is True

    # Lower case also matches because quarantine_actuator normalizes agent_svid
    case_matched = await is_workload_quarantined(agent_svid=svid_lower, redis_client=redis_client)
    assert case_matched is True


@pytest.mark.asyncio
async def test_epoch_bypass_when_header_omitted_or_malformed(monkeypatch):
    """Verify that omitting or sending a malformed x-cage-epoch fails closed when min_epoch > 0.

    When min_epoch is advanced (e.g. to 5), omitting the x-cage-epoch header or sending
    a non-integer value is rejected with HTTP 403 missing_workload_epoch.
    """
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    from src.gateway.server.governance_middleware import governance_app

    mock_gov = MagicMock(spec=SymbolicGovernor)
    mock_gov.profile = MagicMock()
    mock_gov.validate_action = AsyncMock()
    governance_app.state.governor = mock_gov

    client = TestClient(governance_app)
    svid = "spiffe://cluster.local/ns/agents/sa/bypass-test-agent"
    await advance_workload_epoch(svid, 5)
    assert await get_workload_min_epoch(svid) == 5

    payload = {
        "action": "READ_DATA",
        "params": {
            "agent_svid": svid,
            "thread_id": "thread-bypass-1",
        },
    }

    # Stale epoch 3 is rejected
    resp_stale = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "3"},
    )
    assert resp_stale.status_code == 403
    assert resp_stale.json()["error"] == "stale_workload_epoch"

    # Attacker omits x-cage-epoch: fails closed with HTTP 403 missing_workload_epoch
    resp_omitted = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid},
    )
    assert resp_omitted.status_code == 403
    assert resp_omitted.json().get("error") in ("missing_workload_epoch", "stale_workload_epoch")

    # Attacker sends malformed x-cage-epoch: fails closed with HTTP 403 missing_workload_epoch
    resp_malformed = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "invalid_epoch_string"},
    )
    assert resp_malformed.status_code == 403
    assert resp_malformed.json().get("error") in ("missing_workload_epoch", "stale_workload_epoch")

