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

"""Integration and regression test suite for actuator_04 host-kernel substrate."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    QuarantineDirective,
    QuarantineReleaseDirective,
    QuarantineTriggerReason,
    advance_workload_epoch,
    clear_local_quarantine_state,
    get_workload_min_epoch,
    is_workload_quarantined,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.attestation import AttestationStatus
from src.integrations.actuator_04.adapter import Actuator04Adapter
from src.integrations.actuator_04.attestation import Actuator04AttestationProvider
from src.integrations.actuator_04.client import (
    Actuator04Transport,
    validate_destination_url,
)
from src.integrations.actuator_04.constants import (
    ATTESTATION_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


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

    async def sign_raw_async(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest() * 2


# ---------------------------------------------------------------------------
# SSRF & Mathematical IP Validation Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "allow_loopback", "env", "should_block", "desc"),
    [
        (
            "http://2130706433:8080",
            False,
            "dev",
            True,
            "Decimal integer loopback in dev",
        ),
        (
            "https://2130706433:8080",
            False,
            "production",
            True,
            "Decimal integer loopback in prod",
        ),
        (
            "http://2852039166:8080",
            False,
            "dev",
            True,
            "Decimal integer metadata in dev",
        ),
        (
            "https://2852039166:8080",
            False,
            "production",
            True,
            "Decimal integer metadata in prod",
        ),
        ("http://0177.0.0.1:8080", False, "dev", True, "Octal loopback in dev"),
        (
            "https://0177.0.0.1:8080",
            False,
            "production",
            True,
            "Octal loopback in prod",
        ),
        (
            "http://0251.0376.0251.0376:8080",
            False,
            "dev",
            True,
            "Octal metadata in dev",
        ),
        (
            "https://0251.0376.0251.0376:8080",
            False,
            "production",
            True,
            "Octal metadata in prod",
        ),
        ("http://0x7f.0.0.1:8080", False, "dev", True, "Hex loopback in dev"),
        ("https://0x7f.0.0.1:8080", False, "production", True, "Hex loopback in prod"),
        ("http://0xa9.0xfe.0xa9.0xfe:8080", False, "dev", True, "Hex metadata in dev"),
        (
            "https://0xa9.0xfe.0xa9.0xfe:8080",
            False,
            "production",
            True,
            "Hex metadata in prod",
        ),
        (
            "http://169.254.169.254.nip.io:8080",
            False,
            "dev",
            True,
            "DNS rebinding metadata in dev",
        ),
        (
            "https://169.254.169.254.nip.io:8080",
            False,
            "production",
            True,
            "DNS rebinding metadata in prod",
        ),
        (
            "http://127.0.0.1.nip.io:8080",
            False,
            "dev",
            True,
            "DNS rebinding loopback in dev",
        ),
        (
            "https://127.0.0.1.nip.io:8080",
            False,
            "production",
            True,
            "DNS rebinding loopback in prod",
        ),
        (
            "http://[::ffff:127.0.0.1]:8080",
            False,
            "dev",
            True,
            "IPv4-mapped IPv6 loopback in dev",
        ),
        (
            "http://[::ffff:169.254.169.254]:8080",
            False,
            "dev",
            True,
            "IPv4-mapped IPv6 metadata in dev",
        ),
        (
            "http://[::ffff:7f00:1]:8080",
            False,
            "dev",
            True,
            "IPv4-mapped IPv6 hex loopback in dev",
        ),
        (
            "http://[::ffff:a9fe:a9fe]:8080",
            False,
            "dev",
            True,
            "IPv4-mapped IPv6 hex metadata in dev",
        ),
        (
            "http://169.254.169.254:8080",
            False,
            "dev",
            True,
            "Standard dotted metadata in dev",
        ),
        (
            "https://169.254.169.254:8080",
            False,
            "production",
            True,
            "Standard dotted metadata in prod",
        ),
        (
            "http://127.0.0.1:8080",
            False,
            "dev",
            True,
            "Loopback when allow_loopback=False in dev",
        ),
        (
            "http://127.0.0.1:8080",
            True,
            "dev",
            False,
            "Loopback when allow_loopback=True in dev",
        ),
    ],
)
def test_validate_destination_url_ssrf_vectors(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    allow_loopback: bool,
    env: str,
    should_block: bool,
    desc: str,
) -> None:
    monkeypatch.setenv("CAGE_ENV", env)
    blocked = False
    try:
        validate_destination_url(url, allow_loopback=allow_loopback)
    except ValueError:
        blocked = True
    assert blocked == should_block, f"Failed vector: {desc}"


# ---------------------------------------------------------------------------
# Multi-Node Quorum & Fan-Out Tests in Adapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_release_workload_multinode_partial_failure_fails_closed():
    """Verify release_workload fails closed if any node in the cluster returns an error."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    resolver = StubKeyResolver({"node-0": pub})
    signer = StubSigner()

    directive = QuarantineReleaseDirective(
        thread_id="t-multi-1",
        agent_svid="spiffe://cluster.local/ns/default/sa/agent-1",
        sandbox_id="sbx-1",
        quorum_approval_digest="a" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="corr-multi-1",
        nonce="nonce-multi-1",
        expected_min_epoch=1,
    )
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    # Node 0 succeeds with valid signature
    node0_body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 2,
        "released_at": datetime.now(timezone.utc).isoformat(),
        "envelope_digest": env_digest,
        "kid": "node-0",
    }
    node0_sig = priv.sign(
        QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(node0_body)
    )
    node0_body["signature"] = base64.urlsafe_b64encode(node0_sig).decode("ascii")
    node0_resp = httpx.Response(200, json=node0_body)

    # Node 1 fails with HTTP 500 error
    node1_resp = httpx.Response(
        500, json={"error": "Node 1 kernel firewall lock error"}
    )

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = [
        "https://node0",
        "https://node1",
    ]
    mock_transport.post_to_endpoints.return_value = [node0_resp, node1_resp]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.release_workload(directive)
    assert receipt.released is False
    assert receipt.outcome == ActuationOutcome.REJECTED
    assert any(f["code"] == "SUBSTRATE_ERROR_STATUS" for f in receipt.findings)


@pytest.mark.asyncio
async def test_release_workload_multinode_epoch_divergence_fails_closed():
    """Verify release_workload fails closed if nodes return divergent generation epochs."""
    priv0 = ed25519.Ed25519PrivateKey.generate()
    priv1 = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver(
        {"node-0": priv0.public_key(), "node-1": priv1.public_key()}
    )
    signer = StubSigner()

    directive = QuarantineReleaseDirective(
        thread_id="t-div-1",
        agent_svid="spiffe://cluster.local/ns/default/sa/agent-div",
        sandbox_id="sbx-div",
        quorum_approval_digest="b" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="corr-div-1",
        nonce="nonce-div-1",
        expected_min_epoch=1,
    )
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 2,
        "envelope_digest": env_digest,
        "kid": "node-0",
    }
    node0_body["signature"] = base64.urlsafe_b64encode(
        priv0.sign(
            QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(node0_body)
        )
    ).decode("ascii")

    # Node 1 returns epoch_after = 3 (split-brain divergence)
    node1_body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 3,
        "envelope_digest": env_digest,
        "kid": "node-1",
    }
    node1_body["signature"] = base64.urlsafe_b64encode(
        priv1.sign(
            QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(node1_body)
        )
    ).decode("ascii")

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = [
        "https://node0",
        "https://node1",
    ]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json=node0_body),
        httpx.Response(200, json=node1_body),
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.release_workload(directive)
    assert receipt.released is False
    assert receipt.outcome == ActuationOutcome.UNKNOWN
    assert any(f["code"] == "DIVERGENT_NODE_EPOCH" for f in receipt.findings)


@pytest.mark.asyncio
async def test_quarantine_workload_returns_unverified_when_unsigned():
    """Verify quarantine_workload stamps UNVERIFIED when receipts are not signed."""
    signer = StubSigner()
    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0"]

    directive = QuarantineDirective(
        thread_id="t-unver-1",
        agent_svid="spiffe://cluster.local/ns/default/sa/unver-agent",
        sandbox_id="sbx-unver",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="corr-unver-1",
        nonce="nonce-unver-1",
        governance_decision_digest="c" * 64,
        ttl_seconds=300,
    )
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    resp_body = {
        "status": "QUARANTINED",
        "rule_id": "kernel-rule-1",
        "envelope_digest": env_digest,
    }
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json=resp_body)
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=None,
        require_signed_receipts=False,
    )

    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.UNVERIFIED


@pytest.mark.asyncio
async def test_actuate_verifies_http_200():
    """Verify actuate fails closed when substrate returns non-200 HTTP status."""
    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0"]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(502, json={"error": "Bad Gateway"})
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=StubSigner(),
    )

    clearance = ExecutionClearance(
        thread_id="t-1",
        decision="ALLOW",
        decision_path="DIRECT",
        action="EXECUTE_TOOL",
        target="host",
        operator_urn="urn:op",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="corr-act-1",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        params={"cmd": "probe"},
    )

    receipt = await adapter.actuate(clearance)
    assert receipt.accepted is False
    assert receipt.outcome == ActuationOutcome.REJECTED
    assert any(f["code"] == "ACTUATION_ERROR_STATUS" for f in receipt.findings)


@pytest.mark.asyncio
async def test_actuate_awaits_verify_and_consume_seal_and_fails_closed_on_invalid():
    """Verify actuate() awaits verify_and_consume_seal and rejects invalid/replayed seals."""
    mock_transport = AsyncMock(spec=Actuator04Transport)
    adapter = Actuator04Adapter(transport=mock_transport, signer=StubSigner())

    clearance = ExecutionClearance(
        thread_id="t-seal-1",
        decision="ALLOW",
        decision_path="DIRECT",
        action="EXECUTE_TOOL",
        target="host",
        operator_urn="urn:op",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="corr-seal-1",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        params={"cmd": "probe"},
        routing_seal="forged.routing.seal",
    )

    with patch(
        "src.integrations.actuator_04.adapter.verify_and_consume_seal",
        new_callable=AsyncMock,
        side_effect=ValueError("seal replay rejected"),
    ) as mock_verify:
        receipt = await adapter.actuate(clearance)
        mock_verify.assert_awaited_once_with(
            "forged.routing.seal",
            "EXECUTE_TOOL",
            {"cmd": "probe"},
        )
    assert receipt.accepted is False
    assert receipt.outcome == ActuationOutcome.REJECTED
    assert any(f["code"] == "ROUTING_SEAL_INVALID" for f in receipt.findings)
    mock_transport.post_to_endpoints.assert_not_called()
