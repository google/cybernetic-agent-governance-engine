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

"""Adversarial stress harness for actuator_04 mathematical SSRF, multi-node quorum, and attestation freshness."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import time
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    QuarantineReleaseDirective,
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

    def __init__(self, key_id: str = "cage-test-signer") -> None:
        self.key_id = key_id

    async def sign_raw_async(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest() * 2


def make_directive() -> QuarantineReleaseDirective:
    return QuarantineReleaseDirective(
        thread_id="t-test-1",
        agent_svid="spiffe://cluster.local/ns/default/sa/agent-test",
        sandbox_id="sbx-test",
        quorum_approval_digest="d" * 64,
        quorum_count=2,
        issued_at=int(time.time()),
        correlation_id="corr-test-1",
        nonce="nonce-test-1",
        expected_min_epoch=1,
    )


def make_signed_node_body(
    priv: ed25519.Ed25519PrivateKey,
    kid: str,
    env_digest: str,
    epoch_before: int,
    epoch_after: int,
) -> dict[str, Any]:
    body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": epoch_before,
        "epoch_after": epoch_after,
        "released_at": datetime.now(timezone.utc).isoformat(),
        "envelope_digest": env_digest,
        "kid": kid,
    }
    sig = priv.sign(QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(body))
    body["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")
    return body


# ===========================================================================
# 1. MATHEMATICAL SSRF ADVERSARIAL VECTORS
# ===========================================================================

@pytest.mark.parametrize(
    ("url", "allow_loopback", "env", "should_block", "desc"),
    [
        # a) Decimal integer IP hostnames
        ("http://2130706433:8080", False, "dev", True, "Decimal integer loopback in dev"),
        ("https://2130706433:8080", False, "production", True, "Decimal integer loopback in prod"),
        ("http://2852039166:8080", False, "dev", True, "Decimal integer metadata in dev"),
        ("https://2852039166:8080", False, "production", True, "Decimal integer metadata in prod"),
        ("http://0:8080", False, "dev", True, "Decimal zero current network in dev"),
        ("https://0:8080", False, "production", True, "Decimal zero current network in prod"),

        # b) Octal IP hostnames
        ("http://0177.0.0.1:8080", False, "dev", True, "Octal loopback in dev"),
        ("https://0177.0.0.1:8080", False, "production", True, "Octal loopback in prod"),
        ("http://0177.0.0.01:8080", False, "dev", True, "Octal quad with leading 0 in dev"),
        ("https://0177.0.0.01:8080", False, "production", True, "Octal quad with leading 0 in prod"),
        ("http://0251.0376.0251.0376:8080", False, "dev", True, "Octal metadata in dev"),
        ("https://0251.0376.0251.0376:8080", False, "production", True, "Octal metadata in prod"),

        # c) Hex IP hostnames
        ("http://0x7f.0.0.1:8080", False, "dev", True, "Hex dotted quad in dev"),
        ("https://0x7f.0.0.1:8080", False, "production", True, "Hex dotted quad in prod"),
        ("http://0x7f000001:8080", False, "dev", True, "Hex single integer loopback in dev"),
        ("https://0x7f000001:8080", False, "production", True, "Hex single integer loopback in prod"),
        ("http://0xa9fea9fe:8080", False, "dev", True, "Hex single integer metadata in dev"),
        ("https://0xa9fea9fe:8080", False, "production", True, "Hex single integer metadata in prod"),

        # d) Mixed octal/hex/decimal quads
        ("http://127.0.0x0.1:8080", False, "dev", True, "Mixed hex/decimal loopback in dev"),
        ("https://127.0.0x0.1:8080", False, "production", True, "Mixed hex/decimal loopback in prod"),
        ("http://0177.0.0x0.1:8080", False, "dev", True, "Mixed octal/hex/decimal loopback in dev"),
        ("https://0177.0.0x0.1:8080", False, "production", True, "Mixed octal/hex/decimal loopback in prod"),

        # e) IPv4-mapped IPv6 literals
        ("http://[::ffff:127.0.0.1]:8080", False, "dev", True, "IPv4-mapped IPv6 loopback in dev"),
        ("https://[::ffff:127.0.0.1]:8080", False, "production", True, "IPv4-mapped IPv6 loopback in prod"),
        ("http://[::ffff:7f00:1]:8080", False, "dev", True, "IPv4-mapped IPv6 hex loopback in dev"),
        ("https://[::ffff:7f00:1]:8080", False, "production", True, "IPv4-mapped IPv6 hex loopback in prod"),
        ("http://[::ffff:169.254.169.254]:8080", False, "dev", True, "IPv4-mapped IPv6 metadata in dev"),
        ("https://[::ffff:169.254.169.254]:8080", False, "production", True, "IPv4-mapped IPv6 metadata in prod"),
        ("http://[::ffff:a9fe:a9fe]:8080", False, "dev", True, "IPv4-mapped IPv6 hex metadata in dev"),
        ("https://[::ffff:a9fe:a9fe]:8080", False, "production", True, "IPv4-mapped IPv6 hex metadata in prod"),

        # f) Loopback/link-local IPv6
        ("http://[::1]:8080", False, "dev", True, "IPv6 loopback in dev (allow_loopback=False)"),
        ("http://[::1]:8080", True, "dev", False, "IPv6 loopback in dev (allow_loopback=True)"),
        ("https://[::1]:8080", False, "production", True, "IPv6 loopback in prod (allow_loopback=False)"),
        ("https://[::1]:8080", True, "production", True, "IPv6 loopback in prod (allow_loopback=True)"),
        ("http://[fe80::1]:8080", False, "dev", True, "IPv6 link-local in dev"),
        ("https://[fe80::1]:8080", False, "production", True, "IPv6 link-local in prod"),

        # g) DNS rebinding hostnames
        ("http://169.254.169.254.nip.io:8080", False, "dev", True, "DNS rebinding metadata in dev"),
        ("https://169.254.169.254.nip.io:8080", False, "production", True, "DNS rebinding metadata in prod"),
        ("http://127.0.0.1.nip.io:8080", False, "dev", True, "DNS rebinding loopback in dev"),
        ("https://127.0.0.1.nip.io:8080", False, "production", True, "DNS rebinding loopback in prod"),

        # h) Valid public hosts (must be admitted)
        ("https://example.com:443", False, "production", False, "Valid public domain in prod"),
        ("https://example.com:443", False, "dev", False, "Valid public domain in dev"),
        ("http://example.com:80", False, "dev", False, "Valid public domain over http in dev"),
        ("https://8.8.8.8:443", False, "production", False, "Valid public IP 8.8.8.8 in prod"),
        ("https://198.51.100.1:443", False, "dev", False, "Test net IP admitted in dev"),
    ],
)
def test_ssrf_adversarial_vectors(
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
    assert blocked == should_block, f"SSRF vector failed: {desc} (expected_block={should_block}, got_blocked={blocked})"


# ===========================================================================
# 2. MULTI-NODE FAN-OUT QUORUM & CONSENSUS TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_multinode_2a_secondary_node_http_500_fails_closed():
    """2a: Primary node returns 200, but secondary node returns HTTP 500 -> released=False."""
    priv = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver({"node-0": priv.public_key()})
    signer = StubSigner()
    directive = make_directive()
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = make_signed_node_body(priv, "node-0", env_digest, 1, 2)
    node1_resp = httpx.Response(500, json={"error": "Node 1 kernel fault"})

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json=node0_body),
        node1_resp,
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    receipt = await adapter.release_workload(directive)
    assert receipt.released is False
    assert receipt.outcome == ActuationOutcome.REJECTED
    assert receipt.verification == ReceiptVerification.UNVERIFIED
    assert any(f["code"] == "SUBSTRATE_ERROR_STATUS" for f in receipt.findings)


@pytest.mark.asyncio
async def test_multinode_2b_split_brain_epoch_divergence_fails_closed():
    """2b: Primary returns 1->2, secondary returns 1->3 (split-brain) -> released=False."""
    priv0 = ed25519.Ed25519PrivateKey.generate()
    priv1 = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver({"node-0": priv0.public_key(), "node-1": priv1.public_key()})
    signer = StubSigner()
    directive = make_directive()
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = make_signed_node_body(priv0, "node-0", env_digest, 1, 2)
    node1_body = make_signed_node_body(priv1, "node-1", env_digest, 1, 3)

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
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
@pytest.mark.parametrize("require_signed", [True, False])
async def test_multinode_2c_invalid_ed25519_signature_fails_closed_no_crash(require_signed: bool):
    """2c: Node returns invalid Ed25519 signature -> verification=INVALID and released=False without crash."""
    priv0 = ed25519.Ed25519PrivateKey.generate()
    priv1 = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver({"node-0": priv0.public_key(), "node-1": priv1.public_key()})
    signer = StubSigner()
    directive = make_directive()
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = make_signed_node_body(priv0, "node-0", env_digest, 1, 2)
    node1_body = make_signed_node_body(priv1, "node-1", env_digest, 1, 2)
    # Corrupt node1 signature
    node1_body["signature"] = base64.urlsafe_b64encode(b"X" * 64).decode("ascii")

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json=node0_body),
        httpx.Response(200, json=node1_body),
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=require_signed,
    )

    # Must complete cleanly without unhandled ValueError
    receipt = await adapter.release_workload(directive)
    assert receipt.released is False
    assert receipt.verification == ReceiptVerification.INVALID
    assert receipt.outcome == ActuationOutcome.UNKNOWN


@pytest.mark.asyncio
async def test_multinode_2d_unsigned_receipts_return_unverified():
    """2d: Nodes return unsigned receipts (non-strict) -> released=True, verification=UNVERIFIED."""
    signer = StubSigner()
    directive = make_directive()
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 2,
        "envelope_digest": env_digest,
    }
    node1_body = {
        "status": "RELEASED",
        "released": True,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 2,
        "envelope_digest": env_digest,
    }

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json=node0_body),
        httpx.Response(200, json=node1_body),
    ]

    adapter = Actuator04Adapter(
        transport=mock_transport,
        signer=signer,
        receipt_key_resolver=None,
        require_signed_receipts=False,
    )

    receipt = await adapter.release_workload(directive)
    assert receipt.released is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.UNVERIFIED


@pytest.mark.asyncio
async def test_multinode_2e_all_nodes_matching_verified_receipts():
    """2e: All nodes return matching verified receipts -> released=True, verification=VERIFIED."""
    priv0 = ed25519.Ed25519PrivateKey.generate()
    priv1 = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver({"node-0": priv0.public_key(), "node-1": priv1.public_key()})
    signer = StubSigner()
    directive = make_directive()
    env_digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

    node0_body = make_signed_node_body(priv0, "node-0", env_digest, 1, 2)
    node1_body = make_signed_node_body(priv1, "node-1", env_digest, 1, 2)

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
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
    assert receipt.released is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED
    assert receipt.epoch_before == 1
    assert receipt.epoch_after == 2


@pytest.mark.asyncio
async def test_multinode_actuate_partial_failure_fails_closed():
    """Verify actuate fails closed when any node in cluster returns non-200."""
    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node0", "https://node1"]
    mock_transport.post_to_endpoints.return_value = [
        httpx.Response(200, json={"receipt_id": "r1", "session_uuid": "s1"}),
        httpx.Response(503, json={"error": "Service Unavailable"}),
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
        correlation_id="corr-act-multi",
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


# ===========================================================================
# 3. ATTESTATION TIMESTAMP FRESHNESS ADVERSARIAL TESTS
# ===========================================================================

def make_signed_attestation(
    priv: ed25519.Ed25519PrivateKey,
    kid: str,
    timestamp_utc: str,
    tpm_quote: str = "sha256:1111111111111111111111111111111111111111111111111111111111111111",
) -> dict[str, Any]:
    body = {
        "attestation_type": "HOST_TPM_PCR",
        "ring0_posture": "ACTIVE_RING0_ENFORCED",
        "tpm_pcr_quote": tpm_quote,
        "pcr_values": {"0": "1111"},
        "timestamp_utc": timestamp_utc,
        "kid": kid,
        "envelope_digest": tpm_quote,
    }
    preimage = ATTESTATION_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(body)
    sig = priv.sign(preimage)
    body["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("offset_seconds", "should_pass", "desc"),
    [
        # Stale quotes
        (-301, False, "Stale quote 301 seconds ago"),
        (-600, False, "Stale quote 10 minutes ago"),
        (-86400, False, "Stale quote 1 day ago"),
        (-86400 * 365 * 6, False, "Stale quote 6 years ago"),
        # Future quotes (clock skew)
        (301, False, "Future quote 301 seconds ahead"),
        (3600, False, "Future quote 1 hour ahead"),
        # Fresh quotes (within ±300s window)
        (0, True, "Fresh quote exactly now (0s skew)"),
        (-100, True, "Fresh quote 100 seconds ago"),
        (100, True, "Fresh quote 100 seconds ahead"),
        (-299, True, "Fresh quote 299 seconds ago (boundary)"),
        (299, True, "Fresh quote 299 seconds ahead (boundary)"),
    ],
)
async def test_attestation_timestamp_freshness(offset_seconds: int, should_pass: bool, desc: str):
    priv = ed25519.Ed25519PrivateKey.generate()
    resolver = StubKeyResolver({"node-att": priv.public_key()})

    ts = (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()
    tpm_quote = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    body = make_signed_attestation(priv, "node-att", ts, tpm_quote)

    mock_transport = AsyncMock(spec=Actuator04Transport)
    mock_transport.resolve_target_endpoints.return_value = ["https://node-att"]
    mock_transport.get_from_endpoints.return_value = [httpx.Response(200, json=body)]

    provider = Actuator04AttestationProvider(
        transport=mock_transport,
        expected_pcr_quote=tpm_quote,
        receipt_key_resolver=resolver,
    )

    results = await provider.fetch_attestations({})
    assert len(results) == 1
    att = results[0]

    if should_pass:
        assert att.status == AttestationStatus.VERIFIED.value, f"Failed on {desc}: status={att.status}, metadata={att.metadata}"
    else:
        assert att.status == AttestationStatus.ERROR.value, f"Failed on {desc}: expected ERROR, got {att.status}"
        assert att.metadata.get("code") == "ATTESTATION_TIMESTAMP_STALE", f"Failed on {desc}: expected ATTESTATION_TIMESTAMP_STALE, got {att.metadata}"
