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

"""Staged over-the-wire conformance suite for Actuator 03 (POAM-2026-166).

Exercises the out-of-band hardware DPU quarantine contract over mTLS:
``GET /health``, ``POST /v1/dpu/quarantine`` signed with
``CAGE_QUARANTINE_ASSERTION_V1:`` and ``X-CAGE-Envelope-Digest``, detached
Ed25519 receipt verification via ``Ed25519KeyManifestClient``
(``CAGE_QUARANTINE_RECEIPT_V1:``), and mutual exclusion between
``refusal_proof_hash`` (refusal-triggered directives) and
``governance_decision_digest`` (clearance-bridged directives).

Partner harness staging note (POAM-2026-166):
    The partner DPU quarantine sandbox endpoint and CI secrets are not yet
    provisioned, so this module carries ``live_external`` and ``partner``
    without the ``partner_integration`` marker (matching the staged pattern in
    ``tests/integrations/provider_05/test_provider_05_blueprint_live.py``).
    Adding ``partner_integration`` together with ``PARTNER_TARGETS`` and
    ``PROVISIONED_PARTNERS`` registration happens atomically at
    ``POAM-2026-166`` sandbox cutover so ``require_live`` never fails an
    unprovisioned job and ``tests/test_partner_harness.py`` stays in lockstep.

Non-KMS wire-conformance signing mode:
    Quarantine assertions are minted on CAGE's side of the boundary. When
    ``KMS_GOVERNANCE_KEY`` is unset, this suite signs assertions with either an
    explicit 32-byte Ed25519 seed from ``ACTUATOR_03_SIGNING_KEY_HEX`` or a
    run-local ``SoftwareEd25519Provider`` key so wire conformance does not
    depend on runner Cloud KMS credentials (matching ``test_provider_01_live.py``).
    An assertion minted in software fallback mode is never KMS evidence.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import ssl
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineTriggerReason,
)
from src.integrations.actuator_03.adapter import Actuator03Adapter
from src.integrations.actuator_03.constants import QUARANTINE_ASSERTION_DOMAIN_TAG
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient

pytestmark = [
    pytest.mark.live_external,
    pytest.mark.partner,
]

REQUIRED_ENV_VARS: tuple[str, ...] = (
    "ACTUATOR_03_ENDPOINT",
    "ACTUATOR_03_CERT_PATH",
    "ACTUATOR_03_KEY_PATH",
    "ACTUATOR_03_CA_PATH",
    "ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL",
)

_HTTP_TIMEOUT_SECONDS = 10.0
_INITIAL_KMS_GOVERNANCE_KEY = os.environ.get("KMS_GOVERNANCE_KEY", "").strip()
_RUN_LOCAL_SIGNER: KMSGovernanceSigner | None = None


@dataclass(frozen=True)
class Actuator03LiveConfig:
    """Resolved live sandbox configuration for Actuator 03."""

    endpoint: str
    cert_path: str
    key_path: str
    ca_path: str
    receipt_key_manifest_url: str


def load_live_config_or_skip() -> Actuator03LiveConfig:
    """Read required Actuator 03 sandbox variables or skip for ``require_live``."""
    values = {name: os.environ.get(name, "").strip() for name in REQUIRED_ENV_VARS}
    missing = [name for name, value in values.items() if not value]
    if missing:
        pytest.skip(
            "Actuator 03 live credentials not configured — missing: "
            + ", ".join(missing)
        )
    return Actuator03LiveConfig(
        endpoint=values["ACTUATOR_03_ENDPOINT"].rstrip("/"),
        cert_path=values["ACTUATOR_03_CERT_PATH"],
        key_path=values["ACTUATOR_03_KEY_PATH"],
        ca_path=values["ACTUATOR_03_CA_PATH"],
        receipt_key_manifest_url=values["ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL"],
    )


def resolve_live_signer() -> RawMessageSigner:
    """Resolve KMS governance signer or non-KMS Ed25519 wire-conformance fallback."""
    global _RUN_LOCAL_SIGNER

    seed_hex = os.environ.get("ACTUATOR_03_SIGNING_KEY_HEX", "").strip()
    if seed_hex:
        try:
            seed_bytes = bytes.fromhex(seed_hex)
            priv_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        except ValueError as exc:
            raise ValueError(
                "ACTUATOR_03_SIGNING_KEY_HEX must be 64 hex chars (32-byte Ed25519 seed)"
            ) from exc
        return KMSGovernanceSigner(
            provider=SoftwareEd25519Provider(
                key_id="actuator-03-live-seed",
                private_key=priv_key,
            )
        )

    kms_key = (
        os.environ.get("KMS_GOVERNANCE_KEY", "").strip() or _INITIAL_KMS_GOVERNANCE_KEY
    )
    if kms_key:
        prev = os.environ.get("KMS_GOVERNANCE_KEY")
        os.environ["KMS_GOVERNANCE_KEY"] = kms_key
        try:
            return KMSGovernanceSigner.from_env()
        finally:
            if prev is None:
                os.environ.pop("KMS_GOVERNANCE_KEY", None)
            else:
                os.environ["KMS_GOVERNANCE_KEY"] = prev

    if _RUN_LOCAL_SIGNER is None:
        _RUN_LOCAL_SIGNER = KMSGovernanceSigner(
            provider=SoftwareEd25519Provider(key_id="actuator-03-live-run")
        )
    return _RUN_LOCAL_SIGNER


def build_live_http_client(config: Actuator03LiveConfig) -> httpx.AsyncClient:
    """Construct an mTLS-configured httpx.AsyncClient from live certificate paths."""
    ssl_ctx = ssl.create_default_context(cafile=config.ca_path)
    ssl_ctx.load_cert_chain(certfile=config.cert_path, keyfile=config.key_path)
    return httpx.AsyncClient(verify=ssl_ctx, timeout=_HTTP_TIMEOUT_SECONDS)


@pytest.fixture
def live_config() -> Actuator03LiveConfig:
    """Provide validated Actuator 03 live sandbox configuration."""
    return load_live_config_or_skip()


@pytest.fixture
def live_signer(live_config: Actuator03LiveConfig) -> RawMessageSigner:
    """Provide the assertion signer for live wire requests."""
    del live_config
    return resolve_live_signer()


@pytest.fixture
async def live_http_client(
    live_config: Actuator03LiveConfig,
) -> AsyncIterator[httpx.AsyncClient]:
    """Provide a live mTLS HTTP client closed cleanly on teardown."""
    client = build_live_http_client(live_config)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def live_manifest_client(
    live_config: Actuator03LiveConfig,
) -> Ed25519KeyManifestClient:
    """Provide an out-of-band Ed25519 receipt key manifest client."""
    return Ed25519KeyManifestClient(
        live_config.receipt_key_manifest_url,
        timeout_seconds=_HTTP_TIMEOUT_SECONDS,
    )


@pytest.fixture
def live_adapter(
    live_config: Actuator03LiveConfig,
    live_signer: RawMessageSigner,
    live_http_client: httpx.AsyncClient,
    live_manifest_client: Ed25519KeyManifestClient,
) -> Actuator03Adapter:
    """Construct Actuator03Adapter with mandatory detached receipt verification."""
    return Actuator03Adapter(
        endpoint=live_config.endpoint,
        signer=live_signer,
        http_client=live_http_client,
        receipt_key_resolver=live_manifest_client,
        require_signed_receipts=True,
    )


async def _post_signed_raw_quarantine_body(
    *,
    endpoint: str,
    http_client: httpx.AsyncClient,
    signer: RawMessageSigner,
    body: dict[str, Any],
) -> httpx.Response:
    """Sign an arbitrary JSON object with CAGE_QUARANTINE_ASSERTION_V1: and POST it."""
    canonical_bytes = jcs_canonicalize_plan(body)
    envelope_digest = hashlib.sha256(canonical_bytes).hexdigest()
    sig_bytes = await signer.sign_raw_async(
        QUARANTINE_ASSERTION_DOMAIN_TAG + canonical_bytes
    )
    assertion_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii")
    headers = {
        "Content-Type": "application/json",
        "X-CAGE-Envelope-Digest": envelope_digest,
        "X-CAGE-Quarantine-Assertion": assertion_b64,
        "X-CAGE-Correlation-ID": str(body["correlation_id"]),
    }
    return await http_client.post(
        f"{endpoint}/v1/dpu/quarantine",
        content=canonical_bytes,
        headers=headers,
    )


@pytest.mark.asyncio
async def test_live_health_and_receipt_key_manifest(
    live_adapter: Actuator03Adapter,
    live_manifest_client: Ed25519KeyManifestClient,
) -> None:
    """Verify GET /health responds 200 and the receipt manifest yields Ed25519 OKP keys."""
    is_healthy = await live_adapter.health_check()
    assert is_healthy is True, "Actuator 03 GET /health check failed over mTLS"

    capabilities = live_adapter.get_capabilities()
    assert ActuatorCapability.MTLS_REQUIRED in capabilities
    assert ActuatorCapability.REPLAY_PROTECTED in capabilities
    assert ActuatorCapability.DIGEST_ONLY_PAYLOAD in capabilities
    assert ActuatorCapability.SIGNED_RECEIPTS in capabilities

    # Trigger manifest refresh and verify at least one Ed25519 OKP key resolves by kid,
    # while an unknown kid fails closed (None).
    unknown_key = await live_manifest_client.get_key(
        f"nonexistent-kid-{uuid.uuid4().hex}"
    )
    assert unknown_key is None

    discovered_kids = list(live_manifest_client._key_cache)
    assert len(discovered_kids) >= 1, (
        "Expected at least one valid Ed25519 OKP key in ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL"
    )
    for kid in discovered_kids:
        resolved = await live_manifest_client.get_key(kid)
        assert isinstance(resolved, Ed25519PublicKey), (
            f"Manifest kid={kid!r} did not resolve to an Ed25519PublicKey"
        )


@pytest.mark.asyncio
async def test_live_refusal_triggered_quarantine_directive(
    live_adapter: Actuator03Adapter,
) -> None:
    """Verify refusal-triggered QuarantineDirective (refusal_proof_hash only) yields a VERIFIED receipt."""
    refusal_hash = hashlib.sha256(
        f"refusal-receipt-{uuid.uuid4()}".encode()
    ).hexdigest()
    directive = QuarantineDirective(
        thread_id=f"thread-live-refusal-{secrets.token_hex(4)}",
        agent_svid="spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
        sandbox_id=f"sbx-refusal-{secrets.token_hex(4)}",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_SAFETY_BARRIER_BREACH",),
        issued_at=int(time.time()),
        correlation_id=str(uuid.uuid4()),
        refusal_proof_hash=refusal_hash,
        nonce=secrets.token_hex(16),
        ttl_seconds=300,
    )

    wire_dict = directive.to_dict()
    assert wire_dict.get("refusal_proof_hash") == refusal_hash
    assert "governance_decision_digest" not in wire_dict
    expected_digest = hashlib.sha256(jcs_canonicalize_plan(wire_dict)).hexdigest()

    receipt: QuarantineReceipt = await live_adapter.quarantine_workload(directive)

    assert receipt.outcome is ActuationOutcome.ACCEPTED, (
        f"Refusal-triggered quarantine failed (outcome={receipt.outcome}, "
        f"verification={receipt.verification}, findings={receipt.findings})"
    )
    assert receipt.quarantined is True
    assert receipt.verification is ReceiptVerification.VERIFIED
    assert isinstance(receipt.rule_id, str) and bool(receipt.rule_id.strip())
    assert receipt.enforcement_plane == "IN_SILICON_DPU"
    assert receipt.envelope_digest == expected_digest
    assert receipt.findings == []


@pytest.mark.asyncio
async def test_live_clearance_bridged_quarantine_actuation(
    live_adapter: Actuator03Adapter,
) -> None:
    """Verify clearance-bridged actuate() (governance_decision_digest only) yields a VERIFIED receipt."""
    seal_digest = hashlib.sha256(f"routing-seal-{uuid.uuid4()}".encode()).hexdigest()
    opa_digest = hashlib.sha256(f"opa-input-{uuid.uuid4()}".encode()).hexdigest()
    nonce = secrets.token_hex(16)
    sandbox_id = f"sbx-clearance-{secrets.token_hex(4)}"

    clearance = ExecutionClearance(
        thread_id=f"thread-live-clearance-{secrets.token_hex(4)}",
        decision="ALLOW",
        decision_path="DIRECT",
        action="quarantine.isolate_workload",
        target=sandbox_id,
        operator_urn="spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=str(uuid.uuid4()),
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest=seal_digest,
        opa_input_digest=opa_digest,
        nonce=nonce,
        params={
            "sandbox_id": sandbox_id,
            "violation_codes": ["CBF_BREACH"],
        },
        executor_id="actuator_03",
        ttl_seconds=30,
    )

    expected_bridged_directive = QuarantineDirective(
        thread_id=clearance.thread_id,
        agent_svid=clearance.operator_urn,
        sandbox_id=sandbox_id,
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BREACH",),
        issued_at=clearance.issued_at,
        correlation_id=clearance.correlation_id,
        governance_decision_digest=seal_digest,
        nonce=nonce,
        ttl_seconds=clearance.ttl_seconds,
    )
    bridged_dict = expected_bridged_directive.to_dict()
    assert bridged_dict.get("governance_decision_digest") == seal_digest
    assert "refusal_proof_hash" not in bridged_dict
    expected_digest = hashlib.sha256(jcs_canonicalize_plan(bridged_dict)).hexdigest()

    receipt: ActuationReceipt = await live_adapter.actuate(clearance)

    assert receipt.outcome is ActuationOutcome.ACCEPTED, (
        f"Clearance-bridged quarantine actuation failed (outcome={receipt.outcome}, "
        f"verification={receipt.verification}, findings={receipt.findings})"
    )
    assert receipt.accepted is True
    assert receipt.verification is ReceiptVerification.VERIFIED
    assert isinstance(receipt.receipt_id, str) and bool(receipt.receipt_id.strip())
    assert receipt.session_uuid == nonce
    assert receipt.envelope_digest == expected_digest
    assert receipt.findings == []


@pytest.mark.asyncio
async def test_live_partner_rejects_malformed_dual_or_missing_digest_wire_body(
    live_config: Actuator03LiveConfig,
    live_http_client: httpx.AsyncClient,
    live_signer: RawMessageSigner,
) -> None:
    """Verify partner endpoint rejects signed directives carrying neither or both decision digests."""
    now_unix = int(time.time())
    missing_digest_body: dict[str, Any] = {
        "thread_id": f"thread-live-malformed-none-{secrets.token_hex(4)}",
        "agent_svid": "spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
        "sandbox_id": "sbx-malformed-none",
        "reason": QuarantineTriggerReason.CRITICAL_CBF_BREACH.value,
        "violation_codes": ["CBF_SAFETY_BARRIER_BREACH"],
        "issued_at": now_unix,
        "correlation_id": str(uuid.uuid4()),
        "nonce": secrets.token_hex(16),
        "ttl_seconds": 300,
    }
    dual_digest_body: dict[str, Any] = {
        "thread_id": f"thread-live-malformed-both-{secrets.token_hex(4)}",
        "agent_svid": "spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
        "sandbox_id": "sbx-malformed-both",
        "reason": QuarantineTriggerReason.CRITICAL_CBF_BREACH.value,
        "violation_codes": ["CBF_SAFETY_BARRIER_BREACH"],
        "issued_at": now_unix,
        "correlation_id": str(uuid.uuid4()),
        "refusal_proof_hash": hashlib.sha256(b"malformed-dual-refusal").hexdigest(),
        "governance_decision_digest": hashlib.sha256(
            b"malformed-dual-clearance-seal"
        ).hexdigest(),
        "nonce": secrets.token_hex(16),
        "ttl_seconds": 300,
    }

    missing_resp = await _post_signed_raw_quarantine_body(
        endpoint=live_config.endpoint,
        http_client=live_http_client,
        signer=live_signer,
        body=missing_digest_body,
    )
    assert missing_resp.status_code in (400, 422), (
        "Partner endpoint must refuse a signed directive missing both "
        "refusal_proof_hash and governance_decision_digest with HTTP 400/422; "
        f"got HTTP {missing_resp.status_code} ({missing_resp.text!r})"
    )

    dual_resp = await _post_signed_raw_quarantine_body(
        endpoint=live_config.endpoint,
        http_client=live_http_client,
        signer=live_signer,
        body=dual_digest_body,
    )
    assert dual_resp.status_code in (400, 422), (
        "Partner endpoint must refuse a signed directive carrying both "
        "refusal_proof_hash and governance_decision_digest with HTTP 400/422; "
        f"got HTTP {dual_resp.status_code} ({dual_resp.text!r})"
    )
