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

"""Live integration tests for Actuator 01 (execution gateway).

Executes live mTLS requests against the Actuator 01 sandbox endpoint
when configured via environment variables.
"""

from __future__ import annotations

import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.gateway.governance.execution_actuator import (
    ActuationOutcome,
    ActuatorCapability,
    ExecutionClearance,
)
from src.integrations.actuator_01.adapter import Actuator01Adapter
from src.integrations.actuator_01.envelope_builder import build_and_canonicalize
from src.integrations.actuator_01.signatures import (
    SandboxSigningBundle,
    build_webauthn_approval,
)

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]

_REQUIRED_ENV_VARS = (
    "ACTUATOR_01_ENDPOINT",
    "ACTUATOR_01_CERT_PATH",
    "ACTUATOR_01_KEY_PATH",
    "ACTUATOR_01_CA_PATH",
    "ACTUATOR_01_TENANT_ID",
)

_DEFAULT_CERTS_DIR = (
    Path(__file__).resolve().parent.parent / "deployment" / "certs" / "actuator_01"
)


def _is_configured() -> bool:
    """Check if all required Actuator 01 live environment variables are set."""
    return all(os.environ.get(var, "").strip() for var in _REQUIRED_ENV_VARS)


def _load_optional_bundle() -> SandboxSigningBundle | None:
    """Load sandbox Ed25519 signing bundle from env or default cert directory if available."""
    keys_dir = os.environ.get("ACTUATOR_01_SIGNING_KEYS_DIR", "").strip()
    candidate = Path(keys_dir) if keys_dir else _DEFAULT_CERTS_DIR
    try:
        return SandboxSigningBundle.from_directory(candidate)
    except (FileNotFoundError, ValueError, KeyError):
        return None


def _operator_urns() -> list[str]:
    """Return ≥2 distinct operator URNs from CAGE_OPERATOR_URNS or sandbox defaults."""
    raw = os.environ.get("CAGE_OPERATOR_URNS", "").strip()
    if raw:
        urns = [u.strip() for u in raw.split(",") if u.strip()]
        if len(set(urns)) >= 2:
            return urns
    return [
        "urn:archytan:cage:operator:test-alice",
        "urn:archytan:cage:operator:test-bob",
    ]


def _skip_if_kms_inactive(findings: list[dict]) -> None:
    """Skip the test if actuation failed solely because KMS is not active locally."""
    for finding in findings:
        code = finding.get("code", "")
        detail = finding.get("detail", "")
        if code in ("ASSERTION_BUILD_FAILED", "QUORUM_SIGNING_FAILED") and (
            "KMS" in detail or "not active" in detail
        ):
            pytest.skip(f"KMS signer not active in test environment: {detail}")


@pytest.fixture
async def live_adapter() -> Actuator01Adapter:
    """Create a live Actuator 01 adapter instance from environment variables."""
    if not _is_configured():
        missing = [
            var for var in _REQUIRED_ENV_VARS if not os.environ.get(var, "").strip()
        ]
        pytest.skip(
            "Actuator 01 credentials not configured — missing: " + ", ".join(missing)
        )

    bundle = _load_optional_bundle()
    try:
        if bundle is not None:
            adapter = Actuator01Adapter.from_env(
                signer=bundle.assertion_signer,
                signer_resolver=bundle.resolve_signer,
                policy_signer=bundle.policy_signer,
            )
        else:
            adapter = Actuator01Adapter.from_env()
    except RuntimeError as exc:
        pytest.skip(f"Actuator 01 adapter initialization failed: {exc}")

    async with adapter:
        yield adapter


@pytest.mark.asyncio
async def test_live_health_check(live_adapter: Actuator01Adapter) -> None:
    """Verify live Actuator 01 mTLS health endpoint responds."""
    is_healthy = await live_adapter.health_check()
    assert is_healthy, (
        "Actuator 01 health check failed (check mTLS certs and KMS status)"
    )


@pytest.mark.asyncio
async def test_live_capabilities(live_adapter: Actuator01Adapter) -> None:
    """Verify Actuator 01 advertises expected security capabilities."""
    capabilities = live_adapter.get_capabilities()

    assert ActuatorCapability.MULTI_SIG_QUORUM in capabilities
    assert ActuatorCapability.MTLS_REQUIRED in capabilities
    assert ActuatorCapability.DIGEST_ONLY_PAYLOAD in capabilities
    assert ActuatorCapability.REPLAY_PROTECTED in capabilities


@pytest.mark.asyncio
async def test_live_wire_dispatch_roundtrip(
    live_adapter: Actuator01Adapter,
) -> None:
    """Verify live wire dispatch with v3.0 ESCALATE envelope schema and quorum signatures."""
    urns = _operator_urns()
    now_unix = int(time.time())
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    endpoint = os.environ["ACTUATOR_01_ENDPOINT"].strip()
    bundle = _load_optional_bundle()

    action = "test.wire.dispatch"
    target = "sandbox://test-target"
    if bundle is not None and bundle.approver_signer.is_kms_active:
        primary_approval = build_webauthn_approval(
            action=action,
            target=target,
            approver_urn=urns[0],
            webauthn_approver_urn=bundle.approver_urn,
            decision="ALLOW",
            issued_at=now_unix,
            approved_at_utc=now_iso,
            signer=bundle.approver_signer,
        )
    elif live_adapter._signer.is_kms_active:
        primary_approval = build_webauthn_approval(
            action=action,
            target=target,
            approver_urn=urns[0],
            decision="ALLOW",
            issued_at=now_unix,
            approved_at_utc=now_iso,
            signer=live_adapter._signer,
        )
    else:
        primary_approval = {
            "approver_urn": urns[0],
            "approved_at_utc": now_iso,
            "auth_method": "WEBAUTHN",
            "credential_id": "test-credential-alice",
            "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLi4uIn0",
            "authenticator_data": "dGVzdC1hdXRoLWRhdGEtYWxpY2U",
            "challenge_binding": "07" * 32,
            "signature": "dGVzdC1zaWduYXR1cmUtYWxpY2U",
        }

    clearance = ExecutionClearance(
        thread_id=f"test-live-thread-{secrets.token_hex(4)}",
        decision="ALLOW",
        decision_path="ESCALATE",
        action=action,
        target=target,
        operator_urn=urns[0],
        issued_at=now_unix,
        issued_at_provenance="CHALLENGE_TIME",
        correlation_id=str(uuid.uuid4()),
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce=secrets.token_hex(16),
        params={"test": True, "environment": "sandbox"},
        approvals=[
            primary_approval,
            {
                "approver_urn": urns[1],
                "approved_at_utc": now_iso,
                "auth_method": "WEBAUTHN",
                "auth_principal_hash": "e" * 64,
            },
        ],
        required_quorum=2,
        executor_id="actuator_01",
        target_route=endpoint,
        consequence_ceiling="LOW_INFORMATIONAL",
        ttl_seconds=30,
    )

    receipt = await live_adapter.actuate(clearance)

    if not receipt.accepted:
        _skip_if_kms_inactive(receipt.findings)
        pytest.fail(
            f"Actuation failed (outcome={receipt.outcome}): findings={receipt.findings}"
        )

    assert receipt.outcome is ActuationOutcome.ACCEPTED
    assert receipt.receipt_id, "Partner receipt_id should be present on ACCEPTED"
    assert receipt.envelope_digest and len(receipt.envelope_digest) == 64
    assert receipt.timestamp_utc, "Submission timestamp_utc should be present"


@pytest.mark.asyncio
async def test_live_jcs_canonicalization(
    live_adapter: Actuator01Adapter,
) -> None:
    """Verify RFC 8785 (JCS) canonical serialization and digest binding in wire format."""
    urns = _operator_urns()
    now_unix = int(time.time())
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    endpoint = os.environ["ACTUATOR_01_ENDPOINT"].strip()

    clearance = ExecutionClearance(
        thread_id=f"test-jcs-thread-{secrets.token_hex(4)}",
        decision="ALLOW",
        decision_path="DIRECT",
        action="test.canonical.serialize",
        target="sandbox://jcs-target",
        operator_urn=urns[0],
        issued_at=now_unix,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=str(uuid.uuid4()),
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="0" * 64,
        opa_input_digest="1" * 64,
        nonce=secrets.token_hex(16),
        params={"test": True},
        approvals=[
            {
                "approver_urn": urns[0],
                "approved_at_utc": now_iso,
                "signature": "sig-alice",
            },
            {
                "approver_urn": urns[1],
                "approved_at_utc": now_iso,
                "signature": "sig-bob",
            },
        ],
        required_quorum=2,
        executor_id="actuator_01",
        target_route=endpoint,
        consequence_ceiling="LOW_INFORMATIONAL",
        ttl_seconds=30,
    )

    canonical_bytes, expected_digest = build_and_canonicalize(
        clearance, policy_signer=live_adapter._policy_signer
    )
    assert len(canonical_bytes) <= 4096
    assert len(expected_digest) == 64
    assert b'"approval"' not in canonical_bytes

    receipt = await live_adapter.actuate(clearance)
    assert receipt.envelope_digest == expected_digest

    if not receipt.accepted:
        _skip_if_kms_inactive(receipt.findings)
        pytest.fail(
            f"Unexpected failure during JCS live dispatch (outcome={receipt.outcome}): "
            f"findings={receipt.findings}"
        )


@pytest.mark.asyncio
async def test_live_negative_target_route_mismatch(
    live_adapter: Actuator01Adapter,
) -> None:
    """Verify Gate 2 rejects a mismatched target_route fail-closed before wire dispatch."""
    urns = _operator_urns()
    now_unix = int(time.time())
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    clearance = ExecutionClearance(
        thread_id="test-live-route-mismatch",
        decision="ALLOW",
        decision_path="DIRECT",
        action="test.wire.dispatch",
        target="sandbox://test-target",
        operator_urn=urns[0],
        issued_at=now_unix,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=str(uuid.uuid4()),
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce=secrets.token_hex(16),
        params={"test": True},
        approvals=[
            {"approver_urn": urns[0], "approved_at_utc": now_iso, "signature": "sig-1"},
            {"approver_urn": urns[1], "approved_at_utc": now_iso, "signature": "sig-2"},
        ],
        required_quorum=2,
        executor_id="actuator_01",
        target_route="https://unauthorized-route.example.invalid",
        consequence_ceiling="LOW_INFORMATIONAL",
        ttl_seconds=30,
    )

    receipt = await live_adapter.actuate(clearance)

    assert receipt.accepted is False
    assert receipt.outcome is ActuationOutcome.REJECTED
    assert any(f.get("code") == "TARGET_ROUTE_MISMATCH" for f in receipt.findings), (
        f"Expected TARGET_ROUTE_MISMATCH finding, got {receipt.findings}"
    )
