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

"""
Standalone unit test suite for cage-client SDK subpackage.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import tomllib

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Add standalone subpackage src directory to path for testing
subpackage_root = Path(__file__).parent.parent
subpackage_src = subpackage_root / "src"
if str(subpackage_src) not in sys.path:
    sys.path.insert(0, str(subpackage_src))

import cage_client
from cage_client import (
    CageClient,
    CageGatewayError,
    DeferralPending,
    GovernanceEnvelope,
    PolicyViolationException,
    RoutingSealVerificationError,
    cage_guard,
    generate_w3c_traceparent,
)
from cage_client.transport import create_mtls_transport


def _sample_top_level_envelope(**payload_overrides: Any) -> dict[str, Any]:
    """Return a canonical v3.0 top-level GovernanceEnvelope dictionary."""
    payload: dict[str, Any] = {"verdict": "ALLOW"}
    payload.update(payload_overrides)
    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-standalone-001",
        "issued_at": "2026-09-18T20:00:00+00:00",
        "expires_at": "2026-09-18T20:05:00+00:00",
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-001",
            "region": "us-central1",
        },
        "subject": {
            "action": "query_resource",
            "action_hash": "hash-abc",
            "record_hash": "rec-xyz-001",
            "agent_id": "agent-01",
        },
        "governance_context": {
            "policy_version": "1.0",
            "tiers_passed": ["stpa", "opa"],
        },
        "payload": payload,
        "external_attestations": [{"provider": "provider_01", "status": "VERIFIED"}],
        "signature": {
            "algorithm": "ES256",
            "value": "base64url-sig",
            "kid": "cage-kms-key-01",
        },
    }


async def _run_with_mock_handler(
    handler: Any,
    *,
    action: str = "query_resource",
    parameters: dict[str, Any] | None = None,
    agent_id: str = "agent-01",
) -> GovernanceEnvelope:
    """Execute CageClient.validate_action against an in-memory httpx.MockTransport."""
    client = CageClient(gateway_url="https://cage-standalone.example.test")
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://cage-standalone.example.test",
    )
    try:
        return await client.validate_action(
            action=action,
            parameters=parameters or {"limit": 10},
            agent_id=agent_id,
        )
    finally:
        await client.aclose()


def test_standalone_exports() -> None:
    """Verify all top-level symbols export correctly."""
    assert cage_client.__version__ == "0.2.0"
    assert cage_client.CageClient is CageClient
    assert cage_client.GovernanceEnvelope is GovernanceEnvelope
    assert cage_client.cage_guard is cage_guard
    assert issubclass(PolicyViolationException, CageGatewayError)
    assert issubclass(DeferralPending, CageGatewayError)
    assert issubclass(RoutingSealVerificationError, Exception)
    assert "verify_routing_seal" not in cage_client.__all__


def test_routing_seal_secret_rejected() -> None:
    """Verify CageClient v0.2.0 rejects removed routing_seal_secret parameter."""
    with pytest.raises(TypeError):
        CageClient(
            gateway_url="https://cage-gateway.example.com",
            routing_seal_secret="legacy-secret",  # type: ignore[call-arg]
        )


def test_w3c_traceparent_format() -> None:
    """Verify generated W3C traceparent matches specification."""
    tp = generate_w3c_traceparent()
    parts = tp.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32  # 16 bytes hex
    assert len(parts[2]) == 16  # 8 bytes hex
    assert parts[3] == "01"


def test_pyproject_drops_unused_cryptography_and_docs_state_unverified_signature() -> (
    None
):
    """Verify cage-client declares no unused cryptography dep and documents unverified signatures."""
    pyproject_data = tomllib.loads(
        (subpackage_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    runtime_deps = pyproject_data["project"]["dependencies"]
    assert not any("cryptography" in dep.lower() for dep in runtime_deps), (
        f"Unused cryptography dependency must not be declared in pyproject.toml: {runtime_deps}"
    )

    envelope_doc = GovernanceEnvelope.__doc__ or ""
    assert "does NOT verify" in envelope_doc
    assert "GovernanceEnvelope.signature" in envelope_doc
    assert "expires_at" in envelope_doc
    assert "does NOT substitute" in envelope_doc

    validate_doc = CageClient.validate_action.__doc__ or ""
    assert "does NOT verify" in validate_doc
    assert "does NOT substitute" in validate_doc

    allow_doc = CageClient._handle_allow_response.__doc__ or ""
    assert "does NOT verify" in allow_doc
    assert "does NOT substitute" in allow_doc

    readme_text = (subpackage_root / "README.md").read_text(encoding="utf-8")
    assert "does NOT verify `GovernanceEnvelope.signature`" in readme_text
    assert "does NOT substitute for end-to-end" in readme_text


def test_partial_mtls_cert_or_key_fails_closed() -> None:
    """Half-configured mTLS (cert without key or key without cert) raises ValueError (#533)."""
    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path="/nonexistent/cert.pem", key_path=None)

    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path=None, key_path="/nonexistent/key.pem")


def test_standalone_top_level_allow_and_extra_fields_forbidden() -> None:
    """Top-level ALLOW envelope with envelope_id/external_attestations parses; extra keys fail."""
    env_dict = _sample_top_level_envelope()
    del env_dict["signature"]  # Dev/test unsigned wire shape

    envelope = asyncio.run(
        _run_with_mock_handler(lambda req: httpx.Response(200, json=env_dict))
    )
    assert envelope.envelope_id == "env-standalone-001"
    assert envelope.signature is None
    assert envelope.external_attestations == [
        {"provider": "provider_01", "status": "VERIFIED"}
    ]

    extra_env = _sample_top_level_envelope()
    extra_env["unexpected_top_level_field"] = "forbidden"
    with pytest.raises(CageGatewayError, match="Failed to parse governance envelope"):
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=extra_env))
        )


def test_standalone_http_200_verdicts_mediated_fail_closed() -> None:
    """HTTP 200 NARROW, DENY, REQUIRE_APPROVAL, DEFER, and unknown verdicts mediate fail-closed (#484)."""
    # 1. NARROW -> PolicyViolationException(NARROWED)
    narrow_env = _sample_top_level_envelope(
        verdict="NARROW",
        narrowed_params={"limit": 5},
        violations=[
            {
                "tier": "cbf",
                "code": "CBF_CLAMP",
                "message": "clamped",
                "kind": "narrowable",
            }
        ],
    )
    with pytest.raises(PolicyViolationException) as narrow_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=narrow_env))
        )
    assert narrow_exc.value.reason_code == "NARROWED"
    assert narrow_exc.value.recoverable is True
    assert narrow_exc.value.violation_details["narrowed_params"] == {"limit": 5}

    # 2. DENY -> PolicyViolationException
    deny_env = _sample_top_level_envelope(
        verdict="DENY",
        violations=[
            {
                "tier": "cbf",
                "code": "CBF_HARD_STOP",
                "message": "blocked",
                "kind": "hard",
            }
        ],
    )
    with pytest.raises(PolicyViolationException) as deny_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=deny_env))
        )
    assert deny_exc.value.reason_code == "CBF_HARD_STOP"
    assert deny_exc.value.audit_id == "rec-xyz-001"

    # 3. REQUIRE_APPROVAL -> DeferralPending with deferred_id
    hitl_env = _sample_top_level_envelope(
        verdict="REQUIRE_APPROVAL",
        deferred_id="hitl-parked-001",
        classification_reason="hitl_violation",
    )
    with pytest.raises(DeferralPending) as hitl_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=hitl_env))
        )
    assert hitl_exc.value.ticket_id == "hitl-parked-001"
    assert hitl_exc.value.defer_reason == "hitl_violation"

    # 4. REQUIRE_APPROVAL with unpersisted deferred_id=None -> CageGatewayError (never envelope_id!)
    unpersisted_hitl_env = _sample_top_level_envelope(
        verdict="REQUIRE_APPROVAL",
        deferred_id=None,
        classification_reason="hitl_violation",
    )
    with pytest.raises(CageGatewayError, match="DEFER envelope missing required"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=unpersisted_hitl_env)
            )
        )

    # 5. Internal DEFER -> DeferralPending with defer_token
    defer_env = _sample_top_level_envelope(
        verdict="DEFER",
        defer_token="defer-tok-002",
        defer_reason="CONFIDENCE_BELOW_THRESHOLD",
        retry_after_seconds=300,
    )
    with pytest.raises(DeferralPending) as defer_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=defer_env))
        )
    assert defer_exc.value.ticket_id == "defer-tok-002"
    assert defer_exc.value.defer_reason == "CONFIDENCE_BELOW_THRESHOLD"
    assert defer_exc.value.ttl_seconds == 300

    # 6. Unknown verdict -> CageGatewayError
    unknown_env = _sample_top_level_envelope(verdict="ESCALATE")
    with pytest.raises(CageGatewayError, match="unrecognised verdict"):
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=unknown_env))
        )


def test_standalone_v2_refusal_403_and_v1_external_hold_202() -> None:
    """Canonical gateway 403 refusal (proof_hash) and 202 EXTERNAL_HOLD (defer_id) wire formats."""
    refusal_403 = {
        "schema_version": "2.0.0",
        "verdict": "DENIED",
        "violations": ["[CBF_LIMIT_BREACH] Threshold exceeded"],
        "proof_hash": "a" * 64,
        "refusal_receipt": {
            "violated_tier": "cbf",
            "violated_rule": "[CBF_LIMIT_BREACH] Threshold exceeded",
            "proof_hash": "a" * 64,
        },
    }
    with pytest.raises(PolicyViolationException) as refusal_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(403, json=refusal_403))
        )
    assert refusal_exc.value.audit_id == "a" * 64
    assert refusal_exc.value.reason_code == "CBF_LIMIT_BREACH"
    assert (
        refusal_exc.value.violation_details["refusal_receipt"]["proof_hash"] == "a" * 64
    )

    hold_202 = {
        "schema_version": "1.0.0",
        "defer_id": "ext-hold-777",
        "status": "pending_review",
        "poll_url": "/v1/defer/ext-hold-777",
        "verdict": "DEFER",
        "defer_reason": "EXTERNAL_HOLD",
        "ttl_seconds": 300,
    }
    with pytest.raises(DeferralPending) as hold_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(202, json=hold_202))
        )
    assert hold_exc.value.ticket_id == "ext-hold-777"
    assert hold_exc.value.defer_reason == "EXTERNAL_HOLD"
    assert hold_exc.value.ttl_seconds == 300
