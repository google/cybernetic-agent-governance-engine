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

"""Hermetic and live-ASGI contract suite for CageClient SDK core functionality.

Includes respx transport-level tests, cryptographic envelope verification and
JWKS trust-anchor tests, RFC 8785 JCS parity checks against the kernel
canonicalizer, and live FastAPI ASGI tests mounting the real ``governance_app``
at ``/governance`` (with real EC P-256 ``ES256`` and ``SoftwareEd25519Provider``
``EdDSA`` signing + ``GET /governance/.well-known/jwks.json``) across both
``src.gateway.client`` and standalone ``cage_client``.
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils
from fastapi import FastAPI

from src.gateway.client._jcs import canonicalize as client_jcs_canonicalize
from src.gateway.client.core import CageClient, enforce_verification_posture
from src.gateway.client.crypto import (
    compute_expected_action_hash,
    verify_envelope_signature,
)
from src.gateway.client.envelope import ExecutionGrant, GovernanceEnvelope
from src.gateway.client.exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from src.gateway.client.transport import create_mtls_transport
from src.gateway.governance import jwks as gov_jwks
from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.verdicts import build_refusal_receipt
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.server.governance_middleware import governance_app

# Load standalone packages/cage-client/src/cage_client alongside src.gateway.client
_STANDALONE_SRC = (
    Path(__file__).resolve().parents[3] / "packages" / "cage-client" / "src"
)
if str(_STANDALONE_SRC) not in sys.path:
    sys.path.insert(0, str(_STANDALONE_SRC))

import cage_client as standalone_cage_client  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.asyncio]


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_client_envelope(
    envelope_body: dict[str, Any],
    *,
    priv_key: Any,
    kid: str,
    alg: str,
) -> dict[str, Any]:
    """Attach a valid RFC 8785 JCS asymmetric signature to an envelope dict."""
    unsigned = {k: v for k, v in envelope_body.items() if k != "signature"}
    canonical_bytes = client_jcs_canonicalize(unsigned)
    if isinstance(priv_key, ec.EllipticCurvePrivateKey):
        hash_alg: hashes.HashAlgorithm = (
            hashes.SHA384()
            if "384" in alg
            else hashes.SHA512()
            if "512" in alg
            else hashes.SHA256()
        )
        sig_bytes = priv_key.sign(canonical_bytes, ec.ECDSA(hash_alg))
    elif isinstance(priv_key, ed25519.Ed25519PrivateKey):
        sig_bytes = priv_key.sign(canonical_bytes)
    else:
        raise TypeError(f"Unsupported test signing key: {type(priv_key)}")
    signed = dict(unsigned)
    signed["signature"] = {
        "algorithm": alg,
        "kid": kid,
        "value": _b64u(sig_bytes),
    }
    return signed


def _build_signed_allow_envelope(
    *,
    action: str = "query_portfolio",
    parameters: dict[str, Any] | None = None,
    priv_key: Any,
    kid: str = "ec-test-kid-01",
    alg: str = "ES256",
    now: datetime | None = None,
    ttl_s: float = 300.0,
    payload_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a fresh, subject-bound, cryptographically signed v3.0 envelope."""
    params = parameters if parameters is not None else {"symbol": "AAPL", "amount": 100}
    issued = now or datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl_s)
    payload: dict[str, Any] = {"verdict": "ALLOW", "decision": "ALLOW"}
    if payload_overrides:
        payload.update(payload_overrides)
    body: dict[str, Any] = {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "cage-env-signed-001",
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "test-instance-001",
            "region": "us-central1",
        },
        "subject": {
            "action": action,
            "action_hash": compute_expected_action_hash(action, params),
            "record_hash": "rec-signed-001",
            "agent_id": "test-agent",
        },
        "governance_context": {
            "policy_version": "sha256:policy01",
            "tiers_passed": ["tier_1", "tier_2"],
        },
        "payload": payload,
    }
    return _sign_client_envelope(body, priv_key=priv_key, kid=kid, alg=alg)


@pytest.fixture
def mock_gateway_url() -> str:
    """Mock gateway base URL for hermetic tests."""
    return "https://mock-cage-gateway.example.com"


@pytest.fixture
def patched_httpx_no_http2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch transport + httpx.AsyncClient to HTTP/1.1 for respx compatibility."""

    def mock_create_mtls_transport(
        *args: Any, **kwargs: Any
    ) -> httpx.AsyncHTTPTransport:
        return httpx.AsyncHTTPTransport(http2=False)

    monkeypatch.setattr(
        "src.gateway.client.transport.create_mtls_transport", mock_create_mtls_transport
    )

    original_async_client = httpx.AsyncClient

    def patched_async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["http2"] = False
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr("httpx.AsyncClient", patched_async_client)


@pytest.fixture
async def cage_client(
    mock_gateway_url: str,
    monkeypatch: pytest.MonkeyPatch,
    patched_httpx_no_http2: None,
) -> AsyncIterator[CageClient]:
    """Create CageClient for wire-mediation unit tests using synthetic mock envelopes."""
    monkeypatch.setenv("CAGE_ENV", "test")
    client = CageClient(
        gateway_url=mock_gateway_url,
        timeout_s=5.0,
        verify_signature=False,
        verify_expiration=False,
        verify_subject=False,
    )
    yield client
    await client.aclose()


def create_mock_allow_envelope() -> dict[str, Any]:
    """Create mock ALLOW governance envelope with ISO timestamp strings."""
    now_str = "2026-09-18T20:00:00+00:00"
    expires_str = "2026-09-18T20:05:00+00:00"

    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "issued_at": now_str,
        "expires_at": expires_str,
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "test-instance-001",
            "region": "us-central1",
        },
        "subject": {
            "action": "query_portfolio",
            "action_hash": "abc123",
            "record_hash": "def456",
            "agent_id": "test-agent",
        },
        "governance_context": {
            "policy_version": "1.0",
            "tiers_passed": ["tier_1", "tier_2"],
        },
        "payload": {
            "decision": "ALLOW",
            "execution_token": "mock-token-123",
        },
        "signature": {
            "algorithm": "ES256",
            "value": "mock-signature-base64",
            "kid": "test-key-001",
        },
    }


@respx.mock
async def test_validate_action_allow(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test successful ALLOW response returns frozen GovernanceEnvelope."""
    envelope_data = create_mock_allow_envelope()
    response_body = {"envelope": envelope_data}

    mock_route = respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=200,
            json=response_body,
        )
    )

    result = await cage_client.validate_action(
        action="query_portfolio",
        parameters={"symbol": "AAPL", "amount": 1000},
        agent_id="test-agent",
        context={"session_id": "test-session"},
    )

    assert isinstance(result, GovernanceEnvelope)
    assert result.envelope_version == "3.0"
    assert result.envelope_type == "cage_governance_decision"
    assert result.payload["decision"] == "ALLOW"
    assert result.subject["action"] == "query_portfolio"
    assert result.subject["agent_id"] == "test-agent"

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        result.envelope_version = "4.0"  # type: ignore[misc]

    assert mock_route.called
    assert mock_route.call_count == 1
    sent_payload = json.loads(mock_route.calls.last.request.content)
    assert sent_payload["params"] == {"symbol": "AAPL", "amount": 1000}
    assert sent_payload["parameters"] == {"symbol": "AAPL", "amount": 1000}


@respx.mock
async def test_validate_action_deny_raises_policy_violation(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test DENY response raises PolicyViolationException with structured details."""
    response_body = {
        "reason_code": "TIER_3_BLOCKED",
        "details": {
            "failed_tier": "tier_3",
            "policy_rule": "high_value_limit",
            "evidence": "Amount exceeds $10,000 threshold",
            "suggested_alternatives": ["reduce_amount", "request_approval"],
        },
        "audit_id": "audit-12345",
        "recoverable": True,
    }

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=403,
            json=response_body,
        )
    )

    with pytest.raises(PolicyViolationException) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )

    exc = exc_info.value
    assert exc.reason_code == "TIER_3_BLOCKED"
    assert exc.audit_id == "audit-12345"
    assert exc.recoverable is True
    assert exc.violation_details["failed_tier"] == "tier_3"
    assert exc.violation_details["policy_rule"] == "high_value_limit"
    assert "suggested_alternatives" in exc.violation_details
    assert "reduce_amount" in exc.violation_details["suggested_alternatives"]


@respx.mock
async def test_validate_action_defer_raises_deferral_pending(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test DEFER response raises DeferralPending with ticket_id."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=4)
    response_body = {
        "ticket_id": "defer-ticket-789",
        "reason": "Action requires manual approval",
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": 14400,
    }

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=202,
            json=response_body,
        )
    )

    with pytest.raises(DeferralPending) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "GOOGL", "amount": 100000},
            agent_id="test-agent",
        )

    exc = exc_info.value
    assert exc.ticket_id == "defer-ticket-789"
    assert exc.defer_reason == "Action requires manual approval"
    assert exc.ttl_seconds == 14400
    assert isinstance(exc.expires_at, datetime)
    assert exc.expires_at > datetime.now(timezone.utc)


@respx.mock
async def test_validate_action_transport_failure_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test connection timeout/500 errors fail closed with CageGatewayError."""
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        side_effect=httpx.ConnectTimeout("Connection timed out")
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "TSLA", "amount": 5000},
            agent_id="test-agent",
        )

    assert "Failed to reach CAGE Gateway" in str(exc_info.value)

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=500,
            text="Internal Server Error",
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AMZN", "amount": 3000},
            agent_id="test-agent",
        )

    assert "Gateway server error" in str(exc_info.value)
    assert "500" in str(exc_info.value)


def test_routing_seal_secret_rejected(mock_gateway_url: str) -> None:
    """Test CageClient no longer accepts routing_seal_secret parameter."""
    with pytest.raises(TypeError):
        CageClient(
            gateway_url=mock_gateway_url,
            routing_seal_secret="legacy-secret",  # type: ignore[call-arg]
        )


def test_create_mtls_transport_partial_cert_or_key_fails_closed() -> None:
    """Half-configured mTLS (cert without key or key without cert) raises ValueError (#533)."""
    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path="/nonexistent/client.crt", key_path=None)

    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path=None, key_path="/nonexistent/client.key")


@respx.mock
async def test_deny_response_missing_audit_id_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test DENY response without audit_id or proof_hash fails closed with CageGatewayError."""
    response_body = {
        "reason_code": "UNKNOWN_ERROR",
        "details": {},
        "recoverable": True,
    }

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=403,
            json=response_body,
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "META", "amount": 7500},
            agent_id="test-agent",
        )

    assert "missing required 'audit_id' field" in str(exc_info.value)


@respx.mock
async def test_defer_response_missing_ticket_id_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test DEFER response without ticket_id or defer_id fails closed with CageGatewayError."""
    response_body = {
        "reason": "Requires approval",
        "ttl_seconds": 14400,
    }

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=202,
            json=response_body,
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "NFLX", "amount": 4000},
            agent_id="test-agent",
        )

    assert "missing required 'ticket_id' field" in str(exc_info.value)


@respx.mock
async def test_allow_response_missing_envelope_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test ALLOW response without envelope field fails closed."""
    response_body = {
        "status": "success",
    }

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=200,
            json=response_body,
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "ORCL", "amount": 2500},
            agent_id="test-agent",
        )

    assert "missing required 'envelope' field" in str(exc_info.value)


@respx.mock
async def test_unexpected_status_code_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test unexpected HTTP status code fails closed."""
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(
            status_code=418,
            text="I'm a teapot",
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "IBM", "amount": 1000},
            agent_id="test-agent",
        )

    assert "Unexpected gateway response" in str(exc_info.value)
    assert "418" in str(exc_info.value)


async def test_client_context_manager_lifecycle(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Test CageClient async context manager properly opens and closes."""
    async with CageClient(gateway_url=mock_gateway_url) as client:
        assert client._client is not None
        assert hasattr(client._client, "aclose")


def test_parameter_canonicalization() -> None:
    """Test parameter canonicalization produces deterministic RFC 8785 JCS JSON."""
    params1 = {"z": 3, "a": 1, "m": 2}
    params2 = {"a": 1, "m": 2, "z": 3}

    canon1 = CageClient._canonicalize_params(params1)
    canon2 = CageClient._canonicalize_params(params2)

    assert canon1 == canon2
    assert canon1 == '{"a":1,"m":2,"z":3}'

    params3 = {"nested": {"b": 2, "a": 1}, "top": "value"}
    canon3 = CageClient._canonicalize_params(params3)
    assert '{"nested":{"a":1,"b":2},"top":"value"}' == canon3


@respx.mock
async def test_validate_action_top_level_envelope_with_envelope_id(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test top-level v3.0 envelope with envelope_id and external_attestations parses cleanly."""
    envelope_data = create_mock_allow_envelope()
    envelope_data["envelope_id"] = "env-uuid-999"
    envelope_data["external_attestations"] = [{"provider": "provider_01"}]

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    envelope = await cage_client.validate_action(
        action="query_portfolio",
        parameters={"symbol": "AAPL", "amount": 100},
        agent_id="test-agent",
    )
    assert envelope.envelope_id == "env-uuid-999"
    assert envelope.external_attestations == [{"provider": "provider_01"}]
    assert envelope.payload["decision"] == "ALLOW"


@respx.mock
async def test_validate_action_http_200_require_approval_raises_deferral_pending(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test HTTP 200 envelope with verdict REQUIRE_APPROVAL raises DeferralPending."""
    envelope_data = create_mock_allow_envelope()
    envelope_data["payload"]["verdict"] = "REQUIRE_APPROVAL"
    envelope_data["payload"]["deferred_id"] = "hitl-ticket-123"
    envelope_data["payload"]["classification_reason"] = "OPA_MANUAL_REVIEW"

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    with pytest.raises(DeferralPending) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )
    assert exc_info.value.ticket_id == "hitl-ticket-123"
    assert exc_info.value.defer_reason == "OPA_MANUAL_REVIEW"


@respx.mock
async def test_validate_action_http_200_require_approval_unpersisted_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """REQUIRE_APPROVAL with deferred_id=None fails closed instead of using envelope_id."""
    envelope_data = create_mock_allow_envelope()
    envelope_data["envelope_id"] = "env-uuid-never-approvable"
    envelope_data["payload"]["verdict"] = "REQUIRE_APPROVAL"
    envelope_data["payload"]["deferred_id"] = None

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    with pytest.raises(CageGatewayError, match="DEFER envelope missing required"):
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )


@respx.mock
async def test_validate_action_http_200_deny_raises_policy_violation(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test HTTP 200 envelope with verdict DENY raises PolicyViolationException."""
    envelope_data = create_mock_allow_envelope()
    envelope_data["payload"]["verdict"] = "DENY"
    envelope_data["payload"]["violations"] = ["CBF_DRAWDOWN_LIMIT"]

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    with pytest.raises(PolicyViolationException) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )
    assert exc_info.value.reason_code == "POLICY_DENIED"
    assert exc_info.value.violation_details["violations"] == ["CBF_DRAWDOWN_LIMIT"]


@respx.mock
async def test_validate_action_http_200_narrow_raises_policy_violation(
    cage_client: CageClient,
    mock_gateway_url: str,
) -> None:
    """Test HTTP 200 envelope with verdict NARROW does not authorise the original params."""
    envelope_data = create_mock_allow_envelope()
    envelope_data["payload"]["verdict"] = "NARROW"
    envelope_data["payload"]["narrowed_params"] = {"symbol": "AAPL", "amount": 10000}
    envelope_data["payload"]["violations"] = ["CBF_POSITION_LIMIT"]

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    with pytest.raises(PolicyViolationException) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )
    assert exc_info.value.reason_code == "NARROWED"
    assert exc_info.value.recoverable is True
    assert exc_info.value.violation_details["narrowed_params"] == {
        "symbol": "AAPL",
        "amount": 10000,
    }


@respx.mock
@pytest.mark.parametrize("verdict", [None, "ESCALATE"])
async def test_validate_action_http_200_unrecognised_verdict_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
    verdict: str | None,
) -> None:
    """Test HTTP 200 envelope without an ALLOW verdict is never treated as ALLOW."""
    envelope_data = create_mock_allow_envelope()
    del envelope_data["payload"]["decision"]
    if verdict is not None:
        envelope_data["payload"]["verdict"] = verdict

    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=envelope_data)
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )
    assert not isinstance(exc_info.value, PolicyViolationException)
    assert "verdict" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Cryptographic Envelope Verification, JWKS Trust-Anchor & JCS Parity Tests
# ---------------------------------------------------------------------------


def test_jcs_parity_against_kernel_canonicalizer() -> None:
    """Vendored _jcs in both clients is byte-identical to kernel jcs_canonicalize_plan."""
    builder = GovernanceEnvelopeBuilder()
    vectors: list[tuple[str, dict[str, Any]]] = [
        (
            "execute_wire",
            {
                "neg_zero": -0.0,
                "zero": 0.0,
                "int_like_float": 100.0,
                "small_exp": 0.000001,
                "sci_exp": 0.0000001,
                "large_fixed": 1e20,
                "large_sci": 1e21,
                "ieee_edge": 333333333.33333329,
                "unicode_bmp": 'café \u20ac \u0008\t\n\r"\\',
                "unicode_astral": "🚀🔐\U0001f600",
                "nested": {
                    "z": [True, False, None, {"b": 2, "a": -0.0}],
                    "a": "first",
                },
            },
        ),
        (
            "rebalance_portfolio",
            {
                "allocations": [
                    {"ticker": "MSFT", "weight": 0.3333333333333333},
                    {"ticker": "GOOG", "weight": 0.6666666666666666},
                ],
                "dry_run": False,
                "max_slippage_bps": 12,
            },
        ),
    ]
    for action, params in vectors:
        kernel_bytes = jcs_canonicalize_plan({"action": action, "params": params})
        mirror_bytes = client_jcs_canonicalize({"action": action, "params": params})
        standalone_bytes = standalone_cage_client._jcs.canonicalize(
            {"action": action, "params": params}
        )
        assert mirror_bytes == kernel_bytes
        assert standalone_bytes == kernel_bytes

        expected_hash = builder._compute_action_hash(action, params)
        assert compute_expected_action_hash(action, params) == expected_hash
        assert (
            standalone_cage_client.compute_expected_action_hash(action, params)
            == expected_hash
        )


@respx.mock
async def test_validate_action_unknown_kid_fails_closed(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Unknown kid triggers bounded single refresh, fails closed, and enforces cooldown."""
    trusted_priv = ec.generate_private_key(ec.SECP256R1())
    trusted_pem = trusted_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_jwk = gov_jwks.pem_to_jwk(trusted_pem, kid="trusted-kid-01")

    rogue_priv = ec.generate_private_key(ec.SECP256R1())
    params = {"symbol": "AAPL", "amount": 250}
    rogue_env = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=rogue_priv,
        kid="unknown-rogue-kid-99",
        alg="ES256",
    )

    jwks_route = respx.get(f"{mock_gateway_url}/governance/.well-known/jwks.json").mock(
        return_value=httpx.Response(status_code=200, json={"keys": [trusted_jwk]})
    )
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=rogue_env)
    )

    async with CageClient(gateway_url=mock_gateway_url) as client:
        with pytest.raises(RoutingSealVerificationError, match="unknown kid"):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )
        # First call performed initial bootstrap fetch (1 request; no duplicate refresh).
        assert jwks_route.call_count == 1

        # Second immediate call with another unknown kid is rate-limited by cooldown:
        # zero extra JWKS HTTP fetches!
        other_rogue = _build_signed_allow_envelope(
            action="query_portfolio",
            parameters=params,
            priv_key=rogue_priv,
            kid="unknown-rogue-kid-100",
            alg="ES256",
        )
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=other_rogue)
        )
        with pytest.raises(RoutingSealVerificationError, match="unknown kid"):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )
        assert jwks_route.call_count == 1


@respx.mock
async def test_tampered_envelope_verdict_or_narrowed_params_rejected_before_dispatch(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Tampering DENY->ALLOW or narrowed_params raises RoutingSealVerificationError before verdict."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk = gov_jwks.pem_to_jwk(pem, kid="ec-tamper-01")
    params = {"symbol": "AAPL", "amount": 50000}

    # 1. Signed DENY tampered to ALLOW on wire
    signed_deny = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=priv,
        kid="ec-tamper-01",
        payload_overrides={"verdict": "DENY", "decision": "DENY"},
    )
    tampered_allow = json.loads(json.dumps(signed_deny))
    tampered_allow["payload"]["verdict"] = "ALLOW"
    tampered_allow["payload"]["decision"] = "ALLOW"

    respx.get(f"{mock_gateway_url}/governance/.well-known/jwks.json").mock(
        return_value=httpx.Response(status_code=200, json={"keys": [jwk]})
    )
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=tampered_allow)
    )

    async with CageClient(gateway_url=mock_gateway_url) as client:
        with pytest.raises(RoutingSealVerificationError):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )

        # 2. Signed NARROW with tampered narrowed_params must NOT surface PolicyViolationException
        signed_narrow = _build_signed_allow_envelope(
            action="query_portfolio",
            parameters=params,
            priv_key=priv,
            kid="ec-tamper-01",
            payload_overrides={
                "verdict": "NARROW",
                "decision": "NARROW",
                "narrowed_params": {"symbol": "AAPL", "amount": 5000},
            },
        )
        tampered_narrow = json.loads(json.dumps(signed_narrow))
        tampered_narrow["payload"]["narrowed_params"]["amount"] = 49999
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=tampered_narrow)
        )
        with pytest.raises(RoutingSealVerificationError):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )


@respx.mock
async def test_client_acts_only_on_the_values_that_were_signed(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Every body below must fail closed: the client acts on the JSON exactly as signed.

    Each body is validly signed, or is the signed body with a repeated key or a
    ``NaN`` spliced in. Before the envelope model became strict, every one but
    the ``NaN`` body (refused later, at canonicalisation) came back as ALLOW.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    kid = "ec-exact-01"
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    params = {"symbol": "AAPL", "amount": 100}
    valid = _build_signed_allow_envelope(
        action="query_portfolio", parameters=params, priv_key=priv, kid=kid
    )
    valid_json = json.dumps(valid)

    def signed(body: dict[str, Any]) -> str:
        return json.dumps(
            _sign_client_envelope(body, priv_key=priv, kid=kid, alg="ES256")
        )

    def signed_payload(**payload: Any) -> str:
        return json.dumps(
            _build_signed_allow_envelope(
                action="query_portfolio",
                parameters=params,
                priv_key=priv,
                kid=kid,
                payload_overrides=payload,
            )
        )

    def relabelled(**signature: str) -> str:
        return json.dumps({**valid, "signature": {**valid["signature"], **signature}})

    cases: list[tuple[str, str, type[CageGatewayError], str]] = [
        (
            "padded key beside the signed DENY",
            signed_payload(
                **{"verdict": "DENY", "decision": "DENY", "verdict ": "ALLOW"}
            ),
            PolicyViolationException,
            "POLICY_DENIED",
        ),
        (
            "padded subject.action",
            signed(
                {
                    **valid,
                    "subject": {**valid["subject"], "action": " query_portfolio "},
                }
            ),
            RoutingSealVerificationError,
            "subject.action mismatch",
        ),
        (
            "lower-case verdict",
            signed_payload(verdict="allow", decision="allow"),
            CageGatewayError,
            "unrecognised verdict 'allow'",
        ),
        *[
            (
                f"expires_at {value!r}",
                signed({**valid, "expires_at": value}),
                CageGatewayError,
                "Failed to parse governance envelope",
            )
            for value in (4102444800, "4102444800", "2100-01-01 00:00:00Z")
        ],
        (
            "padded kid",
            relabelled(kid=f" {kid}"),
            RoutingSealVerificationError,
            "unknown kid",
        ),
        (
            "padded signature value",
            relabelled(value=f"{valid['signature']['value']} "),
            RoutingSealVerificationError,
            "Invalid base64url encoding",
        ),
        (
            "repeated key",
            valid_json.replace('"payload": {', '"payload": {"verdict": "DENY", ', 1),
            RoutingSealVerificationError,
            "duplicate JSON object key 'verdict'",
        ),
        (
            "NaN",
            valid_json.replace('"payload": {', '"payload": {"score": NaN, ', 1),
            RoutingSealVerificationError,
            "non-finite JSON number NaN",
        ),
    ]

    route = respx.post(f"{mock_gateway_url}/governance/validate-action")
    async with CageClient(
        gateway_url=mock_gateway_url, public_keys={kid: pem}
    ) as client:
        route.mock(return_value=httpx.Response(200, content=valid_json.encode()))
        allowed = await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="test-agent"
        )
        assert allowed.payload["verdict"] == "ALLOW"

        for name, body, expected, message in cases:
            route.mock(return_value=httpx.Response(200, content=body.encode()))
            try:
                await client.validate_action(
                    action="query_portfolio", parameters=params, agent_id="test-agent"
                )
            except expected as exc:
                assert message in str(exc), f"{name}: {exc!r}"
            else:
                pytest.fail(f"{name}: accepted")


def test_execution_grant_validates_without_coercion() -> None:
    """ExecutionGrant shares the strict wire config: nothing coerced, nothing stripped."""
    from pydantic import ValidationError

    grant: dict[str, Any] = {
        "iss": "cage-gateway",
        "sub": "test-agent",
        "aud": "actuator_01",
        "exp": 4102444800,
        "iat": 4102444500,
        "nonce": " nonce-01 ",
        "action_hash": "abc123",
        "record_hash": "def456",
        "signature": "c2lnbmF0dXJl",
    }
    assert ExecutionGrant(**grant).nonce == " nonce-01 "
    with pytest.raises(ValidationError):
        ExecutionGrant(**{**grant, "exp": "4102444800"})


@respx.mock
async def test_embedded_public_key_in_envelope_never_trusted(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Attacker-supplied jwk/public_key/x5c inside the envelope is rejected fail-closed."""
    trusted_priv = ec.generate_private_key(ec.SECP256R1())
    trusted_pem = trusted_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_jwk = gov_jwks.pem_to_jwk(trusted_pem, kid="trusted-kid-01")

    attacker_priv = ec.generate_private_key(ec.SECP256R1())
    attacker_pem = attacker_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    attacker_jwk = gov_jwks.pem_to_jwk(attacker_pem, kid="attacker-embedded-kid")

    params = {"symbol": "AAPL", "amount": 100}
    env = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=attacker_priv,
        kid="attacker-embedded-kid",
    )
    env["signature"]["jwk"] = attacker_jwk
    env["signature"]["public_key"] = attacker_pem.decode("utf-8")
    env["issuer"]["jwk"] = attacker_jwk

    respx.get(f"{mock_gateway_url}/governance/.well-known/jwks.json").mock(
        return_value=httpx.Response(status_code=200, json={"keys": [trusted_jwk]})
    )
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=env)
    )

    async with CageClient(gateway_url=mock_gateway_url) as client:
        with pytest.raises(RoutingSealVerificationError, match="embedded key"):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )


@respx.mock
async def test_only_es256_and_eddsa_are_accepted(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Keys other than P-256/Ed25519 are refused when pinned; labels other than ES256/EdDSA when verified."""
    pem = (
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    p384_key = ec.generate_private_key(ec.SECP384R1()).public_key()
    rsa_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()
    for pinned in (p384_key.public_bytes(*pem), p384_key):
        with pytest.raises(RoutingSealVerificationError, match="only P-256"):
            CageClient(gateway_url=mock_gateway_url, public_keys={"p384-kid": pinned})
    for pinned in (rsa_key.public_bytes(*pem), rsa_key):
        with pytest.raises(
            RoutingSealVerificationError, match="only EC P-256 and Ed25519"
        ):
            CageClient(gateway_url=mock_gateway_url, public_keys={"rsa-kid": pinned})

    params = {"symbol": "AAPL", "amount": 100}
    p256_priv = ec.generate_private_key(ec.SECP256R1())
    valid_env = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=p256_priv,
        kid="p256-kid",
        alg="ES256",
    )
    route = respx.post(f"{mock_gateway_url}/governance/validate-action")
    async with CageClient(
        gateway_url=mock_gateway_url,
        public_keys={"p256-kid": p256_priv.public_key().public_bytes(*pem)},
    ) as client:
        route.mock(return_value=httpx.Response(status_code=200, json=valid_env))
        verified = await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="test-agent"
        )
        assert verified.signature is not None
        assert verified.signature["algorithm"] == "ES256"

        # The same valid ES256 signature under any other label is refused,
        # including spellings that name the same algorithm.
        for label in (
            "ES384",
            "ES512",
            "RS256",
            "PS256",
            "HS256",
            "none",
            "es256",
            " ES256",
            "ES256 ",
            "ECDSA_P256_SHA256",
        ):
            relabeled = {
                **valid_env,
                "signature": {**valid_env["signature"], "algorithm": label},
            }
            route.mock(return_value=httpx.Response(status_code=200, json=relabeled))
            with pytest.raises(RoutingSealVerificationError, match="not accepted"):
                await client.validate_action(
                    action="query_portfolio", parameters=params, agent_id="test-agent"
                )

        # An accepted label still has to match the key type.
        eddsa_label = {
            **valid_env,
            "signature": {**valid_env["signature"], "algorithm": "EdDSA"},
        }
        route.mock(return_value=httpx.Response(status_code=200, json=eddsa_label))
        with pytest.raises(RoutingSealVerificationError, match="requires an Ed25519"):
            await client.validate_action(
                action="query_portfolio", parameters=params, agent_id="test-agent"
            )


def test_verify_envelope_signature_binds_algorithm_to_key_type() -> None:
    """ES256 verifies only with a P-256 key and EdDSA only with an Ed25519 key."""
    canonical = b'{"action":"query_portfolio"}'
    p384_priv = ec.generate_private_key(ec.SECP384R1())
    p384_sig = _b64u(p384_priv.sign(canonical, ec.ECDSA(hashes.SHA256())))
    with pytest.raises(
        RoutingSealVerificationError, match="ES256 requires an EC P-256"
    ):
        verify_envelope_signature(
            canonical_bytes=canonical,
            algorithm="ES256",
            signature_b64=p384_sig,
            public_key=p384_priv.public_key(),
        )

    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_sig = _b64u(ed_priv.sign(canonical))
    with pytest.raises(
        RoutingSealVerificationError, match="ES256 requires an EC P-256"
    ):
        verify_envelope_signature(
            canonical_bytes=canonical,
            algorithm="ES256",
            signature_b64=ed_sig,
            public_key=ed_priv.public_key(),
        )
    with pytest.raises(RoutingSealVerificationError, match="EdDSA requires an Ed25519"):
        verify_envelope_signature(
            canonical_bytes=canonical,
            algorithm="EdDSA",
            signature_b64=ed_sig,
            public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        )


@respx.mock
async def test_envelope_expiration_and_subject_binding_enforced(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """Expired/future envelopes and replayed action/params hashes fail closed."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    params = {"symbol": "AAPL", "amount": 100}

    async with CageClient(
        gateway_url=mock_gateway_url,
        public_keys={"ec-pin-01": pem},
        clock_skew_seconds=5.0,
    ) as client:
        # 1. Expired beyond clock_skew_seconds
        expired_env = _build_signed_allow_envelope(
            action="query_portfolio",
            parameters=params,
            priv_key=priv,
            kid="ec-pin-01",
            now=datetime.now(timezone.utc) - timedelta(seconds=400),
            ttl_s=60.0,
        )
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=expired_env)
        )
        with pytest.raises(RoutingSealVerificationError, match="expired"):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )

        # 2. Future issued_at beyond clock_skew_seconds
        future_env = _build_signed_allow_envelope(
            action="query_portfolio",
            parameters=params,
            priv_key=priv,
            kid="ec-pin-01",
            now=datetime.now(timezone.utc) + timedelta(seconds=120),
            ttl_s=300.0,
        )
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=future_env)
        )
        with pytest.raises(RoutingSealVerificationError, match="future"):
            await client.validate_action(
                action="query_portfolio",
                parameters=params,
                agent_id="test-agent",
            )

        # 3. Valid fresh envelope replayed for different parameters -> action_hash mismatch
        fresh_env = _build_signed_allow_envelope(
            action="query_portfolio",
            parameters=params,
            priv_key=priv,
            kid="ec-pin-01",
        )
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=fresh_env)
        )
        with pytest.raises(RoutingSealVerificationError, match="action_hash"):
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 999999},
                agent_id="test-agent",
            )

        # 4. Replayed for different action name -> subject.action mismatch
        with pytest.raises(RoutingSealVerificationError, match="subject.action"):
            await client.validate_action(
                action="execute_wire",
                parameters=params,
                agent_id="test-agent",
            )


@respx.mock
async def test_jwks_ttl_staleness_304_and_key_rotation_eviction(
    mock_gateway_url: str,
    patched_httpx_no_http2: None,
) -> None:
    """JWKS caches for TTL, rejects 304, evicts revoked keys on rotation, and fails closed past staleness."""
    clock = [1000.0]
    priv1 = ec.generate_private_key(ec.SECP256R1())
    pem1 = priv1.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk1 = gov_jwks.pem_to_jwk(pem1, kid="rot-kid-1")

    priv2 = ec.generate_private_key(ec.SECP256R1())
    pem2 = priv2.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk2 = gov_jwks.pem_to_jwk(pem2, kid="rot-kid-2")

    params = {"symbol": "AAPL", "amount": 100}
    env1 = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=priv1,
        kid="rot-kid-1",
    )
    env2 = _build_signed_allow_envelope(
        action="query_portfolio",
        parameters=params,
        priv_key=priv2,
        kid="rot-kid-2",
    )

    jwks_route = respx.get(f"{mock_gateway_url}/governance/.well-known/jwks.json").mock(
        return_value=httpx.Response(status_code=200, json={"keys": [jwk1]})
    )
    respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
        return_value=httpx.Response(status_code=200, json=env1)
    )

    client = CageClient(
        gateway_url=mock_gateway_url,
        jwks_ttl_s=300.0,
        max_jwks_staleness_s=3600.0,
        jwks_clock=lambda: clock[0],
    )

    try:
        # Initial fetch at t=1000, cached at t=1200 (within 300s TTL)
        await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="a1"
        )
        clock[0] = 1200.0
        await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="a1"
        )
        assert jwks_route.call_count == 1

        # At t=1400 (past TTL, within max_jwks_staleness_s), HTTP 304 is NOT treated as fresh;
        # cached key serves within grace window, then past t=4601 (max staleness) fails closed!
        jwks_route.mock(return_value=httpx.Response(status_code=304))
        clock[0] = 1400.0
        await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="a1"
        )
        assert jwks_route.call_count == 2

        clock[0] = 4605.0
        with pytest.raises(RoutingSealVerificationError):
            await client.validate_action(
                action="query_portfolio", parameters=params, agent_id="a1"
            )

        # Recovery + rotation to rot-kid-2 evicts revoked rot-kid-1 immediately
        jwks_route.mock(
            return_value=httpx.Response(status_code=200, json={"keys": [jwk2]})
        )
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=env2)
        )
        clock[0] = 4700.0
        await client.validate_action(
            action="query_portfolio", parameters=params, agent_id="a1"
        )

        # Replay of old revoked rot-kid-1 now fails closed!
        respx.post(f"{mock_gateway_url}/governance/validate-action").mock(
            return_value=httpx.Response(status_code=200, json=env1)
        )
        clock[0] = 4750.0
        with pytest.raises(RoutingSealVerificationError, match="unknown kid"):
            await client.validate_action(
                action="query_portfolio", parameters=params, agent_id="a1"
            )
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "posture",
    ["production", "prod", "staging", "uat", "canary", "preprod", "custom-enforcing"],
)
@pytest.mark.parametrize(
    "opt_out_kwargs",
    [
        {"verify_signature": False},
        {"verify_expiration": False},
        {"verify_subject": False},
    ],
)
async def test_verification_posture_guard_enforced_in_non_dev_postures(
    mock_gateway_url: str,
    monkeypatch: pytest.MonkeyPatch,
    posture: str,
    opt_out_kwargs: dict[str, bool],
) -> None:
    """Disabling any verification invariant in non-dev/test CAGE_ENV raises ValueError."""
    monkeypatch.setenv("CAGE_ENV", posture)
    with pytest.raises(ValueError, match="enforcing posture"):
        enforce_verification_posture(**opt_out_kwargs)
    with pytest.raises(ValueError, match="enforcing posture"):
        CageClient(gateway_url=mock_gateway_url, **opt_out_kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# End-to-End Live ASGI Wire-Contract Tests (real governance_app + KMS + JWKS)
# ---------------------------------------------------------------------------


class _RealAsgiEcKmsSigner:
    """Real EC P-256 asymmetric signer for live ASGI ES256 envelope signing."""

    is_kms_active = True
    kms_active = True

    def __init__(self, kid: str = "cage-kms-asgi-ec-01") -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.pem_bytes = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_jwk = gov_jwks.pem_to_jwk(self.pem_bytes, kid=kid)

    async def sign_precomputed_digest_async(self, digest: bytes) -> str:
        der_sig = self._priv.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return der_sig.hex()


@pytest.fixture(params=["es256", "eddsa"])
def live_governance_asgi(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FastAPI, MagicMock, str]:
    """Mount real governance_app at /governance with real asymmetric KMS + /.well-known/jwks.json."""
    alg_mode: str = request.param
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._check_validate_action_rate_limit",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._emit_refusal_receipt",
        AsyncMock(return_value=None),
    )

    jwks = gov_jwks.JWKSet(max_keys=8)
    if alg_mode == "es256":
        ec_signer = _RealAsgiEcKmsSigner(kid="cage-kms-asgi-ec-01")
        jwks.add_key(ec_signer.pem_bytes, kid="cage-kms-asgi-ec-01")
        expected_alg = "ES256"
        active_signer: Any = ec_signer
    else:
        ed_provider = SoftwareEd25519Provider(key_id="cage-kms-asgi-ed25519-01")
        ed_signer = KMSGovernanceSigner(provider=ed_provider)
        monkeypatch.setattr(
            "src.gateway.governance.kms_signer.get_governance_signer",
            lambda: ed_signer,
        )
        gov_jwks._initialize_jwks_from_kms(jwks)
        expected_alg = "EdDSA"
        active_signer = ed_signer

    monkeypatch.setattr(
        "src.gateway.governance.kms_signer.get_governance_signer",
        lambda: active_signer,
    )
    monkeypatch.setattr(gov_jwks, "_global_jwks", jwks)

    mock_governor = MagicMock(spec=SymbolicGovernor)
    mock_governor.validate_action = AsyncMock()

    had_governor = hasattr(governance_app.state, "governor")
    prev_governor = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = mock_governor

    root_app = FastAPI()
    root_app.mount("/governance", governance_app)

    try:
        yield root_app, mock_governor, expected_alg
    finally:
        if had_governor:
            governance_app.state.governor = prev_governor
        elif hasattr(governance_app.state, "governor"):
            delattr(governance_app.state, "governor")


async def _make_asgi_client(
    client_cls: Any,
    root_app: FastAPI,
    **kwargs: Any,
) -> Any:
    """Bind CageClient (kernel mirror or standalone package) to httpx.ASGITransport."""
    client = client_cls(gateway_url="https://cage-asgi.example.test", **kwargs)
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root_app),
        base_url="https://cage-asgi.example.test",
    )
    return client


@pytest.mark.parametrize(
    "client_cls",
    [CageClient, standalone_cage_client.CageClient],
    ids=["kernel_mirror", "standalone_pkg"],
)
async def test_live_asgi_all_seven_gateway_outcomes(
    client_cls: Any,
    live_governance_asgi: tuple[FastAPI, MagicMock, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify both synced CageClient classes with real JWKS + ES256/EdDSA verification across all 7 outcomes."""
    root_app, mock_governor, expected_alg = live_governance_asgi
    client = await _make_asgi_client(client_cls, root_app)

    try:
        # 1. ALLOW (HTTP 200 signed top-level GovernanceEnvelope + external_attestations)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.ALLOW,
            "record_hash": "rec-allow-001",
            "agent_id": "agent-asgi-01",
            "tiers_passed": ["stpa", "opa", "cbf"],
            "controls_satisfied": ["AU-10"],
            "external_attestations": [
                {
                    "type": "fria",
                    "status": "VERIFIED",
                    "receipt_id": "att-001",
                    "attested_at": "2026-09-18T20:00:00Z",
                    "provider_name": "provider_01",
                }
            ],
        }
        allow_env = await client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 250},
            agent_id="agent-asgi-01",
        )
        assert allow_env.envelope_id is not None
        assert allow_env.payload["verdict"] == "ALLOW"
        assert allow_env.subject["record_hash"] == "rec-allow-001"
        assert allow_env.signature is not None
        assert allow_env.signature["algorithm"] == expected_alg
        assert allow_env.external_attestations is not None
        assert allow_env.external_attestations[0]["provider_name"] == "provider_01"

        # 2. NARROW (HTTP 200 signed GovernanceEnvelope with clamped params)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.NARROW,
            "record_hash": "rec-narrow-002",
            "violations": [
                Violation(
                    tier="cbf",
                    code="CBF_POSITION_LIMIT",
                    message="Clamped amount to barrier ceiling",
                    kind=ViolationKind.NARROWABLE,
                    bound=10000.0,
                )
            ],
            "original_params": {"symbol": "AAPL", "amount": 50000},
            "narrowed_params": {"symbol": "AAPL", "amount": 10000},
            "narrowing_reason": "Clamped to max position bound",
            "constraints_applied": ["amount<=10000"],
            "execution_allowed": True,
        }
        with pytest.raises(
            (PolicyViolationException, standalone_cage_client.PolicyViolationException)
        ) as narrow_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 50000},
                agent_id="agent-asgi-01",
            )
        assert narrow_exc.value.reason_code == "NARROWED"
        assert narrow_exc.value.recoverable is True
        assert narrow_exc.value.audit_id == "rec-narrow-002"
        assert narrow_exc.value.violation_details["narrowed_params"] == {
            "symbol": "AAPL",
            "amount": 10000,
        }

        # 3. REQUIRE_APPROVAL (HTTP 200 signed GovernanceEnvelope with deferred_id)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
            "violations": [
                Violation(
                    tier="consensus",
                    code="HITL_NOTIONAL_GATE",
                    message="Requires human operator approval",
                    kind=ViolationKind.HITL,
                )
            ],
            "deferred_id": "hitl-parked-token-003",
            "classification_reason": "hitl_violation",
            "narrowed_params": None,
        }
        with pytest.raises(
            (DeferralPending, standalone_cage_client.DeferralPending)
        ) as hitl_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 75000},
                agent_id="agent-asgi-01",
            )
        assert hitl_exc.value.ticket_id == "hitl-parked-token-003"
        assert hitl_exc.value.defer_reason == "hitl_violation"

        # 3b. Unpersisted REQUIRE_APPROVAL (deferred_id=None) fails closed even when validly signed
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
            "deferred_id": None,
            "classification_reason": "hitl_store_unavailable",
        }
        with pytest.raises(
            (CageGatewayError, standalone_cage_client.CageGatewayError)
        ) as unpersisted_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 75000},
                agent_id="agent-asgi-01",
            )
        assert not isinstance(
            unpersisted_exc.value,
            (DeferralPending, standalone_cage_client.DeferralPending),
        )

        # 4. Internal DEFER (HTTP 200 signed GovernanceEnvelope with defer_token)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.DEFER,
            "violations": [
                Violation(
                    tier="confidence",
                    code="CONFIDENCE_GATE",
                    message="Confidence below threshold",
                    kind=ViolationKind.DEFERRABLE,
                )
            ],
            "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
            "defer_token": "defer-parked-token-004",
            "deferrable": True,
            "retry_after_seconds": 300,
        }
        with pytest.raises(
            (DeferralPending, standalone_cage_client.DeferralPending)
        ) as defer_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 500},
                agent_id="agent-asgi-01",
            )
        assert defer_exc.value.ticket_id == "defer-parked-token-004"
        assert defer_exc.value.defer_reason == "CONFIDENCE_BELOW_THRESHOLD"
        assert defer_exc.value.ttl_seconds == 300

        # 5. EXTERNAL_HOLD DEFER: the same signed HTTP 200 envelope as any other
        #    DEFER, in the shape handle_defer() returns (defer_token and
        #    retry_after_seconds). The gateway has no separate 202 receipt.
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.DEFER,
            "violations": [],
            "defer_reason": "EXTERNAL_HOLD",
            "defer_token": "ext-hold-token-005",
            "deferrable": True,
            "retry_after_seconds": 300,
        }
        with pytest.raises(
            (DeferralPending, standalone_cage_client.DeferralPending)
        ) as ext_hold_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 500},
                agent_id="agent-asgi-01",
            )
        assert ext_hold_exc.value.ticket_id == "ext-hold-token-005"
        assert ext_hold_exc.value.defer_reason == "EXTERNAL_HOLD"
        assert ext_hold_exc.value.ttl_seconds == 300

        # 6. Envelope DENY (HTTP 200 signed GovernanceEnvelope with verdict=DENY)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.DENY,
            "record_hash": "rec-deny-006",
            "violations": [
                Violation(
                    tier="cbf",
                    code="CBF_DRAWDOWN_LIMIT",
                    message="Max drawdown exceeded",
                    kind=ViolationKind.HARD,
                )
            ],
        }
        with pytest.raises(
            (PolicyViolationException, standalone_cage_client.PolicyViolationException)
        ) as env_deny_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 90000},
                agent_id="agent-asgi-01",
            )
        assert env_deny_exc.value.reason_code == "CBF_DRAWDOWN_LIMIT"
        assert env_deny_exc.value.audit_id == "rec-deny-006"

        # 7. Hard DENY GovernanceError with real RefusalReceipt (HTTP 403 v2.0.0 refusal)
        hard_violation = Violation(
            tier="cbf",
            code="CBF_HARD_BARRIER",
            message="Barrier invariant breached",
            kind=ViolationKind.HARD,
        )
        tier_failure = GovernanceTierFailure(
            tier="CBF",
            control_id="CAGE-CTRL-001",
            rule_description="Barrier invariant breached",
            governing_state={"headroom": -120.0},
            protected_consequence="Prevent invariant violation",
        )
        real_receipt = build_refusal_receipt(
            action="query_portfolio",
            params={"symbol": "AAPL", "amount": 999999},
            violations=[hard_violation],
            tier_failures=[tier_failure],
        )
        mock_governor.validate_action.side_effect = GovernanceError(
            "[CBF_HARD_BARRIER] Barrier invariant breached",
            receipt=real_receipt,
            violations=["[CBF_HARD_BARRIER] Barrier invariant breached"],
        )
        with pytest.raises(
            (PolicyViolationException, standalone_cage_client.PolicyViolationException)
        ) as hard_deny_exc:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 999999},
                agent_id="agent-asgi-01",
            )
        assert hard_deny_exc.value.audit_id == real_receipt.proof_hash
        assert len(hard_deny_exc.value.audit_id) == 64
        assert hard_deny_exc.value.reason_code == "CBF_HARD_BARRIER"
        assert (
            hard_deny_exc.value.violation_details["refusal_receipt"]["proof_hash"]
            == real_receipt.proof_hash
        )

        # 8. Unsigned envelope when KMS is inactive:
        #    - Default CageClient (verify_signature=True) MUST fail closed!
        #    - Explicit verify_signature=False under CAGE_ENV=development succeeds
        #      (while still verifying expiration + subject binding).
        mock_governor.validate_action.side_effect = None
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.ALLOW,
            "record_hash": "rec-unsigned-007",
            "agent_id": "agent-asgi-01",
        }
        inactive_signer = MagicMock(is_kms_active=False, kms_active=False)
        monkeypatch.setattr(
            "src.gateway.governance.kms_signer.get_governance_signer",
            lambda: inactive_signer,
        )
        with pytest.raises(
            (
                RoutingSealVerificationError,
                standalone_cage_client.RoutingSealVerificationError,
            )
        ):
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 50},
                agent_id="agent-asgi-01",
            )

        dev_opt_out_client = await _make_asgi_client(
            client_cls,
            root_app,
            verify_signature=False,
        )
        try:
            unsigned_env = await dev_opt_out_client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": 50},
                agent_id="agent-asgi-01",
            )
            assert unsigned_env.signature is None
            assert unsigned_env.subject["record_hash"] == "rec-unsigned-007"
        finally:
            await dev_opt_out_client.aclose()
    finally:
        await client.aclose()
