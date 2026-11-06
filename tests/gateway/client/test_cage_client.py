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

Includes both respx transport-level tests and live FastAPI ASGI tests mounting
the real ``governance_app`` at ``/governance`` to verify all 7 gateway wire
outcomes against both ``src.gateway.client`` and standalone ``cage_client``.
"""

from __future__ import annotations

import hashlib
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
from fastapi import FastAPI

from src.gateway.client.core import CageClient
from src.gateway.client.envelope import GovernanceEnvelope
from src.gateway.client.exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
)
from src.gateway.client.transport import create_mtls_transport
from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.verdicts import build_refusal_receipt
from src.gateway.server.governance_middleware import governance_app

# Load standalone packages/cage-client/src/cage_client alongside src.gateway.client
_STANDALONE_SRC = (
    Path(__file__).resolve().parents[3] / "packages" / "cage-client" / "src"
)
if str(_STANDALONE_SRC) not in sys.path:
    sys.path.insert(0, str(_STANDALONE_SRC))

import cage_client as standalone_cage_client  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.asyncio]


@pytest.fixture
def mock_gateway_url() -> str:
    """Mock gateway base URL for hermetic tests."""
    return "https://mock-cage-gateway.example.com"


@pytest.fixture
async def cage_client(
    mock_gateway_url: str, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[CageClient]:
    """Create CageClient instance for hermetic testing with mocked transport."""

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

    client = CageClient(
        gateway_url=mock_gateway_url,
        timeout_s=5.0,
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
            "algorithm": "RS256",
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
    mock_gateway_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test CageClient async context manager properly opens and closes."""

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

    async with CageClient(gateway_url=mock_gateway_url) as client:
        assert client._client is not None
        assert hasattr(client._client, "aclose")


def test_parameter_canonicalization() -> None:
    """Test parameter canonicalization produces deterministic JSON."""
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
# End-to-End Live ASGI Wire-Contract Tests (real governance_app + EnvelopeBuilder)
# ---------------------------------------------------------------------------


class _StubKmsSigner:
    """Deterministic stub KMS signer exercising real GovernanceEnvelopeBuilder.attach_signature."""

    is_kms_active = True
    kms_active = True
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "cage-kms-asgi-key-01",
        "alg": "ES256",
    }

    async def sign_precomputed_digest_async(self, digest: bytes) -> str:
        return hashlib.sha256(digest).hexdigest() * 2


@pytest.fixture
def live_governance_asgi(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FastAPI, MagicMock]:
    """Mount real governance_app at /governance with hermetic rate-limit, KMS, and governor."""
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._check_validate_action_rate_limit",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._emit_refusal_receipt",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        "src.gateway.governance.kms_signer.get_governance_signer",
        lambda: _StubKmsSigner(),
    )

    mock_governor = MagicMock(spec=SymbolicGovernor)
    mock_governor.validate_action = AsyncMock()

    had_governor = hasattr(governance_app.state, "governor")
    prev_governor = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = mock_governor

    root_app = FastAPI()
    root_app.mount("/governance", governance_app)

    try:
        yield root_app, mock_governor
    finally:
        if had_governor:
            governance_app.state.governor = prev_governor
        elif hasattr(governance_app.state, "governor"):
            delattr(governance_app.state, "governor")


async def _make_asgi_client(client_cls: Any, root_app: FastAPI) -> Any:
    """Bind CageClient (kernel mirror or standalone package) to httpx.ASGITransport."""
    client = client_cls(gateway_url="https://cage-asgi.example.test")
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
    live_governance_asgi: tuple[FastAPI, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify both synced CageClient classes against all 7 real governance_app wire outcomes."""
    root_app, mock_governor = live_governance_asgi
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
        assert allow_env.signature["kid"] == "cage-kms-asgi-key-01"
        assert allow_env.external_attestations is not None
        assert allow_env.external_attestations[0]["provider_name"] == "provider_01"

        # 2. NARROW (HTTP 200 top-level GovernanceEnvelope with clamped params)
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

        # 3. REQUIRE_APPROVAL (HTTP 200 top-level GovernanceEnvelope with deferred_id)
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

        # 4. Internal DEFER (HTTP 200 top-level GovernanceEnvelope with defer_token)
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

        # 5. EXTERNAL_HOLD DEFER (HTTP 202 async receipt with defer_id)
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.DEFER,
            "defer_reason": "EXTERNAL_HOLD",
            "is_external_hold": True,
            "defer_id": "ext-hold-token-005",
            "latency_ms": 9.4,
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

        # 6. Envelope DENY (HTTP 200 top-level GovernanceEnvelope with verdict=DENY)
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

        # Also verify dev/test unsigned ALLOW envelope (when KMS is inactive)
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
        unsigned_env = await client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 50},
            agent_id="agent-asgi-01",
        )
        assert unsigned_env.signature is None
        assert unsigned_env.subject["record_hash"] == "rec-unsigned-007"
    finally:
        await client.aclose()
