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

"""Hermetic test suite for CageClient SDK core functionality.

All tests run without live external gateway or vendor SDK dependencies.
Mocking uses respx for HTTP/2 interception and unittest.mock for crypto.
"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from src.gateway.client.core import CageClient
from src.gateway.client.crypto import RoutingSealVerificationError
from src.gateway.client.envelope import GovernanceEnvelope
from src.gateway.client.exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.asyncio]


@pytest.fixture
def mock_gateway_url() -> str:
    """Mock gateway base URL for hermetic tests."""
    return "https://mock-cage-gateway.example.com"


@pytest.fixture
def mock_routing_seal_secret() -> str:
    """Mock routing seal shared secret for hermetic tests."""
    return "test-seal-secret-32-bytes-long!!"


@pytest.fixture
async def cage_client(
    mock_gateway_url: str, mock_routing_seal_secret: str, monkeypatch
):
    """Create CageClient instance for hermetic testing with mocked transport."""
    from unittest.mock import MagicMock

    # Mock create_mtls_transport to return a simple httpx.HTTPTransport without h2
    def mock_create_mtls_transport(*args, **kwargs):
        return httpx.HTTPTransport()

    monkeypatch.setattr(
        "src.gateway.client.transport.create_mtls_transport", mock_create_mtls_transport
    )

    # Also disable http2 in the client initialization by patching AsyncClient
    original_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        # Force http2=False to avoid h2 dependency
        kwargs["http2"] = False
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr("httpx.AsyncClient", patched_async_client)

    client = CageClient(
        gateway_url=mock_gateway_url,
        routing_seal_secret=mock_routing_seal_secret,
        timeout_s=5.0,
    )
    yield client
    await client.aclose()


def generate_mock_routing_seal(body_bytes: bytes, secret: str) -> str:
    """Generate valid routing seal for mock responses."""
    import hmac

    timestamp = str(time.time())
    message = f"{timestamp}.{body_bytes.hex()}".encode()
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{timestamp}.{signature}"


def create_mock_allow_envelope() -> dict:
    """Create mock ALLOW governance envelope with ISO timestamp strings."""
    # Use fixed timestamps for deterministic sealing
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
            "action": "execute_trade",
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
    mock_routing_seal_secret: str,
    monkeypatch,
):
    """Test successful ALLOW response returns frozen GovernanceEnvelope."""

    # Mock verify_routing_seal to always succeed (hermetic test)
    def mock_verify_seal(*args, **kwargs):
        return True

    monkeypatch.setattr("src.gateway.client.core.verify_routing_seal", mock_verify_seal)

    # Mock ALLOW response
    envelope_data = create_mock_allow_envelope()
    response_body = {"envelope": envelope_data}

    # Mock HTTP endpoint
    mock_route = respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=200,
            json=response_body,
            headers={"X-CAGE-Routing-Seal": "mock.seal"},
        )
    )

    # Execute validation
    result = await cage_client.validate_action(
        action="execute_trade",
        parameters={"symbol": "AAPL", "amount": 1000},
        agent_id="test-agent",
        context={"session_id": "test-session"},
    )

    # Assertions
    assert isinstance(result, GovernanceEnvelope)
    assert result.envelope_version == "3.0"
    assert result.envelope_type == "cage_governance_decision"
    assert result.payload["decision"] == "ALLOW"
    assert result.subject["action"] == "execute_trade"
    assert result.subject["agent_id"] == "test-agent"

    # Verify envelope is frozen (immutable) - test the model itself
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        result.envelope_version = "4.0"  # type: ignore

    # Verify request was made
    assert mock_route.called
    assert mock_route.call_count == 1


@respx.mock
async def test_validate_action_deny_raises_policy_violation(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test DENY response raises PolicyViolationException with structured details."""
    # Mock DENY response
    response_body = {
        "reason_code": "TIER_3_BLOCKED",
        "details": {
            "failed_tier": "tier_3",
            "policy_rule": "high_value_trade_limit",
            "evidence": "Trade amount exceeds $10,000 threshold",
            "suggested_alternatives": ["reduce_amount", "request_approval"],
        },
        "audit_id": "audit-12345",
        "recoverable": True,
    }

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=403,
            json=response_body,
        )
    )

    # Execute validation and assert exception
    with pytest.raises(PolicyViolationException) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "AAPL", "amount": 50000},
            agent_id="test-agent",
        )

    # Verify exception attributes
    exc = exc_info.value
    assert exc.reason_code == "TIER_3_BLOCKED"
    assert exc.audit_id == "audit-12345"
    assert exc.recoverable is True
    assert exc.violation_details["failed_tier"] == "tier_3"
    assert exc.violation_details["policy_rule"] == "high_value_trade_limit"
    assert "suggested_alternatives" in exc.violation_details
    assert "reduce_amount" in exc.violation_details["suggested_alternatives"]


@respx.mock
async def test_validate_action_defer_raises_deferral_pending(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test DEFER response raises DeferralPending with ticket_id."""
    # Mock DEFER response
    expires_at = datetime.now(timezone.utc) + timedelta(hours=4)
    response_body = {
        "ticket_id": "defer-ticket-789",
        "reason": "High-value trade requires manual approval",
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": 14400,
    }

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=202,
            json=response_body,
        )
    )

    # Execute validation and assert exception
    with pytest.raises(DeferralPending) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "GOOGL", "amount": 100000},
            agent_id="test-agent",
        )

    # Verify exception attributes
    exc = exc_info.value
    assert exc.ticket_id == "defer-ticket-789"
    assert exc.defer_reason == "High-value trade requires manual approval"
    assert exc.ttl_seconds == 14400
    assert isinstance(exc.expires_at, datetime)
    # Verify expires_at is in the future
    assert exc.expires_at > datetime.now(timezone.utc)


@respx.mock
async def test_validate_action_transport_failure_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test connection timeout/500 errors fail closed with CageGatewayError."""
    # Test 1: Connection timeout (network failure)
    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        side_effect=httpx.ConnectTimeout("Connection timed out")
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "TSLA", "amount": 5000},
            agent_id="test-agent",
        )

    assert "Failed to reach CAGE Gateway" in str(exc_info.value)

    # Test 2: 500 Internal Server Error (fail-closed)
    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=500,
            text="Internal Server Error",
        )
    )

    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "AMZN", "amount": 3000},
            agent_id="test-agent",
        )

    assert "Gateway server error" in str(exc_info.value)
    assert "500" in str(exc_info.value)


@respx.mock
async def test_routing_seal_tamper_detection(
    cage_client: CageClient,
    mock_gateway_url: str,
    mock_routing_seal_secret: str,
):
    """Test verify_routing_seal raises on body tampering."""
    # Create valid envelope
    envelope_data = create_mock_allow_envelope()
    response_body = {"envelope": envelope_data}
    original_bytes = json.dumps(response_body).encode("utf-8")

    # Generate seal for original body
    valid_seal = generate_mock_routing_seal(original_bytes, mock_routing_seal_secret)

    # Tamper with response body (change decision to DENY)
    tampered_body = response_body.copy()
    tampered_body["envelope"]["payload"]["decision"] = "DENY"

    # Mock endpoint with tampered body but original seal
    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=200,
            json=tampered_body,  # Tampered content
            headers={"X-CAGE-Routing-Seal": valid_seal},  # Seal for original
        )
    )

    # Execute validation and assert seal verification failure
    with pytest.raises(RoutingSealVerificationError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "MSFT", "amount": 2000},
            agent_id="test-agent",
        )

    assert (
        "tampering detected" in str(exc_info.value).lower()
        or "mismatch" in str(exc_info.value).lower()
    )


@respx.mock
async def test_routing_seal_missing_header_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test missing routing seal header fails closed when seal is configured."""
    # Mock ALLOW response without routing seal header
    envelope_data = create_mock_allow_envelope()
    response_body = {"envelope": envelope_data}

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=200,
            json=response_body,
            # No X-CAGE-Routing-Seal header
        )
    )

    # Execute validation and assert failure
    with pytest.raises(RoutingSealVerificationError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "NVDA", "amount": 1500},
            agent_id="test-agent",
        )

    assert "missing" in str(exc_info.value).lower()
    assert "X-CAGE-Routing-Seal" in str(exc_info.value)


@respx.mock
async def test_deny_response_missing_audit_id_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test DENY response without audit_id fails closed with CageGatewayError."""
    # Mock malformed DENY response (no audit_id)
    response_body = {
        "reason_code": "UNKNOWN_ERROR",
        "details": {},
        # Missing audit_id field
        "recoverable": True,
    }

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=403,
            json=response_body,
        )
    )

    # Execute validation and assert CageGatewayError
    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "META", "amount": 7500},
            agent_id="test-agent",
        )

    assert "missing required 'audit_id' field" in str(exc_info.value)


@respx.mock
async def test_defer_response_missing_ticket_id_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test DEFER response without ticket_id fails closed with CageGatewayError."""
    # Mock malformed DEFER response (no ticket_id)
    response_body = {
        "reason": "Requires approval",
        "ttl_seconds": 14400,
        # Missing ticket_id field
    }

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=202,
            json=response_body,
        )
    )

    # Execute validation and assert CageGatewayError
    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "NFLX", "amount": 4000},
            agent_id="test-agent",
        )

    assert "missing required 'ticket_id' field" in str(exc_info.value)


@respx.mock
async def test_allow_response_missing_envelope_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test ALLOW response without envelope field fails closed."""
    # Mock malformed ALLOW response (no envelope)
    response_body = {
        "status": "success",
        # Missing envelope field
    }

    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=200,
            json=response_body,
        )
    )

    # Execute validation and assert CageGatewayError
    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "ORCL", "amount": 2500},
            agent_id="test-agent",
        )

    assert "missing required 'envelope' field" in str(exc_info.value)


@respx.mock
async def test_unexpected_status_code_fails_closed(
    cage_client: CageClient,
    mock_gateway_url: str,
):
    """Test unexpected HTTP status code fails closed."""
    # Mock 418 I'm a teapot (unexpected status)
    respx.post(f"{mock_gateway_url}/v1/governance/validate").mock(
        return_value=httpx.Response(
            status_code=418,
            text="I'm a teapot",
        )
    )

    # Execute validation and assert CageGatewayError
    with pytest.raises(CageGatewayError) as exc_info:
        await cage_client.validate_action(
            action="execute_trade",
            parameters={"symbol": "IBM", "amount": 1000},
            agent_id="test-agent",
        )

    assert "Unexpected gateway response" in str(exc_info.value)
    assert "418" in str(exc_info.value)


async def test_client_context_manager_lifecycle(mock_gateway_url: str, monkeypatch):
    """Test CageClient async context manager properly opens and closes."""

    # Mock transport to avoid h2 dependency
    def mock_create_mtls_transport(*args, **kwargs):
        return httpx.HTTPTransport()

    monkeypatch.setattr(
        "src.gateway.client.transport.create_mtls_transport", mock_create_mtls_transport
    )

    # Patch AsyncClient to disable http2
    original_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs["http2"] = False
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr("httpx.AsyncClient", patched_async_client)

    async with CageClient(gateway_url=mock_gateway_url) as client:
        assert client._client is not None
        # Verify client was initialized (can't use isinstance due to monkeypatch)
        assert hasattr(client._client, "aclose")

    # After context exit, client should be closed


def test_parameter_canonicalization():
    """Test parameter canonicalization produces deterministic JSON."""
    # Test 1: Key ordering
    params1 = {"z": 3, "a": 1, "m": 2}
    params2 = {"a": 1, "m": 2, "z": 3}

    canon1 = CageClient._canonicalize_params(params1)
    canon2 = CageClient._canonicalize_params(params2)

    assert canon1 == canon2
    assert canon1 == '{"a":1,"m":2,"z":3}'

    # Test 2: Nested structures
    params3 = {"nested": {"b": 2, "a": 1}, "top": "value"}
    canon3 = CageClient._canonicalize_params(params3)
    assert '{"nested":{"a":1,"b":2},"top":"value"}' == canon3
