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
test_execution_actuator_broker.py — Credential Broker Integration Tests

Verifies that ExecutionActuator correctly integrates with CredentialBrokerAdapter:
- Fetches and attaches outbound authentication headers
- Masks credentials in logs and audit records
- Fails closed on unauthorized SVIDs
"""

import hashlib
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.gateway.governance.execution_actuator import (
    ActuationReceipt,
    ExecutionClearance,
)
from src.gateway.governance.seams.credential_broker import (
    CredentialAccessDenied,
    CredentialBrokerAdapter,
    CredentialNotFound,
)
from src.integrations.actuator_01.adapter import Actuator01Adapter
from src.integrations.actuator_01.client import ActuatorHttpClient

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ── Mock Helpers ──────────────────────────────────────────────────────────


class MockCredentialBroker:
    """Mock credential broker that returns test credentials."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        raise_error: Exception | None = None,
    ):
        self.headers = headers or {"Authorization": "Bearer test-token-12345678"}
        self.raise_error = raise_error
        self.fetch_calls: list[tuple[str, str, str | None]] = []

    async def fetch_credential(
        self,
        agent_svid: str,
        tool_name: str,
        scope: str | None = None,
    ) -> dict[str, str]:
        self.fetch_calls.append((agent_svid, tool_name, scope))
        if self.raise_error:
            raise self.raise_error
        return self.headers.copy()


class MockSigner:
    """Mock signer for test purposes."""

    is_kms_active = True

    def sign_raw(self, message: bytes) -> bytes:
        """Return a deterministic 64-byte signature."""
        return hashlib.sha512(b"test-key" + message).digest()[:64]


def make_valid_clearance(
    operator_urns: list[str] | None = None,
    action: str = "execute_trade",
) -> ExecutionClearance:
    """Factory for valid ExecutionClearance."""
    if operator_urns is None:
        operator_urns = ["urn:cage:agent:advisor-prod", "urn:cage:agent:trader-prod"]

    return ExecutionClearance(
        thread_id="test-thread-broker-001",
        decision="ALLOW",
        decision_path="DIRECT",
        action=action,
        target="account:1234567890",
        operator_urn=operator_urns[0],
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        approvals=[
            {
                "approver_urn": urn,
                "timestamp": 1785012000,
                "method": "hardware_token",
            }
            for urn in operator_urns
        ],
        required_quorum=2,
        executor_id="actuator_01",
        target_route="https://test.actuator.example.com",
    )


# ── Tests ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_actuator_fetches_and_attaches_credentials():
    """ExecutionActuator fetches credentials and attaches to outbound request."""
    # Arrange
    mock_broker = MockCredentialBroker(
        headers={"Authorization": "Bearer secret-api-key-abcd1234"}
    )
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    # Mock successful response
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "accepted",
        "receipt_id": "receipt-001",
        "session_uuid": "session-001",
    }
    mock_client.submit_envelope = AsyncMock(return_value=mock_response)

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=mock_broker,
    )

    clearance = make_valid_clearance()

    # Act
    receipt = await adapter.actuate(clearance)

    # Assert
    assert receipt.accepted is True
    assert receipt.receipt_id == "receipt-001"

    # Verify broker was called with correct parameters
    assert len(mock_broker.fetch_calls) == 1
    agent_svid, tool_name, scope = mock_broker.fetch_calls[0]
    assert agent_svid == "urn:cage:agent:advisor-prod"
    assert tool_name == "execute_trade"
    assert scope is None

    # Verify credentials were passed to HTTP client
    assert mock_client.submit_envelope.called
    call_kwargs = mock_client.submit_envelope.call_args.kwargs
    assert "extra_headers" in call_kwargs
    assert call_kwargs["extra_headers"] == {
        "Authorization": "Bearer secret-api-key-abcd1234"
    }


@pytest.mark.asyncio
async def test_actuator_masks_credentials_in_logs(caplog):
    """Actuator masks credential values in debug logs."""
    # Arrange
    mock_broker = MockCredentialBroker(
        headers={"Authorization": "Bearer sensitive-secret-token-xyz"}
    )
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "accepted",
        "receipt_id": "receipt-002",
        "session_uuid": "session-002",
    }
    mock_client.submit_envelope = AsyncMock(return_value=mock_response)

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=mock_broker,
    )

    clearance = make_valid_clearance()

    # Act
    with caplog.at_level("INFO"):
        await adapter.actuate(clearance)

    # Assert: Full credential value must NOT appear in logs
    log_text = caplog.text
    assert "sensitive-secret-token-xyz" not in log_text

    # Masked prefix should appear
    assert "Bearer s****" in log_text or "Credentials fetched" in log_text


@pytest.mark.asyncio
async def test_actuator_fails_closed_on_credential_access_denied():
    """Actuator fails closed when SVID is unauthorized."""
    # Arrange
    mock_broker = MockCredentialBroker(
        raise_error=CredentialAccessDenied(
            "SVID urn:cage:agent:advisor-prod not authorized for execute_trade"
        )
    )
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=mock_broker,
    )

    clearance = make_valid_clearance()

    # Act
    receipt = await adapter.actuate(clearance)

    # Assert
    assert receipt.accepted is False
    assert receipt.receipt_id is None
    assert len(receipt.findings) == 1
    assert receipt.findings[0]["code"] == "CREDENTIAL_BROKER_FAILED"
    assert receipt.findings[0]["severity"] == "TERMINAL"
    assert "not authorized" in receipt.findings[0]["detail"]


@pytest.mark.asyncio
async def test_actuator_fails_closed_on_credential_not_found():
    """Actuator fails closed when no credential exists for the tool."""
    # Arrange
    mock_broker = MockCredentialBroker(
        raise_error=CredentialNotFound("No credential found for tool: execute_trade")
    )
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=mock_broker,
    )

    clearance = make_valid_clearance()

    # Act
    receipt = await adapter.actuate(clearance)

    # Assert
    assert receipt.accepted is False
    assert len(receipt.findings) == 1
    assert receipt.findings[0]["code"] == "CREDENTIAL_BROKER_FAILED"
    assert "No credential found" in receipt.findings[0]["detail"]


@pytest.mark.asyncio
async def test_actuator_without_broker_proceeds_normally():
    """Actuator operates normally when credential_broker is None."""
    # Arrange
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "accepted",
        "receipt_id": "receipt-003",
        "session_uuid": "session-003",
    }
    mock_client.submit_envelope = AsyncMock(return_value=mock_response)

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=None,  # No broker configured
    )

    clearance = make_valid_clearance()

    # Act
    receipt = await adapter.actuate(clearance)

    # Assert
    assert receipt.accepted is True

    # Verify no extra_headers were passed
    call_kwargs = mock_client.submit_envelope.call_args.kwargs
    assert call_kwargs.get("extra_headers") is None


@pytest.mark.asyncio
async def test_credential_headers_not_in_audit_record():
    """Verify that injected credentials never appear in ActuationReceipt fields."""
    # Arrange
    mock_broker = MockCredentialBroker(
        headers={"Authorization": "Bearer ultra-secret-token-should-not-leak"}
    )
    mock_client = MagicMock(spec=ActuatorHttpClient)
    mock_client.base_url = "https://test.actuator.example.com"

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "accepted",
        "receipt_id": "receipt-004",
        "session_uuid": "session-004",
    }
    mock_client.submit_envelope = AsyncMock(return_value=mock_response)

    adapter = Actuator01Adapter(
        client=mock_client,
        signer=MockSigner(),
        credential_broker=mock_broker,
    )

    clearance = make_valid_clearance()

    # Act
    receipt = await adapter.actuate(clearance)

    # Assert: Credential must NOT appear anywhere in receipt
    receipt_str = str(receipt)
    assert "ultra-secret-token-should-not-leak" not in receipt_str
    assert receipt.raw_receipt is not None
    assert "ultra-secret-token-should-not-leak" not in str(receipt.raw_receipt)
    assert all(
        "ultra-secret-token-should-not-leak" not in str(finding)
        for finding in receipt.findings
    )
