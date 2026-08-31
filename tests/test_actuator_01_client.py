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
test_actuator_01_client.py — mTLS HTTP Client Tests

Tests for the mTLS transport layer per Phase 2, Stream C.
"""

import base64
import time

import pytest
from respx import MockRouter

from src.integrations.actuator_01.client import ActuatorHttpClient

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_client(monkeypatch, tmp_path):
    """Create a test client with mocked SSL context."""
    import ssl
    from unittest.mock import MagicMock
    
    # Create placeholder cert files (content doesn't matter, we mock SSL)
    cert_file = tmp_path / "test-cert.pem"
    key_file = tmp_path / "test-key.pem"
    ca_file = tmp_path / "test-ca.pem"
    
    cert_file.write_text("mock cert")
    key_file.write_text("mock key")
    ca_file.write_text("mock ca")
    
    # Mock SSL context creation (respx already mocks HTTP, we just need valid context object)
    mock_context = MagicMock(spec=ssl.SSLContext)
    original_create_context = ssl.create_default_context
    
    def mock_create_context(*args, **kwargs):
        # Call original but return mock
        return mock_context
    
    monkeypatch.setattr(ssl, "create_default_context", mock_create_context)
    
    return ActuatorHttpClient(
        base_url="https://actuator.example.com",
        cert_path=str(cert_file),
        key_path=str(key_file),
        ca_path=str(ca_file),
        tenant_id="test-tenant-001",
    )


class TestActuatorHttpClient:
    """Test the mTLS HTTP client."""

    @pytest.mark.asyncio
    async def test_submit_envelope_sends_content_bytes(self, mock_client, respx_mock: MockRouter):
        """Client uses content= (not json=) to preserve exact bytes."""
        canonical_bytes = b'{"action":"execute_trade"}'
        operator_urns = ["urn:cage:operator:a", "urn:cage:operator:b"]
        signatures = ["aabbcc" * 21 + "aa", "ddeeff" * 21 + "dd"]  # 128 hex chars each
        assertion = base64.b64encode(b"x" * 120).decode()
        issued_at = int(time.time())

        # Mock the POST /submit endpoint
        route = respx_mock.post("https://actuator.example.com/submit").mock(
            return_value=httpx.Response(
                status_code=200,
                json={"receipt_id": "receipt-001", "executed_at": issued_at, "status": "EXECUTED"},
            )
        )

        async with mock_client:
            response = await mock_client.submit_envelope(
                canonical_bytes, operator_urns, signatures, assertion, issued_at
            )

        assert response.status_code == 200
        
        # Verify request was made with exact bytes
        request = route.calls.last.request
        assert request.content == canonical_bytes

    @pytest.mark.asyncio
    async def test_submit_envelope_headers_positionally_aligned(self, mock_client, respx_mock: MockRouter):
        """URNs and signatures are positionally aligned in headers."""
        canonical_bytes = b'{"test":"data"}'
        operator_urns = ["urn:cage:operator:alice", "urn:cage:operator:bob"]
        signatures = ["sig1" + "0" * 124, "sig2" + "0" * 124]
        assertion = base64.b64encode(b"y" * 120).decode()
        issued_at = 1234567890

        route = respx_mock.post("https://actuator.example.com/submit").mock(
            return_value=httpx.Response(200, json={"receipt_id": "test"})
        )

        async with mock_client:
            await mock_client.submit_envelope(
                canonical_bytes, operator_urns, signatures, assertion, issued_at
            )

        request = route.calls.last.request
        headers = dict(request.headers)

        # Verify positional alignment
        assert headers["x-operator-urns"] == "urn:cage:operator:alice,urn:cage:operator:bob"
        assert headers["x-quorum-signatures"] == f"sig1{'0' * 124},sig2{'0' * 124}"

    @pytest.mark.asyncio
    async def test_submit_envelope_validates_quorum(self, mock_client):
        """Client rejects insufficient quorum before sending."""
        canonical_bytes = b'{"test":"data"}'
        operator_urns = ["urn:cage:operator:alice"]  # Only 1 URN
        signatures = ["sig1" + "0" * 124]
        assertion = base64.b64encode(b"z" * 120).decode()
        issued_at = int(time.time())

        async with mock_client:
            with pytest.raises(RuntimeError, match="Insufficient quorum"):
                await mock_client.submit_envelope(
                    canonical_bytes, operator_urns, signatures, assertion, issued_at
                )

    @pytest.mark.asyncio
    async def test_submit_envelope_validates_signature_count(self, mock_client):
        """Client rejects URN/signature count mismatch."""
        canonical_bytes = b'{"test":"data"}'
        operator_urns = ["urn:cage:operator:a", "urn:cage:operator:b"]
        signatures = ["sig1" + "0" * 124]  # Only 1 signature for 2 URNs
        assertion = base64.b64encode(b"w" * 120).decode()
        issued_at = int(time.time())

        async with mock_client:
            with pytest.raises(RuntimeError, match="URN/signature count mismatch"):
                await mock_client.submit_envelope(
                    canonical_bytes, operator_urns, signatures, assertion, issued_at
                )

    @pytest.mark.asyncio
    async def test_health_check_returns_true_on_200(self, mock_client, respx_mock: MockRouter):
        """Health check returns True when endpoint responds 200."""
        respx_mock.get("https://actuator.example.com/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )

        async with mock_client:
            healthy = await mock_client.health_check()

        assert healthy is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(self, mock_client, respx_mock: MockRouter):
        """Health check returns False when endpoint is unreachable."""
        respx_mock.get("https://actuator.example.com/health").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        async with mock_client:
            healthy = await mock_client.health_check()

        assert healthy is False


# Import httpx for Response mocking
import httpx
