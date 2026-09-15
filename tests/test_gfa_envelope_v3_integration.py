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
Regression test suite for GFA GovernanceEnvelope v3.0 integration.

This suite verifies the silent denial bug fix where `GatewayClient.validate_action()`
was incorrectly parsing v3.0 envelopes, resulting in `result.get("verdict", "DENIED")`
evaluating to "DENIED" because the verdict was nested at `result["payload"]["verdict"]`.

Tests:
1. test_gfa_unwraps_v3_envelope_correctly: Verifies APPROVED verdict unwrapping
2. test_gfa_raises_permission_error_on_denied_verdict: Verifies DENIED raises PermissionError
3. test_gfa_preserves_envelope_metadata: Verifies envelope metadata is retained
4. test_gfa_falls_back_gracefully_on_legacy_flat_dict: Backward compatibility check
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_v3_envelope_approved():
    """Mock HTTP response with v3.0 envelope containing APPROVED verdict."""
    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-test-12345",
        "issued_at": "2026-09-14T21:00:00.000Z",
        "expires_at": "2026-09-14T21:05:00.000Z",
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gke-test-abc123",
            "region": "us-central1",
        },
        "subject": {
            "action": "execute_trade",
            "action_hash": "sha256:abc123def456",
            "record_hash": "sha256:rec789",
            "consequence_ceiling": "LOW_INFORMATIONAL",
            "target_route": "local://default",
            "executor_id": "kernel",
        },
        "governance_context": {
            "policy_version": "sha256:policy-v1",
            "tiers_passed": ["stpa", "cbf", "opa", "consensus"],
            "deployment_region": "US_FED",
            "controls_satisfied": ["CTRL_OPA_001", "CTRL_CBF_002"],
        },
        "payload": {
            "verdict": "APPROVED",
            "seal": "seal-abc123",
            "violations": [],
            "latency_ms": 42.5,
        },
        "external_attestations": [],
        "signature": {
            "algorithm": "ES256",
            "kid": "key-123",
            "value": "base64url-signature-value",
        },
    }


@pytest.fixture
def mock_v3_envelope_denied():
    """Mock HTTP response with v3.0 envelope containing DENIED verdict."""
    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-test-67890",
        "issued_at": "2026-09-14T21:00:00.000Z",
        "expires_at": "2026-09-14T21:05:00.000Z",
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gke-test-abc123",
            "region": "us-central1",
        },
        "subject": {
            "action": "execute_trade",
            "action_hash": "sha256:xyz789",
            "consequence_ceiling": "LOW_INFORMATIONAL",
            "target_route": "local://default",
            "executor_id": "kernel",
        },
        "governance_context": {
            "policy_version": "sha256:policy-v1",
            "tiers_passed": ["stpa"],
            "deployment_region": "US_FED",
            "controls_satisfied": [],
        },
        "payload": {
            "verdict": "DENIED",
            "seal": "",
            "violations": ["OPA policy violation: trade_amount exceeds limit"],
            "latency_ms": 15.2,
        },
        "external_attestations": [],
    }


@pytest.fixture
def mock_legacy_flat_response():
    """Mock HTTP response with legacy flat dictionary (pre-v3.0)."""
    return {
        "verdict": "APPROVED",
        "seal": "seal-legacy-123",
        "violations": [],
        "latency_ms": 30.0,
    }


@pytest.mark.asyncio
async def test_gfa_unwraps_v3_envelope_correctly(mock_v3_envelope_approved):
    """
    Test that GatewayClient correctly unwraps a v3.0 envelope with APPROVED verdict.

    This test verifies the fix for the silent denial bug where the client
    incorrectly parsed `result.get("verdict", "DENIED")` from the outer envelope
    instead of unwrapping `result["payload"]["verdict"]`.

    Expected behavior:
    - Verdict should be "APPROVED" (from payload)
    - Seal should be present (from payload)
    - Envelope metadata should be merged into the result
    """
    client = GatewayClient()

    with patch.object(
        client, "_ensure_client", return_value=AsyncMock()
    ) as mock_client_factory:
        mock_http = mock_client_factory.return_value
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: mock_v3_envelope_approved
        mock_response.raise_for_status = lambda: None
        mock_http.post.return_value = mock_response

        result = await client.validate_action(
            "execute_trade", {"symbol": "AAPL", "amount": 1000}
        )

        # Verify unwrapping occurred correctly
        assert result["verdict"] == "APPROVED", (
            "Verdict should be unwrapped from payload"
        )
        assert result["seal"] == "seal-abc123", "Seal should be unwrapped from payload"
        assert result["violations"] == [], "Violations should be unwrapped from payload"
        assert result["latency_ms"] == 42.5, "Latency should be unwrapped from payload"

        # Verify envelope metadata is preserved
        assert result["envelope_id"] == "env-test-12345"
        assert result["envelope_version"] == "3.0"
        assert result["issuer"]["service"] == "cage-gateway"
        assert result["subject"]["action"] == "execute_trade"
        assert result["governance_context"]["tiers_passed"] == [
            "stpa",
            "cbf",
            "opa",
            "consensus",
        ]


@pytest.mark.asyncio
async def test_gfa_raises_permission_error_on_denied_verdict(mock_v3_envelope_denied):
    """
    Test that GatewayClient raises PermissionError on DENIED verdict from v3.0 envelope.

    Expected behavior:
    - PermissionError should be raised
    - Error message should contain the action name and violations
    """
    client = GatewayClient()

    with patch.object(
        client, "_ensure_client", return_value=AsyncMock()
    ) as mock_client_factory:
        mock_http = mock_client_factory.return_value
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: mock_v3_envelope_denied
        mock_response.raise_for_status = lambda: None
        mock_http.post.return_value = mock_response

        with pytest.raises(PermissionError) as exc_info:
            await client.validate_action(
                "execute_trade", {"symbol": "AAPL", "amount": 999999}
            )

        # Verify error message contains violations
        assert "execute_trade" in str(exc_info.value)
        assert "trade_amount exceeds limit" in str(exc_info.value)


@pytest.mark.asyncio
async def test_gfa_preserves_envelope_metadata(mock_v3_envelope_approved):
    """
    Test that envelope metadata (envelope_id, version, subject, etc.) is preserved.

    Expected behavior:
    - All top-level envelope fields are merged into the returned dictionary
    - Payload fields are at the top level (verdict, seal, violations, latency_ms)
    - Envelope metadata is accessible alongside payload data
    """
    client = GatewayClient()

    with patch.object(
        client, "_ensure_client", return_value=AsyncMock()
    ) as mock_client_factory:
        mock_http = mock_client_factory.return_value
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: mock_v3_envelope_approved
        mock_response.raise_for_status = lambda: None
        mock_http.post.return_value = mock_response

        result = await client.validate_action("execute_trade", {"symbol": "AAPL"})

        # Verify envelope metadata
        assert "envelope_id" in result
        assert "envelope_version" in result
        assert "issuer" in result
        assert "subject" in result
        assert "signature" in result
        assert "governance_context" in result
        assert "external_attestations" in result

        # Verify payload data is at top level
        assert "verdict" in result
        assert "seal" in result
        assert "violations" in result
        assert "latency_ms" in result


@pytest.mark.asyncio
async def test_gfa_falls_back_gracefully_on_legacy_flat_dict(mock_legacy_flat_response):
    """
    Test backward compatibility with legacy flat dictionary responses (pre-v3.0).

    If the gateway returns a flat dict without envelope_version, the client
    should process it as-is without attempting to unwrap.

    Expected behavior:
    - Verdict is read directly from top-level "verdict" key
    - No unwrapping occurs
    - No errors are raised
    """
    client = GatewayClient()

    with patch.object(
        client, "_ensure_client", return_value=AsyncMock()
    ) as mock_client_factory:
        mock_http = mock_client_factory.return_value
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: mock_legacy_flat_response
        mock_response.raise_for_status = lambda: None
        mock_http.post.return_value = mock_response

        result = await client.validate_action("execute_trade", {"symbol": "AAPL"})

        # Verify legacy flat response is processed correctly
        assert result["verdict"] == "APPROVED"
        assert result["seal"] == "seal-legacy-123"
        assert result["violations"] == []
        assert result["latency_ms"] == 30.0

        # Verify no envelope metadata is present (legacy format)
        assert "envelope_id" not in result
        assert "envelope_version" not in result


@pytest.mark.asyncio
async def test_gfa_unwraps_v3_envelope_on_retry_path(mock_v3_envelope_approved):
    """
    Test that v3.0 envelope unwrapping also works in the retry path (policy drift recovery).

    Expected behavior:
    - 403 with drift violation triggers retry
    - Retry response with v3.0 envelope is correctly unwrapped
    - APPROVED verdict is returned after unwrapping
    """
    client = GatewayClient()

    # First response: 403 with drift violation
    first_response_json = {
        "violations": ["Substrate Policy Drift Detected: policy version mismatch"]
    }

    # Policy version response
    policy_version_response = {"active_hash": "sha256:policy-v2"}

    with patch.object(
        client, "_ensure_client", return_value=AsyncMock()
    ) as mock_client_factory:
        mock_http = mock_client_factory.return_value

        # Mock first POST (403 response)
        first_response = AsyncMock()
        first_response.status_code = 403
        first_response.json = lambda: first_response_json

        # Mock GET /governance/policy-version
        policy_response = AsyncMock()
        policy_response.json = lambda: policy_version_response
        policy_response.raise_for_status = lambda: None

        # Mock retry POST (200 with v3.0 envelope)
        retry_response = AsyncMock()
        retry_response.status_code = 200
        retry_response.json = lambda: mock_v3_envelope_approved
        retry_response.raise_for_status = lambda: None

        # Configure mock HTTP client
        mock_http.post.side_effect = [first_response, retry_response]
        mock_http.get.return_value = policy_response

        result = await client.validate_action("execute_trade", {"symbol": "AAPL"})

        # Verify unwrapping occurred correctly on retry path
        assert result["verdict"] == "APPROVED"
        assert result["seal"] == "seal-abc123"
        assert result["envelope_id"] == "env-test-12345"
        assert result["envelope_version"] == "3.0"
