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
test_defer_polling_endpoint.py — Unit and integration tests for ADR-008 Phase 4.

Verifies:
  1. DeferQueue.get_token() returns None on unknown defer_id without error
  2. GET /v1/defer/{unknown_id} returns HTTP 404
  3. GET /v1/defer/{defer_id} returns HTTP 200 with status="PARKED" for parked tokens
  4. GET /v1/defer/{defer_id} includes routing_seal when status="RESOLVED"
"""

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Mark all tests in this module
pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for DeferQueue tests."""
    client = MagicMock()
    client.hget = AsyncMock(return_value=None)
    client.hset = AsyncMock()
    client.expire = AsyncMock()
    client.zadd = AsyncMock()
    client.zrem = AsyncMock()
    client.pipeline = MagicMock()
    client.aclose = AsyncMock()
    return client


@pytest.fixture
def mock_defer_queue(mock_redis_client):
    """Fixture providing a DeferQueue instance with mocked Redis."""
    from src.gateway.governance.defer_queue import DeferQueue

    return DeferQueue(mock_redis_client)


# ---------------------------------------------------------------------------
# Unit Tests — DeferQueue.get_token()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_token_returns_none_on_unknown_token(
    mock_defer_queue, mock_redis_client
):
    """Verify get_token returns None on unknown token without raising an error."""
    mock_redis_client.hget.return_value = None

    result = await mock_defer_queue.get_token("unknown-defer-id-12345")

    assert result is None
    mock_redis_client.hget.assert_awaited_once_with(
        "DEFER:unknown-defer-id-12345", "token"
    )


@pytest.mark.asyncio
async def test_get_token_returns_token_when_exists(mock_defer_queue, mock_redis_client):
    """Verify get_token deserializes and returns a valid DeferToken."""
    from src.gateway.governance.defer_queue import DeferReason, DeferToken

    mock_token = DeferToken(
        defer_id="test-defer-123",
        thread_id="thread-456",
        defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        confidence_score=0.65,
        ttl_seconds=3600,
    )
    mock_redis_client.hget.return_value = mock_token.model_dump_json()

    result = await mock_defer_queue.get_token("test-defer-123")

    assert result is not None
    assert result.defer_id == "test-defer-123"
    assert result.thread_id == "thread-456"
    assert result.defer_reason == DeferReason.CONFIDENCE_BELOW_THRESHOLD
    assert result.confidence_score == 0.65


# ---------------------------------------------------------------------------
# Integration Tests — GET /v1/defer/{defer_id} Endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def compliance_bridge_client():
    """FastAPI test client for compliance-bridge."""
    from src.compliance_bridge.main import app

    return TestClient(app)


def test_get_defer_status_returns_404_on_unknown_token(compliance_bridge_client):
    """Verify GET /v1/defer/{unknown_id} returns HTTP 404."""
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379"}):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.hget = AsyncMock(return_value=None)
            mock_client.aclose = AsyncMock()
            mock_from_url.return_value = mock_client

            response = compliance_bridge_client.get("/v1/defer/unknown-defer-id-999")

            assert response.status_code == 404
            data = response.json()
            assert "detail" in data
            # detail can be a string or dict depending on response format
            detail_str = (
                data["detail"]
                if isinstance(data["detail"], str)
                else str(data["detail"])
            )
            assert "not found" in detail_str.lower()


def test_get_defer_status_returns_200_with_parked_status(compliance_bridge_client):
    """Verify GET /v1/defer/{defer_id} returns HTTP 200 with status='PARKED'."""
    from src.gateway.governance.defer_queue import DeferReason, DeferToken

    mock_token = DeferToken(
        defer_id="parked-token-001",
        thread_id="thread-789",
        defer_reason=DeferReason.INSUFFICIENT_CONTEXT,
        confidence_score=0.68,
        ttl_seconds=3600,
        deferred_at_utc=datetime.now(tz=timezone.utc).isoformat(),
    )

    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379"}):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.hget = AsyncMock()
            # First call returns token JSON, second call returns status
            mock_client.hget.side_effect = [
                mock_token.model_dump_json(),  # token data
                "PARKED",  # status
            ]
            mock_client.aclose = AsyncMock()
            mock_from_url.return_value = mock_client

            response = compliance_bridge_client.get("/v1/defer/parked-token-001")

            assert response.status_code == 200
            data = response.json()
            assert data["defer_id"] == "parked-token-001"
            assert data["status"] == "PARKED"
            assert data["defer_reason"] == "INSUFFICIENT_CONTEXT"
            assert data["confidence_score"] == 0.68
            assert data["ttl_seconds"] == 3600
            assert "created_at" in data
            # routing_seal should be None when status != RESOLVED
            assert data["routing_seal"] is None


def test_get_defer_status_includes_routing_seal_when_resolved(compliance_bridge_client):
    """Verify GET /v1/defer/{defer_id} includes routing_seal field when status='RESOLVED'.

    Note: routing_seal is currently None since DeferToken model doesn't include it yet.
    This test verifies the response structure includes the field for future compatibility.
    """
    from src.gateway.governance.defer_queue import DeferReason, DeferToken

    mock_token = DeferToken(
        defer_id="resolved-token-002",
        thread_id="thread-abc",
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=0.85,
        ttl_seconds=300,
        deferred_at_utc=datetime.now(tz=timezone.utc).isoformat(),
        resolved_at_utc=datetime.now(tz=timezone.utc).isoformat(),
        resolution="ESCALATED",
    )

    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379"}):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.hget = AsyncMock()
            mock_client.hget.side_effect = [
                mock_token.model_dump_json(),  # token data
                "RESOLVED",  # status
            ]
            mock_client.aclose = AsyncMock()
            mock_from_url.return_value = mock_client

            response = compliance_bridge_client.get("/v1/defer/resolved-token-002")

            assert response.status_code == 200
            data = response.json()
            assert data["defer_id"] == "resolved-token-002"
            assert data["status"] == "RESOLVED"
            assert data["defer_reason"] == "EXTERNAL_HOLD"
            # Verify routing_seal field exists in response (None when not in model schema)
            assert "routing_seal" in data
            # When RESOLVED, the field should be included (currently None since model lacks it)
            assert (
                data["routing_seal"] is None
            )  # Will be populated when DeferToken.routing_seal is added


def test_get_defer_status_handles_redis_unavailable(compliance_bridge_client):
    """Verify GET /v1/defer/{defer_id} returns HTTP 503 when Redis is unavailable."""
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379"}):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.side_effect = ConnectionError("Connect call failed")

            response = compliance_bridge_client.get("/v1/defer/any-defer-id")

            assert response.status_code == 503
            data = response.json()
            # FastAPI wraps detail dict, so check both formats
            if "error" in data:
                assert "DEFER_QUEUE_UNAVAILABLE" in data["error"]
            else:
                assert "detail" in data
                assert "DEFER_QUEUE_UNAVAILABLE" in str(data["detail"])


def test_get_defer_status_with_partially_approved_status(compliance_bridge_client):
    """Verify GET /v1/defer/{defer_id} handles PARTIALLY_APPROVED status correctly."""
    from src.gateway.governance.defer_queue import DeferReason, DeferToken

    mock_token = DeferToken(
        defer_id="partial-token-003",
        thread_id="thread-xyz",
        defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
        confidence_score=0.75,
        ttl_seconds=3600,
        deferred_at_utc=datetime.now(tz=timezone.utc).isoformat(),
        required_quorum=3,
    )

    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379"}):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.hget = AsyncMock()
            mock_client.hget.side_effect = [
                mock_token.model_dump_json(),  # token data
                "PARTIALLY_APPROVED",  # status
            ]
            mock_client.aclose = AsyncMock()
            mock_from_url.return_value = mock_client

            response = compliance_bridge_client.get("/v1/defer/partial-token-003")

            assert response.status_code == 200
            data = response.json()
            assert data["defer_id"] == "partial-token-003"
            assert data["status"] == "PARTIALLY_APPROVED"
            assert data["defer_reason"] == "FTRA_IRREVERSIBLE_TERMINAL"
            # routing_seal should be None when status != RESOLVED
            assert data["routing_seal"] is None


def test_get_defer_status_handles_missing_redis_url():
    """Verify endpoint returns HTTP 503 when REDIS_URL is not configured."""
    from src.compliance_bridge.main import app

    client = TestClient(app)

    with patch.dict(os.environ, {"REDIS_URL": ""}, clear=False):
        response = client.get("/v1/defer/any-defer-id")

        assert response.status_code == 503
        data = response.json()
        # FastAPI wraps detail dict, so check both formats
        if "error" in data:
            assert "REDIS_URL_NOT_CONFIGURED" in data["error"]
        else:
            assert "detail" in data
            assert "REDIS_URL_NOT_CONFIGURED" in str(data["detail"])
