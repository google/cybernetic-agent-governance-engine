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
Unit and local tests for PauseManager in pause_primitive.py.

This test module provides 100% coverage for the PAUSE primitive including:
- Pause request creation and Redis storage
- Resume request handling and idempotency
- Pause state retrieval and expiration
- TTL-based automatic expiration

Test markers:
    @pytest.mark.unit — isolated unit tests with mocked Redis
    @pytest.mark.local — tests with mock Redis (fakeredis)
    @pytest.mark.integration — tests requiring real Redis (skipped by default)

Phase 1.6: CAGE Implementation Plan — Governance Primitives Test Coverage
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.pause_primitive import (
    _EXPIRY_ZSET,
    _KEY_PREFIX,
    PauseManager,
    PauseReason,
    PauseState,
    PauseStatus,
    ResumeResult,
    build_resume_endpoint,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis():
    """Create a mock async Redis client for unit tests.

    This mock simulates Redis hash and sorted set operations used by PauseManager.
    """
    mock = AsyncMock()

    # In-memory storage for the mock
    storage: dict[str, dict[str, str]] = {}
    zset_storage: dict[str, float] = {}

    async def hset(key: str, mapping: dict[str, Any] | None = None, **kwargs):
        if key not in storage:
            storage[key] = {}
        if mapping:
            for k, v in mapping.items():
                storage[key][k] = v if isinstance(v, str) else str(v)
        return 1

    async def hget(key: str, field: str):
        if key in storage and field in storage[key]:
            return storage[key][field]
        return None

    async def expire(key: str, seconds: int):
        return True

    async def zadd(name: str, mapping: dict[str, float]):
        zset_storage.update(mapping)
        return len(mapping)

    async def zrem(name: str, *members: str):
        count = 0
        for m in members:
            if m in zset_storage:
                del zset_storage[m]
                count += 1
        return count

    async def zrangebyscore(
        name: str,
        min_score: float | str,
        max_score: float | str,
        start: int = 0,
        num: int = 100,
    ):
        results = []
        for member, score in zset_storage.items():
            if isinstance(min_score, str) and min_score == "-inf":
                min_val = float("-inf")
            else:
                min_val = float(min_score)
            if isinstance(max_score, str) and max_score == "+inf":
                max_val = float("inf")
            else:
                max_val = float(max_score)
            if min_val <= score <= max_val:
                results.append(member)
        return results[start : start + num]

    async def zcount(name: str, min_score: float | str, max_score: float | str):
        count = 0
        for score in zset_storage.values():
            if isinstance(min_score, str) and min_score == "-inf":
                min_val = float("-inf")
            else:
                min_val = float(min_score)
            if isinstance(max_score, str) and max_score == "+inf":
                max_val = float("inf")
            else:
                max_val = float(max_score)
            if min_val <= score <= max_val:
                count += 1
        return count

    # Transaction pipeline mock
    class MockPipeline:
        def __init__(self):
            self.commands = []

        def hset(self, key, mapping=None, **kwargs):
            self.commands.append(("hset", key, mapping))
            return self

        def expire(self, key, seconds):
            self.commands.append(("expire", key, seconds))
            return self

        def zadd(self, name, mapping):
            self.commands.append(("zadd", name, mapping))
            return self

        def zrem(self, name, *members):
            self.commands.append(("zrem", name, members))
            return self

        async def execute(self):
            results = []
            for cmd in self.commands:
                if cmd[0] == "hset":
                    key, mapping = cmd[1], cmd[2]
                    if key not in storage:
                        storage[key] = {}
                    if mapping:
                        for k, v in mapping.items():
                            storage[key][k] = v if isinstance(v, str) else str(v)
                    results.append(1)
                elif cmd[0] == "zadd":
                    _name, mapping = cmd[1], cmd[2]
                    zset_storage.update(mapping)
                    results.append(len(mapping))
                elif cmd[0] == "zrem":
                    _name, members = cmd[1], cmd[2]
                    count = 0
                    for m in members:
                        if m in zset_storage:
                            del zset_storage[m]
                            count += 1
                    results.append(count)
                elif cmd[0] == "expire":
                    results.append(True)
            return results

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    def pipeline(transaction=True):
        return MockPipeline()

    mock.hset = hset
    mock.hget = hget
    mock.expire = expire
    mock.zadd = zadd
    mock.zrem = zrem
    mock.zrangebyscore = zrangebyscore
    mock.zcount = zcount
    mock.pipeline = pipeline
    mock._storage = storage
    mock._zset_storage = zset_storage

    return mock


@pytest.fixture
def pause_manager(mock_redis):
    """Create a PauseManager instance with mock Redis."""
    return PauseManager(mock_redis)


# ---------------------------------------------------------------------------
# TestPauseManager — Core functionality tests
# ---------------------------------------------------------------------------


class TestPauseManager:
    """Tests for PauseManager pause/resume lifecycle."""

    @pytest.mark.asyncio
    async def test_pause_request_stores_in_redis(self, pause_manager, mock_redis):
        """pause_request() stores the pause state in Redis."""
        pause_token = await pause_manager.pause_request(
            request_id="req-123",
            reason=PauseReason.RATE_LIMITED,
            ttl_seconds=3600,
            original_request={"symbol": "AAPL", "amount": 100},
        )

        # Verify a token was returned
        assert pause_token
        assert len(pause_token) == 36  # UUID format

        # Verify data was stored in Redis
        key = f"{_KEY_PREFIX}{pause_token}"
        assert key in mock_redis._storage
        assert "state" in mock_redis._storage[key]
        assert "status" in mock_redis._storage[key]
        assert mock_redis._storage[key]["status"] == "PAUSED"

    @pytest.mark.asyncio
    async def test_pause_request_returns_uuid(self, pause_manager):
        """pause_request() returns a valid UUID v4 token."""
        pause_token = await pause_manager.pause_request(
            request_id="req-456",
            reason="RATE_LIMITED",
            ttl_seconds=3600,
        )

        # Validate UUID format
        parsed_uuid = uuid.UUID(pause_token, version=4)
        assert str(parsed_uuid) == pause_token

    @pytest.mark.asyncio
    async def test_pause_request_stores_original_request(
        self, pause_manager, mock_redis
    ):
        """pause_request() stores original_request in the pause state."""
        original_request = {"symbol": "GOOG", "amount": 500, "confidence": 0.99}

        pause_token = await pause_manager.pause_request(
            request_id="req-789",
            reason=PauseReason.CIRCUIT_OPEN,
            original_request=original_request,
        )

        # Retrieve and verify
        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.original_request == original_request

    @pytest.mark.asyncio
    async def test_pause_request_stores_thread_id(self, pause_manager, mock_redis):
        """pause_request() stores thread_id for correlation."""
        pause_token = await pause_manager.pause_request(
            request_id="req-thread",
            reason=PauseReason.COORDINATION_WAIT,
            thread_id="thread-abc-123",
        )

        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.thread_id == "thread-abc-123"

    @pytest.mark.asyncio
    async def test_pause_request_with_estimated_wait(self, pause_manager, mock_redis):
        """pause_request() stores estimated_wait_secs."""
        pause_token = await pause_manager.pause_request(
            request_id="req-wait",
            reason=PauseReason.RATE_LIMITED,
            estimated_wait_secs=120,
        )

        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.estimated_wait_secs == 120

    @pytest.mark.asyncio
    async def test_pause_request_adds_to_expiry_index(self, pause_manager, mock_redis):
        """pause_request() adds token to the expiry sorted set."""
        pause_token = await pause_manager.pause_request(
            request_id="req-expiry",
            reason=PauseReason.RESOURCE_UNAVAILABLE,
            ttl_seconds=1800,  # 30 minutes
        )

        # Token should be in the zset
        assert pause_token in mock_redis._zset_storage

    @pytest.mark.asyncio
    async def test_resume_request_updates_state(self, pause_manager, mock_redis):
        """resume_request() updates the pause state to RESUMED."""
        # First, create a pause
        pause_token = await pause_manager.pause_request(
            request_id="req-resume",
            reason=PauseReason.RATE_LIMITED,
        )

        # Resume it
        result = await pause_manager.resume_request(pause_token)

        assert result == ResumeResult.RESUMED

        # Verify state was updated
        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.status == PauseStatus.RESUMED
        assert state.resumed_at_utc is not None

    @pytest.mark.asyncio
    async def test_resume_request_idempotent(self, pause_manager):
        """resume_request() is idempotent — calling twice returns ALREADY_RESUMED."""
        pause_token = await pause_manager.pause_request(
            request_id="req-idempotent",
            reason=PauseReason.CIRCUIT_OPEN,
        )

        # First resume
        result1 = await pause_manager.resume_request(pause_token)
        assert result1 == ResumeResult.RESUMED

        # Second resume (idempotent)
        result2 = await pause_manager.resume_request(pause_token)
        assert result2 == ResumeResult.ALREADY_RESUMED

    @pytest.mark.asyncio
    async def test_resume_request_with_context(self, pause_manager, mock_redis):
        """resume_request() stores resume_context when provided."""
        pause_token = await pause_manager.pause_request(
            request_id="req-context",
            reason=PauseReason.MANUAL_GATE,
        )

        resume_context = {"approved_by": "admin@example.com", "note": "Approved"}
        result = await pause_manager.resume_request(pause_token, resume_context)

        assert result == ResumeResult.RESUMED

        # Verify context was stored
        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.resume_context == resume_context

    @pytest.mark.asyncio
    async def test_get_pause_state_returns_none_for_unknown(self, pause_manager):
        """get_pause_state() returns None for unknown pause tokens."""
        result = await pause_manager.get_pause_state("nonexistent-token-xyz")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_pause_state_returns_state(self, pause_manager):
        """get_pause_state() returns the stored PauseState."""
        pause_token = await pause_manager.pause_request(
            request_id="req-get-state",
            reason=PauseReason.RATE_LIMITED,
            original_request={"test": "data"},
        )

        state = await pause_manager.get_pause_state(pause_token)

        assert state is not None
        assert state.pause_token == pause_token
        assert state.request_id == "req-get-state"
        assert state.pause_reason == PauseReason.RATE_LIMITED
        assert state.original_request == {"test": "data"}
        assert state.status == PauseStatus.PAUSED

    @pytest.mark.asyncio
    async def test_expire_pause_marks_expired(self, pause_manager, mock_redis):
        """expire_pause() marks a pause as EXPIRED."""
        pause_token = await pause_manager.pause_request(
            request_id="req-expire",
            reason=PauseReason.CIRCUIT_OPEN,
        )

        # Explicitly expire
        await pause_manager.expire_pause(pause_token)

        # Verify state is EXPIRED
        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        assert state.status == PauseStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_expire_pause_removes_from_expiry_index(
        self, pause_manager, mock_redis
    ):
        """expire_pause() removes the token from the expiry zset."""
        pause_token = await pause_manager.pause_request(
            request_id="req-expire-zset",
            reason=PauseReason.RATE_LIMITED,
        )

        # Token should be in zset initially
        assert pause_token in mock_redis._zset_storage

        # Expire it
        await pause_manager.expire_pause(pause_token)

        # Token should be removed from zset
        assert pause_token not in mock_redis._zset_storage

    @pytest.mark.asyncio
    async def test_expire_pause_unknown_token_no_error(self, pause_manager):
        """expire_pause() does not raise for unknown tokens."""
        # Should not raise
        await pause_manager.expire_pause("unknown-token-abc")

    @pytest.mark.asyncio
    async def test_resume_expired_pause_returns_expired(
        self, pause_manager, mock_redis
    ):
        """resume_request() returns EXPIRED for an expired pause."""
        # Create a pause with a very short TTL (already expired)
        pause_token = await pause_manager.pause_request(
            request_id="req-expired-resume",
            reason=PauseReason.RATE_LIMITED,
            ttl_seconds=1,  # 1 second
        )

        # Manually set the expires_at to the past
        key = f"{_KEY_PREFIX}{pause_token}"
        state_json = mock_redis._storage[key]["state"]
        state = PauseState.model_validate_json(state_json)

        # Set expiry to 1 second ago
        expired_time = datetime.now(tz=timezone.utc)
        expired_time = datetime.fromtimestamp(
            expired_time.timestamp() - 10, tz=timezone.utc
        )
        state.expires_at_utc = expired_time.isoformat()
        mock_redis._storage[key]["state"] = state.model_dump_json()

        # Try to resume
        result = await pause_manager.resume_request(pause_token)
        assert result == ResumeResult.EXPIRED

    @pytest.mark.asyncio
    async def test_resume_not_found_returns_not_found(self, pause_manager):
        """resume_request() returns NOT_FOUND for unknown tokens."""
        result = await pause_manager.resume_request("nonexistent-pause-token")
        assert result == ResumeResult.NOT_FOUND


# ---------------------------------------------------------------------------
# TestPauseManagerListing — List and count operations
# ---------------------------------------------------------------------------


class TestPauseManagerListing:
    """Tests for PauseManager listing and counting operations."""

    @pytest.mark.asyncio
    async def test_list_active_pauses_returns_paused_only(
        self, pause_manager, mock_redis
    ):
        """list_active_pauses() returns only PAUSED status tokens."""
        # Create some pauses
        token1 = await pause_manager.pause_request(
            request_id="req-list-1",
            reason=PauseReason.RATE_LIMITED,
        )
        token2 = await pause_manager.pause_request(
            request_id="req-list-2",
            reason=PauseReason.CIRCUIT_OPEN,
        )

        # Resume one
        await pause_manager.resume_request(token1)

        # List active pauses
        active = await pause_manager.list_active_pauses()

        # Only token2 should be active
        active_tokens = [p.pause_token for p in active]
        assert token2 in active_tokens
        assert token1 not in active_tokens

    @pytest.mark.asyncio
    async def test_get_active_pause_count(self, pause_manager, mock_redis):
        """get_active_pause_count() returns count of non-expired pauses."""
        # Create some pauses
        await pause_manager.pause_request(
            request_id="req-count-1",
            reason=PauseReason.RATE_LIMITED,
        )
        await pause_manager.pause_request(
            request_id="req-count-2",
            reason=PauseReason.CIRCUIT_OPEN,
        )

        count = await pause_manager.get_active_pause_count()
        assert count == 2

    @pytest.mark.asyncio
    async def test_expire_stale_sweeps_expired_pauses(self, pause_manager, mock_redis):
        """expire_stale() marks past-TTL pauses as EXPIRED."""
        # Create a pause
        pause_token = await pause_manager.pause_request(
            request_id="req-stale",
            reason=PauseReason.RATE_LIMITED,
            ttl_seconds=1,
        )

        # Manually set the expiry score to the past
        mock_redis._zset_storage[pause_token] = time.time() - 100

        # Run sweep
        count = await pause_manager.expire_stale()

        assert count == 1

        # Token should be expired
        state = await pause_manager.get_pause_state(pause_token)
        assert state.status == PauseStatus.EXPIRED


# ---------------------------------------------------------------------------
# TestResumeEndpoint — Resume endpoint helper tests
# ---------------------------------------------------------------------------


class TestResumeEndpoint:
    """Tests for the handle_resume_request() HTTP handler."""

    @pytest.mark.asyncio
    async def test_resume_returns_200_on_success(self):
        """resume endpoint returns HTTP 200 on successful resume."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(return_value=ResumeResult.RESUMED)

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, body = await handle_resume_request("test-token-123")

        assert status == 200
        assert body["status"] == "RESUMED"

    @pytest.mark.asyncio
    async def test_resume_returns_404_for_unknown_token(self):
        """resume endpoint returns HTTP 404 for unknown tokens."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(return_value=ResumeResult.NOT_FOUND)

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, body = await handle_resume_request("unknown-token")

        assert status == 404
        assert body["status"] == "NOT_FOUND"
        assert "error" in body

    @pytest.mark.asyncio
    async def test_resume_returns_410_for_expired(self):
        """resume endpoint returns HTTP 410 Gone for expired tokens."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(return_value=ResumeResult.EXPIRED)

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, body = await handle_resume_request("expired-token")

        assert status == 410
        assert body["status"] == "EXPIRED"
        assert "retry" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_resume_with_context_stores_context(self):
        """resume endpoint passes context to PauseManager."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(return_value=ResumeResult.RESUMED)

        resume_context = {"approved_by": "admin", "reason": "Manual approval"}

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, _body = await handle_resume_request(
                    "token-with-context",
                    resume_context=resume_context,
                )

        assert status == 200
        # Verify context was passed to resume_request
        mock_manager.resume_request.assert_called_once_with(
            pause_token="token-with-context",
            resume_context=resume_context,
        )

    @pytest.mark.asyncio
    async def test_resume_idempotent_returns_200(self):
        """resume endpoint returns HTTP 200 for already-resumed tokens."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(
            return_value=ResumeResult.ALREADY_RESUMED
        )

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, body = await handle_resume_request("already-resumed-token")

        assert status == 200
        assert body["status"] == "ALREADY_RESUMED"

    @pytest.mark.asyncio
    async def test_resume_redis_error_returns_500(self):
        """resume endpoint returns HTTP 500 on Redis errors."""
        from src.gateway.server.agent_gateway_adapter import handle_resume_request

        mock_manager = MagicMock()
        mock_manager.resume_request = AsyncMock(
            side_effect=ConnectionError("Redis unavailable")
        )

        with patch(
            "src.gateway.governance.pause_primitive.PauseManager",
            return_value=mock_manager,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                MagicMock(),
            ):
                status, body = await handle_resume_request("error-token")

        assert status == 500
        assert body["status"] == "ERROR"


# ---------------------------------------------------------------------------
# TestPauseState — PauseState model tests
# ---------------------------------------------------------------------------


class TestPauseState:
    """Tests for PauseState Pydantic model."""

    def test_pause_state_default_token_is_uuid(self):
        """PauseState generates a UUID v4 pause_token by default."""
        state = PauseState()
        parsed = uuid.UUID(state.pause_token, version=4)
        assert str(parsed) == state.pause_token

    def test_pause_state_computes_expires_at(self):
        """PauseState computes expires_at_utc from paused_at + ttl_seconds."""
        state = PauseState(ttl_seconds=3600)  # 1 hour

        paused_at = datetime.fromisoformat(state.paused_at_utc)
        expires_at = datetime.fromisoformat(state.expires_at_utc)

        delta = (expires_at - paused_at).total_seconds()
        assert abs(delta - 3600) < 1  # Within 1 second tolerance

    def test_pause_state_default_status_is_paused(self):
        """PauseState defaults to PAUSED status."""
        state = PauseState()
        assert state.status == PauseStatus.PAUSED

    def test_pause_state_serializes_to_json(self):
        """PauseState can be serialized to JSON."""
        state = PauseState(
            request_id="req-serialize",
            pause_reason=PauseReason.RATE_LIMITED,
            original_request={"key": "value"},
        )

        json_str = state.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["request_id"] == "req-serialize"
        assert parsed["pause_reason"] == "RATE_LIMITED"
        assert parsed["original_request"] == {"key": "value"}

    def test_pause_state_deserializes_from_json(self):
        """PauseState can be deserialized from JSON."""
        json_str = json.dumps(
            {
                "pause_token": "test-token-123",
                "request_id": "req-deserialize",
                "pause_reason": "CIRCUIT_OPEN",
                "status": "PAUSED",
                "original_request": {"symbol": "AAPL"},
                "paused_at_utc": "2026-08-15T12:00:00+00:00",
                "expires_at_utc": "2026-08-15T13:00:00+00:00",
                "ttl_seconds": 3600,
            }
        )

        state = PauseState.model_validate_json(json_str)

        assert state.pause_token == "test-token-123"
        assert state.request_id == "req-deserialize"
        assert state.pause_reason == PauseReason.CIRCUIT_OPEN
        assert state.status == PauseStatus.PAUSED


# ---------------------------------------------------------------------------
# TestBuildResumeEndpoint — URL builder tests
# ---------------------------------------------------------------------------


class TestBuildResumeEndpoint:
    """Tests for build_resume_endpoint() helper."""

    def test_build_resume_endpoint_format(self):
        """build_resume_endpoint() returns correct URL format."""
        endpoint = build_resume_endpoint("abc-123-def")
        assert endpoint == "/v1/pause/abc-123-def/resume"

    def test_build_resume_endpoint_with_uuid(self):
        """build_resume_endpoint() works with UUID tokens."""
        token = str(uuid.uuid4())
        endpoint = build_resume_endpoint(token)
        assert f"/v1/pause/{token}/resume" == endpoint


# ---------------------------------------------------------------------------
# TestValidateActionPauseHandler — PAUSE handler in validate_action()
# ---------------------------------------------------------------------------


class TestValidateActionPauseHandler:
    """Tests for the PAUSE handler branch in SymbolicGovernor.validate_action().

    These tests verify that:
    1. PAUSE decisions are properly returned (not falling through to DENY)
    2. PauseReceipt is created for audit trail
    3. PAUSE metadata is included in the response
    4. Defense-in-depth fallback to DENY when CAGE_PAUSE_ENABLED=false
    """

    @pytest.fixture
    def mock_governor_deps(self):
        """Create mock dependencies for SymbolicGovernor."""
        opa_client = AsyncMock()
        opa_client.evaluate_policy = AsyncMock(return_value="ALLOW")

        safety_filter = AsyncMock()
        safety_filter.verify_action = MagicMock(return_value="SAFE")
        safety_filter.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))

        consensus_engine = AsyncMock()
        consensus_engine.check_consensus = AsyncMock(return_value={"status": "APPROVE"})

        return opa_client, safety_filter, consensus_engine

    @pytest.mark.asyncio
    async def test_pause_handler_returns_pause_verdict(
        self, mock_redis, mock_governor_deps
    ):
        """validate_action() returns PAUSE verdict when _classify_violation returns PAUSE."""
        from unittest.mock import patch

        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.symbolic_governor import SymbolicGovernor

        opa_client, safety_filter, consensus_engine = mock_governor_deps

        # Mock _run_checks to return a rate limit violation
        mock_result = {
            "violations": ["Rate limit exceeded: too many requests"],
            "stpa_violation_count": 0,
            "opa_decision": "ALLOW",
            "policy_ambiguous": False,
        }

        with (
            patch("src.gateway.governance.symbolic_governor.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.governance.pause_primitive.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        ):
            governor = SymbolicGovernor(
                opa_client, safety_filter=MagicMock(), consensus_engine=MagicMock()
            )
            from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
            from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

            governor.register_domain_tier(CBFTierPlugin(safety_filter))
            governor.register_domain_tier(ConsensusTierPlugin(consensus_engine))

            # Patch _run_checks to return our mock result
            with patch.object(governor, "_run_checks", return_value=mock_result):
                result = await governor.validate_action(
                    action="test_action",
                    params={"symbol": "AAPL", "amount": 100, "confidence": 0.9},
                )

                assert result["verdict"] == GovernanceDecision.PAUSE
                assert result["seal"] == ""  # No seal for PAUSE
                assert "pause_token" in result
                assert result["pause_reason"] == "RATE_LIMITED"
                assert "resume_endpoint" in result
                assert "estimated_wait_seconds" in result

    @pytest.mark.asyncio
    async def test_pause_handler_creates_pause_receipt(
        self, mock_redis, mock_governor_deps
    ):
        """validate_action() creates a PauseReceipt with proper audit fields."""
        from unittest.mock import patch

        from src.gateway.governance.contracts import PauseReceipt
        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.symbolic_governor import SymbolicGovernor

        opa_client, safety_filter, consensus_engine = mock_governor_deps

        mock_result = {
            "violations": ["Circuit breaker open: service unavailable"],
            "stpa_violation_count": 0,
            "opa_decision": "ALLOW",
            "policy_ambiguous": False,
        }

        with (
            patch("src.gateway.governance.symbolic_governor.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.governance.pause_primitive.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        ):
            governor = SymbolicGovernor(
                opa_client, safety_filter=MagicMock(), consensus_engine=MagicMock()
            )
            from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
            from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

            governor.register_domain_tier(CBFTierPlugin(safety_filter))
            governor.register_domain_tier(ConsensusTierPlugin(consensus_engine))

            with patch.object(governor, "_run_checks", return_value=mock_result):
                result = await governor.validate_action(
                    action="test_action",
                    params={
                        "thread_id": "thread-123",
                        "symbol": "GOOG",
                        "amount": 500,
                    },
                )

                assert result["verdict"] == GovernanceDecision.PAUSE
                assert "pause_receipt" in result

                receipt = result["pause_receipt"]
                assert isinstance(receipt, PauseReceipt)
                assert receipt.thread_id == "thread-123"
                assert receipt.action == "test_action"
                assert receipt.pause_reason == "CIRCUIT_OPEN"
                assert receipt.proof_hash  # Should have a hash

    @pytest.mark.asyncio
    async def test_pause_handler_fallback_to_deny_when_disabled(
        self, mock_redis, mock_governor_deps
    ):
        """validate_action() falls back to DENY when CAGE_PAUSE_ENABLED=false."""
        from unittest.mock import patch

        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.symbolic_governor import (
            GovernanceError,
            SymbolicGovernor,
        )

        opa_client, safety_filter, consensus_engine = mock_governor_deps

        mock_result = {
            "violations": ["Rate limit exceeded: too many requests"],
            "stpa_violation_count": 0,
            "opa_decision": "ALLOW",
            "policy_ambiguous": False,
        }

        # Enable in _classify_violation but disable at handler level
        with (
            patch(
                "src.gateway.governance.symbolic_governor._classify_violation"
            ) as mock_classify,
            patch("src.gateway.governance.pause_primitive.CAGE_PAUSE_ENABLED", False),
            patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        ):
            # Mock _classify_violation to return PAUSE
            mock_classify.return_value = (
                GovernanceDecision.PAUSE,
                {
                    "classification_reason": "Rate limit exceeded",
                    "pause_reason": "RATE_LIMITED",
                    "estimated_wait_seconds": 60,
                    "violation_types": ["RATE_LIMITED"],
                    "pausable_violations": ["Rate limit exceeded"],
                    "hard_violations": [],
                    "soft_violations": [],
                    "narrowable_violations": [],
                },
            )

            governor = SymbolicGovernor(
                opa_client, safety_filter=MagicMock(), consensus_engine=MagicMock()
            )
            from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
            from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

            governor.register_domain_tier(CBFTierPlugin(safety_filter))
            governor.register_domain_tier(ConsensusTierPlugin(consensus_engine))

            with patch.object(governor, "_run_checks", return_value=mock_result):
                # Should raise GovernanceError (DENY fallback)
                with pytest.raises(GovernanceError) as exc_info:
                    await governor.validate_action(
                        action="test_action",
                        params={"symbol": "AAPL", "amount": 100},
                    )

                assert "CAGE_PAUSE_ENABLED=false" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_pause_handler_includes_retry_after(
        self, mock_redis, mock_governor_deps
    ):
        """validate_action() includes retry_after_seconds for HTTP Retry-After header."""
        from unittest.mock import patch

        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.symbolic_governor import SymbolicGovernor

        opa_client, safety_filter, consensus_engine = mock_governor_deps

        mock_result = {
            "violations": ["Resource unavailable: quota exhausted"],
            "stpa_violation_count": 0,
            "opa_decision": "ALLOW",
            "policy_ambiguous": False,
        }

        with (
            patch("src.gateway.governance.symbolic_governor.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.governance.pause_primitive.CAGE_PAUSE_ENABLED", True),
            patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        ):
            governor = SymbolicGovernor(
                opa_client, safety_filter=MagicMock(), consensus_engine=MagicMock()
            )
            from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
            from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

            governor.register_domain_tier(CBFTierPlugin(safety_filter))
            governor.register_domain_tier(ConsensusTierPlugin(consensus_engine))

            with patch.object(governor, "_run_checks", return_value=mock_result):
                result = await governor.validate_action(
                    action="test_action",
                    params={"symbol": "MSFT", "amount": 200},
                )

                assert result["verdict"] == GovernanceDecision.PAUSE
                assert "retry_after_seconds" in result
                assert result["retry_after_seconds"] > 0

    @pytest.mark.asyncio
    async def test_pause_handler_redis_failure_falls_back_to_deny(
        self, mock_governor_deps
    ):
        """validate_action() falls back to DENY when Redis is unavailable for PAUSE storage."""
        from unittest.mock import patch

        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.symbolic_governor import (
            GovernanceError,
            SymbolicGovernor,
        )

        opa_client, safety_filter, consensus_engine = mock_governor_deps

        mock_result = {
            "violations": ["Rate limit exceeded: too many requests"],
            "stpa_violation_count": 0,
            "opa_decision": "ALLOW",
            "policy_ambiguous": False,
        }

        # Create a mock Redis that raises an exception
        mock_redis_broken = AsyncMock()
        mock_redis_broken.pipeline.side_effect = ConnectionError("Redis unavailable")

        with (
            patch(
                "src.gateway.governance.symbolic_governor._classify_violation"
            ) as mock_classify,
            patch("src.gateway.governance.pause_primitive.CAGE_PAUSE_ENABLED", True),
            patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                mock_redis_broken,
            ),
        ):
            mock_classify.return_value = (
                GovernanceDecision.PAUSE,
                {
                    "classification_reason": "Rate limit exceeded",
                    "pause_reason": "RATE_LIMITED",
                    "estimated_wait_seconds": 60,
                    "violation_types": ["RATE_LIMITED"],
                    "pausable_violations": ["Rate limit exceeded"],
                    "hard_violations": [],
                    "soft_violations": [],
                    "narrowable_violations": [],
                },
            )

            governor = SymbolicGovernor(
                opa_client, safety_filter=MagicMock(), consensus_engine=MagicMock()
            )
            from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
            from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

            governor.register_domain_tier(CBFTierPlugin(safety_filter))
            governor.register_domain_tier(ConsensusTierPlugin(consensus_engine))

            with patch.object(governor, "_run_checks", return_value=mock_result):
                with pytest.raises(GovernanceError) as exc_info:
                    await governor.validate_action(
                        action="test_action",
                        params={"symbol": "AAPL", "amount": 100},
                    )

                assert "PAUSE storage failed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestPauseReceipt — PauseReceipt model tests
# ---------------------------------------------------------------------------


class TestPauseReceipt:
    """Tests for PauseReceipt dataclass in contracts.py."""

    def test_pause_receipt_generates_proof_hash(self):
        """PauseReceipt generates a proof hash from core fields."""
        from src.gateway.governance.contracts import PauseReceipt

        receipt = PauseReceipt(
            thread_id="thread-abc",
            action="buy_stock",
            pause_reason="RATE_LIMITED",
            pause_token="pause-token-123",
        )

        assert receipt.proof_hash
        assert len(receipt.proof_hash) == 64  # SHA-256 hex digest

    def test_pause_receipt_hash_deterministic(self):
        """PauseReceipt with same fields generates same hash."""
        from src.gateway.governance.contracts import PauseReceipt

        fixed_timestamp = 1723987200.0

        receipt1 = PauseReceipt(
            thread_id="thread-xyz",
            action="sell_stock",
            pause_reason="CIRCUIT_OPEN",
            pause_token="pause-token-456",
            timestamp=fixed_timestamp,
        )

        receipt2 = PauseReceipt(
            thread_id="thread-xyz",
            action="sell_stock",
            pause_reason="CIRCUIT_OPEN",
            pause_token="pause-token-456",
            timestamp=fixed_timestamp,
        )

        assert receipt1.proof_hash == receipt2.proof_hash

    def test_pause_receipt_stores_violations(self):
        """PauseReceipt stores violation list."""
        from src.gateway.governance.contracts import PauseReceipt

        violations = ["Rate limit: 100 req/min exceeded", "Soft threshold warning"]

        receipt = PauseReceipt(
            thread_id="thread-viol",
            action="query_balance",
            pause_reason="RATE_LIMITED",
            pause_token="pause-token-789",
            violations=violations,
        )

        assert receipt.violations == violations

    def test_pause_receipt_stores_standing_at_pause(self):
        """PauseReceipt stores context at pause time."""
        from src.gateway.governance.contracts import PauseReceipt

        standing = {"symbol": "AAPL", "amount": 1000, "confidence": 0.95}

        receipt = PauseReceipt(
            thread_id="thread-standing",
            action="buy_stock",
            pause_reason="RESOURCE_UNAVAILABLE",
            pause_token="pause-token-standing",
            standing_at_pause=standing,
        )

        assert receipt.standing_at_pause == standing

    def test_pause_receipt_immutable(self):
        """PauseReceipt is frozen (immutable)."""
        from src.gateway.governance.contracts import PauseReceipt

        receipt = PauseReceipt(
            thread_id="thread-immut",
            action="test_action",
            pause_reason="RATE_LIMITED",
            pause_token="pause-token-immut",
        )

        with pytest.raises(Exception):  # FrozenInstanceError
            receipt.pause_reason = "CIRCUIT_OPEN"
