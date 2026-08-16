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
Tests for EVIDENCE_CHAIN_BLOCKING gate (Phase 2.1 — R-06 mitigation).

These tests verify that:
  1. Default behavior (EVIDENCE_CHAIN_BLOCKING=false) preserves fire-and-forget
  2. Blocking mode (EVIDENCE_CHAIN_BLOCKING=true) blocks until evidence commit
  3. Timeout handling raises EvidenceChainUnavailableError
  4. Redis unavailability raises EvidenceChainUnavailableError
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestEvidenceChainBlockingGate:
    """Tests for the EVIDENCE_CHAIN_BLOCKING gate behavior."""

    def test_default_blocking_mode_is_false(self):
        """Verify default EVIDENCE_CHAIN_BLOCKING is false for backward compatibility."""
        with patch.dict("os.environ", {}, clear=False):
            # Force reimport to pick up env var
            import importlib

            import src.compliance_bridge.evidence_stream as es

            importlib.reload(es)

            # Default should be false
            assert es._EVIDENCE_CHAIN_BLOCKING is False
            assert es.is_evidence_chain_blocking() is False

    def test_blocking_mode_enabled_when_env_true(self):
        """Verify EVIDENCE_CHAIN_BLOCKING=true enables blocking mode."""
        with patch.dict("os.environ", {"EVIDENCE_CHAIN_BLOCKING": "true"}, clear=False):
            import importlib

            import src.compliance_bridge.evidence_stream as es

            importlib.reload(es)

            assert es._EVIDENCE_CHAIN_BLOCKING is True
            assert es.is_evidence_chain_blocking() is True


class TestEvidenceCommitResult:
    """Tests for EvidenceCommitResult dataclass."""

    def test_evidence_commit_result_fields(self):
        """Verify EvidenceCommitResult has all required fields."""
        from src.compliance_bridge.evidence_stream import EvidenceCommitResult

        result = EvidenceCommitResult(
            success=True,
            evidence_id="1234567890-0",
            commit_timestamp=datetime.now(tz=timezone.utc),
            hash="abc123def456789",
            sequence=42,
        )

        assert result.success is True
        assert result.evidence_id == "1234567890-0"
        assert result.hash == "abc123def456789"
        assert result.sequence == 42
        assert result.commit_timestamp.tzinfo is not None

    def test_evidence_commit_result_is_frozen(self):
        """Verify EvidenceCommitResult is immutable."""
        from src.compliance_bridge.evidence_stream import EvidenceCommitResult

        result = EvidenceCommitResult(
            success=True,
            evidence_id="test",
            commit_timestamp=datetime.now(tz=timezone.utc),
            hash="test",
        )

        with pytest.raises(AttributeError):
            result.success = False  # type: ignore[misc]


class TestEvidenceChainUnavailableError:
    """Tests for EvidenceChainUnavailableError exception."""

    def test_error_preserves_original_exception(self):
        """Verify EvidenceChainUnavailableError preserves original error."""
        from src.compliance_bridge.evidence_stream import EvidenceChainUnavailableError

        original = ConnectionError("Redis unavailable")
        error = EvidenceChainUnavailableError(
            "Evidence commit failed", original_error=original
        )

        assert error.original_error is original
        assert "Evidence commit failed" in str(error)

    def test_error_without_original_exception(self):
        """Verify EvidenceChainUnavailableError works without original error."""
        from src.compliance_bridge.evidence_stream import EvidenceChainUnavailableError

        error = EvidenceChainUnavailableError("Redis connection not established")

        assert error.original_error is None
        assert "Redis connection not established" in str(error)


class TestIngestSync:
    """Tests for EvidenceStreamSink.ingest_sync() blocking method."""

    @pytest.mark.asyncio
    async def test_ingest_sync_raises_when_redis_unavailable(self):
        """Verify ingest_sync raises EvidenceChainUnavailableError when Redis is None."""
        from src.compliance_bridge.evidence_stream import (
            EvidenceChainUnavailableError,
            EvidenceStreamSink,
        )

        sink = EvidenceStreamSink(redis_url="redis://localhost:6379")
        # Don't start — _redis remains None
        assert sink._redis is None

        with pytest.raises(EvidenceChainUnavailableError) as exc_info:
            await sink.ingest_sync({"type": "TEST", "controlId": "TEST-001"})

        assert "Redis connection not established" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_ingest_sync_success_returns_commit_result(self):
        """Verify ingest_sync returns EvidenceCommitResult on success."""
        from src.compliance_bridge.evidence_stream import (
            EvidenceCommitResult,
            EvidenceStreamSink,
        )

        sink = EvidenceStreamSink(redis_url="redis://localhost:6379")

        # Mock Redis client
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="1234567890-0")
        sink._redis = mock_redis

        result = await sink.ingest_sync({"type": "TEST", "controlId": "TEST-001"})

        assert isinstance(result, EvidenceCommitResult)
        assert result.success is True
        assert result.evidence_id == "1234567890-0"
        assert len(result.hash) == 64  # SHA-256 hex
        assert result.sequence == 0

    @pytest.mark.asyncio
    async def test_ingest_sync_timeout_raises_error(self):
        """Verify ingest_sync raises EvidenceChainUnavailableError on timeout."""
        from src.compliance_bridge.evidence_stream import (
            EvidenceChainUnavailableError,
            EvidenceStreamSink,
        )

        sink = EvidenceStreamSink(redis_url="redis://localhost:6379")

        # Mock Redis client that hangs forever
        async def slow_xadd(*args, **kwargs):
            await asyncio.sleep(10.0)  # Much longer than timeout
            return "never-reached"

        mock_redis = AsyncMock()
        mock_redis.xadd = slow_xadd
        sink._redis = mock_redis

        with pytest.raises(EvidenceChainUnavailableError) as exc_info:
            await sink.ingest_sync(
                {"type": "TEST", "controlId": "TEST-001"},
                timeout_seconds=0.1,  # Very short timeout
            )

        assert "timeout" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_ingest_sync_redis_error_raises_unavailable(self):
        """Verify ingest_sync raises EvidenceChainUnavailableError on Redis error.

        When Redis xadd fails, _ingest_with_result returns a failure result
        (success=False), and ingest_sync raises EvidenceChainUnavailableError.
        The original_error is only preserved for timeout and unexpected exceptions,
        not for graceful failure results.
        """
        from src.compliance_bridge.evidence_stream import (
            EvidenceChainUnavailableError,
            EvidenceStreamSink,
        )

        sink = EvidenceStreamSink(redis_url="redis://localhost:6379")

        # Mock Redis client that raises
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(side_effect=ConnectionError("Connection refused"))
        sink._redis = mock_redis

        with pytest.raises(EvidenceChainUnavailableError) as exc_info:
            await sink.ingest_sync({"type": "TEST", "controlId": "TEST-001"})

        # Redis failure returns a failure result, not an exception with original_error
        assert "commit failed" in str(exc_info.value).lower()


class TestGenerateSealWithEvidence:
    """Tests for generate_seal_with_evidence() function."""

    @pytest.mark.asyncio
    async def test_fire_and_forget_mode_returns_seal_immediately(self):
        """Verify fire-and-forget mode returns seal without blocking."""
        with patch.dict("os.environ", {"EVIDENCE_CHAIN_BLOCKING": "false"}, clear=False):
            import importlib

            import src.compliance_bridge.evidence_stream as es

            importlib.reload(es)

            # Mock evidence sink to track calls
            mock_sink = MagicMock()
            mock_sink.is_running = True
            mock_sink.ingest = AsyncMock(return_value="msg-id-123")

            with patch.object(es, "get_evidence_sink", return_value=mock_sink):
                from src.gateway.governance.routing_seal import (
                    generate_seal_with_evidence,
                )

                seal = await generate_seal_with_evidence(
                    action="execute_trade",
                    params={"symbol": "AAPL", "amount": 1000},
                )

                # Seal should be issued
                assert seal is not None
                assert len(seal) > 0
                # Fire-and-forget ingest should be called
                mock_sink.ingest.assert_called_once()

    @pytest.mark.asyncio
    async def test_blocking_mode_raises_when_evidence_fails(self):
        """Verify blocking mode raises EvidenceChainUnavailableError on failure."""
        with patch.dict("os.environ", {"EVIDENCE_CHAIN_BLOCKING": "true"}, clear=False):
            import importlib

            import src.compliance_bridge.evidence_stream as es

            importlib.reload(es)

            # Mock evidence sink that fails
            mock_sink = MagicMock()
            mock_sink.is_running = True
            mock_sink.ingest_sync = AsyncMock(
                side_effect=es.EvidenceChainUnavailableError("Redis unavailable")
            )

            with patch.object(es, "get_evidence_sink", return_value=mock_sink):
                from src.gateway.governance.routing_seal import (
                    generate_seal_with_evidence,
                )

                with pytest.raises(es.EvidenceChainUnavailableError):
                    await generate_seal_with_evidence(
                        action="execute_trade",
                        params={"symbol": "AAPL", "amount": 1000},
                    )

    @pytest.mark.asyncio
    async def test_blocking_mode_returns_seal_on_success(self):
        """Verify blocking mode returns seal after successful evidence commit."""
        with patch.dict("os.environ", {"EVIDENCE_CHAIN_BLOCKING": "true"}, clear=False):
            import importlib

            import src.compliance_bridge.evidence_stream as es

            importlib.reload(es)

            # Mock evidence sink that succeeds
            commit_result = es.EvidenceCommitResult(
                success=True,
                evidence_id="1234567890-0",
                commit_timestamp=datetime.now(tz=timezone.utc),
                hash="abc123" * 10 + "abcd",
                sequence=1,
            )
            mock_sink = MagicMock()
            mock_sink.is_running = True
            mock_sink.ingest_sync = AsyncMock(return_value=commit_result)

            with patch.object(es, "get_evidence_sink", return_value=mock_sink):
                from src.gateway.governance.routing_seal import (
                    generate_seal_with_evidence,
                )

                seal = await generate_seal_with_evidence(
                    action="execute_trade",
                    params={"symbol": "AAPL", "amount": 1000},
                )

                # Seal should be issued after evidence commit
                assert seal is not None
                assert len(seal) > 0
                # Blocking ingest_sync should be called
                mock_sink.ingest_sync.assert_called_once()
