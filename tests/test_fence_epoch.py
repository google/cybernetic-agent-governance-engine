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
Tests for R-05 fence epoch implementation in CBF.

Validates the fence epoch mechanism that detects potential double-spend
vulnerability across Redis primary-to-replica failover scenarios.

§2.6 Risk R-05 mitigation: The fence epoch is a monotonically increasing
counter that increments on every CBF-mutating write. After a failover,
if a replica hasn't replicated the latest epoch, reads from that replica
will return a regressed epoch, which we detect and reject (fail-closed).
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Markers for test categorization
pytestmark = [pytest.mark.local, pytest.mark.unit]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis_client():
    """Create a mock async Redis client for testing."""
    mock = AsyncMock()
    mock.get.return_value = None
    mock.set.return_value = True
    mock.incr.return_value = 1
    mock.get_raw_client = MagicMock(return_value=mock)

    # Mock pipeline context manager
    pipeline_mock = MagicMock()
    pipeline_mock.get = MagicMock()
    pipeline_mock.incr = MagicMock()
    pipeline_mock.set = MagicMock()
    pipeline_mock.execute = AsyncMock(return_value=["100000.0", "5"])
    pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
    pipeline_mock.__aexit__ = AsyncMock(return_value=None)
    mock.pipeline = MagicMock(return_value=pipeline_mock)

    return mock


@pytest.fixture
def cbf_instance():
    """Create a CBF instance with mocked dependencies."""
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # B3a: Use skip_epoch_seed=True to avoid Redis seeding in tests
    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None
    cbf.min_cash_balance = 10000.0
    cbf.gamma = 0.1
    cbf._last_seen_epoch = 0
    return cbf


# ---------------------------------------------------------------------------
# Test: Fence epoch increments on every CBF-mutating write
# ---------------------------------------------------------------------------


class TestFenceEpochIncrements:
    """Tests that fence epoch increments on every CBF-mutating write."""

    @pytest.mark.asyncio
    async def test_fence_epoch_increments_on_update_state(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: Fence epoch must increment on update_state() call."""
        import warnings

        with patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client):
            # update_state is deprecated but still used
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                # Mock the pipeline to return balance and epoch
                pipeline_mock = MagicMock()
                pipeline_mock.watch = AsyncMock()
                pipeline_mock.get = AsyncMock(return_value="100000.0")
                pipeline_mock.multi = MagicMock()
                pipeline_mock.set = MagicMock()
                pipeline_mock.incr = MagicMock()
                pipeline_mock.execute = AsyncMock(
                    return_value=[True, 5]
                )  # [set_result, new_epoch]
                pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
                pipeline_mock.__aexit__ = AsyncMock(return_value=None)
                mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

                await cbf_instance._update_state_unsafe(1000.0)

                # Verify incr was called for fence epoch
                pipeline_mock.incr.assert_called_once()
                # Verify last_seen_epoch was updated
                assert cbf_instance._last_seen_epoch == 5

    @pytest.mark.asyncio
    async def test_fence_epoch_increments_on_rollback_state(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: Fence epoch must increment on rollback_state() call."""
        with patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client):
            # Mock the pipeline
            pipeline_mock = MagicMock()
            pipeline_mock.watch = AsyncMock()
            pipeline_mock.get = AsyncMock(return_value="100000.0")
            pipeline_mock.multi = MagicMock()
            pipeline_mock.set = MagicMock()
            pipeline_mock.incr = MagicMock()
            pipeline_mock.execute = AsyncMock(return_value=[True, 7])
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            await cbf_instance.rollback_state(1000.0)

            # Verify incr was called for fence epoch
            pipeline_mock.incr.assert_called_once()
            # Verify last_seen_epoch was updated
            assert cbf_instance._last_seen_epoch == 7

    @pytest.mark.asyncio
    async def test_fence_epoch_increments_on_atomic_verify_and_commit(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: Fence epoch must increment on atomic_verify_and_commit() call."""
        with patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client):
            # Mock evalsha to return committed result with epoch
            mock_redis_client.script_load = AsyncMock(return_value="sha123")
            mock_redis_client.evalsha = AsyncMock(
                return_value=[1, b"COMMITTED", b"99000.0", 10]
            )

            success, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"amount": 1000.0}
            )

            assert success is True
            assert msg == "COMMITTED"
            # Verify epoch was updated from Lua result
            assert cbf_instance._last_seen_epoch == 10


# ---------------------------------------------------------------------------
# Test: Fence epoch regression detected and rejected
# ---------------------------------------------------------------------------


class TestFenceEpochRegressionDetection:
    """Tests that epoch regression is detected and rejected (fail-closed)."""

    @pytest.mark.asyncio
    async def test_fence_epoch_regression_detected_and_rejected(self, cbf_instance):
        """R-05: Epoch regression must be detected and rejected."""
        # Set last seen epoch higher than current
        cbf_instance._last_seen_epoch = 100

        # Check with a regressed epoch
        is_valid, reason = await cbf_instance._check_fence_epoch(50)

        assert is_valid is False
        assert "epoch=50 < last_seen=100" in reason
        assert "possible failover" in reason

    @pytest.mark.asyncio
    async def test_fence_epoch_valid_when_advancing(self, cbf_instance):
        """R-05: Epoch must be accepted when advancing."""
        cbf_instance._last_seen_epoch = 50

        # Check with an advancing epoch
        is_valid, reason = await cbf_instance._check_fence_epoch(51)

        assert is_valid is True
        assert reason == "OK"
        assert cbf_instance._last_seen_epoch == 51

    @pytest.mark.asyncio
    async def test_fence_epoch_valid_when_equal(self, cbf_instance):
        """R-05: Epoch must be accepted when equal (same transaction)."""
        cbf_instance._last_seen_epoch = 50

        # Check with same epoch
        is_valid, reason = await cbf_instance._check_fence_epoch(50)

        assert is_valid is True
        assert reason == "OK"

    @pytest.mark.asyncio
    async def test_epoch_regression_returns_none_balance(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: When epoch regresses, _read_cbf_state_atomic returns None balance."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._FENCE_EPOCH_ENABLED", True),
        ):
            # Set last seen epoch higher
            cbf_instance._last_seen_epoch = 100

            # Mock the pipeline to return regressed epoch
            pipeline_mock = MagicMock()
            pipeline_mock.get = MagicMock()
            pipeline_mock.execute = AsyncMock(
                return_value=["100000.0", "50"]  # epoch 50 < 100
            )
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.get_raw_client = MagicMock(return_value=mock_redis_client)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            # Mock reconciliation to fail so we hit self-reported path
            with patch(
                "src.cage_finance.safety.cbf.asyncio.to_thread",
                side_effect=Exception("mock reconciliation failure"),
            ):
                state = await cbf_instance._read_cbf_state_atomic()

            assert state["current_cash"] is None
            assert state["source"] == "epoch_regression"
            assert state["fence_epoch"] == 50

    @pytest.mark.asyncio
    async def test_verify_action_rejects_on_epoch_regression(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: verify_action must reject when epoch has regressed."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._FENCE_EPOCH_ENABLED", True),
        ):
            cbf_instance._last_seen_epoch = 100

            pipeline_mock = MagicMock()
            pipeline_mock.get = MagicMock()
            pipeline_mock.execute = AsyncMock(return_value=["100000.0", "50"])
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.get_raw_client = MagicMock(return_value=mock_redis_client)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            with patch(
                "src.cage_finance.safety.cbf.asyncio.to_thread",
                side_effect=Exception("mock"),
            ):
                result = await cbf_instance.verify_action(
                    "execute_trade", {"amount": 1000.0}
                )

            assert "R-05 Fence epoch regression detected" in result
            assert "Fail-closed" in result


# ---------------------------------------------------------------------------
# Test: Fence epoch check disabled by default
# ---------------------------------------------------------------------------


class TestFenceEpochDisabledByDefault:
    """Tests that fence epoch validation default and toggle behavior."""

    def test_fence_epoch_flag_disabled_by_default(self):
        """R-05: CAGE_REDIS_SYNCHRONOUS_REPLICATION is enabled by default (Fix A2).

        DEFAULT CHANGED (peer review Fix A2): Enabled by default to provide failover
        protection out-of-box. Operators can disable with CAGE_REDIS_SYNCHRONOUS_REPLICATION=false.
        """
        # Save original and test with clean environment
        original_env = os.environ.get("CAGE_REDIS_SYNCHRONOUS_REPLICATION")
        try:
            if "CAGE_REDIS_SYNCHRONOUS_REPLICATION" in os.environ:
                del os.environ["CAGE_REDIS_SYNCHRONOUS_REPLICATION"]

            # Re-import to get fresh flag evaluation
            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            # Fix A2: Default is now True for failover safety
            assert cbf_module._FENCE_EPOCH_ENABLED is True
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_SYNCHRONOUS_REPLICATION"] = original_env

    def test_fence_epoch_flag_disabled_when_set_to_false(self):
        """R-05: CAGE_REDIS_SYNCHRONOUS_REPLICATION=false disables epoch validation."""
        original_env = os.environ.get("CAGE_REDIS_SYNCHRONOUS_REPLICATION")
        try:
            os.environ["CAGE_REDIS_SYNCHRONOUS_REPLICATION"] = "false"

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._FENCE_EPOCH_ENABLED is False
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_SYNCHRONOUS_REPLICATION"] = original_env
            elif "CAGE_REDIS_SYNCHRONOUS_REPLICATION" in os.environ:
                del os.environ["CAGE_REDIS_SYNCHRONOUS_REPLICATION"]

    @pytest.mark.asyncio
    async def test_epoch_tracked_but_not_validated_when_disabled(
        self, cbf_instance, mock_redis_client
    ):
        """R-05: When disabled, epoch is tracked but not validated."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._FENCE_EPOCH_ENABLED", False),
        ):
            cbf_instance._last_seen_epoch = 100

            pipeline_mock = MagicMock()
            pipeline_mock.get = MagicMock()
            # Return regressed epoch (50 < 100) but should still succeed
            pipeline_mock.execute = AsyncMock(return_value=["100000.0", "50"])
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.get_raw_client = MagicMock(return_value=mock_redis_client)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            with patch(
                "src.cage_finance.safety.cbf.asyncio.to_thread",
                side_effect=Exception("mock"),
            ):
                state = await cbf_instance._read_cbf_state_atomic()

            # Should return valid balance (not rejected)
            assert state["current_cash"] == 100000.0
            assert state["source"] == "self_reported"
            assert state["fence_epoch"] == 50
            # Last seen epoch should be updated to 50 (tracking only)
            assert cbf_instance._last_seen_epoch == 50


# ---------------------------------------------------------------------------
# Test: Prometheus telemetry
# ---------------------------------------------------------------------------


class TestFenceEpochTelemetry:
    """Tests for Prometheus counter and gauge telemetry."""

    @pytest.mark.asyncio
    async def test_epoch_regression_increments_prometheus_counter(self, cbf_instance):
        """R-05: Epoch regression must increment Prometheus counter."""
        cbf_instance._last_seen_epoch = 100

        with patch(
            "src.cage_finance.safety.cbf._EPOCH_REGRESSION_COUNTER"
        ) as mock_counter:
            mock_counter.inc = MagicMock()

            await cbf_instance._check_fence_epoch(50)

            mock_counter.inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_valid_epoch_updates_prometheus_gauge(self, cbf_instance):
        """R-05: Valid epoch must update Prometheus gauge."""
        cbf_instance._last_seen_epoch = 50

        with patch(
            "src.cage_finance.safety.cbf._CURRENT_FENCE_EPOCH_GAUGE"
        ) as mock_gauge:
            mock_gauge.set = MagicMock()

            await cbf_instance._check_fence_epoch(60)

            mock_gauge.set.assert_called_once_with(60)


# ---------------------------------------------------------------------------
# Test: Lua script includes fence epoch
# ---------------------------------------------------------------------------


class TestLuaScriptFenceEpoch:
    """Tests that Lua script correctly handles fence epoch."""

    def test_lua_script_includes_fence_epoch_key(self, cbf_instance):
        """R-05: Lua script must reference safety:fence_epoch key."""
        assert "KEYS[3]" in cbf_instance.LUA_ATOMIC_CBF
        assert "safety:fence_epoch" in cbf_instance.LUA_ATOMIC_CBF

    def test_lua_script_increments_epoch(self, cbf_instance):
        """R-05: Lua script must INCR the fence epoch."""
        assert "INCR" in cbf_instance.LUA_ATOMIC_CBF
        assert "KEYS[3]" in cbf_instance.LUA_ATOMIC_CBF

    def test_lua_script_returns_epoch(self, cbf_instance):
        """R-05: Lua script must return new_epoch in result array."""
        # The Lua script returns 4 values: status_code, message, new_balance_str, new_epoch
        assert "new_epoch" in cbf_instance.LUA_ATOMIC_CBF
        # Check that return statement includes epoch
        assert (
            "return {1," in cbf_instance.LUA_ATOMIC_CBF
            or "return {0," in cbf_instance.LUA_ATOMIC_CBF
        )


# ---------------------------------------------------------------------------
# Test: Phase 4.3 WAIT command support
# ---------------------------------------------------------------------------


class TestWaitCommandSupport:
    """Tests for Phase 4.3 Redis WAIT command support for synchronous replication."""

    @pytest.mark.asyncio
    async def test_wait_disabled_by_default(self, cbf_instance, mock_redis_client):
        """Phase 4.3: WAIT is disabled when CAGE_REDIS_WAIT_REPLICAS=0 (default)."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 0),
        ):
            # _sync_to_replicas should return True immediately (no-op)
            result = await cbf_instance._sync_to_replicas()

            assert result is True
            # Verify WAIT was not called
            mock_redis_client.get_raw_client().execute_command.assert_not_called() if hasattr(
                mock_redis_client.get_raw_client(), "execute_command"
            ) else None

    @pytest.mark.asyncio
    async def test_wait_command_called_when_replicas_configured(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: WAIT command is called when CAGE_REDIS_WAIT_REPLICAS > 0."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 2),
            patch("src.cage_finance.safety.cbf._WAIT_TIMEOUT_MS", 1000),
        ):
            # Mock execute_command to return successful replication count
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                return_value=2
            )

            result = await cbf_instance._sync_to_replicas()

            assert result is True
            mock_redis_client.get_raw_client().execute_command.assert_called_once_with(
                "WAIT", 2, 1000
            )

    @pytest.mark.asyncio
    async def test_wait_timeout_logs_warning(self, cbf_instance, mock_redis_client):
        """Phase 4.3: WAIT timeout logs warning and returns False."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 2),
            patch("src.cage_finance.safety.cbf._WAIT_TIMEOUT_MS", 100),
            patch("src.cage_finance.safety.cbf.logger") as mock_logger,
        ):
            # Mock execute_command to return fewer replicas than requested (timeout)
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                return_value=1
            )

            result = await cbf_instance._sync_to_replicas()

            assert result is False
            # Verify warning was logged
            mock_logger.warning.assert_called()
            warning_call = mock_logger.warning.call_args
            assert "CBF_WAIT_TIMEOUT" in str(warning_call)

    @pytest.mark.asyncio
    async def test_wait_accepts_override_parameters(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: _sync_to_replicas accepts override parameters."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
            patch("src.cage_finance.safety.cbf._WAIT_TIMEOUT_MS", 500),
        ):
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                return_value=3
            )

            # Override with different values
            result = await cbf_instance._sync_to_replicas(
                num_replicas=3, timeout_ms=2000
            )

            assert result is True
            mock_redis_client.get_raw_client().execute_command.assert_called_once_with(
                "WAIT", 3, 2000
            )

    @pytest.mark.asyncio
    async def test_wait_handles_redis_error_gracefully(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: WAIT handles Redis errors gracefully."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
        ):
            # Mock execute_command to raise an exception
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                side_effect=Exception("Redis connection error")
            )

            result = await cbf_instance._sync_to_replicas()

            assert result is False

    @pytest.mark.asyncio
    async def test_wait_returns_true_when_zero_replicas_requested(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: WAIT returns True immediately when num_replicas=0."""
        with patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client):
            # Even with env var set, override to 0 should skip WAIT
            result = await cbf_instance._sync_to_replicas(num_replicas=0)

            assert result is True

    @pytest.mark.asyncio
    async def test_wait_integration_with_update_state(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: update_state calls _sync_to_replicas when configured."""
        import warnings

        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
            patch.object(
                cbf_instance, "_sync_to_replicas", new_callable=AsyncMock
            ) as mock_sync,
        ):
            mock_sync.return_value = True

            # Setup pipeline mock
            pipeline_mock = MagicMock()
            pipeline_mock.watch = AsyncMock()
            pipeline_mock.get = AsyncMock(return_value="100000.0")
            pipeline_mock.multi = MagicMock()
            pipeline_mock.set = MagicMock()
            pipeline_mock.incr = MagicMock()
            pipeline_mock.execute = AsyncMock(return_value=[True, 5])
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                await cbf_instance._update_state_unsafe(1000.0)

            # Verify _sync_to_replicas was called
            mock_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_wait_integration_with_rollback_state(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: rollback_state calls _sync_to_replicas when configured."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
            patch.object(
                cbf_instance, "_sync_to_replicas", new_callable=AsyncMock
            ) as mock_sync,
        ):
            mock_sync.return_value = True

            # Setup pipeline mock
            pipeline_mock = MagicMock()
            pipeline_mock.watch = AsyncMock()
            pipeline_mock.get = AsyncMock(return_value="100000.0")
            pipeline_mock.multi = MagicMock()
            pipeline_mock.set = MagicMock()
            pipeline_mock.incr = MagicMock()
            pipeline_mock.execute = AsyncMock(return_value=[True, 7])
            pipeline_mock.__aenter__ = AsyncMock(return_value=pipeline_mock)
            pipeline_mock.__aexit__ = AsyncMock(return_value=None)
            mock_redis_client.pipeline = MagicMock(return_value=pipeline_mock)

            await cbf_instance.rollback_state(1000.0)

            # Verify _sync_to_replicas was called
            mock_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_wait_integration_with_atomic_verify_and_commit(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: atomic_verify_and_commit calls _sync_to_replicas when configured."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
            patch.object(
                cbf_instance, "_sync_to_replicas", new_callable=AsyncMock
            ) as mock_sync,
        ):
            mock_sync.return_value = True

            # Mock evalsha to return committed result
            mock_redis_client.script_load = AsyncMock(return_value="sha123")
            mock_redis_client.evalsha = AsyncMock(
                return_value=[1, b"COMMITTED", b"99000.0", 10]
            )

            success, _msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"amount": 1000.0}
            )

            assert success is True
            # Verify _sync_to_replicas was called after successful commit
            mock_sync.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Phase 4.3 WAIT telemetry
# ---------------------------------------------------------------------------


class TestWaitTelemetry:
    """Tests for Phase 4.3 WAIT command Prometheus telemetry."""

    @pytest.mark.asyncio
    async def test_wait_latency_histogram_recorded(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: WAIT latency is recorded in Prometheus histogram."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 1),
            patch(
                "src.cage_finance.safety.cbf._WAIT_LATENCY_HISTOGRAM"
            ) as mock_histogram,
        ):
            mock_histogram.observe = MagicMock()
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                return_value=1
            )

            await cbf_instance._sync_to_replicas()

            # Verify histogram.observe was called with elapsed time
            mock_histogram.observe.assert_called_once()
            elapsed = mock_histogram.observe.call_args[0][0]
            assert elapsed >= 0

    @pytest.mark.asyncio
    async def test_wait_timeout_counter_incremented(
        self, cbf_instance, mock_redis_client
    ):
        """Phase 4.3: WAIT timeout increments Prometheus counter."""
        with (
            patch("src.cage_finance.safety.cbf.redis_client", mock_redis_client),
            patch("src.cage_finance.safety.cbf._WAIT_REPLICAS", 2),
            patch("src.cage_finance.safety.cbf._WAIT_TIMEOUT_COUNTER") as mock_counter,
        ):
            mock_counter.inc = MagicMock()
            # Return fewer replicas than requested (timeout scenario)
            mock_redis_client.get_raw_client().execute_command = AsyncMock(
                return_value=1
            )

            await cbf_instance._sync_to_replicas()

            mock_counter.inc.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Phase 4.3 Environment variable configuration
# ---------------------------------------------------------------------------


class TestWaitEnvironmentVariables:
    """Tests for Phase 4.3 WAIT environment variable configuration."""

    def test_wait_replicas_defaults_to_one(self):
        """Phase 4.3: CAGE_REDIS_WAIT_REPLICAS defaults to 1 (enabled, Fix A1).

        DEFAULT CHANGED (peer review Fix A1): Enabled by default (1 replica) to ensure
        durability before returning success to caller. Set CAGE_REDIS_WAIT_REPLICAS=0 to disable.
        """
        original_env = os.environ.get("CAGE_REDIS_WAIT_REPLICAS")
        try:
            if "CAGE_REDIS_WAIT_REPLICAS" in os.environ:
                del os.environ["CAGE_REDIS_WAIT_REPLICAS"]

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            # Fix A1: Default is now 1 for durability
            assert cbf_module._WAIT_REPLICAS == 1
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_WAIT_REPLICAS"] = original_env

    def test_wait_timeout_defaults_to_1000ms(self):
        """Phase 4.3: CAGE_REDIS_WAIT_TIMEOUT_MS defaults to 1000."""
        original_env = os.environ.get("CAGE_REDIS_WAIT_TIMEOUT_MS")
        try:
            if "CAGE_REDIS_WAIT_TIMEOUT_MS" in os.environ:
                del os.environ["CAGE_REDIS_WAIT_TIMEOUT_MS"]

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._WAIT_TIMEOUT_MS == 1000
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_WAIT_TIMEOUT_MS"] = original_env

    def test_wait_replicas_configurable(self):
        """Phase 4.3: CAGE_REDIS_WAIT_REPLICAS is configurable."""
        original_env = os.environ.get("CAGE_REDIS_WAIT_REPLICAS")
        try:
            os.environ["CAGE_REDIS_WAIT_REPLICAS"] = "3"

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._WAIT_REPLICAS == 3
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_WAIT_REPLICAS"] = original_env
            elif "CAGE_REDIS_WAIT_REPLICAS" in os.environ:
                del os.environ["CAGE_REDIS_WAIT_REPLICAS"]

    def test_wait_timeout_configurable(self):
        """Phase 4.3: CAGE_REDIS_WAIT_TIMEOUT_MS is configurable."""
        original_env = os.environ.get("CAGE_REDIS_WAIT_TIMEOUT_MS")
        try:
            os.environ["CAGE_REDIS_WAIT_TIMEOUT_MS"] = "5000"

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._WAIT_TIMEOUT_MS == 5000
        finally:
            if original_env is not None:
                os.environ["CAGE_REDIS_WAIT_TIMEOUT_MS"] = original_env
            elif "CAGE_REDIS_WAIT_TIMEOUT_MS" in os.environ:
                del os.environ["CAGE_REDIS_WAIT_TIMEOUT_MS"]


# ---------------------------------------------------------------------------
# Test: Phase 4.3 Sentinel awareness stub
# ---------------------------------------------------------------------------


class TestSentinelAwarenessStub:
    """Tests for Phase 4.3 Sentinel awareness configuration stub."""

    def test_sentinel_master_name_env_var_read(self):
        """Phase 4.3: REDIS_SENTINEL_MASTER_NAME env var is read."""
        original_env = os.environ.get("REDIS_SENTINEL_MASTER_NAME")
        try:
            os.environ["REDIS_SENTINEL_MASTER_NAME"] = "mymaster"

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._REDIS_SENTINEL_MASTER_NAME == "mymaster"
        finally:
            if original_env is not None:
                os.environ["REDIS_SENTINEL_MASTER_NAME"] = original_env
            elif "REDIS_SENTINEL_MASTER_NAME" in os.environ:
                del os.environ["REDIS_SENTINEL_MASTER_NAME"]

    def test_sentinel_master_name_defaults_to_none(self):
        """Phase 4.3: REDIS_SENTINEL_MASTER_NAME defaults to None."""
        original_env = os.environ.get("REDIS_SENTINEL_MASTER_NAME")
        try:
            if "REDIS_SENTINEL_MASTER_NAME" in os.environ:
                del os.environ["REDIS_SENTINEL_MASTER_NAME"]

            import importlib

            import src.cage_finance.safety.cbf as cbf_module

            importlib.reload(cbf_module)

            assert cbf_module._REDIS_SENTINEL_MASTER_NAME is None
        finally:
            if original_env is not None:
                os.environ["REDIS_SENTINEL_MASTER_NAME"] = original_env


# ---------------------------------------------------------------------------
# Test: B3a Fence Epoch Cold-Start Seeding
# ---------------------------------------------------------------------------


class TestFenceEpochColdStartSeeding:
    """Tests for B3a: fence epoch cold-start seeding from Redis."""

    def test_cbf_seeds_epoch_from_redis_on_init(self):
        """B3a: CBF must seed _last_seen_epoch from Redis at construction."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        # Mock the sync_redis_client to return an epoch value
        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(return_value="42")

        with patch("src.cage_finance.safety.cbf.sync_redis_client", mock_sync_redis):
            cbf = ControlBarrierFunction()

        # The epoch should be seeded from Redis
        assert cbf._last_seen_epoch == 42
        mock_sync_redis.get.assert_called_once_with("safety:fence_epoch")

    def test_cbf_first_ever_startup_initializes_epoch_to_zero(self):
        """B3a: First-ever startup (no epoch key) initializes epoch to 0 and writes it."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        # Mock sync_redis_client to return None (no epoch key exists)
        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(return_value=None)
        mock_raw_client = MagicMock()
        mock_sync_redis._get = MagicMock(return_value=mock_raw_client)

        with patch("src.cage_finance.safety.cbf.sync_redis_client", mock_sync_redis):
            cbf = ControlBarrierFunction()

        # Epoch should be 0 and written to Redis
        assert cbf._last_seen_epoch == 0
        mock_raw_client.set.assert_called_once_with("safety:fence_epoch", "0")

    def test_cbf_skip_epoch_seed_flag_bypasses_redis(self):
        """B3a: skip_epoch_seed=True bypasses Redis and sets epoch to 0."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        # Even with sync_redis_client=None, should not raise
        with patch("src.cage_finance.safety.cbf.sync_redis_client", None):
            cbf = ControlBarrierFunction(skip_epoch_seed=True)

        assert cbf._last_seen_epoch == 0

    def test_cbf_raises_on_redis_unavailable_in_production(self):
        """B3a: CBF raises CBFInitializationError if Redis unavailable in production."""
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        with (
            patch("src.cage_finance.safety.cbf.sync_redis_client", None),
            patch("src.cage_finance.safety.cbf._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction()

        assert "sync Redis client unavailable" in str(exc_info.value)
        assert "Failing closed" in str(exc_info.value)

    def test_cbf_warns_on_redis_unavailable_in_dev_mode(self):
        """B3a: CBF warns but proceeds with epoch=0 if Redis unavailable in dev mode."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        with (
            patch("src.cage_finance.safety.cbf.sync_redis_client", None),
            patch("src.cage_finance.safety.cbf._IS_PRODUCTION", False),
            patch("src.cage_finance.safety.cbf.logger") as mock_logger,
        ):
            cbf = ControlBarrierFunction()

        assert cbf._last_seen_epoch == 0
        # Verify warning was logged
        mock_logger.warning.assert_called()
        warning_call = str(mock_logger.warning.call_args)
        assert "B3a" in warning_call or "dev/test mode" in warning_call

    def test_cbf_raises_on_redis_error_in_production(self):
        """B3a: CBF raises CBFInitializationError on Redis error in production."""
        from src.gateway.governance.safety.cbf_engine import (
            CBFInitializationError,
            ControlBarrierFunction,
        )

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(
            side_effect=ConnectionError("Redis connection refused")
        )

        with (
            patch("src.cage_finance.safety.cbf.sync_redis_client", mock_sync_redis),
            patch("src.cage_finance.safety.cbf._IS_PRODUCTION", True),
        ):
            with pytest.raises(CBFInitializationError) as exc_info:
                ControlBarrierFunction()

        assert "fence epoch unavailable from Redis" in str(exc_info.value)
        assert "Redis connection refused" in str(exc_info.value)

    def test_cbf_updates_prometheus_gauge_on_successful_seed(self):
        """B3a: Successful epoch seed updates the Prometheus gauge."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(return_value="100")

        with (
            patch("src.cage_finance.safety.cbf.sync_redis_client", mock_sync_redis),
            patch(
                "src.cage_finance.safety.cbf._CURRENT_FENCE_EPOCH_GAUGE"
            ) as mock_gauge,
        ):
            mock_gauge.set = MagicMock()
            ControlBarrierFunction()

        mock_gauge.set.assert_called_once_with(100)

    def test_cbf_logs_successful_seed(self):
        """B3a: Successful epoch seed logs the seeded value."""
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        mock_sync_redis = MagicMock()
        mock_sync_redis.get = MagicMock(return_value="50")

        with (
            patch("src.cage_finance.safety.cbf.sync_redis_client", mock_sync_redis),
            patch("src.cage_finance.safety.cbf.logger") as mock_logger,
        ):
            ControlBarrierFunction()

        # Verify info log contains the epoch value
        mock_logger.info.assert_called()
        info_calls = [str(call) for call in mock_logger.info.call_args_list]
        assert any("50" in call and "B3a" in call for call in info_calls)

    def test_cbf_initialization_error_message_contains_security_context(self):
        """B3a: CBFInitializationError message explains the security rationale."""
        from src.gateway.governance.safety.cbf_engine import CBFInitializationError

        exc = CBFInitializationError("test message")

        # Verify it's a RuntimeError subclass
        assert isinstance(exc, RuntimeError)
        assert str(exc) == "test message"
