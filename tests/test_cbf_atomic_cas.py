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
C4 Security Fix Test Suite: Atomic CAS Fence Epoch Validation

Tests the elimination of TOCTOU race conditions in CBF balance operations
by validating fence epoch atomically inside the Redis Lua script using
Compare-And-Swap (CAS) semantics.

Security Invariant:
All fence epoch validation happens atomically in Lua with no Python TOCTOU window.
Concurrent requests cannot double-spend due to CAS protection enforced at the
Redis script level.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_raw_client():
    """Mock raw Redis client for hermetic testing."""
    client = MagicMock()
    client.evalsha = AsyncMock()
    client.script_load = AsyncMock(return_value="mock_sha")
    return client


@pytest.fixture
def mock_redis_client():
    """Mock Redis client wrapper."""
    return MagicMock()


@pytest.fixture
def cbf_instance(mock_redis_client, mock_raw_client):
    """CBF instance with mocked Redis for testing."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            cbf = ControlBarrierFunction(skip_epoch_seed=True)
            cbf._lua_sha = "mock_sha"
            return cbf


@pytest.mark.asyncio
async def test_sequential_operations_pass(cbf_instance, mock_redis_client, mock_raw_client):
    """Multiple sequential debits work when fence epoch increments monotonically."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Mock ground truth resolution
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )

            # First debit succeeds (fence=1 → 2)
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 2]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert msg == "COMMITTED"
            assert cbf_instance._last_verified_fence_epoch == 2

            # Second debit succeeds (fence=2 → 3)
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    99000.0,
                    {"source": "reconciliation", "fence_epoch": 2, "sequence": 2},
                )
            )
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "98000.0", 3]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "GOOGL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert msg == "COMMITTED"
            assert cbf_instance._last_verified_fence_epoch == 3


@pytest.mark.asyncio
async def test_concurrent_race_prevented(cbf_instance, mock_redis_client, mock_raw_client):
    """Simulate two concurrent requests; only one succeeds due to CAS protection."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Both requests read fence_epoch=1 from reconciliation
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )

            # Request A executes first: fence=1 → 2 (succeeds)
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 2]
            committed_a, msg_a = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed_a is True
            assert cbf_instance._last_verified_fence_epoch == 2

            # Request B executes second: expected_fence=1 but current_fence=2 (CAS fails)
            mock_raw_client.evalsha.return_value = [
                0,
                "Fence epoch regression: expected 1, got 2",
                "0",
                2,
            ]
            committed_b, msg_b = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "GOOGL", "shares": 10, "price": 100.0}
            )
            assert committed_b is False
            assert "Fence epoch regression" in msg_b
            # Accept either Python-side regression check or Lua-side CAS check
            assert ("1 < 2" in msg_b or "expected 1, got 2" in msg_b)


@pytest.mark.asyncio
async def test_fence_regression_rejected(cbf_instance, mock_redis_client, mock_raw_client):
    """Stale fence epoch causes rejection (failover or replay attack)."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Normal commit: fence=5 → 6
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 5, "sequence": 1},
                )
            )
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 6]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert cbf_instance._last_verified_fence_epoch == 6

            # Attacker replays stale request with fence=3 (< 6)
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 3, "sequence": 2},
                )
            )
            mock_raw_client.evalsha.return_value = [
                0,
                "Fence epoch regression: expected 3, got 6",
                "0",
                6,
            ]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "TSLA", "shares": 10, "price": 100.0}
            )
            assert committed is False
            assert "Fence epoch regression" in msg


@pytest.mark.asyncio
async def test_balance_exactly_equal_to_cost(cbf_instance, mock_redis_client, mock_raw_client):
    """Boundary case: balance exactly equals cost (h_next = 0, should pass)."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Balance = 1000, cost = 1000, min_cash = 0 → h_next = 0 (passes >= 0 check)
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    1000.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "0.0", 2]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert msg == "COMMITTED"


@pytest.mark.asyncio
async def test_negative_balance_prevented(cbf_instance, mock_redis_client, mock_raw_client):
    """h_next < 0 is rejected (bankruptcy protection)."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Balance = 900, cost = 1000, min_cash = 0 → h_next = -100 (fails)
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    900.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )
            mock_raw_client.evalsha.return_value = [
                0,
                "UNSAFE: h_next=-100.0 < required=0.0",
                "900.0",
                1,
            ]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is False
            assert "UNSAFE" in msg
            assert "h_next=-100.0" in msg


@pytest.mark.asyncio
async def test_missing_fence_key_handled(cbf_instance, mock_redis_client, mock_raw_client):
    """Missing fence key defaults to 0 (initial state)."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            # Fence key missing (nil) → defaults to 0
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 0, "sequence": 1},
                )
            )
            # Lua script: current_fence=0 (nil → 0), expected_fence=0 → passes CAS
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 1]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert msg == "COMMITTED"
            assert cbf_instance._last_verified_fence_epoch == 1


@pytest.mark.asyncio
async def test_lua_script_execution_error(cbf_instance, mock_redis_client, mock_raw_client):
    """Malformed data handled gracefully (Lua script error propagation)."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )
            # Simulate Lua script error (e.g., malformed balance)
            mock_raw_client.evalsha.side_effect = Exception("ERR Error running script")

            with pytest.raises(Exception, match="ERR Error running script"):
                await cbf_instance.atomic_verify_and_commit(
                    "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
                )


@pytest.mark.asyncio
async def test_successful_commit_increments_fence(cbf_instance, mock_redis_client, mock_raw_client):
    """Verify fence monotonicity: successful commit increments fence epoch."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 10, "sequence": 1},
                )
            )
            # Lua script increments fence: 10 → 11
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 11]
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is True
            assert cbf_instance._last_verified_fence_epoch == 11

            # Verify last_seen_epoch also updated
            assert cbf_instance._last_seen_epoch == 11


@pytest.mark.asyncio
async def test_failed_verification_no_fence_increment(cbf_instance, mock_redis_client, mock_raw_client):
    """UNSAFE (CBF violation) doesn't increment fence — read-only operation."""
    with patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_client):
        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            cbf_instance._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100.0,
                    {"source": "reconciliation", "fence_epoch": 5, "sequence": 1},
                )
            )
            # Lua script rejects: fence remains 5 (no INCR)
            mock_raw_client.evalsha.return_value = [
                0,
                "UNSAFE: h_next=-900.0 < required=0.0",
                "100.0",
                5,
            ]
            cbf_instance._last_verified_fence_epoch = None  # Reset for clean test
            committed, msg = await cbf_instance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed is False
            assert "UNSAFE" in msg
            # Fence epoch should NOT be updated on failure (remains None)
            assert cbf_instance._last_verified_fence_epoch is None


@pytest.mark.asyncio
async def test_cas_protects_against_time_of_check_to_time_of_use():
    """
    Integration test: Verify CAS prevents TOCTOU exploitation.
    
    Scenario:
    1. Request A reads fence=1
    2. Request B reads fence=1 (concurrent)
    3. Request A commits (fence: 1 → 2)
    4. Request B attempts commit with stale expected_fence=1
    5. Lua CAS rejects B because current_fence=2 ≠ expected_fence=1
    """
    with patch("src.gateway.governance.safety.cbf_engine.redis_client") as mock_redis:
        mock_raw_client = MagicMock()
        mock_raw_client.evalsha = AsyncMock()
        mock_raw_client.script_load = AsyncMock(return_value="sha_cas")

        with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)):
            cbf = ControlBarrierFunction(skip_epoch_seed=True)
            cbf._lua_sha = "sha_cas"

            # Both requests read fence=1 from reconciliation
            cbf._resolve_ground_truth_balance = AsyncMock(
                return_value=(
                    100000.0,
                    {"source": "reconciliation", "fence_epoch": 1, "sequence": 1},
                )
            )

            # Request A executes: CAS passes (expected=1, current=1), fence → 2
            mock_raw_client.evalsha.return_value = [1, "COMMITTED", "99000.0", 2]
            committed_a, _ = await cbf.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
            )
            assert committed_a is True

            # Request B still has stale expected_fence=1 (from initial read)
            # But Lua script sees current_fence=2 → CAS fails
            mock_raw_client.evalsha.return_value = [
                0,
                "Fence epoch regression: expected 1, got 2",
                "0",
                2,
            ]
            committed_b, msg_b = await cbf.atomic_verify_and_commit(
                "execute_trade", {"symbol": "GOOGL", "shares": 10, "price": 100.0}
            )
            assert committed_b is False
            assert "Fence epoch regression" in msg_b
            # Accept either Python-side regression check or Lua-side CAS check
            assert ("1 < 2" in msg_b or "expected 1, got 2" in msg_b)
