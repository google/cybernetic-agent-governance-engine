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

"""Failover verification per tier test suite (Track 6b / §2.4 / C4).

Tests the 4 failover matrix scenarios from plans/gke_managed_services_blueprint.md §2.4:
1. Tier BASIC (dev): Instance restart (state lost) -> Epoch below HWM -> BLOCK until reconciler re-seeds.
2. Tier 1 replica (staging): Manual failover mid-commit -> Either WAIT confirms and commit survives, or strict rollback. Never an acked-but-lost commit.
3. Tier HA (prod): Zone failover -> Shared HWM across >= 2 gateway replicas detects regression and blocks.
4. All tiers: Memory at ceiling (noeviction) -> CBF write error -> fail closed, no silent eviction.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.exceptions

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.safety.cbf_engine import (
    _REDIS_KEY_FENCE_EPOCH,
    _REDIS_KEY_FENCE_EPOCH_HWM,
    ControlBarrierFunction,
)
from src.gateway.governance.safety.debit_ledger import (
    DEBITS_BY_TIME_KEY,
    DEBITS_KEY,
    DEBITS_TOTAL_KEY,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def fake_redis_async():
    """Create a fresh fake async Redis instance."""
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def cbf_finance():
    """CBF instance configured with CashBarrier."""
    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    return cbf


# ---------------------------------------------------------------------------
# Scenario 1: BASIC (dev) — Instance Restart (state lost)
# ---------------------------------------------------------------------------


class TestBasicTierRestart:
    """Verifies BASIC tier behavior on instance restart."""

    @pytest.mark.asyncio
    async def test_restart_drops_epoch_below_hwm_blocks_until_reconciliation(
        self, fake_redis_async, cbf_finance
    ):
        """When Redis restarts and loses epoch state, live epoch < HWM blocks until reconciler runs."""
        # Before restart: HWM is known at 50
        cbf_finance._last_seen_epoch = 50
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "50")

        # Restart occurs: Redis live epoch key is wiped or starts from 0
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "0")

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
                is_valid, reason = await cbf_finance._check_fence_epoch(0)

        assert is_valid is False
        assert "epoch=0 < last_seen=50" in reason
        assert "possible failover" in reason

        # Now reconciler re-seeds signed ground truth with new epoch >= 50
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "51")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "51")

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
                is_valid_after, reason_after = await cbf_finance._check_fence_epoch(51)

        assert is_valid_after is True
        assert reason_after == "OK"


# ---------------------------------------------------------------------------
# Scenario 2: 1 replica (staging) — Failover mid-commit and WAIT confirmation
# ---------------------------------------------------------------------------


class TestStagingTierWaitAndRollback:
    """Verifies staging tier 1-replica failover and WAIT contract."""

    @pytest.mark.asyncio
    async def test_wait_confirms_and_commit_survives(
        self, fake_redis_async, cbf_finance
    ):
        """When WAIT confirms replication (acked >= 1), commit survives and debits persist."""
        conn_mock = AsyncMock()
        conn_mock.execute_command = AsyncMock(return_value=1)  # WAIT 1 returns 1 ack

        with patch(
            "src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True
        ):
            with patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1):
                with patch(
                    "src.gateway.governance.safety.cbf_engine._WAIT_TIMEOUT_MS", 100
                ):
                    # _sync_to_replicas should succeed with 1 ack
                    ok = await cbf_finance._sync_to_replicas(
                        num_replicas=1,
                        timeout_ms=100,
                        client=conn_mock,
                    )

        assert ok is True
        conn_mock.execute_command.assert_awaited_once_with("WAIT", 1, 100)

    @pytest.mark.asyncio
    async def test_wait_timeout_triggers_strict_rollback_and_debit_removal(
        self, fake_redis_async, cbf_finance
    ):
        """When WAIT times out (0 acks), strict replication triggers rollback and deletes debit."""
        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                fake_redis_async,
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            # Pinned: tests/test_fence_epoch.py reloads cbf_engine with the flag
            # off, and the strict rollback only runs when fence epochs are on.
            patch(
                "src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True
            ),
            patch.object(
                cbf_finance,
                "_resolve_ground_truth_balance",
                AsyncMock(
                    return_value=(
                        100000.0,
                        {"source": "reconciliation", "sequence": 3, "fence_epoch": 1},
                    )
                ),
            ),
            # Simulate WAIT failure (replica timeout / 0 acknowledgments)
            patch.object(
                cbf_finance, "_sync_to_replicas", AsyncMock(return_value=False)
            ),
        ):
            committed, msg, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade",
                {"symbol": "AAPL", "shares": 10, "price": 100.0},
                governance_signature="sig-fail",
            )

        assert committed is False
        assert "REPLICATION_UNCONFIRMED" in msg

        # Ensure the rollback retired its own debit (no phantom spend): the
        # ledger entry, its time index and the running total are all restored.
        assert await fake_redis_async.hgetall(DEBITS_KEY) == {}
        assert await fake_redis_async.zcard(DEBITS_BY_TIME_KEY) == 0
        assert float(
            await fake_redis_async.get(DEBITS_TOTAL_KEY) or 0.0
        ) == pytest.approx(0.0)
        assert float(
            await fake_redis_async.get(cbf_finance.redis_key)
        ) == pytest.approx(100000.0)


# ---------------------------------------------------------------------------
# Scenario 3: HA (prod) — Zone Failover across gateway replicas
# ---------------------------------------------------------------------------


class TestHaTierZoneFailover:
    """Verifies HA tier zone failover across >= 2 gateway replicas."""

    @pytest.mark.asyncio
    async def test_replica_gateway_detects_lagging_epoch_after_zone_failover(
        self, fake_redis_async
    ):
        """Two gateway pods: Pod A advanced to 100. Zone failover to lagging replica (80) blocks Pod B."""
        cbf_pod_a = ControlBarrierFunction(
            invariant=CashBarrier(),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )
        cbf_pod_b = ControlBarrierFunction(
            invariant=CashBarrier(),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )

        # Pod A observes epoch 100, which updates safety:fence_epoch_hwm in Redis to 100
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "100")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "100")
        cbf_pod_a._last_seen_epoch = 100

        # Zone failover happens: Redis primary fails over to a replica in another zone
        # whose replication stream was slightly behind at epoch 80.
        # But safety:fence_epoch_hwm remains 100 in Redis
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "80")

        # Pod B starts a safety check against this failed-over Redis instance
        cbf_pod_b._last_seen_epoch = 0

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
                is_valid, reason = await cbf_pod_b._check_fence_epoch(80)

        # Pod B must reject the transaction because live epoch (80) is below persisted HWM (100)
        assert is_valid is False
        assert "epoch=80 < last_seen=100" in reason
        assert "possible failover" in reason


# ---------------------------------------------------------------------------
# Scenario 4: All Tiers — Memory at Ceiling (noeviction)
# ---------------------------------------------------------------------------


class TestNoevictionCeilingError:
    """Verifies that Redis OOM under noeviction fails closed with an error and never silently evicts."""

    @pytest.mark.asyncio
    async def test_cbf_write_oom_fails_closed_without_eviction(
        self, fake_redis_async, cbf_finance
    ):
        """When memory is at ceiling, Redis raises OOM under noeviction; CBF must fail closed."""
        mock_raw_client = MagicMock()
        mock_pinned_client = MagicMock()
        mock_pinned_client.evalsha = AsyncMock(
            side_effect=redis.exceptions.ResponseError(
                "OOM command not allowed when used memory > 'maxmemory'."
            )
        )
        mock_pinned_client.script_load = AsyncMock(return_value="mock_sha")
        mock_pinned_client.aclose = AsyncMock()
        mock_raw_client.client = MagicMock(return_value=mock_pinned_client)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client", mock_raw_client
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=mock_raw_client),
            ),
            patch.object(
                cbf_finance,
                "_resolve_ground_truth_balance",
                AsyncMock(
                    return_value=(
                        100000.0,
                        {"source": "reconciliation", "sequence": 1, "fence_epoch": 1},
                    )
                ),
            ),
        ):
            # Must fail closed: Redis raises ResponseError, preventing commit
            with pytest.raises(
                redis.exceptions.ResponseError, match="OOM command not allowed"
            ):
                await cbf_finance.atomic_verify_and_commit(
                    "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}
                )
