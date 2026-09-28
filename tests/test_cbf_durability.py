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

"""Unit and chaos tests for CBF durability (Track 6b.0 / G4).

Verifies the 5 durability fixes specified in plans/gke_managed_services_blueprint.md §2.3:
1. Shared Epoch High-Water Mark (`safety:fence_epoch_hwm`) across pods/replicas and restarts.
2. Atomic debit execution inside `LUA_ATOMIC_CBF` as `KEYS[4]` (no crash window).
3. Sequence-based debit trimming (no count-based `LTRIM -1000` drop).
4. `rollback_state()` removes the debit to prevent phantom spend.
5. `EVALSHA` and `WAIT` execute on a single pinned connection.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.reconciliation.daemon import ReconciliationResult
from src.gateway.governance.safety.cbf_engine import (
    _REDIS_KEY_FENCE_EPOCH,
    _REDIS_KEY_FENCE_EPOCH_HWM,
    _REDIS_KEY_LOCAL_DEBITS,
    ControlBarrierFunction,
    trim_local_debits_through_sequence,
    trim_local_debits_through_sequence_sync,
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
# Item 1: Epoch High-Water Mark (safety:fence_epoch_hwm)
# ---------------------------------------------------------------------------


class TestFenceEpochHighWaterMark:
    """Verifies that failover/rollback detection is shared via safety:fence_epoch_hwm."""

    @pytest.mark.asyncio
    async def test_replica_detects_epoch_regression_via_persisted_hwm(
        self, fake_redis_async, cbf_finance
    ):
        """A fresh pod (last_seen=0) must reject an epoch below persisted HWM."""
        # Pod 1 advanced epoch to 10, updating HWM in Redis to 10
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "5")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "10")

        # Pod 2 initializes fresh with last_seen_epoch = 0
        cbf_finance._last_seen_epoch = 0

        with patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async):
            with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)):
                is_valid, reason = await cbf_finance._check_fence_epoch(5)

        assert is_valid is False
        assert "epoch=5 < last_seen=10" in reason
        assert "possible failover" in reason

    @pytest.mark.asyncio
    async def test_advancing_epoch_updates_hwm_monotonically(
        self, fake_redis_async, cbf_finance
    ):
        """Advancing live epoch updates HWM, but lower epoch never decreases HWM."""
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "5")
        cbf_finance._last_seen_epoch = 5

        with patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async):
            with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)):
                # Advance to 8
                is_valid, _ = await cbf_finance._check_fence_epoch(8)
                assert is_valid is True
                hwm_after = await fake_redis_async.get(_REDIS_KEY_FENCE_EPOCH_HWM)
                assert int(hwm_after) == 8

                # Live epoch regresses to 6 (< 8)
                is_valid_regress, _ = await cbf_finance._check_fence_epoch(6)
                assert is_valid_regress is False
                # HWM remains 8
                hwm_still_8 = await fake_redis_async.get(_REDIS_KEY_FENCE_EPOCH_HWM)
                assert int(hwm_still_8) == 8

    def test_startup_seeding_uses_hwm_when_epoch_is_lower(self, fake_redis_async):
        """On startup, if Redis live epoch < HWM, _last_seen_epoch seeds from HWM."""
        sync_mock = MagicMock()
        sync_mock._has_hwm = True
        sync_mock.get.side_effect = lambda k: "3" if k == _REDIS_KEY_FENCE_EPOCH else "9"

        with patch("src.gateway.governance.safety.cbf_engine.sync_redis_client", sync_mock):
            cbf = ControlBarrierFunction(
                invariant=CashBarrier(),
                cost_resolver=finance_cost_resolver,
                skip_epoch_seed=False,
            )
            # Must seed to max(epoch, hwm) = 9
            assert cbf._last_seen_epoch == 9


# ---------------------------------------------------------------------------
# Item 2: Atomic Debit in Lua (KEYS[4])
# ---------------------------------------------------------------------------


class TestAtomicDebitInLua:
    """Verifies that debits are committed atomically in Lua, closing crash windows."""

    @pytest.mark.asyncio
    async def test_atomic_commit_pushes_debit_in_lua_script(
        self, fake_redis_async, cbf_finance
    ):
        """Debit is pushed inside LUA_ATOMIC_CBF without separate Python rpush."""
        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "1")

        mock_result = ReconciliationResult(
            source="reconciliation",
            state_scalar=100000.0,
            verified_at=time.time(),
            signature="valid_sig",
            kms_key_id="reconciler-kid",
            signing_algorithm="gcp_kms",
            ttl_seconds=300,
            sequence=7,
        )

        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async),
            patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(cbf_finance, "_resolve_ground_truth_balance", AsyncMock(return_value=(
                100000.0,
                {"source": "reconciliation", "sequence": 7, "fence_epoch": 1},
            ))),
        ):
            committed, msg, cost = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0, "amount": 1000.0}, governance_signature="sig-item2"
            )

        assert committed is True
        assert cost == 1000.0

        # Verify debit was written to Redis list
        raw_debits = await fake_redis_async.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(raw_debits) == 1
        entry = json.loads(raw_debits[0])
        assert entry["amount"] == 1000.0
        assert entry["reconciliation_sequence"] == 7
        assert entry["action_signature"] == "sig-item2"

    @pytest.mark.asyncio
    async def test_unsafe_transaction_does_not_push_debit(
        self, fake_redis_async, cbf_finance
    ):
        """Unsafe transactions must never push a debit entry to Redis."""
        await fake_redis_async.set(cbf_finance.redis_key, "50000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async),
            patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(cbf_finance, "_resolve_ground_truth_balance", AsyncMock(return_value=(
                50000.0,
                {"source": "reconciliation", "sequence": 1, "fence_epoch": 1},
            ))),
        ):
            # Cost of $60,000 breaches the $50,000 threshold
            committed, msg, cost = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 600, "price": 100.0, "amount": 60000.0}
            )

        assert committed is False
        assert "UNSAFE" in msg
        raw_debits = await fake_redis_async.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(raw_debits) == 0


# ---------------------------------------------------------------------------
# Item 3: Sequence-based debit trimming (no count-based LTRIM -1000 drop)
# ---------------------------------------------------------------------------


class TestSequenceBasedDebitTrimming:
    """Verifies that debits are pruned by reconciliation sequence, preserving high volumes."""

    @pytest.mark.asyncio
    async def test_trim_local_debits_through_sequence_prunes_older(
        self, fake_redis_async
    ):
        """Debits <= signed sequence are pruned; debits > signed sequence are kept."""
        debits = [
            {"amount": 100.0, "reconciliation_sequence": 1},
            {"amount": 200.0, "reconciliation_sequence": 2},
            {"amount": 300.0, "reconciliation_sequence": 3},
            {"amount": 400.0, "reconciliation_sequence": 4},
        ]
        for d in debits:
            await fake_redis_async.rpush(_REDIS_KEY_LOCAL_DEBITS, json.dumps(d))

        # Trim up to sequence 2
        pruned = await trim_local_debits_through_sequence(fake_redis_async, signed_sequence=2)
        assert pruned == 2

        remaining_raw = await fake_redis_async.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(remaining_raw) == 2
        remaining = [json.loads(r) for r in remaining_raw]
        assert remaining[0]["reconciliation_sequence"] == 3
        assert remaining[1]["reconciliation_sequence"] == 4

    def test_sync_version_works_with_sync_client(self, fake_redis_async):
        """trim_local_debits_through_sequence_sync correctly prunes via sync client."""
        fakeredis = pytest.importorskip("fakeredis")
        sync_redis = fakeredis.FakeRedis(decode_responses=True)

        sync_redis.rpush(_REDIS_KEY_LOCAL_DEBITS, json.dumps({"amount": 50.0, "reconciliation_sequence": 10}))
        sync_redis.rpush(_REDIS_KEY_LOCAL_DEBITS, json.dumps({"amount": 75.0, "reconciliation_sequence": 11}))

        pruned = trim_local_debits_through_sequence_sync(sync_redis, signed_sequence=10)
        assert pruned == 1
        rem = sync_redis.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(rem) == 1
        assert json.loads(rem[0])["reconciliation_sequence"] == 11

    @pytest.mark.asyncio
    async def test_more_than_1000_debits_in_sequence_not_dropped(
        self, fake_redis_async, cbf_finance
    ):
        """Over 1000 debits in the current sequence are never dropped (replaces LTRIM -1000)."""
        # Push 1050 debits in sequence 10
        pipe = fake_redis_async.pipeline()
        for i in range(1050):
            pipe.rpush(
                _REDIS_KEY_LOCAL_DEBITS,
                json.dumps({"amount": 1.0, "reconciliation_sequence": 10}),
            )
        await pipe.execute()

        raw_count = await fake_redis_async.llen(_REDIS_KEY_LOCAL_DEBITS)
        assert raw_count == 1050

        # Now test that atomic_verify_and_commit sums all 1050 debits without truncation
        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async),
            patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(cbf_finance, "_resolve_ground_truth_balance", AsyncMock(return_value=(
                100000.0,
                {"source": "reconciliation", "sequence": 10, "fence_epoch": 1},
            ))),
        ):
            # Effective balance should be 100000 - 1050 = 98950.0
            # Let's verify by committing a 50.0 trade
            committed, _, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"shares": 1, "price": 50.0, "amount": 50.0}
            )
            assert committed is True

            # Debits count is now 1051 (NOT truncated to 1000 by LTRIM!)
            new_count = await fake_redis_async.llen(_REDIS_KEY_LOCAL_DEBITS)
            assert new_count == 1051


# ---------------------------------------------------------------------------
# Item 4: Rollback State Removes Debit (Phantom Spend Prevention)
# ---------------------------------------------------------------------------


class TestRollbackDebitRemoval:
    """Verifies that rollback_state prunes the matching debit entry."""

    @pytest.mark.asyncio
    async def test_rollback_state_removes_matching_debit(
        self, fake_redis_async, cbf_finance
    ):
        """rollback_state restores balance AND clears the local debit in the same script."""
        await fake_redis_async.set(cbf_finance.redis_key, "99000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "2")
        await fake_redis_async.rpush(
            _REDIS_KEY_LOCAL_DEBITS,
            json.dumps({
                "amount": 1000.0,
                "reconciliation_sequence": 5,
                "action_signature": "sig-rb",
            }),
        )

        with patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async):
            with patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)):
                await cbf_finance.rollback_state(
                    1000.0,
                    governance_signature="sig-rb",
                    reconciliation_sequence=5,
                )

        # Balance restored
        restored_balance = await fake_redis_async.get(cbf_finance.redis_key)
        assert float(restored_balance) == 100000.0

        # Debit removed from cbf:local_debits (preventing phantom spend)
        rem_debits = await fake_redis_async.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(rem_debits) == 0

    @pytest.mark.asyncio
    async def test_wait_timeout_rollback_removes_debit_and_fails_closed(
        self, fake_redis_async, cbf_finance
    ):
        """Strict replication failure triggers rollback that deletes the unconfirmed debit."""
        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async),
            patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=fake_redis_async)),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
            patch.object(cbf_finance, "_resolve_ground_truth_balance", AsyncMock(return_value=(
                100000.0,
                {"source": "reconciliation", "sequence": 3, "fence_epoch": 1},
            ))),
            # Simulate WAIT failure (e.g. replica timeout)
            patch.object(cbf_finance, "_sync_to_replicas", AsyncMock(return_value=False)),
        ):
            committed, msg, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0}, governance_signature="sig-fail"
            )

        assert committed is False
        assert "REPLICATION_UNCONFIRMED" in msg

        # Ensure debit was pruned by the rollback
        debits = await fake_redis_async.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
        assert len(debits) == 0


# ---------------------------------------------------------------------------
# Item 5: Pinned Connection for EVALSHA and WAIT
# ---------------------------------------------------------------------------


class TestPinnedConnection:
    """Verifies that EVALSHA and WAIT execute on one pinned connection."""

    @pytest.mark.asyncio
    async def test_evalsha_and_wait_use_same_pinned_client(
        self, cbf_finance
    ):
        """atomic_verify_and_commit must pin a connection and run both EVALSHA and WAIT on it."""
        mock_raw_client = MagicMock()
        mock_pinned_client = MagicMock()
        mock_pinned_client.evalsha = AsyncMock(return_value=[1, "COMMITTED", "99000.0", 2])
        mock_pinned_client.script_load = AsyncMock(return_value="mock_sha")
        mock_pinned_client.execute_command = AsyncMock(return_value=1)
        mock_pinned_client.aclose = AsyncMock()

        # client() returns the pinned connection
        mock_raw_client.client = MagicMock(return_value=mock_pinned_client)

        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_raw_client),
            patch("src.gateway.governance.safety.cbf_engine._get_raw_redis", AsyncMock(return_value=mock_raw_client)),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
            patch.object(cbf_finance, "_resolve_ground_truth_balance", AsyncMock(return_value=(
                100000.0,
                {"source": "reconciliation", "sequence": 1, "fence_epoch": 1},
            ))),
        ):
            committed, msg, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"symbol": "AAPL", "shares": 10, "price": 100.0, "amount": 1000.0}
            )

        assert committed is True
        # Both EVALSHA and WAIT must have executed on mock_pinned_client!
        assert mock_pinned_client.evalsha.called
        assert mock_pinned_client.execute_command.called
        # And neither on mock_raw_client directly
        assert not hasattr(mock_raw_client.evalsha, "called") or not mock_raw_client.evalsha.called
        # Pinned client was closed/released
        assert mock_pinned_client.aclose.called
