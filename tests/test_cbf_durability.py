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

Verifies the 5 durability fixes specified in plans/gke_managed_services_blueprint.md §2.3,
as carried forward by ADR-010 (settlement-aware debit ledger):
1. Shared Epoch High-Water Mark (`safety:fence_epoch_hwm`) across pods/replicas and restarts.
2. Atomic debit ledgering inside `LUA_ATOMIC_CBF` (`cbf:debits` HASH, no crash window).
3. Settlement-based debit pruning (no count-based `LTRIM -1000` drop, no O(L) read).
4. `rollback_state()` retires exactly its own debit to prevent phantom spend.
5. `EVALSHA` and `WAIT` execute on a single pinned connection.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.reconciliation.daemon import (
    ReconciliationResult,
    reconciled_state_key,
)
from src.gateway.governance.safety.cbf_engine import (
    _REDIS_KEY_FENCE_EPOCH,
    _REDIS_KEY_FENCE_EPOCH_HWM,
    ControlBarrierFunction,
)
from src.gateway.governance.safety.debit_ledger import (
    DEBITS_BY_TIME_KEY,
    DEBITS_KEY,
    DEBITS_PENDING_KEY,
    DEBITS_ROLLED_BACK_KEY,
    DEBITS_TOTAL_KEY,
    settle_debits,
    settle_debits_sync,
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
        invariant=CashBarrier(gamma=0.5),
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

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
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

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
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
        sync_mock.get.side_effect = lambda k: (
            "3" if k == _REDIS_KEY_FENCE_EPOCH else "9"
        )

        with patch(
            "src.gateway.governance.safety.cbf_engine.sync_redis_client", sync_mock
        ):
            cbf = ControlBarrierFunction(
                invariant=CashBarrier(gamma=0.5),
                cost_resolver=finance_cost_resolver,
                skip_epoch_seed=False,
            )
            # Must seed to max(epoch, hwm) = 9
            assert cbf._last_seen_epoch == 9


# ---------------------------------------------------------------------------
# Item 2: Atomic Debit Ledgering in Lua (KEYS[4] / KEYS[6] / KEYS[7])
# ---------------------------------------------------------------------------


async def _seed_debit(r, debit_id: str, amount: float, submitted_at: float) -> None:
    await r.hset(
        DEBITS_KEY,
        debit_id,
        json.dumps({"amount": amount, "submitted_at": submitted_at}),
    )
    await r.zadd(DEBITS_BY_TIME_KEY, {debit_id: submitted_at})
    await r.incrbyfloat(DEBITS_TOTAL_KEY, amount)


async def _ledger(r) -> dict[str, dict]:
    return {k: json.loads(v) for k, v in (await r.hgetall(DEBITS_KEY)).items()}


async def _total(r) -> float:
    raw = await r.get(DEBITS_TOTAL_KEY)
    return float(raw) if raw is not None else 0.0


class TestAtomicDebitInLua:
    """Verifies that debits are ledgered atomically in Lua, closing crash windows."""

    @pytest.mark.asyncio
    async def test_atomic_commit_ledgers_debit_in_lua_script(
        self, fake_redis_async, cbf_finance
    ):
        """The debit entry, time index and running total are written by LUA_ATOMIC_CBF itself."""
        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH_HWM, "1")

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                fake_redis_async,
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(
                cbf_finance,
                "_resolve_ground_truth_balance",
                AsyncMock(
                    return_value=(
                        100000.0,
                        {"source": "reconciliation", "sequence": 7, "fence_epoch": 1},
                    )
                ),
            ),
        ):
            committed, _msg, cost = await cbf_finance.atomic_verify_and_commit(
                "execute_trade",
                {"symbol": "AAPL", "shares": 10, "price": 100.0, "amount": 1000.0},
                governance_signature="sig-item2",
                debit_id="debit-item2",
            )

        assert committed is True
        assert cost == 1000.0

        ledger = await _ledger(fake_redis_async)
        assert set(ledger) == {"debit-item2"}
        entry = ledger["debit-item2"]
        assert entry["amount"] == 1000.0
        assert entry["snapshot_sequence"] == 7
        assert entry["submitted_at"] == pytest.approx(time.time(), abs=5.0)
        # A commit enters the pending set; only confirm() makes it settleable.
        assert await fake_redis_async.zscore(
            DEBITS_PENDING_KEY, "debit-item2"
        ) == pytest.approx(entry["submitted_at"])
        assert await fake_redis_async.zscore(DEBITS_BY_TIME_KEY, "debit-item2") is None
        assert await _total(fake_redis_async) == pytest.approx(1000.0)
        # Governance signature still lands in the audit ledger.
        (audit_entry,) = await fake_redis_async.lrange("audit:state_ledger", 0, -1)
        sig, _, new_state = audit_entry.partition(":")
        assert sig == "sig-item2" and float(new_state) == pytest.approx(99000.0)

    @pytest.mark.asyncio
    async def test_unsafe_transaction_does_not_ledger_debit(
        self, fake_redis_async, cbf_finance
    ):
        """Unsafe transactions must never leave a ledger entry or move the total."""
        await fake_redis_async.set(cbf_finance.redis_key, "50000.0")
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
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(
                cbf_finance,
                "_resolve_ground_truth_balance",
                AsyncMock(
                    return_value=(
                        50000.0,
                        {"source": "reconciliation", "sequence": 1, "fence_epoch": 1},
                    )
                ),
            ),
        ):
            # Cost of $60,000 breaches the $50,000 threshold
            committed, msg, _cost = await cbf_finance.atomic_verify_and_commit(
                "execute_trade",
                {"symbol": "AAPL", "shares": 600, "price": 100.0, "amount": 60000.0},
            )

        assert committed is False
        assert "UNSAFE" in msg
        assert await _ledger(fake_redis_async) == {}
        assert await fake_redis_async.zcard(DEBITS_BY_TIME_KEY) == 0
        assert await fake_redis_async.get(DEBITS_TOTAL_KEY) is None


class TestSelfReportedLiveRead:
    """Self-reported mode (dev only): the script trusts live Redis, never Python's read.

    Closes the two defects the distributed CBF model found: a stale scalar
    passing the epoch CAS after the epoch climbs back (ABA), and a rollback
    crediting a debit the primary has no ledger entry for.
    """

    _TRADE = {"symbol": "AAPL", "shares": 300, "price": 100.0, "amount": 30000.0}

    async def _commit(self, r, cbf, python_read: float):
        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", r),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=r),
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(
                cbf,
                "_resolve_ground_truth_balance",
                AsyncMock(
                    return_value=(
                        python_read,
                        {
                            "source": "self_reported",
                            "mode": "self_reported",
                            "fence_epoch": 1,
                        },
                    )
                ),
            ),
        ):
            return await cbf.atomic_verify_and_commit(
                "execute_trade", dict(self._TRADE)
            )

    @pytest.mark.asyncio
    async def test_stale_python_read_is_ignored(self, fake_redis_async, cbf_finance):
        """Python read 100k, but live state is 20k: the 30k debit must be refused."""
        await fake_redis_async.set(cbf_finance.redis_key, "20000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        committed, msg, _ = await self._commit(
            fake_redis_async, cbf_finance, python_read=100000.0
        )

        assert committed is False and "UNSAFE" in msg, msg
        assert float(await fake_redis_async.get(cbf_finance.redis_key)) == 20000.0
        assert await _ledger(fake_redis_async) == {}

    @pytest.mark.asyncio
    async def test_unset_state_key_uses_the_seed(self, fake_redis_async, cbf_finance):
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")

        committed, msg, _ = await self._commit(
            fake_redis_async, cbf_finance, python_read=100000.0
        )

        assert committed is True, msg
        assert float(
            await fake_redis_async.get(cbf_finance.redis_key)
        ) == pytest.approx(70000.0)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("lua", [True, False], ids=["lua", "watch_fallback"])
    async def test_rollback_without_ledger_entry_restores_nothing(
        self, fake_redis_async, cbf_finance, lua
    ):
        """A debit the primary never ledgered (lost in a failover, or settled)
        is tombstoned and bumps the epoch, but credits nothing."""
        await fake_redis_async.set(cbf_finance.redis_key, "5000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "3")

        with patch(
            "src.gateway.governance.safety.cbf_engine._is_mock",
            (lambda _obj: False) if lua else (lambda _obj: True),
        ):
            await cbf_finance.rollback_state(
                1000.0, debit_id="lost", client=fake_redis_async
            )
            assert float(await fake_redis_async.get(cbf_finance.redis_key)) == 5000.0
            assert int(await fake_redis_async.get(_REDIS_KEY_FENCE_EPOCH)) == 4
            assert await fake_redis_async.hexists(DEBITS_ROLLED_BACK_KEY, "lost")
            assert await fake_redis_async.get(DEBITS_TOTAL_KEY) is None

            await cbf_finance.rollback_state(
                1000.0, debit_id="lost", client=fake_redis_async
            )
            assert float(await fake_redis_async.get(cbf_finance.redis_key)) == 5000.0
            assert int(await fake_redis_async.get(_REDIS_KEY_FENCE_EPOCH)) == 4

    @pytest.mark.asyncio
    @pytest.mark.parametrize("lua", [True, False], ids=["lua", "watch_fallback"])
    async def test_rollback_restores_the_ledgered_amount(
        self, fake_redis_async, cbf_finance, lua
    ):
        await fake_redis_async.set(cbf_finance.redis_key, "5000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "3")
        await _seed_debit(fake_redis_async, "d1", 750.0, submitted_at=1.0)

        with patch(
            "src.gateway.governance.safety.cbf_engine._is_mock",
            (lambda _obj: False) if lua else (lambda _obj: True),
        ):
            # The caller's magnitude is ignored; the ledger is authoritative.
            await cbf_finance.rollback_state(
                1000.0, debit_id="d1", client=fake_redis_async
            )

        assert float(
            await fake_redis_async.get(cbf_finance.redis_key)
        ) == pytest.approx(5750.0)
        assert await _ledger(fake_redis_async) == {}
        assert await _total(fake_redis_async) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Item 3: Settlement-based debit pruning (no count-based LTRIM -1000 drop)
# ---------------------------------------------------------------------------


class TestSettlementBasedDebitPruning:
    """Debits are pruned by settlement cutoff, never by count or snapshot sequence."""

    @pytest.mark.asyncio
    async def test_settle_prunes_only_debits_at_or_before_cutoff(
        self, fake_redis_async
    ):
        """Debits submitted <= cutoff are settled; later ones survive and the total is re-derived."""
        for i, amount in enumerate((100.0, 200.0, 300.0, 400.0), start=1):
            await _seed_debit(fake_redis_async, f"d{i}", amount, submitted_at=float(i))

        settled = await settle_debits(fake_redis_async, cutoff=2.0)
        assert settled == 2

        ledger = await _ledger(fake_redis_async)
        assert set(ledger) == {"d3", "d4"}
        assert await fake_redis_async.zrange(DEBITS_BY_TIME_KEY, 0, -1) == ["d3", "d4"]
        assert await _total(fake_redis_async) == pytest.approx(700.0)

    def test_sync_version_works_with_sync_client(self):
        """settle_debits_sync (the daemon's path) prunes via a sync client."""
        fakeredis = pytest.importorskip("fakeredis")
        sync_redis = fakeredis.FakeRedis(decode_responses=True)
        for debit_id, amount, ts in (("a", 50.0, 10.0), ("b", 75.0, 11.0)):
            sync_redis.hset(
                DEBITS_KEY, debit_id, json.dumps({"amount": amount, "submitted_at": ts})
            )
            sync_redis.zadd(DEBITS_BY_TIME_KEY, {debit_id: ts})
        sync_redis.set(DEBITS_TOTAL_KEY, "125.0")

        assert settle_debits_sync(sync_redis, cutoff=10.0) == 1
        assert sync_redis.hkeys(DEBITS_KEY) == ["b"]
        assert float(sync_redis.get(DEBITS_TOTAL_KEY)) == pytest.approx(75.0)

    @pytest.mark.asyncio
    async def test_more_than_1000_outstanding_debits_all_count(
        self, fake_redis_async, cbf_finance
    ):
        """Over 1000 outstanding debits are never dropped (replaces LTRIM -1000) and all net the scalar."""
        now = time.time()
        pipe = fake_redis_async.pipeline()
        for i in range(1050):
            debit_id = f"d{i}"
            pipe.hset(
                DEBITS_KEY, debit_id, json.dumps({"amount": 1.0, "submitted_at": now})
            )
            pipe.zadd(DEBITS_BY_TIME_KEY, {debit_id: now})
        pipe.set(DEBITS_TOTAL_KEY, "1050.0")
        await pipe.execute()
        assert await fake_redis_async.hlen(DEBITS_KEY) == 1050

        await fake_redis_async.set(cbf_finance.redis_key, "100000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "1")
        snapshot_key = reconciled_state_key(cbf_finance.invariant.invariant_id)

        # Publish the snapshot the metadata claims to have verified so the
        # script's generation check (ADR-010) sees matching bytes.
        snapshot = ReconciliationResult(
            source="reconciliation",
            state_scalar=100000.0,
            verified_at=now,
            signature="valid_sig",
            kms_key_id="reconciler-kid",
            signing_algorithm="gcp_kms",
            ttl_seconds=300,
            sequence=10,
        )
        payload = snapshot.to_redis_payload()
        await fake_redis_async.set(snapshot_key, payload)
        metadata = {
            "source": "reconciled",
            "mode": "reconciled",
            "state_scalar": 100000.0,
            "raw_payload": payload,
            "sequence": 10,
            "verified_at": now,
            "fence_epoch": 1,
        }

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client",
                fake_redis_async,
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 0),
            patch.object(
                cbf_finance,
                "_resolve_ground_truth_balance",
                AsyncMock(return_value=(100000.0 - 1050.0, metadata)),
            ),
        ):
            # Effective balance is 100000 - 1050 = 98950 (floor 1000, gamma 0.5):
            # the largest admissible cost is 48975, so 49000 must be refused ...
            denied, reason, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade", {"amount": 49000.0}
            )
            assert denied is False and "UNSAFE" in reason, reason
            # ... while a small trade still clears.
            committed, reason, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade",
                {"shares": 1, "price": 50.0, "amount": 50.0},
                debit_id="fresh",
            )
            assert committed is True, reason

        # 1051 outstanding debits: nothing was truncated, the total tracks them all.
        assert await fake_redis_async.hlen(DEBITS_KEY) == 1051
        assert await _total(fake_redis_async) == pytest.approx(1100.0)
        assert float(
            await fake_redis_async.get(cbf_finance.redis_key)
        ) == pytest.approx(98900.0)


# ---------------------------------------------------------------------------
# Item 4: Rollback State Retires Its Debit (Phantom Spend Prevention)
# ---------------------------------------------------------------------------


class TestRollbackDebitRemoval:
    """Verifies that rollback_state retires exactly the matching debit entry."""

    @pytest.mark.asyncio
    async def test_rollback_state_removes_matching_debit(
        self, fake_redis_async, cbf_finance
    ):
        """rollback_state restores balance AND retires the ledgered debit in the same script."""
        await fake_redis_async.set(cbf_finance.redis_key, "99000.0")
        await fake_redis_async.set(_REDIS_KEY_FENCE_EPOCH, "2")
        await _seed_debit(fake_redis_async, "other", 250.0, submitted_at=1.0)
        await _seed_debit(fake_redis_async, "sig-rb-debit", 1000.0, submitted_at=2.0)

        with patch(
            "src.gateway.governance.safety.cbf_engine.redis_client", fake_redis_async
        ):
            with patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=fake_redis_async),
            ):
                await cbf_finance.rollback_state(
                    1000.0,
                    governance_signature="sig-rb",
                    debit_id="sig-rb-debit",
                )

        # Balance restored
        assert float(await fake_redis_async.get(cbf_finance.redis_key)) == 100000.0
        # Exactly that debit is gone; the other one is untouched (no phantom spend either way)
        assert set(await _ledger(fake_redis_async)) == {"other"}
        assert await fake_redis_async.zrange(DEBITS_BY_TIME_KEY, 0, -1) == ["other"]
        assert await _total(fake_redis_async) == pytest.approx(250.0)
        # A tombstone makes a second rollback of the same debit a no-op
        assert await fake_redis_async.hexists(DEBITS_ROLLED_BACK_KEY, "sig-rb-debit")
        assert int(await fake_redis_async.get(_REDIS_KEY_FENCE_EPOCH)) == 3

    @pytest.mark.asyncio
    async def test_wait_timeout_rollback_removes_debit_and_fails_closed(
        self, fake_redis_async, cbf_finance
    ):
        """Strict replication failure triggers rollback that retires the unconfirmed debit."""
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
            # Simulate WAIT failure (e.g. replica timeout)
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

        # The rollback retired its own debit: entry, index and total are all restored.
        assert await _ledger(fake_redis_async) == {}
        assert await fake_redis_async.zcard(DEBITS_BY_TIME_KEY) == 0
        assert await _total(fake_redis_async) == pytest.approx(0.0)
        assert float(
            await fake_redis_async.get(cbf_finance.redis_key)
        ) == pytest.approx(100000.0)


# ---------------------------------------------------------------------------
# Item 5: Pinned Connection for EVALSHA and WAIT
# ---------------------------------------------------------------------------


class TestPinnedConnection:
    """Verifies that EVALSHA and WAIT execute on one pinned connection."""

    @pytest.mark.asyncio
    async def test_evalsha_and_wait_use_same_pinned_client(self, cbf_finance):
        """atomic_verify_and_commit must pin a connection and run both EVALSHA and WAIT on it."""
        mock_raw_client = MagicMock()
        mock_pinned_client = MagicMock()
        mock_pinned_client.evalsha = AsyncMock(
            return_value=[1, "COMMITTED", "99000.0", 2]
        )
        mock_pinned_client.script_load = AsyncMock(return_value="mock_sha")
        mock_pinned_client.execute_command = AsyncMock(return_value=1)
        mock_pinned_client.aclose = AsyncMock()

        # client() returns the pinned connection
        mock_raw_client.client = MagicMock(return_value=mock_pinned_client)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client", mock_raw_client
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine._get_raw_redis",
                AsyncMock(return_value=mock_raw_client),
            ),
            patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
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
            committed, _msg, _ = await cbf_finance.atomic_verify_and_commit(
                "execute_trade",
                {"symbol": "AAPL", "shares": 10, "price": 100.0, "amount": 1000.0},
            )

        assert committed is True
        # Both EVALSHA and WAIT must have executed on mock_pinned_client!
        assert mock_pinned_client.evalsha.called
        assert mock_pinned_client.execute_command.called
        # And neither on mock_raw_client directly
        assert (
            not hasattr(mock_raw_client.evalsha, "called")
            or not mock_raw_client.evalsha.called
        )
        # Pinned client was closed/released
        assert mock_pinned_client.aclose.called
