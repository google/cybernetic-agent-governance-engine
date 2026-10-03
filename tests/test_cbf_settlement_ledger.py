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

"""Settlement-aware local-debit ledger (ADR-010, POAM-2026-087).

Hermetic (fakeredis + software Ed25519) end-to-end checks that the CBF, the
reconciliation daemon and the simulated custodian agree on *when* a debit
stops being outstanding, and that every disagreement fails closed:

* a custodian that has not yet absorbed a debit cannot be double-spent;
* the ledger is pruned only up to the signed ``settled_through`` minus the
  clock-skew margin, never by snapshot sequence;
* rollback is exact (by ``debit_id``) and idempotent;
* a commit against a snapshot that was replaced mid-flight is refused;
* commit cost does not grow with the number of outstanding debits;
* previews and commits see the same netted headroom;
* a stalled custodian starves the barrier instead of feeding it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.reconciliation import trust
from src.gateway.governance.reconciliation.daemon import (
    FENCE_EPOCH_KEY,
    GroundTruthReconciler,
    ReconciliationResult,
    read_verified_state,
    reconciled_state_key,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.safety.debit_ledger import (
    DEBITS_BY_TIME_KEY,
    DEBITS_KEY,
    DEBITS_PENDING_KEY,
    DEBITS_ROLLED_BACK_KEY,
    DEBITS_TOTAL_KEY,
    settle_debits_sync,
    settlement_cutoff,
    unsettled_total_sync,
)
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    InMemoryLedgerJournal,
    RedisLedgerJournal,
    SimulatedSource,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

INVARIANT = "finance.cash_balance"
ACTION = "execute_trade"
RECONCILER_KID = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/"
    "cage-reconciler-snapshot-signer/cryptoKeyVersions/1"
)
INITIAL = 100_000.0
FLOOR = 1_000.0  # domains.finance.cbf.min_cash_balance
GAMMA = 0.5


def _max_admissible(balance: float) -> float:
    """Largest single cost the barrier admits from ``balance``: gamma * h(balance)."""
    return GAMMA * (balance - FLOOR)


@dataclass
class World:
    """One custodian, one reconciler, one CBF, one fakeredis — all wired together."""

    signer: KMSGovernanceSigner
    verifier: KMSGovernanceSigner
    sync_redis: Any
    async_redis: Any
    provider: SimulatedCashLedgerProvider
    reconciler: GroundTruthReconciler
    cbf: ControlBarrierFunction

    @contextlib.contextmanager
    def live(self):
        """Point the CBF at this world's Redis and trust anchors, strict mode on."""
        redis_mod = MagicMock()
        redis_mod.get_raw_client = MagicMock(return_value=self.async_redis)
        redis_mod.get = self.async_redis.get
        with (
            patch("src.gateway.governance.safety.cbf_engine.redis_client", redis_mod),
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                self.sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
            patch(
                "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
                lambda: self.verifier,
            ),
        ):
            yield self

    # -- custodian / reconciler -------------------------------------------------
    def reconcile(self) -> ReconciliationResult | None:
        return self.reconciler.reconcile_once(INVARIANT)

    def settle_everything(self) -> None:
        """Let the custodian catch up: immediate settlement, no skew margin."""
        self.provider.source.settlement_lag_s = 0.0
        self.reconciler._settlement_clock_skew_s = 0.0

    # -- barrier -----------------------------------------------------------------
    async def commit(
        self, amount: float, *, debit_id: str | None = None, execute: bool = True
    ) -> tuple[bool, str, str]:
        """Commit through the CBF and, if admitted and ``execute``, run the action.

        Mirrors the production split: the barrier ledgers the debit (pending)
        under ``debit_id``; the actuator tells the custodian about the fill;
        then the governor's settlement confirms the debit.
        """
        debit_id = debit_id or uuid.uuid4().hex
        committed, reason, _ = await self.cbf.atomic_verify_and_commit(
            ACTION, {"amount": amount}, debit_id=debit_id
        )
        if committed and execute:
            self.provider.record_debit(
                amount, submitted_at=time.time(), debit_id=debit_id
            )
            assert await self.confirm(debit_id)
        return committed, reason, debit_id

    async def confirm(self, debit_id: str) -> bool:
        return await self.cbf.confirm_debit(debit_id)

    async def rollback(self, amount: float, debit_id: str) -> None:
        await self.cbf.rollback_state(amount, debit_id=debit_id)

    async def headroom(self) -> float | None:
        return await self.cbf.admissible_cost()

    # -- ledger inspection -------------------------------------------------------
    def ledger(self) -> dict[str, dict[str, Any]]:
        return {
            k: json.loads(v) for k, v in self.sync_redis.hgetall(DEBITS_KEY).items()
        }

    def total(self) -> float:
        raw = self.sync_redis.get(DEBITS_TOTAL_KEY)
        return float(raw) if raw is not None else 0.0

    def state(self) -> float:
        return float(self.sync_redis.get(CashBarrier.state_key))

    def epoch(self) -> int:
        return int(self.sync_redis.get(FENCE_EPOCH_KEY) or 0)

    def pending(self) -> dict[str, float]:
        return dict(self.sync_redis.zrange(DEBITS_PENDING_KEY, 0, -1, withscores=True))

    def confirmed(self) -> dict[str, float]:
        return dict(self.sync_redis.zrange(DEBITS_BY_TIME_KEY, 0, -1, withscores=True))


def _build_world(
    monkeypatch: pytest.MonkeyPatch,
    *,
    custodian_lag_s: float,
    skew_s: float = 0.0,
    lag_fallback_s: float = 120.0,
    initial: float = INITIAL,
    pending_max_age_s: float = 600.0,
) -> World:
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.delenv(trust.RECONCILER_KMS_KEY_ENV, raising=False)
    monkeypatch.delenv(trust.GATEWAY_KMS_KEY_ENV, raising=False)
    signer = KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id=RECONCILER_KID)
    )
    verifier = trust.build_reconciler_verifier(
        {RECONCILER_KID: signer.get_public_key_pem()}
    )

    server = fakeredis.FakeServer()
    sync_redis = fakeredis.FakeRedis(server=server, decode_responses=True)
    async_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    sync_redis.set(CashBarrier.state_key, repr(initial))
    sync_redis.set(FENCE_EPOCH_KEY, "0")

    provider = SimulatedCashLedgerProvider(
        initial_scalar=initial,
        seed=7,
        journal=InMemoryLedgerJournal(),
        settlement_lag_s=custodian_lag_s,
    )
    reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
        settlement_lag_seconds=lag_fallback_s,
        settlement_clock_skew_seconds=skew_s,
        pending_debit_max_age_seconds=pending_max_age_s,
    )
    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    return World(signer, verifier, sync_redis, async_redis, provider, reconciler, cbf)


# ---------------------------------------------------------------------------
# Pure pieces
# ---------------------------------------------------------------------------


def test_settlement_cutoff_prefers_attestation_then_lag_and_always_subtracts_skew() -> (
    None
):
    assert (
        settlement_cutoff(1_000.0, 990.0, lag_seconds=120.0, skew_seconds=5.0) == 985.0
    )
    # Attestation can never run ahead of the snapshot itself.
    assert (
        settlement_cutoff(1_000.0, 2_000.0, lag_seconds=120.0, skew_seconds=5.0)
        == 995.0
    )
    # No attestation: assume the configured lag.
    assert (
        settlement_cutoff(1_000.0, None, lag_seconds=120.0, skew_seconds=5.0) == 875.0
    )
    assert (
        settlement_cutoff(1_000.0, math.nan, lag_seconds=120.0, skew_seconds=5.0)
        == 875.0
    )


def test_settled_through_is_part_of_the_signed_payload_and_round_trips() -> None:
    snap = ReconciliationResult(
        source="simulated", state_scalar=1.0, verified_at=10.0, settled_through=7.5
    )
    assert trust.snapshot_signing_payload(snap)["settled_through"] == 7.5
    payload = snap.to_redis_payload()
    back = ReconciliationResult.from_redis_payload(payload)
    assert back.settled_through == 7.5
    assert back.raw_payload == payload
    # Absent / non-finite attestations collapse to None (lag fallback).
    assert (
        ReconciliationResult(
            source="s", state_scalar=1.0, settled_through=math.inf
        ).settled_through
        is None
    )
    assert (
        ReconciliationResult.from_redis_payload(
            json.dumps({"source": "s", "verified_at": 1.0})
        ).settled_through
        is None
    )


def test_simulated_source_settles_after_lag_and_attests_settled_through() -> None:
    src = SimulatedSource(
        invariant_id="x.y", initial_scalar=100.0, settlement_lag_s=60.0
    )
    src.record_debit(30.0, submitted_at=1_000.0)
    early = src.next_snapshot(now=1_030.0)
    assert early.scalar == 100.0 and early.settled_through == 970.0
    late = src.next_snapshot(now=1_061.0)
    assert late.scalar == 70.0 and late.settled_through == 1_001.0


def test_settlement_stall_freezes_the_attestation_but_keeps_the_feed_healthy() -> None:
    src = SimulatedSource(
        invariant_id="x.y", initial_scalar=100.0, settlement_lag_s=0.0
    )
    src.inject_fault(FaultMode.SETTLEMENT_STALL)
    frozen = src.next_snapshot(now=1_000.0)
    src.record_debit(40.0, submitted_at=1_001.0)
    later = src.next_snapshot(now=2_000.0)
    assert frozen.settled_through == later.settled_through == 1_000.0
    assert later.scalar == 100.0  # the debit never settles while stalled
    assert later.invariant_id == "x.y" and math.isfinite(later.scalar)
    src.clear_fault()
    assert src.next_snapshot(now=2_001.0).scalar == 60.0


def test_redis_ledger_journal_is_shared_state() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    writer = RedisLedgerJournal(r, "x.y")
    reader = RedisLedgerJournal(r, "x.y")
    writer.record(debit_id="a", amount=10.0, submitted_at=100.0)
    writer.record(debit_id="b", amount=5.0, submitted_at=200.0)
    assert reader.settled_total(150.0) == 10.0
    assert reader.settled_total(200.0) == 15.0
    assert reader.total() == 15.0
    reader.clear()
    assert writer.total() == 0.0


# ---------------------------------------------------------------------------
# Settle script
# ---------------------------------------------------------------------------


def _seed_ledger(r: Any, entries: dict[str, tuple[float, float]]) -> None:
    for debit_id, (amount, submitted_at) in entries.items():
        r.hset(
            DEBITS_KEY,
            debit_id,
            json.dumps({"amount": amount, "submitted_at": submitted_at}),
        )
        r.zadd(DEBITS_BY_TIME_KEY, {debit_id: submitted_at})
    r.set(DEBITS_TOTAL_KEY, repr(sum(a for a, _ in entries.values())))


def test_skew_margin_delays_settlement() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    t = 1_000.0
    _seed_ledger(r, {"d": (50.0, t)})
    not_yet = settlement_cutoff(t + 1.0, t + 1.0, lag_seconds=120.0, skew_seconds=5.0)
    assert settle_debits_sync(r, not_yet) == 0
    assert r.hexists(DEBITS_KEY, "d") and float(r.get(DEBITS_TOTAL_KEY)) == 50.0
    settled = settlement_cutoff(t + 6.0, t + 6.0, lag_seconds=120.0, skew_seconds=5.0)
    assert settle_debits_sync(r, settled) == 1
    assert not r.hexists(DEBITS_KEY, "d") and float(r.get(DEBITS_TOTAL_KEY)) == 0.0


def test_total_drift_corrected_on_settle_and_tombstones_pruned() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    _seed_ledger(r, {"a": (10.0, 100.0), "b": (20.5, 200.0), "c": (30.0, 300.0)})
    r.set(DEBITS_TOTAL_KEY, "999999")  # INCRBYFLOAT drift / tampering
    r.hset(DEBITS_ROLLED_BACK_KEY, mapping={"old": "50", "fresh": "250"})
    assert settle_debits_sync(r, 150.0) == 1  # only "a"
    assert float(r.get(DEBITS_TOTAL_KEY)) == pytest.approx(50.5)
    assert set(r.hkeys(DEBITS_ROLLED_BACK_KEY)) == {"fresh"}
    assert unsettled_total_sync(r, 200.0) == pytest.approx(30.0)  # strictly after


class _Clock:
    """Deterministic wall clock for the modules under test; everything else delegates to ``time``."""

    def __init__(self, start: float) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


def _frozen_clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    clock = _Clock(1_700_000_000.0)
    for module in (
        "src.gateway.governance.seams.ground_truth",
        "src.gateway.governance.safety.cbf_engine",
        "src.gateway.governance.safety.debit_ledger",
        "src.gateway.governance.reconciliation.daemon",
    ):
        monkeypatch.setattr(f"{module}.time", clock)
    return clock


@pytest.mark.asyncio
async def test_unconfirmed_debit_is_never_settled_however_late_the_actuator_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The commit-to-custodian gap is closed by confirm(), not by the skew margin.

    ``submitted_at`` is stamped when the CBF commits, before the actuator tells
    the custodian about the fill. A debit stays pending (never settled) until
    the governor confirms it after execution; confirm stamps it with the
    confirm time, which is at or after the custodian's receipt, so the skew
    margin only has to cover clock skew.
    """
    skew = 5.0
    clock = _frozen_clock(monkeypatch)
    world = _build_world(monkeypatch, custodian_lag_s=0.0, skew_s=skew)
    with world.live():
        assert world.reconcile() is not None
        ok, _, debit_id = await world.commit(10_000.0, execute=False)
        assert ok
        assert world.ledger()[debit_id]["submitted_at"] == clock.now
        assert set(world.pending()) == {debit_id} and world.confirmed() == {}

        # Ten times the skew margin later the actuator still has not run. Under
        # the old commit-time stamp this debit would already be settled while
        # the custodian does not carry it (headroom overstated by 10k).
        clock.advance(10 * skew)
        snap = world.reconcile()
        assert snap is not None and snap.state_scalar == INITIAL
        assert debit_id in world.ledger()
        assert await world.headroom() == pytest.approx(
            _max_admissible(INITIAL - 10_000.0)
        )

        # The actuator journals the fill, then the governor confirms.
        world.provider.record_debit(10_000.0, submitted_at=clock.now, debit_id=debit_id)
        assert await world.confirm(debit_id)
        assert world.confirmed() == {debit_id: clock.now} and world.pending() == {}
        assert world.ledger()[debit_id]["confirmed_at"] == clock.now
        assert not await world.confirm(debit_id)  # idempotent

        # The custodian reflects the fill at once (lag 0), but the cutoff
        # (now - skew) is before the confirm stamp: the debit is counted twice
        # for one skew window, which errs toward less headroom.
        snap = world.reconcile()
        assert snap is not None and snap.state_scalar == pytest.approx(INITIAL - 10_000.0)
        assert debit_id in world.ledger()
        assert await world.headroom() == pytest.approx(
            _max_admissible(INITIAL - 20_000.0)
        )

        clock.advance(skew)
        assert world.reconcile() is not None
        assert world.ledger() == {} and world.total() == 0.0
        assert await world.headroom() == pytest.approx(
            _max_admissible(INITIAL - 10_000.0)
        )


@pytest.mark.asyncio
async def test_unconfirmed_debit_is_promoted_after_the_max_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No confirm ever arrives (the governor's settlement hold expired) but the
    action may have executed: once older than the max age the debit is promoted
    to confirmed, stamped at promotion, and settles a skew window later."""
    skew, max_age = 5.0, 60.0
    clock = _frozen_clock(monkeypatch)
    world = _build_world(
        monkeypatch, custodian_lag_s=0.0, skew_s=skew, pending_max_age_s=max_age
    )
    with world.live():
        assert world.reconcile() is not None
        ok, _, debit_id = await world.commit(10_000.0, execute=False)
        assert ok
        committed_at = clock.now
        world.provider.record_debit(10_000.0, submitted_at=clock.now, debit_id=debit_id)

        clock.advance(max_age - 1.0)
        assert world.reconcile() is not None
        assert set(world.pending()) == {debit_id}

        clock.advance(1.0)  # exactly max_age old: promoted, not yet settled
        assert world.reconcile() is not None
        assert world.pending() == {}
        assert world.confirmed() == {debit_id: committed_at + max_age}
        assert debit_id in world.ledger()

        clock.advance(skew)
        assert world.reconcile() is not None
        assert world.ledger() == {} and world.total() == 0.0


def test_settle_never_prunes_pending_debits() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    r.hset(DEBITS_KEY, "p", json.dumps({"amount": 25.0, "submitted_at": 100.0}))
    r.zadd(DEBITS_PENDING_KEY, {"p": 100.0})
    r.set(DEBITS_TOTAL_KEY, "25.0")
    assert settle_debits_sync(r, 10_000.0) == 0
    assert r.hexists(DEBITS_KEY, "p") and float(r.get(DEBITS_TOTAL_KEY)) == 25.0
    # Pending debits are unsettled by definition, whatever the cutoff.
    assert unsettled_total_sync(r, 10_000.0) == pytest.approx(25.0)
    # An orphan cutoff before the commit leaves it pending.
    assert settle_debits_sync(r, 10_000.0, orphan_before=99.0, now=500.0) == 0
    assert r.zscore(DEBITS_PENDING_KEY, "p") == 100.0


# ---------------------------------------------------------------------------
# CBF + reconciler + custodian end to end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lagging_ledger_blocks_double_spend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review pt 5: a debit the custodian has not absorbed yet must still count."""
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok, reason, _ = await world.commit(40_000.0)
        assert ok, reason

        # The custodian still reports the pre-trade balance ...
        snap = world.reconcile()
        assert snap is not None and snap.state_scalar == INITIAL
        assert world.total() == pytest.approx(
            40_000.0
        )  # ... so the debit stays outstanding
        assert await world.headroom() == pytest.approx(
            _max_admissible(INITIAL - 40_000.0)
        )

        denied, reason, _ = await world.commit(40_000.0)
        assert not denied and reason.startswith("UNSAFE"), reason

        # After settlement the custodian reflects the trade, the ledger is
        # pruned, and the answer is the same — just derived from a different term.
        world.settle_everything()
        snap = world.reconcile()
        assert snap is not None and snap.state_scalar == pytest.approx(
            INITIAL - 40_000.0
        )
        assert world.ledger() == {} and world.total() == 0.0
        still_denied, _, _ = await world.commit(40_000.0)
        assert not still_denied
        ok, reason, _ = await world.commit(_max_admissible(INITIAL - 40_000.0) - 1.0)
        assert ok, reason


@pytest.mark.asyncio
async def test_settle_never_prunes_before_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok, _, debit_id = await world.commit(10_000.0)
        assert ok
        for _ in range(5):
            assert world.reconcile() is not None
            assert debit_id in world.ledger()
            assert world.total() == pytest.approx(10_000.0)
        world.settle_everything()
        assert world.reconcile() is not None
        assert debit_id not in world.ledger() and world.total() == 0.0


@pytest.mark.asyncio
async def test_rollback_by_debit_id_is_exact_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok_a, _, a = await world.commit(10_000.0)
        ok_b, _, b = await world.commit(10_000.0)
        assert ok_a and ok_b
        state_after_commits = world.state()

        await world.rollback(10_000.0, a)
        assert set(world.ledger()) == {b}
        assert world.total() == pytest.approx(10_000.0)
        assert world.state() == pytest.approx(state_after_commits + 10_000.0)
        epoch = world.epoch()

        await world.rollback(10_000.0, a)  # second rollback: NOOP
        assert set(world.ledger()) == {b}
        assert world.total() == pytest.approx(10_000.0)
        assert world.state() == pytest.approx(state_after_commits + 10_000.0)
        assert world.epoch() == epoch


@pytest.mark.asyncio
async def test_rollback_after_settlement_restores_fallback_state_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=0.0)
    with world.live():
        assert world.reconcile() is not None
        ok, _, debit_id = await world.commit(10_000.0)
        assert ok
        assert world.reconcile() is not None  # settles immediately (lag 0, skew 0)
        assert world.ledger() == {}
        settled_state = world.state()

        await world.rollback(10_000.0, debit_id)
        assert world.state() == pytest.approx(settled_state + 10_000.0)
        assert world.total() == 0.0
        await world.rollback(10_000.0, debit_id)
        assert world.state() == pytest.approx(settled_state + 10_000.0)


@pytest.mark.asyncio
async def test_wait_timeout_rollback_removes_its_own_debit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with (
        world.live(),
        patch("src.gateway.governance.safety.cbf_engine._STRICT_REPLICATION", True),
        patch("src.gateway.governance.safety.cbf_engine._FENCE_EPOCH_ENABLED", True),
        patch("src.gateway.governance.safety.cbf_engine._WAIT_REPLICAS", 1),
    ):
        assert world.reconcile() is not None
        before = world.state()
        world.cbf._sync_to_replicas = AsyncMock(return_value=False)  # type: ignore[method-assign]
        committed, reason, _ = await world.commit(10_000.0)
        assert committed is False and "REPLICATION_UNCONFIRMED" in reason
        assert world.ledger() == {}
        assert world.total() == pytest.approx(0.0)
        assert world.state() == pytest.approx(before)


@pytest.mark.asyncio
async def test_commit_is_constant_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review pt 2: no O(L) LRANGE on the hot path."""
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    counts = {"n": 0}

    def _count(client: Any) -> None:
        original = client.execute_command

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            counts["n"] += 1
            return original(*args, **kwargs)

        client.execute_command = wrapped

    async def _measure() -> int:
        counts["n"] = 0
        ok, reason, _ = await world.commit(1.0, execute=False)
        assert ok, reason
        return counts["n"]

    with world.live():
        assert world.reconcile() is not None
        await world.commit(1.0, execute=False)  # warm-up: loads the Lua SHA
        _count(world.async_redis)
        _count(world.sync_redis)
        _seed_ledger(world.sync_redis, {f"d{i}": (1.0, 0.0) for i in range(10)})
        with_ten = await _measure()
        _seed_ledger(world.sync_redis, {f"d{i}": (1.0, 0.0) for i in range(1_000)})
        with_thousand = await _measure()
    assert with_ten == with_thousand


@pytest.mark.asyncio
async def test_preview_matches_commit_headroom(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review pt 5 / A5: previews are debit-aware, so preview == commit."""
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok, _, _ = await world.commit(40_000.0)
        assert ok
        bound = await world.headroom()
        assert bound == pytest.approx(_max_admissible(INITIAL - 40_000.0))
        denied, _, _ = await world.commit(bound + 1.0)
        assert not denied
        ok, reason, _ = await world.commit(bound)
        assert ok, reason


@pytest.mark.asyncio
async def test_previews_never_touch_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok, _, _ = await world.commit(5_000.0)
        assert ok
        image = (
            world.sync_redis.hgetall(DEBITS_KEY),
            world.sync_redis.zrange(DEBITS_BY_TIME_KEY, 0, -1, withscores=True),
            world.sync_redis.get(DEBITS_TOTAL_KEY),
        )
        for _ in range(5):
            assert await world.cbf.verify_action(ACTION, {"amount": 1_000.0}) == "SAFE"
            await world.headroom()
        assert image == (
            world.sync_redis.hgetall(DEBITS_KEY),
            world.sync_redis.zrange(DEBITS_BY_TIME_KEY, 0, -1, withscores=True),
            world.sync_redis.get(DEBITS_TOTAL_KEY),
        )


@pytest.mark.asyncio
async def test_settlement_stall_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """FaultMode.SETTLEMENT_STALL: the feed stays healthy, the barrier starves."""
    world = _build_world(monkeypatch, custodian_lag_s=0.0)
    with world.live():
        assert world.reconcile() is not None
        world.provider.inject_fault(FaultMode.SETTLEMENT_STALL)
        assert world.reconcile() is not None  # reconciler still accepts the snapshot

        # 100k -> 30k ok (headroom 49.5k) -> 30k ok (34.5k) -> 30k refused (19.5k).
        amount = 30_000.0
        balance = INITIAL
        admitted = 0
        for _ in range(10):
            ok, reason, _ = await world.commit(amount)
            snap = world.reconcile()
            assert snap is not None  # the feed stays healthy ...
            assert snap.state_scalar == INITIAL  # ... but never absorbs a fill
            if not ok:
                assert reason.startswith("UNSAFE"), reason
                break
            admitted += 1
            balance -= amount
        else:  # pragma: no cover - the loop must terminate with a refusal
            pytest.fail("barrier never refused under a settlement stall")
        assert admitted == 2
        # The refusal came purely from the local ledger: nothing was pruned.
        assert world.total() == pytest.approx(INITIAL - balance)
        assert len(world.ledger()) == admitted
        assert await world.headroom() == pytest.approx(_max_admissible(balance))

        world.provider.clear_fault()
        assert world.reconcile() is not None
        assert world.ledger() == {}  # attestation resumed: everything settles


@pytest.mark.asyncio
async def test_tampered_settled_through_fails_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        key = reconciled_state_key(INVARIANT)
        doc = json.loads(world.sync_redis.get(key))
        doc["settled_through"] = time.time() + 3_600.0  # "everything has settled"
        world.sync_redis.set(key, json.dumps(doc))

        assert (
            read_verified_state(world.sync_redis, INVARIANT, signer=world.verifier)
            is None
        )
        committed, reason, _ = await world.commit(1.0, execute=False)
        assert committed is False and "RECONCILIATION_UNAVAILABLE" in reason


@pytest.mark.asyncio
async def test_snapshot_replaced_between_read_and_commit_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The script nets against the generation Python verified, or not at all."""
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        original = world.cbf._resolve_ground_truth_balance

        async def read_then_let_the_reconciler_publish() -> Any:
            resolved = await original()
            assert world.reconcile() is not None  # new verified_at → new payload bytes
            return resolved

        world.cbf._resolve_ground_truth_balance = read_then_let_the_reconciler_publish  # type: ignore[method-assign]
        before = world.state()
        committed, reason, _ = await world.commit(1_000.0, execute=False)
        assert committed is False and "SNAPSHOT_CHANGED" in reason
        assert world.ledger() == {} and world.state() == before


@pytest.mark.asyncio
async def test_discrepancy_guard_tolerates_unsettled_debits_but_not_external_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WS-B guard, made settlement-aware: custodian ∈ [self-reported, self-reported + unsettled]."""
    world = _build_world(monkeypatch, custodian_lag_s=3_600.0)
    with world.live():
        assert world.reconcile() is not None
        ok, _, _ = await world.commit(40_000.0)
        assert ok
        # Custodian 100k vs self-reported 60k is exactly the unsettled 40k: fine.
        assert world.reconcile() is not None

        # Money left the account behind our back: below the band → spike.
        world.provider.source.initial_scalar = INITIAL - 90_000.0
        assert world.reconcile() is None
        assert world.reconciler._failure_count == 1

        # Unexplained credit: above the band → spike.
        world.provider.source.initial_scalar = INITIAL + 200_000.0
        assert world.reconcile() is None


# ---------------------------------------------------------------------------
# Actuator → custodian journal
# ---------------------------------------------------------------------------


def _clearance(amount: float) -> ExecutionClearance:
    params = {
        "symbol": "AAPL",
        "amount": amount,
        "currency": "USD",
        "confidence": 0.99,
        "transaction_id": str(uuid.uuid4()),
        "trader_id": "agent_001",
        "trader_role": "junior",
        "side": "buy",
    }
    return ExecutionClearance(
        thread_id=params["transaction_id"],
        decision="ALLOW",
        decision_path="DIRECT",
        action=ACTION,
        target="AAPL",
        operator_urn="agent_001",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=params["transaction_id"],
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=hashlib.sha256(b"seal").hexdigest(),
        opa_input_digest=hashlib.sha256(
            json.dumps(params, sort_keys=True).encode()
        ).hexdigest(),
        nonce=uuid.uuid4().hex,
        params=params,
        required_quorum=0,
        executor_id="cage_finance_broker",
    )


@pytest.mark.asyncio
async def test_broker_actuator_journals_the_fill_with_the_custodian(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("USE_MOCK_BROKER", "true")
    journal = InMemoryLedgerJournal()
    custodian = SimulatedCashLedgerProvider(journal=journal, settlement_lag_s=0.0)
    actuator = BrokerActuator(ledger=custodian)
    clearance = _clearance(250.0)
    with (
        patch(
            "src.cage_finance.actuators.broker_actuator.execute_trade",
            new_callable=AsyncMock,
            return_value="EXECUTED",
        ),
        patch(
            "src.gateway.governance.execution_actuator.ingest_actuation_receipt",
            new_callable=AsyncMock,
        ),
    ):
        receipt = await actuator.actuate(clearance)
    assert receipt.accepted is True
    assert receipt.raw_receipt["custodian_debit_usd"] == 250.0
    assert len(journal) == 1
    assert journal.total() == 250.0
    assert custodian.source.current_scalar == pytest.approx(
        CashBarrier.initial_state - 250.0
    )


@pytest.mark.asyncio
async def test_broker_actuator_refuses_when_the_custodian_journal_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("USE_MOCK_BROKER", "true")
    broken = MagicMock()
    broken.record_debit = MagicMock(side_effect=ConnectionError("journal down"))
    actuator = BrokerActuator(ledger=broken)
    with (
        patch(
            "src.cage_finance.actuators.broker_actuator.execute_trade",
            new_callable=AsyncMock,
            return_value="EXECUTED",
        ),
        patch(
            "src.gateway.governance.execution_actuator.ingest_actuation_receipt",
            new_callable=AsyncMock,
        ),
    ):
        receipt = await actuator.actuate(_clearance(250.0))
    assert receipt.accepted is False
    assert receipt.retryable is True
    assert [f["code"] for f in receipt.findings] == ["CUSTODIAN_JOURNAL_FAILED"]


def test_pending_max_age_outlasts_the_governor_settlement_hold() -> None:
    """Promotion must not race a confirm or rollback that can still arrive."""
    from src.gateway.governance.governor.settlement import DEFAULT_HOLD_SECONDS
    from src.gateway.governance.schemas.thresholds import (
        get_reconciliation_pending_debit_max_age_seconds,
    )

    assert get_reconciliation_pending_debit_max_age_seconds() >= DEFAULT_HOLD_SECONDS
