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

"""Hermetic fault-injection tests for GroundTruthReconciler and domain GroundTruthProviders.

Verifies all 10 FaultMode failure modes across finance, healthcare, and
physical-AI simulated ground-truth providers, confirming that every single
fault fails closed (reconcile_once returns None, read_verified_state returns
None, and ControlBarrierFunction blocks in enforcing/strict posture).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest

from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.cage_healthcare.ground_truth import SimulatedSerumAssayProvider
from src.cage_healthcare.invariants import (
    SerumConcentrationBarrier,
    healthcare_cost_resolver,
)
from src.cage_physical_ai.ground_truth import (
    SimulatedSpatialSensorProvider,
    SimulatedTorqueSensorProvider,
    SimulatedVelocitySensorProvider,
)
from src.cage_physical_ai.invariants import (
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
    spatial_cost_resolver,
    torque_cost_resolver,
    velocity_cost_resolver,
)
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.reconciliation.daemon import (
    FENCE_EPOCH_KEY,
    GroundTruthReconciler,
    read_verified_state,
    reconciled_state_key,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.seams.ground_truth import FaultMode, SimulatedSource

pytestmark = [pytest.mark.unit, pytest.mark.local]

ALL_TEN_FAULT_MODES: tuple[FaultMode, ...] = (
    FaultMode.TIMEOUT,
    FaultMode.CONNECTION_ERROR,
    FaultMode.MALFORMED_PAYLOAD,
    FaultMode.NEGATIVE_VALUE,
    FaultMode.NAN_VALUE,
    FaultMode.STALE_TIMESTAMP,
    FaultMode.FUTURE_TIMESTAMP,
    FaultMode.UNVERIFIED_SOURCE,
    FaultMode.SCALAR_BELOW_BARRIER,
    FaultMode.DISCREPANCY_SPIKE,
)


def _domain_provider_specs() -> list[tuple[str, Any, Any, Any, str, dict[str, Any]]]:
    """Return (domain_label, provider_factory, invariant, cost_resolver, action, params)."""
    return [
        (
            "finance_cash",
            lambda: SimulatedCashLedgerProvider(seed=42),
            CashBarrier(gamma=0.5),
            finance_cost_resolver,
            "execute_trade",
            {"amount": 500.0},
        ),
        (
            "healthcare_serum",
            lambda: SimulatedSerumAssayProvider(seed=42),
            SerumConcentrationBarrier(),
            healthcare_cost_resolver,
            "administer_dose",
            {"dose_mg": 1.0},
        ),
        (
            "physical_ai_spatial",
            lambda: SimulatedSpatialSensorProvider(seed=42),
            SpatialSeparationBarrier(),
            spatial_cost_resolver,
            "dispatch_trajectory",
            {"approach_distance_mm": 50.0},
        ),
        (
            "physical_ai_velocity",
            lambda: SimulatedVelocitySensorProvider(seed=42),
            KinematicVelocityBarrier(),
            velocity_cost_resolver,
            "dispatch_trajectory",
            {"target_velocity_mm_s": 25.0},
        ),
        (
            "physical_ai_torque",
            lambda: SimulatedTorqueSensorProvider(seed=42),
            TorqueSaturationBarrier(),
            torque_cost_resolver,
            "actuate_joint",
            {"torque_nm": 5.0},
        ),
    ]


def _make_ed25519_signer(monkeypatch: pytest.MonkeyPatch) -> KMSGovernanceSigner:
    monkeypatch.setenv("CAGE_ENV", "development")
    return KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="ground-truth-ed25519-k1")
    )


def test_all_ten_fault_modes_enumerated() -> None:
    """FaultMode defines NONE, the 10 reconciler-rejected modes, and SETTLEMENT_STALL.

    SETTLEMENT_STALL is deliberately *not* in ``ALL_TEN_FAULT_MODES``: a
    stalled custodian still emits a well-formed, signed snapshot, so the
    reconciler accepts it and the CBF fails closed instead as outstanding
    debits stop settling (see tests/test_cbf_settlement_ledger.py).
    """
    non_none = [m for m in FaultMode if m != FaultMode.NONE]
    assert len(non_none) == 11
    assert set(non_none) == set(ALL_TEN_FAULT_MODES) | {FaultMode.SETTLEMENT_STALL}


def test_simulated_source_deterministic_seeding() -> None:
    """Two SimulatedSource instances with the same seed produce identical snapshot sequences."""
    s1 = SimulatedSource(
        invariant_id="finance.cash_balance",
        state_key="safety:current_cash",
        initial_scalar=100_000.0,
        barrier_floor=20_000.0,
        seed=1337,
        jitter_amplitude=25.0,
    )
    s2 = SimulatedSource(
        invariant_id="finance.cash_balance",
        state_key="safety:current_cash",
        initial_scalar=100_000.0,
        barrier_floor=20_000.0,
        seed=1337,
        jitter_amplitude=25.0,
    )

    seq1 = [s1.next_snapshot(now=1700000000.0 + i).scalar for i in range(5)]
    seq2 = [s2.next_snapshot(now=1700000000.0 + i).scalar for i in range(5)]
    assert seq1 == seq2


@pytest.mark.parametrize(
    (
        "domain_label",
        "provider_factory",
        "invariant",
        "cost_resolver",
        "action",
        "params",
    ),
    _domain_provider_specs(),
    ids=[spec[0] for spec in _domain_provider_specs()],
)
def test_healthy_reconcile_writes_signed_verified_state(
    monkeypatch: pytest.MonkeyPatch,
    domain_label: str,
    provider_factory: Any,
    invariant: Any,
    cost_resolver: Any,
    action: str,
    params: dict[str, Any],
) -> None:
    """Under FaultMode.NONE, GroundTruthReconciler signs and writes verified state readable by read_verified_state."""
    signer = _make_ed25519_signer(monkeypatch)
    sync_redis = fakeredis.FakeRedis(decode_responses=True)
    provider = provider_factory()

    reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
    )
    res = reconciler.reconcile_once(invariant.invariant_id)
    assert res is not None
    assert res.is_valid
    assert res.signature != ""

    verified_scalar = read_verified_state(
        sync_redis,
        invariant.invariant_id,
        signer=signer,
    )
    assert verified_scalar == pytest.approx(provider.source.initial_scalar)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault_mode", ALL_TEN_FAULT_MODES)
@pytest.mark.parametrize(
    (
        "domain_label",
        "provider_factory",
        "invariant",
        "cost_resolver",
        "action",
        "params",
    ),
    _domain_provider_specs(),
    ids=[spec[0] for spec in _domain_provider_specs()],
)
async def test_every_fault_mode_fails_closed_across_all_domains(
    monkeypatch: pytest.MonkeyPatch,
    fault_mode: FaultMode,
    domain_label: str,
    provider_factory: Any,
    invariant: Any,
    cost_resolver: Any,
    action: str,
    params: dict[str, Any],
) -> None:
    """Every FaultMode across finance, healthcare, and physical-AI must fail closed."""
    signer = _make_ed25519_signer(monkeypatch)
    server = fakeredis.FakeServer()
    sync_redis = fakeredis.FakeRedis(server=server, decode_responses=True)
    async_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    provider = provider_factory()
    # Seed self-reported baseline in Redis so DISCREPANCY_SPIKE and strict CBF have baseline state
    sync_redis.set(invariant.state_key, str(provider.source.initial_scalar))
    sync_redis.set(FENCE_EPOCH_KEY, "0")

    reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
    )

    # First reconcile healthy state to confirm fault invalidates prior verified state
    ok_res = reconciler.reconcile_once(invariant.invariant_id)
    assert ok_res is not None
    assert (
        read_verified_state(sync_redis, invariant.invariant_id, signer=signer)
        is not None
    )

    # Inject fault and run reconciliation tick
    provider.inject_fault(fault_mode)
    fault_res = reconciler.reconcile_once(invariant.invariant_id)
    assert fault_res is None, (
        f"Expected reconcile_once to return None on {fault_mode} for {domain_label}"
    )

    # Verified state in Redis must be invalidated (read_verified_state returns None)
    verified_after_fault = read_verified_state(
        sync_redis,
        invariant.invariant_id,
        signer=signer,
    )
    assert verified_after_fault is None, (
        f"Expected read_verified_state to return None on {fault_mode} for {domain_label}"
    )

    # In strict/enforcing mode, CBF must block the governed action (fail-closed)
    cbf = ControlBarrierFunction(
        invariant=invariant,
        cost_resolver=cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=async_redis)
    mock_redis_mod.get = async_redis.get

    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch("src.gateway.governance.safety.cbf_engine.sync_redis_client", sync_redis),
        patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
    ):
        committed, reason, _ = await cbf.atomic_verify_and_commit(action, dict(params))
        assert committed is False, (
            f"CBF atomic_verify_and_commit must fail closed on {fault_mode} for {domain_label}, got {reason!r}"
        )
        assert "RECONCILIATION_UNAVAILABLE" in reason, (
            f"Expected RECONCILIATION_UNAVAILABLE on {fault_mode} for {domain_label}, got {reason!r}"
        )


def test_tampered_redis_payload_fails_signature_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tampering with scalar or sequence in Redis after reconcile_once causes read_verified_state to return None."""
    signer = _make_ed25519_signer(monkeypatch)
    sync_redis = fakeredis.FakeRedis(decode_responses=True)
    provider = SimulatedCashLedgerProvider(seed=42)

    reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
    )
    res = reconciler.reconcile_once("finance.cash_balance")
    assert res is not None

    key = reconciled_state_key("finance.cash_balance")
    raw = sync_redis.get(key)
    assert raw is not None

    # Tamper with state_scalar without re-signing
    tampered = json.loads(raw)
    tampered["state_scalar"] = 999_999.0
    sync_redis.set(key, json.dumps(tampered))

    assert (
        read_verified_state(sync_redis, "finance.cash_balance", signer=signer) is None
    )


def test_non_prefixed_rogue_source_and_unverified_flag_never_prune_cbf_debits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconciler source verification must use allowlist + source_verified, never an 'unverified' prefix.

    A rogue snapshot whose source_id does NOT start with 'unverified' (e.g.
    'rogue_custodian') or whose source_verified is False must fail closed,
    invalidate verified Redis state, and leave confirmed CBF debits untouched.
    """
    import time

    from src.gateway.governance.safety.debit_ledger import DebitLedger
    from src.gateway.governance.seams.ground_truth import GroundTruthSnapshot

    signer = _make_ed25519_signer(monkeypatch)
    sync_redis = fakeredis.FakeRedis(decode_responses=True)

    class _ConfigurableProvider:
        invariant_id = "finance.cash_balance"
        state_key = "safety:current_cash"
        source_id = "custodian:primary_ledger"

        def __init__(self) -> None:
            self.seq = 0
            self.snap_source = self.source_id
            self.snap_verified = True

        def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
            self.seq += 1
            now = time.time()
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=100_000.0,
                observed_at=now,
                sequence=self.seq,
                source_id=self.snap_source,
                source_verified=self.snap_verified,
                settled_through=now + 60.0,
            )

        async def fetch_snapshot(self) -> GroundTruthSnapshot:
            return self.fetch_snapshot_sync()

    provider = _ConfigurableProvider()
    reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
        settlement_clock_skew_seconds=0.0,
    )

    # Healthy tick establishes signed verified state.
    healthy = reconciler.reconcile_once("finance.cash_balance")
    assert healthy is not None
    assert read_verified_state(
        sync_redis, "finance.cash_balance", signer=signer
    ) == pytest.approx(100_000.0)

    # Seed a confirmed CBF debit that any accepted snapshot (settled_through > now) would prune.
    ledger = DebitLedger(sync_redis, namespace="finance.cash_balance")
    debit_ts = time.time() - 10.0
    sync_redis.hset(
        ledger.DEBITS_KEY,
        "deb-protect-1",
        json.dumps({"amount": 500.0, "submitted_at": debit_ts}),
    )
    sync_redis.zadd(ledger.DEBITS_BY_TIME_KEY, {"deb-protect-1": debit_ts})
    sync_redis.set(ledger.DEBITS_TOTAL_KEY, "500.0")
    assert sync_redis.hexists(ledger.DEBITS_KEY, "deb-protect-1")

    # 1. Rogue source WITHOUT 'unverified' prefix, even with source_verified=True -> rejected!
    provider.snap_source = "rogue_custodian"
    provider.snap_verified = True
    rogue_res = reconciler.reconcile("finance.cash_balance")
    assert not rogue_res.is_valid
    assert rogue_res.source_verified is False
    assert (
        rogue_res.error is not None
        and "Unverified ground-truth source" in rogue_res.error
    )
    assert (
        read_verified_state(sync_redis, "finance.cash_balance", signer=signer) is None
    )
    # Confirmed CBF debit MUST NOT have been pruned by the untrusted snapshot.
    assert sync_redis.hexists(ledger.DEBITS_KEY, "deb-protect-1")
    assert float(sync_redis.get(ledger.DEBITS_TOTAL_KEY) or 0.0) == pytest.approx(500.0)

    # 2. Matching source_id but source_verified=False -> rejected, debit preserved!
    provider.snap_source = "custodian:primary_ledger"
    provider.snap_verified = False
    unver_res = reconciler.reconcile("finance.cash_balance")
    assert not unver_res.is_valid
    assert unver_res.source_verified is False
    assert (
        read_verified_state(sync_redis, "finance.cash_balance", signer=signer) is None
    )
    assert sync_redis.hexists(ledger.DEBITS_KEY, "deb-protect-1")
    assert float(sync_redis.get(ledger.DEBITS_TOTAL_KEY) or 0.0) == pytest.approx(500.0)

    # 3. Explicit trusted_sources allowlist accepts an allowlisted secondary source and prunes.
    allowlisted_reconciler = GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        signer=signer,
        trusted_sources={"finance.cash_balance": {"custodian:secondary_ledger"}},
        settlement_clock_skew_seconds=0.0,
    )
    provider.snap_source = "custodian:secondary_ledger"
    provider.snap_verified = True
    ok_secondary = allowlisted_reconciler.reconcile_once("finance.cash_balance")
    assert ok_secondary is not None
    assert not sync_redis.hexists(ledger.DEBITS_KEY, "deb-protect-1")
    assert float(sync_redis.get(ledger.DEBITS_TOTAL_KEY) or 0.0) == pytest.approx(0.0)


def test_ground_truth_provider_without_declared_source_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A GroundTruthProvider declaring no source_id and no trusted_sources fails closed."""
    import time

    from src.gateway.governance.seams.ground_truth import GroundTruthSnapshot

    signer = _make_ed25519_signer(monkeypatch)
    sync_redis = fakeredis.FakeRedis(decode_responses=True)

    class _AnonymousProvider:
        invariant_id = "finance.cash_balance"
        state_key = "safety:current_cash"

        def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=100_000.0,
                observed_at=time.time(),
                sequence=1,
                source_id="arbitrary_unregistered_source",
                source_verified=True,
            )

        async def fetch_snapshot(self) -> GroundTruthSnapshot:
            return self.fetch_snapshot_sync()

    reconciler = GroundTruthReconciler(
        provider=_AnonymousProvider(),
        redis_client=sync_redis,
        signer=signer,
    )
    res = reconciler.reconcile("finance.cash_balance")
    assert not res.is_valid
    assert res.source_verified is False
    assert (
        read_verified_state(sync_redis, "finance.cash_balance", signer=signer) is None
    )
