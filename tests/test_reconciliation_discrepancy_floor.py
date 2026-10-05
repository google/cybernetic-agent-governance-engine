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

"""Discrepancy guard: ratio + absolute floor (POAM-2026-087, ADR-010 §6).

Before this change the reconciler refused any snapshot whose delta exceeded
``0.5 * |baseline|`` and fell back to ``100.0`` only when the baseline was
falsy. A balance of 10 could therefore not move by 6. The guard is now
``max(ratio * |baseline|, abs_floor)`` with both terms owned by
``config/governance_thresholds.json`` (``reconciliation.*``).

Every fail-closed path below is observed *failing*: the discrepancy flag,
the fence-epoch bump, the deleted verified state and the strict CBF refusal.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest

import src.gateway.governance.schemas.thresholds as thresholds_module
from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.reconciliation.daemon import (
    FENCE_EPOCH_KEY,
    GroundTruthReconciler,
    read_verified_state,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.schemas.thresholds import (
    ReconciliationThresholds,
    load_and_validate_thresholds,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

INVARIANT_ID = CashBarrier.invariant_id
STATE_KEY = CashBarrier.state_key


def _signer(monkeypatch: pytest.MonkeyPatch) -> KMSGovernanceSigner:
    monkeypatch.setenv("CAGE_ENV", "development")
    return KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="discrepancy-floor-ed25519-k1")
    )


def _reconciler(
    *,
    baseline: float,
    snapshot: float,
    redis: fakeredis.FakeRedis,
    signer: KMSGovernanceSigner,
    **kwargs: float | None,
) -> GroundTruthReconciler:
    """Seed ``baseline`` as the self-reported balance and make the custodian report ``snapshot``."""
    redis.set(STATE_KEY, str(baseline))
    redis.set(FENCE_EPOCH_KEY, "0")
    provider = SimulatedCashLedgerProvider(
        initial_scalar=snapshot, barrier_floor=0.0, seed=42
    )
    return GroundTruthReconciler(
        provider=provider, redis_client=redis, signer=signer, **kwargs
    )


# ---------------------------------------------------------------------------
# Defaults from config: ratio 0.5, floor 100.0
# ---------------------------------------------------------------------------


def test_defaults_come_from_governance_thresholds() -> None:
    recon = thresholds_module.THRESHOLDS.reconciliation
    assert isinstance(recon, ReconciliationThresholds)
    assert recon.discrepancy_ratio == pytest.approx(0.5)
    assert recon.discrepancy_abs_floor == pytest.approx(100.0)
    assert thresholds_module.THRESHOLDS.resolve(
        "reconciliation.discrepancy_abs_floor"
    ) == pytest.approx(100.0)


def test_small_balance_change_within_floor_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """baseline 10 -> snapshot 16: delta 6 exceeds 0.5*10 but is under the 100 floor."""
    signer = _signer(monkeypatch)
    redis = fakeredis.FakeRedis(decode_responses=True)
    reconciler = _reconciler(baseline=10.0, snapshot=16.0, redis=redis, signer=signer)

    res = reconciler.reconcile_once(INVARIANT_ID)

    assert res is not None and res.is_valid
    assert res.discrepancy_detected is False
    assert res.signature != ""
    assert read_verified_state(redis, INVARIANT_ID, signer=signer) == pytest.approx(
        16.0
    )
    assert redis.get(FENCE_EPOCH_KEY) == "0"


def test_zero_baseline_uses_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a zero baseline the ratio term is 0, so the floor alone decides."""
    signer = _signer(monkeypatch)
    redis = fakeredis.FakeRedis(decode_responses=True)

    ok = _reconciler(baseline=0.0, snapshot=99.0, redis=redis, signer=signer)
    assert ok.reconcile_once(INVARIANT_ID) is not None

    redis.flushall()
    bad = _reconciler(baseline=0.0, snapshot=101.0, redis=redis, signer=signer)
    result = bad.reconcile(invariant_id=INVARIANT_ID)
    assert result.discrepancy_detected is True
    assert result.discrepancy_delta == pytest.approx(101.0)


# ---------------------------------------------------------------------------
# Fail-closed: above both the ratio and the floor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delta_above_floor_and_ratio_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """baseline 1000 -> snapshot 400: delta 600 > max(500, 100). Everything downstream must refuse."""
    signer = _signer(monkeypatch)
    server = fakeredis.FakeServer()
    redis = fakeredis.FakeRedis(server=server, decode_responses=True)
    async_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    # A healthy tick first, so the guard has verified state to invalidate.
    healthy = _reconciler(baseline=1000.0, snapshot=1000.0, redis=redis, signer=signer)
    assert healthy.reconcile_once(INVARIANT_ID) is not None
    assert read_verified_state(redis, INVARIANT_ID, signer=signer) is not None
    epoch_before = int(redis.get(FENCE_EPOCH_KEY))

    bad = _reconciler(baseline=1000.0, snapshot=400.0, redis=redis, signer=signer)
    # _reconciler re-seeds the epoch to 0; restore the live value so the bump is observable.
    redis.set(FENCE_EPOCH_KEY, str(epoch_before))
    result = bad.reconcile(invariant_id=INVARIANT_ID)

    assert result.is_valid is False
    assert result.discrepancy_detected is True
    assert result.discrepancy_delta == pytest.approx(600.0)
    assert "Discrepancy spike detected" in (result.error or "")
    assert "threshold=500.00" in (result.error or "")
    assert bad.failure_count == 1
    assert int(redis.get(FENCE_EPOCH_KEY)) == epoch_before + 1
    assert read_verified_state(redis, INVARIANT_ID, signer=signer) is None

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    mock_redis_mod = MagicMock()
    mock_redis_mod.get_raw_client = MagicMock(return_value=async_redis)
    mock_redis_mod.get = async_redis.get
    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod),
        patch("src.gateway.governance.safety.cbf_engine.sync_redis_client", redis),
        patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
    ):
        committed, reason, _ = await cbf.atomic_verify_and_commit(
            "execute_trade", {"amount": 1.0}
        )
    assert committed is False
    assert "RECONCILIATION_UNAVAILABLE" in reason


def test_explicit_absolute_threshold_still_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A constructor ``discrepancy_threshold`` bypasses ratio and floor entirely."""
    signer = _signer(monkeypatch)
    redis = fakeredis.FakeRedis(decode_responses=True)
    reconciler = _reconciler(
        baseline=10.0,
        snapshot=16.0,
        redis=redis,
        signer=signer,
        discrepancy_threshold=5.0,
    )
    result = reconciler.reconcile(invariant_id=INVARIANT_ID)
    assert result.discrepancy_detected is True
    assert "threshold=5.00" in (result.error or "")


def test_floor_violation_never_writes_cbf_state_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A snapshot below the barrier floor fails closed without touching the state key.

    The reconciler writes only snapshot keys. Overwriting ``STATE_KEY`` would
    bypass the gateway's Lua CAS and re-anchor the discrepancy baseline to the
    custodian's own value, so the next cycle's band check could never trip.
    """
    signer = _signer(monkeypatch)
    redis = fakeredis.FakeRedis(decode_responses=True)
    redis.set(STATE_KEY, "1000.0")
    redis.set(FENCE_EPOCH_KEY, "0")
    provider = SimulatedCashLedgerProvider(
        initial_scalar=400.0, barrier_floor=500.0, seed=42
    )
    reconciler = GroundTruthReconciler(
        provider=provider, redis_client=redis, signer=signer
    )

    result = reconciler.reconcile(invariant_id=INVARIANT_ID)

    assert result.is_valid is False
    assert "below barrier floor" in (result.error or "")
    assert redis.get(STATE_KEY) == "1000.0"
    assert int(redis.get(FENCE_EPOCH_KEY)) == 1
    assert read_verified_state(redis, INVARIANT_ID, signer=signer) is None

    # With the floor lifted, the untouched baseline still lets the band trip:
    # delta 600 > max(0.5 * 1000, 100).
    follow_up = GroundTruthReconciler(
        provider=SimulatedCashLedgerProvider(
            initial_scalar=400.0, barrier_floor=0.0, seed=42
        ),
        redis_client=redis,
        signer=signer,
    ).reconcile(invariant_id=INVARIANT_ID)
    assert follow_up.discrepancy_detected is True


def test_constructor_floor_overrides_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinning ``discrepancy_abs_floor=0.0`` restores the ratio-only behaviour (and it refuses)."""
    signer = _signer(monkeypatch)
    redis = fakeredis.FakeRedis(decode_responses=True)
    reconciler = _reconciler(
        baseline=10.0,
        snapshot=16.0,
        redis=redis,
        signer=signer,
        discrepancy_abs_floor=0.0,
    )
    result = reconciler.reconcile(invariant_id=INVARIANT_ID)
    assert result.discrepancy_detected is True
    assert read_verified_state(redis, INVARIANT_ID, signer=signer) is None


# ---------------------------------------------------------------------------
# Env override -> reloaded singleton -> daemon
# ---------------------------------------------------------------------------


def test_env_override_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    """RECONCILIATION_DISCREPANCY_ABS_FLOOR=0 flows through the loader into the daemon."""
    monkeypatch.setenv("RECONCILIATION_DISCREPANCY_ABS_FLOOR", "0")
    monkeypatch.setenv("RECONCILIATION_DISCREPANCY_RATIO", "0.25")
    load_and_validate_thresholds.cache_clear()
    try:
        reloaded = load_and_validate_thresholds()
        assert reloaded.reconciliation.discrepancy_abs_floor == pytest.approx(0.0)
        assert reloaded.reconciliation.discrepancy_ratio == pytest.approx(0.25)
        monkeypatch.setattr(thresholds_module, "THRESHOLDS", reloaded)

        signer = _signer(monkeypatch)
        redis = fakeredis.FakeRedis(decode_responses=True)
        # baseline 100 -> snapshot 70: delta 30 > max(0.25*100, 0) = 25 -> refused.
        reconciler = _reconciler(
            baseline=100.0, snapshot=70.0, redis=redis, signer=signer
        )
        assert reconciler._discrepancy_ratio == pytest.approx(0.25)
        assert reconciler._discrepancy_abs_floor == pytest.approx(0.0)
        result = reconciler.reconcile(invariant_id=INVARIANT_ID)
        assert result.discrepancy_detected is True
        assert "threshold=25.00" in (result.error or "")
    finally:
        # Never leak the overridden singleton into other modules' tests.
        load_and_validate_thresholds.cache_clear()
        monkeypatch.delenv("RECONCILIATION_DISCREPANCY_ABS_FLOOR", raising=False)
        monkeypatch.delenv("RECONCILIATION_DISCREPANCY_RATIO", raising=False)
        load_and_validate_thresholds()
