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

"""Causal world-model phase 2: the placebo refutation must be able to fail.

dowhy's default placebo for a float treatment is drawn from N(0, 0), so every
simulated effect is exactly 0.0. dowhy's normal test (< 100 simulations) then
returns a NaN p-value, and its bootstrap test (>= 100 simulations) a finite
p = 1.0. The gatekeeper used that default and read a missing or NaN p-value
as a pass, so phase 2 could never return an untrusted verdict.

These tests pin the three guards: a permutation placebo; fail-closed handling
of missing or non-finite results; and refusal when the simulated effects have
zero spread, which is the case a NaN check alone misses at >= 100
simulations. The degenerate tests drive the real dowhy 0.14 refuter code, so
a future dowhy change to that behaviour shows up here.
"""

from __future__ import annotations

import math
import time
from typing import Any
from unittest.mock import AsyncMock

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("networkx", reason="networkx required by the causal gatekeeper")

from src.cage_finance.causal.synthetic_telemetry import generate_mock_telemetry
from src.cage_finance.tiers.causal_tier import (
    CODE_CHECK_FAILED,
    CausalTierPlugin,
    build_finance_causal_gatekeeper,
)
from src.gateway.governance.causal import gatekeeper as gk_mod
from src.gateway.governance.causal.gatekeeper import (
    REASON_DESIGN_ILL_CONDITIONED,
    REASON_PLACEBO_DEGENERATE,
    REASON_PLACEBO_EFFECT_MAGNITUDE,
    REASON_PLACEBO_P_VALUE,
    REASON_PLACEBO_RESULT_INVALID,
    REASON_TRUSTED,
    PlaceboRefutation,
    WorldModelVerdict,
    _placebo_lock_reason,
)
from src.gateway.governance.consensus.engine import extract_field_magnitude
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.errors import GovernanceError
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

requires_dowhy = pytest.mark.skipif(
    not gk_mod._DOWHY_AVAILABLE, reason="dowhy not installed"
)

BETA = 0.49  # a trusted finance-scale slope (risk per $10,000 of trade amount)
HEALTHY_EFFECTS = (-0.02, -0.01, 0.0, 0.01, 0.02)  # mean 0.0, spread 0.04


def _healthy(**overrides: Any) -> PlaceboRefutation:
    fields: dict[str, Any] = {
        "p_value": 0.45,
        "new_effect": float(np.mean(HEALTHY_EFFECTS)),
        "effects": HEALTHY_EFFECTS,
    }
    fields.update(overrides)
    return PlaceboRefutation(**fields)


def _validate(telemetry: pd.DataFrame) -> WorldModelVerdict:
    return build_finance_causal_gatekeeper()._validate_world_model(telemetry)


@pytest.fixture
def recorded_placebo(monkeypatch: pytest.MonkeyPatch) -> list[PlaceboRefutation]:
    """Record every real PlaceboRefutation that validate_world_model computes."""
    seen: list[PlaceboRefutation] = []
    real = gk_mod._placebo_refutation

    def _recording(*args: Any, **kwargs: Any) -> PlaceboRefutation:
        result = real(*args, **kwargs)
        seen.append(result)
        return result

    monkeypatch.setattr(gk_mod, "_placebo_refutation", _recording)
    return seen


# ---------------------------------------------------------------------------
# Guard 3: zero spread (the degenerate case), against the real dowhy refuter
# ---------------------------------------------------------------------------


@requires_dowhy
@pytest.mark.parametrize(
    ("num_simulations", "dowhy_p_value"),
    [
        (50, "nan"),  # normal test: (0 - 0) / 0
        (100, 1.0),  # bootstrap test: a clean pass that no NaN check can see
    ],
)
def test_degenerate_default_placebo_is_refused_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
    recorded_placebo: list[PlaceboRefutation],
    num_simulations: int,
    dowhy_p_value: Any,
) -> None:
    """Feed dowhy's degenerate default placebo through phase 2: it must refuse."""
    monkeypatch.setattr(gk_mod, "PLACEBO_TYPE", "Random Data")  # dowhy's default
    monkeypatch.setattr(gk_mod, "PLACEBO_NUM_SIMULATIONS", num_simulations)

    verdict = _validate(generate_mock_telemetry())

    (placebo,) = recorded_placebo
    # What dowhy 0.14 actually returns for the default float placebo.
    assert len(placebo.effects) == num_simulations
    assert set(placebo.effects) == {0.0}
    if dowhy_p_value == "nan":
        assert placebo.p_value is not None and math.isnan(placebo.p_value)
    else:
        assert placebo.p_value == dowhy_p_value
    assert placebo.new_effect == 0.0
    # The verdict the shipped code returned for this result was trusted.
    assert verdict.trusted is False
    assert verdict.reason == REASON_PLACEBO_DEGENERATE


@requires_dowhy
@pytest.mark.parametrize("amount", [0.0, 5_000.0, 2.5e9])
def test_constant_treatment_is_refused_before_the_fit(amount: float) -> None:
    """A constant treatment makes the regression rank-deficient; phase 1 refuses it.

    The slope fitted to a rank-deficient design is rounding noise. For the
    $5,000 frame it was +0.10 on macOS arm64 and -6.5e11 on Linux x86_64, so
    which later guard refused the frame depended on the platform. The design
    is now refused before it is fitted, with the same verdict everywhere.
    """
    telemetry = generate_mock_telemetry()
    telemetry["trade_amount"] = amount
    assert _validate(telemetry) == WorldModelVerdict(
        False, None, REASON_DESIGN_ILL_CONDITIONED
    )


@requires_dowhy
def test_treatment_collinear_with_a_covariate_is_refused_before_the_fit() -> None:
    """Rank deficiency through the adjustment set, not the intercept, is refused too."""
    telemetry = generate_mock_telemetry()
    telemetry["trade_amount"] = telemetry["market_volatility"] * 20_000.0
    assert _validate(telemetry) == WorldModelVerdict(
        False, None, REASON_DESIGN_ILL_CONDITIONED
    )


def _error_bound(telemetry: pd.DataFrame) -> float:
    frame = telemetry.copy()
    frame["trade_amount"] = frame["trade_amount"] / gk_mod.CAUSAL_NORMALIZATION_SCALE
    return gk_mod._least_squares_error_bound(
        frame, "trade_amount", "risk_score", ["market_volatility"]
    )


def test_tolerance_separates_sound_fits_from_near_degenerate_ones() -> None:
    """The tolerance sits between numerically sound fits and near-degenerate ones.

    Amounts with a $1 spread around $5,000 fit accurately (a bound near 1e-8):
    whether to trust them is phase 2's statistical question, and phase 2
    refuses them (``test_working_refuter_locks_on_near_constant_trade_amounts``).
    Amounts recorded to the cent around $5,000 are not exactly constant, but
    rounding alone could move their coefficients by more than the tolerance.
    """
    limit = gk_mod._LSQ_ERROR_BOUND_MAX
    assert _error_bound(generate_mock_telemetry()) < limit * 1e-6
    assert _error_bound(_near_constant_amount_telemetry(0)) < limit / 50
    to_the_cent = generate_mock_telemetry()
    rng = np.random.default_rng(2)
    to_the_cent["trade_amount"] = 5_000.0 + rng.normal(
        0.0, 0.01, len(to_the_cent)
    ).round(2)
    assert _error_bound(to_the_cent) > limit * 10


def test_error_bound_of_an_exact_perfectly_conditioned_fit_is_two_eps() -> None:
    """Pins the bound's formula: kappa = 1 and theta = 0 leave eps * 2."""
    frame = pd.DataFrame({"t": [1.0, -1.0] * 4, "y": [5.0, 1.0] * 4})  # y = 3 + 2t
    assert gk_mod._least_squares_error_bound(frame, "t", "y", []) == pytest.approx(
        2 * np.finfo(np.float64).eps
    )


@pytest.mark.parametrize("column", ["t", "v", "y"])
def test_error_bound_fails_closed_on_a_non_finite_value(column: str) -> None:
    frame = pd.DataFrame(
        {
            "t": [0.1, 0.4, 0.2, 0.8, 0.5],
            "v": [0.3, 0.1, 0.9, 0.2, 0.6],
            "y": [0.2, 0.5, 0.4, 0.9, 0.6],
        }
    )
    frame.loc[2, column] = math.nan
    assert gk_mod._least_squares_error_bound(frame, "t", "y", ["v"]) == math.inf


@pytest.mark.parametrize(
    "effects",
    [
        pytest.param((0.0,) * 50, id="all-zero"),
        pytest.param((0.3,) * 50, id="constant-nonzero"),
        pytest.param(tuple(1e-18 * (-1) ** i for i in range(50)), id="float-noise"),
    ],
)
@pytest.mark.parametrize("p_value", [1.0, 0.45, 0.0])
def test_zero_spread_is_refused_whatever_the_p_value(
    effects: tuple[float, ...], p_value: float
) -> None:
    placebo = PlaceboRefutation(
        p_value=p_value, new_effect=float(np.mean(effects)), effects=effects
    )
    assert _placebo_lock_reason(placebo, BETA) == REASON_PLACEBO_DEGENERATE


def test_healthy_spread_is_not_degenerate() -> None:
    assert _placebo_lock_reason(_healthy(), BETA) is None


# ---------------------------------------------------------------------------
# Guard 2: missing or non-finite results fail closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placebo",
    [
        pytest.param(_healthy(effects=()), id="no-effects"),
        pytest.param(_healthy(effects=(0.01,)), id="one-effect"),
        pytest.param(_healthy(effects=(*HEALTHY_EFFECTS, math.nan)), id="effect-nan"),
        pytest.param(_healthy(effects=(*HEALTHY_EFFECTS, math.inf)), id="effect-inf"),
        pytest.param(
            _healthy(effects=(*HEALTHY_EFFECTS, -math.inf)), id="effect-neg-inf"
        ),
        pytest.param(_healthy(p_value=None), id="p-missing"),
        pytest.param(_healthy(p_value=math.nan), id="p-nan"),
        pytest.param(_healthy(p_value=math.inf), id="p-inf"),
        pytest.param(_healthy(p_value=-math.inf), id="p-neg-inf"),
        pytest.param(_healthy(new_effect=None), id="effect-mean-missing"),
        pytest.param(_healthy(new_effect=math.nan), id="effect-mean-nan"),
        pytest.param(_healthy(new_effect=math.inf), id="effect-mean-inf"),
        pytest.param(_healthy(new_effect=-math.inf), id="effect-mean-neg-inf"),
    ],
)
def test_missing_or_non_finite_result_fails_closed(placebo: PlaceboRefutation) -> None:
    assert _placebo_lock_reason(placebo, BETA) == REASON_PLACEBO_RESULT_INVALID


@requires_dowhy
@pytest.mark.parametrize(
    "placebo",
    [
        pytest.param(_healthy(p_value=None), id="p-missing"),
        pytest.param(_healthy(p_value=math.nan), id="p-nan"),
        pytest.param(_healthy(new_effect=math.inf), id="effect-mean-inf"),
    ],
)
def test_validate_world_model_returns_untrusted_on_invalid_result(
    monkeypatch: pytest.MonkeyPatch, placebo: PlaceboRefutation
) -> None:
    """The verdict path, not only the helper, refuses a missing/non-finite result."""
    monkeypatch.setattr(gk_mod, "_placebo_refutation", lambda *_a, **_k: placebo)
    verdict = _validate(generate_mock_telemetry())
    assert verdict.trusted is False
    assert verdict.reason == REASON_PLACEBO_RESULT_INVALID


# ---------------------------------------------------------------------------
# Guard 1: the placebo is a permutation of the treatment
# ---------------------------------------------------------------------------


@requires_dowhy
def test_placebo_is_a_permutation_and_healthy_data_stays_trusted(
    monkeypatch: pytest.MonkeyPatch, recorded_placebo: list[PlaceboRefutation]
) -> None:
    from dowhy.causal_refuters import placebo_treatment_refuter as ptr

    placebo_types: list[Any] = []
    real_refute_once = ptr._refute_once

    def _spy(*args: Any, **kwargs: Any) -> Any:
        placebo_types.append(kwargs.get("placebo_type"))
        return real_refute_once(*args, **kwargs)

    monkeypatch.setattr(ptr, "_refute_once", _spy)

    verdict = _validate(generate_mock_telemetry())

    assert placebo_types == [ptr.PlaceboType.PERMUTE] * gk_mod.PLACEBO_NUM_SIMULATIONS
    (placebo,) = recorded_placebo
    assert max(placebo.effects) - min(placebo.effects) > 0.0
    assert placebo.p_value is not None and math.isfinite(placebo.p_value)
    assert verdict == WorldModelVerdict(True, verdict.beta, REASON_TRUSTED)


# ---------------------------------------------------------------------------
# Lock direction (unchanged): p < 0.05 means the refutation failed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"p_value": 0.049}, REASON_PLACEBO_P_VALUE),
        ({"p_value": 0.0}, REASON_PLACEBO_P_VALUE),
        ({"p_value": 0.05}, None),  # not below the threshold
        ({"p_value": 0.96}, None),
        ({"new_effect": 0.21}, REASON_PLACEBO_EFFECT_MAGNITUDE),
        ({"new_effect": -0.21}, REASON_PLACEBO_EFFECT_MAGNITUDE),
        ({"new_effect": 0.19}, None),
    ],
)
def test_lock_direction(overrides: dict[str, float], reason: str | None) -> None:
    assert gk_mod.CAUSAL_LOCK_P_VALUE_THRESHOLD == 0.05
    assert gk_mod.CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE == 0.2
    assert _placebo_lock_reason(_healthy(**overrides), BETA) == reason


def _near_constant_amount_telemetry(seed: int) -> pd.DataFrame:
    """400 rows whose trade amounts barely vary (sd $1 around $5,000)."""
    rng = np.random.default_rng(seed)
    n = 400
    vol = rng.uniform(0.1, 0.9, n)
    amount = 5_000.0 + rng.normal(0.0, 1.0, n)
    risk = 0.5 * vol + 0.02 * (amount - 5_000.0) + rng.normal(0.0, 0.05, n)
    return pd.DataFrame(
        {
            "market_volatility": vol,
            "trade_amount": amount,
            "risk_score": risk,
            "timestamp": time.time() - rng.uniform(0, 60, n),
        }
    )


def _validate_seeded(telemetry: pd.DataFrame, rng_seed: int) -> WorldModelVerdict:
    """``_validate`` with numpy's global RNG seeded, leaving its state as found.

    dowhy's permutation placebo draws from numpy's global RNG (the gatekeeper
    passes ``_refute_once`` no ``random_state``), so without a seed a verdict
    on borderline data depends on whatever ran before it in the process.
    """
    saved = np.random.get_state()
    try:
        np.random.seed(rng_seed)
        return _validate(telemetry)
    finally:
        np.random.set_state(saved)


#: Fixed test vector: case ``k`` seeds the global RNG with this plus ``k``.
#: Under it all ten cases lock, each with the mean placebo effect at least 1.59x
#: the 0.2 magnitude threshold, so no case sits near the decision boundary.
#: The vectors seed=k and seed=1000+k lock 9 and 8 of 10: the lock is likely,
#: not certain, on this data, and the rate is pinned by the slow sweep below.
_LOCK_VECTOR_SEED = 20_261_026


@requires_dowhy
def test_working_refuter_locks_on_near_constant_trade_amounts() -> None:
    """Non-vacuity: phase 2 can refuse a world-model it cannot trust.

    Trade amounts that barely vary make the slope and every placebo effect
    large and noisy, so the placebo-magnitude lock fires. Deterministic: each
    case seeds numpy's global RNG from ``_LOCK_VECTOR_SEED``.
    """
    reasons = []
    for seed in range(10):
        verdict = _validate_seeded(
            _near_constant_amount_telemetry(seed), _LOCK_VECTOR_SEED + seed
        )
        assert verdict.trusted is False, (seed, verdict)
        reasons.append(verdict.reason)
    assert reasons == [REASON_PLACEBO_EFFECT_MAGNITUDE] * 10, reasons


@pytest.mark.slow
@pytest.mark.timeout(600)
@requires_dowhy
def test_working_refuter_lock_rate_over_a_seed_sweep() -> None:
    """Distribution coverage for the lock: a fixed 10 x 10 grid of data and RNG seeds.

    Deterministic (every case is seeded); slower than the test above (100
    refutations). Measured with dowhy 0.14 on this grid: 93 of 100 cases lock,
    8 to 10 per data seed, all by the magnitude lock. No case falls between
    0.84x and 1.6x of the threshold, so platform-level numeric noise cannot
    flip one. The floors below leave room for that, and catch a refuter that
    stops locking.

    The work is fixed, so its duration measures the runner: 14 s on an Apple
    M-series laptop, 62 s on a CI runner, and over the suite's 120 s timeout on
    a runner 1.8x slower, where the timeout killed the xdist worker. 600 s
    leaves room for slow runners and still catches a hang.
    """
    locked_per_data_seed: dict[int, int] = {}
    reasons: set[str] = set()
    for data_seed in range(10):
        telemetry = _near_constant_amount_telemetry(data_seed)
        locked = 0
        for rng_seed in range(10):
            verdict = _validate_seeded(telemetry, rng_seed)
            if not verdict.trusted:
                locked += 1
                reasons.add(verdict.reason)
        locked_per_data_seed[data_seed] = locked
    assert sum(locked_per_data_seed.values()) >= 90, locked_per_data_seed
    assert min(locked_per_data_seed.values()) >= 7, locked_per_data_seed
    assert reasons == {REASON_PLACEBO_EFFECT_MAGNITUDE}, reasons


# ---------------------------------------------------------------------------
# Admission and evidence: an untrusted placebo verdict is a DENY
# ---------------------------------------------------------------------------


class _TraceRecorder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)


@requires_dowhy
@pytest.mark.asyncio
async def test_degenerate_placebo_denies_trade_and_records_causal_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gk_mod, "PLACEBO_TYPE", "Random Data")  # dowhy's default
    recorder = _TraceRecorder()
    monkeypatch.setattr(governor_module, "publish_trace", recorder.publish)
    monkeypatch.setattr(verdicts_module, "publish_refusal", AsyncMock())

    gatekeeper = build_finance_causal_gatekeeper()
    tier = CausalTierPlugin(causal_gatekeeper=gatekeeper)
    assert tier.refresher is not None
    verdict = gatekeeper._validate_world_model(generate_mock_telemetry())
    assert verdict.reason == REASON_PLACEBO_DEGENERATE
    tier.refresher.seed_snapshot(verdict, telemetry_watermark=time.time())

    (violation,) = await tier.evaluate("execute_trade", {"amount": 1.0})
    assert violation.kind is ViolationKind.HARD
    assert violation.code == CODE_CHECK_FAILED

    governor = make_governor(
        domain_tiers=(tier,), magnitude_extractor=extract_field_magnitude("amount")
    )
    with pytest.raises(GovernanceError):
        await governor.validate_action(
            "execute_trade", {"amount": 1.0, "symbol": "AAPL", "confidence": 0.99}
        )
    (event,) = recorder.events
    assert event["verdict"] == "DENY"
    assert ["causal", "FAIL"] in event["outcomes"]
    assert [o for o in event["outcomes"] if o[1] == "FAIL"] == [["causal", "FAIL"]]
