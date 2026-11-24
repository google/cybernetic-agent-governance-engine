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

"""Causal marginal risk boundary: beta's units and where the boundary trips.

The documented rule is ``beta * amount / scale > CAUSAL_LOCK_RISK_BOUNDARY``
(``0.45``, with no hardcoded ``0.5`` intercept under ``POAM-2026-117``).
``validate_world_model`` divides the treatment column by
``CausalSpec.normalization_scale`` before fitting, so beta is per normalised
unit ($10,000 of trade amount for finance) and the boundary divides by the same
scale: the scale cancels. On the finance synthetic telemetry the boundary
re-derives the same $9,143.93 trip point (``0.45 * 10_000 / 0.4921298``).

Previously beta was fitted per dollar and then divided by the scale again, so
the boundary tripped 10,000x too high (about $91.4M). Every earlier test
hard-coded beta and passed either way; these run the real estimator.
"""

from __future__ import annotations

import dataclasses
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
    build_finance_causal_spec,
)
from src.gateway.governance.causal import gatekeeper as gk_mod
from src.gateway.governance.causal.gatekeeper import (
    REASON_DESIGN_ILL_CONDITIONED,
    REASON_TRUSTED,
    CausalGatekeeper,
    _marginal_risk,
    _spec_fingerprint,
)
from src.gateway.governance.causal.world_model_refresher import WorldModelRefresher
from src.gateway.governance.consensus.engine import extract_field_magnitude
from src.gateway.governance.contracts import CausalSpec, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.telemetry_provider import BaseTelemetryProvider
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

requires_dowhy = pytest.mark.skipif(
    not gk_mod._DOWHY_AVAILABLE, reason="dowhy not installed"
)

# 0.45 / beta on the finance synthetic telemetry (beta = 4.921298e-05 per dollar).
SYNTHETIC_TRIP_USD = 9_143.93


def _gatekeeper(scale: float | None = None) -> CausalGatekeeper:
    spec = build_finance_causal_spec()
    if scale is not None:
        spec = dataclasses.replace(spec, normalization_scale=scale)
    return CausalGatekeeper(spec)


def _trip_point(gatekeeper: CausalGatekeeper, beta: float) -> float:
    """Treatment value at which beta * x / scale reaches CAUSAL_LOCK_RISK_BOUNDARY (0.45)."""
    return gk_mod.CAUSAL_LOCK_RISK_BOUNDARY * gatekeeper.spec.normalization_scale / beta


@requires_dowhy
def test_real_estimator_trips_at_the_documented_point() -> None:
    gatekeeper = _gatekeeper()
    verdict = gatekeeper._validate_world_model(generate_mock_telemetry())

    assert verdict.trusted, verdict
    assert verdict.beta == pytest.approx(0.49213, abs=1e-4)  # risk per $10,000
    assert _trip_point(gatekeeper, verdict.beta) == pytest.approx(
        SYNTHETIC_TRIP_USD, abs=0.01
    )
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_000.0) is True
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_143.0) is True
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_145.0) is False
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_500.0) is False


@requires_dowhy
def test_poam_2026_117_20261027_rng_frame_bounds_causal_effect_without_intercept() -> (
    None
):
    """Reproduce the exact POAM-2026-117 seed-20261027 frame and verify zero 0.5 intercept."""
    rng = np.random.default_rng(20261027)
    n = 600
    volatility = rng.uniform(0.1, 0.9, n)
    amount = np.clip(rng.normal(5_000, 1_500, n) - 2_000 * volatility, 100, 10_000)
    noise = rng.normal(0, 0.05, n)
    risk = 0.05 + 0.8 * volatility + 0.2 * amount / 10_000.0 + noise
    frame = pd.DataFrame(
        {
            "market_volatility": volatility,
            "trade_amount": amount,
            "risk_score": risk,
            "timestamp": np.full(n, time.time()),
        }
    )

    gatekeeper = _gatekeeper()
    verdict = gatekeeper._validate_world_model(frame)
    assert verdict.trusted, verdict
    assert verdict.beta == pytest.approx(0.1764373, abs=1e-5)

    # Zero treatment must yield zero causal risk contribution (fails at 0.5 before fix).
    assert _marginal_risk(verdict.beta, 0.0, gatekeeper.spec.normalization_scale) == 0.0
    # Marginal effect is strictly linear beta * amount / scale (no +0.5 offset).
    assert _marginal_risk(
        verdict.beta, 10_000.0, gatekeeper.spec.normalization_scale
    ) == pytest.approx(verdict.beta, rel=1e-12)
    assert _marginal_risk(
        verdict.beta, 9_619.17, gatekeeper.spec.normalization_scale
    ) == pytest.approx(verdict.beta * 9_619.17 / 10_000.0, rel=1e-12)
    assert gk_mod.CAUSAL_LOCK_RISK_BOUNDARY == pytest.approx(0.45)
    assert _trip_point(gatekeeper, verdict.beta) == pytest.approx(25_504.81, abs=0.05)


@requires_dowhy
@pytest.mark.parametrize("scale", [1.0, 200.0, 10_000.0])
def test_trip_point_does_not_depend_on_normalization_scale(scale: float) -> None:
    gatekeeper = _gatekeeper(scale)
    verdict = gatekeeper._validate_world_model(generate_mock_telemetry())

    assert verdict.trusted, verdict
    assert verdict.beta == pytest.approx(4.9213e-05 * scale, rel=1e-4)
    assert _trip_point(gatekeeper, verdict.beta) == pytest.approx(
        SYNTHETIC_TRIP_USD, abs=0.01
    )
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_000.0) is True
    assert gatekeeper._within_risk_boundary(verdict.beta, 9_500.0) is False


@requires_dowhy
def test_trip_point_scales_with_the_treatment_unit() -> None:
    """Amounts recorded in cents instead of dollars move the trip point 100x."""
    telemetry = generate_mock_telemetry()
    telemetry["trade_amount"] = telemetry["trade_amount"] * 100.0
    gatekeeper = _gatekeeper()
    verdict = gatekeeper._validate_world_model(telemetry)

    assert verdict.trusted, verdict
    assert _trip_point(gatekeeper, verdict.beta) == pytest.approx(
        SYNTHETIC_TRIP_USD * 100.0, rel=1e-6
    )
    assert gatekeeper._within_risk_boundary(verdict.beta, 900_000.0) is True
    assert gatekeeper._within_risk_boundary(verdict.beta, 950_000.0) is False


def _seeded_tier() -> CausalTierPlugin:
    gatekeeper = build_finance_causal_gatekeeper()
    tier = CausalTierPlugin(causal_gatekeeper=gatekeeper)
    assert tier.refresher is not None
    verdict = gatekeeper._validate_world_model(generate_mock_telemetry())
    assert verdict.reason == REASON_TRUSTED
    tier.refresher.seed_snapshot(verdict, telemetry_watermark=time.time())
    return tier


@requires_dowhy
@pytest.mark.asyncio
async def test_finance_tier_refuses_9500_and_admits_9000() -> None:
    tier = _seeded_tier()

    assert await tier.evaluate("execute_trade", {"amount": 9_000.0}) == []
    (violation,) = await tier.evaluate("execute_trade", {"amount": 9_500.0})
    assert violation.kind is ViolationKind.HARD
    assert violation.code == CODE_CHECK_FAILED


class _TraceRecorder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)


@requires_dowhy
@pytest.mark.asyncio
async def test_dry_run_denies_9500_trade_with_causal_fail_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DRY_RUN of a $9,500 execute_trade through the real causal tier: DENY.

    FTRA uses the finance plugin's magnitude extractor, so both amounts are
    inside its $10,000 autonomous envelope. OPA is a permissive mock, standing
    in for the senior RBAC ALLOW that applies up to $500,000. The causal tier
    alone separates the two amounts.
    """
    recorder = _TraceRecorder()
    monkeypatch.setattr(governor_module, "publish_trace", recorder.publish)
    monkeypatch.setattr(verdicts_module, "publish_refusal", AsyncMock())
    governor = make_governor(
        domain_tiers=(_seeded_tier(),),
        magnitude_extractor=extract_field_magnitude("amount"),
    )
    params = {"symbol": "AAPL", "confidence": 0.99}

    allowed = await governor.validate_action(
        "execute_trade", {**params, "amount": 9_000.0}
    )
    assert allowed["verdict"] == GovernanceDecision.ALLOW
    with pytest.raises(GovernanceError):
        await governor.validate_action("execute_trade", {**params, "amount": 9_500.0})

    allow_event, deny_event = recorder.events
    assert ["causal", "PASS"] in allow_event["outcomes"]
    assert deny_event["verdict"] == GovernanceDecision.DENY.value
    assert ["causal", "FAIL"] in deny_event["outcomes"]


# ---------------------------------------------------------------------------
# Both world-model call sites normalise (the process-pool path is production)
# ---------------------------------------------------------------------------


class _FrameProvider(BaseTelemetryProvider):
    def __init__(self, frame: pd.DataFrame) -> None:
        self._frame = frame

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        return self._frame


def _constant_treatment() -> pd.DataFrame:
    frame = generate_mock_telemetry()
    frame["trade_amount"] = 5_000.0
    return frame


@requires_dowhy
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("frame_factory", "reason"),
    [
        (generate_mock_telemetry, REASON_TRUSTED),
        (_constant_treatment, REASON_DESIGN_ILL_CONDITIONED),
    ],
)
async def test_process_pool_path_matches_in_thread_path(
    frame_factory: Any, reason: str
) -> None:
    """The refresher's process-pool call normalises exactly as the in-thread path.

    Production refreshes through the process pool, so a change applied only to
    the in-thread path would leave production in the old units.
    """
    gatekeeper = build_finance_causal_gatekeeper()
    in_thread = gatekeeper._validate_world_model(frame_factory())

    refresher = WorldModelRefresher(
        gatekeeper, _FrameProvider(frame_factory()), use_process_pool=True
    )
    try:
        snapshot = await refresher.refresh_once()
        assert refresher._executor is not None  # it ran in the worker process
    finally:
        refresher.close()

    assert in_thread.reason == reason
    assert snapshot.verdict.trusted == in_thread.trusted
    assert snapshot.verdict.reason == in_thread.reason
    if in_thread.beta is None:  # refused before the fit: no slope to compare
        assert snapshot.verdict.beta is None
    else:
        assert snapshot.verdict.beta == pytest.approx(in_thread.beta, rel=1e-12)


# ---------------------------------------------------------------------------
# The treatment unit is part of the contract
# ---------------------------------------------------------------------------


def test_cache_fingerprint_includes_the_treatment_unit() -> None:
    """A verdict whose beta is in other units is never served from the cache."""
    spec = build_finance_causal_spec()
    assert _spec_fingerprint(spec) != _spec_fingerprint(
        dataclasses.replace(spec, normalization_scale=1.0)
    )
    assert _spec_fingerprint(spec) == _spec_fingerprint(
        dataclasses.replace(spec, normalization_scale=10_000)
    )


@pytest.mark.parametrize("scale", [0.0, -1.0, math.nan, math.inf, True])
def test_causal_spec_rejects_an_invalid_normalization_scale(scale: Any) -> None:
    with pytest.raises(ValueError, match="normalization_scale"):
        CausalSpec(graph_dot="digraph { a -> b; }", normalization_scale=scale)


@pytest.mark.parametrize("scale", [0.0, -1.0, math.nan, math.inf])
def test_validate_world_model_rejects_an_invalid_normalization_scale(
    scale: float,
) -> None:
    spec = build_finance_causal_spec()
    with pytest.raises(ValueError, match="normalization_scale"):
        gk_mod.validate_world_model(
            spec.graph_dot,
            spec.treatment_col,
            spec.outcome_col,
            generate_mock_telemetry(),
            normalization_scale=scale,
        )


def test_normalization_scale_is_not_read_from_the_environment() -> None:
    """The former CAUSAL_NORMALIZATION_SCALE override is gone.

    It would silently change the units of the placebo-effect threshold, and a
    value left over from the pre-upgrade workaround must have no effect.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(gk_mod))
    env_reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and any(
            isinstance(arg, ast.Constant) and arg.value == "CAUSAL_NORMALIZATION_SCALE"
            for arg in node.args
        )
    ]
    assert env_reads == []
    assert gk_mod.CAUSAL_NORMALIZATION_SCALE == 10_000.0
    assert build_finance_causal_spec().normalization_scale == 10_000.0
