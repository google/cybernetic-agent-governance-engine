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

"""WS-C (POAM-2026-088): the causal tier runs on live telemetry.

Before this change ``CausalTierPlugin`` never passed telemetry, so in an
enforcing posture every ``execute_trade`` was denied with the generic
``CAUSAL_CHECK_FAILED`` and the DoWhy refuter was unreachable. These tests pin
the decision D3 contract:

* enforcing posture, no live rows      -> HARD ``CAUSAL_TELEMETRY_UNAVAILABLE``
* enforcing posture, < min_samples     -> HARD ``CAUSAL_INSUFFICIENT_SAMPLES``
* enforcing posture, >= min_samples    -> the refuter runs (ALLOW on a stable model)
* dev posture, empty frame             -> synthetic telemetry stands in
* dev posture, non-empty frame         -> validated as given, never replaced
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

from src.cage_finance.tiers import causal_tier
from src.cage_finance.tiers.causal_tier import (
    CODE_CHECK_FAILED,
    CODE_INSUFFICIENT_SAMPLES,
    CODE_TELEMETRY_UNAVAILABLE,
    CausalTierPlugin,
    build_finance_causal_gatekeeper,
)
from src.gateway.governance.causal import gatekeeper as gk_mod
from src.gateway.governance.causal.gatekeeper import (
    REASON_INSUFFICIENT_SAMPLES,
    REASON_NO_LIVE_TELEMETRY,
    REASON_RISK_BOUNDARY,
    REASON_TRUSTED,
    CausalDecision,
)
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.schemas.thresholds import get_causal_min_samples
from src.gateway.governance.telemetry_provider import (
    BaseTelemetryProvider,
    ConfigurationError,
    NullTelemetryProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

PARAMS = {"symbol": "AAPL", "amount": 1_000.0}


def _frame(n: int) -> pd.DataFrame:
    """Fresh finance telemetry with ``n`` rows (columns of causal_graph.yaml)."""
    rng = np.random.default_rng(7)
    vol = rng.uniform(0.1, 0.9, n)
    amount = np.clip(rng.normal(5_000, 1_000, n) - vol * 2_000, 100, 10_000)
    risk = np.clip(vol * 0.5 + amount / 10_000 * 0.5 + rng.normal(0, 0.05, n), 0, 1)
    return pd.DataFrame(
        {
            "market_volatility": vol,
            "trade_amount": amount,
            "risk_score": risk,
            "timestamp": time.time() - rng.uniform(0, 600, n),
        }
    )


class _Provider(BaseTelemetryProvider):
    def __init__(self, frame: pd.DataFrame | None = None, exc: Exception | None = None):
        self._frame = frame
        self._exc = exc
        self.requested: list[int] = []

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        self.requested.append(n_samples)
        if self._exc is not None:
            raise self._exc
        assert self._frame is not None
        return self._frame


class _StableDoWhy:
    """Stand-in for ``dowhy.CausalModel`` with a small positive slope and a
    placebo refuter that does not reject. Records that the refuter ran."""

    refuted = 0

    def __init__(self, data: pd.DataFrame, treatment: str, outcome: str, graph: str):
        self.n = len(data)

    def identify_effect(self, proceed_when_unidentifiable: bool = True) -> Any:
        return object()

    def estimate_effect(self, estimand: Any, method_name: str) -> Any:
        return SimpleNamespace(value=1e-5)

    def refute_estimate(self, estimand: Any, estimate: Any, **_: Any) -> Any:
        type(self).refuted += 1
        return SimpleNamespace(refutation_result={"p_value": 0.9}, new_effect=0.0)


@pytest.fixture
def enforcing(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "staging")


@pytest.fixture
def dev(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "dev")


@pytest.fixture
def stable_dowhy(monkeypatch):
    _StableDoWhy.refuted = 0
    monkeypatch.setattr(gk_mod, "_DOWHY_AVAILABLE", True)
    monkeypatch.setattr(gk_mod, "_CausalModel", _StableDoWhy)
    return _StableDoWhy


def _only(violations):
    assert len(violations) == 1, violations
    v = violations[0]
    assert v.kind is ViolationKind.HARD
    assert v.tier == "causal"
    return v


# ---------------------------------------------------------------------------
# Enforcing posture (decision D3: HARD deny with distinct codes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enforcing_posture_null_provider_denies_with_telemetry_unavailable(
    enforcing, stable_dowhy
):
    tier = CausalTierPlugin(telemetry_provider=NullTelemetryProvider())
    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_TELEMETRY_UNAVAILABLE
    assert stable_dowhy.refuted == 0


@pytest.mark.asyncio
async def test_enforcing_posture_no_provider_denies_with_telemetry_unavailable(
    enforcing, stable_dowhy
):
    v = _only(await CausalTierPlugin().evaluate("execute_trade", PARAMS))
    assert v.code == CODE_TELEMETRY_UNAVAILABLE


@pytest.mark.asyncio
async def test_enforcing_posture_30_rows_denies_with_insufficient_samples(
    enforcing, stable_dowhy
):
    assert get_causal_min_samples() > 30
    tier = CausalTierPlugin(telemetry_provider=_Provider(_frame(30)))
    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_INSUFFICIENT_SAMPLES
    assert stable_dowhy.refuted == 0


@pytest.mark.asyncio
async def test_enforcing_posture_60_rows_reaches_refuter(enforcing, stable_dowhy):
    assert get_causal_min_samples() <= 60
    provider = _Provider(_frame(60))
    tier = CausalTierPlugin(telemetry_provider=provider)
    assert await tier.evaluate("execute_trade", PARAMS) == []
    assert stable_dowhy.refuted == 1
    assert provider.requested and provider.requested[0] >= get_causal_min_samples()


@pytest.mark.asyncio
async def test_enforcing_posture_risk_boundary_keeps_generic_code(
    enforcing, stable_dowhy, monkeypatch
):
    monkeypatch.setattr(gk_mod, "CAUSAL_LOCK_RISK_BOUNDARY", 0.5)
    tier = CausalTierPlugin(telemetry_provider=_Provider(_frame(60)))
    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_CHECK_FAILED
    assert stable_dowhy.refuted == 1


@pytest.mark.asyncio
async def test_provider_error_denies_with_telemetry_unavailable(
    enforcing, stable_dowhy
):
    tier = CausalTierPlugin(telemetry_provider=_Provider(exc=RuntimeError("feed down")))
    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_TELEMETRY_UNAVAILABLE
    assert "feed down" in v.message


# ---------------------------------------------------------------------------
# Non-enforcing posture
# ---------------------------------------------------------------------------


def _spy_validate(monkeypatch) -> list[pd.DataFrame]:
    seen: list[pd.DataFrame] = []

    def _validate(self, telemetry):
        seen.append(telemetry)
        return gk_mod.WorldModelVerdict(True, 1e-5, REASON_TRUSTED)

    monkeypatch.setattr(gk_mod.CausalGatekeeper, "_validate_world_model", _validate)
    monkeypatch.setattr(gk_mod, "_DOWHY_AVAILABLE", True)
    monkeypatch.setattr(gk_mod, "get_causal_cache_ttl_seconds", lambda: 0)
    return seen


@pytest.mark.asyncio
async def test_dev_posture_empty_frame_uses_synthetic(dev, monkeypatch):
    seen = _spy_validate(monkeypatch)
    synthetic = _frame(200)
    gk = build_finance_causal_gatekeeper()
    object.__setattr__(gk.spec, "synthetic_telemetry_factory", lambda: synthetic)
    tier = CausalTierPlugin(
        causal_gatekeeper=gk, telemetry_provider=NullTelemetryProvider()
    )

    assert await tier.evaluate("execute_trade", PARAMS) == []
    assert len(seen) == 1 and seen[0] is synthetic


@pytest.mark.asyncio
async def test_dev_posture_nonempty_frame_is_not_overridden(dev, monkeypatch):
    factory = MagicMock(return_value=_frame(200))
    monkeypatch.setattr(gk_mod, "_DOWHY_AVAILABLE", True)
    gk = build_finance_causal_gatekeeper()
    object.__setattr__(gk.spec, "synthetic_telemetry_factory", factory)
    tier = CausalTierPlugin(
        causal_gatekeeper=gk, telemetry_provider=_Provider(_frame(30))
    )

    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_INSUFFICIENT_SAMPLES
    factory.assert_not_called()


# ---------------------------------------------------------------------------
# Kernel decision object
# ---------------------------------------------------------------------------


def test_gatekeeper_evaluate_reports_reasons(enforcing, stable_dowhy):
    gk = build_finance_causal_gatekeeper()
    assert gk.evaluate(PARAMS, None) == CausalDecision(False, REASON_NO_LIVE_TELEMETRY)
    assert gk.evaluate(PARAMS, _frame(0)) == CausalDecision(
        False, REASON_NO_LIVE_TELEMETRY
    )
    assert gk.evaluate(PARAMS, _frame(30)) == CausalDecision(
        False, REASON_INSUFFICIENT_SAMPLES
    )
    assert gk.evaluate(PARAMS, _frame(60)) == CausalDecision(True, REASON_TRUSTED)
    assert gk.causal_safety_check(PARAMS, _frame(60)) is True
    assert gk.causal_safety_check(PARAMS, _frame(30)) is False


def test_gatekeeper_evaluate_risk_boundary_reason(enforcing, stable_dowhy, monkeypatch):
    monkeypatch.setattr(gk_mod, "CAUSAL_LOCK_RISK_BOUNDARY", 0.5)
    gk = build_finance_causal_gatekeeper()
    assert gk.evaluate(PARAMS, _frame(60)) == CausalDecision(
        False, REASON_RISK_BOUNDARY
    )


@pytest.mark.asyncio
async def test_patched_bool_check_still_maps_to_generic_code(enforcing, monkeypatch):
    """Tests that patch the module-level check keep working (bool → CHECK_FAILED)."""
    monkeypatch.setattr(
        causal_tier, "causal_safety_check", MagicMock(return_value=False)
    )
    tier = CausalTierPlugin(telemetry_provider=_Provider(_frame(60)))
    v = _only(await tier.evaluate("execute_trade", PARAMS))
    assert v.code == CODE_CHECK_FAILED


# ---------------------------------------------------------------------------
# Construction (create_finance_tiers)
# ---------------------------------------------------------------------------


def _causal_tier_of(tiers) -> CausalTierPlugin:
    (tier,) = [t for t in tiers if isinstance(t, CausalTierPlugin)]
    return tier


def test_create_finance_tiers_wires_resolved_provider(monkeypatch):
    import src.cage_finance as finance

    sentinel = NullTelemetryProvider()
    monkeypatch.setattr(finance, "get_telemetry_provider", lambda: sentinel)
    tiers = finance.create_finance_tiers(MagicMock(), MagicMock(), MagicMock())
    assert _causal_tier_of(tiers)._telemetry_provider is sentinel


def test_create_finance_tiers_prefers_explicit_provider(monkeypatch):
    import src.cage_finance as finance

    explicit = _Provider(_frame(60))
    monkeypatch.setattr(
        finance,
        "get_telemetry_provider",
        MagicMock(side_effect=AssertionError("unused")),
    )
    tiers = finance.create_finance_tiers(
        MagicMock(), MagicMock(), MagicMock(), telemetry_provider=explicit
    )
    assert _causal_tier_of(tiers)._telemetry_provider is explicit


def test_create_finance_tiers_remote_without_credentials_fails_at_assembly(monkeypatch):
    import src.cage_finance as finance

    monkeypatch.setenv("CAGE_TELEMETRY_PROVIDER", "remote")
    monkeypatch.delenv("TELEMETRY_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("TELEMETRY_SECRET_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="TELEMETRY_PUBLIC_KEY"):
        finance.create_finance_tiers(MagicMock(), MagicMock(), MagicMock())


def test_create_finance_tiers_enforcing_posture_requires_explicit_provider(monkeypatch):
    """Staging/prod never fall back to the null provider silently."""
    import src.cage_finance as finance

    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.delenv("CAGE_TELEMETRY_PROVIDER", raising=False)
    with pytest.raises(ConfigurationError, match="CAGE_TELEMETRY_PROVIDER must be set"):
        finance.create_finance_tiers(MagicMock(), MagicMock(), MagicMock())
