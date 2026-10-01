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

"""Causal world-model cache: only the verdict is cached, never the decision.

Regression suite for the cache bypass in ``CausalGatekeeper.causal_safety_check``:
the old implementation cached the *final* decision (including the per-request
marginal risk boundary) under a key that ignored the treatment value, so a
cached ALLOW for a small trade was replayed for an arbitrarily large one. The
cache now holds only the params-independent :class:`WorldModelVerdict`; the
risk boundary is recomputed from ``beta`` on every call.

DoWhy is stubbed with a counting fake so the tests are hermetic and can observe
whether refutation re-ran; Redis is a ``fakeredis`` sync client.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("networkx", reason="networkx required by the causal gatekeeper")

import fakeredis
import pandas as pd

from src.gateway.governance.causal import gatekeeper as gk_mod
from src.gateway.governance.causal.gatekeeper import (
    CausalGatekeeper,
    WorldModelVerdict,
)
from src.gateway.governance.contracts import CausalSpec

pytestmark = [pytest.mark.unit, pytest.mark.local]

_GRAPH_A = "digraph { c -> x; c -> y; x -> y; }"
_GRAPH_B = "digraph { z -> x; z -> y; x -> y; }"

# beta=0.5, scale=10_000: risk = 0.5 + 0.5 * amount / 10_000
_SMALL = 100.0  # risk 0.505 -> within the 0.95 boundary
_LARGE = 10_000_000.0  # risk clamps to 1.0 -> exceeds the boundary


class _FakeDoWhy:
    """Counting stand-in for ``dowhy.CausalModel`` with tunable outputs."""

    def __init__(self) -> None:
        self.beta: float = 0.5
        self.p_value: float = 0.9
        self.new_effect: float = 0.0
        self.raise_on_estimate: bool = False
        self.constructed = 0
        self.refutations = 0

    def __call__(self, **_kwargs: Any) -> Any:
        self.constructed += 1
        fake = self

        class _Model:
            def identify_effect(self, proceed_when_unidentifiable: bool = True) -> str:
                return "estimand"

            def estimate_effect(self, _estimand: Any, method_name: str) -> Any:
                if fake.raise_on_estimate:
                    raise ValueError("estimator blew up")
                return SimpleNamespace(value=fake.beta)

            def refute_estimate(self, *_a: Any, **_kw: Any) -> Any:
                fake.refutations += 1
                return SimpleNamespace(
                    refutation_result={"p_value": fake.p_value},
                    new_effect=fake.new_effect,
                )

        return _Model()


def _fresh_telemetry() -> pd.DataFrame:
    now = time.time()
    n = 100
    return pd.DataFrame(
        {
            "c": [0.5] * n,
            "x": [float(i) for i in range(n)],
            "y": [0.1] * n,
            "timestamp": [now - i for i in range(n)],
        }
    )


def _spec(graph: str = _GRAPH_A) -> CausalSpec:
    return CausalSpec(
        graph_dot=graph,
        treatment_col="x",
        outcome_col="y",
        treatment_extractor=lambda p: p.get("amount"),
        context_extractor=lambda p: str(p.get("market_regime", "unknown")),
        normalization_scale=10_000.0,
        synthetic_telemetry_factory=_fresh_telemetry,
    )


class _StubControlRegistry:
    """Region-independent ControlRegistry stand-in (span metadata only)."""

    active_region = "TEST"

    def get_mapping(self, control: Any) -> dict[str, str]:
        return {
            "internal_id": control.value,
            "primary_framework": "test-framework",
            "legacy_citation": "test-citation",
            "scope": "test-scope",
        }


@pytest.fixture
def fake_dowhy(monkeypatch: pytest.MonkeyPatch) -> _FakeDoWhy:
    fake = _FakeDoWhy()
    monkeypatch.setattr(gk_mod, "_DOWHY_AVAILABLE", True)
    monkeypatch.setattr(gk_mod, "_CausalModel", fake)
    monkeypatch.setattr(gk_mod, "ControlRegistry", _StubControlRegistry)
    monkeypatch.setenv("CAGE_ENV", "development")
    return fake


@pytest.fixture
def redis_store(monkeypatch: pytest.MonkeyPatch) -> fakeredis.FakeRedis:
    store = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.sync_redis_client", store
    )
    monkeypatch.setattr(gk_mod, "get_causal_cache_ttl_seconds", lambda: 60)
    return store


def _check(gatekeeper: CausalGatekeeper, amount: float, **kw: Any) -> bool:
    return gatekeeper.causal_safety_check(
        {"amount": amount, "market_regime": "calm"}, action="execute_trade", **kw
    )


class TestRiskBoundaryIsPerRequest:
    def test_cached_allow_for_small_trade_does_not_admit_large_trade(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        """Regression: a warm cache must not bypass the risk boundary."""
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _SMALL) is True
        assert _check(gatekeeper, _LARGE) is False
        # The large trade was decided from the cached verdict, not a recompute.
        assert fake_dowhy.refutations == 1

    def test_large_trade_denial_does_not_deny_small_trade(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _LARGE) is False
        assert _check(gatekeeper, _SMALL) is True
        assert fake_dowhy.refutations == 1

    def test_cache_holds_only_the_world_model_verdict(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        _check(gatekeeper, _LARGE)
        keys = redis_store.keys("*")
        assert len(keys) == 1
        assert gk_mod._causal_cache_get_sync(keys[0]) == WorldModelVerdict(
            True, 0.5, "world_model_trusted"
        )


class TestWorldModelVerdictCaching:
    def test_second_call_does_not_rerun_refutation(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _SMALL) is True
        assert _check(gatekeeper, _SMALL * 2) is True
        assert fake_dowhy.constructed == 1
        assert fake_dowhy.refutations == 1

    def test_action_kwarg_namespaces_the_entry(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        params = {"amount": _SMALL, "market_regime": "calm"}
        assert gatekeeper.causal_safety_check(params, action="a") is True
        assert gatekeeper.causal_safety_check(params, action="b") is True
        assert gatekeeper.causal_safety_check(params, action="a") is True
        assert fake_dowhy.constructed == 2

    @pytest.mark.parametrize(
        ("attr", "value", "reason"),
        [
            ("beta", -0.2, "negative_or_zero_causal_slope"),
            ("beta", 0.0, "negative_or_zero_causal_slope"),
            ("beta", float("nan"), "non_finite_causal_slope"),
            ("p_value", 0.01, "p_value_threshold"),
            ("new_effect", 0.9, "placebo_effect_magnitude"),
        ],
    )
    def test_untrusted_world_model_is_cached_and_denies_every_amount(
        self,
        fake_dowhy: _FakeDoWhy,
        redis_store: fakeredis.FakeRedis,
        attr: str,
        value: float,
        reason: str,
    ) -> None:
        setattr(fake_dowhy, attr, value)
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _SMALL) is False

        # Even once the model would now validate, the cached untrusted verdict
        # keeps denying — for any amount — without recomputing.
        fake_dowhy.beta, fake_dowhy.p_value, fake_dowhy.new_effect = 0.5, 0.9, 0.0
        for amount in (1.0, _SMALL, _LARGE):
            assert _check(gatekeeper, amount) is False
        assert fake_dowhy.constructed == 1
        (key,) = redis_store.keys("*")
        cached = gk_mod._causal_cache_get_sync(key)
        assert cached is not None
        assert cached.trusted is False
        assert cached.reason == reason

    def test_different_specs_do_not_share_entries(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        trusted_spec = CausalGatekeeper(_spec(_GRAPH_A))
        assert _check(trusted_spec, _SMALL) is True

        # Same action and context, different graph: must recompute, not reuse.
        fake_dowhy.beta = -1.0
        other_spec = CausalGatekeeper(_spec(_GRAPH_B))
        assert _check(other_spec, _SMALL) is False
        assert fake_dowhy.constructed == 2
        assert len(redis_store.keys("*")) == 2

        # And the first spec's trusted verdict is still served from its own key.
        assert _check(trusted_spec, _SMALL) is True
        assert fake_dowhy.constructed == 2


class TestCachePolicyBoundaries:
    def test_explicit_telemetry_never_touches_the_cache(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        telemetry = _fresh_telemetry()
        assert _check(gatekeeper, _SMALL, current_telemetry=telemetry) is True
        assert _check(gatekeeper, _SMALL, current_telemetry=telemetry) is True
        assert fake_dowhy.constructed == 2
        assert redis_store.keys("*") == []

    def test_explicit_telemetry_is_not_served_a_cached_verdict(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _SMALL) is True  # warms the synthetic entry
        fake_dowhy.beta = -1.0
        assert (
            _check(gatekeeper, _SMALL, current_telemetry=_fresh_telemetry()) is False
        )

    def test_exception_path_is_not_cached(
        self, fake_dowhy: _FakeDoWhy, redis_store: fakeredis.FakeRedis
    ) -> None:
        gatekeeper = CausalGatekeeper(_spec())
        fake_dowhy.raise_on_estimate = True
        assert _check(gatekeeper, _SMALL) is False
        assert redis_store.keys("*") == []

        fake_dowhy.raise_on_estimate = False
        assert _check(gatekeeper, _SMALL) is True

    def test_redis_unavailable_fails_closed_when_cache_enabled(
        self, fake_dowhy: _FakeDoWhy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "src.gateway.infrastructure.redis_client.sync_redis_client", None
        )
        monkeypatch.setattr(gk_mod, "get_causal_cache_ttl_seconds", lambda: 60)
        assert _check(CausalGatekeeper(_spec()), _SMALL) is False
        assert fake_dowhy.constructed == 0

    def test_disabled_cache_does_not_consult_redis(
        self, fake_dowhy: _FakeDoWhy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "src.gateway.infrastructure.redis_client.sync_redis_client", None
        )
        monkeypatch.setattr(gk_mod, "get_causal_cache_ttl_seconds", lambda: 0)
        gatekeeper = CausalGatekeeper(_spec())
        assert _check(gatekeeper, _SMALL) is True
        assert _check(gatekeeper, _LARGE) is False
        assert fake_dowhy.constructed == 2

    def test_invalid_treatment_fails_before_cache_lookup(
        self, fake_dowhy: _FakeDoWhy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lookups: list[str] = []
        monkeypatch.setattr(gk_mod, "get_causal_cache_ttl_seconds", lambda: 60)
        monkeypatch.setattr(
            gk_mod, "_causal_cache_get_sync", lambda key: lookups.append(key)
        )
        gatekeeper = CausalGatekeeper(_spec())
        for amount in (None, 0.0, -5.0, float("nan"), float("inf")):
            assert _check(gatekeeper, amount) is False  # type: ignore[arg-type]
        assert lookups == []
        assert fake_dowhy.constructed == 0


class TestWorldModelVerdict:
    def test_trusted_requires_positive_finite_beta(self) -> None:
        for beta in (None, 0.0, -1.0, float("nan"), float("inf")):
            with pytest.raises(ValueError):
                WorldModelVerdict(True, beta, "x")

    def test_round_trip(self) -> None:
        verdict = WorldModelVerdict(True, 0.25, "world_model_trusted")
        import json

        assert WorldModelVerdict.from_payload(json.loads(verdict.to_json())) == verdict
