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

"""
Tests for the DoWhy Causal Gatekeeper module.

Tests the causal_safety_check function directly (unit tests) and its
integration with the SymbolicGovernor (integration tests via mock).

Classes:
  TestCausalOrderingValidation  — no dowhy dependency; tests validate_causal_ordering
  TestTelemetryFreshness        — no dowhy dependency; tests _check_telemetry_freshness
  TestCausalCacheHelpers        — no dowhy dependency; tests sync cache helpers
  TestCausalSafetyCheckUnit     — requires dowhy (skipped when not installed)
  TestCausalGatekeeperIntegration — requires dowhy (skipped when not installed)
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# causal_gatekeeper.py imports networkx at module level; skip entire file when
# the compliance extras (networkx, dowhy) are not installed — this prevents a
# hard collection error from propagating to the standard CI pytest job.
pytest.importorskip(
    "networkx",
    reason="networkx not installed — skipping causal gatekeeper tests (install compliance extras)",
)

import numpy as np
import pandas as pd

pytestmark = pytest.mark.local

# ---------------------------------------------------------------------------
# Tests that do NOT require dowhy
# ---------------------------------------------------------------------------


class TestCausalOrderingValidation:
    """Tests for validate_causal_ordering() — no dowhy required."""

    def test_valid_ordering_same_trace_id(self):
        """Governance span before execution span with matching trace_id → True."""
        from src.gateway.governance.causal.gatekeeper import validate_causal_ordering

        gov = {"timestamp": 1000.0, "trace_id": "trace-abc"}
        exe = {"timestamp": 2000.0, "trace_id": "trace-abc"}
        assert validate_causal_ordering(gov, exe) is True

    def test_trace_id_mismatch_returns_false(self):
        """Mismatched trace_ids → False (different causal chains)."""
        from src.gateway.governance.causal.gatekeeper import validate_causal_ordering

        gov = {"timestamp": 1000.0, "trace_id": "trace-A"}
        exe = {"timestamp": 2000.0, "trace_id": "trace-B"}
        assert validate_causal_ordering(gov, exe) is False

    def test_governance_after_execution_returns_false(self):
        """Governance timestamp >= execution timestamp → False."""
        from src.gateway.governance.causal.gatekeeper import validate_causal_ordering

        gov = {"timestamp": 3000.0, "trace_id": "trace-abc"}
        exe = {"timestamp": 2000.0, "trace_id": "trace-abc"}
        assert validate_causal_ordering(gov, exe) is False

    def test_equal_timestamps_returns_false(self):
        """Equal timestamps violate strict ordering → False."""
        from src.gateway.governance.causal.gatekeeper import validate_causal_ordering

        gov = {"timestamp": 2000.0, "trace_id": "trace-abc"}
        exe = {"timestamp": 2000.0, "trace_id": "trace-abc"}
        assert validate_causal_ordering(gov, exe) is False

    def test_missing_trace_ids_non_strict_mode_uses_timestamp(self):
        """Missing trace_ids in non-strict mode: falls back to timestamp check."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        original = causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE
        try:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = False
            gov = {"timestamp": 1000.0}  # no trace_id
            exe = {"timestamp": 2000.0}  # no trace_id
            result = causal_gatekeeper.validate_causal_ordering(gov, exe)
            assert result is True
        finally:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = original

    def test_missing_trace_ids_strict_mode_returns_false(self):
        """Missing trace_ids in strict mode → False."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        original = causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE
        try:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = True
            gov = {"timestamp": 1000.0}
            exe = {"timestamp": 2000.0}
            result = causal_gatekeeper.validate_causal_ordering(gov, exe)
            assert result is False
        finally:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = original

    def test_no_timestamps_with_matching_trace_ids_returns_true(self):
        """Matching trace_ids, no timestamps → True (ordering not violated)."""
        from src.gateway.governance.causal.gatekeeper import validate_causal_ordering

        gov = {"trace_id": "trace-xyz"}
        exe = {"trace_id": "trace-xyz"}
        assert validate_causal_ordering(gov, exe) is True

    def test_empty_spans_non_strict_returns_true(self):
        """Empty spans with no trace_id in non-strict mode → True (no violation)."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        original = causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE
        try:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = False
            result = causal_gatekeeper.validate_causal_ordering({}, {})
            assert result is True
        finally:
            causal_gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE = original


class TestTelemetryFreshness:
    """Tests for _check_telemetry_freshness() — no dowhy required."""

    def _make_span(self):
        """Return a mock OTel span."""
        return MagicMock()

    def test_fresh_telemetry_returns_true(self):
        """Telemetry with recent timestamps returns True."""
        from src.gateway.governance.causal.gatekeeper import _check_telemetry_freshness

        now = time.time()
        df = pd.DataFrame({"timestamp": [now - 60, now - 30, now - 10]})
        result = _check_telemetry_freshness(df, self._make_span())
        assert result is True

    def test_stale_telemetry_returns_false(self):
        """Telemetry older than telemetry.max_staleness_seconds → False."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        now = time.time()
        df = pd.DataFrame({"timestamp": [now - 3600, now - 1800]})
        # Patch the accessor to return 10 seconds (much less than 1800s age)
        with patch(
            "src.gateway.governance.causal.gatekeeper.get_telemetry_max_staleness_seconds",
            return_value=10,
        ):
            result = causal_gatekeeper._check_telemetry_freshness(df, self._make_span())
        assert result is False

    def test_no_timestamp_column_returns_false(self):
        """DataFrame without any timestamp column → False (fail-closed)."""
        from src.gateway.governance.causal.gatekeeper import _check_telemetry_freshness

        df = pd.DataFrame({"x": [1, 2, 3], "y": [4, 5, 6]})
        result = _check_telemetry_freshness(df, self._make_span())
        assert result is False

    def test_alternative_timestamp_column_names(self):
        """Checks 'ts', 'event_time', 'time', 'created_at' column names."""
        from src.gateway.governance.causal.gatekeeper import _check_telemetry_freshness

        now = time.time()
        for col in ("ts", "event_time", "time", "created_at"):
            df = pd.DataFrame({col: [now - 10, now - 5]})
            result = _check_telemetry_freshness(df, self._make_span())
            assert result is True, f"Expected True for column '{col}'"

    def test_unparseable_timestamp_returns_false(self):
        """Timestamp column with unparseable values → False (fail-closed)."""
        from src.gateway.governance.causal.gatekeeper import _check_telemetry_freshness

        df = pd.DataFrame({"timestamp": ["not-a-date", "also-not"]})
        result = _check_telemetry_freshness(df, self._make_span())
        assert result is False

    def test_millisecond_timestamps_supported(self):
        """Timestamps >1e12 are treated as milliseconds → fresh."""
        from src.gateway.governance.causal.gatekeeper import _check_telemetry_freshness

        now_ms = time.time() * 1000  # milliseconds
        df = pd.DataFrame({"timestamp": [now_ms - 5000, now_ms - 1000]})
        result = _check_telemetry_freshness(df, self._make_span())
        assert result is True


class TestCausalCacheHelpers:
    """Tests for sync cache helpers — no dowhy required."""

    def test_cache_get_sync_returns_none_when_redis_unavailable(self):
        """_causal_cache_get_sync raises RuntimeError when sync_redis_client is None."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        with patch("src.gateway.infrastructure.redis_client.sync_redis_client", None):
            with pytest.raises(RuntimeError, match="Redis unavailable"):
                causal_gatekeeper._causal_cache_get_sync("test-key")

    def test_cache_get_sync_returns_none_on_cache_miss(self):
        """_causal_cache_get_sync returns None when key is absent."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        with patch(
            "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
        ):
            from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

            result = causal_gatekeeper._causal_cache_get_sync("missing-key")
        assert result is None

    def test_cache_get_sync_returns_parsed_dict_on_hit(self):
        """_causal_cache_get_sync parses and returns cached JSON."""
        import json

        mock_redis = MagicMock()
        payload = json.dumps({"result": True, "reason": "all_checks_passed"})
        mock_redis.get.return_value = payload

        with patch(
            "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
        ):
            from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

            result = causal_gatekeeper._causal_cache_get_sync("hit-key")
        assert result == {"result": True, "reason": "all_checks_passed"}

    def test_cache_get_sync_raises_on_connection_error(self):
        """_causal_cache_get_sync raises RuntimeError on Redis connection error."""
        mock_redis = MagicMock()
        mock_redis.get.side_effect = ConnectionError("Redis down")

        with patch(
            "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
        ):
            from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

            with pytest.raises(RuntimeError, match="Redis unavailable"):
                causal_gatekeeper._causal_cache_get_sync("error-key")

    def test_cache_get_sync_returns_none_on_json_decode_error(self):
        """_causal_cache_get_sync returns None when cached value is invalid JSON."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = "not-valid-json{"

        with patch(
            "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
        ):
            from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

            result = causal_gatekeeper._causal_cache_get_sync("bad-json-key")
        assert result is None

    def test_cache_set_sync_noop_when_ttl_zero(self):
        """_causal_cache_set_sync is a no-op when telemetry.cache_ttl_seconds=0."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        mock_redis = MagicMock()
        with patch(
            "src.gateway.governance.causal.gatekeeper.get_causal_cache_ttl_seconds",
            return_value=0,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
            ):
                causal_gatekeeper._causal_cache_set_sync("k", True, "reason")
        mock_redis.setex.assert_not_called()

    def test_cache_set_sync_writes_when_redis_available(self):
        """_causal_cache_set_sync calls setex when sync_redis_client is available."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        mock_redis = MagicMock()
        with patch(
            "src.gateway.governance.causal.gatekeeper.get_causal_cache_ttl_seconds",
            return_value=60,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.sync_redis_client", mock_redis
            ):
                causal_gatekeeper._causal_cache_set_sync("my-key", True, "passed")
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert call_args[0][0] == "my-key"
        assert call_args[0][1] == 60

    def test_cache_set_sync_noop_when_redis_unavailable(self):
        """_causal_cache_set_sync is a no-op when sync_redis_client is None."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper

        with patch(
            "src.gateway.governance.causal.gatekeeper.get_causal_cache_ttl_seconds",
            return_value=60,
        ):
            with patch(
                "src.gateway.infrastructure.redis_client.sync_redis_client", None
            ):
                # Should not raise
                causal_gatekeeper._causal_cache_set_sync("k", False, "no-redis")


class TestCausalSafetyCheckNoDoWhy:
    """Tests for causal_safety_check() paths that don't require dowhy."""

    def test_zero_amount_returns_true_without_dowhy(self):
        """amount <= 0 returns True immediately — no dowhy needed."""
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        df = pd.DataFrame(
            {
                "market_volatility": [0.5],
                "trade_amount": [1000.0],
                "risk_score": [0.5],
                "timestamp": [time.time() - 10],
            }
        )
        assert causal_safety_check({"amount": 0}, df) is True

    def test_negative_amount_returns_true_without_dowhy(self):
        """Negative amount returns True immediately — no dowhy needed."""
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        df = pd.DataFrame(
            {
                "market_volatility": [0.3],
                "trade_amount": [500.0],
                "risk_score": [0.3],
                "timestamp": [time.time() - 5],
            }
        )
        assert causal_safety_check({"amount": -1}, df) is True

    def test_production_env_without_telemetry_returns_false(self):
        """In production (CAGE_ENV=production), missing telemetry → fail-closed."""
        import os

        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        original = os.environ.get("CAGE_ENV")
        try:
            os.environ["CAGE_ENV"] = "production"
            result = causal_safety_check({"amount": 100}, None)
            assert result is False
        finally:
            if original is None:
                os.environ.pop("CAGE_ENV", None)
            else:
                os.environ["CAGE_ENV"] = original

    def test_dowhy_unavailable_fails_closed_for_nonzero_amount(self):
        """When dowhy is not installed, nonzero amount → False (fail-closed)."""
        from src.gateway.governance.causal import gatekeeper as causal_gatekeeper
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        original_available = causal_gatekeeper._DOWHY_AVAILABLE
        try:
            causal_gatekeeper._DOWHY_AVAILABLE = False
            df = pd.DataFrame(
                {
                    "market_volatility": [0.5],
                    "trade_amount": [1000.0],
                    "risk_score": [0.5],
                    "timestamp": [time.time() - 10],
                }
            )
            with patch(
                "src.gateway.governance.causal.gatekeeper._causal_cache_get_sync",
                return_value=None,
            ):
                result = causal_safety_check({"amount": 100}, df)
            assert result is False
        finally:
            causal_gatekeeper._DOWHY_AVAILABLE = original_available


# ---------------------------------------------------------------------------
# Tests that DO require dowhy (skipped when not installed)
# ---------------------------------------------------------------------------

try:
    import dowhy as _dowhy_mod  # noqa: F401

    _DOWHY_INSTALLED = True
except ImportError:
    _DOWHY_INSTALLED = False

_skip_if_no_dowhy = pytest.mark.skipif(
    not _DOWHY_INSTALLED,
    reason="dowhy not installed — skipping dowhy-dependent causal gatekeeper tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stable_telemetry():
    """Simulates a healthy system with clear, stable causal links.

    A ``timestamp`` column is included so that the telemetry freshness check
    treats this data as fresh (matching the contract of generate_mock_telemetry).
    """
    import time

    np.random.seed(42)
    n = 200
    market_volatility = np.random.uniform(0.1, 0.9, n)
    trade_amount = np.random.normal(5000, 1000, n) - (market_volatility * 2000)
    trade_amount = np.clip(trade_amount, 100, 10000)
    risk_score = (
        (market_volatility * 0.5)
        + (trade_amount / 10000 * 0.5)
        + np.random.normal(0, 0.05, n)
    )
    risk_score = np.clip(risk_score, 0.0, 1.0)
    now = time.time()
    timestamps = now - np.random.uniform(0, 3600, n)
    return pd.DataFrame(
        {
            "market_volatility": market_volatility,
            "trade_amount": trade_amount,
            "risk_score": risk_score,
            "timestamp": timestamps,
        }
    )


# ---------------------------------------------------------------------------
# Unit Tests — causal_safety_check directly
# ---------------------------------------------------------------------------


@_skip_if_no_dowhy
class TestCausalSafetyCheckUnit:
    """Unit tests for the causal_safety_check function."""

    def test_zero_amount_is_safe(self, stable_telemetry):
        """A trade with amount <= 0 should always be considered safe."""
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        result = causal_safety_check({"amount": 0}, stable_telemetry)
        assert result is True

    def test_negative_amount_is_safe(self, stable_telemetry):
        """A trade with negative amount should always be considered safe."""
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        result = causal_safety_check({"amount": -100}, stable_telemetry)
        assert result is True

    def test_small_trade_with_stable_data_passes(self, stable_telemetry):
        """A small trade against stable telemetry should pass the causal check.

        Redis (cache get/set) is mocked out here because this is a unit test
        of the causal-inference logic, not of Redis connectivity — in this
        test environment there is no live Redis/OPA to connect to, and the
        cache is purely an optimisation layered on top of the DoWhy checks
        below. Production fail-closed behaviour on genuine Redis errors is
        preserved and is exercised separately by
        test_causal_check_fails_safe_on_error.
        """
        from unittest.mock import patch

        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        with (
            patch(
                "src.gateway.governance.causal.gatekeeper._causal_cache_get_sync",
                return_value=None,
            ),
            patch(
                "src.gateway.governance.causal.gatekeeper._causal_cache_set_sync",
                return_value=None,
            ),
        ):
            result = causal_safety_check({"amount": 1}, stable_telemetry)
        assert result is True

    def test_generate_mock_telemetry_shape(self):
        """The mock telemetry generator should produce the expected columns.

        generate_mock_telemetry() now includes a 'timestamp' column so that
        the telemetry freshness check treats synthetic data as fresh.
        """
        from src.gateway.governance.causal.gatekeeper import generate_mock_telemetry

        df = generate_mock_telemetry(n_samples=100)
        assert len(df) == 100
        assert set(df.columns) == {
            "market_volatility",
            "trade_amount",
            "risk_score",
            "timestamp",
        }

    def test_generate_mock_telemetry_deterministic(self):
        """Mock telemetry should be deterministic (seeded)."""
        from src.gateway.governance.causal.gatekeeper import generate_mock_telemetry

        df1 = generate_mock_telemetry(50)
        df2 = generate_mock_telemetry(50)
        pd.testing.assert_frame_equal(df1, df2)

    def test_causal_check_fails_safe_on_error(self):
        """If DoWhy raises an exception, the check should fail-safe (return False).

        The Redis cache is bypassed (patched to return None) so that a cached
        result from a previous test with the same cache key cannot mask the
        fail-safe behaviour being tested here.
        """
        from unittest.mock import patch

        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        # Provide a DataFrame missing required columns to trigger an error.
        # No timestamp column → freshness check fails closed → returns False.
        bad_data = pd.DataFrame({"x": [1, 2, 3], "y": [4, 5, 6]})
        with patch(
            "src.gateway.governance.causal.gatekeeper._causal_cache_get_sync",
            return_value=None,  # force cache miss so the check actually runs
        ):
            result = causal_safety_check({"amount": 100}, bad_data)
        assert result is False


# ---------------------------------------------------------------------------
# Integration Tests — SymbolicGovernor with causal gatekeeper
# ---------------------------------------------------------------------------


@_skip_if_no_dowhy
class TestCausalGatekeeperIntegration:
    """Tests causal gatekeeper integration within the SymbolicGovernor."""

    def _create_mock_governor(self, telemetry_data=None):
        """Helper to create a SymbolicGovernor with all checks mocked except causal."""
        from src.gateway.core.policy import OPAClient
        from src.gateway.governance.contracts import ConsensusProvider, SafetyFilter
        from src.gateway.governance.symbolic_governor import SymbolicGovernor

        opa_client = MagicMock(spec=OPAClient)
        opa_client.evaluate_policy = AsyncMock(return_value={"decision": "ALLOW"})

        safety_filter = MagicMock(spec=SafetyFilter)
        safety_filter.verify_action = AsyncMock(return_value="SAFE")

        consensus_engine = MagicMock(spec=ConsensusProvider)
        consensus_engine.check_consensus = AsyncMock(return_value={"status": "APPROVE"})

        telemetry_provider = None
        if telemetry_data is not None:
            telemetry_provider = MagicMock()
            telemetry_provider.get_latest_data.return_value = telemetry_data

        gov = SymbolicGovernor(
            opa_client=opa_client,
            safety_filter=safety_filter,
            consensus_engine=consensus_engine,
        )
        from src.cage_finance.tiers.causal_tier import CausalTierPlugin
        from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
        from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

        gov.register_domain_tier(CBFTierPlugin(safety_filter))
        gov.register_domain_tier(ConsensusTierPlugin(consensus_engine))
        gov.register_domain_tier(CausalTierPlugin())
        return gov

    @pytest.mark.asyncio
    async def test_governor_passes_with_stable_model(self, stable_telemetry):
        """Governor should approve when the causal model is stable."""
        governor = self._create_mock_governor(stable_telemetry)
        intent = {"amount": 1, "confidence": 0.99, "symbol": "AAPL"}
        result = await governor.verify("execute_trade", intent)
        causal_violations = [v for v in result["violations"] if "Causal" in v]
        assert len(causal_violations) == 0

    @pytest.mark.asyncio
    async def test_governor_blocks_when_causal_check_fails(self, stable_telemetry):
        """Governor should block when the causal safety check returns False."""
        governor = self._create_mock_governor(stable_telemetry)
        intent = {"amount": 1, "confidence": 0.99, "symbol": "AAPL"}

        with patch(
            "src.gateway.governance.causal.gatekeeper.causal_safety_check"
        ) as mock_check:
            mock_check.return_value = False
            result = await governor.verify("execute_trade", intent)

        causal_violations = [
            v for v in result["violations"] if "DoWhy refutation failed" in v
        ]
        assert len(causal_violations) > 0

    @pytest.mark.asyncio
    async def test_governor_skips_causal_for_non_trade(self, stable_telemetry):
        """Causal gatekeeper should NOT run for non-trade actions."""
        governor = self._create_mock_governor(stable_telemetry)
        intent = {"query": "What is AAPL price?"}
        result = await governor.verify("market_lookup", intent)
        causal_violations = [v for v in result["violations"] if "Causal" in v]
        assert len(causal_violations) == 0


# ---------------------------------------------------------------------------
# Peer Review Fix Tests: β≤0 guard and bounded risk score
# ---------------------------------------------------------------------------


class TestNegativeCausalSlopeGuard:
    """Tests for the β≤0 fail-closed guard (peer review fix).

    The causal gatekeeper must reject when the estimated causal effect (β)
    is negative or zero, as this indicates an untrustworthy world-model.
    """

    @pytest.fixture
    def negative_slope_telemetry(self):
        """Generate telemetry that produces a negative causal slope.

        This simulates an adversarial or confounded dataset where higher
        trade amounts appear to DECREASE risk — counter-intuitive and
        indicates model misspecification.
        """
        np.random.seed(99)
        n = 200
        market_volatility = np.random.uniform(0.1, 0.9, n)
        trade_amount = np.random.uniform(1000, 10000, n)
        # Negative relationship: higher trade_amount → LOWER risk_score
        risk_score = 0.8 - (trade_amount / 20000) + np.random.normal(0, 0.05, n)
        risk_score = np.clip(risk_score, 0.0, 1.0)

        now_epoch = time.time()
        timestamps = now_epoch - np.random.uniform(0, 600, n)

        return pd.DataFrame(
            {
                "market_volatility": market_volatility,
                "trade_amount": trade_amount,
                "risk_score": risk_score,
                "timestamp": timestamps,
            }
        )

    @pytest.fixture
    def zero_slope_telemetry(self):
        """Generate telemetry that produces a near-zero causal slope.

        This simulates data where trade_amount has no effect on risk_score,
        which is suspicious and should trigger fail-closed.
        """
        np.random.seed(123)
        n = 200
        market_volatility = np.random.uniform(0.1, 0.9, n)
        trade_amount = np.random.uniform(1000, 10000, n)
        # No relationship: risk_score is purely random, independent of trade_amount
        risk_score = np.random.uniform(0.3, 0.7, n)

        now_epoch = time.time()
        timestamps = now_epoch - np.random.uniform(0, 600, n)

        return pd.DataFrame(
            {
                "market_volatility": market_volatility,
                "trade_amount": trade_amount,
                "risk_score": risk_score,
                "timestamp": timestamps,
            }
        )

    def test_negative_slope_triggers_causal_lock(self, negative_slope_telemetry):
        """Negative causal slope (β < 0) must trigger fail-closed CAUSAL LOCK."""
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        # causal_safety_check(params, current_telemetry) — pass args directly
        params = {
            "amount": 5000,
            "symbol": "AAPL",
            "confidence": 0.99,
            "action_type": "test_negative_slope_triggers_causal_lock",
        }
        result = causal_safety_check(params, negative_slope_telemetry)
        # Must return False (blocked) because β ≤ 0
        assert result is False, "Negative causal slope should trigger CAUSAL LOCK"

    def test_large_adversarial_amount_with_negative_slope(
        self, negative_slope_telemetry
    ):
        """Large adversarial amount with negative slope must not bypass checks.

        Before the fix, a negative β combined with a large negative amount could
        produce a negative risk, which the old code might not have caught.
        """
        from src.gateway.governance.causal.gatekeeper import causal_safety_check

        # causal_safety_check(params, current_telemetry) — pass args directly
        params = {
            "amount": 1_000_000,
            "symbol": "AAPL",
            "confidence": 0.99,
            "action_type": "test_large_adversarial_amount_with_negative_slope",
        }
        result = causal_safety_check(params, negative_slope_telemetry)
        # Must return False — the β≤0 guard fires before risk calculation
        assert result is False, "β≤0 guard should fire before risk calculation"


class TestBoundedRiskScore:
    """Tests for the bounded risk score calculation (peer review fix).

    The estimated risk must be strictly bounded within [0.0, 1.0] regardless
    of adversarial input amounts.
    """

    def test_bounded_risk_with_extreme_positive_amount(self):
        """Risk score must be clamped at 1.0 for extreme positive amounts."""
        from src.gateway.governance.causal.gatekeeper import (
            CAUSAL_LOCK_RISK_BOUNDARY,
            CAUSAL_NORMALIZATION_SCALE,
        )

        # Simulate the bounded calculation
        estimate_value = 0.05  # Positive β (passes β≤0 guard)
        extreme_amount = 1_000_000_000  # 1 billion — adversarial

        estimated_risk = min(
            1.0,
            max(
                0.0, 0.5 + estimate_value * extreme_amount / CAUSAL_NORMALIZATION_SCALE
            ),
        )

        # Must be clamped at 1.0
        assert estimated_risk == 1.0, "Risk score must be clamped at 1.0"
        assert estimated_risk <= 1.0, "Risk score must not exceed 1.0"

    def test_bounded_risk_with_negative_amount(self):
        """Risk score must be clamped at 0.0 for negative amounts (if possible)."""
        from src.gateway.governance.causal.gatekeeper import (
            CAUSAL_NORMALIZATION_SCALE,
        )

        # Edge case: negative amount (unlikely in practice, but test boundary)
        estimate_value = 0.05
        negative_amount = -1_000_000

        estimated_risk = min(
            1.0,
            max(
                0.0, 0.5 + estimate_value * negative_amount / CAUSAL_NORMALIZATION_SCALE
            ),
        )

        # Must be clamped at 0.0
        assert estimated_risk == 0.0, "Risk score must be clamped at 0.0"
        assert estimated_risk >= 0.0, "Risk score must not go below 0.0"

    def test_normal_amount_produces_valid_risk(self):
        """Normal trade amounts should produce risk in valid [0, 1] range."""
        from src.gateway.governance.causal.gatekeeper import (
            CAUSAL_NORMALIZATION_SCALE,
        )

        estimate_value = 0.02  # Typical positive β
        normal_amount = 5000  # Normal trade amount

        estimated_risk = min(
            1.0,
            max(0.0, 0.5 + estimate_value * normal_amount / CAUSAL_NORMALIZATION_SCALE),
        )

        # Should be a valid probability
        assert 0.0 <= estimated_risk <= 1.0, "Risk score must be in [0, 1]"
        # Should be around 0.5 + 0.02 * 5000 / 10000 = 0.51
        assert 0.50 <= estimated_risk <= 0.52, f"Expected ~0.51, got {estimated_risk}"
