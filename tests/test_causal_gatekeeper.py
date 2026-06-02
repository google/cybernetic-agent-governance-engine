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
"""

import numpy as np
import pandas as pd
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

pytestmark = pytest.mark.local


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def stable_telemetry():
    """Simulates a healthy system with clear, stable causal links."""
    np.random.seed(42)
    n = 200
    market_volatility = np.random.uniform(0.1, 0.9, n)
    trade_amount = np.random.normal(5000, 1000, n) - (market_volatility * 2000)
    trade_amount = np.clip(trade_amount, 100, 10000)
    risk_score = (market_volatility * 0.5) + (trade_amount / 10000 * 0.5) + np.random.normal(0, 0.05, n)
    risk_score = np.clip(risk_score, 0.0, 1.0)
    return pd.DataFrame({
        'market_volatility': market_volatility,
        'trade_amount': trade_amount,
        'risk_score': risk_score
    })


# ---------------------------------------------------------------------------
# Unit Tests — causal_safety_check directly
# ---------------------------------------------------------------------------

class TestCausalSafetyCheckUnit:
    """Unit tests for the causal_safety_check function."""

    def test_zero_amount_is_safe(self, stable_telemetry):
        """A trade with amount <= 0 should always be considered safe."""
        from src.gateway.governance.causal_gatekeeper import causal_safety_check
        result = causal_safety_check({"amount": 0}, stable_telemetry)
        assert result is True

    def test_negative_amount_is_safe(self, stable_telemetry):
        """A trade with negative amount should always be considered safe."""
        from src.gateway.governance.causal_gatekeeper import causal_safety_check
        result = causal_safety_check({"amount": -100}, stable_telemetry)
        assert result is True

    def test_small_trade_with_stable_data_passes(self, stable_telemetry):
        """A small trade against stable telemetry should pass the causal check."""
        from src.gateway.governance.causal_gatekeeper import causal_safety_check
        result = causal_safety_check({"amount": 1}, stable_telemetry)
        assert result is True

    def test_generate_mock_telemetry_shape(self):
        """The mock telemetry generator should produce the expected columns."""
        from src.gateway.governance.causal_gatekeeper import generate_mock_telemetry
        df = generate_mock_telemetry(n_samples=100)
        assert len(df) == 100
        assert set(df.columns) == {'market_volatility', 'trade_amount', 'risk_score'}

    def test_generate_mock_telemetry_deterministic(self):
        """Mock telemetry should be deterministic (seeded)."""
        from src.gateway.governance.causal_gatekeeper import generate_mock_telemetry
        df1 = generate_mock_telemetry(50)
        df2 = generate_mock_telemetry(50)
        pd.testing.assert_frame_equal(df1, df2)

    def test_causal_check_fails_safe_on_error(self):
        """If DoWhy raises an exception, the check should fail-safe (return False)."""
        from src.gateway.governance.causal_gatekeeper import causal_safety_check
        # Provide a DataFrame missing required columns to trigger an error
        bad_data = pd.DataFrame({'x': [1, 2, 3], 'y': [4, 5, 6]})
        result = causal_safety_check({"amount": 100}, bad_data)
        assert result is False


# ---------------------------------------------------------------------------
# Integration Tests — SymbolicGovernor with causal gatekeeper
# ---------------------------------------------------------------------------

class TestCausalGatekeeperIntegration:
    """Tests causal gatekeeper integration within the SymbolicGovernor."""

    def _create_mock_governor(self, telemetry_data=None):
        """Helper to create a SymbolicGovernor with all checks mocked except causal."""
        from src.gateway.governance.symbolic_governor import SymbolicGovernor
        from src.gateway.governance.contracts import SafetyFilter, ConsensusProvider
        from src.gateway.core.policy import OPAClient

        opa_client = MagicMock(spec=OPAClient)
        opa_client.evaluate_policy = AsyncMock(return_value={"decision": "ALLOW"})

        safety_filter = MagicMock(spec=SafetyFilter)
        safety_filter.verify_action = AsyncMock(return_value="SAFE")

        consensus_engine = MagicMock(spec=ConsensusProvider)
        consensus_engine.check_consensus = AsyncMock(
            return_value={"status": "APPROVE"}
        )

        telemetry_provider = None
        if telemetry_data is not None:
            telemetry_provider = MagicMock()
            telemetry_provider.get_latest_data.return_value = telemetry_data

        return SymbolicGovernor(
            opa_client=opa_client,
            safety_filter=safety_filter,
            consensus_engine=consensus_engine,
            stpa_validator=None,
            telemetry_provider=telemetry_provider,
        )

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
            "src.gateway.governance.causal_gatekeeper.causal_safety_check"
        ) as mock_check:
            mock_check.return_value = False
            result = await governor.verify("execute_trade", intent)

        causal_violations = [v for v in result["violations"] if "DoWhy refutation failed" in v]
        assert len(causal_violations) > 0

    @pytest.mark.asyncio
    async def test_governor_skips_causal_for_non_trade(self, stable_telemetry):
        """Causal gatekeeper should NOT run for non-trade actions."""
        governor = self._create_mock_governor(stable_telemetry)
        intent = {"query": "What is AAPL price?"}
        result = await governor.verify("market_lookup", intent)
        causal_violations = [v for v in result["violations"] if "Causal" in v]
        assert len(causal_violations) == 0
