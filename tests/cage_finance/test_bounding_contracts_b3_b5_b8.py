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

"""Tests for bounding contracts B3, B5, B8 (market-data dependent contracts).

Phase 5 Step 5: Validates provider integration, staleness checks, and
fail-closed behavior when market data is unavailable.
"""

import time
from unittest.mock import MagicMock

import pytest

from src.cage_finance.safety.bounding.contracts import (
    contract_b3_liquidity_depth,
    contract_b5_volatility_sizing,
    contract_b8_twap_slippage,
)
from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.providers import StubMarketDataProvider


@pytest.fixture(autouse=True)
def _force_dev_env(monkeypatch):
    """Force CAGE_ENV=dev for stub provider tests."""
    monkeypatch.setenv("CAGE_ENV", "dev")


class TestContractB3LiquidityDepth:
    """Tests for B3 — Liquidity depth ratio verification."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B3."""
        return {
            "bounding": {"min_liquidity_depth_ratio": 2.0},
            "telemetry": {"max_staleness_seconds": 300},
        }

    @pytest.fixture
    def provider(self):
        """Stub market data provider."""
        return StubMarketDataProvider()

    def test_sufficient_liquidity_is_admitted(self, valid_thresholds, provider):
        """Trade with sufficient liquidity is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        # StubMarketDataProvider returns depth_usd=10M, so ratio = 10M / 1000 = 10000 >> 2.0
        result = contract_b3_liquidity_depth(request, valid_thresholds, provider)

        assert result.contract_id == "B3"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 0

    def test_insufficient_liquidity_escalates_to_hitl(self, provider):
        """Trade with insufficient liquidity escalates to HITL."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1_000_000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {
            "bounding": {"min_liquidity_depth_ratio": 50.0},  # Requires 50M depth
            "telemetry": {"max_staleness_seconds": 300},
        }
        # StubMarketDataProvider returns 10M depth, ratio = 10M / 1M = 10 < 50
        result = contract_b3_liquidity_depth(request, thresholds, provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 1
        assert result.findings[0]["reason"] == "Insufficient market liquidity depth"
        assert result.findings[0]["depth_ratio"] == 10.0
        assert result.findings[0]["min_required_ratio"] == 50.0

    def test_provider_unavailable_fails_closed(self, valid_thresholds):
        """Provider unavailable fails closed with HITL_ESCALATE."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_order_book_depth.side_effect = RuntimeError("Provider down")

        result = contract_b3_liquidity_depth(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Market data provider unavailable"

    def test_stale_data_fails_closed(self, valid_thresholds):
        """Stale market depth data fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_order_book_depth.return_value = {
            "depth_usd": 10_000_000.0,
            "timestamp": time.time() - 400,  # 400 seconds old (> 300s threshold)
            "levels_aggregated": 10,
        }

        result = contract_b3_liquidity_depth(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Market depth data is stale"

    def test_missing_threshold_fails_closed(self, provider):
        """Missing threshold configuration fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b3_liquidity_depth(request, {}, provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Missing threshold configuration"


class TestContractB5VolatilitySizing:
    """Tests for B5 — Volatility-adjusted position sizing cap."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B5."""
        return {
            "bounding": {
                "max_volatility_percentile": 70.0,
                "volatility_window_days": 30,
            },
            "telemetry": {"max_staleness_seconds": 300},
        }

    @pytest.fixture
    def provider(self):
        """Stub market data provider."""
        return StubMarketDataProvider()

    def test_low_volatility_is_admitted(self, valid_thresholds, provider):
        """Trade with low volatility is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        # StubMarketDataProvider returns percentile=30 < 70
        result = contract_b5_volatility_sizing(request, valid_thresholds, provider)

        assert result.contract_id == "B5"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 0

    def test_high_volatility_escalates_to_hitl(self, provider):
        """Trade with high volatility escalates to HITL."""
        request = BoundedTradeRequest(
            symbol="BTC", amount=10000.0, side="buy", venue="COINBASE"
        )
        thresholds = {
            "bounding": {
                "max_volatility_percentile": 20.0,  # Very strict threshold
                "volatility_window_days": 30,
            },
            "telemetry": {"max_staleness_seconds": 300},
        }
        # StubMarketDataProvider returns percentile=30 > 20
        result = contract_b5_volatility_sizing(request, thresholds, provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 1
        assert result.findings[0]["reason"] == "Asset volatility exceeds maximum threshold"
        assert result.findings[0]["volatility_percentile"] == 30.0
        assert result.findings[0]["max_percentile"] == 20.0

    def test_provider_unavailable_fails_closed(self, valid_thresholds):
        """Provider unavailable fails closed with HITL_ESCALATE."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_volatility_percentile.side_effect = RuntimeError("Provider down")

        result = contract_b5_volatility_sizing(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Market data provider unavailable"

    def test_stale_volatility_data_fails_closed(self, valid_thresholds):
        """Stale volatility data fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_volatility_percentile.return_value = {
            "percentile": 25.0,
            "annualized_vol": 0.15,
            "timestamp": time.time() - 400,  # Stale
        }

        result = contract_b5_volatility_sizing(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Volatility data is stale"

    def test_missing_threshold_fails_closed(self, provider):
        """Missing threshold configuration fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b5_volatility_sizing(request, {}, provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Missing threshold configuration"


class TestContractB8TwapSlippage:
    """Tests for B8 — TWAP slippage bound."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B8."""
        return {
            "bounding": {
                "max_twap_slippage_bps": 50.0,  # 0.5% slippage
                "twap_window_seconds": 300,
            },
            "telemetry": {"max_staleness_seconds": 300},
        }

    @pytest.fixture
    def provider(self):
        """Stub market data provider."""
        return StubMarketDataProvider()

    def test_low_slippage_is_admitted(self, valid_thresholds, provider):
        """Trade with low slippage is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        # StubMarketDataProvider returns zero slippage (twap_price = current_mid)
        result = contract_b8_twap_slippage(request, valid_thresholds, provider)

        assert result.contract_id == "B8"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 0

    def test_high_slippage_escalates_to_hitl(self, valid_thresholds):
        """Trade with high slippage escalates to HITL."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=10000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_recent_twap.return_value = {
            "twap_price": 100.0,
            "current_mid": 101.0,  # 1% slippage = 100 bps > 50 bps threshold
            "timestamp": time.time(),
        }

        result = contract_b8_twap_slippage(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 1
        assert result.findings[0]["reason"] == "TWAP slippage exceeds maximum threshold"
        assert result.findings[0]["slippage_bps"] == 100.0
        assert result.findings[0]["max_slippage_bps"] == 50.0

    def test_provider_unavailable_fails_closed(self, valid_thresholds):
        """Provider unavailable fails closed with HITL_ESCALATE."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_recent_twap.side_effect = RuntimeError("Provider down")

        result = contract_b8_twap_slippage(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Market data provider unavailable"

    def test_zero_twap_price_fails_closed(self, valid_thresholds):
        """Zero TWAP price fails closed (division by zero protection)."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_recent_twap.return_value = {
            "twap_price": 0.0,  # Invalid
            "current_mid": 100.0,
            "timestamp": time.time(),
        }

        result = contract_b8_twap_slippage(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "TWAP price is zero (cannot compute slippage)"

    def test_stale_twap_data_fails_closed(self, valid_thresholds):
        """Stale TWAP data fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_recent_twap.return_value = {
            "twap_price": 100.0,
            "current_mid": 100.0,
            "timestamp": time.time() - 400,  # Stale
        }

        result = contract_b8_twap_slippage(request, valid_thresholds, mock_provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "TWAP data is stale"

    def test_missing_threshold_fails_closed(self, provider):
        """Missing threshold configuration fails closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b8_twap_slippage(request, {}, provider)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Missing threshold configuration"


class TestMarketDataContractInteractions:
    """Integration tests for B3, B5, B8 contract interactions."""

    @pytest.fixture
    def provider(self):
        """Stub market data provider."""
        return StubMarketDataProvider()

    @pytest.fixture
    def permissive_thresholds(self):
        """Permissive thresholds that allow stub provider data to pass."""
        return {
            "bounding": {
                "min_liquidity_depth_ratio": 2.0,
                "max_volatility_percentile": 70.0,
                "max_twap_slippage_bps": 50.0,
                "volatility_window_days": 30,
                "twap_window_seconds": 300,
            },
            "telemetry": {"max_staleness_seconds": 300},
        }

    def test_all_market_contracts_pass_with_stub_provider(
        self, permissive_thresholds, provider
    ):
        """All three market contracts pass with permissive stub data."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )

        b3_result = contract_b3_liquidity_depth(request, permissive_thresholds, provider)
        b5_result = contract_b5_volatility_sizing(request, permissive_thresholds, provider)
        b8_result = contract_b8_twap_slippage(request, permissive_thresholds, provider)

        assert b3_result.admitted is True
        assert b5_result.admitted is True
        assert b8_result.admitted is True

    def test_provider_failure_cascades_to_all_contracts(self, permissive_thresholds):
        """Provider failure causes all market contracts to fail closed."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        mock_provider = MagicMock()
        mock_provider.get_order_book_depth.side_effect = RuntimeError("Provider down")
        mock_provider.get_volatility_percentile.side_effect = RuntimeError("Provider down")
        mock_provider.get_recent_twap.side_effect = RuntimeError("Provider down")

        b3_result = contract_b3_liquidity_depth(request, permissive_thresholds, mock_provider)
        b5_result = contract_b5_volatility_sizing(request, permissive_thresholds, mock_provider)
        b8_result = contract_b8_twap_slippage(request, permissive_thresholds, mock_provider)

        assert b3_result.admitted is False
        assert b5_result.admitted is False
        assert b8_result.admitted is False
