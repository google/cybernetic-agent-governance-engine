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

"""Tests for bounding contract provider protocols and stub implementations.

Phase 5 Step 3: Validates that stub providers hard-fail when CAGE_ENV=production
and return permissive mock data in dev/test environments.
"""

import time

import pytest

from src.cage_finance.safety.bounding.providers import (
    MarketDataProvider,
    RollbackCapabilityProvider,
    StubMarketDataProvider,
    StubRollbackCapabilityProvider,
)


class TestMarketDataProviderProtocol:
    """Tests for MarketDataProvider protocol structure."""

    def test_protocol_has_get_order_book_depth_method(self):
        """MarketDataProvider protocol must define get_order_book_depth()."""
        assert hasattr(MarketDataProvider, "get_order_book_depth")

    def test_protocol_has_get_volatility_percentile_method(self):
        """MarketDataProvider protocol must define get_volatility_percentile()."""
        assert hasattr(MarketDataProvider, "get_volatility_percentile")

    def test_protocol_has_get_recent_twap_method(self):
        """MarketDataProvider protocol must define get_recent_twap()."""
        assert hasattr(MarketDataProvider, "get_recent_twap")


class TestRollbackCapabilityProviderProtocol:
    """Tests for RollbackCapabilityProvider protocol structure."""

    def test_protocol_has_verify_rollback_window_method(self):
        """RollbackCapabilityProvider protocol must define verify_rollback_window()."""
        assert hasattr(RollbackCapabilityProvider, "verify_rollback_window")


class TestStubMarketDataProviderDevEnvironment:
    """Tests for StubMarketDataProvider in dev/test environments."""

    @pytest.fixture(autouse=True)
    def _force_dev_env(self, monkeypatch):
        """Force CAGE_ENV=dev for these tests."""
        monkeypatch.setenv("CAGE_ENV", "dev")

    def test_stub_provider_initializes_in_dev_env(self):
        """StubMarketDataProvider initializes successfully when CAGE_ENV=dev."""
        provider = StubMarketDataProvider()
        assert provider is not None

    def test_get_order_book_depth_returns_permissive_data(self):
        """get_order_book_depth() returns deep liquidity mock data."""
        provider = StubMarketDataProvider()
        depth = provider.get_order_book_depth(symbol="AAPL", venue="NASDAQ", side="buy")

        assert "depth_usd" in depth
        assert "timestamp" in depth
        assert "levels_aggregated" in depth

        # Permissive mock: deep liquidity (should pass B3 contract)
        assert depth["depth_usd"] >= 1_000_000.0
        assert isinstance(depth["timestamp"], float)
        assert depth["levels_aggregated"] > 0

    def test_get_order_book_depth_timestamp_is_recent(self):
        """get_order_book_depth() timestamp is current (not stale)."""
        provider = StubMarketDataProvider()
        depth = provider.get_order_book_depth(
            symbol="BTC", venue="COINBASE", side="sell"
        )

        now = time.time()
        assert abs(depth["timestamp"] - now) < 5.0  # Within 5 seconds

    def test_get_volatility_percentile_returns_permissive_data(self):
        """get_volatility_percentile() returns low volatility mock data."""
        provider = StubMarketDataProvider()
        vol = provider.get_volatility_percentile(symbol="AAPL", window_days=30)

        assert "percentile" in vol
        assert "annualized_vol" in vol
        assert "timestamp" in vol

        # Permissive mock: low volatility percentile (should pass B5 contract)
        assert 0 <= vol["percentile"] <= 50  # Low volatility
        assert 0 <= vol["annualized_vol"] <= 0.3  # Reasonable volatility
        assert isinstance(vol["timestamp"], float)

    def test_get_recent_twap_returns_permissive_data(self):
        """get_recent_twap() returns zero slippage mock data."""
        provider = StubMarketDataProvider()
        twap = provider.get_recent_twap(
            symbol="AAPL", venue="NASDAQ", window_seconds=300
        )

        assert "twap_price" in twap
        assert "current_mid" in twap
        assert "timestamp" in twap

        # Permissive mock: zero slippage (should pass B8 contract)
        assert twap["twap_price"] > 0
        assert twap["current_mid"] > 0
        assert (
            abs(twap["twap_price"] - twap["current_mid"]) < 0.01
        )  # Near-zero slippage
        assert isinstance(twap["timestamp"], float)

    def test_stub_provider_works_in_test_env(self, monkeypatch):
        """StubMarketDataProvider works when CAGE_ENV=test."""
        monkeypatch.setenv("CAGE_ENV", "test")
        provider = StubMarketDataProvider()
        depth = provider.get_order_book_depth(
            symbol="TEST", venue="TEST_VENUE", side="buy"
        )
        assert depth["depth_usd"] > 0


class TestStubMarketDataProviderProductionFailure:
    """Tests for StubMarketDataProvider production hard-fail."""

    def test_stub_provider_raises_when_cage_env_production(self, monkeypatch):
        """StubMarketDataProvider raises RuntimeError when CAGE_ENV=production.

        Per Ratified Decision 3 (Section 12): Stub providers must hard-fail
        when CAGE_ENV=production to prevent accidental production deployment
        with permissive mock data.
        """
        monkeypatch.setenv("CAGE_ENV", "production")

        with pytest.raises(
            RuntimeError,
            match="StubMarketDataProvider cannot be used when CAGE_ENV=production",
        ):
            StubMarketDataProvider()

    def test_stub_provider_raises_when_cage_env_prod(self, monkeypatch):
        """StubMarketDataProvider raises when CAGE_ENV=prod (case-insensitive)."""
        monkeypatch.setenv("CAGE_ENV", "prod")

        with pytest.raises(
            RuntimeError,
            match="StubMarketDataProvider cannot be used when CAGE_ENV=production",
        ):
            StubMarketDataProvider()


class TestStubRollbackCapabilityProviderDevEnvironment:
    """Tests for StubRollbackCapabilityProvider in dev/test environments."""

    @pytest.fixture(autouse=True)
    def _force_dev_env(self, monkeypatch):
        """Force CAGE_ENV=dev for these tests."""
        monkeypatch.setenv("CAGE_ENV", "dev")

    def test_stub_provider_initializes_in_dev_env(self):
        """StubRollbackCapabilityProvider initializes when CAGE_ENV=dev."""
        provider = StubRollbackCapabilityProvider()
        assert provider is not None

    def test_verify_rollback_window_returns_permissive_data(self):
        """verify_rollback_window() returns permissive mock capability."""
        provider = StubRollbackCapabilityProvider()
        result = provider.verify_rollback_window(
            venue="NASDAQ", rollback_window_seconds=300
        )

        assert "supported" in result
        assert "max_window_seconds" in result
        assert "api_available" in result

        # Permissive mock: always supports 5-minute rollback (should pass B10 contract)
        assert result["supported"] is True
        assert result["max_window_seconds"] >= 300
        assert result["api_available"] is True

    def test_verify_rollback_window_accepts_any_venue(self):
        """verify_rollback_window() returns permissive data for any venue."""
        provider = StubRollbackCapabilityProvider()

        test_venues = ["NYSE", "NASDAQ", "COINBASE", "UNKNOWN_VENUE"]
        for venue in test_venues:
            result = provider.verify_rollback_window(
                venue=venue, rollback_window_seconds=300
            )
            assert result["supported"] is True

    def test_verify_rollback_window_accepts_any_window(self):
        """verify_rollback_window() returns permissive data for any window <= 300s."""
        provider = StubRollbackCapabilityProvider()

        test_windows = [60, 120, 300]
        for window in test_windows:
            result = provider.verify_rollback_window(
                venue="NASDAQ", rollback_window_seconds=window
            )
            assert result["supported"] is True
            assert result["max_window_seconds"] >= window


class TestStubRollbackCapabilityProviderProductionFailure:
    """Tests for StubRollbackCapabilityProvider production hard-fail."""

    def test_stub_provider_raises_when_cage_env_production(self, monkeypatch):
        """StubRollbackCapabilityProvider raises when CAGE_ENV=production.

        Per Ratified Decision 3 (Section 12): Stub providers must hard-fail
        when CAGE_ENV=production to prevent accidental production deployment
        with permissive mock data.
        """
        monkeypatch.setenv("CAGE_ENV", "production")

        with pytest.raises(
            RuntimeError,
            match="StubRollbackCapabilityProvider cannot be used when CAGE_ENV=production",
        ):
            StubRollbackCapabilityProvider()

    def test_stub_provider_raises_when_cage_env_prod(self, monkeypatch):
        """StubRollbackCapabilityProvider raises when CAGE_ENV=prod."""
        monkeypatch.setenv("CAGE_ENV", "prod")

        with pytest.raises(
            RuntimeError,
            match="StubRollbackCapabilityProvider cannot be used when CAGE_ENV=production",
        ):
            StubRollbackCapabilityProvider()


class TestProviderIntegrationScenarios:
    """Integration tests for provider usage in bounding contracts."""

    @pytest.fixture(autouse=True)
    def _force_dev_env(self, monkeypatch):
        """Force CAGE_ENV=dev for these tests."""
        monkeypatch.setenv("CAGE_ENV", "dev")

    def test_market_data_provider_supports_b3_liquidity_check(self):
        """MarketDataProvider provides data required for B3 liquidity depth check."""
        provider = StubMarketDataProvider()
        depth = provider.get_order_book_depth(symbol="AAPL", venue="NASDAQ", side="buy")

        # B3 contract needs depth_usd to compute depth ratio
        assert depth["depth_usd"] > 0
        # Contract will compare: depth_usd / trade_amount >= threshold

    def test_market_data_provider_supports_b5_volatility_check(self):
        """MarketDataProvider provides data required for B5 volatility sizing check."""
        provider = StubMarketDataProvider()
        vol = provider.get_volatility_percentile(symbol="BTC", window_days=60)

        # B5 contract needs percentile to adjust position sizing
        assert 0 <= vol["percentile"] <= 100
        assert vol["annualized_vol"] >= 0

    def test_market_data_provider_supports_b8_twap_check(self):
        """MarketDataProvider provides data required for B8 TWAP slippage check."""
        provider = StubMarketDataProvider()
        twap = provider.get_recent_twap(
            symbol="AAPL", venue="NASDAQ", window_seconds=300
        )

        # B8 contract needs twap_price and current_mid to compute slippage
        assert twap["twap_price"] > 0
        assert twap["current_mid"] > 0
        # Contract will compute: abs(current_mid - twap_price) / twap_price <= threshold

    def test_rollback_provider_supports_b10_window_check(self):
        """RollbackCapabilityProvider provides data required for B10 rollback window check."""
        provider = StubRollbackCapabilityProvider()
        result = provider.verify_rollback_window(
            venue="NASDAQ", rollback_window_seconds=300
        )

        # B10 contract needs supported flag and max_window_seconds
        assert isinstance(result["supported"], bool)
        assert isinstance(result["max_window_seconds"], int)
        assert isinstance(result["api_available"], bool)
        # Contract will check: supported and max_window_seconds >= requested_window

    def test_all_stub_providers_can_be_instantiated_together(self):
        """All stub providers can coexist in the same process (no singletons)."""
        market_provider = StubMarketDataProvider()
        rollback_provider = StubRollbackCapabilityProvider()

        assert market_provider is not None
        assert rollback_provider is not None
        assert market_provider is not rollback_provider
