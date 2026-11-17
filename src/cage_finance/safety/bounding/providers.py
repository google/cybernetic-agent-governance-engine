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

"""Provider protocols and posture-gated implementations for bounding contracts.

Phase 5 Master Plan Step 3: Defines protocols for market data and rollback
capability providers required by contracts B3, B5, B8, and B10.

Posture enforcement ([DA-06]):
- StubMarketDataProvider and StubRollbackCapabilityProvider hard-fail whenever
  ``is_enforcing(resolve_posture())`` is True (production, staging, local, or
  unset/unknown CAGE_ENV).
- UnconfiguredEnforcingMarketDataProvider and UnconfiguredEnforcingRollbackProvider
  instantiate cleanly during governor assembly in enforcing postures (allowing
  check_balance, execute_trade, market_analysis, and canary probes to operate)
  while failing closed whenever execute_trade_bounded evaluates B3/B5/B8/B10.
"""

import logging
import time
from typing import Protocol

from src.gateway.governance.env_posture import is_enforcing, resolve_posture

logger = logging.getLogger(__name__)


class UnconfiguredEnforcingProviderError(RuntimeError):
    """Raised when an enforcing-posture bounding provider has not been configured."""


class MarketDataProvider(Protocol):
    """Protocol for market data provider used by bounding contracts."""

    def get_order_book_depth(
        self, symbol: str, venue: str, side: str
    ) -> dict[str, float]:
        """Fetch order book depth for liquidity validation (Contract B3)."""
        ...

    def get_volatility_percentile(
        self, symbol: str, window_days: int
    ) -> dict[str, float]:
        """Fetch rolling volatility percentile for sizing validation (Contract B5)."""
        ...

    def get_recent_twap(
        self, symbol: str, venue: str, window_seconds: int
    ) -> dict[str, float]:
        """Fetch recent TWAP for slippage validation (Contract B8)."""
        ...


class RollbackCapabilityProvider(Protocol):
    """Protocol for rollback capability provider used by Contract B10."""

    def verify_rollback_window(
        self, venue: str, rollback_window_seconds: int
    ) -> dict[str, bool | int]:
        """Verify venue supports rollback within the requested window (Contract B10)."""
        ...


class UnconfiguredEnforcingMarketDataProvider:
    """Fail-closed market data provider wired in enforcing postures when unconfigured."""

    def get_order_book_depth(
        self, symbol: str, venue: str, side: str
    ) -> dict[str, float]:
        raise UnconfiguredEnforcingProviderError(
            f"Live MarketDataProvider is unconfigured in enforcing posture "
            f"(cannot evaluate order book depth for {symbol} on {venue})."
        )

    def get_volatility_percentile(
        self, symbol: str, window_days: int
    ) -> dict[str, float]:
        raise UnconfiguredEnforcingProviderError(
            f"Live MarketDataProvider is unconfigured in enforcing posture "
            f"(cannot evaluate {window_days}d volatility for {symbol})."
        )

    def get_recent_twap(
        self, symbol: str, venue: str, window_seconds: int
    ) -> dict[str, float]:
        raise UnconfiguredEnforcingProviderError(
            f"Live MarketDataProvider is unconfigured in enforcing posture "
            f"(cannot evaluate {window_seconds}s TWAP for {symbol} on {venue})."
        )


class UnconfiguredEnforcingRollbackProvider:
    """Fail-closed rollback capability provider wired in enforcing postures when unconfigured."""

    def verify_rollback_window(
        self, venue: str, rollback_window_seconds: int
    ) -> dict[str, bool | int]:
        raise UnconfiguredEnforcingProviderError(
            f"Live RollbackCapabilityProvider is unconfigured in enforcing posture "
            f"(cannot verify {rollback_window_seconds}s rollback window on {venue})."
        )


class StubMarketDataProvider:
    """Stub market data provider for permissive dev/test/ci environments only."""

    def __init__(self) -> None:
        """Initialize stub provider with enforcing-posture guard."""
        posture = resolve_posture()
        if is_enforcing(posture):
            raise RuntimeError(
                f"StubMarketDataProvider cannot be used when CAGE_ENV={posture.value} "
                "(enforcing posture). Inject a real MarketDataProvider implementation "
                "(e.g., Bloomberg, Refinitiv)."
            )
        logger.warning(
            "⚠️  StubMarketDataProvider active (posture=%s) — returns permissive mock data. "
            "Replace with real provider before staging/production deployment.",
            posture.value,
        )

    def get_order_book_depth(
        self, symbol: str, venue: str, side: str
    ) -> dict[str, float]:
        """Return permissive mock order book depth (always deep liquidity)."""
        return {
            "depth_usd": 10_000_000.0,
            "timestamp": time.time(),
            "levels_aggregated": 10,
        }

    def get_volatility_percentile(
        self, symbol: str, window_days: int
    ) -> dict[str, float]:
        """Return permissive mock volatility (always low volatility percentile)."""
        _ = window_days
        return {
            "percentile": 30.0,
            "annualized_vol": 0.15,
            "timestamp": time.time(),
        }

    def get_recent_twap(
        self, symbol: str, venue: str, window_seconds: int
    ) -> dict[str, float]:
        """Return permissive mock TWAP (zero slippage)."""
        return {
            "twap_price": 100.0,
            "current_mid": 100.0,
            "timestamp": time.time(),
        }


class StubRollbackCapabilityProvider:
    """Stub rollback capability provider for permissive dev/test/ci environments only."""

    def __init__(self) -> None:
        """Initialize stub provider with enforcing-posture guard."""
        posture = resolve_posture()
        if is_enforcing(posture):
            raise RuntimeError(
                f"StubRollbackCapabilityProvider cannot be used when CAGE_ENV={posture.value} "
                "(enforcing posture). Inject a real RollbackCapabilityProvider implementation."
            )
        logger.warning(
            "⚠️  StubRollbackCapabilityProvider active (posture=%s) — returns permissive mock data. "
            "Replace with real provider before staging/production deployment.",
            posture.value,
        )

    def verify_rollback_window(
        self, venue: str, rollback_window_seconds: int
    ) -> dict[str, bool | int]:
        """Return permissive mock rollback capability (always supports 5-minute window)."""
        return {
            "supported": True,
            "max_window_seconds": 300,
            "api_available": True,
        }
