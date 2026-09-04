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

"""Provider protocols and stub implementations for bounding contracts.

Phase 5 Master Plan Step 3: Defines protocols for market data and rollback
capability providers required by contracts B3, B5, B8, and B10.

Per Ratified Decision 3 (Section 12):
- Stub providers hard-fail when CAGE_ENV=production
- Stub providers return permissive mock data in dev/test environments
- Production deployments must inject real provider implementations

Contracts requiring external providers:
- B3 (Liquidity depth ratio): MarketDataProvider.get_order_book_depth()
- B5 (Volatility-adjusted sizing): MarketDataProvider.get_volatility_percentile()
- B8 (TWAP slippage bound): MarketDataProvider.get_recent_twap()
- B10 (Rollback window validation): RollbackCapabilityProvider.verify_rollback_window()
"""

import logging
import os
from typing import Protocol

logger = logging.getLogger(__name__)


class MarketDataProvider(Protocol):
    """Protocol for market data provider used by bounding contracts.

    Contracts B3, B5, and B8 require market data to evaluate liquidity,
    volatility, and TWAP slippage bounds. This protocol abstracts the
    data source (e.g., Bloomberg, Refinitiv, exchange APIs).

    Fail-closed semantics:
    - Provider unavailable → contract returns admitted=False, severity=HARD_BLOCK
    - Non-finite data (NaN/inf) → contract returns admitted=False, severity=HARD_BLOCK
    - Stale data (timestamp too old) → contract returns admitted=False, severity=HARD_BLOCK
    """

    def get_order_book_depth(
        self, symbol: str, venue: str, side: str
    ) -> dict[str, float]:
        """Fetch order book depth for liquidity validation (Contract B3).

        Args:
            symbol: Ticker symbol (e.g., 'AAPL', 'BTC')
            venue: Execution venue (e.g., 'NYSE', 'NASDAQ', 'COINBASE')
            side: Trade direction ('buy' or 'sell')

        Returns:
            Dict with keys:
            - 'depth_usd': Total USD liquidity available at best N price levels
            - 'timestamp': Unix epoch timestamp of the order book snapshot
            - 'levels_aggregated': Number of price levels aggregated

        Raises:
            RuntimeError: If provider is unavailable or data is corrupt
        """
        ...

    def get_volatility_percentile(
        self, symbol: str, window_days: int
    ) -> dict[str, float]:
        """Fetch rolling volatility percentile for sizing validation (Contract B5).

        Args:
            symbol: Ticker symbol (e.g., 'AAPL', 'BTC')
            window_days: Historical window in days (e.g., 30, 60, 90)

        Returns:
            Dict with keys:
            - 'percentile': Current volatility as percentile (0-100)
            - 'annualized_vol': Annualized volatility (decimal, e.g., 0.25 = 25%)
            - 'timestamp': Unix epoch timestamp of the calculation

        Raises:
            RuntimeError: If provider is unavailable or data is corrupt
        """
        ...

    def get_recent_twap(
        self, symbol: str, venue: str, window_seconds: int
    ) -> dict[str, float]:
        """Fetch recent TWAP for slippage validation (Contract B8).

        Args:
            symbol: Ticker symbol (e.g., 'AAPL', 'BTC')
            venue: Execution venue (e.g., 'NYSE', 'NASDAQ', 'COINBASE')
            window_seconds: TWAP window in seconds (e.g., 60, 300, 900)

        Returns:
            Dict with keys:
            - 'twap_price': Time-weighted average price over the window
            - 'current_mid': Current bid-ask midpoint price
            - 'timestamp': Unix epoch timestamp of the TWAP calculation

        Raises:
            RuntimeError: If provider is unavailable or data is corrupt
        """
        ...


class RollbackCapabilityProvider(Protocol):
    """Protocol for rollback capability provider used by Contract B10.

    Contract B10 validates that the execution venue supports rollback/cancellation
    within the specified rollback_window_seconds. This justifies the
    EXTERNALLY_REVERSIBLE classification for execute_trade_bounded.

    Fail-closed semantics:
    - Provider unavailable → contract returns admitted=False, severity=HARD_BLOCK
    - Venue does not support rollback → contract returns admitted=False, severity=HARD_BLOCK
    - Rollback window exceeds venue capability → emit classification override
      to IRREVERSIBLE_TERMINAL (per Ratified Decision 2)
    """

    def verify_rollback_window(
        self, venue: str, rollback_window_seconds: int
    ) -> dict[str, bool | int]:
        """Verify venue supports rollback within the requested window (Contract B10).

        Args:
            venue: Execution venue (e.g., 'NYSE', 'NASDAQ', 'COINBASE')
            rollback_window_seconds: Requested rollback window in seconds

        Returns:
            Dict with keys:
            - 'supported': True if venue supports rollback
            - 'max_window_seconds': Maximum rollback window the venue supports
            - 'api_available': True if rollback API is currently operational

        Raises:
            RuntimeError: If provider is unavailable or venue metadata is corrupt
        """
        ...


class StubMarketDataProvider:
    """Stub market data provider for dev/test environments.

    Per Ratified Decision 3 (Section 12):
    - Hard-fails when CAGE_ENV=production
    - Returns permissive mock data in dev/test environments
    - Mock data is designed to pass contracts B3, B5, B8 by default

    WARNING: Do not use in production. Inject a real MarketDataProvider
    implementation (e.g., BloombergMarketDataProvider, RefinitivMarketDataProvider).
    """

    def __init__(self) -> None:
        """Initialize stub provider with environment check."""
        cage_env = os.getenv("CAGE_ENV", "dev").lower()
        if cage_env in ("production", "prod"):
            raise RuntimeError(
                "StubMarketDataProvider cannot be used when CAGE_ENV=production. "
                "Inject a real MarketDataProvider implementation (e.g., Bloomberg, Refinitiv)."
            )
        logger.warning(
            "⚠️  StubMarketDataProvider active (CAGE_ENV=%s) — returns permissive mock data. "
            "Replace with real provider before production deployment.",
            cage_env,
        )

    def get_order_book_depth(
        self, symbol: str, venue: str, side: str
    ) -> dict[str, float]:
        """Return permissive mock order book depth (always deep liquidity)."""
        import time

        return {
            "depth_usd": 10_000_000.0,  # $10M liquidity (passes B3 depth ratio check)
            "timestamp": time.time(),
            "levels_aggregated": 10,
        }

    def get_volatility_percentile(
        self, symbol: str, window_days: int
    ) -> dict[str, float]:
        """Return permissive mock volatility (always low volatility percentile)."""
        import time

        return {
            "percentile": 30.0,  # 30th percentile (low volatility, passes B5 check)
            "annualized_vol": 0.15,  # 15% annualized volatility
            "timestamp": time.time(),
        }

    def get_recent_twap(
        self, symbol: str, venue: str, window_seconds: int
    ) -> dict[str, float]:
        """Return permissive mock TWAP (zero slippage)."""
        import time

        return {
            "twap_price": 100.0,  # Mock price
            "current_mid": 100.0,  # Zero slippage (passes B8 TWAP check)
            "timestamp": time.time(),
        }


class StubRollbackCapabilityProvider:
    """Stub rollback capability provider for dev/test environments.

    Per Ratified Decision 3 (Section 12):
    - Hard-fails when CAGE_ENV=production
    - Returns permissive mock rollback capability in dev/test environments
    - Mock data assumes all venues support 5-minute rollback windows

    WARNING: Do not use in production. Inject a real RollbackCapabilityProvider
    implementation that queries venue APIs for actual rollback capabilities.
    """

    def __init__(self) -> None:
        """Initialize stub provider with environment check."""
        cage_env = os.getenv("CAGE_ENV", "dev").lower()
        if cage_env in ("production", "prod"):
            raise RuntimeError(
                "StubRollbackCapabilityProvider cannot be used when CAGE_ENV=production. "
                "Inject a real RollbackCapabilityProvider implementation."
            )
        logger.warning(
            "⚠️  StubRollbackCapabilityProvider active (CAGE_ENV=%s) — returns permissive mock data. "
            "Replace with real provider before production deployment.",
            cage_env,
        )

    def verify_rollback_window(
        self, venue: str, rollback_window_seconds: int
    ) -> dict[str, bool | int]:
        """Return permissive mock rollback capability (always supports 5-minute window)."""
        return {
            "supported": True,
            "max_window_seconds": 300,  # 5 minutes (default rollback window)
            "api_available": True,
        }
