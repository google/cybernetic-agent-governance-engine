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

"""Simulated reference data sources for the trade tool's STPA inputs.

These are Tier-2 reference backends for data, not for security primitives
(AGENTS.md, Completeness Principle). They stand in for a market-data vendor
feed and for the custodian's NAV / P&L feed. Each is deterministically
seedable and supports fault injection for every fail-closed path in
:mod:`src.cage_finance.tools.trade_inputs`. Each reuses the kernel's
:class:`~src.gateway.governance.seams.ground_truth.FaultMode` vocabulary.

The trade tool *measures* latency against these sources the same way it
would against a live feed. The simulation only decides when a quote was
published (``published_at``); the gateway computes the age from its own
clock. The market feed also publishes each symbol's average daily volume
(UCA-6), with its own fault channel so the quote and the volume can fail
independently.
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Callable

from src.cage_finance.invariants import CashBarrier
from src.cage_finance.tools.trade_inputs import DailyVolume, MarketQuote, NavSnapshot
from src.gateway.governance.seams.ground_truth import FaultMode

_FAULT_SHIFT_S = 3600.0
#: A stale daily-volume reading must be older than the four-day acceptance window.
_VOLUME_STALE_SHIFT_S = 30 * 24 * 3600.0


class SimulatedMarketQuoteFeed:
    """Deterministic market-data feed: latest quote and average daily volume.

    Each quote is published ``uniform(*publication_delay_ms)`` before the
    fetch, so its measured age lands in that range plus the fetch time. Every
    symbol's average daily volume is ``daily_volume`` shares (settable with
    :meth:`set_daily_volume`), computed at the start of the current day.
    :meth:`inject_fault` faults quotes; :meth:`inject_volume_fault` faults
    daily-volume readings.
    """

    source_id = "simulated:finance_market_feed"

    def __init__(
        self,
        *,
        seed: int | None = None,
        publication_delay_ms: tuple[float, float] = (5.0, 40.0),
        base_price: float = 100.0,
        daily_volume: float = 2_000_000.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        lo, hi = publication_delay_ms
        if not (0.0 <= lo <= hi):
            raise ValueError("publication_delay_ms must satisfy 0 <= lo <= hi")
        self._rng = random.Random(seed)
        self._delay_ms = (float(lo), float(hi))
        self._base_price = float(base_price)
        self._clock = clock
        self._fault = FaultMode.NONE
        self._volume_fault = FaultMode.NONE
        self.set_daily_volume(daily_volume)

    @property
    def fault_mode(self) -> FaultMode:
        return self._fault

    def inject_fault(self, mode: FaultMode | str) -> None:
        self._fault = FaultMode(mode)

    def clear_fault(self) -> None:
        self._fault = FaultMode.NONE

    def set_daily_volume(self, shares: float) -> None:
        if not float(shares) > 0.0:
            raise ValueError("daily_volume must be positive")
        self._daily_volume = float(shares)

    @property
    def volume_fault_mode(self) -> FaultMode:
        return self._volume_fault

    def inject_volume_fault(self, mode: FaultMode | str) -> None:
        self._volume_fault = FaultMode(mode)

    def clear_volume_fault(self) -> None:
        self._volume_fault = FaultMode.NONE

    async def average_daily_volume(self, symbol: str) -> DailyVolume:
        mode = self._volume_fault
        if mode is FaultMode.TIMEOUT:
            raise TimeoutError("simulated daily-volume timeout")
        if mode is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated daily-volume connection error")
        now = self._clock()
        as_of = now - (now % 86400.0)  # computed at the start of the UTC day
        shares = self._daily_volume
        source_id = self.source_id
        volume_symbol = symbol.upper()
        if mode is FaultMode.STALE_TIMESTAMP:
            as_of -= _VOLUME_STALE_SHIFT_S
        elif mode is FaultMode.FUTURE_TIMESTAMP:
            as_of = now + _FAULT_SHIFT_S
        elif mode is FaultMode.NAN_VALUE:
            shares = float("nan")
        elif mode is FaultMode.NEGATIVE_VALUE:
            shares = -shares
        elif mode is FaultMode.MALFORMED_PAYLOAD:
            volume_symbol = ""
        elif mode is FaultMode.UNVERIFIED_SOURCE:
            source_id = "unverified_rogue_feed"
        return DailyVolume(
            symbol=volume_symbol, shares=shares, as_of=as_of, source_id=source_id
        )

    async def latest_quote(self, symbol: str) -> MarketQuote:
        mode = self._fault
        if mode is FaultMode.TIMEOUT:
            raise TimeoutError("simulated market-data timeout")
        if mode is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated market-data connection error")
        published_at = self._clock() - self._rng.uniform(*self._delay_ms) / 1000.0
        price = self._base_price * (1.0 + self._rng.uniform(-0.01, 0.01))
        source_id = self.source_id
        quoted_symbol = symbol.upper()
        if mode is FaultMode.STALE_TIMESTAMP:
            published_at -= _FAULT_SHIFT_S
        elif mode is FaultMode.FUTURE_TIMESTAMP:
            published_at += _FAULT_SHIFT_S
        elif mode is FaultMode.NAN_VALUE:
            price = float("nan")
        elif mode is FaultMode.NEGATIVE_VALUE:
            price = -price
        elif mode is FaultMode.MALFORMED_PAYLOAD:
            quoted_symbol = ""
        elif mode is FaultMode.UNVERIFIED_SOURCE:
            source_id = "unverified_rogue_feed"
        return MarketQuote(
            symbol=quoted_symbol,
            price=price,
            published_at=published_at,
            source_id=source_id,
        )


class SimulatedPortfolioNavSource:
    """Deterministic portfolio NAV feed: opening NAV and a set daily drawdown.

    ``current_nav = open_nav * (1 - drawdown_pct / 100)``. The drawdown is
    whatever the scenario sets (:meth:`set_drawdown_pct`), so the UCA-5 path
    can be driven to any value.
    """

    source_id = "simulated:finance_portfolio_nav"

    def __init__(
        self,
        *,
        open_nav: float = CashBarrier.initial_state,
        drawdown_pct: float = 0.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not open_nav > 0.0:
            raise ValueError("open_nav must be positive")
        self._open_nav = float(open_nav)
        self._clock = clock
        self._fault = FaultMode.NONE
        self.set_drawdown_pct(drawdown_pct)

    @classmethod
    def from_env(cls) -> SimulatedPortfolioNavSource:
        """Build from ``CAGE_SIM_NAV_OPEN_USD`` / ``CAGE_SIM_NAV_DRAWDOWN_PCT``."""
        return cls(
            open_nav=float(
                os.environ.get("CAGE_SIM_NAV_OPEN_USD", CashBarrier.initial_state)
            ),
            drawdown_pct=float(os.environ.get("CAGE_SIM_NAV_DRAWDOWN_PCT", 0.0)),
        )

    def set_drawdown_pct(self, drawdown_pct: float) -> None:
        if not 0.0 <= float(drawdown_pct) <= 100.0:
            raise ValueError("drawdown_pct must be within [0, 100]")
        self._drawdown_pct = float(drawdown_pct)

    @property
    def fault_mode(self) -> FaultMode:
        return self._fault

    def inject_fault(self, mode: FaultMode | str) -> None:
        self._fault = FaultMode(mode)

    def clear_fault(self) -> None:
        self._fault = FaultMode.NONE

    async def fetch_nav(self) -> NavSnapshot:
        mode = self._fault
        if mode is FaultMode.TIMEOUT:
            raise TimeoutError("simulated NAV timeout")
        if mode is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated NAV connection error")
        open_nav = self._open_nav
        current_nav = open_nav * (1.0 - self._drawdown_pct / 100.0)
        observed_at = self._clock()
        source_id = self.source_id
        if mode is FaultMode.STALE_TIMESTAMP:
            observed_at -= _FAULT_SHIFT_S
        elif mode is FaultMode.FUTURE_TIMESTAMP:
            observed_at += _FAULT_SHIFT_S
        elif mode is FaultMode.NAN_VALUE:
            current_nav = float("nan")
        elif mode is FaultMode.NEGATIVE_VALUE:
            current_nav = -abs(current_nav) - 1.0
        elif mode is FaultMode.MALFORMED_PAYLOAD:
            open_nav = 0.0
        elif mode is FaultMode.UNVERIFIED_SOURCE:
            source_id = "unverified_rogue_feed"
        return NavSnapshot(
            open_nav=open_nav,
            current_nav=current_nav,
            observed_at=observed_at,
            source_id=source_id,
        )


__all__ = ["SimulatedMarketQuoteFeed", "SimulatedPortfolioNavSource"]
