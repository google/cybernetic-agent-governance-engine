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

"""Server-side STPA inputs for a governed trade: ``latency_ms`` and ``drawdown``.

UCA-2 / FIN-2 and UCA-5 read ``latency_ms`` and ``drawdown`` from the trade
params. The trade tool never takes either value from its caller. It measures
or reads them here, at the gateway tool boundary, for every committing run
(including the POST_HITL re-run after an approval).

``latency_ms`` (UCA-2 / FIN-2)
    FIN-2: "Agent must not execute trade if latency exceeds max_latency_ms";
    UCA-2: "Agent executes trade with stale market data". The value is the
    **age of the latest quote for the traded symbol when the gateway holds
    it**::

        latency_ms = (t_received - quote.published_at) * 1000

    ``t_received`` is the gateway's wall clock just after the quote fetch
    returns. ``published_at`` is the feed's publication timestamp for the
    quote. The age therefore includes feed-side publication-to-delivery
    delay and the gateway's fetch round trip. It excludes time spent later
    in governance and broker routing. A stale quote is not an error: it is
    measured, and UCA-2 refuses it against the regional ``max_latency_ms``.

``drawdown`` (UCA-5)
    The daily drawdown of the portfolio's net asset value, in percent::

        drawdown = max(0, (open_nav - current_nav) / open_nav * 100)

    The value comes from a :class:`PortfolioNavSource`, not from the custodian
    cash ledger. A cash ledger falls when the account *buys* securities, so
    deriving drawdown from it would count purchases as losses.

Fail closed: if a source is missing, times out, or returns a reading that
fails validation, the input is left out of the params. The generated UCA-2 /
UCA-5 rules then refuse the trade inside the governor, which records the
refusal in the evidence chain.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from src.gateway.governance.reconciliation.daemon import TTL_SECONDS

logger = logging.getLogger(__name__)

#: Upper bound on one source fetch; a slower source is treated as unavailable.
FETCH_TIMEOUT_S: float = 2.0

#: Future-timestamp tolerance, matching the reconciler's clock-skew default.
MAX_CLOCK_SKEW_S: float = 5.0

#: Oldest NAV reading accepted, matching the reconciler's verified-state TTL.
MAX_NAV_AGE_S: float = float(TTL_SECONDS)


@dataclass(frozen=True)
class MarketQuote:
    """One quote from a market-data feed."""

    symbol: str
    price: float
    #: Feed publication time of the quote (Unix epoch seconds).
    published_at: float
    source_id: str


@dataclass(frozen=True)
class NavSnapshot:
    """The portfolio's net asset value at the start of the day and now."""

    open_nav: float
    current_nav: float
    #: When the source computed ``current_nav`` (Unix epoch seconds).
    observed_at: float
    source_id: str


@runtime_checkable
class MarketQuoteFeed(Protocol):
    """Latest-quote reader for the traded instrument."""

    async def latest_quote(self, symbol: str) -> MarketQuote: ...


@runtime_checkable
class PortfolioNavSource(Protocol):
    """Reader for the portfolio's start-of-day and current net asset value."""

    async def fetch_nav(self) -> NavSnapshot: ...


class TradeInputUnavailable(RuntimeError):
    """A server-side STPA input could not be measured or trusted."""


def _verified(source_id: object) -> bool:
    return (
        isinstance(source_id, str)
        and bool(source_id)
        and not source_id.startswith("unverified")
    )


async def measure_market_data_latency_ms(
    feed: MarketQuoteFeed,
    symbol: str,
    *,
    clock: Callable[[], float] = time.time,
) -> float:
    """Return the age in ms of ``symbol``'s latest quote at the tool boundary.

    Raises:
        TradeInputUnavailable: the fetch fails or times out, or the quote is
            for another symbol, unverified, unpriced, or dated in the future.
    """
    try:
        quote = await asyncio.wait_for(feed.latest_quote(symbol), FETCH_TIMEOUT_S)
    except Exception as exc:
        raise TradeInputUnavailable(
            f"market-data fetch failed: {type(exc).__name__}: {exc}"
        ) from exc
    t_received = clock()

    if not isinstance(quote.symbol, str) or quote.symbol.upper() != symbol.upper():
        raise TradeInputUnavailable(f"quote is for {quote.symbol!r}, not {symbol!r}")
    if not _verified(quote.source_id):
        raise TradeInputUnavailable(
            f"unverified market-data source {quote.source_id!r}"
        )
    try:
        price = float(quote.price)
        published_at = float(quote.published_at)
    except (TypeError, ValueError) as exc:
        raise TradeInputUnavailable(f"malformed quote: {exc}") from exc
    if not math.isfinite(price) or price <= 0.0:
        raise TradeInputUnavailable(f"invalid quote price {price!r}")
    if not math.isfinite(published_at):
        raise TradeInputUnavailable("non-finite quote timestamp")
    age_s = t_received - published_at
    if age_s < -MAX_CLOCK_SKEW_S:
        raise TradeInputUnavailable(f"quote timestamp {-age_s:.1f}s in the future")
    return max(age_s, 0.0) * 1000.0


async def resolve_daily_drawdown_pct(
    source: PortfolioNavSource,
    *,
    clock: Callable[[], float] = time.time,
) -> float:
    """Return the portfolio's daily NAV drawdown in percent (0 when up on the day).

    Raises:
        TradeInputUnavailable: the fetch fails or times out, or the snapshot
            is unverified, non-finite, non-positive, stale, or future-dated.
    """
    try:
        snap = await asyncio.wait_for(source.fetch_nav(), FETCH_TIMEOUT_S)
    except Exception as exc:
        raise TradeInputUnavailable(
            f"NAV fetch failed: {type(exc).__name__}: {exc}"
        ) from exc
    if not _verified(snap.source_id):
        raise TradeInputUnavailable(f"unverified NAV source {snap.source_id!r}")
    try:
        open_nav = float(snap.open_nav)
        current_nav = float(snap.current_nav)
        observed_at = float(snap.observed_at)
    except (TypeError, ValueError) as exc:
        raise TradeInputUnavailable(f"malformed NAV snapshot: {exc}") from exc
    if not math.isfinite(open_nav) or open_nav <= 0.0:
        raise TradeInputUnavailable(f"invalid opening NAV {open_nav!r}")
    if not math.isfinite(current_nav) or current_nav < 0.0:
        raise TradeInputUnavailable(f"invalid current NAV {current_nav!r}")
    if not math.isfinite(observed_at):
        raise TradeInputUnavailable("non-finite NAV timestamp")
    age_s = clock() - observed_at
    if age_s > MAX_NAV_AGE_S:
        raise TradeInputUnavailable(
            f"stale NAV snapshot: age {age_s:.1f}s > {MAX_NAV_AGE_S:.1f}s"
        )
    if age_s < -MAX_CLOCK_SKEW_S:
        raise TradeInputUnavailable(f"NAV timestamp {-age_s:.1f}s in the future")
    return max(0.0, (open_nav - current_nav) / open_nav * 100.0)


@dataclass(frozen=True)
class ServerTradeInputs:
    """The gateway's sources for the STPA inputs of a governed trade.

    Built once by the finance plugin (the composition root) and bound into the
    trade tool, so a caller can never supply these values.
    """

    market_feed: MarketQuoteFeed | None
    nav_source: PortfolioNavSource | None

    async def resolve(self, symbol: str) -> dict[str, float]:
        """Return the measurable inputs for a trade in ``symbol``.

        An input that cannot be measured or trusted is left out and logged;
        the governor's STPA stage then refuses the trade.
        """
        inputs: dict[str, float] = {}
        if self.market_feed is None:
            logger.warning(
                "trade inputs: no market-data feed assembled (UCA-2 will refuse)"
            )
        else:
            try:
                inputs["latency_ms"] = await measure_market_data_latency_ms(
                    self.market_feed, symbol
                )
            except TradeInputUnavailable as exc:
                logger.warning(
                    "trade inputs: latency_ms unavailable (UCA-2 will refuse): %s", exc
                )
        if self.nav_source is None:
            logger.warning("trade inputs: no NAV source assembled (UCA-5 will refuse)")
        else:
            try:
                inputs["drawdown"] = await resolve_daily_drawdown_pct(self.nav_source)
            except TradeInputUnavailable as exc:
                logger.warning(
                    "trade inputs: drawdown unavailable (UCA-5 will refuse): %s", exc
                )
        return inputs


__all__ = [
    "FETCH_TIMEOUT_S",
    "MAX_CLOCK_SKEW_S",
    "MAX_NAV_AGE_S",
    "MarketQuote",
    "MarketQuoteFeed",
    "NavSnapshot",
    "PortfolioNavSource",
    "ServerTradeInputs",
    "TradeInputUnavailable",
    "measure_market_data_latency_ms",
    "resolve_daily_drawdown_pct",
]
