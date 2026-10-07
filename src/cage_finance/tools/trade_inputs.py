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

"""Server-side STPA inputs for a governed trade.

UCA-2 / FIN-2 read ``latency_ms``, UCA-5 reads ``drawdown`` and, for a sell,
UCA-13 / FIN-1 reads ``portfolio_total`` from the trade params. The trade tool
never takes any of these values from its caller. It measures or reads them
here, at the gateway tool boundary, for every committing run (including the
POST_HITL re-run after an approval).

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

``portfolio_total`` (UCA-13 / FIN-1, sells only)
    The portfolio's current net asset value, ``current_nav``, from the same
    NAV snapshot as ``drawdown``. FIN-1 bounds a sell to
    ``stpa.max_sell_portfolio_fraction`` of the whole portfolio, so the
    denominator is NAV (cash plus marked positions), not the cash balance.
    A NAV of zero is a valid drawdown reading but no basis for a sell
    fraction, so it leaves ``portfolio_total`` unset.

Every NAV reading gets the checks the reconciler applies before it trusts a
ground-truth snapshot (:func:`fetch_verified_nav`): verified source, finite
values, positive opening NAV, an age within the reconciler's TTL, and no more
than :data:`MAX_CLOCK_SKEW_S` of future skew. One snapshot is fetched per
trade, so ``drawdown`` and ``portfolio_total`` always describe the same
moment.

:class:`TradeInputResolver` is the finance plugin's ``execute_trade``
:class:`~src.gateway.governance.contracts.ServerInputResolver`. The kernel
applies it on every path that evaluates a trade (``validate-action`` and the
other previews, and the committing run in the trade tool). It drops any caller
value for these keys, including the UCA-5 aliases ``portfolio_drawdown_pct``
and ``current_drawdown``, so a preview and the binding run see the same
measured values.

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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

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


async def fetch_verified_nav(
    source: PortfolioNavSource,
    *,
    clock: Callable[[], float] = time.time,
) -> NavSnapshot:
    """Fetch one NAV snapshot and return it, normalised, if it can be trusted.

    Raises:
        TradeInputUnavailable: the fetch fails or times out, or the snapshot
            is unverified, non-finite, has a non-positive opening NAV or a
            negative current NAV, is older than the reconciler TTL, or is
            dated more than :data:`MAX_CLOCK_SKEW_S` in the future.
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
    return NavSnapshot(
        open_nav=open_nav,
        current_nav=current_nav,
        observed_at=observed_at,
        source_id=snap.source_id,
    )


def daily_drawdown_pct(snap: NavSnapshot) -> float:
    """Return the daily NAV drawdown in percent (0 when up on the day)."""
    return max(0.0, (snap.open_nav - snap.current_nav) / snap.open_nav * 100.0)


def portfolio_total(snap: NavSnapshot) -> float:
    """Return the FIN-1 denominator: the current NAV.

    Raises:
        TradeInputUnavailable: the current NAV is not positive.
    """
    if snap.current_nav <= 0.0:
        raise TradeInputUnavailable(
            f"current NAV {snap.current_nav!r} is no basis for a sell fraction"
        )
    return snap.current_nav


async def resolve_daily_drawdown_pct(
    source: PortfolioNavSource,
    *,
    clock: Callable[[], float] = time.time,
) -> float:
    """Return the daily NAV drawdown in percent from one verified snapshot."""
    return daily_drawdown_pct(await fetch_verified_nav(source, clock=clock))


async def resolve_portfolio_total(
    source: PortfolioNavSource,
    *,
    clock: Callable[[], float] = time.time,
) -> float:
    """Return the current NAV from one verified snapshot (FIN-1 denominator)."""
    return portfolio_total(await fetch_verified_nav(source, clock=clock))


@dataclass(frozen=True)
class ServerTradeInputs:
    """The gateway's sources for the STPA inputs of a governed trade.

    Built once by the finance plugin (the composition root) and bound into the
    trade tool, so a caller can never supply these values.
    """

    market_feed: MarketQuoteFeed | None
    nav_source: PortfolioNavSource | None

    async def resolve(self, symbol: str, *, side: str) -> dict[str, float]:
        """Return the measurable inputs for a ``side`` trade in ``symbol``.

        ``latency_ms`` and ``drawdown`` are resolved for every trade;
        ``portfolio_total`` only for a sell, from the same NAV snapshot as
        ``drawdown``. An input that cannot be measured or trusted is left out
        and logged; the governor's STPA stage then refuses the trade.
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
        refusing = "UCA-5 / UCA-13" if side == "sell" else "UCA-5"
        if self.nav_source is None:
            logger.warning(
                "trade inputs: no NAV source assembled (%s will refuse)", refusing
            )
            return inputs
        try:
            nav = await fetch_verified_nav(self.nav_source)
        except TradeInputUnavailable as exc:
            logger.warning(
                "trade inputs: NAV unavailable (%s will refuse): %s", refusing, exc
            )
            return inputs
        inputs["drawdown"] = daily_drawdown_pct(nav)
        if side == "sell":
            try:
                inputs["portfolio_total"] = portfolio_total(nav)
            except TradeInputUnavailable as exc:
                logger.warning(
                    "trade inputs: portfolio_total unavailable (UCA-13 will "
                    "refuse): %s",
                    exc,
                )
        return inputs


#: Every ``execute_trade`` param a UCA-2 / UCA-5 / UCA-13 rule reads as measured
#: state, including UCA-5's aliases (``trade_hazards.yaml``). Only the gateway
#: sets these; a caller value is always dropped.
TRADE_SERVER_INPUT_KEYS: frozenset[str] = frozenset(
    {
        "latency_ms",
        "drawdown",
        "portfolio_drawdown_pct",
        "current_drawdown",
        "portfolio_total",
    }
)


@dataclass(frozen=True)
class TradeInputResolver:
    """``execute_trade`` server-input resolver over :class:`ServerTradeInputs`.

    Reads ``symbol`` and ``side`` from the (already stripped) params. A
    missing symbol resolves nothing, so UCA-2 / UCA-5 refuse. ``side`` is
    matched case-insensitively, like UCA-13's ``applies_when``, so every
    request UCA-13 treats as a sell gets ``portfolio_total``.
    """

    inputs: ServerTradeInputs
    owned_keys: frozenset[str] = TRADE_SERVER_INPUT_KEYS

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        symbol = params.get("symbol")
        if not isinstance(symbol, str) or not symbol.strip():
            logger.warning(
                "trade inputs: no symbol in %s; nothing resolved", sorted(params)
            )
            return {}
        side = str(params.get("side") or "buy").lower()
        return await self.inputs.resolve(symbol, side=side)


__all__ = [
    "FETCH_TIMEOUT_S",
    "MAX_CLOCK_SKEW_S",
    "MAX_NAV_AGE_S",
    "TRADE_SERVER_INPUT_KEYS",
    "MarketQuote",
    "MarketQuoteFeed",
    "NavSnapshot",
    "PortfolioNavSource",
    "ServerTradeInputs",
    "TradeInputResolver",
    "TradeInputUnavailable",
    "daily_drawdown_pct",
    "fetch_verified_nav",
    "measure_market_data_latency_ms",
    "portfolio_total",
    "resolve_daily_drawdown_pct",
    "resolve_portfolio_total",
]
