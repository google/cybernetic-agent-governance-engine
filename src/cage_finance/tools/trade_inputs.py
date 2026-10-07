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

UCA-2 / FIN-2 read ``latency_ms``, UCA-5 reads ``drawdown``, UCA-6 reads
``order_size`` and ``daily_vol`` and, for a sell, UCA-13 / FIN-1 reads
``portfolio_total`` from the trade params. The gateway never takes any of
these values from its caller. It measures or derives them here for every
evaluation of a trade: each preview and each committing run (including the
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

``order_size`` (UCA-6)
    The order's size in shares, derived from the caller's notional ``amount``
    and the verified quote price of the same quote that gives ``latency_ms``::

        order_size = amount / quote.price

    ``amount`` is caller intent (how much to trade), so it stays the
    caller's. ``order_size`` is what UCA-6 compares with market volume, so
    the gateway derives it and the caller cannot state it. The amount is
    taken to be in the quote currency; no FX conversion is applied (a
    non-USD order against a USD quote is a commercial-deployment concern).

``daily_vol`` (UCA-6)
    The traded symbol's average daily volume in shares, from the market-data
    feed (:meth:`MarketQuoteFeed.average_daily_volume`). UCA-6 refuses an
    order larger than ``stpa.uca6_max_order_volume_fraction`` of it. The
    reading must come from a verified source, be for the traded symbol, be
    finite and positive, be no older than :data:`MAX_DAILY_VOLUME_AGE_S`
    (an average published once per session, allowing for a weekend and a
    holiday), and be dated no more than :data:`MAX_CLOCK_SKEW_S` ahead.

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
fails validation, or ``amount`` is not a usable number, the input is left out
of the params. The generated UCA-2 / UCA-5 / UCA-6 / UCA-13 rules then refuse
the trade inside the governor, which records the refusal in the evidence
chain.
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

#: Oldest average-daily-volume reading accepted: published once per session,
#: so four days spans a weekend plus a market holiday.
MAX_DAILY_VOLUME_AGE_S: float = 4 * 24 * 3600.0


@dataclass(frozen=True)
class MarketQuote:
    """One quote from a market-data feed."""

    symbol: str
    price: float
    #: Feed publication time of the quote (Unix epoch seconds).
    published_at: float
    source_id: str


@dataclass(frozen=True)
class VerifiedQuote:
    """A quote that passed validation, with its measured age."""

    price: float
    latency_ms: float


@dataclass(frozen=True)
class DailyVolume:
    """A symbol's average daily traded volume, as published by the feed."""

    symbol: str
    #: Average shares traded per session.
    shares: float
    #: When the feed computed the average (Unix epoch seconds).
    as_of: float
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
    """Market-data reader for the traded instrument."""

    async def latest_quote(self, symbol: str) -> MarketQuote: ...

    async def average_daily_volume(self, symbol: str) -> DailyVolume: ...


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
        TradeInputUnavailable: as :func:`fetch_verified_quote`.
    """
    return (await fetch_verified_quote(feed, symbol, clock=clock)).latency_ms


async def fetch_verified_quote(
    feed: MarketQuoteFeed,
    symbol: str,
    *,
    clock: Callable[[], float] = time.time,
) -> VerifiedQuote:
    """Fetch ``symbol``'s latest quote; return its price and measured age.

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
    return VerifiedQuote(price=price, latency_ms=max(age_s, 0.0) * 1000.0)


async def fetch_verified_daily_volume(
    feed: MarketQuoteFeed,
    symbol: str,
    *,
    clock: Callable[[], float] = time.time,
) -> float:
    """Return ``symbol``'s average daily volume in shares, if it can be trusted.

    Raises:
        TradeInputUnavailable: the fetch fails or times out, or the reading is
            for another symbol, unverified, non-finite or not positive, older
            than :data:`MAX_DAILY_VOLUME_AGE_S`, or dated in the future.
    """
    try:
        vol = await asyncio.wait_for(feed.average_daily_volume(symbol), FETCH_TIMEOUT_S)
    except Exception as exc:
        raise TradeInputUnavailable(
            f"daily-volume fetch failed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(vol.symbol, str) or vol.symbol.upper() != symbol.upper():
        raise TradeInputUnavailable(
            f"daily volume is for {vol.symbol!r}, not {symbol!r}"
        )
    if not _verified(vol.source_id):
        raise TradeInputUnavailable(f"unverified daily-volume source {vol.source_id!r}")
    try:
        shares = float(vol.shares)
        as_of = float(vol.as_of)
    except (TypeError, ValueError) as exc:
        raise TradeInputUnavailable(f"malformed daily volume: {exc}") from exc
    if not math.isfinite(shares) or shares <= 0.0:
        raise TradeInputUnavailable(f"invalid daily volume {shares!r}")
    if not math.isfinite(as_of):
        raise TradeInputUnavailable("non-finite daily-volume timestamp")
    age_s = clock() - as_of
    if age_s > MAX_DAILY_VOLUME_AGE_S:
        raise TradeInputUnavailable(
            f"stale daily volume: age {age_s:.0f}s > {MAX_DAILY_VOLUME_AGE_S:.0f}s"
        )
    if age_s < -MAX_CLOCK_SKEW_S:
        raise TradeInputUnavailable(
            f"daily-volume timestamp {-age_s:.1f}s in the future"
        )
    return shares


def order_size_shares(amount: object, price: float) -> float:
    """Return the order size in shares for a notional ``amount`` at ``price``.

    Raises:
        TradeInputUnavailable: ``amount`` is not a finite, non-negative number
            (booleans are rejected), or ``price`` is not positive.
    """
    if isinstance(amount, bool) or not isinstance(amount, (int, float, str)):
        raise TradeInputUnavailable(f"amount {amount!r} is not a number")
    try:
        notional = float(amount)
    except ValueError as exc:
        raise TradeInputUnavailable(f"amount {amount!r} is not a number") from exc
    if not math.isfinite(notional) or notional < 0.0:
        raise TradeInputUnavailable(f"invalid amount {notional!r}")
    if not price > 0.0:
        raise TradeInputUnavailable(f"invalid quote price {price!r}")
    return notional / price


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


async def _resolve_market(
    feed: MarketQuoteFeed, symbol: str, amount: object, inputs: dict[str, float]
) -> None:
    """Add ``latency_ms`` / ``order_size`` (one quote) and ``daily_vol``."""
    try:
        quote = await fetch_verified_quote(feed, symbol)
    except TradeInputUnavailable as exc:
        logger.warning(
            "trade inputs: quote unavailable (UCA-2 / UCA-6 will refuse): %s", exc
        )
    else:
        inputs["latency_ms"] = quote.latency_ms
        try:
            inputs["order_size"] = order_size_shares(amount, quote.price)
        except TradeInputUnavailable as exc:
            logger.warning(
                "trade inputs: order_size unavailable (UCA-6 will refuse): %s", exc
            )
    try:
        inputs["daily_vol"] = await fetch_verified_daily_volume(feed, symbol)
    except TradeInputUnavailable as exc:
        logger.warning(
            "trade inputs: daily_vol unavailable (UCA-6 will refuse): %s", exc
        )


@dataclass(frozen=True)
class ServerTradeInputs:
    """The gateway's sources for the STPA inputs of a governed trade.

    Built once by the finance plugin (the composition root) and bound into the
    trade tool, so a caller can never supply these values.
    """

    market_feed: MarketQuoteFeed | None
    nav_source: PortfolioNavSource | None

    async def resolve(
        self, symbol: str, *, side: str, amount: object
    ) -> dict[str, float]:
        """Return the measurable inputs for a ``side`` trade of ``amount`` in ``symbol``.

        ``latency_ms``, ``order_size``, ``daily_vol`` and ``drawdown`` are
        resolved for every trade; ``portfolio_total`` only for a sell, from
        the same NAV snapshot as ``drawdown``. ``order_size`` uses the price
        of the quote that gives ``latency_ms``. An input that cannot be
        measured or trusted is left out and logged; the governor's STPA stage
        then refuses the trade.
        """
        inputs: dict[str, float] = {}
        if self.market_feed is None:
            logger.warning(
                "trade inputs: no market-data feed assembled "
                "(UCA-2 / UCA-6 will refuse)"
            )
        else:
            await _resolve_market(self.market_feed, symbol, amount, inputs)
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


#: Every ``execute_trade`` param a UCA-2 / UCA-5 / UCA-6 / UCA-13 rule reads as
#: measured state, including UCA-5's aliases (``trade_hazards.yaml``). Only the
#: gateway sets these; a caller value is always dropped.
TRADE_SERVER_INPUT_KEYS: frozenset[str] = frozenset(
    {
        "latency_ms",
        "drawdown",
        "portfolio_drawdown_pct",
        "current_drawdown",
        "order_size",
        "daily_vol",
        "portfolio_total",
    }
)


@dataclass(frozen=True)
class TradeInputResolver:
    """``execute_trade`` server-input resolver over :class:`ServerTradeInputs`.

    Reads ``symbol``, ``side`` and ``amount`` from the (already stripped)
    params. A missing symbol resolves nothing, so UCA-2 / UCA-5 / UCA-6
    refuse; an unusable ``amount`` leaves ``order_size`` unset. ``side`` is
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
        return await self.inputs.resolve(symbol, side=side, amount=params.get("amount"))


__all__ = [
    "FETCH_TIMEOUT_S",
    "MAX_CLOCK_SKEW_S",
    "MAX_DAILY_VOLUME_AGE_S",
    "MAX_NAV_AGE_S",
    "TRADE_SERVER_INPUT_KEYS",
    "DailyVolume",
    "MarketQuote",
    "MarketQuoteFeed",
    "NavSnapshot",
    "PortfolioNavSource",
    "ServerTradeInputs",
    "TradeInputResolver",
    "TradeInputUnavailable",
    "VerifiedQuote",
    "daily_drawdown_pct",
    "fetch_verified_daily_volume",
    "fetch_verified_nav",
    "fetch_verified_quote",
    "measure_market_data_latency_ms",
    "order_size_shares",
    "portfolio_total",
    "resolve_daily_drawdown_pct",
    "resolve_portfolio_total",
]
