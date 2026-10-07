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

"""UCA-6 is evaluated on every trade, from server-side inputs (POAM-2026-106).

UCA-6 refuses an order larger than ``stpa.uca6_max_order_volume_fraction`` of
the symbol's average daily volume. Before this change neither the preview nor
the committing path supplied ``order_size`` / ``daily_vol``, and the
generated rule skipped when both were absent, so UCA-6 never ran. Now the
finance resolver derives ``order_size`` (shares = notional amount / verified
quote price) and reads ``daily_vol`` (average daily volume, shares) from the
market-data feed. A missing input is a HARD refusal (``require_params``).
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.stpa import uca_rules
from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator
from src.cage_finance.tools.trade_inputs import (
    MAX_DAILY_VOLUME_AGE_S,
    DailyVolume,
    ServerTradeInputs,
    TradeInputResolver,
    TradeInputUnavailable,
    fetch_verified_daily_volume,
    order_size_shares,
)
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import FaultMode

pytestmark = [pytest.mark.unit, pytest.mark.local]

_UCA_6 = "STPA_UCA_UCA_6"
#: region -> UCA-6 max order size as a fraction of average daily volume
_FRACTION = {"US_FED": 0.01, "APAC_MAS": 0.008, "EU_ECB": 0.005}
_VOLUME = 1_000_000.0  # shares per session
_PRICE = 100.0  # simulated quote price (±1 % jitter)
_FEED_FAULTS = [
    m
    for m in FaultMode
    if m
    not in {
        FaultMode.NONE,
        FaultMode.SCALAR_BELOW_BARRIER,
        FaultMode.DISCREPANCY_SPIKE,
        FaultMode.SETTLEMENT_STALL,
    }
]


@pytest.fixture(params=tuple(_FRACTION))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated rules to ``region``'s effective thresholds."""
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


def _feed(**kwargs: Any) -> SimulatedMarketQuoteFeed:
    return SimulatedMarketQuoteFeed(
        seed=3,
        publication_delay_ms=(10.0, 10.0),
        base_price=_PRICE,
        daily_volume=_VOLUME,
        **kwargs,
    )


def _resolver(feed: SimulatedMarketQuoteFeed | None = None) -> TradeInputResolver:
    return TradeInputResolver(
        ServerTradeInputs(
            market_feed=feed if feed is not None else _feed(),
            nav_source=SimulatedPortfolioNavSource(),
        )
    )


async def _uca6(
    resolver: TradeInputResolver, **params: Any
) -> tuple[dict[str, Any], list[str]]:
    """Bind ``params`` as the kernel does and return (bound, UCA-6 findings)."""
    request = {"symbol": "AAPL", "amount": 500.0, "side": "buy", **params}
    bound = await bind_server_inputs(
        {"execute_trade": resolver}, "execute_trade", request
    )
    found = [
        v.message
        for v in GeneratedSTPAValidator().validate("execute_trade", dict(bound))
        if v.code == _UCA_6 and v.kind is ViolationKind.HARD
    ]
    return bound, found


def _notional(fraction_of_volume: float) -> float:
    return fraction_of_volume * _VOLUME * _PRICE


# ---------------------------------------------------------------------------
# Per-region enforcement
# ---------------------------------------------------------------------------


def test_regional_uca6_fraction_is_the_effective_threshold(region: str) -> None:
    assert uca_rules.THRESHOLDS.resolve(
        "domains.finance.stpa.uca6_max_order_volume_fraction"
    ) == pytest.approx(_FRACTION[region])


async def test_an_order_under_the_regional_fraction_passes(region: str) -> None:
    bound, found = await _uca6(_resolver(), amount=_notional(_FRACTION[region] * 0.9))

    assert found == []
    assert bound["daily_vol"] == _VOLUME
    assert bound["order_size"] == pytest.approx(
        _FRACTION[region] * 0.9 * _VOLUME, rel=0.02
    )


async def test_an_order_over_the_regional_fraction_is_refused(region: str) -> None:
    _, found = await _uca6(_resolver(), amount=_notional(_FRACTION[region] * 1.1))

    assert found, "UCA-6 must refuse an order over the regional volume fraction"


async def test_the_same_order_is_judged_by_each_region(region: str) -> None:
    # 0.7 % of daily volume: inside US_FED (1 %) and APAC_MAS (0.8 %),
    # outside EU_ECB (0.5 %).
    _, found = await _uca6(_resolver(), amount=_notional(0.007))

    assert bool(found) is (region == "EU_ECB")


# ---------------------------------------------------------------------------
# The caller cannot state order_size or daily_vol
# ---------------------------------------------------------------------------


async def test_caller_values_cannot_hide_an_oversized_order(region: str) -> None:
    _, found = await _uca6(
        _resolver(),
        amount=_notional(_FRACTION[region] * 2),
        order_size=1.0,
        daily_vol=1e12,
    )

    assert found


async def test_caller_values_cannot_refuse_a_small_order(region: str) -> None:
    bound, found = await _uca6(_resolver(), order_size=1e12, daily_vol=1.0)

    assert found == []
    assert bound["order_size"] == pytest.approx(5.0, rel=0.02)  # $500 / ~$100


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fault", _FEED_FAULTS, ids=str)
async def test_a_faulted_daily_volume_refuses_the_trade(fault: FaultMode) -> None:
    feed = _feed()
    feed.inject_volume_fault(fault)

    bound, found = await _uca6(_resolver(feed))

    assert "daily_vol" not in bound
    assert found
    assert "latency_ms" in bound  # the quote channel is independent


@pytest.mark.parametrize("fault", _FEED_FAULTS, ids=str)
async def test_a_faulted_quote_refuses_the_trade(fault: FaultMode) -> None:
    feed = _feed()
    feed.inject_fault(fault)

    bound, found = await _uca6(_resolver(feed))

    if fault is FaultMode.STALE_TIMESTAMP:
        # A stale quote still prices the order; UCA-2 refuses its age.
        assert "order_size" in bound
    else:
        assert "order_size" not in bound
        assert found


async def test_no_market_feed_refuses_the_trade() -> None:
    resolver = TradeInputResolver(
        ServerTradeInputs(market_feed=None, nav_source=SimulatedPortfolioNavSource())
    )

    bound, found = await _uca6(resolver)

    assert not {"order_size", "daily_vol"} & set(bound)
    assert found


@pytest.mark.parametrize("amount", [None, "lots", True, math.nan, math.inf, -1.0])
async def test_an_unusable_amount_leaves_order_size_unset(amount: Any) -> None:
    bound, found = await _uca6(_resolver(), amount=amount)

    assert "order_size" not in bound
    assert found


def test_uca6_refuses_when_either_input_is_missing() -> None:
    validator = GeneratedSTPAValidator()
    for params in ({}, {"order_size": 1.0}, {"daily_vol": 1.0}):
        codes = [v.code for v in validator.validate("execute_trade", params)]
        assert _UCA_6 in codes, params


# ---------------------------------------------------------------------------
# Derivation and validation units
# ---------------------------------------------------------------------------


def test_order_size_is_notional_over_price() -> None:
    assert order_size_shares(1_000.0, 50.0) == 20.0
    assert order_size_shares("250", 25.0) == 10.0
    assert order_size_shares(0, 10.0) == 0.0


@pytest.mark.parametrize("price", [0.0, -1.0, math.nan])
def test_order_size_needs_a_positive_price(price: float) -> None:
    with pytest.raises(TradeInputUnavailable):
        order_size_shares(100.0, price)


class _FixedVolume:
    def __init__(self, vol: DailyVolume) -> None:
        self._vol = vol

    async def latest_quote(self, symbol: str) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def average_daily_volume(self, symbol: str) -> DailyVolume:
        return self._vol


def _vol(age_s: float, **kw: Any) -> DailyVolume:
    fields: dict[str, Any] = {
        "symbol": "AAPL",
        "shares": _VOLUME,
        "as_of": 1_000_000.0 - age_s,
        "source_id": "simulated:finance_market_feed",
    }
    fields.update(kw)
    return DailyVolume(**fields)


async def test_daily_volume_age_window_is_inclusive() -> None:
    clock = lambda: 1_000_000.0  # noqa: E731
    at_limit = _FixedVolume(_vol(MAX_DAILY_VOLUME_AGE_S))
    assert await fetch_verified_daily_volume(at_limit, "AAPL", clock=clock) == _VOLUME

    too_old = _FixedVolume(_vol(MAX_DAILY_VOLUME_AGE_S + 1.0))
    with pytest.raises(TradeInputUnavailable, match="stale"):
        await fetch_verified_daily_volume(too_old, "AAPL", clock=clock)


@pytest.mark.parametrize(
    "override",
    [{"symbol": "MSFT"}, {"shares": 0.0}, {"shares": "x"}, {"source_id": ""}],
)
async def test_daily_volume_rejects_untrustworthy_readings(
    override: dict[str, Any],
) -> None:
    source = _FixedVolume(_vol(0.0, **override))
    with pytest.raises(TradeInputUnavailable):
        await fetch_verified_daily_volume(source, "AAPL", clock=lambda: 1_000_000.0)
