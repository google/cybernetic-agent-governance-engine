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

"""The trade tool measures UCA-2 ``latency_ms`` and reads UCA-5 ``drawdown`` itself.

``execute_trade_action`` takes neither value from its caller. For every
committing run the kernel binds them through the governor's ``execute_trade``
server-input resolver
(:class:`~src.cage_finance.tools.trade_inputs.TradeInputResolver` over
:class:`~src.cage_finance.tools.trade_inputs.ServerTradeInputs`). The params
it hands to governance run through the generated finance STPA rules for each
region (UCA-5 drawdown 3.5 / 4.0 / 4.5 %, FIN-2 latency 150 / 175 / 200 ms):

* in-limit inputs clear the STPA stage; over-limit inputs are HARD UCA-2 / UCA-5;
* a missing or faulted source leaves its input unset, and the rule refuses;
* the advisor's ``/tools/execute`` trade path now clears the STPA stage for a
  normal buy (before, UCA-2 and UCA-5 refused every advisor trade).
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.stpa import uca_rules
from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator
from src.cage_finance.tools import tool_provider
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.cage_finance.tools.trade_inputs import (
    MarketQuote,
    ServerTradeInputs,
    TradeInputResolver,
    TradeInputUnavailable,
    measure_market_data_latency_ms,
    resolve_daily_drawdown_pct,
)
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import FaultMode
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_UCA_2 = "STPA_UCA_UCA_2"
_UCA_5 = "STPA_UCA_UCA_5"
#: region -> (UCA-5 drawdown %, FIN-2 max latency ms)
_LIMITS = {
    "EU_ECB": (3.5, 150.0),
    "APAC_MAS": (4.0, 175.0),
    "US_FED": (4.5, 200.0),
}


class _Cleared(Exception):
    def __init__(self, params: dict[str, Any]) -> None:
        super().__init__("cleared")
        self.params = params


@pytest.fixture(params=tuple(_LIMITS))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated rules to ``region``'s effective thresholds."""
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


@pytest.fixture
def stpa_gateway(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """``enforce_governance`` replaced by the generated finance STPA stage.

    A HARD violation raises the ``PermissionError`` the middleware raises
    (the tool returns ``BLOCKED: ...``); a clean run raises :class:`_Cleared`.
    """
    seen: list[dict[str, Any]] = []

    async def _enforce(_governor: Any, action: str, params: dict[str, Any]) -> str:
        seen.append(dict(params))
        hard = [
            v
            for v in GeneratedSTPAValidator().validate(action, dict(params))
            if v.kind is ViolationKind.HARD
        ]
        if hard:
            raise PermissionError("; ".join(f"{v.code}: {v.message}" for v in hard))
        raise _Cleared(dict(params))

    monkeypatch.setattr(tool_provider, "enforce_governance", _enforce)
    return seen


def _feed(delay_ms: float, **kwargs: Any) -> SimulatedMarketQuoteFeed:
    return SimulatedMarketQuoteFeed(
        seed=7, publication_delay_ms=(delay_ms, delay_ms), **kwargs
    )


def _inputs(
    *, delay_ms: float = 20.0, drawdown_pct: float = 0.0, **overrides: Any
) -> ServerTradeInputs:
    fields: dict[str, Any] = {
        "market_feed": _feed(delay_ms),
        "nav_source": SimulatedPortfolioNavSource(drawdown_pct=drawdown_pct),
    }
    fields.update(overrides)
    return ServerTradeInputs(**fields)


async def _buy(inputs: ServerTradeInputs) -> str:
    return await execute_trade_action(
        symbol="AAPL",
        amount=500.0,
        currency="USD",
        confidence=0.99,
        governor=trade_governor({"execute_trade": TradeInputResolver(inputs)}),
    )


def test_regional_limits_are_the_effective_thresholds(region: str) -> None:
    drawdown, latency = _LIMITS[region]
    t = uca_rules.THRESHOLDS
    assert t.resolve(
        "domains.finance.stpa.uca5_drawdown_threshold_pct"
    ) == pytest.approx(drawdown)
    assert t.resolve("domains.finance.stpa.max_latency_ms") == pytest.approx(latency)


# ── STPA outcomes per region ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_in_limit_inputs_clear_stpa(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    drawdown, latency = _LIMITS[region]
    with pytest.raises(_Cleared) as cleared:
        await _buy(_inputs(delay_ms=latency - 20.0, drawdown_pct=drawdown - 0.01))
    params = cleared.value.params
    assert latency - 20.0 <= params["latency_ms"] < latency
    assert params["drawdown"] == pytest.approx(drawdown - 0.01)


@pytest.mark.asyncio
async def test_latency_over_fin2_is_hard_uca2(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    _, latency = _LIMITS[region]
    result = await _buy(_inputs(delay_ms=latency + 5.0))
    assert result.startswith("BLOCKED:")
    assert f"{_UCA_2}: Agent executes trade with stale market data" in result
    assert _UCA_5 not in result
    assert stpa_gateway[-1]["latency_ms"] > latency


@pytest.mark.asyncio
async def test_drawdown_over_limit_is_hard_uca5(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    drawdown, _ = _LIMITS[region]
    result = await _buy(_inputs(drawdown_pct=drawdown + 0.01))
    assert result.startswith("BLOCKED:")
    assert (
        f"{_UCA_5}: Agent executes buy order when daily drawdown exceeds limit"
        in result
    )
    assert _UCA_2 not in result


@pytest.mark.asyncio
async def test_regions_differ_at_the_same_inputs(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """160 ms and 3.8 % breach only EU_ECB's limits (150 ms, 3.5 %)."""
    try:
        result = await _buy(_inputs(delay_ms=160.0, drawdown_pct=3.8))
    except _Cleared:
        result = "CLEARED"
    assert (_UCA_2 in result) is (region == "EU_ECB")
    assert (_UCA_5 in result) is (region == "EU_ECB")


# ── Fail closed on missing or untrustworthy sources ────────────────────────


@pytest.mark.asyncio
async def test_missing_market_feed_is_refused_by_uca2(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _buy(_inputs(market_feed=None))
    assert f"{_UCA_2}: Missing required param `latency_ms`." in result
    assert "latency_ms" not in stpa_gateway[-1]


@pytest.mark.asyncio
async def test_missing_nav_source_is_refused_by_uca5(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _buy(_inputs(nav_source=None))
    assert f"{_UCA_5}: Missing required param `drawdown`." in result
    assert "drawdown" not in stpa_gateway[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.FUTURE_TIMESTAMP,
        FaultMode.NAN_VALUE,
        FaultMode.NEGATIVE_VALUE,
        FaultMode.MALFORMED_PAYLOAD,
        FaultMode.UNVERIFIED_SOURCE,
    ],
)
async def test_faulted_market_feed_is_refused_by_uca2(
    region: str, stpa_gateway: list[dict[str, Any]], fault: FaultMode
) -> None:
    feed = _feed(20.0)
    feed.inject_fault(fault)
    result = await _buy(_inputs(market_feed=feed))
    assert f"{_UCA_2}: Missing required param `latency_ms`." in result
    assert "latency_ms" not in stpa_gateway[-1]


@pytest.mark.asyncio
async def test_stale_quote_is_measured_and_refused_by_uca2(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    feed = _feed(20.0)
    feed.inject_fault(FaultMode.STALE_TIMESTAMP)
    result = await _buy(_inputs(market_feed=feed))
    assert f"{_UCA_2}: Agent executes trade with stale market data" in result
    assert stpa_gateway[-1]["latency_ms"] >= 3_600_000.0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.STALE_TIMESTAMP,
        FaultMode.FUTURE_TIMESTAMP,
        FaultMode.NAN_VALUE,
        FaultMode.NEGATIVE_VALUE,
        FaultMode.MALFORMED_PAYLOAD,
        FaultMode.UNVERIFIED_SOURCE,
    ],
)
async def test_faulted_nav_source_is_refused_by_uca5(
    region: str, stpa_gateway: list[dict[str, Any]], fault: FaultMode
) -> None:
    nav = SimulatedPortfolioNavSource()
    nav.inject_fault(fault)
    result = await _buy(_inputs(nav_source=nav))
    assert f"{_UCA_5}: Missing required param `drawdown`." in result
    assert "drawdown" not in stpa_gateway[-1]


# ── latency_ms is a measurement ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_latency_tracks_quote_age() -> None:
    slow = await measure_market_data_latency_ms(_feed(120.0), "AAPL")
    fast = await measure_market_data_latency_ms(_feed(10.0), "AAPL")
    assert 120.0 <= slow < 170.0
    assert 10.0 <= fast < 60.0


@pytest.mark.asyncio
async def test_latency_includes_the_fetch_round_trip() -> None:
    """A quote published at the request instant still ages by the fetch time."""

    class _SlowFeed:
        async def latest_quote(self, symbol: str) -> MarketQuote:
            import time

            published = time.time()
            await asyncio.sleep(0.06)
            return MarketQuote(symbol, 100.0, published, "simulated:test")

    assert await measure_market_data_latency_ms(_SlowFeed(), "AAPL") >= 60.0


@pytest.mark.asyncio
async def test_latency_uses_the_gateway_clock() -> None:
    feed = SimulatedMarketQuoteFeed(
        seed=1, publication_delay_ms=(0.0, 0.0), clock=lambda: 1_000.0
    )
    assert await measure_market_data_latency_ms(
        feed, "AAPL", clock=lambda: 1_000.25
    ) == pytest.approx(250.0)


@pytest.mark.asyncio
async def test_hung_feed_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.cage_finance.tools import trade_inputs

    monkeypatch.setattr(trade_inputs, "FETCH_TIMEOUT_S", 0.01)

    class _Hung:
        async def latest_quote(self, symbol: str) -> MarketQuote:
            await asyncio.sleep(10)
            raise AssertionError

    with pytest.raises(TradeInputUnavailable, match="TimeoutError"):
        await measure_market_data_latency_ms(_Hung(), "AAPL")


@pytest.mark.asyncio
async def test_drawdown_is_zero_when_nav_is_up() -> None:
    class _Up:
        async def fetch_nav(self) -> Any:
            import time

            from src.cage_finance.tools.trade_inputs import NavSnapshot

            return NavSnapshot(100.0, 103.0, time.time(), "simulated:test")

    assert await resolve_daily_drawdown_pct(_Up()) == 0.0


# ── The caller cannot supply the inputs ────────────────────────────────────


def test_tool_takes_no_caller_latency_or_drawdown() -> None:
    params = inspect.signature(execute_trade_action).parameters
    assert "latency_ms" not in params
    assert "drawdown" not in params
    assert "inputs" not in params


def test_registered_mcp_tool_takes_no_caller_latency_or_drawdown() -> None:
    registered = _register_with(tool_provider.FinancialToolProvider())
    params = inspect.signature(registered["execute_trade_action"]).parameters
    assert "latency_ms" not in params
    assert "drawdown" not in params
    assert "inputs" not in params


# ── Advisor path ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_advisor_buy_now_clears_the_stpa_stage(
    region: str, stpa_gateway: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/tools/execute`` -> gateway ``execute_trade_action`` -> STPA stage.

    The gateway tool and its server-input resolver are the ones the finance
    plugin contributes, with the plugin's own simulated sources. The advisor
    forwards no latency or drawdown; the gateway supplies both and the buy
    clears UCA-2 and UCA-5.
    """
    from src.cage_finance.plugin import FinanceCagePlugin
    from src.governed_financial_advisor.tools import api

    contribution = FinanceCagePlugin().contribute()
    tool = _register_with(
        contribution.tool_provider, trade_governor(dict(contribution.server_inputs))
    )["execute_trade_action"]

    async def _gateway_execute(name: str, params: dict[str, Any]) -> dict[str, Any]:
        assert name == "execute_trade_action"
        assert "latency_ms" not in params and "drawdown" not in params
        try:
            output = await tool(**params)
        except _Cleared:
            output = "STPA_CLEARED"
        return {"status": "SUCCESS", "output": output}

    monkeypatch.setattr(api._gateway_client, "execute_tool", _gateway_execute)
    response = await api.execute_tool_endpoint(
        api.ToolExecutionRequest(
            tool_name="execute_trade",
            params={
                "symbol": "AAPL",
                "amount": 500.0,
                "currency": "USD",
                "confidence": 0.99,
                "trader_id": "agent_001",
            },
        ),
        MagicMock(),
        "test-key",
    )
    assert response == {"status": "SUCCESS", "output": "STPA_CLEARED"}
    params = stpa_gateway[-1]
    assert 0.0 <= params["latency_ms"] < _LIMITS[region][1]
    assert params["drawdown"] == 0.0
    assert GeneratedSTPAValidator().validate("execute_trade", params) == []


def _register_with(provider: Any, governor: Any = None) -> dict[str, Any]:
    registered: dict[str, Any] = {}

    class _Server:
        def tool(self, name: str | None = None, **_kw: Any) -> Any:
            def _register_fn(fn: Any) -> Any:
                registered[name or fn.__name__] = fn
                return fn

            return _register_fn

    provider.register_tools(_Server(), governor or trade_governor())
    return registered
