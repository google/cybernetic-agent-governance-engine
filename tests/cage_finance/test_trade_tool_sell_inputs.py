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

"""The trade tool sends ``side`` and a server-side ``portfolio_total`` to UCA-13.

``execute_trade_action`` takes the order side from the caller. For a sell it
sets ``portfolio_total`` to the current NAV from the gateway's
:class:`~src.cage_finance.tools.trade_inputs.PortfolioNavSource`, never from
the caller and never from the custodian cash balance. These tests run the
params the tool hands to governance through the generated finance STPA rules
for each region (FIN-1 sell fraction EU_ECB 0.08 / APAC_MAS 0.09 / US_FED 0.10):

* a sell within the regional fraction of NAV clears the STPA stage;
* a sell over it is a HARD UCA-13 violation;
* a missing, faulted or untrustworthy NAV source leaves ``portfolio_total``
  unset, and UCA-13 refuses the sell;
* a buy carries no ``portfolio_total`` and skips UCA-13.
"""

from __future__ import annotations

import inspect
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.stpa import uca_rules
from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator
from src.cage_finance.tools import tool_provider, trade_inputs
from src.cage_finance.tools.tool_provider import (
    _approval_covers_trade,
    execute_trade_action,
)
from src.cage_finance.tools.trade_inputs import (
    NavSnapshot,
    ServerTradeInputs,
    TradeInputUnavailable,
    resolve_portfolio_total,
)
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import FaultMode

pytestmark = [pytest.mark.unit, pytest.mark.local]

_UCA_13 = "STPA_UCA_UCA_13"
_OPEN_NAV = 100_000.0
_FRACTION = {"US_FED": 0.10, "EU_ECB": 0.08, "APAC_MAS": 0.09}
_CASH = "finance.cash_balance"


class _Cleared(Exception):
    """Raised by the fake gateway when the STPA stage has no HARD violation."""

    def __init__(self, params: dict[str, Any]) -> None:
        super().__init__("cleared")
        self.params = params


@pytest.fixture(params=tuple(_FRACTION))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated rules to ``region``'s effective thresholds."""
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


@pytest.fixture
def stpa_gateway(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace ``enforce_governance`` with the generated finance STPA stage.

    A HARD violation becomes the ``PermissionError`` the real middleware
    raises (the tool returns ``BLOCKED: ...``). A clean run raises
    :class:`_Cleared` carrying the params, so the test stops before sealing.
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


def _nav(drawdown_pct: float = 0.0) -> SimulatedPortfolioNavSource:
    return SimulatedPortfolioNavSource(open_nav=_OPEN_NAV, drawdown_pct=drawdown_pct)


def _inputs(nav_source: Any = None, *, no_nav: bool = False) -> ServerTradeInputs:
    """In-limit UCA-2 latency and the given NAV source (default: flat day)."""
    return ServerTradeInputs(
        market_feed=SimulatedMarketQuoteFeed(seed=0, publication_delay_ms=(10.0, 10.0)),
        nav_source=None if no_nav else (nav_source or _nav()),
    )


def _governor(providers: dict[str, Any] | None = None) -> MagicMock:
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    governor.components.ground_truth_providers = providers or {}
    return governor


async def _trade(
    amount: float,
    *,
    inputs: ServerTradeInputs | None = None,
    governor: Any = None,
    **kwargs: Any,
) -> str:
    return await execute_trade_action(
        symbol="AAPL",
        amount=amount,
        currency="USD",
        confidence=0.99,
        inputs=inputs or _inputs(),
        governor=governor or _governor(),
        **kwargs,
    )


def _limit(region: str, nav: float = _OPEN_NAV) -> float:
    return _FRACTION[region] * nav


# ── STPA stage outcomes per region ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_sell_within_regional_limit_clears_stpa(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    with pytest.raises(_Cleared) as cleared:
        await _trade(_limit(region) * 0.5, side="sell")
    params = cleared.value.params
    assert params["side"] == "sell"
    assert params["portfolio_total"] == pytest.approx(_OPEN_NAV)


@pytest.mark.asyncio
async def test_sell_at_regional_limit_clears_stpa(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    with pytest.raises(_Cleared):
        await _trade(_limit(region), side="sell")


@pytest.mark.asyncio
async def test_sell_over_regional_limit_is_hard_uca13(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _trade(_limit(region) * 1.5, side="sell")
    assert result.startswith("BLOCKED:")
    assert _UCA_13 in result
    assert stpa_gateway[-1]["portfolio_total"] == pytest.approx(_OPEN_NAV)


@pytest.mark.asyncio
async def test_regions_differ_at_the_same_sell(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """8,500 of a 100,000 NAV is refused under EU_ECB (8%) only."""
    try:
        result = await _trade(8_500.0, side="sell")
    except _Cleared:
        result = "CLEARED"
    assert (_UCA_13 in result) is (region == "EU_ECB")


@pytest.mark.asyncio
async def test_limit_tracks_current_nav_not_opening_nav(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """After a 2% drawdown the FIN-1 base is the current NAV (98,000).

    A sell between the fraction of current NAV and the fraction of opening
    NAV is refused: the denominator is what the portfolio is worth now.
    """
    current = _OPEN_NAV * 0.98
    inputs = _inputs(_nav(drawdown_pct=2.0))
    amount = (_limit(region, current) + _limit(region)) / 2
    result = await _trade(amount, side="sell", inputs=inputs)
    assert _UCA_13 in result
    assert stpa_gateway[-1]["portfolio_total"] == pytest.approx(current)
    assert stpa_gateway[-1]["drawdown"] == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_cash_balance_is_not_the_denominator(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """The custodian cash ledger is never read for FIN-1.

    The cash balance (10,000) is a tenth of NAV; a sell within the NAV
    fraction clears although it exceeds the same fraction of cash.
    """
    ledger = MagicMock()
    ledger.fetch_snapshot = AsyncMock(side_effect=AssertionError("cash ledger read"))
    with pytest.raises(_Cleared) as cleared:
        await _trade(
            _limit(region) * 0.9, side="sell", governor=_governor({_CASH: ledger})
        )
    assert cleared.value.params["portfolio_total"] == pytest.approx(_OPEN_NAV)
    ledger.fetch_snapshot.assert_not_awaited()


# ── Fail closed when NAV is unavailable ────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_nav_source_refuses_sell(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _trade(1.0, side="sell", inputs=_inputs(no_nav=True))
    assert result.startswith("BLOCKED:")
    assert _UCA_13 in result
    assert "portfolio_total" not in stpa_gateway[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.NEGATIVE_VALUE,
        FaultMode.NAN_VALUE,
        FaultMode.STALE_TIMESTAMP,
        FaultMode.FUTURE_TIMESTAMP,
        FaultMode.MALFORMED_PAYLOAD,
        FaultMode.UNVERIFIED_SOURCE,
    ],
)
async def test_faulted_nav_source_refuses_sell(
    region: str, stpa_gateway: list[dict[str, Any]], fault: FaultMode
) -> None:
    nav = _nav()
    nav.inject_fault(fault)
    result = await _trade(1.0, side="sell", inputs=_inputs(nav))
    assert result.startswith("BLOCKED:")
    assert _UCA_13 in result
    assert "portfolio_total" not in stpa_gateway[-1]


@pytest.mark.asyncio
async def test_zero_nav_refuses_sell(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """A 100% drawdown is a valid UCA-5 reading but no FIN-1 base."""
    result = await _trade(1.0, side="sell", inputs=_inputs(_nav(drawdown_pct=100.0)))
    assert _UCA_13 in result
    assert "portfolio_total" not in stpa_gateway[-1]
    assert stpa_gateway[-1]["drawdown"] == pytest.approx(100.0)


@pytest.mark.asyncio
async def test_buy_carries_no_portfolio_total(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """A buy carries no portfolio_total and is not subject to UCA-13."""
    with pytest.raises(_Cleared) as cleared:
        await _trade(_OPEN_NAV * 10)
    params = cleared.value.params
    assert params["side"] == "buy"
    assert "portfolio_total" not in params


@pytest.mark.asyncio
async def test_invalid_side_is_blocked_before_governance(
    stpa_gateway: list[dict[str, Any]],
) -> None:
    result = await _trade(1.0, side="short")  # type: ignore[arg-type]
    assert result.startswith("BLOCKED: invalid trade side")
    assert stpa_gateway == []


@pytest.mark.asyncio
async def test_one_nav_snapshot_per_trade() -> None:
    """``drawdown`` and ``portfolio_total`` come from a single NAV fetch."""
    nav = _nav(drawdown_pct=1.0)
    calls = 0
    real = nav.fetch_nav

    async def _counting() -> NavSnapshot:
        nonlocal calls
        calls += 1
        return await real()

    nav.fetch_nav = _counting  # type: ignore[method-assign]
    resolved = await _inputs(nav).resolve("AAPL", side="sell")
    assert calls == 1
    assert resolved["portfolio_total"] == pytest.approx(_OPEN_NAV * 0.99)
    assert resolved["drawdown"] == pytest.approx(1.0)


# ── Caller cannot supply the valuation ─────────────────────────────────────


def test_tool_takes_no_caller_portfolio_total() -> None:
    assert "portfolio_total" not in inspect.signature(execute_trade_action).parameters


def test_registered_mcp_tool_takes_no_caller_portfolio_total() -> None:
    registered: dict[str, Any] = {}

    class _Server:
        def tool(self, name: str | None = None, **_kw: Any) -> Any:
            def _register(fn: Any) -> Any:
                registered[name or fn.__name__] = fn
                return fn

            return _register

    tool_provider.FinancialToolProvider(_inputs()).register_tools(
        _Server(), MagicMock()
    )  # type: ignore[arg-type]
    params = inspect.signature(registered["execute_trade_action"]).parameters
    assert "side" in params
    assert "portfolio_total" not in params


def test_approval_binds_side() -> None:
    approved = {
        "symbol": "AAPL",
        "currency": "USD",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "side": "buy",
        "amount": 100.0,
    }
    assert _approval_covers_trade(approved, dict(approved))
    assert not _approval_covers_trade(approved, {**approved, "side": "sell"})


# ── resolve_portfolio_total snapshot checks ────────────────────────────────


class _FixedNav:
    def __init__(self, **overrides: Any) -> None:
        fields: dict[str, Any] = {
            "open_nav": _OPEN_NAV,
            "current_nav": _OPEN_NAV,
            "observed_at": time.time(),
            "source_id": "simulated:finance_portfolio_nav",
        }
        fields.update(overrides)
        self._snap = NavSnapshot(**fields)

    async def fetch_nav(self) -> NavSnapshot:
        return self._snap


@pytest.mark.asyncio
async def test_resolve_returns_current_nav() -> None:
    total = await resolve_portfolio_total(_FixedNav(current_nav=97_500.0))
    assert total == pytest.approx(97_500.0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"source_id": "unverified_rogue_feed"},
        {"source_id": ""},
        {"current_nav": 0.0},
        {"current_nav": -1.0},
        {"current_nav": float("inf")},
        {"current_nav": float("nan")},
        {"open_nav": 0.0},
        {"current_nav": "lots"},
        {"observed_at": time.time() + trade_inputs.MAX_CLOCK_SKEW_S + 60.0},
        {"observed_at": time.time() - trade_inputs.MAX_NAV_AGE_S - 1.0},
    ],
    ids=[
        "unverified",
        "no-source",
        "zero",
        "negative",
        "inf",
        "nan",
        "zero-open",
        "malformed",
        "future",
        "stale",
    ],
)
async def test_resolve_rejects_untrustworthy_nav(overrides: dict[str, Any]) -> None:
    with pytest.raises(TradeInputUnavailable):
        await resolve_portfolio_total(_FixedNav(**overrides))


@pytest.mark.asyncio
async def test_resolve_accepts_small_future_skew() -> None:
    skewed = time.time() + trade_inputs.MAX_CLOCK_SKEW_S / 2
    assert await resolve_portfolio_total(
        _FixedNav(observed_at=skewed)
    ) == pytest.approx(_OPEN_NAV)
