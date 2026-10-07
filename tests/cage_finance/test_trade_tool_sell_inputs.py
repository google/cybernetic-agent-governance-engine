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
reads ``portfolio_total`` from the governor's custodian-ledger ground-truth
provider, never from the caller. These tests run the params the tool hands to
governance through the generated finance STPA rules for each region:

* a sell within the regional fraction clears the STPA stage;
* a sell over it is a HARD UCA-13 violation;
* a missing or untrustworthy ledger leaves ``portfolio_total`` unset, and
  UCA-13 refuses the sell;
* a buy is unchanged: no ledger read, no ``portfolio_total``, no UCA-13.
"""

from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.stpa import uca_rules
from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator
from src.cage_finance.tools import portfolio_valuation, tool_provider
from src.cage_finance.tools.portfolio_valuation import (
    PortfolioValuationUnavailable,
    resolve_portfolio_total,
)
from src.cage_finance.tools.tool_provider import (
    _approval_covers_trade,
    execute_trade_action,
)
from src.cage_finance.tools.trade_inputs import ServerTradeInputs
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    GroundTruthSnapshot,
    InMemoryLedgerJournal,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

#: In-limit UCA-2 / UCA-5 inputs, so only UCA-13 decides the sell.
_TRADE_INPUTS = ServerTradeInputs(
    market_feed=SimulatedMarketQuoteFeed(seed=0, publication_delay_ms=(10.0, 10.0)),
    nav_source=SimulatedPortfolioNavSource(),
)

_UCA_13 = "STPA_UCA_UCA_13"
_PORTFOLIO = 100_000.0
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


def _ledger(total: float = _PORTFOLIO) -> SimulatedCashLedgerProvider:
    return SimulatedCashLedgerProvider(
        initial_scalar=total,
        barrier_floor=0.0,
        seed=7,
        journal=InMemoryLedgerJournal(),
        settlement_lag_s=0.0,
    )


def _governor(providers: dict[str, Any] | None = None) -> MagicMock:
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    governor.components.ground_truth_providers = (
        {_CASH: _ledger()} if providers is None else providers
    )
    return governor


async def _trade(governor: Any, amount: float, **kwargs: Any) -> str:
    return await execute_trade_action(
        symbol="AAPL",
        amount=amount,
        currency="USD",
        confidence=0.99,
        inputs=_TRADE_INPUTS,
        governor=governor,
        **kwargs,
    )


def _limit(region: str) -> float:
    return _FRACTION[region] * _PORTFOLIO


# ── STPA stage outcomes per region ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_sell_within_regional_limit_clears_stpa(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    with pytest.raises(_Cleared) as cleared:
        await _trade(_governor(), _limit(region) * 0.5, side="sell")
    params = cleared.value.params
    assert params["side"] == "sell"
    assert params["portfolio_total"] == pytest.approx(_PORTFOLIO)


@pytest.mark.asyncio
async def test_sell_over_regional_limit_is_hard_uca13(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _trade(_governor(), _limit(region) * 1.5, side="sell")
    assert result.startswith("BLOCKED:")
    assert _UCA_13 in result
    assert stpa_gateway[-1]["portfolio_total"] == pytest.approx(_PORTFOLIO)


@pytest.mark.asyncio
async def test_regions_differ_at_the_same_sell(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """8,500 of 100,000 is refused under EU_ECB (8%) only."""
    try:
        result = await _trade(_governor(), 8_500.0, side="sell")
    except _Cleared:
        result = "CLEARED"
    assert (_UCA_13 in result) is (region == "EU_ECB")


@pytest.mark.asyncio
async def test_missing_ledger_provider_refuses_sell(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    result = await _trade(_governor(providers={}), 1.0, side="sell")
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
        FaultMode.MALFORMED_PAYLOAD,
    ],
)
async def test_faulted_ledger_refuses_sell(
    region: str, stpa_gateway: list[dict[str, Any]], fault: FaultMode
) -> None:
    ledger = _ledger()
    ledger.inject_fault(fault)
    result = await _trade(_governor({_CASH: ledger}), 1.0, side="sell")
    assert result.startswith("BLOCKED:")
    assert _UCA_13 in result
    assert "portfolio_total" not in stpa_gateway[-1]


@pytest.mark.asyncio
async def test_buy_is_unchanged(
    region: str, stpa_gateway: list[dict[str, Any]]
) -> None:
    """A buy never reads the ledger, carries no portfolio_total, and skips UCA-13."""
    provider = MagicMock()
    provider.fetch_snapshot = AsyncMock(side_effect=AssertionError("ledger read"))
    with pytest.raises(_Cleared) as cleared:
        await _trade(_governor({_CASH: provider}), _PORTFOLIO * 10)
    params = cleared.value.params
    assert params["side"] == "buy"
    assert "portfolio_total" not in params
    provider.fetch_snapshot.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_side_is_blocked_before_governance(
    stpa_gateway: list[dict[str, Any]],
) -> None:
    result = await _trade(_governor(), 1.0, side="short")  # type: ignore[arg-type]
    assert result.startswith("BLOCKED: invalid trade side")
    assert stpa_gateway == []


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

    tool_provider.FinancialToolProvider(_TRADE_INPUTS).register_tools(
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


def _snapshot_provider(**overrides: Any) -> MagicMock:
    fields: dict[str, Any] = {
        "invariant_id": _CASH,
        "state_key": "safety:current_cash",
        "scalar": _PORTFOLIO,
        "source_id": "simulated:finance_cash_ledger",
    }
    fields.update(overrides)
    provider = MagicMock()
    provider.fetch_snapshot = AsyncMock(return_value=GroundTruthSnapshot(**fields))
    return provider


@pytest.mark.asyncio
async def test_resolve_returns_ledger_value() -> None:
    total = await resolve_portfolio_total(_governor({_CASH: _snapshot_provider()}))
    assert total == pytest.approx(_PORTFOLIO)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"source_id": "unverified_rogue_feed"},
        {"source_id": ""},
        {"invariant_id": "other.invariant"},
        {"scalar": 0.0},
        {"scalar": float("inf")},
        {"observed_at": 10_000_000_000.0},
    ],
    ids=["unverified", "no-source", "wrong-invariant", "zero", "inf", "future"],
)
async def test_resolve_rejects_untrustworthy_snapshot(overrides: dict) -> None:
    governor = _governor({_CASH: _snapshot_provider(**overrides)})
    with pytest.raises(PortfolioValuationUnavailable):
        await resolve_portfolio_total(governor)


@pytest.mark.asyncio
async def test_resolve_rejects_snapshot_older_than_reconciler_ttl() -> None:
    import time

    old = time.time() - portfolio_valuation.MAX_SNAPSHOT_AGE_S - 1.0
    governor = _governor({_CASH: _snapshot_provider(observed_at=old)})
    with pytest.raises(PortfolioValuationUnavailable, match="stale"):
        await resolve_portfolio_total(governor)
