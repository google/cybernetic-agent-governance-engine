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

"""Advisor graph -> gateway previews -> trade tool, end to end (POAM-2026-105).

The advisor's two previews (``safety_check_node`` and the
``gateway_tool_guard`` around the trader) ask the real gateway app over ASGI
at ``/governance/validate-action``. The trade tool then runs the single
committing pass with the same governor. Before the server-input seam, the
previews evaluated whatever STPA inputs the caller sent. The advisor sent
none, so UCA-2 / UCA-5 (and UCA-13 on sells) refused every trade before it
reached the tool. The evaluator only passed because it injected 0.0 defaults.

Now both paths bind the finance plugin's server-side inputs (quote age,
NAV drawdown, current NAV) through ``PluginContribution.server_inputs``:

* a normal buy clears both previews and executes once, in every region;
* caller values for those keys are ignored, both out-of-limit and
  falsely in-limit ones;
* a faulted source refuses the trade in the preview, with a refusal receipt,
  and the committing tool refuses it as well, with nothing actuated.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from typing import Any

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from src.cage_finance.stpa import uca_rules
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.server.workload_identity import CLIENT_IDENTITY_HEADER
from src.governed_financial_advisor.graph.governance.tool_guard import (
    gateway_tool_guard,
)
from src.governed_financial_advisor.graph.nodes.safety_node import safety_check_node
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from tests.test_trade_governance_e2e import (  # noqa: F401  (gw is a fixture)
    ADVISOR,
    Gateway,
    gw,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_UCA_2 = "STPA_UCA_UCA_2"
_UCA_5 = "STPA_UCA_UCA_5"
_UCA_13 = "STPA_UCA_UCA_13"
#: region -> UCA-5 max daily drawdown (%)
_DRAWDOWN_LIMIT = {"US_FED": 4.5, "APAC_MAS": 4.0, "EU_ECB": 3.5}
_TOOL_KWARGS = frozenset(inspect.signature(execute_trade_action).parameters)


@pytest.fixture(params=tuple(_DRAWDOWN_LIMIT))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated finance rules to ``region``'s effective thresholds."""
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


@pytest.fixture
async def advisor(gw: Gateway) -> AsyncIterator[Gateway]:  # noqa: F811
    """Route the advisor's ``GatewayClient`` singleton to the gateway app."""
    GatewayClient._instance = None
    gw.http.headers[CLIENT_IDENTITY_HEADER] = ADVISOR  # mesh workload identity
    GatewayClient()._http = gw.http
    yield gw
    GatewayClient._instance = None


def _plan(side: str = "buy", amount: float = 500.0) -> dict[str, Any]:
    return {
        "action": "execute_trade",
        "symbol": "AAPL",
        "amount": amount,
        "currency": "USD",
        "confidence": 0.99,
        "side": side,
    }


def _tool_call(side: str = "buy", **extra: Any) -> dict[str, Any]:
    return {
        "name": "execute_trade_action",
        "id": "call-1",
        "args": {
            "symbol": "AAPL",
            "amount": 500.0,
            "currency": "USD",
            "confidence": 0.99,
            "trader_id": "agent_001",
            "trader_role": "junior",
            "side": side,
            **extra,
        },
    }


def _trader(gateway: Gateway, results: list[str]) -> Any:
    """The governed trader: the trade tool's committing run, per tool call.

    The live node calls the tool over MCP; arguments the tool does not accept
    are rejected there, so they are dropped here too.
    """

    async def node(state: dict[str, Any]) -> dict[str, Any]:
        messages = []
        for call in state["messages"][-1].tool_calls:
            kwargs = {k: v for k, v in call["args"].items() if k in _TOOL_KWARGS}
            result = await execute_trade_action(
                **kwargs,
                deferred_id=state.get("deferred_id"),
                governor=gateway.governor,
            )
            results.append(result)
            messages.append(ToolMessage(content=result, tool_call_id=call["id"]))
        return {"messages": messages}

    return node


async def _run_trader(gateway: Gateway, call: dict[str, Any]) -> tuple[dict, list[str]]:
    results: list[str] = []
    guarded = gateway_tool_guard("execute_trade", approvable=True)(
        _trader(gateway, results)
    )
    out = await guarded({"messages": [AIMessage(content="", tool_calls=[call])]})
    return out, results


def _refused_codes(gateway: Gateway) -> str:
    return " ".join(
        f"{c.kwargs.get('refusal_reason')} {c.kwargs.get('receipt')}"
        for c in gateway.refusals.await_args_list
    )


# ---------------------------------------------------------------------------
# A normal buy reaches and clears the trade tool, in every region
# ---------------------------------------------------------------------------


async def test_normal_buy_clears_both_previews_and_executes_once(
    advisor: Gateway, region: str
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan()})
    assert safety["safety_status"] == "APPROVED", safety

    out, results = await _run_trader(advisor, _tool_call())

    assert out["governance_status"] != "DENIED", out
    assert len(results) == 1 and results[0].startswith("EXECUTED"), results
    advisor.actuate.assert_awaited_once()
    advisor.refusals.assert_not_awaited()


async def test_normal_sell_clears_both_previews_and_executes_once(
    advisor: Gateway, region: str
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan(side="sell")})
    assert safety["safety_status"] == "APPROVED", safety

    out, results = await _run_trader(advisor, _tool_call(side="sell"))

    assert len(results) == 1 and results[0].startswith("EXECUTED"), (out, results)
    advisor.actuate.assert_awaited_once()


# ---------------------------------------------------------------------------
# Caller-supplied STPA inputs are never read
# ---------------------------------------------------------------------------


async def test_out_of_limit_caller_inputs_do_not_refuse_the_preview(
    advisor: Gateway,
) -> None:
    call = _tool_call(
        latency_ms=10_000.0, drawdown=99.0, current_drawdown=0.99, portfolio_total=1.0
    )

    out, results = await _run_trader(advisor, call)

    assert len(results) == 1 and results[0].startswith("EXECUTED"), (out, results)
    advisor.refusals.assert_not_awaited()


async def test_in_limit_caller_inputs_do_not_mask_a_server_breach(
    advisor: Gateway, region: str
) -> None:
    # The NAV source reports a drawdown just over the region's limit; the
    # caller claims a flat book and a fresh quote, under every alias.
    advisor.nav_source.set_drawdown_pct(_DRAWDOWN_LIMIT[region] + 0.25)
    call = _tool_call(
        latency_ms=0.0, drawdown=0.0, portfolio_drawdown_pct=0.0, current_drawdown=0.0
    )

    out, results = await _run_trader(advisor, call)

    assert results == [], "the preview must refuse before the tool runs"
    assert out["governance_status"] == "DENIED", out
    assert _UCA_5 in _refused_codes(advisor)
    advisor.actuate.assert_not_awaited()


async def test_the_regional_drawdown_floor_binds_the_preview(
    advisor: Gateway, region: str
) -> None:
    # 4.25 % is inside the US limit (4.5) but outside APAC (4.0) and EU (3.5).
    advisor.nav_source.set_drawdown_pct(4.25)

    safety = await safety_check_node({"execution_plan_output": _plan()})

    expected = "APPROVED" if region == "US_FED" else "BLOCKED"
    assert safety["safety_status"] == expected, safety


# ---------------------------------------------------------------------------
# Faulted sources: refused in the preview with evidence, and at commit
# ---------------------------------------------------------------------------


async def _assert_refused_everywhere(
    gateway: Gateway, codes: tuple[str, ...], side: str = "buy"
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan(side=side)})
    assert safety["safety_status"] == "BLOCKED", safety
    for code in codes:
        assert code in safety["last_violation"]["evidence"], safety

    # Refusal receipt for the preview (validate-action).
    gateway.refusals.assert_awaited()
    assert all(
        c.kwargs.get("action_id") == "execute_trade"
        for c in gateway.refusals.await_args_list
    )
    assert codes[0] in _refused_codes(gateway)

    # The committing tool, called directly (no preview), refuses too.
    gateway.refusals.reset_mock()
    result = await execute_trade_action(
        "AAPL",
        500.0,
        "USD",
        0.99,
        None,
        "agent_001",
        "junior",
        side=side,
        governor=gateway.governor,
    )
    assert result.startswith("BLOCKED"), result
    assert codes[0] in _refused_codes(gateway)
    gateway.actuate.assert_not_awaited()
    assert await gateway.seal_redis.dbsize() == 0


@pytest.mark.parametrize("fault", [FaultMode.TIMEOUT, FaultMode.STALE_TIMESTAMP])
async def test_market_feed_fault_refuses_with_uca_2(
    advisor: Gateway, region: str, fault: FaultMode
) -> None:
    advisor.market_feed.inject_fault(fault)
    await _assert_refused_everywhere(advisor, (_UCA_2,))


async def test_nav_fault_refuses_a_buy_with_uca_5(
    advisor: Gateway, region: str
) -> None:
    advisor.nav_source.inject_fault(FaultMode.CONNECTION_ERROR)
    await _assert_refused_everywhere(advisor, (_UCA_5,))


async def test_nav_fault_refuses_a_sell_with_uca_5_and_uca_13(
    advisor: Gateway,
) -> None:
    advisor.nav_source.inject_fault(FaultMode.NAN_VALUE)
    await _assert_refused_everywhere(advisor, (_UCA_5, _UCA_13), side="sell")
    # The committing run's receipt records the bound params: no NAV-derived
    # input was resolved, and none was taken from the caller.
    (receipt,) = advisor.refusals.await_args_list
    assert not {"drawdown", "portfolio_total"} & set(receipt.kwargs["params"])


async def test_the_regional_volume_fraction_binds_the_preview(
    advisor: Gateway, region: str
) -> None:
    # 70 shares (~$7,000 at ~$100) of a 10,000-share average day is 0.7 %:
    # inside US_FED (1 %) and APAC_MAS (0.8 %), outside EU_ECB (0.5 %).
    advisor.market_feed.set_daily_volume(10_000.0)

    safety = await safety_check_node({"execution_plan_output": _plan(amount=7_000.0)})

    if region == "EU_ECB":
        assert safety["safety_status"] == "BLOCKED", safety
        assert "STPA_UCA_UCA_6" in safety["last_violation"]["evidence"]
    else:
        assert safety["safety_status"] == "APPROVED", safety


async def test_daily_volume_fault_refuses_with_uca_6(
    advisor: Gateway, region: str
) -> None:
    advisor.market_feed.inject_volume_fault(FaultMode.STALE_TIMESTAMP)
    await _assert_refused_everywhere(advisor, ("STPA_UCA_UCA_6",))
