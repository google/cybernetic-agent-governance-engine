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

"""Unit tests for the advisor's gateway tool guard (POAM-2026-080).

``gateway_tool_guard`` gates the data-analyst and governed-trader tool
executors on ``POST /governance/validate-action``. These tests drive the real
``GatewayClient`` over an ``httpx.MockTransport`` and assert that the wrapped
node runs only on an explicit APPROVED verdict for every tool call, and that
every other outcome refuses the whole batch without executing any tool.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END

from src.governed_financial_advisor.graph.governance.tool_guard import (
    gateway_tool_guard,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

pytestmark = [pytest.mark.unit, pytest.mark.local]

Handler = Callable[[httpx.Request], httpx.Response]

_APPROVED = {"verdict": "APPROVED", "violations": [], "latency_ms": 1.0}


@pytest.fixture
def gateway() -> Iterator[Callable[[Handler], list[httpx.Request]]]:
    """Install a MockTransport behind the GatewayClient singleton."""
    GatewayClient._instance = None

    def install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(recording), base_url="http://gateway.test"
        )
        return seen

    yield install
    GatewayClient._instance = None


class _SpyNode:
    """Stand-in tool executor that records whether it ran."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return {"messages": [ToolMessage(content="executed", tool_call_id="t1")]}


def _state(*tool_calls: dict[str, Any]) -> dict[str, Any]:
    return {"messages": [AIMessage(content="", tool_calls=list(tool_calls))]}


def _call(call_id: str, symbol: str = "AAPL", amount: float = 100.0) -> dict[str, Any]:
    return {
        "name": "execute_trade_action",
        "args": {"symbol": symbol, "amount": amount, "confidence": 0.99},
        "id": call_id,
    }


class TestGuardApproval:
    @pytest.mark.asyncio
    async def test_all_approved_runs_node(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(200, json=_APPROVED))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(
            _state(_call("t1"), _call("t2", symbol="MSFT"))
        )

        assert spy.calls == 1
        assert result["governance_status"] == "ALLOWED"
        assert result["messages"][0].content == "executed"
        # Every tool call is validated individually — not just the first.
        assert [r.url.path for r in seen] == ["/governance/validate-action"] * 2
        bodies = [json.loads(r.content) for r in seen]
        assert {b["params"]["symbol"] for b in bodies} == {"AAPL", "MSFT"}
        assert all(b["action"] == "execute_trade" for b in bodies)
        assert all(
            b["params"]["tool_name"] == "execute_trade_action" for b in bodies
        )

    @pytest.mark.asyncio
    async def test_no_tool_calls_does_not_run_node(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(200, json=_APPROVED))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(
            {"messages": [AIMessage(content="done")]}
        )

        assert result == {"messages": []}
        assert spy.calls == 0
        assert seen == []


class TestGuardFailClosed:
    """Any non-APPROVED gateway outcome refuses the batch; no tool runs."""

    @pytest.mark.parametrize(
        "handler",
        [
            pytest.param(
                lambda r: httpx.Response(
                    403, json={"verdict": "DENIED", "violations": ["limit"]}
                ),
                id="denied-403",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "DENIED"}),
                id="denied-200",
            ),
            pytest.param(lambda r: httpx.Response(500), id="gateway-500"),
            pytest.param(lambda r: httpx.Response(401), id="unauthenticated-401"),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "PAUSE"}), id="pause"
            ),
            pytest.param(
                lambda r: httpx.Response(
                    202, json={"verdict": "DEFER", "defer_id": "d-1"}
                ),
                id="defer",
            ),
            pytest.param(lambda r: httpx.Response(200, json={}), id="no-verdict"),
        ],
    )
    @pytest.mark.asyncio
    async def test_non_approval_refuses(self, gateway, handler: Handler) -> None:
        gateway(handler)
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(_state(_call("t1")))

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        assert result["governance_envelope"] is None
        (msg,) = result["messages"]
        assert isinstance(msg, ToolMessage)
        assert msg.tool_call_id == "t1"
        assert msg.content.startswith("Governance refused this action")

    @pytest.mark.parametrize(
        "exc",
        [httpx.ReadTimeout, httpx.ConnectError],
        ids=["timeout", "unreachable"],
    )
    @pytest.mark.asyncio
    async def test_transport_failure_refuses(self, gateway, exc) -> None:
        def fail(request: httpx.Request) -> httpx.Response:
            raise exc("gateway down", request=request)

        gateway(fail)
        spy = _SpyNode()

        result = await gateway_tool_guard("fetch_market_data")(spy)(
            _state(_call("t1"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        assert exc.__name__ in result["messages"][0].content

    @pytest.mark.asyncio
    async def test_one_denial_refuses_whole_batch(self, gateway) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            symbol = json.loads(request.content)["params"]["symbol"]
            if symbol == "EVIL":
                return httpx.Response(403, json={"verdict": "DENIED"})
            return httpx.Response(200, json=_APPROVED)

        gateway(handler)
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(
            _state(_call("ok"), _call("bad", symbol="EVIL"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        by_id = {m.tool_call_id: m.content for m in result["messages"]}
        assert set(by_id) == {"ok", "bad"}
        assert "another tool call in the same batch was refused" in by_id["ok"]


class TestSubgraphWiring:
    def test_trader_ends_on_refusal(self) -> None:
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_after_tools,
        )

        assert route_after_tools({"governance_status": "DENIED"}) == END
        assert route_after_tools({}) == END
        assert route_after_tools({"governance_status": "ALLOWED"}) == "executor"

    def test_trader_graph_compiles_with_guarded_tools(self) -> None:
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            build_governed_trader_graph,
        )

        graph = build_governed_trader_graph()
        assert "tools" in graph.get_graph().nodes

    def test_subgraphs_wrap_their_tool_executors(self) -> None:
        from src.governed_financial_advisor.graph.subgraphs import (
            data_analyst_graph,
            governed_trader_graph,
        )

        for module in (data_analyst_graph, governed_trader_graph):
            guarded = module.guarded_tool_executor_node
            assert guarded is not module.tool_executor_node
            assert guarded.__wrapped__ is module.tool_executor_node
