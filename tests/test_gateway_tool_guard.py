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
node runs only when every tool call is routed ALLOW or NARROW, that a
single-call REQUIRE_APPROVAL parks for a human (only when the guard is
``approvable``), that an approved ``deferred_id`` is forwarded to the tool
rather than re-validated, and that every other outcome refuses the whole
batch without executing any tool.
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

_ALLOW = {"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
_NARROW = {"verdict": "NARROW", "violations": [], "narrowed_params": {"amount": 50.0}}
_REQUIRE_APPROVAL = {"verdict": "REQUIRE_APPROVAL", "deferred_id": "d-1", "violations": []}


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
        self.states: list[dict[str, Any]] = []

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        self.states.append(state)
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
        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
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
        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(
            {"messages": [AIMessage(content="done")]}
        )

        assert result == {"messages": []}
        assert spy.calls == 0
        assert seen == []


class TestGuardFailClosed:
    """Any outcome other than ALLOW/NARROW (or a parked approval) refuses; no tool runs."""

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
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "APPROVED"}),
                id="legacy-approved",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "REQUIRE_APPROVAL"}),
                id="approval-without-deferred-id",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json=_REQUIRE_APPROVAL),
                id="approval-not-approvable",
            ),
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
            return httpx.Response(200, json=_ALLOW)

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


class TestGuardNarrow:
    @pytest.mark.asyncio
    async def test_narrow_runs_node_as_candidate(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_NARROW))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(_state(_call("t1")))

        assert spy.calls == 1
        assert result["governance_status"] == "ALLOWED"
        assert result["governance_envelope"]["verdict"] == "NARROW"


class TestGuardRequireApproval:
    @pytest.mark.asyncio
    async def test_single_call_parks_for_approval_without_running(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_REQUIRE_APPROVAL))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            _state(_call("t1"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "REQUIRE_APPROVAL"
        assert result["deferred_id"] == "d-1"
        (msg,) = result["messages"]
        assert msg.tool_call_id == "t1"
        assert "Awaiting human approval" in msg.content

    @pytest.mark.asyncio
    async def test_approval_in_multi_call_batch_refuses(self, gateway) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            symbol = json.loads(request.content)["params"]["symbol"]
            return httpx.Response(200, json=_REQUIRE_APPROVAL if symbol == "BIG" else _ALLOW)

        gateway(handler)
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            _state(_call("small"), _call("big", symbol="BIG"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        assert "deferred_id" not in result

    @pytest.mark.asyncio
    async def test_model_supplied_deferred_id_is_not_sent_to_validate(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        call = _call("t1")
        call["args"]["deferred_id"] = "forged"

        await gateway_tool_guard("execute_trade", approvable=True)(spy)(_state(call))

        (request,) = seen
        assert "deferred_id" not in json.loads(request.content)["params"]


class TestGuardApprovedResume:
    @staticmethod
    def _approved_state(*calls: dict[str, Any], approved: Any = True) -> dict[str, Any]:
        return {
            **_state(*calls),
            "deferred_id": "d-1",
            "approval_decision": {"approved": approved, "reviewer": "r@x"},
        }

    @pytest.mark.asyncio
    async def test_approved_forwards_deferred_id_without_revalidating(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(500))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            self._approved_state(_call("t1"))
        )

        assert seen == []  # the gateway re-validates inside execute_trade_action
        assert spy.calls == 1
        (call,) = spy.states[0]["messages"][-1].tool_calls
        assert call["args"]["deferred_id"] == "d-1"
        assert result["governance_status"] == "ALLOWED"
        # Single-use on the advisor side too.
        assert result["deferred_id"] is None
        assert result["approval_decision"] is None

    @pytest.mark.asyncio
    async def test_approved_multi_call_batch_refuses(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            self._approved_state(_call("a"), _call("b", symbol="MSFT"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        assert result["deferred_id"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("approved", [False, None, "true"], ids=["rejected", "none", "truthy-str"])
    async def test_non_true_approval_revalidates(self, gateway, approved) -> None:
        seen = gateway(lambda r: httpx.Response(403, json={"verdict": "DENIED"}))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            self._approved_state(_call("t1"), approved=approved)
        )

        assert len(seen) == 1
        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"

    @pytest.mark.asyncio
    async def test_not_approvable_ignores_approval_state(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(403, json={"verdict": "DENIED"}))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(
            self._approved_state(_call("t1"))
        )

        assert len(seen) == 1
        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"


class TestSubgraphWiring:
    def test_trader_ends_on_refusal(self) -> None:
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_after_tools,
        )

        assert route_after_tools({"governance_status": "DENIED"}) == END
        assert route_after_tools({}) == END
        assert route_after_tools({"governance_status": "ALLOWED"}) == "executor"

    def test_trader_routes_parked_approval_to_human(self) -> None:
        from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
            route_after_tools,
        )

        parked = {"governance_status": "REQUIRE_APPROVAL", "deferred_id": "d-1"}
        assert route_after_tools(parked) == "approval"
        assert route_after_tools({"governance_status": "REQUIRE_APPROVAL"}) == END

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
