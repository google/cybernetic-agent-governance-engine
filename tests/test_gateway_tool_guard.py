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
``GatewayClient`` over an ``httpx.MockTransport`` whose verdicts are signed by
``SignedGatewayStub`` (the advisor verifies every envelope through the
``cage-client`` wheel) and assert that the wrapped
node runs only when every tool call is routed ALLOW or NARROW, that a
single-call REQUIRE_APPROVAL parks for a human (only when the guard is
``approvable``), that an approved ``deferred_id`` is forwarded to the tool
rather than re-validated, and that every other outcome refuses the whole
batch without executing any tool.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END

import src.governed_financial_advisor.graph.governance.tool_guard as tool_guard_module
from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.infrastructure.mcp_client import MCPToolOutcomeUnknownError
from src.governed_financial_advisor.graph.governance.tool_guard import (
    COMMIT_OUTCOMES,
    derive_transaction_id,
    gateway_tool_guard,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from tests.fixtures.signed_gateway import SignedGatewayStub

pytestmark = [pytest.mark.unit, pytest.mark.local]

Handler = Callable[[httpx.Request], httpx.Response]

_ALLOW = {"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
_NARROW = {"verdict": "NARROW", "violations": [], "narrowed_params": {"amount": 50.0}}
_REQUIRE_APPROVAL = {
    "verdict": "REQUIRE_APPROVAL",
    "deferred_id": "d-1",
    "violations": [],
}


@pytest.fixture
def gateway() -> Iterator[Callable[[Handler], list[httpx.Request]]]:
    """Install a signing MockTransport behind the GatewayClient singleton.

    ``SignedGatewayStub`` signs each 200 verdict a handler returns, so the
    advisor's cage-client envelope verification runs for real. JWKS fetches
    are answered by the stub and are not recorded.
    """
    GatewayClient._instance = None
    stub = SignedGatewayStub()

    def install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(stub.transport_handler(recording)),
            base_url="http://gateway.test",
        )
        return seen

    yield install
    GatewayClient._instance = None


class _SpyNode:
    """Stand-in tool executor that records whether it ran.

    It always reports EXECUTED; ``_ScriptedOutcomeNode`` reports the outcomes
    that can follow a sent request without confirming it.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.states: list[dict[str, Any]] = []

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        self.states.append(state)
        calls = getattr(state["messages"][-1], "tool_calls", None) or []
        # Like tool_executor_node: one typed outcome per committing call.
        return {
            "messages": [ToolMessage(content="executed", tool_call_id="t1")],
            COMMIT_OUTCOMES: {
                str(c.get("id")): CommitOutcome(CommitStatus.EXECUTED, "executed")
                for c in calls
                if c.get("name") == "execute_trade_action"
            },
        }


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
        assert all(b["params"]["tool_name"] == "execute_trade_action" for b in bodies)

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
                    403,
                    json={
                        "schema_version": "2.0.0",
                        "verdict": "DENIED",
                        "violations": ["limit"],
                        "proof_hash": "sha256:test-guard-refusal-1",
                    },
                ),
                id="denied-403",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "DENIED"}),
                id="denied-200",
            ),
            pytest.param(lambda r: httpx.Response(401), id="unauthenticated-401"),
            pytest.param(
                # PAUSE was removed from GovernanceDecision; a gateway that still
                # says it is speaking a vocabulary the advisor does not route on.
                lambda r: httpx.Response(200, json={"verdict": "PAUSE"}),
                id="legacy-pause",
            ),
            pytest.param(
                lambda r: httpx.Response(
                    200,
                    json={
                        "verdict": "DEFER",
                        "defer_token": "d-1",
                        "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                        "violations": [],
                    },
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

    @pytest.mark.asyncio
    async def test_gateway_500_fails_as_unavailable(self, gateway) -> None:
        gateway(lambda _r: httpx.Response(500))
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade")(spy)(_state(_call("t1")))

        assert spy.calls == 0
        assert result["governance_status"] == "UNAVAILABLE"
        assert result["governance_envelope"] is None
        (msg,) = result["messages"]
        assert isinstance(msg, ToolMessage)
        assert msg.tool_call_id == "t1"
        assert msg.content.startswith(
            "Governance unavailable (gateway infrastructure error)"
        )

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

        result = await gateway_tool_guard("market_analysis")(spy)(_state(_call("t1")))

        assert spy.calls == 0
        assert result["governance_status"] == "UNAVAILABLE"
        assert result["messages"][0].content.startswith(
            "Governance unavailable (gateway infrastructure error)"
        )
        assert exc.__name__ in result["messages"][0].content

    @pytest.mark.asyncio
    async def test_one_denial_refuses_whole_batch(self, gateway) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            symbol = json.loads(request.content)["params"]["symbol"]
            if symbol == "EVIL":
                return httpx.Response(
                    403,
                    json={
                        "schema_version": "2.0.0",
                        "verdict": "DENIED",
                        "violations": ["blocked symbol"],
                        "proof_hash": "sha256:test-guard-refusal-2",
                    },
                )
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
    async def test_single_call_parks_for_approval_without_running(
        self, gateway
    ) -> None:
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
        assert "needs reviewer approval" in msg.content
        # Deferral handles belong to reviewers at the bridge (SA-1, POAM-2026-245).
        assert "d-1" not in msg.content and "deferred_id" not in msg.content

    @pytest.mark.asyncio
    async def test_approval_in_multi_call_batch_refuses(self, gateway) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            symbol = json.loads(request.content)["params"]["symbol"]
            return httpx.Response(
                200, json=_REQUIRE_APPROVAL if symbol == "BIG" else _ALLOW
            )

        gateway(handler)
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            _state(_call("small"), _call("big", symbol="BIG"))
        )

        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"
        assert "deferred_id" not in result

    @pytest.mark.asyncio
    async def test_model_supplied_deferred_id_is_not_sent_to_validate(
        self, gateway
    ) -> None:
        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        call = _call("t1")
        call["args"]["deferred_id"] = "forged"

        await gateway_tool_guard("execute_trade", approvable=True)(spy)(_state(call))

        (request,) = seen
        assert "deferred_id" not in json.loads(request.content)["params"]

    @pytest.mark.parametrize("approvable", [True, False], ids=["approvable", "plain"])
    @pytest.mark.asyncio
    async def test_model_supplied_deferred_id_never_reaches_the_executed_call(
        self, gateway, approvable: bool
    ) -> None:
        # GHSA-w39v-5v7h-fxg9: validate-action previewed these calls without
        # the model's deferred_id, so the calls that execute must not carry it
        # either. Otherwise an ALLOW for one trade lets the executed call
        # redeem an approval the model named, outside the approval path.
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        forged = _call("t1")
        forged["args"]["deferred_id"] = "forged"
        other = _call("t2", symbol="MSFT")
        other["args"]["deferred_id"] = "forged-too"

        result = await gateway_tool_guard("execute_trade", approvable=approvable)(spy)(
            _state(forged, other)
        )

        assert spy.calls == 1
        executed = spy.states[0]["messages"][-1].tool_calls
        assert [c["id"] for c in executed] == ["t1", "t2"]
        assert [
            {k: v for k, v in c["args"].items() if k != "transaction_id"}
            for c in executed
        ] == [
            _call("t1")["args"],
            _call("t2", symbol="MSFT")["args"],
        ]
        assert result["governance_status"] == "ALLOWED"


class TestGuardApprovedResume:
    @staticmethod
    def _approved_state(*calls: dict[str, Any], approved: Any = True) -> dict[str, Any]:
        return {
            **_state(*calls),
            "deferred_id": "d-1",
            "approval_decision": {"approved": approved, "reviewer": "r@x"},
        }

    @pytest.mark.asyncio
    async def test_approved_forwards_deferred_id_without_revalidating(
        self, gateway
    ) -> None:
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
    async def test_approved_resume_replaces_a_model_supplied_deferred_id(
        self, gateway
    ) -> None:
        gateway(lambda r: httpx.Response(500))
        spy = _SpyNode()
        call = _call("t1")
        call["args"]["deferred_id"] = "forged"

        await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            self._approved_state(call)
        )

        (executed,) = spy.states[0]["messages"][-1].tool_calls
        assert {k: v for k, v in executed["args"].items() if k != "transaction_id"} == {
            **_call("t1")["args"],
            "deferred_id": "d-1",
        }

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
    @pytest.mark.parametrize(
        "approved", [False, None, "true"], ids=["rejected", "none", "truthy-str"]
    )
    async def test_non_true_approval_revalidates(self, gateway, approved) -> None:
        seen = gateway(
            lambda r: httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["approval not true"],
                    "proof_hash": "sha256:test-guard-refusal-3",
                },
            )
        )
        spy = _SpyNode()

        result = await gateway_tool_guard("execute_trade", approvable=True)(spy)(
            self._approved_state(_call("t1"), approved=approved)
        )

        assert len(seen) == 1
        assert spy.calls == 0
        assert result["governance_status"] == "DENIED"

    @pytest.mark.asyncio
    async def test_not_approvable_ignores_approval_state(self, gateway) -> None:
        seen = gateway(
            lambda r: httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["not approvable"],
                    "proof_hash": "sha256:test-guard-refusal-4",
                },
            )
        )
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


class TestGuardTransactionIds:
    """Trade tool calls carry a derived, deterministic transaction_id (#514)."""

    @staticmethod
    def _txn(state: dict[str, Any], index: int = 0) -> str:
        return state["messages"][-1].tool_calls[index]["args"]["transaction_id"]

    @pytest.mark.asyncio
    async def test_overrides_the_model_supplied_transaction_id(self, gateway) -> None:
        from src.governed_financial_advisor.graph.governance.tool_guard import (
            derive_plan_step_key,
        )

        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        call = _call("call-1")
        call["args"]["transaction_id"] = "chosen-by-the-model"
        state = {"messages": [AIMessage(content="", tool_calls=[call], id="ai-1")]}

        await gateway_tool_guard("execute_trade")(spy)(state)

        executed = spy.states[0]["messages"][-1].tool_calls[0]
        txn = executed["args"]["transaction_id"]
        assert txn != "chosen-by-the-model"
        assert uuid.UUID(txn).version == 5
        expected_step = derive_plan_step_key(call["args"])
        assert txn == derive_transaction_id(
            expected_step, thread_id=None, message_id="ai-1"
        )
        # Only transaction_id changes.
        assert {k: v for k, v in executed["args"].items() if k != "transaction_id"} == {
            k: v for k, v in call["args"].items() if k != "transaction_id"
        }
        # The preview authorizes the order; the call's key is not part of it.
        assert "transaction_id" not in json.loads(seen[0].content)["params"]

    @pytest.mark.asyncio
    async def test_same_intent_in_same_thread_keeps_key_even_with_new_tool_call_id(
        self, gateway, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.governed_financial_advisor.graph.governance.tool_guard import (
            derive_plan_step_key,
        )

        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        guarded = gateway_tool_guard("execute_trade")(spy)
        thread = {"configurable": {"thread_id": "thread-7"}}
        monkeypatch.setattr(tool_guard_module, "get_config", lambda: thread)

        # A regenerated AIMessage produces a fresh LLM tool_call_id and message id,
        # yet the trade intent in the same thread must keep the same transaction_id.
        await guarded(
            {"messages": [AIMessage(content="", tool_calls=[_call("c-1")], id="a")]}
        )
        await guarded(
            {
                "messages": [
                    AIMessage(content="", tool_calls=[_call("c-regenerated")], id="b")
                ]
            }
        )
        thread["configurable"]["thread_id"] = "thread-8"
        await guarded(
            {"messages": [AIMessage(content="", tool_calls=[_call("c-1")], id="a")]}
        )

        first, rerun, other_thread = (self._txn(s) for s in spy.states)
        assert first == rerun
        assert first != other_thread
        expected_step = derive_plan_step_key(_call("c-1")["args"])
        assert first == derive_transaction_id(
            expected_step, thread_id="thread-7", message_id=None
        )

    @pytest.mark.asyncio
    async def test_each_trade_call_in_a_batch_gets_its_own_key(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()

        await gateway_tool_guard("execute_trade")(spy)(
            _state(_call("t1"), _call("t2", symbol="MSFT"))
        )

        state = spy.states[0]
        assert self._txn(state, 0) != self._txn(state, 1)

    @pytest.mark.asyncio
    async def test_other_tool_calls_are_untouched(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        call = {"name": "get_market_sentiment", "args": {"symbol": "AAPL"}, "id": "m1"}

        await gateway_tool_guard("market_data")(spy)(_state(call))

        assert spy.states[0]["messages"][-1].tool_calls[0]["args"] == {"symbol": "AAPL"}

    @pytest.mark.asyncio
    async def test_approved_resubmission_keeps_the_derived_key(self, gateway) -> None:
        from src.governed_financial_advisor.graph.governance.tool_guard import (
            derive_plan_step_key,
        )

        seen = gateway(lambda r: httpx.Response(200, json=_ALLOW))
        spy = _SpyNode()
        state = {
            "messages": [AIMessage(content="", tool_calls=[_call("t1")], id="ai-9")],
            "deferred_id": "d-1",
            "approval_decision": {"approved": True},
        }

        await gateway_tool_guard("execute_trade", approvable=True)(spy)(state)

        args = spy.states[0]["messages"][-1].tool_calls[0]["args"]
        assert args["deferred_id"] == "d-1"
        expected_step = derive_plan_step_key(_call("t1")["args"])
        assert args["transaction_id"] == derive_transaction_id(
            expected_step, thread_id=None, message_id="ai-9"
        )
        assert seen == []  # an approved call is not re-validated


class TestLinkerdEmpty403FailsClosed:
    """POAM-2026-227: empty-body Linkerd HTTP 403 fails closed on every advisor path.

    From ``#746`` (``f0ca9f4d``) until ``#782`` (``8a3e86bb``) and ``#783``
    (``5d98e1e2``), ``HTTPRoute/gateway-canary`` matched exact ``POST
    /governance/validate-action`` and ``POST /governance/policy-precheck``
    without binding ``gateway-trusted-clients``, causing Linkerd's inbound
    proxy to reject ``cage-advisor-sa`` with ``HTTP 403`` and an empty
    ``text/plain`` body before FastAPI ran. Every caller in the advisor must
    fail closed (outage, never governance bypass).
    """

    @staticmethod
    def _linkerd_empty_403(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=b"", headers={"content-type": "text/plain"})

    @pytest.mark.asyncio
    async def test_validate_action_raises_http_status_error_on_empty_mesh_403(
        self, gateway
    ) -> None:
        gateway(self._linkerd_empty_403)

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await GatewayClient().validate_action(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100.0},
            )
        assert exc_info.value.response.status_code == 403
        assert not isinstance(exc_info.value, PermissionError)

    @pytest.mark.asyncio
    async def test_gateway_tool_guard_refuses_batch_without_executing_node(
        self, gateway
    ) -> None:
        gateway(self._linkerd_empty_403)
        spy = _SpyNode()
        state = {
            **_state(_call("t1")),
            "routing_verdict_cache": {"params_digest": "stale"},
        }

        out = await gateway_tool_guard("execute_trade", approvable=True)(spy)(state)

        assert spy.calls == 0
        assert out["governance_status"] == "DENIED"
        assert out["routing_verdict_cache"] is None
        assert len(out["messages"]) == 1
        assert "Governance refused this action" in out["messages"][0].content

    @pytest.mark.asyncio
    async def test_safety_check_node_blocks_plan_on_empty_mesh_403(
        self, gateway
    ) -> None:
        from src.governed_financial_advisor.graph.nodes.safety_node import (
            safety_check_node,
        )

        gateway(self._linkerd_empty_403)
        state: dict[str, Any] = {
            "execution_plan_output": {
                "steps": [
                    {
                        "action": "execute_trade",
                        "symbol": "AAPL",
                        "amount": 100.0,
                        "side": "BUY",
                    }
                ]
            },
            "consecutive_denials": 0,
        }

        out = await safety_check_node(state)  # type: ignore[arg-type]

        assert out["safety_status"] == "GATEWAY_ERROR"
        assert out["consecutive_denials"] == 0
        assert out["last_violation"]["reason_code"] == "GATEWAY_ERROR"
        assert out["last_violation"]["recoverable"] is False
        assert out["routing_verdict_cache"] is None

    @pytest.mark.asyncio
    async def test_policy_precheck_returns_deny_on_empty_mesh_403(
        self, gateway
    ) -> None:
        gateway(self._linkerd_empty_403)

        decision = await GatewayClient().evaluate_policy_dry_run(
            "execute_trade", {"symbol": "AAPL", "amount": 100.0}
        )

        assert decision == "DENY"


# ---------------------------------------------------------------------------
# After the request was sent: outcomes that do not confirm execution
# ---------------------------------------------------------------------------

#: The guard's three ways of running a committing call (see ``_path_state``).
_GUARD_PATHS = ("autonomous", "approved_redemption", "multi_step_approved")
#: What may follow a sent request without confirming it: a ``CommitStatus``,
#: ``"none"`` (no decodable outcome) or ``"missing"`` (no ``COMMIT_OUTCOMES``
#: entry for the call).
_UNCONFIRMED_MODES = ("none", "missing", "INDETERMINATE", "UNSETTLED_DUPLICATE")


class _ScriptedOutcomeNode:
    """Stand-in tool executor that ran the batch and reports a scripted outcome.

    ``_SpyNode`` always reports EXECUTED, so it cannot drive the guard down a
    path where the request went out and no outcome came back confirmed. This
    one reports ``mode`` for the last trade call of the batch (earlier ones
    report EXECUTED): a ``CommitStatus`` value, ``"none"`` (what
    ``tool_executor_node`` records when it decoded no outcome) or
    ``"missing"`` (no ``COMMIT_OUTCOMES`` entry for the call at all).
    """

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls = 0

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        trades = [
            c
            for c in state["messages"][-1].tool_calls
            if c.get("name") == "execute_trade_action"
        ]
        messages: list[ToolMessage] = []
        outcomes: dict[str, CommitOutcome | None] = {}
        for index, call in enumerate(trades):
            mode = self.mode if index == len(trades) - 1 else "EXECUTED"
            messages.append(
                ToolMessage(
                    content=f"executor reported {mode}",
                    tool_call_id=call["id"],
                    name=call["name"],
                )
            )
            if mode == "missing":
                continue
            outcomes[str(call["id"])] = (
                None
                if mode == "none"
                else CommitOutcome(CommitStatus(mode), f"executor reported {mode}")
            )
        return {"messages": messages, COMMIT_OUTCOMES: outcomes}


def _path_state(path: str) -> tuple[dict[str, Any], str]:
    """The guard's input on ``path``, and the id of the call whose outcome is tested.

    * ``autonomous``: one call, routed ALLOW by validate-action.
    * ``approved_redemption``: one call redeeming the approved ``d-1``.
    * ``multi_step_approved``: step 1 routed ALLOW (it executes), step 2
      redeeming the approved ``d-2``.
    """
    approval = {"approved": True, "reviewer": "r@x"}
    if path == "autonomous":
        return _state(_call("t1", symbol="MSFT")), "t1"
    if path == "approved_redemption":
        return {
            **_state(_call("t1", symbol="MSFT")),
            "deferred_id": "d-1",
            "approval_decision": approval,
        }, "t1"
    assert path == "multi_step_approved", path
    return {
        **_state(_call("s1"), _call("s2", symbol="MSFT")),
        "deferred_id": "d-2",
        "deferred_step_ids": [None, "d-2"],
        "approval_decision": approval,
    }, "s2"


def _assert_held_for_reconciliation(result: dict[str, Any], call_id: str) -> None:
    """The batch ends and the model is told not to resubmit the trade."""
    # DENIED, never UNAVAILABLE: that status says nothing was sent.
    assert result["governance_status"] == "DENIED"
    assert result["deferred_id"] is None
    replies = [m.content for m in result["messages"] if m.tool_call_id == call_id]
    assert len(replies) == 1, replies
    assert "could not be confirmed" in replies[0]
    assert "Do not submit it again until it has been reconciled" in replies[0]
    for message in result["messages"]:
        assert "Nothing was executed" not in message.content
        assert "Submit a new request" not in message.content


class TestGuardUnconfirmedOutcome:
    """After a send, an unconfirmed outcome holds the trade for reconciliation.

    POAM-2026-232: after a possible fill, telling the model that nothing was
    executed, or to submit a new request, asks it to place an order that may
    already be live.
    """

    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.parametrize("mode", _UNCONFIRMED_MODES)
    @pytest.mark.asyncio
    async def test_unconfirmed_outcome_is_held_for_reconciliation(
        self, gateway, mode: str, path: str
    ) -> None:
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        state, call_id = _path_state(path)
        node = _ScriptedOutcomeNode(mode)

        result = await gateway_tool_guard("execute_trade", approvable=True)(node)(state)

        assert node.calls == 1  # the batch ran: the request went out
        _assert_held_for_reconciliation(result, call_id)

    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.asyncio
    async def test_executed_outcome_is_allowed(self, gateway, path: str) -> None:
        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        state, _ = _path_state(path)
        node = _ScriptedOutcomeNode("EXECUTED")

        result = await gateway_tool_guard("execute_trade", approvable=True)(node)(state)

        assert node.calls == 1
        assert result["governance_status"] == "ALLOWED"


def _read_timeout() -> Exception:
    return httpx.ReadTimeout(
        "timed out reading the reply to a sent request",
        request=httpx.Request("POST", "http://gateway.test/mcp/"),
    )


def _outcome_unknown() -> Exception:
    """What ``GatewayMCPClient`` raises when a sent call's reply is lost."""
    exc = MCPToolOutcomeUnknownError(
        "execute_trade_action",
        "MCP tool 'execute_trade_action' may have run: the request was sent "
        "but no result came back",
    )
    exc.__cause__ = _read_timeout()
    return exc


class _LostReplyTradeTool:
    """``execute_trade_action`` over MCP, whose reply for ``lost_symbol`` is lost."""

    name = "execute_trade_action"

    def __init__(self, error: Callable[[], Exception], lost_symbol: str) -> None:
        self.error = error
        self.lost_symbol = lost_symbol
        self.sent: list[dict[str, Any]] = []

    async def ainvoke_commit(self, args: dict[str, Any]) -> CommitOutcome:
        self.sent.append(dict(args))
        if args.get("symbol") == self.lost_symbol:
            raise self.error()
        return CommitOutcome(CommitStatus.EXECUTED, f"EXECUTED: {args.get('symbol')}")


class _FakeMCPClient:
    def __init__(self, *tools: Any) -> None:
        self.tools = list(tools)

    async def ensure_connected(self) -> None:
        return None

    async def get_tools(self) -> list[Any]:
        return self.tools


class TestRealExecutorUnconfirmedOutcome:
    """The trader graph's own guarded executor, when a sent trade's reply is lost."""

    @pytest.mark.parametrize(
        "error",
        [_read_timeout, _outcome_unknown],
        ids=["read_timeout", "outcome_unknown"],
    )
    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.asyncio
    async def test_lost_reply_is_held_for_reconciliation(
        self,
        gateway,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
        error: Callable[[], Exception],
    ) -> None:
        from src.governed_financial_advisor.graph.subgraphs import (
            governed_trader_graph as trader,
        )

        gateway(lambda r: httpx.Response(200, json=_ALLOW))
        tool = _LostReplyTradeTool(error, lost_symbol="MSFT")
        monkeypatch.setattr(trader, "get_mcp_client", lambda: _FakeMCPClient(tool))
        state, call_id = _path_state(path)

        result = await trader.guarded_tool_executor_node(state)

        # tool_executor_node sent every call; the MSFT reply never came back.
        assert [args["symbol"] for args in tool.sent] == [
            c["args"]["symbol"] for c in state["messages"][-1].tool_calls
        ]
        _assert_held_for_reconciliation(result, call_id)


# Regression coverage binding: POAM-2026-080, POAM-2026-227, POAM-2026-228, POAM-2026-232
