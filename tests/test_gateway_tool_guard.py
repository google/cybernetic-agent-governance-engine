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

"""Unit tests for advisor tool governance via ``cage_client.langgraph.governed_tool_node`` (POAM-2026-080 / POAM-2026-251).

Exercises ``governed_trader_graph.guarded_tool_executor_node`` (``mode="execute"``,
``idempotency_param="transaction_id"``), ``data_analyst_graph.guarded_tool_executor_node``
(``mode="preview"``), and the advisor-specific policy hooks in ``tool_guard.py``
against the real ``GatewayClient`` + ``SignedGatewayStub`` over ``httpx.MockTransport``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import cage_client.langgraph as lg_mod
import httpx
import pytest
from cage_client import derive_idempotency_key, derive_plan_step_key
from cage_client.outcomes import CommitStatus
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END

from src.governed_financial_advisor.graph.governance.tool_guard import (
    canonical_trade_intent,
)
from src.governed_financial_advisor.graph.subgraphs import (
    data_analyst_graph as analyst,
)
from src.governed_financial_advisor.graph.subgraphs import (
    governed_trader_graph as trader,
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


def _ok_execute_response(message: str = "executed") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "status": "SUCCESS",
            "output": message,
            "outcome": {"status": "EXECUTED", "message": message},
        },
    )


@pytest.fixture
def gateway() -> Iterator[Callable[[Handler], list[httpx.Request]]]:
    """Install a signing MockTransport behind the GatewayClient singleton."""
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


def _state(*tool_calls: dict[str, Any]) -> dict[str, Any]:
    return {"messages": [AIMessage(content="", tool_calls=list(tool_calls))]}


def _call(call_id: str, symbol: str = "AAPL", amount: float = 100.0) -> dict[str, Any]:
    return {
        "name": "execute_trade_action",
        "args": {"symbol": symbol, "amount": amount, "confidence": 0.99},
        "id": call_id,
    }


def _preview_reqs(seen: list[httpx.Request]) -> list[httpx.Request]:
    return [r for r in seen if r.url.path == "/governance/validate-action"]


def _execute_reqs(seen: list[httpx.Request]) -> list[httpx.Request]:
    return [r for r in seen if r.url.path == "/tools/execute"]


class TestGuardApproval:
    @pytest.mark.asyncio
    async def test_all_approved_runs_execute(self, gateway) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )

        cmd = await trader.guarded_tool_executor_node(
            _state(_call("t1"), _call("t2", symbol="MSFT"))
        )
        result = dict(cmd.update or {})

        assert cmd.goto == "executor"
        assert result["governance_status"] == "ALLOWED"
        assert [m.content for m in result["messages"]] == ["executed", "executed"]
        previews = _preview_reqs(seen)
        execs = _execute_reqs(seen)
        assert len(previews) == 2
        assert len(execs) == 2
        bodies = [json.loads(r.content) for r in previews]
        assert {b["params"]["symbol"] for b in bodies} == {"AAPL", "MSFT"}
        assert all(b["action"] == "execute_trade" for b in bodies)
        assert all(b["params"]["tool_name"] == "execute_trade_action" for b in bodies)

    @pytest.mark.asyncio
    async def test_analyst_preview_mode_routes_without_calling_tools_execute(
        self, gateway
    ) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_ALLOW))
        ro_call = {
            "name": "get_market_data",
            "args": {"symbol": "AAPL"},
            "id": "ro-1",
        }

        cmd = await analyst.guarded_tool_executor_node(_state(ro_call))
        result = dict(cmd.update or {})

        assert cmd.goto == "mcp_execute"
        assert result["governance_status"] == "ALLOWED"
        assert len(_preview_reqs(seen)) == 1
        assert _execute_reqs(seen) == []

    @pytest.mark.asyncio
    async def test_no_tool_calls_does_not_call_gateway(self, gateway) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_ALLOW))

        cmd = await trader.guarded_tool_executor_node(
            {"messages": [AIMessage(content="done")]}
        )

        assert cmd.goto == "executor"
        assert cmd.update == {"messages": []}
        assert seen == []


class TestGuardFailClosed:
    """Any non-executable outcome fails closed and never dispatches /tools/execute."""

    @pytest.mark.parametrize(
        ("handler", "expected_status"),
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
                "DENIED",
                id="denied-403",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "DENIED"}),
                "DENIED",
                id="denied-200",
            ),
            pytest.param(
                lambda r: httpx.Response(401), "UNAVAILABLE", id="unauthenticated-401"
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "PAUSE"}),
                "UNAVAILABLE",
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
                "DEFERRED",
                id="defer",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={}),
                "UNAVAILABLE",
                id="no-verdict",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "APPROVED"}),
                "UNAVAILABLE",
                id="legacy-approved",
            ),
            pytest.param(
                lambda r: httpx.Response(200, json={"verdict": "REQUIRE_APPROVAL"}),
                "UNAVAILABLE",
                id="approval-without-deferred-id",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_non_approval_refuses_trader(
        self, gateway, handler: Handler, expected_status: str
    ) -> None:
        seen = gateway(handler)

        cmd = await trader.guarded_tool_executor_node(_state(_call("t1")))
        result = dict(cmd.update or {})

        assert _execute_reqs(seen) == []
        assert cmd.goto == END
        assert result["governance_status"] == expected_status
        assert result["governance_envelope"] is None
        (msg,) = result["messages"]
        assert isinstance(msg, ToolMessage)
        assert msg.tool_call_id == "t1"

    @pytest.mark.asyncio
    async def test_non_approvable_analyst_refuses_require_approval(
        self, gateway
    ) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_REQUIRE_APPROVAL))
        ro_call = {"name": "get_market_data", "args": {"symbol": "AAPL"}, "id": "t1"}

        cmd = await analyst.guarded_tool_executor_node(_state(ro_call))
        result = dict(cmd.update or {})

        assert cmd.goto == "reporter"
        assert _execute_reqs(seen) == []
        assert result["governance_status"] == "DENIED"
        assert "non-approvable" in result["messages"][0].content

    @pytest.mark.asyncio
    async def test_gateway_500_fails_as_unavailable(self, gateway) -> None:
        seen = gateway(lambda _r: httpx.Response(500))

        cmd = await trader.guarded_tool_executor_node(_state(_call("t1")))
        result = dict(cmd.update or {})

        assert _execute_reqs(seen) == []
        assert cmd.goto == END
        assert result["governance_status"] == "UNAVAILABLE"
        assert result["governance_envelope"] is None
        (msg,) = result["messages"]
        assert isinstance(msg, ToolMessage)
        assert msg.tool_call_id == "t1"
        assert msg.content.startswith("Governance unavailable")

    @pytest.mark.parametrize(
        "exc",
        [httpx.ReadTimeout, httpx.ConnectError],
        ids=["timeout", "unreachable"],
    )
    @pytest.mark.asyncio
    async def test_transport_failure_refuses(self, gateway, exc) -> None:
        def fail(request: httpx.Request) -> httpx.Response:
            raise exc("gateway down", request=request)

        seen = gateway(fail)
        ro_call = {"name": "get_market_data", "args": {"symbol": "AAPL"}, "id": "t1"}

        cmd = await analyst.guarded_tool_executor_node(_state(ro_call))
        result = dict(cmd.update or {})

        assert _execute_reqs(seen) == []
        assert cmd.goto == "reporter"
        assert result["governance_status"] == "UNAVAILABLE"
        assert result["messages"][0].content.startswith("Governance unavailable")

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

        seen = gateway(handler)

        cmd = await trader.guarded_tool_executor_node(
            _state(_call("ok"), _call("bad", symbol="EVIL"))
        )
        result = dict(cmd.update or {})

        assert _execute_reqs(seen) == []
        assert cmd.goto == END
        assert result["governance_status"] == "DENIED"
        by_id = {m.tool_call_id: m.content for m in result["messages"]}
        assert set(by_id) == {"ok", "bad"}
        assert "another tool call in the batch was refused" in by_id["ok"]


class TestGuardNarrow:
    @pytest.mark.asyncio
    async def test_narrow_executes_with_narrowed_params(self, gateway) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_NARROW)
            )
        )

        cmd = await trader.guarded_tool_executor_node(_state(_call("t1")))
        result = dict(cmd.update or {})

        assert cmd.goto == "executor"
        assert result["governance_status"] == "ALLOWED"
        assert result["governance_envelope"]["verdict"] == "NARROW"
        exec_reqs = _execute_reqs(seen)
        assert len(exec_reqs) == 1
        assert json.loads(exec_reqs[0].content)["params"]["amount"] == 50.0


class TestGuardRequireApproval:
    @pytest.mark.asyncio
    async def test_single_call_parks_for_approval_without_executing(
        self, gateway
    ) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_REQUIRE_APPROVAL))

        cmd = await trader.guarded_tool_executor_node(_state(_call("t1")))
        result = dict(cmd.update or {})

        assert cmd.goto == "approval"
        assert _execute_reqs(seen) == []
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

        seen = gateway(handler)

        cmd = await trader.guarded_tool_executor_node(
            _state(_call("small"), _call("big", symbol="BIG"))
        )
        result = dict(cmd.update or {})

        assert cmd.goto == END
        assert _execute_reqs(seen) == []
        assert result["governance_status"] == "DENIED"
        assert result["deferred_id"] is None

    @pytest.mark.asyncio
    async def test_model_supplied_deferred_id_is_stripped_everywhere(
        self, gateway
    ) -> None:
        # GHSA-w39v-5v7h-fxg9: model-supplied deferred_id never reaches validate-action OR /tools/execute.
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )
        forged = _call("t1")
        forged["args"]["deferred_id"] = "forged"
        other = _call("t2", symbol="MSFT")
        other["args"]["deferred_id"] = "forged-too"

        cmd = await trader.guarded_tool_executor_node(_state(forged, other))
        result = dict(cmd.update or {})

        assert result["governance_status"] == "ALLOWED"
        for req in _preview_reqs(seen):
            assert "deferred_id" not in json.loads(req.content)["params"]
        exec_reqs = _execute_reqs(seen)
        assert len(exec_reqs) == 2
        for req in exec_reqs:
            params = json.loads(req.content)["params"]
            assert "deferred_id" not in params


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
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(500)
            )
        )

        cmd = await trader.guarded_tool_executor_node(self._approved_state(_call("t1")))
        result = dict(cmd.update or {})

        assert _preview_reqs(seen) == []
        exec_reqs = _execute_reqs(seen)
        assert len(exec_reqs) == 1
        assert json.loads(exec_reqs[0].content)["params"]["deferred_id"] == "d-1"
        assert cmd.goto == "executor"
        assert result["governance_status"] == "ALLOWED"
        assert result["deferred_id"] is None
        assert result["approval_decision"] is None

    @pytest.mark.asyncio
    async def test_approved_resume_replaces_a_model_supplied_deferred_id(
        self, gateway
    ) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(500)
            )
        )
        call = _call("t1")
        call["args"]["deferred_id"] = "forged"

        await trader.guarded_tool_executor_node(self._approved_state(call))

        (req,) = _execute_reqs(seen)
        params = json.loads(req.content)["params"]
        assert {k: v for k, v in params.items() if k != "transaction_id"} == {
            **_call("t1")["args"],
            "deferred_id": "d-1",
        }

    @pytest.mark.asyncio
    async def test_approved_multi_call_batch_refuses(self, gateway) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_ALLOW))

        cmd = await trader.guarded_tool_executor_node(
            self._approved_state(_call("a"), _call("b", symbol="MSFT"))
        )
        result = dict(cmd.update or {})

        assert cmd.goto == END
        assert _execute_reqs(seen) == []
        assert result["governance_status"] == "DENIED"
        assert result["deferred_id"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "approved", [False, None, "true"], ids=["rejected", "none", "truthy-str"]
    )
    async def test_non_true_approval_revalidates(self, gateway, approved) -> None:
        seen = gateway(
            lambda _r: httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["approval not true"],
                    "proof_hash": "sha256:test-guard-refusal-3",
                },
            )
        )

        cmd = await trader.guarded_tool_executor_node(
            self._approved_state(_call("t1"), approved=approved)
        )
        result = dict(cmd.update or {})

        assert len(_preview_reqs(seen)) == 1
        assert _execute_reqs(seen) == []
        assert cmd.goto == END
        assert result["governance_status"] == "DENIED"

    @pytest.mark.asyncio
    async def test_not_approvable_ignores_approval_state(self, gateway) -> None:
        seen = gateway(
            lambda _r: httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["not approvable"],
                    "proof_hash": "sha256:test-guard-refusal-4",
                },
            )
        )
        ro_call = {"name": "get_market_data", "args": {"symbol": "AAPL"}, "id": "t1"}

        cmd = await analyst.guarded_tool_executor_node(self._approved_state(ro_call))
        result = dict(cmd.update or {})

        assert len(_preview_reqs(seen)) == 1
        assert cmd.goto == "reporter"
        assert result["governance_status"] == "DENIED"


class TestSubgraphWiring:
    def test_trader_graph_compiles_with_sdk_tools_node(self) -> None:
        graph = trader.build_governed_trader_graph()
        assert "tools" in graph.get_graph().nodes

    def test_analyst_graph_has_preview_and_mcp_execute_nodes(self) -> None:
        nodes = analyst.data_analyst_graph.get_graph().nodes
        assert "execute_tool" in nodes
        assert "mcp_execute" in nodes
        assert analyst.guarded_tool_executor_node is not analyst.tool_executor_node


class TestGuardTransactionIds:
    """Trade tool calls carry a derived, deterministic transaction_id (#514 / POAM-2026-232)."""

    @pytest.mark.asyncio
    async def test_overrides_the_model_supplied_transaction_id(self, gateway) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )
        call = _call("call-1")
        call["args"]["transaction_id"] = "chosen-by-the-model"
        state = {"messages": [AIMessage(content="", tool_calls=[call], id="ai-1")]}

        await trader.guarded_tool_executor_node(state)

        exec_params = json.loads(_execute_reqs(seen)[0].content)["params"]
        txn = exec_params["transaction_id"]
        assert txn != "chosen-by-the-model"
        assert uuid.UUID(txn).version == 5
        expected_step = derive_plan_step_key(
            call["args"], canonical_extractor=canonical_trade_intent
        )
        assert txn == derive_idempotency_key(
            expected_step, thread_id=None, message_id="ai-1"
        )
        # The preview authorizes the order; the call's key is not part of it.
        assert (
            "transaction_id" not in json.loads(_preview_reqs(seen)[0].content)["params"]
        )

    @pytest.mark.asyncio
    async def test_same_intent_in_same_thread_keeps_key_even_with_new_tool_call_id(
        self, gateway, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )
        thread = {"configurable": {"thread_id": "thread-7"}}
        monkeypatch.setattr(lg_mod, "get_config", lambda: thread)

        await trader.guarded_tool_executor_node(
            {"messages": [AIMessage(content="", tool_calls=[_call("c-1")], id="a")]}
        )
        await trader.guarded_tool_executor_node(
            {
                "messages": [
                    AIMessage(content="", tool_calls=[_call("c-regenerated")], id="b")
                ]
            }
        )
        thread["configurable"]["thread_id"] = "thread-8"
        await trader.guarded_tool_executor_node(
            {"messages": [AIMessage(content="", tool_calls=[_call("c-1")], id="a")]}
        )

        txns = [
            json.loads(r.content)["params"]["transaction_id"]
            for r in _execute_reqs(seen)
        ]
        first, rerun, other_thread = txns
        assert first == rerun
        assert first != other_thread
        expected_step = derive_plan_step_key(
            _call("c-1")["args"], canonical_extractor=canonical_trade_intent
        )
        assert first == derive_idempotency_key(
            expected_step, thread_id="thread-7", message_id=None
        )

    @pytest.mark.asyncio
    async def test_each_trade_call_in_a_batch_gets_its_own_key(self, gateway) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )

        await trader.guarded_tool_executor_node(
            _state(_call("t1"), _call("t2", symbol="MSFT"))
        )

        exec_reqs = _execute_reqs(seen)
        assert len(exec_reqs) == 2
        t0 = json.loads(exec_reqs[0].content)["params"]["transaction_id"]
        t1 = json.loads(exec_reqs[1].content)["params"]["transaction_id"]
        assert t0 != t1

    @pytest.mark.asyncio
    async def test_other_tool_calls_in_preview_mode_never_mint_transaction_id(
        self, gateway
    ) -> None:
        seen = gateway(lambda _r: httpx.Response(200, json=_ALLOW))
        call = {"name": "get_market_sentiment", "args": {"symbol": "AAPL"}, "id": "m1"}

        await analyst.guarded_tool_executor_node(_state(call))

        preview_params = json.loads(_preview_reqs(seen)[0].content)["params"]
        assert "transaction_id" not in preview_params
        assert _execute_reqs(seen) == []

    @pytest.mark.asyncio
    async def test_approved_resubmission_keeps_the_derived_key(self, gateway) -> None:
        seen = gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )
        state = {
            "messages": [AIMessage(content="", tool_calls=[_call("t1")], id="ai-9")],
            "deferred_id": "d-1",
            "approval_decision": {"approved": True},
        }

        await trader.guarded_tool_executor_node(state)

        assert _preview_reqs(seen) == []
        params = json.loads(_execute_reqs(seen)[0].content)["params"]
        assert params["deferred_id"] == "d-1"
        expected_step = derive_plan_step_key(
            _call("t1")["args"], canonical_extractor=canonical_trade_intent
        )
        assert params["transaction_id"] == derive_idempotency_key(
            expected_step, thread_id=None, message_id="ai-9"
        )


class TestLinkerdEmpty403FailsClosed:
    """POAM-2026-227: empty-body Linkerd HTTP 403 fails closed on every advisor path."""

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
    async def test_governed_tool_node_refuses_batch_on_empty_mesh_403(
        self, gateway
    ) -> None:
        seen = gateway(self._linkerd_empty_403)
        state = {
            **_state(_call("t1")),
            "routing_verdict_cache": {"params_digest": "stale"},
        }

        cmd = await trader.guarded_tool_executor_node(state)
        out = dict(cmd.update or {})

        assert cmd.goto == END
        assert _execute_reqs(seen) == []
        assert out["governance_status"] == "UNAVAILABLE"
        assert out["routing_verdict_cache"] is None
        assert len(out["messages"]) == 1
        assert "Governance unavailable" in out["messages"][0].content

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

_GUARD_PATHS = ("autonomous", "approved_redemption", "multi_step_approved")
_UNCONFIRMED_MODES = ("none", "INDETERMINATE", "UNSETTLED_DUPLICATE")


def _path_state(path: str) -> tuple[dict[str, Any], str]:
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
    assert result["governance_status"] == CommitStatus.INDETERMINATE.value
    assert result["may_have_executed"] is True
    assert result["deferred_id"] is None
    replies = [m.content for m in result["messages"] if m.tool_call_id == call_id]
    assert len(replies) == 1, replies
    assert "could not be confirmed" in replies[0]
    assert "Do not submit it again until it has been reconciled" in replies[0]
    for message in result["messages"]:
        assert "Nothing was executed" not in message.content
        assert "Submit a new request" not in message.content


class TestGuardUnconfirmedOutcome:
    """After a send, an unconfirmed outcome holds the trade for reconciliation (POAM-2026-232)."""

    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.parametrize("mode", _UNCONFIRMED_MODES)
    @pytest.mark.asyncio
    async def test_unconfirmed_outcome_is_held_for_reconciliation(
        self, gateway, mode: str, path: str
    ) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/governance/validate-action":
                return httpx.Response(200, json=_ALLOW)
            symbol = json.loads(request.content)["params"]["symbol"]
            if symbol != "MSFT":
                return _ok_execute_response("EXECUTED: AAPL")
            if mode == "none":
                return httpx.Response(200, json={"status": "ERROR", "output": ""})
            return httpx.Response(
                200,
                json={
                    "status": "ERROR",
                    "actuation_outcome": "UNKNOWN",
                    "may_have_executed": True,
                    "outcome": {"status": mode, "message": f"reported {mode}"},
                },
            )

        seen = gateway(_handler)
        state, call_id = _path_state(path)

        cmd = await trader.guarded_tool_executor_node(state)
        result = dict(cmd.update or {})

        assert cmd.goto == END
        assert len(_execute_reqs(seen)) == len(state["messages"][-1].tool_calls)
        _assert_held_for_reconciliation(result, call_id)

    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.asyncio
    async def test_executed_outcome_is_allowed(self, gateway, path: str) -> None:
        gateway(
            lambda r: (
                _ok_execute_response()
                if r.url.path == "/tools/execute"
                else httpx.Response(200, json=_ALLOW)
            )
        )
        state, _ = _path_state(path)

        cmd = await trader.guarded_tool_executor_node(state)
        result = dict(cmd.update or {})

        assert cmd.goto == "executor"
        assert result["governance_status"] == "ALLOWED"

    @pytest.mark.parametrize("path", _GUARD_PATHS)
    @pytest.mark.asyncio
    async def test_read_timeout_is_held_for_reconciliation(
        self, gateway, path: str
    ) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/governance/validate-action":
                return httpx.Response(200, json=_ALLOW)
            symbol = json.loads(request.content)["params"]["symbol"]
            if symbol == "MSFT":
                raise httpx.ReadTimeout(
                    "timed out reading the reply to a sent request",
                    request=request,
                )
            return _ok_execute_response("EXECUTED: AAPL")

        seen = gateway(_handler)
        state, call_id = _path_state(path)

        cmd = await trader.guarded_tool_executor_node(state)
        result = dict(cmd.update or {})

        assert cmd.goto == END
        assert len(_execute_reqs(seen)) == len(state["messages"][-1].tool_calls)
        _assert_held_for_reconciliation(result, call_id)


# Regression coverage binding: POAM-2026-080, POAM-2026-227, POAM-2026-228, POAM-2026-232, POAM-2026-251
