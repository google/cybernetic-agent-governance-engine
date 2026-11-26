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

"""The gateway ``deferred_id`` never reaches an advisor HTTP body or message.

Drives the real compiled parent graph (``create_graph``), the real
``governed_trader_node``, the real governed-trader subgraph, the real
``gateway_tool_guard`` and the real subgraph ``approval`` interrupt through
the advisor's own HTTP surface (``POST /agent/query``,
``GET /v1/approvals/pending``, ``POST /agent/resume``). Only the leaves are
stubbed: upstream parent nodes (guardrails, thinker/doer, execution analyst,
evaluator, FTRA, OPA safety check, explainer, output rail), the executor LLM,
the MCP client (whose committing tool answers a typed ``CommitOutcome``),
quote sampling and ``GatewayClient.validate_action``, which answers
``REQUIRE_APPROVAL`` with a recognisable ``deferred_id``.

The deferral handle belongs to reviewers at the compliance bridge, never to
the end user or to the service acting for them, so it must not appear in any
response body, nor in any message content the advisor checkpoints (parent
graph and governed_trader subgraph namespace), whatever the guard's wording.
Stubbed gateway prose on refusals deliberately embeds the id, so a guard that
forwarded it would be caught. Each body is printed
(``[HTTP-EXPOSURE-DIAGNOSTIC]``) so a ``-s`` run shows what was returned.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver

from src.gateway.governance.commit_outcome import (
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitStatus,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ISSUER = "https://idp.example"
_AUDIENCE = "cage-advisor"
_KID = "k1"
_SERVICE_KEY = "test-service-api-key"
_OWNER = "alice"
#: Recognisable gateway deferral handle; searched for verbatim everywhere.
_DEFERRED_ID = "d3fe44ed-1d00-4e5a-9c1e-5ca1ab1e0042"
_DEFER_KEYS = ("deferred_id", "defer_id")
_TRADE_ARGS = {"symbol": "MSFT", "amount": 100.0, "side": "buy", "confidence": 0.99}
_PLAN = {
    "plan_id": "plan-hitl-exposure",
    "steps": [
        {
            "action": "execute_trade",
            "parameters": {"symbol": "MSFT", "amount": 100.0, "side": "buy"},
        }
    ],
}
_PRE_TRADER_MARKER = "Execution plan prepared for MSFT."
_POST_TRADE_MARKER = "Trade submitted for MSFT."
_EXECUTED_PROSE = "executed"

_EXECUTED = CommitOutcome(status=CommitStatus.EXECUTED, message=_EXECUTED_PROSE)
_PENDING = CommitOutcome(
    status=CommitStatus.REFUSED,
    message=f"approval deferred_id={_DEFERRED_ID} is still pending",
    redemption_refusal=ApprovalRedemptionRefusal.PENDING,
)


# ---------------------------------------------------------------------------
# Diagnostics / assertions
# ---------------------------------------------------------------------------


def _record_and_assert_no_deferred_id(label: str, response: Any) -> None:
    """Print the full HTTP response body, then assert the deferral id is absent."""
    body = response.text
    print(
        f"\n[HTTP-EXPOSURE-DIAGNOSTIC] {label}: status={response.status_code} "
        f"body={body}"
    )
    try:
        parsed: Any = response.json()
    except ValueError:
        parsed = None
    json_values = json.dumps(parsed) if parsed is not None else ""
    assert _DEFERRED_ID not in body and _DEFERRED_ID not in json_values, (
        f"gateway deferred_id {_DEFERRED_ID[:8]}... exposed in {label} "
        f"response body: {body}"
    )


def _thread_checkpoints(graph: Any, thread_id: str) -> list[tuple[str, Any]]:
    """Every ``(checkpoint_ns, CheckpointTuple)`` of ``thread_id``, all namespaces."""
    out = []
    for tup in graph.checkpointer.list(None):
        conf = tup.config.get("configurable", {})
        if conf.get("thread_id") == thread_id:
            out.append((conf.get("checkpoint_ns", ""), tup))
    return out


_FORBIDDEN_PROMPT_HANDLES = (
    "deferred_id",
    "defer_id",
    "deferred_ids",
    "transaction_id",
    "routing_seal",
    "governance_envelope",
)


def _message_text(message: Any) -> str:
    """Content, tool-call args, and metadata of one message."""
    content = getattr(message, "content", message)
    calls = getattr(message, "tool_calls", None) or []
    extra = getattr(message, "additional_kwargs", None) or {}
    meta = getattr(message, "response_metadata", None) or {}
    return (
        f"{content!s} {json.dumps(calls, default=str)} "
        f"{json.dumps(extra, default=str)} {json.dumps(meta, default=str)}"
    )


def _assert_no_deferral_in_checkpoint_messages(
    graph: Any, thread_id: str, label: str
) -> None:
    """No checkpointed message (parent or subgraph, any step) names a deferral."""
    checkpoints = _thread_checkpoints(graph, thread_id)
    assert checkpoints, f"{label}: no checkpoints for {thread_id}"
    assert any(ns for ns, _ in checkpoints), f"{label}: no subgraph checkpoints"
    for ns, tup in checkpoints:
        for message in tup.checkpoint.get("channel_values", {}).get("messages") or []:
            text = _message_text(message)
            leaked = _DEFERRED_ID in text or any(k in text for k in _DEFER_KEYS)
            assert not leaked, (
                f"{label}: deferral id/key in checkpointed message "
                f"(ns={ns or '<root>'}): {text}"
            )


def _assert_no_sensitive_handles_in_llm_prompts(
    prompts: list[list[Any]], label: str, *, expected_calls: int
) -> None:
    """Every ``messages`` payload passed to ``executor_node``'s LLM is handle-free."""
    assert len(prompts) == expected_calls, (
        f"{label}: expected {expected_calls} executor LLM call(s), got {len(prompts)}"
    )
    for call_idx, prompt_messages in enumerate(prompts):
        assert prompt_messages, f"{label}: empty prompt at call {call_idx}"
        for msg_idx, message in enumerate(prompt_messages):
            text = _message_text(message)
            leaked = _DEFERRED_ID in text or any(
                handle in text for handle in _FORBIDDEN_PROMPT_HANDLES
            )
            assert not leaked, (
                f"{label}: sensitive handle in executor_node LLM prompt "
                f"(call={call_idx}, msg={msg_idx}, type={type(message).__name__}): {text}"
            )


def _latest_subgraph_values(graph: Any, thread_id: str) -> dict[str, Any]:
    """Channel values of the newest governed_trader subgraph checkpoint."""
    sub = [
        (tup.checkpoint.get("ts", ""), tup)
        for ns, tup in _thread_checkpoints(graph, thread_id)
        if ns
    ]
    assert sub, "no governed_trader subgraph checkpoint"
    _, tup = max(sub, key=lambda item: item[0])
    return dict(tup.checkpoint.get("channel_values", {}))


def _interrupts(snapshot: Any) -> list[Any]:
    return [
        intr
        for task in (snapshot.tasks or [])
        for intr in (getattr(task, "interrupts", None) or [])
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def advisor_server() -> Any:
    """Import the advisor app with its import-time telemetry hooks stubbed."""
    stubs = (
        ("src.integrations.nemo.manager", "load_rails", {"return_value": MagicMock()}),
        ("src.gateway.infrastructure.telemetry_client", "configure_telemetry", {}),
        (
            "opentelemetry.instrumentation.langchain",
            "LangchainInstrumentor.instrument",
            {},
        ),
    )
    with contextlib.ExitStack() as stack:
        for module_name, attr, kwargs in stubs:
            try:
                importlib.import_module(module_name)
            except ImportError:
                continue
            stack.enter_context(patch(f"{module_name}.{attr}", **kwargs))
        import src.governed_financial_advisor.server as srv
    return srv


@pytest.fixture
def mint_user_jwt(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], str]:
    """Production posture with service key + end-user OIDC; returns a JWT minter."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()

    def _b64(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()

    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64(nums.x),
                "y": _b64(nums.y),
                "kid": _KID,
                "alg": "ES256",
            }
        ]
    }
    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setenv("CAGE_API_KEY", _SERVICE_KEY)
    monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _ISSUER)
    monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _AUDIENCE)
    monkeypatch.setenv("CAGE_USER_OIDC_JWKS_JSON", json.dumps(jwks))
    monkeypatch.setenv("MODEL_FAST", "stub-fast-model")
    for name in (
        "CAGE_USER_OIDC_TRUST_ANCHORS_FILE",
        "CAGE_ALLOW_ASSERTED_PRINCIPAL",
        "CAGE_REQUIRE_VERIFIED_PRINCIPAL",
        "PROVIDER_02_ATTESTATION_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)

    def _mint(sub: str) -> str:
        now = int(time.time())
        return pyjwt.encode(
            {
                "iss": _ISSUER,
                "aud": _AUDIENCE,
                "sub": sub,
                "iat": now,
                "exp": now + 300,
            },
            priv,
            algorithm="ES256",
            headers={"kid": _KID},
        )

    return _mint


class _FakeLLM:
    """Executor LLM: proposes the plan's trade until an executed result is seen."""

    def __init__(self, events: list[tuple[str, Any]]) -> None:
        self.calls = 0
        self.prompts: list[list[Any]] = []
        self._events = events

    def bind_tools(self, _tools: Any) -> _FakeLLM:
        return self

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls += 1
        self.prompts.append(list(messages))
        self._events.append(("llm", self.calls))
        last = messages[-1] if messages else None
        if isinstance(last, ToolMessage) and last.content == _EXECUTED_PROSE:
            return AIMessage(content=_POST_TRADE_MARKER)
        return AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "execute_trade_action",
                    "args": dict(_TRADE_ARGS),
                    "id": f"call_exec_trade_{self.calls}",
                    "type": "tool_call",
                }
            ],
        )


class _FakeTradeTool:
    """Committing MCP tool answering the configured ``CommitOutcome`` (or raising)."""

    name = "execute_trade_action"

    def __init__(self, events: list[tuple[str, Any]]) -> None:
        self.invocations: list[dict[str, Any]] = []
        self.outcome: CommitOutcome | BaseException = _EXECUTED
        self._events = events

    async def ainvoke_commit(self, args: dict[str, Any] | None = None) -> CommitOutcome:
        self.invocations.append(dict(args or {}))
        self._events.append(("commit", (args or {}).get("deferred_id")))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    async def ainvoke(self, args: dict[str, Any] | None = None) -> str:
        """Pre-CommitOutcome API (1279cf95): the prose only."""
        return (await self.ainvoke_commit(args)).message


class _FakeMCPClient:
    def __init__(self, tool: _FakeTradeTool) -> None:
        self._tool = tool

    async def ensure_connected(self) -> None:
        return None

    async def get_tools(self) -> list[Any]:
        return [self._tool]

    async def close(self) -> None:
        return None


@pytest.fixture
def hitl_graph(
    advisor_server: Any,
    mint_user_jwt: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[SimpleNamespace]:
    """Compile the real parent graph with stubbed leaves and install it on the app."""
    import httpx

    import src.governed_financial_advisor.graph.graph as graph_mod
    import src.governed_financial_advisor.graph.subgraphs.governed_trader_graph as trader_mod
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )
    from tests.fixtures.signed_gateway import SignedGatewayStub

    events: list[tuple[str, Any]] = []
    validate_calls: list[dict[str, Any]] = []
    llm = _FakeLLM(events)
    trade_tool = _FakeTradeTool(events)
    mcp = _FakeMCPClient(trade_tool)

    GatewayClient._instance = None
    stub = SignedGatewayStub()

    def _gw_handler(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        if request.url.path == "/governance/validate-action":
            validate_calls.append(
                {"action": sent["action"], "params": dict(sent["params"])}
            )
            events.append(("validate", sent["action"]))
            return httpx.Response(
                200,
                json={"verdict": "REQUIRE_APPROVAL", "deferred_id": _DEFERRED_ID},
            )
        if request.url.path == "/tools/execute":
            params = dict(sent.get("params") or {})
            trade_tool.invocations.append(params)
            events.append(("commit", params.get("deferred_id")))
            cur = trade_tool.outcome
            if isinstance(cur, BaseException):
                return httpx.Response(
                    200,
                    json={"status": "ERROR", "outcome": {"status": "BOGUS"}},
                )
            http_status = (
                200
                if cur.status in {CommitStatus.EXECUTED, CommitStatus.DEFERRED}
                else 403
            )
            return httpx.Response(
                http_status,
                json={
                    "status": "SUCCESS"
                    if cur.status is CommitStatus.EXECUTED
                    else "ERROR",
                    "output": cur.message,
                    "outcome": cur.to_wire(include_signature=False),
                },
            )
        return httpx.Response(404)

    gw_client = GatewayClient()
    gw_client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(stub.transport_handler(_gw_handler)),
        base_url="http://gateway.test",
    )

    # --- Upstream parent nodes (stubbed; topology stays real) ---------------
    async def _guardrail(state: Any) -> dict[str, Any]:
        return {"guardrail_blocked": False}

    async def _thinker(state: Any) -> dict[str, Any]:
        return {"reasoning_output": "execute the plan"}

    async def _doer(state: Any) -> dict[str, Any]:
        return {"next_step": "execution_analyst"}

    async def _execution_analyst(state: Any) -> dict[str, Any]:
        return {
            "execution_plan_output": _PLAN,
            "data_analyst_ticker": "MSFT",
            "loop_count": (state.get("loop_count") or 0) + 1,
            "messages": [AIMessage(content=_PRE_TRADER_MARKER)],
        }

    async def _evaluator(state: Any) -> dict[str, Any]:
        return {"evaluation_result": {"verdict": "APPROVED"}}

    async def _ftra(state: Any) -> dict[str, Any]:
        return {}

    async def _safety(state: Any) -> dict[str, Any]:
        return {"safety_status": "APPROVED"}

    async def _passthrough(state: Any) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(graph_mod, "nemo_guardrail_node", _guardrail)
    monkeypatch.setattr(graph_mod, "thinker_node", _thinker)
    monkeypatch.setattr(graph_mod, "doer_node", _doer)
    monkeypatch.setattr(graph_mod, "execution_analyst_node", _execution_analyst)
    monkeypatch.setattr(graph_mod, "evaluator_node", _evaluator)
    monkeypatch.setattr(graph_mod, "create_ftra_node", lambda *a, **k: _ftra)
    monkeypatch.setattr(graph_mod, "route_after_ftra", lambda state: "safety_check")
    monkeypatch.setattr(graph_mod, "safety_check_node", _safety)
    monkeypatch.setattr(graph_mod, "explainer_node", _passthrough)
    monkeypatch.setattr(graph_mod, "nemo_output_rail_node", _passthrough)

    # --- Governed-trader subgraph leaves ------------------------------------
    async def _ref_quote(state: Any, *, ticker: str, **_: Any) -> dict[str, Any]:
        return {
            "ticker": ticker,
            "price": 400.0,
            "source": "stub",
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        }

    async def _live_price(sym: str, **_: Any) -> float:
        return 400.0

    monkeypatch.setattr(trader_mod, "chat_model", lambda *a, **k: llm)
    monkeypatch.setattr(trader_mod, "get_mcp_client", lambda: mcp)
    monkeypatch.setattr(trader_mod, "get_executor_instruction", lambda: "Execute.")
    monkeypatch.setattr(trader_mod, "resolve_check_time_reference_quote", _ref_quote)
    monkeypatch.setattr(trader_mod, "fetch_live_yfinance_price", _live_price)

    graph = graph_mod.create_graph(checkpointer=MemorySaver())
    app = advisor_server.app
    had_graph = hasattr(app.state, "graph")
    saved_graph = getattr(app.state, "graph", None)
    saved_overrides = dict(app.dependency_overrides)
    app.dependency_overrides.clear()
    app.state.graph = graph
    try:
        yield SimpleNamespace(
            graph=graph,
            client=TestClient(app, raise_server_exceptions=False),
            mint=mint_user_jwt,
            validate_calls=validate_calls,
            trade_tool=trade_tool,
            llm=llm,
            events=events,
        )
    finally:
        GatewayClient._instance = None
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved_overrides)
        if had_graph:
            app.state.graph = saved_graph
        else:
            del app.state.graph


def _new_thread(tag: str) -> str:
    # Unique per test: the advisor query cache keys on (prompt, thread_id).
    return f"hitl-exposure-{tag}-{uuid.uuid4().hex[:12]}"


def _service_headers(env: SimpleNamespace) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_SERVICE_KEY}",
        "X-CAGE-User-Token": env.mint(_OWNER),
    }


async def _query_to_interrupt(env: SimpleNamespace, thread_id: str) -> None:
    """POST /agent/query as the end user and verify it parked at the guard interrupt."""
    resp = env.client.post(
        "/agent/query",
        json={
            "prompt": "Buy 100 USD of MSFT",
            "user_id": _OWNER,
            "thread_id": thread_id,
        },
        headers={"Authorization": f"Bearer {env.mint(_OWNER)}"},
    )
    _record_and_assert_no_deferred_id("POST /agent/query (end-user bearer JWT)", resp)
    assert resp.status_code == 200, resp.text

    # The run must really have reached the gateway guard and parked.
    assert [c["action"] for c in env.validate_calls] == ["execute_trade"]
    assert env.trade_tool.invocations == [], "trade must not run before approval"
    snapshot = await env.graph.aget_state({"configurable": {"thread_id": thread_id}})
    interrupts = _interrupts(snapshot)
    assert snapshot.next == ("governed_trader",), snapshot.next
    assert interrupts, "graph did not park at the approval interrupt"
    assert interrupts[0].value.get("reason") == "trade_approval_required"
    sub = _latest_subgraph_values(env.graph, thread_id)
    assert any(isinstance(m, ToolMessage) for m in sub.get("messages") or []), (
        "guard did not answer the parked tool call"
    )
    print(
        "[HTTP-EXPOSURE-DIAGNOSTIC] governed_trader checkpoint messages="
        f"{[(type(m).__name__, getattr(m, 'content', m)) for m in sub.get('messages') or []]}"
    )
    _assert_no_deferral_in_checkpoint_messages(env.graph, thread_id, "after query")


def _resume(env: SimpleNamespace, thread_id: str, *, approved: bool, label: str) -> Any:
    resp = env.client.post(
        "/agent/resume",
        json={
            "thread_id": thread_id,
            "user_id": _OWNER,
            "approved": approved,
            "reviewer": "reviewer@example.com",
            "rationale": "within mandate" if approved else "outside mandate",
        },
        headers=_service_headers(env),
    )
    _record_and_assert_no_deferred_id(label, resp)
    assert resp.status_code == 200, resp.text
    return resp


def _pending(env: SimpleNamespace, label: str) -> list[dict[str, Any]]:
    resp = env.client.get(
        "/v1/approvals/pending",
        params={"user_id": _OWNER},
        headers=_service_headers(env),
    )
    _record_and_assert_no_deferred_id(label, resp)
    assert resp.status_code == 200, resp.text
    return resp.json()["pending"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_and_pending_listing_never_expose_deferred_id(
    hitl_graph: SimpleNamespace,
) -> None:
    """The REQUIRE_APPROVAL park is reachable over HTTP and no body carries the id."""
    env = hitl_graph
    thread_id = _new_thread("query")
    await _query_to_interrupt(env, thread_id)

    entries = _pending(env, "GET /v1/approvals/pending (service key acting for owner)")
    assert [e["thread_id"] for e in entries] == [thread_id]
    assert entries[0]["interrupt_payload"].get("reason") == "trade_approval_required"
    assert "trade" in entries[0]["interrupt_payload"]


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False], ids=["approved", "rejected"])
async def test_resume_never_exposes_deferred_id(
    hitl_graph: SimpleNamespace, approved: bool
) -> None:
    """``POST /agent/resume`` (both outcomes) exposes the id in no body, message, or LLM prompt."""
    env = hitl_graph
    thread_id = _new_thread("ok" if approved else "no")
    await _query_to_interrupt(env, thread_id)
    _assert_no_sensitive_handles_in_llm_prompts(
        env.llm.prompts, "after initial query", expected_calls=1
    )

    env.trade_tool.outcome = _EXECUTED
    resp = _resume(
        env,
        thread_id,
        approved=approved,
        label=f"POST /agent/resume approved={approved} (service key acting for owner)",
    )
    _assert_no_deferral_in_checkpoint_messages(
        env.graph, thread_id, f"after resume approved={approved}"
    )

    snapshot = await env.graph.aget_state({"configurable": {"thread_id": thread_id}})
    assert not snapshot.next, f"thread still parked after resume: {snapshot.next}"
    if approved:
        # On approved resume, executor_node receives [SystemMessage, *state["messages"]]
        # at call index 1 (parked ToolMessage) and call index 2 (post-trade summary).
        assert isinstance(env.llm.prompts[1][-1], ToolMessage), (
            f"expected parked ToolMessage at tail of resume prompt, got {env.llm.prompts[1]}"
        )
        _assert_no_sensitive_handles_in_llm_prompts(
            env.llm.prompts, "after approved resume", expected_calls=3
        )
        # The gateway, not the advisor, redeems the approval: the trade tool
        # receives exactly the gateway-held id once.
        assert [i.get("deferred_id") for i in env.trade_tool.invocations] == [
            _DEFERRED_ID
        ]
        assert resp.json()["response"] == _POST_TRADE_MARKER
    else:
        _assert_no_sensitive_handles_in_llm_prompts(
            env.llm.prompts, "after rejected resume", expected_calls=1
        )
        assert env.trade_tool.invocations == []
        assert "Trade Rejected" in resp.json()["response"]


@pytest.mark.asyncio
async def test_premature_then_final_resume_never_exposes_deferred_id(
    hitl_graph: SimpleNamespace,
) -> None:
    """A premature resume re-parks without exposing the id in HTTP bodies, checkpoints, or LLM prompts."""
    env = hitl_graph
    thread_id = _new_thread("premature")
    await _query_to_interrupt(env, thread_id)

    # Bridge approval not recorded yet: the gateway's prose names the id.
    env.trade_tool.outcome = _PENDING
    _resume(env, thread_id, approved=True, label="POST /agent/resume (premature)")
    _assert_no_deferral_in_checkpoint_messages(
        env.graph, thread_id, "after premature resume"
    )
    assert isinstance(env.llm.prompts[1][-1], ToolMessage)
    _assert_no_sensitive_handles_in_llm_prompts(
        env.llm.prompts, "after premature resume", expected_calls=2
    )
    snapshot = await env.graph.aget_state({"configurable": {"thread_id": thread_id}})
    assert snapshot.next == ("governed_trader",), "premature resume must re-park"
    entries = _pending(env, "GET /v1/approvals/pending (after premature resume)")
    assert [e["thread_id"] for e in entries] == [thread_id]

    env.trade_tool.outcome = _EXECUTED
    resp = _resume(env, thread_id, approved=True, label="POST /agent/resume (final)")
    _assert_no_deferral_in_checkpoint_messages(
        env.graph, thread_id, "after final resume"
    )
    assert isinstance(env.llm.prompts[2][-1], ToolMessage)
    assert isinstance(env.llm.prompts[3][-1], ToolMessage)
    _assert_no_sensitive_handles_in_llm_prompts(
        env.llm.prompts, "after final resume", expected_calls=4
    )
    snapshot = await env.graph.aget_state({"configurable": {"thread_id": thread_id}})
    assert not snapshot.next
    assert [i.get("deferred_id") for i in env.trade_tool.invocations] == [
        _DEFERRED_ID,
        _DEFERRED_ID,
    ]
    assert resp.json()["response"] == _POST_TRADE_MARKER
    assert _pending(env, "GET /v1/approvals/pending (after final resume)") == []
