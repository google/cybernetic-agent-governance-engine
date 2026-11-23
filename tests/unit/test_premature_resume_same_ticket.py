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

"""An approved resume the gateway cannot redeem yet re-parks on the same ticket.

Drives the real compiled parent graph, ``governed_trader_node``, the
governed-trader subgraph, ``gateway_tool_guard`` and the subgraph ``approval``
interrupt through the advisor's HTTP handlers, with the same stubbed leaves as
``test_hitl_deferral_id_http_exposure``. The committing MCP tool answers a
configurable typed ``CommitOutcome``:

* a retryable refusal (``PENDING`` / ``QUORUM_INCOMPLETE``) or a ``DEFERRED``
  outcome that retained the approval → the thread re-parks on the same
  ``deferred_id`` (no new deferral, no executor loop), and a later resume
  redeems that same ticket;
* any terminal outcome → ``DENIED``, the subgraph ends and HITL state clears.

At 1279cf95 the guard reported any approved redemption ``ALLOWED`` and looped
back into the executor, whatever the gateway answered.
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
    RETRYABLE_REDEMPTION_REFUSALS,
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitStatus,
)
from src.gateway.infrastructure.mcp_client import MCPCommitOutcomeUnrecognizedError

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


def _message_text(message: Any) -> str:
    """Content plus tool-call args of one checkpointed message."""
    content = getattr(message, "content", message)
    calls = getattr(message, "tool_calls", None) or []
    return f"{content!s} {json.dumps(calls, default=str)}"


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
        self._events = events

    def bind_tools(self, _tools: Any) -> _FakeLLM:
        return self

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls += 1
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
    import src.governed_financial_advisor.graph.graph as graph_mod
    import src.governed_financial_advisor.graph.subgraphs.governed_trader_graph as trader_mod
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )

    events: list[tuple[str, Any]] = []
    validate_calls: list[dict[str, Any]] = []

    async def _validate_action(
        self: Any, action: str, params: dict[str, Any], *a: Any, **k: Any
    ) -> dict[str, Any]:
        validate_calls.append({"action": action, "params": dict(params)})
        events.append(("validate", action))
        return {"verdict": "REQUIRE_APPROVAL", "deferred_id": _DEFERRED_ID}

    monkeypatch.setattr(GatewayClient, "validate_action", _validate_action)

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
    llm = _FakeLLM(events)
    trade_tool = _FakeTradeTool(events)
    mcp = _FakeMCPClient(trade_tool)

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
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved_overrides)
        if had_graph:
            app.state.graph = saved_graph
        else:
            del app.state.graph


def _new_thread(tag: str) -> str:
    # Unique per test: the advisor query cache keys on (prompt, thread_id).
    return f"premature-resume-{tag}-{uuid.uuid4().hex[:12]}"


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
# Outcomes
# ---------------------------------------------------------------------------

_RETRYABLE_OUTCOMES: dict[str, tuple[CommitOutcome, str | None]] = {
    "PENDING": (_PENDING, ApprovalRedemptionRefusal.PENDING.value),
    "QUORUM_INCOMPLETE": (
        CommitOutcome(
            status=CommitStatus.REFUSED,
            message=f"deferred_id={_DEFERRED_ID} has 1 of 2 approvals",
            redemption_refusal=ApprovalRedemptionRefusal.QUORUM_INCOMPLETE,
        ),
        ApprovalRedemptionRefusal.QUORUM_INCOMPLETE.value,
    ),
    "DEFERRED_RETAINED": (
        CommitOutcome(
            status=CommitStatus.DEFERRED,
            message=f"deferred again; approval {_DEFERRED_ID} retained",
            deferred_id=_DEFERRED_ID,
            approval_retained=True,
        ),
        None,
    ),
}


def _terminal_cases() -> dict[str, tuple[Any, str | None]]:
    cases: dict[str, tuple[Any, str | None]] = {
        member.value: (
            CommitOutcome(
                status=CommitStatus.REFUSED,
                message=f"deferral {_DEFERRED_ID} refused: {member.value}",
                redemption_refusal=member,
            ),
            member.value,
        )
        for member in ApprovalRedemptionRefusal
        if member not in RETRYABLE_REDEMPTION_REFUSALS
    }
    cases["REFUSED_NO_REASON"] = (
        CommitOutcome(
            status=CommitStatus.REFUSED,
            message=f"deferral {_DEFERRED_ID} refused",
        ),
        None,
    )
    cases["DEFERRED_NOT_RETAINED"] = (
        CommitOutcome(
            status=CommitStatus.DEFERRED,
            message=f"deferred as a new ticket; {_DEFERRED_ID} not retained",
            deferred_id="0f0f0f0f-0000-4000-8000-00000000d2d2",
        ),
        None,
    )
    cases["UNRECOGNIZED_OUTCOME"] = (
        MCPCommitOutcomeUnrecognizedError(
            "execute_trade_action",
            f"MCP tool 'execute_trade_action' returned no recognised commit "
            f"outcome (deferred_id={_DEFERRED_ID})",
        ),
        None,
    )
    return cases


_TERMINAL_CASES = _terminal_cases()


def _events_after_last_commit(env: SimpleNamespace) -> list[tuple[str, Any]]:
    commits = [i for i, (kind, _) in enumerate(env.events) if kind == "commit"]
    assert commits, "the committing tool was never called"
    return env.events[commits[-1] + 1 :]


async def _premature_resume(
    env: SimpleNamespace, thread_id: str, outcome: CommitOutcome
) -> None:
    """Resume approved while the gateway answers ``outcome`` and expect a re-park."""
    env.trade_tool.outcome = outcome
    _resume(env, thread_id, approved=True, label="POST /agent/resume (premature)")
    _assert_no_deferral_in_checkpoint_messages(
        env.graph, thread_id, "after premature resume"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(_RETRYABLE_OUTCOMES))
async def test_premature_resume_reparks_on_same_ticket_then_redeems_it(
    hitl_graph: SimpleNamespace, case: str
) -> None:
    """Retryable outcome → re-park on D (no loop, no new deferral); next resume redeems D."""
    env = hitl_graph
    outcome, expected_refusal = _RETRYABLE_OUTCOMES[case]
    thread_id = _new_thread(f"retry-{case.lower()}")

    # (a) query → REQUIRE_APPROVAL interrupt on D.
    await _query_to_interrupt(env, thread_id)
    assert len(env.validate_calls) == 1

    # (b) premature approved resume → re-parked on the same ticket.
    await _premature_resume(env, thread_id, outcome)
    config = {"configurable": {"thread_id": thread_id}}
    snapshot = await env.graph.aget_state(config)
    interrupts = _interrupts(snapshot)
    assert snapshot.next == ("governed_trader",), snapshot.next
    assert interrupts, "premature resume did not re-interrupt"
    assert interrupts[0].value.get("deferred_id") == _DEFERRED_ID
    sub = _latest_subgraph_values(env.graph, thread_id)
    assert sub.get("governance_status") == "REQUIRE_APPROVAL"
    assert sub.get("deferred_id") == _DEFERRED_ID
    assert sub.get("approval_decision") is None
    assert sub.get("redemption_refusal") == expected_refusal
    assert _events_after_last_commit(env) == [], (
        f"executor re-invoked after the refusal: {env.events}"
    )
    assert len(env.validate_calls) == 1, "a new deferral was requested"
    assert [i.get("deferred_id") for i in env.trade_tool.invocations] == [_DEFERRED_ID]
    entries = _pending(env, "GET /v1/approvals/pending (re-parked)")
    assert [e["thread_id"] for e in entries] == [thread_id]
    assert "trade" in entries[0]["interrupt_payload"]

    # (c) bridge approval recorded → the same ticket is redeemed.
    env.trade_tool.outcome = _EXECUTED
    resp = _resume(env, thread_id, approved=True, label="POST /agent/resume (final)")
    _assert_no_deferral_in_checkpoint_messages(env.graph, thread_id, "after final")
    assert [i.get("deferred_id") for i in env.trade_tool.invocations] == [
        _DEFERRED_ID,
        _DEFERRED_ID,
    ]
    assert len(env.validate_calls) == 1
    snapshot = await env.graph.aget_state(config)
    assert not snapshot.next, f"thread still parked: {snapshot.next}"
    assert (
        _latest_subgraph_values(env.graph, thread_id).get("governance_status")
        == "ALLOWED"
    )
    assert resp.json()["response"] == _POST_TRADE_MARKER


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(_TERMINAL_CASES))
async def test_terminal_redemption_outcome_denies_and_ends(
    hitl_graph: SimpleNamespace, case: str
) -> None:
    """Terminal outcome → DENIED, no re-interrupt, no executor loop, HITL state cleared."""
    env = hitl_graph
    outcome, expected_refusal = _TERMINAL_CASES[case]
    thread_id = _new_thread(f"terminal-{case.lower()}")
    await _query_to_interrupt(env, thread_id)

    env.trade_tool.outcome = outcome
    resp = _resume(
        env, thread_id, approved=True, label=f"POST /agent/resume (terminal {case})"
    )
    _assert_no_deferral_in_checkpoint_messages(
        env.graph, thread_id, f"after terminal {case}"
    )

    config = {"configurable": {"thread_id": thread_id}}
    snapshot = await env.graph.aget_state(config)
    assert not snapshot.next, f"terminal outcome re-parked: {snapshot.next}"
    assert not _interrupts(snapshot)
    sub = _latest_subgraph_values(env.graph, thread_id)
    assert sub.get("governance_status") == "DENIED"
    assert sub.get("redemption_refusal") == expected_refusal
    for field in (
        "deferred_id",
        "deferred_step_ids",
        "approval_decision",
        "hitl_reference_quote",
    ):
        assert sub.get(field) is None, (
            f"subgraph {field} not cleared: {sub.get(field)!r}"
        )
    parent = snapshot.values
    assert parent.get("deferred_id") is None
    assert parent.get("approval_decision") is None
    assert parent.get("redemption_refusal") == expected_refusal
    assert _events_after_last_commit(env) == [], (
        f"executor re-invoked after the refusal: {env.events}"
    )
    assert len(env.validate_calls) == 1
    assert [i.get("deferred_id") for i in env.trade_tool.invocations] == [_DEFERRED_ID]
    assert resp.json()["response"] != _POST_TRADE_MARKER
    assert _pending(env, f"GET /v1/approvals/pending (terminal {case})") == []


@pytest.mark.asyncio
async def test_regression_1279cf95_premature_resume_is_not_reported_allowed(
    hitl_graph: SimpleNamespace,
) -> None:
    """At 1279cf95 a PENDING redemption was labelled ALLOWED and re-entered the executor."""
    env = hitl_graph
    thread_id = _new_thread("regression")
    await _query_to_interrupt(env, thread_id)
    llm_calls_before = env.llm.calls

    await _premature_resume(env, thread_id, _PENDING)

    sub = _latest_subgraph_values(env.graph, thread_id)
    assert sub.get("governance_status") != "ALLOWED"
    # At 1279cf95 the mislabelled run looped back and re-parked, so the newest
    # checkpoint alone is not enough: no subgraph checkpoint may ever carry
    # ALLOWED (the commit was the only governed step after the query).
    allowed = [
        tup.checkpoint.get("ts", "")
        for ns, tup in _thread_checkpoints(env.graph, thread_id)
        if ns
        and tup.checkpoint.get("channel_values", {}).get("governance_status")
        == "ALLOWED"
    ]
    assert allowed == [], f"subgraph checkpoint(s) labelled ALLOWED at {allowed}"
    assert _events_after_last_commit(env) == [], (
        f"executor re-invoked after the refusal: {env.events}"
    )
    assert len(env.validate_calls) == 1, "a second deferral was requested"
    # Exactly one executor turn on resume: the one that proposed the redemption.
    assert env.llm.calls == llm_calls_before + 1
