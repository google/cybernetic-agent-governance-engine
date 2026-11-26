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

"""Real-checkpointer advisor E2E for POAM-2026-251.

Drives the advisor's own compiled ``governed_trader_graph`` with a real
LangGraph ``MemorySaver`` checkpointer against the live gateway app (ES256 JWKS
+ ``DeferQueue`` + ``execute_trade_action`` + signed ``CommitOutcome``):

1. ``REQUIRE_APPROVAL`` checkpoints ``deferred_id`` before ``approval_node`` calls
   ``interrupt()`` (without leaking ``deferred_id`` into checkpointed messages);
2. premature resume (before compliance bridge approval) receives signed
   ``CommitStatus.REFUSED`` (``PENDING``) and re-interrupts on the same ticket;
3. compliance bridge approval unlocks single-use redemption -> ``EXECUTED``;
4. replay of the redeemed ``deferred_id`` on a fresh thread refuses with
   ``ApprovalRedemptionRefusal.CONSUMED`` without re-actuating.
5. Also verifies ``data_analyst_graph`` read-only ``mode="preview"`` routing and
   advisor substrate policy-drift recovery via ``preview_trade_with_drift_revalidation``.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from cage_client import MissingDeferralTicketError
from cage_client.outcomes import ApprovalRedemptionRefusal, CommitStatus
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.commit_outcome import sign_commit_outcome_wire
from src.gateway.governance.defer_queue import (
    ApprovalRecord,
    ApprovalStatus,
    DeferQueue,
)
from src.gateway.server.workload_identity import CLIENT_IDENTITY_HEADER, _serving
from src.governed_financial_advisor.graph.governance.tool_guard import (
    preview_trade_with_drift_revalidation,
)
from src.governed_financial_advisor.graph.nodes.approval_node import approval_node
from src.governed_financial_advisor.graph.subgraphs import (
    data_analyst_graph as analyst_mod,
)
from src.governed_financial_advisor.graph.subgraphs import (
    governed_trader_graph as trader_mod,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from tests.fixtures.signed_gateway import SignedGatewayStub
from tests.test_advisor_trade_preview_e2e import _install_es256_signer
from tests.test_trade_governance_e2e import (  # noqa: F401
    ADVISOR,
    JUNIOR_DESK,
    Gateway,
    gw,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TOOL_KWARGS = frozenset(inspect.signature(execute_trade_action).parameters)


class _TraderGatewayTransport(httpx.AsyncBaseTransport):
    """Routes ``/governance/*`` to ``gw.http`` and ``/tools/execute`` to ``execute_trade_action``."""

    def __init__(self, gateway: Gateway) -> None:
        self._gateway = gateway
        self.execute_calls: list[dict[str, Any]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/tools/execute":
            return await self._gateway.http.request(
                request.method,
                request.url.raw_path.decode("ascii"),
                content=request.content if request.method == "POST" else None,
                headers=dict(request.headers),
            )
        sent = json.loads(request.content)
        params = dict(sent.get("params") or {})
        self.execute_calls.append(params)
        kwargs = {k: v for k, v in params.items() if k in _TOOL_KWARGS}
        with _serving(JUNIOR_DESK):
            outcome = await execute_trade_action(
                **kwargs,
                governor=self._gateway.governor,
            )
        signed = await sign_commit_outcome_wire(
            outcome,
            tool_name=str(sent.get("tool_name") or ""),
            idempotency_key=params.get("transaction_id"),
        )
        http_status = (
            200
            if outcome.status in {CommitStatus.EXECUTED, CommitStatus.DEFERRED}
            else 403
        )
        return httpx.Response(
            http_status,
            json={
                "status": "SUCCESS"
                if outcome.status is CommitStatus.EXECUTED
                else "ERROR",
                "output": outcome.message,
                "outcome": signed,
            },
        )


class _FakeExecutorLLM:
    def __init__(self) -> None:
        self.calls = 0

    def bind_tools(self, _tools: Any) -> _FakeExecutorLLM:
        return self

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls += 1
        last = messages[-1] if messages else None
        if isinstance(last, ToolMessage) and "EXECUTED:" in str(last.content):
            return AIMessage(content="Order completed.")
        return AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "execute_trade_action",
                    "args": {
                        "symbol": "AAPL",
                        "amount": 6000.0,
                        "currency": "USD",
                        "confidence": 0.99,
                        "side": "buy",
                        "deferred_id": "forged-by-model",
                    },
                    "id": f"call-hitl-{self.calls}",
                }
            ],
        )


class _DummyMCPTool:
    name = "execute_trade_action"
    description = "Execute trade"


class _StubSchemaMCPClient:
    async def ensure_connected(self) -> None:
        return None

    async def get_tools(self) -> list[Any]:
        return [_DummyMCPTool()]


@pytest.fixture
async def real_advisor_env(
    gw: Gateway,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[Gateway, _TraderGatewayTransport]]:
    _install_es256_signer(monkeypatch)
    GatewayClient._instance = None
    gw.http.headers[CLIENT_IDENTITY_HEADER] = JUNIOR_DESK
    transport = _TraderGatewayTransport(gw)
    gw_client = GatewayClient()
    gw_client._http = httpx.AsyncClient(
        transport=transport,
        base_url="http://gateway.test",
    )
    try:
        yield gw, transport
    finally:
        await gw_client.close()
        GatewayClient._instance = None


@pytest.mark.asyncio
async def test_advisor_trader_graph_checkpointer_defer_interrupt_redeem_replay_e2e(
    real_advisor_env: tuple[Gateway, _TraderGatewayTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full DEFER -> checkpoint -> interrupt -> premature re-park -> redeem -> CONSUMED replay E2E."""
    gateway, transport = real_advisor_env

    fake_llm = _FakeExecutorLLM()

    async def _ref_quote(state: Any, *, ticker: str, **_: Any) -> dict[str, Any]:
        return {
            "ticker": ticker,
            "price": 200.0,
            "source": "stub",
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        }

    async def _live_price(sym: str, **_: Any) -> float:
        return 200.0

    monkeypatch.setattr(trader_mod, "chat_model", lambda *a, **k: fake_llm)
    monkeypatch.setattr(trader_mod, "get_mcp_client", lambda: _StubSchemaMCPClient())
    monkeypatch.setattr(trader_mod, "get_executor_instruction", lambda: "Execute.")
    monkeypatch.setattr(trader_mod, "resolve_check_time_reference_quote", _ref_quote)
    monkeypatch.setattr(trader_mod, "fetch_live_yfinance_price", _live_price)

    graph = trader_mod.build_governed_trader_graph(checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "advisor-e2e-hitl-1"}}
    base_state = {
        "messages": [],
        "execution_plan": json.dumps(
            {
                "steps": [
                    {
                        "action": "execute_trade",
                        "symbol": "AAPL",
                        "amount": 6000.0,
                        "currency": "USD",
                        "side": "buy",
                        "confidence": 0.99,
                    }
                ]
            }
        ),
        "evaluation_result": "APPROVED",
        "deferred_id": None,
        "deferred_step_ids": None,
        "approval_required": False,
        "approval_decision": None,
        "hitl_expires_at": None,
        "data_analyst_ticker": "AAPL",
        "hitl_reference_quote": None,
        "rehydration_result": None,
        "post_hitl_safety_status": None,
        "governance_envelope": None,
        "governance_status": None,
        "routing_verdict_cache": None,
        "redemption_refusal": None,
    }

    # 1. REQUIRE_APPROVAL -> checkpoint deferred_id before interrupt().
    r1 = await graph.ainvoke(base_state, config=cfg)
    assert "__interrupt__" in r1
    ticket_id = r1["deferred_id"]
    assert isinstance(ticket_id, str) and ticket_id.strip()
    assert ticket_id not in str(r1["messages"][-1].content)
    assert transport.execute_calls == []
    gateway.actuate.assert_not_awaited()

    # 2. Premature resume before DeferQueue approval -> gateway REFUSED(PENDING) -> re-interrupt on same ticket.
    r2 = await graph.ainvoke(
        Command(
            resume={
                "approved": True,
                "reviewer": "alice@example.com",
                "rationale": "premature check",
                "max_slippage_pct": 2.0,
            }
        ),
        config=cfg,
    )
    assert "__interrupt__" in r2
    assert r2["deferred_id"] == ticket_id
    assert r2["approval_decision"] is None
    assert r2["redemption_refusal"] == ApprovalRedemptionRefusal.PENDING.value
    assert len(transport.execute_calls) == 1
    assert transport.execute_calls[0]["deferred_id"] == ticket_id
    gateway.actuate.assert_not_awaited()

    # 3. Record approvals in the gateway's real DeferQueue (quorum=2), then resume -> single-use EXECUTED.
    queue = DeferQueue(gateway.defer_redis)
    for idx, approver in enumerate(
        ("reviewer:compliance1@example.com", "reviewer:compliance2@example.com"),
        start=1,
    ):
        status, _ = await queue.approve(
            ticket_id,
            ApprovalRecord(
                approver_urn=approver,
                approved_at_utc=datetime.now(timezone.utc).isoformat(),
                auth_method="OIDC",
                auth_principal_hash=f"sha256:reviewer-hash-{idx}",
            ),
        )
    assert status is ApprovalStatus.QUORUM_REACHED

    r3 = await graph.ainvoke(
        Command(
            resume={
                "approved": True,
                "reviewer": "alice@example.com",
                "rationale": "approved after compliance clearance",
                "max_slippage_pct": 2.0,
            }
        ),
        config=cfg,
    )
    assert "__interrupt__" not in r3
    assert r3["deferred_id"] is None
    assert len(transport.execute_calls) == 2
    assert (
        transport.execute_calls[1]["transaction_id"]
        == transport.execute_calls[0]["transaction_id"]
    )
    gateway.actuate.assert_awaited_once()

    # 4. Replay of the consumed ticket on a fresh thread refuses CONSUMED without re-actuating.
    replay_cfg = {"configurable": {"thread_id": "advisor-e2e-replay-2"}}
    r4 = await graph.ainvoke(
        {
            **base_state,
            "deferred_id": ticket_id,
            "approval_decision": {
                "approved": True,
                "reviewer": "alice@example.com",
                "rationale": "replay attempt",
                "max_slippage_pct": 2.0,
            },
            "hitl_reference_quote": {
                "ticker": "AAPL",
                "price": 200.0,
                "source": "stub",
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            },
        },
        config=replay_cfg,
    )
    assert "__interrupt__" not in r4
    assert r4["governance_status"] == "DENIED"
    assert r4["redemption_refusal"] == ApprovalRedemptionRefusal.CONSUMED.value
    assert "already been used" in str(r4["messages"][-1].content)
    gateway.actuate.assert_awaited_once()


@pytest.mark.asyncio
async def test_advisor_preview_mode_drift_revalidation_and_missing_ticket_error() -> (
    None
):
    """Covers data_analyst_graph preview mode, verified 403 drift retry, and MissingDeferralTicketError."""
    with pytest.raises(MissingDeferralTicketError):
        approval_node({"execution_plan": {}, "evaluation_result": "APPROVED"})

    GatewayClient._instance = None
    stub = SignedGatewayStub()
    pins: list[str | None] = []
    paths: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/governance/policy-version":
            return httpx.Response(200, json={"active_hash": "fresh-pin-2"})
        body = json.loads(request.content)
        pins.append(body.get("policy_version_id"))
        if len(pins) == 1:
            return httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["Substrate Policy Drift Detected"],
                    "proof_hash": "sha256:drift-1",
                },
            )
        return httpx.Response(
            200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
        )

    gw_client = GatewayClient()
    gw_client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(stub.transport_handler(_handler)),
        base_url="http://gateway.test",
    )
    try:
        ro_call = {"name": "get_market_data", "args": {"symbol": "AAPL"}, "id": "ro-1"}
        cmd = await analyst_mod.guarded_tool_executor_node(
            {
                "messages": [
                    AIMessage(id="ai-ro-drift", content="", tool_calls=[ro_call])
                ],
                "policy_version_id": "stale-pin-1",
            }
        )
        assert cmd.goto == "mcp_execute"
        assert (cmd.update or {}).get("governance_status") == "ALLOWED"
        assert pins == ["stale-pin-1", "fresh-pin-2"]
        assert "/tools/execute" not in paths

        sdk = await gw_client.sdk_client()
        prev = await preview_trade_with_drift_revalidation(
            sdk,
            "market_analysis",
            {"symbol": "AAPL"},
            "advisor-sa",
            {"policy_version_id": "fresh-pin-2"},
        )
        assert prev.decision.value == "ALLOWED"
    finally:
        await gw_client.close()
        GatewayClient._instance = None
