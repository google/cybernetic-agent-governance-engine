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

"""Hermetic unit tests for SC-7 workload quarantine enforcement on governance and MCP surfaces."""

from __future__ import annotations

import hashlib
import json
from contextlib import AsyncExitStack, asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

import src.gateway.infrastructure.redis_client as redis_client_mod
from proof.stream_invariants import check_stream
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.quarantine_actuator import (
    QuarantineDirective,
    QuarantineTriggerReason,
    bind_quarantine_redis,
    clear_local_quarantine_state,
    dispatch_quarantine,
)
from src.gateway.infrastructure.mcp_client import GatewayMCPClient
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.quarantine_guard import (
    McpQuarantineMiddleware,
    resolve_verified_workload_identity,
)
from src.gateway.server.workload_identity import (
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

POD_IP = "10.112.0.43"
PROXY_PEER = (POD_IP, 50000)
OTHER_POD_PEER = ("10.112.3.7", 51000)
POD_BASE_URL = f"http://{POD_IP}:8080"

QUARANTINED_ID = (
    "rogue-agent-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
CLEAN_ID = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


def _make_directive(
    *,
    thread_id: str = "",
    agent_svid: str = "",
    ttl_seconds: int = 600,
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id,
        agent_svid=agent_svid,
        sandbox_id="sbx-ingress-1",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BREACH",),
        issued_at=1700000000,
        correlation_id="corr-ingress-1",
        refusal_proof_hash=hashlib.sha256(b"prior-refusal-1").hexdigest(),
        nonce="nonce-ingress-1",
        ttl_seconds=ttl_seconds,
    )


def _read_stream_entries(
    stream_server: fakeredis.FakeServer,
) -> list[tuple[str, dict[str, str]]]:
    sync_r = fakeredis.FakeRedis(server=stream_server, decode_responses=True)
    return list(sync_r.xrange("cage:evidence:stream", min="-", max="+"))


@pytest.fixture(autouse=True)
async def _isolated_quarantine_and_app_state(monkeypatch: pytest.MonkeyPatch):
    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    iso_server = fakeredis.FakeServer()
    iso_sync_redis = fakeredis.FakeRedis(server=iso_server, decode_responses=True)
    monkeypatch.setattr(
        redis_client_mod,
        "sync_redis_client",
        SimpleNamespace(_get=lambda: iso_sync_redis),
    )
    active_sinks: list[EvidenceStreamSink] = []
    prev_gov = getattr(governance_app.state, "governor", None)
    prev_redis = getattr(governance_app.state, "redis", None)
    prev_sink = getattr(governance_app.state, "evidence_sink", None)
    yield SimpleNamespace(iso_redis=iso_sync_redis, sinks=active_sinks)
    for s in active_sinks:
        await s.stop(drain_timeout_s=1.0)
    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    governance_app.state.governor = prev_gov
    governance_app.state.redis = prev_redis
    governance_app.state.evidence_sink = prev_sink


def _make_real_sink(
    stream_server: fakeredis.FakeServer,
    sinks_tracker: list[EvidenceStreamSink],
) -> EvidenceStreamSink:
    """Create a real hash-chained EvidenceStreamSink backed by FakeRedis."""
    sink_redis = fakeredis.aioredis.FakeRedis(
        server=stream_server, decode_responses=False
    )
    sink = EvidenceStreamSink(stream_key="cage:evidence:stream")
    sink._redis = sink_redis
    sink._running = True
    sinks_tracker.append(sink)
    return sink


def _install_mock_governor() -> MagicMock:
    gov = MagicMock(spec=SymbolicGovernor)
    gov.validate_action = AsyncMock(
        return_value={"verdict": "ALLOW", "violations": [], "latency_ms": 0.5}
    )
    gov.bind_server_inputs = AsyncMock(side_effect=lambda _a, p: dict(p))
    opa = MagicMock()
    opa.evaluate_policy = AsyncMock(return_value="ALLOW")
    gov.components = SimpleNamespace(opa=opa)
    governance_app.state.governor = gov
    return gov


def _gated_governance_root() -> FastAPI:
    root = FastAPI()
    root.add_middleware(
        WorkloadIdentityMiddleware,
        policy=IdentityPolicy(trusted=frozenset({QUARANTINED_ID, CLEAN_ID})),
    )
    root.mount("/governance", governance_app)
    return root


@pytest.mark.asyncio
async def test_validate_action_blocks_quarantined_svid_and_commits_sc7_receipt(
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """Quarantined Linkerd SVID gets 403 + chained SC-7 receipt on /governance/validate-action."""
    q_server = fakeredis.FakeServer()
    redis_a = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    redis_b = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)

    await dispatch_quarantine(
        _make_directive(agent_svid=QUARANTINED_ID), redis_client=redis_a
    )
    clear_local_quarantine_state()

    gov = _install_mock_governor()
    governance_app.state.redis = redis_b
    governance_app.state.evidence_sink = sink
    root = _gated_governance_root()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root, client=PROXY_PEER),
        base_url=POD_BASE_URL,
        headers={"l5d-client-id": QUARANTINED_ID},
    ) as client:
        resp = await client.post(
            "/governance/validate-action",
            json={
                "action": "execute_trade",
                "params": {"amount": 250, "symbol": "AAPL"},
            },
        )

    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "workload_quarantined"
    assert body["agent_id"] == QUARANTINED_ID
    assert len(body["proof_hash"]) == 64
    gov.validate_action.assert_not_awaited()

    entries = _read_stream_entries(stream_server)
    assert len(entries) == 1
    _msg_id, fields = entries[0]
    assert fields["event_type"] == "GOVERNANCE_REFUSAL_RECEIPT"
    assert fields["control_id"] == "SC-7"
    payload = json.loads(fields["payload_json"])
    assert payload["oscal_control_ref"] == "SC-7"
    assert payload["control_id"] == "SC-7"
    assert payload["decision"] == "DENY"
    assert payload["surface"] == "governance_middleware"
    assert payload["agent_id"] == QUARANTINED_ID
    assert payload["proof_hash"] == body["proof_hash"]

    findings = check_stream([fields], expected_refusal_hashes=[body["proof_hash"]])
    assert findings == [], f"Stream invariant findings: {findings}"

    iso_entries = _isolated_quarantine_and_app_state.iso_redis.xrange(
        "iso_control:audit_trail", min="-", max="+"
    )
    assert any(
        f.get("control") == "SC-7" and f.get("outcome") == "BLOCK"
        for _, f in iso_entries
    )


@pytest.mark.asyncio
async def test_governance_routes_block_quarantined_thread_and_decoy_mismatch(
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """Quarantined thread_id is refused on /validate-action and /policy-precheck even with decoy mismatch."""
    q_server = fakeredis.FakeServer()
    redis_shared = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)

    await dispatch_quarantine(
        _make_directive(thread_id="thread-compromised-77"), redis_client=redis_shared
    )
    clear_local_quarantine_state()

    gov = _install_mock_governor()
    governance_app.state.redis = redis_shared
    governance_app.state.evidence_sink = sink
    root = _gated_governance_root()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root, client=PROXY_PEER),
        base_url=POD_BASE_URL,
        headers={"l5d-client-id": CLEAN_ID},
    ) as client:
        # 1. Quarantined thread_id in body.params on /validate-action -> 403
        r_param = await client.post(
            "/governance/validate-action",
            json={
                "action": "execute_trade",
                "params": {"amount": 100, "thread_id": "thread-compromised-77"},
            },
        )
        assert r_param.status_code == 403
        assert r_param.json()["thread_id"] == "thread-compromised-77"

        # 2. Quarantined thread_id in x-cage-thread-id with decoy body.params.thread_id -> still 403!
        r_decoy = await client.post(
            "/governance/validate-action",
            headers={"x-cage-thread-id": "thread-compromised-77"},
            json={
                "action": "execute_trade",
                "params": {"amount": 100, "thread_id": "innocent-decoy-thread"},
            },
        )
        assert r_decoy.status_code == 403
        assert r_decoy.json()["thread_id"] == "thread-compromised-77"

        # 3. Quarantined thread_id in x-cage-thread-id header on /policy-precheck -> 403
        r_hdr = await client.post(
            "/governance/policy-precheck",
            headers={"x-cage-thread-id": "thread-compromised-77"},
            json={"action": "execute_trade", "params": {"amount": 100}},
        )
        assert r_hdr.status_code == 403
        assert r_hdr.json()["error"] == "workload_quarantined"
        gov.validate_action.assert_not_awaited()

        # 4. Clean thread_id on same CLEAN_ID SVID -> 200
        r_clean = await client.post(
            "/governance/policy-precheck",
            headers={"x-cage-thread-id": "thread-clean-1"},
            json={"action": "execute_trade", "params": {"amount": 100}},
        )
        assert r_clean.status_code == 200

    entries = _read_stream_entries(stream_server)
    assert len(entries) == 3
    assert check_stream([f for _, f in entries], expected_refusal_count=3) == []


@pytest.mark.asyncio
async def test_caller_supplied_svid_headers_are_ignored_and_forged_peers_untrusted(
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """Caller-supplied x-cage-agent-svid / agent_svid fields never override l5d-client-id."""
    q_server = fakeredis.FakeServer()
    redis_shared = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    stream_server = fakeredis.FakeServer()

    await dispatch_quarantine(
        _make_directive(agent_svid=QUARANTINED_ID), redis_client=redis_shared
    )

    _install_mock_governor()
    governance_app.state.redis = redis_shared
    governance_app.state.evidence_sink = _make_real_sink(
        stream_server, _isolated_quarantine_and_app_state.sinks
    )
    root = _gated_governance_root()

    # Forged l5d-client-id from another pod IP or malformed uppercase is never trusted
    forged_scope = {
        "type": "http",
        "headers": [(b"l5d-client-id", CLEAN_ID.encode("latin-1"))],
        "client": OTHER_POD_PEER,
        "server": (POD_IP, 8080),
    }
    assert resolve_verified_workload_identity(forged_scope) is None
    malformed_scope = {
        "type": "http",
        "headers": [(b"l5d-client-id", QUARANTINED_ID.upper().encode("latin-1"))],
        "client": PROXY_PEER,
        "server": (POD_IP, 8080),
    }
    assert resolve_verified_workload_identity(malformed_scope) is None

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root, client=PROXY_PEER),
        base_url=POD_BASE_URL,
    ) as client:
        # (a) Quarantined workload attempting to spoof x-cage-agent-svid=CLEAN_ID is still blocked
        r_evade = await client.post(
            "/governance/validate-action",
            headers={
                "l5d-client-id": QUARANTINED_ID,
                "x-cage-agent-svid": CLEAN_ID,
            },
            json={
                "action": "execute_trade",
                "params": {"amount": 50, "agent_svid": CLEAN_ID},
            },
        )
        assert r_evade.status_code == 403
        assert r_evade.json()["agent_id"] == QUARANTINED_ID

        # (b) Clean workload sending x-cage-agent-svid=QUARANTINED_ID is NOT framed
        r_clean = await client.post(
            "/governance/policy-precheck",
            headers={
                "l5d-client-id": CLEAN_ID,
                "x-cage-agent-svid": QUARANTINED_ID,
            },
            json={
                "action": "execute_trade",
                "params": {"amount": 50, "agent_svid": QUARANTINED_ID},
            },
        )
        assert r_clean.status_code == 200


@pytest.mark.asyncio
async def test_quarantine_refusal_fails_closed_to_503_when_blocking_sink_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When EVIDENCE_CHAIN_BLOCKING=true and sink cannot commit, endpoints return 503 (never un-evidenced 403)."""
    q_server = fakeredis.FakeServer()
    redis_shared = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    await dispatch_quarantine(
        _make_directive(agent_svid=QUARANTINED_ID), redis_client=redis_shared
    )
    clear_local_quarantine_state()

    _install_mock_governor()
    governance_app.state.redis = redis_shared
    broken_sink = EvidenceStreamSink()
    governance_app.state.evidence_sink = broken_sink
    root = _gated_governance_root()

    monkeypatch.setenv("EVIDENCE_CHAIN_BLOCKING", "true")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root, client=PROXY_PEER),
        base_url=POD_BASE_URL,
        headers={"l5d-client-id": QUARANTINED_ID},
    ) as client:
        r_503 = await client.post(
            "/governance/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )
        assert r_503.status_code == 503
        assert r_503.json()["error"] == "evidence_chain_unavailable"

        # Non-blocking mode degrades gracefully to 403 when sink is inactive
        monkeypatch.setenv("EVIDENCE_CHAIN_BLOCKING", "false")
        r_403 = await client.post(
            "/governance/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )
        assert r_403.status_code == 403
        assert r_403.json()["error"] == "workload_quarantined"


class _HeaderInjectingTransport(httpx.AsyncBaseTransport):
    """Injects pod-local Linkerd identity headers onto GatewayMCPClient ASGI requests."""

    def __init__(self, app: Any, headers: dict[str, str]) -> None:
        self._inner = httpx.ASGITransport(app=app, client=PROXY_PEER)
        self._headers = headers

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        merged = httpx.Headers(request.headers)
        for k, v in self._headers.items():
            merged[k] = v
        merged["host"] = "gateway:8080"
        rewritten = httpx.Request(
            method=request.method,
            url=request.url,
            headers=merged,
            stream=request.stream,
            extensions=request.extensions,
        )
        return await self._inner.handle_async_request(rewritten)


@pytest.mark.asyncio
async def test_mcp_streamable_http_and_tools_execute_enforce_quarantine(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """/mcp on mts.app and /tools/execute block quarantined SVIDs and threads with SC-7 evidence."""
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", f"{QUARANTINED_ID},{CLEAN_ID}")
    q_server = fakeredis.FakeServer()
    redis_shared = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)

    await dispatch_quarantine(
        _make_directive(agent_svid=QUARANTINED_ID, thread_id="mcp-bad-thread"),
        redis_client=redis_shared,
    )
    clear_local_quarantine_state()

    import src.gateway.server.mcp_tool_server as mts

    executed_calls: list[str] = []

    @mts.mcp.tool()
    async def sample_ingress_tool(symbol: str, thread_id: str = "clean-thread") -> str:
        executed_calls.append(f"{symbol}:{thread_id}")
        return f"OK:{symbol}:{thread_id}"

    prev_mts_redis = getattr(mts.app.state, "redis", None)
    prev_mts_sink = getattr(mts.app.state, "evidence_sink", None)
    try:
        mts.app.state.redis = redis_shared
        mts.app.state.evidence_sink = sink

        async with AsyncExitStack() as stack:
            await stack.enter_async_context(mts.mcp.session_manager.run())

            # 1. Quarantined SVID hitting /mcp/ on mts.app -> 403 + SC-7 receipt before FastMCP runs
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mts.app, client=PROXY_PEER),
                base_url=POD_BASE_URL,
                headers={"l5d-client-id": QUARANTINED_ID, "host": "gateway:8080"},
            ) as q_http:
                r_mcp_svid = await q_http.post(
                    "/mcp/",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                assert r_mcp_svid.status_code == 403
                assert r_mcp_svid.json()["error"] == "workload_quarantined"
                assert r_mcp_svid.json()["agent_id"] == QUARANTINED_ID

            # 2. Clean SVID with unquarantined thread succeeds via real GatewayMCPClient on mts.app (replay verified)
            mcp_client = GatewayMCPClient(
                f"{POD_BASE_URL}/mcp/",
                http_transport=_HeaderInjectingTransport(
                    mts.app, {"l5d-client-id": CLEAN_ID}
                ),
            )
            ok_out = await mcp_client.call_tool(
                "sample_ingress_tool", {"symbol": "MSFT", "thread_id": "clean-thread"}
            )
            assert "OK:MSFT:clean-thread" in ok_out
            assert executed_calls == ["MSFT:clean-thread"]
            await mcp_client._reset_unlocked()

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mts.app, client=PROXY_PEER),
                base_url=POD_BASE_URL,
                headers={
                    "l5d-client-id": CLEAN_ID,
                    "host": "gateway:8080",
                    "accept": "application/json, text/event-stream",
                },
            ) as c_http:
                # 3. Clean SVID carrying quarantined arguments.thread_id -> refused 403
                r_rpc_thread = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "innocent-decoy-header"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "sample_ingress_tool",
                            "arguments": {
                                "symbol": "NVDA",
                                "thread_id": "mcp-bad-thread",
                            },
                        },
                    },
                )
                assert r_rpc_thread.status_code == 403
                assert r_rpc_thread.json()["thread_id"] == "mcp-bad-thread"
                assert executed_calls == ["MSFT:clean-thread"]

                # 4. Body exceeding inspection limit (> 64 KiB) carrying quarantined thread_id
                #    fails closed to 413 (payload_too_large) and never executes tool
                padded_args = {
                    "symbol": "NVDA",
                    "thread_id": "mcp-bad-thread",
                    "padding": "x" * 70_000,
                }
                r_too_large = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "innocent-decoy-header"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "sample_ingress_tool",
                            "arguments": padded_args,
                        },
                    },
                )
                assert r_too_large.status_code == 413
                assert r_too_large.json()["error"] == "payload_too_large"
                assert executed_calls == ["MSFT:clean-thread"]

                # 5. Blocking evidence sink failure on /mcp/ -> 503
                mts.app.state.evidence_sink = EvidenceStreamSink()
                r_mcp_503 = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "mcp-bad-thread"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                assert r_mcp_503.status_code == 503
                assert r_mcp_503.json()["error"] == "evidence_chain_unavailable"

        # 6. /tools/execute on mts.app enforces quarantine + blocking SC-7 receipt
        mts.app.state.evidence_sink = sink
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mts.app, client=PROXY_PEER),
            base_url=POD_BASE_URL,
            headers={"l5d-client-id": QUARANTINED_ID},
        ) as exec_http:
            r_exec = await exec_http.post(
                "/tools/execute",
                json={
                    "tool_name": "verify_content_safety",
                    "params": {"text": "hello"},
                },
            )
            assert r_exec.status_code == 403
            assert r_exec.json()["error"] == "workload_quarantined"

            mts.app.state.evidence_sink = EvidenceStreamSink()
            r_exec_503 = await exec_http.post(
                "/tools/execute",
                json={
                    "tool_name": "verify_content_safety",
                    "params": {"text": "hello"},
                },
            )
            assert r_exec_503.status_code == 503
            assert r_exec_503.json()["error"] == "evidence_chain_unavailable"
    finally:
        mts.app.state.redis = prev_mts_redis
        mts.app.state.evidence_sink = prev_mts_sink

    entries = _read_stream_entries(stream_server)
    assert len(entries) == 3  # /mcp SVID, /mcp RPC thread, /tools/execute SVID
    findings = check_stream([f for _, f in entries], expected_refusal_count=3)
    assert findings == [], f"Stream invariant findings: {findings}"
