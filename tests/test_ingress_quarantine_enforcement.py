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
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI

import src.gateway.governance.evidence.stream as es_mod
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
    extract_candidate_thread_ids,
    refuse_if_quarantined,
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
    return list(sync_r.xrange("cage:evidence:stream", min="-", max="+"))  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
async def _isolated_quarantine_and_app_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    from src.gateway.governance.kms_signer import reset_governance_signer

    monkeypatch.setenv("CAGE_KMS_PROVIDER", "ed25519")
    reset_governance_signer()
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
    prev_sink = es_mod._evidence_sink
    yield SimpleNamespace(iso_redis=iso_sync_redis, sinks=active_sinks)
    for s in active_sinks:
        await s.stop(drain_timeout_s=1.0)
    reset_governance_signer()
    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    governance_app.state.governor = prev_gov
    governance_app.state.redis = prev_redis
    es_mod._evidence_sink = prev_sink


def _make_real_sink(
    stream_server: fakeredis.FakeServer,
    sinks_tracker: list[EvidenceStreamSink],
) -> EvidenceStreamSink:
    """Create a real hash-chained EvidenceStreamSink backed by FakeRedis."""
    sink_redis = fakeredis.aioredis.FakeRedis(
        server=stream_server, decode_responses=False
    )
    sink = EvidenceStreamSink(stream_key="cage:evidence:stream")
    sink._redis = sink_redis  # type: ignore[assignment]
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
    es_mod._evidence_sink = sink
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
    assert (
        isinstance(payload["kms_signature"], str)
        and len(payload["kms_signature"]) >= 64
    )

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
    es_mod._evidence_sink = sink
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
    es_mod._evidence_sink = _make_real_sink(
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
    es_mod._evidence_sink = EvidenceStreamSink()
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
    await dispatch_quarantine(
        _make_directive(thread_id="77777"),
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
    try:
        mts.app.state.redis = redis_shared
        es_mod._evidence_sink = sink

        async with _enter_mts_session(mts):
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

                # 3b. Non-conforming client embedding thread_id in params.thread_id -> refused 403
                r_params_thread = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "innocent-decoy-header"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 98,
                        "method": "tools/call",
                        "params": {
                            "name": "sample_ingress_tool",
                            "thread_id": "mcp-bad-thread",
                            "arguments": {
                                "symbol": "NVDA",
                            },
                        },
                    },
                )
                assert r_params_thread.status_code == 403
                assert r_params_thread.json()["thread_id"] == "mcp-bad-thread"
                assert executed_calls == ["MSFT:clean-thread"]

                # 3c. Non-conforming client embedding thread_id at root item level -> refused 403
                r_root_thread = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "innocent-decoy-header"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 99,
                        "thread_id": "mcp-bad-thread",
                        "method": "tools/call",
                        "params": {
                            "name": "sample_ingress_tool",
                            "arguments": {
                                "symbol": "NVDA",
                            },
                        },
                    },
                )
                assert r_root_thread.status_code == 403
                assert r_root_thread.json()["thread_id"] == "mcp-bad-thread"
                assert executed_calls == ["MSFT:clean-thread"]

                # 3d. Integer scalar thread_id 77777 in JSON-RPC arguments -> refused 403
                r_int_thread = await c_http.post(
                    "/mcp/",
                    headers={"x-cage-thread-id": "innocent-decoy-header"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 100,
                        "method": "tools/call",
                        "params": {
                            "name": "sample_ingress_tool",
                            "arguments": {
                                "symbol": "NVDA",
                                "thread_id": 77777,
                            },
                        },
                    },
                )
                assert r_int_thread.status_code == 403
                assert r_int_thread.json()["thread_id"] == "77777"
                assert executed_calls == ["MSFT:clean-thread"]

                # 3e. JSON null thread_id in JSON-RPC payload does not extract candidate "None" or refuse clean call
                r_null_thread = await c_http.post(
                    "/mcp/",
                    json={
                        "jsonrpc": "2.0",
                        "id": 101,
                        "method": "tools/list",
                        "params": {
                            "thread_id": None,
                        },
                    },
                )
                assert r_null_thread.status_code == 200
                assert r_null_thread.json().get("error") is None

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
                es_mod._evidence_sink = EvidenceStreamSink()
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
        es_mod._evidence_sink = sink
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

            es_mod._evidence_sink = EvidenceStreamSink()
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

    entries = _read_stream_entries(stream_server)
    assert (
        len(entries) == 6
    )  # /mcp SVID, 4 /mcp RPC thread variants, /tools/execute SVID
    findings = check_stream([f for _, f in entries], expected_refusal_count=6)
    assert findings == [], f"Stream invariant findings: {findings}"


def test_shared_redis_builder_enforcing_fail_fast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify _build_shared_redis_from_env fails fast at startup under enforcing posture."""
    from src.gateway.server.hybrid_server import _build_shared_redis_from_env

    # 1. Enforcing posture without REDIS_URL / REDIS_HOST fails fast at startup
    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    with pytest.raises(
        RuntimeError,
        match="Shared Redis client is required under an enforcing posture",
    ):
        _build_shared_redis_from_env()

    # 2. Enforcing posture with Redis init failure fails fast at startup
    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.build_async_redis",
        MagicMock(side_effect=ConnectionError("Redis connection refused")),
    )
    with pytest.raises(
        RuntimeError,
        match="Shared Redis client initialization failed under an enforcing posture",
    ):
        _build_shared_redis_from_env()

    # 3. Non-enforcing posture without Redis returns None without raising
    monkeypatch.setenv("CAGE_ENV", "dev")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    assert _build_shared_redis_from_env() is None


@pytest.mark.asyncio
async def test_mcp_quarantine_middleware_chunked_streaming_fails_closed_at_64k() -> (
    None
):
    """Verify ASGI body chunk accumulation past 64 KiB returns HTTP 413 and suppresses downstream app."""
    downstream_called = False

    async def _dummy_downstream(scope: Any, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        downstream_called = True

    mw = McpQuarantineMiddleware(_dummy_downstream)

    # 1. Stream 9 chunks of 8 KiB (72 KiB total > 64 KiB)
    chunk_size = 8192
    num_chunks = 9
    chunks_sent = 0

    async def _oversized_receive() -> dict[str, Any]:
        nonlocal chunks_sent
        chunks_sent += 1
        return {
            "type": "http.request",
            "body": b"A" * chunk_size,
            "more_body": chunks_sent < num_chunks,
        }

    sent_messages: list[dict[str, Any]] = []
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-type", b"application/json")],
    }

    await mw(scope, _oversized_receive, _make_async_collector(sent_messages))

    assert not downstream_called
    assert len(sent_messages) == 2
    assert sent_messages[0]["type"] == "http.response.start"
    assert sent_messages[0]["status"] == 413
    body = json.loads(sent_messages[1]["body"].decode("utf-8"))
    assert body["error"] == "payload_too_large"

    # 2. Clean small request (< 64 KiB) passes through to downstream app intact
    downstream_called = False
    clean_received: list[dict[str, Any]] = []

    async def _clean_downstream(scope: Any, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        downstream_called = True
        msg = await receive()
        clean_received.append(msg)

    mw_clean = McpQuarantineMiddleware(_clean_downstream)

    async def _clean_receive() -> dict[str, Any]:
        return {
            "type": "http.request",
            "body": b'{"jsonrpc": "2.0", "method": "ping"}',
            "more_body": False,
        }

    sent_clean: list[dict[str, Any]] = []
    await mw_clean(scope, _clean_receive, _make_async_collector(sent_clean))
    assert downstream_called
    assert len(clean_received) == 1
    assert clean_received[0]["body"] == b'{"jsonrpc": "2.0", "method": "ping"}'


@pytest.mark.asyncio
async def test_mcp_quarantine_middleware_exact_64k_boundary_and_jitter() -> None:
    """Verify precise 64 KiB (65,536) boundary: 65,535/65,536 pass, 65,537 fails closed (413)."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-type", b"application/json")],
    }

    # Case 1: Exact 65,536 bytes split into 65,535 bytes + 1 byte (more_body=False) -> passes through
    downstream_1 = False
    replayed_chunks: list[bytes] = []

    async def _downstream_1(_scope: Any, receive: Any, _send: Any) -> None:
        nonlocal downstream_1
        downstream_1 = True
        while True:
            m = await receive()
            if m.get("type") == "http.request":
                replayed_chunks.append(m.get("body", b""))
                if not m.get("more_body", False):
                    break

    mw_1 = McpQuarantineMiddleware(_downstream_1)
    chunk_stream_1 = [
        {"type": "http.request", "body": b"B" * 65535, "more_body": True},
        {"type": "http.request", "body": b"C", "more_body": False},
    ]

    async def _recv_1() -> dict[str, Any]:
        return chunk_stream_1.pop(0)

    sent_1: list[dict[str, Any]] = []
    await mw_1(scope, _recv_1, _make_async_collector(sent_1))
    assert downstream_1
    assert len(replayed_chunks) == 2
    assert sum(len(c) for c in replayed_chunks) == 65536
    assert len(sent_1) == 0

    # Case 2: 65,537 bytes (65,535 + 2 bytes with more_body=True and trailing chunk left on wire) -> 413
    downstream_2 = False

    async def _downstream_2(_scope: Any, _receive: Any, _send: Any) -> None:
        nonlocal downstream_2
        downstream_2 = True

    mw_2 = McpQuarantineMiddleware(_downstream_2)
    chunk_stream_2 = [
        {"type": "http.request", "body": b"X" * 65535, "more_body": True},
        {"type": "http.request", "body": b"YZ", "more_body": True},
        {"type": "http.request", "body": b"TRAILING_UNREAD_DATA", "more_body": False},
    ]

    async def _recv_2() -> dict[str, Any]:
        return chunk_stream_2.pop(0)

    sent_2: list[dict[str, Any]] = []
    await mw_2(scope, _recv_2, _make_async_collector(sent_2))
    assert not downstream_2
    assert len(sent_2) == 2
    assert sent_2[0]["type"] == "http.response.start"
    assert sent_2[0]["status"] == 413
    assert (
        len(chunk_stream_2) == 1
    )  # Trailing chunk was not read; middleware failed closed immediately

    # Case 3: Jitter with 0-byte chunks and 65,535 bytes total -> passes through intact
    downstream_3 = False
    replayed_chunks_3: list[bytes] = []

    async def _downstream_3(_scope: Any, receive: Any, _send: Any) -> None:
        nonlocal downstream_3
        downstream_3 = True
        while True:
            m = await receive()
            if m.get("type") == "http.request":
                replayed_chunks_3.append(m.get("body", b""))
                if not m.get("more_body", False):
                    break

    mw_3 = McpQuarantineMiddleware(_downstream_3)
    chunk_stream_3 = [
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"H" * 30000, "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"I" * 35535, "more_body": False},
    ]

    async def _recv_3() -> dict[str, Any]:
        return chunk_stream_3.pop(0)

    sent_3: list[dict[str, Any]] = []
    await mw_3(scope, _recv_3, _make_async_collector(sent_3))
    assert downstream_3
    assert sum(len(c) for c in replayed_chunks_3) == 65535


def test_extract_candidate_thread_ids_coverage() -> None:
    """Verify thread_id extraction across direct body, nested arguments, params, and headers."""
    # Direct thread_id in body
    scope_empty: dict[str, Any] = {"headers": []}
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": "t-direct"}) == (
        "t-direct",
    )

    # Nested arguments and params in body
    assert extract_candidate_thread_ids(
        scope_empty, {"arguments": {"thread_id": "t-args"}}
    ) == ("t-args",)
    assert extract_candidate_thread_ids(
        scope_empty, {"params": {"thread_id": "t-params"}}
    ) == ("t-params",)

    # Integer scalar converted to string
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": 12345}) == ("12345",)
    assert extract_candidate_thread_ids(
        scope_empty, {"arguments": {"thread_id": 67890}}
    ) == ("67890",)

    # None, null, empty, boolean, and container structures safely ignored (never synthesizes "None")
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": None}) == ()
    assert (
        extract_candidate_thread_ids(scope_empty, {"arguments": {"thread_id": None}})
        == ()
    )
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": ""}) == ()
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": "   "}) == ()
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": "None"}) == ()
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": "null"}) == ()
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": True}) == ()
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": False}) == ()
    assert (
        extract_candidate_thread_ids(scope_empty, {"thread_id": {"nested": "dict"}})
        == ()
    )
    assert extract_candidate_thread_ids(scope_empty, {"thread_id": [1, 2, 3]}) == ()

    # Header extraction with deduplication and sentinel filtering
    scope_with_hdr: dict[str, Any] = {
        "headers": [(b"x-cage-thread-id", b"t-header"), (b"host", b"localhost")]
    }
    assert extract_candidate_thread_ids(scope_with_hdr) == ("t-header",)

    scope_with_none_hdr: dict[str, Any] = {
        "headers": [(b"x-cage-thread-id", b"None"), (b"host", b"localhost")]
    }
    assert extract_candidate_thread_ids(scope_with_none_hdr) == ()

    # Combined with duplicate elimination
    res = extract_candidate_thread_ids(
        scope_with_hdr,
        {
            "thread_id": "t-header",
            "arguments": {"thread_id": "t-nested"},
        },
    )
    assert res == ("t-header", "t-nested")


@asynccontextmanager
async def _enter_mts_session(mts_mod: Any) -> AsyncIterator[None]:
    """Run ``mts.mcp.session_manager`` across multiple hermetic tests in one worker."""
    mgr = mts_mod.mcp.session_manager
    if (
        getattr(mgr, "_has_started", False)
        and getattr(mgr, "_task_group", None) is None
    ):
        mgr._has_started = False
    async with AsyncExitStack() as stack:
        await stack.enter_async_context(mgr.run())
        yield


def _make_async_collector(bucket: list[dict[str, Any]]) -> Any:
    async def _send(msg: dict[str, Any]) -> None:
        bucket.append(msg)

    return _send


@pytest.mark.asyncio
async def test_mcp_streaming_content_length_disconnect_and_sse_passthrough() -> None:
    """Verify Content-Length fast-fail, spoofed-length byte cap, mid-body disconnect, and post-body SSE receive."""
    downstream_calls = 0
    post_body_events: list[dict[str, Any]] = []

    async def _sse_downstream(_scope: Any, receive: Any, _send: Any) -> None:
        nonlocal downstream_calls
        downstream_calls += 1
        first = await receive()
        assert first["type"] == "http.request"
        assert first["more_body"] is False
        # Simulate FastMCP SSE task awaiting subsequent http.disconnect after body drain
        second = await receive()
        post_body_events.append(second)

    mw = McpQuarantineMiddleware(_sse_downstream)

    # 1. Declared Content-Length > 64 KiB fails closed (413) WITHOUT calling receive()
    receive_invocations = 0

    async def _unexpected_receive() -> dict[str, Any]:
        nonlocal receive_invocations
        receive_invocations += 1
        return {"type": "http.request", "body": b"{}", "more_body": False}

    sent_cl: list[dict[str, Any]] = []
    oversized_cl_scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", b"1048576"),
        ],
    }
    await mw(oversized_cl_scope, _unexpected_receive, _make_async_collector(sent_cl))
    assert receive_invocations == 0
    assert downstream_calls == 0
    assert sent_cl[0]["status"] == 413

    # 2. Spoofed small Content-Length (64) with > 64 KiB actual streamed body still fails closed (413)
    sent_spoof: list[dict[str, Any]] = []
    spoof_chunks = [
        {"type": "http.request", "body": b"A" * 40_000, "more_body": True},
        {"type": "http.request", "body": b"B" * 30_000, "more_body": False},
    ]
    spoof_scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", b"64"),
        ],
    }

    async def _spoof_recv() -> dict[str, Any]:
        return spoof_chunks.pop(0)

    await mw(spoof_scope, _spoof_recv, _make_async_collector(sent_spoof))
    assert downstream_calls == 0
    assert sent_spoof[0]["status"] == 413

    # 3. Mid-upload http.disconnect aborts cleanly without invoking downstream or sending onto closed socket
    sent_disc: list[dict[str, Any]] = []
    disc_frames: list[dict[str, Any]] = [
        {
            "type": "http.request",
            "body": b'{"jsonrpc":"2.0","method":"tools/list"',
            "more_body": True,
        },
        {"type": "http.disconnect"},
    ]
    base_scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-type", b"application/json")],
    }

    async def _disc_recv() -> dict[str, Any]:
        return disc_frames.pop(0)

    await mw(base_scope, _disc_recv, _make_async_collector(sent_disc))
    assert downstream_calls == 0
    assert sent_disc == []

    # 4. Post-body SSE receive() delegates transparently to live receive() after buffered body drains
    sse_frames: list[dict[str, Any]] = [
        {
            "type": "http.request",
            "body": b'{"jsonrpc":"2.0","method":"ping"}',
            "more_body": False,
        },
        {"type": "http.disconnect"},
    ]

    async def _sse_recv() -> dict[str, Any]:
        return sse_frames.pop(0)

    sent_sse: list[dict[str, Any]] = []
    await mw(base_scope, _sse_recv, _make_async_collector(sent_sse))
    assert downstream_calls == 1
    assert post_body_events == [{"type": "http.disconnect"}]


async def _invoke_chunked_asgi_post(
    app: Any,
    path: str,
    raw_bytes: bytes,
    split_index: int,
    headers: list[tuple[bytes, bytes]],
) -> tuple[int, bytes]:
    """Send a two-chunk ASGI POST splitting ``raw_bytes`` at ``split_index``."""
    frames: list[dict[str, Any]] = [
        {
            "type": "http.request",
            "body": raw_bytes[:split_index],
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": raw_bytes[split_index:],
            "more_body": False,
        },
        {"type": "http.disconnect"},
    ]
    sent: list[dict[str, Any]] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": PROXY_PEER,
        "server": (POD_IP, 8080),
        "state": {},
    }

    async def _recv() -> dict[str, Any]:
        return frames.pop(0) if frames else {"type": "http.disconnect"}

    await app(scope, _recv, _make_async_collector(sent))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    )
    return status, body


@pytest.mark.asyncio
async def test_mcp_split_utf8_replay_and_batch_rpc_quarantine_on_mts_app(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """Verify multi-chunk split thread_id/UTF-8 replay and JSON-RPC batch refusal directly on mts.app."""
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", f"{QUARANTINED_ID},{CLEAN_ID}")
    q_server = fakeredis.FakeServer()
    redis_shared = fakeredis.aioredis.FakeRedis(server=q_server, decode_responses=True)
    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)

    await dispatch_quarantine(
        _make_directive(thread_id="mcp-split-bad-thread"),
        redis_client=redis_shared,
    )
    clear_local_quarantine_state()

    import src.gateway.server.mcp_tool_server as mts

    executed: list[str] = []

    @mts.mcp.tool()
    async def sample_split_replay_tool(
        label: str, thread_id: str = "clean-thread"
    ) -> str:
        executed.append(f"{label}:{thread_id}")
        return f"OK:{label}:{thread_id}"

    prev_redis = getattr(mts.app.state, "redis", None)
    base_hdrs = [
        (b"host", b"gateway:8080"),
        (b"content-type", b"application/json"),
        (b"accept", b"application/json, text/event-stream"),
        (b"l5d-client-id", CLEAN_ID.encode("latin-1")),
    ]
    try:
        mts.app.state.redis = redis_shared
        es_mod._evidence_sink = sink

        async with _enter_mts_session(mts):
            # 1. Quarantined thread_id split right down the middle across two ASGI chunks -> 403
            bad_rpc = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 201,
                    "method": "tools/call",
                    "params": {
                        "name": "sample_split_replay_tool",
                        "arguments": {
                            "label": "AAPL",
                            "thread_id": "mcp-split-bad-thread",
                        },
                    },
                }
            ).encode("utf-8")
            split_pos = bad_rpc.index(b"mcp-split-") + len(b"mcp-split-")
            st_bad, raw_bad = await _invoke_chunked_asgi_post(
                mts.app, "/mcp/", bad_rpc, split_pos, base_hdrs
            )
            assert st_bad == 403
            assert json.loads(raw_bad)["thread_id"] == "mcp-split-bad-thread"
            assert executed == []

            # 2. Clean 3-byte UTF-8 character ('€' = \xe2\x82\xac) split mid-codepoint across chunks -> replays cleanly
            clean_rpc = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 202,
                    "method": "tools/call",
                    "params": {
                        "name": "sample_split_replay_tool",
                        "arguments": {
                            "label": "€-FUND",
                            "thread_id": "clean-thread",
                        },
                    },
                },
                ensure_ascii=False,
            ).encode("utf-8")
            euro_pos = (
                clean_rpc.index("€".encode()) + 1
            )  # Split inside 3-byte UTF-8 sequence
            st_clean, raw_clean = await _invoke_chunked_asgi_post(
                mts.app, "/mcp/", clean_rpc, euro_pos, base_hdrs
            )
            assert st_clean == 200
            assert "€-FUND" in raw_clean.decode("utf-8")
            assert executed == ["€-FUND:clean-thread"]

            # 3. JSON-RPC batch array [clean_call, quarantined_call] -> entire batch refused 403 before item[0] runs
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mts.app, client=PROXY_PEER),
                base_url=POD_BASE_URL,
                headers={
                    "l5d-client-id": CLEAN_ID,
                    "host": "gateway:8080",
                    "accept": "application/json, text/event-stream",
                },
            ) as c_http:
                r_batch = await c_http.post(
                    "/mcp/",
                    json=[
                        {
                            "jsonrpc": "2.0",
                            "id": 203,
                            "method": "tools/call",
                            "params": {
                                "name": "sample_split_replay_tool",
                                "arguments": {
                                    "label": "SHOULD_NOT_RUN",
                                    "thread_id": "clean-thread",
                                },
                            },
                        },
                        {
                            "jsonrpc": "2.0",
                            "id": 204,
                            "method": "tools/call",
                            "params": {
                                "name": "sample_split_replay_tool",
                                "arguments": {
                                    "label": "BLOCKED",
                                    "thread_id": "mcp-split-bad-thread",
                                },
                            },
                        },
                    ],
                )
                assert r_batch.status_code == 403
                assert r_batch.json()["thread_id"] == "mcp-split-bad-thread"
                assert executed == ["€-FUND:clean-thread"]
    finally:
        mts.app.state.redis = prev_redis

    entries = _read_stream_entries(stream_server)
    assert len(entries) == 2
    assert check_stream([f for _, f in entries], expected_refusal_count=2) == []


@pytest.mark.parametrize("enforcing_env", ["staging", "prod", "production"])
@pytest.mark.asyncio
async def test_production_workload_identity_and_redis_failure_edge_cases(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_and_app_state: SimpleNamespace,
    enforcing_env: str,
) -> None:
    """Verify loopback/duplicate-header/spiffe rejections and startup/runtime Redis fail-closed behavior."""
    from src.gateway.server.hybrid_server import (
        _build_shared_redis_from_env,
        _verify_shared_redis_startup,
    )

    monkeypatch.setenv("CAGE_ENV", enforcing_env)
    monkeypatch.setenv("CAGE_ALLOW_DEV_LOOPBACK_IDENTITY", "true")

    # 1. Loopback peers (IPv4, IPv6, IPv4-mapped IPv6), duplicate l5d-client-id, and spiffe:// are rejected
    for bad_peer in (("127.0.0.1", 50000), ("::1", 50000), ("::ffff:127.0.0.1", 50000)):
        loopback_scope = {
            "type": "http",
            "headers": [(b"l5d-client-id", CLEAN_ID.encode("latin-1"))],
            "client": bad_peer,
            "server": (bad_peer[0], 8080),
        }
        assert resolve_verified_workload_identity(loopback_scope) is None

    dup_scope = {
        "type": "http",
        "headers": [
            (b"l5d-client-id", CLEAN_ID.encode("latin-1")),
            (b"l5d-client-id", QUARANTINED_ID.encode("latin-1")),
        ],
        "client": PROXY_PEER,
        "server": (POD_IP, 8080),
    }
    assert resolve_verified_workload_identity(dup_scope) is None

    spiffe_scope = {
        "type": "http",
        "headers": [
            (
                b"l5d-client-id",
                b"spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
            )
        ],
        "client": PROXY_PEER,
        "server": (POD_IP, 8080),
    }
    assert resolve_verified_workload_identity(spiffe_scope) is None

    # 2. Startup Redis PING probe fails fast and closes lazy pool when Redis is unreachable in enforcing postures
    dead_redis = MagicMock()
    dead_redis.ping = AsyncMock(side_effect=ConnectionError("Connection refused"))
    dead_redis.aclose = AsyncMock()
    with pytest.raises(
        RuntimeError,
        match="Shared Redis connectivity check \\(PING\\) failed under an enforcing posture",
    ):
        await _verify_shared_redis_startup(dead_redis)
    dead_redis.aclose.assert_awaited_once()

    # URL DB path preserved when REDIS_DB is unset; malformed REDIS_DB fails fast in enforcing postures
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/2")
    monkeypatch.delenv("REDIS_DB", raising=False)
    captured_db: list[Any] = []

    def _spy_build_redis(url: str, *, db: Any = None) -> Any:
        captured_db.append((url, db))
        return MagicMock()

    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.build_async_redis",
        _spy_build_redis,
    )
    _build_shared_redis_from_env()
    assert captured_db == [("redis://localhost:6379/2", None)]

    monkeypatch.setenv("REDIS_DB", "not-an-integer")
    with pytest.raises(
        RuntimeError,
        match="Shared Redis client initialization failed under an enforcing posture",
    ):
        _build_shared_redis_from_env()

    # 3. Runtime Redis outage mid-request fails closed with HTTP 503 and unsigned
    #    GOVERNANCE_INFRASTRUCTURE_BLOCK (dependency='redis'), never fabricating a signed SC-7 refusal
    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)
    flaky_runtime_redis = MagicMock()
    flaky_runtime_redis.exists = AsyncMock(
        side_effect=TimeoutError("Redis socket read timed out")
    )
    gov = _install_mock_governor()
    governance_app.state.redis = flaky_runtime_redis
    es_mod._evidence_sink = sink
    root = _gated_governance_root()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root, client=PROXY_PEER),
        base_url=POD_BASE_URL,
        headers={"l5d-client-id": CLEAN_ID},
    ) as client:
        r_outage = await client.post(
            "/governance/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )
        assert r_outage.status_code == 503
        assert "Retry-After" not in r_outage.headers
        outage_body = r_outage.json()
        assert outage_body["error"] == "governance_dependency_unavailable"
        assert outage_body["dependency"] == "redis"
        assert outage_body["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"
        assert "proof_hash" not in outage_body
        assert "refusal_receipt" not in outage_body
        gov.validate_action.assert_not_awaited()

    entries = _read_stream_entries(stream_server)
    assert len(entries) == 1
    assert entries[0][1]["event_type"] == "GOVERNANCE_INFRASTRUCTURE_BLOCK"
    infra_payload = json.loads(entries[0][1]["payload_json"])
    assert infra_payload["dependency"] == "redis"
    assert infra_payload["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"
    assert infra_payload["controlId"] == "SC-7"
    assert len(infra_payload["params_hash"]) == 64
    assert "proof_hash" not in infra_payload
    assert check_stream([f for _, f in entries], expected_refusal_count=0) == []


@pytest.mark.asyncio
async def test_redis_outage_kms_failure_and_scope_without_app(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_and_app_state: SimpleNamespace,
) -> None:
    """Verify scope.get('app') safety, Redis 503 infrastructure blocks, and KMS signing fail-closed 503."""
    from prometheus_client import CollectorRegistry
    from starlette.requests import Request

    import src.gateway.server.mcp_tool_server as mts
    import src.gateway.server.quarantine_guard as qg_mod
    from src.gateway.governance.governor.metrics import GovernorMetrics
    from src.gateway.governance.kms_signer import KMSGovernanceSigner

    monkeypatch.setenv("EVIDENCE_CHAIN_BLOCKING", "true")
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", f"{CLEAN_ID},{QUARANTINED_ID}")

    # 1. Request scope omitting 'app' does not raise KeyError: 'app' in refuse_if_quarantined()
    scope_no_app = {
        "type": "http",
        "method": "POST",
        "path": "/tools/execute",
        "headers": [(b"l5d-client-id", CLEAN_ID.encode("latin-1"))],
        "client": PROXY_PEER,
        "server": (POD_IP, 8080),
    }
    assert (
        await refuse_if_quarantined(
            Request(scope_no_app),
            action_id="verify_content_safety",
            surface="mcp_tool_server",
        )
        is None
    )

    # 2. Redis connectivity outage across /validate-action, /policy-precheck, /tools/execute, and /mcp
    #    fails closed with 503 + GOVERNANCE_INFRASTRUCTURE_BLOCK (dependency='redis'), 0 KMS calls, 0 refusals
    reg = CollectorRegistry()
    metrics = GovernorMetrics(reg)
    monkeypatch.setattr(qg_mod, "governor_metrics", lambda: metrics)
    monkeypatch.setattr(
        "src.gateway.governance.governor.verdicts.governor_metrics", lambda: metrics
    )
    spy_signer = MagicMock()
    spy_signer.sign_async = AsyncMock(return_value="sig-must-not-run-on-redis-outage")
    monkeypatch.setattr(qg_mod, "get_governance_signer", lambda: spy_signer)

    stream_server = fakeredis.FakeServer()
    sink = _make_real_sink(stream_server, _isolated_quarantine_and_app_state.sinks)
    es_mod._evidence_sink = sink

    down_redis = MagicMock()
    down_redis.exists = AsyncMock(
        side_effect=ConnectionError("Redis connection reset by peer")
    )
    gov = _install_mock_governor()
    governance_app.state.redis = down_redis
    prev_mts_redis = getattr(mts.app.state, "redis", None)
    mts.app.state.redis = down_redis

    executed_mcp: list[str] = []

    @mts.mcp.tool()
    async def sample_infra_block_tool(
        symbol: str, thread_id: str = "clean-thread"
    ) -> str:
        executed_mcp.append(f"{symbol}:{thread_id}")
        return f"OK:{symbol}"

    try:
        gov_root = _gated_governance_root()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gov_root, client=PROXY_PEER),
            base_url=POD_BASE_URL,
            headers={"l5d-client-id": CLEAN_ID},
        ) as gov_client:
            for route in ("/governance/validate-action", "/governance/policy-precheck"):
                r_gov = await gov_client.post(
                    route,
                    json={"action": "execute_trade", "params": {"amount": 50}},
                )
                assert r_gov.status_code == 503
                assert "Retry-After" not in r_gov.headers
                b_gov = r_gov.json()
                assert b_gov["error"] == "governance_dependency_unavailable"
                assert b_gov["dependency"] == "redis"
                assert b_gov["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"
                assert "proof_hash" not in b_gov
            gov.validate_action.assert_not_awaited()
            gov.components.opa.evaluate_policy.assert_not_awaited()

        mcp_root = FastAPI()
        mcp_root.add_middleware(
            WorkloadIdentityMiddleware,
            policy=IdentityPolicy(trusted=frozenset({QUARANTINED_ID, CLEAN_ID})),
        )
        mcp_root.mount("/", mts.app)

        async with AsyncExitStack() as stack:
            mts.mcp.session_manager._has_started = False
            await stack.enter_async_context(mts.mcp.session_manager.run())
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mcp_root, client=PROXY_PEER),
                base_url=POD_BASE_URL,
                headers={"l5d-client-id": CLEAN_ID},
            ) as mcp_client:
                r_exec_down = await mcp_client.post(
                    "/tools/execute",
                    json={
                        "tool_name": "sample_infra_block_tool",
                        "params": {"symbol": "AAPL", "thread_id": "t-1"},
                    },
                )
                assert r_exec_down.status_code == 503
                assert r_exec_down.json()["dependency"] == "redis"

                r_mcp_down = await mcp_client.post(
                    "/mcp/",
                    headers={
                        "accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "sample_infra_block_tool",
                            "arguments": {"symbol": "AAPL", "thread_id": "t-2"},
                        },
                    },
                )
                assert r_mcp_down.status_code == 503
                assert r_mcp_down.json()["dependency"] == "redis"
                assert executed_mcp == []

        assert spy_signer.sign_async.await_count == 0
        redis_entries = _read_stream_entries(stream_server)
        assert len(redis_entries) == 4
        assert all(
            f["event_type"] == "GOVERNANCE_INFRASTRUCTURE_BLOCK"
            for _, f in redis_entries
        )
        assert (
            check_stream([f for _, f in redis_entries], expected_refusal_count=0) == []
        )

        # 3. Confirmed quarantine refusal with KMS signing failure (exception or empty signature)
        #    fails closed as 503 infrastructure block (dependency='kms'), never writing unsigned refusal
        q_server = fakeredis.FakeServer()
        live_q_redis = fakeredis.aioredis.FakeRedis(
            server=q_server, decode_responses=True
        )
        await dispatch_quarantine(
            _make_directive(agent_svid=QUARANTINED_ID), redis_client=live_q_redis
        )
        clear_local_quarantine_state()

        kms_stream_server = fakeredis.FakeServer()
        kms_sink = _make_real_sink(
            kms_stream_server, _isolated_quarantine_and_app_state.sinks
        )
        es_mod._evidence_sink = kms_sink
        governance_app.state.redis = live_q_redis
        mts.app.state.redis = live_q_redis

        inactive_signer = KMSGovernanceSigner(
            kms_client=None,
            key_version_name="",
            public_key_pem=b"",
            provider=None,
        )
        for mode in ("exception", "empty_sig", "inactive_signer"):
            if mode == "exception":
                spy_signer.sign_async = AsyncMock(
                    side_effect=RuntimeError("Cloud KMS HSM unreachable")
                )
                monkeypatch.setattr(qg_mod, "get_governance_signer", lambda: spy_signer)
            elif mode == "empty_sig":
                spy_signer.sign_async = AsyncMock(return_value="")
                monkeypatch.setattr(qg_mod, "get_governance_signer", lambda: spy_signer)
            else:
                monkeypatch.setattr(
                    qg_mod, "get_governance_signer", lambda: inactive_signer
                )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gov_root, client=PROXY_PEER),
                base_url=POD_BASE_URL,
                headers={"l5d-client-id": QUARANTINED_ID},
            ) as q_client:
                r_kms = await q_client.post(
                    "/governance/validate-action",
                    json={"action": "execute_trade", "params": {"amount": 75}},
                )
                assert r_kms.status_code == 503
                assert "Retry-After" not in r_kms.headers
                b_kms = r_kms.json()
                assert b_kms["error"] == "governance_dependency_unavailable"
                assert b_kms["dependency"] == "kms"
                assert b_kms["failure_code"] == "KMS_SIGNING_UNAVAILABLE"
                assert "proof_hash" not in b_kms
                gov.validate_action.assert_not_awaited()

        kms_entries = _read_stream_entries(kms_stream_server)
        assert len(kms_entries) == 3
        for _, fields in kms_entries:
            assert fields["event_type"] == "GOVERNANCE_INFRASTRUCTURE_BLOCK"
            payload = json.loads(fields["payload_json"])
            assert payload["dependency"] == "kms"
            assert payload["failure_code"] == "KMS_SIGNING_UNAVAILABLE"
            assert "kms_signature" not in payload
            assert "proof_hash" not in payload
        assert check_stream([f for _, f in kms_entries], expected_refusal_count=0) == []

        refusal_samples = [
            s.value
            for m in reg.collect()
            if m.name == "cage_governance_refusals"
            for s in m.samples
            if s.name == "cage_governance_refusals_total"
        ]
        assert sum(refusal_samples) == 0.0

        infra_samples = {
            (s.labels["dependency"], s.labels["code"]): s.value
            for m in reg.collect()
            if m.name == "cage_governance_infrastructure_blocks"
            for s in m.samples
            if s.name == "cage_governance_infrastructure_blocks_total"
        }
        assert infra_samples == {
            ("redis", "REDIS_QUARANTINE_UNAVAILABLE"): 4.0,
            ("kms", "KMS_SIGNING_UNAVAILABLE"): 3.0,
        }
    finally:
        mts.mcp._tool_manager._tools.pop("sample_infra_block_tool", None)
        mts.app.state.redis = prev_mts_redis
