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

"""Unit & ASGI integration tests for gateway-mediated checkpoint storage.

Covers ``POAM-2026-226`` (silent ``MemorySaver`` fallback / durability across pod
restarts) and the checkpoint-retention item of ``POAM-2026-225`` (resumption-window
TTL without refresh-on-read, hashed Redis keys, and body-only ``thread_id``
transport).
"""

from __future__ import annotations

from typing import Annotated, TypedDict

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from src.gateway.governance import defer_queue
from src.gateway.governance.checkpoint_store import (
    ChannelBlobEntry,
    ChannelVersionRef,
    CheckpointPayloadTooLargeError,
    CheckpointStoreUnavailableError,
    CheckpointValidationError,
    GatewayCheckpointStore,
    PendingWriteEntry,
    TypedBlob,
    compute_checkpoint_ttl_seconds,
    resolve_max_ttl_seconds,
)
from src.gateway.server.checkpoint_api import router as checkpoint_router
from src.gateway.server.workload_identity import (
    CLIENT_IDENTITY_HEADER,
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)
from src.governed_financial_advisor.graph.checkpointer import (
    CheckpointDurabilityError,
    GatewayCheckpointSaver,
    checkpointer_type_of,
    get_checkpointer,
)
from src.governed_financial_advisor.graph.nodes.approval_node import (
    resolve_hitl_approval_ttl_seconds,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ADVISOR_ID = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
_OTHER_AGENT_ID = (
    "other-agent-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
_CANARY_ID = "cage-gateway-canary-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
_POD_IP = "10.24.0.19"


def _build_gated_checkpoint_app(
    store: GatewayCheckpointStore | None,
    *,
    recorded_paths: list[str] | None = None,
) -> FastAPI:
    sub_app = FastAPI()
    if store is not None:
        sub_app.state.checkpoint_store = store
    sub_app.include_router(checkpoint_router)

    root = FastAPI()
    if store is not None:
        root.state.checkpoint_store = store

    if recorded_paths is not None:

        @root.middleware("http")
        async def _record(request, call_next):  # type: ignore[no-untyped-def]
            raw_qs = request.url.query
            recorded_paths.append(
                f"{request.url.path}?{raw_qs}" if raw_qs else request.url.path
            )
            return await call_next(request)

    policy = IdentityPolicy(
        trusted=frozenset({_ADVISOR_ID, _OTHER_AGENT_ID}),
        canary=frozenset({_CANARY_ID}),
    )
    root.add_middleware(WorkloadIdentityMiddleware, policy=policy)
    root.mount("/governance", sub_app)
    return root


class _PodLocalASGITransport(httpx.ASGITransport):
    """ASGI transport presenting matching non-loopback peer/server pod IP (Linkerd inbound proxy)."""

    def __init__(self, app: FastAPI, *, peer_ip: str = _POD_IP) -> None:
        super().__init__(app=app, client=(peer_ip, 51234))
        self._peer_ip = peer_ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Ensure ASGI scope["server"] matches scope["client"][0] like Linkerd inbound proxy.
        orig_app = self.app

        async def _wrapped_app(scope, receive, send):  # type: ignore[no-untyped-def]
            if scope.get("type") == "http":
                scope = dict(scope)
                scope["server"] = (self._peer_ip, 8080)
            await orig_app(scope, receive, send)

        temp = httpx.ASGITransport(
            app=_wrapped_app,
            client=(self._peer_ip, 51234),
            raise_app_exceptions=self.raise_app_exceptions,
        )
        return await temp.handle_async_request(request)


# ---------------------------------------------------------------------------
# 1. Resumption-window TTL derivation (POAM-2026-225)
# ---------------------------------------------------------------------------


def test_ttl_derives_from_live_defer_and_hitl_constants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default TTL equals max(_DEFAULT_TTL=14400, _DEFAULT_HOLD_TTL=300, hitl=300) + 60s = 14460s."""
    monkeypatch.delenv("HITL_APPROVAL_TTL_SECONDS", raising=False)
    monkeypatch.delenv("CAGE_CHECKPOINT_MAX_TTL_SECONDS", raising=False)

    hitl_s = resolve_hitl_approval_ttl_seconds()
    assert hitl_s == 300
    assert compute_checkpoint_ttl_seconds(hitl_s) == 14_460  # 241 minutes (4h 1m)

    # Raising HITL_APPROVAL_TTL_SECONDS above 4h shifts the derived TTL dynamically
    # and rounds up to whole minutes.
    monkeypatch.setenv("HITL_APPROVAL_TTL_SECONDS", "18001")
    assert compute_checkpoint_ttl_seconds(resolve_hitl_approval_ttl_seconds()) == 18_120

    # Raising defer_queue._DEFAULT_TTL directly shifts compute_checkpoint_ttl_seconds
    # because the store reads the live constant rather than a copied literal.
    monkeypatch.setattr(defer_queue, "_DEFAULT_TTL", 21_600)
    assert compute_checkpoint_ttl_seconds(300) == 21_660


def test_ttl_rejects_excessive_or_invalid_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TTL ceiling rejects windows above CAGE_CHECKPOINT_MAX_TTL_SECONDS or 90-day PIA ceiling."""
    with pytest.raises(CheckpointValidationError):
        compute_checkpoint_ttl_seconds(-1)
    with pytest.raises(CheckpointValidationError):
        compute_checkpoint_ttl_seconds(True)  # type: ignore[arg-type]
    with pytest.raises(CheckpointValidationError):
        compute_checkpoint_ttl_seconds(90_000, max_ttl_seconds=86_400)

    monkeypatch.setenv("CAGE_CHECKPOINT_MAX_TTL_SECONDS", str(91 * 86_400))
    with pytest.raises(CheckpointValidationError, match="90-day privacy ceiling"):
        resolve_max_ttl_seconds()


# ---------------------------------------------------------------------------
# 2. GatewayCheckpointStore key hashing, caller isolation & non-refresh TTL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_hashes_keys_and_never_refreshes_ttl_on_read() -> None:
    """Reads (get/list) must never refresh TTL; writes refresh all keys of the thread."""
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(redis)
    sensitive_thread_id = "advisor_session_alice.investor@example.com"

    applied_ttl = await store.put_checkpoint(
        caller_identity=_ADVISOR_ID,
        thread_id=sensitive_thread_id,
        checkpoint_ns="",
        checkpoint_id="0001",
        parent_checkpoint_id=None,
        checkpoint=TypedBlob(type_tag="json", data_b64="eyJ2IjoxfQ=="),
        metadata=TypedBlob(type_tag="json", data_b64="eyJzdGVwIjowfQ=="),
        channel_versions=[
            ChannelVersionRef(channel="messages", version_type="str", version="001")
        ],
        new_blobs=[
            ChannelBlobEntry(
                ref=ChannelVersionRef(
                    channel="messages", version_type="str", version="001"
                ),
                blob=TypedBlob(type_tag="json", data_b64="WyJoZWxsbyJd"),
            )
        ],
    )
    assert applied_ttl == 14_460

    all_keys = await redis.keys("*")
    assert len(all_keys) >= 4
    for key in all_keys:
        assert key.startswith("cage:ckpt:v1:")
        # User identifier must never appear in plaintext Redis key names.
        assert "alice" not in key
        assert "advisor_session_" not in key
        ttl = await redis.ttl(key)
        assert 14_400 < ttl <= 14_460

    # Simulate elapsed idle time by setting all keys down to 90s remaining.
    for key in all_keys:
        await redis.expire(key, 90)

    # Reading via get_checkpoint and list_checkpoints must NOT extend TTL.
    loaded = await store.get_checkpoint(
        caller_identity=_ADVISOR_ID,
        thread_id=sensitive_thread_id,
    )
    assert loaded is not None
    assert loaded.checkpoint_id == "0001"
    listed = await store.list_checkpoints(caller_identity=_ADVISOR_ID)
    assert len(listed) == 1

    for key in all_keys:
        ttl_after_read = await redis.ttl(key)
        assert 0 < ttl_after_read <= 90, f"Read unexpectedly refreshed TTL on {key}"

    # Writing a new checkpoint (e.g. resume) refreshes all thread keys back to 14,460s.
    await store.put_checkpoint(
        caller_identity=_ADVISOR_ID,
        thread_id=sensitive_thread_id,
        checkpoint_ns="",
        checkpoint_id="0002",
        parent_checkpoint_id="0001",
        checkpoint=TypedBlob(type_tag="json", data_b64="eyJ2IjoxfQ=="),
        metadata=TypedBlob(type_tag="json", data_b64="eyJzdGVwIjoxfQ=="),
        channel_versions=[
            ChannelVersionRef(channel="messages", version_type="str", version="001")
        ],
        new_blobs=[],
    )
    for key in all_keys:
        ttl_after_write = await redis.ttl(key)
        assert ttl_after_write > 14_400


@pytest.mark.asyncio
async def test_store_isolates_caller_identities_and_enforces_write_semantics() -> None:
    """Different mesh identities cannot read, list, or delete each other's threads."""
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(redis, max_payload_bytes=512)

    await store.put_checkpoint(
        caller_identity=_ADVISOR_ID,
        thread_id="shared-thread-name",
        checkpoint_ns="",
        checkpoint_id="cp-1",
        parent_checkpoint_id=None,
        checkpoint=TypedBlob(type_tag="json", data_b64="eyJ2IjoxfQ=="),
        metadata=TypedBlob(type_tag="json", data_b64="e30="),
        channel_versions=[],
        new_blobs=[],
    )
    # Regular write idx >= 0 is write-once (HSETNX); negative idx overwrites.
    await store.put_writes(
        caller_identity=_ADVISOR_ID,
        thread_id="shared-thread-name",
        checkpoint_ns="",
        checkpoint_id="cp-1",
        writes=[
            PendingWriteEntry(
                task_id="t1",
                idx=0,
                channel="ch",
                blob=TypedBlob(type_tag="json", data_b64="ImZpcnN0Ig=="),
            ),
            PendingWriteEntry(
                task_id="t1",
                idx=-3,
                channel="__interrupt__",
                blob=TypedBlob(type_tag="json", data_b64="ImludDEi"),
            ),
        ],
    )
    await store.put_writes(
        caller_identity=_ADVISOR_ID,
        thread_id="shared-thread-name",
        checkpoint_ns="",
        checkpoint_id="cp-1",
        writes=[
            PendingWriteEntry(
                task_id="t1",
                idx=0,
                channel="ch",
                blob=TypedBlob(type_tag="json", data_b64="InNlY29uZCI="),
            ),
            PendingWriteEntry(
                task_id="t1",
                idx=-3,
                channel="__interrupt__",
                blob=TypedBlob(type_tag="json", data_b64="ImludDIi"),
            ),
        ],
    )

    # Other workload sees nothing and cannot delete Advisor's thread.
    assert (
        await store.get_checkpoint(
            caller_identity=_OTHER_AGENT_ID, thread_id="shared-thread-name"
        )
        is None
    )
    assert await store.list_checkpoints(caller_identity=_OTHER_AGENT_ID) == []
    await store.delete_thread(
        caller_identity=_OTHER_AGENT_ID, thread_id="shared-thread-name"
    )

    owner_rec = await store.get_checkpoint(
        caller_identity=_ADVISOR_ID, thread_id="shared-thread-name"
    )
    assert owner_rec is not None
    writes_by_idx = {w.idx: w.blob.data_b64 for w in owner_rec.pending_writes}
    assert writes_by_idx[0] == "ImZpcnN0Ig=="  # first write preserved
    assert writes_by_idx[-3] == "ImludDIi"  # negative index overwritten

    # Oversized payload fails closed with CheckpointPayloadTooLargeError.
    huge_b64 = "QUFB" * 300
    with pytest.raises(CheckpointPayloadTooLargeError):
        await store.put_checkpoint(
            caller_identity=_ADVISOR_ID,
            thread_id="shared-thread-name",
            checkpoint_ns="",
            checkpoint_id="cp-2",
            parent_checkpoint_id="cp-1",
            checkpoint=TypedBlob(type_tag="json", data_b64=huge_b64),
            metadata=TypedBlob(type_tag="json", data_b64="e30="),
            channel_versions=[],
            new_blobs=[],
        )

    # Disconnected store fails closed with CheckpointStoreUnavailableError (never memory).
    disconnected = GatewayCheckpointStore(None)
    with pytest.raises(CheckpointStoreUnavailableError):
        await disconnected.get_checkpoint(
            caller_identity=_ADVISOR_ID, thread_id="shared-thread-name"
        )


# ---------------------------------------------------------------------------
# 3. Full LangGraph interrupt() + pod restart + Command(resume=...) over ASGI
# ---------------------------------------------------------------------------


class _ApprovalGraphState(TypedDict, total=False):
    user_id: str
    amount: int
    approved: bool
    summary: str
    steps: Annotated[list[str], lambda a, b: list(a or []) + list(b or [])]


def _compile_interruptible_graph(saver: GatewayCheckpointSaver):  # type: ignore[no-untyped-def]
    def plan_step(state: _ApprovalGraphState) -> dict[str, object]:
        return {"steps": ["planned"]}

    def hitl_step(state: _ApprovalGraphState) -> Command:
        decision = interrupt({"amount": state["amount"], "reason": "manual_review"})
        is_ok = bool(decision.get("approved"))
        return Command(
            update={"approved": is_ok, "steps": ["approved" if is_ok else "rejected"]},
            goto="finish_step",
        )

    def finish_step(state: _ApprovalGraphState) -> dict[str, object]:
        verdict = "EXECUTED" if state.get("approved") else "ABORTED"
        return {"summary": f"{verdict}:{state['amount']}", "steps": ["finished"]}

    builder = StateGraph(_ApprovalGraphState)
    builder.add_node("plan_step", plan_step)
    builder.add_node("hitl_step", hitl_step)
    builder.add_node("finish_step", finish_step)
    builder.add_edge(START, "plan_step")
    builder.add_edge("plan_step", "hitl_step")
    builder.add_edge("finish_step", END)
    return builder.compile(checkpointer=saver)


@pytest.mark.asyncio
async def test_langgraph_interrupt_survives_pod_restart_via_gateway_and_hides_thread_from_url() -> (
    None
):
    """POAM-2026-226 / POAM-2026-225: paused HITL thread survives pod replacement via gateway."""
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(redis)
    recorded_paths: list[str] = []
    gateway_app = _build_gated_checkpoint_app(store, recorded_paths=recorded_paths)
    transport = _PodLocalASGITransport(gateway_app)

    thread_id = "advisor_session_bob.smith@example.org"
    run_config = {"configurable": {"thread_id": thread_id}}

    # Pod 1: start graph, verify ready, invoke until dynamic interrupt() pauses execution.
    saver_pod_1 = GatewayCheckpointSaver(
        "http://gateway.governance-stack.svc.cluster.local:8080",
        transport=transport,
        headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
    )
    ready_info = await saver_pod_1.verify_ready()
    assert ready_info["status"] == "ok"
    assert saver_pod_1.ttl_seconds == 14_460

    graph_pod_1 = _compile_interruptible_graph(saver_pod_1)
    await graph_pod_1.ainvoke(
        {"user_id": "bob.smith@example.org", "amount": 7500},
        run_config,
    )
    snap_1 = await graph_pod_1.aget_state(run_config)
    assert snap_1.next == ("hitl_step",)
    await saver_pod_1.aclose()
    del graph_pod_1
    del saver_pod_1

    # Pod 2 (fresh process/instance after pod eviction): list pending threads & resume!
    saver_pod_2 = GatewayCheckpointSaver(
        "http://gateway.governance-stack.svc.cluster.local:8080",
        transport=transport,
        headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
    )
    graph_pod_2 = _compile_interruptible_graph(saver_pod_2)

    listed_threads = {
        tup.config["configurable"]["thread_id"]
        async for tup in saver_pod_2.alist(None, limit=50)
    }
    assert thread_id in listed_threads

    resumed = await graph_pod_2.ainvoke(
        Command(resume={"approved": True}),
        run_config,
    )
    assert resumed["summary"] == "EXECUTED:7500"
    assert resumed["steps"] == ["planned", "approved", "finished"]

    # Delete thread removes all checkpoints cleanly.
    await saver_pod_2.adelete_thread(thread_id)
    assert await saver_pod_2.aget_tuple(run_config) is None
    await saver_pod_2.aclose()

    # Privacy invariant: user-identifying thread_id never appeared in any HTTP URL/query.
    assert len(recorded_paths) >= 6
    for url_path in recorded_paths:
        assert "bob.smith" not in url_path
        assert "advisor_session_" not in url_path


@pytest.mark.asyncio
async def test_gateway_checkpoint_routes_refuse_unauthenticated_loopback_and_canary() -> (
    None
):
    """POAM-2026-080 / POAM-2026-226: /governance/checkpoints/* requires trusted pod-local mTLS."""
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(redis)
    gateway_app = _build_gated_checkpoint_app(store)

    # 1. Missing l5d-client-id -> refused before handler
    async with httpx.AsyncClient(
        transport=_PodLocalASGITransport(gateway_app),
        base_url="http://gateway:8080",
    ) as unauth_client:
        resp = await unauth_client.get("/governance/checkpoints/health")
        assert resp.status_code in (401, 403)

    # 2. Loopback peer (port-forward / local process) -> refused even with trusted header
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway_app, client=("127.0.0.1", 55000)),
        base_url="http://gateway:8080",
    ) as loopback_client:
        resp = await loopback_client.get(
            "/governance/checkpoints/health",
            headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
        )
        assert resp.status_code in (401, 403)

    # 3. Synthetic canary identity -> refused on /governance/checkpoints/*
    async with httpx.AsyncClient(
        transport=_PodLocalASGITransport(gateway_app),
        base_url="http://gateway:8080",
    ) as canary_client:
        resp = await canary_client.get(
            "/governance/checkpoints/health",
            headers={CLIENT_IDENTITY_HEADER: _CANARY_ID},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. Fail-closed enforcing-posture startup & /health reporting (POAM-2026-226)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "enforcing_env",
    ["prod", "production", "staging", "local", "unrecognized-posture"],
)
def test_enforcing_postures_refuse_memory_checkpointer_and_missing_gateway_url(
    enforcing_env: str,
) -> None:
    """POAM-2026-226: Every enforcing posture refuses MemorySaver and missing GATEWAY_URL."""
    with pytest.raises(
        CheckpointDurabilityError, match="refused in enforcing postures"
    ):
        get_checkpointer(
            env={
                "CAGE_ENV": enforcing_env,
                "CAGE_CHECKPOINT_BACKEND": "memory",
                "GATEWAY_URL": "http://gateway:8080",
            }
        )

    with pytest.raises(CheckpointDurabilityError, match="GATEWAY_URL is required"):
        get_checkpointer(env={"CAGE_ENV": enforcing_env})

    saver = get_checkpointer(
        env={"CAGE_ENV": enforcing_env, "GATEWAY_URL": "http://gateway:8080"}
    )
    assert isinstance(saver, GatewayCheckpointSaver)
    assert checkpointer_type_of(saver) == "gateway"


def test_permissive_posture_allows_memory_only_when_gateway_unset_or_explicit() -> None:
    """Permissive postures use MemorySaver when GATEWAY_URL is unset, and Gateway when set."""
    mem = get_checkpointer(env={"CAGE_ENV": "test"})
    assert isinstance(mem, MemorySaver)
    assert checkpointer_type_of(mem) == "memory"

    gw = get_checkpointer(
        env={"CAGE_ENV": "test", "GATEWAY_URL": "http://gateway:8080"}
    )
    assert isinstance(gw, GatewayCheckpointSaver)

    with pytest.raises(CheckpointDurabilityError, match="Unsupported"):
        get_checkpointer(
            env={"CAGE_ENV": "test", "CAGE_CHECKPOINT_BACKEND": "redis-legacy"}
        )


@pytest.mark.asyncio
async def test_advisor_health_endpoint_reports_checkpointer_and_fails_closed_in_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POAM-2026-226: /health returns 503 on non-durable or unreachable checkpointer."""
    from types import SimpleNamespace

    from src.governed_financial_advisor.server import app as advisor_app

    prev_graph = getattr(advisor_app.state, "graph", None)
    try:
        # 1. Enforcing posture with MemorySaver -> HTTP 503 non_durable_checkpointer
        monkeypatch.setenv("CAGE_ENV", "staging")
        advisor_app.state.graph = SimpleNamespace(checkpointer=MemorySaver())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=advisor_app),
            base_url="http://advisor.local",
        ) as client:
            resp_mem = await client.get("/health")
            assert resp_mem.status_code == 503
            body_mem = resp_mem.json()
            assert body_mem["reason"] == "non_durable_checkpointer"
            assert body_mem["checkpointer"] == "memory"
            assert body_mem["durable"] is False

        # 2. Enforcing posture with healthy GatewayCheckpointSaver -> HTTP 200 durable=True
        redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        store = GatewayCheckpointStore(redis)
        gw_app = _build_gated_checkpoint_app(store)
        healthy_saver = GatewayCheckpointSaver(
            "http://gateway:8080",
            transport=_PodLocalASGITransport(gw_app),
            headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
        )
        advisor_app.state.graph = SimpleNamespace(checkpointer=healthy_saver)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=advisor_app),
            base_url="http://advisor.local",
        ) as client:
            resp_ok = await client.get("/health")
            assert resp_ok.status_code == 200
            body_ok = resp_ok.json()
            assert body_ok["status"] == "ok"
            assert body_ok["checkpointer"] == "gateway"
            assert body_ok["durable"] is True
            assert body_ok["checkpoint_ttl_seconds"] == 14_460
        await healthy_saver.aclose()

        # 3. Enforcing posture when gateway checkpoint store goes down -> HTTP 503
        down_gw_app = _build_gated_checkpoint_app(GatewayCheckpointStore(None))
        down_saver = GatewayCheckpointSaver(
            "http://gateway:8080",
            transport=_PodLocalASGITransport(down_gw_app),
            headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
        )
        advisor_app.state.graph = SimpleNamespace(checkpointer=down_saver)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=advisor_app),
            base_url="http://advisor.local",
        ) as client:
            resp_down = await client.get("/health")
            assert resp_down.status_code == 503
            assert resp_down.json()["reason"] == "gateway_checkpointer_unreachable"
        await down_saver.aclose()
    finally:
        advisor_app.state.graph = prev_graph


@pytest.mark.asyncio
async def test_alist_supports_metadata_filter_and_before_cursor() -> None:
    """alist() honors metadata filter and before cursor in descending checkpoint_id order."""
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(redis)
    gw_app = _build_gated_checkpoint_app(store)
    saver = GatewayCheckpointSaver(
        "http://gateway:8080",
        transport=_PodLocalASGITransport(gw_app),
        headers={CLIENT_IDENTITY_HEADER: _ADVISOR_ID},
    )
    graph = _compile_interruptible_graph(saver)
    cfg = {"configurable": {"thread_id": "filter-thread"}}
    await graph.ainvoke({"user_id": "u1", "amount": 100}, cfg)

    all_items = [t async for t in saver.alist(cfg)]
    assert len(all_items) >= 2
    newest_id = all_items[0].config["configurable"]["checkpoint_id"]
    older = [
        t
        async for t in saver.alist(
            cfg, before={"configurable": {"checkpoint_id": newest_id}}
        )
    ]
    assert len(older) == len(all_items) - 1
    assert all(t.config["configurable"]["checkpoint_id"] < newest_id for t in older)

    loop_only = [t async for t in saver.alist(cfg, filter={"source": "loop"})]
    assert len(loop_only) >= 1
    assert all(t.metadata.get("source") == "loop" for t in loop_only)
    await saver.aclose()


def test_governed_advisor_terraform_configures_gateway_checkpointer_and_health_probes() -> (
    None
):
    """POAM-2026-226: governed_advisor Deployment sets CAGE_CHECKPOINT_BACKEND=gateway and /health readiness_probe."""
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    tf_text = (repo / "infra/modules/governed_advisor/main.tf").read_text(
        encoding="utf-8"
    )
    assert 'name  = "CAGE_CHECKPOINT_BACKEND"' in tf_text
    assert 'value = "gateway"' in tf_text
    assert "readiness_probe" in tf_text
    assert 'path = "/health"' in tf_text
    assert "liveness_probe" in tf_text
    assert "REDIS_HOST" not in tf_text
    assert "REDIS_URL" not in tf_text
