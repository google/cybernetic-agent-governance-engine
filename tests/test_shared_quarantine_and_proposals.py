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

"""Unit tests for shared Redis quarantine enforcement and NeMo proposal state (PR A5)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI

from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.quarantine_actuator import (
    InferenceProxySvidQuarantineActuator,
    QuarantineDirective,
    QuarantineTriggerReason,
    bind_quarantine_redis,
    clear_local_quarantine_state,
    dispatch_quarantine,
    is_workload_quarantined,
)
from src.gateway.governance.seams.actuation import ActuationOutcome

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _make_directive(
    *,
    thread_id: str = "thread-cross-1",
    agent_svid: str = "spiffe://cluster.local/ns/default/sa/compromised-agent",
    ttl_seconds: int = 600,
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id,
        agent_svid=agent_svid,
        sandbox_id="sbx-1",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BREACH",),
        issued_at=1700000000,
        correlation_id="corr-1",
        governance_decision_digest="digest-1",
        nonce="nonce-1",
        ttl_seconds=ttl_seconds,
    )


@pytest.fixture(autouse=True)
def _clean_quarantine_state():
    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    yield
    clear_local_quarantine_state()
    bind_quarantine_redis(None)


@pytest.mark.asyncio
async def test_quarantine_set_on_replica_a_enforced_on_replica_b():
    """A quarantine written via Replica A's Redis client is enforced on Replica B."""
    server = fakeredis.FakeServer()
    redis_a = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    redis_b = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    directive = _make_directive(
        thread_id="thread-cross-1",
        agent_svid="spiffe://cluster.local/ns/default/sa/compromised-agent",
        ttl_seconds=600,
    )

    receipt = await dispatch_quarantine(directive, redis_client=redis_a)
    assert receipt.quarantined is True
    assert receipt.outcome is ActuationOutcome.ACCEPTED

    # Replica B (with its own client connection and empty local process memory) sees the quarantine
    clear_local_quarantine_state()
    assert (
        await is_workload_quarantined(
            thread_id="thread-cross-1",
            agent_svid=None,
            redis_client=redis_b,
        )
        is True
    )
    assert (
        await is_workload_quarantined(
            thread_id=None,
            agent_svid="spiffe://cluster.local/ns/default/sa/compromised-agent",
            redis_client=redis_b,
        )
        is True
    )
    assert (
        await is_workload_quarantined(
            thread_id="clean-thread",
            agent_svid="spiffe://cluster.local/ns/default/sa/clean-agent",
            redis_client=redis_b,
        )
        is False
    )


@pytest.mark.asyncio
async def test_is_workload_quarantined_executes_single_exists_command():
    """is_workload_quarantined checks both thread and SVID keys in one EXISTS call."""
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=1)

    quarantined = await is_workload_quarantined(
        thread_id="t-100",
        agent_svid="spiffe://cluster.local/ns/default/sa/agent-1",
        redis_client=mock_redis,
    )
    assert quarantined is True
    mock_redis.exists.assert_awaited_once_with(
        "quarantine:thread:t-100",
        "quarantine:svid:spiffe://cluster.local/ns/default/sa/agent-1",
    )


@pytest.mark.asyncio
async def test_quarantine_fails_closed_when_redis_missing_or_errors_in_enforcing_posture(
    monkeypatch,
):
    """In enforcing postures, missing Redis or Redis errors fail closed."""
    monkeypatch.setattr(
        "src.gateway.governance.quarantine_actuator.resolve_posture",
        lambda: DeploymentPosture.PRODUCTION,
    )

    # 1. Missing Redis -> is_workload_quarantined returns True (fail-closed)
    assert (
        await is_workload_quarantined(
            thread_id="t-prod",
            agent_svid="spiffe://cluster.local/ns/default/sa/prod-agent",
            redis_client=None,
        )
        is True
    )

    # 2. Redis error on EXISTS -> returns True (fail-closed)
    broken_redis = AsyncMock()
    broken_redis.exists = AsyncMock(side_effect=RuntimeError("redis connection lost"))
    assert (
        await is_workload_quarantined(
            thread_id="t-prod",
            agent_svid=None,
            redis_client=broken_redis,
        )
        is True
    )

    # 3. Missing Redis on actuator -> quarantined=False, UNKNOWN
    actuator = InferenceProxySvidQuarantineActuator(redis_client=None)
    directive = _make_directive(thread_id="t-prod", agent_svid="")
    receipt = await actuator.quarantine_workload(directive)
    assert receipt.quarantined is False
    assert receipt.outcome is ActuationOutcome.UNKNOWN


@pytest.mark.asyncio
async def test_inference_proxy_rejects_quarantined_workload_via_app_state_redis(
    monkeypatch,
):
    """Inference proxy on Replica B rejects a thread quarantined on Replica A via app.state.redis."""
    trusted_id = (
        "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    )
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", trusted_id)
    import src.gateway.server.hybrid_server as gw_srv
    from src.gateway.server.workload_identity import (
        WorkloadIdentityMiddleware,
        load_identity_policy,
    )

    for mw in gw_srv.root_app.user_middleware:
        if mw.cls is WorkloadIdentityMiddleware:
            mw.kwargs["policy"] = load_identity_policy()
    gw_srv.root_app.middleware_stack = gw_srv.root_app.build_middleware_stack()

    server = fakeredis.FakeServer()
    redis_a = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    redis_b = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    directive = _make_directive(
        thread_id="quarantined-thread-42",
        agent_svid="",
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive, redis_client=redis_a)
    clear_local_quarantine_state()

    monkeypatch.setattr(gw_srv.inference_app.state, "redis", redis_b, raising=False)
    monkeypatch.setattr(
        gw_srv.inference_app.state,
        "nemo_rails",
        MagicMock(name="stub_rails"),
        raising=False,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gw_srv.root_app),
        base_url="http://test",
        headers={
            "l5d-client-id": trusted_id,
            "x-cage-thread-id": "quarantined-thread-42",
        },
    ) as client:
        resp = await client.post(
            "/inference/v1/chat/completions",
            json={
                "model": "gemini-2.5-flash",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert resp.status_code == 403
    assert resp.json()["error"] == "workload_quarantined"


@pytest.mark.asyncio
async def test_nemo_proposal_staged_on_replica_a_approved_on_replica_b_and_pubsub_reloads(
    monkeypatch,
):
    """A proposal staged on Replica A is visible and approvable on Replica B, and broadcasts reload."""
    proposer_id = (
        "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    )
    approver_id = "compliance-bridge.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", f"{proposer_id},{approver_id}")
    # Applying a refinement rebuilds the rails, which needs them switched on.
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)

    import src.gateway.server.hybrid_server as gw_srv
    from src.gateway.server.workload_identity import (
        WorkloadIdentityMiddleware,
        load_identity_policy,
    )

    def _build_replica_app(redis_client) -> FastAPI:
        replica = FastAPI()
        replica.add_middleware(
            WorkloadIdentityMiddleware,
            policy=load_identity_policy(),
        )
        for route in gw_srv.root_app.router.routes:
            if getattr(route, "path", "").startswith("/v1/nemo/"):
                replica.router.routes.append(route)
        replica.state.redis = redis_client
        replica.state.nemo_rails = MagicMock(name="initial_rails")
        return replica

    server = fakeredis.FakeServer()
    redis_a = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    redis_b = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    replica_a = _build_replica_app(redis_a)
    replica_b = _build_replica_app(redis_b)

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=replica_a), base_url="http://replica-a"
        ) as client_a,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=replica_b), base_url="http://replica-b"
        ) as client_b,
    ):
        # 1. Stage proposal on Replica A
        stage_resp = await client_a.post(
            "/v1/nemo/propose-refinement",
            json={
                "control_id": "AU-6",
                "verdict": "FAIL: drift detected",
                "proposed_colang": "define flow check_drift\n  bot refuse",
                "rationale": "mitigate drift",
                "source": "bridge",
            },
            headers={"l5d-client-id": proposer_id},
        )
        assert stage_resp.status_code == 200
        proposal_id = stage_resp.json()["proposal_id"]

        # 2. List pending proposals on Replica B
        list_resp = await client_b.get(
            "/v1/nemo/proposals/pending",
            headers={"l5d-client-id": approver_id},
        )
        assert list_resp.status_code == 200
        pending_ids = [p["proposal_id"] for p in list_resp.json()["pending"]]
        assert proposal_id in pending_ids

        # 3. Approve proposal on Replica B and verify Pub/Sub reload broadcast to Replica A
        reloaded_manager = MagicMock(name="reloaded_rails_manager")
        with (
            patch(
                "src.gateway.governance.langgraph_harness.nemo_node_factory.create_nemo_manager",
                return_value=reloaded_manager,
            ) as mock_create_mgr,
        ):
            sub_task = asyncio.create_task(
                gw_srv._subscribe_nemo_reload(redis_a, replica_a)
            )
            await asyncio.sleep(0.05)

            approve_resp = await client_b.post(
                f"/v1/nemo/approve-refinement/{proposal_id}",
                json={
                    "approved": True,
                    "reviewer": "sec-reviewer@example.com",
                    "rationale": "verified colang rule",
                },
                headers={"l5d-client-id": approver_id},
            )
            assert approve_resp.status_code == 200
            assert approve_resp.json()["status"] == "applied"

            # Allow Pub/Sub message to be processed by Replica A's subscriber task
            await asyncio.sleep(0.1)
            sub_task.cancel()
            try:
                await sub_task
            except asyncio.CancelledError:
                pass

            assert mock_create_mgr.call_count >= 1
            assert replica_b.state.nemo_rails is reloaded_manager
            assert replica_a.state.nemo_rails is reloaded_manager


@pytest.mark.asyncio
async def test_nemo_proposal_routes_fail_closed_with_503_when_redis_unavailable(
    monkeypatch,
):
    """When app.state.redis is None, staging, listing, and approving proposals fail closed with 503."""
    trusted_id = (
        "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    )
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", trusted_id)

    import src.gateway.server.hybrid_server as gw_srv
    from src.gateway.server.workload_identity import (
        WorkloadIdentityMiddleware,
        load_identity_policy,
    )

    replica = FastAPI()
    replica.add_middleware(
        WorkloadIdentityMiddleware,
        policy=load_identity_policy(),
    )
    for route in gw_srv.root_app.router.routes:
        if getattr(route, "path", "").startswith("/v1/nemo/"):
            replica.router.routes.append(route)
    replica.state.redis = None

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=replica),
        base_url="http://replica-no-redis",
        headers={"l5d-client-id": trusted_id},
    ) as client:
        stage_resp = await client.post(
            "/v1/nemo/propose-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
        )
        assert stage_resp.status_code == 503

        list_resp = await client.get("/v1/nemo/proposals/pending")
        assert list_resp.status_code == 503

        approve_resp = await client.post(
            "/v1/nemo/approve-refinement/00000000-0000-0000-0000-000000000001",
            json={
                "approved": True,
                "reviewer": "sec-reviewer@example.com",
                "rationale": "test",
            },
        )
        assert approve_resp.status_code == 503
