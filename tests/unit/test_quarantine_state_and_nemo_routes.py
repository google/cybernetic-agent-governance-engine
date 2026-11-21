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

"""Regression tests for consolidated SC-7 workload quarantine across ``/governance/state-commitments``, ``/v1/nemo/*``, and ``/governance/checkpoints/*``."""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from src.gateway.governance.checkpoint_store import GatewayCheckpointStore
from src.gateway.governance.evidence import stream as es_mod
from src.gateway.governance.evidence.state_commitment import StateCommitmentService
from src.gateway.governance.kms_signer import reset_governance_signer
from src.gateway.governance.quarantine_actuator import (
    QuarantineDirective,
    QuarantineTriggerReason,
    bind_quarantine_redis,
    clear_local_quarantine_state,
    dispatch_quarantine,
    probe_workload_quarantine,
)
from src.gateway.governance.seams.state_commitment import StateCommitmentLinkage
from src.gateway.server.checkpoint_api import router as checkpoint_router
from src.gateway.server.state_commitment_api import router as state_commitment_router
from src.gateway.server.workload_identity import (
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)
from tests.integrations.provider_02.state_commitment_support import (
    RecordingEvidenceSink,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

PROPOSER_SVID = "advisor.cage.serviceaccount.identity.linkerd.cluster.local"
APPROVER_SVID = "bridge.cage.serviceaccount.identity.linkerd.cluster.local"


@pytest.fixture(autouse=True)
def _isolated_quarantine_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    monkeypatch.setenv("CAGE_KMS_PROVIDER", "ed25519")
    monkeypatch.setenv("CAGE_ED25519_PRIVATE_KEY_PEM", priv_pem)
    monkeypatch.setenv("CAGE_ED25519_KEY_ID", "test-quarantine-guard-kid")
    reset_governance_signer()

    prev_sink = es_mod._evidence_sink
    audit_sink = MagicMock(name="quarantine_audit_sink")
    audit_sink._running = True
    audit_sink.is_running = True
    audit_sink.events = []

    async def _record_event(event: dict[str, Any]) -> str:
        audit_sink.events.append(event)
        return f"{len(audit_sink.events)}-0"

    audit_sink.ingest_sync = AsyncMock(side_effect=_record_event)
    audit_sink.ingest = AsyncMock(side_effect=_record_event)
    es_mod._evidence_sink = audit_sink

    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    yield audit_sink
    es_mod._evidence_sink = prev_sink
    reset_governance_signer()
    clear_local_quarantine_state()
    bind_quarantine_redis(None)


def _directive(
    *,
    agent_svid: str = PROPOSER_SVID,
    thread_id: str = "t-quarantined",
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id,
        agent_svid=agent_svid,
        sandbox_id="sbx-q1",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BREACH",),
        issued_at=1700000000,
        correlation_id="corr-q1",
        refusal_proof_hash=hashlib.sha256(b"refusal-q1").hexdigest(),
        nonce="nonce-q1",
        ttl_seconds=600,
    )


def _state_commitment_body(thread_id: str = "t-clean") -> dict[str, Any]:
    return {
        "snapshot": {"loop_count": 1, "note": "step"},
        "linkage": StateCommitmentLinkage(
            namespace="provider_02",
            bundle_id="b-1",
            step_id="s-1",
            thread_id=thread_id,
            label="evaluator",
        ).to_dict(),
    }


def _checkpoint_put_body(thread_id: str = "t-clean") -> dict[str, Any]:
    empty_b64 = base64.b64encode(b"{}").decode("ascii")
    return {
        "thread_id": thread_id,
        "checkpoint_ns": "",
        "checkpoint_id": "cp-001",
        "checkpoint": {"type_tag": "json", "data_b64": empty_b64},
        "metadata": {"type_tag": "json", "data_b64": empty_b64},
        "channel_versions": [],
        "new_blobs": [],
    }


def _checkpoint_writes_body(thread_id: str = "t-clean") -> dict[str, Any]:
    empty_b64 = base64.b64encode(b"{}").decode("ascii")
    return {
        "thread_id": thread_id,
        "checkpoint_ns": "",
        "checkpoint_id": "cp-001",
        "writes": [
            {
                "task_id": "task-1",
                "idx": 0,
                "channel": "messages",
                "blob": {"type_tag": "json", "data_b64": empty_b64},
            }
        ],
    }


def _build_state_commitment_app(
    redis_client: Any, sink: RecordingEvidenceSink
) -> FastAPI:
    governance = FastAPI()
    governance.include_router(state_commitment_router)
    governance.state.state_commitments = StateCommitmentService(sink)
    governance.state.redis = redis_client

    root = FastAPI()
    root.mount("/governance", governance)
    root.add_middleware(
        WorkloadIdentityMiddleware,
        policy=IdentityPolicy(trusted=frozenset({PROPOSER_SVID, APPROVER_SVID})),
    )
    return root


def _build_nemo_app(redis_client: Any) -> FastAPI:
    import src.gateway.server.hybrid_server as gw_srv

    replica = FastAPI()
    replica.add_middleware(
        WorkloadIdentityMiddleware,
        policy=IdentityPolicy(trusted=frozenset({PROPOSER_SVID, APPROVER_SVID})),
    )
    for route in gw_srv.root_app.router.routes:
        if getattr(route, "path", "").startswith("/v1/nemo/"):
            replica.router.routes.append(route)
    replica.state.redis = redis_client
    replica.state.nemo_rails = None
    return replica


def _build_checkpoint_app(
    quarantine_redis: Any,
    store: GatewayCheckpointStore | None,
    *,
    attach_redis_attr: bool = True,
) -> FastAPI:
    governance = FastAPI()
    governance.include_router(checkpoint_router)
    if store is not None:
        governance.state.checkpoint_store = store
    if attach_redis_attr:
        governance.state.redis = quarantine_redis

    root = FastAPI()
    root.mount("/governance", governance)
    root.add_middleware(
        WorkloadIdentityMiddleware,
        policy=IdentityPolicy(trusted=frozenset({PROPOSER_SVID, APPROVER_SVID})),
    )
    return root


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.state_commitment_api:commit_state_endpoint#return q_resp",
    "src.gateway.server.quarantine_guard:refuse_if_quarantined#return JSONResponse",
    "src.gateway.server.quarantine_guard:check_and_refuse_quarantined_workload#if infra_failure is not None:",
    "src.gateway.server.quarantine_guard:_emit_quarantine_infrastructure_block#governance_dependency_unavailable",
)
async def test_state_commitments_blocks_quarantined_svid_and_thread_with_403_and_redis_outage_with_503(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_state: Any,
) -> None:
    """POST /governance/state-commitments returns signed 403 receipt on quarantine and 503 on Redis outage."""
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    commitment_sink = RecordingEvidenceSink()
    app = _build_state_commitment_app(redis_client, commitment_sink)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.112.0.43", 50000)),
        base_url="http://10.112.0.43:8080",
    ) as client:
        # 1. Clean caller succeeds (200)
        ok_resp = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-clean"),
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert ok_resp.status_code == 200
        assert len(commitment_sink.payloads) == 1

        # 2. Quarantine PROPOSER_SVID & t-quarantined -> SVID refused with signed 403 receipt
        await dispatch_quarantine(_directive(), redis_client=redis_client)
        svid_blocked = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-other"),
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert svid_blocked.status_code == 403
        svid_body = svid_blocked.json()
        assert svid_body["error"] == "workload_quarantined"
        assert len(svid_body["proof_hash"]) == 64
        assert len(commitment_sink.payloads) == 1

        # 3. Unquarantined APPROVER_SVID submitting quarantined thread_id in linkage -> 403
        thread_blocked = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-quarantined"),
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert thread_blocked.status_code == 403
        thread_body = thread_blocked.json()
        assert thread_body["error"] == "workload_quarantined"
        assert thread_body["thread_id"] == "t-quarantined"
        assert len(thread_body["proof_hash"]) == 64
        assert len(commitment_sink.payloads) == 1

    refusal_receipts = [
        e
        for e in _isolated_quarantine_state.events
        if e.get("type") == "GOVERNANCE_REFUSAL_RECEIPT"
    ]
    assert len(refusal_receipts) == 2
    assert all(r["kms_signature"] for r in refusal_receipts)
    assert all(r["surface"] == "state_commitment_api" for r in refusal_receipts)

    # 4. Redis connectivity failure returns 503 governance_dependency_unavailable (NOT false 403)
    broken_redis = AsyncMock()
    broken_redis.exists = AsyncMock(
        side_effect=ConnectionError("redis connection lost")
    )
    assert (
        await probe_workload_quarantine(
            agent_svid=APPROVER_SVID, redis_client=broken_redis
        )
    ).unavailable_code == "REDIS_QUARANTINE_UNAVAILABLE"

    outage_app = _build_state_commitment_app(broken_redis, commitment_sink)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=outage_app, client=("10.112.0.43", 50000)),
        base_url="http://10.112.0.43:8080",
    ) as client:
        outage_resp = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-clean"),
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert outage_resp.status_code == 503
        outage_body = outage_resp.json()
        assert outage_body["error"] == "governance_dependency_unavailable"
        assert outage_body["dependency"] == "redis"
        assert outage_body["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"

    # 5. Missing Redis in enforcing posture also fails closed with 503
    monkeypatch.setenv("CAGE_ENV", "production")
    missing_redis_app = _build_state_commitment_app(None, commitment_sink)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=missing_redis_app, client=("10.112.0.43", 50000)
        ),
        base_url="http://10.112.0.43:8080",
    ) as client:
        missing_resp = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-clean"),
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert missing_resp.status_code == 503
        assert missing_resp.json()["error"] == "governance_dependency_unavailable"
        assert missing_resp.json()["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.hybrid_server:propose_nemo_refinement#return q_resp",
    "src.gateway.server.hybrid_server:apply_nemo_refinement#return q_resp",
    "src.gateway.server.hybrid_server:list_pending_nemo_proposals#return q_resp",
    "src.gateway.server.hybrid_server:approve_nemo_refinement#return q_resp",
    "src.gateway.server.quarantine_guard:check_and_refuse_quarantined_workload#if infra_failure is not None:",
    "src.gateway.server.quarantine_guard:_emit_quarantine_infrastructure_block#governance_dependency_unavailable",
)
async def test_all_four_nemo_routes_enforce_quarantine_403_and_redis_outage_503(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_state: Any,
) -> None:
    """All four /v1/nemo/* routes block quarantined SVIDs with signed 403 receipts and Redis failures with 503."""
    monkeypatch.setenv("CAGE_NEMO_APPROVER_IDENTITIES", APPROVER_SVID)
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app = _build_nemo_app(redis_client)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.112.0.43", 50000)),
        base_url="http://10.112.0.43:8080",
    ) as client:
        # Stage one proposal before quarantine so approve-refinement has a live proposal_id
        staged = await client.post(
            "/v1/nemo/propose-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert staged.status_code == 200
        proposal_id = staged.json()["proposal_id"]

        # Quarantine both SVIDs
        await dispatch_quarantine(
            _directive(agent_svid=PROPOSER_SVID, thread_id="t-q1"),
            redis_client=redis_client,
        )
        await dispatch_quarantine(
            _directive(agent_svid=APPROVER_SVID, thread_id="t-q2"),
            redis_client=redis_client,
        )

        r_propose = await client.post(
            "/v1/nemo/propose-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert r_propose.status_code == 403
        assert r_propose.json()["error"] == "workload_quarantined"
        assert len(r_propose.json()["proof_hash"]) == 64

        r_apply = await client.post(
            "/v1/nemo/apply-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert r_apply.status_code == 403
        assert r_apply.json()["error"] == "workload_quarantined"
        assert len(r_apply.json()["proof_hash"]) == 64

        r_pending = await client.get(
            "/v1/nemo/proposals/pending",
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert r_pending.status_code == 403
        assert r_pending.json()["error"] == "workload_quarantined"
        assert len(r_pending.json()["proof_hash"]) == 64

        r_approve = await client.post(
            f"/v1/nemo/approve-refinement/{proposal_id}",
            json={
                "approved": True,
                "reviewer": "sec@example.com",
                "rationale": "attempt while quarantined",
            },
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert r_approve.status_code == 403
        assert r_approve.json()["error"] == "workload_quarantined"
        assert len(r_approve.json()["proof_hash"]) == 64

    nemo_receipts = [
        e
        for e in _isolated_quarantine_state.events
        if e.get("type") == "GOVERNANCE_REFUSAL_RECEIPT"
        and e.get("surface") == "hybrid_server"
    ]
    assert len(nemo_receipts) == 4
    assert all(r["kms_signature"] for r in nemo_receipts)

    # Redis connectivity outage on /v1/nemo/* returns 503 governance_dependency_unavailable (not 403)
    broken_redis = AsyncMock()
    broken_redis.exists = AsyncMock(side_effect=TimeoutError("redis timeout"))
    outage_nemo_app = _build_nemo_app(broken_redis)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=outage_nemo_app, client=("10.112.0.43", 50000)
        ),
        base_url="http://10.112.0.43:8080",
    ) as client:
        outage_propose = await client.post(
            "/v1/nemo/propose-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert outage_propose.status_code == 503
        assert outage_propose.json()["error"] == "governance_dependency_unavailable"
        assert outage_propose.json()["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.checkpoint_api:checkpoint_health_endpoint#return q_resp",
    "src.gateway.server.checkpoint_api:put_checkpoint_endpoint#return q_resp",
    "src.gateway.server.checkpoint_api:put_writes_endpoint#return q_resp",
    "src.gateway.server.checkpoint_api:get_checkpoint_endpoint#return q_resp",
    "src.gateway.server.checkpoint_api:list_checkpoints_endpoint#return q_resp",
    "src.gateway.server.checkpoint_api:delete_thread_endpoint#return q_resp",
    "src.gateway.server.quarantine_guard:check_and_refuse_quarantined_workload#if infra_failure is not None:",
    "src.gateway.server.quarantine_guard:_emit_quarantine_infrastructure_block#governance_dependency_unavailable",
)
async def test_all_six_checkpoint_routes_enforce_quarantine_403_and_redis_outage_503(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_quarantine_state: Any,
) -> None:
    """All six /governance/checkpoints/* routes enforce SC-7 SVID/thread quarantine and fail closed 503 on Redis outage."""
    q_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cp_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = GatewayCheckpointStore(cp_redis)
    app = _build_checkpoint_app(q_redis, store)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.112.0.43", 50000)),
        base_url="http://10.112.0.43:8080",
    ) as client:
        # 1. Baseline: clean caller succeeds across all 6 endpoints
        assert (
            await client.get(
                "/governance/checkpoints/health",
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200
        assert (
            await client.put(
                "/governance/checkpoints/tuple",
                json=_checkpoint_put_body("t-clean"),
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200
        assert (
            await client.put(
                "/governance/checkpoints/writes",
                json=_checkpoint_writes_body("t-clean"),
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200
        assert (
            await client.post(
                "/governance/checkpoints/get",
                json={"thread_id": "t-clean"},
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200
        assert (
            await client.post(
                "/governance/checkpoints/list",
                json={"thread_id": "t-clean"},
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200
        assert (
            await client.post(
                "/governance/checkpoints/delete",
                json={"thread_id": "t-clean"},
                headers={"l5d-client-id": PROPOSER_SVID},
            )
        ).status_code == 200

        # 2. Quarantine PROPOSER_SVID and t-quarantined -> all 6 endpoints refuse SVID with 403
        await dispatch_quarantine(
            _directive(agent_svid=PROPOSER_SVID, thread_id="t-quarantined"),
            redis_client=q_redis,
        )
        for method, path, payload in (
            ("GET", "/governance/checkpoints/health", None),
            ("PUT", "/governance/checkpoints/tuple", _checkpoint_put_body("t-other")),
            (
                "PUT",
                "/governance/checkpoints/writes",
                _checkpoint_writes_body("t-other"),
            ),
            ("POST", "/governance/checkpoints/get", {"thread_id": "t-other"}),
            ("POST", "/governance/checkpoints/list", {"thread_id": "t-other"}),
            ("POST", "/governance/checkpoints/delete", {"thread_id": "t-other"}),
        ):
            r_svid = await client.request(
                method,
                path,
                json=payload,
                headers={"l5d-client-id": PROPOSER_SVID},
            )
            assert r_svid.status_code == 403, f"{method} {path}: {r_svid.text}"
            body_svid = r_svid.json()
            assert body_svid["error"] == "workload_quarantined"
            assert body_svid["agent_id"] == PROPOSER_SVID
            assert len(body_svid["proof_hash"]) == 64

        # 3. Unquarantined APPROVER_SVID passing quarantined body.thread_id -> refused with 403 across all 5 body routes
        for method, path, payload in (
            (
                "PUT",
                "/governance/checkpoints/tuple",
                _checkpoint_put_body("t-quarantined"),
            ),
            (
                "PUT",
                "/governance/checkpoints/writes",
                _checkpoint_writes_body("t-quarantined"),
            ),
            ("POST", "/governance/checkpoints/get", {"thread_id": "t-quarantined"}),
            ("POST", "/governance/checkpoints/list", {"thread_id": "t-quarantined"}),
            ("POST", "/governance/checkpoints/delete", {"thread_id": "t-quarantined"}),
        ):
            r_tid = await client.request(
                method,
                path,
                json=payload,
                headers={"l5d-client-id": APPROVER_SVID},
            )
            assert r_tid.status_code == 403, f"{method} {path}: {r_tid.text}"
            body_tid = r_tid.json()
            assert body_tid["error"] == "workload_quarantined"
            assert body_tid["thread_id"] == "t-quarantined"
            assert len(body_tid["proof_hash"]) == 64

    cp_receipts = [
        e
        for e in _isolated_quarantine_state.events
        if e.get("type") == "GOVERNANCE_REFUSAL_RECEIPT"
        and e.get("surface") == "checkpoint_api"
    ]
    assert len(cp_receipts) == 11
    assert all(r["kms_signature"] for r in cp_receipts)

    # 4. Quarantine Redis connectivity error -> 503 governance_dependency_unavailable
    broken_redis = AsyncMock()
    broken_redis.exists = AsyncMock(
        side_effect=ConnectionError("quarantine redis unreachable")
    )
    outage_app = _build_checkpoint_app(broken_redis, store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=outage_app, client=("10.112.0.43", 50000)),
        base_url="http://10.112.0.43:8080",
    ) as client:
        r_outage = await client.post(
            "/governance/checkpoints/get",
            json={"thread_id": "t-clean"},
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert r_outage.status_code == 503
        assert r_outage.json()["error"] == "governance_dependency_unavailable"
        assert r_outage.json()["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"

    # 5. Enforcing posture with missing app.state.redis fails closed 503 even when
    #    checkpoint_store (Redis DB 3) is healthy — never crosses logical DBs!
    monkeypatch.setenv("CAGE_ENV", "production")
    no_q_redis_app = _build_checkpoint_app(None, store, attach_redis_attr=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=no_q_redis_app, client=("10.112.0.43", 50000)
        ),
        base_url="http://10.112.0.43:8080",
    ) as client:
        r_missing = await client.get(
            "/governance/checkpoints/health",
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert r_missing.status_code == 503
        assert r_missing.json()["error"] == "governance_dependency_unavailable"
        assert r_missing.json()["failure_code"] == "REDIS_QUARANTINE_UNAVAILABLE"
