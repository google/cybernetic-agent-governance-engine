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

"""Regression tests for SC-7 workload quarantine on ``/governance/state-commitments`` and ``/v1/nemo/*``."""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import AsyncMock

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI

from src.gateway.governance.evidence.state_commitment import StateCommitmentService
from src.gateway.governance.quarantine_actuator import (
    QuarantineCheckStatus,
    QuarantineDirective,
    QuarantineTriggerReason,
    bind_quarantine_redis,
    check_workload_quarantine_status,
    clear_local_quarantine_state,
    dispatch_quarantine,
)
from src.gateway.governance.seams.state_commitment import StateCommitmentLinkage
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
def _isolated_quarantine_state():
    clear_local_quarantine_state()
    bind_quarantine_redis(None)
    yield
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


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.state_commitment_api:commit_state_endpoint#workload_quarantined",
    "src.gateway.server.state_commitment_api:commit_state_endpoint#quarantine_backend_unavailable",
    "src.gateway.governance.quarantine_actuator:probe_workload_quarantine#Redis EXISTS check failed",
    "src.gateway.governance.quarantine_actuator:probe_workload_quarantine#Shared Redis client unavailable in enforcing posture — failing closed",
)
async def test_state_commitments_blocks_quarantined_svid_and_thread_with_403_and_redis_outage_with_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /governance/state-commitments returns 403 on confirmed quarantine and 503 on Redis outage."""
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sink = RecordingEvidenceSink()
    app = _build_state_commitment_app(redis_client, sink)

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
        assert len(sink.payloads) == 1

        # 2. Quarantine PROPOSER_SVID & t-quarantined -> SVID refused with 403, zero new commitments
        await dispatch_quarantine(_directive(), redis_client=redis_client)
        svid_blocked = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-other"),
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert svid_blocked.status_code == 403
        assert svid_blocked.json()["error"] == "workload_quarantined"
        assert len(sink.payloads) == 1

        # 3. Unquarantined APPROVER_SVID submitting quarantined thread_id in linkage -> 403
        thread_blocked = await client.post(
            "/governance/state-commitments",
            json=_state_commitment_body("t-quarantined"),
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert thread_blocked.status_code == 403
        assert thread_blocked.json()["error"] == "workload_quarantined"
        assert len(sink.payloads) == 1

    # 4. Redis connectivity failure returns 503 quarantine_backend_unavailable (NOT false 403)
    broken_redis = AsyncMock()
    broken_redis.exists = AsyncMock(
        side_effect=ConnectionError("redis connection lost")
    )
    assert (
        await check_workload_quarantine_status(
            agent_svid=APPROVER_SVID, redis_client=broken_redis
        )
        is QuarantineCheckStatus.BACKEND_UNAVAILABLE
    )
    outage_app = _build_state_commitment_app(broken_redis, sink)
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
        assert outage_resp.json()["error"] == "quarantine_backend_unavailable"

    # 5. Missing Redis in enforcing posture also fails closed with 503
    monkeypatch.setenv("CAGE_ENV", "production")
    missing_redis_app = _build_state_commitment_app(None, sink)
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
        assert missing_resp.json()["error"] == "quarantine_backend_unavailable"


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.hybrid_server:_enforce_nemo_quarantine#workload_quarantined",
    "src.gateway.server.hybrid_server:_enforce_nemo_quarantine#quarantine_backend_unavailable",
    "src.gateway.server.hybrid_server:propose_nemo_refinement#_enforce_nemo_quarantine",
    "src.gateway.server.hybrid_server:apply_nemo_refinement#_enforce_nemo_quarantine",
    "src.gateway.server.hybrid_server:list_pending_nemo_proposals#_enforce_nemo_quarantine",
    "src.gateway.server.hybrid_server:approve_nemo_refinement#_enforce_nemo_quarantine",
)
async def test_all_four_nemo_routes_enforce_quarantine_403_and_redis_outage_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All four /v1/nemo/* routes block quarantined SVIDs with 403 and Redis failures with 503."""
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
        assert r_propose.json()["detail"]["error"] == "workload_quarantined"

        r_apply = await client.post(
            "/v1/nemo/apply-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL"},
            headers={"l5d-client-id": PROPOSER_SVID},
        )
        assert r_apply.status_code == 403
        assert r_apply.json()["detail"]["error"] == "workload_quarantined"

        r_pending = await client.get(
            "/v1/nemo/proposals/pending",
            headers={"l5d-client-id": APPROVER_SVID},
        )
        assert r_pending.status_code == 403
        assert r_pending.json()["detail"]["error"] == "workload_quarantined"

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
        assert r_approve.json()["detail"]["error"] == "workload_quarantined"

    # Redis connectivity outage on /v1/nemo/* returns 503 quarantine_backend_unavailable (not 403)
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
        assert (
            outage_propose.json()["detail"]["error"] == "quarantine_backend_unavailable"
        )
