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

"""``POST /governance/state-commitments`` — commit an agent-state snapshot.

Mounted on ``governance_app`` (prefix ``/governance``). Authentication is the
root app's :class:`~src.gateway.server.workload_identity.WorkloadIdentityMiddleware`:
the request only reaches this handler if it carries exactly one trusted
Linkerd ``l5d-client-id``. The handler records that identity in the
commitment record; it never accepts an HMAC routing seal as authentication.

Response codes:

* ``200`` — committed; body is a :class:`StateCommitmentReceipt` wire dict.
* ``413`` — canonical preimage exceeds the gateway limit.
* ``422`` — malformed snapshot or linkage.
* ``503`` — the evidence chain did not commit (or no service is configured).
  Producers must not emit an attestation step on any non-200.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.gateway.governance.seams.state_commitment import (
    InvalidStateSnapshotError,
    StateCommitmentError,
    StateCommitmentLinkage,
    StateSnapshotTooLargeError,
)
from src.gateway.server.app_state import state_commitment_service_of
from src.gateway.server.workload_identity import extract_client_identity

logger = logging.getLogger("cage.gateway.state_commitment_api")

router = APIRouter()


class StateCommitmentRequest(BaseModel):
    """Body of ``POST /governance/state-commitments``."""

    snapshot: dict[str, Any]
    linkage: dict[str, Any]


@router.post("/state-commitments", response_model=None)
async def commit_state_endpoint(
    request: Request, body: StateCommitmentRequest
) -> dict[str, Any] | JSONResponse:
    """Sanitize, hash and retain ``body.snapshot``; return the receipt."""
    from src.gateway.governance.governor.verdicts import (
        publish_infrastructure_block,
    )
    from src.gateway.governance.quarantine_actuator import (
        QuarantineCheckStatus,
        check_workload_quarantine_status,
    )
    from src.gateway.server.rate_limit import get_shared_rate_limiter

    try:
        caller_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        # Unreachable behind WorkloadIdentityMiddleware; refuse regardless.
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    rl_verdict = await get_shared_rate_limiter().check_request(
        request, "state-commitments"
    )
    if not rl_verdict.allowed:
        retry_after = max(1, int(rl_verdict.retry_after_seconds or 1))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "rate_limit_exceeded",
                "scope": rl_verdict.scope or "principal",
                "retry_after_seconds": retry_after,
            },
        )

    app_obj = request.scope.get("app")
    app_state = getattr(app_obj, "state", None)
    shared_redis = getattr(app_state, "redis", None)
    candidate_threads: list[str] = []
    if isinstance(body.linkage, dict):
        for t_key in ("threadId", "thread_id"):
            raw_t = body.linkage.get(t_key)
            if (
                isinstance(raw_t, str)
                and raw_t.strip()
                and raw_t.strip() not in candidate_threads
            ):
                candidate_threads.append(raw_t.strip())
    hdr_t = request.headers.get("x-cage-thread-id")
    if (
        isinstance(hdr_t, str)
        and hdr_t.strip()
        and hdr_t.strip() not in candidate_threads
    ):
        candidate_threads.append(hdr_t.strip())
    primary_thread_id = candidate_threads[0] if candidate_threads else None

    q_status = QuarantineCheckStatus.CLEAR
    matched_thread_id = primary_thread_id
    for idx, cand_tid in enumerate(candidate_threads or [None]):  # type: ignore[list-item]
        step_status = await check_workload_quarantine_status(
            thread_id=cand_tid,
            agent_svid=caller_identity if idx == 0 else None,
            redis_client=shared_redis,
        )
        if step_status is QuarantineCheckStatus.BACKEND_UNAVAILABLE:
            q_status = QuarantineCheckStatus.BACKEND_UNAVAILABLE
            break
        if step_status is QuarantineCheckStatus.QUARANTINED:
            q_status = QuarantineCheckStatus.QUARANTINED
            matched_thread_id = cand_tid or primary_thread_id
            break

    if q_status is QuarantineCheckStatus.BACKEND_UNAVAILABLE:
        try:
            await publish_infrastructure_block(
                action="state_commitment",
                params={"thread_id": primary_thread_id or "default"},
                dependency="redis",
                failure_code="QUARANTINE_REDIS_UNAVAILABLE",
                detail="Quarantine Redis backend unavailable on POST /governance/state-commitments",
                control_id="SC-7",
            )
        except Exception as infra_exc:
            logger.error(
                "[StateCommitmentAPI] Failed to publish infrastructure block: %s",
                infra_exc,
            )
        return JSONResponse(
            status_code=503,
            content={
                "error": "quarantine_backend_unavailable",
                "message": "Quarantine state store unavailable; failing closed.",
            },
        )
    if q_status is QuarantineCheckStatus.QUARANTINED:
        return JSONResponse(
            status_code=403,
            content={
                "error": "workload_quarantined",
                "message": "Workload SVID or thread is quarantined by CAGE out-of-band governance",
                "agent_id": caller_identity,
                "thread_id": matched_thread_id,
            },
        )

    try:
        service = state_commitment_service_of(
            app_obj if app_obj is not None else request.app
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        linkage = StateCommitmentLinkage.from_dict(body.linkage)
        receipt = await service.commit_state(
            body.snapshot, linkage=linkage, caller_identity=caller_identity
        )
    except StateSnapshotTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except InvalidStateSnapshotError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except StateCommitmentError as exc:
        logger.error("[StateCommitmentAPI] commit refused: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return receipt.to_dict()
