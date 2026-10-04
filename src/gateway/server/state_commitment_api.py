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


@router.post("/state-commitments")
async def commit_state_endpoint(
    request: Request, body: StateCommitmentRequest
) -> dict[str, Any]:
    """Sanitize, hash and retain ``body.snapshot``; return the receipt."""
    try:
        caller_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        # Unreachable behind WorkloadIdentityMiddleware; refuse regardless.
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        service = state_commitment_service_of(request.app)
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
