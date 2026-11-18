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

"""``/governance/checkpoints/*`` — gateway-mediated agent working-state endpoints.

Mounted on ``governance_app`` (prefix ``/governance``). Every endpoint is gated
by the root app's
:class:`~src.gateway.server.workload_identity.WorkloadIdentityMiddleware` and
additionally extracts the verified Linkerd ``l5d-client-id`` via
:func:`~src.gateway.server.workload_identity.extract_client_identity`.

Privacy invariant: ``thread_id`` values (which may carry a default
``<prefix><user_id>`` identifier) are transmitted exclusively in JSON request
bodies — never in URL path segments or query parameters — so HTTP access logs
and route span names never record end-user identifiers.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.gateway.governance.checkpoint_store import (
    ChannelBlobEntry,
    ChannelVersionRef,
    CheckpointPayloadTooLargeError,
    CheckpointStoreError,
    CheckpointStoreUnavailableError,
    CheckpointValidationError,
    PendingWriteEntry,
    TypedBlob,
)
from src.gateway.server.app_state import checkpoint_store_of
from src.gateway.server.workload_identity import extract_client_identity

logger = logging.getLogger("cage.gateway.checkpoint_api")

router = APIRouter(prefix="/checkpoints")


class TypedBlobModel(BaseModel):
    type_tag: str
    data_b64: str


class ChannelVersionRefModel(BaseModel):
    channel: str
    version_type: str
    version: str


class ChannelBlobModel(BaseModel):
    channel: str
    version_type: str
    version: str
    blob: TypedBlobModel


class PendingWriteModel(BaseModel):
    task_id: str
    idx: int
    channel: str
    blob: TypedBlobModel
    task_path: str = ""


class PutCheckpointRequest(BaseModel):
    thread_id: str
    checkpoint_ns: str = ""
    checkpoint_id: str
    parent_checkpoint_id: str | None = None
    checkpoint: TypedBlobModel
    metadata: TypedBlobModel
    channel_versions: list[ChannelVersionRefModel] = Field(default_factory=list)
    new_blobs: list[ChannelBlobModel] = Field(default_factory=list)
    resumption_window_seconds: int | None = None


class PutWritesRequest(BaseModel):
    thread_id: str
    checkpoint_ns: str = ""
    checkpoint_id: str
    writes: list[PendingWriteModel] = Field(default_factory=list)
    resumption_window_seconds: int | None = None


class GetCheckpointRequest(BaseModel):
    thread_id: str
    checkpoint_ns: str = ""
    checkpoint_id: str | None = None


class ListCheckpointsRequest(BaseModel):
    thread_id: str | None = None
    checkpoint_ns: str | None = None
    checkpoint_id: str | None = None
    before_checkpoint_id: str | None = None
    limit: int | None = None


class DeleteThreadRequest(BaseModel):
    thread_id: str


def _require_caller_and_store(request: Request) -> tuple[str, Any]:
    try:
        caller_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        store = checkpoint_store_of(request.app)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return caller_identity, store


@router.get("/health")
async def checkpoint_health_endpoint(request: Request) -> dict[str, Any]:
    """Authenticated readiness probe for agent startup and health checks."""
    _caller_identity, store = _require_caller_and_store(request)
    try:
        await store.ping()
    except CheckpointStoreUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "ok",
        "ttl_seconds": store.default_ttl_seconds,
        "max_ttl_seconds": store.max_ttl_seconds,
    }


@router.put("/tuple")
async def put_checkpoint_endpoint(
    request: Request, body: PutCheckpointRequest
) -> dict[str, Any]:
    """Persist a serialized checkpoint and its channel blobs under caller identity."""
    caller_identity, store = _require_caller_and_store(request)
    try:
        ttl_seconds = await store.put_checkpoint(
            caller_identity=caller_identity,
            thread_id=body.thread_id,
            checkpoint_ns=body.checkpoint_ns,
            checkpoint_id=body.checkpoint_id,
            parent_checkpoint_id=body.parent_checkpoint_id,
            checkpoint=TypedBlob(
                type_tag=body.checkpoint.type_tag,
                data_b64=body.checkpoint.data_b64,
            ),
            metadata=TypedBlob(
                type_tag=body.metadata.type_tag,
                data_b64=body.metadata.data_b64,
            ),
            channel_versions=[
                ChannelVersionRef(
                    channel=cv.channel,
                    version_type=cv.version_type,
                    version=cv.version,
                )
                for cv in body.channel_versions
            ],
            new_blobs=[
                ChannelBlobEntry(
                    ref=ChannelVersionRef(
                        channel=nb.channel,
                        version_type=nb.version_type,
                        version=nb.version,
                    ),
                    blob=TypedBlob(
                        type_tag=nb.blob.type_tag,
                        data_b64=nb.blob.data_b64,
                    ),
                )
                for nb in body.new_blobs
            ],
            resumption_window_seconds=body.resumption_window_seconds,
        )
    except CheckpointPayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except CheckpointValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckpointStoreError as exc:
        logger.error("[CheckpointAPI] put_checkpoint failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {
        "checkpoint_id": body.checkpoint_id,
        "ttl_seconds": ttl_seconds,
    }


@router.put("/writes")
async def put_writes_endpoint(
    request: Request, body: PutWritesRequest
) -> dict[str, Any]:
    """Persist intermediate task writes linked to ``body.checkpoint_id``."""
    caller_identity, store = _require_caller_and_store(request)
    try:
        ttl_seconds = await store.put_writes(
            caller_identity=caller_identity,
            thread_id=body.thread_id,
            checkpoint_ns=body.checkpoint_ns,
            checkpoint_id=body.checkpoint_id,
            writes=[
                PendingWriteEntry(
                    task_id=w.task_id,
                    idx=w.idx,
                    channel=w.channel,
                    blob=TypedBlob(
                        type_tag=w.blob.type_tag,
                        data_b64=w.blob.data_b64,
                    ),
                    task_path=w.task_path,
                )
                for w in body.writes
            ],
            resumption_window_seconds=body.resumption_window_seconds,
        )
    except CheckpointPayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except CheckpointValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckpointStoreError as exc:
        logger.error("[CheckpointAPI] put_writes failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {"ttl_seconds": ttl_seconds}


@router.post("/get")
async def get_checkpoint_endpoint(
    request: Request, body: GetCheckpointRequest
) -> dict[str, Any]:
    """Fetch a stored checkpoint without refreshing TTL."""
    caller_identity, store = _require_caller_and_store(request)
    try:
        record = await store.get_checkpoint(
            caller_identity=caller_identity,
            thread_id=body.thread_id,
            checkpoint_ns=body.checkpoint_ns,
            checkpoint_id=body.checkpoint_id,
        )
    except CheckpointValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckpointStoreError as exc:
        logger.error("[CheckpointAPI] get_checkpoint failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if record is None:
        return {"found": False, "record": None}
    return {"found": True, "record": record.to_dict()}


@router.post("/list")
async def list_checkpoints_endpoint(
    request: Request, body: ListCheckpointsRequest
) -> dict[str, Any]:
    """List stored checkpoints newest-first without refreshing TTL."""
    caller_identity, store = _require_caller_and_store(request)
    try:
        records = await store.list_checkpoints(
            caller_identity=caller_identity,
            thread_id=body.thread_id,
            checkpoint_ns=body.checkpoint_ns,
            checkpoint_id=body.checkpoint_id,
            before_checkpoint_id=body.before_checkpoint_id,
            limit=body.limit,
        )
    except CheckpointValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckpointStoreError as exc:
        logger.error("[CheckpointAPI] list_checkpoints failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {"records": [r.to_dict() for r in records]}


@router.post("/delete")
async def delete_thread_endpoint(
    request: Request, body: DeleteThreadRequest
) -> dict[str, Any]:
    """Delete all stored checkpoints and writes for ``body.thread_id``."""
    caller_identity, store = _require_caller_and_store(request)
    try:
        deleted = await store.delete_thread(
            caller_identity=caller_identity,
            thread_id=body.thread_id,
        )
    except CheckpointValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckpointStoreError as exc:
        logger.error("[CheckpointAPI] delete_thread failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {"deleted_keys": deleted}
