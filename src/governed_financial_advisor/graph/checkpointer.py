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

"""Gateway-mediated LangGraph checkpointer and fail-closed durability policy.

Remediates ``POAM-2026-226`` (silent ``MemorySaver`` fallback losing deferred/HITL
working state on pod restart) and the checkpoint-retention item of
``POAM-2026-225``:

* **Gateway-mediated storage:** Durable checkpoints flow exclusively over
  ``/governance/checkpoints/*`` on ``GATEWAY_URL``, authenticated by the
  advisor's Linkerd mTLS workload identity (``POAM-2026-195`` — the advisor
  opens zero direct Redis connections and holds no storage credentials).
* **Client-side serialization:** Checkpoints, metadata, channel values, and
  intermediate writes are serialized locally via ``JsonPlusSerializer`` into
  opaque ``(type_tag, base64_bytes)`` pairs; the gateway never deserializes
  agent objects.
* **Resumption-window TTL:** Each write forwards
  :func:`~src.governed_financial_advisor.graph.nodes.approval_node.resolve_hitl_approval_ttl_seconds`
  so the gateway derives TTL from ``max(_DEFAULT_TTL, _DEFAULT_HOLD_TTL,
  hitl_window) + 60s`` rounded up to whole minutes (4h 1m default) without
  refresh-on-read.
* **Fail-closed posture enforcement:** Under every enforcing posture
  (:func:`~src.gateway.governance.env_posture.is_enforcing`), ``MemorySaver``
  is unconditionally refused (:class:`CheckpointDurabilityError`) and startup
  verifies gateway checkpoint readiness via ``GET /governance/checkpoints/health``.
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import logging
import os
import secrets
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

import httpx
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    SerializerProtocol,
    get_checkpoint_id,
    get_checkpoint_metadata,
)
from langgraph.checkpoint.memory import MemorySaver
from opentelemetry.propagate import inject as otel_inject

from src.gateway.governance.env_posture import is_enforcing
from src.governed_financial_advisor.graph.nodes.approval_node import (
    resolve_hitl_approval_ttl_seconds,
)

logger = logging.getLogger(__name__)

_CHECKPOINTER_TYPE: str = "uninitialized"
_VALID_BACKENDS = frozenset({"gateway", "memory"})


class CheckpointDurabilityError(RuntimeError):
    """Durable checkpoint storage is required by posture or configuration and unavailable."""


def checkpointer_type_of(checkpointer: BaseCheckpointSaver[Any] | None) -> str:
    """Classify a checkpointer instance as ``'gateway'``, ``'memory'``, or ``'uninitialized'``."""
    if isinstance(checkpointer, GatewayCheckpointSaver):
        return "gateway"
    if isinstance(checkpointer, MemorySaver):
        return "memory"
    if checkpointer is not None:
        return type(checkpointer).__name__.lower()
    return "uninitialized"


def get_checkpointer_type() -> str:
    """Return the most recently constructed checkpointer type."""
    return _CHECKPOINTER_TYPE


def _validate_gateway_base_url(raw_url: str) -> str:
    clean = raw_url.strip().rstrip("/")
    parsed = urlparse(clean)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise CheckpointDurabilityError(
            f"GATEWAY_URL must be an http:// or https:// origin, got {raw_url!r}"
        )
    return clean


def _encode_version(version: str | int | float) -> tuple[str, str]:
    if isinstance(version, bool):
        raise ValueError("boolean channel version is invalid")
    if isinstance(version, int):
        return ("int", str(version))
    if isinstance(version, float):
        return ("float", repr(version))
    return ("str", str(version))


class GatewayCheckpointSaver(BaseCheckpointSaver[str]):
    """LangGraph :class:`BaseCheckpointSaver` backed by ``/governance/checkpoints/*``."""

    def __init__(
        self,
        gateway_url: str | None = None,
        *,
        serde: SerializerProtocol | None = None,
        resumption_window_seconds: int | None = None,
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(serde=serde)
        effective_url = (
            gateway_url
            if gateway_url is not None
            else os.environ.get("GATEWAY_URL", "")
        )
        if not effective_url or not effective_url.strip():
            raise CheckpointDurabilityError(
                "GATEWAY_URL is required to construct GatewayCheckpointSaver"
            )
        self._base_url: str = _validate_gateway_base_url(effective_url)
        self._resumption_window_override: int | None = resumption_window_seconds
        self._timeout: float = timeout
        self._transport: httpx.AsyncBaseTransport | None = transport
        self._extra_headers: dict[str, str] = dict(headers) if headers else {}
        self._async_client: httpx.AsyncClient | None = None
        self._async_client_loop: asyncio.AbstractEventLoop | None = None
        self._ttl_seconds: int | None = None

    @property
    def ttl_seconds(self) -> int | None:
        """Server-reported checkpoint TTL in seconds once verified or written."""
        return self._ttl_seconds

    def _effective_resumption_window_seconds(self) -> int:
        if self._resumption_window_override is not None:
            return int(self._resumption_window_override)
        return resolve_hitl_approval_ttl_seconds()

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        otel_inject(headers)
        headers.update(self._extra_headers)
        return headers

    async def _ensure_client(self) -> httpx.AsyncClient:
        current_loop = asyncio.get_running_loop()
        if (
            self._async_client is not None
            and not self._async_client.is_closed
            and self._async_client_loop is current_loop
        ):
            return self._async_client
        if self._async_client is not None and not self._async_client.is_closed:
            try:
                await self._async_client.aclose()
            except Exception as exc:
                logger.debug("Closing stale-loop checkpoint HTTP client: %s", exc)
        self._async_client = httpx.AsyncClient(
            base_url=self._base_url,
            transport=self._transport,
            timeout=self._timeout,
            follow_redirects=False,
        )
        self._async_client_loop = current_loop
        return self._async_client

    async def aclose(self) -> None:
        """Close the underlying async HTTP client pool."""
        client = self._async_client
        self._async_client = None
        self._async_client_loop = None
        if client is not None and not client.is_closed:
            await client.aclose()

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        client = await self._ensure_client()
        try:
            response = await client.request(
                method,
                path,
                json=dict(payload) if payload is not None else None,
                headers=self._build_headers(),
            )
        except httpx.HTTPError as exc:
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} transport error: {exc}"
            ) from exc
        if response.status_code != 200:
            detail = ""
            try:
                body = response.json()
                if isinstance(body, dict):
                    detail = str(body.get("detail") or body)
            except ValueError:
                detail = response.text[:200]
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} failed with HTTP "
                f"{response.status_code}: {detail}"
            )
        try:
            parsed = response.json()
        except ValueError as exc:
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} returned non-JSON body"
            ) from exc
        if not isinstance(parsed, dict):
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} returned non-object JSON"
            )
        return parsed

    def _run_sync(self, coro_factory: Any) -> Any:
        """Execute an async checkpointer operation from a synchronous caller."""
        try:
            asyncio.get_running_loop()
            loop_running = True
        except RuntimeError:
            loop_running = False

        async def _isolated() -> Any:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
            ) as temp_client:
                return await coro_factory(temp_client)

        if not loop_running:
            return asyncio.run(_isolated())

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(_isolated())).result()

    async def _request_json_with_client(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = await client.request(
                method,
                path,
                json=dict(payload) if payload is not None else None,
                headers=self._build_headers(),
            )
        except httpx.HTTPError as exc:
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} transport error: {exc}"
            ) from exc
        if response.status_code != 200:
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} failed with HTTP {response.status_code}"
            )
        body = response.json()
        if not isinstance(body, dict):
            raise CheckpointDurabilityError(
                f"gateway checkpoint {method} {path} returned non-object JSON"
            )
        return body

    def _encode_blob(self, value: Any) -> dict[str, str]:
        type_tag, raw_bytes = self.serde.dumps_typed(value)
        return {
            "type_tag": type_tag,
            "data_b64": base64.b64encode(raw_bytes).decode("ascii"),
        }

    def _decode_blob(self, wire: Mapping[str, Any]) -> Any:
        data_b64 = str(wire.get("data_b64", ""))
        raw_bytes = base64.b64decode(data_b64, validate=True) if data_b64 else b""
        return self.serde.loads_typed((str(wire["type_tag"]), raw_bytes))

    def _record_to_tuple(
        self,
        record: Mapping[str, Any],
        *,
        requested_config: RunnableConfig | None = None,
    ) -> CheckpointTuple:
        thread_id = str(record["thread_id"])
        checkpoint_ns = str(record.get("checkpoint_ns", ""))
        checkpoint_id = str(record["checkpoint_id"])
        parent_id = record.get("parent_checkpoint_id")

        checkpoint_decoded: Checkpoint = self._decode_blob(record["checkpoint"])
        channel_values: dict[str, Any] = {}
        for entry in record.get("channel_blobs") or []:
            blob = entry.get("blob") or {}
            if blob.get("type_tag") == "empty":
                continue
            channel_values[str(entry["channel"])] = self._decode_blob(blob)

        metadata_decoded: CheckpointMetadata = self._decode_blob(record["metadata"])
        pending_writes = [
            (
                str(w["task_id"]),
                str(w["channel"]),
                self._decode_blob(w["blob"]),
            )
            for w in (record.get("pending_writes") or [])
        ]

        if requested_config is not None and get_checkpoint_id(requested_config):
            tuple_config = requested_config
        else:
            tuple_config = {
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                }
            }

        parent_config: RunnableConfig | None = (
            {
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": str(parent_id),
                }
            }
            if parent_id
            else None
        )

        return CheckpointTuple(
            config=tuple_config,
            checkpoint={
                **checkpoint_decoded,
                "channel_values": channel_values,
            },
            metadata=metadata_decoded,
            parent_config=parent_config,
            pending_writes=pending_writes,
        )

    async def verify_ready(self) -> dict[str, Any]:
        """Probe ``GET /governance/checkpoints/health``; raises on any failure."""
        body = await self._request_json("GET", "/governance/checkpoints/health")
        if body.get("status") != "ok":
            raise CheckpointDurabilityError(
                f"gateway checkpoint health returned unexpected payload: {body!r}"
            )
        ttl = body.get("ttl_seconds")
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            self._ttl_seconds = ttl
        return body

    def _build_put_payload(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> tuple[dict[str, Any], RunnableConfig]:
        c = checkpoint.copy()
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        values: dict[str, Any] = c.pop("channel_values")  # type: ignore[misc]

        new_blobs: list[dict[str, Any]] = []
        for ch_name, ver in new_versions.items():
            ver_type, ver_str = _encode_version(ver)
            blob_wire = (
                self._encode_blob(values[ch_name])
                if ch_name in values
                else {"type_tag": "empty", "data_b64": ""}
            )
            new_blobs.append(
                {
                    "channel": ch_name,
                    "version_type": ver_type,
                    "version": ver_str,
                    "blob": blob_wire,
                }
            )

        channel_versions_wire: list[dict[str, str]] = []
        for ch_name, ver in (c.get("channel_versions") or {}).items():
            ver_type, ver_str = _encode_version(ver)
            channel_versions_wire.append(
                {
                    "channel": ch_name,
                    "version_type": ver_type,
                    "version": ver_str,
                }
            )

        payload: dict[str, Any] = {
            "thread_id": thread_id,
            "checkpoint_ns": checkpoint_ns,
            "checkpoint_id": str(checkpoint["id"]),
            "parent_checkpoint_id": config["configurable"].get("checkpoint_id"),
            "checkpoint": self._encode_blob(c),
            "metadata": self._encode_blob(get_checkpoint_metadata(config, metadata)),
            "channel_versions": channel_versions_wire,
            "new_blobs": new_blobs,
            "resumption_window_seconds": self._effective_resumption_window_seconds(),
        }
        next_config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": str(checkpoint["id"]),
            }
        }
        return payload, next_config

    def _build_put_writes_payload(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> dict[str, Any]:
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = str(config["configurable"]["checkpoint_id"])
        writes_wire = [
            {
                "task_id": str(task_id),
                "idx": int(WRITES_IDX_MAP.get(channel, idx)),
                "channel": str(channel),
                "blob": self._encode_blob(value),
                "task_path": str(task_path),
            }
            for idx, (channel, value) in enumerate(writes)
        ]
        return {
            "thread_id": thread_id,
            "checkpoint_ns": checkpoint_ns,
            "checkpoint_id": checkpoint_id,
            "writes": writes_wire,
            "resumption_window_seconds": self._effective_resumption_window_seconds(),
        }

    # ── Async BaseCheckpointSaver interface ───────────────────────────────────

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = get_checkpoint_id(config)
        body = await self._request_json(
            "POST",
            "/governance/checkpoints/get",
            payload={
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            },
        )
        if not body.get("found") or not isinstance(body.get("record"), Mapping):
            return None
        return self._record_to_tuple(body["record"], requested_config=config)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        if limit is not None and limit <= 0:
            return
        thread_id = (
            str(config["configurable"]["thread_id"])
            if config and "thread_id" in config.get("configurable", {})
            else None
        )
        checkpoint_ns = (
            str(config["configurable"]["checkpoint_ns"])
            if config and "checkpoint_ns" in config.get("configurable", {})
            else None
        )
        checkpoint_id = get_checkpoint_id(config) if config else None
        before_id = get_checkpoint_id(before) if before else None

        body = await self._request_json(
            "POST",
            "/governance/checkpoints/list",
            payload={
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
                "before_checkpoint_id": before_id,
                # When metadata filter is set, filter decoded metadata locally first.
                "limit": limit if not filter else None,
            },
        )
        yielded = 0
        for rec in body.get("records") or []:
            tup = self._record_to_tuple(rec)
            if filter and not all(tup.metadata.get(k) == v for k, v in filter.items()):
                continue
            yield tup
            yielded += 1
            if limit is not None and yielded >= limit:
                return

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        payload, next_config = self._build_put_payload(
            config, checkpoint, metadata, new_versions
        )
        body = await self._request_json(
            "PUT", "/governance/checkpoints/tuple", payload=payload
        )
        ttl = body.get("ttl_seconds")
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            self._ttl_seconds = ttl
        return next_config

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        if not writes:
            return
        payload = self._build_put_writes_payload(config, writes, task_id, task_path)
        body = await self._request_json(
            "PUT", "/governance/checkpoints/writes", payload=payload
        )
        ttl = body.get("ttl_seconds")
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            self._ttl_seconds = ttl

    async def adelete_thread(self, thread_id: str) -> None:
        await self._request_json(
            "POST",
            "/governance/checkpoints/delete",
            payload={"thread_id": str(thread_id)},
        )

    # ── Sync BaseCheckpointSaver interface ────────────────────────────────────

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = get_checkpoint_id(config)
        body = self._run_sync(
            lambda c: self._request_json_with_client(
                c,
                "POST",
                "/governance/checkpoints/get",
                payload={
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                },
            )
        )
        if not body.get("found") or not isinstance(body.get("record"), Mapping):
            return None
        return self._record_to_tuple(body["record"], requested_config=config)

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        if limit is not None and limit <= 0:
            return
        thread_id = (
            str(config["configurable"]["thread_id"])
            if config and "thread_id" in config.get("configurable", {})
            else None
        )
        checkpoint_ns = (
            str(config["configurable"]["checkpoint_ns"])
            if config and "checkpoint_ns" in config.get("configurable", {})
            else None
        )
        checkpoint_id = get_checkpoint_id(config) if config else None
        before_id = get_checkpoint_id(before) if before else None
        body = self._run_sync(
            lambda c: self._request_json_with_client(
                c,
                "POST",
                "/governance/checkpoints/list",
                payload={
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                    "before_checkpoint_id": before_id,
                    "limit": limit if not filter else None,
                },
            )
        )
        yielded = 0
        for rec in body.get("records") or []:
            tup = self._record_to_tuple(rec)
            if filter and not all(tup.metadata.get(k) == v for k, v in filter.items()):
                continue
            yield tup
            yielded += 1
            if limit is not None and yielded >= limit:
                return

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        payload, next_config = self._build_put_payload(
            config, checkpoint, metadata, new_versions
        )
        body = self._run_sync(
            lambda c: self._request_json_with_client(
                c, "PUT", "/governance/checkpoints/tuple", payload=payload
            )
        )
        ttl = body.get("ttl_seconds")
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            self._ttl_seconds = ttl
        return next_config

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        if not writes:
            return
        payload = self._build_put_writes_payload(config, writes, task_id, task_path)
        body = self._run_sync(
            lambda c: self._request_json_with_client(
                c, "PUT", "/governance/checkpoints/writes", payload=payload
            )
        )
        ttl = body.get("ttl_seconds")
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            self._ttl_seconds = ttl

    def delete_thread(self, thread_id: str) -> None:
        self._run_sync(
            lambda c: self._request_json_with_client(
                c,
                "POST",
                "/governance/checkpoints/delete",
                payload={"thread_id": str(thread_id)},
            )
        )

    def get_next_version(self, current: str | None, channel: None) -> str:
        if current is None:
            current_v = 0
        elif isinstance(current, int):
            current_v = current
        else:
            current_v = int(str(current).split(".")[0])
        next_v = current_v + 1
        return f"{next_v:032}.{secrets.token_hex(8)}"


def get_checkpointer(
    gateway_url: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> BaseCheckpointSaver[Any]:
    """Construct the graph checkpointer under fail-closed posture rules.

    * Under every enforcing posture (:func:`is_enforcing` is ``True`` —
      ``production``, ``staging``, ``local``, or any unrecognized ``CAGE_ENV``),
      ``MemorySaver`` is unconditionally refused (:class:`CheckpointDurabilityError`)
      and ``GATEWAY_URL`` must be configured.
    * In permissive postures (``dev``, ``test``, ``ci``), ``GatewayCheckpointSaver``
      is used whenever ``CAGE_CHECKPOINT_BACKEND=gateway`` or a ``gateway_url`` /
      ``GATEWAY_URL`` is configured; ``MemorySaver`` is allowed only in
      permissive postures when ``CAGE_CHECKPOINT_BACKEND=memory`` or no gateway
      URL is configured (hermetic unit tests).
    """
    global _CHECKPOINTER_TYPE

    source = os.environ if env is None else env
    enforcing = is_enforcing(source)
    raw_backend = source.get("CAGE_CHECKPOINT_BACKEND", "").strip().lower()
    if raw_backend and raw_backend not in _VALID_BACKENDS:
        raise CheckpointDurabilityError(
            f"Unsupported CAGE_CHECKPOINT_BACKEND={raw_backend!r}; "
            f"expected one of {sorted(_VALID_BACKENDS)}"
        )

    effective_gateway_url = (
        gateway_url.strip()
        if isinstance(gateway_url, str) and gateway_url.strip()
        else source.get("GATEWAY_URL", "").strip()
    )

    if raw_backend == "memory":
        if enforcing:
            raise CheckpointDurabilityError(
                "CAGE_CHECKPOINT_BACKEND='memory' is refused in enforcing postures "
                "(POAM-2026-226): deferred and HITL state require durable gateway-mediated storage"
            )
        _CHECKPOINTER_TYPE = "memory"
        logger.warning(
            "Using non-durable MemorySaver in permissive posture (CAGE_CHECKPOINT_BACKEND=memory)"
        )
        return MemorySaver()

    if raw_backend == "gateway" or enforcing or bool(effective_gateway_url):
        if not effective_gateway_url:
            raise CheckpointDurabilityError(
                "GATEWAY_URL is required for durable gateway-mediated checkpoint storage"
            )
        saver = GatewayCheckpointSaver(effective_gateway_url)
        _CHECKPOINTER_TYPE = "gateway"
        logger.info("Using GatewayCheckpointSaver via %s", saver._base_url)
        return saver

    # Permissive posture (dev/test/ci) with neither GATEWAY_URL nor explicit backend.
    _CHECKPOINTER_TYPE = "memory"
    logger.info(
        "Using non-durable MemorySaver in permissive posture (no GATEWAY_URL configured)"
    )
    return MemorySaver()
