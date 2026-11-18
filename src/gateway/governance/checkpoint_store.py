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

"""Gateway-mediated working-state checkpoint store (Layer 1 kernel).

Stores opaque, client-serialized graph checkpoints and intermediate writes in a
dedicated logical database of the governance Valkey/Redis instance, partitioned
strictly by the caller's verified Linkerd mesh workload identity.

Architectural invariants
------------------------
1. **Domain-agnostic & framework-neutral:** This module never imports agent
   orchestration libraries or deserializes client Python objects. Checkpoint,
   metadata, channel-value, and pending-write payloads are stored and returned
   as opaque ``(type_tag, base64_bytes)`` pairs validated for size and base64
   well-formedness.
2. **Caller-identity isolation:** Every key is derived from
   ``SHA-256(caller_identity)``, ``SHA-256(thread_id)``, and
   ``SHA-256(checkpoint_ns)`` so one workload identity can never read, list,
   overwrite, or delete another workload's checkpoints, and user-derived thread
   identifiers never appear in plaintext Redis key names.
3. **Resumption-window TTL (never refresh-on-read):** Key expiry is derived from
   the kernel defer queue's park and hold windows
   (:data:`~src.gateway.governance.defer_queue._DEFAULT_TTL` and
   :data:`~src.gateway.governance.defer_queue._DEFAULT_HOLD_TTL`) plus any
   caller-declared resumption window, with a 60-second park margin rounded up to
   whole minutes and bounded by ``CAGE_CHECKPOINT_MAX_TTL_SECONDS`` (default
   86,400 s, hard ceiling 90 days). Only writes (``put_checkpoint``,
   ``put_writes``) set ``EXPIRE``; reads (``get_checkpoint``,
   ``list_checkpoints``) never extend TTL.
4. **No in-memory fallback:** When Redis is unconfigured or unreachable, every
   operation raises :class:`CheckpointStoreUnavailableError` so callers never
   mistake ephemeral memory for durable state.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import json
import logging
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from src.gateway.governance import defer_queue as _defer_queue
from src.gateway.governance.env_posture import is_enforcing

logger = logging.getLogger("cage.gateway.checkpoint_store")

_KEY_NAMESPACE = "cage:ckpt:v1"
_PARK_MARGIN_SECONDS = 60
_DEFAULT_REDIS_DB = 3
_DEFAULT_MAX_TTL_SECONDS = 86_400  # 24h default ceiling
_HARD_MAX_TTL_SECONDS = 90 * 86_400  # 90-day PIA hard ceiling
_DEFAULT_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024  # 4 MiB max serialized payload per write
_MAX_IDENTIFIER_CHARS = 512
_VALID_VERSION_TYPES = frozenset({"str", "int", "float"})
_FIELD_SEP = "\x1f"


class CheckpointStoreError(RuntimeError):
    """Base error raised by :class:`GatewayCheckpointStore`."""


class CheckpointStoreUnavailableError(CheckpointStoreError):
    """Redis backing store is unconfigured or unreachable."""


class CheckpointValidationError(ValueError):
    """Malformed identifier, invalid base64 blob, or out-of-bounds TTL."""


class CheckpointPayloadTooLargeError(CheckpointValidationError):
    """Serialized checkpoint write exceeds ``CAGE_CHECKPOINT_MAX_PAYLOAD_BYTES``."""


@dataclass(frozen=True)
class TypedBlob:
    """Opaque ``(type_tag, data_b64)`` pair produced by a client serializer."""

    type_tag: str
    data_b64: str

    def validate(self, *, field_name: str) -> int:
        """Validate ``type_tag`` and base64 payload; return decoded byte length."""
        if (
            not isinstance(self.type_tag, str)
            or not self.type_tag
            or len(self.type_tag) > 128
        ):
            raise CheckpointValidationError(
                f"{field_name}.type_tag must be a non-empty string <= 128 chars"
            )
        if not isinstance(self.data_b64, str):
            raise CheckpointValidationError(
                f"{field_name}.data_b64 must be a base64 string"
            )
        if self.data_b64 == "":
            return 0
        try:
            raw = base64.b64decode(self.data_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CheckpointValidationError(
                f"{field_name}.data_b64 is not valid base64"
            ) from exc
        return len(raw)

    def to_dict(self) -> dict[str, str]:
        return {"type_tag": self.type_tag, "data_b64": self.data_b64}

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, field_name: str) -> TypedBlob:
        if not isinstance(data, dict):
            raise CheckpointValidationError(f"{field_name} must be an object")
        blob = cls(
            type_tag=str(data.get("type_tag", "")),
            data_b64=str(data.get("data_b64", "")),
        )
        blob.validate(field_name=field_name)
        return blob


@dataclass(frozen=True)
class ChannelVersionRef:
    """Typed channel-version reference ``(channel, version_type, version)``."""

    channel: str
    version_type: str
    version: str

    def validate(self) -> None:
        _validate_identifier(self.channel, field_name="channel", allow_empty=False)
        if self.version_type not in _VALID_VERSION_TYPES:
            raise CheckpointValidationError(
                f"version_type must be one of {sorted(_VALID_VERSION_TYPES)}, "
                f"got {self.version_type!r}"
            )
        _validate_identifier(self.version, field_name="version", allow_empty=False)

    def hash_field(self) -> str:
        return f"{self.channel}{_FIELD_SEP}{self.version_type}:{self.version}"

    def to_dict(self) -> dict[str, str]:
        return {
            "channel": self.channel,
            "version_type": self.version_type,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChannelVersionRef:
        if not isinstance(data, dict):
            raise CheckpointValidationError("channel_version entry must be an object")
        ref = cls(
            channel=str(data.get("channel", "")),
            version_type=str(data.get("version_type", "")),
            version=str(data.get("version", "")),
        )
        ref.validate()
        return ref


@dataclass(frozen=True)
class ChannelBlobEntry:
    """Serialized value for one ``(channel, version)`` slot."""

    ref: ChannelVersionRef
    blob: TypedBlob

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.ref.channel,
            "version_type": self.ref.version_type,
            "version": self.ref.version,
            "blob": self.blob.to_dict(),
        }


@dataclass(frozen=True)
class PendingWriteEntry:
    """Serialized intermediate task write attached to a checkpoint."""

    task_id: str
    idx: int
    channel: str
    blob: TypedBlob
    task_path: str = ""

    def validate(self) -> int:
        _validate_identifier(self.task_id, field_name="task_id", allow_empty=False)
        _validate_identifier(self.channel, field_name="channel", allow_empty=False)
        _validate_identifier(self.task_path, field_name="task_path", allow_empty=True)
        if not isinstance(self.idx, int) or isinstance(self.idx, bool):
            raise CheckpointValidationError("write.idx must be an integer")
        return self.blob.validate(field_name="write.blob")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "idx": self.idx,
            "channel": self.channel,
            "blob": self.blob.to_dict(),
            "task_path": self.task_path,
        }


@dataclass(frozen=True)
class StoredCheckpoint:
    """Complete stored checkpoint tuple returned by ``get`` and ``list``."""

    thread_id: str
    checkpoint_ns: str
    checkpoint_id: str
    parent_checkpoint_id: str | None
    checkpoint: TypedBlob
    metadata: TypedBlob
    channel_blobs: list[ChannelBlobEntry]
    pending_writes: list[PendingWriteEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "checkpoint_ns": self.checkpoint_ns,
            "checkpoint_id": self.checkpoint_id,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "checkpoint": self.checkpoint.to_dict(),
            "metadata": self.metadata.to_dict(),
            "channel_blobs": [b.to_dict() for b in self.channel_blobs],
            "pending_writes": [w.to_dict() for w in self.pending_writes],
        }


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_identifier(
    value: str, *, field_name: str, allow_empty: bool = False
) -> str:
    if not isinstance(value, str):
        raise CheckpointValidationError(f"{field_name} must be a string")
    if not allow_empty and not value:
        raise CheckpointValidationError(f"{field_name} must be non-empty")
    if len(value) > _MAX_IDENTIFIER_CHARS:
        raise CheckpointValidationError(
            f"{field_name} exceeds maximum length ({_MAX_IDENTIFIER_CHARS} chars)"
        )
    if "\x00" in value:
        raise CheckpointValidationError(f"{field_name} must not contain NUL bytes")
    return value


def resolve_max_ttl_seconds() -> int:
    """Resolve ``CAGE_CHECKPOINT_MAX_TTL_SECONDS`` within ``[60, 90d]``."""
    raw = os.environ.get("CAGE_CHECKPOINT_MAX_TTL_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_MAX_TTL_SECONDS
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise CheckpointValidationError(
            f"CAGE_CHECKPOINT_MAX_TTL_SECONDS must be an integer, got {raw!r}"
        ) from exc
    if parsed < 60 or parsed > _HARD_MAX_TTL_SECONDS:
        raise CheckpointValidationError(
            f"CAGE_CHECKPOINT_MAX_TTL_SECONDS={parsed} must be between 60 and "
            f"{_HARD_MAX_TTL_SECONDS} seconds (90-day privacy ceiling)"
        )
    return parsed


def compute_checkpoint_ttl_seconds(
    *extra_resumption_windows_s: int,
    max_ttl_seconds: int | None = None,
) -> int:
    """Derive checkpoint TTL from the defer/hold resumption windows.

    Reads :data:`~src.gateway.governance.defer_queue._DEFAULT_TTL` and
    :data:`~src.gateway.governance.defer_queue._DEFAULT_HOLD_TTL` directly (never
    copied), takes the maximum with any caller-supplied resumption window, adds
    a 60-second park margin, and rounds up to whole minutes.
    """
    ceiling = resolve_max_ttl_seconds() if max_ttl_seconds is None else max_ttl_seconds
    windows: list[int] = [
        int(_defer_queue._DEFAULT_TTL),
        int(_defer_queue._DEFAULT_HOLD_TTL),
    ]
    for extra in extra_resumption_windows_s:
        if extra is None:
            continue
        if not isinstance(extra, int) or isinstance(extra, bool) or extra < 0:
            raise CheckpointValidationError(
                f"resumption_window_seconds must be a non-negative integer, got {extra!r}"
            )
        if extra > 0:
            windows.append(extra)

    with_margin = max(windows) + _PARK_MARGIN_SECONDS
    rounded = ((with_margin + 59) // 60) * 60
    if rounded > ceiling:
        raise CheckpointValidationError(
            f"Derived checkpoint TTL ({rounded}s) exceeds maximum allowed ceiling "
            f"({ceiling}s)"
        )
    return rounded


class GatewayCheckpointStore:
    """Redis/Valkey-backed checkpoint store partitioned by caller mesh identity."""

    def __init__(
        self,
        redis: Any | None,
        *,
        max_ttl_seconds: int | None = None,
        max_payload_bytes: int | None = None,
        owns_redis: bool = False,
    ) -> None:
        self._redis = redis
        self._owns_redis = owns_redis
        self._max_ttl_seconds = (
            resolve_max_ttl_seconds() if max_ttl_seconds is None else max_ttl_seconds
        )
        if self._max_ttl_seconds < 60 or self._max_ttl_seconds > _HARD_MAX_TTL_SECONDS:
            raise CheckpointValidationError(
                f"max_ttl_seconds={self._max_ttl_seconds} outside [60, {_HARD_MAX_TTL_SECONDS}]"
            )
        self._max_payload_bytes = (
            int(
                os.environ.get(
                    "CAGE_CHECKPOINT_MAX_PAYLOAD_BYTES", str(_DEFAULT_MAX_PAYLOAD_BYTES)
                )
            )
            if max_payload_bytes is None
            else max_payload_bytes
        )

    @property
    def default_ttl_seconds(self) -> int:
        """Default checkpoint TTL derived from kernel defer/hold constants."""
        return compute_checkpoint_ttl_seconds(max_ttl_seconds=self._max_ttl_seconds)

    @property
    def max_ttl_seconds(self) -> int:
        """Configured upper bound on checkpoint TTL in seconds."""
        return self._max_ttl_seconds

    def _require_redis(self) -> Any:
        if self._redis is None:
            raise CheckpointStoreUnavailableError(
                "gateway checkpoint store has no Redis connection"
            )
        return self._redis

    async def ping(self) -> bool:
        """Verify Redis connectivity; raises :class:`CheckpointStoreUnavailableError` on failure."""
        redis = self._require_redis()
        try:
            ok = await redis.ping()
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint Redis ping failed: {exc}"
            ) from exc
        if not ok:
            raise CheckpointStoreUnavailableError(
                "checkpoint Redis ping returned falsy response"
            )
        return True

    async def close(self) -> None:
        """Close the owned Redis connection pool on gateway shutdown."""
        redis = self._redis
        self._redis = None
        if self._owns_redis and redis is not None and hasattr(redis, "aclose"):
            try:
                close_res = redis.aclose()
                if inspect.isawaitable(close_res):
                    await close_res
            except Exception as exc:
                logger.debug("Checkpoint Redis close error: %s", exc)

    # ── Key builders (all SHA-256 hashed for isolation & PII-free key names) ──

    @staticmethod
    def _threads_key(caller_h: str) -> str:
        return f"{_KEY_NAMESPACE}:{caller_h}:threads"

    @staticmethod
    def _thread_meta_key(caller_h: str, thread_h: str) -> str:
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:meta"

    @staticmethod
    def _thread_ns_key(caller_h: str, thread_h: str) -> str:
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:namespaces"

    @staticmethod
    def _ns_ids_key(caller_h: str, thread_h: str, ns_h: str) -> str:
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:ns:{ns_h}:ids"

    @staticmethod
    def _ns_blobs_key(caller_h: str, thread_h: str, ns_h: str) -> str:
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:ns:{ns_h}:blobs"

    @staticmethod
    def _cp_key(caller_h: str, thread_h: str, ns_h: str, cp_id: str) -> str:
        cp_h = _sha256_hex(cp_id)
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:ns:{ns_h}:cp:{cp_h}"

    @staticmethod
    def _writes_key(caller_h: str, thread_h: str, ns_h: str, cp_id: str) -> str:
        cp_h = _sha256_hex(cp_id)
        return f"{_KEY_NAMESPACE}:{caller_h}:t:{thread_h}:ns:{ns_h}:writes:{cp_h}"

    async def _collect_thread_keys_for_ttl(
        self,
        redis: Any,
        caller_h: str,
        thread_h: str,
        *,
        extra_ns: str,
        extra_cp_id: str,
    ) -> list[str]:
        """Gather all existing keys of ``(caller_h, thread_h)`` so a write refreshes them coherently."""
        ns_set_raw = await redis.smembers(self._thread_ns_key(caller_h, thread_h))
        namespaces = {str(ns) for ns in (ns_set_raw or set())}
        namespaces.add(extra_ns)

        keys: list[str] = [
            self._thread_meta_key(caller_h, thread_h),
            self._thread_ns_key(caller_h, thread_h),
        ]
        for ns in namespaces:
            ns_h = _sha256_hex(ns)
            ids_key = self._ns_ids_key(caller_h, thread_h, ns_h)
            keys.append(ids_key)
            keys.append(self._ns_blobs_key(caller_h, thread_h, ns_h))
            cp_ids_raw = await redis.zrange(ids_key, 0, -1)
            cp_ids = {str(cid) for cid in (cp_ids_raw or [])}
            if ns == extra_ns and extra_cp_id:
                cp_ids.add(extra_cp_id)
            for cid in cp_ids:
                keys.append(self._cp_key(caller_h, thread_h, ns_h, cid))
                keys.append(self._writes_key(caller_h, thread_h, ns_h, cid))
        return keys

    async def put_checkpoint(
        self,
        *,
        caller_identity: str,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        parent_checkpoint_id: str | None,
        checkpoint: TypedBlob,
        metadata: TypedBlob,
        channel_versions: Sequence[ChannelVersionRef],
        new_blobs: Sequence[ChannelBlobEntry],
        resumption_window_seconds: int | None = None,
    ) -> int:
        """Persist a checkpoint and its newly written channel blobs; return applied TTL in seconds."""
        _validate_identifier(caller_identity, field_name="caller_identity")
        _validate_identifier(thread_id, field_name="thread_id")
        _validate_identifier(
            checkpoint_ns, field_name="checkpoint_ns", allow_empty=True
        )
        _validate_identifier(checkpoint_id, field_name="checkpoint_id")
        if parent_checkpoint_id is not None:
            _validate_identifier(
                parent_checkpoint_id,
                field_name="parent_checkpoint_id",
                allow_empty=True,
            )

        total_bytes = checkpoint.validate(field_name="checkpoint") + metadata.validate(
            field_name="metadata"
        )
        for ref in channel_versions:
            ref.validate()
        blob_mapping: dict[str, str] = {}
        for entry in new_blobs:
            entry.ref.validate()
            total_bytes += entry.blob.validate(field_name="channel_blob")
            blob_mapping[entry.ref.hash_field()] = json.dumps(
                {"t": entry.blob.type_tag, "b": entry.blob.data_b64},
                separators=(",", ":"),
            )

        if total_bytes > self._max_payload_bytes:
            raise CheckpointPayloadTooLargeError(
                f"checkpoint payload ({total_bytes} bytes) exceeds limit "
                f"({self._max_payload_bytes} bytes)"
            )

        ttl_seconds = compute_checkpoint_ttl_seconds(
            *(
                (resumption_window_seconds,)
                if resumption_window_seconds is not None
                else ()
            ),
            max_ttl_seconds=self._max_ttl_seconds,
        )

        redis = self._require_redis()
        caller_h = _sha256_hex(caller_identity)
        thread_h = _sha256_hex(thread_id)
        ns_h = _sha256_hex(checkpoint_ns)

        cp_hash = {
            "checkpoint_id": checkpoint_id,
            "parent_checkpoint_id": parent_checkpoint_id or "",
            "checkpoint_type": checkpoint.type_tag,
            "checkpoint_b64": checkpoint.data_b64,
            "metadata_type": metadata.type_tag,
            "metadata_b64": metadata.data_b64,
            "channel_versions": json.dumps(
                [r.to_dict() for r in channel_versions], separators=(",", ":")
            ),
        }

        try:
            keys_to_expire = await self._collect_thread_keys_for_ttl(
                redis,
                caller_h,
                thread_h,
                extra_ns=checkpoint_ns,
                extra_cp_id=checkpoint_id,
            )
            threads_key = self._threads_key(caller_h)
            cur_index_ttl = await redis.ttl(threads_key)
            effective_index_ttl = max(
                ttl_seconds,
                int(cur_index_ttl)
                if isinstance(cur_index_ttl, int) and cur_index_ttl > 0
                else 0,
            )

            now_ms = float(int(time.time() * 1000))
            async with redis.pipeline(transaction=True) as pipe:
                pipe.set(self._thread_meta_key(caller_h, thread_h), thread_id)
                pipe.sadd(self._thread_ns_key(caller_h, thread_h), checkpoint_ns)
                if blob_mapping:
                    pipe.hset(
                        self._ns_blobs_key(caller_h, thread_h, ns_h),
                        mapping=blob_mapping,
                    )
                pipe.hset(
                    self._cp_key(caller_h, thread_h, ns_h, checkpoint_id),
                    mapping=cp_hash,
                )
                pipe.zadd(
                    self._ns_ids_key(caller_h, thread_h, ns_h), {checkpoint_id: 0.0}
                )
                pipe.zadd(threads_key, {thread_id: now_ms})
                for key in keys_to_expire:
                    pipe.expire(key, ttl_seconds)
                pipe.expire(threads_key, effective_index_ttl)
                await pipe.execute()
        except CheckpointStoreError:
            raise
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint write failed: {exc}"
            ) from exc

        return ttl_seconds

    async def put_writes(
        self,
        *,
        caller_identity: str,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        writes: Sequence[PendingWriteEntry],
        resumption_window_seconds: int | None = None,
    ) -> int:
        """Persist intermediate task writes for ``checkpoint_id``; return applied TTL in seconds."""
        _validate_identifier(caller_identity, field_name="caller_identity")
        _validate_identifier(thread_id, field_name="thread_id")
        _validate_identifier(
            checkpoint_ns, field_name="checkpoint_ns", allow_empty=True
        )
        _validate_identifier(checkpoint_id, field_name="checkpoint_id")

        total_bytes = 0
        for entry in writes:
            total_bytes += entry.validate()
        if total_bytes > self._max_payload_bytes:
            raise CheckpointPayloadTooLargeError(
                f"checkpoint writes payload ({total_bytes} bytes) exceeds limit "
                f"({self._max_payload_bytes} bytes)"
            )

        ttl_seconds = compute_checkpoint_ttl_seconds(
            *(
                (resumption_window_seconds,)
                if resumption_window_seconds is not None
                else ()
            ),
            max_ttl_seconds=self._max_ttl_seconds,
        )
        if not writes:
            return ttl_seconds

        redis = self._require_redis()
        caller_h = _sha256_hex(caller_identity)
        thread_h = _sha256_hex(thread_id)
        ns_h = _sha256_hex(checkpoint_ns)
        writes_key = self._writes_key(caller_h, thread_h, ns_h, checkpoint_id)

        try:
            keys_to_expire = await self._collect_thread_keys_for_ttl(
                redis,
                caller_h,
                thread_h,
                extra_ns=checkpoint_ns,
                extra_cp_id=checkpoint_id,
            )
            threads_key = self._threads_key(caller_h)
            cur_index_ttl = await redis.ttl(threads_key)
            effective_index_ttl = max(
                ttl_seconds,
                int(cur_index_ttl)
                if isinstance(cur_index_ttl, int) and cur_index_ttl > 0
                else 0,
            )

            now_ms = float(int(time.time() * 1000))
            async with redis.pipeline(transaction=True) as pipe:
                pipe.set(self._thread_meta_key(caller_h, thread_h), thread_id)
                pipe.sadd(self._thread_ns_key(caller_h, thread_h), checkpoint_ns)
                for entry in writes:
                    field = f"{entry.task_id}{_FIELD_SEP}{entry.idx}"
                    encoded = json.dumps(
                        {
                            "task_id": entry.task_id,
                            "idx": entry.idx,
                            "channel": entry.channel,
                            "t": entry.blob.type_tag,
                            "b": entry.blob.data_b64,
                            "task_path": entry.task_path,
                        },
                        separators=(",", ":"),
                    )
                    if entry.idx >= 0:
                        # Regular writes are write-once per (task_id, idx); special
                        # negative indices (ERROR/INTERRUPT/SCHEDULED/RESUME) overwrite.
                        pipe.hsetnx(writes_key, field, encoded)
                    else:
                        pipe.hset(writes_key, field, encoded)
                pipe.zadd(threads_key, {thread_id: now_ms})
                for key in keys_to_expire:
                    pipe.expire(key, ttl_seconds)
                pipe.expire(threads_key, effective_index_ttl)
                await pipe.execute()
        except CheckpointStoreError:
            raise
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint put_writes failed: {exc}"
            ) from exc

        return ttl_seconds

    async def _load_single_checkpoint(
        self,
        redis: Any,
        *,
        caller_h: str,
        thread_id: str,
        thread_h: str,
        checkpoint_ns: str,
        ns_h: str,
        checkpoint_id: str,
    ) -> StoredCheckpoint | None:
        """Pure read of one checkpoint hash + its referenced channel blobs + pending writes."""
        cp_data = await redis.hgetall(
            self._cp_key(caller_h, thread_h, ns_h, checkpoint_id)
        )
        if not cp_data:
            return None

        raw_versions = json.loads(cp_data.get("channel_versions", "[]"))
        refs = [ChannelVersionRef.from_dict(item) for item in raw_versions]
        channel_blobs: list[ChannelBlobEntry] = []
        if refs:
            fields = [r.hash_field() for r in refs]
            raw_blobs = await redis.hmget(
                self._ns_blobs_key(caller_h, thread_h, ns_h), fields
            )
            for ref, raw_val in zip(refs, raw_blobs, strict=False):
                if not raw_val:
                    continue
                decoded = json.loads(raw_val)
                type_tag = str(decoded.get("t", "empty"))
                if type_tag == "empty":
                    continue
                channel_blobs.append(
                    ChannelBlobEntry(
                        ref=ref,
                        blob=TypedBlob(
                            type_tag=type_tag,
                            data_b64=str(decoded.get("b", "")),
                        ),
                    )
                )

        raw_writes = await redis.hgetall(
            self._writes_key(caller_h, thread_h, ns_h, checkpoint_id)
        )
        parsed_writes: list[PendingWriteEntry] = []
        for raw_write in (raw_writes or {}).values():
            w_obj = json.loads(raw_write)
            parsed_writes.append(
                PendingWriteEntry(
                    task_id=str(w_obj["task_id"]),
                    idx=int(w_obj["idx"]),
                    channel=str(w_obj["channel"]),
                    blob=TypedBlob(
                        type_tag=str(w_obj["t"]),
                        data_b64=str(w_obj["b"]),
                    ),
                    task_path=str(w_obj.get("task_path", "")),
                )
            )
        parsed_writes.sort(key=lambda w: (w.task_id, w.idx))

        parent_id = cp_data.get("parent_checkpoint_id") or None
        return StoredCheckpoint(
            thread_id=thread_id,
            checkpoint_ns=checkpoint_ns,
            checkpoint_id=checkpoint_id,
            parent_checkpoint_id=parent_id,
            checkpoint=TypedBlob(
                type_tag=str(cp_data["checkpoint_type"]),
                data_b64=str(cp_data["checkpoint_b64"]),
            ),
            metadata=TypedBlob(
                type_tag=str(cp_data["metadata_type"]),
                data_b64=str(cp_data["metadata_b64"]),
            ),
            channel_blobs=channel_blobs,
            pending_writes=parsed_writes,
        )

    async def get_checkpoint(
        self,
        *,
        caller_identity: str,
        thread_id: str,
        checkpoint_ns: str = "",
        checkpoint_id: str | None = None,
    ) -> StoredCheckpoint | None:
        """Read one checkpoint (or the latest in ``checkpoint_ns``) without refreshing TTL."""
        _validate_identifier(caller_identity, field_name="caller_identity")
        _validate_identifier(thread_id, field_name="thread_id")
        _validate_identifier(
            checkpoint_ns, field_name="checkpoint_ns", allow_empty=True
        )
        if checkpoint_id is not None:
            _validate_identifier(
                checkpoint_id, field_name="checkpoint_id", allow_empty=True
            )

        redis = self._require_redis()
        caller_h = _sha256_hex(caller_identity)
        thread_h = _sha256_hex(thread_id)
        ns_h = _sha256_hex(checkpoint_ns)

        try:
            if checkpoint_id:
                return await self._load_single_checkpoint(
                    redis,
                    caller_h=caller_h,
                    thread_id=thread_id,
                    thread_h=thread_h,
                    checkpoint_ns=checkpoint_ns,
                    ns_h=ns_h,
                    checkpoint_id=checkpoint_id,
                )

            # Walk newest-first in case an older member lingered in the ZSET.
            candidates = await redis.zrevrangebylex(
                self._ns_ids_key(caller_h, thread_h, ns_h), "+", "-"
            )
            for cid in candidates or []:
                found = await self._load_single_checkpoint(
                    redis,
                    caller_h=caller_h,
                    thread_id=thread_id,
                    thread_h=thread_h,
                    checkpoint_ns=checkpoint_ns,
                    ns_h=ns_h,
                    checkpoint_id=str(cid),
                )
                if found is not None:
                    return found
            return None
        except CheckpointStoreError:
            raise
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint read failed: {exc}"
            ) from exc

    async def list_checkpoints(
        self,
        *,
        caller_identity: str,
        thread_id: str | None = None,
        checkpoint_ns: str | None = None,
        checkpoint_id: str | None = None,
        before_checkpoint_id: str | None = None,
        limit: int | None = None,
    ) -> list[StoredCheckpoint]:
        """List checkpoints newest-first for ``caller_identity`` without refreshing TTL."""
        _validate_identifier(caller_identity, field_name="caller_identity")
        if thread_id is not None:
            _validate_identifier(thread_id, field_name="thread_id")
        if checkpoint_ns is not None:
            _validate_identifier(
                checkpoint_ns, field_name="checkpoint_ns", allow_empty=True
            )
        if checkpoint_id is not None:
            _validate_identifier(
                checkpoint_id, field_name="checkpoint_id", allow_empty=True
            )
        if before_checkpoint_id is not None:
            _validate_identifier(
                before_checkpoint_id,
                field_name="before_checkpoint_id",
                allow_empty=True,
            )
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 0
        ):
            raise CheckpointValidationError("limit must be a non-negative integer")
        if limit == 0:
            return []

        redis = self._require_redis()
        caller_h = _sha256_hex(caller_identity)

        try:
            if thread_id is not None:
                thread_ids = [thread_id]
            else:
                raw_threads = await redis.zrevrange(self._threads_key(caller_h), 0, -1)
                thread_ids = [str(t) for t in (raw_threads or [])]

            results: list[StoredCheckpoint] = []
            lex_max = f"({before_checkpoint_id}" if before_checkpoint_id else "+"

            for tid in thread_ids:
                thread_h = _sha256_hex(tid)
                if checkpoint_ns is not None:
                    namespaces = [checkpoint_ns]
                else:
                    raw_ns = await redis.smembers(
                        self._thread_ns_key(caller_h, thread_h)
                    )
                    namespaces = sorted(str(ns) for ns in (raw_ns or set()))

                for ns in namespaces:
                    ns_h = _sha256_hex(ns)
                    if checkpoint_id:
                        if (
                            before_checkpoint_id
                            and checkpoint_id >= before_checkpoint_id
                        ):
                            continue
                        candidate_ids = [checkpoint_id]
                    else:
                        raw_ids = await redis.zrevrangebylex(
                            self._ns_ids_key(caller_h, thread_h, ns_h),
                            lex_max,
                            "-",
                        )
                        candidate_ids = [str(cid) for cid in (raw_ids or [])]

                    for cid in candidate_ids:
                        loaded = await self._load_single_checkpoint(
                            redis,
                            caller_h=caller_h,
                            thread_id=tid,
                            thread_h=thread_h,
                            checkpoint_ns=ns,
                            ns_h=ns_h,
                            checkpoint_id=cid,
                        )
                        if loaded is None:
                            continue
                        results.append(loaded)
                        if limit is not None and len(results) >= limit:
                            return results

            return results
        except CheckpointStoreError:
            raise
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint list failed: {exc}"
            ) from exc

    async def delete_thread(
        self,
        *,
        caller_identity: str,
        thread_id: str,
    ) -> int:
        """Delete all checkpoints, channel blobs, and writes for ``thread_id`` under ``caller_identity``."""
        _validate_identifier(caller_identity, field_name="caller_identity")
        _validate_identifier(thread_id, field_name="thread_id")

        redis = self._require_redis()
        caller_h = _sha256_hex(caller_identity)
        thread_h = _sha256_hex(thread_id)

        try:
            keys_to_delete = await self._collect_thread_keys_for_ttl(
                redis,
                caller_h,
                thread_h,
                extra_ns="",
                extra_cp_id="",
            )
            async with redis.pipeline(transaction=True) as pipe:
                if keys_to_delete:
                    pipe.delete(*keys_to_delete)
                pipe.zrem(self._threads_key(caller_h), thread_id)
                res = await pipe.execute()
            return int(res[0]) if keys_to_delete and res else 0
        except CheckpointStoreError:
            raise
        except Exception as exc:
            raise CheckpointStoreUnavailableError(
                f"checkpoint delete_thread failed: {exc}"
            ) from exc


def _resolve_checkpoint_redis_url() -> str | None:
    """Resolve the gateway's Redis URL from ``CAGE_CHECKPOINT_REDIS_URL`` or ``REDIS_URL``/``REDIS_HOST``."""
    explicit = os.environ.get("CAGE_CHECKPOINT_REDIS_URL", "").strip()
    if explicit:
        return explicit
    url = os.environ.get("REDIS_URL", "").strip()
    if url:
        return url
    host = os.environ.get("REDIS_HOST", "").strip()
    if not host:
        return None
    port = os.environ.get("REDIS_PORT", "6379").strip() or "6379"
    scheme = (
        "rediss"
        if os.environ.get("REDIS_TLS", "").lower() in ("true", "1", "yes")
        else "redis"
    )
    return f"{scheme}://{host}:{port}"


async def start_checkpoint_store_from_env() -> GatewayCheckpointStore:
    """Build and verify the gateway's :class:`GatewayCheckpointStore` at startup.

    Under every enforcing posture (:func:`is_enforcing`), Redis must be
    configured and reachable on ``CAGE_CHECKPOINT_REDIS_DB`` (default ``3``) or
    gateway startup fails closed (:class:`CheckpointStoreUnavailableError`).
    In permissive postures (``dev``, ``test``, ``ci``), an unreachable Redis
    logs a warning and leaves the store returning HTTP 503 if called (never
    falling back to in-memory storage).
    """
    from src.gateway.infrastructure.redis_client import build_async_redis

    enforcing = is_enforcing()
    max_ttl = resolve_max_ttl_seconds()
    # Validate default resumption-window TTL against max_ttl at boot.
    compute_checkpoint_ttl_seconds(max_ttl_seconds=max_ttl)

    raw_db = os.environ.get("CAGE_CHECKPOINT_REDIS_DB", str(_DEFAULT_REDIS_DB)).strip()
    try:
        db = int(raw_db)
    except ValueError as exc:
        raise CheckpointValidationError(
            f"CAGE_CHECKPOINT_REDIS_DB must be an integer, got {raw_db!r}"
        ) from exc

    url = _resolve_checkpoint_redis_url()
    if not url:
        if enforcing:
            raise CheckpointStoreUnavailableError(
                "REDIS_URL/REDIS_HOST is required for gateway checkpoint storage in enforcing postures"
            )
        logger.warning(
            "Gateway checkpoint store disabled: no REDIS_URL/REDIS_HOST configured (permissive posture)"
        )
        return GatewayCheckpointStore(None, max_ttl_seconds=max_ttl, owns_redis=False)

    client = build_async_redis(url, db=db, socket_timeout=5.0)
    store = GatewayCheckpointStore(client, max_ttl_seconds=max_ttl, owns_redis=True)
    try:
        await store.ping()
        logger.info(
            "✅ Gateway checkpoint store connected (db=%d, default_ttl=%ds, max_ttl=%ds)",
            db,
            store.default_ttl_seconds,
            store.max_ttl_seconds,
        )
        return store
    except Exception as exc:
        await store.close()
        if enforcing:
            raise CheckpointStoreUnavailableError(
                f"Gateway checkpoint store failed readiness check on db={db}: {exc}"
            ) from exc
        logger.warning(
            "⚠️ Gateway checkpoint store unreachable on db=%d (permissive posture; endpoints will return 503): %s",
            db,
            exc,
        )
        return GatewayCheckpointStore(None, max_ttl_seconds=max_ttl, owns_redis=False)
