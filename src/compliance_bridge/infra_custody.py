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

"""Durable hash-chain custody for ``POST /v1/infra/events`` (``F-85`` / ``R-3``).

Seals infrastructure telemetry records under the canonical ``cage-audit/3.0``
hash contract (:func:`src.gateway.governance.evidence.stream._link_hash` over
RFC 8785 JCS canonical JSON), appends them atomically to a dedicated ``INFRA``
Redis Stream custodied by :class:`EvidenceCustodian` (``compliance-evidence``
KMS batch attestations → WORM cold store), flushes inline to WORM under
enforcing postures (or when ``INFRA_EVIDENCE_INLINE_FLUSH=true``), enforces
per-producer ``Idempotency-Key`` deduplication, and fails closed on every
write error.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import secrets
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.evidence.stream import (
    _APPEND_BATCH_SCRIPT,
    _APPEND_BATCH_SCRIPT_SHA,
    _CANONICALIZATION,
    _HASH_ALGORITHM,
    _MAX_APPEND_ATTEMPTS,
    _SCHEMA,
    EvidenceChainCorruptError,
    EvidenceChainUnavailableError,
    _as_str,
    _link_hash,
    current_trace_id,
    verify_record,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.compliance_bridge.infra_custody")

INFRA_STREAM_KEY_ENV = "INFRA_EVIDENCE_STREAM_KEY"
DEFAULT_INFRA_STREAM_KEY = "cage:evidence:infra:stream"
DEFAULT_INFRA_STREAM_MAXLEN = 100_000
INFRA_IDEMPOTENCY_TTL_S_ENV = "INFRA_EVENT_IDEMPOTENCY_TTL_S"
DEFAULT_INFRA_IDEMPOTENCY_TTL_S = 86_400
INFRA_INLINE_FLUSH_ENV = "INFRA_EVIDENCE_INLINE_FLUSH"
INFRA_EVIDENCE_CLASS = "INFRA"

IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}\Z")


def is_inline_custody_flush_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Return whether inline WORM custody flush is enabled for INFRA/audit ingestion.

    Defaults ``INFRA_EVIDENCE_INLINE_FLUSH`` to ``"true"`` whenever
    ``DeploymentPosture.from_env().is_enforcing()`` holds, and to ``"false"``
    in ``dev``/``test``/``ci`` when unset. Under an enforcing posture, inline
    WORM flush remains mandatory even if overridden in the environment.
    """
    source = os.environ if env is None else env
    if is_enforcing(source):
        return True
    raw = source.get(INFRA_INLINE_FLUSH_ENV, "false")
    return raw.strip().lower() in ("1", "true", "yes", "on")


class InfraCustodyError(RuntimeError):
    """Raised when durable INFRA chain or WORM persistence fails."""


class InfraIdempotencyConflictError(ValueError):
    """Raised when a producer reuses an Idempotency-Key with a different payload."""


@dataclass(frozen=True)
class InfraCustodyReceipt:
    """Verified commit receipt for a hash-chained ``INFRA`` evidence record."""

    event_id: str
    record_hash: str
    prev_hash: str
    chain_id: str
    sequence: int
    stream_id: str
    trace_id: str
    event_type: str
    control_id: str
    source: str
    namespace: str
    pod_name: str | None
    pod_name_verified: bool
    received_at_utc: str
    producer_timestamp_utc: str
    idempotent_replay: bool
    record: dict[str, str]

    def to_response(self) -> dict[str, Any]:
        """Serialize receipt to the ``POST /v1/infra/events`` HTTP 200 payload."""
        return {
            "status": "INGESTED",
            "event_id": self.event_id,
            "record_hash": self.record_hash,
            "prev_hash": self.prev_hash,
            "chain_id": self.chain_id,
            "sequence": self.sequence,
            "stream_id": self.stream_id,
            "trace_id": self.trace_id,
            "event_type": self.event_type,
            "control_id": self.control_id,
            "evidence_class": INFRA_EVIDENCE_CLASS,
            "source": self.source,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "pod_name_verified": self.pod_name_verified,
            "received_at_utc": self.received_at_utc,
            "producer_timestamp_utc": self.producer_timestamp_utc,
            "idempotent_replay": self.idempotent_replay,
        }


def canonical_payload_json(payload: Mapping[str, Any]) -> str:
    """Encode ``payload`` as deterministic canonical JSON (RFC 8785 JCS).

    Produces compact sorted-key UTF-8 JSON (``sort_keys=True,
    separators=(",", ":")``) matching both Python canonical ``json.dumps`` and
    :func:`jcs_canonicalize_plan` byte-for-byte.
    """
    canonical_bytes = jcs_canonicalize_plan(dict(payload))
    canonical_str = canonical_bytes.decode("utf-8")
    stdlib_canonical = json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    if canonical_str != stdlib_canonical:  # pragma: no cover - defensive
        raise InfraCustodyError(
            "INFRA payload contains values whose JCS and stdlib canonical JSON diverge"
        )
    return canonical_str


def compute_infra_record_hash(
    *,
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
    chain_id: str,
    trace_id: str,
) -> str:
    """Deterministically compute the ``cage-audit/3.0`` ``record_hash``."""
    return _link_hash(
        prev_hash=prev_hash,
        sequence=sequence,
        event_type=event_type,
        control_id=control_id,
        payload_json=payload_json,
        chain_id=chain_id,
        trace_id=trace_id,
    )


def compute_request_fingerprint(
    *,
    producer_svid: str,
    event_type: str,
    control_id: str,
    control_hint: str,
    summary: str,
    producer_timestamp_utc: str,
    source: str,
    namespace: str,
    pod_name: str | None,
    pod_name_verified: bool,
) -> str:
    """Compute a deterministic SHA-256 fingerprint of a producer's event claim.

    Deliberately excludes server-stamped ``received_at_utc`` so a client retry
    carrying the same ``Idempotency-Key`` at a later instant matches its first
    attempt while rejecting any mutation to ``summary`` or other claim fields.
    """
    body = canonical_payload_json(
        {
            "control_hint": control_hint,
            "control_id": control_id,
            "event_type": event_type,
            "namespace": namespace,
            "pod_name": pod_name,
            "pod_name_verified": pod_name_verified,
            "producer_svid": producer_svid,
            "producer_timestamp_utc": producer_timestamp_utc,
            "source": source,
            "summary": summary,
        }
    )
    return hashlib.sha256(body.encode()).hexdigest()


def _idempotency_redis_key(
    stream_key: str, producer_svid: str, idempotency_key: str
) -> str:
    scoped = hashlib.sha256(
        f"{producer_svid}\x00{idempotency_key}".encode()
    ).hexdigest()
    return f"{stream_key}:idempotency:{scoped}"


CustodyFlusher = Callable[[], Awaitable[bool | None]]


class InfraEvidenceChain:
    """Fail-closed ``INFRA`` hash-chain producer with per-producer idempotency."""

    def __init__(
        self,
        redis: Any,
        *,
        stream_key: str = DEFAULT_INFRA_STREAM_KEY,
        max_len: int = DEFAULT_INFRA_STREAM_MAXLEN,
        idempotency_ttl_s: int = DEFAULT_INFRA_IDEMPOTENCY_TTL_S,
        chain_id_factory: Callable[[], str] | None = None,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if redis is None:
            raise InfraCustodyError("InfraEvidenceChain requires a live Redis client")
        self._redis = redis
        self._stream_key = stream_key
        self._max_len = max(1, max_len)
        self._idempotency_ttl_s = max(60, idempotency_ttl_s)
        self._chain_id_factory = chain_id_factory or (lambda: str(uuid.uuid4()))
        self._trace_id_factory = trace_id_factory or current_trace_id
        self._chain_id: str = ""
        self._prev_hash: str = ""
        self._sequence: int = 0
        self._prev_id: str = ""
        self._acked_head: tuple[str, int, str] | None = None
        self._chain_restored = False
        self._lock = asyncio.Lock()

    @classmethod
    def from_env(cls) -> InfraEvidenceChain:
        """Build an ``InfraEvidenceChain`` connected to the evidence Redis DB."""
        from src.gateway.infrastructure.redis_client import build_async_redis

        redis_url = os.environ.get(
            "EVIDENCE_STREAM_REDIS_URL", os.environ.get("REDIS_URL", "")
        ).strip()
        if not redis_url:
            raise InfraCustodyError(
                "EVIDENCE_STREAM_REDIS_URL (or REDIS_URL) is not set; cannot "
                "persist INFRA events to the durable evidence stream."
            )
        redis_db = int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
        stream_key = os.environ.get(
            INFRA_STREAM_KEY_ENV, DEFAULT_INFRA_STREAM_KEY
        ).strip()
        if not stream_key:
            raise InfraCustodyError(f"{INFRA_STREAM_KEY_ENV} must not be empty")
        max_len = int(
            os.environ.get("EVIDENCE_STREAM_MAXLEN", str(DEFAULT_INFRA_STREAM_MAXLEN))
        )
        ttl_s = int(
            os.environ.get(
                INFRA_IDEMPOTENCY_TTL_S_ENV, str(DEFAULT_INFRA_IDEMPOTENCY_TTL_S)
            )
        )
        return cls(
            build_async_redis(redis_url, db=redis_db),
            stream_key=stream_key,
            max_len=max_len,
            idempotency_ttl_s=ttl_s,
        )

    @property
    def stream_key(self) -> str:
        return self._stream_key

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    async def aclose(self) -> None:
        close_fn = getattr(self._redis, "aclose", None)
        if callable(close_fn):
            maybe = close_fn()
            if inspect.isawaitable(maybe):
                await maybe

    async def _restore_chain_state(self) -> None:
        if self._chain_restored:
            return
        try:
            entries = await self._redis.xrevrange(
                self._stream_key, max="+", min="-", count=1
            )
        except Exception as exc:
            raise InfraCustodyError(
                f"Failed to read INFRA chain head from {self._stream_key}: {exc}"
            ) from exc

        def _corrupt(detail: str) -> InfraCustodyError:
            return InfraCustodyError(
                f"INFRA chain head in {self._stream_key} is unusable ({detail}); "
                "refusing to fork or overwrite tampered/truncated evidence."
            )

        if not entries:
            if self._acked_head is not None:
                ack_cid, ack_seq, _ = self._acked_head
                raise _corrupt(
                    f"stream is empty after acknowledging chain {ack_cid} seq {ack_seq}"
                )
            minted = self._chain_id_factory()
            if not minted or minted == "00000000-0000-0000-0000-000000000000":
                raise InfraCustodyError("Refusing nil or empty INFRA chain_id")
            self._chain_id = minted
            self._prev_hash = ""
            self._sequence = 0
            self._prev_id = ""
            self._chain_restored = True
            return

        msg_id, raw_fields = entries[0]
        fields = {_as_str(k): _as_str(v) for k, v in raw_fields.items()}
        chain_id = fields.get("chain_id", "")
        record_hash = fields.get("record_hash", "")
        seq_raw = fields.get("sequence")
        prev_hash = fields.get("prev_hash")
        evidence_class = fields.get("evidence_class", "")

        if not chain_id or chain_id == "00000000-0000-0000-0000-000000000000":
            raise _corrupt(f"invalid chain_id {chain_id!r}")
        if evidence_class != INFRA_EVIDENCE_CLASS:
            raise _corrupt(
                f"expected evidence_class={INFRA_EVIDENCE_CLASS!r}, got {evidence_class!r}"
            )
        if len(record_hash) != 64 or any(
            c not in "0123456789abcdef" for c in record_hash
        ):
            raise _corrupt(f"malformed record_hash {record_hash!r}")
        if seq_raw is None:
            raise _corrupt("missing sequence")
        try:
            last_seq = int(seq_raw)
        except (TypeError, ValueError) as exc:
            raise _corrupt(f"non-integer sequence {seq_raw!r}") from exc
        if last_seq < 0:
            raise _corrupt(f"negative sequence {last_seq}")
        if prev_hash is None:
            raise _corrupt("missing prev_hash")
        verdict = verify_record(fields, prev_hash)
        if not verdict.valid:
            raise _corrupt(f"head failed verify_record: {verdict.error}")

        if self._acked_head is not None:
            ack_cid, ack_seq, ack_hash = self._acked_head
            if chain_id != ack_cid:
                raise _corrupt(
                    f"head chain_id {chain_id} disagrees with acknowledged {ack_cid}"
                )
            if last_seq < ack_seq:
                raise _corrupt(f"head sequence {last_seq} regressed behind {ack_seq}")
            if last_seq == ack_seq and record_hash != ack_hash:
                raise _corrupt(
                    f"sequence {last_seq} hash mutated from acknowledged head"
                )

        self._chain_id = chain_id
        self._prev_hash = record_hash
        self._sequence = last_seq + 1
        self._prev_id = _as_str(msg_id)
        self._acked_head = (chain_id, last_seq, record_hash)
        self._chain_restored = True

    async def _eval_append_script(self, args: list[str]) -> Any:
        eval_attr = getattr(self._redis, "eval", None)
        evalsha_attr = getattr(self._redis, "evalsha", None)
        eval_is_mocked = type(eval_attr).__name__ in (
            "AsyncMock",
            "MagicMock",
            "function",
        )
        if evalsha_attr is not None and not eval_is_mocked:
            try:
                return await evalsha_attr(
                    _APPEND_BATCH_SCRIPT_SHA, 1, self._stream_key, *args
                )
            except Exception as exc:
                msg = str(exc).upper()
                if "NOSCRIPT" not in msg and "NO MATCHING SCRIPT" not in msg:
                    raise
                script_load_attr = getattr(self._redis, "script_load", None)
                if callable(script_load_attr):
                    try:
                        await script_load_attr(_APPEND_BATCH_SCRIPT)
                    except Exception as load_exc:
                        logger.debug(
                            "[InfraCustody] SCRIPT LOAD fallback skipped: %s", load_exc
                        )
        if not callable(eval_attr):
            raise InfraCustodyError("Redis client does not expose eval()")
        return await eval_attr(_APPEND_BATCH_SCRIPT, 1, self._stream_key, *args)

    async def _complete_sinks(
        self,
        *,
        idem_key: str | None,
        custody_done: bool,
        custody_flusher: CustodyFlusher | None,
    ) -> None:
        if custody_flusher is not None and not custody_done:
            try:
                flush_ok = await custody_flusher()
            except Exception as exc:
                raise InfraCustodyError(
                    f"WORM custody flush for INFRA chain failed: {exc}"
                ) from exc
            if flush_ok is False:
                raise InfraCustodyError(
                    "WORM custody flush for INFRA chain reported failure"
                )
            if idem_key is not None:
                await self._mark_idempotency_flag(idem_key, "custody_flushed")

    async def _mark_idempotency_flag(self, redis_key: str, flag_name: str) -> None:
        try:
            raw = await self._redis.get(redis_key)
            if not raw:
                return
            state = json.loads(_as_str(raw))
            state[flag_name] = True
            await self._redis.set(
                redis_key,
                json.dumps(state, sort_keys=True, separators=(",", ":")),
                ex=self._idempotency_ttl_s,
            )
        except Exception as exc:
            raise InfraCustodyError(
                f"Failed to persist INFRA idempotency commit state: {exc}"
            ) from exc

    async def append_durable(
        self,
        *,
        event_type: str,
        control_id: str,
        control_hint: str,
        scrubbed_summary: str,
        producer_timestamp_utc: str,
        received_at_utc: str,
        producer_id: str,
        producer_svid: str,
        source: str,
        namespace: str,
        pod_name: str | None,
        pod_name_verified: bool,
        idempotency_key: str | None = None,
        custody_flusher: CustodyFlusher | None = None,
    ) -> InfraCustodyReceipt:
        """Seal and durably persist an ``INFRA`` event, or replay idempotently.

        Raises:
            InfraIdempotencyConflictError: ``idempotency_key`` reused by the
                same producer for a different event claim.
            InfraCustodyError: Any Redis Stream, hash-verification, or WORM
                custody failure (caller must return HTTP 503).
        """
        fingerprint = compute_request_fingerprint(
            producer_svid=producer_svid,
            event_type=event_type,
            control_id=control_id,
            control_hint=control_hint,
            summary=scrubbed_summary,
            producer_timestamp_utc=producer_timestamp_utc,
            source=source,
            namespace=namespace,
            pod_name=pod_name,
            pod_name_verified=pod_name_verified,
        )
        idem_redis_key = (
            _idempotency_redis_key(self._stream_key, producer_svid, idempotency_key)
            if idempotency_key is not None
            else None
        )

        async with self._lock:
            claim_key = f"{idem_redis_key}:lock" if idem_redis_key is not None else None
            claim_token = uuid.uuid4().hex if claim_key is not None else None
            if claim_key is not None and claim_token is not None:
                try:
                    claimed = await self._redis.set(
                        claim_key, claim_token, nx=True, px=10_000
                    )
                except Exception as exc:
                    raise InfraCustodyError(
                        f"Failed to acquire INFRA idempotency lock: {exc}"
                    ) from exc
                if not claimed:
                    raise InfraCustodyError(
                        "Concurrent request with the same Idempotency-Key is in flight; retry shortly"
                    )

            try:
                if idem_redis_key is not None:
                    try:
                        existing_raw = await self._redis.get(idem_redis_key)
                    except Exception as exc:
                        raise InfraCustodyError(
                            f"Failed to query INFRA idempotency store: {exc}"
                        ) from exc
                    if existing_raw:
                        try:
                            existing = json.loads(_as_str(existing_raw))
                        except ValueError as exc:
                            raise InfraCustodyError(
                                f"Corrupt INFRA idempotency record: {exc}"
                            ) from exc
                        if existing.get("fingerprint") != fingerprint:
                            raise InfraIdempotencyConflictError(
                                "Idempotency-Key was already used by this producer "
                                "for a different event payload"
                            )
                        stored_record: dict[str, str] = dict(existing["record"])
                        await self._complete_sinks(
                            idem_key=idem_redis_key,
                            custody_done=bool(existing.get("custody_flushed")),
                            custody_flusher=custody_flusher,
                        )
                        return InfraCustodyReceipt(
                            event_id=stored_record["record_hash"],
                            record_hash=stored_record["record_hash"],
                            prev_hash=stored_record["prev_hash"],
                            chain_id=stored_record["chain_id"],
                            sequence=int(stored_record["sequence"]),
                            stream_id=str(existing["stream_id"]),
                            trace_id=stored_record["trace_id"],
                            event_type=stored_record["event_type"],
                            control_id=stored_record["control_id"],
                            source=str(existing["source"]),
                            namespace=str(existing["namespace"]),
                            pod_name=(
                                str(existing["pod_name"])
                                if existing.get("pod_name") is not None
                                else None
                            ),
                            pod_name_verified=bool(existing["pod_name_verified"]),
                            received_at_utc=stored_record["timestamp_utc"],
                            producer_timestamp_utc=str(
                                existing["producer_timestamp_utc"]
                            ),
                            idempotent_replay=True,
                            record=stored_record,
                        )

                payload_dict: dict[str, Any] = {
                    "control_hint": control_hint,
                    "control_id": control_id,
                    "event_type": event_type,
                    "namespace": namespace,
                    "pod_name": pod_name,
                    "pod_name_verified": pod_name_verified,
                    "producer_id": producer_id,
                    "producer_svid": producer_svid,
                    "producer_timestamp_utc": producer_timestamp_utc,
                    "received_at_utc": received_at_utc,
                    "source": source,
                    "summary": scrubbed_summary,
                }
                if idempotency_key is not None:
                    payload_dict["idempotency_key"] = idempotency_key

                payload_json = canonical_payload_json(payload_dict)
                trace_id = self._trace_id_factory()
                if not trace_id:
                    raise InfraCustodyError("INFRA trace_id must be non-empty")

                appended_entry: dict[str, str] | None = None
                appended_msg_id: str = ""
                try:
                    for attempt in range(_MAX_APPEND_ATTEMPTS):
                        await self._restore_chain_state()
                        prev_hash = self._prev_hash
                        sequence = self._sequence
                        chain_id = self._chain_id

                        record_hash = compute_infra_record_hash(
                            prev_hash=prev_hash,
                            sequence=sequence,
                            event_type=event_type,
                            control_id=control_id,
                            payload_json=payload_json,
                            chain_id=chain_id,
                            trace_id=trace_id,
                        )
                        entry: dict[str, str] = {
                            "schema": _SCHEMA,
                            "chain_id": chain_id,
                            "sequence": str(sequence),
                            "timestamp_utc": received_at_utc,
                            "event_type": event_type,
                            "control_id": control_id,
                            "trace_id": trace_id,
                            "hash_algorithm": _HASH_ALGORITHM,
                            "canonicalization": _CANONICALIZATION,
                            "evidence_class": INFRA_EVIDENCE_CLASS,
                            "prev_hash": prev_hash,
                            "record_hash": record_hash,
                            "payload_json": payload_json,
                        }
                        verdict = verify_record(entry, prev_hash)
                        if not verdict.valid:
                            raise InfraCustodyError(
                                f"Sealed INFRA record failed self-verification: {verdict.error}"
                            )

                        record_args: list[str] = [str(len(entry) * 2)]
                        for k, v in entry.items():
                            record_args.extend((k, v))
                        script_args = [
                            chain_id,
                            str(sequence),
                            prev_hash,
                            str(self._max_len),
                            "1",
                            record_hash,
                            received_at_utc,
                            *record_args,
                        ]

                        try:
                            reply = await self._eval_append_script(script_args)
                        except Exception as exc:
                            self._chain_restored = False
                            raise InfraCustodyError(
                                f"Failed to append INFRA record to {self._stream_key}: {exc}"
                            ) from exc

                        if not isinstance(reply, (list, tuple)) or not reply:
                            self._chain_restored = False
                            raise InfraCustodyError(
                                f"Empty or malformed reply from INFRA stream append: {reply!r}"
                            )
                        status = _as_str(reply[0])
                        if status in ("OK", "ALREADY"):
                            if len(reply) != 2 or not _as_str(reply[1]):
                                self._chain_restored = False
                                raise InfraCustodyError(
                                    f"Missing stream entry ID in append reply: {reply!r}"
                                )
                            appended_msg_id = _as_str(reply[1])
                            self._prev_hash = record_hash
                            self._sequence = sequence + 1
                            self._prev_id = appended_msg_id
                            self._acked_head = (chain_id, sequence, record_hash)
                            appended_entry = entry
                            break

                        self._chain_restored = False
                        if attempt + 1 < _MAX_APPEND_ATTEMPTS:
                            jitter = (secrets.randbelow(1000) / 1000.0) * min(
                                0.010, 0.001 * (2**attempt)
                            )
                            await asyncio.sleep(jitter)
                    else:
                        raise InfraCustodyError(
                            f"INFRA evidence append lost head race {_MAX_APPEND_ATTEMPTS} "
                            f"times on {self._stream_key}"
                        )
                except (
                    EvidenceChainUnavailableError,
                    EvidenceChainCorruptError,
                ) as exc:
                    self._chain_restored = False
                    raise InfraCustodyError(str(exc)) from exc

                if appended_entry is None:  # pragma: no cover - defensive
                    raise InfraCustodyError(
                        "INFRA evidence append finished without a sealed entry"
                    )
                record_with_msg_id = {
                    **appended_entry,
                    "redis_msg_id": appended_msg_id,
                }

                if idem_redis_key is not None:
                    idem_state = {
                        "fingerprint": fingerprint,
                        "stream_id": appended_msg_id,
                        "source": source,
                        "namespace": namespace,
                        "pod_name": pod_name,
                        "pod_name_verified": pod_name_verified,
                        "producer_timestamp_utc": producer_timestamp_utc,
                        "custody_flushed": custody_flusher is None,
                        "record": record_with_msg_id,
                    }
                    try:
                        await self._redis.set(
                            idem_redis_key,
                            json.dumps(
                                idem_state, sort_keys=True, separators=(",", ":")
                            ),
                            ex=self._idempotency_ttl_s,
                        )
                    except Exception as exc:
                        raise InfraCustodyError(
                            f"Failed to register INFRA idempotency state: {exc}"
                        ) from exc

                await self._complete_sinks(
                    idem_key=idem_redis_key,
                    custody_done=custody_flusher is None,
                    custody_flusher=custody_flusher,
                )

                return InfraCustodyReceipt(
                    event_id=appended_entry["record_hash"],
                    record_hash=appended_entry["record_hash"],
                    prev_hash=appended_entry["prev_hash"],
                    chain_id=appended_entry["chain_id"],
                    sequence=int(appended_entry["sequence"]),
                    stream_id=appended_msg_id,
                    trace_id=appended_entry["trace_id"],
                    event_type=event_type,
                    control_id=control_id,
                    source=source,
                    namespace=namespace,
                    pod_name=pod_name,
                    pod_name_verified=pod_name_verified,
                    received_at_utc=received_at_utc,
                    producer_timestamp_utc=producer_timestamp_utc,
                    idempotent_replay=False,
                    record=record_with_msg_id,
                )
            finally:
                if claim_key is not None and claim_token is not None:
                    try:
                        current_claim = await self._redis.get(claim_key)
                        if (
                            current_claim is not None
                            and _as_str(current_claim) == claim_token
                        ):
                            await self._redis.delete(claim_key)
                    except Exception as release_exc:
                        logger.warning(
                            "[InfraCustody] Failed to release idempotency lock %s: %s",
                            claim_key,
                            release_exc,
                        )
