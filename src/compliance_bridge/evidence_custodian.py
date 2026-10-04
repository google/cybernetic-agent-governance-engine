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

"""evidence_custodian.py — WORM custody of the gateway evidence stream (Layer 3)

The gateway's ``EvidenceStreamSink`` hash-chains governance evidence into a
Redis Stream and holds no signing key. This module is the other half: the
compliance bridge reads that stream, **independently re-verifies** the hash
chain, signs one batch attestation per batch with ``EVIDENCE_KMS_KEY``, writes
both to the WORM cold store, and only then advances a durable cursor.

Custody cycle (:meth:`EvidenceCustodian.flush_once`)
----------------------------------------------------
1. Read the cursor hash ``<stream_key>:custody`` (``last_id``,
   ``last_record_hash``, ``last_sequence``, ``chain_id``, ``pending_end_id``).
2. ``XRANGE`` entries after ``last_id``. If ``pending_end_id`` is set, a
   previous cycle failed mid-write; the range is bounded to it so the retry
   reproduces the same object keys and bytes.
3. Keep only the prefix that shares the first entry's ``chain_id`` (a chain
   rotation starts a new batch on the next cycle).
4. Continuity check against the cursor. A sequence jump on the same chain, or
   a first-ever batch that does not start at genesis, is a **gap**: records
   were trimmed (``EVIDENCE_STREAM_MAX_LEN``) before custody. The batch is
   still written — the remaining evidence must not be lost too — but the gap
   is recorded in the attestation, logged CRITICAL and counted. A new
   ``chain_id`` starting at sequence 0 with an empty ``prev_hash`` is a clean
   rotation.
5. Re-verify every record's hash and ``prev_hash`` link. Any mismatch raises
   :class:`EvidenceCustodyIntegrityError`: nothing is written and the cursor
   does not move, so custody stays stuck until an operator investigates.
6. Sign the attestation. Under an enforcing posture a signing failure writes
   nothing and does not advance. In a permissive posture without an active
   signer the attestation is written **non-evidentiary** (see below).
7. ``put_if_absent`` the NDJSON batch, then its attestation, each through
   :func:`~src.gateway.governance.evidence.cold_store.put_if_absent_verified`:
   a pre-existing object is read back and must hold the same bytes (for the
   attestation: the same body, ignoring the non-deterministic signature).
   Anything else is an integrity failure, never a silent "already written".
8. Advance the cursor and clear ``pending_end_id``.

Object layout
-------------
``evidence-stream/YYYY/MM/DD/<chain_id>/<first:012d>-<last:012d>.ndjson`` and
``<same>.attestation.json``. The date comes from the first entry's Redis
stream ID, and each NDJSON line is the entry's fields plus ``stream_id``
serialized with sorted keys, so a retry produces identical bytes and the
existing object is accepted as the idempotent result.

Unsigned attestations are not evidence
--------------------------------------
Every attestation carries ``signature_status`` (``SIGNED`` | ``UNSIGNED``)
and ``evidentiary`` (``true`` only when signed; the flag is inside the signed
body). An unsigned attestation — only possible in dev/test/ci — is written
under a distinct key, ``<same>.attestation.unsigned.json``, with object
metadata ``evidentiary=false``, and counted as
``cage_evidence_custody_batches_total{outcome="written_unsigned"}``. Anything
that cites an attestation as evidence (OSCAL, POAM closure, audit export)
must pass it through :func:`assert_citable`, which fails closed on it.
:mod:`src.compliance_bridge.evidence_verifier` performs the full read-back
verification (kid-resolved signature, object binding, record re-verification
and cross-batch continuity).

Environment variables
---------------------
  EVIDENCE_STREAM_ENABLED        — custody runs only when "true"
  EVIDENCE_STREAM_REDIS_URL/_DB  — must match the gateway (default DB 1)
  EVIDENCE_STREAM_KEY            — must match the gateway
  EVIDENCE_CUSTODY_INTERVAL_S    — seconds between cycles (default 60)
  EVIDENCE_CUSTODY_BATCH_SIZE    — max entries per batch (default 5000)
  EVIDENCE_COLD_STORE            — gcs | s3 | null (null forbidden when enforcing)
  EVIDENCE_KMS_KEY               — attestation signing key (required when enforcing)
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.evidence.cold_store import (
    ColdStoreIntegrityError,
    EvidenceColdStore,
    put_if_absent_verified,
)
from src.gateway.governance.evidence.stream import verify_record

logger = logging.getLogger("cage.compliance_bridge.evidence_custodian")

ATTESTATION_SCHEMA = "cage-evidence-batch/1"
# Every evidence-stream payload is PII-sanitized before it is hash-chained
# (EvidenceStreamSink._append), so custodied objects are Internal and
# PII-sanitized — not PII-free by construction for every possible input; see
# docs/architecture/EVIDENCE_CHAIN.md for the sanitizer's coverage limits.
DATA_CLASSIFICATION = "internal-pii-sanitized"
DEFAULT_STREAM_KEY = "cage:evidence:stream"
DEFAULT_BATCH_SIZE = 5000
DEFAULT_INTERVAL_S = 60.0

_PROM_AVAILABLE = False
try:
    from prometheus_client import REGISTRY, Counter

    def _counter(name: str, doc: str, labels: list[str] | None = None) -> Any:
        try:
            return Counter(name, doc, labels or [])
        except ValueError:
            return REGISTRY._names_to_collectors.get(name)

    CUSTODY_BATCHES_TOTAL = _counter(
        "cage_evidence_custody_batches_total",
        "Evidence custody cycles by outcome",
        ["outcome"],
    )
    CUSTODY_GAPS_TOTAL = _counter(
        "cage_evidence_custody_gaps_total",
        "Batches whose first record did not continue the custodied chain",
    )
    COLD_STORE_WRITES_TOTAL = _counter(
        "cage_evidence_cold_store_writes_total",
        "Evidence cold store writes by backend and outcome",
        ["backend", "outcome"],
    )
    _PROM_AVAILABLE = True
except ImportError:  # pragma: no cover - prometheus_client is a runtime dep
    pass


class EvidenceCustodyIntegrityError(Exception):
    """A stream record failed hash or link re-verification.

    Custody refuses to write or advance past it. This is a tamper or
    corruption signal and requires operator investigation.
    """


class EvidenceCustodyConfigError(Exception):
    """The custodian cannot run safely with the current configuration."""


class NonEvidentiaryAttestationError(Exception):
    """An attestation was offered as evidence but is unsigned or malformed."""


SIGNED = "SIGNED"
UNSIGNED = "UNSIGNED"


def assert_citable(attestation: dict[str, Any]) -> None:
    """Fail closed unless ``attestation`` may be cited as evidence.

    Checks the structural markers only: schema, ``signature_status`` of
    ``SIGNED``, ``evidentiary`` true, and a complete ``signature`` object.
    Cryptographic verification is separate:
    :class:`~src.compliance_bridge.evidence_verifier.CustodyVerifier` resolves
    the public key by ``signature.key_id`` from independently loaded trust
    anchors, never from the document itself.

    Raises:
        NonEvidentiaryAttestationError: The attestation is unsigned, marked
            non-evidentiary, or missing signature fields.
    """
    if attestation.get("schema") != ATTESTATION_SCHEMA:
        raise NonEvidentiaryAttestationError(
            f"unknown attestation schema {attestation.get('schema')!r}"
        )
    if attestation.get("signature_status") != SIGNED:
        raise NonEvidentiaryAttestationError(
            "attestation is UNSIGNED (permissive posture); it is not evidence"
        )
    if attestation.get("evidentiary") is not True:
        raise NonEvidentiaryAttestationError("attestation is marked non-evidentiary")
    signature = attestation.get("signature")
    if not isinstance(signature, dict) or not all(
        isinstance(signature.get(k), str) and signature.get(k)
        for k in ("algorithm", "key_id", "value")
    ):
        raise NonEvidentiaryAttestationError("attestation signature is incomplete")


class AttestationSigner(Protocol):
    """The subset of ``KMSGovernanceSigner`` the custodian needs."""

    @property
    def is_kms_active(self) -> bool: ...

    @property
    def key_id(self) -> str: ...

    @property
    def signing_algorithm(self) -> str: ...

    def sign(self, plan: dict[str, Any]) -> str: ...


class CustodyStatus(enum.Enum):
    """Outcome of one custody cycle."""

    IDLE = "idle"  # nothing new in the stream
    WRITTEN = "written"  # batch and attestation persisted, cursor advanced


@dataclass(frozen=True)
class CustodyOutcome:
    """Result of :meth:`EvidenceCustodian.flush_once`."""

    status: CustodyStatus
    entries: int = 0
    data_key: str = ""
    attestation_key: str = ""
    first_sequence: int = -1
    last_sequence: int = -1
    gap: bool = False
    evidentiary: bool = False


def _cursor_key(stream_key: str) -> str:
    return f"{stream_key}:custody"


def _stream_id_date(stream_id: str) -> str:
    millis = int(stream_id.split("-", 1)[0])
    return datetime.fromtimestamp(millis / 1000, tz=timezone.utc).strftime("%Y/%m/%d")


def _ndjson(entries: list[tuple[str, dict[str, str]]]) -> bytes:
    lines = [
        json.dumps(
            {**fields, "stream_id": stream_id}, sort_keys=True, separators=(",", ":")
        )
        for stream_id, fields in entries
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _same_attestation_body(stored: bytes, supplied: bytes) -> bool:
    """True if two attestations differ at most in their signature value.

    KMS ECDSA signatures are randomized, so a retry after a crash between the
    attestation write and the cursor update re-signs an identical body. That
    is the same evidence; any other difference is a conflict.
    """
    try:
        stored_body = json.loads(stored)
        supplied_body = json.loads(supplied)
    except ValueError:
        return False
    if not isinstance(stored_body, dict) or not isinstance(supplied_body, dict):
        return False
    stored_body.pop("signature", None)
    supplied_body.pop("signature", None)
    return stored_body == supplied_body


class EvidenceCustodian:
    """Moves verified evidence from the Redis Stream into WORM storage.

    Args:
        redis: ``redis.asyncio`` client with ``decode_responses=True``.
        cold_store: WORM backend (``put_if_absent`` must be atomic).
        signer: Attestation signer (``EVIDENCE_KMS_KEY``). May be ``None`` or
            inactive only when ``require_signature`` is false.
        stream_key: Redis Stream key shared with the gateway.
        batch_size: Maximum entries per batch.
        require_signature: Refuse to write unsigned attestations.
        interval_s: Sleep between cycles in :meth:`run_forever`.
    """

    def __init__(
        self,
        redis: Any,
        cold_store: EvidenceColdStore,
        signer: AttestationSigner | None = None,
        *,
        stream_key: str = DEFAULT_STREAM_KEY,
        batch_size: int = DEFAULT_BATCH_SIZE,
        require_signature: bool,
        interval_s: float = DEFAULT_INTERVAL_S,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if is_enforcing() and cold_store.backend_id == "null":
            # EVIDENCE_COLD_STORE defaults to null when unset; a null store
            # silently discards custodied evidence (including retained state
            # preimages), so it is refused at composition time.
            raise EvidenceCustodyConfigError(
                "EVIDENCE_COLD_STORE=null (or unset) is forbidden under an "
                "enforcing posture; evidence custody needs a WORM backend (gcs or s3)."
            )
        if require_signature and (signer is None or not signer.is_kms_active):
            raise EvidenceCustodyConfigError(
                "Evidence custody requires an active KMS attestation signer "
                "(EVIDENCE_KMS_KEY) under an enforcing posture."
            )
        self._redis = redis
        self._cold_store = cold_store
        self._signer = signer
        self._stream_key = stream_key
        self._cursor_key = _cursor_key(stream_key)
        self._batch_size = batch_size
        self._require_signature = require_signature
        self._interval_s = interval_s

    # -- construction -------------------------------------------------------

    @classmethod
    def from_env(cls) -> EvidenceCustodian:
        """Build a custodian from the environment, failing closed when enforcing.

        Raises:
            EvidenceCustodyConfigError: Enforcing posture with a ``null`` cold
                store, or without an active ``EVIDENCE_KMS_KEY`` signer.
        """
        from src.gateway.governance.evidence.factory import get_cold_store
        from src.gateway.infrastructure.redis_client import build_async_redis

        from .kms_batch_signer import build_evidence_signer

        enforcing = is_enforcing()
        redis_url = os.environ.get(
            "EVIDENCE_STREAM_REDIS_URL", os.environ.get("REDIS_URL", "")
        )
        if not redis_url:
            raise EvidenceCustodyConfigError(
                "EVIDENCE_STREAM_REDIS_URL is not set; the custodian cannot read "
                "the evidence stream."
            )

        cold_store = get_cold_store()
        if enforcing and cold_store.backend_id == "null":
            raise EvidenceCustodyConfigError(
                "EVIDENCE_COLD_STORE=null is forbidden under an enforcing posture; "
                "evidence custody needs a WORM backend (gcs or s3)."
            )

        try:
            signer = build_evidence_signer()
        except RuntimeError as exc:
            raise EvidenceCustodyConfigError(str(exc)) from exc

        return cls(
            redis=build_async_redis(
                redis_url, db=int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
            ),
            cold_store=cold_store,
            signer=signer,
            stream_key=os.environ.get("EVIDENCE_STREAM_KEY", DEFAULT_STREAM_KEY),
            batch_size=int(
                os.environ.get("EVIDENCE_CUSTODY_BATCH_SIZE", str(DEFAULT_BATCH_SIZE))
            ),
            require_signature=enforcing,
            interval_s=float(
                os.environ.get("EVIDENCE_CUSTODY_INTERVAL_S", str(DEFAULT_INTERVAL_S))
            ),
        )

    # -- custody cycle ------------------------------------------------------

    async def flush_once(self) -> CustodyOutcome:
        """Run one custody cycle. See the module docstring for the algorithm.

        Raises:
            EvidenceCustodyIntegrityError: A record failed re-verification.
            RuntimeError: Signing failed while signatures are required.
            ColdStoreError: The WORM write failed (cursor not advanced).
        """
        cursor = await self._redis.hgetall(self._cursor_key)
        last_id = cursor.get("last_id", "")
        pending_end_id = cursor.get("pending_end_id", "")

        entries = await self._redis.xrange(
            self._stream_key,
            min=f"({last_id}" if last_id else "-",
            max=pending_end_id or "+",
            count=self._batch_size,
        )
        if not entries:
            if pending_end_id:
                # The pending range was trimmed away entirely; nothing to retry.
                await self._redis.hdel(self._cursor_key, "pending_end_id")
            if _PROM_AVAILABLE:
                CUSTODY_BATCHES_TOTAL.labels(outcome="idle").inc()
            return CustodyOutcome(status=CustodyStatus.IDLE)

        chain_id = entries[0][1].get("chain_id", "")
        # Stop at the first chain change so a batch never spans two chains.
        batch = entries
        for i, (_sid, fields) in enumerate(entries):
            if fields.get("chain_id", "") != chain_id:
                batch = entries[:i]
                break

        first_seq, gap, expected = self._check_continuity(cursor, batch)
        self._verify_batch(batch)

        last_stream_id, last_fields = batch[-1]
        last_seq = int(last_fields["sequence"])
        content = _ndjson(batch)
        content_sha256 = hashlib.sha256(content).hexdigest()
        base = (
            f"evidence-stream/{_stream_id_date(batch[0][0])}/{chain_id}/"
            f"{first_seq:012d}-{last_seq:012d}"
        )
        data_key = f"{base}.ndjson"
        attestation: dict[str, Any] = {
            "schema": ATTESTATION_SCHEMA,
            "chain_id": chain_id,
            "stream_key": self._stream_key,
            "first_sequence": first_seq,
            "last_sequence": last_seq,
            "first_stream_id": batch[0][0],
            "last_stream_id": last_stream_id,
            "first_prev_hash": batch[0][1].get("prev_hash", ""),
            "last_record_hash": last_fields["record_hash"],
            "entries_count": len(batch),
            "content_sha256": content_sha256,
            "data_key": data_key,
            "gap": {"detected": gap, **expected} if gap else {"detected": False},
            # Signed body asserts it is evidence; flipped below if unsigned.
            "signature_status": SIGNED,
            "evidentiary": True,
        }
        signature = await self._sign(attestation)
        if signature is None:
            attestation["signature_status"] = UNSIGNED
            attestation["evidentiary"] = False
            attestation_key = f"{base}.attestation.unsigned.json"
        else:
            attestation_key = f"{base}.attestation.json"
        attestation["signature"] = signature
        evidentiary = "true" if signature is not None else "false"
        attestation_bytes = json.dumps(
            attestation, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        # Mark the range before writing so a crash retries the same bytes.
        await self._redis.hset(
            self._cursor_key, mapping={"pending_end_id": last_stream_id}
        )

        await self._put(
            data_key,
            content,
            {
                "content-type": "application/x-ndjson",
                "chain-id": chain_id,
                "first-sequence": str(first_seq),
                "last-sequence": str(last_seq),
                "content-sha256": content_sha256,
                "evidentiary": evidentiary,
                "x-data-classification": DATA_CLASSIFICATION,
            },
        )
        await self._put(
            attestation_key,
            attestation_bytes,
            {
                "content-type": "application/json",
                "data-key": data_key,
                "evidentiary": evidentiary,
                "x-data-classification": DATA_CLASSIFICATION,
            },
            equivalent=_same_attestation_body,
        )

        await self._redis.hset(
            self._cursor_key,
            mapping={
                "last_id": last_stream_id,
                "last_record_hash": last_fields["record_hash"],
                "last_sequence": str(last_seq),
                "chain_id": chain_id,
            },
        )
        await self._redis.hdel(self._cursor_key, "pending_end_id")

        if _PROM_AVAILABLE:
            CUSTODY_BATCHES_TOTAL.labels(
                outcome="written" if signature is not None else "written_unsigned"
            ).inc()
        logger.info(
            "[EvidenceCustodian] Custodied %d records chain=%s seq=%d..%d → %s",
            len(batch),
            chain_id,
            first_seq,
            last_seq,
            data_key,
        )
        return CustodyOutcome(
            status=CustodyStatus.WRITTEN,
            entries=len(batch),
            data_key=data_key,
            attestation_key=attestation_key,
            first_sequence=first_seq,
            last_sequence=last_seq,
            gap=gap,
            evidentiary=signature is not None,
        )

    def _check_continuity(
        self,
        cursor: dict[str, str],
        batch: list[tuple[str, dict[str, str]]],
    ) -> tuple[int, bool, dict[str, Any]]:
        """Return ``(first_sequence, gap, expected)`` for the batch head."""
        first = batch[0][1]
        try:
            first_seq = int(first["sequence"])
        except (KeyError, ValueError) as exc:
            raise EvidenceCustodyIntegrityError(
                f"Record {batch[0][0]} has no integer sequence."
            ) from exc
        first_prev = first.get("prev_hash", "")
        chain_id = first.get("chain_id", "")
        is_genesis = first_seq == 0 and first_prev == ""

        cursor_chain = cursor.get("chain_id", "")
        if cursor_chain and cursor_chain == chain_id:
            expected_seq = int(cursor["last_sequence"]) + 1
            expected_prev = cursor.get("last_record_hash", "")
            if first_seq == expected_seq and first_prev == expected_prev:
                return first_seq, False, {}
            if first_seq == expected_seq:
                # Same position, different link: this is not trimming.
                raise EvidenceCustodyIntegrityError(
                    f"Chain {chain_id} seq {first_seq}: prev_hash does not match "
                    "the last custodied record_hash."
                )
            if first_seq < expected_seq:
                raise EvidenceCustodyIntegrityError(
                    f"Chain {chain_id} went backwards: seq {first_seq} after "
                    f"custodied seq {expected_seq - 1}."
                )
            expected = {
                "expected_sequence": expected_seq,
                "expected_prev_hash": expected_prev,
            }
        elif is_genesis:
            if cursor_chain:
                logger.warning(
                    "[EvidenceCustodian] Chain rotation %s → %s at genesis.",
                    cursor_chain,
                    chain_id,
                )
            return first_seq, False, {}
        else:
            # First-ever batch, or a new chain, that does not start at genesis.
            expected = {"expected_sequence": 0, "expected_prev_hash": ""}

        logger.critical(
            "[EvidenceCustodian] GAP: chain %s resumes at seq %d (expected %s). "
            "Records were trimmed from the stream before custody.",
            chain_id,
            first_seq,
            expected["expected_sequence"],
        )
        if _PROM_AVAILABLE:
            CUSTODY_GAPS_TOTAL.inc()
        return first_seq, True, expected

    def _verify_batch(self, batch: list[tuple[str, dict[str, str]]]) -> None:
        """Re-verify every record hash and link; raise on the first failure."""
        prev_hash = batch[0][1].get("prev_hash", "")
        prev_seq: int | None = None
        for stream_id, fields in batch:
            if fields.get("prev_hash", "") != prev_hash:
                self._integrity_failure(
                    stream_id, "prev_hash does not link to prior record"
                )
            seq = int(fields.get("sequence", "-1"))
            if prev_seq is not None and seq != prev_seq + 1:
                self._integrity_failure(
                    stream_id, f"sequence {seq} does not follow {prev_seq}"
                )
            result = verify_record(fields, prev_hash=prev_hash)
            if not result.valid:
                self._integrity_failure(
                    stream_id, result.error or "record_hash mismatch"
                )
            prev_hash = fields["record_hash"]
            prev_seq = seq

    def _integrity_failure(self, stream_id: str, detail: str) -> None:
        if _PROM_AVAILABLE:
            CUSTODY_BATCHES_TOTAL.labels(outcome="integrity_failure").inc()
        logger.critical(
            "[EvidenceCustodian] INTEGRITY FAILURE at %s on %s: %s. Custody halted; "
            "nothing written, cursor not advanced.",
            stream_id,
            self._stream_key,
            detail,
        )
        raise EvidenceCustodyIntegrityError(f"{stream_id}: {detail}")

    async def _sign(self, attestation: dict[str, Any]) -> dict[str, str] | None:
        signer = self._signer
        if signer is None or not signer.is_kms_active:
            if self._require_signature:  # pragma: no cover - blocked in __init__
                raise RuntimeError("Attestation signer is not active.")
            logger.warning(
                "[EvidenceCustodian] Writing UNSIGNED, non-evidentiary attestation "
                "(permissive posture, no active EVIDENCE_KMS_KEY signer)."
            )
            return None
        try:
            value = await asyncio.to_thread(signer.sign, dict(attestation))
        except Exception as exc:
            if _PROM_AVAILABLE:
                CUSTODY_BATCHES_TOTAL.labels(outcome="sign_failure").inc()
            if self._require_signature:
                raise RuntimeError(
                    f"Evidence attestation signing failed: {exc}. Nothing written."
                ) from exc
            logger.warning(
                "[EvidenceCustodian] Signing failed (%s); writing UNSIGNED, "
                "non-evidentiary attestation (permissive posture).",
                exc,
            )
            return None
        return {
            "algorithm": signer.signing_algorithm,
            "key_id": signer.key_id,
            "value": value,
        }

    async def _put(
        self,
        key: str,
        content: bytes,
        metadata: dict[str, str],
        *,
        equivalent: Any = None,
    ) -> None:
        backend = self._cold_store.backend_id
        try:
            _receipt, created = await put_if_absent_verified(
                self._cold_store,
                key,
                content,
                metadata,
                equivalent=equivalent,
            )
        except ColdStoreIntegrityError as exc:
            if _PROM_AVAILABLE:
                COLD_STORE_WRITES_TOTAL.labels(
                    backend=backend, outcome="conflict"
                ).inc()
            self._integrity_failure(key, str(exc))
        except Exception:
            if _PROM_AVAILABLE:
                COLD_STORE_WRITES_TOTAL.labels(backend=backend, outcome="error").inc()
            raise
        if _PROM_AVAILABLE:
            COLD_STORE_WRITES_TOTAL.labels(
                backend=backend, outcome="created" if created else "exists"
            ).inc()

    # -- loop ---------------------------------------------------------------

    async def run_forever(self) -> None:
        """Run custody cycles until cancelled.

        A full batch loops immediately to drain backlog. An integrity failure
        keeps retrying on the interval without ever advancing past the bad
        record, so the stuck cursor and the CRITICAL log remain visible.
        """
        while True:
            try:
                outcome = await self.flush_once()
                if outcome.entries >= self._batch_size:
                    continue
            except asyncio.CancelledError:
                raise
            except EvidenceCustodyIntegrityError as exc:
                # Already logged CRITICAL in _integrity_failure; stay halted.
                logger.debug("[EvidenceCustodian] Custody still halted: %s", exc)
            except Exception as exc:
                if _PROM_AVAILABLE:
                    CUSTODY_BATCHES_TOTAL.labels(outcome="error").inc()
                logger.error("[EvidenceCustodian] Custody cycle failed: %s", exc)
            await asyncio.sleep(self._interval_s)

    async def aclose(self) -> None:
        """Close the Redis connection."""
        close = getattr(self._redis, "aclose", None)
        if close is not None:
            await close()
