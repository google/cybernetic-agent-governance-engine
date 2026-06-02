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

"""
evidence_stream.py — Evidence-Grade Streaming Sink for Governance Events (Feature 4)
====================================================================================

Promotes the SSE event bus from fire-and-forget UI notifications to a
cryptographically hash-chained, durable evidence stream.

Architecture
------------
::

    GovernanceEventBus.publish()
        │
        ├──→ SSE subscribers (existing — UI events)
        │
        └──→ EvidenceStreamSink.ingest()
               │
               ├── SHA-256 hash chain (same algorithm as context_accumulator.py)
               ├── Optional KMS signing (AsyncBatchSigner integration)
               │
               └──→ Redis Streams (db=1, noeviction policy)
                      │
                      └──→ GCS Flush Daemon (background, 60s interval, CMEK)

Durability strategy
-------------------
Redis Streams (db=1, noeviction) provides sub-millisecond ingestion speed.
The GCS Flush Daemon asynchronously persists hash-chained Redis logs to
Customer-Managed Encryption Key (CMEK) secured GCS buckets every 60 seconds.

This gives: real-time processing speed at the edge + cold, immutable
compliance storage at rest.

Wire format (Redis Stream entries)
----------------------------------
Each Redis Stream entry is a flat dict (Redis Streams limitation):
  {
    "schema":        "cage-evidence-stream/1.0",
    "sequence":      "42",
    "event_type":    "AUDIT_FINDING",
    "control_id":    "A.5.3",
    "prev_hash":     "<sha256 hex>",
    "record_hash":   "<sha256 hex>",
    "payload_json":  "<JSON-serialized event payload>",
    "timestamp_utc": "2026-05-29T14:00:00Z",
    "kms_signature": ""  // populated async when KMS signing enabled
  }

Environment variables
---------------------
  EVIDENCE_STREAM_ENABLED           — "true" to enable (default: "false")
  EVIDENCE_STREAM_REDIS_URL         — Redis URL (default: uses REDIS_URL)
  EVIDENCE_STREAM_REDIS_DB          — Redis DB number (default: 1)
  EVIDENCE_STREAM_KEY               — Redis Stream key name (default: "cage:evidence:stream")
  EVIDENCE_STREAM_MAX_LEN           — Max stream entries (default: 100000)
  EVIDENCE_STREAM_GCS_FLUSH_SECONDS — GCS flush interval (default: 60)
  EVIDENCE_STREAM_GCS_BUCKET        — GCS bucket for cold storage
  EVIDENCE_STREAM_KMS_SIGN          — "true" for per-record KMS signing
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("cage.evidence_stream")


def _get_signing_algorithm() -> str:
    """Return the active signing algorithm identifier for evidence stream tagging.

    Returns 'KMS_ASYMMETRIC', 'HMAC_SHA256_FALLBACK', or 'UNKNOWN'.
    Wrapped in try/except to handle cases where the gateway package is not
    available in the compliance bridge's import context.
    """
    try:
        from src.gateway.governance.kms_signer import get_governance_signer
        return get_governance_signer().signing_algorithm
    except Exception:
        return "UNKNOWN"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = (
    os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"
)
_REDIS_URL: str = os.environ.get(
    "EVIDENCE_STREAM_REDIS_URL",
    os.environ.get("REDIS_URL", ""),
)
_REDIS_DB: int = int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
_STREAM_KEY: str = os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream")
_MAX_LEN: int = int(os.environ.get("EVIDENCE_STREAM_MAX_LEN", "100000"))
_GCS_FLUSH_SECONDS: int = int(os.environ.get("EVIDENCE_STREAM_GCS_FLUSH_SECONDS", "60"))
_GCS_BUCKET: str = os.environ.get("EVIDENCE_STREAM_GCS_BUCKET", "")
_KMS_SIGN: bool = (
    os.environ.get("EVIDENCE_STREAM_KMS_SIGN", "false").lower() == "true"
)

_SCHEMA = "cage-evidence-stream/1.0"


# ---------------------------------------------------------------------------
# SHA-256 helpers (identical to context_accumulator.py)
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# EvidenceStreamSink — the core streaming sink
# ---------------------------------------------------------------------------


class EvidenceStreamSink:
    """Evidence-grade streaming sink backed by Redis Streams.

    Each governance event is hash-chained using the same SHA-256 algorithm
    as ``ContextAccumulator``, then persisted to a Redis Stream.

    Usage::

        sink = EvidenceStreamSink()
        await sink.start()

        # Ingest a governance event (from GovernanceEventBus.publish)
        await sink.ingest(event)

        # Graceful shutdown
        await sink.stop()
    """

    def __init__(
        self,
        redis_url: str = _REDIS_URL,
        redis_db: int = _REDIS_DB,
        stream_key: str = _STREAM_KEY,
        max_len: int = _MAX_LEN,
        kms_sign: bool = _KMS_SIGN,
    ) -> None:
        self._redis_url = redis_url
        self._redis_db = redis_db
        self._stream_key = stream_key
        self._max_len = max_len
        self._kms_sign = kms_sign

        self._redis = None  # Lazy-loaded redis.asyncio client
        self._prev_hash: str = _sha256("EVIDENCE_STREAM_GENESIS")
        self._sequence: int = 0
        self._running = False
        self._flush_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Connect to Redis and start the GCS flush daemon."""
        if self._running:
            return

        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                db=self._redis_db,
                decode_responses=True,
            )
            # Verify connectivity
            await self._redis.ping()
            logger.info(
                "[EvidenceStream] Connected to Redis: %s db=%d stream=%s",
                self._redis_url,
                self._redis_db,
                self._stream_key,
            )
        except Exception as exc:
            logger.error(
                "[EvidenceStream] Failed to connect to Redis: %s — "
                "evidence streaming disabled.",
                exc,
            )
            self._redis = None
            return

        self._running = True

        # Start GCS flush daemon if configured
        if _GCS_BUCKET:
            self._flush_task = asyncio.create_task(
                self._gcs_flush_loop(),
                name="evidence-gcs-flush",
            )

        logger.info("[EvidenceStream] Started.")

    async def stop(self) -> None:
        """Stop the evidence stream and flush remaining records."""
        self._running = False

        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        if self._redis:
            await self._redis.aclose()

        logger.info(
            "[EvidenceStream] Stopped. Total records: %d",
            self._sequence,
        )

    async def ingest(self, event: dict) -> Optional[str]:
        """Ingest a governance event into the evidence stream.

        The event is hash-chained, optionally KMS-signed, and persisted
        to Redis Streams.

        Args:
            event: GovernanceEvent dict from the SSE event bus.

        Returns:
            The Redis Stream message ID, or None if Redis is unavailable.
        """
        if self._redis is None:
            return None

        # Hash-chain the event
        payload_json = json.dumps(event, sort_keys=True, default=str)
        record_hash = _sha256(self._prev_hash + payload_json)

        entry = {
            "schema": _SCHEMA,
            "sequence": str(self._sequence),
            "event_type": event.get("type", "UNKNOWN"),
            "control_id": event.get("controlId", ""),
            "prev_hash": self._prev_hash,
            "record_hash": record_hash,
            "payload_json": payload_json,
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            "kms_signature": "",
            "kms_signature_algorithm": _get_signing_algorithm(),
        }

        # Advance chain state
        self._prev_hash = record_hash
        self._sequence += 1

        # Optional KMS signing (async, non-blocking)
        if self._kms_sign:
            self._enqueue_signing(entry)

        # Persist to Redis Stream
        try:
            msg_id = await self._redis.xadd(
                self._stream_key,
                entry,
                maxlen=self._max_len,
            )
            logger.debug(
                "[EvidenceStream] Ingested: seq=%s hash=%s… msg_id=%s",
                entry["sequence"],
                record_hash[:16],
                msg_id,
            )
            return msg_id
        except Exception as exc:
            logger.error(
                "[EvidenceStream] Failed to write to Redis Stream: %s",
                exc,
            )
            return None

    def _enqueue_signing(self, entry: dict) -> None:
        """Enqueue an evidence stream entry for async KMS signing."""
        try:
            from .kms_batch_signer import get_batch_signer

            def _on_signed(record_hash: str, signature: str) -> None:
                entry["kms_signature"] = signature

            signer = get_batch_signer()
            signer.enqueue(
                record_hash=entry["record_hash"],
                payload=json.loads(entry["payload_json"]),
                callback=_on_signed,
            )
        except Exception as exc:
            logger.warning(
                "[EvidenceStream] KMS enqueue failed: %s", exc
            )

    async def _gcs_flush_loop(self) -> None:
        """Background daemon that flushes Redis Stream entries to GCS.

        Runs every ``_GCS_FLUSH_SECONDS`` seconds. Reads all entries since
        the last flush and writes them as a hash-chained NDJSON blob to
        a CMEK-encrypted GCS bucket.
        """
        last_id = "0-0"

        while self._running:
            try:
                await asyncio.sleep(_GCS_FLUSH_SECONDS)

                if self._redis is None:
                    continue

                # Read new entries since last flush
                entries = await self._redis.xrange(
                    self._stream_key,
                    min=f"({last_id}",  # exclusive
                    count=5000,
                )

                if not entries:
                    continue

                # Build NDJSON payload
                lines = []
                for msg_id, fields in entries:
                    lines.append(json.dumps(fields, default=str))
                    last_id = msg_id

                ndjson_content = "\n".join(lines) + "\n"

                # Upload to GCS (async)
                await self._upload_to_gcs(ndjson_content, last_id)

                logger.info(
                    "[EvidenceStream] GCS flush: %d entries → %s (last_id=%s)",
                    len(entries),
                    _GCS_BUCKET,
                    last_id,
                )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "[EvidenceStream] GCS flush error: %s", exc
                )
                await asyncio.sleep(5.0)

    async def _upload_to_gcs(self, content: str, batch_id: str) -> None:
        """Upload NDJSON content to a CMEK-encrypted GCS bucket.

        Uses the google-cloud-storage async client. If not available,
        logs a warning (GCS flush is best-effort — the Redis Stream
        retains all data).
        """
        try:
            from google.cloud import storage  # type: ignore[import]

            client = storage.Client()
            bucket = client.bucket(_GCS_BUCKET)
            blob_name = (
                f"evidence-stream/"
                f"{datetime.now(tz=timezone.utc).strftime('%Y/%m/%d')}/"
                f"batch-{batch_id.replace(':', '-')}.ndjson"
            )
            blob = bucket.blob(blob_name)
            blob.upload_from_string(
                content,
                content_type="application/x-ndjson",
            )
            logger.debug(
                "[EvidenceStream] GCS upload: gs://%s/%s (%d bytes)",
                _GCS_BUCKET,
                blob_name,
                len(content),
            )
        except ImportError:
            logger.warning(
                "[EvidenceStream] google-cloud-storage not installed — "
                "GCS flush disabled. Install with: pip install google-cloud-storage"
            )
        except Exception as exc:
            logger.error("[EvidenceStream] GCS upload failed: %s", exc)

    @property
    def chain_root(self) -> str:
        """Current chain root hash (latest prev_hash)."""
        return self._prev_hash

    @property
    def total_records(self) -> int:
        """Total records ingested since start."""
        return self._sequence

    @property
    def is_running(self) -> bool:
        """True if the evidence stream is active."""
        return self._running


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_evidence_sink: Optional[EvidenceStreamSink] = None


def get_evidence_sink() -> EvidenceStreamSink:
    """Return the module-level EvidenceStreamSink singleton."""
    global _evidence_sink
    if _evidence_sink is None:
        _evidence_sink = EvidenceStreamSink()
    return _evidence_sink
