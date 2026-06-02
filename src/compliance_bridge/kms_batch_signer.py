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
kms_batch_signer.py — Asynchronous Ring-Buffer Batch Signer for Evidence Chain Records
=======================================================================================

Decouples per-record KMS signing from the hot-path evidence chain writes.

Problem
-------
Calling Cloud KMS ``asymmetricSign`` inline for every evidence record adds
20-50ms of network latency per record.  In a hot-path governance loop with
7+ tiers, this destroys sub-millisecond execution targets.

Solution: Asymmetric Ring-Buffer Batch Signer
---------------------------------------------
1. Evidence chain records are appended to a thread-safe ``collections.deque``
   immediately after hash-chain computation — zero blocking on the hot path.

2. A background ``asyncio.Task`` worker drains the queue at a configurable
   interval (default: 500ms) or when the batch reaches a configurable size
   (default: 32 records), whichever comes first.

3. The worker calls ``KMSGovernanceSigner.sign()`` for each record in the
   batch and writes the signature back to the record's ``kms_signature``
   field via a callback.

4. A ``drain()`` coroutine is provided for graceful shutdown — flushes all
   pending records before the process exits.

Architecture precedent: follows the same deferred-signing pattern as
``config/compliance/reconciliation_worker.py`` (L493-L522) where the
``ExternalLedgerReconciler.reconcile()`` calls ``get_governance_signer()``
outside the balance-fetch critical path.

Environment variables
---------------------
  KMS_BATCH_FLUSH_INTERVAL_MS  — flush interval in ms (default: 500)
  KMS_BATCH_MAX_SIZE           — max records per batch (default: 32)
  KMS_BATCH_ENABLED            — "true" to enable batch signing (default: "false")
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("cage.kms_batch_signer")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_FLUSH_INTERVAL_MS: int = int(
    os.environ.get("KMS_BATCH_FLUSH_INTERVAL_MS", "500")
)
_MAX_BATCH_SIZE: int = int(
    os.environ.get("KMS_BATCH_MAX_SIZE", "32")
)
_ENABLED: bool = (
    os.environ.get("KMS_BATCH_ENABLED", "false").lower() == "true"
)


# ---------------------------------------------------------------------------
# Pending record — queued for signing
# ---------------------------------------------------------------------------

@dataclass
class PendingSignatureRecord:
    """A record waiting in the ring buffer for KMS signing.

    Attributes:
        record_hash:  SHA-256 hash of the evidence record (used as signing input).
        payload:      The canonical JSON payload that was hashed.
        callback:     Called with (record_hash, signature_hex) when signing completes.
        enqueued_at:  Monotonic timestamp when the record was enqueued.
    """
    record_hash: str
    payload: dict[str, Any]
    callback: Optional[Callable[[str, str], None]] = None
    enqueued_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# AsyncBatchSigner — the ring-buffer worker
# ---------------------------------------------------------------------------

class AsyncBatchSigner:
    """Asynchronous ring-buffer batch signer for evidence chain records.

    The signer maintains a thread-safe deque and a background asyncio task
    that periodically drains the queue and signs records via Cloud KMS.

    Usage::

        signer = AsyncBatchSigner()
        await signer.start()

        # Hot path — zero blocking
        signer.enqueue(record_hash, payload, callback=on_signed)

        # Graceful shutdown
        await signer.drain()
        await signer.stop()
    """

    def __init__(
        self,
        flush_interval_ms: int = _FLUSH_INTERVAL_MS,
        max_batch_size: int = _MAX_BATCH_SIZE,
    ) -> None:
        self._queue: collections.deque[PendingSignatureRecord] = collections.deque()
        self._flush_interval = flush_interval_ms / 1000.0  # convert to seconds
        self._max_batch_size = max_batch_size
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self._signed_count = 0
        self._failed_count = 0
        self._signer = None  # Lazy-loaded KMSGovernanceSigner

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background signing worker."""
        if self._running:
            return

        self._running = True
        self._worker_task = asyncio.create_task(
            self._worker_loop(), name="kms-batch-signer"
        )
        logger.info(
            "[KMSBatchSigner] Started: flush_interval=%.0fms max_batch=%d",
            self._flush_interval * 1000,
            self._max_batch_size,
        )

        # Eagerly load the signer so we can check its mode at startup
        if self._signer is None:
            try:
                from src.gateway.governance.kms_signer import get_governance_signer
                self._signer = get_governance_signer()
            except Exception as _exc:
                logger.error("[KMSBatchSigner] Failed to load signer at startup: %s", _exc)

        if self._signer is not None and not getattr(self._signer, "is_kms_active", False):
            logger.critical(
                json.dumps({
                    "event": "KMS_BATCH_SIGNER_HMAC_FALLBACK",
                    "severity": "CRITICAL",
                    "signing_path": "HMAC_SHA256_FALLBACK",
                    "audit_note": (
                        "AsyncBatchSigner is operating in HMAC fallback mode. "
                        "All evidence stream records will be signed with HMAC-SHA256, "
                        "not Cloud KMS. kms_signature fields in the evidence stream "
                        "will contain HMAC digests with no non-repudiation value."
                    ),
                })
            )

    async def stop(self) -> None:
        """Stop the background worker (does NOT drain pending records)."""
        self._running = False
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info(
            "[KMSBatchSigner] Stopped. Signed: %d, Failed: %d, Pending: %d",
            self._signed_count,
            self._failed_count,
            len(self._queue),
        )

    async def drain(self) -> int:
        """Flush all pending records synchronously before shutdown.

        Returns:
            Number of records successfully signed during drain.
        """
        count = 0
        while self._queue:
            batch = self._collect_batch()
            signed = await self._sign_batch(batch)
            count += signed
        logger.info("[KMSBatchSigner] Drain complete: %d records signed.", count)
        return count

    # ------------------------------------------------------------------
    # Hot-path enqueue — MUST be non-blocking
    # ------------------------------------------------------------------

    def enqueue(
        self,
        record_hash: str,
        payload: dict[str, Any],
        callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Enqueue a record for background KMS signing.

        This method is designed to be called from the hot path.
        It performs zero I/O and zero blocking — just a deque.append().

        Args:
            record_hash:  SHA-256 hash of the evidence record.
            payload:      The canonical JSON payload.
            callback:     Optional callback(record_hash, signature_hex) on completion.
        """
        self._queue.append(
            PendingSignatureRecord(
                record_hash=record_hash,
                payload=payload,
                callback=callback,
            )
        )

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    async def _worker_loop(self) -> None:
        """Background loop: drain queue at interval or batch size."""
        while self._running:
            try:
                await asyncio.sleep(self._flush_interval)

                if not self._queue:
                    continue

                batch = self._collect_batch()
                await self._sign_batch(batch)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "[KMSBatchSigner] Worker loop error: %s", exc
                )
                # Don't crash — the worker must survive transient errors
                await asyncio.sleep(1.0)

    def _collect_batch(self) -> list[PendingSignatureRecord]:
        """Pop up to max_batch_size records from the queue."""
        batch: list[PendingSignatureRecord] = []
        while self._queue and len(batch) < self._max_batch_size:
            batch.append(self._queue.popleft())
        return batch

    async def _sign_batch(
        self, batch: list[PendingSignatureRecord]
    ) -> int:
        """Sign a batch of records via KMS.

        Returns:
            Number of successfully signed records.
        """
        if not batch:
            return 0

        # Lazy-load the signer
        if self._signer is None:
            from src.gateway.governance.kms_signer import get_governance_signer
            self._signer = get_governance_signer()

        signed = 0
        for record in batch:
            try:
                signature = self._signer.sign(record.payload)

                if record.callback is not None:
                    record.callback(record.record_hash, signature)

                self._signed_count += 1
                signed += 1

            except Exception as exc:
                self._failed_count += 1
                logger.warning(
                    "[KMSBatchSigner] Failed to sign record %s…: %s",
                    record.record_hash[:16],
                    exc,
                )

        if signed > 0:
            logger.debug(
                "[KMSBatchSigner] Batch signed: %d/%d records (queue=%d)",
                signed,
                len(batch),
                len(self._queue),
            )

        return signed

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def pending_count(self) -> int:
        """Number of records waiting in the queue."""
        return len(self._queue)

    @property
    def signed_count(self) -> int:
        """Total records successfully signed since start."""
        return self._signed_count

    @property
    def failed_count(self) -> int:
        """Total signing failures since start."""
        return self._failed_count

    @property
    def is_running(self) -> bool:
        """True if the background worker is active."""
        return self._running

    @property
    def is_kms_active(self) -> bool:
        """True if the underlying KMSGovernanceSigner is in KMS mode (not HMAC fallback)."""
        if self._signer is None:
            return False
        return getattr(self._signer, "is_kms_active", False)

    def assert_kms_active_in_production(self) -> None:
        """Raise RuntimeError if HMAC fallback is active in a production environment."""
        env = (os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")).lower()
        if env in ("development", "test", "dev", "ci"):
            return
        if not self.is_kms_active:
            raise RuntimeError(
                "CAGE STARTUP FAILURE: AsyncBatchSigner is in HMAC fallback mode "
                "in a non-development environment. Evidence stream records will not "
                "have non-repudiable KMS signatures. Set KMS_GOVERNANCE_KEY."
            )


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_batch_signer: Optional[AsyncBatchSigner] = None


def get_batch_signer() -> AsyncBatchSigner:
    """Return the module-level AsyncBatchSigner singleton.

    The signer is NOT started automatically — call ``await signer.start()``
    during application lifespan init.
    """
    global _batch_signer
    if _batch_signer is None:
        _batch_signer = AsyncBatchSigner()
    return _batch_signer
