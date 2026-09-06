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
clickhouse_sink.py — ClickHouse Evidence Stream Sink

Production evidence stream sink for CAGE's append-only, tamper-evident audit mirror.
Implements non-blocking batch ingestion with exponential backoff, circuit breaker,
and graceful degradation. ClickHouse failures never block Redis consumption.

Architecture Position (Layer 3):
    Redis Streams → Compliance Bridge → GCS (60s flush)
                                     ↓
                              ClickHouse (5s batch) ← THIS MODULE
                                     ↓
                        Materialized Views → Prometheus

Design Specification: docs/architecture/CLICKHOUSE_EVIDENCE_SINK.md
Schema DDL: deployment/clickhouse/evidence_stream_schema.sql
Source of Truth: src/gateway/governance/evidence/stream.py (cage-audit/3.0)

Key Invariants:
    1. Never block Redis consumption (all operations are async, fire-and-forget)
    2. Preserve payload_json as opaque bytes (no re-serialization)
    3. Circuit breaker opens after 10 consecutive failures
    4. Bounded queue (10k records) with drop-oldest policy on overflow
    5. Retry with decorrelated jitter: 0.5s → 1s → 2s (max 3 attempts)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any

from .metrics import (
    CLICKHOUSE_SINK_BATCH_DURATION_SECONDS,
    CLICKHOUSE_SINK_CIRCUIT_OPEN,
    CLICKHOUSE_SINK_DROPPED_TOTAL,
    CLICKHOUSE_SINK_ERRORS_TOTAL,
    CLICKHOUSE_SINK_QUEUE_DEPTH,
    CLICKHOUSE_SINK_RECORDS_TOTAL,
)

logger = logging.getLogger("cage.clickhouse_sink")

# Environment configuration
CLICKHOUSE_ENABLED = os.environ.get("CLICKHOUSE_ENABLED", "false").lower() == "true"
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "cage_evidence")
CLICKHOUSE_USERNAME = os.environ.get("CLICKHOUSE_USERNAME", "evidence_writer")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_BATCH_SIZE = int(os.environ.get("CLICKHOUSE_SINK_BATCH_SIZE", "100"))
CLICKHOUSE_FLUSH_SECONDS = float(os.environ.get("CLICKHOUSE_SINK_FLUSH_SECONDS", "5.0"))
CLICKHOUSE_MAX_QUEUE = int(os.environ.get("CLICKHOUSE_SINK_MAX_QUEUE", "10000"))
CLICKHOUSE_TIMEOUT = int(os.environ.get("CLICKHOUSE_SINK_TIMEOUT_S", "30"))


class CircuitBreaker:
    """Simple circuit breaker for ClickHouse health.

    Opens after 10 consecutive failures, stays open for 60 seconds.
    """

    def __init__(
        self, failure_threshold: int = 10, cooldown_seconds: float = 60.0
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    def is_open(self) -> bool:
        """Check if circuit is currently open."""
        if self._opened_at is None:
            return False
        # Close circuit after cooldown period
        if time.monotonic() - self._opened_at >= self._cooldown_seconds:
            logger.info("[ClickHouseSink] Circuit breaker closed after cooldown")
            self._opened_at = None
            self._consecutive_failures = 0
            CLICKHOUSE_SINK_CIRCUIT_OPEN.set(0)
            return False
        return True

    def record_success(self) -> None:
        """Record successful operation."""
        self._consecutive_failures = 0
        if self._opened_at is not None:
            logger.info("[ClickHouseSink] Circuit breaker closed after success")
            self._opened_at = None
            CLICKHOUSE_SINK_CIRCUIT_OPEN.set(0)

    def record_failure(self) -> None:
        """Record failed operation."""
        self._consecutive_failures += 1
        if (
            self._consecutive_failures >= self._failure_threshold
            and self._opened_at is None
        ):
            self._opened_at = time.monotonic()
            logger.error(
                "[ClickHouseSink] Circuit breaker opened after %d consecutive failures",
                self._consecutive_failures,
            )
            CLICKHOUSE_SINK_CIRCUIT_OPEN.set(1)


class ClickHouseSink:
    """ClickHouse evidence stream sink with batch buffering and circuit breaker.

    Non-blocking design: ClickHouse failures never block Redis consumption.
    All operations return immediately; failures are logged and counted.

    Example:
        sink = ClickHouseSink()
        await sink.start()
        await sink.ingest(record)  # Never blocks, never raises
        await sink.close()
    """

    def __init__(
        self,
        host: str = CLICKHOUSE_HOST,
        port: int = CLICKHOUSE_PORT,
        username: str = CLICKHOUSE_USERNAME,
        password: str = CLICKHOUSE_PASSWORD,
        database: str = CLICKHOUSE_DATABASE,
        batch_size: int = CLICKHOUSE_BATCH_SIZE,
        flush_seconds: float = CLICKHOUSE_FLUSH_SECONDS,
        max_queue: int = CLICKHOUSE_MAX_QUEUE,
    ) -> None:
        """Initialize ClickHouse sink.

        Args:
            host: ClickHouse server hostname
            port: ClickHouse native protocol port (default: 9000)
            username: ClickHouse username (default: evidence_writer)
            password: ClickHouse password (required, no default)
            database: Target database (default: cage_evidence)
            batch_size: Records per batch (default: 100)
            flush_seconds: Max time between flushes (default: 5.0)
            max_queue: Maximum queue depth before dropping (default: 10000)
        """
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._database = database
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._max_queue = max_queue
        self._max_retries = 3

        self._client: Any = None
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue)
        self._buffer: list[dict[str, Any]] = []
        self._buffer_lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self._running = False
        self._flush_task: asyncio.Task[None] | None = None
        self._breaker = CircuitBreaker()

        # Never log password
        logger.info(
            "[ClickHouseSink] Initialized: host=%s port=%d db=%s user=%s batch=%d flush=%.1fs",
            self._host,
            self._port,
            self._database,
            self._username,
            self._batch_size,
            self._flush_seconds,
        )

    async def start(self) -> None:
        """Start the sink and flush task.

        Connects to ClickHouse lazily on first insert, not here.
        Starts the background flush loop immediately.
        """
        if self._running:
            return

        self._running = True
        self._flush_task = asyncio.create_task(
            self._flush_loop(),
            name="clickhouse-flush",
        )
        logger.info("[ClickHouseSink] Started")

    async def close(self) -> None:
        """Stop the sink gracefully and flush remaining records."""
        self._running = False

        # Flush remaining buffer
        async with self._buffer_lock:
            if self._buffer:
                await self._flush_buffer(self._buffer[:])
                self._buffer.clear()

        # Cancel flush task
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Close client
        if self._client:
            try:
                self._client.close()
            except Exception as exc:
                logger.warning("[ClickHouseSink] Error closing client: %s", exc)

        logger.info("[ClickHouseSink] Closed")

    async def ingest(self, record: dict[str, Any]) -> None:
        """Ingest evidence record into buffer (non-blocking).

        Never blocks, never raises. If queue is full, drops the oldest record.

        Args:
            record: Evidence record in cage-audit/3.0 wire format
        """
        try:
            self._queue.put_nowait(record)
            CLICKHOUSE_SINK_QUEUE_DEPTH.set(self._queue.qsize())
        except asyncio.QueueFull:
            # Drop oldest record, insert newest
            try:
                dropped = self._queue.get_nowait()
                self._queue.put_nowait(record)
                CLICKHOUSE_SINK_DROPPED_TOTAL.inc()
                logger.error(
                    "[ClickHouseSink] Queue full; dropped record seq=%s chain=%s. "
                    "Evidence remains durable in Redis and GCS.",
                    dropped.get("sequence"),
                    dropped.get("chain_id"),
                )
            except Exception as exc:
                logger.error("[ClickHouseSink] Queue overflow handling failed: %s", exc)

    async def _flush_loop(self) -> None:
        """Background flush loop (runs as separate task)."""
        while self._running:
            try:
                # Accumulate records from queue into buffer
                deadline = time.monotonic() + self._flush_seconds
                while (
                    time.monotonic() < deadline and len(self._buffer) < self._batch_size
                ):
                    timeout = deadline - time.monotonic()
                    if timeout <= 0:
                        break
                    try:
                        record = await asyncio.wait_for(
                            self._queue.get(), timeout=timeout
                        )
                        async with self._buffer_lock:
                            self._buffer.append(record)
                        CLICKHOUSE_SINK_QUEUE_DEPTH.set(self._queue.qsize())
                    except asyncio.TimeoutError:
                        break

                # Flush if buffer is full or time expired
                async with self._buffer_lock:
                    if self._buffer and (
                        len(self._buffer) >= self._batch_size
                        or (time.monotonic() - self._last_flush) >= self._flush_seconds
                    ):
                        batch = self._buffer[:]
                        self._buffer.clear()
                        self._last_flush = time.monotonic()

                if batch:
                    await self._flush_buffer(batch)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[ClickHouseSink] Flush loop error: %s", exc)
                await asyncio.sleep(1.0)

    async def _flush_buffer(self, batch: list[dict[str, Any]]) -> None:
        """Flush batch to ClickHouse with retry and circuit breaker.

        Never raises. Logs errors and increments failure metrics.

        Args:
            batch: List of evidence records to insert
        """
        if not batch:
            return

        if self._breaker.is_open():
            logger.warning(
                "[ClickHouseSink] Circuit breaker open, skipping batch of %d records",
                len(batch),
            )
            return

        # Lazy client initialization
        if self._client is None:
            try:
                await self._init_client()
            except Exception as exc:
                logger.error("[ClickHouseSink] Failed to initialize client: %s", exc)
                CLICKHOUSE_SINK_ERRORS_TOTAL.labels(error_type=type(exc).__name__).inc()
                self._breaker.record_failure()
                return

        # Transform records to ClickHouse rows
        try:
            rows = [self._evidence_to_row(record) for record in batch]
        except Exception as exc:
            logger.error("[ClickHouseSink] Failed to transform batch: %s", exc)
            CLICKHOUSE_SINK_ERRORS_TOTAL.labels(error_type=type(exc).__name__).inc()
            return

        # Insert with retry and exponential backoff
        for attempt in range(self._max_retries):
            try:
                start_time = time.monotonic()

                # Extract chain_id range for deduplication token
                chain_ids = set(row["chain_id"] for row in rows)
                sequences = [row["sequence"] for row in rows]
                dedup_token = f"{','.join(str(c) for c in sorted(chain_ids))}:{min(sequences)}-{max(sequences)}"

                # Insert batch - define helper to avoid lambda variable capture issue
                def _do_insert(token: str = dedup_token) -> None:
                    self._client.insert(
                        f"{self._database}.evidence_stream",
                        rows,
                        column_names=list(rows[0].keys()) if rows else [],
                        settings={
                            "insert_deduplication_token": token,
                            "async_insert": 1,
                            "wait_for_async_insert": 1,
                        },
                    )

                await asyncio.get_event_loop().run_in_executor(None, _do_insert)

                duration = time.monotonic() - start_time
                CLICKHOUSE_SINK_BATCH_DURATION_SECONDS.observe(duration)
                CLICKHOUSE_SINK_RECORDS_TOTAL.inc(len(rows))
                self._breaker.record_success()

                logger.debug(
                    "[ClickHouseSink] Inserted batch of %d records in %.3fs",
                    len(rows),
                    duration,
                    extra={
                        "batch_size": len(rows),
                        "chain_ids": list(chain_ids)[:5],  # First 5 only
                        "trace_ids": [row["trace_id"] for row in rows[:5]],
                    },
                )
                return

            except Exception as exc:
                CLICKHOUSE_SINK_ERRORS_TOTAL.labels(error_type=type(exc).__name__).inc()

                if attempt == self._max_retries - 1:
                    # Final attempt failed
                    self._breaker.record_failure()
                    logger.error(
                        "[ClickHouseSink] Batch of %d dropped after %d attempts: %s. "
                        "Evidence remains durable in Redis and GCS.",
                        len(rows),
                        self._max_retries,
                        exc,
                        extra={
                            "error_type": type(exc).__name__,
                            "batch_size": len(rows),
                        },
                    )
                    return

                # Exponential backoff with decorrelated jitter
                backoff = min(0.5 * (2**attempt), 8.0) * (0.5 + random.random())
                logger.warning(
                    "[ClickHouseSink] Insert failed (attempt %d/%d), retrying in %.2fs: %s",
                    attempt + 1,
                    self._max_retries,
                    backoff,
                    exc,
                )
                await asyncio.sleep(backoff)

    async def _init_client(self) -> None:
        """Initialize ClickHouse client (lazy, called on first insert)."""
        try:
            import clickhouse_connect
        except ImportError as exc:
            logger.error("[ClickHouseSink] clickhouse-connect not installed: %s", exc)
            raise

        # Run blocking connect in executor
        self._client = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: clickhouse_connect.get_client(
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                database=self._database,
                connect_timeout=CLICKHOUSE_TIMEOUT,
                send_receive_timeout=CLICKHOUSE_TIMEOUT,
            ),
        )

        logger.info(
            "[ClickHouseSink] Connected to ClickHouse: %s:%d db=%s",
            self._host,
            self._port,
            self._database,
        )

    def _evidence_to_row(self, record: dict[str, Any]) -> dict[str, Any]:
        """Transform evidence record to ClickHouse row dict.

        Maps cage-audit/3.0 wire format to ClickHouse schema.
        Preserves payload_json as opaque bytes (no re-serialization).

        Args:
            record: Evidence record in cage-audit/3.0 wire format

        Returns:
            ClickHouse row dict matching evidence_stream table schema
        """
        # Extract schema version (strip "cage-audit/" prefix)
        schema_version = record.get("schema", "cage-audit/3.0").replace(
            "cage-audit/", ""
        )

        # Parse timestamp to datetime if string
        timestamp = record.get("timestamp_utc", "")
        if isinstance(timestamp, str):
            # ISO 8601 → DateTime64(3, 'UTC')
            timestamp = timestamp.replace("Z", "+00:00")

        # Handle nullable fields: empty string → None
        prev_hash = record.get("prev_hash", "")
        if prev_hash == "":
            prev_hash = None

        kms_signature = record.get("kms_signature", "")
        if kms_signature == "":
            kms_signature = None

        kms_signature_algorithm = record.get("kms_signature_algorithm", "")
        if kms_signature_algorithm == "":
            kms_signature_algorithm = None

        # Extract sparse header members from payload
        # These are inside the hash when present, so must be preserved
        payload_dict = {}
        payload_json = record.get("payload_json", "")
        if payload_json:
            try:
                payload_dict = json.loads(payload_json)
            except Exception:
                pass  # Keep as empty dict if parse fails

        classification_reason = payload_dict.get("classification_reason")
        narrowing_applied_raw = payload_dict.get("narrowing_applied")
        # narrowing_applied is already JCS-canonicalized JSON, store as-is
        narrowing_applied = (
            json.dumps(narrowing_applied_raw) if narrowing_applied_raw else None
        )
        pause_token = payload_dict.get("pause_token")

        # Redis message ID from record context (may be None for non-Redis sources)
        redis_msg_id = record.get("redis_msg_id", "")

        return {
            "schema_version": schema_version,
            "chain_id": record.get("chain_id", ""),
            "sequence": int(record.get("sequence", 0)),
            "timestamp": timestamp,
            "event_type": record.get("event_type", ""),
            "control_id": record.get("control_id", ""),
            "trace_id": record.get("trace_id", ""),
            "hash_algorithm": record.get("hash_algorithm", "SHA-256"),
            "canonicalization": record.get("canonicalization", "RFC8785"),
            # Payload as opaque string (NEVER re-serialize)
            "payload": payload_json,
            "classification_reason": classification_reason,
            "narrowing_applied": narrowing_applied,
            "pause_token": pause_token,
            "record_hash": record.get("record_hash", ""),
            "prev_hash": prev_hash,
            "kms_signature": kms_signature,
            "kms_signature_algorithm": kms_signature_algorithm,
            # ingested_at is DEFAULT now64(3) in ClickHouse schema
            "redis_msg_id": redis_msg_id,
        }

    async def health_check(self) -> bool:
        """Verify ClickHouse connectivity.

        Returns:
            True if ClickHouse is reachable, False otherwise
        """
        if self._client is None:
            try:
                await self._init_client()
            except Exception as exc:
                logger.error(
                    "[ClickHouseSink] Health check failed (no client): %s", exc
                )
                return False

        try:
            # Simple ping query
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.command("SELECT 1"),
            )
            return result == 1
        except Exception as exc:
            logger.error("[ClickHouseSink] Health check failed: %s", exc)
            return False
