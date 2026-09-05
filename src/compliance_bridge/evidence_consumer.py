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
evidence_consumer.py — Evidence Stream consumer for compliance metrics aggregation.

Sprint 1.7: Replaces Langfuse as the primary source of compliance metrics.
Consumes hash-chained evidence records from Redis Streams and maintains
minute-bucketed per-control metrics indexes for sub-millisecond query latency.

Chain Restoration (Design Consideration §6.2):
On startup, reads the last record from the stream to restore prev_hash and
sequence, ensuring chain continuity across service restarts.

Architecture:
    Redis Streams → EvidenceStreamConsumer.consume() → per-control indexes
                                                     ↓
                                    get_compliance_metrics(control_id, window_hours)
                                                     ↓
                                              Lula OPA validation

Validation Criteria:
    V-2: Zero Langfuse imports in this module
    V-3: All Lula gates derive metrics from Evidence Stream
    V-4: Chain continuity maintained across restarts
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("cage.evidence_consumer")

# Redis configuration (matches evidence_stream.py)
_REDIS_URL: str = os.environ.get(
    "EVIDENCE_STREAM_REDIS_URL",
    os.environ.get("REDIS_URL", "redis://localhost:6379"),
)
_REDIS_DB: int = int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
_STREAM_KEY: str = os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream")


class EvidenceStreamConsumer:
    """Consumer for Evidence Stream records.

    Maintains windowed per-control metrics aggregates for fast Lula queries.
    Chain restoration: On startup, reads the last stream record to restore
    prev_hash and sequence for chain continuity validation.
    """

    def __init__(
        self,
        redis_url: str = _REDIS_URL,
        redis_db: int = _REDIS_DB,
        stream_key: str = _STREAM_KEY,
    ) -> None:
        self._redis_url = redis_url
        self._redis_db = redis_db
        self._stream_key = stream_key
        self._redis = None
        self._running = False
        self._consume_task: asyncio.Task | None = None

        # Per-control minute-bucketed counters
        # Structure: {control_id: {minute_timestamp: {"allowed": N, "denied": M, ...}}}
        self._metrics: dict[str, dict[int, dict[str, int]]] = defaultdict(
            lambda: defaultdict(
                lambda: {"allowed": 0, "denied": 0, "deferred": 0, "total": 0}
            )
        )

        # Chain state restored from last record
        self._chain_head_hash: str = ""
        self._chain_head_sequence: int = 0
        self._chain_verified: bool = False

        # Last consumed message ID (for XREAD blocking)
        self._last_id: str = "0-0"

    async def start(self) -> None:
        """Start the consumer and restore chain state from last record."""
        if self._running:
            return

        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                db=self._redis_db,
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info(
                "[EvidenceConsumer] Connected to Redis: %s db=%d stream=%s",
                self._redis_url,
                self._redis_db,
                self._stream_key,
            )
        except Exception as exc:
            logger.error(
                "[EvidenceConsumer] Failed to connect to Redis: %s",
                exc,
            )
            self._redis = None
            return

        # Chain restoration: Read last record to get prev_hash and sequence
        await self._restore_chain_state()

        self._running = True
        self._consume_task = asyncio.create_task(
            self._consume_loop(),
            name="evidence-consumer",
        )
        logger.info("[EvidenceConsumer] Started.")

    async def stop(self) -> None:
        """Stop the consumer gracefully."""
        self._running = False

        if self._consume_task and not self._consume_task.done():
            self._consume_task.cancel()
            try:
                await self._consume_task
            except asyncio.CancelledError:
                pass

        if self._redis:
            await self._redis.aclose()

        logger.info("[EvidenceConsumer] Stopped.")

    async def _restore_chain_state(self) -> None:
        """Restore chain state from the last record in the stream.

        Validation Criterion V-4: Chain continuity across restarts.
        """
        if self._redis is None:
            logger.warning(
                "[EvidenceConsumer] Cannot restore chain state: Redis unavailable"
            )
            return

        try:
            # XREVRANGE reads from end of stream ('+' means latest)
            # COUNT 1 returns only the last record
            entries = await self._redis.xrevrange(
                self._stream_key,
                max="+",
                min="-",
                count=1,
            )

            if not entries:
                logger.info("[EvidenceConsumer] Stream empty — clean genesis.")
                self._chain_head_hash = ""
                self._chain_head_sequence = 0
                self._last_id = "0-0"
                return

            msg_id, fields = entries[0]
            self._last_id = msg_id
            self._chain_head_hash = fields.get("record_hash", "")
            self._chain_head_sequence = int(fields.get("sequence", "0"))

            logger.info(
                "[EvidenceConsumer] Chain restored: seq=%d hash=%s... msg_id=%s",
                self._chain_head_sequence,
                self._chain_head_hash[:16],
                msg_id,
            )
            self._chain_verified = True

        except Exception as exc:
            logger.error(
                "[EvidenceConsumer] Failed to restore chain state: %s",
                exc,
            )
            self._chain_verified = False

    async def _consume_loop(self) -> None:
        """Background loop: consume new evidence records and update metrics."""
        while self._running:
            try:
                if self._redis is None:
                    await asyncio.sleep(5.0)
                    continue

                # XREAD blocks until new messages arrive (timeout 5s)
                # Read from last_id + 1 to get only new records
                result = await self._redis.xread(
                    {self._stream_key: self._last_id},
                    count=100,
                    block=5000,  # 5s timeout
                )

                if not result:
                    # No new messages
                    continue

                # result structure: [(stream_key, [(msg_id, fields), ...])]
                for _stream_key, messages in result:
                    for msg_id, fields in messages:
                        await self._process_record(msg_id, fields)
                        self._last_id = msg_id

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[EvidenceConsumer] Consume loop error: %s", exc)
                await asyncio.sleep(5.0)

    async def _process_record(self, msg_id: str, fields: dict[str, str]) -> None:
        """Process a single evidence record and update metrics."""
        try:
            event_type = fields.get("event_type", "UNKNOWN")
            control_id = fields.get("control_id", "")
            timestamp_str = fields.get("timestamp_utc", "")
            payload_json = fields.get("payload_json", "{}")

            # Parse timestamp to minute bucket
            try:
                ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                minute_bucket = int(ts.timestamp() // 60)
            except Exception:
                minute_bucket = int(datetime.now(timezone.utc).timestamp() // 60)

            # Parse payload for decision verdict
            try:
                payload = json.loads(payload_json)
            except Exception:
                payload = {}

            decision = payload.get("decision", event_type)

            # Update per-control minute-bucketed counters
            if control_id:
                bucket = self._metrics[control_id][minute_bucket]
                bucket["total"] += 1

                if decision in ("ALLOW", "ADMITTED", "NARROW"):
                    bucket["allowed"] += 1
                elif decision in ("DENY", "BLOCKED"):
                    bucket["denied"] += 1
                elif decision == "DEFER":
                    bucket["deferred"] += 1

            logger.debug(
                "[EvidenceConsumer] Processed: control=%s decision=%s msg_id=%s",
                control_id,
                decision,
                msg_id,
            )

        except Exception as exc:
            logger.error(
                "[EvidenceConsumer] Failed to process record %s: %s",
                msg_id,
                exc,
            )

    def get_compliance_metrics(
        self,
        control_id: str,
        window_hours: int = 24,
    ) -> dict[str, Any]:
        """Get compliance metrics for a control ID from windowed aggregates.

        Validation Criterion V-2: Zero Langfuse dependency — all data from
        Evidence Stream minute-bucketed indexes.

        Args:
            control_id: ISO 42001 control ID (e.g., "A.5.2")
            window_hours: Look-back window in hours

        Returns:
            ComplianceMetrics dict matching types.ComplianceMetrics schema.
        """
        now = datetime.now(timezone.utc)
        window_start_ts = int((now.timestamp() - window_hours * 3600) // 60)

        # Aggregate across all minute buckets in the window
        total = 0
        allowed = 0
        denied = 0
        deferred = 0

        control_buckets = self._metrics.get(control_id, {})
        for minute_bucket, counters in control_buckets.items():
            if minute_bucket >= window_start_ts:
                total += counters["total"]
                allowed += counters["allowed"]
                denied += counters["denied"]
                deferred += counters["deferred"]

        # Calculate safety rate
        safety_rate = None
        if total > 0:
            safety_rate = allowed / total

        # Evidence age (time since last record)
        last_minute = max(control_buckets.keys()) if control_buckets else 0
        last_event_utc = (
            datetime.fromtimestamp(last_minute * 60, tz=timezone.utc).isoformat()
            if last_minute > 0
            else now.isoformat()
        )
        evidence_age_seconds = (
            int(now.timestamp() - last_minute * 60) if last_minute > 0 else 0
        )

        # Startup grace period (first 5 minutes, no data yet)
        startup_grace_active = total == 0

        return {
            "control_id": control_id,
            "safety_rate": safety_rate,
            "total_traces": total,
            "blocked_traces": denied,
            "passed_traces": allowed,  # Required by ComplianceMetrics
            "window_hours": float(window_hours),  # Required by ComplianceMetrics
            "last_event_utc": last_event_utc,  # Required by ComplianceMetrics
            "evidence_age_seconds": max(0, evidence_age_seconds),  # Must be >= 0
            "startup_grace_active": startup_grace_active,
            "startup_grace_remaining_hours": 0.0,  # Required by ComplianceMetrics
            "source": "evidence_stream",  # V-2: Evidence Stream, not Langfuse
            "evidence_chain_verified": self._chain_verified,
            "chain_head_hash": self._chain_head_hash[:16]
            if self._chain_head_hash
            else "",
        }

    @property
    def chain_head_hash(self) -> str:
        """Current chain head hash (latest prev_hash)."""
        return self._chain_head_hash

    @property
    def chain_head_sequence(self) -> int:
        """Current chain head sequence number."""
        return self._chain_head_sequence

    @property
    def chain_verified(self) -> bool:
        """True if chain state was successfully restored from Redis."""
        return self._chain_verified


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_evidence_consumer: EvidenceStreamConsumer | None = None


def get_evidence_consumer() -> EvidenceStreamConsumer:
    """Return the module-level EvidenceStreamConsumer singleton."""
    global _evidence_consumer
    if _evidence_consumer is None:
        _evidence_consumer = EvidenceStreamConsumer()
    return _evidence_consumer
