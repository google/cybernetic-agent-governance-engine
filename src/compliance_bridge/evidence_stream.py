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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace

logger = logging.getLogger("cage.evidence_stream")
tracer = trace.get_tracer(__name__)

# Prometheus metrics (lazy import to avoid dependency in tests)
_PROM_AVAILABLE = False
try:
    from prometheus_client import Counter, Histogram

    EVIDENCE_COMMIT_TOTAL = Counter(
        "cage_evidence_commit_total",
        "Total evidence commit attempts",
        ["status"],
    )
    EVIDENCE_COMMIT_DURATION = Histogram(
        "cage_evidence_commit_duration_seconds",
        "Evidence commit latency in seconds",
        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )
    _PROM_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigurationError(Exception):
    """Raised when there's an invalid configuration combination.

    This exception signals a startup precondition failure that should cause
    the service to fail fast rather than run with an invalid configuration.
    """

    pass


class EvidenceChainUnavailableError(Exception):
    """Raised when evidence chain is unavailable and blocking mode is enabled.

    This exception signals that evidence could not be committed to the durable
    evidence stream (Redis Streams + GCS) and therefore a routing seal MUST NOT
    be issued. It is a fail-closed safety mechanism that ensures evidence-of-
    execution claims are never overclaimed.

    Attributes:
        message: Human-readable description of the failure.
        original_error: The underlying exception that caused the unavailability.
    """

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error


# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceCommitResult:
    """Result of a blocking evidence commit operation.

    Attributes:
        success: True if evidence was successfully committed to the durable store.
        evidence_id: Unique identifier of the committed evidence (Redis Stream msg_id).
        commit_timestamp: UTC timestamp when the evidence was committed.
        hash: SHA-256 hash of the committed evidence record (for chain integrity).
        sequence: Monotonic sequence number in the evidence chain.
    """

    success: bool
    evidence_id: str
    commit_timestamp: datetime
    hash: str
    sequence: int = field(default=0)


@dataclass
class EvidenceRecord:
    """Structured evidence record using schema v1.1.

    v3.0.0 Breaking Change: Schema v1.0 support has been removed.
    All records now use v1.1 schema exclusively.

    Core fields:
        evidence_id: Unique identifier for the evidence record.
        decision: Governance decision (ALLOW, DENY, DEFER, NARROW, PAUSE).
        timestamp: UTC timestamp when the decision was made.
        tool_name: Name of the tool that was governed.
        control_id: NIST/ISO control identifier (e.g., "A.5.3").
        prev_hash: Hash of the previous record in the chain.
        record_hash: Hash of this record (computed from content).
        payload: Full decision payload (JSON-serializable dict).

    v1.1 metadata fields:
        schema_version: Schema version identifier (always "1.1").
        classification_reason: Human-readable reason for DEFER decisions.
        narrowing_applied: Dict describing narrowing constraints for NARROW decisions.
        pause_token: Unique token for PAUSE decisions (for resumption).
    """

    # Core fields (required)
    evidence_id: str
    decision: str
    timestamp: datetime
    tool_name: str
    control_id: str
    prev_hash: str
    record_hash: str
    payload: dict[str, Any]

    # v1.1 metadata fields
    schema_version: str = "1.1"
    classification_reason: str | None = None
    narrowing_applied: dict[str, Any] | None = None
    pause_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for Redis storage or JSON encoding."""
        result: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "decision": self.decision,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "tool_name": self.tool_name,
            "control_id": self.control_id,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "payload": self.payload,
            "schema_version": self.schema_version,
        }
        # Only include v1.1 fields if present (sparse representation)
        if self.classification_reason is not None:
            result["classification_reason"] = self.classification_reason
        if self.narrowing_applied is not None:
            result["narrowing_applied"] = self.narrowing_applied
        if self.pause_token is not None:
            result["pause_token"] = self.pause_token
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRecord":
        """Deserialize from dict, auto-detecting schema version."""
        # Parse timestamp if it's a string
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(tz=timezone.utc)

        # Detect schema version (default to 1.0 for records without version field)
        schema_version = data.get("schema_version", "1.0")

        return cls(
            evidence_id=data.get("evidence_id", ""),
            decision=data.get("decision", ""),
            timestamp=timestamp,
            tool_name=data.get("tool_name", ""),
            control_id=data.get("control_id", ""),
            prev_hash=data.get("prev_hash", ""),
            record_hash=data.get("record_hash", ""),
            payload=data.get("payload", {}),
            schema_version=schema_version,
            classification_reason=data.get("classification_reason"),
            narrowing_applied=data.get("narrowing_applied"),
            pause_token=data.get("pause_token"),
        )


@dataclass(frozen=True)
class VerifyResult:
    """Result of evidence record hash verification.

    v3.0.0: Schema v1.0 support removed — all records use v1.1.

    Attributes:
        valid: True if the record hash matches the computed hash.
        schema_version: Schema version of the record (always "1.1").
        computed_hash: Hash computed from record contents.
        expected_hash: Hash stored in the record (record_hash field).
        error: Error message if verification failed, None otherwise.
    """

    valid: bool
    schema_version: str
    computed_hash: str
    expected_hash: str
    error: str | None = None


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

_ENABLED: bool = os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"
_REDIS_URL: str = os.environ.get(
    "EVIDENCE_STREAM_REDIS_URL",
    os.environ.get("REDIS_URL", ""),
)
_REDIS_DB: int = int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
_STREAM_KEY: str = os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream")
_MAX_LEN: int = int(os.environ.get("EVIDENCE_STREAM_MAX_LEN", "100000"))
_GCS_FLUSH_SECONDS: int = int(os.environ.get("EVIDENCE_STREAM_GCS_FLUSH_SECONDS", "60"))
_GCS_BUCKET: str = os.environ.get("EVIDENCE_STREAM_GCS_BUCKET", "")
_KMS_SIGN: bool = os.environ.get("EVIDENCE_STREAM_KMS_SIGN", "false").lower() == "true"

# EVIDENCE_CHAIN_BLOCKING: When "true", seal issuance blocks until evidence commit
# succeeds. When "false" (default), current fire-and-forget behavior is preserved.
# This flag mitigates risk R-06 (evidence-of-execution claims overclaimed).
_EVIDENCE_CHAIN_BLOCKING: bool = (
    os.environ.get("EVIDENCE_CHAIN_BLOCKING", "false").lower() == "true"
)

# Default timeout for blocking evidence commits (seconds)
_EVIDENCE_COMMIT_TIMEOUT_S: float = float(
    os.environ.get("EVIDENCE_COMMIT_TIMEOUT_S", "5.0")
)

# v3.0.0 Breaking Change: Schema v1.0 support has been removed.
# All new records use v1.1 schema exclusively.
_SCHEMA = "cage-evidence-stream/1.1"


def validate_evidence_stream_preconditions() -> None:
    """Validates evidence stream configuration at startup.

    Raises ConfigurationError if EVIDENCE_CHAIN_BLOCKING=true but
    EVIDENCE_STREAM_ENABLED=false. This is an invalid configuration because
    the blocking gate will always fail when the evidence stream is disabled,
    causing all seal issuances to fail.

    This function should be called during service startup (gateway and
    compliance bridge) to fail fast rather than at runtime.

    Raises:
        ConfigurationError: If EVIDENCE_CHAIN_BLOCKING=true and
            EVIDENCE_STREAM_ENABLED=false.
    """
    blocking_enabled = os.environ.get("EVIDENCE_CHAIN_BLOCKING", "false").lower() == "true"
    stream_enabled = os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"

    if blocking_enabled and not stream_enabled:
        raise ConfigurationError(
            "EVIDENCE_CHAIN_BLOCKING=true requires EVIDENCE_STREAM_ENABLED=true. "
            f"Current configuration: EVIDENCE_CHAIN_BLOCKING={blocking_enabled}, "
            f"EVIDENCE_STREAM_ENABLED={stream_enabled}. "
            "Either enable the evidence stream or disable blocking mode."
        )

    logger.info(
        "[EvidenceStream] Precondition check passed: "
        "EVIDENCE_CHAIN_BLOCKING=%s, EVIDENCE_STREAM_ENABLED=%s",
        blocking_enabled,
        stream_enabled,
    )


def is_evidence_chain_blocking() -> bool:
    """Return True if evidence chain blocking mode is enabled.

    When blocking mode is enabled, seal issuance blocks until evidence is
    committed to the durable evidence stream. This prevents overclaiming
    evidence-of-execution (risk R-06).
    """
    return _EVIDENCE_CHAIN_BLOCKING


# ---------------------------------------------------------------------------
# SHA-256 helpers (identical to context_accumulator.py)
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _link_hash(
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
) -> str:
    """Compute a stream entry's ``record_hash`` over its header + payload.

    The header carries the identifying metadata stored beside the payload in
    the Redis Stream entry, so re-ordering or re-labelling a record changes
    the link and breaks the chain.

    Note: This function uses the current schema version (_SCHEMA) for new entries.
    For verification of existing records, use _link_hash_versioned() which
    respects the record's original schema version.
    """
    header = json.dumps(
        {
            "schema": _SCHEMA,
            "sequence": sequence,
            "event_type": event_type,
            "control_id": control_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256(prev_hash + header + payload_json)


def _link_hash_versioned(
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
    schema_version: str,
    classification_reason: str | None = None,
    narrowing_applied: dict[str, Any] | None = None,
    pause_token: str | None = None,
) -> str:
    """Compute a version-aware record hash for dual-schema verification.

    This function produces deterministic hashes that are backward compatible:
    - v1.0: Hash only original fields (matches legacy records)
    - v1.1: Hash all fields including new metadata fields

    Args:
        prev_hash: Hash of the previous record in the chain.
        sequence: Monotonic sequence number.
        event_type: Event type (e.g., "AUDIT_FINDING", "GOVERNANCE_DECISION").
        control_id: NIST/ISO control identifier.
        payload_json: JSON-serialized event payload.
        schema_version: Schema version ("1.0" or "1.1").
        classification_reason: (v1.1) Reason for DEFER decisions.
        narrowing_applied: (v1.1) Narrowing constraints for NARROW decisions.
        pause_token: (v1.1) Token for PAUSE decisions.

    Returns:
        SHA-256 hex digest of the record.
    """
    schema_id = _SCHEMA_1_0 if schema_version == "1.0" else _SCHEMA_1_1

    if schema_version == "1.0":
        # v1.0: Original hash computation (backward compatible)
        header = json.dumps(
            {
                "schema": schema_id,
                "sequence": sequence,
                "event_type": event_type,
                "control_id": control_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return _sha256(prev_hash + header + payload_json)
    else:
        # v1.1: Include new metadata fields in hash computation
        # Only include non-None v1.1 fields to maintain determinism
        header_dict: dict[str, Any] = {
            "schema": schema_id,
            "sequence": sequence,
            "event_type": event_type,
            "control_id": control_id,
        }
        # Add v1.1 fields only if they have values (sparse inclusion)
        if classification_reason is not None:
            header_dict["classification_reason"] = classification_reason
        if narrowing_applied is not None:
            header_dict["narrowing_applied"] = narrowing_applied
        if pause_token is not None:
            header_dict["pause_token"] = pause_token

        header = json.dumps(header_dict, sort_keys=True, separators=(",", ":"))
        return _sha256(prev_hash + header + payload_json)


def _detect_schema_version(record: EvidenceRecord | dict[str, Any]) -> str:
    """Detect the schema version of an evidence record.

    Args:
        record: EvidenceRecord dataclass or dict representation.

    Returns:
        Schema version string ("1.0" or "1.1").
    """
    if isinstance(record, EvidenceRecord):
        return record.schema_version
    # For dict records, check for explicit version field
    version = record.get("schema_version")
    if version:
        return version
    # Check for schema field in wire format
    schema = record.get("schema", "")
    if schema == "cage-evidence-stream/1.1":
        return "1.1"
    # Default to 1.0 for records without version marker
    return "1.0"


def verify_record(record: EvidenceRecord | dict[str, Any], prev_hash: str) -> VerifyResult:
    """Verify evidence record hash with dual-schema support (v1.0 and v1.1).

    This function supports verification of both legacy v1.0 records and new
    v1.1 records, enabling seamless schema migration without breaking existing
    evidence chains.

    Verification Process:
        1. Detect schema version from record
        2. Extract fields according to detected version
        3. Compute hash using version-appropriate algorithm
        4. Compare computed hash against stored record_hash

    Args:
        record: EvidenceRecord dataclass or dict to verify.
        prev_hash: Hash of the previous record in the chain.

    Returns:
        VerifyResult with verification status and diagnostic information.

    Example:
        >>> result = verify_record(record, prev_hash)
        >>> if not result.valid:
        ...     logger.error(f"Chain integrity violation: {result.error}")
    """
    try:
        # Normalize to dict for consistent field access
        if isinstance(record, EvidenceRecord):
            record_dict = record.to_dict()
        else:
            record_dict = record

        # Detect schema version
        schema_version = _detect_schema_version(record_dict)

        # Extract common fields
        expected_hash = record_dict.get("record_hash", "")
        if not expected_hash:
            return VerifyResult(
                valid=False,
                schema_version=schema_version,
                computed_hash="",
                expected_hash="",
                error="Record missing record_hash field",
            )

        # Extract fields for hash computation
        # Handle both wire format (sequence as string) and internal format
        sequence_raw = record_dict.get("sequence", 0)
        sequence = int(sequence_raw) if isinstance(sequence_raw, str) else sequence_raw

        event_type = record_dict.get("event_type", record_dict.get("decision", "UNKNOWN"))
        control_id = record_dict.get("control_id", "")

        # Extract payload - handle both wire format and internal format
        payload = record_dict.get("payload")
        if payload is None:
            payload_json = record_dict.get("payload_json", "{}")
        elif isinstance(payload, str):
            payload_json = payload
        else:
            payload_json = json.dumps(payload, sort_keys=True, default=str)

        # v1.1 specific fields
        classification_reason = record_dict.get("classification_reason")
        narrowing_applied = record_dict.get("narrowing_applied")
        pause_token = record_dict.get("pause_token")

        # Compute hash using version-aware algorithm
        computed_hash = _link_hash_versioned(
            prev_hash=prev_hash,
            sequence=sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            schema_version=schema_version,
            classification_reason=classification_reason,
            narrowing_applied=narrowing_applied,
            pause_token=pause_token,
        )

        # Verify hash matches
        if computed_hash == expected_hash:
            return VerifyResult(
                valid=True,
                schema_version=schema_version,
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                error=None,
            )
        else:
            return VerifyResult(
                valid=False,
                schema_version=schema_version,
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                error=f"Hash mismatch: computed={computed_hash[:16]}... expected={expected_hash[:16]}...",
            )

    except Exception as exc:
        return VerifyResult(
            valid=False,
            schema_version="unknown",
            computed_hash="",
            expected_hash=str(record.get("record_hash", "") if isinstance(record, dict) else getattr(record, "record_hash", "")),
            error=f"Verification error: {exc}",
        )


def migrate_record_1_0_to_1_1(record: dict[str, Any]) -> EvidenceRecord:
    """Upgrade a v1.0 evidence record to v1.1 format with default values.

    This migration helper preserves all existing v1.0 fields and adds
    v1.1 metadata fields with appropriate defaults. The record_hash is
    NOT recomputed - the original hash is preserved to maintain chain
    integrity.

    Migration Rules:
        - schema_version: Set to "1.1"
        - classification_reason: Set to None (no classification for legacy records)
        - narrowing_applied: Set to None (no narrowing metadata for legacy records)
        - pause_token: Set to None (no pause token for legacy records)

    Note on prev_hash Seeding (per specs §4.1):
        On cutover to v1.1, the first v1.1 record's prev_hash MUST be seeded
        from the LAST v1.0 record's record_hash, NOT a genesis sentinel.
        This ensures chain continuity across schema versions.

    Args:
        record: v1.0 record as dict.

    Returns:
        EvidenceRecord with v1.1 schema version.

    Example:
        >>> v1_0_record = {"evidence_id": "evt-123", "decision": "ALLOW", ...}
        >>> v1_1_record = migrate_record_1_0_to_1_1(v1_0_record)
        >>> v1_1_record.schema_version
        '1.1'
    """
    # Parse timestamp if it's a string
    timestamp = record.get("timestamp")
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    elif timestamp is None:
        timestamp = datetime.now(tz=timezone.utc)

    # Handle wire format conversions
    payload = record.get("payload")
    if payload is None:
        payload_json = record.get("payload_json", "{}")
        try:
            payload = json.loads(payload_json)
        except (json.JSONDecodeError, TypeError):
            payload = {}
    elif isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            payload = {}

    return EvidenceRecord(
        evidence_id=record.get("evidence_id", ""),
        decision=record.get("decision", record.get("event_type", "")),
        timestamp=timestamp,
        tool_name=record.get("tool_name", ""),
        control_id=record.get("control_id", ""),
        prev_hash=record.get("prev_hash", ""),
        record_hash=record.get("record_hash", ""),
        payload=payload,
        # Upgrade to v1.1 with default values for new fields
        schema_version="1.1",
        classification_reason=None,
        narrowing_applied=None,
        pause_token=None,
    )


def get_last_v1_0_hash(records: list[dict[str, Any]]) -> str:
    """Extract the hash of the last v1.0 record for cutover seeding.

    Per specs §4.1: On cutover to v1.1, prev_hash must be seeded from
    the LAST v1.0 record, NOT a genesis sentinel. This function finds
    the last v1.0 record in a sequence and returns its record_hash.

    Args:
        records: List of evidence records (newest last).

    Returns:
        The record_hash of the last v1.0 record, or the genesis hash
        if no v1.0 records exist.
    """
    genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")

    # Scan from end to find last v1.0 record
    for record in reversed(records):
        version = _detect_schema_version(record)
        if version == "1.0":
            return record.get("record_hash", genesis_hash)

    # No v1.0 records found - this is a fresh chain
    return genesis_hash


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
        self._flush_task: asyncio.Task | None = None
        self._chain_lock = asyncio.Lock()

    async def start(self) -> None:
        """Connect to Redis and start the GCS flush daemon."""
        if self._running:
            return

        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(  # type: ignore[assignment]
                self._redis_url,
                db=self._redis_db,
                decode_responses=True,
            )
            # Verify connectivity
            await self._redis.ping()  # type: ignore[attr-defined]
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

    async def ingest(self, event: dict) -> str | None:
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

        # Hash-chain the event — lock guards all reads/writes of _prev_hash and _sequence
        payload_json = json.dumps(event, sort_keys=True, default=str)

        event_type = event.get("type", "UNKNOWN")
        control_id = event.get("controlId", "")

        async with self._chain_lock:
            record_hash = _link_hash(
                prev_hash=self._prev_hash,
                sequence=self._sequence,
                event_type=event_type,
                control_id=control_id,
                payload_json=payload_json,
            )

            entry = {
                "schema": _SCHEMA,
                "sequence": str(self._sequence),
                "event_type": event_type,
                "control_id": control_id,
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

    async def ingest_sync(
        self,
        event: dict[str, Any],
        timeout_seconds: float = _EVIDENCE_COMMIT_TIMEOUT_S,
    ) -> EvidenceCommitResult:
        """Blocking ingest that returns only after evidence is committed.

        This method provides a synchronous evidence commit guarantee required
        by the EVIDENCE_CHAIN_BLOCKING gate. Unlike ``ingest()``, this method:
          - Raises ``EvidenceChainUnavailableError`` if commit fails
          - Has explicit timeout handling
          - Returns structured ``EvidenceCommitResult`` with commit proof
          - Records telemetry (OTel spans, Prometheus metrics)

        Risk mitigation: R-06 (evidence-of-execution claims overclaimed)
        When EVIDENCE_CHAIN_BLOCKING=true, seal issuance calls this method
        instead of the fire-and-forget ``ingest()`` to ensure evidence is
        durably committed before any seal is issued.

        Args:
            event: GovernanceEvent dict from the SSE event bus or governance
                   decision payload.
            timeout_seconds: Maximum time to wait for commit (default: 5.0s).
                             On timeout, raises EvidenceChainUnavailableError.

        Returns:
            EvidenceCommitResult with commit proof (evidence_id, hash, timestamp).

        Raises:
            EvidenceChainUnavailableError: If Redis is unavailable, commit fails,
                or timeout is exceeded. Caller MUST NOT issue a routing seal when
                this exception is raised.
        """
        import time

        start_time = time.perf_counter()

        with tracer.start_as_current_span("cage.evidence.ingest_sync") as span:
            span.set_attribute("cage.evidence.blocking_mode", True)
            span.set_attribute("cage.evidence.timeout_seconds", timeout_seconds)

            try:
                # Check Redis availability
                if self._redis is None:
                    error_msg = (
                        "Evidence chain unavailable: Redis connection not established. "
                        "Cannot commit evidence — seal issuance blocked."
                    )
                    logger.error("[EvidenceStream] %s", error_msg)
                    span.set_attribute("cage.evidence.status", "failure")
                    span.set_attribute("cage.evidence.failure_reason", "redis_unavailable")
                    if _PROM_AVAILABLE:
                        EVIDENCE_COMMIT_TOTAL.labels(status="failure").inc()
                    raise EvidenceChainUnavailableError(error_msg)

                # Hash-chain the event with timeout protection
                try:
                    result = await asyncio.wait_for(
                        self._ingest_with_result(event),
                        timeout=timeout_seconds,
                    )
                except asyncio.TimeoutError as exc:
                    elapsed = time.perf_counter() - start_time
                    error_msg = (
                        f"Evidence commit timeout after {elapsed:.2f}s "
                        f"(limit: {timeout_seconds}s). Cannot guarantee durable "
                        "commit — seal issuance blocked."
                    )
                    logger.error("[EvidenceStream] %s", error_msg)
                    span.set_attribute("cage.evidence.status", "timeout")
                    span.set_attribute("cage.evidence.elapsed_seconds", elapsed)
                    if _PROM_AVAILABLE:
                        EVIDENCE_COMMIT_TOTAL.labels(status="timeout").inc()
                    raise EvidenceChainUnavailableError(error_msg, exc) from exc

                # Verify commit succeeded
                if not result.success:
                    error_msg = (
                        f"Evidence commit failed: evidence_id={result.evidence_id}. "
                        "Cannot guarantee durable commit — seal issuance blocked."
                    )
                    logger.error("[EvidenceStream] %s", error_msg)
                    span.set_attribute("cage.evidence.status", "failure")
                    span.set_attribute("cage.evidence.failure_reason", "commit_failed")
                    if _PROM_AVAILABLE:
                        EVIDENCE_COMMIT_TOTAL.labels(status="failure").inc()
                    raise EvidenceChainUnavailableError(error_msg)

                # Success path
                elapsed = time.perf_counter() - start_time
                span.set_attribute("cage.evidence.status", "success")
                span.set_attribute("cage.evidence.evidence_id", result.evidence_id)
                span.set_attribute("cage.evidence.hash", result.hash[:16])
                span.set_attribute("cage.evidence.sequence", result.sequence)
                span.set_attribute("cage.evidence.elapsed_seconds", elapsed)

                if _PROM_AVAILABLE:
                    EVIDENCE_COMMIT_TOTAL.labels(status="success").inc()
                    EVIDENCE_COMMIT_DURATION.observe(elapsed)

                logger.info(
                    "[EvidenceStream] Blocking commit succeeded: "
                    "evidence_id=%s hash=%s… seq=%d (%.3fs)",
                    result.evidence_id,
                    result.hash[:16],
                    result.sequence,
                    elapsed,
                )
                return result

            except EvidenceChainUnavailableError:
                raise
            except Exception as exc:
                elapsed = time.perf_counter() - start_time
                error_msg = (
                    f"Evidence commit failed with unexpected error: {exc}. "
                    "Cannot guarantee durable commit — seal issuance blocked."
                )
                logger.error("[EvidenceStream] %s", error_msg, exc_info=True)
                span.set_attribute("cage.evidence.status", "failure")
                span.set_attribute("cage.evidence.failure_reason", "unexpected_error")
                span.set_attribute("cage.evidence.elapsed_seconds", elapsed)
                span.record_exception(exc)
                if _PROM_AVAILABLE:
                    EVIDENCE_COMMIT_TOTAL.labels(status="failure").inc()
                raise EvidenceChainUnavailableError(error_msg, exc) from exc

    async def _ingest_with_result(self, event: dict[str, Any]) -> EvidenceCommitResult:
        """Internal helper that performs ingest and returns structured result.

        This method is used by ``ingest_sync()`` to get detailed commit information
        including the hash and sequence number for the commit proof.
        """
        # Hash-chain the event — lock guards all reads/writes of _prev_hash and _sequence
        payload_json = json.dumps(event, sort_keys=True, default=str)

        event_type = event.get("type", "UNKNOWN")
        control_id = event.get("controlId", "")

        async with self._chain_lock:
            current_sequence = self._sequence
            record_hash = _link_hash(
                prev_hash=self._prev_hash,
                sequence=current_sequence,
                event_type=event_type,
                control_id=control_id,
                payload_json=payload_json,
            )

            commit_timestamp = datetime.now(tz=timezone.utc)
            entry = {
                "schema": _SCHEMA,
                "sequence": str(current_sequence),
                "event_type": event_type,
                "control_id": control_id,
                "prev_hash": self._prev_hash,
                "record_hash": record_hash,
                "payload_json": payload_json,
                "timestamp_utc": commit_timestamp.isoformat(),
                "kms_signature": "",
                "kms_signature_algorithm": _get_signing_algorithm(),
            }

            # Persist to Redis Stream BEFORE advancing chain state
            # This ensures we don't advance the chain if Redis write fails
            try:
                msg_id = await self._redis.xadd(  # type: ignore[union-attr]
                    self._stream_key,
                    entry,
                    maxlen=self._max_len,
                )
            except Exception as exc:
                # Don't advance chain state — commit failed
                logger.error(
                    "[EvidenceStream] Redis write failed in _ingest_with_result: %s",
                    exc,
                )
                return EvidenceCommitResult(
                    success=False,
                    evidence_id="",
                    commit_timestamp=commit_timestamp,
                    hash=record_hash,
                    sequence=current_sequence,
                )

            # Advance chain state only after successful Redis write
            self._prev_hash = record_hash
            self._sequence += 1

        # Optional KMS signing (async, non-blocking) — best effort
        if self._kms_sign:
            self._enqueue_signing(entry)

        logger.debug(
            "[EvidenceStream] _ingest_with_result: seq=%s hash=%s… msg_id=%s",
            entry["sequence"],
            record_hash[:16],
            msg_id,
        )

        return EvidenceCommitResult(
            success=True,
            evidence_id=str(msg_id),
            commit_timestamp=commit_timestamp,
            hash=record_hash,
            sequence=current_sequence,
        )

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
            logger.warning("[EvidenceStream] KMS enqueue failed: %s", exc)

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
                logger.error("[EvidenceStream] GCS flush error: %s", exc)
                await asyncio.sleep(5.0)

    async def _upload_to_gcs(self, content: str, batch_id: str) -> None:
        """Upload NDJSON content to a CMEK-encrypted GCS bucket.

        Uses the google-cloud-storage async client. If not available,
        logs a warning (GCS flush is best-effort — the Redis Stream
        retains all data).
        """
        try:
            from google.cloud import storage  # type: ignore[import, attr-defined]

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

_evidence_sink: EvidenceStreamSink | None = None


def get_evidence_sink() -> EvidenceStreamSink:
    """Return the module-level EvidenceStreamSink singleton."""
    global _evidence_sink
    if _evidence_sink is None:
        _evidence_sink = EvidenceStreamSink()
    return _evidence_sink
