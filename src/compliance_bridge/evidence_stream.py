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
from decimal import Decimal
from typing import Any

from opentelemetry import trace

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

# ---------------------------------------------------------------------------
# JSON normalization helper for JCS
# ---------------------------------------------------------------------------


def _normalize_for_jcs(obj: Any) -> Any:
    """Recursively normalize objects for JCS canonicalization.

    JCS (RFC 8785) requires JSON-native types only. This helper converts:
    - datetime -> ISO 8601 string
    - Decimal -> str
    - Any other non-JSON-native -> str
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return str(obj)
    elif isinstance(obj, dict):
        return {k: _normalize_for_jcs(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_for_jcs(item) for item in obj]
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        # Fallback for unknown types
        return str(obj)


logger = logging.getLogger("cage.evidence_stream")
tracer = trace.get_tracer(__name__)

# Prometheus metrics (lazy import to avoid dependency in tests)
_PROM_AVAILABLE = False
try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram

    try:
        EVIDENCE_COMMIT_TOTAL = Counter(
            "cage_evidence_commit_total",
            "Total evidence commit attempts",
            ["status"],
        )
    except ValueError:
        EVIDENCE_COMMIT_TOTAL = REGISTRY._names_to_collectors.get("cage_evidence_commit_total")  # type: ignore[assignment]
    
    try:
        EVIDENCE_COMMIT_DURATION = Histogram(
            "cage_evidence_commit_duration_seconds",
            "Evidence commit latency in seconds",
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
        )
    except ValueError:
        EVIDENCE_COMMIT_DURATION = REGISTRY._names_to_collectors.get("cage_evidence_commit_duration_seconds")  # type: ignore[assignment]
    
    try:
        EVIDENCE_BLOCKING_DISABLED = Gauge(
            "cage_evidence_blocking_disabled",
            "Set to 1 when evidence blocking is disabled (seals issued without evidence guarantee)",
            ["env"],
        )
    except ValueError:
        EVIDENCE_BLOCKING_DISABLED = REGISTRY._names_to_collectors.get("cage_evidence_blocking_disabled")  # type: ignore[assignment]
    
    try:
        EVIDENCE_STREAM_DISABLED = Gauge(
            "cage_evidence_stream_disabled",
            "Set to 1 when evidence stream is disabled (no durable evidence chain)",
            ["env"],
        )
    except ValueError:
        EVIDENCE_STREAM_DISABLED = REGISTRY._names_to_collectors.get("cage_evidence_stream_disabled")  # type: ignore[assignment]
    
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
    classification_reason: str | None = None
    narrowing_applied: dict[str, Any] | None = None
    pause_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for Redis storage or JSON encoding."""
        result: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "decision": self.decision,
            "timestamp": self.timestamp.isoformat()
            if isinstance(self.timestamp, datetime)
            else self.timestamp,
            "tool_name": self.tool_name,
            "control_id": self.control_id,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "payload": self.payload,
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
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        """Deserialize from dict (v1.1 schema only)."""
        # Parse timestamp if it's a string
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(tz=timezone.utc)

        return cls(
            evidence_id=data.get("evidence_id", ""),
            decision=data.get("decision", ""),
            timestamp=timestamp,
            tool_name=data.get("tool_name", ""),
            control_id=data.get("control_id", ""),
            prev_hash=data.get("prev_hash", ""),
            record_hash=data.get("record_hash", ""),
            payload=data.get("payload", {}),
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
# succeeds. When "false", fire-and-forget behavior is used (lower latency, weaker guarantee).
# This flag mitigates risk R-06 (evidence-of-execution claims overclaimed).
# DEFAULT CHANGED (peer review Fix B): Enabled by default to ensure evidence durability
# before execution proceeds. This guarantees audit trail integrity at the cost of ~5ms latency.
# Operators can disable with EVIDENCE_CHAIN_BLOCKING=false if latency is critical.
# Cross-region impact: US_FED, EU_ECB, APAC_MAS all require evidence durability for compliance.
_EVIDENCE_CHAIN_BLOCKING: bool = (
    os.environ.get("EVIDENCE_CHAIN_BLOCKING", "true").lower() == "true"
)

# Default timeout for blocking evidence commits (seconds)
_EVIDENCE_COMMIT_TIMEOUT_S: float = float(
    os.environ.get("EVIDENCE_COMMIT_TIMEOUT_S", "5.0")
)

# v3.0.0 Breaking Change: Schema v1.0 support has been removed.
# All new records use v1.1 schema exclusively.
# v3.1.0 Breaking Change: Migrated to RFC 8785 JCS canonicalization.
_SCHEMA = "cage-evidence-stream/2.0"


def validate_evidence_stream_preconditions() -> None:
    """Validates evidence stream configuration at startup.

    B4 Enhancement: Extended validation with three checks:

    1. **Contradictory config (existing)**: Raises ConfigurationError if
       EVIDENCE_CHAIN_BLOCKING=true but EVIDENCE_STREAM_ENABLED=false.
       This is an invalid configuration because the blocking gate will
       always fail when the evidence stream is disabled.

    2. **Production non-blocking (new)**: When CAGE_ENV=prod and
       EVIDENCE_CHAIN_BLOCKING=false, logs a critical warning and fails
       startup unless CAGE_ALLOW_NONBLOCKING_PROD=true is set. This prevents
       operators from accidentally running production without evidence
       guarantees.

    3. **Stream disabled warning (new)**: When EVIDENCE_STREAM_ENABLED=false
       in any environment, logs a warning that evidence chain is not active.
       This is informational - does not fail startup.

    This function should be called during service startup (gateway and
    compliance bridge) to fail fast rather than at runtime.

    Environment Variables:
        EVIDENCE_STREAM_ENABLED: Enable the evidence stream (default: "false")
        EVIDENCE_CHAIN_BLOCKING: Block seal issuance until evidence commit
            succeeds (default: "true")
        CAGE_ENV: Deployment environment ("dev", "staging", "prod")
        CAGE_ALLOW_NONBLOCKING_PROD: Override to allow non-blocking mode in
            production (default: "false")

    Raises:
        ConfigurationError: If EVIDENCE_CHAIN_BLOCKING=true and
            EVIDENCE_STREAM_ENABLED=false (contradictory config).
        ConfigurationError: If CAGE_ENV=prod and EVIDENCE_CHAIN_BLOCKING=false
            without CAGE_ALLOW_NONBLOCKING_PROD=true (unsafe production config).
    """
    # Read configuration from environment
    stream_enabled = (
        os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"
    )
    # Note: Default matches module-level _EVIDENCE_CHAIN_BLOCKING (line ~320)
    blocking_enabled = (
        os.environ.get("EVIDENCE_CHAIN_BLOCKING", "true").lower() == "true"
    )
    cage_env = os.environ.get("CAGE_ENV", "dev").lower()
    allow_nonblocking_prod = (
        os.environ.get("CAGE_ALLOW_NONBLOCKING_PROD", "false").lower() == "true"
    )

    # -------------------------------------------------------------------------
    # Check 1: Contradictory config (blocking=true but stream=false)
    # This is always an error - the blocking gate will always fail.
    # -------------------------------------------------------------------------
    if blocking_enabled and not stream_enabled:
        raise ConfigurationError(
            "EVIDENCE_CHAIN_BLOCKING=true requires EVIDENCE_STREAM_ENABLED=true. "
            f"Current configuration: EVIDENCE_CHAIN_BLOCKING={blocking_enabled}, "
            f"EVIDENCE_STREAM_ENABLED={stream_enabled}. "
            "Either enable the evidence stream or disable blocking mode."
        )

    # -------------------------------------------------------------------------
    # Check 2: Production non-blocking (B4 Enhancement)
    # When CAGE_ENV=prod and blocking is disabled, seals are issued regardless
    # of whether evidence writes succeed. This is dangerous in production.
    # -------------------------------------------------------------------------
    if cage_env == "prod" and not blocking_enabled:
        logger.critical(
            "[EvidenceStream] CRITICAL: EVIDENCE_CHAIN_BLOCKING=false in production! "
            "Seals will be issued without evidence durability guarantee. "
            "This violates compliance requirements for audit trail integrity. "
            "Set CAGE_ALLOW_NONBLOCKING_PROD=true to acknowledge and override.",
            extra={"env": cage_env, "blocking_enabled": blocking_enabled},
        )

        # Emit Prometheus metric for monitoring/alerting
        if _PROM_AVAILABLE and EVIDENCE_BLOCKING_DISABLED is not None:
            EVIDENCE_BLOCKING_DISABLED.labels(env=cage_env).set(1)

        # Fail startup unless explicitly overridden
        if not allow_nonblocking_prod:
            raise ConfigurationError(
                "Non-blocking evidence mode is forbidden in production. "
                "EVIDENCE_CHAIN_BLOCKING=false means seals are issued without "
                "waiting for evidence to be durably committed, which violates "
                "audit trail integrity requirements. "
                "Set CAGE_ALLOW_NONBLOCKING_PROD=true to explicitly acknowledge "
                "and override this safety check."
            )
        else:
            logger.warning(
                "[EvidenceStream] CAGE_ALLOW_NONBLOCKING_PROD=true override active. "
                "Production is running without evidence blocking. "
                "Audit trail integrity is NOT guaranteed.",
                extra={"env": cage_env},
            )

    # -------------------------------------------------------------------------
    # Check 3: Stream disabled warning (B4 Enhancement)
    # When evidence stream is disabled, log a warning for visibility.
    # This is informational and does not fail startup.
    # -------------------------------------------------------------------------
    if not stream_enabled:
        logger.warning(
            "[EvidenceStream] EVIDENCE_STREAM_ENABLED=false - evidence chain is not active. "
            "Governance decisions will NOT be hash-chained or durably persisted. "
            "This is acceptable for local development but not recommended for "
            "staging or production environments.",
            extra={"env": cage_env, "stream_enabled": stream_enabled},
        )

        # Emit Prometheus metric for monitoring
        if _PROM_AVAILABLE and EVIDENCE_STREAM_DISABLED is not None:
            EVIDENCE_STREAM_DISABLED.labels(env=cage_env).set(1)

    # Log final configuration state
    logger.info(
        "[EvidenceStream] Precondition check passed: "
        "EVIDENCE_CHAIN_BLOCKING=%s, EVIDENCE_STREAM_ENABLED=%s, CAGE_ENV=%s",
        blocking_enabled,
        stream_enabled,
        cage_env,
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


def _sha256(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _link_hash(
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
    classification_reason: str | None = None,
    narrowing_applied: dict[str, Any] | None = None,
    pause_token: str | None = None,
) -> str:
    """Compute a stream entry's ``record_hash`` over its header + payload.

    The header carries the identifying metadata stored beside the payload in
    the Redis Stream entry, so re-ordering or re-labelling a record changes
    the link and breaks the chain.

    v3.0.0: Collapsed from _link_hash_v1_1 - all records now use v1.1 schema.

    Args:
        prev_hash: Hash of the previous record in the chain.
        sequence: Monotonic sequence number.
        event_type: Event type (e.g., "AUDIT_FINDING", "GOVERNANCE_DECISION").
        control_id: NIST/ISO control identifier.
        payload_json: JSON-serialized event payload.
        classification_reason: Reason for DEFER decisions (optional).
        narrowing_applied: Narrowing constraints for NARROW decisions (optional).
        pause_token: Token for PAUSE decisions (optional).

    Returns:
        SHA-256 hex digest of the record.
    """
    # v1.1: Include metadata fields in hash computation
    # Only include non-None fields to maintain determinism
    # v2.0: Migrated to RFC 8785 JCS canonicalization
    header_dict: dict[str, Any] = {
        "schema": _SCHEMA,
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

    header_bytes = jcs_canonicalize_plan(header_dict)
    return _sha256(
        prev_hash.encode("utf-8") + header_bytes + payload_json.encode("utf-8")
    )


def verify_record(
    record: EvidenceRecord | dict[str, Any], prev_hash: str
) -> VerifyResult:
    """Verify evidence record hash (v1.1 schema only).

    v3.0.0 Breaking Change: Schema v1.0 support has been removed.
    All records use v1.1 schema exclusively.

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

        # Extract common fields
        expected_hash = record_dict.get("record_hash", "")
        if not expected_hash:
            return VerifyResult(
                valid=False,
                schema_version="1.1",
                computed_hash="",
                expected_hash="",
                error="Record missing record_hash field",
            )

        # Extract fields for hash computation
        # Handle both wire format (sequence as string) and internal format
        sequence_raw = record_dict.get("sequence", 0)
        sequence = int(sequence_raw) if isinstance(sequence_raw, str) else sequence_raw

        event_type = record_dict.get(
            "event_type", record_dict.get("decision", "UNKNOWN")
        )
        control_id = record_dict.get("control_id", "")

        # Extract payload - handle both wire format and internal format
        # v2.0: Migrated to JCS with pre-normalization
        payload = record_dict.get("payload")
        if payload is None:
            payload_json = record_dict.get("payload_json", "{}")
        elif isinstance(payload, str):
            payload_json = payload
        else:
            normalized_payload = _normalize_for_jcs(payload)
            payload_json = jcs_canonicalize_plan(normalized_payload).decode("utf-8")

        # v1.1 specific fields
        classification_reason = record_dict.get("classification_reason")
        narrowing_applied = record_dict.get("narrowing_applied")
        pause_token = record_dict.get("pause_token")

        # Compute hash using current algorithm
        computed_hash = _link_hash(
            prev_hash=prev_hash,
            sequence=sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            classification_reason=classification_reason,
            narrowing_applied=narrowing_applied,
            pause_token=pause_token,
        )

        # Verify hash matches
        if computed_hash == expected_hash:
            return VerifyResult(
                valid=True,
                schema_version="1.1",
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                error=None,
            )
        else:
            return VerifyResult(
                valid=False,
                schema_version="1.1",
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                error=f"Hash mismatch: computed={computed_hash[:16]}... expected={expected_hash[:16]}...",
            )

    except Exception as exc:
        return VerifyResult(
            valid=False,
            schema_version="1.1",
            computed_hash="",
            expected_hash=str(
                record.get("record_hash", "")
                if isinstance(record, dict)
                else getattr(record, "record_hash", "")
            ),
            error=f"Verification error: {exc}",
        )


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
        # v2.0: Migrated to RFC 8785 JCS with pre-normalization
        normalized_event = _normalize_for_jcs(event)
        payload_json = jcs_canonicalize_plan(normalized_event).decode("utf-8")

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
                    span.set_attribute(
                        "cage.evidence.failure_reason", "redis_unavailable"
                    )
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
        # v2.0: Migrated to RFC 8785 JCS with pre-normalization
        normalized_event = _normalize_for_jcs(event)
        payload_json = jcs_canonicalize_plan(normalized_event).decode("utf-8")

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
            if self._redis is None:
                logger.error(
                    "[EvidenceStream] Redis not connected in _ingest_with_result"
                )
                return EvidenceCommitResult(
                    success=False,
                    evidence_id="",
                    commit_timestamp=commit_timestamp,
                    hash=record_hash,
                    sequence=current_sequence,
                )

            try:
                msg_id = await self._redis.xadd(
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
