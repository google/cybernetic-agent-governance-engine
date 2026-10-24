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
stream.py — Evidence-Grade Streaming Sink for Governance Events (Layer 1 Kernel)
================================================================================

Promotes the SSE event bus from fire-and-forget UI notifications to a
cryptographically hash-chained, durable evidence stream.

Architecture
------------
::

    GovernanceEventBus.publish() / routing seal / refusal receipts
        │
        └──→ EvidenceStreamSink.ingest() / ingest_sync()      (gateway, L1)
               │
               ├── PII sanitization, RFC 8785 JCS payload
               ├── SHA-256 hash chain (cage-audit/3.0 header + payload)
               ├── compare-and-append Lua script: XADD only if the stream
               │   head is still the head this record was sealed against,
               │   so replicas sharing the stream cannot fork the chain
               │
               └──→ Redis Stream on the governance instance (noeviction)
                      │
                      └──→ EvidenceCustodian                   (compliance bridge, L3)
                             re-verifies the chain, signs a batch attestation
                             with EVIDENCE_KMS_KEY, writes WORM batches, and
                             advances a durable cursor only after the write.

Responsibilities
----------------
This module is the **producer** only. It holds no signing key and no cold-store
credentials: signing and cold-store custody live in
``src/compliance_bridge/evidence_custodian.py``. Keeping the evidence key out of
the kernel workload preserves the per-workload key partition, and the
custodian's independent re-verification means a compromised producer cannot
get a broken chain signed.

Retry-safe appends
------------------
The pooled Redis client re-sends a command whose reply was lost (redis-py
``Retry`` on ``ConnectionError`` / ``TimeoutError``), so the append script
can run twice. Each batch therefore carries its last record's identity: a
re-sent script that finds that record at the head answers ``ALREADY`` with
the batch's entry IDs and writes nothing. A ``CONFLICT`` is not taken at face
value either: the sink first reads the ``k`` entries after the record the
batch was sealed against, and if they are the batch (it landed, then another
writer appended before the re-send arrived) it resolves from them instead of
re-sealing. When Redis does not answer at all, the identical script is
re-sent to settle the outcome; a batch is never re-sealed while its outcome
is unknown, and one that stays unknown fails with
``EvidenceAppendUnsettledError``. A record is therefore on the stream at most
once, and exactly once when its commit succeeds.

Chain restore
-------------
Chain state is restored from the stream head, which must hash to its own
``record_hash``. Only a sink that holds no chain yet may start a new one on
an empty stream (cold start). A sink that already holds a chain treats an
emptied stream, a head on another chain, or a head behind the last one it
acknowledged as truncation or tampering, and raises
``EvidenceChainCorruptError`` rather than starting over.

Wire format (Redis Stream entries, ``cage-audit/3.0``)
------------------------------------------------------
Each Redis Stream entry is a flat dict of strings (Redis Streams limitation)::

    {
      "schema":           "cage-audit/3.0",
      "chain_id":         "<uuid4>",
      "sequence":         "42",
      "timestamp_utc":    "2026-05-29T14:00:00+00:00",
      "event_type":       "GOVERNANCE_DECISION",
      "control_id":       "A.5.3",
      "trace_id":         "<32 hex>",
      "hash_algorithm":   "SHA-256",
      "canonicalization": "RFC8785",
      "evidence_class":   "GOVERNANCE",
      "prev_hash":        "<sha256 hex, empty at genesis>",
      "record_hash":      "<sha256 hex>",
      "payload_json":     "<JCS-canonical payload>",
      # sparse, only when present (inside the hash):
      "classification_reason", "narrowing_applied", "pause_token"
    }

Environment variables
---------------------
  EVIDENCE_STREAM_ENABLED    — "true" to enable (default: "false")
  EVIDENCE_STREAM_REDIS_URL  — Redis URL (default: uses REDIS_URL)
  EVIDENCE_STREAM_REDIS_DB   — Redis DB number (default: 1)
  EVIDENCE_STREAM_KEY        — Redis Stream key name (default: "cage:evidence:stream")
  EVIDENCE_STREAM_MAX_LEN    — Exact stream cap (default: 100000). The
                               custodian reports records trimmed before custody
                               as a gap.
  EVIDENCE_CHAIN_BLOCKING    — "true" (default): seals wait for the XADD ack
  EVIDENCE_COMMIT_TIMEOUT_S  — Blocking commit timeout (default: 5.0)
  EVIDENCE_GROUP_COMMIT_MAX_BATCH  — Max records coalesced per batch XADD (default: 64)
  EVIDENCE_GROUP_COMMIT_MAX_WAIT_MS — Coalescing window in milliseconds (default: 2.0)
  EVIDENCE_GROUP_COMMIT_QUEUE_SIZE — Bounded producer queue capacity (default: 1024)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
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


logger = logging.getLogger("cage.governance.evidence.stream")
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
        EVIDENCE_COMMIT_TOTAL = REGISTRY._names_to_collectors.get(
            "cage_evidence_commit_total"
        )  # type: ignore[assignment]

    try:
        EVIDENCE_COMMIT_DURATION = Histogram(
            "cage_evidence_commit_duration_seconds",
            "Evidence commit latency in seconds",
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
        )
    except ValueError:
        EVIDENCE_COMMIT_DURATION = REGISTRY._names_to_collectors.get(
            "cage_evidence_commit_duration_seconds"
        )  # type: ignore[assignment]

    try:
        EVIDENCE_BLOCKING_DISABLED = Gauge(
            "cage_evidence_blocking_disabled",
            "Set to 1 when evidence blocking is disabled (seals issued without evidence guarantee)",
            ["env"],
        )
    except ValueError:
        EVIDENCE_BLOCKING_DISABLED = REGISTRY._names_to_collectors.get(
            "cage_evidence_blocking_disabled"
        )  # type: ignore[assignment]

    try:
        EVIDENCE_STREAM_DISABLED = Gauge(
            "cage_evidence_stream_disabled",
            "Set to 1 when evidence stream is disabled (no durable evidence chain)",
            ["env"],
        )
    except ValueError:
        EVIDENCE_STREAM_DISABLED = REGISTRY._names_to_collectors.get(
            "cage_evidence_stream_disabled"
        )  # type: ignore[assignment]

    try:
        EVIDENCE_APPEND_CONFLICTS_TOTAL = Counter(
            "cage_evidence_append_conflicts_total",
            "Compare-and-append attempts that lost the chain head to another writer",
        )
    except ValueError:
        EVIDENCE_APPEND_CONFLICTS_TOTAL = REGISTRY._names_to_collectors.get(
            "cage_evidence_append_conflicts_total"
        )  # type: ignore[assignment]

    try:
        EVIDENCE_TRACE_SHED_TOTAL = Counter(
            "cage_evidence_trace_shed_total",
            "GOVERNANCE_TRACE events shed when the bounded evidence queue is full",
        )
    except ValueError:
        EVIDENCE_TRACE_SHED_TOTAL = REGISTRY._names_to_collectors.get(
            "cage_evidence_trace_shed_total"
        )  # type: ignore[assignment]

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


class EvidenceChainCorruptError(EvidenceChainUnavailableError):
    """Raised when Redis is reachable but the chain head cannot be trusted.

    This is deliberately distinct from a cold start. An empty stream is a
    legitimate genesis condition for a sink that holds no chain yet; a
    *non-empty* stream whose newest entry is missing its chain fields, carries
    a non-integer sequence, or does not hash to its own ``record_hash`` is
    evidence of truncation or tampering. So is, for a sink that already holds
    a chain, an emptied stream, a head on another chain, or a head behind the
    last one it acknowledged. Re-seeding genesis or resuming in that situation
    would silently fork the chain and destroy the only signal that something
    went wrong, so the sink refuses instead.

    Subclasses ``EvidenceChainUnavailableError`` so that callers already written
    to fail closed on an unavailable chain also fail closed on a corrupt one.
    """


class EvidenceAppendUnsettledError(EvidenceChainUnavailableError):
    """Raised when Redis did not answer an append, even after re-sending it.

    The append script may have run with only its reply lost, so the batch is
    on the stream at most once, but whether it landed is unknown. Re-sealing
    it is how one event ends up in the chain twice, so the sink fails the
    batch instead and re-reads the head before the next one. Blocking callers
    must not seal, as for any unavailable chain; best-effort ``ingest()``
    reports it like any other failed write.
    """


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
    """Structured evidence record on the ``cage-audit/3.0`` wire schema.

    v3.0.0 Breaking Change: Schema v1.0 support has been removed.
    v3.2.0 Breaking Change: ``chain_id``, ``trace_id`` and ``sequence`` are now
    first-class fields. All three are inside the record hash, so a record that
    omits them cannot be verified or rebuilt.

    Core fields:
        evidence_id: Unique identifier for the evidence record.
        decision: Governance decision (ALLOW, DENY, DEFER, NARROW, REQUIRE_APPROVAL).
        timestamp: UTC timestamp when the decision was made.
        tool_name: Name of the tool that was governed.
        control_id: NIST/ISO control identifier (e.g., "A.5.3").
        prev_hash: Hash of the previous record in the chain; ``""`` at genesis.
        record_hash: Hash of this record (computed from content).
        payload: Full decision payload (JSON-serializable dict).

    cage-audit/3.0 chain identity:
        chain_id: UUID of the chain this record belongs to. Inside the hash, so
            records cannot be spliced from one chain into another.
        trace_id: 32-hex-character OTel trace ID that produced the decision.
        sequence: Monotonic position within ``chain_id``.

    v1.1 metadata fields:
        classification_reason: Human-readable reason for DEFER decisions.
        narrowing_applied: Dict describing narrowing constraints for NARROW decisions.
        pause_token: Legacy. Written by the removed PAUSE verdict; kept so
            historical ``cage-audit/3.0`` records hash identically. No writer
            exists at HEAD.
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

    # cage-audit/3.0 chain identity
    chain_id: str = ""
    trace_id: str = ""
    sequence: int = 0

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
            "chain_id": self.chain_id,
            "trace_id": self.trace_id,
            "sequence": self.sequence,
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
        """Deserialize from dict (cage-audit/3.0 schema)."""
        # Parse timestamp if it's a string
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(tz=timezone.utc)

        # Redis Streams stringify every field, so sequence arrives as a str.
        sequence_raw = data.get("sequence", 0)
        sequence = int(sequence_raw) if sequence_raw not in (None, "") else 0

        return cls(
            evidence_id=data.get("evidence_id", ""),
            decision=data.get("decision", ""),
            timestamp=timestamp,
            tool_name=data.get("tool_name", ""),
            control_id=data.get("control_id", ""),
            chain_id=data.get("chain_id", ""),
            trace_id=data.get("trace_id", ""),
            sequence=sequence,
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

_EVIDENCE_STREAM_ENABLED: bool = (
    os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"
)

# Default timeout for blocking evidence commits (seconds)
_EVIDENCE_COMMIT_TIMEOUT_S: float = float(
    os.environ.get("EVIDENCE_COMMIT_TIMEOUT_S", "5.0")
)

# Group-commit batching configuration (Wave C2)
_GROUP_COMMIT_MAX_BATCH: int = max(
    1, int(os.environ.get("EVIDENCE_GROUP_COMMIT_MAX_BATCH", "64"))
)
_GROUP_COMMIT_MAX_WAIT_MS: float = max(
    0.0, float(os.environ.get("EVIDENCE_GROUP_COMMIT_MAX_WAIT_MS", "2.0"))
)
_GROUP_COMMIT_QUEUE_SIZE: int = max(
    1, int(os.environ.get("EVIDENCE_GROUP_COMMIT_QUEUE_SIZE", "1024"))
)
_STOP_DRAIN_TIMEOUT_S: float = float(
    os.environ.get("EVIDENCE_STOP_DRAIN_TIMEOUT_S", "5.0")
)

# v3.0.0 Breaking Change: Schema v1.0 support has been removed.
# All new records use v1.1 schema exclusively.
# v3.1.0 Breaking Change: Migrated to RFC 8785 JCS canonicalization.
#
# v3.2.0 BREAKING: wire schema realigned to ``cage-audit/3.0``.
# The kernel previously emitted ``cage-evidence-stream/2.0`` with no
# ``chain_id`` and no ``trace_id``.  The durable sink and the ClickHouse DDL
# (``deployment/clickhouse/evidence_stream_schema.sql``) require
# ``schema_version IN ('3.0')`` and enforce ``length(trace_id) > 0``, so every
# kernel-emitted record was rejected at INSERT.  The authoritative definition
# of the hashed header is the ``mv_evidence_hash_verification`` materialized
# view in that DDL; ``_link_hash()`` below mirrors it field for field.
_SCHEMA_VERSION = "3.0"
_SCHEMA = f"cage-audit/{_SCHEMA_VERSION}"

# Header members that the ClickHouse rebuild view pins to constants. They are
# inside the hash, so they cannot be silently changed on one side only.
_HASH_ALGORITHM = "SHA-256"
_CANONICALIZATION = "RFC8785"

# Evidence emitted by the kernel is always GOVERNANCE class. The DDL's other
# value, INFRA, is reserved for the compliance bridge's own operational rows.
_EVIDENCE_CLASS = "GOVERNANCE"


def validate_evidence_stream_preconditions() -> None:
    """Validate the gateway's evidence-stream configuration at startup.

    The gateway is the evidence *producer*: it hash-chains records into the
    Redis Stream. Signing and WORM custody belong to the compliance bridge
    (``src/compliance_bridge/evidence_custodian.py``), which validates its own
    preconditions. This function therefore checks only producer-side config:

    1. **Contradictory config**: ``EVIDENCE_CHAIN_BLOCKING=true`` with
       ``EVIDENCE_STREAM_ENABLED=false`` is always an error, because the
       blocking gate could never succeed.
    2. **Non-blocking under an enforcing posture**: when
       :func:`~src.gateway.governance.env_posture.is_enforcing` is true and
       ``EVIDENCE_CHAIN_BLOCKING=false``, startup fails unless
       ``CAGE_ALLOW_NONBLOCKING_PROD=true`` acknowledges the override.
    3. **Stream disabled under an enforcing posture**: an enforcing posture
       with ``EVIDENCE_STREAM_ENABLED=false`` fails startup; refusals and
       pause receipts would otherwise be silently dropped. Permissive
       postures (dev/test/ci) only log a warning.

    Raises:
        ConfigurationError: On any of the failing conditions above.
    """
    from src.gateway.governance.env_posture import is_enforcing, resolve_posture

    stream_enabled = (
        os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() == "true"
    )
    # Default matches module-level _EVIDENCE_CHAIN_BLOCKING.
    blocking_enabled = (
        os.environ.get("EVIDENCE_CHAIN_BLOCKING", "true").lower() == "true"
    )
    posture = resolve_posture()
    enforcing = is_enforcing(posture)
    allow_nonblocking_prod = (
        os.environ.get("CAGE_ALLOW_NONBLOCKING_PROD", "false").lower() == "true"
    )

    # Check 1: contradictory config.
    if blocking_enabled and not stream_enabled:
        raise ConfigurationError(
            "EVIDENCE_CHAIN_BLOCKING=true requires EVIDENCE_STREAM_ENABLED=true. "
            f"Current configuration: EVIDENCE_CHAIN_BLOCKING={blocking_enabled}, "
            f"EVIDENCE_STREAM_ENABLED={stream_enabled}. "
            "Either enable the evidence stream or disable blocking mode."
        )

    # Check 2: non-blocking mode under an enforcing posture.
    if enforcing and not blocking_enabled:
        logger.critical(
            "[EvidenceStream] CRITICAL: EVIDENCE_CHAIN_BLOCKING=false under "
            "enforcing posture %s. Seals would be issued without an evidence "
            "durability guarantee.",
            posture.value,
            extra={"env": posture.value, "blocking_enabled": blocking_enabled},
        )
        if _PROM_AVAILABLE and EVIDENCE_BLOCKING_DISABLED is not None:
            EVIDENCE_BLOCKING_DISABLED.labels(env=posture.value).set(1)

        if not allow_nonblocking_prod:
            raise ConfigurationError(
                "Non-blocking evidence mode is forbidden under an enforcing "
                f"posture ({posture.value}). EVIDENCE_CHAIN_BLOCKING=false means "
                "seals are issued without waiting for evidence to be durably "
                "committed. Set CAGE_ALLOW_NONBLOCKING_PROD=true to explicitly "
                "acknowledge and override this safety check."
            )
        logger.warning(
            "[EvidenceStream] CAGE_ALLOW_NONBLOCKING_PROD=true override active. "
            "Audit trail integrity is NOT guaranteed.",
            extra={"env": posture.value},
        )

    # Check 3: stream disabled.
    if not stream_enabled:
        if _PROM_AVAILABLE and EVIDENCE_STREAM_DISABLED is not None:
            EVIDENCE_STREAM_DISABLED.labels(env=posture.value).set(1)
        if enforcing:
            raise ConfigurationError(
                "EVIDENCE_STREAM_ENABLED=false is forbidden under an enforcing "
                f"posture ({posture.value}): refusal and pause receipts would "
                "be dropped instead of entering the tamper-evident chain."
            )
        logger.warning(
            "[EvidenceStream] EVIDENCE_STREAM_ENABLED=false - evidence chain is "
            "not active. Acceptable only for local development.",
            extra={"env": posture.value, "stream_enabled": stream_enabled},
        )

    logger.info(
        "[EvidenceStream] Precondition check passed: "
        "EVIDENCE_CHAIN_BLOCKING=%s, EVIDENCE_STREAM_ENABLED=%s, posture=%s",
        blocking_enabled,
        stream_enabled,
        posture.value,
    )


def is_evidence_chain_blocking() -> bool:
    """Return True if evidence chain blocking mode is enabled.

    When blocking mode is enabled, seal issuance blocks until evidence is
    committed to the durable evidence stream. This prevents overclaiming
    evidence-of-execution (risk R-06).
    """
    return _EVIDENCE_CHAIN_BLOCKING


def is_evidence_stream_enabled() -> bool:
    """Return True if evidence stream is enabled."""
    return _EVIDENCE_STREAM_ENABLED


# ---------------------------------------------------------------------------
# SHA-256 helpers (identical to context_accumulator.py)
# ---------------------------------------------------------------------------


def _sha256(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def current_trace_id() -> str:
    """Return the active OTel trace ID as 32 lowercase hex characters.

    The ClickHouse DDL enforces ``CONSTRAINT chk_trace_id_present CHECK
    length(trace_id) > 0``, and ``trace_id`` is inside the hashed header, so an
    empty value is not representable — a record with no trace would be rejected
    at INSERT and could never be rebuilt.

    When no valid span context is active (background daemons, tests, direct
    library use) a random 128-bit value is generated instead. It is
    deliberately random rather than a fixed sentinel: a constant would collapse
    every untraced record onto one bloom-filter key and make ``idx_trace_id``
    useless.
    """
    try:
        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            return f"{span_context.trace_id:032x}"
    except (ImportError, AttributeError):  # pragma: no cover - defensive
        pass
    return uuid.uuid4().hex


def _link_hash(
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
    chain_id: str,
    trace_id: str,
    classification_reason: str | None = None,
    narrowing_applied: dict[str, Any] | None = None,
    pause_token: str | None = None,
) -> str:
    """Compute a stream entry's ``record_hash`` over its header + payload.

    The header carries the identifying metadata stored beside the payload in
    the Redis Stream entry, so re-ordering or re-labelling a record changes
    the link and breaks the chain.

    v3.0.0: Collapsed from _link_hash_v1_1 - all records now use v1.1 schema.

    v3.2.0 BREAKING — ``cage-audit/3.0``: the header now mirrors the
    ``mv_evidence_hash_verification`` materialized view in
    ``deployment/clickhouse/evidence_stream_schema.sql``, which is the
    authoritative rebuild definition. Members, in the lexicographic order JCS
    produces and the view hardcodes:

        canonicalization, chain_id, [classification_reason], control_id,
        event_type, hash_algorithm, [narrowing_applied], [pause_token],
        schema, sequence, trace_id

    Bracketed members are sparse — emitted only when non-None, matching the
    view's ``if(... IS NULL, '', ...)`` branches.

    Args:
        prev_hash: Hash of the previous record in the chain. Must be ``""`` at
            sequence 0; the DDL enforces ``(sequence = 0) = (prev_hash IS NULL)``
            and the view hashes ``ifNull(prev_hash, '')``.
        sequence: Monotonic sequence number.
        event_type: Event type (e.g., "AUDIT_FINDING", "GOVERNANCE_DECISION").
        control_id: NIST/ISO control identifier.
        payload_json: JCS-canonical JSON payload. Hashed as opaque bytes and
            never re-serialized.
        chain_id: UUID identifying this chain. Inside the hash so records
            cannot be spliced between chains.
        trace_id: 32-hex-character OTel trace ID.
        classification_reason: Reason for DEFER decisions (optional).
        narrowing_applied: Narrowing constraints for NARROW decisions (optional).
        pause_token: Legacy PAUSE-verdict token (optional, read-only; see
            :class:`EvidenceRecord`).

    Returns:
        SHA-256 hex digest of the record.
    """
    header_dict: dict[str, Any] = {
        "canonicalization": _CANONICALIZATION,
        "chain_id": chain_id,
        "control_id": control_id,
        "event_type": event_type,
        "hash_algorithm": _HASH_ALGORITHM,
        "schema": _SCHEMA,
        "sequence": sequence,
        "trace_id": trace_id,
    }
    # Sparse members — present only when set, mirroring the view's NULL branches.
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


def _extract_sparse_header(
    event: dict[str, Any],
) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """Pull the three sparse ``cage-audit/3.0`` header members from an event.

    ``classification_reason``, ``narrowing_applied`` and ``pause_token`` are
    inside the record hash whenever they are present, and the ClickHouse table
    stores each in its own nullable column. Both ingest paths must agree
    exactly on how they are read, or the same event would hash differently
    depending on which entry point produced it — so extraction lives here, once.

    A ``narrowing_applied`` that is not a mapping is treated as absent: the
    column is populated from canonical JSON object text, and a scalar there
    could not be rebuilt by ``mv_evidence_hash_verification``.

    Returns:
        ``(classification_reason, narrowing_applied, pause_token)``, each None
        when the member is absent.
    """
    classification_reason = event.get("classification_reason")
    if classification_reason is not None:
        classification_reason = str(classification_reason)

    narrowing_applied = event.get("narrowing_applied")
    if not isinstance(narrowing_applied, dict):
        narrowing_applied = None

    pause_token = event.get("pause_token")
    if pause_token is not None:
        pause_token = str(pause_token)

    return classification_reason, narrowing_applied, pause_token


def verify_record(
    record: EvidenceRecord | dict[str, Any], prev_hash: str
) -> VerifyResult:
    """Verify an evidence record hash against the ``cage-audit/3.0`` contract.

    v3.0.0 Breaking Change: Schema v1.0 support has been removed.
    v3.2.0 Breaking Change: ``chain_id`` and ``trace_id`` are inside the hash.
    A record that carries neither cannot be verified — the recomputation will
    not match, and that is the correct outcome rather than a soft pass.

    Args:
        record: EvidenceRecord dataclass or wire dict to verify.
        prev_hash: Hash of the previous record in the chain. Pass ``""`` for
            the genesis record, matching the DDL's ``ifNull(prev_hash, '')``.

    Returns:
        VerifyResult with verification status and diagnostic information.

    Example:
        >>> result = verify_record(record, prev_hash)
        >>> if not result.valid:
        ...     logger.error(f"Chain integrity violation: {result.error}")
    """
    schema_version = _SCHEMA_VERSION
    try:
        # Normalize to dict for consistent field access
        if isinstance(record, EvidenceRecord):
            record_dict = record.to_dict()
        else:
            record_dict = record

        # Report the version the record actually claims, not the one we hope for.
        raw_schema = record_dict.get("schema", _SCHEMA)
        if isinstance(raw_schema, str) and raw_schema.startswith("cage-audit/"):
            schema_version = raw_schema.split("/", 1)[1]

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

        event_type = record_dict.get(
            "event_type", record_dict.get("decision", "UNKNOWN")
        )
        control_id = record_dict.get("control_id", "")
        chain_id = record_dict.get("chain_id", "")
        trace_id = record_dict.get("trace_id", "")

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
        # On the wire every Redis Stream field is a string, so narrowing_applied
        # arrives as canonical JSON text. Re-inflate it: _link_hash canonicalizes
        # the whole header, and feeding it a string would hash the quotes too.
        if isinstance(narrowing_applied, str):
            narrowing_applied = json.loads(narrowing_applied)
        pause_token = record_dict.get("pause_token")

        # Compute hash using current algorithm
        computed_hash = _link_hash(
            prev_hash=prev_hash,
            sequence=sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=chain_id,
            trace_id=trace_id,
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
            schema_version=schema_version,
            computed_hash="",
            expected_hash=str(
                record.get("record_hash", "")
                if isinstance(record, dict)
                else getattr(record, "record_hash", "")
            ),
            error=f"Verification error: {exc}",
        )


# ---------------------------------------------------------------------------
# Compare-and-append
# ---------------------------------------------------------------------------

# The head check and the XADDs run atomically inside Redis. Each gateway
# replica keeps its chain head in memory, and HA deployments run more than
# one replica against the same stream; a plain XADD would let two replicas
# seal against the same head and fork the chain. The script appends a batch
# only if the stream's newest entry is still the record the batch was sealed
# against (chain_id, first_sequence - 1, first_prev_hash), or the stream is
# empty and the batch starts at genesis.
#
# The pooled client re-sends a script whose reply was lost, so the script must
# also be safe to run twice. A re-sent script finds the batch's own last
# record at the head and answers ALREADY with the batch's entry IDs, writing
# nothing. That record is matched on chain_id, sequence, record_hash and
# timestamp_utc: the record hash is content-addressed, and the timestamp ties
# the match to this sealing rather than to a byte-identical event.
#
# KEYS[1] = stream key
# ARGV[1] = chain_id, ARGV[2] = first_sequence, ARGV[3] = first_prev_hash,
# ARGV[4] = MAXLEN, ARGV[5] = k (records in the batch),
# ARGV[6] = last record_hash, ARGV[7] = last timestamp_utc,
# followed by k records: [field_token_count_i, f1, v1, f2, v2, ...]
#
# Returns {'OK', id_1..id_k}, {'ALREADY', id_1..id_k} or {'CONFLICT'}.
_APPEND_BATCH_SCRIPT = """
local count = tonumber(ARGV[5])
local head = redis.call('XREVRANGE', KEYS[1], '+', '-', 'COUNT', 1)
if #head == 0 then
  if ARGV[2] ~= '0' or ARGV[3] ~= '' then
    return {'CONFLICT'}
  end
else
  local fields = head[1][2]
  local h = {}
  for i = 1, #fields, 2 do
    h[fields[i]] = fields[i + 1]
  end
  local head_seq = tonumber(h['sequence'])
  if h['chain_id'] == ARGV[1] and h['record_hash'] == ARGV[6]
      and h['timestamp_utc'] == ARGV[7]
      and head_seq == tonumber(ARGV[2]) + count - 1 then
    local landed = redis.call('XREVRANGE', KEYS[1], '+', '-', 'COUNT', count)
    local out = {'ALREADY'}
    for r = #landed, 1, -1 do
      out[#out + 1] = landed[r][1]
    end
    return out
  end
  if h['chain_id'] ~= ARGV[1] or h['record_hash'] ~= ARGV[3]
      or head_seq == nil or head_seq + 1 ~= tonumber(ARGV[2]) then
    return {'CONFLICT'}
  end
end
local idx = 8
local out = {'OK'}
for r = 1, count do
  local nfields = tonumber(ARGV[idx])
  idx = idx + 1
  out[r + 1] = redis.call('XADD', KEYS[1], 'MAXLEN', ARGV[4], '*', unpack(ARGV, idx, idx + nfields - 1))
  idx = idx + nfields
end
return out
"""

# nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
_APPEND_BATCH_SCRIPT_SHA = hashlib.sha1(
    _APPEND_BATCH_SCRIPT.encode("utf-8"), usedforsecurity=False
).hexdigest()

# Bound on re-seal attempts when another writer keeps winning the head.
_MAX_APPEND_ATTEMPTS = 8
_CONFLICT_BACKOFF_BASE_S = 0.001
_CONFLICT_BACKOFF_CAP_S = 0.010

# Bound on re-sending the identical script after Redis did not answer. The
# pooled client has already retried by then; these sends only settle whether
# the batch landed. The batch is never re-sealed while that is unknown.
_MAX_SETTLE_ATTEMPTS = 2
_SETTLE_BACKOFF_S = 0.05


def _redis_transport_errors() -> tuple[type[Exception], ...]:
    """Errors after which a sent command may or may not have run.

    redis-py raises its own ``ConnectionError`` / ``TimeoutError``, which do
    not subclass the builtins; it is imported lazily, like the client.
    """
    errors: tuple[type[Exception], ...] = (
        ConnectionError,
        TimeoutError,
        asyncio.TimeoutError,
    )
    try:
        from redis.exceptions import ConnectionError as RedisConnectionError
        from redis.exceptions import TimeoutError as RedisTimeoutError
    except ImportError:  # pragma: no cover - redis is a runtime dependency
        return errors
    return (*errors, RedisConnectionError, RedisTimeoutError)


def _as_str(value: Any) -> str:
    """Decode a Redis reply element (``bytes`` unless ``decode_responses``)."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


@dataclass(frozen=True)
class _AppendedRecord:
    """A record Redis has acknowledged, with the chain position it took."""

    entry: dict[str, str]
    record_hash: str
    msg_id: str
    sequence: int
    timestamp: datetime


@dataclass(frozen=True)
class _SealedRecord:
    """A record sealed for a batch that Redis has not acknowledged yet."""

    entry: dict[str, str]
    record_hash: str
    sequence: int
    timestamp: datetime


@dataclass(frozen=True)
class _SealedBatch:
    """One sealing of a queued batch against a specific chain head.

    ``prev_id`` is the stream ID of the record the batch was sealed against
    (``""`` at genesis). A batch that landed sits immediately after it, which
    is how a ``CONFLICT`` that hides an already-landed batch is told apart
    from a genuine lost race. ``args`` is the script ARGV, re-sent verbatim
    whenever the same sealing is re-sent.
    """

    chain_id: str
    first_sequence: int
    prev_id: str
    records: tuple[_SealedRecord, ...]
    args: tuple[str, ...]

    @property
    def last_sequence(self) -> int:
        return self.records[-1].sequence


@dataclass(frozen=True)
class _ChainHead:
    """The newest record a sink knows to be on the stream."""

    chain_id: str
    sequence: int
    record_hash: str


@dataclass(frozen=True)
class _QueuedEvidenceItem:
    """One pre-sanitized, JCS-encoded event waiting in the group-commit queue."""

    event: dict[str, Any]
    payload_json: str
    event_type: str
    control_id: str
    trace_id: str
    future: asyncio.Future[_AppendedRecord] | None = None


# ---------------------------------------------------------------------------
# EvidenceStreamSink — the core streaming sink
# ---------------------------------------------------------------------------


class EvidenceStreamSink:
    """Evidence-grade streaming sink backed by Redis Streams.

    Each governance event is hash-chained using the same SHA-256 algorithm
    as ``ContextAccumulator``, then persisted to a Redis Stream via a
    per-process group-commit appender task.

    Usage::

        sink = EvidenceStreamSink()
        await sink.start()

        # Ingest a governance event (from GovernanceEventBus.publish)
        await sink.ingest(event)

        # Graceful shutdown (drains pending items before closing Redis)
        await sink.stop()
    """

    def __init__(
        self,
        redis_url: str = _REDIS_URL,
        redis_db: int = _REDIS_DB,
        stream_key: str = _STREAM_KEY,
        max_len: int = _MAX_LEN,
        *,
        max_batch_size: int | None = None,
        max_wait_ms: float | None = None,
        queue_size: int | None = None,
    ) -> None:
        self._redis_url = redis_url
        self._redis_db = redis_db
        self._stream_key = stream_key
        self._max_len = max_len

        self._max_batch_size = (
            max(1, max_batch_size)
            if max_batch_size is not None
            else _GROUP_COMMIT_MAX_BATCH
        )
        self._max_wait_ms = (
            max(0.0, max_wait_ms)
            if max_wait_ms is not None
            else _GROUP_COMMIT_MAX_WAIT_MS
        )
        self._queue_size = (
            max(1, queue_size) if queue_size is not None else _GROUP_COMMIT_QUEUE_SIZE
        )

        self._redis = None  # Lazy-loaded redis.asyncio client
        # Chain state is NOT seeded here. Seeding genesis in __init__ meant
        # every process restart silently restarted the chain at sequence 0 with
        # a fresh prev_hash, forking the chain and producing SEQUENCE_GAP /
        # GENESIS_VIOLATION rows downstream. ``start()`` now restores this from
        # Redis and only falls back to genesis when the chain is provably empty.
        self._chain_id: str = ""
        self._prev_hash: str = ""
        self._sequence: int = 0
        # Stream ID of the record at ``_sequence - 1`` ("" at genesis): the
        # predecessor the next batch is sealed against.
        self._prev_id: str = ""
        # Newest record this sink has seen on the stream, restored or appended.
        # Minting a genesis chain does not set it, so a sink that loses a
        # cold-start race still adopts the winner's chain; once it is set,
        # restore refuses an emptied stream, another chain or a regressed head.
        self._acked_head: _ChainHead | None = None
        self._chain_restored = False
        self._running = False
        self._stopping = False
        self._chain_lock = asyncio.Lock()

        self._queue: asyncio.Queue[_QueuedEvidenceItem | None] | None = None
        self._queue_loop: asyncio.AbstractEventLoop | None = None
        self._appender_task: asyncio.Task[None] | None = None

    def _ensure_queue(self) -> asyncio.Queue[_QueuedEvidenceItem | None]:
        """Return the bounded producer queue for the active event loop."""
        loop = asyncio.get_running_loop()
        if self._queue is None or self._queue_loop is not loop:
            self._queue = asyncio.Queue(maxsize=self._queue_size)
            self._queue_loop = loop
        return self._queue

    def _ensure_appender_started(self) -> None:
        """Ensure the background group-commit appender task is running."""
        if self._redis is None or self._stopping:
            return
        queue = self._ensure_queue()
        loop = asyncio.get_running_loop()
        if (
            self._appender_task is None
            or self._appender_task.done()
            or self._appender_task.get_loop() is not loop
        ):
            self._appender_task = loop.create_task(
                self._appender_loop(queue),
                name=f"evidence-group-commit:{self._stream_key}",
            )

    async def start(self) -> None:
        """Connect to Redis, restore chain state, and launch the appender task.

        The sink is a producer only. Signing and WORM custody of the stream
        are the compliance bridge's job (``EvidenceCustodian``).
        """
        if self._running:
            return

        self._stopping = False

        try:
            from src.gateway.infrastructure.redis_client import build_async_redis

            self._redis = build_async_redis(self._redis_url, db=self._redis_db)
            # Verify connectivity
            await self._redis.ping()  # type: ignore[attr-defined]
            logger.info(
                "[EvidenceStream] Connected to Redis: db=%d stream=%s",
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

        # Recover chain state before accepting any writes. This is deliberately
        # outside the connect try/except: an unreachable Redis degrades to a
        # no-op sink, but a *reachable* Redis holding an unparseable chain head
        # is a fail-closed condition and must abort start().
        try:
            async with self._chain_lock:
                await self._ensure_chain_restored()
        except EvidenceChainUnavailableError:
            await self._redis.aclose()  # type: ignore[attr-defined]
            self._redis = None
            raise

        self._running = True
        self._ensure_appender_started()
        logger.info("[EvidenceStream] Started.")

    async def stop(self, drain_timeout_s: float = _STOP_DRAIN_TIMEOUT_S) -> None:
        """Drain pending queued records against a deadline and close Redis."""
        self._running = False
        self._stopping = True

        task = self._appender_task
        queue = self._queue
        if (
            task is not None
            and not task.done()
            and queue is not None
            and self._redis is not None
        ):
            try:
                await asyncio.wait_for(
                    self._shutdown_appender(queue, task),
                    timeout=drain_timeout_s,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "[EvidenceStream] Drain timed out after %.2fs; cancelling appender.",
                    drain_timeout_s,
                )
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            except Exception as exc:
                logger.warning("[EvidenceStream] Error draining appender: %s", exc)
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        elif task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # Fail any residual futures still sitting in the queue.
        if queue is not None:
            while not queue.empty():
                try:
                    item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if (
                    item is not None
                    and item.future is not None
                    and not item.future.done()
                ):
                    item.future.set_exception(
                        EvidenceChainUnavailableError("Evidence stream sink stopped.")
                    )

        self._appender_task = None

        if self._redis:
            await self._redis.aclose()
            self._redis = None

        logger.info(
            "[EvidenceStream] Stopped. Total records: %d",
            self._sequence,
        )

    async def _shutdown_appender(
        self,
        queue: asyncio.Queue[_QueuedEvidenceItem | None],
        task: asyncio.Task[None],
    ) -> None:
        """Enqueue sentinel and wait for the appender loop to finish draining."""
        await queue.put(None)
        await task

    # -- Chain state ------------------------------------------------------

    async def _ensure_chain_restored(self) -> None:
        """Restore chain state once, idempotently.

        Callers must already hold ``self._chain_lock``. Both ingest paths call
        this before reading chain state so that a sink handed a live Redis
        client without going through ``start()`` still resumes the existing
        chain rather than silently forking it.
        """
        if self._chain_restored:
            return
        await self._restore_chain_state()
        self._chain_restored = True

    async def _restore_chain_state(self) -> None:
        """Recover ``chain_id`` / ``sequence`` / ``prev_hash`` from the stream.

        The stream is the single source of truth. A separate chain-state key
        would be a second copy of the same facts, and the only thing two copies
        can add is the possibility of disagreeing.

        Three outcomes, and only three:

        * **Stream empty, and this sink holds no chain yet** — a genuine cold
          start. Mint a new ``chain_id`` and begin at sequence 0 with
          ``prev_hash = ""`` (stored NULL), satisfying the DDL's
          ``CONSTRAINT chk_genesis_prev_hash``.
        * **Stream has a head that verifies** — resume at ``sequence + 1`` with
          ``prev_hash`` set to that record's hash, under the same ``chain_id``.
          A sink that already holds a chain resumes only if the head is on
          that chain and not behind the last head it acknowledged.
        * **Anything else** — raise. That covers a head that cannot be parsed
          or does not hash to its own ``record_hash`` and, for a sink that
          already holds a chain, an emptied stream, a head on another chain,
          or a head behind (or forked from) the last acknowledged one. Redis
          answered, so none of these is a cold start: it is truncation or
          tampering, and re-genesising or resuming would overwrite the only
          evidence that it happened.

        The hash check rejects a corrupted head, or a forged one that was not
        re-hashed. It cannot authenticate the writer (the chain carries no
        secret), so write access to the stream stays a trust boundary.

        Raises:
            EvidenceChainUnavailableError: Redis client is absent, or the read
                itself failed.
            EvidenceChainCorruptError: The head is unusable, as described above.
        """
        if self._redis is None:
            raise EvidenceChainUnavailableError(
                "Cannot restore evidence chain state: no Redis client."
            )

        try:
            entries = await self._redis.xrevrange(
                self._stream_key, max="+", min="-", count=1
            )
        except Exception as exc:
            raise EvidenceChainUnavailableError(
                f"Failed to read evidence chain head from {self._stream_key}: {exc}",
                exc,
            ) from exc

        acked = self._acked_head

        def _corrupt(detail: str) -> EvidenceChainCorruptError:
            return EvidenceChainCorruptError(
                f"Evidence chain head in {self._stream_key} is unusable: {detail}. "
                "Refusing to start or resume a chain over it — this is a "
                "truncation or tampering signal, not a cold start."
            )

        if not entries:
            if acked is not None:
                raise _corrupt(
                    f"the stream is empty, but this sink already holds chain "
                    f"{acked.chain_id} up to sequence {acked.sequence}"
                )
            self._chain_id = str(uuid.uuid4())
            self._prev_hash = ""
            self._sequence = 0
            self._prev_id = ""
            logger.info(
                "[EvidenceStream] Stream %s is empty — starting new chain %s at "
                "sequence 0.",
                self._stream_key,
                self._chain_id,
            )
            return

        msg_id, fields = entries[0]

        chain_id = fields.get("chain_id") or ""
        record_hash = fields.get("record_hash") or ""
        sequence_raw = fields.get("sequence")

        if not chain_id:
            raise _corrupt("chain_id is missing or empty")
        if len(record_hash) != 64 or any(
            c not in "0123456789abcdef" for c in record_hash
        ):
            raise _corrupt(
                f"record_hash is not 64 lowercase hex chars ({record_hash!r})"
            )
        if sequence_raw is None:
            raise _corrupt("sequence is missing")
        try:
            last_sequence = int(sequence_raw)
        except (TypeError, ValueError) as exc:
            raise _corrupt(f"sequence {sequence_raw!r} is not an integer") from exc
        if last_sequence < 0:
            raise _corrupt(f"sequence {last_sequence} is negative")
        prev_hash = fields.get("prev_hash")
        if prev_hash is None:
            raise _corrupt("prev_hash is missing")
        verdict = verify_record(fields, prev_hash)
        if not verdict.valid:
            raise _corrupt(
                f"the head record does not hash to its record_hash ({verdict.error})"
            )

        if acked is not None:
            if chain_id != acked.chain_id:
                raise _corrupt(
                    f"the head is on chain {chain_id}, but this sink holds chain "
                    f"{acked.chain_id}"
                )
            if last_sequence < acked.sequence:
                raise _corrupt(
                    f"the head (sequence {last_sequence}) is behind the last "
                    f"acknowledged sequence {acked.sequence}"
                )
            if last_sequence == acked.sequence and record_hash != acked.record_hash:
                raise _corrupt(
                    f"sequence {last_sequence} no longer holds the acknowledged record"
                )

        self._chain_id = chain_id
        self._prev_hash = record_hash
        self._sequence = last_sequence + 1
        self._prev_id = _as_str(msg_id)
        self._acked_head = _ChainHead(chain_id, last_sequence, record_hash)
        logger.info(
            "[EvidenceStream] Resumed chain %s at sequence %d (head=%s…).",
            self._chain_id,
            self._sequence,
            record_hash[:16],
        )

    def _seal_record(
        self,
        event: dict[str, Any],
        payload_json: str,
        event_type: str,
        control_id: str,
        timestamp: datetime,
        *,
        prev_hash: str | None = None,
        sequence: int | None = None,
        trace_id: str | None = None,
    ) -> tuple[dict[str, str], str]:
        """Build one ``cage-audit/3.0`` wire entry and its record hash.

        Callers must hold ``self._chain_lock`` and must have restored chain
        state first. This does **not** advance the chain: ``_commit_batch()``
        does that, and only after Redis has acknowledged the write.

        Every field here is a string because Redis Streams store nothing else.

        Returns:
            ``(entry, record_hash)``.
        """
        classification_reason, narrowing_applied, pause_token = _extract_sparse_header(
            event
        )
        effective_prev_hash = self._prev_hash if prev_hash is None else prev_hash
        effective_sequence = self._sequence if sequence is None else sequence
        effective_trace_id = current_trace_id() if trace_id is None else trace_id

        record_hash = _link_hash(
            prev_hash=effective_prev_hash,
            sequence=effective_sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=self._chain_id,
            trace_id=effective_trace_id,
            classification_reason=classification_reason,
            narrowing_applied=narrowing_applied,
            pause_token=pause_token,
        )

        entry: dict[str, str] = {
            "schema": _SCHEMA,
            "chain_id": self._chain_id,
            "sequence": str(effective_sequence),
            "timestamp_utc": timestamp.isoformat(),
            "event_type": event_type,
            "control_id": control_id,
            "trace_id": effective_trace_id,
            "hash_algorithm": _HASH_ALGORITHM,
            "canonicalization": _CANONICALIZATION,
            "evidence_class": _EVIDENCE_CLASS,
            # "" at genesis; the sink maps it to NULL to satisfy
            # CONSTRAINT chk_genesis_prev_hash.
            "prev_hash": effective_prev_hash,
            "record_hash": record_hash,
            "payload_json": payload_json,
        }

        # Sparse members travel as top-level fields so the ClickHouse sink can
        # populate its nullable columns without re-parsing the payload.
        # narrowing_applied is stored as canonical JSON text — the exact bytes
        # that went into the hash — so the rebuild view can concatenate it raw.
        if classification_reason is not None:
            entry["classification_reason"] = classification_reason
        if narrowing_applied is not None:
            entry["narrowing_applied"] = jcs_canonicalize_plan(
                _normalize_for_jcs(narrowing_applied)
            ).decode("utf-8")
        if pause_token is not None:
            entry["pause_token"] = pause_token

        return entry, record_hash

    def _prepare_item(
        self,
        event: dict[str, Any],
        *,
        future: asyncio.Future[_AppendedRecord] | None,
    ) -> _QueuedEvidenceItem:
        """Sanitize, normalize, and JCS-encode ``event`` on the producer side."""
        from src.gateway.governance.pii_sanitizer import _get_pii_sanitizer

        sanitized_event = _get_pii_sanitizer().sanitize_dict(event)
        normalized_event = _normalize_for_jcs(sanitized_event)
        payload_json = jcs_canonicalize_plan(normalized_event).decode("utf-8")

        event_type = str(event.get("type", "UNKNOWN"))
        control_id = str(event.get("controlId") or event.get("control_id") or "")
        trace_id = current_trace_id()
        return _QueuedEvidenceItem(
            event=event,
            payload_json=payload_json,
            event_type=event_type,
            control_id=control_id,
            trace_id=trace_id,
            future=future,
        )

    def submit(self, event: dict[str, Any]) -> bool:
        """Non-blocking enqueue for best-effort ``GOVERNANCE_TRACE`` events.

        Refusal receipts, deferrals, and decision evidence MUST NOT use
        ``submit()`` — they use ``ingest()`` or ``ingest_sync()``, which
        await ``queue.put(...)`` and never drop primary evidence.

        When the bounded group-commit queue is full and the event is a
        ``GOVERNANCE_TRACE`` event, the event is shed and
        ``cage_evidence_trace_shed_total`` is incremented.

        Returns:
            True if the event was enqueued, False if Redis is unavailable or
            the trace event was shed due to a full queue.
        """
        if self._redis is None or self._stopping:
            return False

        event_type = str(event.get("type", "UNKNOWN"))
        if event_type != "GOVERNANCE_TRACE":
            raise ValueError(
                f"submit() may only be used for GOVERNANCE_TRACE events (got {event_type!r}); "
                "primary evidence and refusal receipts must use await ingest() or ingest_sync()."
            )

        self._ensure_appender_started()
        queue = self._ensure_queue()

        if queue.full():
            if _PROM_AVAILABLE and EVIDENCE_TRACE_SHED_TOTAL is not None:
                EVIDENCE_TRACE_SHED_TOTAL.inc()
            logger.warning(
                "[EvidenceStream] Queue full (%d); shedding GOVERNANCE_TRACE event.",
                self._queue_size,
            )
            return False

        item = self._prepare_item(event, future=None)
        try:
            queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            if _PROM_AVAILABLE and EVIDENCE_TRACE_SHED_TOTAL is not None:
                EVIDENCE_TRACE_SHED_TOTAL.inc()
            logger.warning(
                "[EvidenceStream] Queue full (%d); shedding GOVERNANCE_TRACE event.",
                self._queue_size,
            )
            return False

    async def ingest(self, event: dict) -> str | None:
        """Ingest a governance event into the evidence stream (best effort).

        The event is hash-chained and appended to the Redis Stream with a
        compare-and-append (see :meth:`_append`). Chain state only advances
        after Redis acknowledges the write, so a failed write never consumes
        a sequence number or forks the chain. Use ``ingest_sync()`` wherever
        the commit must gate a downstream decision.

        Args:
            event: GovernanceEvent dict from the SSE event bus.

        Returns:
            The Redis Stream message ID, or None if Redis is unavailable or
            the write failed. An append whose outcome Redis never settled
            (``EvidenceAppendUnsettledError``) counts as a failed write: the
            record is on the stream at most once either way.

        Raises:
            EvidenceChainUnavailableError: Chain state could not be restored,
                or the head stayed contended for every append attempt.
                Emitting into an unrestored chain would fork it, so this fails
                closed rather than returning None.
            EvidenceChainCorruptError: The stream head cannot be trusted (see
                :meth:`_restore_chain_state`).
        """
        if self._redis is None:
            return None

        try:
            appended = await self._append(event)
        except EvidenceAppendUnsettledError as exc:
            logger.error(
                "[EvidenceStream] Failed to write to Redis Stream: %s",
                exc,
            )
            return None
        except EvidenceChainUnavailableError:
            raise
        except Exception as exc:
            logger.error(
                "[EvidenceStream] Failed to write to Redis Stream: %s",
                exc,
            )
            return None

        logger.debug(
            "[EvidenceStream] Ingested: seq=%d hash=%s… msg_id=%s",
            appended.sequence,
            appended.record_hash[:16],
            appended.msg_id,
        )
        return appended.msg_id

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
        """Append ``event`` and return a structured commit proof.

        Used by ``ingest_sync()``. A Redis write failure yields
        ``success=False``; chain state is untouched in that case. An append
        whose outcome Redis never settled raises ``EvidenceAppendUnsettledError``
        instead, so the caller sees why it must not seal.
        """
        if self._redis is None:
            logger.error("[EvidenceStream] Redis not connected in _ingest_with_result")
            return EvidenceCommitResult(
                success=False,
                evidence_id="",
                commit_timestamp=datetime.now(tz=timezone.utc),
                hash="",
                sequence=self._sequence,
            )

        try:
            appended = await self._append(event)
        except EvidenceChainUnavailableError:
            raise
        except Exception as exc:
            logger.error(
                "[EvidenceStream] Redis write failed in _ingest_with_result: %s",
                exc,
            )
            return EvidenceCommitResult(
                success=False,
                evidence_id="",
                commit_timestamp=datetime.now(tz=timezone.utc),
                hash="",
                sequence=self._sequence,
            )

        logger.debug(
            "[EvidenceStream] _ingest_with_result: seq=%d hash=%s… msg_id=%s",
            appended.sequence,
            appended.record_hash[:16],
            appended.msg_id,
        )
        return EvidenceCommitResult(
            success=True,
            evidence_id=appended.msg_id,
            commit_timestamp=appended.timestamp,
            hash=appended.record_hash,
            sequence=appended.sequence,
        )

    async def _append(self, event: dict[str, Any]) -> _AppendedRecord:
        """Sanitize, JCS-encode, enqueue ``event``, and await its group-commit."""
        if self._redis is None or self._stopping:
            raise EvidenceChainUnavailableError(
                "Evidence chain unavailable: Redis connection not established."
            )

        loop = asyncio.get_running_loop()
        future: asyncio.Future[_AppendedRecord] = loop.create_future()
        item = self._prepare_item(event, future=future)

        self._ensure_appender_started()
        queue = self._ensure_queue()
        await queue.put(item)
        return await future

    async def _appender_loop(
        self, queue: asyncio.Queue[_QueuedEvidenceItem | None]
    ) -> None:
        """Background group-commit loop: drains batches and commits via Lua."""
        stop_requested = False
        while not stop_requested:
            first = await queue.get()
            if first is None:
                break

            batch: list[_QueuedEvidenceItem] = [first]
            wait_s = self._max_wait_ms / 1000.0
            deadline = time.perf_counter() + wait_s

            while len(batch) < self._max_batch_size:
                try:
                    nxt = queue.get_nowait()
                except asyncio.QueueEmpty:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0 or self._stopping:
                        break
                    try:
                        nxt = await asyncio.wait_for(queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                if nxt is None:
                    stop_requested = True
                    break
                batch.append(nxt)

            await self._commit_batch(batch)

        # If a stop sentinel arrived while items were still queued behind or
        # alongside it, drain any remaining items before exiting.
        residual: list[_QueuedEvidenceItem] = []
        while not queue.empty():
            try:
                nxt = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if nxt is not None:
                residual.append(nxt)
                if len(residual) >= self._max_batch_size:
                    await self._commit_batch(residual)
                    residual = []
        if residual:
            await self._commit_batch(residual)

    async def _eval_batch_script(self, args: list[str]) -> Any:
        """Execute ``_APPEND_BATCH_SCRIPT`` via EVALSHA with EVAL fallback."""
        redis = self._redis
        if redis is None:
            raise EvidenceChainUnavailableError(
                "Evidence chain unavailable: Redis connection not established."
            )

        # Prefer EVALSHA on real Redis / FakeRedis clients; fall back to EVAL on
        # NOSCRIPT / "No matching script" or when a test replaces ``redis.eval``
        # with an AsyncMock.
        eval_attr = getattr(redis, "eval", None)
        evalsha_attr = getattr(redis, "evalsha", None)
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
                script_load_attr = getattr(redis, "script_load", None)
                if callable(script_load_attr):
                    try:
                        await script_load_attr(_APPEND_BATCH_SCRIPT)
                    except Exception as load_exc:
                        logger.debug(
                            "[EvidenceStream] SCRIPT LOAD fallback skipped: %s",
                            load_exc,
                        )
        return await redis.eval(  # type: ignore[attr-defined]
            _APPEND_BATCH_SCRIPT, 1, self._stream_key, *args
        )

    def _seal_batch(self, batch: list[_QueuedEvidenceItem]) -> _SealedBatch:
        """Seal ``batch`` against the current head without advancing it.

        Callers hold ``self._chain_lock`` and have restored chain state.
        """
        prev_hash = self._prev_hash
        sequence = self._sequence
        records: list[_SealedRecord] = []
        record_args: list[str] = []
        for item in batch:
            timestamp = datetime.now(tz=timezone.utc)
            entry, record_hash = self._seal_record(
                event=item.event,
                payload_json=item.payload_json,
                event_type=item.event_type,
                control_id=item.control_id,
                timestamp=timestamp,
                prev_hash=prev_hash,
                sequence=sequence,
                trace_id=item.trace_id,
            )
            records.append(_SealedRecord(entry, record_hash, sequence, timestamp))
            record_args.append(str(len(entry) * 2))
            for name, value in entry.items():
                record_args.extend((name, value))
            prev_hash = record_hash
            sequence += 1

        last = records[-1]
        args = (
            self._chain_id,
            str(self._sequence),
            self._prev_hash,
            str(self._max_len),
            str(len(records)),
            last.record_hash,
            last.entry["timestamp_utc"],
            *record_args,
        )
        return _SealedBatch(
            chain_id=self._chain_id,
            first_sequence=self._sequence,
            prev_id=self._prev_id,
            records=tuple(records),
            args=args,
        )

    async def _send_settled(self, sealed: _SealedBatch) -> Any:
        """Run the append script, re-sending the identical ARGV if Redis is silent.

        A transport error that survives the pooled client's own retries leaves
        the outcome unknown: the script may have run and only its reply been
        lost. Re-sending the same sealing is safe (a landed batch answers
        ``ALREADY``); re-sealing it is not, so this never re-seals.

        Raises:
            EvidenceAppendUnsettledError: No send got an answer.
        """
        transport_errors = _redis_transport_errors()
        sends = _MAX_SETTLE_ATTEMPTS + 1
        last_error: Exception | None = None
        for send in range(1, sends + 1):
            try:
                return await self._eval_batch_script(list(sealed.args))
            except transport_errors as exc:
                last_error = exc
                if send == sends:
                    break
                logger.warning(
                    "[EvidenceStream] No reply to the append of seq=%d..%d (%s); "
                    "re-sending the identical script to settle it (%d/%d).",
                    sealed.first_sequence,
                    sealed.last_sequence,
                    exc,
                    send,
                    _MAX_SETTLE_ATTEMPTS,
                )
                await asyncio.sleep(_SETTLE_BACKOFF_S * send)
        raise EvidenceAppendUnsettledError(
            f"Evidence commit failed: Redis did not answer the append of sequences "
            f"{sealed.first_sequence}..{sealed.last_sequence} on {self._stream_key} "
            f"after {sends} sends ({last_error}). The batch is on the stream at "
            "most once, but whether it landed is unknown.",
            last_error,
        ) from last_error

    async def _find_landed(self, sealed: _SealedBatch) -> list[str] | None:
        """Return the entry IDs of ``sealed`` if a previous send already landed it.

        ``CONFLICT`` does not prove the batch is absent: if its first send ran
        and the reply was lost, the client re-sent it, and another writer may
        have appended in between, so the re-send no longer finds the batch at
        the head. A landed batch sits immediately after the record it was
        sealed against, so this reads exactly ``k`` entries after that
        predecessor. The read is bounded by the batch size, however far the
        head has moved since.

        Returns:
            The batch's entry IDs in order, or None when the position it was
            sealed for holds another writer's record (a genuine lost race) or
            nothing at all.

        Raises:
            EvidenceAppendUnsettledError: The read got no answer, or that
                position has been trimmed, so the outcome cannot be told.
            EvidenceChainCorruptError: Only part of the batch is present.
        """
        redis = self._redis
        if redis is None:
            raise EvidenceChainUnavailableError(
                "Evidence chain unavailable: Redis connection not established."
            )
        try:
            entries = await redis.xrange(
                self._stream_key,
                min=f"({sealed.prev_id}" if sealed.prev_id else "-",
                max="+",
                count=len(sealed.records),
            )
        except _redis_transport_errors() as exc:
            raise EvidenceAppendUnsettledError(
                f"Evidence commit failed: could not read back sequences "
                f"{sealed.first_sequence}..{sealed.last_sequence} on "
                f"{self._stream_key} after a CONFLICT ({exc}).",
                exc,
            ) from exc
        if not entries:
            return None

        _first_id, first = entries[0]
        if first != sealed.records[0].entry:
            try:
                first_sequence = int(first.get("sequence", ""))
            except (TypeError, ValueError):
                return None
            if (
                first.get("chain_id") == sealed.chain_id
                and first_sequence > sealed.first_sequence
            ):
                raise EvidenceAppendUnsettledError(
                    f"Evidence commit failed: sequence {sealed.first_sequence} on "
                    f"{self._stream_key} was trimmed before this append's outcome "
                    "could be checked."
                )
            return None

        if [fields for _id, fields in entries] != [r.entry for r in sealed.records]:
            raise EvidenceChainCorruptError(
                f"Evidence chain in {self._stream_key} holds only part of the batch "
                f"sealed for sequences {sealed.first_sequence}..{sealed.last_sequence}; "
                "an atomic append cannot leave that behind."
            )
        return [_as_str(entry_id) for entry_id, _fields in entries]

    def _acknowledge(
        self,
        batch: list[_QueuedEvidenceItem],
        sealed: _SealedBatch,
        ids: list[str],
    ) -> None:
        """Advance chain state past ``sealed`` and resolve each caller's future."""
        if len(ids) != len(sealed.records):
            raise EvidenceChainUnavailableError(
                f"Evidence append of sequences {sealed.first_sequence}.."
                f"{sealed.last_sequence} on {self._stream_key} was acknowledged "
                f"with {len(ids)} entry IDs for {len(sealed.records)} records; "
                "cannot bind each record to its entry."
            )
        last = sealed.records[-1]
        self._prev_hash = last.record_hash
        self._sequence = last.sequence + 1
        self._prev_id = ids[-1]
        self._acked_head = _ChainHead(sealed.chain_id, last.sequence, last.record_hash)
        for item, record, msg_id in zip(batch, sealed.records, ids, strict=True):
            if item.future is not None and not item.future.done():
                item.future.set_result(
                    _AppendedRecord(
                        entry=record.entry,
                        record_hash=record.record_hash,
                        msg_id=msg_id,
                        sequence=record.sequence,
                        timestamp=record.timestamp,
                    )
                )

    async def _append_once(
        self, batch: list[_QueuedEvidenceItem], sealed: _SealedBatch
    ) -> bool:
        """Send one sealing: True once the batch is on the stream, False if it lost the head."""
        result = await self._send_settled(sealed)
        status = _as_str(result[0]) if result else ""
        if status in ("OK", "ALREADY"):
            if status == "ALREADY":
                logger.warning(
                    "[EvidenceStream] Re-sent append of seq=%d..%d found the batch "
                    "already at the head (its reply was lost); not re-sealing.",
                    sealed.first_sequence,
                    sealed.last_sequence,
                )
            self._acknowledge(batch, sealed, [_as_str(i) for i in result[1:]])
            return True

        landed = await self._find_landed(sealed)
        if landed is None:
            return False
        logger.warning(
            "[EvidenceStream] Append of seq=%d..%d had landed before another writer "
            "appended (its reply was lost); resolving it without re-sealing.",
            sealed.first_sequence,
            sealed.last_sequence,
        )
        self._acknowledge(batch, sealed, landed)
        # The head has moved past this batch; re-read it before the next one.
        self._chain_restored = False
        return True

    async def _commit_batch(self, batch: list[_QueuedEvidenceItem]) -> None:
        """Seal ``batch`` and append it to the stream exactly once.

        Each attempt seals the batch against the current head and sends it
        with ``_APPEND_BATCH_SCRIPT``:

        * ``OK`` — appended. ``ALREADY`` — a re-sent script found the batch at
          the head: its first send landed and only the reply was lost.
        * ``CONFLICT`` — first check whether this sealing landed anyway
          (:meth:`_find_landed`) and resolve from those entries if so. Only a
          genuine lost race re-reads the head and re-seals, up to
          ``_MAX_APPEND_ATTEMPTS`` times.
        * No answer — :meth:`_send_settled` re-sends the identical script. A
          batch whose outcome stays unknown fails with
          ``EvidenceAppendUnsettledError`` and is never re-sealed.

        Chain state advances only once Redis has acknowledged the batch. Any
        failure after a send invalidates it, so the next batch re-reads (and
        re-checks) the head first.
        """
        if not batch:
            return

        try:
            async with self._chain_lock:
                for attempt in range(_MAX_APPEND_ATTEMPTS):
                    await self._ensure_chain_restored()
                    sealed = self._seal_batch(batch)
                    try:
                        appended = await self._append_once(batch, sealed)
                    except BaseException:
                        # The batch may or may not be on the stream; whatever
                        # this sink believed about the head no longer holds.
                        self._chain_restored = False
                        raise
                    if appended:
                        return

                    # Another writer took the head. Re-read it and re-seal the batch.
                    logger.info(
                        "[EvidenceStream] Chain head moved under batch starting seq=%d "
                        "(len=%d); re-reading.",
                        sealed.first_sequence,
                        len(batch),
                    )
                    if _PROM_AVAILABLE and EVIDENCE_APPEND_CONFLICTS_TOTAL is not None:
                        EVIDENCE_APPEND_CONFLICTS_TOTAL.inc()
                    self._chain_restored = False

                    if attempt + 1 < _MAX_APPEND_ATTEMPTS:
                        cap = min(
                            _CONFLICT_BACKOFF_CAP_S,
                            _CONFLICT_BACKOFF_BASE_S * (2**attempt),
                        )
                        jitter_s = (secrets.randbelow(1000) / 1000.0) * cap
                        await asyncio.sleep(jitter_s)

                raise EvidenceChainUnavailableError(
                    f"Evidence append lost the chain head race {_MAX_APPEND_ATTEMPTS} "
                    f"times on {self._stream_key}; refusing to fork the chain."
                )

        except BaseException as exc:
            for item in batch:
                if item.future is not None and not item.future.done():
                    item.future.set_exception(exc)
            if isinstance(exc, asyncio.CancelledError):
                raise

    @property
    def chain_root(self) -> str:
        """Current chain root hash — the ``prev_hash`` the next record will use.

        Empty before chain state has been restored, and empty at genesis. It is
        deliberately not a sentinel digest: the DDL requires ``prev_hash IS
        NULL`` exactly when ``sequence = 0``.
        """
        return self._prev_hash

    @property
    def chain_id(self) -> str:
        """UUID of the chain being appended to; empty until state is restored."""
        return self._chain_id

    @property
    def chain_restored(self) -> bool:
        """True once chain state has been recovered (or genesis established)."""
        return self._chain_restored

    @property
    def total_records(self) -> int:
        """Next sequence number — i.e. records in the chain, across restarts.

        This counts the whole chain, not this process's share of it, because
        the sequence is recovered from the stream on start.
        """
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


async def start_evidence_sink() -> EvidenceStreamSink | None:
    """Start the gateway's evidence sink for the process lifetime.

    Called from the gateway lifespan after
    :func:`validate_evidence_stream_preconditions`. Returns ``None`` when
    ``EVIDENCE_STREAM_ENABLED`` is false (only reachable under a permissive
    posture, since the preconditions forbid it otherwise).

    Under an enforcing posture the sink must actually be connected: a sink
    that failed to reach Redis silently drops refusal and pause receipts and
    fails every blocking seal, so startup fails instead.

    Raises:
        EvidenceChainUnavailableError: Enforcing posture and the sink did not
            connect, or chain state could not be restored.
    """
    from src.gateway.governance.env_posture import is_enforcing

    if os.environ.get("EVIDENCE_STREAM_ENABLED", "false").lower() != "true":
        return None

    sink = get_evidence_sink()
    await sink.start()
    if not sink.is_running:
        if is_enforcing():
            raise EvidenceChainUnavailableError(
                "Evidence stream sink failed to connect to Redis under an "
                "enforcing posture; refusing to serve without an evidence chain."
            )
        logger.warning(
            "[EvidenceStream] Sink not connected; evidence will be dropped "
            "(permissive posture only)."
        )
    return sink
