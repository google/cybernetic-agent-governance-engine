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
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
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
    """Raised when Redis is reachable but the chain head cannot be parsed.

    This is deliberately distinct from a cold start. An empty stream is a
    legitimate genesis condition; a *non-empty* stream whose newest entry is
    missing its chain fields, or carries a non-integer sequence, is evidence of
    truncation or tampering. Re-seeding genesis in that situation would silently
    fork the chain and destroy the only signal that something went wrong, so the
    sink refuses to start instead.

    Subclasses ``EvidenceChainUnavailableError`` so that callers already written
    to fail closed on an unavailable chain also fail closed on a corrupt one.
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
        decision: Governance decision (ALLOW, DENY, DEFER, NARROW, PAUSE).
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
        pause_token: Token for PAUSE decisions (optional).

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

# The head check and the XADD run atomically inside Redis. Each gateway
# replica keeps its chain head in memory, and HA deployments run more than
# one replica against the same stream; a plain XADD would let two replicas
# seal against the same head and fork the chain. The script appends only if
# the stream's newest entry is still (chain_id, sequence - 1, prev_hash), or
# the stream is empty and the record is a genesis record.
#
# KEYS[1] = stream key
# ARGV[1] = chain_id, ARGV[2] = sequence, ARGV[3] = prev_hash,
# ARGV[4] = MAXLEN, ARGV[5..] = flattened entry field/value pairs.
_APPEND_SCRIPT = """
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
  if h['chain_id'] ~= ARGV[1] or h['record_hash'] ~= ARGV[3]
      or tonumber(h['sequence']) + 1 ~= tonumber(ARGV[2]) then
    return {'CONFLICT'}
  end
end
local id = redis.call('XADD', KEYS[1], 'MAXLEN', ARGV[4], '*', unpack(ARGV, 5))
return {'OK', id}
"""

# Bound on re-seal attempts when another writer keeps winning the head.
_MAX_APPEND_ATTEMPTS = 8


@dataclass(frozen=True)
class _AppendedRecord:
    """A record Redis has acknowledged, with the chain position it took."""

    entry: dict[str, str]
    record_hash: str
    msg_id: str
    sequence: int
    timestamp: datetime


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
    ) -> None:
        self._redis_url = redis_url
        self._redis_db = redis_db
        self._stream_key = stream_key
        self._max_len = max_len

        self._redis = None  # Lazy-loaded redis.asyncio client
        # Chain state is NOT seeded here. Seeding genesis in __init__ meant
        # every process restart silently restarted the chain at sequence 0 with
        # a fresh prev_hash, forking the chain and producing SEQUENCE_GAP /
        # GENESIS_VIOLATION rows downstream. ``start()`` now restores this from
        # Redis and only falls back to genesis when the chain is provably empty.
        self._chain_id: str = ""
        self._prev_hash: str = ""
        self._sequence: int = 0
        self._chain_restored = False
        self._running = False
        self._chain_lock = asyncio.Lock()

    async def start(self) -> None:
        """Connect to Redis and restore chain state.

        The sink is a producer only. Signing and WORM custody of the stream
        are the compliance bridge's job (``EvidenceCustodian``).
        """
        if self._running:
            return

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
        logger.info("[EvidenceStream] Started.")

    async def stop(self) -> None:
        """Stop the evidence stream and close the Redis connection."""
        self._running = False

        if self._redis:
            await self._redis.aclose()
            self._redis = None

        logger.info(
            "[EvidenceStream] Stopped. Total records: %d",
            self._sequence,
        )

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

        * **Stream empty** — a genuine cold start. Mint a new ``chain_id`` and
          begin at sequence 0 with ``prev_hash = ""`` (stored NULL), satisfying
          the DDL's ``CONSTRAINT chk_genesis_prev_hash``.
        * **Stream has a well-formed head** — resume at ``sequence + 1`` with
          ``prev_hash`` set to that record's hash, under the same ``chain_id``.
        * **Stream has a head we cannot parse** — raise. Redis answered, so this
          is not a cold start; it is truncation or tampering, and re-genesising
          would overwrite the only evidence that it happened.

        Raises:
            EvidenceChainUnavailableError: Redis client is absent, or the read
                itself failed.
            EvidenceChainCorruptError: The newest entry exists but is missing
                or malforming the fields needed to continue the chain.
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

        if not entries:
            self._chain_id = str(uuid.uuid4())
            self._prev_hash = ""
            self._sequence = 0
            logger.info(
                "[EvidenceStream] Stream %s is empty — starting new chain %s at "
                "sequence 0.",
                self._stream_key,
                self._chain_id,
            )
            return

        _msg_id, fields = entries[0]

        def _corrupt(detail: str) -> EvidenceChainCorruptError:
            return EvidenceChainCorruptError(
                f"Evidence chain head in {self._stream_key} is unusable: {detail}. "
                "Refusing to start a new chain over an existing one — this is a "
                "truncation or tampering signal, not a cold start."
            )

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

        self._chain_id = chain_id
        self._prev_hash = record_hash
        self._sequence = last_sequence + 1
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
    ) -> tuple[dict[str, str], str]:
        """Build one ``cage-audit/3.0`` wire entry and its record hash.

        Callers must hold ``self._chain_lock`` and must have restored chain
        state first. This does **not** advance the chain: ``_append()`` does
        that, and only after Redis has acknowledged the write.

        Every field here is a string because Redis Streams store nothing else.

        Returns:
            ``(entry, record_hash)``.
        """
        classification_reason, narrowing_applied, pause_token = _extract_sparse_header(
            event
        )
        trace_id = current_trace_id()

        record_hash = _link_hash(
            prev_hash=self._prev_hash,
            sequence=self._sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=self._chain_id,
            trace_id=trace_id,
            classification_reason=classification_reason,
            narrowing_applied=narrowing_applied,
            pause_token=pause_token,
        )

        entry: dict[str, str] = {
            "schema": _SCHEMA,
            "chain_id": self._chain_id,
            "sequence": str(self._sequence),
            "timestamp_utc": timestamp.isoformat(),
            "event_type": event_type,
            "control_id": control_id,
            "trace_id": trace_id,
            "hash_algorithm": _HASH_ALGORITHM,
            "canonicalization": _CANONICALIZATION,
            "evidence_class": _EVIDENCE_CLASS,
            # "" at genesis; the sink maps it to NULL to satisfy
            # CONSTRAINT chk_genesis_prev_hash.
            "prev_hash": self._prev_hash,
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
            the write failed.

        Raises:
            EvidenceChainUnavailableError: Chain state could not be restored,
                or the head stayed contended for every append attempt.
                Emitting into an unrestored chain would fork it, so this fails
                closed rather than returning None.
        """
        if self._redis is None:
            return None

        try:
            appended = await self._append(event)
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
        """Append ``event`` and return a structured commit proof.

        Used by ``ingest_sync()``. A Redis write failure yields
        ``success=False``; chain state is untouched in that case.
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
        """Hash-chain ``event`` and compare-and-append it to the stream.

        The head check and the ``XADD`` run as one Lua script
        (:data:`_APPEND_SCRIPT`), so the record lands only if the stream's
        newest entry is still the head this process sealed against. On a
        conflict (another gateway replica appended first) the head is
        re-read and the record re-sealed, up to
        :data:`_MAX_APPEND_ATTEMPTS` times. Chain state advances only after
        Redis acknowledges the write.

        Raises:
            EvidenceChainUnavailableError: Chain state could not be restored,
                or every attempt lost the race for the head.
            Exception: Whatever the Redis client raised for the write itself.
        """
        # Wire PIISanitizer into the evidence path before the hash is computed.
        # This prevents un-verifiable records if the sink applies masking later.
        from src.gateway.governance.pii_sanitizer import _get_pii_sanitizer

        sanitized_event = _get_pii_sanitizer().sanitize_dict(event)
        normalized_event = _normalize_for_jcs(sanitized_event)
        payload_json = jcs_canonicalize_plan(normalized_event).decode("utf-8")

        event_type = event.get("type", "UNKNOWN")
        control_id = event.get("controlId", "")

        async with self._chain_lock:
            for _attempt in range(_MAX_APPEND_ATTEMPTS):
                await self._ensure_chain_restored()

                sequence = self._sequence
                timestamp = datetime.now(tz=timezone.utc)
                entry, record_hash = self._seal_record(
                    event=event,
                    payload_json=payload_json,
                    event_type=event_type,
                    control_id=control_id,
                    timestamp=timestamp,
                )

                args: list[str] = [
                    self._chain_id,
                    str(sequence),
                    self._prev_hash,
                    str(self._max_len),
                ]
                for name, value in entry.items():
                    args.extend((name, value))

                result = await self._redis.eval(  # type: ignore[attr-defined]
                    _APPEND_SCRIPT, 1, self._stream_key, *args
                )
                if result and result[0] == "OK":
                    self._prev_hash = record_hash
                    self._sequence += 1
                    return _AppendedRecord(
                        entry=entry,
                        record_hash=record_hash,
                        msg_id=str(result[1]),
                        sequence=sequence,
                        timestamp=timestamp,
                    )

                # Another writer moved the head. Re-read it and re-seal.
                logger.info(
                    "[EvidenceStream] Chain head moved under seq=%d; re-reading.",
                    sequence,
                )
                if _PROM_AVAILABLE and EVIDENCE_APPEND_CONFLICTS_TOTAL is not None:
                    EVIDENCE_APPEND_CONFLICTS_TOTAL.inc()
                self._chain_restored = False

        raise EvidenceChainUnavailableError(
            f"Evidence append lost the chain head race {_MAX_APPEND_ATTEMPTS} "
            f"times on {self._stream_key}; refusing to fork the chain."
        )

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
