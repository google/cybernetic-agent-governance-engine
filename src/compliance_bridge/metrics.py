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
metrics.py — Authoritative custody-chain compliance metrics aggregation.

Computes per-control ISO/IEC 42001 and NIST SP 800-53 compliance posture
metrics exclusively over the signed, SHA-256 hash-chained ``cage_evidence``
custody chain (`R-16`, `F-84`, `F-103`):

  1. **WORM Cold Store Archive (`EVIDENCE_COLD_STORE` / `EVIDENCE_ARCHIVE_BUCKET`)**:
     NDJSON custody batches (`evidence-stream/YYYY/MM/DD/<chain_id>/<first>-<last>.ndjson`)
     written and attested by :class:`~src.compliance_bridge.evidence_custodian.EvidenceCustodian`.
  2. **Redis DB 1 Hot Evidence Stream (`EVIDENCE_STREAM_REDIS_DB=1`)**:
     Unarchived or recently appended records on `EVIDENCE_STREAM_KEY`
     (default `cage:evidence:stream`) and `INFRA_EVIDENCE_STREAM_KEY`
     (`cage:evidence:infra:stream`), merged and deduplicated with the WORM
     archive by `record_hash`, `(chain_id, sequence)`, or `stream_id`.

Operational Langfuse traces (`LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`) and
retired ClickHouse sinks are never queried for compliance control outcomes.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import threading
import weakref
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote, urlparse

from cachetools import TTLCache

from src.gateway.governance.env_posture import (
    is_enforcing,
    resolve_deployment_region,
    resolve_posture,
)
from src.gateway.governance.evidence.cold_store import EvidenceColdStore
from src.gateway.governance.evidence.factory import get_cold_store

from .evidence_custodian import (
    ATTESTATION_SCHEMA_V2,
    EvidenceCustodyIntegrityError,
    NonEvidentiaryAttestationError,
    assert_citable,
)
from .infra_custody import DEFAULT_INFRA_STREAM_KEY, INFRA_STREAM_KEY_ENV
from .types import (
    CONTROL_EVALUATION_EVENT_TYPES,
    STATISTICAL_TRACE_LULA_SPECS,
    Cm6ThresholdsPosture,
    ComplianceMetrics,
    derive_min_sample_size,
)

logger = logging.getLogger(__name__)

# Cap concurrent custody-chain scans when /v1/metrics/summary, oscal-export,
# and aarm-report fan out across all supported controls simultaneously.
_EVIDENCE_CONCURRENCY = asyncio.Semaphore(6)
_LANGFUSE_CONCURRENCY = _EVIDENCE_CONCURRENCY

_EVIDENCE_ARCHIVE_PREFIX = "evidence-stream"
_MAX_DATE_PREFIX_SCAN_DAYS = 14
_DEFAULT_COLD_STORE_READ_CONCURRENCY = 16
_DEFAULT_BATCH_CACHE_MAX_ENTRIES = 32768
_DEFAULT_BATCH_CACHE_TTL_SECONDS = 604800


def _resolve_min_sample_size(control_id: str = "A.5.3") -> int:
    """Return the threshold-derived minimum population floor (or explicit env override)."""
    derived = derive_min_sample_size(control_id)
    raw = os.environ.get("COMPLIANCE_MIN_SAMPLE_SIZE", "").strip()
    if not raw:
        return derived
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning(
            "[metrics] Invalid COMPLIANCE_MIN_SAMPLE_SIZE=%r for %s; using derived floor %d.",
            raw,
            control_id,
            derived,
        )
        return derived


def _resolve_cold_store_read_concurrency() -> int:
    """Return bounded concurrent batch download parallelism for WORM cold store."""
    raw = os.environ.get("EVIDENCE_COLD_STORE_READ_CONCURRENCY", "").strip()
    if not raw:
        return _DEFAULT_COLD_STORE_READ_CONCURRENCY
    try:
        return max(1, min(64, int(raw)))
    except ValueError:
        return _DEFAULT_COLD_STORE_READ_CONCURRENCY


def _resolve_batch_cache_ttl() -> int:
    raw = os.environ.get("EVIDENCE_BATCH_CACHE_TTL_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_BATCH_CACHE_TTL_SECONDS
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_BATCH_CACHE_TTL_SECONDS


def _resolve_batch_cache_maxsize() -> int:
    raw = os.environ.get("EVIDENCE_BATCH_CACHE_MAX_ENTRIES", "").strip()
    if not raw:
        return _DEFAULT_BATCH_CACHE_MAX_ENTRIES
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_BATCH_CACHE_MAX_ENTRIES


# ---------------------------------------------------------------------------
# Deployment cold-start grace period
# DEPLOYMENT_START_UTC may be patched by CI at deploy time.
# Falls back to module-load time so local dev always starts with grace active.
# ---------------------------------------------------------------------------

_DEPLOYMENT_START_UTC: datetime = (
    datetime(
        *[  # type: ignore[arg-type, misc]
            int(x)
            for x in (
                os.environ.get(
                    "DEPLOYMENT_START_UTC", datetime.now(tz=timezone.utc).isoformat()
                )
                .replace("Z", "+00:00")
                .split("T")[0]
                .split("-")
            )
        ],
        tzinfo=timezone.utc,
    )
    if os.environ.get("DEPLOYMENT_START_UTC")
    else datetime.now(tz=timezone.utc)
)

_STARTUP_GRACE_HOURS: int = int(os.environ.get("STARTUP_GRACE_HOURS", "6"))


def _parse_deployment_start() -> datetime:
    """Parse DEPLOYMENT_START_UTC env var safely, fallback to now."""
    raw = os.environ.get("DEPLOYMENT_START_UTC")
    if not raw:
        return datetime.now(tz=timezone.utc)
    try:
        cleaned = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        return (
            parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        )
    except ValueError:
        logger.warning(
            "[metrics] Could not parse DEPLOYMENT_START_UTC=%r; using module load time.",
            raw,
        )
        return datetime.now(tz=timezone.utc)


_DEPLOYMENT_START: datetime = _parse_deployment_start()


def _get_grace_status() -> dict[str, float | bool]:
    age_hours = (
        datetime.now(tz=timezone.utc) - _DEPLOYMENT_START
    ).total_seconds() / 3600
    remaining = max(0.0, _STARTUP_GRACE_HOURS - age_hours)
    return {"active": remaining > 0, "remaining_hours": remaining}


# ---------------------------------------------------------------------------
# TTL caches:
#   - _metrics_cache: per-(control_id, window_hours) aggregated ComplianceMetrics
#   - _raw_custody_cache: 30s snapshot of merged WORM + Redis stream records
#   - _verified_batch_cache: verified, KMS-attested, immutable WORM `.ndjson`
#     batches (keyed by store identity, posture, and object key) so unchanged
#     historical batches are not re-downloaded on every poll. Tampered/unsigned
#     objects and integrity failures are NEVER cached; `CustodyVerifier` performs
#     independent uncached read-back verification.
#   - _cold_store_cache: process-scoped cold-store client reuse to prevent TLS/
#     OAuth metadata contention under concurrent scans.
# ---------------------------------------------------------------------------

_metrics_cache: TTLCache[str, ComplianceMetrics] = TTLCache(maxsize=32, ttl=300)
_raw_custody_cache: TTLCache[tuple[Any, ...], list[dict[str, Any]]] = TTLCache(
    maxsize=16, ttl=30
)
_raw_custody_lock = threading.Lock()
_inflight_fetch_guard = threading.Lock()
_inflight_fetch_locks: dict[tuple[Any, ...], threading.Lock] = {}

_verified_batch_cache: TTLCache[
    tuple[int, str, str, str], tuple[dict[str, Any], ...]
] = TTLCache(
    maxsize=_resolve_batch_cache_maxsize(),
    ttl=_resolve_batch_cache_ttl(),
)
_verified_batch_lock = threading.Lock()

_cold_store_cache: dict[tuple[int, str, str, str, str], EvidenceColdStore] = {}
_cold_store_lock = threading.Lock()


def _get_inflight_lock(cache_key: tuple[Any, ...]) -> threading.Lock:
    """Return a single-flight lock for `cache_key` to prevent duplicate scans."""
    with _inflight_fetch_guard:
        if len(_inflight_fetch_locks) > 64:
            # Drop uncontended entries only so active waiters keep the same lock.
            stale_keys = [
                k for k, lk in _inflight_fetch_locks.items() if not lk.locked()
            ]
            for k in stale_keys:
                _inflight_fetch_locks.pop(k, None)
        lock = _inflight_fetch_locks.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            _inflight_fetch_locks[cache_key] = lock
        return lock


def invalidate_compliance_metrics_cache(control_id: str | None = None) -> None:
    """Invalidate cached compliance metrics globally or for a single control.

    When called with `control_id=None`, resets every cache including the
    immutable verified-batch cache and process-scoped cold-store client cache.
    When called for a single control (e.g. after ingesting one new INFRA event),
    invalidates the short-lived snapshot/metrics caches while retaining already
    verified immutable WORM `.ndjson` batches.
    """
    with _raw_custody_lock:
        _raw_custody_cache.clear()
    if control_id is None:
        _metrics_cache.clear()
        with _verified_batch_lock:
            _verified_batch_cache.clear()
        with _cold_store_lock:
            _cold_store_cache.clear()
        return
    prefix = f"{_normalize_control_id(control_id)}:"
    for key in list(_metrics_cache.keys()):
        if key.startswith(prefix):
            _metrics_cache.pop(key, None)


# ---------------------------------------------------------------------------
# Canonical Producer Event & Verdict Classification (Gate 11 Verified)
# ---------------------------------------------------------------------------

PASSING_EVIDENCE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "GOVERNANCE_DECISION",
        "GOVERNANCE_SEAL_CONSUMED",
        "ACTUATION_RECEIPT",
        "GOVERNANCE_SETTLEMENT",
        "CONSEQUENCE_GATEWAY_DECISION",
        "CBF_COMMIT",
        "INFERENCE_PROXY_STAGE1_PASS",
        "INFERENCE_PROXY_PII_SCRUB_PASS",
    }
)

BLOCKING_EVIDENCE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "GOVERNANCE_REFUSAL",
        "GOVERNANCE_REFUSAL_RECEIPT",
        "GOVERNANCE_DEFERRAL",
        "DEFER_PARKED",
        "ACTUATION_REFUSAL_RECEIPT",
        "ACTUATION_INDETERMINATE_RECEIPT",
        "CONSEQUENCE_GATEWAY_REFUSAL",
        "INFERENCE_PROXY_BLOCK",
        "TOKEN_QUOTA_DENIED",
        "CBF_ROLLBACK",
        "WORKLOAD_QUARANTINE_RECEIPT",
        "GOVERNANCE_VIOLATION",
    }
)

PREVENTIVE_ENFORCEMENT_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "GOVERNANCE_REFUSAL",
        "GOVERNANCE_REFUSAL_RECEIPT",
        "GOVERNANCE_DEFERRAL",
        "DEFER_PARKED",
        "CONSEQUENCE_GATEWAY_REFUSAL",
        "INFERENCE_PROXY_BLOCK",
        "TOKEN_QUOTA_DENIED",
    }
)

_CONTROL_FAILURE_EVENT_TOKENS: tuple[str, ...] = (
    "ROLLBACK",
    "QUARANTINE",
    "VIOLATION",
    "FENCE",
)

_BLOCKING_EVENT_TOKENS: tuple[str, ...] = (
    "REFUSAL",
    "DEFERRAL",
    "ROLLBACK",
    "QUARANTINE",
    "VIOLATION",
    "FENCE",
)

_PASSING_VERDICTS: frozenset[str] = frozenset(
    {
        "ALLOW",
        "NARROW",
        "PASS",
        "PASSED",
        "APPROVED",
        "ACCEPTED",
        "EXECUTE",
        "CONFIRMED",
        "SATISFIED",
        "ADMITTED",
    }
)

_BLOCKING_VERDICTS: frozenset[str] = frozenset(
    {
        "DENY",
        "BLOCK",
        "BLOCKED",
        "REFUSED",
        "DEFER",
        "HOLD",
        "REQUIRE_APPROVAL",
        "FAIL",
        "FAILED",
        "ERROR",
        "ROLLED_BACK",
        "ROLLED_BACK_UNLEDGERED",
        "NOOP",
        "REJECTED",
        "UNKNOWN",
        "INDETERMINATE",
        "VIOLATION",
        "NOT-SATISFIED",
    }
)


def _get_record_field(record: Mapping[str, Any] | Any, key: str) -> Any:
    """Read a field from either a dict-like evidence record or an object."""
    if isinstance(record, Mapping):
        return record.get(key)
    return getattr(record, key, None)


def _parse_evidence_payload(record: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Extract and parse the JSON payload dictionary from a cage_evidence record."""
    for field_name in ("payload_json", "payload", "metadata"):
        raw = _get_record_field(record, field_name)
        if raw is None:
            continue
        if isinstance(raw, Mapping):
            return dict(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except ValueError:
                continue
    return {}


def _parse_evidence_timestamp(record: Mapping[str, Any] | Any) -> datetime | None:
    """Extract a timezone-aware UTC datetime from a cage_evidence record."""
    payload = _parse_evidence_payload(record)
    candidates: list[Any] = [
        _get_record_field(record, "timestamp_utc"),
        _get_record_field(record, "timestamp"),
        payload.get("timestamp_utc"),
        payload.get("timestamp"),
    ]
    for raw in candidates:
        if raw is None:
            continue
        if isinstance(raw, datetime):
            return raw if raw.tzinfo is not None else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            sec = float(raw) / 1000.0 if float(raw) > 1e11 else float(raw)
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip()
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                return (
                    parsed
                    if parsed.tzinfo is not None
                    else parsed.replace(tzinfo=timezone.utc)
                )
            except ValueError:
                continue

    stream_id = _get_record_field(record, "stream_id")
    if isinstance(stream_id, str) and "-" in stream_id:
        ms_part = stream_id.split("-", 1)[0]
        if ms_part.isdigit():
            return datetime.fromtimestamp(int(ms_part) / 1000.0, tz=timezone.utc)
    return None


def _normalize_control_id(raw: Any) -> str:
    """Normalize a control identifier, stripping any optional `control:` tag prefix."""
    if not isinstance(raw, str):
        return ""
    cleaned = raw.strip()
    if cleaned.lower().startswith("control:"):
        cleaned = cleaned[len("control:") :].strip()
    return cleaned


_INTERNAL_CONTROL_TO_FRAMEWORKS: dict[str, frozenset[str]] = {
    "agentic_scope_statement": frozenset({"A.5.3", "A.8.4", "SC-4"}),
    "CTRL_OPA_005": frozenset({"A.5.3", "A.8.4", "SC-4", "AC-3"}),
    "CTRL_AGT_001": frozenset({"A.5.3", "A.8.4"}),
    "CTRL_WAL_002": frozenset({"A.5.3", "A.8.4"}),
    "CTRL_TQP_007": frozenset({"A.5.3", "TQP-007"}),
    "TQP-007": frozenset({"A.5.3", "TQP-007"}),
    "CTRL_FTRA_001": frozenset({"A.5.3", "A.8.4"}),
    "CTRL_FRIA_006": frozenset({"A.5.2", "A.5.3"}),
}


def _candidate_matches_target(raw_candidate: str, target: str) -> bool:
    norm = _normalize_control_id(raw_candidate)
    if not norm:
        return False
    if norm == target:
        return True
    mapped = _INTERNAL_CONTROL_TO_FRAMEWORKS.get(norm)
    return bool(mapped and target in mapped)


def _record_matches_control(record: Mapping[str, Any] | Any, control_id: str) -> bool:
    """Return True when `record` is attributed to `control_id` (directly or via Layer 1 `GovernanceControl`)."""
    target = _normalize_control_id(control_id)
    if not target:
        return False

    payload = _parse_evidence_payload(record)
    receipt = payload.get("receipt")
    receipt_control = (
        receipt.get("control_id") if isinstance(receipt, Mapping) else None
    )

    candidates: list[Any] = [
        _get_record_field(record, "control_id"),
        _get_record_field(record, "iso_42001_control"),
        payload.get("control_id"),
        payload.get("controlId"),
        payload.get("iso_42001_control"),
        payload.get("oscal_control_ref"),
        receipt_control,
    ]

    for candidate in candidates:
        if isinstance(candidate, str):
            if _candidate_matches_target(candidate, target):
                return True
        elif isinstance(candidate, (list, tuple, set, frozenset)):
            for item in candidate:
                if isinstance(item, str) and _candidate_matches_target(item, target):
                    return True

    for tf_list in (
        payload.get("tier_failures"),
        receipt.get("tier_failures") if isinstance(receipt, Mapping) else None,
    ):
        if isinstance(tf_list, (list, tuple)):
            for tf in tf_list:
                tf_cid = tf.get("control_id") if isinstance(tf, Mapping) else None
                if isinstance(tf_cid, str) and _candidate_matches_target(
                    tf_cid, target
                ):
                    return True
    return False


_CONTROL_TOKEN_PUNCT_RE = re.compile(r"[^a-z0-9]+")
_EVALUATION_RECORD_ROLES: frozenset[str] = frozenset(
    {"control_evaluation", "control_assessment", "assessment_result"}
)


def _canonical_control_token(raw: Any) -> str:
    """Normalize any control ID or Lula manifest stem to a canonical comparison token.

    Maps e.g. ``"A.5.3"``, ``"control:A.5.3"``, ``"lula-validation-a53"``, and
    ``"lula-validation-a53.yaml"`` uniformly to ``"a53"``; ``"CM-6"`` and
    ``"lula-validation-cm6"`` to ``"cm6"``; ``"SC-7"`` and ``"lula-validation-sc7"``
    to ``"sc7"``.
    """
    if not isinstance(raw, str):
        return ""
    cleaned = _normalize_control_id(raw).lower()
    if not cleaned:
        return ""
    if cleaned.endswith((".yaml", ".yml")):
        cleaned = cleaned.rsplit(".", 1)[0]
    if cleaned.startswith("lula-validation-"):
        cleaned = cleaned[len("lula-validation-") :]
    return _CONTROL_TOKEN_PUNCT_RE.sub("", cleaned)


def _expand_control_tokens(value: Any, out: set[str]) -> None:
    """Add canonical tokens for a scalar/sequence control identifier or spec stem."""
    if value is None:
        return
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                for item in parsed:
                    _expand_control_tokens(item, out)
                return
        norm = _normalize_control_id(stripped)
        token = _canonical_control_token(norm)
        if token:
            out.add(token)
        mapped = _INTERNAL_CONTROL_TO_FRAMEWORKS.get(norm)
        if mapped:
            for fw_cid in mapped:
                fw_tok = _canonical_control_token(fw_cid)
                if fw_tok:
                    out.add(fw_tok)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _expand_control_tokens(item, out)


def _is_control_evaluation_record(
    record: Mapping[str, Any] | Any,
    payload: Mapping[str, Any] | None = None,
) -> bool:
    """Return True when `record` is the output of evaluating a control (meta-level).

    Applies generally to any assessment/validation emitter — not hard-coded to a
    single control ID. Ordinary governed runtime telemetry (`GOVERNANCE_DECISION`,
    `GOVERNANCE_REFUSAL`, `CBF_COMMIT`, `INFERENCE_PROXY_*`, `agentsight_*`,
    `cilium_l7_flow`, etc.) returns False.
    """
    resolved_payload = (
        payload if payload is not None else _parse_evidence_payload(record)
    )
    raw_event_type = str(
        _get_record_field(record, "event_type")
        or _get_record_field(record, "type")
        or resolved_payload.get("event_type")
        or resolved_payload.get("type")
        or ""
    ).strip()
    if raw_event_type.lower() in CONTROL_EVALUATION_EVENT_TYPES:
        return True

    for role_key in ("record_role", "evidence_role", "producer_role"):
        role_val = resolved_payload.get(role_key)
        if role_val is None:
            role_val = _get_record_field(record, role_key)
        if (
            isinstance(role_val, str)
            and role_val.strip().lower() in _EVALUATION_RECORD_ROLES
        ):
            return True

    for explicit_key in (
        "evaluated_control_id",
        "evaluated_controls",
        "target_control_id",
        "target_controls",
    ):
        val = resolved_payload.get(explicit_key)
        if val is None:
            val = _get_record_field(record, explicit_key)
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, (list, tuple, set, frozenset)) and len(val) > 0:
            return True

    return False


def _extract_evaluated_control_tokens(
    record: Mapping[str, Any] | Any,
    payload: Mapping[str, Any] | None = None,
) -> frozenset[str]:
    """Return canonical tokens of every control whose evaluation produced `record`."""
    resolved_payload = (
        payload if payload is not None else _parse_evidence_payload(record)
    )
    tokens: set[str] = set()
    has_explicit_target = False

    for explicit_key in (
        "evaluated_control_id",
        "evaluated_controls",
        "target_control_id",
        "target_controls",
    ):
        for candidate in (
            resolved_payload.get(explicit_key),
            _get_record_field(record, explicit_key),
        ):
            before = len(tokens)
            _expand_control_tokens(candidate, tokens)
            if len(tokens) > before:
                has_explicit_target = True

    for spec_list_key in (
        "failed_controls",
        "satisfied_controls",
        "insufficient_traffic_controls",
        "insufficient_sample_controls",
        "startup_grace_controls",
    ):
        _expand_control_tokens(resolved_payload.get(spec_list_key), tokens)
        _expand_control_tokens(_get_record_field(record, spec_list_key), tokens)

    raw_event_type = str(
        _get_record_field(record, "event_type")
        or _get_record_field(record, "type")
        or resolved_payload.get("event_type")
        or resolved_payload.get("type")
        or ""
    ).strip()

    # Suite-wide `lula_audit` records always cover the control under which they are
    # sealed (`control_id` / `control_hint`). Generic `control_assessment` records
    # without an explicit `evaluated_control*` / `target_control*` list fall back
    # to their own attribution fields so self-evaluation is blocked uniformly.
    if raw_event_type.lower() == "lula_audit" or not has_explicit_target:
        for attr_key in (
            "control_id",
            "controlId",
            "control_hint",
            "iso_42001_control",
            "oscal_control_ref",
        ):
            _expand_control_tokens(resolved_payload.get(attr_key), tokens)
            _expand_control_tokens(_get_record_field(record, attr_key), tokens)

    return frozenset(tokens)


def _is_self_evaluation_record(
    record: Mapping[str, Any] | Any,
    target_control_id: str,
    payload: Mapping[str, Any] | None = None,
) -> bool:
    """Return True when `record` is a control-evaluation output produced for `target_control_id`.

    Structural anti-latch invariant (`POAM-2026-201` / `POAM-2026-244`):
    records emitted by evaluating control `X` (e.g. a Lula validation outcome or
    control-assessment receipt for `X`) must never enter `X`'s own input
    population (`total_traces`, `passed_traces`, `blocked_traces`, `safety_rate`,
    or `last_event_date`). Applied uniformly to every control `X`.
    """
    target_token = _canonical_control_token(target_control_id)
    if not target_token:
        return False
    resolved_payload = (
        payload if payload is not None else _parse_evidence_payload(record)
    )
    if not _is_control_evaluation_record(record, resolved_payload):
        return False
    return target_token in _extract_evaluated_control_tokens(record, resolved_payload)


_LULA_PASS_PREFIX_RE = re.compile(r"\blula_audit\s+pass\s*:", re.IGNORECASE)
_LULA_INSUFFICIENT_PREFIX_RE = re.compile(
    r"\blula_audit\s+insufficient_traffic\s*:", re.IGNORECASE
)
_LULA_INSUFFICIENT_SAMPLE_PREFIX_RE = re.compile(
    r"\blula_audit\s+insufficient_sample\s*:", re.IGNORECASE
)
_LULA_FAIL_PREFIX_RE = re.compile(r"\blula_audit\s+fail\b", re.IGNORECASE)
_LULA_RATIO_RE = re.compile(
    r"\blula_audit\s+(?:pass|fail)\s*:\s*(\d+)\s*/\s*(\d+)\b",
    re.IGNORECASE,
)
_LULA_FAILED_COUNT_RE = re.compile(r"\b(\d+)\s+failed\b", re.IGNORECASE)
_LULA_NOT_SATISFIED_COUNT_RE = re.compile(r"\b(\d+)\s+not-satisfied\b", re.IGNORECASE)
_LULA_ZERO_NOT_SATISFIED_RE = re.compile(r"\b0\s+not-satisfied\b", re.IGNORECASE)


def _coerce_optional_int(value: Any) -> tuple[bool, int | None]:
    """Parse an optional integer field, returning `(valid, parsed_or_none)`."""
    if value is None:
        return True, None
    if isinstance(value, bool):
        return False, None
    if isinstance(value, int):
        return True, value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return True, None
        try:
            return True, int(text)
        except ValueError:
            return False, None
    return False, None


def _has_nonempty_failed_controls(value: Any) -> bool:
    """Return True when `failed_controls` is non-empty or malformed."""
    if value is None:
        return False
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped or stripped == "[]":
            return False
        try:
            parsed = json.loads(stripped)
        except ValueError:
            return True
        if isinstance(parsed, list):
            return len(parsed) > 0
        return bool(parsed)
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value) > 0
    return bool(value)


def _parse_control_list(value: Any) -> tuple[bool, list[str]]:
    """Parse an optional control list field, returning `(valid, cleaned_items)`."""
    if value is None:
        return True, []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped or stripped == "[]":
            return True, []
        try:
            parsed = json.loads(stripped)
        except ValueError:
            return False, []
        if not isinstance(parsed, list):
            return False, []
        value = parsed
    if isinstance(value, (list, tuple)):
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                return False, []
            cleaned.append(item.strip())
        return True, cleaned
    return False, []


def _lula_min_manifests_floor() -> int:
    """Return the minimum active Lula manifest floor (never below 1)."""
    raw = os.environ.get("LULA_AUDIT_MIN_MANIFESTS", "26").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 26


def _is_insufficient_traffic_lula_audit(
    record: Mapping[str, Any] | Any,
    payload: dict[str, Any],
) -> bool:
    """Return True iff `record` is a healthy `lula_audit` run whose sole non-satisfied specs are statistical `insufficient_traffic` controls (`a52`/`a53`/`a92`).

    Enforces server-authoritative invariants:
      - `evaluated_count >= LULA_AUDIT_MIN_MANIFESTS` (`26` default),
      - `failed_count` and `not_satisfied_count` are absent or `0`,
      - `failed_controls` is empty,
      - `insufficient_traffic_controls` is a non-empty subset of
        `STATISTICAL_TRACE_LULA_SPECS`,
      - `satisfied_count + len(insufficient_traffic_controls) == evaluated_count`,
      - `summary` carries `lula_audit INSUFFICIENT_TRAFFIC:` with zero `FAIL`.
    """
    raw_failed = payload.get("failed_count")
    if raw_failed is None:
        raw_failed = _get_record_field(record, "failed_count")
    ok_failed, failed_count = _coerce_optional_int(raw_failed)
    if not ok_failed or (failed_count is not None and failed_count != 0):
        return False

    raw_not_sat = payload.get("not_satisfied_count")
    if raw_not_sat is None:
        raw_not_sat = _get_record_field(record, "not_satisfied_count")
    ok_not_sat, not_satisfied_count = _coerce_optional_int(raw_not_sat)
    if not ok_not_sat or (not_satisfied_count is not None and not_satisfied_count != 0):
        return False

    raw_failed_controls = payload.get("failed_controls")
    if raw_failed_controls is None:
        raw_failed_controls = _get_record_field(record, "failed_controls")
    if _has_nonempty_failed_controls(raw_failed_controls):
        return False

    raw_insuff_controls = payload.get("insufficient_traffic_controls")
    if raw_insuff_controls is None:
        raw_insuff_controls = _get_record_field(record, "insufficient_traffic_controls")
    ok_insuff_list, insuff_controls = _parse_control_list(raw_insuff_controls)
    if not ok_insuff_list or not insuff_controls:
        return False
    if any(c not in STATISTICAL_TRACE_LULA_SPECS for c in insuff_controls):
        return False

    raw_insuff_count = payload.get("insufficient_traffic_count")
    if raw_insuff_count is None:
        raw_insuff_count = _get_record_field(record, "insufficient_traffic_count")
    ok_insuff_cnt, insuff_count = _coerce_optional_int(raw_insuff_count)
    if not ok_insuff_cnt or (
        insuff_count is not None and insuff_count != len(insuff_controls)
    ):
        return False

    raw_eval = payload.get("evaluated_count")
    if raw_eval is None:
        raw_eval = _get_record_field(record, "evaluated_count")
    ok_eval, evaluated_count = _coerce_optional_int(raw_eval)
    min_manifests = _lula_min_manifests_floor()
    if not ok_eval or evaluated_count is None or evaluated_count < min_manifests:
        return False

    raw_sat = payload.get("satisfied_count")
    if raw_sat is None:
        raw_sat = _get_record_field(record, "satisfied_count")
    ok_sat, satisfied_count = _coerce_optional_int(raw_sat)
    if (
        not ok_sat
        or satisfied_count is None
        or satisfied_count < 0
        or satisfied_count + len(insuff_controls) != evaluated_count
    ):
        return False

    summaries = [
        cand.strip()
        for cand in (
            _get_record_field(record, "scrubbed_summary"),
            _get_record_field(record, "summary"),
            payload.get("summary"),
        )
        if isinstance(cand, str) and cand.strip()
    ]
    if not summaries:
        return False

    saw_insuff_prefix = False
    for text in summaries:
        if _LULA_FAIL_PREFIX_RE.search(text):
            return False
        for m_fc in _LULA_FAILED_COUNT_RE.finditer(text):
            if int(m_fc.group(1)) > 0:
                return False
        if _LULA_INSUFFICIENT_PREFIX_RE.search(text):
            saw_insuff_prefix = True

    return saw_insuff_prefix


def _is_insufficient_evidence_only_lula_audit(
    record: Mapping[str, Any] | Any,
    payload: dict[str, Any],
) -> bool:
    """Return True iff `record` is an auditor-healthy `lula_audit` run whose sole non-satisfied specs are statistical `insufficient_traffic` / `insufficient_sample` controls (`a52`/`a53`/`a92`).

    Answers the auditor-liveness question (separate from statistical satisfaction):
    `evaluated_count >= LULA_AUDIT_MIN_MANIFESTS`, zero `failed_count` /
    `not_satisfied_count` / `failed_controls`, disjoint subset of
    `STATISTICAL_TRACE_LULA_SPECS`, exact count conservation, and an
    `INSUFFICIENT_TRAFFIC` or `INSUFFICIENT_SAMPLE` summary with zero `FAIL`.
    """
    raw_failed = payload.get("failed_count")
    if raw_failed is None:
        raw_failed = _get_record_field(record, "failed_count")
    ok_failed, failed_count = _coerce_optional_int(raw_failed)
    if not ok_failed or (failed_count is not None and failed_count != 0):
        return False

    raw_not_sat = payload.get("not_satisfied_count")
    if raw_not_sat is None:
        raw_not_sat = _get_record_field(record, "not_satisfied_count")
    ok_not_sat, not_satisfied_count = _coerce_optional_int(raw_not_sat)
    if not ok_not_sat or (not_satisfied_count is not None and not_satisfied_count != 0):
        return False

    raw_failed_controls = payload.get("failed_controls")
    if raw_failed_controls is None:
        raw_failed_controls = _get_record_field(record, "failed_controls")
    if _has_nonempty_failed_controls(raw_failed_controls):
        return False

    raw_insuff_controls = payload.get("insufficient_traffic_controls")
    if raw_insuff_controls is None:
        raw_insuff_controls = _get_record_field(record, "insufficient_traffic_controls")
    if raw_insuff_controls is None:
        insuff_controls: list[str] = []
    else:
        ok_insuff_list, insuff_controls = _parse_control_list(raw_insuff_controls)
        if not ok_insuff_list:
            return False

    raw_sample_controls = payload.get("insufficient_sample_controls")
    if raw_sample_controls is None:
        raw_sample_controls = _get_record_field(record, "insufficient_sample_controls")
    if raw_sample_controls is None:
        sample_controls: list[str] = []
    else:
        ok_sample_list, sample_controls = _parse_control_list(raw_sample_controls)
        if not ok_sample_list:
            return False

    if not insuff_controls and not sample_controls:
        return False
    if any(c not in STATISTICAL_TRACE_LULA_SPECS for c in insuff_controls):
        return False
    if any(c not in STATISTICAL_TRACE_LULA_SPECS for c in sample_controls):
        return False
    if set(insuff_controls) & set(sample_controls):
        return False

    raw_insuff_count = payload.get("insufficient_traffic_count")
    if raw_insuff_count is None:
        raw_insuff_count = _get_record_field(record, "insufficient_traffic_count")
    ok_insuff_cnt, insuff_count = _coerce_optional_int(raw_insuff_count)
    if not ok_insuff_cnt or (
        insuff_count is not None and insuff_count != len(insuff_controls)
    ):
        return False

    raw_sample_count = payload.get("insufficient_sample_count")
    if raw_sample_count is None:
        raw_sample_count = _get_record_field(record, "insufficient_sample_count")
    ok_sample_cnt, sample_count = _coerce_optional_int(raw_sample_count)
    if not ok_sample_cnt or (
        sample_count is not None and sample_count != len(sample_controls)
    ):
        return False

    raw_eval = payload.get("evaluated_count")
    if raw_eval is None:
        raw_eval = _get_record_field(record, "evaluated_count")
    ok_eval, evaluated_count = _coerce_optional_int(raw_eval)
    min_manifests = _lula_min_manifests_floor()
    if not ok_eval or evaluated_count is None or evaluated_count < min_manifests:
        return False

    raw_sat = payload.get("satisfied_count")
    if raw_sat is None:
        raw_sat = _get_record_field(record, "satisfied_count")
    ok_sat, satisfied_count = _coerce_optional_int(raw_sat)
    if (
        not ok_sat
        or satisfied_count is None
        or satisfied_count < 0
        or satisfied_count + len(insuff_controls) + len(sample_controls)
        != evaluated_count
    ):
        return False

    summaries = [
        cand.strip()
        for cand in (
            _get_record_field(record, "scrubbed_summary"),
            _get_record_field(record, "summary"),
            payload.get("summary"),
        )
        if isinstance(cand, str) and cand.strip()
    ]
    if not summaries:
        return False

    expected_prefix_re = (
        _LULA_INSUFFICIENT_SAMPLE_PREFIX_RE
        if sample_controls
        else _LULA_INSUFFICIENT_PREFIX_RE
    )
    saw_expected_prefix = False
    for text in summaries:
        if _LULA_FAIL_PREFIX_RE.search(text):
            return False
        for m_fc in _LULA_FAILED_COUNT_RE.finditer(text):
            if int(m_fc.group(1)) > 0:
                return False
        if expected_prefix_re.search(text):
            saw_expected_prefix = True

    return saw_expected_prefix


def _is_passing_lula_audit(
    record: Mapping[str, Any] | Any,
    payload: dict[str, Any],
) -> bool:
    """Fail-closed classifier for `lula_audit` INFRA custody records (A.5.3)."""
    raw_failed = payload.get("failed_count")
    if raw_failed is None:
        raw_failed = _get_record_field(record, "failed_count")
    ok_failed, failed_count = _coerce_optional_int(raw_failed)
    if not ok_failed or (failed_count is not None and failed_count != 0):
        return False

    raw_insuff_count = payload.get("insufficient_traffic_count")
    if raw_insuff_count is None:
        raw_insuff_count = _get_record_field(record, "insufficient_traffic_count")
    ok_insuff, insuff_count = _coerce_optional_int(raw_insuff_count)
    if not ok_insuff or (insuff_count is not None and insuff_count != 0):
        return False

    raw_insuff_controls = payload.get("insufficient_traffic_controls")
    if raw_insuff_controls is None:
        raw_insuff_controls = _get_record_field(record, "insufficient_traffic_controls")
    if _has_nonempty_failed_controls(raw_insuff_controls):
        return False

    raw_sample_count = payload.get("insufficient_sample_count")
    if raw_sample_count is None:
        raw_sample_count = _get_record_field(record, "insufficient_sample_count")
    ok_sample, sample_count = _coerce_optional_int(raw_sample_count)
    if not ok_sample or (sample_count is not None and sample_count != 0):
        return False

    raw_sample_controls = payload.get("insufficient_sample_controls")
    if raw_sample_controls is None:
        raw_sample_controls = _get_record_field(record, "insufficient_sample_controls")
    if _has_nonempty_failed_controls(raw_sample_controls):
        return False

    raw_not_sat = payload.get("not_satisfied_count")
    if raw_not_sat is None:
        raw_not_sat = _get_record_field(record, "not_satisfied_count")
    ok_not_sat, not_satisfied_count = _coerce_optional_int(raw_not_sat)
    if not ok_not_sat or (not_satisfied_count is not None and not_satisfied_count != 0):
        return False

    raw_failed_controls = payload.get("failed_controls")
    if raw_failed_controls is None:
        raw_failed_controls = _get_record_field(record, "failed_controls")
    if _has_nonempty_failed_controls(raw_failed_controls):
        return False

    raw_eval = payload.get("evaluated_count")
    if raw_eval is None:
        raw_eval = _get_record_field(record, "evaluated_count")
    ok_eval, evaluated_count = _coerce_optional_int(raw_eval)
    if not ok_eval or (evaluated_count is not None and evaluated_count < 1):
        return False

    raw_sat = payload.get("satisfied_count")
    if raw_sat is None:
        raw_sat = _get_record_field(record, "satisfied_count")
    ok_sat, satisfied_count = _coerce_optional_int(raw_sat)
    if not ok_sat or (satisfied_count is not None and satisfied_count < 0):
        return False

    for key in ("verdict", "decision", "outcome", "status", "result"):
        val = payload.get(key)
        if val is None:
            val = _get_record_field(record, key)
        if isinstance(val, str) and val.strip():
            if val.strip().upper() in _BLOCKING_VERDICTS:
                return False
    if payload.get("accepted") is False:
        return False

    summaries: list[str] = []
    for cand in (
        _get_record_field(record, "scrubbed_summary"),
        _get_record_field(record, "summary"),
        payload.get("summary"),
    ):
        if isinstance(cand, str) and cand.strip():
            summaries.append(cand.strip())

    if not summaries:
        return False

    saw_pass_prefix = False
    for text in summaries:
        if (
            _LULA_FAIL_PREFIX_RE.search(text)
            or _LULA_INSUFFICIENT_PREFIX_RE.search(text)
            or _LULA_INSUFFICIENT_SAMPLE_PREFIX_RE.search(text)
        ):
            return False
        for m_fc in _LULA_FAILED_COUNT_RE.finditer(text):
            if int(m_fc.group(1)) > 0:
                return False
        for m_ns in _LULA_NOT_SATISFIED_COUNT_RE.finditer(text):
            if int(m_ns.group(1)) > 0:
                return False
        residual = _LULA_ZERO_NOT_SATISFIED_RE.sub("", text.lower())
        if "not-satisfied" in residual:
            return False
        if _LULA_PASS_PREFIX_RE.search(text):
            saw_pass_prefix = True
        m_ratio = _LULA_RATIO_RE.search(text)
        if m_ratio is not None:
            ratio_sat = int(m_ratio.group(1))
            ratio_eval = int(m_ratio.group(2))
            if ratio_eval < 1 or ratio_sat < ratio_eval:
                return False
            if evaluated_count is None:
                evaluated_count = ratio_eval
            if satisfied_count is None:
                satisfied_count = ratio_sat

    if not saw_pass_prefix:
        return False

    min_manifests = _lula_min_manifests_floor()
    if evaluated_count is None or evaluated_count < min_manifests:
        return False
    if satisfied_count is not None and satisfied_count < evaluated_count:
        return False

    return True


_OCSF_HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
_OCSF_ALLOW_DISPOSITIONS: frozenset[str] = frozenset({"allowed", "logged", "observed"})
_OCSF_CONTAINMENT_DISPOSITIONS: frozenset[str] = frozenset(
    {"blocked", "denied", "dropped", "rejected"}
)
_OCSF_ALLOW_ACTIONS: frozenset[str] = frozenset({"observed", "allowed", "logged"})
_OCSF_CONTAINMENT_ACTIONS: frozenset[str] = frozenset(
    {"observed", "blocked", "denied", "dropped", "rejected"}
)


def _classify_sandbox_ocsf_telemetry(
    record: Mapping[str, Any] | Any,
    payload: dict[str, Any],
) -> tuple[bool, bool]:
    """Classify `SANDBOX_OCSF_TELEMETRY` into `(is_passing, is_control_effective)`."""
    raw_digest = payload.get("governance_decision_digest")
    if raw_digest is None:
        raw_digest = _get_record_field(record, "governance_decision_digest")
    if not isinstance(raw_digest, str) or not _OCSF_HEX64_RE.fullmatch(
        raw_digest.strip()
    ):
        return False, False

    raw_disp = payload.get("ocsf_disposition")
    if raw_disp is None:
        raw_disp = _get_record_field(record, "ocsf_disposition")
    if not isinstance(raw_disp, str) or not raw_disp.strip():
        return False, False
    disposition = raw_disp.strip().lower()

    raw_action = payload.get("ocsf_action")
    if raw_action is None:
        raw_action = _get_record_field(record, "ocsf_action")
    if raw_action is None:
        action = "observed"
    elif isinstance(raw_action, str) and raw_action.strip():
        action = raw_action.strip().lower()
    else:
        return False, False

    raw_sev = payload.get("ocsf_severity_id")
    if raw_sev is None:
        raw_sev = _get_record_field(record, "ocsf_severity_id")
    ok_sev, parsed_sev = _coerce_optional_int(raw_sev)
    if not ok_sev:
        return False, False
    severity_id = 1 if parsed_sev is None else parsed_sev
    if severity_id < 0 or severity_id > 6:
        return False, False

    if disposition in _OCSF_ALLOW_DISPOSITIONS:
        if action in _OCSF_ALLOW_ACTIONS and 1 <= severity_id <= 3:
            return True, True
        return False, False

    if disposition in _OCSF_CONTAINMENT_DISPOSITIONS:
        if action in _OCSF_CONTAINMENT_ACTIONS and 1 <= severity_id <= 5:
            return False, True
        return False, False

    return False, False


def _is_passing_evidence_record(record: Mapping[str, Any] | Any) -> bool:
    """Classify whether an authoritative `cage_evidence` record represents a passing outcome.

    Canonical producer semantics:
      - Blocking event types (`GOVERNANCE_REFUSAL`, `GOVERNANCE_REFUSAL_RECEIPT`,
        `GOVERNANCE_DEFERRAL`, `DEFER_PARKED`, `ACTUATION_REFUSAL_RECEIPT`,
        `ACTUATION_INDETERMINATE_RECEIPT`, `CONSEQUENCE_GATEWAY_REFUSAL`,
        `CBF_ROLLBACK`, `WORKLOAD_QUARANTINE_RECEIPT`, `GOVERNANCE_VIOLATION`,
        discrepancy fences, and INFRA `cilium_flow_denied`) always return False.
      - `lula_audit`: passes iff structured counts and `summary`/`scrubbed_summary`
        prove a clean `lula_audit PASS:` with zero failed/not-satisfied controls
        and `evaluated_count >= LULA_AUDIT_MIN_MANIFESTS` (`>= 1`).
      - `ACTUATION_RECEIPT`: passes iff `outcome == "ACCEPTED"` (or `accepted is True`
        when `outcome` is omitted); any `outcome != "ACCEPTED"` returns False.
      - `GOVERNANCE_SEAL_CONSUMED`: spent cryptographic seal (`phase == "EXECUTED"`,
        no `verdict` field) returns True unless an explicit blocking verdict is present.
      - `GOVERNANCE_DECISION` / `GOVERNANCE_SETTLEMENT` / `CONSEQUENCE_GATEWAY_DECISION`:
        evaluated against `_PASSING_VERDICTS` (`ALLOW`, `NARROW`, `PASS`, `PASSED`,
        `APPROVED`, `ACCEPTED`, `EXECUTE`, `CONFIRMED`, `SATISFIED`, `ADMITTED`) vs.
        `_BLOCKING_VERDICTS`; unrecognized explicit verdicts fail closed (False).
    """
    payload = _parse_evidence_payload(record)
    raw_event_type = str(
        _get_record_field(record, "event_type")
        or _get_record_field(record, "type")
        or payload.get("event_type")
        or payload.get("type")
        or ""
    ).strip()

    if raw_event_type == "cilium_flow_denied":
        return False

    if raw_event_type.lower() == "lula_audit":
        return _is_passing_lula_audit(record, payload)

    event_type = raw_event_type.upper()
    if event_type == "GOVERNANCE_INFRASTRUCTURE_BLOCK":
        return False

    if event_type == "SANDBOX_OCSF_TELEMETRY":
        is_passing, _ = _classify_sandbox_ocsf_telemetry(record, payload)
        return is_passing

    if event_type in BLOCKING_EVIDENCE_EVENT_TYPES or any(
        token in event_type for token in _BLOCKING_EVENT_TOKENS
    ):
        return False

    if event_type == "ACTUATION_RECEIPT":
        raw_outcome = payload.get("outcome")
        if raw_outcome is None:
            raw_outcome = _get_record_field(record, "outcome")
        if isinstance(raw_outcome, str) and raw_outcome.strip():
            return raw_outcome.strip().upper() == "ACCEPTED"
        accepted_flag = payload.get("accepted")
        if isinstance(accepted_flag, bool):
            return accepted_flag
        return False

    for key in ("verdict", "decision", "outcome", "status", "result"):
        val = payload.get(key)
        if val is None:
            val = _get_record_field(record, key)
        if isinstance(val, str) and val.strip():
            norm = val.strip().upper()
            if norm in _BLOCKING_VERDICTS:
                return False
            if norm in _PASSING_VERDICTS:
                return True
            return False

    if payload.get("accepted") is False:
        return False

    if event_type in PASSING_EVIDENCE_EVENT_TYPES:
        return True

    if str(
        _get_record_field(record, "evidence_class") or ""
    ).upper() == "INFRA" and bool(raw_event_type):
        return True

    return False


_PREVENTIVE_ENFORCEMENT_VERDICTS: frozenset[str] = frozenset(
    {
        "DENY",
        "BLOCK",
        "BLOCKED",
        "REFUSED",
        "DEFER",
        "HOLD",
        "REQUIRE_APPROVAL",
        "REJECTED",
    }
)

_EXPLICIT_CONTROL_FAILURE_VERDICTS: frozenset[str] = frozenset(
    {
        "FAIL",
        "FAILED",
        "ERROR",
        "ROLLED_BACK",
        "ROLLED_BACK_UNLEDGERED",
        "NOOP",
        "UNKNOWN",
        "INDETERMINATE",
        "VIOLATION",
        "NOT-SATISFIED",
    }
)


def _is_control_effective_record(record: Mapping[str, Any] | Any) -> bool:
    """Return True when `record` proves the control operated effectively.

    Admitted passes (`_is_passing_evidence_record() is True`) and intentional,
    fail-closed preventive enforcement (`GOVERNANCE_REFUSAL`, `GOVERNANCE_DEFERRAL`,
    `DEFER_PARKED`, `INFERENCE_PROXY_BLOCK`, `TOKEN_QUOTA_DENIED`,
    `CONSEQUENCE_GATEWAY_REFUSAL`, or `GOVERNANCE_DECISION` with `DENY`/`DEFER`)
    both demonstrate active control enforcement. Operational/integrity failures
    (`lula_audit FAIL`, `CBF_ROLLBACK`, `GOVERNANCE_VIOLATION`, `WORKLOAD_QUARANTINE_RECEIPT`,
    `ACTUATION_REFUSAL_RECEIPT`, `ACTUATION_INDETERMINATE_RECEIPT`, discrepancy
    fences, `cilium_flow_denied`, and `FAIL`/`ERROR`/`ROLLED_BACK` outcomes)
    return False.
    """
    if _is_passing_evidence_record(record):
        return True

    payload = _parse_evidence_payload(record)
    raw_event_type = str(
        _get_record_field(record, "event_type")
        or _get_record_field(record, "type")
        or payload.get("event_type")
        or payload.get("type")
        or ""
    ).strip()

    if raw_event_type == "cilium_flow_denied" or raw_event_type.lower() == "lula_audit":
        return False

    event_type = raw_event_type.upper()
    if event_type == "GOVERNANCE_INFRASTRUCTURE_BLOCK":
        return False

    if event_type == "SANDBOX_OCSF_TELEMETRY":
        _, is_effective = _classify_sandbox_ocsf_telemetry(record, payload)
        return is_effective

    if event_type in {
        "CBF_ROLLBACK",
        "WORKLOAD_QUARANTINE_RECEIPT",
        "GOVERNANCE_VIOLATION",
        "ACTUATION_REFUSAL_RECEIPT",
        "ACTUATION_INDETERMINATE_RECEIPT",
        "ACTUATION_RECEIPT",
        "GOVERNANCE_SETTLEMENT",
    } or any(tok in event_type for tok in _CONTROL_FAILURE_EVENT_TOKENS):
        return False

    for key in ("verdict", "decision", "outcome", "status", "result"):
        val = payload.get(key)
        if val is None:
            val = _get_record_field(record, key)
        if isinstance(val, str) and val.strip():
            if val.strip().upper() in _EXPLICIT_CONTROL_FAILURE_VERDICTS:
                return False

    if event_type in PREVENTIVE_ENFORCEMENT_EVENT_TYPES:
        return True

    if event_type in {"GOVERNANCE_DECISION", "CONSEQUENCE_GATEWAY_DECISION"}:
        for key in ("verdict", "decision", "outcome", "status", "result"):
            val = payload.get(key)
            if val is None:
                val = _get_record_field(record, key)
            if isinstance(val, str) and val.strip():
                return val.strip().upper() in _PREVENTIVE_ENFORCEMENT_VERDICTS

    return False


# ---------------------------------------------------------------------------
# Custody-Chain Readers: WORM Cold Store + Redis DB 1 Hot Stream
# ---------------------------------------------------------------------------


def _run_with_io_pool(coro: Any) -> Any:
    """Execute `coro` in an isolated event loop with an I/O-sized thread pool.

    Python's default `ThreadPoolExecutor` caps concurrency at `min(32, cpu + 4)`,
    which leaves 1-2 vCPU containers limited to 5-6 parallel `asyncio.to_thread`
    downloads. Sizing a dedicated loop executor to the configured cold-store read
    concurrency ensures concurrent `.ndjson` + `.attestation.json` reads proceed in
    parallel without exhausting the host process's default pool.
    """
    workers = max(8, _resolve_cold_store_read_concurrency() * 2)
    loop = asyncio.new_event_loop()
    io_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="cage-cold-store"
    )
    loop.set_default_executor(io_pool)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()
            io_pool.shutdown(wait=True)


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine from synchronous code even if a loop is active."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _run_with_io_pool(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_run_with_io_pool, coro).result()


def _resolve_metrics_cold_store() -> EvidenceColdStore | None:
    """Resolve a process-scoped WORM cold store for archived custody batches, or None.

    Reuses the constructed :class:`EvidenceColdStore` instance per backend/bucket
    configuration key so underlying `google-cloud-storage` HTTPS keep-alive pools
    and OAuth token caches stay warm across concurrent scrapes rather than opening
    fresh clients (which triggered `google-auth` TLS contention under load).
    """
    raw_backend = os.environ.get("EVIDENCE_COLD_STORE", "").strip().lower()
    archive_bucket = os.environ.get("EVIDENCE_ARCHIVE_BUCKET", "").strip()
    s3_endpoint = os.environ.get("EVIDENCE_COLD_STORE_S3_ENDPOINT", "").strip()
    gcs_project = (
        os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
        or os.environ.get("GCS_PROJECT_ID", "").strip()
    )

    backend_arg: str | None = None
    bucket_arg: str | None = None
    if raw_backend in ("gcs", "s3"):
        backend_arg = raw_backend
        bucket_arg = archive_bucket or None
    elif raw_backend not in ("", "null"):
        backend_arg = raw_backend
        bucket_arg = archive_bucket or None
    elif archive_bucket:
        backend_arg = "s3" if s3_endpoint else "gcs"
        bucket_arg = archive_bucket
    else:
        return None

    cache_key = (
        id(get_cold_store),
        backend_arg,
        bucket_arg or "",
        s3_endpoint,
        gcs_project,
    )
    with _cold_store_lock:
        existing = _cold_store_cache.get(cache_key)
        if existing is not None:
            return existing
        store = get_cold_store(backend=backend_arg, bucket=bucket_arg)
        _cold_store_cache[cache_key] = store
        return store


def _date_prefixes_for_window(window_start: datetime, now: datetime) -> list[str]:
    """Build UTC date prefixes (`evidence-stream/YYYY/MM/DD/`) spanning the window."""
    start_day = window_start.astimezone(timezone.utc).date()
    end_day = now.astimezone(timezone.utc).date()
    span_days = (end_day - start_day).days
    if span_days < 0:
        return [f"{_EVIDENCE_ARCHIVE_PREFIX}/{end_day.strftime('%Y/%m/%d')}/"]
    if span_days > _MAX_DATE_PREFIX_SCAN_DAYS:
        return [f"{_EVIDENCE_ARCHIVE_PREFIX}/"]

    prefixes: list[str] = []
    cursor = start_day
    while cursor <= end_day:
        prefixes.append(f"{_EVIDENCE_ARCHIVE_PREFIX}/{cursor.strftime('%Y/%m/%d')}/")
        cursor += timedelta(days=1)
    return prefixes


_tracked_store_finalizers: set[int] = set()


def _evict_store_batches(store_id: int) -> None:
    """Remove `_verified_batch_cache` entries owned by a garbage-collected store."""
    with _verified_batch_lock:
        _tracked_store_finalizers.discard(store_id)
        for key in [k for k in _verified_batch_cache.keys() if k[0] == store_id]:
            _verified_batch_cache.pop(key, None)


def _track_cold_store_for_batch_cache(cold_store: EvidenceColdStore) -> bool:
    """Ensure cached batches are evicted if `cold_store` is GC'd (blocks `id()` reuse)."""
    store_id = id(cold_store)
    with _verified_batch_lock:
        if store_id in _tracked_store_finalizers:
            return True
    try:
        weakref.finalize(cold_store, _evict_store_batches, store_id)
    except TypeError:
        return False
    with _verified_batch_lock:
        _tracked_store_finalizers.add(store_id)
    return True


def _cold_store_bucket_id(cold_store: EvidenceColdStore) -> str:
    return str(
        getattr(
            cold_store,
            "_bucket_name",
            getattr(
                cold_store, "bucket", os.environ.get("EVIDENCE_ARCHIVE_BUCKET", "")
            ),
        )
    )


async def _read_cold_store_records_async(
    cold_store: EvidenceColdStore,
    window_start: datetime,
    now: datetime,
) -> list[dict[str, Any]]:
    """Read `.ndjson` custody batches from WORM cold storage across `[window_start, now]`.

    Fetches UTC date-prefix listings and uncached `(batch, attestation)` pairs
    with bounded concurrency (`EVIDENCE_COLD_STORE_READ_CONCURRENCY`, default 16).
    Signed, KMS-attested batches whose SHA-256 and posture verified cleanly are
    retained in `_verified_batch_cache` (bounded TTL) so historical immutable
    WORM objects are not re-downloaded on every scrape. Unsigned or tampered
    objects are never cached and always fail closed immediately.
    """
    posture = resolve_posture()
    enforcing = is_enforcing(posture)
    prefixes = _date_prefixes_for_window(window_start, now)

    listed_keys: set[str] = set()
    if len(prefixes) == 1:
        listed_keys.update(await cold_store.list_keys(prefixes[0]))
    elif prefixes:
        prefix_batches = await asyncio.gather(
            *(cold_store.list_keys(prefix) for prefix in prefixes)
        )
        for keys in prefix_batches:
            listed_keys.update(keys)

    ndjson_keys = sorted(k for k in listed_keys if k.endswith(".ndjson"))
    if not ndjson_keys:
        return []

    can_cache_store = _track_cold_store_for_batch_cache(cold_store)
    store_id = id(cold_store)
    bucket_id = _cold_store_bucket_id(cold_store)
    posture_val = posture.value
    batch_results: list[tuple[dict[str, Any], ...]] = [() for _ in ndjson_keys]
    pending: list[tuple[int, str, str, bool]] = []

    for idx, data_key in enumerate(ndjson_keys):
        base = data_key[: -len(".ndjson")]
        signed_att_key = f"{base}.attestation.json"
        has_signed_att = signed_att_key in listed_keys

        if enforcing and not has_signed_att:
            unsigned_att_key = f"{base}.attestation.unsigned.json"
            if unsigned_att_key in listed_keys:
                raise NonEvidentiaryAttestationError(
                    f"Unsigned custody batch {data_key!r} is non-evidentiary under enforcing posture."
                )
            # In-flight batch whose companion attestation has not been committed yet;
            # those entries remain readable from Redis DB 1 until cursor advance.
            continue

        if has_signed_att and can_cache_store:
            batch_cache_key = (store_id, bucket_id, posture_val, data_key)
            with _verified_batch_lock:
                cached_batch = _verified_batch_cache.get(batch_cache_key)
            if cached_batch is not None:
                batch_results[idx] = cached_batch
                continue

        pending.append((idx, data_key, signed_att_key, has_signed_att))

    if pending:
        sem = asyncio.Semaphore(_resolve_cold_store_read_concurrency())

        async def _load_and_verify(
            slot: int, data_key: str, signed_att_key: str, has_signed_att: bool
        ) -> None:
            async with sem:
                if has_signed_att:
                    ndjson_bytes, att_bytes = await asyncio.gather(
                        cold_store.get(data_key),
                        cold_store.get(signed_att_key),
                    )
                    try:
                        attestation = json.loads(att_bytes.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise EvidenceCustodyIntegrityError(
                            f"Malformed custody attestation JSON at {signed_att_key!r}: {exc}"
                        ) from exc
                    if not isinstance(attestation, dict):
                        raise EvidenceCustodyIntegrityError(
                            f"Custody attestation at {signed_att_key!r} must be a JSON object."
                        )
                    assert_citable(attestation)
                    if (
                        enforcing
                        and attestation.get("schema") == ATTESTATION_SCHEMA_V2
                        and attestation.get("deployment_posture") != posture_val
                    ):
                        raise NonEvidentiaryAttestationError(
                            f"Custody batch {data_key!r} carries deployment_posture="
                            f"{attestation.get('deployment_posture')!r}, expected {posture_val!r}."
                        )
                    actual_sha = hashlib.sha256(ndjson_bytes).hexdigest()
                    if attestation.get("content_sha256") != actual_sha:
                        raise EvidenceCustodyIntegrityError(
                            f"Custody batch {data_key!r} SHA-256 mismatch against {signed_att_key!r}."
                        )
                else:
                    ndjson_bytes = await cold_store.get(data_key)

                parsed_records: list[dict[str, Any]] = []
                for raw_line in ndjson_bytes.decode("utf-8").splitlines():
                    line = raw_line.strip()
                    if not line:
                        continue
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        parsed_records.append(parsed)
                frozen = tuple(parsed_records)
                batch_results[slot] = frozen
                if has_signed_att and can_cache_store:
                    batch_cache_key = (store_id, bucket_id, posture_val, data_key)
                    with _verified_batch_lock:
                        _verified_batch_cache[batch_cache_key] = frozen

        await asyncio.gather(
            *(
                _load_and_verify(slot, data_key, signed_att_key, has_signed_att)
                for slot, data_key, signed_att_key, has_signed_att in pending
            )
        )

    records: list[dict[str, Any]] = []
    for batch in batch_results:
        for rec in batch:
            records.append(dict(rec))
    return records


def _build_evidence_sync_redis(redis_url: str, db: int | None = None) -> Any:
    """Build a synchronous Redis client targeting the `cage_evidence` DB (default DB 1)."""
    import redis

    from src.gateway.infrastructure.redis_client import resolve_redis_tls
    from src.gateway.infrastructure.redis_credential_factory import (
        get_redis_credential_provider,
    )

    parsed = urlparse(redis_url)
    url_db: int | None = None
    if parsed.path and parsed.path.lstrip("/").isdigit():
        url_db = int(parsed.path.lstrip("/"))
    effective_db = (
        db
        if db is not None
        else (
            url_db
            if url_db is not None
            else int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1"))
        )
    )

    tls_env = os.environ.get("REDIS_TLS", "").lower()
    use_tls = parsed.scheme == "rediss" or tls_env in ("true", "1", "yes")
    cert_reqs, ca_certs = resolve_redis_tls(use_tls)
    cred_provider = get_redis_credential_provider()
    password = None
    if cred_provider is None:
        password = (
            unquote(parsed.password)
            if parsed.password
            else os.environ.get("REDIS_PASSWORD") or None
        )

    kwargs: dict[str, Any] = {
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 6379,
        "db": effective_db,
        "decode_responses": True,
        "socket_connect_timeout": 2.0,
        "socket_timeout": 2.0,
    }
    if cred_provider is not None:
        kwargs["credential_provider"] = cred_provider
    elif password is not None:
        kwargs["password"] = password
    if use_tls:
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = cert_reqs
        if ca_certs:
            kwargs["ssl_ca_certs"] = ca_certs
    return redis.Redis(**kwargs)


def _read_redis_stream_records(
    redis_url: str,
    window_start: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    """Read hot custody records from Redis DB 1 governance and INFRA streams."""
    primary_stream = (
        os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream").strip()
        or "cage:evidence:stream"
    )
    infra_stream = (
        os.environ.get(INFRA_STREAM_KEY_ENV, DEFAULT_INFRA_STREAM_KEY).strip()
        or DEFAULT_INFRA_STREAM_KEY
    )
    stream_keys = [primary_stream]
    if infra_stream not in stream_keys:
        stream_keys.append(infra_stream)

    min_ms = max(0, int(window_start.timestamp() * 1000))
    min_stream_id = f"{min_ms}-0"

    client = _build_evidence_sync_redis(redis_url)
    records: list[dict[str, Any]] = []
    try:
        for stream_key in stream_keys:
            entries = client.xrevrange(stream_key, "+", min_stream_id, count=limit)
            for entry_id, fields in entries or []:
                if not isinstance(fields, Mapping):
                    continue
                rec = dict(fields)
                rec.setdefault("stream_id", entry_id)
                records.append(rec)
    finally:
        if hasattr(client, "close"):
            try:
                client.close()
            except Exception as close_exc:
                logger.debug(
                    "[metrics] Ignoring Redis client close error: %s", close_exc
                )
    return records


def _record_dedup_key(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Compute a deterministic deduplication key across WORM archive and Redis DB 1."""
    record_hash = str(record.get("record_hash") or "").strip()
    if record_hash:
        return ("record_hash", record_hash)
    chain_id = str(record.get("chain_id") or "").strip()
    sequence = record.get("sequence")
    if chain_id and sequence is not None and str(sequence).strip() != "":
        return ("chain_seq", chain_id, str(sequence).strip())
    stream_id = str(record.get("stream_id") or "").strip()
    if stream_id:
        return ("stream_id", stream_id)
    return (
        "content_sha256",
        hashlib.sha256(
            json.dumps(dict(record), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest(),
    )


def _build_snapshot_cache_key(
    scope: str,
    window_hours: int,
    *,
    enforcing: bool,
    cold_store: EvidenceColdStore | None,
    redis_url: str,
    stream_keys: tuple[str, ...],
) -> tuple[Any, ...]:
    """Return a structural cache key for the raw custody snapshot window."""
    bucket_id = (
        _cold_store_bucket_id(cold_store)
        if cold_store is not None
        else os.environ.get("EVIDENCE_ARCHIVE_BUCKET", "")
    )
    return (
        scope,
        window_hours,
        enforcing,
        id(cold_store) if cold_store is not None else 0,
        bucket_id,
        redis_url,
        stream_keys,
        id(globals().get("_read_cold_store_records_async")),
        id(globals().get("_build_evidence_sync_redis")),
    )


def _query_cage_evidence_records(
    control_id: str,
    window_hours: int,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Query and deduplicate `cage_evidence` custody records for `control_id`.

    Combines archived WORM `.ndjson` custody batches (`EVIDENCE_COLD_STORE` /
    `EVIDENCE_ARCHIVE_BUCKET`) with hot Redis DB 1 stream records
    (`EVIDENCE_STREAM_REDIS_URL` / `REDIS_URL`), deduplicating overlapping
    records that appear in both stores prior to stream trimming.

    Under enforcing postures (`is_enforcing()`), missing custody configuration
    or backend read/integrity failures raise immediately (fail-closed) rather
    than returning fabricated scores or falling back to Langfuse.
    """
    now = datetime.now(tz=timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    enforcing = is_enforcing()

    cold_store = _resolve_metrics_cold_store()
    redis_url = (
        os.environ.get("EVIDENCE_STREAM_REDIS_URL", "").strip()
        or os.environ.get("REDIS_URL", "").strip()
    )

    if cold_store is None and not redis_url:
        if enforcing:
            raise RuntimeError(
                "No authoritative custody-chain store is configured "
                "(set EVIDENCE_COLD_STORE/EVIDENCE_ARCHIVE_BUCKET and/or "
                "EVIDENCE_STREAM_REDIS_URL) under enforcing posture."
            )
        return []

    raw_cache_key = _build_snapshot_cache_key(
        "metrics",
        window_hours,
        enforcing=enforcing,
        cold_store=cold_store,
        redis_url=redis_url,
        stream_keys=(
            os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream").strip(),
            os.environ.get(INFRA_STREAM_KEY_ENV, DEFAULT_INFRA_STREAM_KEY).strip(),
        ),
    )

    combined_raw: list[dict[str, Any]] | None = None
    with _raw_custody_lock:
        cached_raw = _raw_custody_cache.get(raw_cache_key)
        if cached_raw is not None:
            combined_raw = list(cached_raw)

    if combined_raw is None:
        flight_lock = _get_inflight_lock(raw_cache_key)
        with flight_lock:
            with _raw_custody_lock:
                cached_raw = _raw_custody_cache.get(raw_cache_key)
                if cached_raw is not None:
                    combined_raw = list(cached_raw)

            if combined_raw is None:
                fetched_raw: list[dict[str, Any]] = []
                if cold_store is not None:
                    try:
                        archived = _run_coro_sync(
                            _read_cold_store_records_async(
                                cold_store, window_start, now
                            )
                        )
                        fetched_raw.extend(archived)
                    except Exception as exc:
                        if enforcing or isinstance(
                            exc,
                            (
                                EvidenceCustodyIntegrityError,
                                NonEvidentiaryAttestationError,
                            ),
                        ):
                            raise
                        logger.warning(
                            "[metrics] Failed to read WORM custody archive for control %s: %s",
                            control_id,
                            exc,
                        )

                if redis_url:
                    try:
                        hot_records = _read_redis_stream_records(
                            redis_url=redis_url,
                            window_start=window_start,
                            limit=limit,
                        )
                        fetched_raw.extend(hot_records)
                    except Exception as exc:
                        if enforcing or isinstance(
                            exc,
                            (
                                EvidenceCustodyIntegrityError,
                                NonEvidentiaryAttestationError,
                            ),
                        ):
                            raise
                        logger.warning(
                            "[metrics] Failed to read Redis DB 1 custody stream for control %s: %s",
                            control_id,
                            exc,
                        )

                combined_raw = fetched_raw
                if fetched_raw:
                    with _raw_custody_lock:
                        _raw_custody_cache[raw_cache_key] = list(fetched_raw)

    seen_keys: set[tuple[str, ...]] = set()
    matched: list[tuple[datetime, dict[str, Any]]] = []

    for rec in combined_raw:
        if not isinstance(rec, Mapping):
            continue
        rec_dict = dict(rec)
        dedup_key = _record_dedup_key(rec_dict)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        if _is_canary_evidence_record(rec_dict):
            continue

        if not _record_matches_control(rec_dict, control_id):
            continue

        rec_ts = _parse_evidence_timestamp(rec_dict)
        if rec_ts is None or rec_ts < window_start:
            continue
        matched.append((rec_ts, rec_dict))

    matched.sort(key=lambda item: item[0], reverse=True)
    return [rec for _, rec in matched[:limit]]


def _is_canary_evidence_record(record: Mapping[str, Any] | Any) -> bool:
    """Return True when `record` was emitted by the synthetic in-mesh liveness canary.

    Canary records carry top-level `"canary": true` inside the JCS-canonicalized,
    hash-chained `payload_json` (stamped exclusively by `EvidenceStreamSink` from
    Linkerd-verified `CAGE_CANARY_CLIENT_IDENTITIES`, never from caller-supplied
    `params`). Excluding them prevents synthetic liveness traffic from inflating
    Lula trace-volume thresholds (`A.5.2`, `A.5.3`, `A.9.2`) or fabricating
    `safety_rate == 1.0` on an idle cluster.
    """
    raw_top = _get_record_field(record, "canary")
    if raw_top is True or (
        isinstance(raw_top, str) and raw_top.strip().lower() == "true"
    ):
        return True
    payload = _parse_evidence_payload(record)
    return payload.get("canary") is True


def _fetch_from_evidence_stream_sync(
    control_id: str,
    window_hours: int,
) -> ComplianceMetrics:
    """Aggregate per-control compliance metrics from the custody chain."""
    window_start = datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)
    records = _query_cage_evidence_records(control_id, window_hours=window_hours)

    total_traces = 0
    passed_traces = 0
    infrastructure_blocks = 0
    self_evaluation_records_excluded = 0
    last_event_date = datetime.fromtimestamp(0, tz=timezone.utc)

    for record in records:
        if _is_canary_evidence_record(record):
            continue
        if not _record_matches_control(record, control_id):
            continue

        record_date = _parse_evidence_timestamp(record)
        if record_date is not None and record_date < window_start:
            continue

        record_payload = _parse_evidence_payload(record)
        rec_event_type = str(
            _get_record_field(record, "event_type")
            or _get_record_field(record, "type")
            or record_payload.get("event_type")
            or record_payload.get("type")
            or ""
        ).strip()
        # Gateway 503 infrastructure blocks (`GOVERNANCE_INFRASTRUCTURE_BLOCK`)
        # measure dependency availability rather than control effectiveness:
        # partition them into `infrastructure_blocks` without polluting
        # `total_traces`, `passed_traces`, `safety_rate`, or `last_event_date`.
        if rec_event_type.upper() == "GOVERNANCE_INFRASTRUCTURE_BLOCK":
            infrastructure_blocks += 1
            continue
        # Structural anti-latch invariant (`POAM-2026-201` / `POAM-2026-244`):
        # Exclude any control-evaluation output record (`lula_audit`,
        # `control_assessment`, `assessment_result`, or `record_role="control_evaluation"`)
        # emitted by evaluating `control_id` from `control_id`'s own input population.
        # Applies uniformly to every control `X` (not an A.5.3 special case). Evaluation
        # records remain sealed in WORM custody and are counted explicitly in
        # `self_evaluation_records_excluded`; `lula_audit` alerting, Prometheus gauges,
        # and the dead-man's switch stay authoritative for audit outcomes.
        if _is_self_evaluation_record(record, control_id, record_payload):
            self_evaluation_records_excluded += 1
            continue

        total_traces += 1
        is_effective = _is_control_effective_record(record)
        if is_effective:
            passed_traces += 1

        if not (rec_event_type.lower() == "lula_audit" and not is_effective):
            if record_date is not None and record_date > last_event_date:
                last_event_date = record_date

    blocked_traces = total_traces - passed_traces
    min_sample_size = _resolve_min_sample_size(control_id)
    # Return None when no evidence records exist — 1.0 would be a false-positive score
    safety_rate = (passed_traces / total_traces) if total_traces > 0 else None
    now = datetime.now(tz=timezone.utc)
    has_timestamp = total_traces > 0 and last_event_date.timestamp() > 0
    last_event_utc = last_event_date.isoformat() if has_timestamp else now.isoformat()
    evidence_age_seconds = (
        (now - last_event_date).total_seconds() if has_timestamp else 0.0
    )

    grace = _get_grace_status()

    return ComplianceMetrics(
        control_id=control_id,
        safety_rate=round(safety_rate * 10000) / 10000
        if safety_rate is not None
        else None,
        total_traces=total_traces,
        blocked_traces=blocked_traces,
        passed_traces=passed_traces,
        infrastructure_blocks=infrastructure_blocks,
        self_evaluation_records_excluded=self_evaluation_records_excluded,
        min_sample_size=min_sample_size,
        sample_sufficient=total_traces >= min_sample_size,
        window_hours=float(window_hours),
        last_event_utc=last_event_utc,
        evidence_age_seconds=max(0.0, evidence_age_seconds),
        startup_grace_active=bool(grace["active"]),
        startup_grace_remaining_hours=round(float(grace["remaining_hours"]) * 100)
        / 100,
    )


# Backward-compatible alias for callers importing _fetch_from_langfuse_sync
_fetch_from_langfuse_sync = _fetch_from_evidence_stream_sync


# ---------------------------------------------------------------------------
# Public API — cache-first aggregation
# ---------------------------------------------------------------------------


async def get_compliance_metrics(
    control_id: str,
    window_hours: int = 24,
) -> ComplianceMetrics:
    """Return compliance metrics for `control_id` over the custody chain.

    Uses a 5-minute TTL cache to avoid repeated custody scans on every Lula poll.
    On cache hit, `evidence_age_seconds` is updated to reflect real-time staleness.

    Args:
        control_id:   ISO 42001 / NIST SP 800-53 control ID, e.g. "A.5.2"
        window_hours: Look-back window for custody aggregation (default: 24h)

    Returns:
        ComplianceMetrics — the exact JSON Lula's OPA Rego receives as `input`.
    """
    cache_key = f"{control_id}:{window_hours}"
    cached = _metrics_cache.get(cache_key)

    if cached is not None:
        last_event = datetime.fromisoformat(
            cached.last_event_utc.replace("Z", "+00:00")
        )
        now_age = max(
            0.0,
            (datetime.now(tz=timezone.utc) - last_event).total_seconds(),
        )
        return cached.model_copy(update={"evidence_age_seconds": now_age})

    async with _EVIDENCE_CONCURRENCY:
        result = await asyncio.to_thread(
            _fetch_from_evidence_stream_sync, control_id, window_hours
        )
    if result.total_traces > 0:
        _metrics_cache[cache_key] = result
    return result


def get_last_passing_lula_audit_age_seconds(
    window_hours: int = 24,
) -> tuple[float | None, str | None]:
    """Return `(age_seconds, last_pass_iso_utc)` of the newest statistically clean (`26/26 satisfied`) `lula_audit` record.

    Answers **Question 2 (statistical satisfaction attestation, `POAM-2026-234`)**:
    scans `A.5.3` custody records over `window_hours` and considers **strictly**
    `event_type == "lula_audit"` records where `_is_passing_evidence_record(rec)`
    is `True` (proving `>= LULA_AUDIT_MIN_MANIFESTS` specs were evaluated and
    **all** satisfied with zero failures, zero `insufficient_traffic`, and zero
    `insufficient_sample`).

    Auditor-liveness dead-man monitoring uses
    :func:`get_last_healthy_lula_audit_age_seconds` instead so quiet clusters do
    not conflate statistical sample size with CronJob execution liveness.
    Returns `(None, None)` when no clean `26/26` passing `lula_audit` exists in the window.
    """
    records = _query_cage_evidence_records("A.5.3", window_hours=window_hours)
    latest_pass_ts: datetime | None = None

    for rec in records:
        payload = _parse_evidence_payload(rec)
        raw_event_type = str(
            _get_record_field(rec, "event_type")
            or _get_record_field(rec, "type")
            or payload.get("event_type")
            or payload.get("type")
            or ""
        ).strip()
        if raw_event_type.lower() != "lula_audit":
            continue
        if not _is_passing_evidence_record(rec):
            continue
        rec_ts = _parse_evidence_timestamp(rec)
        if rec_ts is None:
            continue
        if latest_pass_ts is None or rec_ts > latest_pass_ts:
            latest_pass_ts = rec_ts

    if latest_pass_ts is None:
        return (None, None)

    now = datetime.now(tz=timezone.utc)
    age_seconds = max(0.0, (now - latest_pass_ts).total_seconds())
    return (age_seconds, latest_pass_ts.isoformat())


def get_last_healthy_lula_audit_age_seconds(
    window_hours: int = 24,
) -> tuple[float | None, str | None]:
    """Return `(age_seconds, last_healthy_iso_utc)` of the newest auditor-healthy `lula_audit` record.

    Answers **Question 1 (auditor & structural liveness)** for the `2 x schedule`
    dead-man's switch: did `CronJob/lula-audit` execute `>= LULA_AUDIT_MIN_MANIFESTS`
    manifests, seal its receipt into WORM custody, and observe `failed_count == 0`
    (`_is_passing_evidence_record(rec)` or
    `_is_insufficient_evidence_only_lula_audit(rec, payload)`)?

    Suspended CronJobs, `< 26` corpus-floor breaches, structural control failures,
    and spoofed non-statistical `insufficient_*` claims never advance this timer.
    """
    records = _query_cage_evidence_records("A.5.3", window_hours=window_hours)
    latest_healthy_ts: datetime | None = None

    for rec in records:
        payload = _parse_evidence_payload(rec)
        raw_event_type = str(
            _get_record_field(rec, "event_type")
            or _get_record_field(rec, "type")
            or payload.get("event_type")
            or payload.get("type")
            or ""
        ).strip()
        if raw_event_type.lower() != "lula_audit":
            continue
        if not (
            _is_passing_evidence_record(rec)
            or _is_insufficient_evidence_only_lula_audit(rec, payload)
        ):
            continue
        rec_ts = _parse_evidence_timestamp(rec)
        if rec_ts is None:
            continue
        if latest_healthy_ts is None or rec_ts > latest_healthy_ts:
            latest_healthy_ts = rec_ts

    if latest_healthy_ts is None:
        return (None, None)

    now = datetime.now(tz=timezone.utc)
    age_seconds = max(0.0, (now - latest_healthy_ts).total_seconds())
    return (age_seconds, latest_healthy_ts.isoformat())


def _read_primary_evidence_stream_records(
    redis_url: str,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    """Read hot records from the primary `cage:evidence:stream` key on Redis DB 1."""
    primary_stream = (
        os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream").strip()
        or "cage:evidence:stream"
    )
    client = _build_evidence_sync_redis(redis_url)
    records: list[dict[str, Any]] = []
    try:
        entries = client.xrevrange(primary_stream, "+", "-", count=limit)
        for entry_id, fields in entries or []:
            if not isinstance(fields, Mapping):
                continue
            rec = dict(fields)
            rec.setdefault("stream_id", entry_id)
            records.append(rec)
    finally:
        if hasattr(client, "close"):
            try:
                client.close()
            except Exception as close_exc:
                logger.debug(
                    "[metrics] Ignoring Redis client close error: %s", close_exc
                )
    return records


def _query_cm6_stream_records(
    window_hours: int = 168,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    """Read custody-verified records from WORM cold store and `cage:evidence:stream` for CM-6."""
    now = datetime.now(tz=timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    enforcing = is_enforcing()

    cold_store = _resolve_metrics_cold_store()
    redis_url = (
        os.environ.get("EVIDENCE_STREAM_REDIS_URL", "").strip()
        or os.environ.get("REDIS_URL", "").strip()
    )

    if cold_store is None and not redis_url:
        if enforcing:
            raise RuntimeError(
                "No authoritative custody-chain store is configured "
                "(set EVIDENCE_COLD_STORE/EVIDENCE_ARCHIVE_BUCKET and/or "
                "EVIDENCE_STREAM_REDIS_URL) under enforcing posture."
            )
        return []

    raw_cache_key = _build_snapshot_cache_key(
        "cm6",
        window_hours,
        enforcing=enforcing,
        cold_store=cold_store,
        redis_url=redis_url,
        stream_keys=(
            os.environ.get("EVIDENCE_STREAM_KEY", "cage:evidence:stream").strip(),
        ),
    )

    with _raw_custody_lock:
        cached_raw = _raw_custody_cache.get(raw_cache_key)
        if cached_raw is not None:
            return list(cached_raw)

    flight_lock = _get_inflight_lock(raw_cache_key)
    with flight_lock:
        with _raw_custody_lock:
            cached_raw = _raw_custody_cache.get(raw_cache_key)
            if cached_raw is not None:
                return list(cached_raw)

        fetched_raw: list[dict[str, Any]] = []
        if cold_store is not None:
            try:
                archived = _run_coro_sync(
                    _read_cold_store_records_async(cold_store, window_start, now)
                )
                fetched_raw.extend(archived)
            except Exception as exc:
                if enforcing or isinstance(
                    exc, (EvidenceCustodyIntegrityError, NonEvidentiaryAttestationError)
                ):
                    raise
                logger.warning(
                    "[metrics] Failed to read WORM custody archive for CM-6: %s", exc
                )

        if redis_url:
            try:
                hot_records = _read_primary_evidence_stream_records(
                    redis_url=redis_url,
                    limit=limit,
                )
                fetched_raw.extend(hot_records)
            except Exception as exc:
                if enforcing or isinstance(
                    exc, (EvidenceCustodyIntegrityError, NonEvidentiaryAttestationError)
                ):
                    raise
                logger.warning(
                    "[metrics] Failed to read Redis DB 1 stream for CM-6: %s", exc
                )

        if fetched_raw:
            with _raw_custody_lock:
                _raw_custody_cache[raw_cache_key] = list(fetched_raw)
        return fetched_raw


def _extract_record_event_type(record: Mapping[str, Any]) -> str:
    payload = _parse_evidence_payload(record)
    return (
        str(
            _get_record_field(record, "event_type")
            or _get_record_field(record, "type")
            or payload.get("event_type")
            or payload.get("type")
            or ""
        )
        .strip()
        .upper()
    )


def _extract_decision_thresholds_digest(record: Mapping[str, Any]) -> Any:
    payload = _parse_evidence_payload(record)
    val = payload.get("thresholds_digest")
    if val is None:
        val = _get_record_field(record, "thresholds_digest")
    return val


def evaluate_cm6_thresholds_records(
    records: Sequence[Mapping[str, Any]],
    active_region: str,
) -> Cm6ThresholdsPosture:
    """Evaluate NIST SP 800-53 CM-6 thresholds-digest posture over stream records."""
    seen_keys: set[tuple[str, ...]] = set()
    deduped: list[tuple[int, dict[str, Any]]] = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, Mapping):
            continue
        rec_dict = dict(rec)
        dedup_key = _record_dedup_key(rec_dict)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        if _is_canary_evidence_record(rec_dict):
            continue
        deduped.append((idx, rec_dict))

    load_candidates: list[tuple[int, dict[str, Any]]] = []
    decision_candidates: list[tuple[int, dict[str, Any]]] = []
    for pos, rec_dict in deduped:
        ev_type = _extract_record_event_type(rec_dict)
        if ev_type == "GOVERNANCE_THRESHOLDS_LOADED" and _record_matches_control(
            rec_dict, "CM-6"
        ):
            load_candidates.append((pos, rec_dict))
        elif ev_type == "GOVERNANCE_DECISION":
            decision_candidates.append((pos, rec_dict))

    if not load_candidates:
        return Cm6ThresholdsPosture(
            assessment_status="not_satisfied",
            active_region=active_region,
        )

    def _load_order_key(item: tuple[int, dict[str, Any]]) -> tuple[float, int, int]:
        pos, rec_dict = item
        ts = _parse_evidence_timestamp(rec_dict)
        ts_val = ts.timestamp() if ts is not None else -1.0
        ok_seq, seq_val = _coerce_optional_int(rec_dict.get("sequence"))
        eff_seq = seq_val if (ok_seq and seq_val is not None) else -1
        return (ts_val, eff_seq, pos)

    # When all candidates share one non-empty chain_id with valid sequences, sequence order wins.
    chains = {
        str(r.get("chain_id") or "").strip()
        for _, r in load_candidates
        if str(r.get("chain_id") or "").strip()
    }
    if len(chains) == 1 and all(
        _coerce_optional_int(r.get("sequence"))[1] is not None
        for _, r in load_candidates
    ):
        load_pos, latest_load = max(
            load_candidates,
            key=lambda it: (
                int(_coerce_optional_int(it[1].get("sequence"))[1] or 0),
                it[0],
            ),
        )
    else:
        load_pos, latest_load = max(load_candidates, key=_load_order_key)

    payload = _parse_evidence_payload(latest_load)
    raw_digest = payload.get("thresholds_digest")
    if raw_digest is None:
        raw_digest = _get_record_field(latest_load, "thresholds_digest")
    digest_str = raw_digest.strip() if isinstance(raw_digest, str) else ""
    digest_valid = bool(_OCSF_HEX64_RE.fullmatch(digest_str))

    raw_region = payload.get("region")
    if raw_region is None:
        raw_region = _get_record_field(latest_load, "region")
    region_str = raw_region.strip().upper() if isinstance(raw_region, str) else ""
    region_valid = bool(region_str) and region_str == active_region.upper()

    raw_schema = payload.get("schema_version")
    if raw_schema is None:
        raw_schema = _get_record_field(latest_load, "schema_version")
    ok_schema, parsed_schema = _coerce_optional_int(raw_schema)
    schema_version = (
        parsed_schema
        if (ok_schema and parsed_schema is not None and parsed_schema >= 1)
        else 0
    )
    schema_valid = schema_version >= 1

    raw_domains = payload.get("domain_sections")
    if raw_domains is None:
        raw_domains = _get_record_field(latest_load, "domain_sections")
    domains_valid = (
        isinstance(raw_domains, list)
        and len(raw_domains) > 0
        and all(isinstance(d, str) and bool(d.strip()) for d in raw_domains)
    )
    domain_sections = [d.strip() for d in raw_domains] if domains_valid else []

    load_ts = _parse_evidence_timestamp(latest_load)
    raw_ts = payload.get("timestamp_utc") or _get_record_field(
        latest_load, "timestamp_utc"
    )
    loaded_at_utc = (
        raw_ts.strip()
        if isinstance(raw_ts, str) and raw_ts.strip()
        else (load_ts.isoformat() if load_ts is not None else None)
    )

    load_chain = str(latest_load.get("chain_id") or "").strip()
    _, load_seq = _coerce_optional_int(latest_load.get("sequence"))

    decisions_checked = 0
    digest_mismatches = 0
    for dec_pos, dec_rec in decision_candidates:
        dec_chain = str(dec_rec.get("chain_id") or "").strip()
        _, dec_seq = _coerce_optional_int(dec_rec.get("sequence"))
        dec_ts = _parse_evidence_timestamp(dec_rec)

        if (
            load_chain
            and dec_chain
            and dec_chain == load_chain
            and load_seq is not None
            and dec_seq is not None
        ):
            is_since = dec_seq > load_seq
        elif (
            not load_chain
            and not dec_chain
            and load_seq is not None
            and dec_seq is not None
        ):
            is_since = dec_seq > load_seq
        elif load_ts is not None and dec_ts is not None:
            is_since = dec_ts >= load_ts
        else:
            is_since = dec_pos > load_pos

        if not is_since:
            continue

        decisions_checked += 1
        dec_digest = _extract_decision_thresholds_digest(dec_rec)
        if (
            not digest_valid
            or not isinstance(dec_digest, str)
            or dec_digest.strip() != digest_str
        ):
            digest_mismatches += 1

    satisfied = (
        digest_valid
        and region_valid
        and schema_valid
        and domains_valid
        and digest_mismatches == 0
    )
    return Cm6ThresholdsPosture(
        control_id="CM-6",
        assessment_status="satisfied" if satisfied else "not_satisfied",
        thresholds_digest=digest_str if digest_valid else "",
        region=region_str,
        active_region=active_region,
        schema_version=schema_version,
        domain_sections=domain_sections,
        decisions_checked=decisions_checked,
        digest_mismatches=digest_mismatches,
        loaded_at_utc=loaded_at_utc,
    )


def _fetch_cm6_thresholds_posture_sync(
    window_hours: int = 168,
) -> Cm6ThresholdsPosture:
    active_region = resolve_deployment_region()
    records = _query_cm6_stream_records(window_hours=window_hours)
    return evaluate_cm6_thresholds_records(records, active_region=active_region)


async def get_cm6_thresholds_posture(
    window_hours: int = 168,
) -> Cm6ThresholdsPosture:
    """Return NIST SP 800-53 CM-6 thresholds-digest posture over the custody chain."""
    async with _EVIDENCE_CONCURRENCY:
        return await asyncio.to_thread(_fetch_cm6_thresholds_posture_sync, window_hours)
