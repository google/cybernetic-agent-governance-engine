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
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote, urlparse

from cachetools import TTLCache

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.evidence.cold_store import EvidenceColdStore
from src.gateway.governance.evidence.factory import get_cold_store

from .evidence_custodian import (
    EvidenceCustodyIntegrityError,
    NonEvidentiaryAttestationError,
    assert_citable,
)
from .infra_custody import DEFAULT_INFRA_STREAM_KEY, INFRA_STREAM_KEY_ENV
from .types import ComplianceMetrics

logger = logging.getLogger(__name__)

# Cap concurrent custody-chain scans when /v1/metrics/summary, oscal-export,
# and aarm-report fan out across all supported controls simultaneously.
_EVIDENCE_CONCURRENCY = asyncio.Semaphore(6)
_LANGFUSE_CONCURRENCY = _EVIDENCE_CONCURRENCY

_EVIDENCE_ARCHIVE_PREFIX = "evidence-stream"
_MAX_DATE_PREFIX_SCAN_DAYS = 14


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
# TTL cache — key: "<control_id>:<window_hours>"  value: ComplianceMetrics
# 5-minute TTL prevents repeated full custody scans on every Lula poll.
# ---------------------------------------------------------------------------

_metrics_cache: TTLCache[str, ComplianceMetrics] = TTLCache(maxsize=32, ttl=300)


def invalidate_compliance_metrics_cache(control_id: str | None = None) -> None:
    """Invalidate cached compliance metrics globally or for a single control."""
    if control_id is None:
        _metrics_cache.clear()
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
        "CBF_ROLLBACK",
        "WORKLOAD_QUARANTINE_RECEIPT",
        "GOVERNANCE_VIOLATION",
    }
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


def _record_matches_control(record: Mapping[str, Any] | Any, control_id: str) -> bool:
    """Return True when `record` is explicitly attributed to `control_id`."""
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
            if _normalize_control_id(candidate) == target:
                return True
        elif isinstance(candidate, (list, tuple, set, frozenset)):
            for item in candidate:
                if _normalize_control_id(item) == target:
                    return True

    for tf_list in (
        payload.get("tier_failures"),
        receipt.get("tier_failures") if isinstance(receipt, Mapping) else None,
    ):
        if isinstance(tf_list, (list, tuple)):
            for tf in tf_list:
                if isinstance(tf, Mapping) and (
                    _normalize_control_id(tf.get("control_id")) == target
                ):
                    return True
    return False


_LULA_PASS_PREFIX_RE = re.compile(r"\blula_audit\s+pass\s*:", re.IGNORECASE)
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


def _lula_min_manifests_floor() -> int:
    """Return the minimum active Lula manifest floor (never below 1)."""
    raw = os.environ.get("LULA_AUDIT_MIN_MANIFESTS", "26").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 26


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
        if _LULA_FAIL_PREFIX_RE.search(text):
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


# ---------------------------------------------------------------------------
# Custody-Chain Readers: WORM Cold Store + Redis DB 1 Hot Stream
# ---------------------------------------------------------------------------


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine from synchronous code even if a loop is active."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _resolve_metrics_cold_store() -> EvidenceColdStore | None:
    """Resolve the WORM cold store used for archived custody batches, or None."""
    raw_backend = os.environ.get("EVIDENCE_COLD_STORE", "").strip().lower()
    archive_bucket = os.environ.get("EVIDENCE_ARCHIVE_BUCKET", "").strip()
    s3_endpoint = os.environ.get("EVIDENCE_COLD_STORE_S3_ENDPOINT", "").strip()

    if raw_backend in ("gcs", "s3"):
        return get_cold_store(backend=raw_backend, bucket=archive_bucket or None)
    if raw_backend not in ("", "null"):
        return get_cold_store(backend=raw_backend, bucket=archive_bucket or None)
    if archive_bucket:
        inferred = "s3" if s3_endpoint else "gcs"
        return get_cold_store(backend=inferred, bucket=archive_bucket)
    return None


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


async def _read_cold_store_records_async(
    cold_store: EvidenceColdStore,
    window_start: datetime,
    now: datetime,
) -> list[dict[str, Any]]:
    """Read `.ndjson` custody batches from WORM cold storage across `[window_start, now]`."""
    enforcing = is_enforcing()
    listed_keys: set[str] = set()
    for prefix in _date_prefixes_for_window(window_start, now):
        keys = await cold_store.list_keys(prefix)
        listed_keys.update(keys)

    ndjson_keys = sorted(k for k in listed_keys if k.endswith(".ndjson"))
    records: list[dict[str, Any]] = []

    for data_key in ndjson_keys:
        base = data_key[: -len(".ndjson")]
        signed_att_key = f"{base}.attestation.json"

        if enforcing and signed_att_key not in listed_keys:
            unsigned_att_key = f"{base}.attestation.unsigned.json"
            if unsigned_att_key in listed_keys:
                raise NonEvidentiaryAttestationError(
                    f"Unsigned custody batch {data_key!r} is non-evidentiary under enforcing posture."
                )
            # In-flight batch whose companion attestation has not been committed yet;
            # those entries remain readable from Redis DB 1 until cursor advance.
            continue

        ndjson_bytes = await cold_store.get(data_key)

        if signed_att_key in listed_keys:
            att_bytes = await cold_store.get(signed_att_key)
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
            actual_sha = hashlib.sha256(ndjson_bytes).hexdigest()
            if attestation.get("content_sha256") != actual_sha:
                raise EvidenceCustodyIntegrityError(
                    f"Custody batch {data_key!r} SHA-256 mismatch against {signed_att_key!r}."
                )

        for raw_line in ndjson_bytes.decode("utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                records.append(parsed)

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

    combined_raw: list[dict[str, Any]] = []

    if cold_store is not None:
        try:
            archived = _run_coro_sync(
                _read_cold_store_records_async(cold_store, window_start, now)
            )
            combined_raw.extend(archived)
        except Exception as exc:
            if enforcing:
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
            combined_raw.extend(hot_records)
        except Exception as exc:
            if enforcing:
                raise
            logger.warning(
                "[metrics] Failed to read Redis DB 1 custody stream for control %s: %s",
                control_id,
                exc,
            )

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

        if not _record_matches_control(rec_dict, control_id):
            continue

        rec_ts = _parse_evidence_timestamp(rec_dict)
        if rec_ts is None or rec_ts < window_start:
            continue
        matched.append((rec_ts, rec_dict))

    matched.sort(key=lambda item: item[0], reverse=True)
    return [rec for _, rec in matched[:limit]]


def _fetch_from_evidence_stream_sync(
    control_id: str,
    window_hours: int,
) -> ComplianceMetrics:
    """Aggregate per-control compliance metrics from the custody chain."""
    window_start = datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)
    records = _query_cage_evidence_records(control_id, window_hours=window_hours)

    total_traces = 0
    passed_traces = 0
    last_event_date = datetime.fromtimestamp(0, tz=timezone.utc)

    for record in records:
        if not _record_matches_control(record, control_id):
            continue

        record_date = _parse_evidence_timestamp(record)
        if record_date is not None and record_date < window_start:
            continue

        total_traces += 1
        is_passing = _is_passing_evidence_record(record)
        if is_passing:
            passed_traces += 1

        record_payload = _parse_evidence_payload(record)
        rec_event_type = str(
            _get_record_field(record, "event_type")
            or _get_record_field(record, "type")
            or record_payload.get("event_type")
            or record_payload.get("type")
            or ""
        ).strip()
        if not (rec_event_type.lower() == "lula_audit" and not is_passing):
            if record_date is not None and record_date > last_event_date:
                last_event_date = record_date

    blocked_traces = total_traces - passed_traces
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
    _metrics_cache[cache_key] = result
    return result


def get_last_passing_lula_audit_age_seconds(
    window_hours: int = 24,
) -> tuple[float | None, str | None]:
    """Return `(age_seconds, last_pass_iso_utc)` of the newest passing `lula_audit` record.

    Scans `A.5.3` custody records over `window_hours` and considers only
    `event_type == "lula_audit"` records where `_is_passing_evidence_record(rec)`
    is `True`. Failing or corpus-floor-breaching `lula_audit` runs never reset
    this age, preventing metric poisoning from silencing the dead-man's switch.
    Returns `(None, None)` when no passing `lula_audit` exists in the window.
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
