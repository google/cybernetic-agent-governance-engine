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
metrics.py — Compliance metrics aggregation via Langfuse Python SDK.

Ported from src/langfuse-bridge/src/metrics.ts (LRUCache → cachetools.TTLCache).

Queries the *application* Langfuse project (LANGFUSE_PUBLIC_KEY /
LANGFUSE_SECRET_KEY) for traces tagged control:<controlId> and aggregates
iso_42001_outcome metadata into a ComplianceMetrics response.

The compliance project (LANGFUSE_COMPLIANCE_PUBLIC_KEY /
LANGFUSE_COMPLIANCE_SECRET_KEY) is used only by audit_workflow.py.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from cachetools import TTLCache

# Lazy import: langfuse is only required at runtime, not at import time.
Langfuse = None  # populated by _get_langfuse_class() on first use


def _get_langfuse_class():  # type: ignore[no-untyped-def]
    global Langfuse
    if Langfuse is None:
        from langfuse import Langfuse as _LF

        Langfuse = _LF
    return Langfuse


from .types import ComplianceMetrics

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HIGH-05: Langfuse credential startup validation
# Warns at module import time if application Langfuse credentials are absent
# so that missing config is surfaced immediately rather than silently
# producing empty compliance metrics.
# ---------------------------------------------------------------------------


def _validate_langfuse_credentials() -> None:
    """Emit a WARNING if any Langfuse credential env vars are missing or empty.

    Does NOT raise — metrics queries degrade gracefully when Langfuse is
    unreachable, but operators must know the credentials are absent.
    Fires once at module import time so the gap is visible in startup logs.
    """
    missing: list[str] = []
    for var in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
        if not os.environ.get(var):
            missing.append(var)

    if missing:
        logger.warning(
            "Langfuse compliance credentials not configured — audit metrics will not be "
            "recorded. Set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST. "
            "Missing: %s",
            ", ".join(missing),
        )


_validate_langfuse_credentials()


# ---------------------------------------------------------------------------
# Langfuse client — application project (NOT the compliance audit project)
# ---------------------------------------------------------------------------

# Short timeout for Langfuse API calls — prevents the metrics endpoint from
# blocking indefinitely when Langfuse is slow or unreachable.
# LANGFUSE_API_TIMEOUT_S env var allows tuning; default 5s.
# Reduced from 8s: with 13 controls x asyncio.to_thread, thread pool contention
# at 8s caused gather timeouts. 5s x 13 parallel = ~5s wall-clock (no starvation).
_LANGFUSE_API_TIMEOUT_S: float = float(os.environ.get("LANGFUSE_API_TIMEOUT_S", "5"))

# Semaphore to cap concurrent Langfuse API calls — prevents thread pool exhaustion
# when metrics/summary, oscal-export, and aarm-report are called concurrently.
# 6 concurrent calls x 5s = 5s wall-clock for 13 controls (two batches).
_LANGFUSE_CONCURRENCY = asyncio.Semaphore(6)


def _make_app_langfuse():  # type: ignore[no-untyped-def]
    import httpx
    from langfuse.api import LangfuseAPI

    return LangfuseAPI(
        username=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
        password=os.environ.get("LANGFUSE_SECRET_KEY", ""),
        base_url=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        httpx_client=httpx.Client(timeout=_LANGFUSE_API_TIMEOUT_S),
    )


# ---------------------------------------------------------------------------
# Deployment cold-start grace period
# DEPLOYMENT_START_UTC may be patched by CI at deploy time.
# Falls back to module-load time so local dev always starts with grace active.
# ---------------------------------------------------------------------------

_DEPLOYMENT_START_UTC: datetime = (
    datetime(
        *[  # type: ignore[arg-type, misc]  # datetime() tzinfo passed via both splat args and kwarg; false positive from env string parse
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
        # Handle both "Z" suffix and "+00:00"
        cleaned = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
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
# 5-minute TTL prevents repeated full Langfuse DB scans on every Lula query.
# ---------------------------------------------------------------------------

_metrics_cache: TTLCache[str, ComplianceMetrics] = TTLCache(maxsize=32, ttl=300)


# ---------------------------------------------------------------------------
# Core aggregation — queries Langfuse SDK for scored traces per control window
# ---------------------------------------------------------------------------


def _fetch_from_langfuse_sync(
    control_id: str,
    window_hours: int,
) -> ComplianceMetrics:
    """Synchronous Langfuse fetch — wrapped in asyncio.to_thread() by caller."""
    langfuse = _make_app_langfuse()
    window_start = datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)

    # M-10: Langfuse API enforces limit <= 100. Use 100 (the maximum) to capture
    # as many traces as possible within the look-back window.
    traces_response = langfuse.trace.list(
        tags=[f"control:{control_id}"],
        from_timestamp=window_start,
        limit=100,
    )

    total_traces = 0
    passed_traces = 0
    last_event_date = datetime.fromtimestamp(0, tz=timezone.utc)

    for trace in traces_response.data:
        total_traces += 1
        trace_date = trace.timestamp
        if isinstance(trace_date, str):
            trace_date = datetime.fromisoformat(trace_date.replace("Z", "+00:00"))
        if trace_date > last_event_date:
            last_event_date = trace_date

        # Check metadata for outcome (set by Python trace_with_iso_control)
        metadata = trace.metadata or {}
        if isinstance(metadata, dict):
            outcome = metadata.get("iso_42001_outcome")
            if outcome == "PASSED":
                passed_traces += 1

    blocked_traces = total_traces - passed_traces
    # M-10: Return None when no traces exist — 1.0 was a false-positive perfect score
    safety_rate = (passed_traces / total_traces) if total_traces > 0 else None
    now = datetime.now(tz=timezone.utc)
    last_event_utc = (
        last_event_date.isoformat() if total_traces > 0 else now.isoformat()
    )
    evidence_age_seconds = (
        (now - last_event_date).total_seconds() if total_traces > 0 else 0.0
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


# ---------------------------------------------------------------------------
# Public API — cache-first aggregation
# ---------------------------------------------------------------------------


async def get_compliance_metrics(
    control_id: str,
    window_hours: int = 24,
) -> ComplianceMetrics:
    """
    Returns compliance metrics for the given control ID.

    Uses a 5-minute TTL cache to avoid hammering Langfuse on every Lula poll.
    On cache hit, evidence_age_seconds is updated to reflect real-time staleness.

    Args:
        control_id:   ISO 42001 control ID, e.g. "A.5.2"
        window_hours: Look-back window for trace aggregation (default: 24h)

    Returns:
        ComplianceMetrics — the exact JSON Lula's OPA Rego receives as `input`.
    """
    cache_key = f"{control_id}:{window_hours}"
    cached = _metrics_cache.get(cache_key)

    if cached is not None:
        # Return cached result but update evidence_age_seconds to real-time
        last_event = datetime.fromisoformat(
            cached.last_event_utc.replace("Z", "+00:00")
        )
        now_age = max(
            0.0,
            (datetime.now(tz=timezone.utc) - last_event).total_seconds(),
        )
        return cached.model_copy(update={"evidence_age_seconds": now_age})

    async with _LANGFUSE_CONCURRENCY:
        result = await asyncio.to_thread(
            _fetch_from_langfuse_sync, control_id, window_hours
        )
    _metrics_cache[cache_key] = result
    return result
