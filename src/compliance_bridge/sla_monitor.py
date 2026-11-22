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
sla_monitor.py — Evidence Age SLA & Lula Dead-Man's Switch Monitor  (Capability 2.5)

Implements NIST SP 800-53 CA-7 (Continuous Monitoring) by periodically
polling per-control compliance metrics and firing notifier alerts when
evidence age exceeds the per-control SLA for the active deployment region
(see get_sla_seconds() in types.py), alongside a `2 x schedule` dead-man's
switch over the most recent auditor-healthy `lula_audit` custody record.

Lifecycle:
  - Started as an asyncio background task in compliance_bridge/main.py lifespan.
  - Polls every EVIDENCE_SLA_POLL_INTERVAL_SECONDS (default: 300 = 5 min).
  - Each poll calls get_compliance_metrics() for every SLA-gated control
    applicable to CAGE_DEPLOYMENT_REGION (universal ISO 42001 controls plus
    any jurisdictional controls for the active region — FINDING-05).
  - On SLA breach, calls notifier.send_critical_alert() with a synthetic
    OscalFinding (result="FAIL", remarks="Evidence SLA breach").
  - Enforces a `2 x schedule` dead-man's switch (`LULA_AUDIT_MAX_AGE_SECONDS`,
    default 43200s = 2 x 6h) over `get_last_healthy_lula_audit_age_seconds()`.
  - Startup grace period is respected — no alerts during grace window.

Environment variables:
  CAGE_DEPLOYMENT_REGION             — one of "US_FED", "EU_ECB", "APAC_MAS".
                                        Unset/unrecognised values monitor
                                        universal ISO 42001 SLA targets only
                                        (mirrors get_control_meta() region
                                        resolution in main.py).
  EVIDENCE_SLA_POLL_INTERVAL_SECONDS — poll cadence (default: 300)
  EVIDENCE_SLA_DISABLED              — set to "1" to disable the monitor
  LULA_AUDIT_MAX_AGE_SECONDS         — max age of last healthy lula_audit (default: 43200)
  LULA_AUDIT_DEADMAN_DISABLED        — set to "1" to opt out of dead-man's switch
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.env_posture import resolve_deployment_region

from .evidence_custodian import (
    EvidenceCustodyIntegrityError,
    NonEvidentiaryAttestationError,
)
from .metrics import (
    get_compliance_metrics,
    get_last_healthy_lula_audit_age_seconds,
)
from .notifier import (
    create_notifier,
    is_external_notifier_configured,
    send_notifier_heartbeat,
)
from .types import OscalFinding, get_sla_seconds

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 300  # 5 minutes
_DEFAULT_HEARTBEAT_INTERVAL = 21600  # 6 hours (POAM-2026-230 synthetic notifier probe)
_DEFAULT_LULA_AUDIT_MAX_AGE_SECONDS = (
    43200  # 2 x 6h default CronJob/lula-audit schedule ("0 */6 * * *")
)
LULA_AUDIT_MAX_AGE_SECONDS: int = int(
    os.environ.get(
        "LULA_AUDIT_MAX_AGE_SECONDS", str(_DEFAULT_LULA_AUDIT_MAX_AGE_SECONDS)
    )
)

# Tracks control IDs whose critical tamper/fetch alerts were already dispatched
# inline during the most recent `_check_sla_once()` call so `run_sla_monitor()`
# does not double-send in the same poll cycle.
_last_inline_alerted_controls: set[str] = set()

LULA_AUDIT_DEADMAN_BREACHES_TOTAL: Any = None
try:
    from prometheus_client import REGISTRY as _PROM_REGISTRY
    from prometheus_client import Counter as _PromCounter

    def _deadman_counter(name: str, doc: str) -> Any:
        try:
            return _PromCounter(name, doc)
        except ValueError:
            return _PROM_REGISTRY._names_to_collectors.get(name)

    LULA_AUDIT_DEADMAN_BREACHES_TOTAL = _deadman_counter(
        "cage_lula_audit_deadman_breaches_total",
        "Total breaches of the 2x-schedule in-cluster Lula audit dead-man's switch",
    )
except ImportError:  # pragma: no cover - optional runtime dependency
    pass


def _is_disabled() -> bool:
    return os.environ.get("EVIDENCE_SLA_DISABLED", "").strip() == "1"


def _is_lula_deadman_disabled() -> bool:
    return os.environ.get("LULA_AUDIT_DEADMAN_DISABLED", "").strip() == "1"


def _lula_audit_max_age_seconds() -> int:
    raw = os.environ.get("LULA_AUDIT_MAX_AGE_SECONDS")
    if raw is not None and raw.strip():
        return int(raw.strip())
    return int(LULA_AUDIT_MAX_AGE_SECONDS)


def _poll_interval() -> int:
    return int(
        os.environ.get("EVIDENCE_SLA_POLL_INTERVAL_SECONDS", _DEFAULT_POLL_INTERVAL)
    )


def _heartbeat_interval() -> int:
    raw = os.environ.get(
        "ALERT_HEARTBEAT_INTERVAL_SECONDS", str(_DEFAULT_HEARTBEAT_INTERVAL)
    )
    return max(0, int(raw.strip() or "0"))


def _active_sla_seconds() -> dict[str, int]:
    """Return the SLA thresholds applicable to the active deployment region.

    Reads CAGE_DEPLOYMENT_REGION fresh on every call (not cached at import
    time) so that runtime region changes and per-test env var patches are
    respected — mirrors the active_region resolution pattern used by
    GET /v1/controls and GET /v1/controls/summary in main.py.  Defaults to
    "" (empty string) when unset, which resolves to the universal ISO 42001
    SLA targets only (get_sla_seconds ignores unrecognised region values).

    FINDING-05: this replaces the previous direct iteration over the
    deprecated flat EVIDENCE_SLA_SECONDS alias, which silently excluded
    jurisdictional SLA targets (SC-7/SC-8 for US_FED, Article 12 for EU_ECB,
    MAS-FEAT-1 for APAC_MAS) in every region.
    """
    return get_sla_seconds(resolve_deployment_region())


async def _check_lula_audit_deadman(
    *,
    startup_grace_active: bool | None = None,
) -> OscalFinding | None:
    """Check the `2 x schedule` dead-man's switch for auditor-healthy `lula_audit` runs."""
    if _is_lula_deadman_disabled():
        return None

    if startup_grace_active is None:
        try:
            a53_metrics = await get_compliance_metrics("A.5.3", window_hours=24)
            startup_grace_active = bool(a53_metrics.startup_grace_active)
        except Exception as exc:
            logger.warning(
                "[sla_monitor] Failed to read A.5.3 startup grace status: %s", exc
            )
            startup_grace_active = False

    if startup_grace_active:
        logger.debug(
            "[sla_monitor] Startup grace active — skipping lula-audit dead-man check."
        )
        return None

    max_age_seconds = _lula_audit_max_age_seconds()
    window_hours = max(24, int((max_age_seconds // 3600) + 2))
    read_error: str | None = None
    try:
        res = await asyncio.to_thread(
            get_last_healthy_lula_audit_age_seconds, window_hours
        )
        if inspect.isawaitable(res):
            res = await res
        age_seconds, last_healthy_utc = res
    except Exception as exc:
        logger.error(
            "[sla_monitor] Failed to query last healthy lula_audit custody age: %s",
            exc,
        )
        age_seconds, last_healthy_utc = None, None
        read_error = str(exc)

    if age_seconds is not None and age_seconds <= max_age_seconds:
        return None

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    if age_seconds is None:
        detail = (
            f"custody query error ({read_error})"
            if read_error
            else f"no auditor-healthy lula_audit record found in last {window_hours}h"
        )
        remarks = (
            f"Lula dead-man's switch breach (2x schedule = {max_age_seconds}s): "
            f"{detail}. CronJob/lula-audit may be suspended, failing closed, or "
            "emitting only failing runs."
        )
    else:
        remarks = (
            f"Lula dead-man's switch breach: last healthy lula_audit was "
            f"{age_seconds:.0f}s ago (max_age={max_age_seconds}s, "
            f"last_healthy_utc={last_healthy_utc})."
        )

    finding = OscalFinding(
        control_id="A.5.3",
        result="FAIL",
        finding_id=f"lula-audit-deadman-{now_ts}",
        evidence_age_s=age_seconds,
        remarks=remarks,
        safety_rate=0.0,
    )

    if LULA_AUDIT_DEADMAN_BREACHES_TOTAL is not None:
        LULA_AUDIT_DEADMAN_BREACHES_TOTAL.inc()

    logger.critical("[sla_monitor] 🚨 %s", remarks)
    audit_id = f"lula-audit-deadman-{now_ts}"
    try:
        notifier = create_notifier()
        delivered = (await notifier.send_critical_alert([finding], audit_id)) is True
        if not delivered:
            logger.error(
                "[sla_monitor] Dead-man alert NOT delivered externally (%s)", audit_id
            )
    except Exception as exc:
        logger.error(
            "[sla_monitor] Failed to send lula-audit-deadman critical alert: %s", exc
        )

    return finding


async def _dispatch_sla_error_alerts(
    *,
    findings: list[OscalFinding],
    audit_id: str,
    label: str,
) -> bool:
    """Dispatch a consolidated critical alert batch, returning observed delivery."""
    if not findings:
        return False
    try:
        notifier = create_notifier()
        delivered = (await notifier.send_critical_alert(findings, audit_id)) is True
        if not delivered:
            logger.error(
                "[sla_monitor] %s critical alert NOT delivered externally (%s)",
                label,
                audit_id,
            )
        return delivered
    except Exception as exc:
        logger.error(
            "[sla_monitor] Failed to send %s critical alert (%s): %s",
            label,
            audit_id,
            exc,
        )
        return False


async def _check_sla_once() -> list[str]:
    """Check all SLA-gated controls and the `2 x schedule` Lula dead-man's switch."""
    breached: list[str] = []
    custody_tamper_errors: dict[str, str] = {}
    fetch_errors: dict[str, str] = {}
    sla_map = _active_sla_seconds()
    a53_grace_active: bool | None = None
    _last_inline_alerted_controls.clear()

    for control_id, sla_seconds in sla_map.items():
        try:
            metrics = await get_compliance_metrics(control_id, window_hours=24)
            if control_id == "A.5.3":
                a53_grace_active = bool(metrics.startup_grace_active)

            # Respect startup grace — no alerts while the system is warming up
            if metrics.startup_grace_active:
                logger.debug(
                    "[sla_monitor] %s — startup grace active (%.1f h remaining), skipping SLA check.",
                    control_id,
                    metrics.startup_grace_remaining_hours,
                )
                continue

            if metrics.evidence_age_seconds > sla_seconds:
                breached.append(control_id)
                age_h = metrics.evidence_age_seconds / 3600
                sla_h = sla_seconds / 3600
                logger.warning(
                    "[sla_monitor] ⚠️  SLA breach: control=%s age=%.2fh SLA=%.2fh",
                    control_id,
                    age_h,
                    sla_h,
                )

        except (EvidenceCustodyIntegrityError, NonEvidentiaryAttestationError) as exc:
            logger.critical(
                "[sla_monitor] 🚨 CRITICAL custody integrity tamper/violation on %s: %s",
                control_id,
                exc,
            )
            custody_tamper_errors[control_id] = str(exc)
            breached.append(control_id)
        except Exception as exc:
            err_kind = (
                "timeout"
                if isinstance(exc, (asyncio.TimeoutError, TimeoutError))
                else type(exc).__name__
            )
            logger.error(
                "[sla_monitor] Metrics fetch failed for %s (%s) — recording SLA check failure: %s",
                control_id,
                err_kind,
                exc,
            )
            fetch_errors[control_id] = f"{err_kind}: {exc}"
            breached.append(control_id)

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    if custody_tamper_errors:
        tamper_findings = [
            OscalFinding(
                control_id=cid,
                result="FAIL",
                assessment_status="custody_integrity_error",
                finding_id=f"sla-custody-tamper-{cid}-{now_ts}",
                remarks=(
                    f"CRITICAL WORM custody integrity violation detected during SLA "
                    f"monitoring for {cid}: {detail}"
                ),
                safety_rate=0.0,
            )
            for cid, detail in custody_tamper_errors.items()
        ]
        _last_inline_alerted_controls.update(custody_tamper_errors.keys())
        await _dispatch_sla_error_alerts(
            findings=tamper_findings,
            audit_id=f"sla-custody-tamper-{now_ts}",
            label="custody-tamper",
        )

    if fetch_errors:
        error_findings = [
            OscalFinding(
                control_id=cid,
                result="ERROR",
                assessment_status="sla_fetch_error",
                finding_id=f"sla-fetch-error-{cid}-{now_ts}",
                remarks=(
                    f"Evidence SLA check failed to fetch custody metrics for {cid} "
                    f"({detail}). Control cannot be verified."
                ),
                safety_rate=0.0,
            )
            for cid, detail in fetch_errors.items()
        ]
        _last_inline_alerted_controls.update(fetch_errors.keys())
        await _dispatch_sla_error_alerts(
            findings=error_findings,
            audit_id=f"sla-fetch-error-{now_ts}",
            label="sla-fetch-error",
        )

    if "A.5.3" in sla_map:
        await _check_lula_audit_deadman(startup_grace_active=a53_grace_active)

    return breached


async def _fire_sla_alerts(breached: list[str]) -> None:
    """Build synthetic OscalFindings for each breached control and notify."""
    if not breached:
        return

    notifier = create_notifier()
    sla_seconds_map = _active_sla_seconds()
    findings: list[OscalFinding] = []
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    for control_id in breached:
        try:
            metrics = await get_compliance_metrics(control_id, window_hours=24)
            sla_h = sla_seconds_map.get(control_id, 0) / 3600
            age_h = metrics.evidence_age_seconds / 3600
            findings.append(
                OscalFinding(
                    control_id=control_id,
                    result="FAIL",
                    finding_id=f"sla-breach-{control_id}-{now_ts}",
                    remarks=(
                        f"Evidence SLA breach: last event {age_h:.2f}h ago "
                        f"(SLA={sla_h:.2f}h). "
                        f"Last event UTC: {metrics.last_event_utc}. "
                        "No new traces in the monitoring window."
                    ),
                    safety_rate=metrics.safety_rate,
                )
            )
        except Exception as exc:
            findings.append(
                OscalFinding(
                    control_id=control_id,
                    result="FAIL"
                    if isinstance(
                        exc,
                        (EvidenceCustodyIntegrityError, NonEvidentiaryAttestationError),
                    )
                    else "ERROR",
                    finding_id=f"sla-breach-{control_id}-{now_ts}",
                    remarks=(
                        f"Evidence SLA check failed for {control_id} "
                        f"({type(exc).__name__}: {exc})."
                    ),
                    safety_rate=0.0,
                )
            )

    audit_id = f"sla-monitor-{now_ts}"
    try:
        delivered = (await notifier.send_critical_alert(findings, audit_id)) is True
        if delivered:
            logger.warning(
                "[sla_monitor] 🚨 SLA breach alert delivered for: %s",
                ", ".join(breached),
            )
        else:
            logger.error(
                "[sla_monitor] SLA breach alert NOT delivered externally for: %s",
                ", ".join(breached),
            )
    except Exception as exc:
        logger.error("[sla_monitor] Failed to send SLA breach alert: %s", exc)


async def _maybe_emit_notifier_heartbeat(
    last_hb_monotonic: float | None,
) -> float | None:
    """Emit a synthetic non-paging notifier heartbeat when the interval elapses."""
    hb_interval = _heartbeat_interval()
    if hb_interval <= 0 or not is_external_notifier_configured():
        return last_hb_monotonic
    now_mono = asyncio.get_running_loop().time()
    if last_hb_monotonic is not None and (now_mono - last_hb_monotonic) < hb_interval:
        return last_hb_monotonic
    try:
        delivered, hb_id = await send_notifier_heartbeat()
        if delivered:
            logger.info(
                "[sla_monitor] Synthetic notifier heartbeat delivered (%s)", hb_id
            )
            return now_mono
        logger.error(
            "[sla_monitor] Synthetic notifier heartbeat NOT delivered (%s)", hb_id
        )
    except Exception as exc:
        logger.error("[sla_monitor] Synthetic notifier heartbeat failed: %s", exc)
    return last_hb_monotonic


async def run_sla_monitor() -> None:
    """
    Continuous SLA monitoring loop — runs until the task is cancelled.

    Designed to be started via asyncio.create_task() inside the FastAPI
    lifespan context manager.  Cancellation is handled gracefully.

    Example lifespan usage::

        async with asyncio.TaskGroup() as tg:
            tg.create_task(run_sla_monitor())
            yield
    """
    if _is_disabled():
        logger.info("[sla_monitor] EVIDENCE_SLA_DISABLED=1 — monitor not started.")
        return

    poll_interval = _poll_interval()
    active_region = resolve_deployment_region()
    logger.info(
        "[sla_monitor] Starting evidence SLA monitor. Poll interval: %ds. Region: %s. Controls: %s",
        poll_interval,
        active_region,
        ", ".join(_active_sla_seconds().keys()),
    )

    last_hb_monotonic: float | None = None
    try:
        last_hb_monotonic = await _maybe_emit_notifier_heartbeat(last_hb_monotonic)
        while True:
            await asyncio.sleep(poll_interval)
            try:
                last_hb_monotonic = await _maybe_emit_notifier_heartbeat(
                    last_hb_monotonic
                )
                sla_keys = set(_active_sla_seconds().keys())
                breached = await _check_sla_once()
                if "A.5.3" not in sla_keys:
                    await _check_lula_audit_deadman()
                pending_age_alerts = [
                    cid for cid in breached if cid not in _last_inline_alerted_controls
                ]
                if pending_age_alerts:
                    await _fire_sla_alerts(pending_age_alerts)
                elif not breached:
                    logger.debug("[sla_monitor] All SLA checks passed.")
            except Exception as exc:
                # Never crash the monitor — log and continue to next cycle
                logger.error(
                    "[sla_monitor] Unexpected error in poll cycle (continuing): %s", exc
                )
    except asyncio.CancelledError:
        logger.info("[sla_monitor] SLA monitor task cancelled — shutting down.")
