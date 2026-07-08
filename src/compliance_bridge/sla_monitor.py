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
sla_monitor.py — Evidence Age SLA Background Monitor  (Tier 2.5)

Implements NIST SP 800-53 CA-7 (Continuous Monitoring) by periodically
polling per-control compliance metrics and firing notifier alerts when
evidence age exceeds the per-control SLA defined in EVIDENCE_SLA_SECONDS.

Lifecycle:
  - Started as an asyncio background task in compliance_bridge/main.py lifespan.
  - Polls every EVIDENCE_SLA_POLL_INTERVAL_SECONDS (default: 300 = 5 min).
  - Each poll calls get_compliance_metrics() for every SLA-gated control.
  - On SLA breach, calls notifier.send_critical_alert() with a synthetic
    OscalFinding (result="FAIL", remarks="Evidence SLA breach").
  - Startup grace period is respected — no alerts during grace window.

Environment variables:
  EVIDENCE_SLA_POLL_INTERVAL_SECONDS — poll cadence (default: 300)
  EVIDENCE_SLA_DISABLED              — set to "1" to disable the monitor
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from .metrics import get_compliance_metrics
from .notifier import create_notifier
from .types import EVIDENCE_SLA_SECONDS, OscalFinding

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 300  # 5 minutes


def _is_disabled() -> bool:
    return os.environ.get("EVIDENCE_SLA_DISABLED", "").strip() == "1"


def _poll_interval() -> int:
    return int(
        os.environ.get("EVIDENCE_SLA_POLL_INTERVAL_SECONDS", _DEFAULT_POLL_INTERVAL)
    )


async def _check_sla_once() -> list[str]:
    """Check all SLA-gated controls. Returns list of breached control IDs."""
    breached: list[str] = []

    for control_id, sla_seconds in EVIDENCE_SLA_SECONDS.items():
        try:
            metrics = await get_compliance_metrics(control_id, window_hours=24)

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

        except Exception as exc:
            logger.warning(
                "[sla_monitor] Failed to fetch metrics for %s (non-fatal): %s",
                control_id,
                exc,
            )

    return breached


async def _fire_sla_alerts(breached: list[str]) -> None:
    """Build synthetic OscalFindings for each breached control and notify."""
    if not breached:
        return

    notifier = create_notifier()
    findings: list[OscalFinding] = []
    for control_id in breached:
        metrics = await get_compliance_metrics(control_id, window_hours=24)
        sla_h = EVIDENCE_SLA_SECONDS[control_id] / 3600
        age_h = metrics.evidence_age_seconds / 3600
        findings.append(
            OscalFinding(
                control_id=control_id,
                result="FAIL",
                finding_id=f"sla-breach-{control_id}-{int(datetime.now(tz=timezone.utc).timestamp())}",
                remarks=(
                    f"Evidence SLA breach: last event {age_h:.2f}h ago "
                    f"(SLA={sla_h:.2f}h). "
                    f"Last event UTC: {metrics.last_event_utc}. "
                    "No new traces in the monitoring window."
                ),
                safety_rate=metrics.safety_rate,
            )
        )

    audit_id = f"sla-monitor-{int(datetime.now(tz=timezone.utc).timestamp())}"
    try:
        await notifier.send_critical_alert(findings, audit_id)
        logger.warning(
            "[sla_monitor] 🚨 SLA breach alert sent for: %s",
            ", ".join(breached),
        )
    except Exception as exc:
        logger.error("[sla_monitor] Failed to send SLA breach alert: %s", exc)


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
    logger.info(
        "[sla_monitor] Starting evidence SLA monitor. Poll interval: %ds. Controls: %s",
        poll_interval,
        ", ".join(EVIDENCE_SLA_SECONDS.keys()),
    )

    try:
        while True:
            await asyncio.sleep(poll_interval)
            try:
                breached = await _check_sla_once()
                if breached:
                    await _fire_sla_alerts(breached)
                else:
                    logger.debug("[sla_monitor] All SLA checks passed.")
            except Exception as exc:
                # Never crash the monitor — log and continue to next cycle
                logger.error(
                    "[sla_monitor] Unexpected error in poll cycle (continuing): %s", exc
                )
    except asyncio.CancelledError:
        logger.info("[sla_monitor] SLA monitor task cancelled — shutting down.")
