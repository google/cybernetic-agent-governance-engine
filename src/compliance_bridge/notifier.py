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
notifier.py — Alert channel abstraction for ISO 42001 compliance events.

Ported from src/langfuse-bridge/src/notifier.ts.

Channel selection is driven by the ALERT_CHANNEL environment variable:

  ALERT_CHANNEL=console    (default) — Logs JSON payload to stdout via logging.warning().
                                        Zero external deps. Visible in `kubectl logs`.

  ALERT_CHANNEL=slack                — Posts Slack Block Kit payloads to
                                        COMPLIANCE_ALERT_WEBHOOK_URL using httpx.

  ALERT_CHANNEL=pagerduty  (Tier 2.4) — Posts PagerDuty Events API v2 incidents.
                                        Requires PAGERDUTY_ROUTING_KEY.
                                        Closes POAM-008 / NIST IR-1 incident response.
                                        Severity mapping:
                                          FAIL critical control  → 'critical'  (pages on-call)
                                          SLA breach             → 'error'
                                          Remediation advisory   → 'info'

  ALERT_CHANNEL=webhook    (Tier 2.4) — Posts a generic JSON payload to any HTTP
                                        endpoint (OpsGenie, Jira Service Mgmt,
                                        ServiceNow). Requires COMPLIANCE_ALERT_WEBHOOK_URL.

  ALERT_CHANNEL=mock                 — Captures calls in-memory, no I/O.
                                        Use in unit tests.

The SLACK_WEBHOOK_URL env var is also accepted as an alias for
COMPLIANCE_ALERT_WEBHOOK_URL (backward compat with the task spec).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Protocol

import httpx

from .types import OscalFinding

logger = logging.getLogger(__name__)

# PagerDuty Events API v2 endpoint — hardcoded per PD docs, not configurable
_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


# ---------------------------------------------------------------------------
# Shared Slack Block Kit payload builders
# ---------------------------------------------------------------------------


def _build_critical_alert_body(
    critical_fails: list[OscalFinding],
    audit_id: str,
) -> dict:
    return {
        "text": "🚨 ISO 42001 CRITICAL COMPLIANCE FAILURE — Cybernetic Governance Engine",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 ISO 42001 Critical Control FAIL",
                },
            },
            *[
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Control:* `{f.control_id}`"},
                        {"type": "mrkdwn", "text": f"*Result:* {f.result}"},
                        {
                            "type": "mrkdwn",
                            "text": f"*Finding ID:* {_escape_slack_mrkdwn(f.finding_id)}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Remarks:* {_escape_slack_mrkdwn(f.remarks or 'none')}",
                        },
                    ],
                }
                for f in critical_fails
            ],
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Audit ID: {_escape_slack_mrkdwn(audit_id)} | "
                            f"Timestamp: {datetime.now(tz=timezone.utc).isoformat()} | "
                            "System: governance-gateway-01"
                        ),
                    }
                ],
            },
        ],
    }


def _escape_slack_mrkdwn(text: str) -> str:
    """M-22: Escape Slack mrkdwn special characters in LLM-generated text.

    Prevents injection of Slack formatting directives (bold, italic, links,
    channel mentions, user mentions) from untrusted LLM output.
    See: https://api.slack.com/reference/surfaces/formatting#escaping
    """
    # Escape the three HTML entities Slack requires
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    # Neutralise mrkdwn formatting characters that could be injected
    for ch in ("*", "_", "`", "~"):
        text = text.replace(ch, f"\\{ch}")
    return text


def _build_remediation_followup_body(
    control_id: str,
    audit_id: str,
    model_name: str,
    remediation_text: str,
    trace_ids: list[str],
) -> dict:
    trace_ref = ", ".join(trace_ids) if trace_ids else "none available"
    # M-22: Escape LLM-generated text before embedding in Slack mrkdwn
    safe_remediation_text = _escape_slack_mrkdwn(remediation_text)
    return {
        "text": f"🔍 Remediation Advisory — {control_id} | Audit {audit_id}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 ISO 42001 Remediation Advisory",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Control:* `{control_id}`"},
                    {"type": "mrkdwn", "text": f"*Audit ID:* `{audit_id}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": safe_remediation_text},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Evidence traces:* {trace_ref}"},
                    {"type": "mrkdwn", "text": f"*Model:* `{model_name}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Generated:* {datetime.now(tz=timezone.utc).isoformat()}",
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            "⚠️ *LLM-generated advisory* — human verification required before applying "
                            "(ISO 42001 A.7.2 Competence). This advisory is logged to the Langfuse compliance project."
                        ),
                    }
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# PagerDuty Events API v2 payload builder
# ---------------------------------------------------------------------------


def _build_pagerduty_trigger(
    summary: str,
    severity: str,
    source: str,
    routing_key: str,
    dedup_key: str,
    details: dict,
) -> dict:
    """Build a PagerDuty Events API v2 trigger payload."""
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": summary,
            "severity": severity,  # critical | error | warning | info
            "source": source,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "custom_details": details,
        },
    }


# ---------------------------------------------------------------------------
# AlertNotifier protocol (interface)
# ---------------------------------------------------------------------------


class AlertNotifier(Protocol):
    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None: ...

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None: ...


# ---------------------------------------------------------------------------
# SlackNotifier — production channel
# ---------------------------------------------------------------------------


class SlackNotifier:
    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None:
        body = _build_critical_alert_body(critical_fails, audit_id)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self._webhook_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
            if resp.is_success:
                logger.info(
                    "[SlackNotifier] 🚨 Alert sent for: %s",
                    ", ".join(f.control_id for f in critical_fails),
                )
            else:
                logger.error(
                    "[SlackNotifier] Alert webhook returned %d", resp.status_code
                )
        except Exception as exc:
            logger.error("[SlackNotifier] Failed to send alert: %s", exc)

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None:
        body = _build_remediation_followup_body(
            control_id, audit_id, model_name, remediation_text, trace_ids
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self._webhook_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
            if resp.is_success:
                logger.info(
                    "[SlackNotifier] 📨 Remediation advisory posted to Slack for %s",
                    control_id,
                )
            else:
                logger.error(
                    "[SlackNotifier] Slack follow-up returned %d", resp.status_code
                )
        except Exception as exc:
            logger.error("[SlackNotifier] Failed to post Slack follow-up: %s", exc)


# ---------------------------------------------------------------------------
# PagerDutyNotifier — incident management channel  (Tier 2.4 / POAM-008)
#
# Uses PagerDuty Events API v2 (https://developer.pagerduty.com/docs/events-api-v2).
# Requires PAGERDUTY_ROUTING_KEY (integration key from a PD service).
#
# Severity mapping:
#   Critical control FAIL → 'critical'   (pages on-call immediately)
#   SLA breach            → 'error'      (high priority, may be suppressed by noise rules)
#   Remediation advisory  → 'info'       (informational, no page)
#
# Dedup key: cage-<audit_id>-<control_id>
# Multiple alerts for the same audit+control are automatically de-duplicated.
# ---------------------------------------------------------------------------


class PagerDutyNotifier:
    def __init__(self, routing_key: str) -> None:
        self._routing_key = routing_key

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None:
        """Trigger one PagerDuty incident per critical failing control."""
        for finding in critical_fails:
            dedup_key = f"cage-{audit_id}-{finding.control_id}"
            payload = _build_pagerduty_trigger(
                summary=(
                    f"[CAGE] ISO 42001 Critical Failure: {finding.control_id} — "
                    f"Audit {audit_id}"
                ),
                severity="critical",
                source="compliance-bridge",
                routing_key=self._routing_key,
                dedup_key=dedup_key,
                details={
                    "control_id": finding.control_id,
                    "result": finding.result,
                    "finding_id": finding.finding_id,
                    "remarks": finding.remarks or "",
                    "safety_rate": finding.safety_rate,
                    "audit_id": audit_id,
                    "standard": "ISO/IEC 42001:2023",
                },
            )
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        _PAGERDUTY_EVENTS_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                if resp.is_success:
                    logger.info(
                        "[PagerDutyNotifier] 🚨 Incident triggered: %s (dedup=%s)",
                        finding.control_id,
                        dedup_key,
                    )
                else:
                    logger.error(
                        "[PagerDutyNotifier] Events API returned %d for %s: %s",
                        resp.status_code,
                        finding.control_id,
                        resp.text,
                    )
            except Exception as exc:
                logger.error(
                    "[PagerDutyNotifier] Failed to trigger incident for %s: %s",
                    finding.control_id,
                    exc,
                )

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None:
        """Post an informational PD event for the remediation advisory."""
        dedup_key = f"cage-remediation-{audit_id}-{control_id}"
        payload = _build_pagerduty_trigger(
            summary=f"[CAGE] Remediation Advisory: {control_id} — Audit {audit_id}",
            severity="info",
            source="compliance-bridge",
            routing_key=self._routing_key,
            dedup_key=dedup_key,
            details={
                "control_id": control_id,
                "audit_id": audit_id,
                "model_name": model_name,
                "remediation_text": remediation_text[:512],  # PD detail limit
                "trace_ids": trace_ids,
                "note": "LLM-generated — human verification required (ISO 42001 A.7.2)",
            },
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    _PAGERDUTY_EVENTS_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
            if resp.is_success:
                logger.info(
                    "[PagerDutyNotifier] 📨 Remediation advisory event posted for %s",
                    control_id,
                )
            else:
                logger.error(
                    "[PagerDutyNotifier] Events API returned %d for remediation %s: %s",
                    resp.status_code,
                    control_id,
                    resp.text,
                )
        except Exception as exc:
            logger.error(
                "[PagerDutyNotifier] Failed to post remediation advisory for %s: %s",
                control_id,
                exc,
            )


# ---------------------------------------------------------------------------
# WebhookNotifier — generic JSON POST channel  (Tier 2.4)
#
# Sends a structured JSON payload to any HTTP endpoint that accepts POST.
# Compatible with OpsGenie, Jira Service Management, ServiceNow, and any
# custom ITSM webhook receiver.
#
# Payload shape:
#   critical_failure: { source, alert_type, audit_id, timestamp, findings: [...] }
#   remediation:      { source, alert_type, audit_id, control_id, timestamp,
#                       model_name, remediation_text, trace_ids, note }
# ---------------------------------------------------------------------------


class WebhookNotifier:
    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    async def _post(self, payload: dict) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self._webhook_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Source": "cage-compliance-bridge",
                    },
                )
            if resp.is_success:
                logger.info(
                    "[WebhookNotifier] ✅ Payload posted (HTTP %d)", resp.status_code
                )
            else:
                logger.error(
                    "[WebhookNotifier] Webhook returned %d: %s",
                    resp.status_code,
                    resp.text,
                )
        except Exception as exc:
            logger.error("[WebhookNotifier] Failed to POST to webhook: %s", exc)

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None:
        await self._post(
            {
                "source": "compliance-bridge",
                "alert_type": "critical_failure",
                "audit_id": audit_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "findings": [
                    {
                        "control_id": f.control_id,
                        "result": f.result,
                        "finding_id": f.finding_id,
                        "remarks": f.remarks,
                        "safety_rate": f.safety_rate,
                    }
                    for f in critical_fails
                ],
            }
        )

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None:
        await self._post(
            {
                "source": "compliance-bridge",
                "alert_type": "remediation",
                "audit_id": audit_id,
                "control_id": control_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "model_name": model_name,
                "remediation_text": remediation_text,
                "trace_ids": trace_ids,
                "note": "LLM-generated advisory — verify before applying (ISO 42001 A.7.2)",
            }
        )


# ---------------------------------------------------------------------------
# ConsoleNotifier — dev / CI channel (default)
# ---------------------------------------------------------------------------


class ConsoleNotifier:
    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None:
        body = _build_critical_alert_body(critical_fails, audit_id)
        logger.warning(
            "[ConsoleNotifier] 🚨 CRITICAL COMPLIANCE ALERT (dev mode — no Slack webhook)\n%s",
            json.dumps(body, indent=2),
        )

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None:
        body = _build_remediation_followup_body(
            control_id, audit_id, model_name, remediation_text, trace_ids
        )
        logger.warning(
            "[ConsoleNotifier] 🔍 REMEDIATION ADVISORY for %s (dev mode — no Slack webhook)\n%s",
            control_id,
            json.dumps(body, indent=2),
        )


# ---------------------------------------------------------------------------
# MockNotifier — test channel
# ---------------------------------------------------------------------------


class MockNotifier:
    """Captures all calls in-memory for assertion in unit tests. No I/O."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    @property
    def alert_count(self) -> int:
        """Number of send_critical_alert calls recorded."""
        return sum(1 for c in self.calls if c["type"] == "critical")

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> None:
        self.calls.append(
            {
                "type": "critical",
                "critical_fails": critical_fails,
                "audit_id": audit_id,
            }
        )

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> None:
        self.calls.append(
            {
                "type": "remediation",
                "control_id": control_id,
                "audit_id": audit_id,
                "model_name": model_name,
                "remediation_text": remediation_text,
                "trace_ids": trace_ids,
            }
        )


# ---------------------------------------------------------------------------
# Factory — reads env vars at call time (not module load) so tests can swap
# ---------------------------------------------------------------------------


def create_notifier() -> (
    ConsoleNotifier | SlackNotifier | PagerDutyNotifier | WebhookNotifier | MockNotifier
):
    """
    Returns the appropriate notifier based on ALERT_CHANNEL env var.

    Precedence:
      1. ALERT_CHANNEL=pagerduty → PagerDutyNotifier (requires PAGERDUTY_ROUTING_KEY)
      2. ALERT_CHANNEL=webhook   → WebhookNotifier   (requires COMPLIANCE_ALERT_WEBHOOK_URL)
      3. ALERT_CHANNEL=slack     → SlackNotifier     (requires COMPLIANCE_ALERT_WEBHOOK_URL
                                                       or SLACK_WEBHOOK_URL)
      4. ALERT_CHANNEL=mock      → MockNotifier      (requires TESTING=1)
      5. ALERT_CHANNEL=console   → ConsoleNotifier   ← default
      6. (anything else)         → ConsoleNotifier with warning
    """
    channel = os.environ.get("ALERT_CHANNEL", "console").lower().strip()

    if channel == "pagerduty":
        routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
        if not routing_key:
            logger.warning(
                "[create_notifier] ALERT_CHANNEL=pagerduty but PAGERDUTY_ROUTING_KEY "
                "is not set. Falling back to ConsoleNotifier. "
                "(Set PAGERDUTY_ROUTING_KEY to enable incident management — POAM-008)"
            )
            return ConsoleNotifier()
        return PagerDutyNotifier(routing_key)

    if channel == "webhook":
        url = os.environ.get("COMPLIANCE_ALERT_WEBHOOK_URL") or os.environ.get(
            "SLACK_WEBHOOK_URL"
        )
        if not url:
            logger.warning(
                "[create_notifier] ALERT_CHANNEL=webhook but COMPLIANCE_ALERT_WEBHOOK_URL "
                "is not set. Falling back to ConsoleNotifier."
            )
            return ConsoleNotifier()
        return WebhookNotifier(url)

    if channel == "slack":
        url = os.environ.get("COMPLIANCE_ALERT_WEBHOOK_URL") or os.environ.get(
            "SLACK_WEBHOOK_URL"
        )
        if not url:
            logger.warning(
                "[create_notifier] ALERT_CHANNEL=slack but COMPLIANCE_ALERT_WEBHOOK_URL "
                "is not set. Falling back to ConsoleNotifier."
            )
            return ConsoleNotifier()
        return SlackNotifier(url)

    if channel == "mock":
        if not os.environ.get("TESTING"):
            raise ValueError(
                "MockNotifier is not permitted in production. "
                "Set ALERT_CHANNEL to a real channel (slack, pagerduty, webhook, etc.) "
                "or set TESTING=1 to enable mock notifications in a test environment."
            )
        return MockNotifier()

    if channel != "console":
        logger.warning(
            "[create_notifier] Unknown ALERT_CHANNEL=%r. Falling back to ConsoleNotifier.",
            channel,
        )

    return ConsoleNotifier()


# ---------------------------------------------------------------------------
# Module-level convenience functions (called by audit_workflow)
# ---------------------------------------------------------------------------


async def notify_critical_failure(control_id: str, finding: OscalFinding) -> None:
    """Convenience wrapper: notifies a single critical control failure."""
    notifier = create_notifier()
    await notifier.send_critical_alert([finding], finding.finding_id)


async def notify_remediation(control_id: str, advice: str) -> None:
    """Convenience wrapper: sends remediation advice notification."""
    notifier = create_notifier()
    await notifier.send_remediation_followup(
        control_id=control_id,
        audit_id="",
        model_name="",
        remediation_text=advice,
        trace_ids=[],
    )
