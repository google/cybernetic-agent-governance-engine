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

Ported from src/langfuse-bridge/src/notifier.ts and hardened for POAM-2026-230.

Channel selection is driven by the ALERT_CHANNEL environment variable:

  ALERT_CHANNEL=pubsub               — Publishes structured JSON alert events to a
                                        Google Cloud Pub/Sub topic via the Pub/Sub REST
                                        API using Workload Identity / ADC credentials.
                                        Requires COMPLIANCE_ALERT_PUBSUB_TOPIC
                                        ('projects/<project>/topics/<topic>').
                                        Reference-architecture terminal sink on GKE.

  ALERT_CHANNEL=slack                — Posts Slack Block Kit payloads to an HTTPS
                                        COMPLIANCE_ALERT_WEBHOOK_URL (or SLACK_WEBHOOK_URL)
                                        using httpx.

  ALERT_CHANNEL=pagerduty            — Posts PagerDuty Events API v2 incidents.
                                        Requires PAGERDUTY_ROUTING_KEY.
                                        Severity mapping:
                                          FAIL critical control  → 'critical'
                                          SLA breach             → 'error'
                                          Heartbeat / advisory   → 'info'

  ALERT_CHANNEL=webhook              — Posts a generic JSON payload to any HTTPS
                                        endpoint (OpsGenie, Jira Service Mgmt,
                                        ServiceNow). Requires COMPLIANCE_ALERT_WEBHOOK_URL.

  ALERT_CHANNEL=console              — Logs JSON payload to stdout via logging.warning()
                                        and returns False (not delivered externally).
                                        Permitted ONLY in permissive postures (dev/test/ci);
                                        refused at startup in enforcing postures (POAM-2026-230).

  ALERT_CHANNEL=mock                 — Captures calls in-memory, no I/O.
                                        Permitted ONLY in non-enforcing test postures
                                        when TESTING=1.

Every notifier returns a boolean from ``send_critical_alert()`` and
``send_remediation_followup()`` reflecting observed destination acknowledgement
(HTTP 2xx / Pub/Sub ``messageIds``), never merely that the notifier was called.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import sys
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urlparse

import httpx

from src.gateway.governance.env_posture import is_enforcing

from .types import OscalFinding

logger = logging.getLogger(__name__)

_PUBSUB_TOPIC_RE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/topics/[A-Za-z][A-Za-z0-9\-_.~%+]{2,254}$"
)
_PUBSUB_API_BASE = "https://pubsub.googleapis.com/v1"
_PUBSUB_SCOPE = "https://www.googleapis.com/auth/pubsub"

# PagerDuty Events API v2 endpoint — hardcoded per PD docs, not configurable
_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

SUPPORTED_ENFORCING_ALERT_CHANNELS = frozenset(
    {"pubsub", "webhook", "slack", "pagerduty"}
)


class NotifierConfigError(RuntimeError, ValueError):
    """Raised when ALERT_CHANNEL or its destination configuration is invalid."""


# ---------------------------------------------------------------------------
# HIGH-3 FIX: Shared HTTP client to prevent resource exhaustion
#
# Creating a new httpx.AsyncClient() per request exhausts file descriptors
# under load. This module-level singleton is lazily initialized with
# double-checked locking for thread/task safety.
# ---------------------------------------------------------------------------

_notifier_http_client: httpx.AsyncClient | None = None
_notifier_http_lock = asyncio.Lock()


async def _get_notifier_http_client() -> httpx.AsyncClient:
    """Return a shared httpx.AsyncClient, creating it if needed.

    Uses double-checked locking pattern for async safety.
    """
    global _notifier_http_client
    if _notifier_http_client is None or _notifier_http_client.is_closed:
        async with _notifier_http_lock:
            if _notifier_http_client is None or _notifier_http_client.is_closed:
                _notifier_http_client = httpx.AsyncClient(timeout=30.0)
                logger.info("[notifier] Shared HTTP client initialized")
    return _notifier_http_client


async def close_notifier_http_client() -> None:
    """Close the shared HTTP client. Call on application shutdown."""
    global _notifier_http_client
    if _notifier_http_client is not None and not _notifier_http_client.is_closed:
        await _notifier_http_client.aclose()
        _notifier_http_client = None
        logger.info("[notifier] Shared HTTP client closed")


def _validate_https_webhook_url(url: str, *, channel: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise NotifierConfigError(
            f"[POAM-2026-230] ALERT_CHANNEL={channel} requires COMPLIANCE_ALERT_WEBHOOK_URL "
            "(or SLACK_WEBHOOK_URL) to be set; console fallback is refused."
        )
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.netloc:
        raise NotifierConfigError(
            f"[POAM-2026-230] ALERT_CHANNEL={channel} requires an https:// webhook URL; "
            f"got scheme={parsed.scheme!r}."
        )
    return cleaned


def _validate_pubsub_topic(topic: str) -> str:
    cleaned = topic.strip()
    if not cleaned or not _PUBSUB_TOPIC_RE.match(cleaned):
        raise NotifierConfigError(
            "[POAM-2026-230] ALERT_CHANNEL=pubsub requires COMPLIANCE_ALERT_PUBSUB_TOPIC "
            "matching 'projects/<project-id>/topics/<topic-name>'; console fallback is refused."
        )
    return cleaned


def validate_notifier_config(env: Mapping[str, str] | None = None) -> str:
    """Validate ``ALERT_CHANNEL`` and its destination settings (POAM-2026-230 Property 1b).

    Under an enforcing posture (``staging``, ``production``, ``local``, or an
    unknown ``CAGE_ENV``), ``ALERT_CHANNEL`` must name a supported external
    channel (``pubsub``, ``webhook``, ``slack``, or ``pagerduty``) with valid
    destination settings; unset, ``console``, and ``mock`` are refused.

    Under permissive postures (``dev``, ``test``, ``ci``), ``console`` (or unset)
    logs a warning and is allowed for local development, and ``mock`` is allowed
    when ``TESTING`` is set; explicitly selecting an external channel with
    missing/invalid settings or an unknown channel still raises
    :class:`NotifierConfigError` rather than silently degrading to stdout.
    """
    source = os.environ if env is None else env
    enforcing = is_enforcing(source)
    raw = source.get("ALERT_CHANNEL", "")
    channel = raw.strip().lower()

    if enforcing:
        if not channel or channel == "console":
            raise NotifierConfigError(
                "[POAM-2026-230] ALERT_CHANNEL is unset or 'console' under an enforcing "
                "posture. Set ALERT_CHANNEL to 'pubsub', 'webhook', 'slack', or 'pagerduty' "
                "with a configured destination."
            )
        if channel == "mock":
            raise NotifierConfigError(
                "[POAM-2026-230] MockNotifier is not permitted under an enforcing posture."
            )

    if not channel or channel == "console":
        logger.warning(
            "[POAM-2026-230] ALERT_CHANNEL=%r in permissive posture — alerts will write "
            "stdout log lines only and report alerted=False.",
            channel or "console",
        )
        return "console"

    if channel == "mock":
        if not source.get("TESTING"):
            raise NotifierConfigError(
                "MockNotifier is not permitted in production. "
                "Set ALERT_CHANNEL to a real channel (pubsub, slack, pagerduty, webhook) "
                "or set TESTING=1 to enable mock notifications in a test environment."
            )
        return "mock"

    if channel == "pagerduty":
        routing_key = source.get("PAGERDUTY_ROUTING_KEY", "").strip()
        if not routing_key:
            raise NotifierConfigError(
                "[POAM-2026-230] ALERT_CHANNEL=pagerduty requires PAGERDUTY_ROUTING_KEY; "
                "console fallback is refused."
            )
        return "pagerduty"

    if channel in ("webhook", "slack"):
        url = source.get("COMPLIANCE_ALERT_WEBHOOK_URL") or source.get(
            "SLACK_WEBHOOK_URL", ""
        )
        _validate_https_webhook_url(url, channel=channel)
        return channel

    if channel == "pubsub":
        _validate_pubsub_topic(source.get("COMPLIANCE_ALERT_PUBSUB_TOPIC", ""))
        return "pubsub"

    raise NotifierConfigError(
        f"[POAM-2026-230] Unknown ALERT_CHANNEL={raw!r}. Expected one of "
        f"{sorted(SUPPORTED_ENFORCING_ALERT_CHANNELS)} (or 'console' in dev/test/ci)."
    )


def is_external_notifier_configured(env: Mapping[str, str] | None = None) -> bool:
    """Return True iff ``env`` configures a valid external alert destination."""
    source = os.environ if env is None else env
    raw = source.get("ALERT_CHANNEL", "").strip().lower()
    if raw not in SUPPORTED_ENFORCING_ALERT_CHANNELS:
        return False
    try:
        validate_notifier_config({**dict(source), "CAGE_ENV": "production"})
        return True
    except NotifierConfigError:
        return False


def _is_heartbeat_batch(findings: list[OscalFinding]) -> bool:
    return bool(findings) and all(
        (f.assessment_status or "").lower() == "heartbeat"
        or f.control_id == "CA-7-HEARTBEAT"
        for f in findings
    )


# ---------------------------------------------------------------------------
# Shared Slack Block Kit payload builders
# ---------------------------------------------------------------------------


def _build_critical_alert_body(
    critical_fails: list[OscalFinding],
    audit_id: str,
) -> dict:
    is_hb = _is_heartbeat_batch(critical_fails)
    title = (
        "💓 CAGE Synthetic Alert Pipeline Heartbeat (No Action Required)"
        if is_hb
        else "🚨 ISO 42001 Critical Control FAIL"
    )
    headline = (
        "💓 CAGE Synthetic Alert Pipeline Heartbeat — No Action Required"
        if is_hb
        else "🚨 ISO 42001 CRITICAL COMPLIANCE FAILURE — Cybernetic Governance Engine"
    )
    return {
        "text": headline,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
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
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
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
    ) -> bool: ...

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool: ...


# ---------------------------------------------------------------------------
# PubSubNotifier — GCP Pub/Sub REST channel (POAM-2026-230 reference sink)
# ---------------------------------------------------------------------------


def _fetch_pubsub_access_token_sync() -> str:
    """Mint a short-lived OAuth2 bearer token via Google ADC / Workload Identity."""
    import google.auth
    from google.auth.transport.requests import Request as GoogleAuthRequest

    creds, _ = google.auth.default(scopes=[_PUBSUB_SCOPE])
    if not creds.valid or not creds.token:
        creds.refresh(GoogleAuthRequest())
    if not creds.token:
        raise RuntimeError("Google ADC returned an empty Pub/Sub access token")
    return str(creds.token)


class PubSubNotifier:
    """Publishes structured JSON alert events to a Google Cloud Pub/Sub topic."""

    def __init__(self, topic: str) -> None:
        self._topic = _validate_pubsub_topic(topic)

    @property
    def topic(self) -> str:
        return self._topic

    async def _publish(self, payload: dict, *, alert_type: str, audit_id: str) -> bool:
        try:
            token = await asyncio.to_thread(_fetch_pubsub_access_token_sync)
            encoded = base64.b64encode(
                json.dumps(payload, sort_keys=True).encode("utf-8")
            ).decode("ascii")
            body = {
                "messages": [
                    {
                        "data": encoded,
                        "attributes": {
                            "source": "compliance-bridge",
                            "alert_type": alert_type,
                            "audit_id": audit_id,
                        },
                    }
                ]
            }
            client = await _get_notifier_http_client()
            resp = await client.post(
                f"{_PUBSUB_API_BASE}/{self._topic}:publish",
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            if not resp.is_success:
                logger.error(
                    "[PubSubNotifier] Pub/Sub publish returned HTTP %d: %s",
                    resp.status_code,
                    resp.text[:256],
                )
                return False
            resp_json = resp.json()
            msg_ids = (
                resp_json.get("messageIds") if isinstance(resp_json, dict) else None
            )
            if not isinstance(msg_ids, list) or not any(
                isinstance(m, str) and m.strip() for m in msg_ids
            ):
                logger.error(
                    "[PubSubNotifier] Pub/Sub publish returned HTTP %d without messageIds",
                    resp.status_code,
                )
                return False
            logger.info(
                "[PubSubNotifier] Published %s alert (audit_id=%s, message_id=%s)",
                alert_type,
                audit_id,
                msg_ids[0],
            )
            return True
        except Exception as exc:
            logger.error("[PubSubNotifier] Failed to publish alert: %s", exc)
            return False

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        if not critical_fails:
            return False
        alert_type = (
            "heartbeat" if _is_heartbeat_batch(critical_fails) else "critical_failure"
        )
        return await self._publish(
            {
                "source": "compliance-bridge",
                "alert_type": alert_type,
                "audit_id": audit_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "findings": [
                    {
                        "control_id": f.control_id,
                        "result": f.result,
                        "finding_id": f.finding_id,
                        "assessment_status": f.assessment_status,
                        "remarks": f.remarks,
                        "safety_rate": f.safety_rate,
                    }
                    for f in critical_fails
                ],
            },
            alert_type=alert_type,
            audit_id=audit_id,
        )

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool:
        return await self._publish(
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
            },
            alert_type="remediation",
            audit_id=audit_id,
        )


# ---------------------------------------------------------------------------
# SlackNotifier — HTTPS Block Kit webhook channel
# ---------------------------------------------------------------------------


class SlackNotifier:
    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = _validate_https_webhook_url(webhook_url, channel="slack")

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        if not critical_fails:
            return False
        body = _build_critical_alert_body(critical_fails, audit_id)
        try:
            client = await _get_notifier_http_client()
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
                return True
            logger.error("[SlackNotifier] Alert webhook returned %d", resp.status_code)
            return False
        except Exception as exc:
            logger.error("[SlackNotifier] Failed to send alert: %s", exc)
            return False

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool:
        body = _build_remediation_followup_body(
            control_id, audit_id, model_name, remediation_text, trace_ids
        )
        try:
            client = await _get_notifier_http_client()
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
                return True
            logger.error(
                "[SlackNotifier] Slack follow-up returned %d", resp.status_code
            )
            return False
        except Exception as exc:
            logger.error("[SlackNotifier] Failed to post Slack follow-up: %s", exc)
            return False


# ---------------------------------------------------------------------------
# PagerDutyNotifier — incident management channel (Capability 2.4 / POAM-008)
# ---------------------------------------------------------------------------


class PagerDutyNotifier:
    def __init__(self, routing_key: str) -> None:
        cleaned = routing_key.strip()
        if not cleaned:
            raise NotifierConfigError(
                "[POAM-2026-230] PagerDutyNotifier requires a non-empty routing_key."
            )
        self._routing_key = cleaned

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        """Trigger one PagerDuty incident per critical failing control."""
        if not critical_fails:
            return False
        is_hb = _is_heartbeat_batch(critical_fails)
        all_delivered = True
        for finding in critical_fails:
            dedup_key = f"cage-{audit_id}-{finding.control_id}"
            payload = _build_pagerduty_trigger(
                summary=(
                    f"[CAGE] Synthetic Alert Heartbeat (No Action Required) — {audit_id}"
                    if is_hb
                    else f"[CAGE] ISO 42001 Critical Failure: {finding.control_id} — Audit {audit_id}"
                ),
                severity="info" if is_hb else "critical",
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
                    "alert_type": "heartbeat" if is_hb else "critical_failure",
                    "standard": "ISO/IEC 42001:2023",
                },
            )
            try:
                client = await _get_notifier_http_client()
                resp = await client.post(
                    _PAGERDUTY_EVENTS_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.is_success:
                    logger.info(
                        "[PagerDutyNotifier] 🚨 Event delivered: %s (dedup=%s)",
                        finding.control_id,
                        dedup_key,
                    )
                else:
                    all_delivered = False
                    logger.error(
                        "[PagerDutyNotifier] Events API returned %d for %s: %s",
                        resp.status_code,
                        finding.control_id,
                        resp.text,
                    )
            except Exception as exc:
                all_delivered = False
                logger.error(
                    "[PagerDutyNotifier] Failed to trigger incident for %s: %s",
                    finding.control_id,
                    exc,
                )
        return all_delivered

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool:
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
                "remediation_text": remediation_text[:512],
                "trace_ids": trace_ids,
                "note": "LLM-generated — human verification required (ISO 42001 A.7.2)",
            },
        )
        try:
            client = await _get_notifier_http_client()
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
                return True
            logger.error(
                "[PagerDutyNotifier] Events API returned %d for remediation %s: %s",
                resp.status_code,
                control_id,
                resp.text,
            )
            return False
        except Exception as exc:
            logger.error(
                "[PagerDutyNotifier] Failed to post remediation advisory for %s: %s",
                control_id,
                exc,
            )
            return False


# ---------------------------------------------------------------------------
# WebhookNotifier — generic HTTPS JSON POST channel (Capability 2.4)
# ---------------------------------------------------------------------------


class WebhookNotifier:
    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = _validate_https_webhook_url(webhook_url, channel="webhook")

    async def _post(self, payload: dict) -> bool:
        try:
            client = await _get_notifier_http_client()
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
                return True
            logger.error(
                "[WebhookNotifier] Webhook returned %d: %s",
                resp.status_code,
                resp.text,
            )
            return False
        except Exception as exc:
            logger.error("[WebhookNotifier] Failed to POST to webhook: %s", exc)
            return False

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        if not critical_fails:
            return False
        alert_type = (
            "heartbeat" if _is_heartbeat_batch(critical_fails) else "critical_failure"
        )
        return await self._post(
            {
                "source": "compliance-bridge",
                "alert_type": alert_type,
                "audit_id": audit_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "findings": [
                    {
                        "control_id": f.control_id,
                        "result": f.result,
                        "finding_id": f.finding_id,
                        "assessment_status": f.assessment_status,
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
    ) -> bool:
        return await self._post(
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
# ConsoleNotifier — permissive dev/test/ci channel ONLY (returns False)
# ---------------------------------------------------------------------------


class ConsoleNotifier:
    """Writes stdout log lines in permissive postures and returns False (not delivered)."""

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        body = _build_critical_alert_body(critical_fails, audit_id)
        logger.warning(
            "[ConsoleNotifier] 🚨 CRITICAL COMPLIANCE ALERT (dev mode — no external sink)\n%s",
            json.dumps(body, indent=2),
        )
        return False

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool:
        body = _build_remediation_followup_body(
            control_id, audit_id, model_name, remediation_text, trace_ids
        )
        logger.warning(
            "[ConsoleNotifier] 🔍 REMEDIATION ADVISORY for %s (dev mode — no external sink)\n%s",
            control_id,
            json.dumps(body, indent=2),
        )
        return False


# ---------------------------------------------------------------------------
# MockNotifier — test channel
# ---------------------------------------------------------------------------


class MockNotifier:
    """Captures all calls in-memory for assertion in unit tests. No I/O."""

    def __init__(self, *, simulate_delivery_failure: bool = False) -> None:
        self.calls: list[dict] = []
        self.simulate_delivery_failure = simulate_delivery_failure

    @property
    def alert_count(self) -> int:
        """Number of send_critical_alert calls recorded."""
        return sum(1 for c in self.calls if c["type"] == "critical")

    async def send_critical_alert(
        self,
        critical_fails: list[OscalFinding],
        audit_id: str,
    ) -> bool:
        self.calls.append(
            {
                "type": "critical",
                "critical_fails": critical_fails,
                "audit_id": audit_id,
            }
        )
        return not self.simulate_delivery_failure

    async def send_remediation_followup(
        self,
        control_id: str,
        audit_id: str,
        model_name: str,
        remediation_text: str,
        trace_ids: list[str],
    ) -> bool:
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
        return not self.simulate_delivery_failure


# ---------------------------------------------------------------------------
# Factory — reads env vars at call time (not module load) and fails closed
# ---------------------------------------------------------------------------


def create_notifier(
    env: Mapping[str, str] | None = None,
) -> (
    PubSubNotifier
    | ConsoleNotifier
    | SlackNotifier
    | PagerDutyNotifier
    | WebhookNotifier
    | MockNotifier
):
    """Return the validated notifier for ``ALERT_CHANNEL`` (POAM-2026-230).

    Never falls back silently to :class:`ConsoleNotifier` when a channel is
    unknown, lacks its credentials/URL/topic, uses non-HTTPS HTTP, or runs
    under an enforcing posture.
    """
    source = os.environ if env is None else env
    channel = validate_notifier_config(source)

    if channel == "pubsub":
        return PubSubNotifier(source.get("COMPLIANCE_ALERT_PUBSUB_TOPIC", ""))

    if channel == "pagerduty":
        return PagerDutyNotifier(source.get("PAGERDUTY_ROUTING_KEY", ""))

    if channel == "webhook":
        url = source.get("COMPLIANCE_ALERT_WEBHOOK_URL") or source.get(
            "SLACK_WEBHOOK_URL", ""
        )
        return WebhookNotifier(url)

    if channel == "slack":
        url = source.get("COMPLIANCE_ALERT_WEBHOOK_URL") or source.get(
            "SLACK_WEBHOOK_URL", ""
        )
        return SlackNotifier(url)

    if channel == "mock":
        return MockNotifier()

    return ConsoleNotifier()


# ---------------------------------------------------------------------------
# Module-level convenience functions & synthetic pipeline heartbeat
# ---------------------------------------------------------------------------


async def notify_critical_failure(control_id: str, finding: OscalFinding) -> bool:
    """Convenience wrapper: notifies a single critical control failure."""
    notifier = create_notifier()
    return (await notifier.send_critical_alert([finding], finding.finding_id)) is True


async def notify_remediation(control_id: str, advice: str) -> bool:
    """Convenience wrapper: sends remediation advice notification."""
    notifier = create_notifier()
    return (
        await notifier.send_remediation_followup(
            control_id=control_id,
            audit_id="",
            model_name="",
            remediation_text=advice,
            trace_ids=[],
        )
    ) is True


async def send_notifier_heartbeat(audit_id: str | None = None) -> tuple[bool, str]:
    """Emit a synthetic non-paging heartbeat through ``send_critical_alert()`` (POAM-2026-230).

    Returns ``(delivered, audit_id)`` where ``delivered`` is ``True`` only when
    the configured destination acknowledged receipt.
    """
    hb_id = (
        audit_id.strip()
        if audit_id and audit_id.strip()
        else f"notifier-heartbeat-{uuid.uuid4().hex[:12]}"
    )
    finding = OscalFinding(
        control_id="CA-7-HEARTBEAT",
        result="PASS",
        finding_id=hb_id,
        assessment_status="heartbeat",
        remarks=(
            "SYNTHETIC_NOTIFIER_HEARTBEAT — end-to-end compliance-bridge alert "
            "pipeline verification probe; no operator action required (POAM-2026-230)."
        ),
        safety_rate=1.0,
    )
    notifier = create_notifier()
    delivered = (await notifier.send_critical_alert([finding], hb_id)) is True
    return delivered, hb_id


def _cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compliance-bridge notifier verification CLI (POAM-2026-230)."
    )
    parser.add_argument(
        "--heartbeat",
        action="store_true",
        required=True,
        help="Emit one synthetic heartbeat via create_notifier().send_critical_alert().",
    )
    parser.add_argument(
        "--audit-id",
        default="",
        help="Optional deterministic audit_id for destination correlation.",
    )
    args = parser.parse_args(argv)

    async def _run() -> tuple[bool, str]:
        try:
            return await send_notifier_heartbeat(args.audit_id or None)
        finally:
            await close_notifier_http_client()

    delivered, hb_id = asyncio.run(_run())
    print(json.dumps({"delivered": delivered, "audit_id": hb_id}))
    return 0 if delivered else 1


if __name__ == "__main__":
    sys.exit(_cli_main())
