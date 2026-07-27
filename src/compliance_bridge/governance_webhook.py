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
Governance Webhook Push (G3)
============================

Pushes governance enforcement events to registered Governance Layer endpoints
when a substrate enforcement event occurs (CBF violation, DEFER parking, HITL
interrupt, OPA deny).

Complements the existing pull-based SSE stream (``GET /v1/events/stream``)
with a push notification mechanism.

Security
--------
- Webhook payloads are signed with HMAC-SHA256 using the registered secret.
- The ``X-CAGE-Webhook-Signature`` header carries the hex-encoded signature.
- Receiving endpoints must verify the signature before processing.
- Webhook secrets must never be logged or included in telemetry exports.

Region guard
------------
Any outbound HTTP call must be gated on ``CAGE_DEPLOYMENT_REGION``.
EU_ECB webhook endpoints must remain within ``europe-west1``;
APAC_MAS within ``asia-southeast1``.
Cross-region webhook registrations are rejected with HTTP 422.

Usage::

    from src.compliance_bridge.governance_webhook import WebhookRegistry, webhook_registry

    # Register a webhook
    webhook_id = await webhook_registry.register(
        endpoint_url="https://governance-layer.example.com/cage-events",
        event_types=["CBF_VIOLATION", "OPA_DENY"],
        secret="my-hmac-secret",
    )

    # Dispatch an event (called by enforcement modules)
    await webhook_registry.dispatch({
        "type": "CBF_VIOLATION",
        "traceId": "abc123",
        "controlId": "A.9.2",
        "result": "FAIL",
        "safetyRate": 0.87,
        "auditId": "uuid-here",
        "timestamp": "2026-07-18T01:00:00Z",
    })
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

logger = logging.getLogger("ComplianceBridge.GovernanceWebhook")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

WebhookEventType = Literal[
    "CBF_VIOLATION",
    "DEFER_PARKING",
    "HITL_INTERRUPT",
    "OPA_DENY",
]

_ALL_EVENT_TYPES: frozenset[str] = frozenset(
    {"CBF_VIOLATION", "DEFER_PARKING", "HITL_INTERRUPT", "OPA_DENY"}
)

# ---------------------------------------------------------------------------
# Region guard configuration
# ---------------------------------------------------------------------------

# Allowed URL hostname suffixes per region
_REGION_ALLOWED_SUFFIXES: dict[str, list[str]] = {
    "EU_ECB": [
        ".europe-west1.",
        "europe-west1",
        # Allow internal/private endpoints within EU region
    ],
    "APAC_MAS": [
        ".asia-southeast1.",
        "asia-southeast1",
    ],
    "US_FED": [],  # US_FED: no geographic restriction on endpoint URLs
}

# Retry configuration
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds (exponential backoff base)
_REQUEST_TIMEOUT = 30.0  # seconds per attempt


# ---------------------------------------------------------------------------
# WebhookRegistration dataclass
# ---------------------------------------------------------------------------


@dataclass
class WebhookRegistration:
    """A registered webhook endpoint."""

    webhook_id: str
    endpoint_url: str
    event_types: list[str]
    secret: str  # HMAC-SHA256 signing secret — never logged
    registered_at: str  # ISO 8601 UTC
    region: str  # CAGE_DEPLOYMENT_REGION at registration time

    def matches_event(self, event_type: str) -> bool:
        """Return True if this webhook should receive the given event type."""
        return event_type in self.event_types


# ---------------------------------------------------------------------------
# WebhookRegistry
# ---------------------------------------------------------------------------


class WebhookRegistry:
    """In-memory registry of webhook registrations with async dispatch.

    Thread-safe for concurrent asyncio tasks. Uses an asyncio.Lock to
    protect the registrations dict.

    For production deployments, replace the in-memory store with a Redis
    backend by subclassing and overriding ``_load_registrations()`` and
    ``_save_registration()``.
    """

    def __init__(self) -> None:
        self._registrations: dict[str, WebhookRegistration] = {}
        self._lock = asyncio.Lock()
        self._region = (
            os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()
        )

    # ------------------------------------------------------------------
    # Region guard
    # ------------------------------------------------------------------

    def _check_region_guard(self, endpoint_url: str) -> None:
        """Raise ValueError if the endpoint URL violates the region guard.

        EU_ECB and APAC_MAS deployments must only register endpoints within
        their respective GCP regions. Cross-region registrations are rejected.

        US_FED has no geographic restriction on endpoint URLs.
        """
        if self._region not in ("EU_ECB", "APAC_MAS"):
            return  # US_FED: no restriction

        allowed_suffixes = _REGION_ALLOWED_SUFFIXES.get(self._region, [])
        if not allowed_suffixes:
            return  # No restriction configured

        parsed = urlparse(endpoint_url)
        hostname = parsed.hostname or ""

        # Allow localhost and private IPs for testing
        if (
            hostname in ("localhost", "127.0.0.1", "::1")
            or hostname.startswith("10.")
            or hostname.startswith("192.168.")
        ):
            return

        # Check if hostname contains an allowed region suffix
        for suffix in allowed_suffixes:
            if suffix in hostname:
                return

        raise ValueError(
            f"WebhookRegistry: endpoint URL '{endpoint_url}' violates region guard for "
            f"'{self._region}'. Endpoints must be within the allowed region. "
            f"Cross-region webhook endpoints are rejected with HTTP 422."
        )

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(
        self,
        endpoint_url: str,
        event_types: list[str],
        secret: str,
    ) -> str:
        """Register a new webhook endpoint.

        Args:
            endpoint_url: The HTTPS URL to POST events to.
            event_types: List of event types to subscribe to.
                         Valid values: ``CBF_VIOLATION``, ``DEFER_PARKING``,
                         ``HITL_INTERRUPT``, ``OPA_DENY``.
            secret: HMAC-SHA256 signing secret. Never logged.

        Returns:
            The generated ``webhook_id`` (UUID).

        Raises:
            ValueError: If the endpoint URL violates the region guard,
                        or if any event_type is invalid.
        """
        # Validate event types
        invalid = [et for et in event_types if et not in _ALL_EVENT_TYPES]
        if invalid:
            raise ValueError(
                f"WebhookRegistry: unknown event types {invalid}. "
                f"Valid types: {sorted(_ALL_EVENT_TYPES)}"
            )

        # Region guard
        self._check_region_guard(endpoint_url)

        webhook_id = str(uuid.uuid4())
        registered_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        registration = WebhookRegistration(
            webhook_id=webhook_id,
            endpoint_url=endpoint_url,
            event_types=list(event_types),
            secret=secret,
            registered_at=registered_at,
            region=self._region,
        )

        async with self._lock:
            self._registrations[webhook_id] = registration

        logger.info(
            "WebhookRegistry: registered webhook_id=%s endpoint=%s events=%s region=%s",
            webhook_id,
            endpoint_url,
            event_types,
            self._region,
        )
        return webhook_id

    async def deregister(self, webhook_id: str) -> bool:
        """Remove a webhook registration.

        Args:
            webhook_id: The webhook ID to remove.

        Returns:
            True if the webhook was found and removed, False if not found.
        """
        async with self._lock:
            if webhook_id in self._registrations:
                del self._registrations[webhook_id]
                logger.info("WebhookRegistry: deregistered webhook_id=%s", webhook_id)
                return True
        return False

    async def list_registrations(self) -> list[dict[str, Any]]:
        """Return all registered webhooks (secrets redacted)."""
        async with self._lock:
            return [
                {
                    "webhook_id": r.webhook_id,
                    "endpoint_url": r.endpoint_url,
                    "event_types": r.event_types,
                    "registered_at": r.registered_at,
                    "region": r.region,
                    # secret intentionally omitted
                }
                for r in self._registrations.values()
            ]

    # ------------------------------------------------------------------
    # HMAC signing
    # ------------------------------------------------------------------

    @staticmethod
    def _sign_payload(payload_bytes: bytes, secret: str) -> str:
        """Compute HMAC-SHA256 signature for a payload.

        Args:
            payload_bytes: The JSON-encoded payload bytes.
            secret: The webhook signing secret.

        Returns:
            Hex-encoded HMAC-SHA256 signature.
        """
        return hmac.new(
            secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _deliver(
        self,
        registration: WebhookRegistration,
        payload: dict[str, Any],
    ) -> bool:
        """Deliver a single webhook event with exponential backoff retry.

        Args:
            registration: The target webhook registration.
            payload: The event payload dict (already includes ``webhook_id``).

        Returns:
            True if delivery succeeded, False after all retries exhausted.
        """
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = self._sign_payload(payload_bytes, registration.secret)

        headers = {
            "Content-Type": "application/json",
            "X-CAGE-Webhook-Signature": signature,
            "X-CAGE-Webhook-ID": registration.webhook_id,
            "User-Agent": "CAGE-GovernanceWebhook/1.0",
        }

        for attempt in range(_MAX_RETRIES):
            try:
                import httpx

                async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                    response = await client.post(
                        registration.endpoint_url,
                        content=payload_bytes,
                        headers=headers,
                    )
                    if response.status_code < 300:
                        logger.info(
                            "WebhookRegistry: delivered event type=%s to webhook_id=%s "
                            "status=%d attempt=%d",
                            payload.get("type"),
                            registration.webhook_id,
                            response.status_code,
                            attempt + 1,
                        )
                        return True
                    else:
                        logger.warning(
                            "WebhookRegistry: delivery failed webhook_id=%s status=%d attempt=%d",
                            registration.webhook_id,
                            response.status_code,
                            attempt + 1,
                        )
            except ImportError:
                # Fall back to urllib if httpx is not available
                try:
                    import urllib.request

                    req = urllib.request.Request(
                        registration.endpoint_url,
                        data=payload_bytes,
                        headers=headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                        if resp.status < 300:
                            logger.info(
                                "WebhookRegistry: delivered event type=%s to webhook_id=%s "
                                "status=%d attempt=%d (urllib fallback)",
                                payload.get("type"),
                                registration.webhook_id,
                                resp.status,
                                attempt + 1,
                            )
                            return True
                except Exception as exc:
                    logger.warning(
                        "WebhookRegistry: urllib delivery failed webhook_id=%s attempt=%d: %s",
                        registration.webhook_id,
                        attempt + 1,
                        exc,
                    )
            except Exception as exc:
                logger.warning(
                    "WebhookRegistry: delivery error webhook_id=%s attempt=%d: %s",
                    registration.webhook_id,
                    attempt + 1,
                    exc,
                )

            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2**attempt)
                await asyncio.sleep(delay)

        logger.error(
            "WebhookRegistry: all %d delivery attempts failed for webhook_id=%s event=%s",
            _MAX_RETRIES,
            registration.webhook_id,
            payload.get("type"),
        )
        return False

    async def dispatch(self, event: dict[str, Any]) -> None:
        """Dispatch a governance event to all matching registered webhooks.

        This method is called by enforcement modules (CBF, OPA, DEFER, HITL)
        when an enforcement event occurs. Delivery is asynchronous and
        non-blocking — failures are logged but do not raise exceptions.

        Args:
            event: A governance event dict with at minimum:
                   ``type``, ``traceId``, ``controlId``, ``result``,
                   ``safetyRate``, ``auditId``, ``timestamp``.
        """
        event_type = event.get("type", "")
        if not event_type:
            logger.warning(
                "WebhookRegistry: dispatch called with event missing 'type' field."
            )
            return

        if event_type not in _ALL_EVENT_TYPES:
            logger.debug(
                "WebhookRegistry: event type '%s' is not a webhook event type — skipping dispatch.",
                event_type,
            )
            return

        async with self._lock:
            matching = [
                r for r in self._registrations.values() if r.matches_event(event_type)
            ]

        if not matching:
            logger.debug(
                "WebhookRegistry: no webhooks registered for event type '%s'.",
                event_type,
            )
            return

        # Build coroutines for all matching webhooks
        coros = []
        for registration in matching:
            payload = {
                **event,
                "webhook_id": registration.webhook_id,
            }
            coros.append(self._deliver(registration, payload))

        logger.info(
            "WebhookRegistry: dispatching event type='%s' to %d webhook(s).",
            event_type,
            len(coros),
        )

        # Dispatch concurrently and await all deliveries so callers can
        # observe results and so that event-loop teardown does not cancel
        # in-flight tasks. Failures are logged in _deliver() and do not
        # propagate exceptions (return_exceptions=True).
        await asyncio.gather(*coros, return_exceptions=True)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

webhook_registry: WebhookRegistry = WebhookRegistry()
