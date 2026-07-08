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
sse_events.py — In-process pub/sub event bus for governance telemetry SSE streaming.

Ports src/compliance_bridge_ts/src/events.ts to Python (asyncio + asyncio.Queue).

Architecture:
  - ``GovernanceEventBus`` maintains a list of per-subscriber ``asyncio.Queue`` instances.
  - Any coroutine (e.g. ``audit_workflow.py``) calls ``await event_bus.publish(event)``
    to broadcast a ``GovernanceEvent`` dict to all currently-connected SSE clients.
  - The FastAPI SSE endpoint (``GET /v1/events/stream``) calls ``event_bus.subscribe()``
    to obtain its own queue and reads from it inside an async generator.
  - On client disconnect the generator exits, and ``event_bus.unsubscribe()`` removes the
    dead queue — mirroring the TypeScript ``subscribers.delete(fn)`` cleanup.

GovernanceEvent wire shape (JSON-serialised in the SSE ``data`` field):
    {
      "type":       "AUDIT_FINDING" | "GOVERNANCE_VIOLATION" | "REMEDIATION_GENERATED"
                  | "CONTEXT_CHAIN_SEALED" | "DEFER_PARKING" | "DEFER_RESOLVED",
      "traceId":    "<langfuse-trace-id>" | null,
      "controlId":  "<ISO-control-id>",
      "result":     "PASS" | "FAIL" | "NOT_APPLICABLE" | null,
      "safetyRate": <float 0-1> | null,
      "auditId":    "<audit-run-uuid>",
      "timestamp":  "<ISO-8601-UTC>"
    }

  For REMEDIATION_GENERATED events, the additional field ``modelName`` and
  ``textLength`` are included; ``result`` and ``safetyRate`` are null.

This shape is defined by the frontend contract in
``src/agentsight-ui/src/KernelDashboard.tsx`` (``GovernanceEvent`` interface) and must
not be changed without a coordinated frontend update.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from typing import Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GovernanceEvent type alias (TypedDict-style)
# Mirrors GovernanceEvent interface in src/compliance_bridge_ts/src/events.ts
# ---------------------------------------------------------------------------

GovernanceEventType = Literal[
    "AUDIT_FINDING",
    "GOVERNANCE_VIOLATION",
    "REMEDIATION_GENERATED",
    # CAGE v0.1.0 — AARM primitives
    "CONTEXT_CHAIN_SEALED",  # emitted when the SHA-256 hash chain is sealed after each audit
    "DEFER_PARKING",  # emitted when an execution context is parked in the DEFER queue
    "DEFER_RESOLVED",  # emitted when a deferred token is resolved (ESCALATED/INJECTED/EXPIRED)
]
OscalResult = Literal["PASS", "FAIL", "NOT_APPLICABLE"]


# We use a plain ``dict`` at the boundary so that ``json.dumps`` can serialise
# it directly into the SSE ``data`` field without extra ceremony.  The type
# alias below documents the expected keys for static analysis.
#
# GovernanceEvent = TypedDict("GovernanceEvent", {
#     "type":       GovernanceEventType,
#     "traceId":    str,
#     "controlId":  str,
#     "result":     OscalResult,
#     "safetyRate": float | None,
#     "auditId":    str,
#     "timestamp":  str,           # ISO 8601 UTC
# })


# ---------------------------------------------------------------------------
# GovernanceEventBus — singleton pub/sub registry
# ---------------------------------------------------------------------------


class GovernanceEventBus:
    """Async pub/sub registry that fans governance events out to SSE subscribers.

    Intentionally keeps zero external dependencies — just ``asyncio.Queue``.

    Usage (publisher side)::

        from compliance_bridge.sse_events import event_bus
        await event_bus.publish({
            "type":       "AUDIT_FINDING",
            "traceId":    trace.id,
            "controlId":  finding.control_id,
            "result":     finding.result,
            "safetyRate": finding.safety_rate,
            "auditId":    audit_id,
            "timestamp":  datetime.now(tz=timezone.utc).isoformat(),
        })

    Usage (SSE endpoint side)::

        async for event in event_bus.subscribe():
            yield ServerSentEvent(data=json.dumps(event), event="governance-event")
    """

    # M-07: Maximum concurrent SSE subscribers to prevent resource exhaustion
    MAX_SUBSCRIBERS: int = 100

    def __init__(self, maxsize: int = 128) -> None:
        # ``_queues`` is the Python equivalent of the TypeScript ``Set<Subscriber>``.
        self._queues: list[asyncio.Queue[dict]] = []
        self._maxsize = maxsize
        # Optional evidence stream sink — set via attach_evidence_sink()
        # When not None, publish() forwards events for hash-chained persistence.
        self._evidence_sink = None

    # ------------------------------------------------------------------
    # subscribe — yields events from the caller's dedicated queue.
    # The caller is responsible for draining the queue (i.e. the SSE
    # generator loop) and calling ``unsubscribe()`` when done.
    # ------------------------------------------------------------------

    def _new_queue(self) -> asyncio.Queue[dict]:
        """Allocate a fresh subscriber queue and register it.

        M-07: Raises RuntimeError if MAX_SUBSCRIBERS is already reached to
        prevent unbounded memory growth from connection floods.
        """
        if len(self._queues) >= self.MAX_SUBSCRIBERS:
            raise RuntimeError(
                f"[event_bus] SSE subscriber limit reached ({self.MAX_SUBSCRIBERS}). "
                "Rejecting new connection to prevent resource exhaustion."
            )
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=self._maxsize)
        self._queues.append(q)
        logger.debug(
            "[event_bus] New SSE subscriber registered. Total subscribers: %d",
            len(self._queues),
        )
        return q

    def unsubscribe(self, q: asyncio.Queue[dict]) -> None:
        """Remove a queue from the registry (called on client disconnect)."""
        try:
            self._queues.remove(q)
            logger.debug(
                "[event_bus] SSE subscriber removed. Remaining subscribers: %d",
                len(self._queues),
            )
        except ValueError:
            pass  # Already removed — safe to ignore

    async def subscribe(self) -> AsyncGenerator[dict, None]:
        """Async generator that yields governance events as they arrive.

        The generator registers a new queue, yields each event that lands on it,
        and cleans up the queue when the caller's ``async for`` loop exits
        (whether normally or due to a ``GeneratorExit`` / client disconnect).

        Example usage inside the SSE endpoint::

            async def event_generator(request: Request):
                async for event in event_bus.subscribe():
                    if await request.is_disconnected():
                        break
                    yield ServerSentEvent(data=json.dumps(event), event="governance-event")
        """
        q = self._new_queue()
        try:
            while True:
                event = await q.get()
                yield event
        except GeneratorExit:
            pass
        finally:
            self.unsubscribe(q)

    # ------------------------------------------------------------------
    # publish — broadcast an event to all active subscriber queues.
    # Dead / full queues are handled gracefully: a full queue drops the
    # event for that subscriber (non-blocking put_nowait) and logs a
    # warning.  This mirrors the TypeScript ``try { fn(event) } catch {}``
    # pattern that silently ignores disconnected subscribers.
    # ------------------------------------------------------------------

    async def publish(self, event: dict) -> None:
        """Put ``event`` on every active subscriber queue.

        Args:
            event: A ``GovernanceEvent``-shaped dict — serialisable via
                   ``json.dumps`` for inclusion in the SSE ``data`` field.
        """
        # M-08: Persist to evidence stream FIRST (durability before fan-out).
        # Evidence must be written regardless of whether any SSE subscribers
        # are connected — decouples audit durability from delivery.
        if self._evidence_sink is not None:
            try:
                await self._evidence_sink.ingest(event)
            except Exception as exc:
                logger.warning("[event_bus] Evidence stream ingest failed: %s", exc)

        if not self._queues:
            logger.debug(
                "[event_bus] publish() called with no subscribers — skipping fan-out."
            )
            return

        dead: list[asyncio.Queue[dict]] = []
        for q in list(self._queues):  # snapshot to avoid mutation during iteration
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "[event_bus] Subscriber queue full — dropping event for slow client."
                )
            except Exception as exc:
                logger.warning(
                    "[event_bus] Failed to deliver event to subscriber: %s", exc
                )
                dead.append(q)

        for q in dead:
            self.unsubscribe(q)

    @property
    def subscriber_count(self) -> int:
        """Number of currently connected SSE subscribers.

        Mirrors ``subscriberCount()`` from events.ts — useful for health logging.
        """
        return len(self._queues)

    def attach_evidence_sink(self, sink) -> None:
        """Attach an EvidenceStreamSink for hash-chained event persistence.

        Args:
            sink: An EvidenceStreamSink instance (from evidence_stream.py).
        """
        self._evidence_sink = sink
        logger.info(
            "[event_bus] Evidence stream sink attached — governance events "
            "will be hash-chained and persisted."
        )


# ---------------------------------------------------------------------------
# Module-level singleton — import from other modules as:
#   from compliance_bridge.sse_events import event_bus
# ---------------------------------------------------------------------------

event_bus: GovernanceEventBus = GovernanceEventBus()
