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

"""Event-loop lag monitor and out-of-band Prometheus metrics HTTP server.

The gateway's main ASGI application runs on a single asyncio event loop. When
synchronous calls (e.g. KMS gRPC signing, synchronous Redis fallbacks, or
CPU-bound JCS/JSON work) block the loop, an in-band ``/metrics`` endpoint on
FastAPI would also stall.

This module provides:
  1. :func:`run_loop_lag_monitor` — an asyncio background coroutine that sleeps
     for a fixed interval (default 250 ms), measures wall-clock wakeup drift via
     :func:`time.monotonic`, and records the excess delay in the
     ``cage_event_loop_lag_seconds`` Prometheus histogram.
  2. :func:`start_metrics_http_server` — starts ``prometheus_client``'s threaded
     WSGI HTTP server on ``CAGE_METRICS_PORT`` (default ``9090``, disabled when
     ``<= 0``) so Prometheus / GKE Managed Prometheus can scrape ``/metrics``
     even while the asyncio event loop is blocked.

``prometheus_client`` is treated as an optional dependency and degrades to a
no-op when absent.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("Gateway.Observability.LoopMonitor")

DEFAULT_METRICS_PORT = 9090
DEFAULT_LOOP_LAG_INTERVAL_SECONDS = 0.25

_LOOP_LAG_BUCKETS = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

try:
    from prometheus_client import (
        REGISTRY,
        CollectorRegistry,
        Histogram,
        start_http_server,
    )

    try:
        EVENT_LOOP_LAG_SECONDS: Any = Histogram(
            "cage_event_loop_lag_seconds",
            "Asyncio event-loop scheduling drift in seconds beyond the target sleep interval",
            buckets=_LOOP_LAG_BUCKETS,
        )
    except ValueError:  # pragma: no cover - duplicate registration guard
        EVENT_LOOP_LAG_SECONDS = REGISTRY._names_to_collectors.get(
            "cage_event_loop_lag_seconds"
        )
except ImportError:  # pragma: no cover - exercised when prometheus_client is absent
    REGISTRY = None  # type: ignore[assignment]
    CollectorRegistry = Any  # type: ignore[misc, assignment]
    Histogram = None  # type: ignore[misc, assignment]
    start_http_server = None  # type: ignore[assignment]
    EVENT_LOOP_LAG_SECONDS = None


def record_loop_lag(lag_seconds: float, histogram: Any = None) -> None:
    """Record a single event-loop lag sample (clamped to ``>= 0.0``)."""
    target = EVENT_LOOP_LAG_SECONDS if histogram is None else histogram
    if target is not None:
        target.observe(max(0.0, float(lag_seconds)))


async def run_loop_lag_monitor(
    interval_seconds: float = DEFAULT_LOOP_LAG_INTERVAL_SECONDS,
    histogram: Any = None,
) -> None:
    """Continuously sample asyncio event-loop scheduling lag until cancelled.

    On each iteration, sleeps for ``interval_seconds`` and records
    ``max(0.0, elapsed - interval_seconds)`` into ``cage_event_loop_lag_seconds``.
    """
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    try:
        while True:
            t0 = time.monotonic()
            await asyncio.sleep(interval_seconds)
            elapsed = time.monotonic() - t0
            lag = max(0.0, elapsed - interval_seconds)
            record_loop_lag(lag, histogram=histogram)
    except asyncio.CancelledError:
        logger.debug("Event-loop lag monitor cancelled cleanly.")
        raise


@dataclass
class MetricsServerHandle:
    """Handle to a background Prometheus WSGI HTTP server started by :func:`start_metrics_http_server`."""

    port: int
    httpd: Any
    thread: threading.Thread | None

    def stop(self) -> None:
        """Shut down the underlying WSGI server and close its listening socket."""
        if self.httpd is not None:
            try:
                self.httpd.shutdown()
            except Exception as exc:  # pragma: no cover - defensive cleanup
                logger.debug("Metrics HTTP server shutdown error: %s", exc)
            try:
                self.httpd.server_close()
            except Exception as exc:  # pragma: no cover - defensive cleanup
                logger.debug("Metrics HTTP server close error: %s", exc)
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=2.0)


def start_metrics_http_server(
    port: int | None = None,
    addr: str = "0.0.0.0",  # nosec B104  # Prometheus scrape endpoint must bind container interface
) -> MetricsServerHandle | None:
    """Start the out-of-band Prometheus HTTP server on its own daemon thread.

    Reads ``CAGE_METRICS_PORT`` (default ``9090``) when ``port`` is ``None``.
    Returns ``None`` when ``port <= 0``, when ``prometheus_client`` is not
    installed, or when the port cannot be bound (logged as a warning so tests
    running multiple lifespans in one process do not crash).
    """
    if port is None:
        raw_port = os.getenv("CAGE_METRICS_PORT", str(DEFAULT_METRICS_PORT)).strip()
        try:
            port = int(raw_port)
        except ValueError:
            logger.warning(
                "Invalid CAGE_METRICS_PORT=%r; falling back to %d",
                raw_port,
                DEFAULT_METRICS_PORT,
            )
            port = DEFAULT_METRICS_PORT

    if port <= 0:
        logger.info(
            "Prometheus metrics HTTP server disabled (CAGE_METRICS_PORT=%d)", port
        )
        return None

    if start_http_server is None:
        logger.debug(
            "prometheus_client not available — skipping metrics HTTP server on port %d",
            port,
        )
        return None

    try:
        result = start_http_server(port, addr=addr)
    except OSError as exc:
        logger.warning(
            "⚠️ Could not bind Prometheus metrics server on %s:%d (%s) — continuing without dedicated metrics listener",
            addr,
            port,
            exc,
        )
        return None

    httpd: Any = None
    thread: threading.Thread | None = None
    if isinstance(result, tuple) and len(result) == 2:
        httpd, thread = result
    bound_port = int(getattr(httpd, "server_port", port) or port)
    logger.info(
        "✅ Prometheus metrics HTTP server listening on %s:%d",
        addr,
        bound_port,
    )
    return MetricsServerHandle(port=bound_port, httpd=httpd, thread=thread)
