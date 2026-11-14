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

"""Prometheus metrics for the governor pipeline, on an explicit registry.

Collectors are created once per registry by :func:`governor_metrics`, so
assembling several governors in one process (tests, CLIs) never registers a
metric twice. Nothing is registered at import time.

``prometheus_client`` is optional: without it every recorder is a no-op.
"""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

try:
    from prometheus_client import REGISTRY, CollectorRegistry, Counter
except ImportError:  # pragma: no cover - exercised only without prometheus_client
    REGISTRY = None  # type: ignore[assignment]
    CollectorRegistry = Any  # type: ignore[misc, assignment]
    Counter = None  # type: ignore[misc, assignment]

GATED_REQUEST_OUTCOMES: tuple[str, str] = ("blocked", "permitted")

#: Per-request flag set when any in-band governance check decides a hard refusal
#: inside a request whose transport layer still returns HTTP 200 (for example,
#: MCP Streamable HTTP JSON-RPC tool calls, ``/tools/execute``, or
#: ``/governance/policy-precheck``). :class:`WorkloadIdentityMiddleware` reads
#: this flag on completion so protocol-wrapped refusals count as ``blocked``.
_REQUEST_REFUSED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cage_gateway_request_refused",
    default=False,
)


@contextmanager
def track_gated_request() -> Iterator[None]:
    """Scope per-request refusal tracking to one gated gateway request."""
    token = _REQUEST_REFUSED.set(False)
    try:
        yield
    finally:
        _REQUEST_REFUSED.reset(token)


def mark_request_refused() -> None:
    """Mark the currently executing gated gateway request as refused."""
    _REQUEST_REFUSED.set(True)


def was_request_refused() -> bool:
    """Return True if any governance check refused the current request."""
    return _REQUEST_REFUSED.get()


class GovernorMetrics:
    """Governor collectors bound to one registry. Build via :func:`governor_metrics`."""

    __slots__ = (
        "_evidence_publish_failures",
        "_ftra_boundary_checks",
        "_gated_requests",
        "_refusals",
    )

    def __init__(self, registry: CollectorRegistry | None) -> None:
        self._ftra_boundary_checks = (
            None
            if Counter is None or registry is None
            else Counter(
                "cage_ftra_boundary_checks_total",
                "Total number of FTRA boundary checks executed",
                ["result"],
                registry=registry,
            )
        )
        self._evidence_publish_failures = (
            None
            if Counter is None or registry is None
            else Counter(
                "cage_governance_evidence_publish_failures_total",
                "Refusal/deferral evidence records that failed to reach the evidence stream",
                ["kind"],
                registry=registry,
            )
        )
        self._refusals = (
            None
            if Counter is None or registry is None
            else Counter(
                "cage_governance_refusals_total",
                "Total hard governance refusals decided by the gateway",
                ["tier"],
                registry=registry,
            )
        )
        if Counter is None or registry is None:
            self._gated_requests = None
        else:
            self._gated_requests = Counter(
                "cage_gateway_gated_requests_total",
                "Total non-open HTTP and WebSocket requests handled at the gateway ingress boundary, partitioned by outcome",
                ["outcome"],
                registry=registry,
            )
            for outcome in GATED_REQUEST_OUTCOMES:
                self._gated_requests.labels(outcome=outcome)

    def evidence_publish_failure(self, kind: str) -> None:
        """Count one best-effort evidence write that failed (``refusal``, ``deferral``, etc.)."""
        if self._evidence_publish_failures is not None:
            self._evidence_publish_failures.labels(kind=kind).inc()

    def refusal_decided(self, tier: str) -> None:
        """Count one hard governance refusal under its lead tier."""
        mark_request_refused()
        if self._refusals is not None:
            self._refusals.labels(tier=tier or "SYMBOLIC_GOVERNOR").inc()

    def gated_request_completed(self, *, blocked: bool) -> None:
        """Count one completed non-open gateway request as ``blocked`` or ``permitted``."""
        if self._gated_requests is not None:
            self._gated_requests.labels(
                outcome="blocked" if blocked else "permitted"
            ).inc()

    def ftra_boundary_check(self, result: str) -> None:
        """Count one FTRA boundary check outcome (``passed``, ``conditional_clear``, ``hitl_required``, ``error``)."""
        if self._ftra_boundary_checks is not None:
            self._ftra_boundary_checks.labels(result=result).inc()


_lock = threading.Lock()
_by_registry: dict[int, tuple[Any, GovernorMetrics]] = {}


def governor_metrics(registry: CollectorRegistry | None = None) -> GovernorMetrics:
    """Return the :class:`GovernorMetrics` for ``registry`` (default: the global one)."""
    target = REGISTRY if registry is None else registry
    with _lock:
        entry = _by_registry.get(id(target))
        if entry is None or entry[0] is not target:
            entry = (target, GovernorMetrics(target))
            _by_registry[id(target)] = entry
        return entry[1]
