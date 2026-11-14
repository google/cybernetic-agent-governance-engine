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
_REQUEST_EVIDENCED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cage_gateway_request_evidenced",
    default=False,
)


@contextmanager
def track_gated_request() -> Iterator[None]:
    """Scope per-request refusal and evidence-obligation tracking to one gated gateway request."""
    refused_token = _REQUEST_REFUSED.set(False)
    evidenced_token = _REQUEST_EVIDENCED.set(False)
    try:
        yield
    finally:
        _REQUEST_EVIDENCED.reset(evidenced_token)
        _REQUEST_REFUSED.reset(refused_token)


def mark_request_refused() -> None:
    """Mark the currently executing gated gateway request as refused."""
    _REQUEST_REFUSED.set(True)


def was_request_refused() -> bool:
    """Return True if any governance check refused the current request."""
    return _REQUEST_REFUSED.get()


def mark_request_evidenced() -> None:
    """Mark the current gated request as obligated to append at least one evidence record."""
    _REQUEST_EVIDENCED.set(True)


def was_request_evidenced() -> bool:
    """Return True if the current gated request entered an evidence-obligated governance path."""
    return _REQUEST_EVIDENCED.get()


class GovernorMetrics:
    """Governor collectors bound to one registry. Build via :func:`governor_metrics`."""

    __slots__ = (
        "_canary_requests",
        "_evidence_publish_failures",
        "_evidence_records_appended",
        "_evidenced_requests_permitted",
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
                "Refusal/deferral/pass evidence records that failed to reach the evidence stream",
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
            self._canary_requests = None
            self._evidence_records_appended = None
            self._evidenced_requests_permitted = None
        else:
            self._gated_requests = Counter(
                "cage_gateway_gated_requests_total",
                "Total non-open HTTP and WebSocket requests handled at the gateway ingress boundary, partitioned by outcome",
                ["outcome"],
                registry=registry,
            )
            self._canary_requests = Counter(
                "cage_gateway_canary_requests_total",
                "Total synthetic in-mesh canary requests handled at the gateway ingress boundary, partitioned by outcome",
                ["outcome"],
                registry=registry,
            )
            self._evidence_records_appended = Counter(
                "cage_gateway_evidence_records_appended_total",
                "Total evidence records durably acknowledged by Redis XADD on the gateway evidence stream",
                registry=registry,
            )
            self._evidenced_requests_permitted = Counter(
                "cage_gateway_evidenced_requests_permitted_total",
                "Total permitted gateway requests on routes or actions obligated to append at least one evidence record",
                registry=registry,
            )
            for outcome in GATED_REQUEST_OUTCOMES:
                self._gated_requests.labels(outcome=outcome)
                self._canary_requests.labels(outcome=outcome)

    def evidence_publish_failure(self, kind: str) -> None:
        """Count one evidence write that failed (``refusal``, ``seal_consumed``, ``inference_proxy_pass``, etc.)."""
        if self._evidence_publish_failures is not None:
            self._evidence_publish_failures.labels(kind=kind).inc()

    def evidence_records_appended(self, count: int = 1) -> None:
        """Count ``count`` records durably acknowledged on ``cage:evidence:stream``."""
        if count > 0 and self._evidence_records_appended is not None:
            self._evidence_records_appended.inc(count)

    def refusal_decided(self, tier: str) -> None:
        """Count one hard governance refusal under its lead tier."""
        mark_request_refused()
        if self._refusals is not None:
            self._refusals.labels(tier=tier or "SYMBOLIC_GOVERNOR").inc()

    def gated_request_completed(
        self,
        *,
        blocked: bool,
        canary: bool = False,
        evidenced: bool = False,
    ) -> None:
        """Count one completed non-open gateway request as ``blocked`` or ``permitted``."""
        outcome = "blocked" if blocked else "permitted"
        if self._gated_requests is not None:
            self._gated_requests.labels(outcome=outcome).inc()
        if canary and self._canary_requests is not None:
            self._canary_requests.labels(outcome=outcome).inc()
        if not blocked and evidenced and self._evidenced_requests_permitted is not None:
            self._evidenced_requests_permitted.inc()

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
