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

import threading
from typing import Any

try:
    from prometheus_client import REGISTRY, CollectorRegistry, Counter
except ImportError:  # pragma: no cover - exercised only without prometheus_client
    REGISTRY = None
    CollectorRegistry = Any  # type: ignore[misc, assignment]
    Counter = None  # type: ignore[misc, assignment]


class GovernorMetrics:
    """Governor collectors bound to one registry. Build via :func:`governor_metrics`."""

    __slots__ = ("_ftra_boundary_checks",)

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

    def ftra_boundary_check(self, result: str) -> None:
        """Count one FTRA boundary check outcome (``passed``, ``hitl_required``, ``error``)."""
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
