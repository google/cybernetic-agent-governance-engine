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
metrics.py — Compliance metrics aggregation via Evidence Stream consumer.

Sprint 1.7: Evidence Stream as Primary Compliance Source (ADR-EV-001).
This module NO LONGER queries Langfuse. All compliance metrics are derived
from the hash-chained, KMS-signed Evidence Stream (cage-audit/3.0 schema).

Validation Criterion V-2: Zero Langfuse imports. All data sourced from
EvidenceStreamConsumer's minute-bucketed per-control index.

Historical context: Originally ported from src/langfuse-bridge/src/metrics.ts
(LRUCache → cachetools.TTLCache). As of v3.0.0, Langfuse is decoupled from
the compliance attestation path and used only for optional trace correlation
(evidence_id → Langfuse span reverse lookup).
"""

from __future__ import annotations

import logging

from .types import ComplianceMetrics

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API — delegate to Evidence Stream consumer
# ---------------------------------------------------------------------------


async def get_compliance_metrics(
    control_id: str,
    window_hours: int = 24,
) -> ComplianceMetrics:
    """
    Returns compliance metrics for the given control ID from the Evidence Stream.

    Zero Langfuse dependency (validation criterion V-2). All metrics are computed
    from the EvidenceStreamConsumer's windowed per-control index, which aggregates
    hash-chained evidence records (cage-audit/3.0 schema) in real-time.

    The consumer provides minute-bucketed counters to avoid per-request joins to
    external telemetry systems, ensuring sub-millisecond hot-path latency.

    Args:
        control_id:   ISO 42001 control ID, e.g. "A.5.2"
        window_hours: Look-back window for evidence aggregation (default: 24h)

    Returns:
        ComplianceMetrics — the exact JSON Lula's OPA Rego receives as `input`.
                           Now includes v3.0 fields: source="evidence_stream",
                           evidence_chain_verified (bool), chain_head_hash (str).
    """
    from .evidence_consumer import get_evidence_consumer

    consumer = get_evidence_consumer()
    metrics_dict = consumer.get_compliance_metrics(control_id, window_hours)
    return ComplianceMetrics(**metrics_dict)
