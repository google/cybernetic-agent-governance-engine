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

"""Human-in-the-loop escalator — ISO 42001 A.8.4 universal control.

Routes governance decisions that exceed the consensus threshold or fall below
the confidence threshold to a human reviewer via the DeferQueue.

POAM: AI600-004
Controls: ConsensusEngine (threshold USD 10,000), HITL escalation path

FINDING-09 (MEDIUM): This module previously declared "Region: US_FED" in its
docstring but contained no runtime CAGE_DEPLOYMENT_REGION check.  The SR 26-2
§3.2 HITL SLA of 4 hours is a US Federal Reserve requirement applied universally.

Correct behaviour (R-2):
  - HITL escalation itself is universal (ISO 42001 A.8.4 human oversight).
  - SR 26-2 §3.2 SLA enforcement (4-hour resolution) is US_FED only.
  - EU_ECB applies DORA Art. 10 HITL requirements.
  - APAC_MAS applies MAS FEAT §3.2 requirements.

The get_hitl_sla_hours(region) function returns the applicable SLA for the
active deployment region.  Callers must use this instead of hardcoding 4 hours.

Usage::

    from src.gateway.governance.hitl_escalator import (
        EscalationReason, EscalationRequest, escalate_to_human,
        get_hitl_sla_hours,
    )

    request = EscalationRequest(
        trace_id="trace-123",
        reason=EscalationReason.CONSENSUS_THRESHOLD,
        amount_usd=15000.0,
        confidence=None,
        reviewer_queue="compliance-review",
    )
    record = escalate_to_human(request)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------------------
# FINDING-09 (MEDIUM) — Jurisdictional HITL SLA map
#
# SR 26-2 §3.2 (4-hour HITL SLA) is a US Federal Reserve requirement.
# It has no legal force outside US_FED (per .clinerules §12.4).
# EU_ECB and APAC_MAS have different HITL requirements.
# ---------------------------------------------------------------------------

_HITL_SLA_HOURS: dict[str, float] = {
    "US_FED":   4.0,   # SR 26-2 §3.2 — Federal Reserve supervisory guidance
    "EU_ECB":   2.0,   # DORA Art. 10 — ICT incident management (major incidents)
    "APAC_MAS": 1.0,   # MAS FEAT §3.2 — human oversight of AI decisions
}
_HITL_SLA_HOURS_DEFAULT = 4.0  # ISO 42001 A.8.4 universal fallback


def get_hitl_sla_hours(region: str | None = None) -> float:
    """Return the applicable HITL SLA in hours for the given deployment region.

    FINDING-09: SR 26-2 §3.2 (4-hour SLA) is US_FED only.  EU_ECB applies
    DORA Art. 10; APAC_MAS applies MAS FEAT §3.2.

    Args:
        region: CAGE_DEPLOYMENT_REGION value.  If None, reads from environment.

    Returns:
        Maximum hours within which a HITL escalation must be resolved.
    """
    active_region = region if region is not None else os.environ.get(
        "CAGE_DEPLOYMENT_REGION", ""
    ).strip().upper()
    return _HITL_SLA_HOURS.get(active_region, _HITL_SLA_HOURS_DEFAULT)

logger = logging.getLogger("Gateway.Governance.HITLEscalator")


# ---------------------------------------------------------------------------
# EscalationReason — why the request was escalated to human review
# ---------------------------------------------------------------------------

class EscalationReason(Enum):
    """Enumeration of reasons for HITL escalation.

    Maps to AI 600-1 §2.5 Human-AI Configuration controls.
    """

    CONSENSUS_THRESHOLD = "consensus_threshold_exceeded"
    """ConsensusEngine: amount_usd > CONSENSUS_THRESHOLD_USD (default USD 10,000)."""

    CONFIDENCE_LOW = "confidence_below_threshold"
    """Confabulation scorer: confidence < CONFIDENCE_MIN_SCORE (default 0.95)."""

    CAUSAL_BLOCK = "causal_gatekeeper_block"
    """CausalGatekeeper: world-model untrustworthy (p-value < 0.05 or placebo > 0.2)."""

    MANUAL_REVIEW = "manual_review_requested"
    """Explicit manual review request from OPA policy (MANUAL_REVIEW decision)."""

    GOVERNANCE_CONFIDENCE_LOW = "governance_layer_confidence_below_threshold"
    """Recursive governance risk: ConsensusEngine's own LLM call has low confidence."""


# ---------------------------------------------------------------------------
# EscalationRequest — structured escalation request
# ---------------------------------------------------------------------------

@dataclass
class EscalationRequest:
    """Structured request for HITL escalation.

    Attributes:
        trace_id:       Langfuse trace ID for the governed request.
        reason:         Why the request is being escalated (EscalationReason).
        amount_usd:     Trade amount in USD, if applicable.
        confidence:     Model confidence score, if applicable.
        reviewer_queue: Target queue for the human reviewer
                        (e.g. "compliance-review" or "security-review").
    """

    trace_id: str
    reason: EscalationReason
    amount_usd: Optional[float] = None
    confidence: Optional[float] = None
    reviewer_queue: str = "compliance-review"


# ---------------------------------------------------------------------------
# EscalationRecord — the persisted escalation record
# ---------------------------------------------------------------------------

@dataclass
class EscalationRecord:
    """Persisted HITL escalation record written to the DeferQueue.

    Attributes:
        event:          Always "hitl_escalation".
        trace_id:       Langfuse trace ID.
        reason:         Escalation reason string (from EscalationReason.value).
        amount_usd:     Trade amount in USD, or None.
        confidence:     Model confidence score, or None.
        reviewer_queue: Target reviewer queue.
        status:         Always "pending_review" at creation time.
        timestamp:      ISO 8601 UTC timestamp of escalation.
    """

    event: str
    trace_id: str
    reason: str
    amount_usd: Optional[float]
    confidence: Optional[float]
    reviewer_queue: str
    status: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    )


# ---------------------------------------------------------------------------
# escalate_to_human — main escalation function
# ---------------------------------------------------------------------------

def escalate_to_human(request: EscalationRequest) -> dict:
    """Create and return an escalation record for the HITL queue.

    Builds a structured escalation record and logs it. In production, the
    caller is responsible for writing the record to the DeferQueue
    (``src/gateway/governance/defer_queue.py``).

    Args:
        request: An ``EscalationRequest`` describing why escalation is needed.

    Returns:
        A dict representing the escalation record, suitable for writing to
        the DeferQueue or Pub/Sub topic (``governance-hitl-escalations``).
        Schema:
        {
            "event": "hitl_escalation",
            "trace_id": str,
            "reason": str,
            "amount_usd": float | None,
            "confidence": float | None,
            "reviewer_queue": str,
            "status": "pending_review",
            "timestamp": str,  # ISO 8601 UTC
        }
    """
    _ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    record = {
        "event": "hitl_escalation",
        "trace_id": request.trace_id,
        "reason": request.reason.value,
        "amount_usd": request.amount_usd,
        "confidence": request.confidence,
        "reviewer_queue": request.reviewer_queue,
        "status": "pending_review",
        "timestamp": _ts,
        "escalated_at": _ts,
    }

    logger.warning(
        "🔔 HITL escalation: trace_id=%s reason=%s amount_usd=%s confidence=%s queue=%s",
        request.trace_id,
        request.reason.value,
        f"${request.amount_usd:,.2f}" if request.amount_usd is not None else "N/A",
        f"{request.confidence:.3f}" if request.confidence is not None else "N/A",
        request.reviewer_queue,
    )

    return record


def should_escalate_for_consensus(amount_usd: float, threshold_usd: float = 10000.0) -> bool:
    """Return True if the amount exceeds the consensus threshold.

    Args:
        amount_usd:    Trade amount in USD.
        threshold_usd: Consensus threshold (default USD 10,000 per US_FED baseline).

    Returns:
        True if ``amount_usd > threshold_usd``, False otherwise.
    """
    return amount_usd > threshold_usd


def get_hitl_regulatory_citation(region: str | None = None) -> str:
    """Return the applicable HITL regulatory citation for the given region.

    FINDING-09: SR 26-2 §3.2 has no legal force outside US_FED.

    Args:
        region: CAGE_DEPLOYMENT_REGION value.  If None, reads from environment.

    Returns:
        Regulatory citation string for the applicable HITL requirement.
    """
    _HITL_CITATIONS: dict[str, str] = {
        "US_FED":   "SR 26-2 §3.2 (Federal Reserve HITL SLA — 4 hours)",
        "EU_ECB":   "DORA Art. 10 (ICT incident management — 2 hours for major incidents)",
        "APAC_MAS": "MAS FEAT §3.2 (human oversight of AI decisions — 1 hour)",
    }
    active_region = region if region is not None else os.environ.get(
        "CAGE_DEPLOYMENT_REGION", ""
    ).strip().upper()
    return _HITL_CITATIONS.get(active_region, "ISO 42001 A.8.4 (AI system operation controls)")


def should_escalate_for_confidence(
    confidence: float, threshold: float = 0.95
) -> bool:
    """Return True if the confidence score is below the escalation threshold.

    Args:
        confidence: Model self-reported confidence score [0.0, 1.0].
        threshold:  Confidence threshold (default 0.95 per CTRL_AGT_001).

    Returns:
        True if ``confidence < threshold``, False otherwise.
    """
    return confidence < threshold
