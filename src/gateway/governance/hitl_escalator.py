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

"""Human-in-the-loop escalator — AI 600-1 §2.5 control.

Routes governance decisions that exceed the consensus threshold or fall below
the confidence threshold to a human reviewer via the DeferQueue.

POAM: AI600-004
Controls: ConsensusGate (threshold USD 10,000), HITL escalation path
SR 26-2 §3.2: HITL SLA — escalations must be resolved within 4 hours (US_FED
only). EU_ECB and APAC_MAS deployments apply their own regional SLA — see
get_hitl_sla_hours() below and docs/governance/HUMAN_OVERSIGHT_SCOPE.md.

Usage::

    from src.gateway.governance.hitl_escalator import (
        EscalationReason, EscalationRequest, escalate_to_human
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
from typing import Any

from src.gateway.observability.attributes import (
    TRACE_METADATA_ISO_CONTROL_ID,
    TRACE_METADATA_ISO_REQUIREMENT,
    TRACE_METADATA_POAM_REF,
)

logger = logging.getLogger("Gateway.Governance.HITLEscalator")


# ---------------------------------------------------------------------------
# FINDING-09 (MEDIUM) — Jurisdictional HITL SLA / regulatory citation
#
# This module previously declared "Region: US_FED" in its docstring only,
# with no runtime CAGE_DEPLOYMENT_REGION check. The SR 26-2 §3.2 4-hour SLA
# is a US Federal Reserve requirement with no legal force outside US_FED.
# get_hitl_sla_hours() / get_hitl_regulatory_citation() resolve the correct
# region-specific value at call time. The citation strings themselves live
# in constants.py (HITL_CITATIONS / HITL_SLA_HOURS), which is intentionally
# excluded from the "no hardcoded regulatory strings" architecture guardrail
# (see tests/test_governance_architecture.py).
# ---------------------------------------------------------------------------


def _get_region() -> str:
    return os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()


def get_hitl_sla_hours(region: str | None = None) -> float:
    """Return the HITL resolution SLA, in hours, for the active region.

    Args:
        region: CAGE_DEPLOYMENT_REGION value. If None, reads from the
                environment. One of "US_FED", "EU_ECB", "APAC_MAS".

    Returns:
        4.0 for US_FED (SR 26-2 §3.2), 2.0 for EU_ECB (DORA Art. 10),
        1.0 for APAC_MAS (MAS FEAT §3.2), 4.0 (ISO 42001 §A.8.4 fallback)
        for any other/unset region.
    """
    from src.gateway.governance.constants import HITL_SLA_HOURS, HITL_SLA_HOURS_DEFAULT

    active_region = (region or _get_region()).strip().upper()
    return HITL_SLA_HOURS.get(active_region, HITL_SLA_HOURS_DEFAULT)


def get_hitl_regulatory_citation(region: str | None = None) -> str:
    """Return the jurisdiction-specific HITL regulatory citation.

    Args:
        region: CAGE_DEPLOYMENT_REGION value. If None, reads from the
                environment. One of "US_FED", "EU_ECB", "APAC_MAS".

    Returns:
        The regulatory authority citation string for the active region, or
        the universal ISO 42001 §A.8.4 citation if the region is unset or
        unrecognised.
    """
    from src.gateway.governance.constants import HITL_CITATION_DEFAULT, HITL_CITATIONS

    active_region = (region or _get_region()).strip().upper()
    return HITL_CITATIONS.get(active_region, HITL_CITATION_DEFAULT)


# ---------------------------------------------------------------------------
# EscalationReason — why the request was escalated to human review
# ---------------------------------------------------------------------------


class EscalationReason(Enum):
    """Enumeration of reasons for HITL escalation.

    Maps to AI 600-1 §2.5 Human-AI Configuration controls.
    """

    CONSENSUS_THRESHOLD = "consensus_threshold_exceeded"
    """ConsensusGate: amount_usd > CONSENSUS_THRESHOLD_USD (default USD 10,000)."""

    CONFIDENCE_LOW = "confidence_below_threshold"
    """Confabulation scorer: confidence < CONFIDENCE_MIN_SCORE (default 0.95)."""

    CAUSAL_BLOCK = "causal_gatekeeper_block"
    """CausalGatekeeper: world-model untrustworthy (p-value < 0.05 or placebo > 0.2)."""

    MANUAL_REVIEW = "manual_review_requested"
    """Explicit manual review request from OPA policy (MANUAL_REVIEW decision)."""

    GOVERNANCE_CONFIDENCE_LOW = "governance_layer_confidence_below_threshold"
    """Recursive governance risk: ConsensusGate's own LLM call has low confidence."""


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
    amount_usd: float | None = None
    confidence: float | None = None
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
    amount_usd: float | None
    confidence: float | None
    reviewer_queue: str
    status: str
    timestamp: str = field(
        default_factory=lambda: (
            datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        )
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


def should_escalate_for_consensus(
    amount_usd: float, threshold_usd: float = 10000.0
) -> bool:
    """Return True if the amount exceeds the consensus threshold.

    Args:
        amount_usd:    Trade amount in USD.
        threshold_usd: Consensus threshold (default USD 10,000 per US_FED baseline).

    Returns:
        True if ``amount_usd > threshold_usd``, False otherwise.
    """
    return amount_usd > threshold_usd


def should_escalate_for_confidence(confidence: float, threshold: float = 0.95) -> bool:
    """Return True if the confidence score is below the escalation threshold.

    Args:
        confidence: Model self-reported confidence score [0.0, 1.0].
        threshold:  Confidence threshold (default 0.95 per CTRL_AGT_001).

    Returns:
        True if ``confidence < threshold``, False otherwise.
    """
    return confidence < threshold


# ---------------------------------------------------------------------------
# hitl_override_audit_span — AI600-005 human override audit trail
# ---------------------------------------------------------------------------


def hitl_override_audit_span(
    trace_id: str,
    reviewer_id: str,
    decision: str,
    original_escalation_reason: str,
    reason: str = "",
    region: str | None = None,
) -> dict[str, Any]:
    """Emit a structured OTel span recording a human override decision.

    Called when a human reviewer resolves a pending HITL escalation. Persists
    an immutable evidence trail for ISO 42001 §A.8.4 / AI 600-1 §2.5, with a
    jurisdiction-specific regulatory citation attached via
    ``get_hitl_regulatory_citation()``.

    Args:
        trace_id:                   Langfuse trace ID of the governed request.
        reviewer_id:                Pseudonymised reviewer identifier.
        decision:                   One of "OVERRIDE", "UPHOLD", "DEFER".
        original_escalation_reason: The ``EscalationReason.value`` that
                                     triggered the original escalation.
        reason:                     Free-text justification (\u2264500 chars).
        region:                     CAGE_DEPLOYMENT_REGION value. If None,
                                     reads from the environment.

    Returns:
        The dict of attributes stamped onto the current OTel span (also
        returned for callers that want to inspect / log it directly).
    """
    _ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    citation = get_hitl_regulatory_citation(region)
    truncated_reason = reason[:500]

    attributes: dict[str, Any] = {
        "hitl.reviewer_id": reviewer_id,
        "hitl.decision": decision,
        "hitl.reason": truncated_reason,
        "hitl.original_escalation_reason": original_escalation_reason,
        "hitl.override_ts": _ts,
        "hitl.trace_id": trace_id,
        "hitl.regulatory_citation": citation,
        TRACE_METADATA_ISO_CONTROL_ID: "A.8.4",
        TRACE_METADATA_ISO_REQUIREMENT: "Human Oversight and Control",
        TRACE_METADATA_POAM_REF: "AI600-005",
    }

    try:
        from opentelemetry import trace as _otel_trace

        span = _otel_trace.get_current_span()
        if span is not None:
            for key, value in attributes.items():
                span.set_attribute(key, value)
    except Exception as exc:  # pragma: no cover — OTel must never break HITL flow
        logger.debug("hitl_override_audit_span: OTel stamping skipped: %s", exc)

    logger.info(
        "\u2696\ufe0f HITL override: trace_id=%s reviewer_id=%s decision=%s "
        "original_reason=%s citation=%s",
        trace_id,
        reviewer_id,
        decision,
        original_escalation_reason,
        citation,
    )

    return attributes
