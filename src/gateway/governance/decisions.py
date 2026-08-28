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
decisions.py — Canonical Governance Decision Vocabulary (CAGE v0.1.1)

This module defines the single authoritative four-state decision enum that
MUST be used at every CAGE gateway boundary: validate_action() return values,
HTTP response bodies, audit events, provenance records, and client adapters.

Background
----------
Prior to CAGE v0.1.1, governance decisions were expressed with at least five
overlapping vocabularies across layers:

  Layer                   | Vocabulary
  ------------------------|------------------------------------------
  OPA policy              | ALLOW / DENY / MANUAL_REVIEW
  normative_provider.py   | ALLOW / DENY / DEFER
  validate_action() return| APPROVED (only; MANUAL_REVIEW never returned)
  adapter HTTP body       | APPROVED / DENIED / DEFERRED
  provenance_chain.py     | ALLOW / BLOCK / ESCALATE

This caused:
  1. MANUAL_REVIEW and DEFER to collapse into the same HTTP 202 "DEFERRED"
     body, making it impossible for clients to distinguish a human-approval
     request from a context-hydration deferral.
  2. The MANUAL_REVIEW branch in handle_check_request() to be dead code
     because validate_action() never returned that string.
  3. Provenance records to be unrecordable for MANUAL_REVIEW and DEFER
     decisions (ValueError from VALID_DECISIONS check).

Canonical four-state model
--------------------------
  ALLOW            — action is approved; routing seal issued.
  DENY             — action is blocked; no seal issued.
  REQUIRE_APPROVAL — action is understood but requires human sign-off before
                     execution. Routes to HITL approval queue.
                     (Previously surfaced as MANUAL_REVIEW internally and
                     DEFERRED externally — now preserved end-to-end.)
  DEFER            — action cannot be evaluated; trusted context or evidence
                     is missing. Routes to DeferQueue for automated
                     data-hydration, NOT human triage.
                     (Previously collapsed into DEFERRED alongside
                     REQUIRE_APPROVAL — now structurally distinct.)

Internal-to-canonical mapping
------------------------------
  OPA "MANUAL_REVIEW"  → GovernanceDecision.REQUIRE_APPROVAL
  OPA "ALLOW"          → GovernanceDecision.ALLOW
  OPA "DENY"           → GovernanceDecision.DENY
  normative "DEFER"    → GovernanceDecision.DEFER

Workflow/execution statuses (NOT policy decisions)
--------------------------------------------------
  APPROVED, BLOCKED, ESCALATED — these are execution-phase status values
  used inside LangGraph nodes and the provenance chain. They are NOT
  canonical policy decisions and must not appear in gateway HTTP responses.

ISO 42001 mapping: A.8.4 (AI System Operation Controls)
AARM mapping: CSA AARM-V7 "Context Window Overflow" (DEFER path)
"""

from __future__ import annotations

from enum import Enum
from typing import Literal


class GovernanceDecision(str, Enum):
    """Canonical five-state governance decision vocabulary for the CAGE gateway boundary.

    This enum MUST be used for:
      - validate_action() return values (``verdict`` key)
      - HTTP response body ``verdict`` fields in agent_gateway_adapter.py
      - Audit event ``verdict`` fields in _emit_audit_event()
      - Provenance chain ``decision`` fields

    It MUST NOT be used for:
      - Internal OPA policy strings (those remain ALLOW/DENY/MANUAL_REVIEW
        and are translated at the validate_action() boundary)
      - LangGraph node execution statuses (APPROVED/BLOCKED/ESCALATED)
    """

    ALLOW = "ALLOW"
    """Action is approved. Routing seal issued. Downstream actuator may execute."""

    DENY = "DENY"
    """Action is blocked. No routing seal issued. Violation details included."""

    PAUSE = "PAUSE"
    """Action is temporarily suspended awaiting an external resume signal.

    Unlike DEFER (which queues for automated data-hydration), PAUSE suspends
    execution waiting for an explicit resume API call. Useful for:
      - Rate limiting (soft, will clear with time)
      - Circuit breaker open (external dependency unavailable)
      - Coordination wait (cross-agent synchronization)
      - Resource temporarily unavailable

    HTTP response: 503 Service Unavailable with Retry-After header.
    Response body includes:
      - pause_token: UUID for resuming via POST /v1/pause/{pause_token}/resume
      - pause_reason: Enum-style reason code (RATE_LIMITED, CIRCUIT_OPEN, etc.)
      - expires_at: ISO-8601 UTC timestamp when pause expires (auto-deny)
      - estimated_wait_seconds: Optional hint for client polling

    Client action: Call POST /v1/pause/{pause_token}/resume when ready to proceed,
    or wait for timeout (which results in auto-deny).

    Feature flag: CAGE_PAUSE_ENABLED (default: false — opt-in).
    When disabled, PAUSE candidates fall back to DENY.

    Control mapping: CTRL_PAUSE_001 (see config/control_mappings.json)
    """

    NARROW = "NARROW"
    """Action is allowed but with constrained/clamped parameters.

    The requested action exceeds soft thresholds but is not a hard violation.
    Instead of denying, the system narrows the scope to fit within allowed
    parameters. The action semantics are preserved (clamped, not transformed).

    Examples:
      - amount > max_allowed → clamp to max_allowed
      - scope: ["read", "write", "delete"] with only ["read", "write"] allowed
        → narrow to allowed scope
      - date_range: 365 days with max 90 days → narrow to 90 days

    HTTP response: 200 OK with ``verdict: NARROW``, ``original_params``,
    ``narrowed_params``, and ``X-Governance-Narrowed: true`` header.
    Client action: proceed with narrowed parameters.

    Feature flag: CAGE_NARROW_ENABLED (default: false — opt-in).
    When disabled, NARROW candidates fall back to DEFER or DENY.

    Control mapping: CTRL_NARROW_001 (see config/control_mappings.json)
    """

    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    """Action is understood but requires explicit human sign-off before execution.

    The action context is complete and evaluable — a human operator must
    review and approve it. Routes to the HITL approval queue.

    HTTP response: 202 with ``verdict: REQUIRE_APPROVAL`` and ``thread_id``.
    Client action: poll GET /v1/approvals/pending for the outcome.

    Corresponds to OPA internal decision ``MANUAL_REVIEW``.
    """

    DEFER = "DEFER"
    """Action cannot be evaluated because trusted context or evidence is missing.

    The action context is incomplete, ambiguous, or below the
    Confidence-Starvation Boundary (default: 0.70). Routing to human review
    at this confidence level creates operational fatigue — instead, the
    execution context is parked in the DeferQueue for automated data-hydration.

    HTTP response: 202 with ``verdict: DEFER``, ``defer_id``, and
    ``missing_input_reason``.
    Client action: poll GET /v1/defer/pending for the outcome.

    Corresponds to DeferReason.CONFIDENCE_BELOW_THRESHOLD and related reasons
    in defer_queue.py. See UCA-7 in ontology.py.
    """


# ---------------------------------------------------------------------------
# OPA internal → canonical translation table
# ---------------------------------------------------------------------------

#: Maps OPA policy decision strings to canonical GovernanceDecision values.
#: Used by validate_action() to translate internal OPA results to the
#: canonical vocabulary before returning to callers.
OPA_TO_CANONICAL: dict[str, GovernanceDecision] = {
    "ALLOW": GovernanceDecision.ALLOW,
    "DENY": GovernanceDecision.DENY,
    "MANUAL_REVIEW": GovernanceDecision.REQUIRE_APPROVAL,
}


# ---------------------------------------------------------------------------
# DeferResponse — HTTP response model for DEFER decisions
# ---------------------------------------------------------------------------


from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DeferResponse(BaseModel):
    """Pydantic model for DEFER decision HTTP response serialization.

    Used by agent_gateway_adapter.py to serialize DEFER responses with
    consistent structure. HTTP 202 Accepted is returned for DEFER.

    Fields:
        decision:              Always "DEFER" for this model.
        classification_reason: Human-readable explanation of why deferred.
        deferrable:            Always True for DEFER decisions.
        violations:            List of soft violations that triggered deferral.
        defer_token:           UUID v4 token for later resume capability.
        retry_after_seconds:   Suggested retry interval (default 300s = 5 minutes).
        missing_input_reason:  Legacy field for backward compatibility.
        defer_reason:          Enum-style reason code (e.g. CONFIDENCE_BELOW_THRESHOLD).

    ISO 42001 mapping: A.8.4 (AI System Operation Controls)
    AARM mapping: CSA AARM-V7 "Context Window Overflow" (DEFER path)
    """

    decision: str = Field(default="DEFER", description="Always DEFER for this model")
    classification_reason: str = Field(
        default="",
        description="Human-readable explanation of why the request was deferred",
    )
    deferrable: bool = Field(
        default=True,
        description="Always True for DEFER — violations are soft/deferrable",
    )
    violations: list[str] = Field(
        default_factory=list,
        description="List of soft violations that triggered deferral",
    )
    defer_token: str = Field(
        default="",
        description="UUID v4 token for resuming/querying deferred request",
    )
    retry_after_seconds: int = Field(
        default=300,
        description="Suggested retry interval in seconds (default 5 minutes)",
    )
    defer_reason: str = Field(
        default="CONFIDENCE_BELOW_THRESHOLD",
        description="Enum-style reason code for the deferral",
    )

    def to_http_body(self) -> dict[str, Any]:
        """Serialize to HTTP response body dict.

        Returns:
            Dict suitable for JSON serialization in HTTP 202 response.
        """
        return {
            "decision": self.decision,
            "classification_reason": self.classification_reason,
            "deferrable": self.deferrable,
            "violations": self.violations,
            "defer_token": self.defer_token,
            "retry_after_seconds": self.retry_after_seconds,
        }


# ---------------------------------------------------------------------------
# NarrowResponse — HTTP response model for NARROW decisions
# ---------------------------------------------------------------------------


class NarrowResponse(BaseModel):
    """Pydantic model for NARROW decision HTTP response serialization.

    Used by agent_gateway_adapter.py to serialize NARROW responses with
    consistent structure. HTTP 200 OK is returned for NARROW (action is
    allowed but with constrained parameters).

    The NARROW primitive allows partial-authority/clamped execution when a
    request exceeds certain soft thresholds but is not a hard violation.
    Instead of denying, the system narrows the scope of the action to fit
    within allowed parameters while preserving action semantics.

    Fields:
        decision:            Always "NARROW" for this model.
        original_params:     The original parameters as submitted by the agent.
        narrowed_params:     The constrained parameters that will be executed.
        narrowing_reason:    Human-readable explanation of why narrowed.
        constraints_applied: List of constraint descriptions applied.
        execution_allowed:   Always True for NARROW — action proceeds with
                             narrowed params.

    Examples:
        - amount > max_allowed → clamp to max_allowed
        - scope: ["read", "write", "delete"] with only ["read", "write"] allowed
          → narrow to allowed scope
        - date_range: 365 days with max 90 days → narrow to 90 days

    Feature flag: CAGE_NARROW_ENABLED (default: false — opt-in).
    When disabled, NARROW candidates fall back to DEFER or DENY.

    ISO 42001 mapping: A.8.4 (AI System Operation Controls)
    """

    decision: Literal["NARROW"] = Field(
        default="NARROW",
        description="Always NARROW for this model",
    )
    original_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Original parameters as submitted by the agent",
    )
    narrowed_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Constrained parameters that will be executed",
    )
    narrowing_reason: str = Field(
        default="",
        description="Human-readable explanation of why parameters were narrowed",
    )
    constraints_applied: list[str] = Field(
        default_factory=list,
        description="List of constraint descriptions applied to narrow the request",
    )
    execution_allowed: bool = Field(
        default=True,
        description="Always True for NARROW — action proceeds with narrowed params",
    )

    def to_http_body(self) -> dict[str, Any]:
        """Serialize to HTTP response body dict.

        Returns:
            Dict suitable for JSON serialization in HTTP 200 response.
        """
        return {
            "decision": self.decision,
            "original_params": self.original_params,
            "narrowed_params": self.narrowed_params,
            "narrowing_reason": self.narrowing_reason,
            "constraints_applied": self.constraints_applied,
            "execution_allowed": self.execution_allowed,
            # Canonical verdict field for consistency with other decisions
            "verdict": GovernanceDecision.NARROW,
        }


# ---------------------------------------------------------------------------
# PauseResponse — HTTP response model for PAUSE decisions
# ---------------------------------------------------------------------------


class PauseResponse(BaseModel):
    """Pydantic model for PAUSE decision HTTP response serialization.

    Used by agent_gateway_adapter.py to serialize PAUSE responses with
    consistent structure. HTTP 503 Service Unavailable is returned for PAUSE.

    The PAUSE primitive allows resumable suspension of action execution.
    Unlike DEFER (which queues for human review or data-hydration), PAUSE
    suspends execution waiting for an external signal to resume — useful for
    rate limiting, circuit breaking, or coordination scenarios.

    Fields:
        decision:               Always "PAUSE" for this model.
        pause_token:            UUID v4 token for resuming via POST
                                /v1/pause/{pause_token}/resume.
        pause_reason:           Enum-style reason code (RATE_LIMITED,
                                CIRCUIT_OPEN, COORDINATION_WAIT, etc.).
        resume_endpoint:        URL path to resume the paused request.
        expires_at:             ISO-8601 UTC timestamp when pause expires
                                (auto-deny if not resumed by this time).
        estimated_wait_seconds: Optional hint for client polling/retry.
        retry_after_seconds:    Seconds until client should retry (maps to
                                HTTP Retry-After header).

    Feature flag: CAGE_PAUSE_ENABLED (default: false — opt-in).
    When disabled, PAUSE candidates fall back to DENY.

    ISO 42001 mapping: A.8.4 (AI System Operation Controls)
    """

    decision: Literal["PAUSE"] = Field(
        default="PAUSE",
        description="Always PAUSE for this model",
    )
    pause_token: str = Field(
        ...,
        description="UUID v4 token for resuming the paused request",
    )
    pause_reason: str = Field(
        ...,
        description="Reason code for the pause (RATE_LIMITED, CIRCUIT_OPEN, etc.)",
    )
    resume_endpoint: str = Field(
        ...,
        description="URL path to resume the paused request",
    )
    expires_at: datetime = Field(
        ...,
        description="ISO-8601 UTC timestamp when pause expires (auto-deny)",
    )
    estimated_wait_seconds: int | None = Field(
        default=None,
        description="Optional hint for client polling/retry interval",
    )
    retry_after_seconds: int = Field(
        default=60,
        description="Seconds until client should retry (HTTP Retry-After header)",
    )

    def to_http_body(self) -> dict[str, Any]:
        """Serialize to HTTP response body dict.

        Returns:
            Dict suitable for JSON serialization in HTTP 503 response.
        """
        return {
            "decision": self.decision,
            "pause_token": self.pause_token,
            "pause_reason": self.pause_reason,
            "resume_endpoint": self.resume_endpoint,
            "expires_at": self.expires_at.isoformat(),
            "estimated_wait_seconds": self.estimated_wait_seconds,
            "retry_after_seconds": self.retry_after_seconds,
            # Canonical verdict field for consistency with other decisions
            "verdict": GovernanceDecision.PAUSE,
        }
