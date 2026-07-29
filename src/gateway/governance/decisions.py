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


class GovernanceDecision(str, Enum):
    """Canonical four-state governance decision vocabulary for the CAGE gateway boundary.

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
