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
CAGE Gateway Client SDK Exception Hierarchy.

This module defines the exception types raised by the CAGE Client SDK when
interacting with the governance gateway. All exceptions are designed to
provide structured, machine-readable error details that enable LLM-based
agents to perform self-correction and replanning.
"""

from datetime import datetime
from typing import Any


class CageGatewayError(Exception):
    """
    Base exception for all CAGE Gateway client errors.

    All exceptions raised by the CAGE Client SDK inherit from this base class,
    enabling clients to catch all gateway-related errors with a single handler.
    """

    pass


class PolicyViolationException(CageGatewayError):
    """
    Raised when a proposed action violates governance policy.

    This exception provides structured violation details that enable LLM-based
    agents to understand why the action was rejected and replan accordingly.
    The `recoverable` flag indicates whether the agent should attempt to
    reformulate the request or abandon the task entirely.

    Attributes:
        reason_code: Machine-readable violation code (e.g., "TIER_3_BLOCKED",
            "CBF_UNSAFE", "FTRA_REACHABILITY_DENIED").
        violation_details: Structured dictionary containing:
            - 'failed_tier': The governance tier that rejected the action
            - 'policy_rule': The specific policy rule that was violated
            - 'evidence': Supporting evidence for the violation
            - 'suggested_alternatives': Optional list of alternative actions
        audit_id: Unique identifier for the audit record of this violation.
        recoverable: If True, the agent may reformulate the request; if False,
            the action is fundamentally prohibited and should be abandoned.

    Example:
        try:
            result = await gateway_client.execute_action(action)
        except PolicyViolationException as e:
            if e.recoverable:
                # Attempt to reformulate based on violation_details
                logger.info(f"Action blocked: {e.reason_code}, replanning...")
                alternatives = e.violation_details.get("suggested_alternatives", [])
            else:
                # Fundamental prohibition, abort task
                logger.error(f"Action prohibited: {e.reason_code}, task aborted.")
                raise
    """

    def __init__(
        self,
        reason_code: str,
        violation_details: dict[str, Any],
        audit_id: str,
        recoverable: bool = True,
    ):
        self.reason_code = reason_code
        self.violation_details = violation_details
        self.audit_id = audit_id
        self.recoverable = recoverable
        super().__init__(
            f"Policy violation ({reason_code}): {violation_details.get('policy_rule', 'unknown')} "
            f"[audit_id={audit_id}, recoverable={recoverable}]"
        )


class DeferralPending(CageGatewayError):
    """
    Raised when an action requires human-in-the-loop approval and is deferred.

    This exception signals to LangGraph-based agents that they should park the
    current checkpoint and wait for human approval via the deferral ticket system.
    The agent's execution state is preserved in the checkpointer, and execution
    resumes when the ticket is resolved.

    Attributes:
        ticket_id: Unique identifier for the deferral ticket, used to poll for
            resolution or resume execution after human approval.
        defer_reason: Human-readable explanation for why the action was deferred
            (e.g., "High-value trade requires manual approval").
        expires_at: UTC datetime when the deferral ticket expires and the action
            is automatically rejected if no human decision is made.
        ttl_seconds: Time-to-live in seconds (default: 14400 = 4 hours), used
            to calculate `expires_at` if not explicitly provided.

    Example:
        try:
            result = await gateway_client.execute_action(action)
        except DeferralPending as e:
            logger.info(f"Action deferred: {e.ticket_id}, parking checkpoint...")
            # LangGraph checkpointer parks execution state
            await checkpointer.park(ticket_id=e.ticket_id, expires_at=e.expires_at)
            # Human resolves ticket via HITL UI
            # Execution resumes when ticket is approved
    """

    def __init__(
        self,
        ticket_id: str,
        defer_reason: str,
        expires_at: datetime,
        ttl_seconds: int = 14400,
    ):
        self.ticket_id = ticket_id
        self.defer_reason = defer_reason
        self.expires_at = expires_at
        self.ttl_seconds = ttl_seconds
        super().__init__(
            f"Action deferred: {defer_reason} [ticket_id={ticket_id}, "
            f"expires_at={expires_at.isoformat()}]"
        )


class RoutingSealVerificationError(CageGatewayError):
    """
    Exception type reserved for cryptographic envelope or routing seal verification failures.

    Note:
        `CageClient` in `packages/cage-client/` does NOT currently verify
        `GovernanceEnvelope.signature` or `expires_at` client-side; it performs
        Pydantic schema validation and fail-closed HTTP status mediation only.
        Callers or downstream verifiers that implement out-of-band `kid` trust
        anchor verification may raise this exception on signature or freshness
        validation failures.
    """

    pass
