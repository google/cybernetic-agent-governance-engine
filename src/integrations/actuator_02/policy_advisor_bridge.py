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

"""OpenShell Policy Advisor to CAGE SymbolicGovernor & DeferQueue bridge.

Evaluates dynamic sandbox policy proposals (e.g., ``SubmitPolicyAnalysis`` /
``ApproveDraftChunk``) against ``SymbolicGovernor.validate_action()`` in
``Profile.DRY_RUN`` mode. Hard STPA violations are deterministically rejected;
``REQUIRE_APPROVAL`` / ``DEFER`` verdicts park a ``DeferToken`` in ``DeferQueue``
without ever bypassing ``DeferQueue._resolve()``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken
from src.gateway.governance.governor.pipeline import Profile


class PolicyAdvisorProposal(BaseModel):
    """Structured sandbox permission proposal from OpenShell Policy Advisor."""

    sandbox_id: str = Field(min_length=1, max_length=128)
    thread_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    requested_endpoint: str = Field(min_length=1, max_length=512)
    requested_http_verb: str = Field(default="POST", min_length=1, max_length=16)
    operator_urn: str = Field(default="urn:cage:agent:sandbox")
    params: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class PolicyAdvisorOutcome:
    """Result of evaluating a Policy Advisor proposal through CAGE."""

    status: str  # "REJECTED" | "PARKED_FOR_HITL" | "ALLOWED"
    decision: GovernanceDecision
    defer_id: str | None = None
    reason: str = ""


class PolicyAdvisorBridge:
    """Bridges OpenShell Policy Advisor proposals to SymbolicGovernor and DeferQueue."""

    def __init__(
        self,
        *,
        governor: Any,
        defer_queue: DeferQueue | None = None,
    ) -> None:
        self._governor = governor
        self._defer_queue = defer_queue

    async def evaluate_proposal(
        self, proposal: PolicyAdvisorProposal
    ) -> PolicyAdvisorOutcome:
        """Evaluate a dynamic policy proposal via DRY_RUN and park if HITL is required."""
        eval_params = {
            **proposal.params,
            "requested_endpoint": proposal.requested_endpoint,
            "requested_http_verb": proposal.requested_http_verb,
            "sandbox_id": proposal.sandbox_id,
        }
        verdict = await self._governor.validate_action(
            action=proposal.action,
            params=eval_params,
            profile=Profile.DRY_RUN,
            thread_id=proposal.thread_id,
        )

        decision = verdict.decision
        if decision == GovernanceDecision.DENY:
            return PolicyAdvisorOutcome(
                status="REJECTED",
                decision=decision,
                defer_id=None,
                reason=verdict.reason or "Rejected by STERA hard constraint",
            )

        if decision in (
            GovernanceDecision.REQUIRE_APPROVAL,
            GovernanceDecision.DEFER,
            GovernanceDecision.NARROW,
        ):
            if self._defer_queue is None:
                return PolicyAdvisorOutcome(
                    status="REJECTED",
                    decision=GovernanceDecision.DENY,
                    defer_id=None,
                    reason="Fail-closed: DeferQueue unavailable for HITL escalation",
                )
            defer_id = f"defer-openshell-{uuid.uuid4().hex[:16]}"
            token = DeferToken(
                defer_id=defer_id,
                thread_id=proposal.thread_id,
                defer_reason=DeferReason.HITL_REQUIRED,
                opa_input_snapshot={
                    "action": proposal.action,
                    "sandbox_id": proposal.sandbox_id,
                    "requested_endpoint": proposal.requested_endpoint,
                    "requested_http_verb": proposal.requested_http_verb,
                    "params": eval_params,
                },
                required_quorum=2,
            )
            await self._defer_queue.park(token)
            return PolicyAdvisorOutcome(
                status="PARKED_FOR_HITL",
                decision=decision,
                defer_id=defer_id,
                reason=verdict.reason or "Parked in DeferQueue for WebAuthn HITL approval",
            )

        return PolicyAdvisorOutcome(
            status="ALLOWED",
            decision=decision,
            defer_id=None,
            reason=verdict.reason or "Allowed by STERA",
        )
