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
Approval Node — LangGraph native human-in-the-loop interrupt.

Phase 2.1: Uses dynamic interrupt() primitive instead of static interrupt_before.

The node ALWAYS calls interrupt() when reached. The graph routes here only
when the gateway answered REQUIRE_APPROVAL and parked a ``deferred_id``; the
advisor applies no approval thresholds of its own.

Flow:
  1. The gateway returns REQUIRE_APPROVAL with a ``deferred_id``
  2. approval_node calls interrupt(payload) → GraphInterrupt suspends execution
  3. Reviewers record the authoritative approval against ``deferred_id`` at the
     compliance bridge (POST /v1/defer/{deferred_id}/escalate), then resume the
     graph through the LangGraph SDK with Command(resume={...}).
  4. interrupt() returns resume payload, node updates state and returns Command

Pure LangGraph — no static compile-time interrupts, no BullMQ.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from langgraph.types import Command, interrupt

from src.governed_financial_advisor.graph.nodes.approval_contract import (
    ApprovalDecision,
)

logger = logging.getLogger(__name__)


def create_approval_node(
    *,
    approved_target: str = "post_hitl_rehydrate",
    rejected_target: str = "rejection",
):
    """Create a human-in-the-loop approval node with configurable resume targets.

    Defaults to the ``governed_trader`` subgraph targets
    (``post_hitl_rehydrate`` / ``rejection``) while allowing the parent graph to
    route to ``governed_trader`` / ``explainer``.
    """

    def _node(state: dict[str, Any]) -> Command:
        logger.info("[ApprovalNode] Trade requires human approval — suspending graph.")

        ttl_seconds: int = int(os.getenv("HITL_APPROVAL_TTL_SECONDS", "300"))
        trade_payload: dict[str, Any] = {
            "reason": "trade_approval_required",
            # The gateway-held approval token. The authoritative approval is
            # recorded against it at POST /v1/defer/{deferred_id}/escalate (the
            # compliance bridge); this interrupt only pauses the advisor's graph.
            "deferred_id": state.get("deferred_id"),
            "trade": {
                "execution_plan": state.get("execution_plan_output"),
                "evaluation_result": state.get("evaluation_result"),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            ).isoformat(),
        }

        # Pause the graph here. On first invocation this raises GraphInterrupt.
        # On resume it returns the value supplied via Command(resume={...}).
        decision: dict[str, Any] = interrupt(trade_payload)

        # Enforce mandatory rationale validation via ApprovalDecision contract
        # A resume payload without a rationale will raise a ValidationError here,
        # protecting the compliance chain from unexplained approvals.
        validated_decision = ApprovalDecision(**decision)

        approved: bool = validated_decision.approved
        reviewer: str = validated_decision.reviewer
        rationale: str = validated_decision.rationale
        comment: str = validated_decision.comment
        timestamp: str = decision.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        )

        approval_decision: dict[str, Any] = {
            "approved": approved,
            "reviewer": reviewer,
            "rationale": rationale,
            "comment": comment,
            "timestamp": timestamp,
            "max_slippage_pct": validated_decision.max_slippage_pct,
        }

        logger.info(
            "[ApprovalNode] Decision received: approved=%s reviewer=%s rationale=%r",
            approved,
            reviewer,
            rationale[:120],
        )

        if approved:
            logger.info(
                "[ApprovalNode] ✅ Trade approved — routing to %s.",
                approved_target,
            )
            return Command(
                update={
                    "approval_decision": approval_decision,
                    "hitl_expires_at": trade_payload["expires_at"],
                },
                goto=approved_target,
            )

        logger.info(
            "[ApprovalNode] ❌ Trade rejected — routing to %s.", rejected_target
        )
        update_payload: dict[str, Any] = {
            "approval_decision": approval_decision,
            "hitl_expires_at": trade_payload["expires_at"],
        }
        if rejected_target != "rejection":
            rejection_update = rejection_node({"approval_decision": approval_decision})
            update_payload["messages"] = rejection_update["messages"]
        return Command(
            update=update_payload,
            goto=rejected_target,
        )

    return _node


def approval_node(state: dict[str, Any]) -> Command:
    """
    Human-in-the-loop approval gate for high-value or high-risk trades.

    Suspends the graph via interrupt() and surfaces the trade payload to a
    human reviewer. On resume, routes via Command(goto=...) based on decision.

    Args:
        state: AgentState with execution_plan_output and evaluation_result.

    Returns:
        Command that updates approval_decision and routes to the next node.
    """
    return create_approval_node()(state)


def rejection_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    Graceful rejection handler — logs the decision and ends the subgraph.

    Appends a human-readable rejection message to the message history so
    the parent graph's explainer node can surface it to the user.

    Args:
        state: GovernedTraderState with "approval_decision" populated.

    Returns:
        State update with a rejection message appended.
    """
    decision: dict[str, Any] = state.get("approval_decision") or {}
    reviewer: str = decision.get("reviewer", "unknown")
    rationale: str = decision.get("rationale", "")
    comment: str = decision.get("comment", "")
    timestamp: str = decision.get("timestamp", datetime.now(timezone.utc).isoformat())
    display_reason = rationale or comment

    logger.info(
        "[RejectionNode] Trade rejected by reviewer '%s' at %s. Rationale: %s",
        reviewer,
        timestamp,
        display_reason,
    )

    rejection_message: str = (
        f"⛔ **Trade Rejected** by reviewer `{reviewer}` at {timestamp}.\n\n"
        f"**Rationale:** {display_reason or 'No rationale provided.'}\n\n"
        "The trade has been cancelled. Please revise your request or contact "
        "your compliance officer if you believe this decision was made in error."
    )

    return {"messages": [("ai", rejection_message)]}
