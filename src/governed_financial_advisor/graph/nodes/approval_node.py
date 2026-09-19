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

The node ALWAYS calls interrupt() when reached. Conditional routing logic
(risk_score > 0.7 OR amount > 10000) belongs in the graph's routing edges,
not in the node itself.

Flow:
  1. Graph routes to approval_node based on runtime conditions
  2. approval_node calls interrupt(payload) → GraphInterrupt suspends execution
  3. Human reviewer calls POST /v1/approvals/{thread_id}/resume
  4. interrupt() returns resume payload, node updates state and returns Command

Pure LangGraph — no static compile-time interrupts, no BullMQ.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from langgraph.types import Command, interrupt

logger = logging.getLogger(__name__)


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
    logger.info("[ApprovalNode] Trade requires human approval — suspending graph.")

    ttl_seconds: int = int(os.getenv("HITL_APPROVAL_TTL_SECONDS", "300"))
    trade_payload: dict[str, Any] = {
        "reason": "trade_approval_required",
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

    approved: bool = bool(decision.get("approved", False))
    reviewer: str = decision.get("reviewer", "unknown")
    rationale: str = decision.get("rationale", "")
    comment: str = decision.get("comment", "")
    timestamp: str = decision.get("timestamp", datetime.now(timezone.utc).isoformat())

    approval_decision: dict[str, Any] = {
        "approved": approved,
        "reviewer": reviewer,
        "rationale": rationale,
        "comment": comment,
        "timestamp": timestamp,
        "max_slippage_pct": float(decision.get("max_slippage_pct", 2.0)),
    }

    logger.info(
        "[ApprovalNode] Decision received: approved=%s reviewer=%s rationale=%r",
        approved,
        reviewer,
        rationale[:120] if rationale else "(empty — compliance gap)",
    )

    if approved:
        logger.info(
            "[ApprovalNode] ✅ Trade approved — routing to post_hitl_rehydrate (TOCTOU remediation)."
        )
        return Command(
            update={
                "approval_decision": approval_decision,
                "hitl_expires_at": trade_payload["expires_at"],
            },
            goto="post_hitl_rehydrate",
        )

    logger.info("[ApprovalNode] ❌ Trade rejected — routing to rejection.")
    return Command(
        update={
            "approval_decision": approval_decision,
            "hitl_expires_at": trade_payload["expires_at"],
        },
        goto="rejection",
    )


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
