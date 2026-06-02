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

Implements the trade-approval gate using LangGraph's built-in interrupt /
Command mechanism (LangGraph ≥ 0.2).  The legacy BullMQ TypeScript
implementation (formerly at governed_financial_advisor_ts/src/jobs/interrupt.ts)
has been deleted — this module is the sole approval mechanism.

Flow:
  1. approval_node calls interrupt(payload) → GraphInterrupt is raised and the
     parent graph persists its checkpoint via the Redis/Memory checkpointer.
  2. A human reviewer calls POST /v1/approvals/{thread_id}/resume with their
     decision.  The server issues Command(resume={...}) to the graph.
  3. LangGraph resumes — interrupt() returns the resume payload.  The node
     routes via Command(goto=...) to either "executor" (approved) or
     "rejection" (rejected).

Pure LangGraph — no BullMQ, no Redis job queues, no Node.js dependency.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from langgraph.types import interrupt, Command

logger = logging.getLogger(__name__)


def approval_node(state: dict[str, Any]) -> Command:
    """
    Human-in-the-loop approval gate for high-value or high-risk trades.

    Suspends the graph via interrupt() and surfaces the trade payload to a
    human reviewer.  On resume, routes to "executor" (approved) or
    "rejection" (rejected) via Command.

    Args:
        state: GovernedTraderState — must contain "execution_plan" and
               "evaluation_result".

    Returns:
        Command that updates approval_decision and routes to the next node.
    """
    logger.info("[ApprovalNode] Trade requires human approval — suspending graph.")

    ttl_seconds: int = int(os.getenv("HITL_APPROVAL_TTL_SECONDS", "300"))
    trade_payload: dict[str, Any] = {
        "reason": "trade_approval_required",
        "trade": {
            "execution_plan": state.get("execution_plan"),
            "evaluation_result": state.get("evaluation_result"),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        # TTL: the UI should display this as a countdown. After expires_at the
        # /resume endpoint returns HTTP 410 Gone and the reviewer must re-request.
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        ).isoformat(),
    }

    # Pause the graph here.  On first invocation this raises GraphInterrupt
    # (which propagates to the parent graph and triggers a checkpoint save).
    # On resume it returns the value supplied via Command(resume={...}).
    decision: dict[str, Any] = interrupt(trade_payload)

    approved: bool = bool(decision.get("approved", False))
    reviewer: str = decision.get("reviewer", "unknown")
    rationale: str = decision.get("rationale", "")   # mandatory human justification
    comment: str = decision.get("comment", "")         # optional supplementary note
    timestamp: str = decision.get(
        "timestamp", datetime.now(timezone.utc).isoformat()
    )

    approval_decision: dict[str, Any] = {
        "approved": approved,
        "reviewer": reviewer,
        "rationale": rationale,
        "comment": comment,
        "timestamp": timestamp,
        # max_slippage_pct: reviewer's execution price tolerance (%).
        # Stored in the tamper-evident evidence chain as part of the approval record.
        # Default: 2.0% (institutional large-cap execution standard).
        # Overridable per-reviewer via the /resume request body.
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
            goto="post_hitl_rehydrate",  # TOCTOU: must re-hydrate + re-validate before execution
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
