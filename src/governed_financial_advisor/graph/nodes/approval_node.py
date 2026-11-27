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
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from cage_client.langgraph import approval_park_node
from langgraph.types import Command, interrupt

from src.governed_financial_advisor.graph.nodes.approval_contract import (
    ApprovalDecision,
)

logger = logging.getLogger(__name__)

DEFAULT_HITL_APPROVAL_TTL_SECONDS: int = 300


def resolve_hitl_approval_ttl_seconds() -> int:
    """Return the configured HITL approval window in seconds (default 300 s)."""
    return int(
        os.getenv("HITL_APPROVAL_TTL_SECONDS", str(DEFAULT_HITL_APPROVAL_TTL_SECONDS))
    )


def create_approval_node(
    *,
    approved_target: str = "post_hitl_rehydrate",
    rejected_target: str = "rejection",
) -> Callable[..., Any]:
    """Create a human-in-the-loop approval node delegated to ``cage_client.langgraph.approval_park_node``.

    Defaults to the ``governed_trader`` subgraph targets
    (``post_hitl_rehydrate`` / ``rejection``) while allowing the parent graph to
    route to ``governed_trader`` / ``explainer``. Raises
    :class:`~cage_client.MissingDeferralTicketError` when reached without a
    checkpointed ``deferred_id`` or ``deferred_step_ids``.
    """

    def _node(state: dict[str, Any]) -> Command:
        logger.info("[ApprovalNode] Trade requires human approval — suspending graph.")
        captured: dict[str, Any] = {}

        def _build_trade_payload(
            cur_state: Any, _primary_ticket: str, _deferred_ids: list[str]
        ) -> dict[str, Any]:
            ttl_seconds = resolve_hitl_approval_ttl_seconds()
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            ).isoformat()
            captured["expires_at"] = expires_at
            execution_plan_view = (
                cur_state.get("execution_plan_output")
                if cur_state.get("execution_plan_output") is not None
                else cur_state.get("execution_plan")
            )
            return {
                "reason": "trade_approval_required",
                "trade": {
                    "execution_plan": execution_plan_view,
                    "evaluation_result": cur_state.get("evaluation_result"),
                },
                "expires_at": expires_at,
            }

        def _validate_decision(resumed: Any, _payload: Any) -> dict[str, Any]:
            # Enforce mandatory rationale & slippage bounds via ApprovalDecision.
            validated_decision = ApprovalDecision(**resumed)
            timestamp = str(
                resumed.get("timestamp") or datetime.now(timezone.utc).isoformat()
            )
            record: dict[str, Any] = {
                "approved": validated_decision.approved,
                "reviewer": validated_decision.reviewer,
                "rationale": validated_decision.rationale,
                "comment": validated_decision.comment,
                "timestamp": timestamp,
                "max_slippage_pct": validated_decision.max_slippage_pct,
            }
            captured["decision"] = record
            logger.info(
                "[ApprovalNode] Decision received: approved=%s reviewer=%s rationale=%r",
                validated_decision.approved,
                validated_decision.reviewer,
                validated_decision.rationale[:120],
            )
            return record

        park = approval_park_node(
            approved_target=approved_target,
            rejected_target=rejected_target,
            payload_builder=_build_trade_payload,
            decision_validator=_validate_decision,
            interrupt_fn=lambda payload: interrupt(payload),
        )
        cmd = park(state)
        update_payload = dict(cmd.update or {})
        expires_at = captured.get("expires_at")
        if expires_at is not None:
            update_payload["hitl_expires_at"] = expires_at

        decision_record = captured.get("decision") or {}
        if decision_record.get("approved"):
            logger.info(
                "[ApprovalNode] ✅ Trade approved — routing to %s.",
                approved_target,
            )
            return Command(update=update_payload, goto=cmd.goto)

        logger.info(
            "[ApprovalNode] ❌ Trade rejected — routing to %s.", rejected_target
        )
        update_payload["hitl_reference_quote"] = None
        update_payload["routing_verdict_cache"] = None
        if decision_record:
            if rejected_target == "rejection":
                update_payload["approval_decision"] = decision_record
            else:
                rejection_update = rejection_node(
                    {"approval_decision": decision_record}
                )
                update_payload["messages"] = rejection_update["messages"]
                update_payload["approval_decision"] = None
        return Command(update=update_payload, goto=cmd.goto)

    return _node


def approval_node(state: dict[str, Any]) -> Command:
    """
    Human-in-the-loop approval gate for high-value or high-risk trades.

    Suspends the graph via ``cage_client.langgraph.approval_park_node`` and
    surfaces the trade payload to a human reviewer. On resume, routes via
    ``Command(goto=...)`` based on decision.

    Args:
        state: AgentState with deferred_id, execution_plan/execution_plan_output,
            and evaluation_result.

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

    return {
        "messages": [("ai", rejection_message)],
        "deferred_id": None,
        "deferred_step_ids": None,
        "approval_decision": None,
        "hitl_reference_quote": None,
        "routing_verdict_cache": None,
        "approval_required": False,
    }
