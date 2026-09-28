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
Defer Node — LangGraph Integration for CageClient Deferral Flow.

Suspends graph execution when the gateway returns a DEFER verdict. The gateway
owns DeferQueue; this node only packages the gateway-issued ticket metadata into
the LangGraph checkpoint payload and finishes the current turn until HITL
resolution resumes the thread.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage

from src.governed_financial_advisor.graph.state import AgentState

logger = logging.getLogger("DeferNode")


async def defer_node(state: AgentState) -> dict[str, Any]:
    """Package gateway-issued deferral ticket metadata for LangGraph checkpointing.

    Args:
        state: Current AgentState with ``deferral_ticket_id`` and ``deferral_reason``
            populated by ``safety_check_node`` from the gateway's DEFER verdict.

    Returns:
        State updates dictionary containing:
          - safety_status: "DEFERRED"
          - deferral_ticket_id: Ticket ID issued by the gateway
          - checkpoint_payload: Snapshot for HITL resumption
          - messages: User-facing explanation of deferral
          - next_step: "FINISH"

    Raises:
        RuntimeError: If ``deferral_ticket_id`` is missing from state (fail-closed).
    """
    thread_id = str(state.get("thread_id") or "anonymous_thread")
    plan_raw = state.get("execution_plan_output")
    plan: dict[str, Any] = plan_raw if isinstance(plan_raw, dict) else {}

    ticket_id = state.get("deferral_ticket_id")
    if not ticket_id:
        raise RuntimeError(
            "defer_node requires a gateway-issued deferral_ticket_id in state; "
            "the advisor does not own DeferQueue."
        )

    defer_reason_str = state.get("deferral_reason", "Human approval required")

    logger.info(
        "⏸️ [DeferNode] Gateway deferral detected: ticket_id=%s, reason=%s",
        ticket_id,
        defer_reason_str,
    )

    checkpoint_payload = {
        "ticket_id": ticket_id,
        "thread_id": thread_id,
        "defer_reason": defer_reason_str,
        "execution_plan_snapshot": plan,
        "parked_at": state.get("timestamp") or "unknown",
    }

    explanation = (
        f"Transaction for {plan.get('symbol', 'asset')} requires human approval "
        f"and has been deferred to the HITL review queue.\n\n"
        f"**Deferral Details:**\n"
        f"- Ticket ID: `{ticket_id}`\n"
        f"- Reason: {defer_reason_str}\n\n"
        f"Execution will resume automatically once the ticket is approved by "
        f"a human reviewer. You can check the ticket status in the governance "
        f"dashboard or wait for notification."
    )

    return {
        "safety_status": "DEFERRED",
        "deferral_ticket_id": ticket_id,
        "checkpoint_payload": checkpoint_payload,
        "messages": [AIMessage(content=explanation)],
        "next_step": "FINISH",
    }
