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
Defer Node — Turn-Terminal Governance Hold (Layer 4 Advisor Integration).

Terminates the current LangGraph turn when the CAGE Gateway returns a ``DEFER``
verdict with a ``defer_token``. The gateway owns ``DeferQueue``; ``defer_node``
records the gateway-issued ticket ID, emits a truthful reason-specific
turn-terminal hold message (epistemic quality hold or warrant reliance hold),
and finishes the turn without claiming human-approval auto-resumption.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage

from src.governed_financial_advisor.graph.state import AgentState

logger = logging.getLogger("DeferNode")


async def defer_node(state: AgentState) -> dict[str, Any]:
    """Emit a turn-terminal governance hold response for a gateway ``DEFER``.

    Args:
        state: Current ``AgentState`` with ``deferral_ticket_id`` and
            ``deferral_reason`` populated by ``safety_check_node`` from the
            gateway's ``DEFER`` envelope (``defer_token`` / ``defer_reason``).

    Returns:
        State updates dictionary containing:
          - safety_status: ``"DEFERRED"``
          - deferral_ticket_id: Non-empty ticket ID issued by the gateway
          - messages: User-facing explanation of the turn-terminal hold
          - next_step: ``"FINISH"``

    Raises:
        RuntimeError: If ``deferral_ticket_id`` is missing or blank in state
            (fail-closed).
    """
    plan_raw = state.get("execution_plan_output")
    plan: dict[str, Any] = plan_raw if isinstance(plan_raw, dict) else {}

    raw_ticket_id = state.get("deferral_ticket_id")
    if not isinstance(raw_ticket_id, str) or not raw_ticket_id.strip():
        raise RuntimeError(
            "defer_node requires a gateway-issued deferral_ticket_id in state; "
            "the advisor does not own DeferQueue."
        )
    ticket_id = raw_ticket_id.strip()

    raw_reason = state.get("deferral_reason")
    defer_reason_str = (
        raw_reason.strip() if isinstance(raw_reason, str) else str(raw_reason or "")
    ) or "CONFIDENCE_BELOW_THRESHOLD"

    logger.info(
        "⏸️ [DeferNode] Turn-terminal governance hold: ticket_id=%s, reason=%s",
        ticket_id,
        defer_reason_str,
    )

    symbol = str(plan.get("symbol") or "asset")
    if "WARRANT_INELIGIBLE" in defer_reason_str:
        guidance = (
            "An external reliance or warrant precondition required to govern "
            "this action was not met. This hold cannot be overridden by human "
            "approval; submit a new request only after a valid, in-scope "
            "warrant is standing."
        )
    else:
        guidance = (
            "Epistemic confidence fell below the minimum admissibility "
            "threshold (< 0.70). This epistemic quality hold prevents "
            "automation-bias rubber-stamping (whereas high-value human review "
            "uses `REQUIRE_APPROVAL`); inject fresh context or market data and "
            "submit a new request once context improves."
        )

    explanation = (
        f"Proposed transaction for {symbol} has been placed on a "
        f"**turn-terminal governance hold** and will not execute in this turn "
        f"or auto-resume via human approval.\n\n"
        f"**Deferral Details:**\n"
        f"- Ticket ID: `{ticket_id}`\n"
        f"- Reason: {defer_reason_str}\n\n"
        f"{guidance}"
    )

    return {
        "safety_status": "DEFERRED",
        "deferral_ticket_id": ticket_id,
        "messages": [AIMessage(content=explanation)],
        "next_step": "FINISH",
    }
