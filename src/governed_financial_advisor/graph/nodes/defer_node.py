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
Defer Node — LangGraph Integration for 4-State DeferQueue (CAGE-REM-004).

Parks transactions exhibiting ambiguous confidence or requiring human review
into DeferQueue (Redis db=1) rather than hard-failing or forcing binary choices.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage

from src.gateway.governance.defer_queue import (
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.governed_financial_advisor.graph.state import AgentState

logger = logging.getLogger("DeferNode")


async def defer_node(state: AgentState) -> dict[str, Any]:
    """Park ambiguous transaction in DeferQueue and pause the graph.

    CAGE-REM-004 / Miracle Owolabi remediation:
    Reconnects the 4-state DeferQueue to the governed financial advisor.
    """
    thread_id = state.get("thread_id") or "anonymous_thread"
    plan = state.get("execution_plan_output") or {}
    confidence = float(plan.get("confidence", 0.0) or 0.0)
    action = plan.get("action", "execute_trade")

    # Determine deferral reason based on confidence tier
    reason = (
        DeferReason.CONFIDENCE_BELOW_THRESHOLD
        if confidence < 0.70
        else DeferReason.EXTERNAL_VALIDATION
    )

    token = DeferToken(
        thread_id=thread_id,
        confidence_score=confidence,
        defer_reason=reason,
        opa_input_snapshot=plan,
    )

    try:
        from src.governed_financial_advisor.infrastructure.redis_client import (
            redis_client,
        )

        queue = DeferQueue(redis_client=redis_client)
        await queue.park(token)
        logger.info(
            "⏸️ [DeferNode] Action '%s' parked in DeferQueue: id=%s confidence=%.2f",
            action,
            token.defer_id,
            confidence,
        )
    except Exception as exc:
        logger.error(
            "🚨 [DeferNode] Failed to persist to Redis DeferQueue — durable park FAILED: %s",
            exc,
        )
        raise

    explanation = (
        f"Transaction for {plan.get('symbol', 'asset')} requires human review "
        f"or additional data hydration (confidence: {confidence:.2f}). "
        f"Parked in DeferQueue [ID: {token.defer_id}]."
    )

    return {
        "defer_token": token.model_dump(),
        "defer_id": token.defer_id,
        "safety_status": "DEFERRED",
        "messages": [AIMessage(content=explanation)],
    }
