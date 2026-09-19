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
Explicit Safety Interceptor Node (Layer 2 Enforcement) — Financial Advisor.

This module provides the governance pre-execution gate that routes action
evaluation through the out-of-process CAGE Gateway via CageClient (PEP/PDP
architecture). It enforces strict architectural separation between Layer 4
domain agents and Layer 1 governance infrastructure.

Key responsibilities:
  - Extract trade payload from AgentState via `_extract_trade_payload`
  - Submit action to CAGE Gateway via `CageClient.validate_action()`
  - Handle tri-state governance response:
      * ALLOW → Reset consecutive_denials counter, route to execution
      * DENY → Increment consecutive_denials, store violation details, route to explainer
      * DEFER → Store deferral ticket, route to defer_node for checkpoint

R-11: Policy evaluation is performed by the out-of-process CAGE Gateway PDP,
enforcing fail-closed governance that cannot be bypassed by LLM agents.
See ADR 2026-03-09 (v3: CageClient SDK enforcement).

MAX_CONSECUTIVE_DENIALS = 2: Policy-probing attack mitigation. When an agent
receives 2 consecutive DENY verdicts without an intervening ALLOW, the graph
halts with HARD_PAUSE_BUDGET_EXCEEDED status, requiring human review to prevent
infinite replanning loops.
"""

from __future__ import annotations

import logging
from typing import Any

from src.gateway.client.exceptions import DeferralPending, PolicyViolationException
from src.governed_financial_advisor.graph.cage_client_singleton import get_cage_client
from src.governed_financial_advisor.graph.state import AgentState

# R-11 / POAM-024: In out-of-process PEP/PDP architecture, CageClient delegates
# policy evaluation to the CAGE Gateway's symbolic_governor PDP.
logger = logging.getLogger("SafetyNode")

# Policy-probing attack mitigation constant (ADR-008)
MAX_CONSECUTIVE_DENIALS = 2


async def safety_check_node(state: AgentState) -> dict[str, Any]:
    """
    Governance pre-execution gate via CageClient (out-of-process PDP).

    Submits the proposed trade action to the CAGE Gateway for policy evaluation.
    Handles tri-state response (ALLOW/DENY/DEFER) and updates agent state accordingly.

    Fail-closed semantics:
      - Network errors, gateway errors, or seal verification failures → halt graph
      - PolicyViolationException → increment consecutive_denials, route to explainer
      - DeferralPending → store ticket, route to defer_node
      - ALLOW → reset consecutive_denials to 0, route to execution

    Args:
        state: Current AgentState containing execution plan and context

    Returns:
        State updates dictionary containing:
          - safety_status: "APPROVED" | "BLOCKED" | "DEFERRED" | "HARD_PAUSE_BUDGET_EXCEEDED"
          - consecutive_denials: Updated counter (reset to 0 on ALLOW, incremented on DENY)
          - last_violation: Structured violation details on DENY
          - deferral_ticket_id: Ticket ID on DEFER
          - deferral_reason: Deferral reason on DEFER

    Raises:
        Exception: On network errors, gateway errors, or budget exhaustion
    """
    logger.info("🛡️ Safety Node: Submitting action to CAGE Gateway via CageClient")

    # Extract trade parameters from state
    plan_raw = state.get("execution_plan_output")
    plan: dict[str, Any] = plan_raw if isinstance(plan_raw, dict) else {}

    if not plan or plan.get("action") != "execute_trade":
        logger.info(
            "Safety node: non-trade plan or missing plan — skipping governance check"
        )
        return {
            "safety_status": "SKIPPED",
        }

    # Build action parameters for CageClient
    parameters = {
        "action": plan.get("action", "execute_trade"),
        "symbol": plan.get("symbol", "UNKNOWN"),
        "amount": float(plan.get("amount", 0) or 0),
        "currency": plan.get("currency", "USD"),
        "trader_role": plan.get("trader_role", "junior"),
        "confidence": plan.get("confidence", 1.0),
    }

    # Add context metadata
    context = {
        "user_id": state.get("user_id", "anonymous"),
        "risk_profile": state.get("risk_attitude", "neutral"),
        "thread_id": str(state.get("thread_id", "unknown")),
    }

    # Use singleton CageClient for consistency across all LangGraph nodes
    client = get_cage_client()

    try:
        try:
            # Submit action for governance validation
            envelope = await client.validate_action(
                action="execute_trade",
                parameters=parameters,
                agent_id="governed-financial-advisor",
                context=context,
            )

            # ALLOW path: Reset consecutive denials counter
            logger.info(
                "✅ Safety Node: Action ALLOWED by governance (record_hash=%s)",
                envelope.subject.get("record_hash", "unknown"),
            )
            return {
                "safety_status": "APPROVED",
                "consecutive_denials": 0,  # Reset on ALLOW
                "last_violation": None,  # Clear previous violations
                "governance_signature": str(envelope.signature),  # Store envelope signature
            }

        except PolicyViolationException as exc:
            # DENY path: Increment consecutive denials, check budget
            current_denials = state.get("consecutive_denials", 0)
            new_denials = current_denials + 1

            logger.warning(
                "🚫 Safety Node: Action DENIED by governance (reason_code=%s, "
                "audit_id=%s, consecutive_denials=%d→%d, recoverable=%s)",
                exc.reason_code,
                exc.audit_id,
                current_denials,
                new_denials,
                exc.recoverable,
            )

            # Check if replanning budget is exhausted
            if new_denials >= MAX_CONSECUTIVE_DENIALS:
                logger.error(
                    "🛑 Safety Node: MAX_CONSECUTIVE_DENIALS exceeded (%d >= %d) — "
                    "HARD_PAUSE_BUDGET_EXCEEDED (requires human review)",
                    new_denials,
                    MAX_CONSECUTIVE_DENIALS,
                )
                return {
                    "safety_status": "HARD_PAUSE_BUDGET_EXCEEDED",
                    "consecutive_denials": new_denials,
                    "last_violation": {
                        "reason_code": exc.reason_code,
                        "policy_rule": exc.violation_details.get(
                            "policy_rule", "unknown"
                        ),
                        "evidence": exc.violation_details.get("evidence", ""),
                        "audit_id": exc.audit_id,
                        "recoverable": exc.recoverable,
                    },
                }

            # Within budget: Store violation and route to explainer for self-correction
            return {
                "safety_status": "BLOCKED",
                "consecutive_denials": new_denials,
                "last_violation": {
                    "reason_code": exc.reason_code,
                    "policy_rule": exc.violation_details.get("policy_rule", "unknown"),
                    "evidence": exc.violation_details.get("evidence", ""),
                    "suggested_alternatives": exc.violation_details.get(
                        "suggested_alternatives", []
                    ),
                    "audit_id": exc.audit_id,
                    "recoverable": exc.recoverable,
                },
            }

        except DeferralPending as exc:
            # DEFER path: Store ticket and route to defer_node
            logger.info(
                "⏸️ Safety Node: Action DEFERRED by governance (ticket_id=%s, "
                "expires_at=%s)",
                exc.ticket_id,
                exc.expires_at.isoformat(),
            )
            return {
                "safety_status": "DEFERRED",
                "deferral_ticket_id": exc.ticket_id,
                "deferral_reason": exc.defer_reason,
                # Do NOT reset consecutive_denials — deferral doesn't count as approval
            }

        except Exception as exc:
            # Fail-closed: Network errors, gateway errors, seal verification failures
            logger.error(
                "❌ Safety Node: Unexpected error during governance validation — "
                "failing closed (error=%s: %s)",
                type(exc).__name__,
                str(exc),
                exc_info=True,
            )
            current_denials = state.get("consecutive_denials", 0)
            new_denials = current_denials + 1
            return {
                "safety_status": "BLOCKED",
                "consecutive_denials": new_denials,
                "last_violation": {
                    "policy_rule": "GATEWAY_ERROR",
                    "evidence": f"Failed to validate action due to {type(exc).__name__}: {exc!s}",
                    "audit_id": None,
                    "recoverable": False,
                },
            }

    except Exception as exc:
        # Fail-closed: Singleton initialization or network errors
        logger.error(
            "❌ Safety Node: Failed to access CageClient singleton — failing closed (error=%s: %s)",
            type(exc).__name__,
            str(exc),
            exc_info=True,
        )
        current_denials = state.get("consecutive_denials", 0)
        new_denials = current_denials + 1
        return {
            "safety_status": "BLOCKED",
            "consecutive_denials": new_denials,
            "last_violation": {
                "policy_rule": "CLIENT_INIT_ERROR",
                "evidence": f"Failed to initialize governance client: {type(exc).__name__}: {exc!s}",
                "audit_id": None,
                "recoverable": False,
            },
        }


def route_safety(state: AgentState) -> str:
    """
    Deterministic router for safety_check_node outcomes.

    Routes based on safety_status field:
      - "APPROVED" → governed_trader (execute the action)
      - "BLOCKED" → explainer (self-correction or budget check)
      - "DEFERRED" → defer_node (park checkpoint for HITL)
      - "HARD_PAUSE_BUDGET_EXCEEDED" → human_review (escalate to human)
      - default → explainer (defensive fallback)

    Args:
        state: Current AgentState with safety_status set

    Returns:
        Next node name as string
    """
    status = state.get("safety_status", "UNKNOWN")

    if status == "APPROVED":
        logger.info("🟢 route_safety: APPROVED → governed_trader")
        return "governed_trader"
    elif status == "DEFERRED":
        logger.info("🟡 route_safety: DEFERRED → defer_node")
        return "defer_node"
    elif status == "HARD_PAUSE_BUDGET_EXCEEDED":
        logger.error("🔴 route_safety: HARD_PAUSE_BUDGET_EXCEEDED → human_review")
        return "human_review"
    else:
        # "BLOCKED" or defensive fallback
        logger.info("🔴 route_safety: %s → explainer", status)
        return "explainer"
