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
evaluation through the out-of-process CAGE Gateway (PEP/PDP architecture). It
enforces strict architectural separation between Layer 4 domain agents and
Layer 1 governance infrastructure.

Key responsibilities:
  - Extract the proposed trade from ``AgentState.execution_plan_output``
  - Submit it to ``POST /governance/validate-action`` via the advisor's
    standard ``GatewayClient.validate_action()``
  - Handle the gateway verdict:
      * ALLOW / NARROW / REQUIRE_APPROVAL → safety_status "APPROVED": reset
        consecutive_denials and route to the governed trader, whose
        ``gateway_tool_guard`` re-asks the gateway per tool call and parks
        REQUIRE_APPROVAL for a human before anything executes
      * DENIED   → increment consecutive_denials, store violation, route to explainer
      * DEFER    → store the gateway's deferral ticket, route to defer_node

R-11: Policy evaluation is performed by the out-of-process CAGE Gateway PDP,
enforcing fail-closed governance that cannot be bypassed by LLM agents. The
advisor is an untrusted, zero-identity client (POAM-2026-080): the gateway
authenticates it by mesh workload identity, and the advisor holds no
routing-seal secret, signer or governor of its own.

Fail-closed: only an explicit ALLOW, NARROW or REQUIRE_APPROVAL verdict
routes onward (nothing is committed here; the gateway commits only inside
``execute_trade_action``). A DENIED verdict, a
PAUSE / unknown / missing verdict, a DEFER without a ticket, an HTTP error, a
timeout or an unreachable gateway all produce ``BLOCKED``.

MAX_CONSECUTIVE_DENIALS = 2: Policy-probing attack mitigation. When an agent
receives 2 consecutive DENY verdicts without an intervening ALLOW, the graph
halts with HARD_PAUSE_BUDGET_EXCEEDED status, requiring human review to prevent
infinite replanning loops.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger("SafetyNode")

#: Gateway verdicts that may proceed to the governed trader. REQUIRE_APPROVAL
#: proceeds because the human-approval path lives in the trader subgraph.
_PROCEED_VERDICTS = frozenset(
    {
        GovernanceDecision.ALLOW,
        GovernanceDecision.NARROW,
        GovernanceDecision.REQUIRE_APPROVAL,
    }
)

# Policy-probing attack mitigation constant (ADR-008)
MAX_CONSECUTIVE_DENIALS = 2


def _violations_of(response: httpx.Response) -> str:
    """Render the ``violations`` of a gateway refusal body (best effort)."""
    try:
        violations = response.json().get("violations") or ["governance denied"]
    except Exception:
        violations = ["governance denied"]
    return "; ".join(str(v) for v in violations)


def _blocked(
    state: AgentState,
    *,
    policy_rule: str,
    evidence: str,
    reason_code: str,
    recoverable: bool,
) -> dict[str, Any]:
    """Build a BLOCKED (or budget-exhausted) outcome, counting the denial."""
    current_denials = state.get("consecutive_denials", 0) or 0
    new_denials = current_denials + 1
    violation = {
        "reason_code": reason_code,
        "policy_rule": policy_rule,
        "evidence": evidence,
        "audit_id": None,
        "recoverable": recoverable,
    }
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
            "last_violation": violation,
        }
    return {
        "safety_status": "BLOCKED",
        "consecutive_denials": new_denials,
        "last_violation": violation,
    }


async def safety_check_node(state: AgentState) -> dict[str, Any]:
    """
    Governance pre-execution gate via the CAGE Gateway (out-of-process PDP).

    Submits the proposed trade to ``POST /governance/validate-action`` and maps
    the verdict onto agent state.

    Fail-closed semantics:
      - ALLOW, NARROW or REQUIRE_APPROVAL (with ``deferred_id``) → safety_status
        "APPROVED", consecutive_denials reset to 0
      - DENIED (``PermissionError``) → "BLOCKED" (or HARD_PAUSE on budget exhaustion)
      - DEFER with a ``defer_id`` → "DEFERRED" with the gateway's ticket
      - Anything else (PAUSE, unknown verdict, HTTP error, timeout,
        unreachable gateway) → "BLOCKED" with ``GATEWAY_ERROR`` / ``NOT_APPROVED``

    Args:
        state: Current AgentState containing execution plan and context

    Returns:
        State updates dictionary containing:
          - safety_status: "APPROVED" | "BLOCKED" | "DEFERRED" |
            "HARD_PAUSE_BUDGET_EXCEEDED" | "SKIPPED"
          - consecutive_denials: Updated counter (reset to 0 on ALLOW, incremented on DENY)
          - last_violation: Structured violation details on DENY
          - deferral_ticket_id / deferral_reason: On DEFER
    """
    logger.info("🛡️ Safety Node: Submitting action to CAGE Gateway for validation")

    plan_raw = state.get("execution_plan_output")
    plan: dict[str, Any] = plan_raw if isinstance(plan_raw, dict) else {}

    if not plan or plan.get("action") != "execute_trade":
        logger.info(
            "Safety node: non-trade plan or missing plan — skipping governance check"
        )
        return {
            "safety_status": "SKIPPED",
        }

    try:
        params: dict[str, Any] = {
            "action": plan.get("action", "execute_trade"),
            "symbol": plan.get("symbol", "UNKNOWN"),
            "amount": float(plan.get("amount", 0) or 0),
            "currency": plan.get("currency", "USD"),
            "trader_role": plan.get("trader_role", "junior"),
            "confidence": plan.get("confidence", 1.0),
        }
        result = await GatewayClient().validate_action(
            action="execute_trade", params=params
        )
    except PermissionError as exc:
        # Gateway DENIED the action.
        logger.warning("🚫 Safety Node: Action DENIED by governance: %s", exc)
        return _blocked(
            state,
            policy_rule="GOVERNANCE_DENIED",
            evidence=str(exc),
            reason_code="GOVERNANCE_DENIED",
            recoverable=True,
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            # The gateway's refusal contract: HTTP 403 {"verdict": "DENIED", ...}.
            logger.warning("🚫 Safety Node: Action DENIED by governance (HTTP 403)")
            return _blocked(
                state,
                policy_rule="GOVERNANCE_DENIED",
                evidence=_violations_of(exc.response),
                reason_code="GOVERNANCE_DENIED",
                recoverable=True,
            )
        logger.error(
            "❌ Safety Node: Gateway HTTP %d — failing closed",
            exc.response.status_code,
        )
        return _blocked(
            state,
            policy_rule="GATEWAY_ERROR",
            evidence=f"Gateway returned HTTP {exc.response.status_code}",
            reason_code="GATEWAY_ERROR",
            recoverable=False,
        )
    except Exception as exc:
        # Fail closed: HTTP errors, timeouts, unreachable gateway, bad plan data.
        logger.error(
            "❌ Safety Node: Governance validation failed — failing closed (%s: %s)",
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return _blocked(
            state,
            policy_rule="GATEWAY_ERROR",
            evidence=f"Failed to validate action due to {type(exc).__name__}: {exc!s}",
            reason_code="GATEWAY_ERROR",
            recoverable=False,
        )

    verdict = result.get("verdict") if isinstance(result, dict) else None

    if verdict in _PROCEED_VERDICTS:
        logger.info(
            "✅ Safety Node: gateway routed action %s (envelope_id=%s)",
            verdict,
            result.get("envelope_id", "unknown"),
        )
        return {
            "safety_status": "APPROVED",
            "consecutive_denials": 0,
            "last_violation": None,
            "governance_signature": str(result.get("signature") or ""),
        }

    if verdict == "DEFER" and result.get("defer_id"):
        logger.info(
            "⏸️ Safety Node: Action DEFERRED by governance (defer_id=%s)",
            result["defer_id"],
        )
        return {
            "safety_status": "DEFERRED",
            "deferral_ticket_id": str(result["defer_id"]),
            "deferral_reason": str(
                result.get("defer_reason") or "Human approval required"
            ),
            # Do NOT reset consecutive_denials — deferral is not approval.
        }

    logger.warning(
        "🚫 Safety Node: Gateway returned no routable verdict (verdict=%r) — failing closed",
        verdict,
    )
    return _blocked(
        state,
        policy_rule="NOT_APPROVED",
        evidence=f"Gateway returned verdict {verdict!r}, not APPROVED",
        reason_code="NOT_APPROVED",
        recoverable=False,
    )


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
