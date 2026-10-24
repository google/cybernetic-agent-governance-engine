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
  - Extract every proposed trade from ``AgentState.execution_plan_output``
  - Submit each one to ``POST /governance/validate-action`` via the advisor's
    standard ``GatewayClient.validate_action()``
  - Handle the gateway verdicts for the plan as a whole:
      * ALLOW / NARROW / REQUIRE_APPROVAL for every trade step →
        safety_status "APPROVED": reset consecutive_denials and route to the
        governed trader, whose ``gateway_tool_guard`` re-asks the gateway per
        tool call and parks REQUIRE_APPROVAL for a human before anything
        executes
      * DENIED for any step → increment consecutive_denials, store violation,
        route to explainer
      * DEFER for any step (and no refusal) → store the gateway's deferral
        ticket, route to defer_node

R-11: Policy evaluation is performed by the out-of-process CAGE Gateway PDP,
enforcing fail-closed governance that cannot be bypassed by LLM agents. The
advisor is an untrusted, zero-identity client (POAM-2026-080): the gateway
authenticates it by mesh workload identity, and the advisor holds no
routing-seal secret, signer or governor of its own.

Fail-closed: only an explicit ALLOW, NARROW or REQUIRE_APPROVAL verdict for
every trade step routes onward (nothing is committed here; the gateway commits
only inside ``execute_trade_action``). For any step, a DENIED verdict, an
unknown / missing verdict, a DEFER without a ticket, an HTTP error, a
timeout or an unreachable gateway all produce ``BLOCKED``.

MAX_CONSECUTIVE_DENIALS = 2: Policy-probing attack mitigation. When an agent
receives 2 consecutive DENY verdicts without an intervening ALLOW, the graph
halts with HARD_PAUSE_BUDGET_EXCEEDED status, requiring human review to prevent
infinite replanning loops.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

import httpx

from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    PROCEED_VERDICTS,
    TRADE_ACTION,
    build_routing_verdict_cache,
    extract_trade_steps,
    reusable_allow_verdict,
)
from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger("SafetyNode")

# Policy-probing attack mitigation constant (ADR-008)
MAX_CONSECUTIVE_DENIALS = 2

#: How the gateway routed one trade step: onward, parked, or refused.
_Routing = Literal["routed", "deferred", "blocked"]


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
            "routing_verdict_cache": None,
        }
    return {
        "safety_status": "BLOCKED",
        "consecutive_denials": new_denials,
        "last_violation": violation,
        "routing_verdict_cache": None,
    }


async def _route_trade(
    state: AgentState, params: dict[str, Any], *, label: str | None
) -> tuple[_Routing, dict[str, Any]]:
    """Ask the gateway how one trade step must be routed. Never raises.

    Args:
        state: Current AgentState (its denial budget prices a refusal).
        params: The step's canonical ``execute_trade`` parameters.
        label: ``"Trade step i of n"`` for a multi-step plan, prefixed to the
            refusal evidence; ``None`` for a single-step plan.

    Returns:
        ``("routed", result)`` for an ALLOW, NARROW or REQUIRE_APPROVAL
        verdict, ``("deferred", result)`` for a DEFER with a ticket, and
        ``("blocked", update)`` with the BLOCKED (or budget-exhausted) state
        update for anything else.
    """

    def blocked(
        rule: str, evidence: str, *, recoverable: bool
    ) -> tuple[_Routing, dict[str, Any]]:
        return "blocked", _blocked(
            state,
            policy_rule=rule,
            evidence=f"{label}: {evidence}" if label else evidence,
            reason_code=rule,
            recoverable=recoverable,
        )

    try:
        result = await GatewayClient().validate_action(
            action=TRADE_ACTION, params=params
        )
    except PermissionError as exc:
        # Gateway DENIED the action.
        logger.warning("🚫 Safety Node: Action DENIED by governance: %s", exc)
        return blocked("GOVERNANCE_DENIED", str(exc), recoverable=True)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            # The gateway's refusal contract: HTTP 403 {"verdict": "DENIED", ...}.
            logger.warning("🚫 Safety Node: Action DENIED by governance (HTTP 403)")
            return blocked(
                "GOVERNANCE_DENIED", _violations_of(exc.response), recoverable=True
            )
        logger.error(
            "❌ Safety Node: Gateway HTTP %d — failing closed",
            exc.response.status_code,
        )
        return blocked(
            "GATEWAY_ERROR",
            f"Gateway returned HTTP {exc.response.status_code}",
            recoverable=False,
        )
    except Exception as exc:
        # Fail closed: HTTP errors, timeouts, unreachable gateway.
        logger.error(
            "❌ Safety Node: Governance validation failed — failing closed (%s: %s)",
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return blocked(
            "GATEWAY_ERROR",
            f"Failed to validate action due to {type(exc).__name__}: {exc!s}",
            recoverable=False,
        )

    verdict = result.get("verdict") if isinstance(result, dict) else None

    if verdict in PROCEED_VERDICTS:
        logger.info(
            "✅ Safety Node: gateway routed action %s (envelope_id=%s)",
            verdict,
            result.get("envelope_id", "unknown"),
        )
        return "routed", result

    if verdict == GovernanceDecision.DEFER and result.get("defer_id"):
        logger.info(
            "⏸️ Safety Node: Action DEFERRED by governance (defer_id=%s)",
            result["defer_id"],
        )
        return "deferred", result

    logger.warning(
        "🚫 Safety Node: Gateway returned no routable verdict (verdict=%r) — failing closed",
        verdict,
    )
    return blocked(
        "NOT_APPROVED",
        (
            f"Gateway returned verdict {verdict!r}, not one of "
            f"{sorted(v.value for v in PROCEED_VERDICTS)}"
        ),
        recoverable=False,
    )


async def safety_check_node(state: AgentState) -> dict[str, Any]:
    """
    Governance pre-execution gate via the CAGE Gateway (out-of-process PDP).

    Submits every trade step of the plan to ``POST /governance/validate-action``
    (a single-step plan may instead reuse a fresh matching ``ALLOW`` routing
    verdict from ``evaluator_node``) and maps the verdicts onto agent state.

    Fail-closed semantics:
      - ALLOW, NARROW or REQUIRE_APPROVAL (with ``deferred_id``) for every
        trade step → safety_status "APPROVED", consecutive_denials reset to 0
      - DENIED (``PermissionError``) for any step → "BLOCKED" (or HARD_PAUSE
        on budget exhaustion); the remaining steps are not submitted
      - DEFER with a ``defer_id`` for any step and no refusal → "DEFERRED"
        with the first deferred step's ticket. The steps after a deferral are
        still submitted, so that a refused step blocks the plan instead.
      - Anything else (unknown verdict, HTTP error, timeout,
        unreachable gateway) for any step → "BLOCKED" with ``GATEWAY_ERROR`` /
        ``NOT_APPROVED``

    Only a single-step plan answered ``ALLOW`` populates
    ``routing_verdict_cache``: one cache entry binds one order.

    Args:
        state: Current AgentState containing execution plan and context

    Returns:
        State updates dictionary containing:
          - safety_status: "APPROVED" | "BLOCKED" | "DEFERRED" |
            "HARD_PAUSE_BUDGET_EXCEEDED" | "SKIPPED"
          - consecutive_denials: Updated counter (reset to 0 on approval,
            incremented once when any step is refused)
          - last_violation: Structured violation details on DENY
          - governance_signature: On approval, the gateway signature of each
            trade step, comma-separated in plan order
          - deferred_id: On approval, the first ``deferred_id`` a
            REQUIRE_APPROVAL step parked
          - deferral_ticket_id / deferral_reason: On DEFER
    """
    logger.info("🛡️ Safety Node: Submitting action to CAGE Gateway for validation")

    plan_raw = state.get("execution_plan_output")
    plan: dict[str, Any] = plan_raw if isinstance(plan_raw, dict) else {}

    try:
        trades = extract_trade_steps(plan)
    except Exception as exc:
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

    if not trades:
        logger.info(
            "Safety node: non-trade plan or missing plan — skipping governance check"
        )
        return {
            "safety_status": "SKIPPED",
            "routing_verdict_cache": None,
        }

    cached_cache = state.get("routing_verdict_cache")
    reused = (
        reusable_allow_verdict(cached_cache, trades[0]) if len(trades) == 1 else None
    )
    if reused is not None:
        logger.info(
            "✅ Safety Node: reusing fresh ALLOW routing verdict (digest=%s)",
            cached_cache.get("params_digest")
            if isinstance(cached_cache, dict)
            else "unknown",
        )
        return {
            "safety_status": "APPROVED",
            "consecutive_denials": 0,
            "last_violation": None,
            "governance_signature": str(reused.get("signature") or ""),
            "routing_verdict_cache": cached_cache,
        }

    routed: list[dict[str, Any]] = []
    deferral: dict[str, Any] | None = None
    for index, params in enumerate(trades, start=1):
        label = f"Trade step {index} of {len(trades)}" if len(trades) > 1 else None
        routing, payload = await _route_trade(state, params, label=label)
        if routing == "blocked":
            # One refused step blocks the whole plan and counts one denial.
            return payload
        if routing == "routed":
            routed.append(payload)
        elif deferral is None:
            deferral = payload

    if deferral is not None:
        return {
            "safety_status": "DEFERRED",
            "deferral_ticket_id": str(deferral["defer_id"]),
            "deferral_reason": str(
                deferral.get("defer_reason") or "Human approval required"
            ),
            "routing_verdict_cache": None,
            # Do NOT reset consecutive_denials — deferral is not approval.
        }

    routing_cache = (
        build_routing_verdict_cache(
            trades[0],
            verdict=GovernanceDecision.ALLOW.value,
            envelope=routed[0],
        )
        if len(trades) == 1 and routed[0].get("verdict") == GovernanceDecision.ALLOW
        else None
    )
    signatures = [str(result.get("signature") or "") for result in routed]
    out: dict[str, Any] = {
        "safety_status": "APPROVED",
        "consecutive_denials": 0,
        "last_violation": None,
        "governance_signature": ",".join(signatures) if any(signatures) else "",
        "routing_verdict_cache": routing_cache,
    }
    deferred_ids = [
        str(result["deferred_id"]) for result in routed if result.get("deferred_id")
    ]
    if deferred_ids:
        out["deferred_id"] = deferred_ids[0]
    return out


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
