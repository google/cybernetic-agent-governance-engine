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
  - Submit each one to ``POST /governance/validate-action`` via
    ``GatewayClient().sdk_client()`` + ``preview_trade_with_drift_revalidation()``
  - Handle the gateway verdicts for the plan as a whole:
      * ALLOW / NARROW / REQUIRE_APPROVAL for every trade step →
        safety_status "APPROVED": reset consecutive_denials and route to the
        governed trader, whose ``governed_tool_node`` re-asks the gateway per
        tool call and parks REQUIRE_APPROVAL for a human before anything
        executes
      * DENIED for any step → increment consecutive_denials, store violation,
        route to explainer
      * DEFER for any step (with a non-blank ``deferred_id`` and no refusal) →
        store the gateway's deferral ticket, leave ``consecutive_denials``
        untouched, and route to ``defer_node`` for a turn-terminal hold

R-11: Policy evaluation is performed by the out-of-process CAGE Gateway PDP,
enforcing fail-closed governance that cannot be bypassed by LLM agents. The
advisor is an untrusted, zero-identity client (POAM-2026-080): the gateway
authenticates it by mesh workload identity, and the advisor holds no
routing-seal secret, signer or governor of its own.

Fail-closed: only an explicit ALLOW, NARROW or REQUIRE_APPROVAL verdict for
every trade step routes onward (nothing is committed here; the gateway commits
only inside ``execute_trade_action``). For any step, an evidenced DENIED verdict
produces ``BLOCKED`` (counting one denial), while ``UNAVAILABLE`` (HTTP 429/5xx,
un-evidenced proxy/mesh 403, unverified envelope, unknown/missing verdict,
timeout, or unreachable gateway) produces ``GATEWAY_ERROR`` (leaving
``consecutive_denials`` unchanged).

MAX_CONSECUTIVE_DENIALS = 2: Policy-probing attack mitigation. When an agent
receives 2 consecutive DENY verdicts without an intervening ALLOW, the graph
halts with HARD_PAUSE_BUDGET_EXCEEDED status, requiring human review to prevent
infinite replanning loops.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Literal

from cage_client import GovernanceDecision as SdkDecision

from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.graph.governance.tool_guard import (
    advisor_principal_extractor,
    preview_trade_with_drift_revalidation,
)
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    TRADE_ACTION,
    build_routing_verdict_cache,
    extract_trade_steps,
    reusable_allow_verdict,
)
from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger("SafetyNode")

#: Fallback ``agent_id`` when no principal context is set; the gateway
#: authenticates callers by mesh workload identity, never by this string.
_ADVISOR_AGENT_ID = "governed-financial-advisor"

# Policy-probing attack mitigation constant (ADR-008)
MAX_CONSECUTIVE_DENIALS = 2

#: How the gateway routed one trade step: onward, parked, or refused.
_Routing = Literal["routed", "deferred", "blocked"]


def _signature_value(result: Mapping[str, Any]) -> str:
    """The base64url ``signature.value`` of a verified gateway envelope, or ``""``."""
    signature = result.get("signature")
    if isinstance(signature, Mapping):
        return str(signature.get("value") or "")
    return str(signature or "")


def _cleared_hitl_fields() -> dict[str, Any]:
    """Per-turn reset of HITL deferral fields so prior-turn state can never leak."""
    return {
        "deferred_id": None,
        "deferred_step_ids": None,
        "approval_decision": None,
        "hitl_reference_quote": None,
    }


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
            **_cleared_hitl_fields(),
        }
    return {
        "safety_status": "BLOCKED",
        "consecutive_denials": new_denials,
        "last_violation": violation,
        "routing_verdict_cache": None,
        **_cleared_hitl_fields(),
    }


def _gateway_error(
    state: AgentState,
    *,
    evidence: str,
) -> dict[str, Any]:
    """Build a fail-closed GATEWAY_ERROR outcome without incrementing consecutive_denials."""
    current_denials = state.get("consecutive_denials", 0) or 0
    return {
        "safety_status": "GATEWAY_ERROR",
        "consecutive_denials": current_denials,
        "last_violation": {
            "reason_code": "GATEWAY_ERROR",
            "policy_rule": "GATEWAY_ERROR",
            "evidence": evidence,
            "audit_id": None,
            "recoverable": False,
        },
        "routing_verdict_cache": None,
        **_cleared_hitl_fields(),
    }


async def _route_trade(
    state: AgentState, params: dict[str, Any], *, label: str | None
) -> tuple[_Routing, dict[str, Any]]:
    """Ask the gateway how one trade step must be routed. Never raises.

    Args:
        state: Current AgentState (its denial budget prices an evidenced refusal).
        params: The step's canonical ``execute_trade`` parameters.
        label: ``"Trade step i of n"`` for a multi-step plan, prefixed to the
            refusal or error evidence; ``None`` for a single-step plan.

    Returns:
        ``("routed", result)`` for an ALLOWED, NARROWED, or REQUIRE_APPROVAL
        preview, ``("deferred", result)`` for a DEFERRED preview without
        ``requires_approval``, and ``("blocked", update)`` with the BLOCKED,
        HARD_PAUSE_BUDGET_EXCEEDED, or GATEWAY_ERROR state update otherwise.
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

    def gateway_error(evidence: str) -> tuple[_Routing, dict[str, Any]]:
        return "blocked", _gateway_error(
            state,
            evidence=f"{label}: {evidence}" if label else evidence,
        )

    try:
        sdk = await GatewayClient().sdk_client()
        principal = advisor_principal_extractor(state) or _ADVISOR_AGENT_ID
        preview = await preview_trade_with_drift_revalidation(
            sdk, TRADE_ACTION, params, principal, state
        )
    except Exception as exc:
        logger.error(
            "❌ Safety Node: Gateway validation unavailable/unverified — failing closed (%s: %s)",
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return gateway_error(
            f"Failed to validate action due to {type(exc).__name__}: {exc!s}"
        )

    if preview.decision is SdkDecision.ALLOWED:
        env = preview.envelope
        if env is not None:
            routed: dict[str, Any] = {
                **dict(env.payload),
                "verdict": GovernanceDecision.ALLOW,
                "envelope_id": env.envelope_id,
                "envelope_version": env.envelope_version,
                "issuer": dict(env.issuer),
                "subject": dict(env.subject),
                "signature": dict(env.signature) if env.signature is not None else {},
                "governance_context": (
                    dict(env.governance_context)
                    if env.governance_context is not None
                    else {}
                ),
                "external_attestations": list(env.external_attestations or ()),
            }
        else:
            routed = {
                "verdict": GovernanceDecision.ALLOW,
                "envelope_id": preview.audit_id or "unknown",
                "violations": list(preview.violations),
            }
        logger.info(
            "✅ Safety Node: gateway routed action %s (envelope_id=%s)",
            GovernanceDecision.ALLOW,
            routed.get("envelope_id", "unknown"),
        )
        return "routed", routed

    if preview.decision is SdkDecision.NARROWED:
        routed = {
            "verdict": GovernanceDecision.NARROW,
            "narrowed_params": dict(preview.narrowed_params or {}),
            "violations": list(preview.violations),
            "audit_id": preview.audit_id,
            "envelope_id": preview.audit_id or "unknown",
        }
        logger.info(
            "✅ Safety Node: gateway routed action %s (envelope_id=%s)",
            GovernanceDecision.NARROW,
            routed.get("envelope_id", "unknown"),
        )
        return "routed", routed

    if preview.decision is SdkDecision.DEFERRED:
        ticket_id = (
            preview.deferred_id.strip() if isinstance(preview.deferred_id, str) else ""
        )
        if not ticket_id:
            logger.error(
                "❌ Safety Node: Gateway validation unavailable/unverified — failing closed (missing deferral ticket)"
            )
            return gateway_error("Gateway deferred action without a deferral ticket")
        if preview.requires_approval:
            routed = {
                "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                "deferred_id": ticket_id,
                "violations": list(preview.violations),
                "envelope_id": preview.audit_id or "unknown",
            }
            logger.info(
                "✅ Safety Node: gateway routed action %s (envelope_id=%s)",
                GovernanceDecision.REQUIRE_APPROVAL,
                routed.get("envelope_id", "unknown"),
            )
            return "routed", routed
        logger.info(
            "⏸️ Safety Node: Action DEFERRED by governance (ticket_id=%s)",
            ticket_id,
        )
        return "deferred", {
            "verdict": GovernanceDecision.DEFER,
            "defer_token": ticket_id,
            "defer_reason": preview.defer_reason,
        }

    if preview.decision is SdkDecision.DENIED:
        evidence = (
            "; ".join(str(v) for v in preview.violations)
            if preview.violations
            else (preview.reason_code or preview.error or "POLICY_DENIED")
        )
        logger.warning("🚫 Safety Node: Action DENIED by governance: %s", evidence)
        return blocked("GOVERNANCE_DENIED", evidence, recoverable=True)

    reason = preview.error or preview.reason_code or "Gateway unavailable"
    logger.error(
        "❌ Safety Node: Gateway validation unavailable/unverified — failing closed (%s: %s)",
        preview.reason_code or "UNAVAILABLE",
        reason,
    )
    return gateway_error(reason)


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
      - DEFER with a non-blank ``defer_token`` for any step and no refusal →
        "DEFERRED" with the first deferred step's ticket (turn-terminal hold;
        ``consecutive_denials`` is left untouched). The steps after a deferral
        are still submitted, so that a refused step blocks the plan instead.
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
            incremented once when any step is refused, omitted/unchanged on
            DEFER)
          - last_violation: Structured violation details on DENY
          - governance_signature: On approval, the gateway signature of each
            trade step, comma-separated in plan order
          - deferred_id: On approval, the first ``deferred_id`` a
            REQUIRE_APPROVAL step parked
          - deferral_ticket_id / deferral_reason: On DEFER (from ``defer_token``
            and ``defer_reason``)
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
            **_cleared_hitl_fields(),
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
            "governance_signature": _signature_value(reused),
            "routing_verdict_cache": cached_cache,
            **_cleared_hitl_fields(),
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
        raw_reason = deferral.get("defer_reason")
        defer_reason = (
            raw_reason.strip() if isinstance(raw_reason, str) else str(raw_reason or "")
        ) or "CONFIDENCE_BELOW_THRESHOLD"
        return {
            "safety_status": "DEFERRED",
            "deferral_ticket_id": str(deferral["defer_token"]).strip(),
            "deferral_reason": defer_reason,
            "routing_verdict_cache": None,
            **_cleared_hitl_fields(),
            # Do NOT reset or increment consecutive_denials — deferral is
            # neither approval nor refusal (LangGraphHarness.tla SafetyDefer).
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
    signatures = [_signature_value(result) for result in routed]
    out: dict[str, Any] = {
        "safety_status": "APPROVED",
        "consecutive_denials": 0,
        "last_violation": None,
        "governance_signature": ",".join(signatures) if any(signatures) else "",
        "routing_verdict_cache": routing_cache,
        **_cleared_hitl_fields(),
    }
    deferred_steps = [
        (str(result["deferred_id"]), trades[idx])
        for idx, result in enumerate(routed)
        if result.get("deferred_id")
    ]
    if deferred_steps:
        out["deferred_id"] = deferred_steps[0][0]
        out["deferred_step_ids"] = (
            [str(r["deferred_id"]) if r.get("deferred_id") else None for r in routed]
            if len(trades) > 1
            else None
        )

    approval_trade = (
        deferred_steps[0][1]
        if deferred_steps
        else (trades[0] if state.get("approval_required") and trades else None)
    )
    if approval_trade is not None:
        from src.governed_financial_advisor.graph.nodes.toctou_quote import (
            normalize_ticker,
            select_reference_quote_for_ticker,
        )

        deferred_symbol = normalize_ticker(approval_trade.get("symbol"))
        if deferred_symbol is not None:
            out["data_analyst_ticker"] = deferred_symbol
            out["hitl_reference_quote"] = select_reference_quote_for_ticker(
                state,
                ticker=deferred_symbol,
                plan_raw=plan,
            )
    return out


def route_safety(state: AgentState) -> str:
    """
    Deterministic router for safety_check_node outcomes.

    Routes based on safety_status field:
      - "APPROVED" → governed_trader (execute the action)
      - "BLOCKED" → explainer (self-correction or budget check)
      - "DEFERRED" → defer_node (turn-terminal governance hold)
      - "HARD_PAUSE_BUDGET_EXCEEDED" → human_review (escalate to human)
      - "GATEWAY_ERROR" → explainer (fail-closed infrastructure halt)
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
    elif status == "GATEWAY_ERROR":
        logger.error("🔴 route_safety: GATEWAY_ERROR → explainer")
        return "explainer"
    else:
        # "BLOCKED" or defensive fallback
        logger.info("🔴 route_safety: %s → explainer", status)
        return "explainer"
