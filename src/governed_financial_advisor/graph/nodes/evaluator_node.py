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

import logging
from typing import Any

from opentelemetry import trace

from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.agents.evaluator.agent import (
    simulate_governance_check,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    PROCEED_VERDICTS,
    TRADE_ACTION,
    build_routing_verdict_cache,
    extract_trade_steps,
    is_trade_action,
)
from src.governed_financial_advisor.graph.state import AgentState

logger = logging.getLogger("EvaluatorNode")
tracer = trace.get_tracer("src.governed_financial_advisor.graph.nodes.evaluator_node")


@side_effect_node(kind="api_call", external_system="opa_engine")
async def evaluator_node(state: AgentState) -> dict[str, Any]:
    """
    System 3 Control Node: The "Real-Time Monitor".
    Previews the plan against the gateway's governor (dry run) and returns an
    advisory verdict. The advisor signs nothing: it is an untrusted client
    with no signing identity (POAM-2026-079). Authority to execute comes only
    from the gateway, which re-runs the full pipeline and seals the trade.

    Every trade step is dry-run, and the plan is approved only when every
    step's verdict proceeds. Only a single-step plan answered ``ALLOW``
    populates ``routing_verdict_cache``.
    """
    plan = state.get("execution_plan_output")
    if not plan:
        return {
            "risk_status": "REJECTED_REVISE",
            "risk_feedback": "No plan provided.",
            "routing_verdict_cache": None,
        }

    trades: list[dict[str, Any]] = []

    if isinstance(plan, dict):
        if (
            not plan.get("steps")
            and plan.get("reasoning")
            and not is_trade_action(plan.get("action"))
        ):
            logger.info(
                "[INFO] Evaluator: Plan has no steps. Treating as Analysis/Safe."
            )
            return {
                "evaluation_result": {
                    "verdict": "APPROVED",
                    "reasoning": "Plan involves no actions.",
                    "policy_check": "SKIPPED",
                    "semantic_check": "SKIPPED",
                },
                "risk_status": "APPROVED",
                "routing_verdict_cache": None,
            }

        try:
            trades = extract_trade_steps(plan)
        except (TypeError, ValueError) as exc:
            return {
                "risk_status": "REJECTED_REVISE",
                "risk_feedback": f"Trade step has invalid parameters: {exc}",
                "routing_verdict_cache": None,
            }

    # A plan without a trade step is previewed as market analysis.
    previews: list[tuple[str, dict[str, Any]]] = [
        (TRADE_ACTION, params) for params in trades
    ] or [("market_analysis", {})]

    # No STPA inputs are sent. The gateway binds latency_ms, drawdown and,
    # for a sell, portfolio_total server-side for every preview and for the
    # committing run (TradeInputResolver), dropping any value the advisor or
    # the model supplies. The dry run therefore sees the measured state.

    with tracer.start_as_current_span("evaluator.safety_check") as span:
        raw_risk = state.get("risk_attitude")
        risk_profile = raw_risk.capitalize() if raw_risk else "Moderate"
        responses: list[dict[str, Any]] = []
        for target_tool, target_params in previews:
            responses.append(
                await simulate_governance_check(
                    target_tool, target_params, risk_profile
                )
            )

        # The dry run proceeds on the same verdicts as the pre-trade gate
        # (trade_contract.PROCEED_VERDICTS). REQUIRE_APPROVAL proceeds to the
        # human-approval path instead of being re-planned: no revision can
        # remove an approval requirement, so treating it as a rejection only
        # looped the planner until it gave up. DENY, DEFER and errors still
        # send the plan back for revision. Every step must proceed.
        proceed = {v.value for v in PROCEED_VERDICTS}
        verdicts = [resp.get("verdict") for resp in responses]
        is_safe = all(v in proceed for v in verdicts)
        needs_approval = is_safe and any(
            v == GovernanceDecision.REQUIRE_APPROVAL for v in verdicts
        )
        if len(responses) == 1:
            safety_msg = responses[0].get("message", "Unknown safety status")
        else:
            safety_msg = "\n".join(
                f"Trade step {i}: {resp.get('message', 'Unknown safety status')}"
                for i, resp in enumerate(responses, start=1)
            )
        # The decisive dry run: the first refused step, else the last step.
        decisive = next(
            (
                resp
                for resp, v in zip(responses, verdicts, strict=True)
                if v not in proceed
            ),
            responses[-1],
        )
        opa_results = decisive.get("opa_results")

        span.set_attribute("safety_check.passed", is_safe)
        span.set_attribute("safety_check.requires_approval", needs_approval)
        span.set_attribute("safety_check.trade_steps", len(trades))

    verdict = "APPROVED" if is_safe else "REJECTED"
    risk_status = "REJECTED_REVISE" if not is_safe else "APPROVED"

    feedback_msg = safety_msg
    if not is_safe:
        feedback_msg += (
            "\n\n**Action Required:** Governance policy violation. Please revise."
        )

    # One cache entry binds one order: a multi-step plan is never cached.
    routing_cache = (
        build_routing_verdict_cache(
            trades[0],
            verdict=str(verdicts[0] or ""),
            envelope=responses[0] if isinstance(responses[0], dict) else None,
        )
        if len(trades) == 1
        else None
    )

    # NOTE: Output screening/masking is handled by the dedicated nemo_output_rail_node
    # (the final LangGraph node before END on every non-blocked path).
    # The fail-open try/except that previously called verify_and_mask_output() here
    # has been REMOVED — ADR 2026-03-09b.  Do not re-add it here.

    return {
        "evaluation_result": {
            "verdict": verdict,
            "reasoning": safety_msg,
            "policy_check": "PASSED" if is_safe else "FAILED",
            "requires_approval": needs_approval,
        },
        "opa_results": opa_results,  # Pass OPA metadata to Auditor!
        "risk_status": risk_status,
        "risk_feedback": feedback_msg,
        "routing_verdict_cache": routing_cache,
    }
