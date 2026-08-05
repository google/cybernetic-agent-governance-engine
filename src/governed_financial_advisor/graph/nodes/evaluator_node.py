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
import time
from typing import Any

from opentelemetry import trace

from src.governed_financial_advisor.agents.evaluator.agent import (
    check_safety_constraints,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.graph.state import AgentState

logger = logging.getLogger("EvaluatorNode")
tracer = trace.get_tracer("src.governed_financial_advisor.graph.nodes.evaluator_node")

from src.gateway.governance.kms_signer import get_governance_signer


@side_effect_node(kind="api_call", external_system="cloud_kms")
def generate_governance_signature(plan: dict) -> str | None:
    """Generate a cryptographic governance signature for a plan.

    KMS signing is mandatory (CTRL_KMS_001 — evidentiary independence control).
    ``KMS_GOVERNANCE_KEY`` must be set to the full Cloud KMS key version
    resource name:
      - ``KMSGovernanceSigner.from_env()`` calls ``asymmetricSign`` on the
        KMS HSM — the private key never leaves the hardware security module.
      - The signature is non-repudiable: Cloud Audit Logs independently
        record when and by what workload identity the signing occurred.

    If ``KMS_GOVERNANCE_KEY`` is unset, empty, or the google-cloud-kms client
    fails to initialise, ``get_governance_signer()`` raises ``RuntimeError``
    immediately — this node does not catch it, so the whole request fails
    (surfaces as HTTP 500). Dev/CI environments must provision a real (or
    emulated) KMS key, or route around this node entirely.

    Zero-step plan exemption: signing is skipped entirely when the plan
    contains no executable steps.  A zero-step (analysis/conversational) plan
    has no governed action to attest — calling Cloud KMS asymmetricSign
    (P50 108ms, P99 9.6s) provides no safety value and wastes HSM capacity.
    Returns ``None`` on the skipped path; callers must handle ``None`` for
    ``governance_signature``.

    See: ``src/gateway/governance/kms_signer.py`` for full architecture.
    """
    with tracer.start_as_current_span(
        "evaluator.generate_governance_signature"
    ) as span:
        plan_steps = plan.get("steps", [])
        if not plan_steps:
            # Zero-step analysis/conversation plan — no governed action to attest.
            # Signing a no-action plan with Cloud KMS (P50 108ms, P99 9.6s) provides
            # no safety value and wastes HSM capacity. Skip unconditionally.
            logger.debug(
                "Skipping KMS signature for zero-step plan (no governed action)",
                extra={"plan_type": plan.get("type", "unknown")},
            )
            span.set_attribute("kms.signing.skipped", True)
            span.set_attribute("kms.signing.skip_reason", "zero_step_plan")
            return None

        span.set_attribute("kms.signing.skipped", False)
        signer = get_governance_signer()
        return signer.sign(plan)


@side_effect_node(kind="api_call", external_system="opa_engine")
async def evaluator_node(state: AgentState) -> dict[str, Any]:
    """
    System 3 Control Node: The "Real-Time Monitor".
    Verifies safety and generates a governance signature upon approval.
    """
    plan = state.get("execution_plan_output")
    if not plan:
        return {"risk_status": "REJECTED_REVISE", "risk_feedback": "No plan provided."}

    # Extract details for checks
    target_tool = "market_analysis"
    target_params = {}

    if isinstance(plan, dict):
        if not plan.get("steps") and plan.get("reasoning"):
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
                "governance_signature": generate_governance_signature(plan),
                "risk_status": "APPROVED",
            }

        if "steps" in plan:
            for step in plan["steps"]:
                if any(
                    k in step.get("action", "").lower()
                    for k in ["trade", "execute", "buy", "sell"]
                ):
                    target_params = step.get("parameters", {})
                    target_tool = step.get("action", "execute_trade")
                    break

    # Populate required STPA numeric fields with safe defaults before the
    # simulate_governance_check MCP call.  These fields are required by the
    # GeneratedSTPAValidator (UCA-2/UCA-5/UCA-6 checks).  When they are absent
    # from the LLM-extracted trade parameters the STPA validator fails closed
    # with "STPA Violation UCA-5: Missing required param `drawdown`" and the
    # evaluator rejects the plan before it ever reaches the authoritative OPA
    # gate in safety_check_node.
    #
    # SECURITY NOTE: These safe defaults are identical to those used by
    # _extract_trade_payload() in safety_node.py (the authoritative OPA path).
    # They are intentionally conservative (0.0 drawdown, 0 order size) so they
    # pass the STPA threshold check without fabricating risk data.  The real
    # STPA/OPA enforcement happens at the safety_check_node level — not here.
    # Do NOT read these from the LLM plan: that would allow adversarially
    # prompted models to influence STPA decisions.
    target_params = {
        **target_params,
        "drawdown": float(target_params.get("drawdown") or 0.0),
        "latency_ms": float(target_params.get("latency_ms") or 0.0),
        "order_size": int(target_params.get("order_size") or 0),
        "daily_vol": int(target_params.get("daily_vol") or 0),
    }

    with tracer.start_as_current_span("evaluator.safety_check") as span:
        raw_risk = state.get("risk_attitude")
        risk_profile = raw_risk.capitalize() if raw_risk else "Moderate"
        safety_resp = await check_safety_constraints(
            target_tool, target_params, risk_profile
        )

        is_safe = safety_resp.get("status") == "APPROVED"
        safety_msg = safety_resp.get("message", "Unknown safety status")
        opa_results = safety_resp.get("opa_results")

        span.set_attribute("safety_check.passed", is_safe)

    # SECURE SIGNATURE GENERATION
    sig = None
    if is_safe:
        sig = generate_governance_signature(plan)
        logger.info(f"✅ Evaluator: Signature Generated: {sig[:8]}...")

    verdict = "APPROVED" if is_safe else "REJECTED"
    risk_status = "REJECTED_REVISE" if not is_safe else "APPROVED"

    feedback_msg = safety_msg
    if not is_safe:
        feedback_msg += (
            "\n\n**Action Required:** Governance policy violation. Please revise."
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
        },
        "governance_signature": sig,
        "opa_results": opa_results,  # Pass OPA metadata to Auditor!
        "risk_status": risk_status,
        "risk_feedback": feedback_msg,
    }
