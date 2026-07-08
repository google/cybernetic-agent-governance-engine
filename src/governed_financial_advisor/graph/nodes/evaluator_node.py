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
def generate_governance_signature(plan: dict) -> str:
    """Generate a cryptographic governance signature for a plan.

    In production (Cloud KMS configured via KMS_GOVERNANCE_KEY):
      - Calls ``asymmetricSign`` on the KMS HSM — the private key never
        leaves the hardware security module.
      - The signature is non-repudiable: Cloud Audit Logs independently
        record when and by what workload identity the signing occurred.

    In dev/CI (KMS not available):
      - Falls back to legacy HMAC-SHA256 using GOVERNANCE_SALT.
      - Emits an audit WARNING so the evidentiary gap is visible.

    See: ``src/gateway/governance/kms_signer.py`` for full architecture.
    """
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
            logger.info("[INFO] Evaluator: Plan has no steps. Treating as Analysis/Safe.")
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
