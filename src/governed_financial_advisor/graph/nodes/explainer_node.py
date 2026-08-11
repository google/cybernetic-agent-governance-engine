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

from langchain_core.messages import SystemMessage

from config.settings import MODEL_FAST, MODEL_REASONING
from src.gateway.governance.kms_signer import get_governance_signer
from src.governed_financial_advisor.agents.explainer.agent import (
    create_explainer_agent,
    get_explainer_instruction,
)
from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.utils.telemetry import get_tracer
from src.governed_financial_advisor.utils.text_utils import strip_thinking_tags

logger = logging.getLogger("GovernanceAuditor")


def verify_hmac_signature(state: AgentState) -> str:
    """Verify the governance signature in the state.

    Uses the KMSGovernanceSigner for verification:
      - In production: verifies against the Cloud KMS public key
        (no access to signing key needed — true separation of duties).
      - In dev/CI: falls back to HMAC comparison using GOVERNANCE_SALT.

    Returns a human-readable status string for the audit report.
    """
    sig = state.get("governance_signature")
    plan = state.get("execution_plan_output")

    if not plan:
        return "[HMAC: UNSIGNED]"

    if not sig:
        return "[HMAC: FAILED]"

    signer = get_governance_signer()
    if signer.verify(plan, sig):  # type: ignore[arg-type]
        mode = "KMS" if signer.is_kms_active else "HMAC"
        return f"[{mode}: VERIFIED]"
    else:
        return "[SIGNATURE: FAILED]"


def map_opa_rules(opa_results: dict) -> list[str]:
    """Parses OPA explanation trace for triggered rules."""
    rules = []
    if not opa_results or "explanation" not in opa_results:
        return ["No OPA trace available."]

    explanation = opa_results.get("explanation", [])
    for event in explanation:
        # Looking for 'exit' events of rules in the finance package
        if event.get("type") == "exit":
            node = event.get("node", "")
            if "finance" in node and "/" in node:
                loc = event.get("location", {})
                file = loc.get("file", "unknown")
                line = loc.get("line", "unknown")
                rule_name = node.split("/")[-1]
                rules.append(f"Rule: {file} -> {rule_name} (Line {line})")

    return list(set(rules))  # Unique rules


def _is_low_risk_verdict(governance_result: dict) -> bool:
    """Return True if the verdict is a clean ALLOW with no escalation signals.

    Low-risk verdicts skip the expensive reasoning-model justification call and
    use a single fast-model call for both justification and user response.
    High-risk verdicts (DENY, MANUAL_REVIEW, any violation, HITL escalation,
    or elevated risk score) always use the full two-call path.
    """
    return (
        governance_result.get("verdict") in ("ALLOW", "PERMIT")
        and not governance_result.get("violations")
        and not governance_result.get("hitl_required")
        and governance_result.get("risk_score", 1.0) < 0.5
    )


async def explainer_node(state: AgentState) -> dict[str, Any]:
    """
    Formal Governance Auditor Node.
    Extracts audit trail, verifies signatures, maps OPA rules, and justifies the verdict.

    Optimization (Group D / D1): For low-risk verdicts (clean ALLOW, no violations,
    no HITL escalation, risk_score < 0.5), a single fast-model call produces both the
    justification narrative and the user-facing response, skipping the slower
    MODEL_REASONING call entirely.  For high-risk verdicts the original two-call path
    is preserved: MODEL_REASONING for justification, MODEL_FAST for response.
    """
    logger.info("🛡️ Explainer Node: Acting as Formal Governance Auditor.")
    tracer = get_tracer()

    with tracer.start_as_current_span("Auditor: GovernanceVerification") as span:
        # 1. Audit Trail Extraction
        sig_status = verify_hmac_signature(state)
        opa_results = state.get("opa_results")
        rules = map_opa_rules(opa_results)  # type: ignore[arg-type]
        execution_plan = state.get("execution_plan_output", "No plan.")
        evaluation_result = state.get("evaluation_result", {})
        verdict = evaluation_result.get("verdict", "UNKNOWN")  # type: ignore[union-attr]
        user_msg = (
            state["messages"][-1].content if state.get("messages") else "No context"
        )

        if _is_low_risk_verdict(evaluation_result):  # type: ignore[arg-type]
            # --- Single fast-LLM call: combined justification + user response ---
            # Skip the slow reasoning-model call for clean ALLOW verdicts.
            logger.info(
                "🟢 Explainer: low-risk verdict (%s) — using single fast-model call",
                verdict,
            )
            combined_prompt = (
                f"{get_explainer_instruction()}\n\n"
                f"You are the Governance Auditor. The system reached a verdict of "
                f"{verdict} (low-risk clean ALLOW — no violations, no escalation).\n"
                f"OPA Rules triggered: {', '.join(rules)}\n"
                f"User Intent/Plan: {execution_plan}\n\n"
                f"In 2-3 sentences, explain how the OPA rules relate to the user's "
                f"intent (Verdict Justification). Then provide the final user-facing "
                f"response.\n\n"
                f"USER MESSAGE: {user_msg}\n"
                f"ACTION PLAN: {execution_plan}\n"
            )
            fast_llm = create_explainer_agent(MODEL_FAST)  # type: ignore[arg-type]
            final_resp = await fast_llm.ainvoke(
                [SystemMessage(content=combined_prompt)]
            )
            content = strip_thinking_tags(final_resp.content)
            justification = f"[Low-risk verdict — justification embedded in response. Verdict: {verdict}]"
            span.set_attribute("explainer.llm_calls", 1)
            span.set_attribute("explainer.optimization", "low_risk_single_call")
        else:
            # --- Full two-call path: reasoning model for justification, fast model for response ---
            logger.info(
                "🔴 Explainer: high-risk verdict (%s) — using full two-call path",
                verdict,
            )

            # 2. Semantic Justification (using MODEL_REASONING)
            justification = (
                "Manual justification required: No reasoning model available."
            )
            try:
                llm = create_explainer_agent(MODEL_REASONING)  # type: ignore[arg-type]
                prompt = (
                    f"You are the Governance Auditor. Provide a concise 2-3 sentence 'Verdict Justification'.\n"
                    f"Context: The system reached a verdict of {verdict}.\n"
                    f"OPA Rules triggered: {', '.join(rules)}\n"
                    f"User Intent/Plan: {execution_plan}\n"
                    f"Explain how the hard OPA rules relate to the semantic intent of the user."
                )
                response = await llm.ainvoke([SystemMessage(content=prompt)])
                justification = strip_thinking_tags(response.content)
            except Exception as e:
                logger.error(f"Reasoning failure: {e}")

            # 3a. Format Structured Summary (needed as context for the fast-model call)
            summary = (
                f"### 🛡️ Governance Audit Report\n"
                f"- **Integrity Check**: {sig_status}\n"
                f"- **System Verdict**: {verdict}\n\n"
                f"#### 📜 Policy Rule Mapping\n"
            )
            for rule in rules:
                summary += f"- {rule}\n"
            summary += f"\n#### ⚖️ Verdict Justification\n{justification}\n"

            # 4. Final Response Generation (Faithfulness)
            final_llm = create_explainer_agent(MODEL_FAST)  # type: ignore[arg-type]
            explainer_sys = (
                f"{get_explainer_instruction()}\n\n"
                f"GOVERNANCE AUDIT:\n{summary}\n\n"
                f"USER MESSAGE: {user_msg}\n"
                f"ACTION PLAN: {execution_plan}\n"
            )
            final_resp = await final_llm.ainvoke([SystemMessage(content=explainer_sys)])
            content = strip_thinking_tags(final_resp.content)
            span.set_attribute("explainer.llm_calls", 2)
            span.set_attribute("explainer.optimization", "full_two_call")

        # 3/5. Build governance_summary for audit trail (both paths)
        summary = (
            f"### 🛡️ Governance Audit Report\n"
            f"- **Integrity Check**: {sig_status}\n"
            f"- **System Verdict**: {verdict}\n\n"
            f"#### 📜 Policy Rule Mapping\n"
        )
        for rule in rules:
            summary += f"- {rule}\n"
        summary += f"\n#### ⚖️ Verdict Justification\n{justification}\n"

        return {
            "messages": [("ai", content)],
            "governance_summary": summary,
            "next_step": "FINISH",
        }
