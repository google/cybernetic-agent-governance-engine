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
Gateway-Internal NeMo Action Implementations

These async actions delegate to the SymbolicGovernor singleton running inside the
Hybrid Gateway process. They are for GATEWAY-INTERNAL use only.

PRODUCTION registration: config.rails.actions (HTTP-delegating, canonical)
These gateway-internal actions are NOT registered with the top-level NeMo Guardrails instance.

See: src.governed_financial_advisor.governance.nemo_action_registry for registration logic.

Architecture note (re-entrant loop fix):
    These actions NO LONGER import ``symbolic_governor`` from ``singletons`` or call
    ``stpa_validator.validate()`` / ``safety_filter.verify_action()`` directly.
    Doing so created a cyclic dependency: NeMo (Layer 0) → SymbolicGovernor sub-components
    → which then ran again inside ``_run_checks()`` moments later (double execution).

    Instead, ``NeMoManager`` calls ``symbolic_governor.pre_check(params)`` BEFORE invoking
    NeMo rails and injects the results into the NeMo context under the key
    ``"pre_check_results"``.  Actions read from that pre-computed dict.

    Fail-open contract: if ``pre_check_results`` is absent from context (e.g. during
    unit tests or cold-start races), actions return ``True`` (ALLOW) with a WARNING log.
    NeMo is Layer 0; the full SymbolicGovernor pipeline (OPA + STPA + CBF) still runs
    downstream and is the authoritative safety gate.
"""

import logging
import os
from typing import Any

logger = logging.getLogger("NeMo.Actions")

# ---------------------------------------------------------------------------
# Internal helper — read pre-computed results from NeMo context
# ---------------------------------------------------------------------------

_PRE_CHECK_KEY = "pre_check_results"


def _get_pre_check(context: dict[str, Any]) -> dict[str, Any] | None:
    """Return the pre-computed governance results injected by NeMoManager, or None."""
    return context.get(_PRE_CHECK_KEY)


# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------


async def CheckApprovalTokenAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates that an approval token is present (SC-1).
    Reads pre-computed STPA result from NeMo context.
    Fail Open: Returns True (ALLOW) with WARNING if pre_check_results is absent.
    """
    pre_check = _get_pre_check(context)
    if pre_check is None:
        logger.warning(
            "⚠️ NeMo Action WARN: CheckApprovalTokenAction — pre_check_results not in context "
            "(fail-open; full pipeline will still run)."
        )
        return True

    stpa_result = pre_check.get("stpa_result", {})
    violations = stpa_result.get("violations", [])

    # Filter to SC-1 (approval token) violations only
    sc1_violations = [
        v for v in violations if "SC-1" in v or "approval_token" in v.lower()
    ]

    if sc1_violations:
        logger.warning(
            "🛡️ NeMo Action BLOCKED: CheckApprovalTokenAction - %s", sc1_violations
        )
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckApprovalTokenAction")
    return True


async def CheckLatencyAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates latency (SC-2/FIN-2). Alias for check_data_latency.
    """
    return await CheckDataLatencyAction(context, event)


async def CheckDataLatencyAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates market data latency (FIN-2).
    Reads pre-computed STPA result from NeMo context.
    Fail Open: Returns True (ALLOW) with WARNING if pre_check_results is absent.
    """
    latency = context.get("latency_ms")
    if latency is None:
        logger.warning(
            "🛡️ NeMo Action BLOCKED: CheckDataLatencyAction - Latency unknown (Fail Closed)"
        )
        return False

    pre_check = _get_pre_check(context)
    if pre_check is None:
        logger.warning(
            "⚠️ NeMo Action WARN: CheckDataLatencyAction — pre_check_results not in context "
            "(fail-open; full pipeline will still run)."
        )
        return True

    stpa_result = pre_check.get("stpa_result", {})
    violations = stpa_result.get("violations", [])

    # Filter to FIN-2 (latency) violations only
    fin2_violations = [v for v in violations if "FIN-2" in v or "latency" in v.lower()]

    if fin2_violations:
        logger.warning(
            "🛡️ NeMo Action BLOCKED: CheckDataLatencyAction - %s", fin2_violations
        )
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckDataLatencyAction")
    return True


async def CheckDrawdownLimitAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates daily drawdown limit (UCA-5).
    Reads pre-computed CBF result from NeMo context.
    Fail Open: Returns True (ALLOW) with WARNING if pre_check_results is absent.
    """
    pre_check = _get_pre_check(context)
    if pre_check is None:
        logger.warning(
            "⚠️ NeMo Action WARN: CheckDrawdownLimitAction — pre_check_results not in context "
            "(fail-open; full pipeline will still run)."
        )
        return True

    cbf_result = pre_check.get("cbf_result", {})
    allowed = cbf_result.get("allowed", True)
    reason = cbf_result.get("reason", "")

    if not allowed:
        logger.warning("🛡️ NeMo Action BLOCKED: CheckDrawdownLimitAction - %s", reason)
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckDrawdownLimitAction")
    return True


async def CheckSlippageRiskAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates slippage risk (UCA-6).
    Reads pre-computed STPA result from NeMo context (UCA-6 covers slippage/volume).
    Fail Open: Returns True (ALLOW) with WARNING if pre_check_results is absent.
    """
    pre_check = _get_pre_check(context)
    if pre_check is None:
        logger.warning(
            "⚠️ NeMo Action WARN: CheckSlippageRiskAction — pre_check_results not in context "
            "(fail-open; full pipeline will still run)."
        )
        return True

    stpa_result = pre_check.get("stpa_result", {})
    violations = stpa_result.get("violations", [])

    # Filter to UCA-6 (slippage/volume) violations only
    uca6_violations = [
        v
        for v in violations
        if "UCA-6" in v or "slippage" in v.lower() or "volume" in v.lower()
    ]

    if uca6_violations:
        logger.warning(
            "🛡️ NeMo Action BLOCKED: CheckSlippageRiskAction - %s", uca6_violations
        )
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckSlippageRiskAction")
    return True


async def CheckAtomicExecutionAction(
    context: dict[str, Any] = {}, event: dict[str, Any] = {}
) -> bool:
    """
    Validates atomic execution capabilities.
    Fail Closed: If required_legs > 1 and audit_trail is incomplete, returns False.
    This action does not use pre_check_results — it reads directly from context
    because it checks structural properties of the request, not governor sub-components.
    """
    required_legs = context.get("required_legs", event.get("required_legs", 1))
    try:
        required_legs = int(required_legs)
    except (TypeError, ValueError):
        required_legs = 1

    if required_legs <= 1:
        return True  # Single-leg trade — always atomic

    audit_trail = context.get("audit_trail", event.get("audit_trail", []))
    if not audit_trail:
        logger.warning(
            "🛡️ NeMo Action BLOCKED: CheckAtomicExecutionAction - "
            "Multi-leg trade requires %d legs but audit_trail is empty (Fail Closed).",
            required_legs,
        )
        return False

    completed_legs = {
        entry.get("leg_index") for entry in audit_trail if isinstance(entry, dict)
    }
    for required_leg in range(1, required_legs):
        if required_leg not in completed_legs:
            logger.warning(
                "🛡️ NeMo Action BLOCKED: CheckAtomicExecutionAction - "
                "Leg %d missing from audit_trail (Fail Closed).",
                required_leg,
            )
            return False

    return True


# ---------------------------------------------------------------------------
# Snake_case aliases for test imports
# ---------------------------------------------------------------------------
check_approval_token = CheckApprovalTokenAction
check_data_latency = CheckDataLatencyAction
check_drawdown_limit = CheckDrawdownLimitAction
check_slippage_risk = CheckSlippageRiskAction
check_atomic_execution = CheckAtomicExecutionAction


async def InvokeVllmFallbackAction(  # type: ignore[no-untyped-def]
    context: dict | None = None,
    events: list | None = None,
    content: str | None = None,
    **kwargs,  # type: ignore[assignment]
) -> str:
    """
    Action to call vLLM directly for fallback responses.
    Accepts context/events to satisfy NeMo's potential automatic injection, plus explicit content.
    """
    logger.debug(
        "ACTION ARGS: context=%s, events=%s, content=%s, kwargs=%s",
        context,
        events,
        content,
        kwargs,
    )
    # Handle case where content might be passed as positional or keyword, or missing
    # formatting content to be safe
    final_content = content or kwargs.get("content", "")

    logger.warning(f"🔔 InvokeVllmFallbackAction CALLED. content='{final_content}'")

    from src.governed_financial_advisor.utils.telemetry import genai_span

    with genai_span(
        "guardrails.vllm_fallback",
        prompt=final_content,
        model=os.environ.get("MODEL_FAST", "vllm-fast"),
    ) as span:
        if span:
            # ISO 42001 Compliance: Transparency & Explainability
            span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.10.1")
            span.set_attribute(
                "langfuse.trace.metadata.iso.requirement", "Transparency"
            )
            span.set_attribute(
                "langfuse.trace.metadata.guardrails.intervention", "fallback"
            )
            span.set_attribute("langfuse.observation.type", "generation")

        try:
            if not final_content:
                logger.warning(
                    "InvokeVllmFallbackAction returning default due to empty content"
                )
                return "I apologize, but I didn't catch that."

            logger.debug(
                "Executing InvokeVllmFallbackAction with content='%s'", final_content
            )

            # Restore actual VLLM call for fallback
            from langchain_core.messages import HumanMessage

            from src.gateway.governance.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM()
            # Create a simple message list
            messages = [HumanMessage(content=final_content)]

            # Use _acall (or _agenerate) directly
            response = await llm._acall(messages)  # type: ignore[arg-type]

            if span:
                span.set_attribute("langfuse.observation.output", response)

            logger.debug(
                "InvokeVllmFallbackAction returning response length=%d", len(response)
            )
            return response

        except Exception as e:
            logger.error(f"❌ InvokeVllmFallbackAction failed: {e}")
            logger.debug("InvokeVllmFallbackAction EXCEPTION: %s", e)
            import traceback

            traceback.print_exc()
            return "I apologize, but I encountered an error generating a response."
