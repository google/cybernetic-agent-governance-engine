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
"""

import logging
import os
from typing import Any

from src.gateway.governance.singletons import symbolic_governor

logger = logging.getLogger("NeMo.Actions")

async def CheckApprovalTokenAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates that an approval token is present (SC-1).
    Fail Closed: Returns False if token is missing.
    """
    token = context.get("approval_token")
    # STPAValidator SC-1 checks if token is not None
    violations = symbolic_governor.stpa_validator.validate("execute_trade", {"approval_token": token})

    if violations:
        logger.warning(f"🛡️ NeMo Action BLOCKED: CheckApprovalTokenAction - {violations}")
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckApprovalTokenAction")
    return True

async def CheckLatencyAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates latency (SC-2/FIN-2). Alias for check_data_latency.
    """
    return await CheckDataLatencyAction(context, event)

async def CheckDataLatencyAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates market data latency (FIN-2).
    Fail Closed: Returns False if latency is unknown or high.
    """
    latency = context.get("latency_ms")
    if latency is None:
        logger.warning("🛡️ NeMo Action BLOCKED: CheckDataLatencyAction - Latency unknown (Fail Closed)")
        return False

    violations = symbolic_governor.stpa_validator.validate("execute_trade", {"latency_ms": latency})

    if violations:
        logger.warning(f"🛡️ NeMo Action BLOCKED: CheckDataLatencyAction - {violations}")
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckDataLatencyAction")
    return True

async def CheckDrawdownLimitAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates daily drawdown limit (UCA-5).
    Checks if system is healthy enough to trade.
    """
    amount = context.get("amount", 0.0)
    # CBF Check via SafetyFilter
    result = symbolic_governor.safety_filter.verify_action("execute_trade", {"amount": amount})

    if result.startswith("UNSAFE"):
        logger.warning(f"🛡️ NeMo Action BLOCKED: CheckDrawdownLimitAction - {result}")
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckDrawdownLimitAction")
    return True

async def CheckSlippageRiskAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates slippage risk (UCA-6).
    """
    amount = context.get("amount", 0.0)
    # SafetyFilter handles both Drawdown and Slippage
    result = symbolic_governor.safety_filter.verify_action("execute_trade", {"amount": amount})

    if result.startswith("UNSAFE"):
        logger.warning(f"🛡️ NeMo Action BLOCKED: CheckSlippageRiskAction - {result}")
        return False

    logger.debug("🛡️ NeMo Action PASSED: CheckSlippageRiskAction")
    return True

async def CheckAtomicExecutionAction(context: dict[str, Any] = {}, event: dict[str, Any] = {}) -> bool:
    """
    Validates atomic execution capabilities.
    Fail Closed: If required_legs > 1 and audit_trail is incomplete, returns False.
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

    completed_legs = {entry.get("leg_index") for entry in audit_trail if isinstance(entry, dict)}
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


async def InvokeVllmFallbackAction(context: dict = {}, events: list = [], content: str = None, **kwargs) -> str:
    """
    Action to call vLLM directly for fallback responses.
    Accepts context/events to satisfy NeMo's potential automatic injection, plus explicit content.
    """
    logger.debug("ACTION ARGS: context=%s, events=%s, content=%s, kwargs=%s", context, events, content, kwargs)
    # Handle case where content might be passed as positional or keyword, or missing
    # formatting content to be safe
    final_content = content or kwargs.get('content', "")
    
    logger.warning(f"🔔 InvokeVllmFallbackAction CALLED. content='{final_content}'")
    
    from src.governed_financial_advisor.utils.telemetry import genai_span
    
    with genai_span("guardrails.vllm_fallback", prompt=final_content, model=os.environ.get("MODEL_FAST", "vllm-fast")) as span:
        if span:
             # ISO 42001 Compliance: Transparency & Explainability
             span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.10.1")
             span.set_attribute("langfuse.trace.metadata.iso.requirement", "Transparency")
             span.set_attribute("langfuse.trace.metadata.guardrails.intervention", "fallback")
             span.set_attribute("langfuse.observation.type", "generation")

        try:
            if not final_content:
                logger.warning("InvokeVllmFallbackAction returning default due to empty content")
                return "I apologize, but I didn't catch that."
                
            logger.debug("Executing InvokeVllmFallbackAction with content='%s'", final_content)
            
            # Restore actual VLLM call for fallback
            from src.gateway.governance.nemo.vllm_client import VLLMLLM
            from langchain_core.messages import HumanMessage
    
            llm = VLLMLLM()
            # Create a simple message list
            messages = [HumanMessage(content=final_content)]
            
            # Use _acall (or _agenerate) directly
            response = await llm._acall(messages)
            
            if span:
                 span.set_attribute("langfuse.observation.output", response)
            
            logger.debug("InvokeVllmFallbackAction returning response length=%d", len(response))
            return response

        except Exception as e:
            logger.error(f"❌ InvokeVllmFallbackAction failed: {e}")
            logger.debug("InvokeVllmFallbackAction EXCEPTION: %s", e)
            import traceback
            traceback.print_exc()
            return "I apologize, but I encountered an error generating a response."
