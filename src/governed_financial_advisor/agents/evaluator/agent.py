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
import json
import os
from typing import Any, Literal

import httpx
from opentelemetry import trace
from pydantic import BaseModel, Field

from src.governed_financial_advisor.infrastructure.mcp_client import get_mcp_client

logger = logging.getLogger("EvaluatorAgent")
tracer = trace.get_tracer("src.governed_financial_advisor.agents.evaluator")

# ---------------------------------------------------------------------------
# OPA direct HTTP helper — used by verify_policy_opa to avoid MCP round-trip.
# The OPA REST API endpoint is taken from the OPA_URL env var (same source as
# the gateway's OPAClient) and defaults to the standard OPA data API path.
# ---------------------------------------------------------------------------
_OPA_DEFAULT_URL = "http://localhost:8181/v1/data/trade/policy/decision"


async def _call_opa_direct(input_data: dict) -> str:
    """
    Post *input_data* to OPA's REST API and return the decision string.

    Returns one of ``"ALLOW"``, ``"DENY"``, ``"MANUAL_REVIEW"``, or a raw
    string value from the OPA result.  Falls back to ``"DENY"`` on any
    network or parse error so the caller can treat unknown responses safely.
    """
    opa_url = os.getenv("OPA_URL", _OPA_DEFAULT_URL)
    auth_token = os.getenv("OPA_AUTH_TOKEN")
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    with tracer.start_as_current_span("opa.evaluate_policy") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute("opa.url", opa_url)
        span.set_attribute("opa.action", input_data.get("action", "unknown"))
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.post(
                    opa_url,
                    json={"input": input_data},
                    headers=headers,
                )
                response.raise_for_status()
                decision = response.json().get("result", "DENY")
                span.set_attribute("opa.decision", str(decision))
                return decision
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            logger.error("OPA direct HTTP call failed: %s", exc)
            return "DENY"


# --- TOOLS (Real Implementations via Gateway) ---

async def check_market_status(symbol: str) -> str:
    """
    Checks real market status via Gateway (MCP).
    """
    try:
        return await get_mcp_client().call_tool("check_market_status", {"symbol": symbol})
    except Exception as e:
        logger.error(f"Market Check Failed: {e}")
        return f"ERROR: Could not fetch market status: {e}"

async def verify_policy_opa(action: str, params: str) -> str:
    """
    Checks Regulatory Policy (OPA) via a direct HTTP call to OPA's REST API.

    Previously this routed through the Gateway MCP tool ``evaluate_policy``.
    It now calls OPA directly so that policy evaluation has no MCP dependency.
    The OPA endpoint is resolved from the ``OPA_URL`` env var (default:
    ``http://localhost:8181/v1/data/trade/policy/decision``).
    """
    try:
        # Parse params
        params_dict: dict = {}
        if isinstance(params, str):
            try:
                cleaned_params = params.replace("'", '"')
                params_dict = json.loads(cleaned_params)
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse tool arguments as JSON: %s. params=%r", e, params)
                params_dict = {"description": params}
        elif isinstance(params, dict):
            params_dict = params

        # Ensure the action field is always present in the OPA input
        params_dict["action"] = action

        decision = await _call_opa_direct(params_dict)

        if decision == "ALLOW":
            return "APPROVED: Action matches policy."
        elif decision == "DENY":
            return "DENIED: Policy Violation."
        elif decision == "MANUAL_REVIEW":
            return "MANUAL_REVIEW: Requires human approval."
        else:
            return f"UNKNOWN: {decision}"
    except Exception as e:
        logger.error(f"OPA Check Failed: {e}")
        return f"DENIED: System Error: {e}"

async def verify_semantic_nemo(text: str) -> str:
    """
    Checks Semantic Safety via in-process NeMo guardrails (no MCP dependency).

    Calls validate_with_nemo() directly, mirroring the mandatory nemo_guardrail_node
    pattern. This avoids an extra MCP round-trip and ensures NeMo runs in-process
    for defense-in-depth policy checks in the evaluator tool path.
    """
    with tracer.start_as_current_span("nemo.verify_content_safety") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute("nemo.input_length", len(text))
        try:
            from src.governed_financial_advisor.graph.nodes.guardrail_node import (
                get_nemo_rails,
            )
            from src.gateway.governance.nemo.manager import validate_with_nemo

            rails = get_nemo_rails()
            is_safe, reason = await validate_with_nemo(text, rails)
            result = "SAFE" if is_safe else f"BLOCKED: {reason}"
            span.set_attribute("nemo.result", result[:256])
            span.set_attribute("nemo.is_safe", is_safe)
            return result
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            logger.error(f"Semantic Check Failed: {e}")
            return f"BLOCKED: System Error: {e}"

async def simulate_governance_check(target_tool: str, target_params: dict[str, Any], risk_profile: str = "Medium") -> dict[str, Any]:
    """
    Calls the Gateway's SymbolicGovernor to perform a dry-run simulation check.

    This is a SIMULATION ONLY — it calls ``simulate_governance_check`` on the
    Gateway MCP server, which invokes ``symbolic_governor.verify()`` in sim_mode.
    It does NOT enforce governance or block execution.  Mandatory enforcement
    is handled in infrastructure by the ``safety_check`` LangGraph node.

    Returns structured dict with status, violations, and OPA results.
    """
    try:
        return await get_mcp_client().call_tool(
            "simulate_governance_check",
            {
                "target_tool": target_tool,
                "target_params": target_params,
                "risk_profile": risk_profile
            }
        )
    except Exception as e:
        logger.error(f"Safety Simulation Failed: {e}")
        return {"status": "ERROR", "message": str(e), "violations": ["System Error"]}


# Backward-compatible alias — remove once all callers are updated
check_safety_constraints = simulate_governance_check

# --- NEW: SAFETY INTERVENTION TOOL (Module 5) ---
async def safety_intervention(reason: str) -> str:
    """
    EMERGENCY STOP: Signals the Gateway to interrupt any pending execution.
    Sets the 'safety_violation' flag in shared state.
    """
    logger.warning(f"🛑 Evaluator Triggering Intervention: {reason}")
    try:
        # Call the intervention tool on Gateway (which sets Redis key)
        return await get_mcp_client().call_tool("trigger_safety_intervention", {"reason": reason})
    except Exception as e:
        logger.critical(f"FATAL: Could not trigger intervention: {e}")
        return f"ERROR: Intervention Failed: {e}"

# --- AGENT DEFINITION ---

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import SystemMessage

_SYSTEM_PROMPT = """You are a policy evaluator agent for the Cybernetic Governance Engine.
Your role is to evaluate whether AI agent actions comply with governance policies,
risk thresholds, and regulatory requirements. Use the provided tools to assess compliance."""

def build_evaluator_agent() -> Any:
    """Build and return the evaluator agent as a compiled LangGraph.
    
    Returns:
        A compiled LangGraph (CompiledStateGraph) ready to be invoked with messages.
        
    Note:
        In LangChain v1.x / LangGraph 1.1.0+, create_react_agent returns a compiled
        graph optimized for LangGraph state management, not an AgentExecutor.
    """
    api_base = os.environ.get("VLLM_FAST_API_BASE")
    api_key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("MODEL_FAST")

    if not api_base:
        raise RuntimeError("VLLM_FAST_API_BASE must be set for the evaluator agent")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY must be set for the evaluator agent")

    llm = ChatOpenAI(
        base_url=api_base,
        api_key=api_key,
        model=model,
        temperature=0,
    )

    # verify_semantic_nemo removed — NeMo is now enforced as a mandatory graph node (ADR 2026-03-09)
    tools = [
        check_market_status,
        verify_policy_opa,
        simulate_governance_check,
        safety_intervention,
    ]

    # LangGraph 1.1.0+ prebuilt agent — returns a compiled graph
    # state_modifier replaces the old ChatPromptTemplate pattern
    agent_graph = create_react_agent(
        model=llm,
        tools=tools,
        state_modifier=SystemMessage(content=_SYSTEM_PROMPT)
    )
    
    return agent_graph


# Lazy singleton — built on first access to avoid RuntimeError at import time
# when VLLM_FAST_API_BASE / OPENAI_API_KEY are not set (e.g. unit-test collection).
# In v1.x this is a compiled LangGraph (CompiledStateGraph), not an AgentExecutor.
_evaluator_agent: Any = None


def get_evaluator_agent() -> Any:
    """Get or create the evaluator agent LangGraph.
    
    Returns:
        A compiled LangGraph (CompiledStateGraph) that can be invoked with:
        await agent.ainvoke({"messages": [("user", "query")]})
    """
    global _evaluator_agent
    if _evaluator_agent is None:
        _evaluator_agent = build_evaluator_agent()
    return _evaluator_agent
