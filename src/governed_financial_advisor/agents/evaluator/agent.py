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

import json
import logging
import os
from typing import Any

from langchain_core.messages import SystemMessage
from langgraph.prebuilt import create_react_agent

from src.gateway.infrastructure.mcp_client import (
    MCPToolExecutionError,
    MCPToolOutcomeUnknownError,
    get_mcp_client,
)
from src.governed_financial_advisor.infrastructure.llm.models import chat_model

logger = logging.getLogger("EvaluatorAgent")


# --- TOOLS (Real Implementations via Gateway) ---


async def check_market_status(symbol: str) -> str:
    """
    Checks real market status via Gateway (MCP).
    """
    try:
        return await get_mcp_client().call_tool(
            "check_market_status", {"symbol": symbol}
        )
    except MCPToolExecutionError as e:
        logger.error("Market Check Failed: gateway tool error: %s", e.text)
        return f"ERROR: Could not fetch market status: {e.text}"
    except Exception as e:
        logger.error(f"Market Check Failed: {e}")
        return f"ERROR: Could not fetch market status: {e}"


async def simulate_governance_check(
    target_tool: str, target_params: dict[str, Any], risk_profile: str = "Medium"
) -> dict[str, Any]:
    """
    Calls the Gateway's SymbolicGovernor to perform a dry-run simulation check.

    This is a SIMULATION ONLY — it calls ``simulate_governance_check`` on the
    Gateway MCP server, which invokes ``symbolic_governor.verify()`` in sim_mode.
    It does NOT enforce governance or block execution.  Mandatory enforcement
    is handled in infrastructure by the ``safety_check`` LangGraph node.

    Returns structured dict with ``verdict`` (a ``GovernanceDecision`` value,
    or ``"ERROR"``), violations, and OPA results.

    BUG-MCP-DICT-001 fix: GatewayMCPClient.call_tool() always returns a plain
    ``str`` — it joins every MCP content block's ``.text`` field with "\n"
    regardless of the underlying tool's declared return type (see
    ``mcp_client.py::call_tool``). The Gateway's ``simulate_governance_check``
    MCP tool (mcp_tool_server.py) returns a ``dict[str, Any]``, which the MCP
    transport serialises to a JSON string content block; the client then
    handed that raw JSON string straight back to ``evaluator_node.py``, which
    called ``.get("status")`` on it and crashed with
    ``AttributeError: 'str' object has no attribute 'get'`` — a real
    production defect surfaced only once the KMS/Redis/schema fixes earlier
    in this session let a request finally reach this code path. Parsing the
    string back into a dict here (at the single call site expecting
    structured data) fixes this without having to change the generic
    ``call_tool()`` contract that every other (string-returning) MCP tool
    call in this codebase relies on.
    """
    try:
        raw = await get_mcp_client().call_tool(
            "simulate_governance_check",
            {
                "target_tool": target_tool,
                "target_params": target_params,
                "risk_profile": risk_profile,
            },
        )
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
            logger.warning(
                "simulate_governance_check: MCP tool returned a non-JSON-dict "
                "string; treating as an error. raw=%r",
                raw[:500],
            )
        return {
            "verdict": "ERROR",
            "message": f"Unexpected MCP response type/shape: {raw!r:.200}",
            "violations": ["System Error"],
        }
    except MCPToolExecutionError as e:
        logger.error("Safety Simulation Failed: gateway tool error: %s", e.text)
        return {
            "verdict": "ERROR",
            "message": f"Gateway tool error: {e.text}",
            "violations": ["System Error"],
        }
    except Exception as e:
        logger.error(f"Safety Simulation Failed: {e}")
        return {"verdict": "ERROR", "message": str(e), "violations": ["System Error"]}


# --- SAFETY INTERVENTION TOOL (Module 5) ---
async def safety_intervention(reason: str) -> str:
    """
    EMERGENCY STOP: Signals the Gateway to interrupt any pending execution.
    Sets the 'safety_violation' flag in shared state.
    """
    logger.warning(f"🛑 Evaluator Triggering Intervention: {reason}")
    try:
        # Call the intervention tool on Gateway (which sets Redis key)
        return await get_mcp_client().call_tool(
            "trigger_safety_intervention", {"reason": reason}
        )
    except MCPToolExecutionError as e:
        logger.critical("FATAL: Gateway refused the intervention: %s", e.text)
        return f"ERROR: Intervention Failed: {e.text}"
    except MCPToolOutcomeUnknownError as e:
        # The lock may or may not be set; report failure so it is re-triggered
        # (the gateway tool is idempotent).
        logger.critical("FATAL: Intervention outcome unknown: %s", e)
        return f"ERROR: Intervention Failed: outcome unknown, re-trigger it: {e}"
    except Exception as e:
        logger.critical(f"FATAL: Could not trigger intervention: {e}")
        return f"ERROR: Intervention Failed: {e}"


# --- AGENT DEFINITION ---

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

    llm = chat_model(
        "fast",
        model=model,
        base_url=api_base,
        api_key=api_key,
        temperature=0.0,
        require_api_key=True,
    )

    # verify_semantic_nemo and direct OPA HTTP calls removed — NeMo runs as a
    # mandatory graph node and OPA runs exclusively inside the gateway UDS sidecar (OP-1).
    tools = [
        check_market_status,
        simulate_governance_check,
        safety_intervention,
    ]

    agent_graph = create_react_agent(
        model=llm,
        tools=tools,  # type: ignore[arg-type]
        state_modifier=SystemMessage(content=_SYSTEM_PROMPT),  # type: ignore[arg-type]
    )

    return agent_graph
