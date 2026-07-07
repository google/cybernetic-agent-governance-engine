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
LangGraph Agent Nodes

Node functions for the main graph: Data Analyst, Execution Analyst, and Governed Trader.
Uses Dependency Injection pattern to allow mocking during tests.
"""

import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage

from src.governed_financial_advisor.agents.execution_analyst.agent import (
    create_execution_analyst_agent,
)
from src.governed_financial_advisor.utils.telemetry import get_tracer

logger = logging.getLogger(__name__)


def get_valid_last_message(state: dict[str, Any]) -> str:
    messages = state.get("messages", [])
    if not messages:
        return ""
    last_msg = messages[-1]
    if isinstance(last_msg, tuple):
        return str(last_msg[1])
    return getattr(last_msg, "content", str(last_msg))


def get_market_data_from_history(state: dict[str, Any]) -> str:
    # Basic implementation since we're inside the Execution Analyst
    # Typically this looks for ToolMessages or AI messages containing market data
    messages = state.get("messages", [])
    market_data = []
    for msg in reversed(messages):
        content = (
            getattr(msg, "content", "") if not isinstance(msg, tuple) else str(msg[1])
        )
        if "MARKET DATA" in content.upper() or "ANALYSIS" in content.upper():
            market_data.append(content)
            break
    return "\n".join(market_data)


async def data_analyst_node(state):
    """
    Executes the Data Analyst Subgraph.
    The Subgraph encapsulates a Thinker (DeepSeek) -> Doer (Llama 3.1) -> ToolNode (Market Data) pipeline.
    It returns the inherited state dict, seamlessly appending the ToolMessage to the global history.
    """
    logger.info("--- [Graph] Invoking Data Analyst Subgraph ---")

    from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
        data_analyst_graph,
    )

    # We invoke the subgraph natively with the global state.
    # LangGraph will run the internal state workflow and merge the outputs.
    # The return contains the new message history (including the tool output).
    result = await data_analyst_graph.ainvoke(state, {"recursion_limit": 10})

    return {
        "messages": result["messages"],
        # Provide an explicit next_step signal back to the parent graph if needed,
        # or just rely on the parent's Supervisor logic via returning END/FINISH.
        "data_analyst_ticker": result.get("reasoning_output", "UNKNOWN"),
    }


async def execution_analyst_node(state):
    """
    Native LangGraph Execution Analyst (Planner).
    Uses LangChain structured output (async).
    """
    logger.info("--- [Graph] Calling Execution Analyst (Planner) ---")

    # 1. Fetch the Runnable Sequence
    agent_chain = create_execution_analyst_agent()

    # 2. Extract context
    user_msg = get_valid_last_message(state)
    market_data_msg = get_market_data_from_history(state)

    # 3. Context Injection Logic
    # BUG-FIX: loop_count was reset to 0 on every non-REJECTED_REVISE pass, making
    # check_safety_signature's loop guard always see 0 and loop forever.
    # Now we always increment so the evaluator gate can terminate the cycle.
    current_loop = state.get("loop_count", 0) or 0
    if state.get("risk_status") == "REJECTED_REVISE":
        if current_loop >= 3:
            logger.warning(f"🛑 [Circuit Breaker] Max Loops ({current_loop}) reached.")
            # BUG-FIX: Do NOT reset loop_count to 0 here — check_safety_signature uses
            # loop_count >= 3 to break the cycle. Resetting it to 0 causes the guard to
            # always see 0 and route back to execution_analyst indefinitely.
            return {
                "messages": [
                    (
                        "ai",
                        "I cannot recommend a trade at this time due to persistent safety policy violations. Please adjust your risk profile or select a different asset.",
                    )
                ],
                "risk_status": "UNKNOWN",
                "loop_count": current_loop + 1,
                "execution_plan_output": None,
            }

        feedback = state.get("risk_feedback")
        injected_msg = (
            f"CRITICAL: Your previous strategy was REJECTED by Risk Management.\n"
            f"Feedback: {feedback}\n"
            f"Task: Generate a REVISED, SAFER strategy based on this feedback."
        )
        logger.info(f"--- [Loop {current_loop + 1}] Injecting Risk Feedback ---")
    else:
        risk = state.get("risk_attitude", "Unknown")
        period = state.get("investment_period", "Unknown")

        injected_context = ""
        if market_data_msg:
            injected_context = f"\n--- MARKET ANALYSIS SUMMARY ---\n{market_data_msg}\n-------------------------------\n"

        injected_msg = (
            f"CONTEXT: You are continuing a conversation. {injected_context}"
            f"USER PROFILE: Risk Attitude: {risk}, Horizon: {period}\n"
            f"CURRENT REQUEST: {user_msg}\n"
            f"TASK: Generate an Execution Plan.\n"
            f"If information like risk profile or ticker is missing, your plan should be to ask the user."
        )

    # 4. Invoke LangChain structured output asynchronously (ARCH-05)
    tracer = get_tracer()
    with tracer.start_as_current_span("ExecutionAnalyst: Planner") as span:
        span.set_attribute("langfuse.trace.metadata.current_node", "execution_analyst")
        span.set_attribute("langfuse.observation.input", injected_msg)

        try:
            # Chain returns a raw AIMessage (json_object mode, no tool-calling)
            from src.governed_financial_advisor.agents.execution_analyst.agent import (
                parse_execution_plan,
            )

            ai_msg = await agent_chain.ainvoke(
                {"messages": [HumanMessage(content=injected_msg)]}
            )
            raw_content = ai_msg.content if hasattr(ai_msg, "content") else str(ai_msg)
            plan_obj = parse_execution_plan(raw_content)

            # Serialize for state dictionary
            plan_output = plan_obj.model_dump()
            span.set_attribute("langfuse.observation.output", json.dumps(plan_output))
            logger.info(
                f"✅ Generated Execution Plan: {plan_output.get('plan_id', 'unknown')}"
            )
        except Exception as e:
            logger.warning(f"⚠️ Failed to generate Execution Plan: {e}")
            span.record_exception(e)
            plan_output = {
                "steps": [],
                "reasoning": f"Error generating plan: {e}",
                "error": str(e),
            }

    # 5. Format Output Message
    if plan_output and isinstance(plan_output, dict) and "error" not in plan_output:
        steps_text = "\n".join(
            [
                f"{i + 1}. {s.get('action')} ({s.get('description')})"
                for i, s in enumerate(plan_output.get("steps", []))
            ]
        )
        risk_val = plan_output.get("user_risk_attitude") or state.get(
            "risk_attitude", "Unknown"
        )
        ticker_val = state.get("ticker", "the requested asset")
        final_response = (
            f"I have received your request to trade {ticker_val}. Based on your risk profile ({risk_val}), here is my recommendation:\n\n"
            f"### Executive Plan: {plan_output.get('strategy_name', 'Custom Strategy')}\n\n"
            f"**Rationale:** {plan_output.get('rationale')}\n\n"
            f"**Steps:**\n{steps_text}\n\n"
            f"**Risk Factors:** {', '.join(plan_output.get('risk_factors', []))}\n\n"
            f"*(Generated by System 4 Planner)*\n\n"
            f"**Action Required:** I am checking internal governance policies before finalizing this trade.\n"
            f"**Would you like me to execute this trade or implement this plan?**"
        )
    else:
        final_response = "I encountered an error trying to generate an execution plan for this trade."

    # 6. Update State
    # BUG-FIX: loop_count was reset to 0 on non-REJECTED_REVISE paths, so
    # check_safety_signature always saw 0 and cycled infinitely.
    # Always increment so the evaluator gate can cap at 3 and break to explainer.
    updates = {
        "messages": [("ai", final_response)],
        "risk_status": "UNKNOWN",
        "execution_plan_output": plan_output,
        "loop_count": current_loop + 1,
    }

    # Extract Context back to global state
    if plan_output and "error" not in plan_output:
        if plan_output.get("user_risk_attitude"):
            updates["risk_attitude"] = plan_output.get("user_risk_attitude")
        if plan_output.get("user_investment_period"):
            updates["investment_period"] = plan_output.get("user_investment_period")

    return updates


async def governed_trader_node(state):
    """
    Executes the Governed Trader Subgraph (Native LangGraph).
    Executes requested trades based on plan and evaluation.
    """
    logger.info("--- [Graph] Calling Governed Trader ---")

    from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
        governed_trader_graph,
    )

    # We pass the execution plan and evaluation result down to the subgraph.
    # data_analyst_ticker is forwarded so post_hitl_rehydrate_node can fetch a
    # live quote directly without re-parsing execution_plan JSON (more reliable).
    subgraph_state = {
        "messages": state.get("messages", []),
        "execution_plan": str(state.get("execution_plan_output", "No plan.")),
        "evaluation_result": str(
            state.get("evaluation_result", "DENIED")
        ),  # M-06: fail-closed default
        "governance_signature": state.get("governance_signature"),
        "data_analyst_ticker": state.get("data_analyst_ticker"),  # TOCTOU: re-hydration
    }

    # Invoke natively
    result = await governed_trader_graph.ainvoke(
        subgraph_state, {"recursion_limit": 10}
    )

    return {"messages": result["messages"]}
