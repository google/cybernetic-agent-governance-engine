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

logger = logging.getLogger(__name__)
from typing import Annotated, TypedDict

from langchain_core.messages import SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from src.governed_financial_advisor.infrastructure.mcp_client import get_mcp_client
from src.governed_financial_advisor.utils.telemetry import get_tracer
from src.governed_financial_advisor.utils.text_utils import strip_thinking_tags


# ---------------------------------------------------------------------------
# 1. State Definition
# ---------------------------------------------------------------------------
class DataAnalystState(TypedDict):
    messages: Annotated[list, add_messages]  # Inherited global conversation
    reasoning_output: str | None  # Local Thinker payload


# ---------------------------------------------------------------------------
# 2. Tool Definition (Placeholder)
# ---------------------------------------------------------------------------
# Tools are now loaded dynamically from the MCP Server within the node executions.


# ---------------------------------------------------------------------------
# 3. Custom Tool Executor Node (Dynamic MCP)
# ---------------------------------------------------------------------------
async def tool_executor_node(state: DataAnalystState):  # type: ignore[no-untyped-def]
    """
    Manually executes tools requested by the Doer node.
    Bypasses langgraph.prebuilt.ToolNode due to Corporate Airlock versioning issues.
    Dynamically loads tools from the MCP server to execute them.
    """
    from langchain_mcp_adapters.tools import load_mcp_tools

    mcp_client = get_mcp_client()
    if not mcp_client.session:
        await mcp_client.connect()

    mcp_tools = await load_mcp_tools(mcp_client.session)
    tools_by_name = {t.name: t for t in mcp_tools}

    last_message = state["messages"][-1]
    tool_outputs = []

    if hasattr(last_message, "tool_calls"):
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]

            logger.debug(
                "--- [DEBUG] tool_executor checking %s with %s ---",
                tool_name,
                tool_args,
            )
            if tool_name in tools_by_name:
                try:
                    logger.debug(
                        "--- [DEBUG] tool_executor invoking %s... ---", tool_name
                    )
                    result = await tools_by_name[tool_name].ainvoke(tool_args)
                    logger.debug("--- [DEBUG] tool_executor result: %s ---", result)
                    tool_outputs.append(
                        ToolMessage(
                            content=str(result), tool_call_id=tool_id, name=tool_name
                        )
                    )
                except Exception as e:
                    logger.debug("--- [DEBUG] tool_executor ERROR: %s ---", e)
                    tool_outputs.append(
                        ToolMessage(
                            content=f"Error: {e}", tool_call_id=tool_id, name=tool_name
                        )
                    )
            else:
                logger.debug(
                    "--- [DEBUG] tool_executor WARNING: %s not in tools_by_name ---",
                    tool_name,
                )

    logger.debug(
        "--- [DEBUG] tool_executor returning %d tool outputs ---", len(tool_outputs)
    )
    return {"messages": tool_outputs}


# ---------------------------------------------------------------------------
# 4. Thinker Node (DeepSeek)
# ---------------------------------------------------------------------------
def analyst_thinker_node(state: DataAnalystState):  # type: ignore[no-untyped-def]
    tracer = get_tracer()

    with tracer.start_as_current_span("DataAnalyst: Thinker") as span:
        model_name = os.getenv("MODEL_REASONING")
        span.set_attribute("langfuse.observation.model.name", model_name)
        span.set_attribute(
            "langfuse.trace.metadata.current_node", "data_analyst_thinker"
        )
        span.set_attribute("gen_ai.operation.name", "chat")

        _reasoning_base = os.getenv("VLLM_REASONING_API_BASE")
        if not _reasoning_base:
            raise RuntimeError(
                "VLLM_REASONING_API_BASE must be set — no localhost fallback in production"
            )
        llm = ChatOpenAI(
            model=model_name,  # type: ignore[arg-type]
            base_url=_reasoning_base,
            temperature=0.6,
            max_tokens=1024,  # type: ignore[call-arg]  # DeepSeek reasoning model has max_model_len=2048; keep output ≤1024
        )

        sys_msg = SystemMessage(
            content=(
                "You are the Data Analyst PLANNER. "
                "Analyze the conversation and determine WHICH stock ticker the user wants data for. "
                "Think carefully about the context. Your output will guide the data execution."
            )
        )

        messages = [sys_msg] + state["messages"]

        input_str = "\n".join(
            [
                m.content
                for m in messages
                if isinstance(getattr(m, "content", None), str)
            ]
        )
        span.set_attribute(
            "gen_ai.input.messages",
            json.dumps([{"role": "user", "content": input_str}]),
        )
        span.set_attribute("langfuse.observation.input", input_str)

        response = llm.invoke(messages, config={"run_name": "Analyst Thinker"})
        raw_output = response.content
        clean_plan = strip_thinking_tags(raw_output)  # type: ignore[arg-type]

        span.set_attribute(
            "gen_ai.output.messages",
            json.dumps([{"role": "assistant", "content": clean_plan}]),
        )
        span.set_attribute("langfuse.observation.output", clean_plan)

        # Return LOCAL state update
        return {"reasoning_output": raw_output}


# ---------------------------------------------------------------------------
# 5. Doer Node (Llama 3.1 + Dynamic MCP)
# ---------------------------------------------------------------------------
async def analyst_doer_node(state: DataAnalystState):  # type: ignore[no-untyped-def]
    """Llama 3.1 dynamically loads MCP tools and translates reasoning into JSON."""
    tracer = get_tracer()
    reasoning = state["reasoning_output"]

    with tracer.start_as_current_span("DataAnalyst: Doer") as span:
        model_name = os.getenv("MODEL_FAST", "default-fast-model")
        span.set_attribute("langfuse.observation.model.name", model_name)
        span.set_attribute("langfuse.trace.metadata.current_node", "data_analyst_doer")
        span.set_attribute("langfuse.trace.metadata.mcp_server", "gateway_mcp")
        span.set_attribute("gen_ai.operation.name", "chat")

        _fast_base = os.getenv("VLLM_FAST_API_BASE")
        if not _fast_base:
            raise RuntimeError(
                "VLLM_FAST_API_BASE must be set — no localhost fallback in production"
            )
        fast_llm = ChatOpenAI(
            model=model_name,
            base_url=_fast_base,
            temperature=0.0,
            max_tokens=512,  # type: ignore[arg-type, call-arg]
        )

        from langchain_core.messages import HumanMessage
        from langchain_mcp_adapters.tools import load_mcp_tools

        from src.governed_financial_advisor.infrastructure.mcp_client import (
            get_mcp_client,
        )

        sys_prompt = SystemMessage(
            content=(
                "You are the Data Analyst EXECUTOR. Your ONLY function is to call tools.\n"
                "Read the reasoning provided below, identify the ticker, and IMMEDIATELY CALL the correct market data tool.\n"
                "CRITICAL RULES:\n"
                "1. DO NOT output ANY conversational text.\n"
                "2. DO NOT greet the user or explain yourself.\n"
                "3. ONLY use the tool with arguments."
            )
        )

        user_prompt = HumanMessage(
            content=(
                "Based on the reasoning provided, execute the data fetch immediately using the extracted ticker.\n\n"
                f"REASONING:\n{reasoning}"
            )
        )

        messages = [sys_prompt, user_prompt]

        input_str = "\n".join(
            [
                m.content  # type: ignore[misc]  # guarded by isinstance str check above; LangChain content union includes list[...]
                for m in messages
                if isinstance(getattr(m, "content", None), str)
            ]
        )
        span.set_attribute(
            "gen_ai.input.messages",
            json.dumps([{"role": "user", "content": input_str}]),
        )
        span.set_attribute("langfuse.observation.input", input_str)

        mcp_client = get_mcp_client()
        if not mcp_client.session:
            await mcp_client.connect()

        # Dynamically fetch available tools from the Gateway MCP server
        all_mcp_tools = await load_mcp_tools(mcp_client.session)

        # Filter tools down to only Analyst-relevant tools to prevent Llama 3.1 confusion
        analyst_tool_names = {
            "get_market_data",
            "check_market_status",
            "get_market_sentiment",
        }
        mcp_tools = [t for t in all_mcp_tools if t.name in analyst_tool_names]

        logger.debug(
            "--- [DEBUG] Loaded MCP Tools: %s ---", [t.name for t in mcp_tools]
        )
        logger.debug("--- [DEBUG] Doer received reasoning: %s ---", reasoning)

        # Bind tools to Llama 3.1
        llm_with_tools = fast_llm.bind_tools(mcp_tools)

        # Execute tool translation
        response = await llm_with_tools.ainvoke(
            messages, config={"run_name": "Analyst Doer"}
        )
        logger.debug("--- [DEBUG] Llama 3.1 Response: %s ---", response)

        output_str = (
            response.content
            if response.content
            else str(getattr(response, "tool_calls", "No content"))
        )
        span.set_attribute(
            "gen_ai.output.messages",
            json.dumps([{"role": "assistant", "content": output_str}]),
        )
        span.set_attribute("langfuse.observation.output", output_str)

        return {"messages": [response]}


# ---------------------------------------------------------------------------
# 6. Reporter Node (Llama 3.1)
# ---------------------------------------------------------------------------
def analyst_reporter_node(state: DataAnalystState):  # type: ignore[no-untyped-def]
    tracer = get_tracer()

    with tracer.start_as_current_span("DataAnalyst: Reporter") as span:
        model_name = os.getenv("MODEL_FAST")
        span.set_attribute("langfuse.observation.model.name", model_name)
        span.set_attribute(
            "langfuse.trace.metadata.current_node", "data_analyst_reporter"
        )
        span.set_attribute("gen_ai.operation.name", "chat")

        _reporter_fast_base = os.getenv("VLLM_FAST_API_BASE")
        if not _reporter_fast_base:
            raise RuntimeError(
                "VLLM_FAST_API_BASE must be set — no localhost fallback in production"
            )
        llm = ChatOpenAI(
            model=model_name,  # type: ignore[arg-type]
            base_url=_reporter_fast_base,
            temperature=0.3,  # Slight creativity for summarization
            max_tokens=400,  # type: ignore[call-arg]  # Qwen fast model has max_model_len=2048; keep output ≤400 to leave room for input+system prompt
        )

        sys_prompt = SystemMessage(
            content=(
                "You are a Financial Data Analyst. Summarize the market data below in 3-4 sentences covering: "
                "price range, trend direction, and key insight. Be concise and factual."
            )
        )

        # Extract just the user query and the tool output to avoid Llama getting confused by intermediate steps
        user_msg = state["messages"][0].content
        raw_tool_data = (
            state["messages"][-1].content
            if hasattr(state["messages"][-1], "content")
            else str(state["messages"][-1])
        )
        # Truncate tool data to ~800 chars to stay within 2048-token context window (input + output ≤ 2048)
        tool_data = (
            str(raw_tool_data)[:800]
            if len(str(raw_tool_data)) > 800
            else str(raw_tool_data)
        )

        prompt = f"User Request: {user_msg}\n\nMarket Data:\n{tool_data}\n\nProvide a brief analysis."

        from langchain_core.messages import HumanMessage

        messages = [sys_prompt, HumanMessage(content=prompt)]

        input_str = "\n".join(
            [
                m.content  # type: ignore[misc]  # guarded by isinstance str check above; LangChain content union includes list[...]
                for m in messages
                if isinstance(getattr(m, "content", None), str)
            ]
        )
        span.set_attribute(
            "gen_ai.input.messages",
            json.dumps([{"role": "user", "content": input_str}]),
        )
        span.set_attribute("langfuse.observation.input", input_str)

        response = llm.invoke(messages, config={"run_name": "Analyst Reporter"})

        if response.content:
            response.content = "Data Analysis: " + response.content  # type: ignore[operator]  # guarded by truthiness check; LangChain content is str in this path

        span.set_attribute(
            "gen_ai.output.messages",
            json.dumps([{"role": "assistant", "content": response.content}]),
        )
        span.set_attribute("langfuse.observation.output", response.content)

        return {"messages": [response]}


# ---------------------------------------------------------------------------
# 7. Build Subgraph
# ---------------------------------------------------------------------------
builder = StateGraph(DataAnalystState)

# Add Nodes
builder.add_node("thinker", analyst_thinker_node)
builder.add_node("doer", analyst_doer_node)
builder.add_node("execute_tool", tool_executor_node)
builder.add_node("reporter", analyst_reporter_node)

# Edges
builder.set_entry_point("thinker")
builder.add_edge("thinker", "doer")


# Conditional routing out of Doer
def doer_router(state: DataAnalystState):  # type: ignore[no-untyped-def]
    last_message = state["messages"][-1]
    # If the LLM returned tool calls, we execute them
    if getattr(last_message, "tool_calls", None):
        return "execute_tool"
    # Otherwise, it hallucinated text and refused tool calls, just report it
    return "reporter"


builder.add_conditional_edges("doer", doer_router)
builder.add_edge("execute_tool", "reporter")
builder.add_edge("reporter", END)

# Compile!
data_analyst_graph = builder.compile()
