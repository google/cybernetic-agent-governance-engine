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
Supervisor Node: Root Agent Split into Thinker (Reasoner) and Doer (Actor)

This uses the Thinker-Doer pattern to decouple reasoning (DeepSeek)
from pure JSON tool formatting (Llama 3.1).
"""

import logging
import os

logger = logging.getLogger(__name__)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.utils.telemetry import genai_span


class MockChatModel(BaseChatModel):
    model_name: str = "mock-llm"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        # Extract prompt or history content
        prompt = ""
        for m in messages:
            prompt += f"\n{m.content}"

        # Simple ticker and risk extraction
        import re

        ticker_match = re.search(r"\bticker:\s*([A-Z]{2,5})\b", prompt, re.IGNORECASE)
        if not ticker_match:
            ticker_match = re.search(r"\b[A-Z]{2,5}\b", prompt)
        ticker = (
            ticker_match.group(1)
            if ticker_match and len(ticker_match.groups()) > 0
            else (ticker_match.group(0) if ticker_match else "AAPL")
        )

        risk_match = re.search(r"\brisk profile:\s*(\w+)\b", prompt, re.IGNORECASE)
        if not risk_match:
            risk_match = re.search(
                r"\b(conservative|moderate|aggressive)\b", prompt, re.IGNORECASE
            )
        risk = (
            risk_match.group(1)
            if risk_match and len(risk_match.groups()) > 0
            else (risk_match.group(0) if risk_match else "aggressive")
        )

        content = (
            f"STRATEGY_ADVISOR\n\n"
            f"Acknowledging user request for ticker {ticker.upper()} under risk profile {risk.lower()}.\n"
            f"Based on our evaluation of {ticker.upper()} under a {risk.lower()} risk profile, we recommend a disciplined entry strategy. "
            f"Parameters: Entry Price: Market, Target: +15%, Stop Loss: -5%.\n"
            f"Please ensure all execution parameters are verified through the OPA symbolic gatekeeper before placing orders."
        )
        message = AIMessage(content=content)
        generation = ChatGeneration(message=message)
        return ChatResult(generations=[generation])

    @property
    def _llm_type(self) -> str:
        return "mock-chat-model"


class RouteRequest(BaseModel):
    """Routes the request to the appropriate sub-agent based on the user's intent."""

    intent: str = Field(
        description="The intent or target sub-agent to route to. E.g., MARKET_ANALYSIS, TRADING_STRATEGY, EXECUTION_PLAN, risk assessment, human review"
    )
    ticker: str = Field(
        default="",
        description="The stock ticker symbol associated with the request (if any).",
    )


def _build_reasoner_llm():
    """Lazy factory — validates env vars at call time, not at import time."""
    if os.environ.get("USE_MOCK_LLM", "").lower() == "true":
        logger.info("Using MockChatModel for reasoning LLM.")
        return MockChatModel()
    api_base = os.environ.get("VLLM_REASONING_API_BASE")
    if not api_base or "mock" in api_base.lower():
        logger.info("Using MockChatModel for reasoning LLM.")
        return MockChatModel()
    return ChatOpenAI(
        model=os.getenv("MODEL_REASONING"),
        base_url=api_base,
        temperature=0.6,
        max_tokens=1024,  # DeepSeek reasoning model has max_model_len=2048; keep output ≤1024
    )


def _build_fast_llm():
    """Lazy factory — validates env vars at call time, not at import time."""
    if os.environ.get("USE_MOCK_LLM", "").lower() == "true":
        logger.info("Using MockChatModel for fast LLM.")
        return MockChatModel()
    api_base = os.environ.get("VLLM_FAST_API_BASE")
    if not api_base or "mock" in api_base.lower():
        logger.info("Using MockChatModel for fast LLM.")
        return MockChatModel()
    return ChatOpenAI(
        model=os.getenv("MODEL_FAST"),
        base_url=api_base,
        temperature=0.0,
    )


# Module-level lazy singletons — initialised on first use, not at import time.
_reasoner_llm: "ChatOpenAI | None" = None
_fast_llm: "ChatOpenAI | None" = None


def _get_reasoner_llm():
    global _reasoner_llm
    if _reasoner_llm is None:
        _reasoner_llm = _build_reasoner_llm()
    return _reasoner_llm


def _get_fast_llm():
    global _fast_llm
    if _fast_llm is None:
        _fast_llm = _build_fast_llm()
    return _fast_llm


def _parse_routing_intent(reasoning: str) -> str:
    """Extract the routing category from the thinker's first non-empty line.

    The thinker system prompt mandates that Line 1 is the exact routing
    category (DATA_ANALYST, EXECUTION_ANALYST, STRATEGY_ADVISOR, HUMAN_REVIEW).
    We parse this directly to avoid requiring vLLM --enable-auto-tool-choice.
    """
    from src.governed_financial_advisor.utils.text_utils import strip_thinking_tags

    cleaned = strip_thinking_tags(reasoning)
    for line in cleaned.splitlines():
        line = line.strip().upper()
        if not line:
            continue
        # Strip numbering artifacts like "3. STRATEGY_ADVISOR"
        import re

        line = re.sub(r"^\d+\.\s*", "", line)
        if "DATA_ANALYST" in line:
            return "data_analyst"
        if "EXECUTION" in line:
            return "execution_analyst"
        if "STRATEGY" in line:
            return "FINISH"
        if "HUMAN_REVIEW" in line or "HUMAN" in line:
            return "FINISH"
    return "FINISH"


def _prune_message_history(messages: list, max_pairs: int = 4) -> list:
    """Sliding-window context pruner for the conversation history.

    Keeps only the last ``max_pairs`` Human/AI exchange pairs so that total
    input tokens stay within the hardware-constrained context window
    (``--max-model-len 16384`` on NVIDIA L4 24 GB).

    Token budget math (approximate):
    - System prompt:          ~800  tokens
    - 4 history pairs:       ~3 200 tokens
    - Current user message:  ~1 500 tokens
    - Overhead / padding:      ~500 tokens
    ─────────────────────────────────────────
    Total input budget:      ~6 000 tokens
    Remaining for CoT output: ~10 384 tokens  (well above DeepSeek-R1 needs)
    """
    exchange_messages = [
        m for m in messages if isinstance(m, (HumanMessage, AIMessage))
    ]
    max_keep = max_pairs * 2  # each pair = 1 Human + 1 AI reply
    if len(exchange_messages) > max_keep:
        logger.debug(
            "--- [Context Pruning] History truncated from %d → %d messages (kept last %d pairs) ---",
            len(exchange_messages),
            max_keep,
            max_pairs,
        )
        return exchange_messages[-max_keep:]
    return exchange_messages


# Legacy module-level references — resolved lazily on first attribute access.
# Code that previously used bare `reasoner_llm` / `fast_llm` at module level
# must call the getters instead; the nodes below already use the getters.


def _sanitize_user_message(text: str) -> str:
    """Strip control characters and truncate user input before LLM inclusion.

    M-05: Prevents prompt-injection via crafted user messages.
    Removes ASCII control characters (except newline/tab) and caps length.
    """
    import unicodedata

    # Remove ASCII control characters except \n (0x0A) and \t (0x09)
    sanitized = "".join(
        ch for ch in text if unicodedata.category(ch) != "Cc" or ch in ("\n", "\t")
    )
    # Truncate to 4096 characters to prevent context-window stuffing
    return sanitized[:4096]


def thinker_node(state):
    """DeepSeek analyzes the state and creates a plan."""
    logger.debug("--- [Graph] Supervisor (Thinker) ---")

    # --- State Management: Extract and persist user profile ---
    updated_state = state.copy()
    # M-05: Sanitize raw user input before any LLM prompt inclusion
    last_msg_text = _sanitize_user_message(state["messages"][-1].content).lower()

    if any(
        term in last_msg_text for term in ["conservative", "moderate", "aggressive"]
    ):
        if "conservative" in last_msg_text:
            updated_state["risk_attitude"] = "conservative"
        elif "moderate" in last_msg_text:
            updated_state["risk_attitude"] = "moderate"
        elif "aggressive" in last_msg_text:
            updated_state["risk_attitude"] = "aggressive"
        logger.debug(
            "--- [State] Updated risk_attitude: %s ---",
            updated_state.get("risk_attitude"),
        )

    if any(term in last_msg_text for term in ["short-term", "mid-term", "long-term"]):
        if "short-term" in last_msg_text:
            updated_state["investment_period"] = "short-term"
        elif "mid-term" in last_msg_text:
            updated_state["investment_period"] = "mid-term"
        elif "long-term" in last_msg_text:
            updated_state["investment_period"] = "long-term"
        logger.debug(
            "--- [State] Updated investment_period: %s ---",
            updated_state.get("investment_period"),
        )

    # --- Context Augmentation: Prepend user profile to the message ---
    augmented_message = last_msg_text
    if updated_state.get("risk_attitude") and updated_state.get("investment_period"):
        profile_context = (
            f"User Profile Context:\n"
            f"- Risk Attitude: {updated_state['risk_attitude']}\n"
            f"- Investment Period: {updated_state['investment_period']}\n\n"
        )
        augmented_message = f"{profile_context}User Request: {last_msg_text}"

    system_prompt = SystemMessage(
        content=(
            "You are a brilliant financial coordinator. Analyze the user's request and determine "
            "which internal team to route the request to. YOU MUST CHOOSE EXACTLY ONE OF:\n"
            "DATA_ANALYST (for market data, ticker analysis, stock performance, price checks)\n"
            "EXECUTION_ANALYST (ONLY for explicitly executing trades, buying, selling, or building execution plans)\n"
            "STRATEGY_ADVISOR (for trading strategies, risk assessment, portfolio evaluation, or conversational advice)\n"
            "HUMAN_REVIEW (for ambiguous requests lacking a ticker, or highly dangerous requests)\n"
            "Think deeply. Then definitively output ONLY your chosen routing category (e.g., 'STRATEGY_ADVISOR'). "
            "DO NOT output numbers or descriptions like '3. STRATEGY_ADVISOR' or '(for trading strategies)'.\n\n"
            "CRITICAL FORMATTING INSTRUCTION:\n"
            "If you route to STRATEGY_ADVISOR or HUMAN_REVIEW, you must also append a conversational response tailored to the user.\n"
            "Line 1 MUST be the exact routing category name (e.g., STRATEGY_ADVISOR)\n"
            "Line 2 MUST be blank.\n"
            "Line 3+ MUST be the conversational response.\n\n"
            "In this conversational response, you MUST EXPLICITLY state and acknowledge the exact Ticker Symbol requested by the user and their specific Risk Profile in your first sentence to pass compliance checks. Do NOT hallucinate company names (e.g. do not say Micron if the ticker is NVDA).\n"
            "If the user asks for a trading strategy, you MUST provide specific, actionable steps and concrete parameters. If simply answering a conversational query or evaluating risk, provide a helpful, tailored answer."
        )
    )
    # Prune history to last 4 exchanges (8 messages) to stay within the
    # vLLM max-model-len of 16 384 tokens on the NVIDIA L4 24 GB node.
    pruned_history = _prune_message_history(state["messages"][:-1], max_pairs=4)
    messages_to_pass = [
        system_prompt,
        *pruned_history,
        HumanMessage(content=augmented_message),
    ]

    with genai_span(name="reasoning", model=os.getenv("MODEL_REASONING")):
        # 1. Run Thinker Agent (The "Brain")
        response = _get_reasoner_llm().invoke(messages_to_pass)

        # Store DeepSeek's thought process into the state
        updated_state["reasoning_output"] = response.content

        final_output = {
            k: v for k, v in updated_state.items() if k in AgentState.__annotations__
        }
        return final_output


def doer_node(state):
    """Parse the thinker's routing decision and forward to the correct sub-agent.

    The thinker (reasoner_llm) emits a structured response where Line 1 is
    the routing category (DATA_ANALYST, EXECUTION_ANALYST, STRATEGY_ADVISOR,
    HUMAN_REVIEW).  We parse that directly instead of using bind_tools() which
    requires vLLM ``--enable-auto-tool-choice`` / ``--tool-call-parser`` flags
    that are not present on the deployed vllm-service endpoint.
    """
    logger.debug("--- [Graph] Supervisor (Doer) ---")
    reasoning = state.get("reasoning_output", "")
    logger.debug(
        "--- [DEBUG] Retrieved Reasoning from Thinker: ---\n%s\n-----------------------------------------",
        reasoning,
    )

    from src.governed_financial_advisor.utils.text_utils import strip_thinking_tags

    stripped_reasoning = strip_thinking_tags(reasoning)

    # Derive the routing intent by parsing the thinker's structured first line.
    next_step = _parse_routing_intent(reasoning)
    logger.debug("--- [Graph] Parsed Route Intent: %s ---", next_step)

    # Note: We NO LONGER append the routing thought process to state["messages"].
    # The conversational response will be generated by the downstream sub-agent that was routed to.
    updated_state = state.copy()
    updated_state["next_step"] = next_step

    if next_step == "FINISH":
        # If the route terminates here, use the fast LLM to generate the final conversational
        # response combining the user's explicit request with DeepSeek's reasoning.
        import re

        user_msg = state["messages"][-1].content
        risk_attitude = state.get("risk_attitude", "Unknown")

        # Simple heuristic to extract ticker if present
        ticker_match = re.search(r"\b[A-Z]{2,5}\b", user_msg)
        ticker = ticker_match.group(0) if ticker_match else "Unknown"

        final_gen_system_prompt = SystemMessage(
            content=(
                "You are an expert Strategy Advisor and Human Review coordinator. The user's request has been routed to you. "
                "You must provide a highly detailed, helpful, and direct answer to the user's query.\n\n"
                "CRITICAL COMPLIANCE RULE: You MUST EXPLICITLY state and acknowledge the exact Ticker Symbol requested by the user and their specific Risk Profile in your VERY FIRST sentence. "
                f"You must specifically mention ticker: {ticker}, and risk profile: {risk_attitude}.\n"
                "Do NOT hallucinate company names (e.g. do not say Micron if the ticker is NVDA).\n"
                "If the user asks for a trading strategy (e.g. 'Mean Reversion', 'Momentum'), you MUST provide specific, actionable steps and concrete parameters tailored to that exact strategy."
            )
        )

        final_gen_human_prompt = HumanMessage(
            content=(
                f"User Request: {user_msg}\n"
                f"Detected Ticker: {ticker}\n"
                f"User Risk Profile: {risk_attitude}\n\n"
                f"Financial Reasoning:\n{stripped_reasoning}\n\n"
                "Provide the final response answering the user's request directly. Ensure you follow the compliance rules."
            )
        )

        with genai_span(
            name="final_response_generation", model=os.getenv("MODEL_FAST")
        ):
            final_response = _get_fast_llm().invoke(
                [final_gen_system_prompt, final_gen_human_prompt]
            )
            updated_state["messages"] = state["messages"] + [
                AIMessage(content=final_response.content)
            ]

    final_output = {
        k: v for k, v in updated_state.items() if k in AgentState.__annotations__
    }
    return final_output
