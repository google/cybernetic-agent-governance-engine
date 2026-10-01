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
Governed Trader Subgraph (Native LangGraph)

Implements the Executor as a LangGraph state machine linking
a fast LLM to MCP ToolNodes for trade execution.

The gateway decides whether a trade needs a human; the advisor applies no
approval thresholds of its own. Flow:

    START → executor → tools (gateway_tool_guard)
        ALLOW / NARROW    → execute_trade_action runs (the gateway's single
                            committing run) → executor
        REQUIRE_APPROVAL  → approval (interrupt, carries ``deferred_id``)
                            → post_hitl_rehydrate → post_hitl_revalidate
                            (slippage gate) → executor → tools, which forwards
                            ``deferred_id`` so the gateway consumes the
                            approval once and re-validates the fresh params
        anything else     → END

The authoritative approval is recorded against ``deferred_id`` in the
gateway's DeferQueue (compliance bridge ``POST /v1/defer/{id}/escalate``); the
graph is resumed via the LangGraph SDK with:

    Command(resume={"approved": bool, "reviewer": str,
                    "rationale": str, "max_slippage_pct": float})
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict

from langchain_core.messages import (
    BaseMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from src.gateway.infrastructure.mcp_client import get_mcp_client
from src.gateway.infrastructure.telemetry_client import get_tracer
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_MODEL_NAME,
    OBSERVATION_NAME,
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
    TRACE_METADATA_CURRENT_NODE,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.graph.governance.tool_guard import (
    GOVERNANCE_ALLOWED,
    GOVERNANCE_REQUIRE_APPROVAL,
    gateway_tool_guard,
)
from src.governed_financial_advisor.graph.nodes.approval_node import (
    approval_node,
    rejection_node,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subgraph State
# ---------------------------------------------------------------------------


class GovernedTraderState(TypedDict):
    messages: Annotated[list[BaseMessage], "messages"]
    execution_plan: str
    evaluation_result: str
    # Approval fields (populated by gateway_tool_guard and approval_node)
    deferred_id: str | None  # gateway-held approval token (REQUIRE_APPROVAL)
    approval_decision: dict[str, Any] | None
    hitl_expires_at: str | None  # TTL expiration timestamp for pending state
    # TOCTOU Remediation — Phase 2 (Slippage Bounds + TTL)
    # These fields close the ghost-state vulnerability: continuous market variables
    # are re-sampled and re-validated at the moment of actuation, not at check-time.
    data_analyst_ticker: str | None  # passed from parent graph for re-hydration
    rehydration_result: dict | None  # fresh market snapshot + drift metrics
    post_hitl_safety_status: str | None  # "PASSED" | "BLOCKED" after the slippage gate

    # Written by gateway_tool_guard (POST /governance/validate-action)
    governance_envelope: dict[str, Any] | None  # Gateway ALLOW/NARROW verdict
    governance_status: str | None  # "ALLOWED" | "DENIED" | "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

EXECUTOR_FALLBACK_PROMPT = """You are the **Governed Trader (Executor)**, the "System 1 Implementation" arm of the CAGE architecture.
Your role is to **EXECUTE** the plan provided to you. You are a "Dumb Executor" - you do not reason, plan, or strategize.

**Input Context:**
- `Execution Plan`: The approved plan.
- `Evaluation Result`: The official approval from System 3 (Evaluator).

**Protocol:**
1.  Check that `Evaluation Result` is **APPROVED**. (Ideally, you are only called if this is true, but double-check).
2.  Look at the `steps` in `Execution Plan`.
3.  For each step with action `execute_trade`, CALL the `execute_trade_action` tool with the EXACT parameters specified in the plan.
    - Do NOT change the amount.
    - Do NOT change the symbol.
    - **MANDATORY**: You MUST populate the `confidence` field.
      - If the plan is APPROVED and clear, set `confidence` to **0.99**.
      - If the plan is ambiguous or you are unsure, set `confidence` to **0.5**.
      - **CRITICAL**: The Symbolic Governor will REJECT any trade with `confidence < 0.95`.
4.  After execution, summarize the result to the user.

**Strict Constraint:**
- You do NOT "propose" trades. You EXECUTE them.
- You do NOT ask the user for clarification. (The Planner should have done that).
- If the plan is empty or unclear, do nothing.
"""


def get_executor_instruction() -> str:
    from src.gateway.observability.langfuse_utils import get_managed_prompt

    return get_managed_prompt("agent/governed_trader", EXECUTOR_FALLBACK_PROMPT)


# ---------------------------------------------------------------------------
# Executor nodes (CAGE governance enforced)
# ---------------------------------------------------------------------------


@side_effect_node(kind="api_call", external_system="gateway_mcp")
async def tool_executor_node(state: GovernedTraderState) -> dict[str, Any]:
    """Execute trade tools after CAGE governance validation.

    CRITICAL SECURITY GATE: This node invokes execute_trade_action via MCP, which
    triggers real financial transactions. ``gateway_tool_guard`` (applied in the
    graph builder below) submits every pending tool call to the gateway's
    ``POST /governance/validate-action`` (full 8-tier pipeline: FTRA, STPA,
    Confidence, CBF, OPA, Fiscal, Consensus, Causal, FRIA) before ANY tool
    executes.

    Governance Contract:
        - Every tool call must be routed ALLOW or NARROW, or carry the
          ``deferred_id`` of a human-approved REQUIRE_APPROVAL
        - Refusals, DEFER / PAUSE verdicts, HTTP errors, timeouts and an
          unreachable gateway all refuse the batch: this node does not run,
          ``governance_status`` becomes "DENIED" and the subgraph ends
        - The gateway commits and seals inside ``execute_trade_action``; the
          advisor never holds a seal

    TOCTOU Closure: after approval, ``execute_trade_action(deferred_id=...)``
    re-validates the fresh params in the gateway (POST_HITL profile) at
    actuation time, not check time.
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

            if tool_name in tools_by_name:
                try:
                    result = await tools_by_name[tool_name].ainvoke(tool_args)
                    tool_outputs.append(
                        ToolMessage(
                            tool_call_id=tool_id,
                            name=tool_name,
                            content=str(result),
                        )
                    )
                except Exception as e:
                    tool_outputs.append(
                        ToolMessage(
                            tool_call_id=tool_id,
                            name=tool_name,
                            content=f"Error executing tool {tool_name}: {e}",
                        )
                    )
            else:
                tool_outputs.append(
                    ToolMessage(
                        tool_call_id=tool_id,
                        name=tool_name,
                        content=f"Error: Tool {tool_name} not found.",
                    )
                )

    return {"messages": tool_outputs}


async def executor_node(state: GovernedTraderState) -> dict[str, Any]:
    """Generate execute_trade_action tool calls from the approved plan.

    The downstream ``gateway_tool_guard`` validates every emitted tool call with
    the gateway before ``tool_executor_node`` may run it.
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: Executor") as span:
        model_name = os.getenv("MODEL_FAST")
        span.set_attribute(OBSERVATION_MODEL_NAME, model_name)
        span.set_attribute(TRACE_METADATA_CURRENT_NODE, "governed_trader_executor")
        span.set_attribute("gen_ai.operation.name", "chat")

        _fast_api_base = os.getenv("VLLM_FAST_API_BASE")
        if not _fast_api_base:
            raise RuntimeError(
                "VLLM_FAST_API_BASE must be set — no localhost fallback in production"
            )
        llm = ChatOpenAI(
            model=model_name,  # type: ignore[arg-type]
            base_url=_fast_api_base,
            temperature=0.0,
            max_tokens=4096,  # type: ignore[call-arg]
        )

        # Load MCP tools manually
        from langchain_mcp_adapters.tools import load_mcp_tools

        mcp_client = get_mcp_client()
        if not mcp_client.session:
            await mcp_client.connect()
        mcp_tools = await load_mcp_tools(mcp_client.session)

        # Filter strictly to execute_trade_action
        tools = [t for t in mcp_tools if t.name == "execute_trade_action"]
        llm_with_tools = llm.bind_tools(tools)

        # Construct messages — system prompt incorporates dynamic context.
        system_msg = SystemMessage(
            content=(
                f"{get_executor_instruction()}\n\n"
                f"Execution Plan:\n{state.get('execution_plan')}\n\n"
                f"Evaluation Result:\n{state.get('evaluation_result')}"
            )
        )

        messages = [system_msg, *state.get("messages", [])]

        span.set_attribute(OBSERVATION_INPUT, str(messages))

        response = await llm_with_tools.ainvoke(messages)

        span.set_attribute(
            OBSERVATION_OUTPUT, getattr(response, "content", "No content")
        )

        # The tool calls on ``response`` are what gateway_tool_guard submits to
        # the gateway — every one of them, not a summarised first call.
        return {"messages": [response]}


# ---------------------------------------------------------------------------
# Conditional edges: executor → tools | END, tools → executor | END
# ---------------------------------------------------------------------------


def should_continue(state: GovernedTraderState) -> str:
    """Determine if a tool call was requested by the Executor."""
    messages = state["messages"]
    last_message = messages[-1]

    if last_message.tool_calls:  # type: ignore[attr-defined]
        return "tools"
    return END


def route_after_tools(state: GovernedTraderState) -> str:
    """Route on the ``gateway_tool_guard`` outcome.

    ``ALLOWED`` loops to the executor; ``REQUIRE_APPROVAL`` (with a gateway
    ``deferred_id``) pauses at the approval node; anything else ends the
    subgraph, so a refused trade cannot be re-proposed in the same run.
    """
    status = state.get("governance_status")
    if status == GOVERNANCE_ALLOWED:
        return "executor"
    if status == GOVERNANCE_REQUIRE_APPROVAL and state.get("deferred_id"):
        return "approval"
    logger.warning("[GovernedTrader] Gateway refused the tool batch — ending subgraph.")
    return END


# ---------------------------------------------------------------------------
# TOCTOU Remediation Nodes (Phase 2 — Slippage Bounds)
#
# These three nodes close the ghost-state vulnerability by ensuring the system
# samples the continuous market environment and re-validates deterministic bounds
# at the exact moment of execution — not at the moment of human check.
#
# Architectural invariant: the SymbolicGovernor runs only in the gateway
# (POAM-2026-079). Governance re-validation happens there when the approved
# deferred_id is consumed; the advisor cannot approve, seal or actuate a trade.
# ---------------------------------------------------------------------------


@side_effect_node(kind="api_call", external_system="yfinance")
async def post_hitl_rehydrate_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — State Re-hydration Node.

    Samples the live market environment immediately after HITL resumption.
    Runs BEFORE the executor to populate fresh price data for the subsequent
    re-validation step.

    Emits OTel span attributes:
        toctou.rehydration.status    — OK | SKIPPED
        toctou.rehydration.ticker    — symbol fetched
        toctou.rehydration.stale_price  — price from approved execution plan
        toctou.rehydration.fresh_price  — live quote from yfinance
        toctou.rehydration.drift_pct    — abs percentage change

    Fail-open on missing ticker or yfinance errors: sets status=SKIPPED and
    continues so the re-validation step can still run Tier 3a/3b on plan params.
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Rehydration") as span:
        span.set_attribute(OBSERVATION_NAME, "hitl_rehydration")
        span.set_attribute(OBSERVATION_TYPE, "span")

        # 1. Resolve ticker — prefer explicit state field, fall back to plan JSON.
        ticker: str | None = state.get("data_analyst_ticker")
        if not ticker:
            plan_raw = state.get("execution_plan", "")
            try:
                plan = json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
                for step in plan.get("steps", []):
                    if step.get("symbol"):
                        ticker = str(step["symbol"]).upper()
                        break
                if not ticker:
                    ticker = plan.get("symbol") or plan.get("ticker")
                    if ticker:
                        ticker = str(ticker).upper()
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

        def _skipped_result(reason: str) -> dict:
            return {
                "rehydration_result": {
                    "status": "SKIPPED",
                    "reason": reason,
                    "ticker": ticker,
                    "fresh_price": None,
                    "stale_price": None,
                    "drift_pct": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            }

        if not ticker:
            logger.warning(
                "[RehydrateNode] ⚠️ No ticker found in state or execution_plan — "
                "skipping market data fetch (re-validation will use plan params)."
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "no_ticker")
            return _skipped_result("no_ticker")

        # 2. Extract stale price from execution plan for drift calculation.
        stale_price: float | None = None
        try:
            plan_raw = state.get("execution_plan", "")
            plan = json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
            for step in plan.get("steps", []):
                if step.get("price"):
                    stale_price = float(step["price"])
                    break
                # Derive implied price from amount / quantity
                if (
                    step.get("amount")
                    and step.get("quantity")
                    and float(step["quantity"]) > 0
                ):
                    stale_price = float(step["amount"]) / float(step["quantity"])
                    break
        except (json.JSONDecodeError, TypeError, ValueError, ZeroDivisionError):
            pass

        # 3. Fetch live quote via yfinance (lightweight fast_info path).
        try:
            import yfinance as yf

            ticker_obj = yf.Ticker(ticker)
            fresh_price: float | None = None

            # Try fast_info first (single HTTP call, ~200ms).
            try:
                fi = ticker_obj.fast_info
                raw = fi.get("last_price") or fi.get("lastPrice")
                if raw and float(raw) > 0:
                    fresh_price = float(raw)
            except Exception:
                pass

            # Fallback: last close from 1-day history.
            if not fresh_price or fresh_price <= 0:
                hist = ticker_obj.history(period="1d")
                if not hist.empty:
                    fresh_price = float(hist.iloc[-1]["Close"])

            drift_pct: float | None = None
            if stale_price and stale_price > 0 and fresh_price and fresh_price > 0:
                drift_pct = abs(fresh_price - stale_price) / stale_price * 100.0

            result = {
                "status": "OK",
                "ticker": ticker,
                "fresh_price": fresh_price,
                "stale_price": stale_price,
                "drift_pct": drift_pct,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }

            span.set_attribute("toctou.rehydration.status", "OK")
            span.set_attribute("toctou.rehydration.ticker", ticker)
            if fresh_price:
                span.set_attribute("toctou.rehydration.fresh_price", fresh_price)
            if stale_price:
                span.set_attribute("toctou.rehydration.stale_price", stale_price)
            if drift_pct is not None:
                span.set_attribute("toctou.rehydration.drift_pct", drift_pct)

            logger.info(
                "[RehydrateNode] ✅ %s | stale=%.4f fresh=%.4f drift=%.2f%%",
                ticker,
                stale_price or 0.0,
                fresh_price or 0.0,
                drift_pct or 0.0,
            )
            return {"rehydration_result": result}

        except Exception as exc:
            logger.warning(
                "[RehydrateNode] ⚠️ yfinance fetch failed for %s (%s) — "
                "rehydration SKIPPED, re-validation will use plan params.",
                ticker,
                exc,
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "yfinance_error")
            return _skipped_result(f"yfinance_error: {exc}")


async def post_hitl_revalidate_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — reviewer slippage gate.

    Blocks when the market moved further during review than the reviewer's
    ``max_slippage_pct`` allows. This is the only check the advisor applies
    after approval: governance re-validation of the fresh params runs in the
    gateway (POST_HITL profile) when ``execute_trade_action`` consumes the
    ``deferred_id`` — the only process that hosts the ``SymbolicGovernor``
    (POAM-2026-079).

    Emits OTel span attributes:
        toctou.revalidation.result           — PASSED | BLOCKED
        toctou.revalidation.block_reason     — price_slippage_exceeded
        toctou.revalidation.drift_pct        — measured drift at execution time
        toctou.revalidation.max_slippage_pct — reviewer's approved tolerance
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Revalidation") as span:
        span.set_attribute(OBSERVATION_NAME, "hitl_revalidation")
        span.set_attribute(OBSERVATION_TYPE, "span")

        rehydration: dict[str, Any] = state.get("rehydration_result") or {}
        approval_decision: dict[str, Any] = state.get("approval_decision") or {}

        max_slippage_pct: float = float(approval_decision.get("max_slippage_pct", 2.0))
        drift_pct: float | None = rehydration.get("drift_pct")

        span.set_attribute("toctou.revalidation.max_slippage_pct", max_slippage_pct)
        if drift_pct is not None:
            span.set_attribute("toctou.revalidation.drift_pct", drift_pct)

        # The reviewer's approved tolerance defines the envelope within which
        # execution is permitted.
        if drift_pct is not None and drift_pct > max_slippage_pct:
            block_reason = (
                f"Market price of {rehydration.get('ticker', 'the asset')} drifted "
                f"{drift_pct:.2f}% during the review period, exceeding the approved "
                f"\u00b1{max_slippage_pct:.1f}% slippage tolerance. "
                f"Trade aborted to protect mandate boundaries."
            )
            logger.warning(
                "[RevalidateNode] ⛔ Slippage exceeded: drift=%.2f%% > tolerance=%.2f%%",
                drift_pct,
                max_slippage_pct,
            )
            span.set_attribute("toctou.revalidation.result", "BLOCKED")
            span.set_attribute(
                "toctou.revalidation.block_reason", "price_slippage_exceeded"
            )
            return {
                "post_hitl_safety_status": "BLOCKED",
                "rehydration_result": {**rehydration, "block_reason": block_reason},
            }

        span.set_attribute("toctou.revalidation.result", "PASSED")
        return {"post_hitl_safety_status": "PASSED"}


def drift_blocked_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — Fail-Closed Terminal Node.

    Surfaces a human-readable explanation when the post-HITL re-validation
    blocks the trade. Routes to END. Does NOT execute any trade.

    The message is written to the message history so the parent graph's
    explainer node can surface it to the user — identical pattern to
    rejection_node.
    """
    rehydration: dict[str, Any] = state.get("rehydration_result") or {}
    approval_decision: dict[str, Any] = state.get("approval_decision") or {}

    block_reason: str = rehydration.get(
        "block_reason", "Market conditions changed during the review period."
    )
    ticker: str = rehydration.get("ticker") or "the asset"
    drift_pct: float | None = rehydration.get("drift_pct")
    reviewer: str = approval_decision.get("reviewer", "the reviewer")
    max_slippage_pct: float = float(approval_decision.get("max_slippage_pct", 2.0))

    if drift_pct is not None:
        drift_summary = (
            f"The market price of **{ticker}** moved **{drift_pct:.2f}%** during the "
            f"review period, exceeding the approved \u00b1{max_slippage_pct:.1f}% "
            f"slippage tolerance."
        )
    else:
        drift_summary = block_reason

    message = (
        f"\u26d4 **Trade Blocked \u2014 Market Drift Detected**\n\n"
        f"{drift_summary}\n\n"
        f"**What happened:** {reviewer} approved this trade, but by the time the "
        f"system attempted execution, market conditions had moved outside the "
        f"approved safety envelope. The trade was automatically blocked to protect "
        f"the investment mandate.\n\n"
        f"**Next steps:** Please re-submit your request. The agent will generate a "
        f"fresh execution plan based on current market data."
    )

    logger.info(
        "[DriftBlockedNode] Trade blocked post-HITL. ticker=%s drift_pct=%s",
        ticker,
        drift_pct,
    )

    return {
        "messages": [("ai", message)],
        "post_hitl_safety_status": "BLOCKED",
    }


def route_post_revalidation(state: GovernedTraderState) -> str:
    """Route after the slippage gate: drift_blocked if BLOCKED, else executor."""
    if state.get("post_hitl_safety_status") == "BLOCKED":
        logger.info(
            "[GovernedTrader] Post-HITL re-validation BLOCKED — routing to drift_blocked."
        )
        return "drift_blocked"
    logger.info("[GovernedTrader] Slippage gate passed — routing to executor.")
    return "executor"


# ---------------------------------------------------------------------------
# Build Graph
# ---------------------------------------------------------------------------

# Every tool call is routed by the gateway (POST /governance/validate-action)
# before execution; REQUIRE_APPROVAL pauses for a human, and any other
# non-executable outcome refuses the batch (fail closed).
guarded_tool_executor_node = gateway_tool_guard("execute_trade", approvable=True)(
    tool_executor_node
)


def build_governed_trader_graph() -> Any:
    """Compile the governed-trader subgraph.

    Every governance decision is a network call to the gateway; the advisor
    hosts no ``SymbolicGovernor`` (POAM-2026-079). There is no module-level
    compiled graph.
    """
    builder = StateGraph(GovernedTraderState)

    # Nodes
    builder.add_node("approval", approval_node)
    builder.add_node("rejection", rejection_node)
    builder.add_node(
        "post_hitl_rehydrate", post_hitl_rehydrate_node
    )  # TOCTOU: state re-hydration
    builder.add_node(
        "post_hitl_revalidate", post_hitl_revalidate_node
    )  # TOCTOU: pre-actuation re-eval
    builder.add_node("drift_blocked", drift_blocked_node)  # TOCTOU: fail-closed terminal
    builder.add_node("executor", executor_node)
    builder.add_node("tools", guarded_tool_executor_node)  # CAGE governance enforced

    # Entry: the gateway, not the advisor, decides whether a human is needed.
    builder.add_edge(START, "executor")

    # After approval_node (approved path): Command(goto="post_hitl_rehydrate") routes here.
    # TOCTOU remediation chain:
    #   post_hitl_rehydrate → post_hitl_revalidate → executor (PASSED) | drift_blocked (BLOCKED)
    # After approval_node (rejected path): Command(goto="rejection") routes to rejection_node.
    # LangGraph resolves Command.goto automatically — no explicit edge from approval needed.
    builder.add_edge("post_hitl_rehydrate", "post_hitl_revalidate")
    builder.add_conditional_edges(
        "post_hitl_revalidate",
        route_post_revalidation,
        {"executor": "executor", "drift_blocked": "drift_blocked"},
    )
    builder.add_edge("drift_blocked", END)

    # Executor tool-call loop; REQUIRE_APPROVAL pauses for a human and a
    # gateway refusal terminates the subgraph.
    builder.add_conditional_edges("executor", should_continue, {"tools": "tools", END: END})
    builder.add_conditional_edges(
        "tools",
        route_after_tools,
        {"executor": "executor", "approval": "approval", END: END},
    )

    # Rejection terminates the subgraph
    builder.add_edge("rejection", END)

    return builder.compile()
