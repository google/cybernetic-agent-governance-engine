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

Phase 1b: Approval gate added before executor using LangGraph-native
interrupt / Command mechanism.  When approval_required=True, the graph
pauses at approval_node and waits for a human to resume via:

    POST /v1/approvals/{thread_id}/resume
    {"approved": bool, "reviewer": str, "comment": str}

Approval threshold: trade value > $10,000 OR risk_score > 0.7
(derived from the evaluation_result parsed in should_require_approval).
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Any, Optional, TypedDict

from src.governed_financial_advisor.graph.annotations import side_effect_node

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from src.governed_financial_advisor.graph.nodes.approval_node import (
    approval_node,
    rejection_node,
)
from src.governed_financial_advisor.infrastructure.mcp_client import get_mcp_client
from src.governed_financial_advisor.utils.telemetry import get_tracer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subgraph State
# ---------------------------------------------------------------------------

class GovernedTraderState(TypedDict):
    messages: Annotated[list[BaseMessage], "messages"]
    execution_plan: str
    evaluation_result: str
    # Approval fields (populated by the parent graph or by approval_node)
    approval_required: bool
    approval_decision: Optional[dict[str, Any]]
    hitl_expires_at: Optional[str]          # TTL expiration timestamp for pending state
    # TOCTOU Remediation — Phase 2 (Slippage Bounds + TTL)
    # These fields close the ghost-state vulnerability: continuous market variables
    # are re-sampled and re-validated at the moment of actuation, not at check-time.
    data_analyst_ticker: Optional[str]      # passed from parent graph for re-hydration
    rehydration_result: Optional[dict]      # fresh market snapshot + drift metrics
    post_hitl_safety_status: Optional[str]  # "APPROVED" | "BLOCKED" after re-validation


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
    from src.governed_financial_advisor.utils.langfuse_utils import get_managed_prompt
    return get_managed_prompt("agent/governed_trader", EXECUTOR_FALLBACK_PROMPT)


# ---------------------------------------------------------------------------
# Approval threshold helper
# ---------------------------------------------------------------------------

def should_require_approval(state: GovernedTraderState) -> bool:
    """
    Returns True when the trade meets the high-value / high-risk threshold.

    Threshold rules (matches TypeScript BullMQ approval logic):
      - Trade value > $10,000, OR
      - risk_score > 0.7 (parsed from evaluation_result JSON)

    Falls back to the explicit ``approval_required`` flag in state so that
    the parent graph can force approval independently of auto-detection.
    """
    # Explicit override from parent graph state
    if state.get("approval_required"):
        return True

    # Auto-detect from evaluation_result JSON
    eval_result_raw: str = state.get("evaluation_result", "")
    try:
        eval_result: dict[str, Any] = (
            json.loads(eval_result_raw)
            if isinstance(eval_result_raw, str)
            else eval_result_raw
        )
        risk_score: float = float(eval_result.get("risk_score", 0.0))
        if risk_score > 0.7:
            logger.info(
                "[GovernedTrader] risk_score=%.2f > 0.7 → approval required.", risk_score
            )
            return True
    except (json.JSONDecodeError, ValueError, TypeError):
        pass  # Cannot parse — fall through to plan-based check

    # Auto-detect from execution_plan JSON (trade value)
    plan_raw: str = state.get("execution_plan", "")
    try:
        plan: dict[str, Any] = (
            json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
        )
        for step in plan.get("steps", []):
            amount = float(step.get("amount", 0))
            if amount > 10_000:
                logger.info(
                    "[GovernedTrader] Trade amount $%.2f > $10,000 → approval required.",
                    amount,
                )
                return True
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return False


# ---------------------------------------------------------------------------
# Approval routing edge
# ---------------------------------------------------------------------------

def route_approval(state: GovernedTraderState) -> str:
    """Conditional edge: route to approval_node if required, else executor."""
    if should_require_approval(state):
        logger.info("[GovernedTrader] Routing to approval_node.")
        return "approval"
    logger.info("[GovernedTrader] No approval required — routing directly to executor.")
    return "executor"


# ---------------------------------------------------------------------------
# Executor nodes (unchanged from original)
# ---------------------------------------------------------------------------

@side_effect_node(kind="api_call", external_system="gateway_mcp")
async def tool_executor_node(state: GovernedTraderState):
    """
    Manually executes tools requested by the executor node.
    Bypasses langgraph.prebuilt.ToolNode.
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


async def executor_node(state: GovernedTraderState):
    """The fast reasoning executor that calls tools based on the plan."""
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: Executor") as span:
        model_name = os.getenv("MODEL_FAST")
        span.set_attribute("langfuse.observation.model.name", model_name)
        span.set_attribute(
            "langfuse.trace.metadata.current_node", "governed_trader_executor"
        )
        span.set_attribute("gen_ai.operation.name", "chat")

        _fast_api_base = os.getenv("VLLM_FAST_API_BASE")
        if not _fast_api_base:
            raise RuntimeError(
                "VLLM_FAST_API_BASE must be set — no localhost fallback in production"
            )
        llm = ChatOpenAI(
            model=model_name,
            base_url=_fast_api_base,
            temperature=0.0,
            max_tokens=4096,
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

        messages = [system_msg] + state.get("messages", [])

        span.set_attribute("langfuse.observation.input", str(messages))

        response = await llm_with_tools.ainvoke(messages)

        span.set_attribute(
            "langfuse.observation.output", getattr(response, "content", "No content")
        )

        return {"messages": [response]}


# ---------------------------------------------------------------------------
# Conditional edge: executor → tools | END
# ---------------------------------------------------------------------------

def should_continue(state: GovernedTraderState) -> str:
    """Determine if a tool call was requested by the Executor."""
    messages = state["messages"]
    last_message = messages[-1]

    if last_message.tool_calls:
        return "tools"
    return END


# ---------------------------------------------------------------------------
# TOCTOU Remediation Nodes (Phase 2 — Slippage Bounds)
#
# These three nodes close the ghost-state vulnerability by ensuring the system
# samples the continuous market environment and re-validates deterministic bounds
# at the exact moment of execution — not at the moment of human check.
#
# Architectural invariant: SymbolicGovernor.govern() is called via the direct
# singleton path (src.gateway.governance.singletons) — identical to safety_node.py.
# It is NOT routed through MCP and cannot be bypassed by any LLM agent.
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
    continues so the re-validation step can still run Tier 2/4 on plan params.
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Rehydration") as span:
        span.set_attribute("langfuse.observation.name", "hitl_rehydration")
        span.set_attribute("langfuse.observation.type", "span")

        # 1. Resolve ticker — prefer explicit state field, fall back to plan JSON.
        ticker: Optional[str] = state.get("data_analyst_ticker")
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

        _skipped_result = lambda reason: {  # noqa: E731
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
        stale_price: Optional[float] = None
        try:
            plan_raw = state.get("execution_plan", "")
            plan = json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
            for step in plan.get("steps", []):
                if step.get("price"):
                    stale_price = float(step["price"])
                    break
                # Derive implied price from amount / quantity
                if step.get("amount") and step.get("quantity") and float(step["quantity"]) > 0:
                    stale_price = float(step["amount"]) / float(step["quantity"])
                    break
        except (json.JSONDecodeError, TypeError, ValueError, ZeroDivisionError):
            pass

        # 3. Fetch live quote via yfinance (lightweight fast_info path).
        try:
            import yfinance as yf

            ticker_obj = yf.Ticker(ticker)
            fresh_price: Optional[float] = None

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

            drift_pct: Optional[float] = None
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
                ticker, exc,
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", f"yfinance_error")
            return _skipped_result(f"yfinance_error: {exc}")


@side_effect_node(kind="api_call", external_system="symbolic_governor")
async def post_hitl_revalidate_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — Pre-Actuation Re-Validation Node.

    Tests the human-approved intent against fresh market reality using the
    reviewer's slippage tolerance as the bounded acceptance envelope.

    Enforcement tiers re-run at this node:
        Tier 2: Control Barrier Function (CBF) — cash balance against fresh state
        Tier 4: OPA Rego policy — drawdown, position limits, fiscal cap

    Tiers NOT re-run (input-time checks, independent of market state):
        Tier 1: Keyword scan
        Tier 3: SLM similarity sidecar
        Tier 5: Multi-agent consensus
        Tier 6: DoWhy causal gatekeeper

    Note: SymbolicGovernor.govern() runs the full pipeline. All tiers are
    therefore re-evaluated — this is intentionally conservative. Tiers 1/3/5/6
    will pass trivially since the plan was already approved at check-time.

    Emits OTel span attributes:
        toctou.revalidation.result           — APPROVED | BLOCKED
        toctou.revalidation.block_reason     — slippage | governance_violation
        toctou.revalidation.drift_pct        — measured drift at execution time
        toctou.revalidation.max_slippage_pct — reviewer's approved tolerance
    """
    from src.gateway.governance.singletons import symbolic_governor
    from src.gateway.governance.symbolic_governor import GovernanceError

    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Revalidation") as span:
        span.set_attribute("langfuse.observation.name", "hitl_revalidation")
        span.set_attribute("langfuse.observation.type", "span")

        rehydration: dict[str, Any] = state.get("rehydration_result") or {}
        approval_decision: dict[str, Any] = state.get("approval_decision") or {}

        max_slippage_pct: float = float(approval_decision.get("max_slippage_pct", 2.0))
        drift_pct: Optional[float] = rehydration.get("drift_pct")

        span.set_attribute("toctou.revalidation.max_slippage_pct", max_slippage_pct)
        if drift_pct is not None:
            span.set_attribute("toctou.revalidation.drift_pct", drift_pct)

        # --- Step 1: Slippage gate -------------------------------------------
        # This is the primary TOCTOU closure: the reviewer's approved tolerance
        # defines the mathematical envelope within which execution is permitted.
        if drift_pct is not None and drift_pct > max_slippage_pct:
            block_reason = (
                f"Market price of {rehydration.get('ticker', 'the asset')} drifted "
                f"{drift_pct:.2f}% during the review period, exceeding the approved "
                f"\u00b1{max_slippage_pct:.1f}% slippage tolerance. "
                f"Trade aborted to protect mandate boundaries."
            )
            logger.warning(
                "[RevalidateNode] ⛔ Slippage exceeded: drift=%.2f%% > tolerance=%.2f%%",
                drift_pct, max_slippage_pct,
            )
            span.set_attribute("toctou.revalidation.result", "BLOCKED")
            span.set_attribute("toctou.revalidation.block_reason", "price_slippage_exceeded")
            return {
                "post_hitl_safety_status": "BLOCKED",
                "rehydration_result": {**rehydration, "block_reason": block_reason},
            }

        # --- Step 2: Reconstruct trade params with fresh market data ----------
        fresh_params: dict[str, Any] = {}
        try:
            plan_raw = state.get("execution_plan", "")
            plan = json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
            for step in plan.get("steps", []):
                if step.get("action") in ("execute_trade", "buy", "sell", "BUY", "SELL"):
                    fresh_params = {
                        "action": "execute_trade",
                        "symbol": step.get("symbol", rehydration.get("ticker", "UNKNOWN")),
                        "amount": float(step.get("amount", 0)),
                        "currency": step.get("currency", "USD"),
                        "confidence": float(step.get("confidence", 0.99)),
                        "trader_role": step.get("trader_role", "junior"),
                        "latency_ms": 0.0,
                    }
                    # Inject fresh price so CBF / OPA evaluate against live reality.
                    fresh_price = rehydration.get("fresh_price")
                    if fresh_price:
                        fresh_params["price"] = fresh_price
                    break
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        if not fresh_params:
            # Fallback when plan cannot be parsed — use minimal safe defaults.
            fresh_params = {
                "action": "execute_trade",
                "symbol": rehydration.get("ticker", "UNKNOWN"),
                "amount": 0,
                "confidence": 0.99,
                "latency_ms": 0.0,
            }

        span.set_attribute("toctou.revalidation.symbol", fresh_params.get("symbol", ""))
        fresh_price_logged = rehydration.get("fresh_price") or 0.0
        span.set_attribute("toctou.revalidation.fresh_price", fresh_price_logged)

        # --- Step 3: Tier 2 (CBF) + Tier 4 (OPA) re-check via SymbolicGovernor ---
        # Direct singleton path — identical architectural invariant to safety_node.py.
        # Cannot be bypassed or intercepted by any LLM agent.
        try:
            await symbolic_governor.govern("execute_trade", fresh_params)

            logger.info(
                "[RevalidateNode] ✅ Post-HITL re-validation APPROVED — %s within safe bounds.",
                fresh_params.get("symbol"),
            )
            span.set_attribute("toctou.revalidation.result", "APPROVED")
            return {"post_hitl_safety_status": "APPROVED"}

        except GovernanceError as exc:
            block_reason = (
                f"Governance re-validation failed after human approval: {exc}. "
                f"Market conditions changed during the review period."
            )
            logger.warning(
                "[RevalidateNode] ⛔ Post-HITL governance violation: %s", exc
            )
            span.set_attribute("toctou.revalidation.result", "BLOCKED")
            span.set_attribute("toctou.revalidation.block_reason", "governance_violation")
            span.set_attribute("toctou.revalidation.violation", str(exc))
            return {
                "post_hitl_safety_status": "BLOCKED",
                "rehydration_result": {**rehydration, "block_reason": block_reason},
            }


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
    drift_pct: Optional[float] = rehydration.get("drift_pct")
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
        ticker, drift_pct,
    )

    return {
        "messages": [("ai", message)],
        "post_hitl_safety_status": "BLOCKED",
    }


def route_post_revalidation(state: GovernedTraderState) -> str:
    """Route after HITL re-validation: executor if APPROVED, drift_blocked if BLOCKED."""
    if state.get("post_hitl_safety_status") == "BLOCKED":
        logger.info("[GovernedTrader] Post-HITL re-validation BLOCKED — routing to drift_blocked.")
        return "drift_blocked"
    logger.info("[GovernedTrader] Post-HITL re-validation APPROVED — routing to executor.")
    return "executor"


# ---------------------------------------------------------------------------
# Build Graph
# ---------------------------------------------------------------------------

builder = StateGraph(GovernedTraderState)

# Nodes
builder.add_node("approval", approval_node)
builder.add_node("rejection", rejection_node)
builder.add_node("post_hitl_rehydrate", post_hitl_rehydrate_node)    # TOCTOU: state re-hydration
builder.add_node("post_hitl_revalidate", post_hitl_revalidate_node)  # TOCTOU: pre-actuation re-eval
builder.add_node("drift_blocked", drift_blocked_node)                 # TOCTOU: fail-closed terminal
builder.add_node("executor", executor_node)
builder.add_node("tools", tool_executor_node)

# Entry: conditional — approval required or not
builder.add_conditional_edges(
    START,
    route_approval,
    {"approval": "approval", "executor": "executor"},
)

# After approval_node (approved path): Command(goto="post_hitl_rehydrate") routes here.
# TOCTOU remediation chain:
#   post_hitl_rehydrate → post_hitl_revalidate → executor (APPROVED) | drift_blocked (BLOCKED)
# After approval_node (rejected path): Command(goto="rejection") routes to rejection_node.
# LangGraph resolves Command.goto automatically — no explicit edge from approval needed.
builder.add_edge("post_hitl_rehydrate", "post_hitl_revalidate")
builder.add_conditional_edges(
    "post_hitl_revalidate",
    route_post_revalidation,
    {"executor": "executor", "drift_blocked": "drift_blocked"},
)
builder.add_edge("drift_blocked", END)

# Executor tool-call loop
builder.add_conditional_edges(
    "executor", should_continue, {"tools": "tools", END: END}
)
builder.add_edge("tools", "executor")

# Rejection terminates the subgraph
builder.add_edge("rejection", END)

governed_trader_graph = builder.compile()
