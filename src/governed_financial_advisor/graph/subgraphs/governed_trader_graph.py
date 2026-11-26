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

    START → executor → tools (governed_tool_node)
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

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict

from cage_client.langgraph import governed_tool_node
from langchain_core.messages import (
    BaseMessage,
    SystemMessage,
)
from langgraph.graph import END, START, StateGraph

from src.gateway.infrastructure.mcp_client import get_mcp_client
from src.gateway.infrastructure.telemetry_client import get_tracer
from src.gateway.observability.attributes import (
    OBSERVATION_MODEL_NAME,
    OBSERVATION_NAME,
    OBSERVATION_TYPE,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
    TRACE_METADATA_CURRENT_NODE,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.graph.governance.tool_guard import (
    ADVISOR_EXTRA_CLEAR_KEYS,
    ADVISOR_TERMINAL_CLEAR_KEYS,
    advisor_principal_extractor,
    advisor_tool_message,
    canonical_trade_intent,
    extract_trader_plan_steps,
    lookup_cached_trade_preview,
    preview_trade_with_drift_revalidation,
)
from src.governed_financial_advisor.graph.nodes.approval_node import (
    approval_node,
    rejection_node,
)
from src.governed_financial_advisor.graph.nodes.toctou_quote import (
    extract_pending_trade_tool_ticker,
    extract_plan_ticker_and_price,
    extract_reference_quote_from_state,
    fetch_live_yfinance_price,
    non_negative_finite_float,
    normalize_ticker,
    positive_finite_float,
    resolve_check_time_reference_quote,
    resolve_decision_slippage_pct,
)
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    TRADE_ACTION,
    TRADE_TOOL,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.governed_financial_advisor.infrastructure.llm.models import chat_model

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
    deferred_step_ids: list[str | None] | None
    approval_required: bool
    approval_decision: dict[str, Any] | None
    hitl_expires_at: str | None  # TTL expiration timestamp for pending state
    # TOCTOU Remediation — Phase 2 (Slippage Bounds + TTL)
    # These fields close the ghost-state vulnerability: continuous market variables
    # are re-sampled and re-validated at the moment of actuation, not at check-time.
    data_analyst_ticker: str | None  # passed from parent graph for re-hydration
    hitl_reference_quote: (
        dict[str, Any] | None
    )  # check-time {ticker, price, source, captured_at_utc}
    rehydration_result: dict | None  # fresh market snapshot + drift metrics
    post_hitl_safety_status: str | None  # "PASSED" | "BLOCKED" after the slippage gate

    # Written by gateway_tool_guard (POST /governance/validate-action)
    governance_envelope: dict[str, Any] | None  # Gateway ALLOW/NARROW verdict
    governance_status: str | None  # "ALLOWED" | "DENIED" | "REQUIRE_APPROVAL"
    routing_verdict_cache: dict[str, Any] | None  # Cached ALLOW routing verdict
    # ApprovalRedemptionRefusal value of the last refused redemption, or None
    redemption_refusal: str | None


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
# Executor node (CAGE governance enforced downstream by governed_tool_node)
# ---------------------------------------------------------------------------


async def executor_node(state: GovernedTraderState) -> dict[str, Any]:
    """Generate execute_trade_action tool calls from the approved plan.

    The downstream ``governed_tool_node`` previews every emitted tool call with
    the gateway (``POST /governance/validate-action``) and executes approved calls
    over ``POST /tools/execute``."""
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: Executor") as span:
        model_name = os.getenv("MODEL_FAST")
        span.set_attribute(OBSERVATION_MODEL_NAME, model_name)
        span.set_attribute(TRACE_METADATA_CURRENT_NODE, "governed_trader_executor")
        span.set_attribute("gen_ai.operation.name", "chat")

        llm = chat_model(
            "fast",
            model=model_name,
            temperature=0.0,
            max_tokens=4096,
        )

        # Load cached MCP tools over the pooled stateless Streamable HTTP client
        mcp_client = get_mcp_client()
        await mcp_client.ensure_connected()
        mcp_tools = await mcp_client.get_tools()

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

        response = await llm_with_tools.ainvoke(messages)

        span.set_attribute(
            SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
            len(str(getattr(response, "content", "") or "")),
        )

        out: dict[str, Any] = {"messages": [response]}

        # On pre-HITL entry, ensure a fresh check-time reference quote is recorded
        # for the exact tool-call symbol before gateway_tool_guard can park a
        # REQUIRE_APPROVAL interrupt (overwriting any prior turn's quote).
        decision = state.get("approval_decision")
        pre_hitl = not (
            state.get("deferred_id")
            and isinstance(decision, dict)
            and decision.get("approved") is True
        )
        tool_calls = getattr(response, "tool_calls", None) or []
        if pre_hitl and tool_calls:
            first_args = (
                tool_calls[0].get("args") if isinstance(tool_calls[0], dict) else None
            )
            call_symbol = (
                normalize_ticker(first_args.get("symbol"))
                if isinstance(first_args, dict)
                else None
            )
            resolved_sym, _, _ = extract_reference_quote_from_state(
                state,
                preferred_ticker=call_symbol,
            )
            target_sym = call_symbol or resolved_sym
            if target_sym is not None:
                out["data_analyst_ticker"] = target_sym
                out["hitl_reference_quote"] = await resolve_check_time_reference_quote(
                    state,
                    ticker=target_sym,
                    plan_raw=state.get("execution_plan"),
                )

        # The tool calls on ``response`` are what gateway_tool_guard submits to
        # the gateway — every one of them, not a summarised first call.
        return out


# ---------------------------------------------------------------------------
# Conditional edges: executor → tools | END, tools → executor | END
# ---------------------------------------------------------------------------


def should_continue(state: GovernedTraderState) -> str:
    """Determine if a tool call was requested by the Executor."""
    messages = state["messages"]
    last_message = messages[-1]

    if getattr(last_message, "tool_calls", None):
        return "tools"
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


def _resolve_deferred_step_tickers(state: GovernedTraderState) -> list[str]:
    """Return unique normalized trade symbols for deferred steps in ``deferred_step_ids``."""
    raw_step_ids = state.get("deferred_step_ids")
    if not isinstance(raw_step_ids, list) or not any(
        isinstance(item, str) and item.strip() for item in raw_step_ids
    ):
        return []

    from src.governed_financial_advisor.graph.nodes.trade_contract import (
        extract_trade_steps,
    )

    plan_raw = state.get("execution_plan", "")
    plan_dict: dict[str, Any] = {}
    if isinstance(plan_raw, dict):
        plan_dict = plan_raw
    elif isinstance(plan_raw, str) and plan_raw.strip():
        try:
            loaded = json.loads(plan_raw)
            if isinstance(loaded, dict):
                plan_dict = loaded
        except json.JSONDecodeError:
            plan_dict = {}

    try:
        trade_steps = extract_trade_steps(plan_dict)
    except Exception:
        return []

    tickers: list[str] = []
    for idx, step_id in enumerate(raw_step_ids):
        if not (isinstance(step_id, str) and step_id.strip()):
            continue
        if idx >= len(trade_steps):
            continue
        sym = normalize_ticker(trade_steps[idx].get("symbol"))
        if sym is not None and sym not in tickers:
            tickers.append(sym)
    return tickers


async def _rehydrate_multiple_tickers(
    state: GovernedTraderState,
    tickers: list[str],
    span: Any,
) -> dict[str, Any]:
    """Verify check-time and live quotes across every deferred trade symbol in a multi-step plan."""
    step_quotes: list[dict[str, Any]] = []
    worst: dict[str, Any] | None = None

    for sym in tickers:
        _, stale_price, _ = extract_reference_quote_from_state(
            {**state, "data_analyst_ticker": sym},
            preferred_ticker=sym,
        )
        if stale_price is None:
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "missing_reference_price")
            span.set_attribute("toctou.rehydration.ticker", sym)
            return {
                "rehydration_result": {
                    "status": "SKIPPED",
                    "reason": "missing_reference_price",
                    "ticker": sym,
                    "fresh_price": None,
                    "stale_price": None,
                    "drift_pct": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            }
        try:
            fresh_price = await fetch_live_yfinance_price(sym)
        except Exception as exc:
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "yfinance_error")
            span.set_attribute("toctou.rehydration.ticker", sym)
            return {
                "rehydration_result": {
                    "status": "SKIPPED",
                    "reason": f"yfinance_error: {exc}",
                    "ticker": sym,
                    "fresh_price": None,
                    "stale_price": stale_price,
                    "drift_pct": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            }
        if fresh_price is None:
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "missing_fresh_price")
            span.set_attribute("toctou.rehydration.ticker", sym)
            return {
                "rehydration_result": {
                    "status": "SKIPPED",
                    "reason": "missing_fresh_price",
                    "ticker": sym,
                    "fresh_price": None,
                    "stale_price": stale_price,
                    "drift_pct": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            }

        drift_pct = abs(fresh_price - stale_price) / stale_price * 100.0
        entry = {
            "ticker": sym,
            "fresh_price": fresh_price,
            "stale_price": stale_price,
            "drift_pct": drift_pct,
        }
        step_quotes.append(entry)
        if worst is None or drift_pct > worst["drift_pct"]:
            worst = entry

    assert worst is not None  # tickers has >= 2 items
    span.set_attribute("toctou.rehydration.status", "OK")
    span.set_attribute("toctou.rehydration.ticker", worst["ticker"])
    span.set_attribute("toctou.rehydration.stale_price", worst["stale_price"])
    span.set_attribute("toctou.rehydration.fresh_price", worst["fresh_price"])
    span.set_attribute("toctou.rehydration.drift_pct", worst["drift_pct"])
    return {
        "rehydration_result": {
            "status": "OK",
            **worst,
            "step_quotes": step_quotes,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    }


@side_effect_node(kind="api_call", external_system="yfinance")
async def post_hitl_rehydrate_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — State Re-hydration Node.

    Samples the live market environment immediately after HITL resumption.
    Runs BEFORE ``post_hitl_revalidate_node`` to populate fresh price data and
    measured drift against the check-time reference quote.

    Emits OTel span attributes:
        toctou.rehydration.status       — OK | SKIPPED
        toctou.rehydration.reason       — populated when status=SKIPPED
        toctou.rehydration.ticker       — symbol fetched
        toctou.rehydration.stale_price  — check-time reference price
        toctou.rehydration.fresh_price  — live quote from yfinance
        toctou.rehydration.drift_pct    — abs percentage change

    Degrades without raising an exception on missing ticker, missing reference
    price, or yfinance errors by returning ``status="SKIPPED"`` and
    ``drift_pct=None``, which ``post_hitl_revalidate_node`` then blocks
    fail-closed (``drift_unverifiable``).
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Rehydration") as span:
        span.set_attribute(OBSERVATION_NAME, "hitl_rehydration")
        span.set_attribute(OBSERVATION_TYPE, "span")

        deferred_tickers = _resolve_deferred_step_tickers(state)
        if len(deferred_tickers) > 1:
            return await _rehydrate_multiple_tickers(state, deferred_tickers, span)

        # 1. Resolve validated ticker + check-time reference price from state,
        #    hitl_reference_quote, ExecutionPlan (nested PlanStep.parameters or
        #    flat step), pending tool call, or get_market_data message history.
        ticker = (
            deferred_tickers[0]
            if len(deferred_tickers) == 1
            else normalize_ticker(state.get("data_analyst_ticker"))
        )
        plan_ticker, _ = extract_plan_ticker_and_price(
            state.get("execution_plan", ""),
            preferred_ticker=ticker,
        )
        if ticker is None and plan_ticker is not None:
            ticker = plan_ticker
        if ticker is None:
            ticker = extract_pending_trade_tool_ticker(state.get("messages"))

        resolved_ticker, stale_price, _ = extract_reference_quote_from_state(
            state,
            preferred_ticker=ticker,
        )
        if ticker is None and resolved_ticker is not None:
            ticker = resolved_ticker

        def _skipped_result(
            reason: str,
            *,
            stale: float | None = None,
            fresh: float | None = None,
        ) -> dict[str, Any]:
            return {
                "rehydration_result": {
                    "status": "SKIPPED",
                    "reason": reason,
                    "ticker": ticker,
                    "fresh_price": fresh,
                    "stale_price": stale,
                    "drift_pct": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            }

        if not ticker:
            logger.warning(
                "[RehydrateNode] ⚠️ No valid ticker found in state or execution_plan — "
                "marking rehydration SKIPPED (post_hitl_revalidate will block fail-closed)."
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "no_ticker")
            return _skipped_result("no_ticker")

        span.set_attribute("toctou.rehydration.ticker", ticker)

        if stale_price is None:
            logger.warning(
                "[RehydrateNode] ⚠️ No check-time reference price found for %s — "
                "marking rehydration SKIPPED (post_hitl_revalidate will block fail-closed).",
                ticker,
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "missing_reference_price")
            return _skipped_result("missing_reference_price")

        span.set_attribute("toctou.rehydration.stale_price", stale_price)

        # 2. Fetch live quote via yfinance off the event loop with bounded timeout.
        try:
            fresh_price = await fetch_live_yfinance_price(ticker)
            if fresh_price is None:
                logger.warning(
                    "[RehydrateNode] ⚠️ yfinance returned no usable quote for %s — "
                    "marking rehydration SKIPPED (post_hitl_revalidate will block fail-closed).",
                    ticker,
                )
                span.set_attribute("toctou.rehydration.status", "SKIPPED")
                span.set_attribute("toctou.rehydration.reason", "missing_fresh_price")
                return _skipped_result("missing_fresh_price", stale=stale_price)

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
            span.set_attribute("toctou.rehydration.fresh_price", fresh_price)
            span.set_attribute("toctou.rehydration.drift_pct", drift_pct)

            logger.info(
                "[RehydrateNode] ✅ %s | stale=%.4f fresh=%.4f drift=%.2f%%",
                ticker,
                stale_price,
                fresh_price,
                drift_pct,
            )
            return {"rehydration_result": result}

        except Exception as exc:
            logger.warning(
                "[RehydrateNode] ⚠️ yfinance fetch failed for %s (%s) — "
                "rehydration SKIPPED (post_hitl_revalidate will block fail-closed).",
                ticker,
                exc,
            )
            span.set_attribute("toctou.rehydration.status", "SKIPPED")
            span.set_attribute("toctou.rehydration.reason", "yfinance_error")
            return _skipped_result(f"yfinance_error: {exc}", stale=stale_price)


async def post_hitl_revalidate_node(state: GovernedTraderState) -> dict[str, Any]:
    """TOCTOU Remediation — fail-closed reviewer slippage gate.

    Blocks when the market moved further during review than the reviewer's
    ``max_slippage_pct`` allows OR when market drift cannot be verified
    (``status != "OK"``, missing/non-finite ``drift_pct``, missing reference or
    live quote, or invalid ``max_slippage_pct``). Because the gateway never
    receives ``max_slippage_pct``, this node is the sole enforcement point for
    the human reviewer's slippage constraint and must never stamp ``PASSED`` on
    unverifiable drift (POAM-2026-240).

    Governance re-validation of the trade parameters still runs in the gateway
    (POST_HITL profile) when ``execute_trade_action`` consumes ``deferred_id``
    (POAM-2026-079).

    Emits OTel span attributes:
        toctou.revalidation.result           — PASSED | BLOCKED
        toctou.revalidation.block_reason     — price_slippage_exceeded | drift_unverifiable | invalid_slippage_tolerance
        toctou.revalidation.drift_pct        — measured drift at execution time (when finite)
        toctou.revalidation.max_slippage_pct — reviewer's approved tolerance (when valid)
    """
    tracer = get_tracer()

    with tracer.start_as_current_span("GovernedTrader: HITL Revalidation") as span:
        span.set_attribute(OBSERVATION_NAME, "hitl_revalidation")
        span.set_attribute(OBSERVATION_TYPE, "span")

        rehydration: dict[str, Any] = state.get("rehydration_result") or {}
        approval_decision: dict[str, Any] = state.get("approval_decision") or {}

        max_slippage_pct = resolve_decision_slippage_pct(approval_decision, default=2.0)
        if max_slippage_pct is None:
            block_reason = (
                "Approved slippage tolerance (max_slippage_pct) is invalid or "
                "outside [0.0%, 100.0%]. Trade aborted fail-closed."
            )
            logger.warning("[RevalidateNode] ⛔ %s", block_reason)
            span.set_attribute("toctou.revalidation.result", "BLOCKED")
            span.set_attribute(
                "toctou.revalidation.block_reason", "invalid_slippage_tolerance"
            )
            return {
                "post_hitl_safety_status": "BLOCKED",
                "rehydration_result": {**rehydration, "block_reason": block_reason},
            }

        span.set_attribute("toctou.revalidation.max_slippage_pct", max_slippage_pct)

        drift_pct = non_negative_finite_float(rehydration.get("drift_pct"))
        stale_invalid = (
            "stale_price" in rehydration
            and positive_finite_float(rehydration.get("stale_price")) is None
        )
        fresh_invalid = (
            "fresh_price" in rehydration
            and positive_finite_float(rehydration.get("fresh_price")) is None
        )
        if (
            rehydration.get("status") != "OK"
            or drift_pct is None
            or stale_invalid
            or fresh_invalid
        ):
            reason_detail = str(rehydration.get("reason") or "unverified_quote_state")
            asset = rehydration.get("ticker") or "the asset"
            block_reason = (
                f"Unable to verify post-HITL market drift for {asset} against the "
                f"approved \u00b1{max_slippage_pct:.1f}% slippage tolerance "
                f"({reason_detail}). Trade aborted fail-closed."
            )
            logger.warning(
                "[RevalidateNode] ⛔ Drift unverifiable (%s) — failing closed.",
                reason_detail,
            )
            span.set_attribute("toctou.revalidation.result", "BLOCKED")
            span.set_attribute("toctou.revalidation.block_reason", "drift_unverifiable")
            return {
                "post_hitl_safety_status": "BLOCKED",
                "rehydration_result": {
                    **rehydration,
                    "drift_pct": None,
                    "block_reason": block_reason,
                },
            }

        span.set_attribute("toctou.revalidation.drift_pct", drift_pct)

        if drift_pct > max_slippage_pct:
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
        "block_reason",
        "Market conditions could not be verified within the review envelope.",
    )
    ticker: str = rehydration.get("ticker") or "the asset"
    drift_pct = non_negative_finite_float(rehydration.get("drift_pct"))
    reviewer: str = approval_decision.get("reviewer", "the reviewer")
    max_slippage_pct = resolve_decision_slippage_pct(approval_decision, default=2.0)

    if drift_pct is not None and max_slippage_pct is not None:
        drift_summary = (
            f"The market price of **{ticker}** moved **{drift_pct:.2f}%** during the "
            f"review period, exceeding the approved \u00b1{max_slippage_pct:.1f}% "
            f"slippage tolerance."
        )
    else:
        drift_summary = block_reason

    message = (
        f"\u26d4 **Trade Blocked \u2014 Post-HITL Safety Gate**\n\n"
        f"{drift_summary}\n\n"
        f"**What happened:** {reviewer} approved this trade, but at actuation time "
        f"the system could not confirm that live market prices remained within the "
        f"approved safety envelope. The trade was automatically blocked fail-closed "
        f"to protect the investment mandate.\n\n"
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
        "deferred_id": None,
        "deferred_step_ids": None,
        "approval_required": False,
        "approval_decision": None,
        "hitl_reference_quote": None,
    }


def route_entry(state: GovernedTraderState) -> str:
    """Route on subgraph entry: run post-HITL TOCTOU gate when entering with a resolved approval."""
    decision = state.get("approval_decision")
    step_ids = state.get("deferred_step_ids")
    has_step_ids = isinstance(step_ids, list) and any(
        isinstance(item, str) and item.strip() for item in step_ids
    )
    if (
        (state.get("deferred_id") or has_step_ids)
        and isinstance(decision, dict)
        and decision.get("approved") is True
    ):
        logger.info(
            "[GovernedTrader] Entering with pre-approved deferred_id — routing to post_hitl_rehydrate."
        )
        return "post_hitl_rehydrate"
    return "executor"


def route_post_revalidation(state: GovernedTraderState) -> str:
    """Route after the slippage gate: executor ONLY on explicit PASSED, else drift_blocked."""
    if state.get("post_hitl_safety_status") == "PASSED":
        logger.info("[GovernedTrader] Slippage gate passed — routing to executor.")
        return "executor"
    logger.info(
        "[GovernedTrader] Post-HITL re-validation status=%r (not PASSED) — routing fail-closed to drift_blocked.",
        state.get("post_hitl_safety_status"),
    )
    return "drift_blocked"


# ---------------------------------------------------------------------------
# Build Graph
# ---------------------------------------------------------------------------

# Every tool call is previewed by the gateway (POST /governance/validate-action)
# and executed via POST /tools/execute using the canonical ``transaction_id``
# idempotency parameter; REQUIRE_APPROVAL routes to ``approval``, while refusals
# and INDETERMINATE halt directly to END.
guarded_tool_executor_node = governed_tool_node(
    client=lambda: GatewayClient().sdk_client(),
    action=TRADE_ACTION,
    mode="execute",
    idempotency_param="transaction_id",
    committing_tools=frozenset({TRADE_TOOL}),
    principal_extractor=advisor_principal_extractor,
    plan_extractor=lambda s: s.get("execution_plan"),
    step_extractor=extract_trader_plan_steps,
    step_canonical_extractor=canonical_trade_intent,
    preview_cache_lookup=lookup_cached_trade_preview,
    preview_fn=preview_trade_with_drift_revalidation,
    message_formatter=advisor_tool_message,
    on_complete="executor",
    on_approval_required="approval",
    on_defer=END,
    on_deny=END,
    on_unavailable=END,
    on_indeterminate=END,
    approvable=True,
    extra_clear_keys=ADVISOR_EXTRA_CLEAR_KEYS,
    terminal_clear_keys=ADVISOR_TERMINAL_CLEAR_KEYS,
)


def build_governed_trader_graph(*, checkpointer: Any | None = None) -> Any:
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
    builder.add_node(
        "drift_blocked", drift_blocked_node
    )  # TOCTOU: fail-closed terminal
    builder.add_node("executor", executor_node)
    builder.add_node("tools", guarded_tool_executor_node)  # CAGE SDK execute node

    # Entry: if resumed from parent-graph HITL approval with deferred_id +
    # approval_decision, run the post-HITL TOCTOU slippage gate before executor.
    builder.add_conditional_edges(
        START,
        route_entry,
        {"executor": "executor", "post_hitl_rehydrate": "post_hitl_rehydrate"},
    )

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

    # Executor tool-call loop; tools returns Command(goto="executor" | "approval" | END)
    # directly so LangGraph resolves navigation without static edges on tools.
    builder.add_conditional_edges(
        "executor", should_continue, {"tools": "tools", END: END}
    )

    # Rejection terminates the subgraph
    builder.add_edge("rejection", END)

    return builder.compile(checkpointer=checkpointer)
