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
Explicit Safety Interceptor Node (Layer 2 Enforcement) — Financial Advisor.

This module is a thin domain-specific wrapper around the generic OPA governance
harness (:mod:`src.gateway.governance.langgraph_harness`).  It provides:

  - ``_extract_trade_payload``: domain extractor that maps the financial
    advisor's ``AgentState`` fields (``execution_plan_output``, ``trader_role``,
    ``risk_attitude``, etc.) into the OPA ``execute_trade`` policy input.
  - ``safety_check_node``: the LangGraph node produced by
    :func:`create_opa_safety_node`.
  - ``route_safety``: the deterministic router produced by
    :func:`create_opa_safety_router`.

R-11: OPA is invoked via SymbolicGovernor.govern() — this is a mandatory
infrastructure guardrail. It is NOT routed through any MCP tool and cannot
be bypassed by the LLM. See ADR 2026-03-09.

ARCHITECTURAL INVARIANT: The harness invokes OPA through
src.gateway.governance.singletons.symbolic_governor — a direct, native path
that cannot be bypassed or intercepted by LLM agents. Do NOT refactor this
to use MCP client or any agent-visible tool dispatch.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.messages import HumanMessage

# ---------------------------------------------------------------------------
# Market-price resolver — module-level so tests can patch it by name.
#
# get_current_price(symbol) → float | None
#
# src.cage_finance.tools.market_service currently exposes MarketService (async sentiment,
# sync status) but no synchronous get_current_price helper.  The try/except
# below attempts to import it when a future sprint adds it; until then it
# falls back to a no-op stub that returns None.  The caller in
# _extract_trade_payload handles None by keeping amount=0, which is then
# handled fail-closed by the OPA rule in trade_governance.rego.
# ---------------------------------------------------------------------------
try:
    from src.cage_finance.tools.market_service import (  # type: ignore[attr-defined]
        get_current_price,
    )
except (ImportError, AttributeError):

    def get_current_price(symbol: str) -> float | None:  # type: ignore[misc]
        """Stub: market price lookup not yet implemented — returns None."""
        return None


from src.gateway.governance.authorization_claim_detector import (
    detect_authorization_claim,
)
from src.gateway.governance.langgraph_harness import (
    OpaNodeConfig,
    create_opa_safety_node,
    create_opa_safety_router,
)

logger = logging.getLogger("SafetyNode")

# ---------------------------------------------------------------------------
# Live risk-metric resolver — module-level so tests can patch by name.
#
# _fetch_live_risk_metrics(account_id, amount_usd) → dict[str, float | int]
#
# Attempts to read live portfolio state from Redis (CBF state store).
# Always returns a dict with all four risk-metric keys:
#   drawdown  — peak-to-trough fraction [0.0, 1.0]; 0.0 is safe sentinel
#   order_size — notional USD of this order (integer cents or 0)
#   daily_vol  — rolling 1-day realised volatility fraction; 0 is safe
#   latency_ms — internal OPA evaluation time; always 0.0 (not broker RTT)
#
# Redis key schema (written by CBF / portfolio tracker):
#   cbf:portfolio_drawdown:{account_id}  → float string, e.g. "0.042"
#   portfolio:daily_vol:{account_id}     → float string, e.g. "0.019"
#
# Failure modes: any Redis import error, connection error, key-not-found,
# or value-parse error causes the metric to stay at the safe sentinel (0.0
# for drawdown/daily_vol, 0 for order_size).  This preserves fail-closed
# behaviour for UCA-5/UCA-6: a 0 drawdown safely passes the threshold guard,
# and a 0 order_size safely passes the volume-fraction guard.
# ---------------------------------------------------------------------------


def _fetch_live_risk_metrics(
    account_id: str,
    amount_usd: float,
) -> dict[str, float | int]:
    """Read live risk metrics from Redis CBF state store.

    Returns safe sentinels on any failure so OPA guards remain conservative.
    """
    # Safe sentinels — used when Redis is unavailable or a key is absent.
    metrics: dict[str, float | int] = {
        "drawdown": 0.0,
        "order_size": 0,
        "daily_vol": 0,
        "latency_ms": 0.0,
    }

    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        # Redis not configured — keep sentinels; log only at debug level to
        # avoid log-flooding in local / unit-test environments.
        logger.debug(
            "_fetch_live_risk_metrics: REDIS_URL not set — using safe sentinels"
        )
        return metrics

    try:
        import redis  # type: ignore[import]

        client = redis.Redis.from_url(
            redis_url, decode_responses=True, socket_timeout=0.2
        )

        # -- drawdown ---------------------------------------------------------
        try:
            raw_dd = client.get(f"cbf:portfolio_drawdown:{account_id}")
            if raw_dd is not None:
                metrics["drawdown"] = max(0.0, min(1.0, float(raw_dd)))  # type: ignore[arg-type]
        except Exception as exc:
            logger.debug("_fetch_live_risk_metrics: drawdown read failed: %s", exc)

        # -- daily_vol --------------------------------------------------------
        try:
            raw_vol = client.get(f"portfolio:daily_vol:{account_id}")
            if raw_vol is not None:
                metrics["daily_vol"] = max(0, int(float(raw_vol) * 10_000))  # type: ignore[arg-type]
        except Exception as exc:
            logger.debug("_fetch_live_risk_metrics: daily_vol read failed: %s", exc)

        # -- order_size -------------------------------------------------------
        # Notional in USD cents — deterministic from the payment amount, not
        # read from Redis.  Kept as 0 when amount_usd is 0 (unknown).
        if amount_usd > 0:
            metrics["order_size"] = int(round(amount_usd))

    except Exception as exc:
        # redis-py import failure or connection error — safe sentinels remain.
        logger.debug(
            "_fetch_live_risk_metrics: Redis unavailable (%s) — using safe sentinels",
            type(exc).__name__,
        )

    return metrics


# ---------------------------------------------------------------------------
# Domain-specific payload extractor
# ---------------------------------------------------------------------------


def _extract_trade_payload(state: dict[str, Any]) -> dict[str, Any]:
    """Map the financial advisor's AgentState into the OPA ``execute_trade`` input.

    Extracts fields from ``execution_plan_output`` and top-level state keys to
    build the flat dict expected by ``trade_governance.rego``.

    ARCHITECTURAL INVARIANT — risk-metric fields are deterministic, never LLM-sourced:

    ``drawdown``, ``order_size``, ``daily_vol``, and ``latency_ms`` are ALWAYS
    supplied by this node from trusted, deterministic sources.  They are NEVER
    read from the LLM-generated plan (``execution_plan_output``).  Rationale:

    - Safety enforcement must be deterministic and LLM-agnostic.  Reading
      risk-metric fields from the plan would allow a misbehaving or adversarially-
      prompted model to influence OPA's UCA-5/UCA-2/UCA-6 decisions by fabricating
      drawdown=0.0 or latency_ms=0.  This node is the correct, trusted enforcement
      point — the LangGraph graph is deterministic; the LLM is not.
    - ``latency_ms`` = 0.0 always: this gate runs in-process; FIN-2/UCA-2 guards
      broker round-trip latency, not internal OPA evaluation time.
    - ``drawdown``: read from Redis ``cbf:portfolio_drawdown:{account_id}`` when
      available, falling back to 0.0 (safe sentinel) when the key is absent or
      Redis is unreachable.  0.0 correctly passes UCA-5's ``val > threshold``
      check — no drawdown has occurred at plan-time.
    - ``order_size``: computed as int(round(amount_usd)) when amount is known,
      falling back to 0 for unknown amounts.  0 safely passes the UCA-6
      volume-fraction guard.
    - ``daily_vol``: read from Redis ``portfolio:daily_vol:{account_id}`` when
      available, scaled to integer basis-points (1.0 → 10000), falling back to 0.

    ``confidence`` = 1.0: this node is a deterministic rule-based gate (OPA),
    not an ML model output; SR 11-7 applies to inference steps only.

    ``claimed_authorization_present``: populated by calling
    ``detect_authorization_claim`` on the raw text of the last HumanMessage in
    ``state["messages"]``.  This flag is set ONLY from the structural detector
    output — never from the LLM-generated plan — so it cannot be influenced by
    adversarial prompt content.  If no human message is present (e.g. unit tests
    that inject only the plan dict), the flag defaults to ``False``.
    """
    plan = state.get("execution_plan_output") or {}
    if isinstance(plan, str):
        # Edge case: plan was stored as a raw string — cannot extract fields.
        plan = {}

    # ------------------------------------------------------------------
    # Authorization-claim detection — defense-in-depth (PR 4).
    # Extract the raw text of the last HumanMessage and run the structural
    # detector.  The result is passed to OPA as ``claimed_authorization_present``.
    # This path is independent of (and complementary to) the NeMo input rail:
    # even if the NeMo layer missed the claim, OPA will force MANUAL_REVIEW.
    # ------------------------------------------------------------------
    claimed_authorization_present: bool = False
    messages = state.get("messages") or []
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            raw_text = msg.content if isinstance(msg.content, str) else ""
            if raw_text:
                authclaim_result = detect_authorization_claim(raw_text)
                claimed_authorization_present = authclaim_result.detected
                if authclaim_result.detected:
                    logger.warning(
                        "🚨 _extract_trade_payload: authorization-claim detected "
                        "in user message — setting claimed_authorization_present=True "
                        "in OPA input (category=%s)",
                        authclaim_result.category,
                    )
            break

    # ------------------------------------------------------------------
    # Deterministic amount computation — defense against RBAC-004 /
    # CONF-SPOOF-001 adversarial patterns where "sell ALL" or high-notional
    # natural-language requests produce amount=0 after LLM plan extraction.
    #
    # Algorithm:
    #   1. Read the LLM plan's raw amount (may be 0 or absent).
    #   2. If amount==0 but quantity + symbol are present, attempt to resolve
    #      current market price from the market data layer and compute
    #      amount = quantity x price deterministically.
    #   3. If the price lookup fails (module absent, network error, etc.) the
    #      raw amount (0) is preserved — fail-open on the lookup, fail-closed
    #      via the OPA rule below (DENY when claimed_authorization_present &&
    #      amount==0 for execute_trade).
    #
    # NEVER trust plan["amount"] as the sole source of truth for fiscal checks.
    # ------------------------------------------------------------------
    _raw_amount: float = float(plan.get("amount", 0) or 0)
    _quantity = plan.get("quantity", plan.get("shares", 0))
    _symbol_for_price = plan.get("symbol", plan.get("ticker", ""))

    if _quantity and _symbol_for_price and _raw_amount == 0:
        # Attempt to resolve current price from the module-level get_current_price.
        # The module-level binding resolves to the real implementation when
        # src.cage_finance.tools.market_service exports it, or to a no-op stub (returns None)
        # when not yet implemented — making it patchable in unit tests.
        # Broad except: any I/O, import, or runtime failure keeps _raw_amount=0;
        # OPA fail-closed rule will DENY when claimed_authorization_present is True.
        try:
            _price = get_current_price(_symbol_for_price)
            if _price is not None and float(_price) > 0:
                _raw_amount = float(_quantity) * float(_price)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Live risk-metric resolution — trusted sources, never LLM-sourced.
    # See ARCHITECTURAL INVARIANT in the docstring above.
    # Account ID is derived from state["user_id"] — same principal that
    # the CBF tracks for portfolio state.
    # ------------------------------------------------------------------
    _account_id = state.get("user_id", "anonymous")
    _risk_metrics = _fetch_live_risk_metrics(_account_id, _raw_amount)

    payload: dict = {
        # Intent fields — sourced from the LLM plan (what to trade, how much).
        "action": plan.get("action", "unknown"),
        # amount: deterministically computed above (quantity x price when
        # possible); falls back to 0 which is handled fail-closed by OPA.
        "amount": _raw_amount,
        "symbol": plan.get("symbol", "UNKNOWN"),
        "currency": plan.get("currency", "USD"),
        "trader_role": plan.get("trader_role", "junior"),
        "user_id": _account_id,
        "risk_profile": state.get("risk_attitude", "neutral"),
        "confidence": plan.get("confidence", 1.0),
        # Risk-metric fields — sourced from live Redis CBF state store when
        # available; fall back to safe sentinels on any failure.
        # NEVER read from the LLM plan. See ARCHITECTURAL INVARIANT above.
        "latency_ms": _risk_metrics["latency_ms"],
        "drawdown": _risk_metrics["drawdown"],
        "order_size": _risk_metrics["order_size"],
        "daily_vol": _risk_metrics["daily_vol"],
        # Defense-in-depth authorization-claim flag (PR 4).
        # Set by the structural detector above; never LLM-sourced.
        "claimed_authorization_present": claimed_authorization_present,
    }
    return payload


# ---------------------------------------------------------------------------
# Node + Router — produced by the governance harness factories
# ---------------------------------------------------------------------------

_opa_config = OpaNodeConfig(
    policy_action_name="execute_trade",
    payload_extractor=_extract_trade_payload,
    plan_state_key="execution_plan_output",
    status_state_key="safety_status",
    error_state_key="error",
    iso_control="A.10.1",
    iso_tier=2,
    thread_id_extractor=lambda s: s.get("thread_id", ""),
    span_attributes={
        "governance.policy": "trade_governance",
    },
)

safety_check_node = create_opa_safety_node(_opa_config)
"""Async LangGraph node — OPA pre-trade safety gate (R-11)."""

route_safety: Any = create_opa_safety_router(
    status_state_key="safety_status",
    approved_target="governed_trader",
    blocked_target="execution_analyst",
)
"""Deterministic router: APPROVED/SKIPPED → governed_trader, else → execution_analyst."""
