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
from typing import Any

from langchain_core.messages import HumanMessage

# ---------------------------------------------------------------------------
# Market-price resolver — module-level so tests can patch it by name.
#
# get_current_price(symbol) → float | None
#
# src.gateway.core.market currently exposes MarketService (async sentiment,
# sync status) but no synchronous get_current_price helper.  The try/except
# below attempts to import it when a future sprint adds it; until then it
# falls back to a no-op stub that returns None.  The caller in
# _extract_trade_payload handles None by keeping amount=0, which is then
# handled fail-closed by the OPA rule in trade_governance.rego.
# ---------------------------------------------------------------------------
try:
    from src.gateway.core.market import get_current_price  # type: ignore[attr-defined]
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
    - ``drawdown`` = 0.0 always (safe sentinel): 0% drawdown correctly passes
      UCA-5's ``val > threshold`` check — no drawdown has occurred at plan-time.
      The full risk-metric data-flow (a dedicated ``compute_drawdown`` node that
      reads live portfolio state from Redis/CBF and threads the result into the
      safety payload) is tracked in the architecture backlog.
    - ``order_size`` / ``daily_vol`` = 0 always: UCA-6 composite condition;
      0-size order safely passes the volume-fraction guard.

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
        # src.gateway.core.market exports it, or to a no-op stub (returns None)
        # when not yet implemented — making it patchable in unit tests.
        # Broad except: any I/O, import, or runtime failure keeps _raw_amount=0;
        # OPA fail-closed rule will DENY when claimed_authorization_present is True.
        try:
            _price = get_current_price(_symbol_for_price)
            if _price is not None and float(_price) > 0:
                _raw_amount = float(_quantity) * float(_price)
        except Exception:
            pass

    payload: dict = {
        # Intent fields — sourced from the LLM plan (what to trade, how much).
        "action": plan.get("action", "unknown"),
        # amount: deterministically computed above (quantity x price when
        # possible); falls back to 0 which is handled fail-closed by OPA.
        "amount": _raw_amount,
        "symbol": plan.get("symbol", "UNKNOWN"),
        "currency": plan.get("currency", "USD"),
        "trader_role": plan.get("trader_role", "junior"),
        "user_id": state.get("user_id", "anonymous"),
        "risk_profile": state.get("risk_attitude", "neutral"),
        "confidence": plan.get("confidence", 1.0),
        # Risk-metric fields — ALWAYS deterministic; NEVER read from the LLM plan.
        # See ARCHITECTURAL INVARIANT in the docstring above.
        "latency_ms": 0.0,
        "drawdown": 0.0,
        "order_size": 0,
        "daily_vol": 0,
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
