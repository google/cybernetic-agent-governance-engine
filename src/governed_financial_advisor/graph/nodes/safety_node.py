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
from typing import Any, Literal

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

    NOTE: ``confidence`` is set to 1.0 because the safety_check_node is a
    deterministic rule-based gate (OPA), not an ML model output.
    SR 11-7 applies to model inference steps; by the time we reach this node
    the plan is a deterministic structured object.

    ``latency_ms`` is set to 0.0 because the safety gate runs in-process.
    STPA FIN-2 guards against slow broker round-trips, not internal OPA calls.
    """
    plan = state.get("execution_plan_output") or {}
    if isinstance(plan, str):
        # Edge case: plan was stored as a raw string — cannot extract fields
        plan = {}

    payload: dict = {
        "action": plan.get("action", "unknown"),
        "amount": plan.get("amount", 0),
        "symbol": plan.get("symbol", "UNKNOWN"),
        "currency": plan.get("currency", "USD"),
        "trader_role": plan.get("trader_role", "junior"),
        "user_id": state.get("user_id", "anonymous"),
        "risk_profile": state.get("risk_attitude", "neutral"),
        "confidence": plan.get("confidence", 1.0),
        "latency_ms": plan.get("latency_ms", 0.0),
    }
    # Pass through optional STPA-required fields when present in the plan.
    # UCA-5 checks drawdown; UCA-6 checks order_size / daily_vol.
    # These are populated by the risk analyst agent in production.
    for optional_field in ("drawdown", "order_size", "daily_vol"):
        if optional_field in plan:
            payload[optional_field] = plan[optional_field]
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
