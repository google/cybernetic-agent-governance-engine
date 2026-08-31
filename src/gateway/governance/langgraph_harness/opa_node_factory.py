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
OPA safety-node factory — produces async LangGraph nodes with OPA governance.

The factory encapsulates:
  - OPA invocation via ``symbolic_governor.govern()``
  - OTel span instrumentation with Langfuse attributes
  - ISO 42001 evidence stamping (``stamp_iso_control``)
  - Compliance scoring via OTel span events
  - Fail-closed exception handling (any error → BLOCKED)
  - SKIPPED fast path when no plan/action is present

Domain-specific state access is injected via ``OpaNodeConfig.payload_extractor``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from opentelemetry import trace

from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.langgraph_harness.types import OpaNodeConfig, StateDict
from src.gateway.governance.singletons import symbolic_governor
from src.gateway.governance.symbolic_governor import GovernanceError

logger = logging.getLogger("gateway.governance.langgraph_harness.opa_node_factory")
tracer = trace.get_tracer("src.gateway.governance.langgraph_harness.opa_node_factory")


# ---------------------------------------------------------------------------
# Compliance scoring helper — optional, imported at call-time to avoid
# hard-coupling the harness to the governed_financial_advisor package.
# ---------------------------------------------------------------------------


def _score_compliance(thread_id: str, control: str, passed: bool, comment: str) -> None:
    """Best-effort compliance scoring via OTel span events.

    Falls back silently if the compliance scoring module is unavailable
    (e.g. the harness is used outside the financial-advisor codebase).
    """
    try:
        from src.gateway.observability.langfuse_utils import (
            score_compliance_event,
        )

        score_compliance_event(thread_id, control, passed=passed, comment=comment)
    except ImportError:
        # Harness is used in a project that doesn't have langfuse_utils —
        # compliance scoring degrades gracefully to a no-op.
        logger.debug(
            "score_compliance_event not available — skipping compliance score "
            "for control=%s",
            control,
        )


# ---------------------------------------------------------------------------
# Node factory
# ---------------------------------------------------------------------------


def create_opa_safety_node(config: OpaNodeConfig) -> Callable:
    """Return an async LangGraph node function that enforces OPA policy.

    The returned function reads domain-specific data from state via
    ``config.payload_extractor``, invokes ``symbolic_governor.govern()``,
    and writes the outcome to ``config.status_state_key``.

    Governance decisions:
        - **SKIPPED** — ``config.plan_state_key`` is absent/empty in state.
        - **APPROVED** — ``govern()`` succeeded (no exception).
        - **ESCALATED** — ``GovernanceError`` with "Manual Review" or
          "Consensus Escalation" in the message.
        - **BLOCKED** — ``GovernanceError`` (other) or any unexpected exception
          (fail-closed).

    Args:
        config: An :class:`OpaNodeConfig` instance defining the policy action,
                payload extraction, and routing keys.

    Returns:
        An ``async def opa_safety_node(state) -> dict`` suitable for
        ``workflow.add_node()``.
    """

    _thread_id_fn = config.thread_id_extractor or (lambda s: s.get("thread_id", ""))

    async def opa_safety_node(state: StateDict) -> dict[str, Any]:
        with tracer.start_as_current_span("governance.opa_safety_node") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "opa_safety_gate")

            # ----- Apply user-provided span attributes -----
            for attr_key, attr_val in config.span_attributes.items():
                span.set_attribute(attr_key, attr_val)

            # ----- 1. Check for plan presence -----
            plan = state.get(config.plan_state_key)
            if not plan:
                span.set_attribute("governance.decision", "SKIPPED")
                span.set_attribute(
                    "langfuse.observation.output",
                    f"SKIPPED: no {config.plan_state_key}",
                )
                logger.warning(
                    "No %s found to validate. Passing through.",
                    config.plan_state_key,
                )
                return {config.status_state_key: "SKIPPED"}

            # ----- 2. Extract OPA payload via domain extractor -----
            opa_input = config.payload_extractor(state)

            # Propagate extracted payload fields to span for observability
            for key in ("action", "trader_role", "amount"):
                if key in opa_input:
                    span.set_attribute(
                        f"langfuse.trace.metadata.governance.{key}",
                        opa_input[key],
                    )

            thread_id = _thread_id_fn(state)

            # ----- 3. Invoke OPA via SymbolicGovernor -----
            try:
                await symbolic_governor.govern(config.policy_action_name, opa_input)
                logger.info(
                    "✅ Safety Check PASSED: %s",
                    opa_input.get("action", config.policy_action_name),
                )
                span.set_attribute("governance.decision", "APPROVED")
                span.set_attribute("governance.blocked", False)
                span.set_attribute("langfuse.observation.output", "APPROVED")
                stamp_iso_control(
                    span,
                    tier=config.iso_tier,
                    control=config.iso_control,
                    outcome="PASS",
                )
                _score_compliance(
                    thread_id,
                    config.iso_control,
                    passed=True,
                    comment=f"OPA {config.policy_action_name} gate APPROVED",
                )
                return {config.status_state_key: "APPROVED"}

            except GovernanceError as exc:
                msg = str(exc)
                span.set_attribute("governance.reason", msg)
                span.set_attribute("langfuse.observation.output", msg)

                if "Manual Review" in msg or "Consensus Escalation" in msg:
                    logger.warning(
                        "⚠️ Safety Check ESCALATED: %s — %s",
                        opa_input.get("action", config.policy_action_name),
                        msg,
                    )
                    span.set_attribute("governance.decision", "ESCALATED")
                    span.set_attribute("governance.blocked", True)
                    stamp_iso_control(
                        span,
                        tier=config.iso_tier,
                        control=config.iso_control,
                        outcome="ESCALATE",
                    )
                    _score_compliance(
                        thread_id,
                        config.iso_control,
                        passed=False,
                        comment=f"OPA {config.policy_action_name} gate ESCALATED: {msg}",
                    )
                    return {
                        config.status_state_key: "ESCALATED",
                        config.error_state_key: msg,
                    }

                logger.critical(
                    "⛔ Safety Check BLOCKED: %s — %s",
                    opa_input.get("action", config.policy_action_name),
                    msg,
                )
                span.set_attribute("governance.decision", "BLOCKED")
                span.set_attribute("governance.blocked", True)
                span.record_exception(exc)
                span.set_status(trace.Status(trace.StatusCode.ERROR, msg))
                stamp_iso_control(
                    span,
                    tier=config.iso_tier,
                    control=config.iso_control,
                    outcome="BLOCK",
                )
                _score_compliance(
                    thread_id,
                    config.iso_control,
                    passed=False,
                    comment=f"OPA {config.policy_action_name} gate BLOCKED: {msg}",
                )
                return {
                    config.status_state_key: "BLOCKED",
                    config.error_state_key: msg,
                }

            except Exception as exc:
                # Fail-closed: deny rather than silently bypass
                logger.error("Safety Check Error (fail-closed): %s", exc)
                span.record_exception(exc)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
                span.set_attribute("governance.decision", "BLOCKED")
                span.set_attribute("governance.blocked", True)
                stamp_iso_control(
                    span,
                    tier=config.iso_tier,
                    control=config.iso_control,
                    outcome="BLOCK",
                )
                return {
                    config.status_state_key: "BLOCKED",
                    config.error_state_key: f"Governance check failed: {exc}",
                }

    # Preserve a human-readable function name for LangGraph introspection
    opa_safety_node.__qualname__ = f"opa_safety_node[{config.policy_action_name}]"
    return opa_safety_node


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def create_opa_safety_router(
    status_state_key: str = "safety_status",
    approved_target: str = "governed_trader",
    blocked_target: str = "execution_analyst",
) -> Callable:
    """Return a deterministic routing function for OPA safety outcomes.

    Maps:
        - ``APPROVED`` / ``SKIPPED`` → *approved_target*
        - ``BLOCKED`` / ``ESCALATED`` → *blocked_target*

    Args:
        status_state_key: State key holding the OPA decision string.
        approved_target: Node name to route to on success.
        blocked_target: Node name to route to on denial.

    Returns:
        A ``def route(state) -> str`` function suitable for
        ``workflow.add_conditional_edges()``.
    """

    def route_safety(state: StateDict) -> str:
        status = state.get(status_state_key)
        if status in ("APPROVED", "SKIPPED"):
            return approved_target
        return blocked_target

    route_safety.__qualname__ = (
        f"route_safety[{status_state_key}→{approved_target}/{blocked_target}]"
    )
    return route_safety
