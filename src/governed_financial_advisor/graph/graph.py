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
Graph Definition: CAGE Architecture — Phase 3 (Explicit Lifecycle with Signature Gate)
Planner -> Evaluator -> [Signature Gate] -> Executor -> Auditor

Graph Topology
--------------
The governed financial advisor graph is a directed state machine with the
following node sequence:

    START
      └─► nemo_guardrail        (mandatory input rail — ADR 2026-03-09)
            ├─► END             (blocked path — no agent output to screen)
            └─► thinker_node
                  └─► doer_node
                        ├─► data_analyst      ─► nemo_output_rail ─► END
                        ├─► execution_analyst ─► evaluator
                        │     ├─► ftra_node   (CTRL_FTRA_001 — Tier 0.5 reachability gate)
                        │     │     ├─► safety_check ─► governed_trader ─► explainer
                        │     │     │                └─► explainer (BLOCKED/ESCALATED)
                        │     │     ├─► explainer (FTRA BLOCKED)
                        │     │     └─► [DeferQueue park] (FTRA HITL_REQUIRED)
                        │     └─► execution_analyst (loop, max 3)
                        │     └─► explainer (loop cap)
                        └─► nemo_output_rail (FINISH) ─► END

Side-Effect Surface
-------------------
All nodes that perform external I/O (database writes, API calls, message
queue publishes) are annotated with ``@side_effect_node`` from
:mod:`src.governed_financial_advisor.graph.annotations`.

To inspect the complete side-effect surface without running the system,
call :func:`get_side_effect_topology`.  This is the canonical proof
artifact for the July compliance review.

LangGraph 1.1 Notes:
  - StateGraph / TypedDict / add_messages API is fully backward-compatible.
  - Consumers may opt in to typed streaming via ``version="v2"`` on
    ``invoke()`` / ``stream()`` calls (see LangGraph 1.1 migration guide).
  - Typed interrupts are supported for the interrupt_before pattern.
"""

import os

from langgraph.graph import END, StateGraph

from src.gateway.governance.ftra.node_factory import create_ftra_node, route_after_ftra

from .annotations import SIDE_EFFECT_REGISTRY
from .checkpointer import get_checkpointer
from .nodes.agent_nodes import (
    data_analyst_node,
    execution_analyst_node,
    governed_trader_node,
)
from .nodes.defer_node import defer_node
from .nodes.evaluator_node import evaluator_node
from .nodes.explainer_node import explainer_node
from .nodes.guardrail_node import nemo_guardrail_node, nemo_output_rail_node
from .nodes.safety_node import safety_check_node
from .nodes.supervisor_node import doer_node, thinker_node
from .state import AgentState


def get_side_effect_topology() -> dict[str, dict]:
    """Return the complete side-effect topology of the governed financial advisor graph.

    This is the canonical proof artifact for compliance review.  It maps every
    annotated node name to its external mutation profile, allowing auditors to
    inspect the complete I/O surface without running the system.

    All nodes that perform external I/O are annotated with
    ``@side_effect_node`` from
    :mod:`src.governed_financial_advisor.graph.annotations`.  This function
    returns a serialisation-safe snapshot of ``SIDE_EFFECT_REGISTRY`` with the
    ``fn`` key removed so the result can be passed directly to ``json.dumps``.

    Returns:
        dict mapping node qualified name → ``{"kind": str, "external_system": str}``

    Example::

        topology = get_side_effect_topology()
        # {
        #   "execute_trade": {"kind": "api_call", "external_system": "gateway_mcp"},
        #   "tool_executor_node": {"kind": "api_call", "external_system": "gateway_mcp"},
        #   ...
        # }
    """
    return {
        name: {"kind": entry["kind"], "external_system": entry["external_system"]}
        for name, entry in SIDE_EFFECT_REGISTRY.items()
    }


def create_graph(redis_url=None):  # type: ignore[no-untyped-def]
    workflow = StateGraph(AgentState)

    # 1. Add Nodes
    workflow.add_node(
        "nemo_guardrail", nemo_guardrail_node
    )  # ADR 2026-03-09: mandatory first node
    workflow.add_node("thinker_node", thinker_node)
    workflow.add_node("doer_node", doer_node)
    workflow.add_node("data_analyst", data_analyst_node)
    workflow.add_node("execution_analyst", execution_analyst_node)
    workflow.add_node("evaluator", evaluator_node)
    # CTRL_FTRA_001: Tier 0.5 commencement-time reachability gate.
    # Inserted between evaluator and safety_check.  Verdicts:
    #   CLEAR         → safety_check
    #   HITL_REQUIRED → DeferQueue park + NodeInterrupt (→ explainer fallback)
    #   BLOCKED       → explainer
    workflow.add_node("ftra_node", create_ftra_node())  # type: ignore[arg-type]
    workflow.add_node("safety_check", safety_check_node)  # type: ignore[arg-type]  # R-11: OPA pre-trade gate
    # CAGE-REM-004: DeferQueue 4-state confidence router node
    workflow.add_node("defer_node", defer_node)
    workflow.add_node("governed_trader", governed_trader_node)
    workflow.add_node("explainer", explainer_node)
    # ADR 2026-03-09b: mandatory output rail — final node on every non-blocked path
    workflow.add_node("nemo_output_rail", nemo_output_rail_node)

    # 2. Sequential Logic (Centralized)
    # ADR 2026-03-09: NeMo guardrail is the mandatory entry point.
    # START → nemo_guardrail → thinker_node (safe) | END (blocked)
    workflow.set_entry_point("nemo_guardrail")

    def route_after_guardrail(state: AgentState):  # type: ignore[no-untyped-def]
        """
        Route from the NeMo guardrail gate.

        If the input was blocked, terminate immediately via END so no agent
        ever processes the unsafe content.  The blocked path skips
        nemo_output_rail because there is no agent-generated output to screen.
        Otherwise proceed to thinker_node as normal.  This routing function is
        the sole mechanism by which the guardrail result is enforced — the LLM
        cannot influence it.
        """
        if state.get("guardrail_blocked"):
            return END
        return "thinker_node"

    workflow.add_conditional_edges("nemo_guardrail", route_after_guardrail)
    workflow.add_edge("thinker_node", "doer_node")

    # Supervisor Routing — reads the explicit `next_step` field set by doer_node.
    # This avoids fragile keyword scanning of message content (ARCH-03).
    # BUG-FIX: "FINISH" is a valid Literal in AgentState but is NOT a node name.
    # Returning the string "FINISH" causes LangGraph to fail with an empty-message
    # ValueError (→ HTTP 500 {"detail":""}). Map it to the END sentinel explicitly.
    def route_supervisor(state: AgentState):  # type: ignore[no-untyped-def]
        next_step = state.get("next_step", END)
        if next_step == "FINISH" or next_step is None:
            # Route through the output rail before terminating
            return "nemo_output_rail"
        return next_step

    workflow.add_conditional_edges("doer_node", route_supervisor)

    # Lifecycle: Planner -> Evaluator -> [FTRA Tier 0.5] -> [Safety Gate] -> Trader | Re-plan
    workflow.add_edge("execution_analyst", "evaluator")

    def check_safety_signature(state: AgentState):  # type: ignore[no-untyped-def]
        """
        STRICT LIFECYCLE GATE: Verifies that the Evaluator has provided a signature.

        BUG-FIX: Without a loop cap, execution_analyst → evaluator → execution_analyst
        cycles infinitely when governance_signature is never set. Add a hard cap using
        loop_count (which now increments unconditionally in execution_analyst_node).

        CTRL_FTRA_001: On APPROVED + signature, route to ftra_node (Tier 0.5
        commencement-time reachability gate) rather than directly to safety_check.
        The ftra_node then routes to safety_check (CLEAR), explainer (BLOCKED), or
        parks in DeferQueue (HITL_REQUIRED).
        """
        sig = state.get("governance_signature")
        verdict = state.get("evaluation_result", {}).get("verdict")  # type: ignore[union-attr]

        if verdict == "APPROVED" and sig:
            return "ftra_node"  # CTRL_FTRA_001: Tier 0.5 gate before OPA

        # Safety breaker: if we've looped too many times, give up gracefully
        if (state.get("loop_count", 0) or 0) >= 3:
            return "explainer"

        # If rejected or signature missing, loop back to Planner with feedback
        return "execution_analyst"

    workflow.add_conditional_edges("evaluator", check_safety_signature)

    # CTRL_FTRA_001: FTRA verdict routing
    #   CLEAR         → safety_check (OPA pre-trade gate)
    #   HITL_REQUIRED → explainer (NodeInterrupt parks thread; this is the fallback)
    #   BLOCKED       → explainer
    workflow.add_conditional_edges("ftra_node", route_after_ftra)

    def route_after_safety(state: AgentState):  # type: ignore[no-untyped-def]
        """
        R-11 / CAGE-REM-004: Routes after the OPA pre-trade safety gate.

        APPROVED / SKIPPED → proceed to governed_trader (trade is safe)
        DEFERRED / ESCALATED / MANUAL_REVIEW → defer_node (park in DeferQueue)
        BLOCKED            → route to explainer (trade denied, explain to user)
        """
        status = state.get("safety_status")
        if status in ("APPROVED", "SKIPPED"):
            return "governed_trader"
        elif status in ("DEFERRED", "ESCALATED", "MANUAL_REVIEW"):
            return "defer_node"
        # BLOCKED or rejected — surface to explainer
        return "explainer"

    workflow.add_conditional_edges("safety_check", route_after_safety)

    # Connect defer_node to explainer to report deferral reason
    workflow.add_edge("defer_node", "explainer")

    # ADR 2026-03-09b: every non-blocked terminal path routes through the
    # mandatory output rail before END.  The blocked guardrail path (above)
    # is the only path that bypasses the output rail — there is no
    # agent-generated output to screen when the input was blocked.
    workflow.add_edge("governed_trader", "explainer")
    workflow.add_edge("data_analyst", "nemo_output_rail")
    workflow.add_edge("explainer", "nemo_output_rail")
    workflow.add_edge("nemo_output_rail", END)

    # ARCH-04: Use the Redis-backed checkpointer configured via get_checkpointer().
    # Falls back gracefully to MemorySaver when redis_url is None (local dev/test).
    checkpointer = get_checkpointer(redis_url)

    # Provider 02 Attestation — opt-in via PROVIDER_02_ATTESTATION_ENABLED=true
    # When enabled, a Provider02AttestationCallback is created and stored on the
    # compiled graph as ``_provider_02_callback`` for retrieval after execution.
    # Zero overhead when disabled — no import, no instantiation.
    provider_02_callback = None
    if os.environ.get("PROVIDER_02_ATTESTATION_ENABLED", "").lower() == "true":
        try:
            from src.integrations.provider_02 import Provider02AttestationCallback

            provider_02_callback = Provider02AttestationCallback()
        except ImportError:
            pass  # provider_02 adapter not available — skip silently

    compiled = workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["governed_trader"],  # Manual Handshake (Module 6)
    )

    # Attach the callback for caller retrieval (does not affect graph execution)
    compiled._provider_02_callback = provider_02_callback  # type: ignore[attr-defined]

    return compiled
