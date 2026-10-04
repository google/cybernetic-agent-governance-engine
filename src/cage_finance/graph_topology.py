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
Finance Domain Graph Topology — Governed Financial Advisor Structure.

This module defines the concrete graph topology for the Governed Financial Advisor
application. It lives in the cage_finance domain plugin because it names domain-specific
nodes and actions.

External attestation adapters (Provider 02) consume this topology via the
domain-agnostic GraphTopology seam, allowing them to resolve parent edges and
classify terminal paths without hardcoding finance vocabulary.
"""

from __future__ import annotations

from src.gateway.governance.seams.graph_topology import GraphTopology

#: Synthetic attestation step recorded by
#: ``Provider02AttestationCallback.handle_hitl_interrupt()``. It is not a LangGraph
#: node; it is the partner-agreed record of the HITL pause.
HITL_INTERRUPT_STEP = "hitl_interrupt"

# Governed Financial Advisor graph topology.
# Mirrors the nodes, edges and routing functions in
# src/governed_financial_advisor/graph/graph.py::_build_workflow(). Every real
# edge is a parent_edges candidate, and test_graph_topology_drift.py fails on
# drift in either direction.
FINANCIAL_ADVISOR_TOPOLOGY = GraphTopology(
    nodes=frozenset(
        {
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "data_analyst",
            "execution_analyst",
            "evaluator",
            "ftra_node",
            "safety_check",
            "defer_node",
            "approval_node",
            HITL_INTERRUPT_STEP,
            "governed_trader",
            "explainer",
            "nemo_output_rail",
        }
    ),
    parent_edges={
        "nemo_guardrail": [],  # entry point
        "thinker_node": ["nemo_guardrail"],
        "doer_node": ["thinker_node"],
        "data_analyst": ["doer_node"],  # route_supervisor
        "execution_analyst": ["doer_node", "evaluator"],  # loop source
        "evaluator": ["execution_analyst"],
        "ftra_node": ["evaluator"],  # route_after_evaluator (APPROVED)
        "safety_check": ["ftra_node"],  # route_after_ftra (CLEAR)
        "defer_node": ["safety_check"],  # route_after_safety (DEFERRED/...)
        "approval_node": ["safety_check"],  # route_after_safety (risk/amount)
        # Synthetic HITL step: recorded after approval_node resumes with the
        # reviewer's decision. safety_check stays a candidate for callers that
        # do not emit an approval_node event; both contract to safety_check.
        HITL_INTERRUPT_STEP: ["safety_check", "approval_node"],
        "governed_trader": ["safety_check", HITL_INTERRUPT_STEP],
        "explainer": [
            "governed_trader",
            "evaluator",  # loop cap
            "ftra_node",  # FTRA BLOCKED / HITL_REQUIRED fallback
            "safety_check",  # BLOCKED
            "defer_node",
        ],
        "nemo_output_rail": [
            "data_analyst",
            "explainer",
            "doer_node",  # route_supervisor FINISH
        ],
    },
    terminal_node="governed_trader",
    interrupt_node="governed_trader",
    attestation_nodes=frozenset(
        {
            "nemo_guardrail",
            "evaluator",
            "safety_check",
            HITL_INTERRUPT_STEP,
            "governed_trader",
            "explainer",
            "nemo_output_rail",
        }
    ),
)
"""GraphTopology instance for the Governed Financial Advisor.

Unrecorded nodes. ``thinker_node``, ``doer_node``, ``data_analyst``,
``execution_analyst``, ``ftra_node``, ``defer_node`` and ``approval_node`` are
not attestation nodes. Lineage contracts through them over executed edges, so the
recorded chain is the same as before they were declared:

- ``ftra_node`` (CTRL_FTRA_001) is a Layer 1 kernel gate whose verdict is
  evidenced by the gateway. Recording it here would duplicate that evidence and
  change the partner-agreed recorded chain.
- ``defer_node`` parks the request in the gateway DeferQueue, which records the
  deferral as primary evidence.
- ``approval_node`` is represented by the synthetic ``hitl_interrupt`` step.

HITL mapping. ``approval_node`` calls ``interrupt()``. After the reviewer
resumes it, the caller records ``hitl_interrupt`` with the approval decision.
The executed sequence is::

    safety_check -> approval_node -> [hitl_interrupt] -> governed_trader

It contracts to the partner-agreed recorded chain
``safety_check -> hitl_interrupt -> governed_trader``.

Terminal paths:
    1. NeMo block: nemo_guardrail → END (guardrail_blocked=True)
    2. FTRA block: evaluator → ftra_node(BLOCKED) → explainer → nemo_output_rail
    3. CBF fail-closed: evaluator → ftra_node → safety_check(BLOCKED) →
       explainer → nemo_output_rail
    4. Deferral: safety_check(DEFERRED) → defer_node → explainer → nemo_output_rail
    5. Loop breaker: evaluator → explainer (loop_count ≥ 3) → nemo_output_rail
    6. Happy path: nemo_guardrail → thinker → doer → execution_analyst →
       evaluator → ftra_node → safety_check → governed_trader → explainer →
       nemo_output_rail
    7. HITL approval: … → safety_check → approval_node → [hitl_interrupt] →
       governed_trader → explainer → nemo_output_rail
    8. Direct answer: doer_node → data_analyst | (FINISH) → nemo_output_rail
"""
