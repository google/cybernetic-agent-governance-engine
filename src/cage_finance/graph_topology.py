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

# Governed Financial Advisor graph topology
# Derived from src/governed_financial_advisor/graph.py conditional edges
FINANCIAL_ADVISOR_TOPOLOGY = GraphTopology(
    nodes=frozenset(
        {
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "data_analyst",
            "execution_analyst",
            "evaluator",
            "safety_check",
            "governed_trader",
            "explainer",
            "nemo_output_rail",
        }
    ),
    parent_edges={
        "nemo_guardrail": [],  # entry point
        "thinker_node": ["nemo_guardrail"],
        "doer_node": ["thinker_node"],
        "data_analyst": ["doer_node"],
        "execution_analyst": ["doer_node", "evaluator"],  # loop source
        "evaluator": ["execution_analyst"],
        "safety_check": ["evaluator"],
        "governed_trader": ["safety_check"],
        "explainer": ["governed_trader", "evaluator", "safety_check"],
        "nemo_output_rail": ["data_analyst", "explainer"],
    },
    terminal_node="governed_trader",
    interrupt_node="governed_trader",
    attestation_nodes=frozenset(
        {
            "nemo_guardrail",
            "evaluator",
            "safety_check",
            "governed_trader",
            "explainer",
            "nemo_output_rail",
        }
    ),
)
"""GraphTopology instance for the Governed Financial Advisor.

Terminal Paths:
    1. NeMo block: nemo_guardrail → END (guardrail_blocked=True)
    2. CBF fail-closed: evaluator → safety_check(BLOCKED) → explainer → END
    3. Loop breaker: evaluator → explainer (loop_count ≥ 3) → END
    4. Happy path: nemo_guardrail → thinker → doer → execution_analyst →
       evaluator → safety_check → [HITL interrupt] → governed_trader →
       explainer → END
"""
