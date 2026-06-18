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
Tests for the canonical CAGE graph (src.governed_financial_advisor.graph.graph).

This module replaces the legacy tests that targeted the now-deleted src/graph/
shim package (R-06). All assertions use the canonical node names defined in
create_graph() and verify graph structure only — no full execution is performed.

Legacy node names that no longer exist:
  - ``supervisor``          → replaced by ``thinker_node`` / ``doer_node``
  - ``optimistic_execution`` → replaced by ``safety_check`` (OPA pre-trade gate)

Canonical node names (as of R-06):
  thinker_node, doer_node, data_analyst, execution_analyst,
  evaluator, safety_check, governed_trader, explainer
"""

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

from langgraph.graph.state import CompiledStateGraph

from src.governed_financial_advisor.graph.graph import create_graph


def test_graph_compilation_no_redis():
    """Graph compiles successfully when redis_url=None (MemorySaver fallback)."""
    graph = create_graph(redis_url=None)
    assert isinstance(graph, CompiledStateGraph)


def test_graph_has_canonical_nodes():
    """All expected canonical node names are present in the compiled graph."""
    graph = create_graph(redis_url=None)
    nodes = graph.get_graph().nodes

    expected_nodes = {
        "thinker_node",
        "doer_node",
        "data_analyst",
        "execution_analyst",
        "evaluator",
        "safety_check",
        "governed_trader",
        "explainer",
    }
    for node_name in expected_nodes:
        assert node_name in nodes, f"Expected node '{node_name}' not found in graph"


def test_graph_does_not_have_legacy_nodes():
    """Legacy shim node names (supervisor, optimistic_execution) must not exist."""
    graph = create_graph(redis_url=None)
    nodes = graph.get_graph().nodes

    legacy_nodes = {"supervisor", "optimistic_execution"}
    for node_name in legacy_nodes:
        assert node_name not in nodes, (
            f"Legacy node '{node_name}' should not be in the canonical graph"
        )


def test_graph_entry_point():
    """The mandatory first node is nemo_guardrail (ADR 2026-03-09).

    START → nemo_guardrail is the static entry edge.
    thinker_node is reached at runtime via route_after_guardrail() when the
    input is safe, but LangGraph's static edge serialization (get_graph())
    only exposes the conditional fallback edge — not the runtime branches.
    We therefore verify thinker_node is present as a graph node (not an edge).
    """
    graph = create_graph(redis_url=None)
    raw_graph = graph.get_graph()

    # __start__ must connect directly to nemo_guardrail (mandatory first node)
    start_edges = [
        (src, dst)
        for src, dst, *_ in raw_graph.edges
        if src == "__start__"
    ]
    assert len(start_edges) >= 1, "Graph must have at least one edge from __start__"
    assert any(dst == "nemo_guardrail" for _, dst in start_edges), (
        "nemo_guardrail must be the mandatory first node from __start__ "
        "(ADR 2026-03-09). thinker_node is reached via runtime conditional routing."
    )

    # thinker_node must exist as a graph node — it is the safe-input branch
    # destination of route_after_guardrail(), registered in create_graph().
    nodes = raw_graph.nodes
    assert "thinker_node" in nodes, (
        "thinker_node must be registered as a graph node. "
        "It is the runtime destination when the guardrail passes input."
    )


def test_graph_compilation_with_patched_redis():
    """Graph compiles when a Redis URL is supplied but the saver is mocked."""
    with patch(
        "src.governed_financial_advisor.graph.checkpointer.get_checkpointer"
    ) as mock_cp:
        from langgraph.checkpoint.memory import MemorySaver
        mock_cp.return_value = MemorySaver()
        graph = create_graph(redis_url="redis://localhost:6379")
        assert isinstance(graph, CompiledStateGraph)
