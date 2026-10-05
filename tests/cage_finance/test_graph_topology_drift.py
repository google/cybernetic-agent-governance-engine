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

"""Drift guard: FINANCIAL_ADVISOR_TOPOLOGY must match the real advisor graph.

The Provider 02 adapter fails closed (``LineageError``) on any executed edge that
is not a ``parent_edges`` candidate. A node or edge added to
``src/governed_financial_advisor/graph/graph.py`` without updating
``src/cage_finance/graph_topology.py`` would therefore break attestation at
runtime. These tests catch it at CI time instead.

Edges are read from the uncompiled ``StateGraph`` built by ``_build_workflow()``
(no LLM or network calls happen at build time):

- static edges come from ``workflow.edges``;
- conditional edges come from the string literals each routing function in
  ``workflow.branches`` can return (AST). ``compiled.get_graph()`` is not used
  because LangGraph cannot see targets of routers without a ``path_map``, so it
  drops those edges entirely.

A router that returns a non-literal must have its target source declared in
``_DYNAMIC_ROUTER_TARGETS``, so drift in dynamic routing also fails loudly.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from collections.abc import Callable
from typing import Any

import pytest
from langgraph.graph import END, START

from src.cage_finance.graph_topology import (
    FINANCIAL_ADVISOR_TOPOLOGY,
    HITL_INTERRUPT_STEP,
)
from src.governed_financial_advisor.graph.graph import _build_workflow
from src.governed_financial_advisor.graph.nodes.supervisor_node import (
    _parse_routing_intent,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

#: Topology entries that are not LangGraph nodes.
_SYNTHETIC_STEPS = frozenset({HITL_INTERRUPT_STEP})

#: Router source node -> (function whose literal returns are the dynamic
#: targets, mapping of sentinel values to the node the router sends them to).
#: route_supervisor returns ``state["next_step"]``, which doer_node sets from
#: ``_parse_routing_intent``; ``FINISH`` is mapped to ``nemo_output_rail``.
_DYNAMIC_ROUTER_TARGETS: dict[str, tuple[Callable[..., Any], dict[str, str]]] = {
    "doer_node": (_parse_routing_intent, {"FINISH": "nemo_output_rail"}),
}


def _literal_returns(func: Callable[..., Any]) -> tuple[set[str], bool]:
    """Return (string literals returned by ``func``, whether any return is dynamic)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    literals: set[str] = set()
    dynamic = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            literals.add(value.value)
        elif isinstance(value, ast.Name) and value.id == "END":
            literals.add(END)
        else:
            dynamic = True
    return literals, dynamic


def _router_targets(source: str, router: Callable[..., Any]) -> set[str]:
    targets, dynamic = _literal_returns(router)
    if dynamic:
        if source not in _DYNAMIC_ROUTER_TARGETS:
            pytest.fail(
                f"Router for {source!r} ({router.__name__}) returns a non-literal; "
                "declare its target source in _DYNAMIC_ROUTER_TARGETS."
            )
        func, sentinels = _DYNAMIC_ROUTER_TARGETS[source]
        extra, extra_dynamic = _literal_returns(func)
        assert not extra_dynamic, f"{func.__name__} must return literals only"
        targets |= {sentinels.get(t, t) for t in extra}
    return targets


def _real_edges() -> set[tuple[str, str]]:
    workflow = _build_workflow()
    edges = {(s, t) for s, t in workflow.edges}
    for source, branches in workflow.branches.items():
        for branch in branches.values():
            if branch.ends:
                edges |= {(source, t) for t in branch.ends.values()}
            else:
                router = getattr(branch.path, "func", None)
                assert callable(router), f"cannot introspect router for {source!r}"
                edges |= {(source, t) for t in _router_targets(source, router)}
    return {(s, t) for s, t in edges if s != START and t != END}


def _real_nodes() -> set[str]:
    return set(_build_workflow().nodes)


def test_every_graph_node_is_declared_in_topology() -> None:
    missing = _real_nodes() - FINANCIAL_ADVISOR_TOPOLOGY.nodes
    assert not missing, f"graph.py nodes missing from the topology: {sorted(missing)}"


def test_topology_declares_no_phantom_nodes() -> None:
    phantom = FINANCIAL_ADVISOR_TOPOLOGY.nodes - _real_nodes() - _SYNTHETIC_STEPS
    assert not phantom, f"topology nodes absent from graph.py: {sorted(phantom)}"


def test_every_real_edge_is_a_parent_edges_candidate() -> None:
    illegal = sorted(
        (s, t)
        for s, t in _real_edges()
        if s not in FINANCIAL_ADVISOR_TOPOLOGY.parent_edges.get(t, [])
    )
    assert not illegal, (
        f"graph.py edges not declared in parent_edges (the adapter would raise "
        f"LineageError): {illegal}"
    )


def test_parent_edges_declare_no_phantom_edges() -> None:
    """Every non-synthetic candidate must be a real edge; stale ones weaken validation."""
    real = _real_edges()
    phantom = sorted(
        (parent, child)
        for child, parents in FINANCIAL_ADVISOR_TOPOLOGY.parent_edges.items()
        for parent in parents
        if child not in _SYNTHETIC_STEPS
        and parent not in _SYNTHETIC_STEPS
        and (parent, child) not in real
    )
    assert not phantom, f"parent_edges candidates not present in graph.py: {phantom}"


def test_hitl_mapping_contracts_to_partner_chain() -> None:
    """approval_node and hitl_interrupt hang off safety_check; trader follows the step."""
    edges = FINANCIAL_ADVISOR_TOPOLOGY.parent_edges
    assert edges["approval_node"] == ["safety_check"]
    assert set(edges[HITL_INTERRUPT_STEP]) == {"safety_check", "approval_node"}
    assert HITL_INTERRUPT_STEP in edges["governed_trader"]
    assert "approval_node" not in FINANCIAL_ADVISOR_TOPOLOGY.attestation_nodes


def test_drift_check_detects_missing_edge() -> None:
    """The edge reader must actually see conditional routes (not just static edges)."""
    real = _real_edges()
    for edge in [
        ("evaluator", "ftra_node"),
        ("ftra_node", "safety_check"),
        ("safety_check", "approval_node"),
        ("safety_check", "defer_node"),
        ("doer_node", "nemo_output_rail"),
        ("defer_node", "explainer"),
    ]:
        assert edge in real, f"edge reader missed {edge}"
