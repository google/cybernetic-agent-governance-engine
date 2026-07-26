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

"""FTRA Tier 0.5 — Commencement Reachability Gate.

Performs NetworkX graph reachability analysis before the first LangGraph node
executes. Verdicts: CLEAR / HITL_REQUIRED / BLOCKED.

FTRA-001: Commencement Reachability
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

try:
    import networkx as nx

    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False
    logger.warning(
        "networkx not installed; FTRA reachability gate will BLOCK all requests"
    )


class FtraVerdict(str, Enum):
    CLEAR = "CLEAR"
    HITL_REQUIRED = "HITL_REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass
class FtraResult:
    verdict: FtraVerdict
    reason: str
    reachable_nodes: list[str]
    blocked_paths: list[str]


class FtraReachabilityGate:
    """FTRA Tier 0.5 commencement reachability gate.

    Builds a directed graph of agent nodes and checks whether the
    requested action is reachable from the entry node without passing
    through blocked/restricted nodes.

    Verdicts:
    - CLEAR: action is reachable, no restricted nodes on path
    - HITL_REQUIRED: action is reachable but passes through HITL checkpoint
    - BLOCKED: action is not reachable or passes through blocked node
    """

    HITL_NODES = frozenset({"hitl_escalator", "human_review", "approval_gate"})
    BLOCKED_NODES = frozenset({"emergency_stop", "circuit_breaker"})

    def __init__(self) -> None:
        self._graph: Any = None  # nx.DiGraph when available

    def build_graph(self, node_config: dict[str, list[str]]) -> None:
        """Build reachability graph from node adjacency config.

        Args:
            node_config: dict mapping node_name -> list of successor node names
        """
        if not _NX_AVAILABLE:
            return
        import networkx as nx

        self._graph = nx.DiGraph()
        for node, successors in node_config.items():
            for successor in successors:
                self._graph.add_edge(node, successor)

    def analyze(self, entry_node: str, target_node: str) -> FtraResult:
        """Analyze reachability from entry_node to target_node.

        Returns FtraResult with verdict and path analysis.
        """
        if not _NX_AVAILABLE or self._graph is None:
            return FtraResult(
                verdict=FtraVerdict.BLOCKED,
                reason="NetworkX not available or graph not initialized",
                reachable_nodes=[],
                blocked_paths=[],
            )

        import networkx as nx

        if not nx.has_path(self._graph, entry_node, target_node):
            return FtraResult(
                verdict=FtraVerdict.BLOCKED,
                reason=f"No path from {entry_node} to {target_node}",
                reachable_nodes=list(nx.descendants(self._graph, entry_node)),
                blocked_paths=[],
            )

        # Find all simple paths
        try:
            all_paths = list(
                nx.all_simple_paths(self._graph, entry_node, target_node, cutoff=20)
            )
        except nx.NetworkXError:
            all_paths = []

        blocked_paths = []
        hitl_paths = []
        clear_paths = []

        for path in all_paths:
            path_nodes = set(path)
            if path_nodes & self.BLOCKED_NODES:
                blocked_paths.append(" -> ".join(path))
            elif path_nodes & self.HITL_NODES:
                hitl_paths.append(" -> ".join(path))
            else:
                clear_paths.append(" -> ".join(path))

        reachable = list(nx.descendants(self._graph, entry_node))

        if clear_paths:
            return FtraResult(
                verdict=FtraVerdict.CLEAR,
                reason=f"Clear path exists: {clear_paths[0]}",
                reachable_nodes=reachable,
                blocked_paths=blocked_paths,
            )
        elif hitl_paths:
            return FtraResult(
                verdict=FtraVerdict.HITL_REQUIRED,
                reason=f"All paths require HITL: {hitl_paths[0]}",
                reachable_nodes=reachable,
                blocked_paths=blocked_paths,
            )
        else:
            return FtraResult(
                verdict=FtraVerdict.BLOCKED,
                reason="All paths pass through blocked nodes",
                reachable_nodes=reachable,
                blocked_paths=blocked_paths,
            )


_ftra_gate: FtraReachabilityGate | None = None


def get_ftra_gate() -> FtraReachabilityGate:
    """Lazy singleton for FTRA reachability gate."""
    global _ftra_gate
    if _ftra_gate is None:
        _ftra_gate = FtraReachabilityGate()
    return _ftra_gate
