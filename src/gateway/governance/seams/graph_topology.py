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
Graph Topology Seam — Domain-Agnostic Control Graph Structure.

This module defines the shape of a control graph without any domain vocabulary.
It is consumed by external attestation adapters (Provider 02) that need to
understand graph structure for path classification and parent-edge resolution,
but must not hardcode domain-specific node names.

Architectural Invariant:
    This module must NEVER contain domain vocabulary (e.g., "governed_trader",
    "safety_check"). It defines the *shape* of a graph, not any particular graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GraphTopology:
    """Domain-agnostic control graph topology.

    Describes the structure of a LangGraph control flow without naming
    specific nodes or actions. External attestation adapters use this to:

    1. Resolve parent-edge relationships for DAG construction
    2. Classify terminal paths based on structural patterns
    3. Identify governance-significant nodes (attestation boundaries)
    4. Locate interrupt nodes for HITL attestation

    Fields:
        nodes: Frozenset of all node names in the graph
        parent_edges: Maps each node to its possible parent nodes
        terminal_node: The canonical success terminal (e.g., final action executor)
        interrupt_node: The node where HITL interrupts occur (if any)
        attestation_nodes: Nodes that trigger attestation CER emission
    """

    nodes: frozenset[str]
    parent_edges: dict[str, list[str]]
    terminal_node: str
    interrupt_node: str | None = None
    attestation_nodes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate topology invariants."""
        # Terminal node must exist in the graph
        if self.terminal_node not in self.nodes:
            raise ValueError(f"terminal_node '{self.terminal_node}' not in graph nodes")

        # Interrupt node (if specified) must exist
        if self.interrupt_node is not None and self.interrupt_node not in self.nodes:
            raise ValueError(
                f"interrupt_node '{self.interrupt_node}' not in graph nodes"
            )

        # All attestation nodes must exist
        invalid_attestation_nodes = self.attestation_nodes - self.nodes
        if invalid_attestation_nodes:
            raise ValueError(
                f"attestation_nodes {invalid_attestation_nodes} not in graph nodes"
            )

        # All parent edge keys must exist in nodes
        invalid_parent_keys = set(self.parent_edges.keys()) - self.nodes
        if invalid_parent_keys:
            raise ValueError(
                f"parent_edges keys {invalid_parent_keys} not in graph nodes"
            )

        # All parent edge values must exist in nodes
        for node, parents in self.parent_edges.items():
            invalid_parents = set(parents) - self.nodes
            if invalid_parents:
                raise ValueError(
                    f"parent_edges['{node}'] references non-existent nodes: {invalid_parents}"
                )
