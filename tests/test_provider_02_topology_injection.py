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
Test Suite: Provider 02 Graph Topology Injection (C4).

Validates that the Provider 02 attestation adapter no longer hardcodes
Layer 4 finance vocabulary, and correctly accepts topology as a required
constructor argument.

Tests:
    1. Missing topology raises TypeError at construction
    2. Unknown nodes in traversal raise ValueError
    3. Finance topology reproduces all four terminal paths
    4. Non-finance topology classifies correctly
"""

import pytest

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.gateway.governance.seams.graph_topology import GraphTopology
from src.integrations.provider_02.adapter import (
    ProjectBundleStepEntry,
    Provider02AttestationCallback,
    _classify_terminal_path,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]


class TestTopologyInjection:
    """Test topology is required and used correctly."""

    def test_missing_topology_raises_typeerror(self) -> None:
        """Missing topology parameter raises TypeError."""
        with pytest.raises(TypeError, match="topology"):
            Provider02AttestationCallback()  # type: ignore[call-arg]

    def test_callback_accepts_topology(self) -> None:
        """Callback accepts a valid topology and stores it."""
        callback = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="test-123"
        )
        assert callback._topology == FINANCIAL_ADVISOR_TOPOLOGY
        assert callback._thread_id == "test-123"


class TestUnrecognizedNodesFailClosed:
    """Test that unrecognized nodes raise instead of returning happy_path."""

    def test_unknown_node_in_traversal_raises(self) -> None:
        """Traversal containing an unknown node raises ValueError."""
        topology = GraphTopology(
            nodes=frozenset({"start", "middle", "end"}),
            parent_edges={"start": [], "middle": ["start"], "end": ["middle"]},
            terminal_node="end",
            attestation_nodes=frozenset({"start", "end"}),
        )

        steps = [
            ProjectBundleStepEntry(node_name="start"),
            ProjectBundleStepEntry(node_name="unknown_node"),  # Not in topology
        ]

        with pytest.raises(ValueError, match="Unrecognized nodes.*unknown_node"):
            _classify_terminal_path(steps, topology)

    def test_unknown_node_never_returns_happy_path(self) -> None:
        """Unknown node does not silently return happy_path."""
        topology = GraphTopology(
            nodes=frozenset({"node_a", "node_b"}),
            parent_edges={"node_a": [], "node_b": ["node_a"]},
            terminal_node="node_b",
        )

        steps = [
            ProjectBundleStepEntry(node_name="node_a"),
            ProjectBundleStepEntry(node_name="rogue_node"),
        ]

        # Must raise, not return "happy_path" or any other string
        with pytest.raises(ValueError):
            _classify_terminal_path(steps, topology)


class TestFinanceTopologyBehaviorPreserved:
    """Test that finance topology reproduces exact legacy classification."""

    def test_happy_path_classification(self) -> None:
        """Terminal node reached → happy_path."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="thinker_node"),
            ProjectBundleStepEntry(node_name="doer_node"),
            ProjectBundleStepEntry(node_name="execution_analyst"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="safety_check"),
            ProjectBundleStepEntry(node_name="governed_trader"),  # terminal
            ProjectBundleStepEntry(node_name="explainer"),
        ]

        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "happy_path"

    def test_nemo_block_classification(self) -> None:
        """Short traversal with early exit → nemo_block."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
        ]

        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "nemo_block"

    def test_cbf_block_classification(self) -> None:
        """safety_check BLOCKED signal → cbf_block."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="thinker_node"),
            ProjectBundleStepEntry(node_name="doer_node"),
            ProjectBundleStepEntry(node_name="execution_analyst"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(
                node_name="safety_check", signals={"safetyStatus": "BLOCKED"}
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]

        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "cbf_block"

    def test_loop_breaker_classification(self) -> None:
        """Loop count ≥ 3 → loop_breaker."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="thinker_node"),
            ProjectBundleStepEntry(node_name="doer_node"),
            ProjectBundleStepEntry(node_name="execution_analyst"),
            ProjectBundleStepEntry(
                node_name="evaluator", signals={"loopCount": 3}
            ),  # Loop limit
            ProjectBundleStepEntry(node_name="explainer"),
        ]

        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "loop_breaker"


class TestNonFinanceTopology:
    """Test that a non-finance topology classifies correctly."""

    def test_healthcare_style_topology_happy_path(self) -> None:
        """Healthcare-like topology with different node names."""
        healthcare_topology = GraphTopology(
            nodes=frozenset(
                {
                    "intake",
                    "triage",
                    "diagnosis",
                    "treatment_plan",
                    "safety_review",
                    "prescribe",
                    "discharge",
                }
            ),
            parent_edges={
                "intake": [],
                "triage": ["intake"],
                "diagnosis": ["triage"],
                "treatment_plan": ["diagnosis"],
                "safety_review": ["treatment_plan"],
                "prescribe": ["safety_review"],
                "discharge": ["prescribe"],
            },
            terminal_node="prescribe",
            interrupt_node="prescribe",
            attestation_nodes=frozenset(
                {"intake", "safety_review", "prescribe", "discharge"}
            ),
        )

        # Happy path: reaches terminal node
        steps = [
            ProjectBundleStepEntry(node_name="intake"),
            ProjectBundleStepEntry(node_name="triage"),
            ProjectBundleStepEntry(node_name="diagnosis"),
            ProjectBundleStepEntry(node_name="treatment_plan"),
            ProjectBundleStepEntry(node_name="safety_review"),
            ProjectBundleStepEntry(node_name="prescribe"),  # terminal
            ProjectBundleStepEntry(node_name="discharge"),
        ]

        result = _classify_terminal_path(steps, healthcare_topology)
        assert result == "happy_path"

    def test_healthcare_style_topology_early_block(self) -> None:
        """Healthcare topology early exit → nemo_block."""
        healthcare_topology = GraphTopology(
            nodes=frozenset({"intake", "triage", "diagnosis"}),
            parent_edges={"intake": [], "triage": ["intake"], "diagnosis": ["triage"]},
            terminal_node="diagnosis",
        )

        # Early block: only intake node
        steps = [ProjectBundleStepEntry(node_name="intake")]

        result = _classify_terminal_path(steps, healthcare_topology)
        assert result == "nemo_block"

    def test_healthcare_style_topology_safety_block(self) -> None:
        """Healthcare topology safety block → cbf_block."""
        healthcare_topology = GraphTopology(
            nodes=frozenset(
                {"intake", "triage", "safety_review", "prescribe", "discharge"}
            ),
            parent_edges={
                "intake": [],
                "triage": ["intake"],
                "safety_review": ["triage"],
                "prescribe": ["safety_review"],
                "discharge": ["prescribe"],
            },
            terminal_node="prescribe",
        )

        # Safety block
        steps = [
            ProjectBundleStepEntry(node_name="intake"),
            ProjectBundleStepEntry(node_name="triage"),
            ProjectBundleStepEntry(
                node_name="safety_review", signals={"safetyStatus": "BLOCKED"}
            ),
            ProjectBundleStepEntry(node_name="discharge"),
        ]

        result = _classify_terminal_path(steps, healthcare_topology)
        assert result == "cbf_block"


class TestProvider03FieldMapping:
    """Test Provider 03 field mapping injection (same PR scope)."""

    def test_provider_03_accepts_field_map(self) -> None:
        """Provider 03 accepts a field mapping at construction."""
        from src.integrations.provider_03.provider import Provider03NormativeProvider

        provider = Provider03NormativeProvider(
            endpoint="http://localhost:8003",
            action_context_field_map={"amount": "magnitude", "symbol": "context"},
        )

        assert provider._field_map == {"amount": "magnitude", "symbol": "context"}

    def test_provider_03_empty_field_map_by_default(self) -> None:
        """Provider 03 defaults to empty field map (no normalization)."""
        from src.integrations.provider_03.provider import Provider03NormativeProvider

        provider = Provider03NormativeProvider(endpoint="http://localhost:8003")

        assert provider._field_map == {}
