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
tests/test_provider_02_adapter.py
=================================
Hermetic unit tests for src/integrations/provider_02/adapter.py and
src/integrations/provider_02/provider.py.

Gap 6: Both provider_02 adapter and provider are functionally untested.
These tests exercise public APIs, data contracts, and logic branches
without making live HTTP calls (all network I/O is mocked).

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

# Base paths for fixtures
REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "provider_02_native"

# ---------------------------------------------------------------------------
# Tests: adapter.py — data contracts and helper functions
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestProjectBundleStepEntry:
    """Tests for the ProjectBundleStepEntry dataclass."""

    def test_step_entry_auto_generates_step_id(self) -> None:
        """ProjectBundleStepEntry must auto-generate a UUID step_id."""
        from src.integrations.provider_02.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(node_name="evaluator")
        assert entry.step_id, "step_id must be non-empty"
        # Must be a valid UUID
        parsed = uuid.UUID(entry.step_id)
        assert str(parsed) == entry.step_id, "step_id must be a valid UUID string"

    def test_step_entry_to_dict_contains_all_keys(self) -> None:
        """ProjectBundleStepEntry.to_dict() must contain all Provider 02 API keys."""
        from src.integrations.provider_02.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(
            node_name="safety_check",
            parent_step_ids=["parent-id-1"],
            timestamp_utc="2026-01-01T00:00:00+00:00",
            duration_ms=42.5,
            signals={"safetyStatus": "APPROVED"},
            state_hash="a" * 64,
        )
        d = entry.to_dict()

        assert "stepId" in d, "to_dict() must contain 'stepId'"
        assert "nodeName" in d, "to_dict() must contain 'nodeName'"
        assert "parentStepIds" in d, "to_dict() must contain 'parentStepIds'"
        assert "timestampUtc" in d, "to_dict() must contain 'timestampUtc'"
        assert "durationMs" in d, "to_dict() must contain 'durationMs'"
        assert "signals" in d, "to_dict() must contain 'signals'"
        assert "stateHash" in d, "to_dict() must contain 'stateHash'"

    def test_step_entry_to_dict_values_match(self) -> None:
        """ProjectBundleStepEntry.to_dict() values must match field values."""
        from src.integrations.provider_02.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(
            node_name="governed_trader",
            parent_step_ids=["pid-a", "pid-b"],
            duration_ms=99.9,
        )
        d = entry.to_dict()

        assert d["nodeName"] == "governed_trader"
        assert d["parentStepIds"] == ["pid-a", "pid-b"]
        assert d["durationMs"] == 99.9

    def test_step_entry_default_parent_step_ids_is_empty_list(self) -> None:
        """ProjectBundleStepEntry.parent_step_ids defaults to empty list."""
        from src.integrations.provider_02.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(node_name="nemo_guardrail")
        assert entry.parent_step_ids == [], "parent_step_ids must default to empty list"


@pytest.mark.local
class TestAttestationBundle:
    """Tests for the AttestationBundle dataclass."""

    def test_bundle_auto_generates_bundle_id(self) -> None:
        """AttestationBundle must auto-generate a UUID bundle_id."""
        from src.integrations.provider_02.adapter import AttestationBundle

        bundle = AttestationBundle(thread_id="thread-001")
        assert bundle.bundle_id, "bundle_id must be non-empty"
        parsed = uuid.UUID(bundle.bundle_id)
        assert str(parsed) == bundle.bundle_id, "bundle_id must be a valid UUID"

    def test_bundle_to_dict_structure(self) -> None:
        """AttestationBundle.to_dict() must contain all required Provider 02 API keys."""
        from src.integrations.provider_02.adapter import (
            AttestationBundle,
            ProjectBundleStepEntry,
        )

        step = ProjectBundleStepEntry(node_name="evaluator")
        bundle = AttestationBundle(
            thread_id="thread-123",
            steps=[step],
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:01:00+00:00",
            terminal_path="happy_path",
        )
        d = bundle.to_dict()

        assert "bundleId" in d
        assert "threadId" in d
        assert "steps" in d
        assert "startedAt" in d
        assert "completedAt" in d
        assert "terminalPath" in d

    def test_bundle_to_dict_serializes_steps(self) -> None:
        """AttestationBundle.to_dict() must serialize nested steps."""
        from src.integrations.provider_02.adapter import (
            AttestationBundle,
            ProjectBundleStepEntry,
        )

        step1 = ProjectBundleStepEntry(node_name="nemo_guardrail")
        step2 = ProjectBundleStepEntry(node_name="evaluator")
        bundle = AttestationBundle(thread_id="t", steps=[step1, step2])
        d = bundle.to_dict()

        assert isinstance(d["steps"], list), "steps must be a list"
        assert len(d["steps"]) == 2, "steps list must contain 2 entries"
        assert d["steps"][0]["nodeName"] == "nemo_guardrail"
        assert d["steps"][1]["nodeName"] == "evaluator"


@pytest.mark.local
class TestHelperFunctions:
    """Tests for adapter module helper functions."""

    def test_serialize_state_snapshot_deep_copies_state(self) -> None:
        """_serialize_state_snapshot must return an independent deep copy."""
        from src.integrations.provider_02.adapter import _serialize_state_snapshot

        original = {"risk_status": "APPROVED", "loop_count": 1}
        snapshot = _serialize_state_snapshot(original)

        # Modifying the copy must not affect the original
        snapshot["risk_status"] = "MODIFIED"
        assert original["risk_status"] == "APPROVED", (
            "_serialize_state_snapshot must deep-copy; original was mutated"
        )

    def test_serialize_state_snapshot_drops_completed_transactions(self) -> None:
        """_serialize_state_snapshot must drop completed_transactions."""
        from src.integrations.provider_02.adapter import _serialize_state_snapshot

        state = {
            "risk_status": "APPROVED",
            "completed_transactions": [{"seq": 0, "status": "COMPLETED"}],
        }
        snapshot = _serialize_state_snapshot(state)
        assert "completed_transactions" not in snapshot, (
            "completed_transactions must be removed from the snapshot"
        )

    def test_hash_state_is_deterministic(self) -> None:
        """_hash_state must produce the same hash for identical state."""
        from src.integrations.provider_02.adapter import _hash_state

        state = {"risk_status": "APPROVED", "loop_count": 1}
        hash1 = _hash_state(state)
        hash2 = _hash_state(state)
        assert hash1 == hash2, "_hash_state must be deterministic"
        assert len(hash1) == 64, "SHA-256 hex digest must be 64 chars"

    def test_hash_state_differs_for_different_states(self) -> None:
        """_hash_state must produce different hashes for different states."""
        from src.integrations.provider_02.adapter import _hash_state

        state_a = {"risk_status": "APPROVED"}
        state_b = {"risk_status": "REJECTED"}
        assert _hash_state(state_a) != _hash_state(state_b), (
            "Different states must produce different hashes"
        )

    def test_extract_signals_guardrail_blocked(self) -> None:
        """_extract_signals must capture guardrail_blocked and guardrail_reason."""
        from src.integrations.provider_02.adapter import _extract_signals

        state = {
            "guardrail_blocked": True,
            "guardrail_reason": "Prompt injection detected",
        }
        signals = _extract_signals("nemo_guardrail", state)
        assert signals.get("guardrailBlocked") is True
        assert signals.get("guardrailReason") == "Prompt injection detected"

    def test_extract_signals_evaluation_result(self) -> None:
        """_extract_signals must extract evaluation verdict and policy check."""
        from src.integrations.provider_02.adapter import _extract_signals

        state = {
            "evaluation_result": {
                "verdict": "APPROVED",
                "reasoning": "All checks passed",
                "policy_check": "PASSED",
            }
        }
        signals = _extract_signals("evaluator", state)
        assert signals.get("evaluationVerdict") == "APPROVED"
        assert signals.get("policyCheck") == "PASSED"

    def test_classify_terminal_path_happy_path(self) -> None:
        """_classify_terminal_path must return 'happy_path' when governed_trader present."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="governed_trader"),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "happy_path", (
            f"Expected 'happy_path' when governed_trader present, got {result!r}"
        )

    def test_classify_terminal_path_cbf_block(self) -> None:
        """_classify_terminal_path must return 'cbf_block' on BLOCKED safety_check."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(
                node_name="safety_check",
                signals={"safetyStatus": "BLOCKED"},
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "cbf_block", (
            f"Expected 'cbf_block' for BLOCKED safety_check, got {result!r}"
        )

    def test_classify_terminal_path_loop_breaker(self) -> None:
        """_classify_terminal_path returns 'loop_breaker' when loopCount >= 3."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(
                node_name="evaluator",
                signals={"loopCount": 3},
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "loop_breaker", (
            f"Expected 'loop_breaker' for loopCount >= 3, got {result!r}"
        )

    @pytest.mark.parametrize(
        "fixture_name,expected_terminal_path",
        [
            ("01_single_path_happy.json", "happy_path"),
            ("02_cbf_block.json", "cbf_block"),
            ("03_loop_breaker.json", "loop_breaker"),
            ("04_nemo_policy_block.json", "nemo_block"),
            ("05_large_dag.json", "happy_path"),
        ],
    )
    def test_classify_terminal_path_from_native_fixtures(
        self, fixture_name: str, expected_terminal_path: str
    ) -> None:
        """Verify _classify_terminal_path correctly classifies all native Provider 02 fixtures.
        
        This test validates the refactored precedence ladder against real fixture data
        to ensure heuristic-free classification aligned with fixture conventions.
        """
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        # Load fixture data
        fixture_path = FIXTURES_DIR / fixture_name
        with open(fixture_path, encoding="utf-8") as f:
            fixture_data = json.load(f)

        # Convert fixture steps to ProjectBundleStepEntry objects
        steps = []
        for step_dict in fixture_data["steps"]:
            step = ProjectBundleStepEntry(
                step_id=step_dict["stepId"],
                node_name=step_dict["nodeName"],
                parent_step_ids=step_dict["parentStepIds"],
                timestamp_utc=step_dict["timestampUtc"],
                duration_ms=step_dict["durationMs"],
                signals=step_dict.get("signals", {}),
                metadata=step_dict.get("metadata", {}),
                state_hash=step_dict["stateHash"],
            )
            steps.append(step)

        # Collect all unique node names from the fixture
        node_names = {s.node_name for s in steps}
        
        # Build a minimal synthetic topology that includes all fixture nodes
        # Use the last step's node as terminal for happy_path fixtures
        terminal_node = (
            fixture_data["steps"][-1]["nodeName"]
            if expected_terminal_path == "happy_path"
            else "__synthetic_terminal__"
        )
        
        topology = GraphTopology(
            nodes=node_names | {terminal_node},
            attestation_nodes=node_names,
            parent_edges={},  # Not needed for classification
            terminal_node=terminal_node,
        )

        # Classify the terminal path
        result = _classify_terminal_path(steps, topology)

        # Assert matches expected classification
        assert result == expected_terminal_path, (
            f"Fixture {fixture_name} classified as {result!r}, expected {expected_terminal_path!r}. "
            f"Nodes: {sorted(node_names)}, Signals: {[s.signals for s in steps]}"
        )


@pytest.mark.local
class TestProvider02AttestationCallback:
    """Tests for Provider02AttestationCallback lifecycle and step recording."""

    def test_callback_initialises_with_thread_id(self) -> None:
        """Provider02AttestationCallback must store the provided thread_id."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="thread-abc"
        )
        assert cb._thread_id == "thread-abc"

    def test_callback_auto_generates_thread_id_when_not_provided(self) -> None:
        """Provider02AttestationCallback must auto-generate a thread_id when not given."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        assert cb._thread_id, "thread_id must be auto-generated"
        parsed = uuid.UUID(cb._thread_id)
        assert str(parsed) == cb._thread_id

    def test_callback_step_count_starts_at_zero(self) -> None:
        """step_count property must return 0 before any node events."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="t"
        )
        assert cb.step_count == 0

    def test_on_chain_end_records_attestation_nodes(self) -> None:
        """on_chain_end must record a step for governance-significant nodes."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="t"
        )
        cb.on_chain_start("evaluator", {})
        cb.on_chain_end("evaluator", {"risk_status": "APPROVED"})

        assert cb.step_count == 1, (
            f"Expected step_count=1 after evaluator, got {cb.step_count}"
        )

    def test_on_chain_end_skips_non_attestation_nodes(self) -> None:
        """on_chain_end must not record a step for non-significant nodes."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="t"
        )
        cb.on_chain_end("thinker_node", {"some": "state"})

        assert cb.step_count == 0, (
            f"Expected step_count=0 for thinker_node, got {cb.step_count}"
        )

    def test_get_bundle_returns_attestation_bundle(self) -> None:
        """get_bundle() must return an AttestationBundle with collected steps."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import (
            AttestationBundle,
            Provider02AttestationCallback,
        )

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="t"
        )
        cb.on_chain_start("evaluator", {})
        cb.on_chain_end("evaluator", {"risk_status": "APPROVED"})

        bundle = cb.get_bundle()
        assert isinstance(bundle, AttestationBundle), (
            "get_bundle() must return an AttestationBundle"
        )
        assert bundle.thread_id == "t"
        assert len(bundle.steps) == 1

    def test_hitl_interrupt_records_interrupt_step(self) -> None:
        """handle_hitl_interrupt() must record a hitl_interrupt step."""
        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        cb = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id="t"
        )
        # Execute several attestation nodes before the interrupt to establish recorded ancestors
        for node in ["nemo_guardrail", "evaluator", "safety_check"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {"risk_status": "APPROVED"})
        
        state = {
            "approval_required": True,
            "approval_decision": {
                "approved": None,
                "reviewer": "human-reviewer",
                "rationale": "Pending review",
                "timestamp": "2026-01-01T00:00:00+00:00",
            },
        }
        cb.handle_hitl_interrupt(state)

        assert cb.step_count == 4, (
            f"Expected step_count=4 (3 nodes + interrupt), got {cb.step_count}"
        )
        interrupt_step = cb._steps[-1]  # Last step should be the interrupt
        assert interrupt_step.node_name == "hitl_interrupt"
        assert interrupt_step.signals.get("interruptType") == "HITL_MANUAL_REVIEW"

    def test_dag_closure_validation(self) -> None:
        """DAG closure: every parent_step_id must exist in bundle.steps."""
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        # Synthetic topology with all nodes as attestation nodes
        topology = GraphTopology(
            nodes={"A", "B", "C", "D"},
            attestation_nodes={"A", "B", "C", "D"},
            parent_edges={
                "A": [],
                "B": ["A"],
                "C": ["B"],
                "D": ["C"],
            },
            terminal_node="D",
        )

        cb = Provider02AttestationCallback(topology=topology, thread_id="dag-test")

        # Execute nodes in order
        for node in ["A", "B", "C", "D"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {})

        bundle = cb.get_bundle()

        # Closure validation: collect all step IDs present in the bundle
        step_ids_in_bundle = {step.step_id for step in bundle.steps}

        # Validate: every parent_step_id must exist in step_ids_in_bundle
        for step in bundle.steps:
            for parent_id in step.parent_step_ids:
                assert parent_id in step_ids_in_bundle, (
                    f"Step {step.node_name!r} (step_id={step.step_id[:8]}) has "
                    f"parent_step_id {parent_id[:8]} which does not exist in bundle.steps. "
                    f"This violates DAG closure invariant."
                )

    def test_ancestor_contraction_skipped_intermediate_nodes(self) -> None:
        """Ancestor contraction: A (attested) -> B (skipped) -> C (skipped) -> D (attested).
        
        D.parent_step_ids must contract to [A.step_id], skipping B and C.
        """
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        # Only A and D are attestation nodes; B and C are skipped
        topology = GraphTopology(
            nodes={"A", "B", "C", "D"},
            attestation_nodes={"A", "D"},  # B and C are NOT attestation nodes
            parent_edges={
                "A": [],
                "B": ["A"],
                "C": ["B"],
                "D": ["C"],
            },
            terminal_node="D",
        )

        cb = Provider02AttestationCallback(topology=topology, thread_id="contraction-test")

        # Execute all nodes (on_chain_end will skip B and C as non-attestation nodes)
        for node in ["A", "B", "C", "D"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {})

        bundle = cb.get_bundle()

        # Bundle should contain only A and D
        assert len(bundle.steps) == 2, f"Expected 2 steps (A, D), got {len(bundle.steps)}"
        
        step_a = next(s for s in bundle.steps if s.node_name == "A")
        step_d = next(s for s in bundle.steps if s.node_name == "D")

        # A has no parents
        assert step_a.parent_step_ids == [], (
            f"Step A should have no parents, got {step_a.parent_step_ids}"
        )

        # D should have A as parent (contracted through B and C)
        assert step_d.parent_step_ids == [step_a.step_id], (
            f"Step D should have parent [A.step_id], got {step_d.parent_step_ids}. "
            f"Expected ancestor contraction to skip unrecorded nodes B and C."
        )

    def test_ancestor_contraction_branched_dag(self) -> None:
        """Branched DAG: A -> B -> D and A -> C -> D, where B and C are skipped.
        
        D.parent_step_ids must contract to [A.step_id] without duplicates.
        """
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        # A and D are attestation nodes; B and C are skipped intermediate nodes
        topology = GraphTopology(
            nodes={"A", "B", "C", "D"},
            attestation_nodes={"A", "D"},
            parent_edges={
                "A": [],
                "B": ["A"],
                "C": ["A"],
                "D": ["B", "C"],  # D has two parents: B and C
            },
            terminal_node="D",
        )

        cb = Provider02AttestationCallback(topology=topology, thread_id="branch-test")

        # Execute all nodes
        for node in ["A", "B", "C", "D"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {})

        bundle = cb.get_bundle()

        # Bundle should contain only A and D
        assert len(bundle.steps) == 2, f"Expected 2 steps (A, D), got {len(bundle.steps)}"
        
        step_a = next(s for s in bundle.steps if s.node_name == "A")
        step_d = next(s for s in bundle.steps if s.node_name == "D")

        # D should contract both branches (B and C) to A, deduplicated
        assert step_d.parent_step_ids == [step_a.step_id], (
            f"Step D should have parent [A.step_id] (deduplicated), got {step_d.parent_step_ids}. "
            f"Expected ancestor contraction to merge both branches through B and C to A."
        )

    def test_ancestor_contraction_partial_skipped_path(self) -> None:
        """Mixed attestation: A (attested) -> B (skipped) -> C (attested) -> D (attested).
        
        C.parent_step_ids should contract to [A.step_id], and D.parent_step_ids should be [C.step_id].
        """
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        topology = GraphTopology(
            nodes={"A", "B", "C", "D"},
            attestation_nodes={"A", "C", "D"},  # B is skipped
            parent_edges={
                "A": [],
                "B": ["A"],
                "C": ["B"],
                "D": ["C"],
            },
            terminal_node="D",
        )

        cb = Provider02AttestationCallback(topology=topology, thread_id="partial-test")

        for node in ["A", "B", "C", "D"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {})

        bundle = cb.get_bundle()

        # Bundle should contain A, C, D (B is skipped)
        assert len(bundle.steps) == 3, f"Expected 3 steps (A, C, D), got {len(bundle.steps)}"
        
        step_a = next(s for s in bundle.steps if s.node_name == "A")
        step_c = next(s for s in bundle.steps if s.node_name == "C")
        step_d = next(s for s in bundle.steps if s.node_name == "D")

        # C should contract through B to A
        assert step_c.parent_step_ids == [step_a.step_id], (
            f"Step C should have parent [A.step_id], got {step_c.parent_step_ids}"
        )

        # D should have C as direct parent (C is an attestation node)
        assert step_d.parent_step_ids == [step_c.step_id], (
            f"Step D should have parent [C.step_id], got {step_d.parent_step_ids}"
        )

    def test_cycle_detection_in_parent_resolution(self) -> None:
        """Cycle detection: graph with a cycle should raise ValueError during parent resolution."""
        from src.gateway.governance.seams.graph_topology import GraphTopology
        from src.integrations.provider_02.adapter import Provider02AttestationCallback

        # Create a cyclic topology where the cycle doesn't include the target node:
        # A (attested) -> B -> D -> B (cycle among unrecorded nodes B and D)
        #              -> C (attested, depends on B which leads to cycle)
        topology = GraphTopology(
            nodes={"A", "B", "D", "C"},
            attestation_nodes={"A", "C"},  # B and D are unrecorded intermediate nodes
            parent_edges={
                "A": [],
                "B": ["A", "D"],  # B depends on A and D, creating cycle with D
                "D": ["B"],       # D depends on B, completing the cycle B <-> D
                "C": ["B"],       # C depends on B, which is part of the cycle
            },
            terminal_node="C",
        )

        cb = Provider02AttestationCallback(topology=topology, thread_id="cycle-test")

        # Execute A (no issue)
        cb.on_chain_start("A", {})
        cb.on_chain_end("A", {})

        # Execute B and D (both skipped as non-attestation nodes)
        for node in ["B", "D"]:
            cb.on_chain_start(node, {})
            cb.on_chain_end(node, {})

        # Execute C - this should trigger cycle detection when resolving parents through B <-> D
        cb.on_chain_start("C", {})
        
        with pytest.raises(ValueError, match=r"Cycle detected in graph topology"):
            cb.on_chain_end("C", {})


# ---------------------------------------------------------------------------
# Tests: provider.py — CERReceipt, CERVerification, JWKCache, Provider02AttestationProvider
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestProviderDataContracts:
    """Tests for provider.py data contract dataclasses."""

    def test_cer_receipt_is_valid_when_hash_present(self) -> None:
        """CERReceipt.is_valid must be True when certificate_hash is set and no error."""
        from src.integrations.provider_02.provider import CERReceipt

        receipt = CERReceipt(
            certificate_hash="a" * 64,
            receipt_url="https://provider02.example.com/cer/abc",
            signer_key_id="kid-1",
            signed_at="2026-01-01T00:00:00+00:00",
        )
        assert receipt.is_valid is True, (
            "CERReceipt must be valid when hash and no error"
        )

    def test_cer_receipt_is_invalid_when_error_set(self) -> None:
        """CERReceipt.is_valid must be False when error is set."""
        from src.integrations.provider_02.provider import CERReceipt

        receipt = CERReceipt(error="HTTP 503 Service Unavailable")
        assert receipt.is_valid is False, "CERReceipt must be invalid when error is set"

    def test_cer_receipt_is_invalid_when_hash_empty(self) -> None:
        """CERReceipt.is_valid must be False when certificate_hash is empty."""
        from src.integrations.provider_02.provider import CERReceipt

        receipt = CERReceipt(certificate_hash="")
        assert receipt.is_valid is False, (
            "CERReceipt must be invalid when hash is empty"
        )

    def test_jwk_cache_is_stale_when_never_synced(self) -> None:
        """JWKCache.is_stale must be True when last_synced=0."""
        from src.integrations.provider_02.provider import JWKCache

        cache = JWKCache()
        assert cache.is_stale is True, "Fresh JWKCache must be stale (last_synced=0)"

    def test_jwk_cache_has_keys_false_when_empty(self) -> None:
        """JWKCache.has_keys must be False when no keys loaded."""
        from src.integrations.provider_02.provider import JWKCache

        cache = JWKCache()
        assert cache.has_keys is False, "JWKCache.has_keys must be False when empty"

    def test_jwk_cache_has_keys_true_when_populated(self) -> None:
        """JWKCache.has_keys must be True when keys list is non-empty."""
        from src.integrations.provider_02.provider import JWKCache

        cache = JWKCache(
            jwk_set={"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "key-1"}]},
            last_synced=time.time(),
        )
        assert cache.has_keys is True, "JWKCache.has_keys must be True with loaded keys"


@pytest.mark.local
class TestProvider02AttestationProvider:
    """Tests for Provider02AttestationProvider (hermetic — all HTTP mocked)."""

    def test_provider_initialises_without_endpoint(self) -> None:
        """Provider02AttestationProvider must initialise without crashing even if endpoint is unset."""
        from src.integrations.provider_02.provider import Provider02AttestationProvider

        # No env vars set — should not raise
        provider = Provider02AttestationProvider(endpoint="", api_key="")
        assert provider is not None

    def test_provider_has_no_jwk_keys_initially(self) -> None:
        """Provider must report has_jwk_keys=False before any sync."""
        from src.integrations.provider_02.provider import Provider02AttestationProvider

        provider = Provider02AttestationProvider(
            endpoint="https://provider02.example.com"
        )
        assert provider.has_jwk_keys is False

    def test_provider_jwk_cache_age_is_inf_before_sync(self) -> None:
        """jwk_cache_age_seconds must be inf before any sync."""
        from src.integrations.provider_02.provider import Provider02AttestationProvider

        provider = Provider02AttestationProvider()
        assert provider.jwk_cache_age_seconds == float("inf"), (
            "jwk_cache_age_seconds must be inf before sync"
        )

    @pytest.mark.asyncio
    async def test_certify_decision_returns_error_receipt_on_http_failure(self) -> None:
        """certify_decision() must return a CERReceipt with error on HTTP failure."""
        from src.integrations.provider_02.provider import Provider02AttestationProvider

        provider = Provider02AttestationProvider(
            endpoint="https://provider02.example.com"
        )

        # Patch httpx to raise a connection error
        import httpx

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_cls.return_value = mock_client

            receipt = await provider.certify_decision({"signals": {}})

        assert receipt.is_valid is False, "Receipt must be invalid on HTTP failure"
        assert receipt.error is not None, "Error field must be set on HTTP failure"

    @pytest.mark.asyncio
    async def test_register_project_bundle_returns_error_on_failure(self) -> None:
        """register_project_bundle() must return error dict on HTTP failure."""
        from src.integrations.provider_02.provider import Provider02AttestationProvider

        provider = Provider02AttestationProvider(
            endpoint="https://provider02.example.com"
        )

        import httpx

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client_cls.return_value = mock_client

            result = await provider.register_project_bundle({"bundleId": "b1"})

        assert "error" in result, (
            "register_project_bundle must return an error dict on HTTP failure"
        )

    def test_get_provider_02_returns_singleton(self) -> None:
        """get_provider_02() must return the same instance on repeated calls."""
        from src.integrations.provider_02 import provider as provider_module

        # Reset singleton for clean test
        provider_module._provider = None

        p1 = provider_module.get_provider_02()
        p2 = provider_module.get_provider_02()
        assert p1 is p2, "get_provider_02() must return a singleton instance"

        # Cleanup
        provider_module._provider = None
