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
tests/test_provider_02_adapter.py — Tests for the LangGraph-to-Provider 02 attestation adapter.

Verification invariants:
  1. Step serialization captures all AgentState governance fields.
  2. copy.deepcopy guards against state mutation during loop iterations.
  3. Parent step IDs record only executed edges, validated against the topology.
  4. HITL interrupt is recorded as a paused DAG step.
  5. Loop unrolling produces correct parentStepIds across iterations.
  6. All 4 degenerate paths produce valid bundles.
  7. Terminal path classification is correct.
  8. Provider02Client builds correct HTTP requests.
  9. AttestationBundle serialization matches Provider 02 API contract.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.gateway.governance.evidence.state_commitment import canonicalize_state
from src.integrations.provider_02.adapter import (
    AttestationBundle,
    LineageError,
    ProjectBundleStepEntry,
    Provider02AttestationCallback,
    Provider02Client,
    _classify_terminal_path,
    _extract_signals,
    _serialize_state_snapshot,
)
from tests.integrations.provider_02.state_commitment_support import (
    InProcessCommitter,
    seal,
    sealed_bundle,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Fixtures — simulated AgentState dicts
# ---------------------------------------------------------------------------


def _base_state(**overrides) -> dict:  # type: ignore[no-untyped-def]
    """Build a minimal AgentState-like dict for testing."""
    state = {
        "messages": [],
        "next_step": "evaluator",
        "risk_status": "UNKNOWN",
        "risk_feedback": None,
        "loop_count": 0,
        "safety_status": "APPROVED",
        "governance_signature": None,
        "risk_attitude": "moderate",
        "investment_period": "long",
        "reasoning_output": None,
        "execution_plan_output": None,
        "data_analyst_ticker": None,
        "evaluation_result": None,
        "opa_results": None,
        "execution_result": None,
        "governance_summary": None,
        "user_id": "test-user-001",
        "latency_stats": None,
        "completed_transactions": [],
        "approval_required": False,
        "approval_decision": None,
        "guardrail_blocked": False,
        "guardrail_reason": "",
        "output_rail_applied": False,
    }
    state.update(overrides)
    return state


def _approved_state() -> dict:
    """AgentState after successful evaluation + safety check."""
    return _base_state(
        governance_signature="abc123def456",
        evaluation_result={
            "verdict": "APPROVED",
            "reasoning": "Plan meets safety constraints",
            "policy_check": "PASSED",
        },
        safety_status="APPROVED",
        risk_status="APPROVED",
        opa_results={"allow": True, "violations": []},
    )


def _blocked_state() -> dict:
    """AgentState when NeMo guardrail blocks input."""
    return _base_state(
        guardrail_blocked=True,
        guardrail_reason="Harmful content detected",
    )


def _hitl_state() -> dict:
    """AgentState at HITL interrupt with approval decision."""
    return _base_state(
        approval_required=True,
        approval_decision={
            "approved": True,
            "reviewer": "jane.doe@example.com",
            "rationale": "Trade within acceptable parameters",
            "comment": "",
            "timestamp": "2026-05-29T10:00:00Z",
        },
        governance_signature="sig_hitl_approved",
    )


# ---------------------------------------------------------------------------
# Test 1: State serialization
# ---------------------------------------------------------------------------


class TestStateSerialization:
    """Tests for state snapshot serialization and hashing."""

    def test_deepcopy_protects_against_mutation(self):  # type: ignore[no-untyped-def]
        """Modifying the original state after serialization does not affect the snapshot."""
        state = _base_state(governance_signature="original_sig")
        snapshot = _serialize_state_snapshot(state)

        # Mutate original
        state["governance_signature"] = "MUTATED"

        # Snapshot should be unchanged
        assert snapshot["governance_signature"] == "original_sig"

    def test_messages_are_truncated(self):  # type: ignore[no-untyped-def]
        """BaseMessage objects are converted to truncated string representations."""
        msg = MagicMock()
        msg.content = "A" * 1000
        msg.type = "human"
        state = _base_state(messages=[msg])

        snapshot = _serialize_state_snapshot(state)
        assert len(snapshot["messages"][0]["content"]) == 500

    def test_completed_transactions_removed(self):  # type: ignore[no-untyped-def]
        """Saga ledger is removed from snapshot (handled separately in signals)."""
        state = _base_state(completed_transactions=[{"sequence_id": 1}])
        snapshot = _serialize_state_snapshot(state)
        assert "completed_transactions" not in snapshot

    def test_hash_deterministic(self):  # type: ignore[no-untyped-def]
        """Same state produces the same commitment."""
        state = _base_state(governance_signature="test_sig")
        h1 = canonicalize_state(_serialize_state_snapshot(state))[2]
        h2 = canonicalize_state(_serialize_state_snapshot(state))[2]
        assert h1 == h2

    def test_hash_different_for_different_states(self):  # type: ignore[no-untyped-def]
        """Different states produce different commitments."""
        s1 = _base_state(governance_signature="sig_a")
        s2 = _base_state(governance_signature="sig_b")
        assert (
            canonicalize_state(_serialize_state_snapshot(s1))[2]
            != canonicalize_state(_serialize_state_snapshot(s2))[2]
        )


# ---------------------------------------------------------------------------
# Test 2: Signal extraction
# ---------------------------------------------------------------------------


class TestSignalExtraction:
    """Tests for governance signal extraction from AgentState."""

    def test_extracts_governance_signature(self):  # type: ignore[no-untyped-def]
        """Governance signature is captured in signals."""
        state = _base_state(governance_signature="abc123")
        signals = _extract_signals("evaluator", state)
        assert signals["governanceSignature"] == "abc123"

    def test_extracts_evaluation_result(self):  # type: ignore[no-untyped-def]
        """Evaluation verdict and reasoning are captured."""
        state = _approved_state()
        signals = _extract_signals("evaluator", state)
        assert signals["evaluationVerdict"] == "APPROVED"
        assert signals["policyCheck"] == "PASSED"

    def test_extracts_safety_status(self):  # type: ignore[no-untyped-def]
        """Safety status is captured."""
        state = _base_state(safety_status="BLOCKED")
        signals = _extract_signals("safety_check", state)
        assert signals["safetyStatus"] == "BLOCKED"

    def test_extracts_hitl_approval(self):  # type: ignore[no-untyped-def]
        """HITL approval decision fields are captured."""
        state = _hitl_state()
        signals = _extract_signals("governed_trader", state)
        assert signals["hitlApproval"]["approved"] is True
        assert signals["hitlApproval"]["reviewer"] == "jane.doe@example.com"

    def test_extracts_guardrail_block(self):  # type: ignore[no-untyped-def]
        """Guardrail blocked status and reason are captured."""
        state = _blocked_state()
        signals = _extract_signals("nemo_guardrail", state)
        assert signals["guardrailBlocked"] is True
        assert signals["guardrailReason"] == "Harmful content detected"

    def test_extracts_saga_ledger(self):  # type: ignore[no-untyped-def]
        """Completed transactions are serialized into signals."""
        state = _base_state(
            completed_transactions=[
                {
                    "sequence_id": 1,
                    "action": "execute_trade",
                    "status": "COMPLETED",
                    "uca_ref": "UCA-4",
                },
            ]
        )
        signals = _extract_signals("governed_trader", state)
        assert len(signals["sagaLedger"]) == 1
        assert signals["sagaLedger"][0]["action"] == "execute_trade"

    def test_no_signals_for_empty_state(self):  # type: ignore[no-untyped-def]
        """Minimal state produces minimal signals."""
        state = _base_state()
        signals = _extract_signals("thinker_node", state)
        # Only risk_status="UNKNOWN" and safety_status="APPROVED" should be present
        assert "governanceSignature" not in signals


# ---------------------------------------------------------------------------
# Test 3: Callback handler — step recording
# ---------------------------------------------------------------------------


class TestCallbackHandler:
    """Tests for Provider02AttestationCallback step recording."""

    def test_records_attestation_node(self):  # type: ignore[no-untyped-def]
        """Governance-significant nodes produce step entries."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )
        state = _approved_state()

        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", state)

        assert cb.step_count == 1

    def test_skips_non_attestation_node(self):  # type: ignore[no-untyped-def]
        """Non-governance nodes don't produce step entries but track IDs."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )
        state = _base_state()

        cb.on_chain_start("thinker_node", state)
        cb.on_chain_end("thinker_node", state)

        assert cb.step_count == 0

    def test_parent_step_ids_resolve(self):  # type: ignore[no-untyped-def]
        """Parent step IDs contract executed edges back to the nearest recorded step."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )
        state = _base_state()

        # Simulate: nemo_guardrail → thinker → doer → execution_analyst → evaluator
        for node in [
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "execution_analyst",
        ]:
            cb.on_chain_start(node, state)
            cb.on_chain_end(node, state)

        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", _approved_state())

        # evaluator's parent contracts upstream through non-attestation nodes to nemo_guardrail
        evaluator_step = [s for s in cb._steps if s.node_name == "evaluator"][0]
        nemo_guardrail_id = next(
            s.step_id for s in cb._steps if s.node_name == "nemo_guardrail"
        )
        assert evaluator_step.parent_step_ids == [nemo_guardrail_id]

    def test_hitl_interrupt_recorded(self):  # type: ignore[no-untyped-def]
        """HITL interrupt produces a step with approval signals, 64-char hex state_hash,
        and correct causal chain: safety_check -> hitl_interrupt -> governed_trader.
        """
        import re

        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )
        state = _base_state()

        # Simulate path up to safety_check
        for node in [
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "execution_analyst",
            "evaluator",
            "ftra_node",
            "safety_check",
        ]:
            cb.on_chain_start(node, state)
            cb.on_chain_end(node, state)

        # Capture safety_check step_id
        safety_check_step = next(s for s in cb._steps if s.node_name == "safety_check")
        safety_check_step_id = safety_check_step.step_id

        # Record HITL interrupt
        hitl_state = _hitl_state()
        cb.handle_hitl_interrupt(hitl_state)

        hitl_steps = [s for s in cb._steps if s.node_name == "hitl_interrupt"]
        assert len(hitl_steps) == 1
        hitl_step = hitl_steps[0]

        assert hitl_step.signals["hitlApproval"]["approved"] is True
        assert hitl_step.signals["interruptType"] == "HITL_MANUAL_REVIEW"

        # stateHash is the gateway receipt: empty until sealed, then 64 hex chars
        assert hitl_step.state_hash == ""
        seal(cb)
        assert hitl_step.state_hash, "state_hash must be non-empty"
        assert re.match(r"^[a-f0-9]{64}$", hitl_step.state_hash), (
            f"state_hash must be 64 lowercase hex chars, got {hitl_step.state_hash!r}"
        )

        # Confirm causal chain: safety_check -> hitl_interrupt
        assert hitl_step.parent_step_ids == [safety_check_step_id], (
            f"hitl_interrupt must link to safety_check, "
            f"expected [{safety_check_step_id}], got {hitl_step.parent_step_ids}"
        )

        # Simulate resumption: governed_trader should link to hitl_interrupt
        cb.on_chain_start("governed_trader", hitl_state)
        cb.on_chain_end("governed_trader", hitl_state)

        governed_trader_step = next(
            s for s in cb._steps if s.node_name == "governed_trader"
        )
        assert governed_trader_step.parent_step_ids == [hitl_step.step_id], (
            f"governed_trader must link to hitl_interrupt, "
            f"expected [{hitl_step.step_id}], got {governed_trader_step.parent_step_ids}"
        )


# ---------------------------------------------------------------------------
# Test 4: Loop unrolling
# ---------------------------------------------------------------------------


class TestLoopUnrolling:
    """Tests for bounded cycle serialization (execution_analyst → evaluator)."""

    def test_single_iteration(self):  # type: ignore[no-untyped-def]
        """Single loop iteration produces correct parentStepIds."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )
        state = _base_state(loop_count=1)

        # First pass
        cb.on_chain_start("execution_analyst", state)
        cb.on_chain_end("execution_analyst", state)
        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", state)

        assert cb.step_count == 1  # only evaluator is attestation node

    def test_multi_iteration_produces_sequential_parents(self):  # type: ignore[no-untyped-def]
        """Multiple loop iterations produce sequential parent chains."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )

        for iteration in range(3):
            state = _base_state(loop_count=iteration + 1)
            cb.on_chain_start("execution_analyst", state)
            cb.on_chain_end("execution_analyst", state)
            cb.on_chain_start("evaluator", state)
            cb.on_chain_end("evaluator", state)

        evaluator_steps = [s for s in cb._steps if s.node_name == "evaluator"]
        assert len(evaluator_steps) == 3

        # Root evaluator step in isolated loop test has no prior recorded ancestor
        assert evaluator_steps[0].parent_step_ids == []
        # Subsequent iterations link sequentially to previous evaluator iteration
        assert evaluator_steps[1].parent_step_ids == [evaluator_steps[0].step_id]
        assert evaluator_steps[2].parent_step_ids == [evaluator_steps[1].step_id]
        for step in evaluator_steps[1:]:
            assert len(step.parent_step_ids) >= 1

    def test_loop_breaker_at_count_3(self):  # type: ignore[no-untyped-def]
        """After 3 iterations, the path should classify as loop_breaker."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="test-thread",
        )

        for iteration in range(3):
            state = _base_state(loop_count=iteration + 1)
            cb.on_chain_start("execution_analyst", state)
            cb.on_chain_end("execution_analyst", state)
            cb.on_chain_start("evaluator", state)
            cb.on_chain_end("evaluator", state)

        # Explainer after loop break
        state = _base_state(loop_count=3)
        cb.on_chain_start("explainer", state)
        cb.on_chain_end("explainer", state)

        bundle = sealed_bundle(cb)
        assert bundle.terminal_path == "loop_breaker"


# ---------------------------------------------------------------------------
# Test 4b: Executed-edge lineage (NATIVE_SCHEMA_SPEC.md §4.1 rules 2-4)
# ---------------------------------------------------------------------------


def _run(cb: Provider02AttestationCallback, nodes: list[str], state: dict) -> None:
    for node in nodes:
        cb.on_chain_start(node, state)
        cb.on_chain_end(node, state)


def _parents_by_name(cb: Provider02AttestationCallback) -> list[tuple[str, list[str]]]:
    """(node_name, [parent node names]) per recorded step, in emission order."""
    name_by_id = {s.step_id: s.node_name for s in cb._steps}
    return [
        (s.node_name, [name_by_id[p] for p in s.parent_step_ids]) for s in cb._steps
    ]


class TestExecutedLineage:
    """parentStepIds cite only parents along edges actually traversed."""

    def test_post_hitl_steps_cite_only_executed_parents(self) -> None:
        """explainer has static candidates evaluator/safety_check, but only
        governed_trader actually preceded it; nemo_output_rail must not reach
        nemo_guardrail through data_analyst, which never ran."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(
            cb,
            [
                "nemo_guardrail",
                "thinker_node",
                "doer_node",
                "execution_analyst",
                "evaluator",
                "ftra_node",
                "safety_check",
            ],
            _approved_state(),
        )
        cb.handle_hitl_interrupt(_hitl_state())
        _run(cb, ["governed_trader", "explainer", "nemo_output_rail"], _hitl_state())

        assert _parents_by_name(cb) == [
            ("nemo_guardrail", []),
            ("evaluator", ["nemo_guardrail"]),
            ("safety_check", ["evaluator"]),
            ("hitl_interrupt", ["safety_check"]),
            ("governed_trader", ["hitl_interrupt"]),
            ("explainer", ["governed_trader"]),
            ("nemo_output_rail", ["explainer"]),
        ]

    @pytest.mark.parametrize("emit_approval_node", [True, False])
    def test_hitl_step_contracts_through_approval_node(
        self, emit_approval_node: bool
    ) -> None:
        """safety_check -> approval_node -> [hitl_interrupt] contracts to safety_check.

        approval_node is unrecorded; callers that do not emit it (pause recorded
        straight after safety_check) yield the same recorded chain.
        """
        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        _run(
            cb,
            [
                "nemo_guardrail",
                "thinker_node",
                "doer_node",
                "execution_analyst",
                "evaluator",
                "ftra_node",
                "safety_check",
            ],
            _approved_state(),
        )
        if emit_approval_node:
            _run(cb, ["approval_node"], _hitl_state())
        cb.handle_hitl_interrupt(_hitl_state())
        _run(cb, ["governed_trader"], _hitl_state())

        assert _parents_by_name(cb)[-3:] == [
            ("safety_check", ["evaluator"]),
            ("hitl_interrupt", ["safety_check"]),
            ("governed_trader", ["hitl_interrupt"]),
        ]

    def test_deferral_path_contracts_through_defer_node(self) -> None:
        """safety_check -> defer_node -> explainer: explainer cites safety_check."""
        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        _run(
            cb,
            [
                "nemo_guardrail",
                "thinker_node",
                "doer_node",
                "execution_analyst",
                "evaluator",
                "ftra_node",
                "safety_check",
                "defer_node",
                "explainer",
                "nemo_output_rail",
            ],
            _base_state(safety_status="DEFERRED"),
        )
        parents = dict(_parents_by_name(cb))
        assert parents["explainer"] == ["safety_check"]
        assert parents["nemo_output_rail"] == ["explainer"]

    def test_ftra_block_explainer_cites_evaluator(self) -> None:
        """evaluator -> ftra_node(BLOCKED) -> explainer contracts to evaluator."""
        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        _run(
            cb,
            [
                "nemo_guardrail",
                "thinker_node",
                "doer_node",
                "execution_analyst",
                "evaluator",
                "ftra_node",
                "explainer",
            ],
            _base_state(),
        )
        assert dict(_parents_by_name(cb))["explainer"] == ["evaluator"]

    def test_finish_routes_doer_to_output_rail(self) -> None:
        """route_supervisor FINISH: doer_node -> nemo_output_rail is a legal edge."""
        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        _run(
            cb,
            ["nemo_guardrail", "thinker_node", "doer_node", "nemo_output_rail"],
            _base_state(),
        )
        assert dict(_parents_by_name(cb))["nemo_output_rail"] == ["nemo_guardrail"]

    def test_evaluator_to_safety_check_without_ftra_fails_closed(self) -> None:
        """The real graph routes evaluator -> ftra_node -> safety_check; a direct
        evaluator -> safety_check edge no longer exists."""
        cb = Provider02AttestationCallback(topology=FINANCIAL_ADVISOR_TOPOLOGY)
        _run(cb, ["execution_analyst", "evaluator"], _base_state())
        with pytest.raises(LineageError, match="'evaluator' -> 'safety_check'"):
            cb.on_chain_end("safety_check", _base_state())

    def test_data_analyst_path_contracts_to_entry_guardrail(self) -> None:
        """When data_analyst does run, nemo_output_rail contracts through it."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(
            cb,
            [
                "nemo_guardrail",
                "thinker_node",
                "doer_node",
                "data_analyst",
                "nemo_output_rail",
            ],
            _base_state(),
        )
        assert _parents_by_name(cb) == [
            ("nemo_guardrail", []),
            ("nemo_output_rail", ["nemo_guardrail"]),
        ]

    def test_cbf_block_explainer_cites_safety_check_only(self) -> None:
        """CBF fail-closed: explainer follows safety_check, not evaluator."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(
            cb,
            ["nemo_guardrail", "thinker_node", "doer_node", "execution_analyst"],
            _base_state(),
        )
        _run(
            cb,
            ["evaluator", "ftra_node", "safety_check", "explainer"],
            _base_state(safety_status="BLOCKED"),
        )
        assert dict(_parents_by_name(cb))["explainer"] == ["safety_check"]

    def test_loop_unrolling_on_full_path(self) -> None:
        """Each evaluator iteration cites the iteration that actually preceded it."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(cb, ["nemo_guardrail", "thinker_node", "doer_node"], _base_state())
        for i in range(3):
            _run(cb, ["execution_analyst", "evaluator"], _base_state(loop_count=i))
        _run(cb, ["explainer"], _base_state(loop_count=3))

        evaluators = [s for s in cb._steps if s.node_name == "evaluator"]
        guardrail = cb._steps[0]
        assert evaluators[0].parent_step_ids == [guardrail.step_id]
        assert evaluators[1].parent_step_ids == [evaluators[0].step_id]
        assert evaluators[2].parent_step_ids == [evaluators[1].step_id]
        assert cb._steps[-1].parent_step_ids == [evaluators[2].step_id]

    def test_illegal_executed_edge_fails_closed(self) -> None:
        """nemo_guardrail -> evaluator is not a parent_edges candidate: refuse it."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(cb, ["nemo_guardrail"], _base_state())
        cb.on_chain_start("evaluator", _base_state())
        with pytest.raises(LineageError, match="Illegal executed edge"):
            cb.on_chain_end("evaluator", _base_state())
        assert [s.node_name for s in cb._steps] == ["nemo_guardrail"]

    def test_illegal_edge_through_unrecorded_node_fails_closed(self) -> None:
        """Validation applies to unrecorded nodes too (doer_node after nemo_guardrail)."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(cb, ["nemo_guardrail"], _base_state())
        with pytest.raises(LineageError, match="Illegal executed edge"):
            cb.on_chain_end("doer_node", _base_state())

    def test_hitl_interrupt_from_illegal_predecessor_fails_closed(self) -> None:
        """hitl_interrupt may only follow safety_check."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(
            cb,
            ["nemo_guardrail", "thinker_node", "doer_node", "execution_analyst"],
            _base_state(),
        )
        _run(cb, ["evaluator"], _base_state())
        with pytest.raises(LineageError, match="'evaluator' -> 'hitl_interrupt'"):
            cb.handle_hitl_interrupt(_hitl_state())

    def test_declared_predecessor_that_never_ran_fails_closed(self) -> None:
        """A legal candidate that did not execute must not be cited."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=FINANCIAL_ADVISOR_TOPOLOGY
        )
        _run(cb, ["nemo_guardrail", "thinker_node", "doer_node"], _base_state())
        with pytest.raises(LineageError, match="has not executed"):
            cb.on_chain_end(
                "execution_analyst",
                _base_state(),
                executed_predecessors=["doer_node", "evaluator"],
            )

    def test_explicit_fan_in_includes_every_executed_predecessor(self) -> None:
        """Genuine convergence from parallel branches cites every branch."""
        from src.gateway.governance.seams.graph_topology import GraphTopology

        topology = GraphTopology(
            nodes=frozenset({"A", "B", "C", "D"}),
            attestation_nodes=frozenset({"A", "B", "C", "D"}),
            parent_edges={"A": [], "B": ["A"], "C": ["A"], "D": ["B", "C"]},
            terminal_node="D",
        )
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(), topology=topology
        )
        _run(cb, ["A", "B"], {})
        cb.on_chain_end("C", {}, executed_predecessors=["A"])
        cb.on_chain_end("D", {}, executed_predecessors=["B", "C"])
        assert _parents_by_name(cb) == [
            ("A", []),
            ("B", ["A"]),
            ("C", ["A"]),
            ("D", ["B", "C"]),
        ]


# ---------------------------------------------------------------------------
# Test 5: Terminal path classification
# ---------------------------------------------------------------------------


class TestTerminalPathClassification:
    """Tests for degenerate path classification."""

    def test_happy_path(self):  # type: ignore[no-untyped-def]
        """Full traversal with governed_trader is classified as happy_path."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="safety_check"),
            ProjectBundleStepEntry(node_name="governed_trader"),
            ProjectBundleStepEntry(node_name="explainer"),
            ProjectBundleStepEntry(node_name="nemo_output_rail"),
        ]
        assert (
            _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY) == "happy_path"
        )

    def test_nemo_block(self):  # type: ignore[no-untyped-def]
        """NeMo guardrail block path is classified correctly."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
        ]
        assert (
            _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY) == "nemo_block"
        )

    def test_cbf_block(self):  # type: ignore[no-untyped-def]
        """Safety check BLOCKED path is classified correctly."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(
                node_name="safety_check",
                signals={"safetyStatus": "BLOCKED"},
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        assert _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY) == "cbf_block"

    def test_loop_breaker(self):  # type: ignore[no-untyped-def]
        """Loop breaker path (evaluator → explainer, no safety_check) is classified."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        assert (
            _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY) == "loop_breaker"
        )


# ---------------------------------------------------------------------------
# Test 6: Bundle assembly
# ---------------------------------------------------------------------------


class TestBundleAssembly:
    """Tests for AttestationBundle creation."""

    def test_bundle_serialization(self):  # type: ignore[no-untyped-def]
        """Bundle serializes to Provider 02-compatible dict."""
        bundle = AttestationBundle(
            thread_id="thread-001",
            steps=[
                ProjectBundleStepEntry(node_name="evaluator"),
            ],
            started_at="2026-05-29T10:00:00Z",
            completed_at="2026-05-29T10:01:00Z",
            terminal_path="happy_path",
        )
        d = bundle.to_dict()
        assert d["threadId"] == "thread-001"
        assert len(d["steps"]) == 1
        assert d["steps"][0]["nodeName"] == "evaluator"
        assert d["terminalPath"] == "happy_path"

    def test_bundle_from_callback(self):  # type: ignore[no-untyped-def]
        """Full callback flow produces a valid bundle."""
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="e2e-thread",
        )
        state = _base_state()

        cb.on_chain_start("nemo_guardrail", state)
        cb.on_chain_end("nemo_guardrail", state)
        for node in ("thinker_node", "doer_node", "execution_analyst"):
            cb.on_chain_start(node, state)
            cb.on_chain_end(node, state)
        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", _approved_state())
        cb.on_chain_start("ftra_node", _approved_state())
        cb.on_chain_end("ftra_node", _approved_state())
        cb.on_chain_start("safety_check", _approved_state())
        cb.on_chain_end("safety_check", _approved_state())
        cb.on_chain_start("governed_trader", _approved_state())
        cb.on_chain_end("governed_trader", _approved_state())
        cb.on_chain_start("explainer", _approved_state())
        cb.on_chain_end("explainer", _approved_state())

        bundle = sealed_bundle(cb)
        assert bundle.thread_id == "e2e-thread"
        assert bundle.terminal_path == "happy_path"
        assert len(bundle.steps) == 5  # guardrail, evaluator, safety, trader, explainer

    def test_step_entry_serialization(self):  # type: ignore[no-untyped-def]
        """ProjectBundleStepEntry serializes with camelCase keys."""
        step = ProjectBundleStepEntry(
            node_name="evaluator",
            parent_step_ids=["parent-1"],
            signals={"governanceSignature": "sig123"},
        )
        d = step.to_dict()
        assert "stepId" in d
        assert "nodeName" in d
        assert d["parentStepIds"] == ["parent-1"]


# ---------------------------------------------------------------------------
# Test 7: Provider 02 HTTP Client
# ---------------------------------------------------------------------------


class TestProvider02Client:
    """Tests for Provider02Client HTTP request construction."""

    def test_headers_include_bearer_auth(self):  # type: ignore[no-untyped-def]
        """Authorization header uses Bearer scheme."""
        client = Provider02Client(
            endpoint="https://api.provider02.example.com",
            api_key="test-key-123",
        )
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-key-123"
        assert headers["Content-Type"] == "application/json"

    def test_headers_without_api_key(self):  # type: ignore[no-untyped-def]
        """Without API key, only Content-Type header is present."""
        client = Provider02Client(
            endpoint="https://api.provider02.example.com", api_key=""
        )
        headers = client._headers()
        assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_certify_decision_builds_correct_url(self):  # type: ignore[no-untyped-def]
        """certify_decision posts to /certifyDecision."""

        mock_response = MagicMock()
        mock_response.json.return_value = {"certificateHash": "abc123"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            client = Provider02Client(endpoint="https://api.provider02.example.com/v1")
            await client.certify_decision({"test": True})

            mock_instance.post.assert_called_once()
            call_args = mock_instance.post.call_args
            assert (
                call_args[0][0]
                == "https://api.provider02.example.com/v1/certifyDecision"
            )
