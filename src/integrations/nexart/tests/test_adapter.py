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
tests/test_nexart_adapter.py — Tests for the LangGraph-to-NexArt attestation adapter.

Verification invariants:
  1. Step serialization captures all AgentState governance fields.
  2. copy.deepcopy guards against state mutation during loop iterations.
  3. Parent step IDs resolve correctly from graph topology.
  4. HITL interrupt is recorded as a paused DAG step.
  5. Loop unrolling produces correct parentStepIds across iterations.
  6. All 4 degenerate paths produce valid bundles.
  7. Terminal path classification is correct.
  8. NexArtClient builds correct HTTP requests.
  9. AttestationBundle serialization matches NexArt API contract.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.nexart.adapter import (
    AttestationBundle,
    NexArtAttestationCallback,
    NexArtClient,
    ProjectBundleStepEntry,
    _classify_terminal_path,
    _extract_signals,
    _hash_state,
    _serialize_state_snapshot,
)

# ---------------------------------------------------------------------------
# Fixtures — simulated AgentState dicts
# ---------------------------------------------------------------------------


def _base_state(**overrides) -> dict:
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

    def test_deepcopy_protects_against_mutation(self):
        """Modifying the original state after serialization does not affect the snapshot."""
        state = _base_state(governance_signature="original_sig")
        snapshot = _serialize_state_snapshot(state)

        # Mutate original
        state["governance_signature"] = "MUTATED"

        # Snapshot should be unchanged
        assert snapshot["governance_signature"] == "original_sig"

    def test_messages_are_truncated(self):
        """BaseMessage objects are converted to truncated string representations."""
        msg = MagicMock()
        msg.content = "A" * 1000
        msg.type = "human"
        state = _base_state(messages=[msg])

        snapshot = _serialize_state_snapshot(state)
        assert len(snapshot["messages"][0]["content"]) == 500

    def test_completed_transactions_removed(self):
        """Saga ledger is removed from snapshot (handled separately in signals)."""
        state = _base_state(completed_transactions=[{"sequence_id": 1}])
        snapshot = _serialize_state_snapshot(state)
        assert "completed_transactions" not in snapshot

    def test_hash_deterministic(self):
        """Same state produces the same hash."""
        state = _base_state(governance_signature="test_sig")
        h1 = _hash_state(_serialize_state_snapshot(state))
        h2 = _hash_state(_serialize_state_snapshot(state))
        assert h1 == h2

    def test_hash_different_for_different_states(self):
        """Different states produce different hashes."""
        s1 = _base_state(governance_signature="sig_a")
        s2 = _base_state(governance_signature="sig_b")
        assert _hash_state(_serialize_state_snapshot(s1)) != _hash_state(
            _serialize_state_snapshot(s2)
        )


# ---------------------------------------------------------------------------
# Test 2: Signal extraction
# ---------------------------------------------------------------------------


class TestSignalExtraction:
    """Tests for governance signal extraction from AgentState."""

    def test_extracts_governance_signature(self):
        """Governance signature is captured in signals."""
        state = _base_state(governance_signature="abc123")
        signals = _extract_signals("evaluator", state)
        assert signals["governanceSignature"] == "abc123"

    def test_extracts_evaluation_result(self):
        """Evaluation verdict and reasoning are captured."""
        state = _approved_state()
        signals = _extract_signals("evaluator", state)
        assert signals["evaluationVerdict"] == "APPROVED"
        assert signals["policyCheck"] == "PASSED"

    def test_extracts_safety_status(self):
        """Safety status is captured."""
        state = _base_state(safety_status="BLOCKED")
        signals = _extract_signals("safety_check", state)
        assert signals["safetyStatus"] == "BLOCKED"

    def test_extracts_hitl_approval(self):
        """HITL approval decision fields are captured."""
        state = _hitl_state()
        signals = _extract_signals("governed_trader", state)
        assert signals["hitlApproval"]["approved"] is True
        assert signals["hitlApproval"]["reviewer"] == "jane.doe@example.com"

    def test_extracts_guardrail_block(self):
        """Guardrail blocked status and reason are captured."""
        state = _blocked_state()
        signals = _extract_signals("nemo_guardrail", state)
        assert signals["guardrailBlocked"] is True
        assert signals["guardrailReason"] == "Harmful content detected"

    def test_extracts_saga_ledger(self):
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

    def test_no_signals_for_empty_state(self):
        """Minimal state produces minimal signals."""
        state = _base_state()
        signals = _extract_signals("thinker_node", state)
        # Only risk_status="UNKNOWN" and safety_status="APPROVED" should be present
        assert "governanceSignature" not in signals


# ---------------------------------------------------------------------------
# Test 3: Callback handler — step recording
# ---------------------------------------------------------------------------


class TestCallbackHandler:
    """Tests for NexArtAttestationCallback step recording."""

    def test_records_attestation_node(self):
        """Governance-significant nodes produce step entries."""
        cb = NexArtAttestationCallback(thread_id="test-thread")
        state = _approved_state()

        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", state)

        assert cb.step_count == 1

    def test_skips_non_attestation_node(self):
        """Non-governance nodes don't produce step entries but track IDs."""
        cb = NexArtAttestationCallback(thread_id="test-thread")
        state = _base_state()

        cb.on_chain_start("thinker_node", state)
        cb.on_chain_end("thinker_node", state)

        assert cb.step_count == 0

    def test_parent_step_ids_resolve(self):
        """Parent step IDs are correctly resolved from graph topology."""
        cb = NexArtAttestationCallback(thread_id="test-thread")
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

        # evaluator's parent should be execution_analyst's step_id
        evaluator_step = [s for s in cb._steps if s.node_name == "evaluator"][0]
        execution_analyst_id = cb._step_id_by_node["execution_analyst"]
        assert execution_analyst_id in evaluator_step.parent_step_ids

    def test_hitl_interrupt_recorded(self):
        """HITL interrupt produces a step with approval signals."""
        cb = NexArtAttestationCallback(thread_id="test-thread")
        state = _base_state()

        # Simulate path up to safety_check
        for node in [
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "execution_analyst",
            "evaluator",
            "safety_check",
        ]:
            cb.on_chain_start(node, state)
            cb.on_chain_end(node, state)

        # Record HITL interrupt
        cb.handle_hitl_interrupt(_hitl_state())

        hitl_steps = [s for s in cb._steps if s.node_name == "hitl_interrupt"]
        assert len(hitl_steps) == 1
        assert hitl_steps[0].signals["hitlApproval"]["approved"] is True
        assert hitl_steps[0].signals["interruptType"] == "HITL_MANUAL_REVIEW"


# ---------------------------------------------------------------------------
# Test 4: Loop unrolling
# ---------------------------------------------------------------------------


class TestLoopUnrolling:
    """Tests for bounded cycle serialization (execution_analyst → evaluator)."""

    def test_single_iteration(self):
        """Single loop iteration produces correct parentStepIds."""
        cb = NexArtAttestationCallback(thread_id="test-thread")
        state = _base_state(loop_count=1)

        # First pass
        cb.on_chain_start("execution_analyst", state)
        cb.on_chain_end("execution_analyst", state)
        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", state)

        assert cb.step_count == 1  # only evaluator is attestation node

    def test_multi_iteration_produces_sequential_parents(self):
        """Multiple loop iterations produce sequential parent chains."""
        cb = NexArtAttestationCallback(thread_id="test-thread")

        for iteration in range(3):
            state = _base_state(loop_count=iteration + 1)
            cb.on_chain_start("execution_analyst", state)
            cb.on_chain_end("execution_analyst", state)
            cb.on_chain_start("evaluator", state)
            cb.on_chain_end("evaluator", state)

        evaluator_steps = [s for s in cb._steps if s.node_name == "evaluator"]
        assert len(evaluator_steps) == 3

        # Each evaluator step should have a parent from execution_analyst
        for step in evaluator_steps:
            assert len(step.parent_step_ids) >= 1

    def test_loop_breaker_at_count_3(self):
        """After 3 iterations, the path should classify as loop_breaker."""
        cb = NexArtAttestationCallback(thread_id="test-thread")

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

        bundle = cb.get_bundle()
        assert bundle.terminal_path == "loop_breaker"


# ---------------------------------------------------------------------------
# Test 5: Terminal path classification
# ---------------------------------------------------------------------------


class TestTerminalPathClassification:
    """Tests for degenerate path classification."""

    def test_happy_path(self):
        """Full traversal with governed_trader is classified as happy_path."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="safety_check"),
            ProjectBundleStepEntry(node_name="governed_trader"),
            ProjectBundleStepEntry(node_name="explainer"),
            ProjectBundleStepEntry(node_name="nemo_output_rail"),
        ]
        assert _classify_terminal_path(steps) == "happy_path"

    def test_nemo_block(self):
        """NeMo guardrail block path is classified correctly."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
        ]
        assert _classify_terminal_path(steps) == "nemo_block"

    def test_cbf_block(self):
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
        assert _classify_terminal_path(steps) == "cbf_block"

    def test_loop_breaker(self):
        """Loop breaker path (evaluator → explainer, no safety_check) is classified."""
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        assert _classify_terminal_path(steps) == "loop_breaker"


# ---------------------------------------------------------------------------
# Test 6: Bundle assembly
# ---------------------------------------------------------------------------


class TestBundleAssembly:
    """Tests for AttestationBundle creation."""

    def test_bundle_serialization(self):
        """Bundle serializes to NexArt-compatible dict."""
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

    def test_bundle_from_callback(self):
        """Full callback flow produces a valid bundle."""
        cb = NexArtAttestationCallback(thread_id="e2e-thread")
        state = _base_state()

        cb.on_chain_start("nemo_guardrail", state)
        cb.on_chain_end("nemo_guardrail", state)
        cb.on_chain_start("thinker_node", state)
        cb.on_chain_end("thinker_node", state)
        cb.on_chain_start("evaluator", state)
        cb.on_chain_end("evaluator", _approved_state())
        cb.on_chain_start("safety_check", _approved_state())
        cb.on_chain_end("safety_check", _approved_state())
        cb.on_chain_start("governed_trader", _approved_state())
        cb.on_chain_end("governed_trader", _approved_state())
        cb.on_chain_start("explainer", _approved_state())
        cb.on_chain_end("explainer", _approved_state())

        bundle = cb.get_bundle()
        assert bundle.thread_id == "e2e-thread"
        assert bundle.terminal_path == "happy_path"
        assert len(bundle.steps) == 5  # guardrail, evaluator, safety, trader, explainer

    def test_step_entry_serialization(self):
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
# Test 7: NexArt HTTP Client
# ---------------------------------------------------------------------------


class TestNexArtClient:
    """Tests for NexArtClient HTTP request construction."""

    def test_headers_include_bearer_auth(self):
        """Authorization header uses Bearer scheme."""
        client = NexArtClient(
            endpoint="https://api.nexart.io",
            api_key="test-key-123",
        )
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-key-123"
        assert headers["Content-Type"] == "application/json"

    def test_headers_without_api_key(self):
        """Without API key, only Content-Type header is present."""
        client = NexArtClient(endpoint="https://api.nexart.io", api_key="")
        headers = client._headers()
        assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_certify_decision_builds_correct_url(self):
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

            client = NexArtClient(endpoint="https://api.nexart.io/v1")
            result = await client.certify_decision({"test": True})

            mock_instance.post.assert_called_once()
            call_args = mock_instance.post.call_args
            assert call_args[0][0] == "https://api.nexart.io/v1/certifyDecision"
