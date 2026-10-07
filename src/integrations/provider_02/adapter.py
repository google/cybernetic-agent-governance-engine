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
adapter.py — LangGraph-to-Provider 02 Attestation Adapter (Feature 1)
=====================================================================

Emits Provider 02 ``certifyDecision`` CERs at governance-significant node boundaries
and assembles an ``AttestationBundle`` at graph completion — without modifying
any existing node logic.

Architecture
------------
Uses a **LangGraph callback handler** (not a checkpointer wrapper) that subscribes
to node lifecycle events.  This leaves the runtime engine completely stateless
and side-effect free with respect to attestation.

The adapter captures an **immutable deep copy** of ``AgentState`` at each node
boundary to protect against state leakage during conditional loop iterations
(execution_analyst → evaluator → execution_analyst) where state keys may be
modified destructively in place.

Graph Topology Mapping
----------------------
The Governed Financial Advisor graph has 4 terminal paths:

  1. **NeMo block**: nemo_guardrail → END (guardrail_blocked=True)
  2. **CBF fail-closed**: evaluator → safety_check(BLOCKED) → explainer → END
  3. **Loop breaker**: evaluator → explainer (loop_count ≥ 3) → END
  4. **Happy path**: nemo_guardrail → thinker → doer → execution_analyst → evaluator
     → safety_check → [HITL interrupt] → governed_trader → explainer → END

Each path produces a valid ``ProjectBundle`` with ``parentStepIds`` reflecting
the actual DAG traversal.

State commitments (``stateHash``)
---------------------------------
Provider 02 preserves and certificate-binds each step's ``stateHash`` as a
producer-supplied commitment; it never recomputes the preimage. So the
commitment is only verifiable if CAGE keeps the preimage. The adapter does not
hash or store anything itself: it stages a JSON-native snapshot per recorded
step and, in :meth:`Provider02AttestationCallback.seal`, sends each one to the
gateway's generic state-commitment service through an injected
:class:`~src.gateway.governance.seams.state_commitment.StateCommitter`
(``GatewayClient`` in production). The gateway PII-sanitizes the snapshot,
canonicalizes it once (RFC 8785 JCS), hashes it (SHA-256), appends the
sanitized preimage to its tamper-evident evidence chain and returns the
digest. The adapter writes that digest into the step together with the
method metadata (``stateHashAlg`` / ``stateHashCanon`` / ``stateHashScope``).
A bundle cannot be obtained until every step is committed, so a failed
commitment means no step — and no bundle — is emitted.

Environment variables
---------------------
  PROVIDER_02_ATTESTATION_ENABLED   — "true" to enable (default: "false")
  PROVIDER_02_API_ENDPOINT          — API base URL
  PROVIDER_02_API_KEY               — API key for authentication
  PROVIDER_02_ATTESTATION_TIMEOUT   — HTTP timeout in seconds (default: 5.0)
"""

from __future__ import annotations

import copy
import logging
import os
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.gateway.governance.evidence.state_commitment import json_native
from src.gateway.governance.seams.graph_topology import GraphTopology
from src.gateway.governance.seams.state_commitment import (
    STATE_COMMITMENT_METHOD,
    StateCommitmentError,
    StateCommitmentLinkage,
    StateCommitter,
)
from src.integrations.provider_02.governed_cer import (
    AttestationVerdict,
    topology_to_wire,
)

logger = logging.getLogger("cage.provider_02_adapter")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class Provider02Error(Exception):
    """Raised when Provider 02 API calls fail (fail-closed semantics)."""

    def __init__(self, message: str, code: str = "PROVIDER_02_ERROR") -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = (
    os.environ.get("PROVIDER_02_ATTESTATION_ENABLED", "false").lower() == "true"
)
_API_ENDPOINT: str = os.environ.get("PROVIDER_02_API_ENDPOINT", "")
_API_KEY: str = os.environ.get("PROVIDER_02_API_KEY", "")
_TIMEOUT: float = float(os.environ.get("PROVIDER_02_ATTESTATION_TIMEOUT", "5.0"))

#: Linkage namespace under which this adapter's state commitments are recorded.
STATE_COMMITMENT_NAMESPACE = "provider_02"


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class ProjectBundleStepEntry:
    """A single step in the Provider 02 Project Bundle DAG.

    Maps 1:1 to a LangGraph node execution snapshot. The ``parentStepIds``
    field captures the DAG edge from the preceding node.
    """

    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_name: str = ""
    parent_step_ids: list[str] = field(default_factory=list)
    timestamp_utc: str = ""
    duration_ms: float = 0.0
    signals: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Gateway-issued commitment: sha256 over the RFC 8785 JCS bytes of the
    # PII-sanitized snapshot (see STATE_COMMITMENT_METHOD). Empty until sealed.
    state_hash: str = ""

    def to_dict(self) -> dict:
        """Serialize to Provider 02 API-compatible dict."""
        return {
            "stepId": self.step_id,
            "nodeName": self.node_name,
            "parentStepIds": self.parent_step_ids,
            "timestampUtc": self.timestamp_utc,
            "durationMs": self.duration_ms,
            "signals": self.signals,
            "metadata": self.metadata,
            "stateHash": self.state_hash,
        }


@dataclass
class AttestationBundle:
    """A complete Project Bundle for a single graph execution.

    Assembled from all ``ProjectBundleStepEntry`` objects collected during
    a graph run, then sealed into a ``cer.governed.execution.v1`` CER and attested via
    Provider 02's ``POST /api/attest`` (see ``governed_cer.py``).
    """

    bundle_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    thread_id: str = ""
    steps: list[ProjectBundleStepEntry] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    terminal_path: str = (
        ""  # "happy_path" | "nemo_block" | "cbf_block" | "loop_breaker"
    )

    def to_dict(self) -> dict:
        """Serialize to Provider 02 API-compatible dict."""
        return {
            "bundleId": self.bundle_id,
            "threadId": self.thread_id,
            "steps": [s.to_dict() for s in self.steps],
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "terminalPath": self.terminal_path,
        }


# ---------------------------------------------------------------------------
# State serialization
# ---------------------------------------------------------------------------


def _serialize_state_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy and serialize an AgentState snapshot.

    Uses ``copy.deepcopy`` to protect against state mutation during
    conditional loop iterations (execution_analyst → evaluator) where
    LangGraph may modify state keys destructively in place.

    Fields containing non-serializable objects (BaseMessage instances)
    are converted to string representations.
    """
    # Deep copy to protect against state mutation
    snapshot = copy.deepcopy(state)

    # Convert BaseMessage list to serializable form
    messages = snapshot.get("messages", [])
    if messages:
        serialized_messages = []
        for msg in messages:
            if hasattr(msg, "content"):
                serialized_messages.append(
                    {
                        "type": getattr(msg, "type", "unknown"),
                        "content": str(msg.content)[:500],  # Truncate to prevent bloat
                    }
                )
            else:
                serialized_messages.append(str(msg)[:500])  # type: ignore[arg-type]
        snapshot["messages"] = serialized_messages

    # Remove non-serializable or sensitive fields
    snapshot.pop("completed_transactions", None)  # Saga ledger — handled in signals

    return snapshot


def _extract_signals(node_name: str, state: dict[str, Any]) -> dict[str, Any]:
    """Extract governance-significant signals from AgentState for a given node.

    Returns a dict of signals relevant to the Provider 02 CER for this node.
    """
    signals: dict[str, Any] = {}

    # Governance signature (gateway envelope signature stored by safety_check)
    if sig := state.get("governance_signature"):
        signals["governanceSignature"] = sig

    # Evaluation result
    if eval_result := state.get("evaluation_result"):
        signals["evaluationVerdict"] = eval_result.get("verdict")
        signals["evaluationReasoning"] = eval_result.get("reasoning")
        signals["policyCheck"] = eval_result.get("policy_check")

    # OPA results
    if opa := state.get("opa_results"):
        signals["policyResults"] = opa

    # Safety status
    if safety := state.get("safety_status"):
        signals["safetyStatus"] = safety

    # Risk status
    if risk := state.get("risk_status"):
        signals["riskStatus"] = risk

    # HITL approval
    if approval := state.get("approval_decision"):
        signals["hitlApproval"] = {
            "approved": approval.get("approved"),
            "reviewer": approval.get("reviewer"),
            "rationale": approval.get("rationale"),
            "timestamp": approval.get("timestamp"),
        }

    # Guardrail status
    if state.get("guardrail_blocked"):
        signals["guardrailBlocked"] = True
        signals["guardrailReason"] = state.get("guardrail_reason", "")

    # Loop count (for unrolled loop steps)
    if (lc := state.get("loop_count")) is not None:
        signals["loopCount"] = lc

    # Saga transaction ledger
    if txns := state.get("completed_transactions"):
        signals["sagaLedger"] = [
            {
                "sequenceId": t.get("sequence_id"),
                "action": t.get("action"),
                "status": t.get("status"),
                "ucaRef": t.get("uca_ref"),
            }
            for t in txns
        ]

    return signals


def _classify_terminal_path(
    steps: list[ProjectBundleStepEntry], topology: GraphTopology
) -> str:
    """Classify the terminal path from the collected steps.

    Uses a strict precedence ladder to determine the terminal path type:

    1. Priority 1 (Happy Path): Terminal node reached
    2. Priority 2 (CBF Invariant Block): CBF safety violation detected
    3. Priority 3 (Loop Breaker): Iteration limit or loop detection
    4. Priority 4 (Policy Block): NeMo guardrail or policy violation
    5. Priority 5 (Unknown): Unrecognized pattern (fail-closed)

    Args:
        steps: Collected graph execution steps
        topology: Graph topology defining terminal/interrupt nodes

    Returns:
        One of: "happy_path", "nemo_block", "cbf_block", "loop_breaker", "unknown"
    """
    node_names = [s.node_name for s in steps]

    # TC-ERR-03: Allow unrecognized nodes, return "unknown" instead of raising or misclassifying
    unrecognized = set(node_names) - topology.nodes
    if unrecognized:
        logger.warning(
            "[Provider02Adapter] Unrecognized nodes in traversal: %s. "
            "Known nodes: %s. Returning terminal_path='unknown'.",
            sorted(unrecognized),
            sorted(topology.nodes),
        )
        return "unknown"

    # Priority 1 (Happy Path): Terminal node was reached
    if topology.terminal_node in node_names:
        return "happy_path"

    # Priority 2 (CBF Invariant Block): Check for CBF safety violations
    for step in steps:
        # Check modern cbf_verdict signal (canonical convention)
        cbf_verdict = step.signals.get("cbf_verdict")
        if cbf_verdict in ("BLOCK", "BLOCKED"):
            return "cbf_block"

        # Fallback: Legacy safetyStatus signal (backward compatibility)
        if step.signals.get("safetyStatus") == "BLOCKED":
            return "cbf_block"

    # Priority 3 (Loop Breaker / Iteration Limit): Check for loop termination
    for step in steps:
        # Check explicit iteration_limit_reached signal
        if step.signals.get("iteration_limit_reached") is True:
            return "loop_breaker"

        # Check loop_breaker metadata flag
        if step.metadata.get("loop_breaker") is True:
            return "loop_breaker"

        # Check loopCount threshold (3+ iterations)
        if step.signals.get("loopCount", 0) >= 3:
            return "loop_breaker"

    # Fallback: Legacy topology pattern for loop detection
    # Pattern: evaluator → explainer path without reaching terminal (iteration limit)
    if "evaluator" in topology.nodes and "explainer" in topology.nodes:
        has_evaluator = "evaluator" in node_names
        has_explainer = "explainer" in node_names
        if has_evaluator and has_explainer:
            return "loop_breaker"

    # Priority 4 (Policy / NeMo Guardrail Block): Check for policy violations
    for step in steps:
        # Check explicit nemo_verdict signal
        nemo_verdict = step.signals.get("nemo_verdict")
        if nemo_verdict in ("BLOCK", "BLOCKED"):
            return "nemo_block"

    # Fallback: Legacy structural heuristic for early exit (NeMo block pattern)
    # Short traversal (≤2 nodes) indicates guardrail rejection at entry
    first_node = node_names[0] if node_names else None
    if len(node_names) <= 2 and first_node in topology.nodes:
        return "nemo_block"

    # Priority 5 (Unknown / Fail-Closed): Unrecognized pattern
    if node_names:
        logger.warning(
            "[Provider02Adapter] Unable to classify terminal path for nodes %s. "
            "Terminal node '%s' was not reached, and no recognized failure pattern matched. "
            "Returning terminal_path='unknown'.",
            node_names,
            topology.terminal_node,
        )

    return "unknown"


# ---------------------------------------------------------------------------
# Provider 02 Attestation Callback Handler
# ---------------------------------------------------------------------------


class LineageError(ValueError):
    """Raised when an executed edge is not legal under ``GraphTopology.parent_edges``.

    Fail-closed: the adapter refuses to emit a step whose lineage would cite a
    parent that is not a legal ``parentEdges`` candidate, or a predecessor that
    never executed in this run (NATIVE_SCHEMA_SPEC.md §4.1, rules 2-4).
    """


#: Pseudo-node name under which :meth:`Provider02AttestationCallback.handle_hitl_interrupt`
#: records the HITL pause. It is a step name in the Provider 02 native schema, so the
#: topology must declare it (``nodes`` + ``parent_edges``) for its edges to be legal.
HITL_INTERRUPT_STEP = "hitl_interrupt"


class Provider02AttestationCallback:
    """LangGraph callback handler that emits Provider 02 attestation CERs.

    Subscribes to node lifecycle events and captures immutable state snapshots
    at governance-significant node boundaries.

    Lineage (``parentStepIds``) records only **executed** relationships
    (NATIVE_SCHEMA_SPEC.md §4.1 "Possible vs. Actual Relationships"):

    - Every node event — recorded attestation node or not — has an *executed
      predecessor set*: by default the node that completed immediately before
      it (the edge actually taken). Each executed edge is validated against
      ``GraphTopology.parent_edges``; an illegal edge raises
      :class:`LineageError` (fail-closed).
    - Each node execution carries a *lineage*: ``[own step_id]`` for recorded
      steps, otherwise the lineage inherited over its executed edges. A recorded
      step's ``parentStepIds`` is the deduplicated union of its executed
      predecessors' lineages, i.e. executed edges contracted back to the nearest
      recorded steps. Static reachability is never consulted, so a legal-but-
      unexecuted parent can never appear.
    - Loops unroll naturally: each iteration inherits the lineage of the
      iteration that actually preceded it.

    Sequential-event assumption: the callback receives node events in
    completion order, one node at a time (the Governed Financial Advisor graph
    has no parallel branches). Genuine fan-in after parallel branches cannot be
    inferred from a sequential stream; callers declare it by passing
    ``executed_predecessors=[...]`` to :meth:`on_chain_end`, and every declared
    predecessor's lineage is included.

    Args:
        topology: Graph topology defining nodes, edges, terminal/interrupt nodes
        committer: Gateway state-commitment client (``GatewayClient`` in
            production). Required: a step's ``stateHash`` is only ever the
            gateway's receipt for a retained preimage.
        thread_id: Unique thread identifier (generated if not provided). Must
            match ``LINKAGE_ID_PATTERN`` or sealing fails closed.

    Raises:
        TypeError: If topology or committer is not provided.

    Usage::

        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY

        callback = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            committer=GatewayClient(),
            thread_id="thread-123",
        )
        # Pass to LangGraph invoke/stream as a callback
        graph.invoke(input, config={"callbacks": [callback]})

        # After graph completion: commit every staged snapshot, then submit.
        await submit_attested_bundle(callback, Provider02AttestationProvider())
    """

    def __init__(
        self,
        topology: GraphTopology,
        *,
        committer: StateCommitter,
        thread_id: str = "",
    ) -> None:
        self._topology = topology
        self._committer = committer
        self._thread_id = thread_id or str(uuid.uuid4())
        self._bundle_id = str(uuid.uuid4())
        self._steps: list[ProjectBundleStepEntry] = []
        # Steps whose snapshot has not yet been committed by the gateway.
        self._pending: list[tuple[ProjectBundleStepEntry, dict[str, Any]]] = []
        # node_name → lineage of its most recent execution (nearest recorded step ids)
        self._lineage_by_node: dict[str, tuple[str, ...]] = {}
        # node that completed most recently (the default executed predecessor)
        self._last_completed: str | None = None
        self._node_start_times: dict[str, float] = {}
        self._started_at = time.time()
        self._started_at_utc = ""

    def on_chain_start(
        self,
        node_name: str,
        state: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when a LangGraph node begins execution.

        Records the start time for duration calculation.
        """
        self._node_start_times[node_name] = time.monotonic()
        if not self._started_at_utc:
            from datetime import datetime, timezone

            self._started_at_utc = datetime.now(tz=timezone.utc).isoformat()

    def on_chain_end(
        self,
        node_name: str,
        state: dict[str, Any],
        *,
        executed_predecessors: Sequence[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangGraph node completes execution.

        Every node event advances the executed-edge lineage. For
        governance-significant nodes, also captures an immutable state snapshot
        and creates a ProjectBundleStepEntry.

        Args:
            node_name: The node that completed.
            state: The AgentState at the node boundary.
            executed_predecessors: Nodes that actually fed this execution. Defaults
                to the node that completed immediately before (sequential
                execution); pass several names only for genuine fan-in.

        Raises:
            LineageError: If an executed edge is illegal under ``parent_edges``.
        """
        parent_step_ids = self._resolve_executed_parents(
            node_name, executed_predecessors
        )
        start_time = self._node_start_times.pop(node_name, time.monotonic())

        if node_name not in self._topology.attestation_nodes:
            # Unrecorded node: pass its executed lineage through unchanged.
            self._advance(node_name, tuple(parent_step_ids))
            return

        step = self._record_step(
            node_name,
            state,
            parent_step_ids,
            signals=_extract_signals(node_name, state),
            metadata={
                "loopIteration": state.get("loop_count"),
                "threadId": self._thread_id,
            },
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

        logger.debug(
            "[Provider02Adapter] Step recorded: node=%s step_id=%s parents=%s signals=%d",
            node_name,
            step.step_id[:8],
            [p[:8] for p in parent_step_ids],
            len(step.signals),
        )

    def _resolve_executed_parents(
        self, node_name: str, executed_predecessors: Sequence[str] | None
    ) -> list[str]:
        """Contract executed edges into ``node_name`` back to the nearest recorded steps.

        Args:
            node_name: The node whose execution is being recorded.
            executed_predecessors: Explicit executed predecessors, or ``None`` to
                use the node that completed immediately before.

        Returns:
            Deduplicated, order-preserving list of recorded ancestor step ids.
            Empty when no predecessor executed in this run (root of the
            observed execution).

        Raises:
            LineageError: If a predecessor never executed in this run, or an
                executed edge is not a legal ``parent_edges`` candidate.
        """
        if executed_predecessors is None:
            preds: tuple[str, ...] = (
                () if self._last_completed is None else (self._last_completed,)
            )
        else:
            preds = tuple(executed_predecessors)

        legal_parents = self._topology.parent_edges.get(node_name, [])
        lineage: dict[str, None] = {}
        for pred in preds:
            if pred not in self._lineage_by_node:
                raise LineageError(
                    f"Executed predecessor {pred!r} of {node_name!r} has not "
                    f"executed in this run; refusing to record unexecuted lineage."
                )
            if pred not in legal_parents:
                raise LineageError(
                    f"Illegal executed edge {pred!r} -> {node_name!r}: not a "
                    f"parent_edges candidate (legal parents: {sorted(legal_parents)})."
                )
            for step_id in self._lineage_by_node[pred]:
                lineage[step_id] = None
        return list(lineage)

    def _advance(self, node_name: str, lineage: tuple[str, ...]) -> None:
        """Mark ``node_name`` as the most recently completed node with ``lineage``."""
        self._lineage_by_node[node_name] = lineage
        self._last_completed = node_name

    def _record_step(
        self,
        node_name: str,
        state: dict[str, Any],
        parent_step_ids: list[str],
        *,
        signals: dict[str, Any],
        metadata: dict[str, Any],
        duration_ms: float = 0.0,
    ) -> ProjectBundleStepEntry:
        """Append a recorded step and make it the lineage of ``node_name``.

        The step's snapshot is staged (deep-copied, JSON-native) for
        :meth:`seal`; its ``stateHash`` stays empty until the gateway commits it.
        """
        from datetime import datetime, timezone

        # Deep-copy state to protect against mutation during loops
        snapshot = json_native(_serialize_state_snapshot(state))
        step = ProjectBundleStepEntry(
            node_name=node_name,
            parent_step_ids=parent_step_ids,
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            duration_ms=duration_ms,
            signals=signals,
            metadata=metadata,
        )
        self._steps.append(step)
        self._pending.append((step, snapshot))
        self._advance(node_name, (step.step_id,))
        return step

    async def seal(self) -> None:
        """Commit every staged snapshot through the gateway, in step order.

        For each pending step the gateway sanitizes, canonicalizes, hashes and
        retains the snapshot; its receipt supplies the step's ``stateHash`` and
        the method metadata (:data:`STATE_COMMITMENT_METHOD`) is merged into
        the step's ``metadata``. A step leaves the pending set only after its
        receipt validates, so a partial failure can be retried.

        Raises:
            StateCommitmentError: A commitment failed or returned a receipt
                that does not match the expected method. The bundle stays
                unsealed and :meth:`get_bundle` keeps refusing.
        """
        while self._pending:
            step, snapshot = self._pending[0]
            linkage = StateCommitmentLinkage(
                namespace=STATE_COMMITMENT_NAMESPACE,
                bundle_id=self._bundle_id,
                step_id=step.step_id,
                thread_id=self._thread_id,
                label=step.node_name,
            )
            receipt = await self._committer.commit_state(snapshot, linkage=linkage)
            receipt.validate()
            step.state_hash = receipt.state_hash
            step.metadata.update(STATE_COMMITMENT_METHOD)
            self._pending.pop(0)

    @property
    def is_sealed(self) -> bool:
        """True when every recorded step carries a gateway-issued ``stateHash``."""
        return not self._pending

    def handle_hitl_interrupt(
        self,
        state: dict[str, Any],
        *,
        executed_predecessors: Sequence[str] | None = None,
    ) -> None:
        """Record the HITL interrupt as an executed, paused DAG step.

        The pause is treated as one more executed node (``hitl_interrupt``): its
        parents are resolved over the executed edge into it, and the node that
        resumes after approval inherits it as its executed predecessor. The
        approval_decision field captures the reviewer's identity, rationale,
        and timestamp per ISO 42001 A.7.2.

        Raises:
            LineageError: If the topology does not declare the executed edge
                into ``hitl_interrupt``.
        """
        parent_step_ids = self._resolve_executed_parents(
            HITL_INTERRUPT_STEP, executed_predecessors
        )

        signals: dict[str, Any] = {}
        if approval := state.get("approval_decision"):
            signals["hitlApproval"] = {
                "approved": approval.get("approved"),
                "reviewer": approval.get("reviewer"),
                "rationale": approval.get("rationale"),
                "timestamp": approval.get("timestamp"),
            }
        signals["interruptType"] = "HITL_MANUAL_REVIEW"
        signals["approvalRequired"] = state.get("approval_required", False)

        interrupt_node = self._topology.interrupt_node or self._topology.terminal_node
        step = self._record_step(
            HITL_INTERRUPT_STEP,
            state,
            parent_step_ids,
            signals=signals,
            metadata={
                "threadId": self._thread_id,
                "interruptNode": interrupt_node,
            },
        )
        logger.info(
            "[Provider02Adapter] HITL interrupt recorded: step_id=%s (commitment pending)",
            step.step_id[:8],
        )

    def get_bundle(self) -> AttestationBundle:
        """Assemble all collected steps into a Project Bundle.

        Call this after graph execution completes and :meth:`seal` succeeded.

        Raises:
            StateCommitmentError: Some step has no committed ``stateHash`` yet.
        """
        from datetime import datetime, timezone

        if self._pending:
            raise StateCommitmentError(
                f"{len(self._pending)} step(s) have no committed stateHash; "
                "call seal() before get_bundle()"
            )
        terminal_path = _classify_terminal_path(self._steps, self._topology)

        return AttestationBundle(
            bundle_id=self._bundle_id,
            thread_id=self._thread_id,
            steps=list(self._steps),
            started_at=self._started_at_utc,
            completed_at=datetime.now(tz=timezone.utc).isoformat(),
            terminal_path=terminal_path,
        )

    @property
    def topology(self) -> GraphTopology:
        """The graph topology this callback enforces lineage against."""
        return self._topology

    @property
    def step_count(self) -> int:
        """Number of steps recorded so far."""
        return len(self._steps)


class BundleAttestor(Protocol):
    """Attests a serialized ``AttestationBundle`` and verifies the receipt.

    Implemented by ``Provider02AttestationProvider.attest_bundle``.
    """

    async def attest_bundle(
        self,
        bundle: Mapping[str, Any],
        topology: Mapping[str, Any] | None = None,
    ) -> AttestationVerdict: ...


async def submit_attested_bundle(
    callback: Provider02AttestationCallback,
    attestor: BundleAttestor,
    *,
    include_topology: bool = False,
) -> AttestationVerdict:
    """Seal ``callback``'s steps through the gateway, then attest the bundle.

    This is the single submit path: commitments always precede attestation,
    so Provider 02 never receives a ``stateHash`` whose preimage is not
    retained in the evidence chain.

    ``include_topology`` defaults to False: the attestation node currently
    rejects topologies containing a cycle (``TOPOLOGY_ERROR``), and the
    financial-advisor graph has an ``execution_analyst`` <-> ``evaluator``
    loop. CAGE's own lineage checks (``LineageError``) still enforce the
    topology locally before anything is submitted.

    Raises:
        StateCommitmentError: A state commitment failed; nothing was submitted.
        Provider02Error: The bundle was not attested, or CAGE could not verify
            the node's signed receipt (``code="ATTESTATION_REJECTED"``).
    """
    await callback.seal()
    bundle = callback.get_bundle()
    topology = topology_to_wire(callback.topology) if include_topology else None
    verdict = await attestor.attest_bundle(bundle.to_dict(), topology)
    if not verdict.verified:
        raise Provider02Error(
            f"bundle {bundle.bundle_id} not attested: {verdict.code}: {verdict.error}",
            code="ATTESTATION_REJECTED",
        )
    return verdict


# ---------------------------------------------------------------------------
# Provider 02 HTTP Client (raw httpx.AsyncClient)
# ---------------------------------------------------------------------------


class Provider02Client:
    """HTTP client for the Provider 02 attestation API.

    Built against the raw HTTP API (not a SDK wrapper) for supply-chain
    control and FIPS compliance tracking. Follows the same httpx.AsyncClient
    pattern as normative_provider.py Provider01NormativeProvider.

    Environment variables:
        PROVIDER_02_API_ENDPOINT        — Base URL (required)
        PROVIDER_02_API_KEY             — API key for Bearer auth
        PROVIDER_02_ATTESTATION_TIMEOUT — HTTP timeout in seconds (default: 5.0)
        PROVIDER_02_CLIENT_CERT         — Path to client certificate for mTLS (optional)
        PROVIDER_02_CLIENT_KEY          — Path to client private key for mTLS (optional)
        PROVIDER_02_CA_BUNDLE           — Path to CA bundle for server verification (optional)
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _TIMEOUT,
    ) -> None:
        self._endpoint = (endpoint or _API_ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY
        self._timeout = timeout

        # mTLS configuration
        self._client_cert = os.getenv("PROVIDER_02_CLIENT_CERT", "")
        self._client_key = os.getenv("PROVIDER_02_CLIENT_KEY", "")
        self._ca_bundle = os.getenv("PROVIDER_02_CA_BUNDLE", "")

        if not self._endpoint:
            logger.warning(
                "[Provider02Client] PROVIDER_02_API_ENDPOINT not set. "
                "Attestation calls will fail. Set PROVIDER_02_ATTESTATION_ENABLED=false "
                "to suppress this warning."
            )

    def _build_httpx_kwargs(self) -> dict[str, Any]:
        """Build httpx.AsyncClient configuration with optional mTLS."""
        kwargs: dict[str, Any] = {"timeout": self._timeout}

        # mTLS client certificate
        if self._client_cert and self._client_key:
            kwargs["cert"] = (self._client_cert, self._client_key)
            logger.debug(
                "[Provider02Client] mTLS enabled: cert=%s key=%s",
                self._client_cert,
                self._client_key,
            )

        # Server verification (CA bundle or system trust)
        if self._ca_bundle:
            kwargs["verify"] = self._ca_bundle
            logger.debug("[Provider02Client] Custom CA bundle: %s", self._ca_bundle)
        else:
            kwargs["verify"] = True  # Use system trust store

        return kwargs

    def _headers(self) -> dict[str, str]:
        """Authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def certify_decision(self, evidence_record: dict[str, Any]) -> dict[str, Any]:
        """Submit a governance decision for Provider 02 CER certification.

        Args:
            evidence_record: The governance decision payload (signals + state hash).

        Returns:
            CER response dict with ``certificateHash`` and ``receipt``.

        Raises:
            Provider02Error: On any HTTP or network failure (fail-closed).
        """
        import httpx

        url = f"{self._endpoint}/certifyDecision"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.post(
                    url, json=evidence_record, headers=self._headers()
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider02] certify_decision HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            raise Provider02Error(
                f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                code="ENDPOINT_ERROR",
            ) from exc
        except httpx.RequestError as exc:
            logger.error("[Provider02] certify_decision request error: %s %s", url, exc)
            raise Provider02Error(str(exc), code="ENDPOINT_ERROR") from exc
        except Exception as exc:
            logger.error("[Provider02] certify_decision unexpected error: %s", exc)
            raise Provider02Error(
                f"Unexpected error: {exc}", code="ENDPOINT_ERROR"
            ) from exc

    async def verify_cer(self, certificate_hash: str) -> dict[str, Any]:
        """Verify a CER against Provider 02's public JWK set.

        Args:
            certificate_hash: The CER hash to verify.

        Returns:
            Verification result with ``valid``, ``signer``, ``timestamp``.

        Raises:
            Provider02Error: On any HTTP or network failure (fail-closed).
        """
        import httpx

        url = f"{self._endpoint}/verify/{certificate_hash}"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider02] verify_cer HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            raise Provider02Error(
                f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                code="ENDPOINT_ERROR",
            ) from exc
        except httpx.RequestError as exc:
            logger.error("[Provider02] verify_cer request error: %s %s", url, exc)
            raise Provider02Error(str(exc), code="ENDPOINT_ERROR") from exc
        except Exception as exc:
            logger.error("[Provider02] verify_cer unexpected error: %s", exc)
            raise Provider02Error(
                f"Unexpected error: {exc}", code="ENDPOINT_ERROR"
            ) from exc
