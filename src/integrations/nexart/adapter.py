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
nexart_adapter.py — LangGraph-to-NexArt Attestation Adapter (Feature 1)
========================================================================

Emits NexArt ``certifyDecision`` CERs at governance-significant node boundaries
and assembles a ``registerProjectBundle`` at graph completion — without modifying
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

Environment variables
---------------------
  NEXART_ATTESTATION_ENABLED   — "true" to enable (default: "false")
  NEXART_API_ENDPOINT          — NexArt API base URL
  NEXART_API_KEY               — API key for authentication
  NEXART_ATTESTATION_TIMEOUT   — HTTP timeout in seconds (default: 5.0)
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("cage.nexart_adapter")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = (
    os.environ.get("NEXART_ATTESTATION_ENABLED", "false").lower() == "true"
)
_API_ENDPOINT: str = os.environ.get("NEXART_API_ENDPOINT", "")
_API_KEY: str = os.environ.get("NEXART_API_KEY", "")
_TIMEOUT: float = float(os.environ.get("NEXART_ATTESTATION_TIMEOUT", "5.0"))

# Governance-significant nodes that trigger CER emission
_ATTESTATION_NODES = frozenset({
    "nemo_guardrail",
    "evaluator",
    "safety_check",
    "governed_trader",
    "explainer",
    "nemo_output_rail",
})

# Graph topology — maps each node to its possible parent nodes
# Derived from graph.py conditional edges
_GRAPH_PARENTS: dict[str, list[str]] = {
    "nemo_guardrail":  [],  # entry point
    "thinker_node":    ["nemo_guardrail"],
    "doer_node":       ["thinker_node"],
    "data_analyst":    ["doer_node"],
    "execution_analyst": ["doer_node", "evaluator"],  # loop source
    "evaluator":       ["execution_analyst"],
    "safety_check":    ["evaluator"],
    "governed_trader": ["safety_check"],
    "explainer":       ["governed_trader", "evaluator", "safety_check"],
    "nemo_output_rail": ["data_analyst", "explainer"],
}


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class ProjectBundleStepEntry:
    """A single step in the NexArt Project Bundle DAG.

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
    state_hash: str = ""  # SHA-256 of the serialized AgentState snapshot

    def to_dict(self) -> dict:
        """Serialize to NexArt API-compatible dict."""
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
    a graph run, then submitted to NexArt's ``registerProjectBundle`` endpoint.
    """

    bundle_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    thread_id: str = ""
    steps: list[ProjectBundleStepEntry] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    terminal_path: str = ""  # "happy_path" | "nemo_block" | "cbf_block" | "loop_breaker"

    def to_dict(self) -> dict:
        """Serialize to NexArt API-compatible dict."""
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
                serialized_messages.append({
                    "type": getattr(msg, "type", "unknown"),
                    "content": str(msg.content)[:500],  # Truncate to prevent bloat
                })
            else:
                serialized_messages.append(str(msg)[:500])
        snapshot["messages"] = serialized_messages

    # Remove non-serializable or sensitive fields
    snapshot.pop("completed_transactions", None)  # Saga ledger — handled in signals

    return snapshot


def _hash_state(state: dict[str, Any]) -> str:
    """SHA-256 hash of a serialized state snapshot."""
    canonical = json.dumps(state, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _extract_signals(node_name: str, state: dict[str, Any]) -> dict[str, Any]:
    """Extract governance-significant signals from AgentState for a given node.

    Returns a dict of signals relevant to the NexArt CER for this node.
    """
    signals: dict[str, Any] = {}

    # Governance signature (evaluator node)
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


def _classify_terminal_path(steps: list[ProjectBundleStepEntry]) -> str:
    """Classify the terminal path from the collected steps.

    Returns one of: "happy_path", "nemo_block", "cbf_block", "loop_breaker"
    """
    node_names = [s.node_name for s in steps]

    if "governed_trader" in node_names:
        return "happy_path"

    if len(node_names) <= 2 and "nemo_guardrail" in node_names:
        return "nemo_block"

    # Check for safety_check BLOCKED signal
    for step in steps:
        if step.node_name == "safety_check" and step.signals.get("safetyStatus") == "BLOCKED":
            return "cbf_block"

    # Check for loop breaker (evaluator → explainer without safety_check)
    if "evaluator" in node_names and "explainer" in node_names and "safety_check" not in node_names:
        return "loop_breaker"

    # Check loop count
    for step in steps:
        if step.signals.get("loopCount", 0) >= 3:
            return "loop_breaker"

    return "unknown"


# ---------------------------------------------------------------------------
# NexArt Attestation Callback Handler
# ---------------------------------------------------------------------------


class NexArtAttestationCallback:
    """LangGraph callback handler that emits NexArt attestation CERs.

    Subscribes to node lifecycle events and captures immutable state snapshots
    at governance-significant node boundaries.

    Usage::

        callback = NexArtAttestationCallback(thread_id="thread-123")
        # Pass to LangGraph invoke/stream as a callback
        graph.invoke(input, config={"callbacks": [callback]})

        # After graph completion:
        bundle = callback.get_bundle()
    """

    def __init__(self, thread_id: str = "") -> None:
        self._thread_id = thread_id or str(uuid.uuid4())
        self._steps: list[ProjectBundleStepEntry] = []
        self._step_id_by_node: dict[str, str] = {}  # node_name → last step_id
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
        **kwargs: Any,
    ) -> None:
        """Called when a LangGraph node completes execution.

        For governance-significant nodes, captures an immutable state snapshot
        and creates a ProjectBundleStepEntry.
        """
        if node_name not in _ATTESTATION_NODES:
            # Still track step IDs for parent resolution
            step_id = str(uuid.uuid4())
            self._step_id_by_node[node_name] = step_id
            return

        from datetime import datetime, timezone

        start_time = self._node_start_times.pop(node_name, time.monotonic())
        duration_ms = (time.monotonic() - start_time) * 1000

        # Deep-copy state to protect against mutation during loops
        state_snapshot = _serialize_state_snapshot(state)
        state_hash = _hash_state(state_snapshot)

        # Build parent step IDs from graph topology
        parent_step_ids = self._build_parent_step_ids(node_name)

        # Extract governance signals
        signals = _extract_signals(node_name, state)

        step = ProjectBundleStepEntry(
            node_name=node_name,
            parent_step_ids=parent_step_ids,
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            duration_ms=duration_ms,
            signals=signals,
            metadata={
                "loopIteration": state.get("loop_count"),
                "threadId": self._thread_id,
            },
            state_hash=state_hash,
        )

        self._steps.append(step)
        self._step_id_by_node[node_name] = step.step_id

        logger.debug(
            "[NexArtAdapter] Step recorded: node=%s step_id=%s parents=%s signals=%d",
            node_name,
            step.step_id[:8],
            [p[:8] for p in parent_step_ids],
            len(signals),
        )

    def _build_parent_step_ids(self, node_name: str) -> list[str]:
        """Resolve parent step IDs from the graph topology.

        Looks up the possible parents for this node in _GRAPH_PARENTS and
        returns the step IDs of parents that were actually executed in this run.
        """
        possible_parents = _GRAPH_PARENTS.get(node_name, [])
        parent_ids = []
        for parent in possible_parents:
            if parent in self._step_id_by_node:
                parent_ids.append(self._step_id_by_node[parent])
        return parent_ids

    def handle_hitl_interrupt(self, state: dict[str, Any]) -> None:
        """Explicitly record the HITL interrupt as a paused DAG step.

        Called when the graph is interrupted before governed_trader.
        The approval_decision field captures the reviewer's identity,
        rationale, and timestamp per ISO 42001 A.7.2.
        """
        from datetime import datetime, timezone

        signals = {}
        if approval := state.get("approval_decision"):
            signals["hitlApproval"] = {
                "approved": approval.get("approved"),
                "reviewer": approval.get("reviewer"),
                "rationale": approval.get("rationale"),
                "timestamp": approval.get("timestamp"),
            }
        signals["interruptType"] = "HITL_MANUAL_REVIEW"
        signals["approvalRequired"] = state.get("approval_required", False)

        step = ProjectBundleStepEntry(
            node_name="hitl_interrupt",
            parent_step_ids=self._build_parent_step_ids("governed_trader"),
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            signals=signals,
            metadata={
                "threadId": self._thread_id,
                "interruptNode": "governed_trader",
            },
        )

        self._steps.append(step)
        self._step_id_by_node["hitl_interrupt"] = step.step_id
        logger.info(
            "[NexArtAdapter] HITL interrupt recorded: step_id=%s",
            step.step_id[:8],
        )

    def get_bundle(self) -> AttestationBundle:
        """Assemble all collected steps into a Project Bundle.

        Call this after graph execution completes.
        """
        from datetime import datetime, timezone

        terminal_path = _classify_terminal_path(self._steps)

        return AttestationBundle(
            thread_id=self._thread_id,
            steps=list(self._steps),
            started_at=self._started_at_utc,
            completed_at=datetime.now(tz=timezone.utc).isoformat(),
            terminal_path=terminal_path,
        )

    @property
    def step_count(self) -> int:
        """Number of steps recorded so far."""
        return len(self._steps)


# ---------------------------------------------------------------------------
# NexArt HTTP Client (raw httpx.AsyncClient)
# ---------------------------------------------------------------------------


class NexArtClient:
    """HTTP client for the NexArt attestation API.

    Built against the raw HTTP API (not a SDK wrapper) for supply-chain
    control and FIPS compliance tracking. Follows the same httpx.AsyncClient
    pattern as normative_provider.py TrustLayersProvider.

    Environment variables:
        NEXART_API_ENDPOINT   — Base URL (required)
        NEXART_API_KEY        — API key for Bearer auth
        NEXART_ATTESTATION_TIMEOUT — HTTP timeout in seconds (default: 5.0)
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

        if not self._endpoint:
            logger.warning(
                "[NexArtClient] NEXART_API_ENDPOINT not set. "
                "Attestation calls will fail. Set NEXART_ATTESTATION_ENABLED=false "
                "to suppress this warning."
            )

    def _headers(self) -> dict[str, str]:
        """Authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def certify_decision(
        self, evidence_record: dict[str, Any]
    ) -> dict[str, Any]:
        """Submit a governance decision for NexArt CER certification.

        Args:
            evidence_record: The governance decision payload (signals + state hash).

        Returns:
            CER response dict with ``certificateHash`` and ``receipt``.

        Raises:
            httpx.HTTPStatusError: On non-2xx response.
            httpx.TimeoutException: On timeout.
        """
        import httpx

        url = f"{self._endpoint}/certifyDecision"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url, json=evidence_record, headers=self._headers()
            )
            resp.raise_for_status()
            return resp.json()

    async def register_project_bundle(
        self, bundle: dict[str, Any]
    ) -> dict[str, Any]:
        """Register a completed Project Bundle with NexArt.

        Args:
            bundle: The serialized AttestationBundle dict.

        Returns:
            Registration response with ``bundleHash`` and ``receiptUrl``.
        """
        import httpx

        url = f"{self._endpoint}/registerProjectBundle"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url, json=bundle, headers=self._headers()
            )
            resp.raise_for_status()
            return resp.json()

    async def verify_cer(self, certificate_hash: str) -> dict[str, Any]:
        """Verify a CER against NexArt's public JWK set.

        Args:
            certificate_hash: The CER hash to verify.

        Returns:
            Verification result with ``valid``, ``signer``, ``timestamp``.
        """
        import httpx

        url = f"{self._endpoint}/verify/{certificate_hash}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            return resp.json()
