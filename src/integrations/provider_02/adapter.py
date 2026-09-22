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
  PROVIDER_02_ATTESTATION_ENABLED   — "true" to enable (default: "false")
  PROVIDER_02_API_ENDPOINT          — API base URL
  PROVIDER_02_API_KEY               — API key for authentication
  PROVIDER_02_ATTESTATION_TIMEOUT   — HTTP timeout in seconds (default: 5.0)
"""

from __future__ import annotations

import copy
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.graph_topology import GraphTopology

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
    state_hash: str = ""  # SHA-256 of the serialized AgentState snapshot

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
    a graph run, then submitted to Provider 02's ``registerProjectBundle`` endpoint.
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


def _hash_state(state: dict[str, Any]) -> str:
    """SHA-256 hash of a serialized state snapshot.

    v3.1.0: Migrated to RFC 8785 JCS with pre-normalization.
    """
    # Pre-normalize datetime/Decimal (default=str was used)
    from datetime import datetime

    def _normalize(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return str(obj)
        elif isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [_normalize(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return str(obj)

    normalized = _normalize(state)
    canonical_bytes = jcs_canonicalize_plan(normalized)
    return hashlib.sha256(canonical_bytes).hexdigest()


def _extract_signals(node_name: str, state: dict[str, Any]) -> dict[str, Any]:
    """Extract governance-significant signals from AgentState for a given node.

    Returns a dict of signals relevant to the Provider 02 CER for this node.
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


class Provider02AttestationCallback:
    """LangGraph callback handler that emits Provider 02 attestation CERs.

    Subscribes to node lifecycle events and captures immutable state snapshots
    at governance-significant node boundaries.

    Args:
        topology: Graph topology defining nodes, edges, terminal/interrupt nodes
        thread_id: Unique thread identifier (generated if not provided)

    Raises:
        TypeError: If topology is not provided (required parameter)

    Usage::

        from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY

        callback = Provider02AttestationCallback(
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="thread-123"
        )
        # Pass to LangGraph invoke/stream as a callback
        graph.invoke(input, config={"callbacks": [callback]})

        # After graph completion:
        bundle = callback.get_bundle()
    """

    def __init__(self, topology: GraphTopology, thread_id: str = "") -> None:
        self._topology = topology
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
        if node_name not in self._topology.attestation_nodes:
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
            "[Provider02Adapter] Step recorded: node=%s step_id=%s parents=%s signals=%d",
            node_name,
            step.step_id[:8],
            [p[:8] for p in parent_step_ids],
            len(signals),
        )

    def _build_parent_step_ids(self, node_name: str) -> list[str]:
        """Resolve parent step IDs from the graph topology with ancestor contraction.

        If an immediate parent is not an attestation node (not present in self._steps),
        traverses upstream recursively through parent edges until finding the nearest
        recorded ancestor nodes.

        Args:
            node_name: The node name to build parent IDs for

        Returns:
            Deduplicated list of step IDs from recorded ancestor nodes

        Raises:
            ValueError: If infinite recursion is detected during ancestor traversal
        """
        # Dynamic binding: enforce causal parentage when resuming past an interruption
        if (
            node_name == self._topology.interrupt_node
            and "hitl_interrupt" in self._step_id_by_node
        ):
            return [self._step_id_by_node["hitl_interrupt"]]

        def _find_recorded_ancestors(
            current_node: str, visited: set[str], target_node: str
        ) -> list[str]:
            """Recursively find recorded ancestors, with cycle detection.

            Cycle detection only triggers if we visit the same unrecorded node twice
            in a single path, indicating infinite traversal. Topological cycles in
            the graph (like execution_analyst -> evaluator -> execution_analyst) are
            allowed if at least one node in the cycle is recorded.

            Args:
                current_node: The node being examined
                visited: Set of nodes visited in this traversal path
                target_node: The node we're building parents for (cannot be its own ancestor)
            """
            # Check if this node is an attestation node that has been recorded.
            # _step_id_by_node tracks ALL nodes (attestation and non-attestation),
            # but only attestation nodes are actually recorded in self._steps.
            # We must return the step_id ONLY for attestation nodes.
            # For unrolled loops, if target_node itself was recorded in a prior
            # iteration, that prior iteration is a valid sequential ancestor.
            if (
                current_node in self._topology.attestation_nodes
                and current_node in self._step_id_by_node
            ):
                return [self._step_id_by_node[current_node]]

            # Boundary condition: if we've reached the target node during traversal
            # and it has not been recorded previously (e.g. first iteration),
            # stop (a node cannot be its own ancestor on first execution).
            # This naturally breaks cycles that include the unrecorded target node.
            if current_node == target_node:
                return []

            # Node is not recorded. Check for traversal cycle (infinite loop).
            # This prevents infinite recursion when traversing through unrecorded nodes.
            if current_node in visited:
                raise ValueError(
                    f"Cycle detected in graph topology at node {current_node!r}. "
                    f"Visited path: {sorted(visited)}. "
                    f"All nodes in this cycle are unrecorded (not attestation nodes), "
                    f"creating infinite traversal."
                )

            visited.add(current_node)

            # Traverse upstream to find recorded ancestors
            possible_parents = self._topology.parent_edges.get(current_node, [])
            if not possible_parents:
                # No parents; this is a root node that wasn't recorded
                return []

            # Recursively collect ancestors from all parents
            ancestor_ids = []
            for parent in possible_parents:
                # Create a new visited set for each branch to allow DAG convergence
                branch_visited = visited.copy()
                ancestor_ids.extend(
                    _find_recorded_ancestors(parent, branch_visited, target_node)
                )

            return ancestor_ids

        # Start the search from the immediate parents of the target node
        possible_parents = self._topology.parent_edges.get(node_name, [])
        all_ancestor_ids = []

        for parent in possible_parents:
            visited: set[str] = set()
            all_ancestor_ids.extend(
                _find_recorded_ancestors(parent, visited, node_name)
            )

        # Deduplicate while preserving order
        seen: dict[str, None] = {}
        for step_id in all_ancestor_ids:
            seen[step_id] = None

        return list(seen.keys())

    def handle_hitl_interrupt(self, state: dict[str, Any]) -> None:
        """Explicitly record the HITL interrupt as a paused DAG step.

        Called when the graph is interrupted at the configured interrupt node.
        The approval_decision field captures the reviewer's identity,
        rationale, and timestamp per ISO 42001 A.7.2.
        """
        from datetime import datetime, timezone

        # Serialize state snapshot and compute RFC 8785 deterministic hash
        state_snapshot = _serialize_state_snapshot(state)
        state_hash = _hash_state(state_snapshot)

        signals = {}
        if approval := state.get("approval_decision"):
            signals["hitlApproval"] = {
                "approved": approval.get("approved"),
                "reviewer": approval.get("reviewer"),
                "rationale": approval.get("rationale"),
                "timestamp": approval.get("timestamp"),
            }
        signals["interruptType"] = "HITL_MANUAL_REVIEW"  # type: ignore[assignment]
        signals["approvalRequired"] = state.get("approval_required", False)

        interrupt_node = self._topology.interrupt_node or self._topology.terminal_node

        # Resolve parent step IDs with explicit awareness of "hitl_interrupt" in parent_edges
        parent_step_ids = (
            self._build_parent_step_ids("hitl_interrupt")
            if "hitl_interrupt" in self._topology.parent_edges
            else self._build_parent_step_ids(interrupt_node)
        )

        step = ProjectBundleStepEntry(
            node_name="hitl_interrupt",
            parent_step_ids=parent_step_ids,
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            signals=signals,
            metadata={
                "threadId": self._thread_id,
                "interruptNode": interrupt_node,
            },
            state_hash=state_hash,
        )

        self._steps.append(step)
        self._step_id_by_node["hitl_interrupt"] = step.step_id
        logger.info(
            "[Provider02Adapter] HITL interrupt recorded: step_id=%s state_hash=%s",
            step.step_id[:8],
            state_hash[:8],
        )

    def get_bundle(self) -> AttestationBundle:
        """Assemble all collected steps into a Project Bundle.

        Call this after graph execution completes.
        """
        from datetime import datetime, timezone

        terminal_path = _classify_terminal_path(self._steps, self._topology)

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
        PROVIDER_02_INGEST_PATH         — Bundle ingestion endpoint path (default: /v1/governance/bundles)
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

        # Configurable ingestion endpoint with fallback
        self._ingest_path = os.getenv(
            "PROVIDER_02_INGEST_PATH", "/v1/governance/bundles"
        )

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

    async def register_project_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Register a completed Project Bundle with Provider 02.

        Args:
            bundle: The serialized AttestationBundle dict.

        Returns:
            Registration response with ``bundleHash`` and ``receiptUrl``.

        Raises:
            Provider02Error: On any HTTP or network failure (fail-closed).
        """
        import httpx

        # Try primary ingestion endpoint
        url = f"{self._endpoint}{self._ingest_path}"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.post(url, json=bundle, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            # Fallback to legacy endpoint on 404/405
            if exc.response.status_code in (404, 405):
                logger.warning(
                    "[Provider02] Primary endpoint %s failed with %d, "
                    "falling back to /registerProjectBundle",
                    url,
                    exc.response.status_code,
                )
                return await self._register_bundle_fallback(bundle)

            logger.error(
                "[Provider02] register_project_bundle HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            raise Provider02Error(
                f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                code="ENDPOINT_ERROR",
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "[Provider02] register_project_bundle request error: %s %s", url, exc
            )
            raise Provider02Error(str(exc), code="ENDPOINT_ERROR") from exc
        except Exception as exc:
            logger.error(
                "[Provider02] register_project_bundle unexpected error: %s", exc
            )
            raise Provider02Error(
                f"Unexpected error: {exc}", code="ENDPOINT_ERROR"
            ) from exc

    async def _register_bundle_fallback(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Fallback bundle registration using legacy /registerProjectBundle endpoint."""
        import httpx

        url = f"{self._endpoint}/registerProjectBundle"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.post(url, json=bundle, headers=self._headers())
                resp.raise_for_status()
                logger.info(
                    "[Provider02] Fallback endpoint succeeded: /registerProjectBundle"
                )
                return resp.json()
        except Exception as exc:
            logger.error(
                "[Provider02] Fallback registration also failed: %s %s", url, exc
            )
            raise Provider02Error(
                f"Both primary and fallback endpoints failed: {exc}",
                code="ENDPOINT_ERROR",
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
