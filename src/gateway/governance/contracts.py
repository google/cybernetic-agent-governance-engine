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
Governance Contracts (Protocols).
This module defines the interfaces that the Gateway expects for governance components,
decoupling the Gateway from the specific application implementations.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class GovernanceTierFailure:
    """Structured failure record emitted by a specific governance tier.

    CAGE-SEC-009 / Terry Snyder 5-part proof chain:
    Captures the full causal context of a governance tier failure, replacing
    the collapsed violation string with a structured object that preserves
    the governing state at the moment of refusal.

    Fields map to Terry's 5-part chain:
        1. attempted_movement → captured at RefusalReceipt level (action + attempted_params)
        2. standing           → governing_state (tier-specific snapshot)
        3. governing_condition → tier + control_id + rule_description
        4. protected_consequence → what would have formed if allowed
        5. non_formation      → captured at RefusalReceipt level (non_formation_proof)
    """

    tier: str  # e.g., "CBF", "OPA", "NEURAL_CONFIDENCE", "FISCAL", "NEMO", "FTRA"
    control_id: str  # e.g., "CAGE-CTRL-001", GovernanceControl enum value
    rule_description: str  # Human-readable description of the violated rule
    governing_state: dict[str, Any] = field(default_factory=dict)
    protected_consequence: str = ""  # What consequence would have formed


@dataclass(frozen=True)
class RefusalReceipt:
    """Immutable audit-grade proof emitted whenever an action is blocked or denied.

    CAGE-SEC-009 / Terry Snyder seam review protocol:
    Standardizes denial evidence into a cryptographic proof recording the
    exact violated invariant, authority tier, and standing context.

    Schema v2 (5-part proof chain):
    In addition to the original fields, captures Terry Snyder's complete
    causal chain: attempted movement, governing standing, the condition
    that failed, what consequence was protected from forming, and proof
    of non-formation.
    """

    thread_id: str
    action: str
    violated_tier: str  # e.g., "CBF", "OPA", "NEURAL_CONFIDENCE", "FISCAL", "NEMO"
    violated_rule: str
    standing_at_refusal: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    proof_hash: str = field(default="")
    # ── 5-part proof chain fields (Terry Snyder, schema v2) ──
    schema_version: str = field(default="v1")
    attempted_params: dict[str, Any] = field(default_factory=dict)
    standing_snapshot: dict[str, Any] = field(default_factory=dict)
    control_id: str = field(default="")
    protected_consequence: str = field(default="")
    non_formation_proof: str = field(default="")
    tier_failures: tuple[GovernanceTierFailure, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.proof_hash:
            # NOTE: standing_at_refusal MUST be included in the hashed payload
            # to ensure the cryptographic proof binds to the actual refused
            # transaction context (symbol, amount, etc.). Without this, two
            # RefusalReceipts for the same action/tier/rule/timestamp but
            # different amounts would produce identical proof_hash values,
            # breaking the evidentiary chain. (CAGE-SEC-009, plans/unified_implementation_analysis.md:191-193)
            #
            # Backward compatibility: Any Decimal values in standing_at_refusal
            # are serialized via JCS canonicalization (RFC 8785), which
            # converts Python Decimal to JSON number representation. Receipts
            # generated after this fix will have different proof_hash values
            # than hypothetical receipts from an implementation that excluded
            # standing_at_refusal — this is the intended behavior.
            payload: dict[str, Any] = {
                "thread_id": self.thread_id,
                "action": self.action,
                "violated_tier": self.violated_tier,
                "violated_rule": self.violated_rule,
                "standing_at_refusal": self.standing_at_refusal,
                "timestamp": self.timestamp,
            }
            # Schema v2: include 5-part proof chain fields in the hash
            # when populated, ensuring the cryptographic binding covers
            # the full causal chain.
            if self.schema_version != "v1":
                payload["schema_version"] = self.schema_version
                payload["attempted_params"] = self.attempted_params
                payload["standing_snapshot"] = self.standing_snapshot
                payload["control_id"] = self.control_id
                payload["protected_consequence"] = self.protected_consequence
                payload["non_formation_proof"] = self.non_formation_proof
                # Serialize tier_failures for hashing
                payload["tier_failures"] = [
                    {
                        "tier": tf.tier,
                        "control_id": tf.control_id,
                        "rule_description": tf.rule_description,
                        "governing_state": tf.governing_state,
                        "protected_consequence": tf.protected_consequence,
                    }
                    for tf in self.tier_failures
                ]
            from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

            canon = jcs_canonicalize_plan(payload)
            object.__setattr__(self, "proof_hash", hashlib.sha256(canon).hexdigest())


@dataclass(frozen=True)
class PauseReceipt:
    """Immutable audit-grade proof emitted whenever an action is paused.

    Similar to RefusalReceipt but for PAUSE decisions — transient conditions
    that will resolve without human intervention or data-hydration.

    PAUSE decisions are neither approved nor denied; they indicate:
      - Rate limiting (soft, will clear with time)
      - Circuit breaker open (external dependency unavailable)
      - Resource temporarily unavailable (quota exhausted, capacity exceeded)
      - Coordination wait (cross-agent synchronization)

    The pause_token is stored in Redis and can be used to resume the request
    via POST /v1/pause/{pause_token}/resume.

    ISO 42001 mapping: A.8.4 (AI System Operation Controls)
    """

    thread_id: str
    action: str
    pause_reason: str  # e.g., "RATE_LIMITED", "CIRCUIT_OPEN", "RESOURCE_UNAVAILABLE"
    pause_token: str
    violations: list[str] = field(default_factory=list)
    standing_at_pause: dict[str, Any] = field(default_factory=dict)
    estimated_wait_seconds: int = field(default=60)
    expires_at_utc: str = field(default="")
    timestamp: float = field(default_factory=time.time)
    proof_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.proof_hash:
            payload = {
                "thread_id": self.thread_id,
                "action": self.action,
                "pause_reason": self.pause_reason,
                "pause_token": self.pause_token,
                "standing_at_pause": self.standing_at_pause,
                "timestamp": self.timestamp,
            }
            from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

            canon = jcs_canonicalize_plan(payload)
            object.__setattr__(self, "proof_hash", hashlib.sha256(canon).hexdigest())


class SafetyFilter(Protocol):
    """
    Protocol for a Control Barrier Function or similar safety filter.
    Enforces hard constraints on actions (e.g. bankruptcy prevention).
    """

    def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        """
        Verifies if the action is safe.
        Returns "SAFE" or an error message starting with "UNSAFE".

        .. deprecated::
            Use ``atomic_verify_and_commit()`` instead to eliminate the TOCTOU
            window between this read-only check and the subsequent balance debit
            (see CBF Invariance Theorem atomicity premise, Issue #6).
        """
        ...

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
    ) -> tuple[bool, str]:
        """Collapse CBF check and state commit into one atomic Redis Lua hop.

        Eliminates the TOCTOU window between ``verify_action()`` (read-only)
        and the state commit (write) by executing both as a single Lua script
        inside Redis.

        Args:
            action_name:          Name of the action being evaluated.
            payload:              Action parameters dict.
            governance_signature: Optional KMS governance signature string.

        Returns:
            ``(True, "COMMITTED")`` on success.
            ``(False, reason_string)`` when the CBF envelope is violated.
        """
        ...

    async def rollback_state(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        """
        Rolls back the safety state (e.g. restores cash) after a failure.
        """
        ...


class ConsensusProvider(Protocol):
    """
    Protocol for a Multi-Agent Consensus Engine.
    Enforces ISO 42001 Human Oversight and Adaptive Compute requirements.
    """

    async def check_consensus(
        self, action: str, amount: float, symbol: str
    ) -> dict[str, Any]:
        """
        Checks if the action requires consensus and performs it.
        Returns a dict with "status" (APPROVE, REJECT, ESCALATE) and "reason".
        """
        ...


class PolicyClient(Protocol):
    """
    Protocol for an OPA (Open Policy Agent) HTTP client.

    Abstracts the OPA HTTP client for testability — any object implementing
    these two async methods is a valid PolicyClient, regardless of whether it
    uses HTTP, a Unix domain socket, or a test double.

    Structural subtyping note: OPAClient in src/gateway/core/policy.py is
    structurally compatible with this Protocol — it implements both
    ``evaluate_policy`` (mapped to ``evaluate``) and ``check_allowed`` via
    its ``evaluate_policy`` return value.  See the comment below the class.
    """

    async def evaluate(self, policy_path: str, input_data: dict) -> dict:
        """
        Evaluate an OPA policy and return the full result dict.

        Args:
            policy_path: OPA policy path / rule reference (e.g. "trade/governance").
            input_data:  Arbitrary input document forwarded to OPA as ``{"input": ...}``.

        Returns:
            The parsed JSON response body from OPA (typically contains a ``"result"`` key).
        """
        ...

    async def check_allowed(self, policy_path: str, input_data: dict) -> bool:
        """
        Evaluate an OPA policy and return a simple boolean allow/deny decision.

        Args:
            policy_path: OPA policy path / rule reference.
            input_data:  Arbitrary input document forwarded to OPA.

        Returns:
            True if the policy allows the action, False otherwise.
        """
        ...


# Structural compatibility note:
# OPAClient (src/gateway/core/policy.py) exposes ``evaluate_policy(input_data, ...)``
# which covers the semantics of both ``evaluate`` and ``check_allowed`` above.
# Because Python Protocols use structural subtyping (PEP 544), a thin adapter
# or a subclass that adds the two method names is sufficient for full compatibility.


class CausalGatekeeper(Protocol):
    """
    Protocol for the DoWhy causal inference gatekeeper.

    Abstracts the DoWhy causal inference engine for testability — any callable
    object or class implementing ``causal_safety_check`` is a valid
    CausalGatekeeper, regardless of whether it uses DoWhy, a stub, or a mock.

    Structural subtyping note: the module-level function
    ``causal_safety_check`` in src/gateway/governance/causal_gatekeeper.py
    is structurally compatible with this Protocol when wrapped in a class.
    """

    def causal_safety_check(self, params: dict, current_telemetry: Any = None) -> bool:
        """
        Run the causal safety check for a proposed action.

        Args:
            params:            Action parameters dict.  Must contain at minimum
                               ``"amount"`` (float), and optionally
                               ``"action_type"`` and ``"market_regime"`` for
                               cache key construction.
            current_telemetry: Optional live telemetry DataFrame.  If None,
                               synthetic telemetry is generated internally.

        Returns:
            True if the action is causally safe, False if the world-model is
            untrustworthy or the predicted risk exceeds the safety boundary.
            Always fails closed on error.
        """
        ...


# Structural compatibility note:
# The module-level ``causal_safety_check`` function in causal_gatekeeper.py
# matches this Protocol's method signature.  A one-line wrapper class is
# sufficient to make it a fully compatible CausalGatekeeper instance.


class FiscalGuard(Protocol):
    """
    Protocol for the Redis-backed fiscal pre-reservation system.

    Abstracts the FiscalLimitGuard for testability — any object implementing
    ``reserve`` and ``release`` is a valid FiscalGuard, regardless of whether
    it uses a real Redis instance, fakeredis, or an in-memory stub.

    Structural subtyping note: FiscalLimitGuard in
    src/gateway/governance/fiscal_limit_guard.py implements both ``reserve``
    and ``release`` with compatible signatures and is therefore structurally
    compatible with this Protocol without any modification.
    """

    async def reserve(
        self,
        agent_id: str,
        amount_usd: float,
    ) -> "ReservationToken":
        """
        Atomically reserve a slice of the daily fiscal limit.

        Args:
            agent_id:   Logical name of the requesting agent.
            amount_usd: USD amount to reserve (must be > 0).

        Returns:
            ReservationToken — always returns; check ``token.rejected`` to
            determine whether the reservation was accepted or denied.
        """
        ...

    async def release(self, token: "ReservationToken") -> float:
        """
        Release a reservation — called by the Saga compensating node on rollback.

        Safe to call multiple times (idempotent via floor-at-zero).

        Args:
            token: The ReservationToken returned by a prior ``reserve()`` call.

        Returns:
            The new running total in USD after the release.
        """
        ...


# Structural compatibility note:
# FiscalLimitGuard (src/gateway/governance/fiscal_limit_guard.py) implements
# both ``reserve(agent_id, amount_usd) -> ReservationToken`` and
# ``release(token) -> float`` with identical signatures.  It is therefore
# structurally compatible with FiscalGuard under PEP 544 structural subtyping
# with no modification required.

# Import ReservationToken for use in type annotations above.
# The import is placed here (after the class body) to avoid a circular import
# at module load time while still making the type available for runtime
# isinstance checks and static analysis.
try:
    from src.gateway.governance.fiscal_limit_guard import (
        ReservationToken,
    )
except ImportError:
    pass  # ReservationToken unavailable in minimal test environments
