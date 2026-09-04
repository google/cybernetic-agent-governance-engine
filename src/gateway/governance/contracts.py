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
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.symbolic_governor import SymbolicGovernor


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

    Schema evolution:
    - v1: Original fields (thread_id, action, violated_tier, violated_rule, proof_hash)
    - v2: Added 5-part proof chain (Terry Snyder seam: attempted_params,
          standing_snapshot, control_id, protected_consequence, non_formation_proof)
    - v3: Added tier_failures tuple (multi-tier dispatch architecture)
    """

    thread_id: str
    action: str
    violated_tier: str  # e.g., "CBF", "OPA", "NEURAL_CONFIDENCE", "FISCAL", "NEMO"
    violated_rule: str
    standing_at_refusal: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    proof_hash: str = field(default="")
    # ── 5-part proof chain fields (Terry Snyder, schema v2) ──
    # ── tier_failures (multi-tier dispatch, schema v3) ──
    schema_version: str = field(default="v3")
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


# ---------------------------------------------------------------------------
# Violation — structured domain-tier violation record (D8 / F5 fix)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Violation:
    """Structured violation emitted by a GovernanceTierPlugin.

    Every ``evaluate()`` or ``commit()`` call on a domain tier returns a
    (possibly empty) list of ``Violation`` objects.  A non-empty list causes
    the action to be denied; ``needs_human_review`` routes the denial to the
    DEFER/human-review queue rather than an immediate DENY.

    This replaces ad-hoc violation strings with a structured record that
    preserves the tier name, machine-readable code, human-readable message,
    and recoverability context — enabling the ``_rollback_committed()`` method
    to distinguish transient failures from non-recoverable resource
    inconsistencies.
    """

    tier: str  # e.g. "cbf", "fiscal", "consensus", "causal"
    code: str  # machine-readable, e.g. "CBF_BARRIER_VIOLATED", "ROLLBACK_FAILED"
    message: str  # human-readable description
    recoverable: bool = True
    needs_human_review: bool = False


# ---------------------------------------------------------------------------
# GovernanceTierPlugin — domain-specific governance tier protocol
# ---------------------------------------------------------------------------


class GovernanceTierPlugin(Protocol):
    """Protocol for a domain-specific governance evaluation tier.

    Domain plugins (e.g. ``cage_finance``) implement this protocol for each
    governance tier they contribute to the kernel.  Tiers are registered via
    ``SymbolicGovernor.register_domain_tier()`` at startup and are executed in
    ``(phase, order, tier_name)`` order during ``_run_checks()``.

    Phase semantics:
        - **Phase 1** (``phase == 1``): read-only validation.  ``evaluate()``
          is called; ``commit()`` and ``rollback()`` are never called.
        - **Phase 2** (``phase == 2``): atomic mutation.  ``commit()`` is
          called if all Phase 1 tiers passed.  On failure, ``rollback()`` is
          called in LIFO order on all previously committed Phase 2 tiers.

    The ``order`` property (D5 fix) is the explicit integer ordering value
    that corresponds to the paper's tier numbering.  It replaces the v1
    alphabetic ``tier_name`` sort, which silently inverted the Consensus →
    Causal sequence asserted by ``proof/model.py``.
    """

    @property
    def tier_name(self) -> str:
        """Stable identifier for this tier (e.g. 'cbf', 'fiscal')."""
        ...

    @property
    def phase(self) -> int:
        """1 = read-only validation, 2 = atomic mutation."""
        ...

    @property
    def order(self) -> int:
        """Explicit integer tier order matching the formal model.

        Lower values run first within the same phase.  The ``tier_name`` is
        used only as a deterministic tie-break when two tiers share the same
        ``(phase, order)`` pair.
        """
        ...

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        """Return True if this tier has governance authority over the action."""
        ...

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Phase 1: read-only evaluation.  Return violations (may be empty)."""
        ...

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Phase 2: atomic state mutation.  Return violations on failure."""
        ...

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        """Phase 2: undo a prior ``commit()`` — called in LIFO order on failure."""
        ...


# ---------------------------------------------------------------------------
# CagePlugin — capability plugin discovered via entry points (D7 fix)
# ---------------------------------------------------------------------------

CAGE_PLUGIN_API_VERSION = "1.0"


@runtime_checkable
class CagePlugin(Protocol):
    """A CAGE capability plugin discovered via the ``cage.plugins`` entry point.

    Contract
    --------
    * ``name`` must equal the entry-point name (verified at load time).
    * ``api_version`` must be compatible with ``CAGE_PLUGIN_API_VERSION``;
      incompatible plugins are rejected fail-closed at startup.
    * ``register()`` must be idempotent and side-effect-free apart from
      registering tiers/tools on the objects it is handed.
    * ``register()`` must never import from ``gateway.*`` internals beyond the
      public ``contracts`` module.
    * A plugin that cannot fully register must raise; partial registration is
      forbidden (a half-registered governance tier is a fail-open hazard).
    """

    name: str
    api_version: str

    def register(
        self,
        governor: "SymbolicGovernor",
        tool_server: "FastMCP | None" = None,
    ) -> None:
        """Register this plugin's governance tiers and tools with the kernel."""
        ...


def validate_plugin(plugin: object, entry_point_name: str) -> CagePlugin:
    """Fail-closed structural + version validation of a discovered plugin.

    Raises:
        TypeError: If the object does not satisfy the ``CagePlugin`` protocol.
        ValueError: If the plugin's ``name`` does not match the entry-point
            name, or its ``api_version`` major version is incompatible.
    """
    if not isinstance(plugin, CagePlugin):
        raise TypeError(
            f"plugin '{entry_point_name}' does not satisfy the CagePlugin protocol"
        )
    if plugin.name != entry_point_name:
        raise ValueError(
            f"plugin name '{plugin.name}' != entry point '{entry_point_name}'"
        )
    major = plugin.api_version.split(".")[0]
    if major != CAGE_PLUGIN_API_VERSION.split(".")[0]:
        raise ValueError(
            f"plugin '{plugin.name}' api_version {plugin.api_version} is "
            f"incompatible with kernel {CAGE_PLUGIN_API_VERSION}"
        )
    return plugin


# ---------------------------------------------------------------------------
# InvariantModel — abstract safety barrier for domain plugins
# ---------------------------------------------------------------------------


class InvariantModel(Protocol):
    """Declarative affine barrier: h(x) = state[state_key] - thresholds[threshold_key].

    Domain plugins declare their safety barriers by implementing this protocol.
    The barrier is DECLARATIVE, not callable, by necessity: a Python callback
    cannot execute inside the atomic Redis Lua hop, and moving barrier evaluation
    outside that hop reopens the TOCTOU window that proof/DistributedCBF.tla
    exists to close.

    Non-affine barriers (h(x) = f(x) for non-affine f) are a KERNEL change
    requiring a DistributedCBF.tla update and a new proof obligation — never
    a plugin extension. A plugin that needs h(x) = f(x) for non-affine f must
    open a kernel RFC.

    The kernel compiles (invariant_id, state_key, threshold_key, gamma) into
    the Lua script's KEYS and ARGV arrays at invocation time.
    """

    @property
    def invariant_id(self) -> str:
        """Stable identifier for this barrier (e.g. 'finance.cash_balance').

        Must be unique across all registered plugins. Used for telemetry,
        audit logs, and violation attribution.
        """
        ...

    @property
    def state_key(self) -> str:
        """Redis key holding the scalar state variable x.

        Must be namespaced (contain ':') to avoid key collisions across domains.
        Example: 'safety:current_cash', 'safety:serum_concentration'
        """
        ...

    @property
    def threshold_key(self) -> str:
        """THRESHOLDS lookup path for the floor value.

        Resolved from config/thresholds/{REGION}_BASELINE.json at runtime.
        Example: 'cbf.min_cash_balance', 'healthcare.min_therapeutic_concentration'
        """
        ...

    @property
    def gamma(self) -> float:
        """CBF class-K function gain (0 < gamma <= 1).

        Controls how aggressively the barrier enforces forward invariance.
        """
        ...


# ---------------------------------------------------------------------------
# DomainToolProvider — registers domain-specific MCP tools
# ---------------------------------------------------------------------------


class DomainToolProvider(Protocol):
    """Registers domain-specific MCP tools with the tool server.

    Domain plugins implement this to contribute tools (e.g. ``execute_trade``,
    ``check_market_status``) to the MCP tool server.  The kernel calls
    ``register_tools()`` during plugin registration if a tool server is
    available.
    """

    def register_tools(self, server: "FastMCP") -> None:
        """Register this domain's tools with the given MCP server."""
        ...


# ---------------------------------------------------------------------------
# SafetyFilter — CBF / safety constraint protocol
# ---------------------------------------------------------------------------


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
        self, magnitude: float, governance_signature: str | None = None
    ) -> None:
        """
        Rolls back the safety state (e.g. restores cash) after a failure.

        Args:
            magnitude: The magnitude of the state change to reverse (formerly
                ``cost`` — renamed for domain-agnostic semantics in v4.0).
            governance_signature: Optional KMS governance signature string.
        """
        ...


class ConsensusProvider(Protocol):
    """
    Protocol for a Multi-Agent Consensus Engine.
    Enforces ISO 42001 Human Oversight and Adaptive Compute requirements.

    v4.0 signature: domain-agnostic ``context`` dict replaces the financial-
    coupled ``(amount, symbol)`` positional parameters.
    """

    async def check_consensus(
        self,
        action: str,
        context: dict[str, Any],
        magnitude: float | None = None,
    ) -> dict[str, Any]:
        """
        Checks if the action requires consensus and performs it.
        Returns a dict with "status" (APPROVE, REJECT, ESCALATE) and "reason".
        """
        ...


class _LegacyConsensusAdapter:
    """
    Adapter that bridges legacy (action, amount, symbol) calls to the new
    context-based check_consensus(action, context, magnitude) signature.
    
    This adapter is used in tests to verify backward compatibility during
    the v4.0 signature migration. Production code should use the new signature
    directly.
    """

    def __init__(self, inner: ConsensusProvider):
        """
        Args:
            inner: The ConsensusProvider instance with the new signature.
        """
        self._inner = inner

    async def check_consensus(
        self, action: str, amount: float, symbol: str
    ) -> dict[str, Any]:
        """
        Legacy signature: (action, amount, symbol) → dict.
        
        Translates to the new signature: check_consensus(action, context, magnitude).
        """
        context = {"amount": amount, "symbol": symbol}
        return await self._inner.check_consensus(
            action, context=context, magnitude=amount
        )


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


class ResourceGuard(Protocol):
    """
    Protocol for a resource pre-reservation system (e.g. Redis-backed fiscal limits).

    v4.0 rename: ``FiscalGuard`` → ``ResourceGuard`` for domain-agnostic
    semantics.  Parameters generalized from ``(agent_id, amount_usd)`` to
    ``(principal_id, magnitude, context)``.

    Abstracts the FiscalLimitGuard for testability — any object implementing
    ``reserve`` and ``release`` is a valid ResourceGuard, regardless of whether
    it uses a real Redis instance, fakeredis, or an in-memory stub.

    Structural subtyping note: FiscalLimitGuard in
    src/gateway/governance/fiscal_limit_guard.py implements both ``reserve``
    and ``release`` with compatible signatures and is therefore structurally
    compatible with this Protocol without any modification.
    """

    async def reserve(
        self,
        principal_id: str,
        magnitude: float,
        context: dict[str, Any] | None = None,
    ) -> "ReservationToken":
        """
        Atomically reserve a slice of a resource limit.

        Args:
            principal_id: Logical name of the requesting agent (formerly
                ``agent_id`` — renamed for domain-agnostic semantics).
            magnitude:    Amount to reserve (must be > 0).  Formerly
                ``amount_usd``; interpretation is domain-specific.
            context:      Optional domain-specific context dict.

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
            The new running total after the release.
        """
        ...


# Deprecated alias — retained through PR 3 for backward compatibility.
# Deleted in PR 4 when the legacy dispatch path is removed.
FiscalGuard = ResourceGuard

# Structural compatibility note:
# FiscalLimitGuard (src/gateway/governance/fiscal_limit_guard.py) implements
# both ``reserve(agent_id, amount_usd) -> ReservationToken`` and
# ``release(token) -> float`` with compatible signatures.  It is therefore
# structurally compatible with ResourceGuard under PEP 544 structural subtyping
# with no modification required.  The parameter rename (agent_id -> principal_id,
# amount_usd -> magnitude) is source-compatible because Python protocols use
# structural, not nominal, subtyping.

# Import ReservationToken from kernel types module (promoted from Layer 2 in PR B).
# Fixes Finding A: the old path src.gateway.governance.fiscal_limit_guard never
# existed, causing get_type_hints(ResourceGuard) to raise NameError.
from src.gateway.governance.types import ReservationToken
