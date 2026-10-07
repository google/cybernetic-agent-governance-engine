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
import math
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor


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

    ``reliance`` holds the warrant reliance records (JSON objects, see
    ``src.gateway.governance.warrant.reliance``) the refused decision
    evaluated, e.g. a RELIANCE_INELIGIBLE finding co-occurring with the HARD
    one that decided the refusal. Refusals are primary evidence, so they are
    inside ``proof_hash`` with the same fields a seal's evidence record
    carries. Omitted from the hash when empty, so receipts for decisions that
    relied on no warranted norm hash as before.
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
    reliance: tuple[dict[str, Any], ...] = field(default_factory=tuple)

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
            if self.reliance:
                payload["reliance"] = [dict(record) for record in self.reliance]
            from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

            canon = jcs_canonicalize_plan(payload)
            object.__setattr__(self, "proof_hash", hashlib.sha256(canon).hexdigest())


# ---------------------------------------------------------------------------
# Violation — structured domain-tier violation record (D8 / F5 fix)
# ---------------------------------------------------------------------------


class ViolationKind(StrEnum):
    """Classification of violation severity and disposition.

    Precedence: HARD > RELIANCE_INELIGIBLE > HITL > NARROWABLE > DEFERRABLE

    ``RELIANCE_INELIGIBLE`` means CAGE may not rely on a norm because the
    warrant grounding it failed standing verification. It is not a verdict
    on the request: it defers (no human can repair a warrant), and it never
    masks an independent HARD finding.
    """

    HARD = "hard"
    RELIANCE_INELIGIBLE = "reliance_ineligible"
    HITL = "hitl"
    DEFERRABLE = "deferrable"
    NARROWABLE = "narrowable"


def coerce_bound(value: object) -> float | None:
    """``value`` as a valid :attr:`Violation.bound`, else ``None`` (never a guess).

    Tiers read bounds from live state; an unreadable or malformed reading
    means "unknown", not a refusal of its own, so it must not raise.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return float(value)


@dataclass(frozen=True)
class Violation:
    """Structured violation emitted by a governance tier or kernel stage.

    Every ``evaluate()`` or ``commit()`` call on a domain tier returns a
    (possibly empty) list of ``Violation`` objects.  A non-empty list causes
    the action to be denied; classification by ``kind`` determines the verdict
    (DENY, REQUIRE_APPROVAL, DEFER, or NARROW).

    This replaces ad-hoc violation strings with a structured record that
    preserves the tier name, machine-readable code, human-readable message,
    and kind-based classification — removing dual sources of truth
    (recoverable + needs_human_review) and enabling fail-closed classification
    by construction.

    ``bound`` is the largest magnitude, in the units of the tier's cost
    resolver, that the emitting tier would admit at the moment it refused
    (e.g. the fiscal tier's remaining daily headroom, a barrier's admissible
    cost). ``None`` means the tier does not know. It is a hint for
    narrowers, never an authorization: narrowed params are always re-run
    through the pipeline before anything is sealed.
    """

    tier: str  # e.g. "cbf", "fiscal", "consensus", "causal"
    code: str  # machine-readable, e.g. "CBF_BARRIER_VIOLATED", "ROLLBACK_FAILED"
    message: str  # human-readable description (never parsed)
    kind: ViolationKind  # REQUIRED — no default (fail-closed by construction)
    bound: float | None = None

    def __post_init__(self) -> None:
        if self.bound is None:
            return
        if (
            isinstance(self.bound, bool)
            or not isinstance(self.bound, (int, float))
            or not math.isfinite(self.bound)
            or self.bound < 0
        ):
            raise ValueError(
                f"Violation.bound must be a finite, non-negative number or None; got {self.bound!r}"
            )

    @property
    def narrowable(self) -> bool:
        """Return True when this violation is classified as NARROWABLE."""
        return self.kind == ViolationKind.NARROWABLE

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for API / MCP / agent-tool boundaries."""
        out: dict[str, Any] = {
            "tier": self.tier,
            "code": self.code,
            "message": self.message,
            "kind": self.kind.value,
        }
        if self.bound is not None:
            out["bound"] = self.bound
        return out


@dataclass(frozen=True)
class NarrowingResult:
    """Result of a narrower evaluation."""

    can_narrow: bool
    narrowed_params: dict[str, Any]
    constraints_applied: list[str]
    narrowing_reason: str


@runtime_checkable
class Narrower(Protocol):
    """Protocol for parameter narrowing plugins.

    A Narrower evaluates whether a violation can be resolved by
    clamping/restricting parameters while preserving action semantics.
    Contributed via ``PluginContribution.narrowers``.
    """

    def can_narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> bool:
        """Return True if this narrower can handle the violation."""
        ...

    def narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult | None:
        """Compute narrowed parameters that resolve the violation."""
        ...


# ---------------------------------------------------------------------------
# CommitReceipt — what a phase-2 commit changed, so rollback can undo exactly it
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitReceipt:
    """Record of the state a phase-2 ``commit()`` mutated.

    ``rollback()`` receives this receipt and must undo exactly what it records.
    It never re-derives the undo from request params, which may have changed
    or been interpreted differently by the time rollback runs.

    The pipeline holds receipts in a per-request local. They are never stored
    on a tier or stage instance, which are shared across concurrent requests.

    Attributes:
        tier:      ``tier_name`` of the tier that issued the receipt.
        magnitude: Exact quantity the commit consumed, if any.
        token:     Opaque tier-owned handle (e.g. a reservation token).
    """

    tier: str
    magnitude: float | None = None
    token: Any = None


# ---------------------------------------------------------------------------
# Governance tiers — ReadOnlyTier (phase 1) and MutatingTier (phase 2)
# ---------------------------------------------------------------------------


class GovernanceTier(ABC):
    """A domain- or jurisdiction-contributed governance tier.

    Never subclassed directly: a tier is either a :class:`ReadOnlyTier`
    (phase 1, validation only) or a :class:`MutatingTier` (phase 2, reserves
    and releases state). The kind is nominal, so ``phase`` is derived from
    the class and never declared by the tier (ADR-009). A mutating tier that
    forgets a hook cannot be instantiated; it is never silently run as a
    read-only one.

    Tiers are handed over in ``PluginContribution.tiers`` (or a
    ``JurisdictionContribution``) and fixed when ``assemble_governor()``
    builds the immutable governor. They run in ``(phase, order, tier_name)``
    order. ``order`` (D5 fix) is the explicit integer matching the paper's
    tier numbering; ``tier_name`` only breaks ties.
    """

    @property
    @abstractmethod
    def tier_name(self) -> str:
        """Stable identifier for this tier (e.g. 'cbf', 'fiscal')."""

    @property
    @abstractmethod
    def order(self) -> int:
        """Explicit integer tier order matching the formal model.

        Lower values run first within the same phase.  The ``tier_name`` is
        used only as a deterministic tie-break when two tiers share the same
        ``(phase, order)`` pair.
        """

    @property
    @abstractmethod
    def phase(self) -> int:
        """1 for a :class:`ReadOnlyTier`, 2 for a :class:`MutatingTier`. Derived, never declared."""

    @property
    def runtime_requirements(self) -> tuple[str, ...]:
        """Importable modules this tier needs to govern (e.g. ``("dowhy",)``).

        ``assert_production_posture()`` refuses to start an enforcing posture
        when one is missing, so a check is driven by the tier that needs it
        rather than hard-coded in the kernel.  Default: none.
        """
        return ()

    @abstractmethod
    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        """Return True if this tier has governance authority over the action."""

    @abstractmethod
    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Read-only evaluation.  Return violations (may be empty).

        Read-only tier: the tier's validation.  Mutating tier: a
        side-effect-free preview of ``commit()`` (DRY_RUN, or approval
        pending).  Must never mutate state.
        """


class ReadOnlyTier(GovernanceTier):
    """Phase-1 tier: ``evaluate()`` only. It holds and changes no state.

    Defining ``commit`` / ``rollback`` / ``confirm`` on a read-only tier is
    refused when the governor wraps it (``DomainTierStage``): such a tier
    meant to mutate and must be a :class:`MutatingTier`.
    """

    @property
    def phase(self) -> int:
        return 1


class MutatingTier(GovernanceTier):
    """Phase-2 tier: reserves state for a request and settles it afterwards.

    Lifecycle of one reservation (``CommitReceipt``):

    * ``commit()`` reserves, once phase 1 is clean under a committing profile;
    * ``rollback(receipt)`` releases it — the run was refused, or the sealed
      action was not carried out;
    * ``confirm(receipt)`` makes it permanent — the sealed action was carried
      out (``SymbolicGovernor.settle(seal, executed=True)``).

    A reservation that is never settled (the process died between seal and
    actuation) must expire on the tier's own clock: ``commit()`` may not
    assume ``confirm()`` or ``rollback()`` will ever arrive.
    """

    @property
    def phase(self) -> int:
        return 2

    @abstractmethod
    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        """Reserve atomically.

        Returns ``(violations, receipt)``.  ``receipt`` is not None if and only
        if state was mutated.  A commit that returns violations must either
        have mutated nothing (receipt None) or return its receipt so the caller
        can undo it.  A commit that raises must leave no state mutated.
        """

    @abstractmethod
    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        """Release the reservation described by ``receipt`` (LIFO on failure).

        Decides what to undo from ``receipt`` alone; must never re-read
        ``params`` for a magnitude or a handle.
        """

    @abstractmethod
    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        """Make the reservation in ``receipt`` permanent: the action was carried out.

        A tier whose commit is already final (nothing expires) implements this
        as a no-op. Decides from ``receipt`` alone, like ``rollback``.
        """


# ---------------------------------------------------------------------------
# CagePlugin — capability plugin discovered via entry points (D7 fix)
# ---------------------------------------------------------------------------

CAGE_PLUGIN_API_VERSION = "2.0"


@dataclass(frozen=True)
class DomainConfig:
    """Kernel-consumed configuration owned by the single active domain.

    The kernel reads these files for the active domain instead of hard-coding
    one domain's paths. Paths must be absolute (plugins build them from
    ``Path(__file__)``) and must exist; the plugin loader checks both at
    startup and refuses to run otherwise.

    OPA is an external server, so the kernel never loads Rego itself. The
    domain instead names the Rego package the kernel queries
    (``OPA_URL`` + ``/v1/data/<package path>``) and the rules that package
    must define; startup verifies both against the live OPA server and
    refuses to run on any mismatch.

    Attributes:
        ftra_registry_path: FTRA terminal registry JSON for this domain's actions.
        opa_package: Dotted Rego package holding this domain's decision, e.g.
            ``"trade.governance"``.
        opa_required_rules: Rule names the package must define, e.g.
            ``("allow",)``. Must be non-empty.
        causal_graph_path: Causal graph YAML for the causal gatekeeper, or
            ``None`` if the domain has no causal tier.
    """

    ftra_registry_path: Path
    opa_package: str
    opa_required_rules: tuple[str, ...]
    causal_graph_path: Path | None = None


@runtime_checkable
class SagaCompensator(Protocol):
    """Protocol for an STPA-compiled saga compensating handler.

    Contributed by a domain plugin via ``PluginContribution.saga_compensators``.
    """

    @property
    def action_name(self) -> str:
        """Forward action name this compensator reverses."""
        ...

    @property
    def uca_id(self) -> str:
        """STPA UCA identifier associated with this saga."""
        ...

    @property
    def compensating_action(self) -> str:
        """Name of the compensating action invoked on rollback."""
        ...

    async def compensate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute the compensating rollback for ``params``."""
        ...


@dataclass(frozen=True)
class NormBinding:
    """A domain norm the kernel may be asked to rely on, declared as data.

    A plugin declares each norm it enforces whose reliance may need an
    institutional warrant: ``norm_id`` is the issuer-facing identifier,
    ``value`` the exact value the plugin enforces, and ``actions`` the
    actions the norm governs. Whether a warrant is required is regional
    configuration, not plugin code.

    When ``requires_warrant`` is true, ``governing_version`` names the
    governance version the warrant must have been issued for; the kernel
    verifies the warrant against it. The v0.1 warrant carries no value
    field, so the version is what binds a warrant to ``value``: changing a
    warranted norm's value requires a new ``governing_version`` and a
    re-issued warrant.
    """

    norm_id: str
    value: float
    requires_warrant: bool
    actions: frozenset[str]
    governing_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.norm_id, str) or not self.norm_id:
            raise ValueError("NormBinding.norm_id must be a non-empty string")
        if (
            isinstance(self.value, bool)
            or not isinstance(self.value, (int, float))
            or not math.isfinite(self.value)
        ):
            raise ValueError(
                f"NormBinding {self.norm_id!r}: value must be a finite number, "
                f"got {self.value!r}"
            )
        if not isinstance(self.requires_warrant, bool):
            raise ValueError(
                f"NormBinding {self.norm_id!r}: requires_warrant must be a bool"
            )
        if isinstance(self.actions, str):
            raise ValueError(
                f"NormBinding {self.norm_id!r}: actions must be a set of names"
            )
        actions = frozenset(self.actions)
        if not actions or not all(isinstance(a, str) and a for a in actions):
            raise ValueError(
                f"NormBinding {self.norm_id!r}: actions must be non-empty strings"
            )
        object.__setattr__(self, "actions", actions)
        if self.governing_version is not None and (
            not isinstance(self.governing_version, str) or not self.governing_version
        ):
            raise ValueError(
                f"NormBinding {self.norm_id!r}: governing_version must be a "
                "non-empty string or None"
            )
        if self.requires_warrant and self.governing_version is None:
            # Fail closed: a warrant can only be verified against a version.
            raise ValueError(
                f"NormBinding {self.norm_id!r}: requires_warrant needs a "
                "governing_version"
            )

    def governs(self, action: str) -> bool:
        """Whether ``action`` relies on this norm."""
        return action in self.actions


@runtime_checkable
class ServerInputResolver(Protocol):
    """Supplies, from server-side sources, the params a domain never trusts.

    A domain contributes one resolver per action whose governance reads
    measured state (a quote age, a drawdown, a portfolio value) rather than
    caller intent. The kernel (:func:`~src.gateway.governance.governor.
    server_inputs.bind_server_inputs`) removes every ``owned_keys`` entry the
    caller sent, on the preview and the committing path alike, then merges
    what :meth:`resolve` returns for those keys only. A key the resolver
    leaves out stays absent, so the domain's rules must refuse a missing
    value (fail closed).
    """

    #: Params this resolver alone may set for its action.
    owned_keys: frozenset[str]

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return values for (a subset of) ``owned_keys``.

        ``params`` is the caller's request with every owned key removed,
        read-only. Raising is treated as "nothing resolved".
        """
        ...


@dataclass(frozen=True)
class PluginContribution:
    """Everything one domain plugin hands to the kernel, as data.

    ``CagePlugin.contribute()`` returns one of these; ``assemble_governor()``
    validates all contributions together (slot collisions, duplicate domains
    and threshold sections, ungoverned irreversible actions, invariant
    V1-V4) and only then builds an immutable governor.  Plugins never mutate
    the governor.

    Fields marked with a plan section are semantic slots filled by PR 4b;
    they exist now so 4b does not change the assembly API.

    Attributes:
        domain: Unique domain name, e.g. ``"finance"``.
        tiers: Governance tiers for this domain.
        invariants: Declarative CBF barriers; validated at assembly.
        uca_rules: STPA unsafe-control-action rules (4b.9).
        saga_compensators: STPA-compiled saga compensators (4b.9).
        narrowers: Parameter narrowing strategies (4b.6).
        threshold_sections: Threshold schema per section name under
            ``domains.<domain>`` (4b.7); keys must be unique across domains.
        execution_verbs: Claim-detector execution verbs (4b.13).
        ground_truth_providers: External ground-truth readers keyed by
            ``invariant_id`` (4b.2).
        registered_actions: Every action this domain exposes.
        magnitude_extractor: Reads an action's magnitude (trade amount,
            dose, velocity) from its params. Feeds conditional FTRA (a
            registered terminal clears inside its autonomous envelope) and,
            when the consensus contribution declares none, consensus.
        safety_filter: Safety filter (CBF) backing this domain's barriers.
        consensus: Consensus provider backing this domain's consensus tier.
        tool_provider: Registers this domain's MCP tools.
        compliance_overlay_dirs: Compliance overlay directories.
        background_tasks: Named async background workers.
        rail_providers: NeMo rail providers.
        norm_bindings: Norms this domain enforces that a region may require
            a warrant for (:class:`NormBinding`); ``norm_id`` is unique
            across contributions.
        server_inputs: Per-action resolvers for params that only the gateway
            may supply (:class:`ServerInputResolver`); an action has at most
            one across contributions.
    """

    domain: str
    tiers: tuple["GovernanceTier", ...] = ()
    invariants: tuple["InvariantModel", ...] = ()
    uca_rules: tuple["UcaRule", ...] = ()
    saga_compensators: tuple["SagaCompensator", ...] = ()
    narrowers: tuple["Narrower", ...] = ()
    threshold_sections: Mapping[str, type] = field(default_factory=dict)
    execution_verbs: frozenset[str] = frozenset()
    ground_truth_providers: Mapping[str, Any] = field(default_factory=dict)
    registered_actions: frozenset[str] = frozenset()
    magnitude_extractor: Callable[[Mapping[str, Any]], float] | None = None
    safety_filter: "SafetyFilter | None" = None
    consensus: "ConsensusProvider | ConsensusContribution | None" = None
    tool_provider: "DomainToolProvider | None" = None
    compliance_overlay_dirs: tuple[Path, ...] = ()
    background_tasks: Mapping[str, Callable[[], Coroutine[Any, Any, None]]] = field(
        default_factory=dict
    )
    rail_providers: tuple[Any, ...] = ()
    norm_bindings: tuple[NormBinding, ...] = ()
    server_inputs: Mapping[str, ServerInputResolver] = field(default_factory=dict)


@runtime_checkable
class CagePlugin(Protocol):
    """A CAGE capability plugin discovered via the ``cage.plugins`` entry point.

    Contract
    --------
    * ``name`` must equal the entry-point name (verified at load time).
    * ``api_version`` must be compatible with ``CAGE_PLUGIN_API_VERSION``;
      incompatible plugins are rejected fail-closed at startup.
    * ``domain_config`` names the kernel-consumed config for this domain.
      ``None`` means the domain is not yet runnable; loading it fails closed.
    * ``contribute()`` returns data only. It must not mutate process-global
      state: the composition root (``assemble_governor``) and the server
      lifespan apply the contribution.
    * ``contribute()`` must never import from ``gateway.*`` internals beyond
      the public ``contracts`` module.
    * A plugin that cannot build a complete contribution must raise; a
      partial contribution is forbidden (a half-registered governance tier
      is a fail-open hazard).
    """

    name: str
    api_version: str
    domain_config: DomainConfig | None

    def contribute(self) -> PluginContribution:
        """Return this plugin's tiers, invariants, tools and hooks."""
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

        Resolved against the active region's effective thresholds: the global
        ``domains.<section>`` of config/governance_thresholds.json with the
        ``domains`` overlay of config/thresholds/{REGION}_BASELINE.json applied
        (``schemas/regional_overlay.py``).
        Example: 'domains.example.min_resource_floor', 'domains.healthcare.min_therapeutic_concentration'
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

    Domain plugins implement this to contribute tools (e.g. ``execute_action``,
    ``check_state``) to the MCP tool server.  The server lifespan
    calls ``register_tools()`` once, after the governor is assembled, so a
    tool that must be sealed receives the governor that seals it.
    """

    def register_tools(self, server: "FastMCP", governor: "SymbolicGovernor") -> None:
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

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        """
        Side-effect-free preview: would the action be admitted now?
        Returns "SAFE" or an error message starting with "UNSAFE".

        Must not mutate any state — neither the backing store nor in-process
        accumulators — so that ``preview()`` stays pure however often it runs.
        Never use it to authorise execution: only ``atomic_verify_and_commit()``
        checks and debits atomically (CBF Invariance Theorem atomicity
        premise, Issue #6).
        """
        ...

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
        *,
        debit_id: str | None = None,
    ) -> tuple[bool, str, float]:
        """Collapse CBF check and state commit into one atomic Redis Lua hop.

        Eliminates the TOCTOU window between ``verify_action()`` (read-only)
        and the state commit (write) by executing both as a single Lua script
        inside Redis.

        Args:
            action_name:          Name of the action being evaluated.
            payload:              Action parameters dict.
            governance_signature: Optional KMS governance signature string.
            debit_id:             Ledger id the commit is recorded under
                (``CommitReceipt.token``). ``commit_barrier`` mints one per
                attempt; ``rollback_state`` retires exactly that entry.

        Returns:
            ``(True, "COMMITTED", magnitude)`` on success, where ``magnitude``
            is exactly what the commit deducted; pass it, with the
            ``debit_id``, to ``rollback_state()`` to undo the commit.
            ``(False, reason_string, 0.0)`` when nothing was committed.
        """
        ...

    async def rollback_state(
        self,
        magnitude: float,
        governance_signature: str | None = None,
        *,
        debit_id: str | None = None,
    ) -> None:
        """
        Rolls back the safety state (e.g. restores cash) after a failure.

        Args:
            magnitude: The magnitude of the state change to reverse (formerly
                ``cost`` — renamed for domain-agnostic semantics in v4.0).
            governance_signature: Optional KMS governance signature string.
            debit_id: Ledger id from the matching commit. When given, the
                engine restores the amount it ledgered under that id and
                treats a repeated rollback as a no-op.
        """
        ...


@dataclass(frozen=True)
class CriticSpec:
    """Domain-contributed consensus critic specification."""

    role: str
    prompt: str = ""
    prompt_template: str = ""
    weight: float = 1.0
    provider: str = "google"
    model: str = "gemini-2.5-pro"
    temperature: float = 0.0
    system_instruction: str = "You are a strict {role}."
    context_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        resolved = self.prompt or self.prompt_template
        object.__setattr__(self, "prompt", resolved)
        object.__setattr__(self, "prompt_template", resolved)
        object.__setattr__(self, "context_keys", tuple(self.context_keys))


@dataclass(frozen=True)
class ConsensusContribution:
    """Domain-contributed configuration for the multi-agent consensus engine.

    ``magnitude_extractor=None`` inherits ``PluginContribution.magnitude_extractor``
    at assembly; with neither, consensus sees magnitude 0.0.
    """

    critics: tuple[CriticSpec, ...]
    threshold: float
    magnitude_extractor: Callable[[Mapping[str, Any]], float] | None = None
    high_stakes_actions: frozenset[str] = frozenset()


class ConsensusProvider(Protocol):
    """
    Protocol for a Multi-Agent Consensus Engine.
    Enforces ISO 42001 Human Oversight and Adaptive Compute requirements.
    """

    async def check_consensus(
        self,
        action: str,
        context: dict[str, Any],
        magnitude: float | None = None,
    ) -> dict[str, Any]:
        """
        Checks if the action requires consensus and performs it.
        Returns a dict with "status" (APPROVE, REJECT, ESCALATE, DENY, SKIPPED) and "reason".
        """
        ...


@runtime_checkable
class PolicyClient(Protocol):
    """Protocol for the OPA (Open Policy Agent) client the kernel calls.

    These are exactly the members the gateway uses: ``OpaStage`` and the MCP
    tool server call ``evaluate_policy``; server startup calls
    ``verify_domain_policy`` and shutdown calls ``close``.
    :class:`src.gateway.core.policy.OPAClient` implements it structurally; any
    transport (HTTP, Unix socket, test double) with these members is valid.
    """

    async def evaluate_policy(
        self, input_data: dict[str, Any], current_latency_ms: float = 0.0
    ) -> str:
        """Evaluate the domain's OPA decision for ``input_data``.

        Returns:
            The verdict string (``"ALLOW"``, ``"DENY"`` or ``"MANUAL_REVIEW"``).
            Implementations fail closed: an unreachable or erroring policy
            engine yields ``"DENY"``.
        """
        ...

    async def verify_domain_policy(
        self, package: str, required_rules: tuple[str, ...]
    ) -> None:
        """Raise unless ``package`` is loaded and defines every rule in ``required_rules``."""
        ...

    async def close(self) -> None:
        """Release transport resources (pooled connections)."""
        ...


@dataclass(frozen=True)
class CausalSpec:
    """Domain-contributed specification for causal world-model validation."""

    dag_gml: str = ""
    treatment: str = ""
    outcome: str = ""
    confounders: tuple[str, ...] = ()
    context_key: str = "default"
    treatment_extractor: Callable[[Mapping[str, Any]], float | None] = field(
        default=lambda _: None
    )
    graph_dot: str = ""
    treatment_col: str = ""
    outcome_col: str = ""
    context_extractor: Callable[[Mapping[str, Any]], str] | None = None
    normalization_scale: float = 10000.0
    synthetic_telemetry_factory: Callable[[], Any] | None = None

    def __post_init__(self) -> None:
        resolved_graph = self.dag_gml or self.graph_dot
        resolved_treatment = self.treatment or self.treatment_col
        resolved_outcome = self.outcome or self.outcome_col
        object.__setattr__(self, "dag_gml", resolved_graph)
        object.__setattr__(self, "graph_dot", resolved_graph)
        object.__setattr__(self, "treatment", resolved_treatment)
        object.__setattr__(self, "treatment_col", resolved_treatment)
        object.__setattr__(self, "outcome", resolved_outcome)
        object.__setattr__(self, "outcome_col", resolved_outcome)
        if self.context_extractor is None:
            ck = self.context_key
            object.__setattr__(
                self,
                "context_extractor",
                (lambda p, _ck=ck: str(p.get(_ck, "unknown")))
                if ck
                else (lambda _p: "default"),
            )


class CausalGatekeeper(Protocol):
    """
    Protocol for the DoWhy causal inference gatekeeper.

    Abstracts the DoWhy causal inference engine for testability — any callable
    object or class implementing ``causal_safety_check`` is a valid
    CausalGatekeeper, regardless of whether it uses DoWhy, a stub, or a mock.
    """

    def causal_safety_check(self, params: dict, current_telemetry: Any = None) -> bool:
        """
        Run the causal safety check for a proposed action.

        Args:
            params:            Action parameters dict evaluated via the domain's
                               ``CausalSpec.treatment_extractor`` and ``context_key``.
            current_telemetry: Optional live telemetry DataFrame.

        Returns:
            True if the action is causally safe, False if the world-model is
            untrustworthy or the predicted risk exceeds the safety boundary.
            Always fails closed on error.
        """
        ...


@runtime_checkable
class ResourceGuard(Protocol):
    """
    Protocol for a domain-agnostic resource pre-reservation system.

    Any object implementing ``reserve`` and ``release`` is a valid
    ResourceGuard, regardless of whether it uses a live store or an
    in-memory stub.
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


from src.gateway.governance.stpa_validator import UcaRule
from src.gateway.governance.types import ReservationToken
