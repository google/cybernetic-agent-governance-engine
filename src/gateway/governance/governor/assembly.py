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

"""Composition root: the only place a :class:`SymbolicGovernor` is assembled.

Plugins hand over data (:class:`PluginContribution`); nothing mutates a
governor after construction. :func:`assemble_governor` validates every
contribution together and fails at startup, never at the first request, if:

* two contributions claim the same ``domain`` or threshold section;
* a contribution's ``domain`` is not its plugin's ``name``;
* two tiers claim one action in the same ``(phase, order)`` slot;
* an IRREVERSIBLE_TERMINAL action in a domain's FTRA registry has no tier
  claiming it (an ungoverned irreversible action);
* two contributions fill the same engine slot (safety filter, consensus);
* a contributed invariant fails V1-V4 (``invariants.validate_invariant``);
* a contributed :class:`NormBinding` requires a warrant but no
  ``WarrantSource`` is configured, DEFER is disabled (the only remaining
  outcome of a warrant failure would be a fabricated DENY), or one of its
  actions is unknown or claimed by no domain tier (it would never be gated);
* a contributed :class:`ConsequenceMagnitude` names an action its domain
  does not register, or two contributions declare one action, or the
  jurisdiction checks a different consequence-magnitude policy than the
  one the contributions declare.

Contributions are collected before the jurisdiction is resolved, so the
assembled :class:`ConsequenceMagnitudes` policy is threaded into the
jurisdiction it resolves (``resolve_jurisdiction(consequence_magnitudes=...)``)
and exposed, read-only, as ``components.consequence_magnitudes``.

Warranted norms add the kernel :class:`WarrantStage` after the universal
kernel stages; a governor with no warranted norm runs exactly
:func:`kernel_stages`.

The deployment region's :class:`JurisdictionContribution` (e.g. the EU AI
Act Art. 27 impact-assessment tier) is merged after the domain tiers. Its
tiers take part in the slot-collision check but never count as governing an
irreversible action: a jurisdiction assessment is not a barrier.

Engine slots no plugin fills get the deny-by-default null objects, so a
governor assembled with no plugins denies by construction.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from opentelemetry import trace

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes
from src.gateway.governance.contracts import (
    CagePlugin,
    ConsensusContribution,
    ConsensusProvider,
    ConsequenceMagnitude,
    GovernanceTier,
    InvariantModel,
    Narrower,
    NormBinding,
    PluginContribution,
    PolicyClient,
    SafetyFilter,
    ServerInputResolver,
)
from src.gateway.governance.env_posture import (
    DeploymentPosture,
    is_cage_defer_enabled,
    is_cage_narrow_enabled,
    is_enforcing,
)
from src.gateway.governance.execution_idempotency import ExecutionLedger
from src.gateway.governance.ftra.autonomy import MagnitudeExtractor
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.invariants import validate_invariant
from src.gateway.governance.governor.metrics import GovernorMetrics
from src.gateway.governance.governor.pipeline import Stage
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.governor.stages.ftra import FtraStage
from src.gateway.governance.governor.stages.opa import OpaStage
from src.gateway.governance.governor.stages.stpa import StpaStage
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jurisdiction import (
    JurisdictionContribution,
    resolve_jurisdiction,
)
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.null_components import (
    NullConsensusProvider,
    NullSafetyFilter,
)
from src.gateway.governance.warrant.cache import WarrantCache, WarrantClock

if TYPE_CHECKING:
    from src.gateway.governance.schemas.thresholds import GovernanceThresholds
    from src.gateway.governance.seams.warrant import WarrantSource
    from src.gateway.governance.stpa_validator import STPAValidator

logger = logging.getLogger(__name__)


class GovernorAssemblyError(ValueError):
    """The plugin contributions cannot form a safe governor."""


class GovernorPostureError(GovernorAssemblyError, RuntimeError):
    """An enforcing deployment posture precondition failed during governor assembly."""


@dataclass(frozen=True)
class DisabledTier:
    """A contributed tier that is not enabled, and why.

    A disabled tier examined no evidence: it never runs and never yields a
    verdict. ``assert_production_posture()`` refuses an enforcing posture in
    which a tier named in ``PluginContribution.required_tiers`` is disabled.
    """

    tier_name: str
    reason: str


@dataclass(frozen=True)
class GovernorComponents:
    """Everything a :class:`SymbolicGovernor` runs on. Immutable."""

    opa: PolicyClient
    core_stages: tuple[Stage, ...]
    classifier: ClassificationEngine
    domain_tiers: tuple[GovernanceTier, ...] = ()
    narrowers: tuple[Narrower, ...] = ()
    invariants: tuple[InvariantModel, ...] = ()
    uca_rules: tuple[object, ...] = ()
    saga_compensators: tuple[object, ...] = ()
    ground_truth_providers: Mapping[str, object] = field(default_factory=dict)
    safety_filter: SafetyFilter = field(default_factory=NullSafetyFilter)
    consensus: ConsensusProvider = field(default_factory=NullConsensusProvider)
    execution_verbs: frozenset[str] = field(default_factory=frozenset)
    contributions: tuple[PluginContribution, ...] = ()
    posture: DeploymentPosture = DeploymentPosture.PRODUCTION
    # The region's obligations; None when components are composed by hand
    # (tests). assemble_governor always sets it.
    jurisdiction: JurisdictionContribution | None = None
    # Every contributed norm binding, warranted or not.
    norm_bindings: tuple[NormBinding, ...] = ()
    # Per-action resolvers for params only the gateway may supply.
    server_inputs: Mapping[str, ServerInputResolver] = field(default_factory=dict)
    # At-most-once claims for actions a tool executes under an idempotency key.
    # Without Redis it refuses every claim under an enforcing posture.
    execution_ledger: ExecutionLedger = field(
        default_factory=lambda: ExecutionLedger(None)
    )
    # Contributed tiers that are not enabled. Never in ``domain_tiers``.
    disabled_tiers: tuple[DisabledTier, ...] = ()
    # The declared consequence-magnitude policy (read-only). Empty when
    # composed by hand, which declares nothing and so refuses every action
    # wherever a consequence is checked.
    consequence_magnitudes: ConsequenceMagnitudes = field(
        default_factory=ConsequenceMagnitudes
    )

    def __post_init__(self) -> None:
        if self.classifier is None:
            raise TypeError("GovernorComponents requires a classifier")  # fail closed
        if not isinstance(self.consequence_magnitudes, ConsequenceMagnitudes):
            raise TypeError(  # fail closed
                "GovernorComponents.consequence_magnitudes must be a "
                "ConsequenceMagnitudes"
            )
        for name in (
            "core_stages",
            "domain_tiers",
            "narrowers",
            "invariants",
            "uca_rules",
            "saga_compensators",
            "contributions",
            "norm_bindings",
            "disabled_tiers",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(
            self, "ground_truth_providers", dict(self.ground_truth_providers)
        )
        object.__setattr__(
            self, "server_inputs", MappingProxyType(dict(self.server_inputs))
        )
        object.__setattr__(self, "execution_verbs", frozenset(self.execution_verbs))
        enabled = {t.tier_name for t in self.domain_tiers}
        both = sorted(enabled & {d.tier_name for d in self.disabled_tiers})
        if both:
            raise ValueError(f"tiers both enabled and disabled: {both}")

    @property
    def jurisdiction_tiers(self) -> tuple[GovernanceTier, ...]:
        return self.jurisdiction.tiers if self.jurisdiction is not None else ()

    @property
    def plugin_tiers(self) -> tuple[GovernanceTier, ...]:
        """Every non-kernel tier: the domain's, then the jurisdiction's."""
        return (*self.domain_tiers, *self.jurisdiction_tiers)

    @property
    def required_tiers(self) -> frozenset[str]:
        """Every tier some contribution declares it cannot be governed without."""
        return frozenset(n for c in self.contributions for n in c.required_tiers)

    @property
    def unfilled_slots(self) -> tuple[str, ...]:
        """Engine slots still holding a deny-by-default null object."""
        nulls = (
            ("safety_filter", NullSafetyFilter),
            ("consensus", NullConsensusProvider),
        )
        return tuple(
            name for name, null in nulls if isinstance(getattr(self, name), null)
        )


@dataclass(frozen=True)
class DecisionFlags:
    """Which non-DENY verdict paths the classifier may take."""

    defer: bool
    narrow: bool

    @classmethod
    def from_env(cls) -> DecisionFlags:
        return cls(defer=is_cage_defer_enabled(), narrow=is_cage_narrow_enabled())


def _collect_server_inputs(
    contributions: Sequence[PluginContribution], known_actions: set[str]
) -> dict[str, ServerInputResolver]:
    """Merge every contribution's resolvers; one per known action, owning keys."""
    resolvers: dict[str, ServerInputResolver] = {}
    for c in contributions:
        for action, resolver in c.server_inputs.items():
            if action in resolvers:
                raise GovernorAssemblyError(
                    f"duplicate server_inputs resolver: {action!r} is contributed twice"
                )
            if action not in known_actions:
                raise GovernorAssemblyError(
                    f"server_inputs resolver for unknown action {action!r} "
                    f"(domain {c.domain!r})"
                )
            owned = getattr(resolver, "owned_keys", None)
            if (
                not isinstance(owned, frozenset)
                or not owned
                or not all(isinstance(k, str) and k for k in owned)
                or not callable(getattr(resolver, "resolve", None))
            ):
                raise GovernorAssemblyError(
                    f"server_inputs resolver for {action!r} must expose a "
                    "non-empty frozenset of key names and an async resolve()"
                )
            resolvers[action] = resolver
    return resolvers


def _collect_consequence_magnitudes(
    contributions: Sequence[PluginContribution],
) -> ConsequenceMagnitudes:
    """One policy from every contribution's declarations, validated together.

    Each declaration must name an action its own domain registers, and an
    action is declared at most once across contributions.
    """
    declarations: list[ConsequenceMagnitude] = []
    for c in contributions:
        for declaration in c.consequence_magnitudes:
            if not isinstance(declaration, ConsequenceMagnitude):
                raise GovernorAssemblyError(
                    f"domain {c.domain!r}: consequence_magnitudes must hold "
                    f"ConsequenceMagnitude declarations, got {type(declaration).__name__}"
                )
            if declaration.action not in c.registered_actions:
                raise GovernorAssemblyError(
                    f"domain {c.domain!r} declares a consequence magnitude for "
                    f"{declaration.action!r}, which it does not register"
                )
            declarations.append(declaration)
    _reject_duplicates("consequence magnitude", (d.action for d in declarations))
    return ConsequenceMagnitudes(tuple(declarations))


def _reject_foreign_magnitude_policy(
    jurisdiction: JurisdictionContribution, declared: ConsequenceMagnitudes
) -> None:
    """Fail closed when the jurisdiction checks a policy nobody declared.

    A jurisdiction resolved here is built over ``declared``. One passed in
    must have been built over the same policy, or over none (its tiers then
    refuse every action they claim).
    """
    enforced = jurisdiction.consequence_magnitudes
    if enforced is not None and enforced != declared:
        raise GovernorAssemblyError(
            f"jurisdiction {jurisdiction.region!r} checks a consequence-magnitude "
            "policy the domain contributions did not declare"
        )
    for tier in jurisdiction.tiers:
        tier_policy = getattr(tier, "consequence_magnitudes", None)
        if tier_policy is not None and tier_policy != declared:
            raise GovernorAssemblyError(
                f"jurisdiction {jurisdiction.region!r} tier {tier.tier_name!r} "
                "checks a consequence-magnitude policy the domain contributions "
                "did not declare"
            )


def kernel_stages(
    opa: PolicyClient,
    stpa_validator: STPAValidator | None,
    *,
    metrics: GovernorMetrics | None = None,
    magnitude_extractor: MagnitudeExtractor | None = None,
) -> tuple[Stage, ...]:
    """The domain-agnostic stages every governor runs before its domain tiers.

    ``magnitude_extractor`` is the domain's reader of action magnitude; FTRA
    needs it to clear a registered terminal inside its autonomous envelope.
    Without one, no terminal clears autonomously (fail closed).
    """
    return (
        FtraStage(metrics, magnitude_extractor),
        StpaStage(stpa_validator),
        OpaStage(opa),
        ConfidenceStage(),
    )


def assemble_governor(
    plugins: Sequence[CagePlugin],
    *,
    posture: DeploymentPosture,
    opa: PolicyClient | None = None,
    stpa_validator: STPAValidator | None = None,
    flags: DecisionFlags | None = None,
    metrics: GovernorMetrics | None = None,
    jurisdiction: JurisdictionContribution | None = None,
    warrant_source: WarrantSource | None = None,
    warrant_clock: WarrantClock | None = None,
    execution_ledger_redis: Any | None = None,
) -> SymbolicGovernor:
    """Collect every plugin's contribution, validate them together, build the governor.

    ``opa`` and ``stpa_validator`` default to the production clients;
    ``jurisdiction`` defaults to the active region's contribution
    (:func:`~src.gateway.governance.jurisdiction.resolve_jurisdiction`).
    ``warrant_source`` supplies warrants for norms the region marks
    ``requires_warrant``; it is never defaulted here (the composition root,
    :func:`~src.gateway.governance.governor.bootstrap.bootstrap_governor`,
    resolves it from ``CAGE_WARRANT_SOURCE``). ``warrant_clock`` is the
    monotonic and wall clock the warrant cache and stage read (default: the
    process clocks). ``execution_ledger_redis`` backs the governor's
    :class:`~src.gateway.governance.execution_idempotency.ExecutionLedger`
    (``components.execution_ledger``); without it the ledger refuses claims
    under an enforcing posture.

    The contributions' :class:`ConsequenceMagnitude` declarations become one
    :class:`ConsequenceMagnitudes` policy (``components.consequence_magnitudes``).
    A jurisdiction resolved here is built over it; a ``jurisdiction`` passed
    in must carry the same policy or none.

    Raises:
        GovernorAssemblyError: The contributions collide, leave an
            irreversible action ungoverned, declare a warranted norm the
            governor cannot gate, declare a consequence magnitude for an
            action their domain does not register (or one action twice), or
            the jurisdiction's region is not the region the effective
            thresholds were resolved for, or it checks a different
            consequence-magnitude policy.
        ValueError: A contributed invariant fails V1-V4, or two tiers share a
            ``tier_name``.
    """
    _reject_shared_telemetry_credentials(posture)
    _reject_unsafe_causal_activation((), posture)
    contributions = tuple(_contribution_of(plugin) for plugin in plugins)
    _reject_duplicates("domain", (c.domain for c in contributions))
    tiers = tuple(t for c in contributions for t in c.tiers)
    _reject_unsafe_causal_activation(tiers, posture)
    # Collected before the jurisdiction is resolved, so the jurisdiction's
    # tiers and provider are built over the policy the domains declared.
    consequence_magnitudes = _collect_consequence_magnitudes(contributions)
    # ``jurisdiction=None`` means "the active region", never "no jurisdiction":
    # every governor built here has one, so the region check always runs.
    if jurisdiction is None:
        jurisdiction = resolve_jurisdiction(
            consequence_magnitudes=consequence_magnitudes
        )
    _reject_region_mismatch(jurisdiction)
    _require_configured_tracer(posture)
    _reject_foreign_magnitude_policy(jurisdiction, consequence_magnitudes)
    _reject_duplicates(
        "threshold section", (s for c in contributions for s in c.threshold_sections)
    )
    _validate_threshold_sections(contributions)
    disabled_tiers = tuple(d for c in contributions for d in c.disabled_tiers)
    _reject_duplicates("disabled tier", (d.tier_name for d in disabled_tiers))
    _reject_unknown_required_tiers(contributions)
    _reject_slot_collisions(
        (*tiers, *jurisdiction.tiers), _known_actions(plugins, contributions)
    )
    _reject_ungoverned_irreversible(plugins, tiers)  # domain tiers only
    norm_bindings = tuple(b for c in contributions for b in c.norm_bindings)
    _reject_duplicates("norm binding", (b.norm_id for b in norm_bindings))

    invariants: list[InvariantModel] = []
    for invariant in (i for c in contributions for i in c.invariants):
        validate_invariant(invariant, invariants)  # V1 spans every domain
        invariants.append(invariant)

    uca_rules = tuple(r for c in contributions for r in c.uca_rules)
    _reject_duplicates("uca_rule", (getattr(r, "uca_id", str(r)) for r in uca_rules))
    saga_compensators = tuple(s for c in contributions for s in c.saga_compensators)

    ground_truth_providers: dict[str, object] = {}
    for c in contributions:
        for inv_id, prov in c.ground_truth_providers.items():
            if inv_id in ground_truth_providers:
                raise GovernorAssemblyError(
                    f"duplicate ground_truth_provider: {inv_id!r} is contributed twice"
                )
            ground_truth_providers[inv_id] = prov

    server_inputs = _collect_server_inputs(
        contributions, _known_actions(plugins, contributions)
    )
    narrowers = tuple(n for c in contributions for n in c.narrowers)
    flags = flags or DecisionFlags.from_env()
    warranted = tuple(b for b in norm_bindings if b.requires_warrant)
    _reject_ungateable_warranted_norms(
        warranted,
        warrant_source=warrant_source,
        flags=flags,
        tiers=tiers,
        known_actions=_known_actions(plugins, contributions),
    )
    if opa is None:
        from src.gateway.core.policy import OPAClient

        opa = OPAClient()
    if stpa_validator is None:
        from src.gateway.governance.stpa_validator import STPAValidator

        stpa_validator = STPAValidator(rules=uca_rules)
    from src.gateway.governance.schemas.thresholds import get_agent_confidence_threshold

    execution_verbs = frozenset(v for c in contributions for v in c.execution_verbs)
    raw_consensus = _single_slot("consensus", contributions)
    magnitude_extractor = cast(
        "MagnitudeExtractor | None", _single_slot("magnitude_extractor", contributions)
    )
    raw_consensus = _enforce_consensus_advisory_posture(raw_consensus, tiers, posture)
    if isinstance(raw_consensus, ConsensusContribution):
        from src.gateway.governance.consensus.engine import ConsensusGate

        if (
            raw_consensus.magnitude_extractor is None
            and magnitude_extractor is not None
        ):
            raw_consensus = dataclasses.replace(
                raw_consensus, magnitude_extractor=magnitude_extractor
            )
        resolved_consensus: ConsensusProvider = ConsensusGate.from_contribution(
            raw_consensus
        )
    elif raw_consensus is not None:
        resolved_consensus = raw_consensus  # type: ignore[assignment]
    else:
        resolved_consensus = NullConsensusProvider()

    _enforce_resolved_consensus_advisory_posture(resolved_consensus, tiers, posture)
    _reject_unbounded_consensus_critics(raw_consensus, resolved_consensus, tiers)

    core_stages = kernel_stages(
        opa,
        stpa_validator,
        metrics=metrics,
        magnitude_extractor=magnitude_extractor,
    )
    if warranted and warrant_source is not None:  # else refused above
        clock = warrant_clock or WarrantClock()
        core_stages = (
            *core_stages,
            WarrantStage(
                warranted,
                _warrant_cache(warrant_source, clock),
                jurisdiction=jurisdiction.region,
                clock=clock.wall_clock,
            ),
        )

    components = GovernorComponents(
        opa=opa,
        core_stages=core_stages,
        classifier=ClassificationEngine(
            narrower_registry=NarrowerRegistry(narrowers=list(narrowers)),
            confidence_threshold=get_agent_confidence_threshold(),
            defer_enabled=flags.defer,
            narrow_enabled=flags.narrow,
        ),
        domain_tiers=tiers,
        narrowers=narrowers,
        invariants=tuple(invariants),
        uca_rules=uca_rules,
        saga_compensators=saga_compensators,
        ground_truth_providers=ground_truth_providers,
        safety_filter=cast(
            "SafetyFilter | None", _single_slot("safety_filter", contributions)
        )
        or NullSafetyFilter(),
        consensus=resolved_consensus,
        execution_verbs=execution_verbs,
        contributions=contributions,
        posture=posture,
        jurisdiction=jurisdiction,
        norm_bindings=norm_bindings,
        server_inputs=server_inputs,
        execution_ledger=ExecutionLedger(execution_ledger_redis),
        disabled_tiers=disabled_tiers,
        consequence_magnitudes=consequence_magnitudes,
    )
    governor = SymbolicGovernor(components)
    logger.info(
        "governor assembled: domains=%s region=%s tiers=%s posture=%s "
        "unfilled=%s warranted_norms=%s",
        [c.domain for c in contributions],
        jurisdiction.region,
        governor.registered_tier_names(),
        posture.value,
        components.unfilled_slots,
        [b.norm_id for b in warranted],
    )
    return governor


def _warrant_cache(source: WarrantSource, clock: WarrantClock) -> WarrantCache:
    """Wrap ``source`` in the freshness cache the validated thresholds define.

    One cache per governor: the governor (and so the cache) is built only
    here, never at import time.
    """
    window = _effective_thresholds().warrant
    return WarrantCache(
        source,
        max_age_seconds=window.max_age_seconds,
        fetch_timeout_seconds=window.fetch_timeout_seconds,
        monotonic=clock.monotonic,
        wall_clock=clock.wall_clock,
    )


def warranted_assembly_admissible(
    *, has_warranted_norm: bool, defer_enabled: bool, has_source: bool
) -> bool:
    """Whether a governor may be assembled, as far as warranted norms go.

    A warranted norm needs a source to fetch its warrant from and DEFER to
    route a warrant failure to. Mirrors ``proof/model.py::
    warranted_assembly_admissible`` (``tests/test_formal_profile_parity.py``).
    """
    return not has_warranted_norm or (defer_enabled and has_source)


def _reject_ungateable_warranted_norms(
    warranted: Sequence[NormBinding],
    *,
    warrant_source: WarrantSource | None,
    flags: DecisionFlags,
    tiers: Sequence[GovernanceTier],
    known_actions: set[str],
) -> None:
    """Fail closed unless every warranted norm can actually be gated."""
    if not warranted:
        return
    norm_ids = [b.norm_id for b in warranted]
    if warrant_source is None:
        raise GovernorAssemblyError(
            f"norms {norm_ids} require a warrant but no WarrantSource is configured "
            "(set CAGE_WARRANT_SOURCE)"
        )
    from src.gateway.governance.seams.warrant import WarrantSource

    if not isinstance(warrant_source, WarrantSource):
        raise GovernorAssemblyError(
            f"warrant_source {type(warrant_source).__name__} does not implement "
            "the WarrantSource seam"
        )
    if not warranted_assembly_admissible(
        has_warranted_norm=True, defer_enabled=flags.defer, has_source=True
    ):
        raise GovernorAssemblyError(
            f"norms {norm_ids} require a warrant but DEFER is disabled "
            "(CAGE_DEFER_ENABLED=false): a warrant failure could only become a "
            "fabricated DENY"
        )
    for binding in warranted:
        for action in sorted(binding.actions):
            if action not in known_actions:
                raise GovernorAssemblyError(
                    f"warranted norm {binding.norm_id!r} names unknown action {action!r}"
                )
            if not any(t.claims_action(action, {}) for t in tiers):
                raise GovernorAssemblyError(
                    f"warranted norm {binding.norm_id!r} governs {action!r}, which no "
                    "domain tier claims: the warrant gate would never run for it"
                )


def _contribution_of(plugin: CagePlugin) -> PluginContribution:
    contribution = plugin.contribute()
    if not isinstance(contribution, PluginContribution):
        raise GovernorAssemblyError(
            f"plugin {plugin.name!r}: contribute() must return a PluginContribution"
        )
    if contribution.domain != plugin.name:
        raise GovernorAssemblyError(
            f"plugin {plugin.name!r} contributed domain {contribution.domain!r}; they must match"
        )
    return contribution


def _reject_duplicates(what: str, names: Iterable[str]) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise GovernorAssemblyError(
                f"duplicate {what}: {name!r} is contributed twice"
            )
        seen.add(name)


def _reject_unknown_required_tiers(contributions: Sequence[PluginContribution]) -> None:
    """A contribution may only require tiers it contributes itself."""
    for c in contributions:
        known = {t.tier_name for t in c.tiers} | {d.tier_name for d in c.disabled_tiers}
        unknown = sorted(c.required_tiers - known)
        if unknown:
            raise GovernorAssemblyError(
                f"domain {c.domain!r} requires tiers it does not contribute: {unknown}"
            )


def _effective_thresholds() -> GovernanceThresholds:
    """The process's effective thresholds — the object every reader resolves.

    Read through the module attribute at call time (not bound at import) so the
    governor is validated against exactly what its tiers and plugins read.
    """
    from src.gateway.governance.schemas import thresholds as thresholds_module

    return thresholds_module.THRESHOLDS


def _require_configured_tracer(posture: DeploymentPosture) -> None:
    """Fail closed at assembly when an enforcing posture has no active OTel tracer."""
    if not is_enforcing(posture):
        return
    exporter = os.environ.get("OTEL_TRACES_EXPORTER", "otlp").strip().lower()
    if exporter == "none":
        raise GovernorAssemblyError(
            f"enforcing posture {posture.value!r} requires OpenTelemetry tracing, "
            "but OTEL_TRACES_EXPORTER=none"
        )
    with trace.get_tracer(__name__).start_as_current_span(
        "cage.assembly.tracer_probe"
    ) as span:
        if not span.is_recording() or not span.get_span_context().is_valid:
            raise GovernorAssemblyError(
                f"enforcing posture {posture.value!r} requires a configured "
                "OpenTelemetry TracerProvider "
                f"(got {type(trace.get_tracer_provider()).__name__}); "
                "call setup_tracing() before assembling the governor"
            )


def _reject_region_mismatch(jurisdiction: JurisdictionContribution) -> None:
    """Fail closed when thresholds and jurisdiction disagree on the region.

    The regional ``domains`` overlay is applied when the thresholds load; a
    jurisdiction for another region would otherwise assemble silently on the
    wrong region's limits (one region's obligations enforcing another
    region's values).
    """
    thresholds_region = _effective_thresholds().region
    if thresholds_region != jurisdiction.region:
        raise GovernorAssemblyError(
            f"region mismatch: thresholds were resolved for {thresholds_region!r} "
            f"but the jurisdiction contribution is {jurisdiction.region!r}"
        )


def _validate_threshold_sections(contributions: Sequence[PluginContribution]) -> None:
    domains = _effective_thresholds().domains
    for c in contributions:
        for section_name, schema_cls in c.threshold_sections.items():
            if section_name not in domains:
                raise GovernorAssemblyError(
                    f"domain {c.domain!r}: threshold section 'domains.{section_name}' is missing from governance_thresholds.json"
                )
            raw_section = domains[section_name]
            try:
                if hasattr(schema_cls, "model_validate"):
                    schema_cls.model_validate(raw_section)
                elif callable(schema_cls):
                    schema_cls(**raw_section)
            except Exception as exc:
                raise GovernorAssemblyError(
                    f"domain {c.domain!r}: threshold section 'domains.{section_name}' failed validation: {exc}"
                ) from exc


def _single_slot(
    slot: str, contributions: Sequence[PluginContribution]
) -> object | None:
    filled = [
        (c.domain, getattr(c, slot))
        for c in contributions
        if getattr(c, slot) is not None
    ]
    if len(filled) > 1:
        raise GovernorAssemblyError(
            f"slot collision: {slot} contributed by {[d for d, _ in filled]}"
        )
    return filled[0][1] if filled else None


def _registry_of(plugin: CagePlugin) -> dict[str, str]:
    """The plugin's FTRA terminal registry, or ``{}`` if it declares no ``DomainConfig``.

    A plugin without ``DomainConfig`` cannot run: ``plugin_loader.domain_config_of``
    refuses it at startup. A declared registry that cannot load raises here.
    """
    config = plugin.domain_config
    if config is None:
        return {}
    from src.gateway.governance.ftra.classifier import _get_registry

    return dict(_get_registry(config.ftra_registry_path))


def _known_actions(
    plugins: Sequence[CagePlugin], contributions: Sequence[PluginContribution]
) -> set[str]:
    actions = {a for c in contributions for a in c.registered_actions}
    for plugin in plugins:
        actions.update(_registry_of(plugin))
    return actions


def _reject_slot_collisions(
    tiers: Sequence[GovernanceTier], actions: Iterable[str]
) -> None:
    for action in sorted(actions):
        slots: dict[tuple[int, int], list[str]] = defaultdict(list)
        for tier in tiers:
            if tier.claims_action(action, {}):
                slots[(tier.phase, tier.order)].append(tier.tier_name)
        for (phase, order), names in slots.items():
            if len(names) > 1:
                raise GovernorAssemblyError(
                    f"slot collision: tiers {sorted(names)} all claim {action!r} at phase={phase} order={order}"
                )


def _reject_ungoverned_irreversible(
    plugins: Sequence[CagePlugin], tiers: Sequence[GovernanceTier]
) -> None:
    from src.gateway.governance.ftra.models import TerminalClassification

    irreversible = TerminalClassification.IRREVERSIBLE_TERMINAL.value
    for plugin in plugins:
        for action, classification in sorted(_registry_of(plugin).items()):
            if classification == irreversible and not any(
                t.claims_action(action, {}) for t in tiers
            ):
                raise GovernorAssemblyError(
                    f"domain {plugin.name!r}: irreversible action {action!r} in its FTRA registry "
                    "is claimed by no tier (ungoverned irreversible action)"
                )


_RESERVED_CRITIC_CONTEXT_KEYS: frozenset[str] = frozenset(
    {"action", "action_type", "magnitude", "params", "role"}
)


def _is_causal_strict_mode_enabled() -> bool:
    """Return True when CAUSAL_GATEKEEPER_STRICT_MODE is enabled via env or module flag."""
    from src.gateway.governance.causal import gatekeeper

    raw = os.environ.get("CAUSAL_GATEKEEPER_STRICT_MODE")
    if raw is not None:
        return raw.strip().lower() in ("true", "1")
    return bool(gatekeeper.CAUSAL_GATEKEEPER_STRICT_MODE)


def _effective_enforcing_posture(
    posture: DeploymentPosture,
) -> DeploymentPosture | None:
    """Return the active enforcing posture if either ``posture`` or ``DeploymentPosture.from_env()`` enforces."""
    if is_enforcing(posture):
        return posture
    env_posture = DeploymentPosture.from_env()
    if env_posture.is_enforcing():
        return env_posture
    return None


def _reject_shared_telemetry_credentials(posture: DeploymentPosture) -> None:
    """Fail closed under enforcing postures when TELEMETRY_* collides with agent/advisor telemetry keys (F-92)."""
    enforcing = _effective_enforcing_posture(posture)
    if enforcing is None:
        return

    from src.gateway.governance.telemetry_provider import (
        find_colliding_agent_telemetry_env,
    )

    public_key = os.environ.get("TELEMETRY_PUBLIC_KEY", "").strip()
    secret_key = os.environ.get("TELEMETRY_SECRET_KEY", "").strip()
    collision = find_colliding_agent_telemetry_env(public_key, secret_key)
    if collision is not None:
        gateway_var, agent_var = collision
        raise GovernorPostureError(
            f"enforcing posture {enforcing.value!r} requires plane-isolated "
            "TELEMETRY_PUBLIC_KEY / TELEMETRY_SECRET_KEY distinct from the "
            f"governed agent's {agent_var} ({gateway_var} == {agent_var}; F-92 / R-11)"
        )


def _reject_unsafe_causal_activation(
    tiers: Sequence[GovernanceTier], posture: DeploymentPosture
) -> None:
    """Fail closed when the causal tier is enabled under an enforcing posture without F-92 preconditions."""
    from src.gateway.governance.feature_flags import opt_in_enabled
    from src.gateway.governance.telemetry_provider import (
        MockTelemetryProvider,
        NullTelemetryProvider,
    )

    causal_tiers = [t for t in tiers if t.tier_name == "causal"]
    causal_enabled = bool(causal_tiers) or opt_in_enabled("CAGE_CAUSAL_TIER_ENABLED")
    enforcing = _effective_enforcing_posture(posture)
    if not causal_enabled or enforcing is None:
        return

    if not _is_causal_strict_mode_enabled():
        raise GovernorPostureError(
            f"enforcing posture {enforcing.value!r} with causal tier enabled "
            "(CAGE_CAUSAL_TIER_ENABLED=true) requires CAUSAL_GATEKEEPER_STRICT_MODE=true "
            "(F-92 / R-11: producer-supplied span timestamps cannot order causal spans "
            "without trace_id under an enforcing posture)"
        )

    provider_name = os.environ.get("CAGE_TELEMETRY_PROVIDER", "").strip().lower()
    if provider_name in ("null", "mock"):
        raise GovernorPostureError(
            f"enforcing posture {enforcing.value!r} with causal tier enabled "
            f"forbids CAGE_TELEMETRY_PROVIDER={provider_name!r}; dedicated live "
            "telemetry credentials are required (F-92 / R-11)"
        )

    host = os.environ.get("TELEMETRY_HOST", "").strip()
    public_key = os.environ.get("TELEMETRY_PUBLIC_KEY", "").strip()
    secret_key = os.environ.get("TELEMETRY_SECRET_KEY", "").strip()
    if not (host and public_key and secret_key):
        raise GovernorPostureError(
            f"enforcing posture {enforcing.value!r} with causal tier enabled "
            "requires non-empty TELEMETRY_HOST, TELEMETRY_PUBLIC_KEY, and "
            "TELEMETRY_SECRET_KEY (F-92 / R-11)"
        )

    for env_name, val in (
        ("TELEMETRY_HOST", host),
        ("TELEMETRY_PUBLIC_KEY", public_key),
        ("TELEMETRY_SECRET_KEY", secret_key),
    ):
        lowered = val.lower()
        if lowered == "mock" or lowered.startswith(("mock-", "mock_")):
            raise GovernorPostureError(
                f"enforcing posture {enforcing.value!r} with causal tier enabled "
                f"forbids mock telemetry credential value in {env_name} (F-92 / R-11)"
            )

    _reject_shared_telemetry_credentials(enforcing)

    for tier in causal_tiers:
        tp = getattr(tier, "telemetry_provider", None)
        if isinstance(tp, (NullTelemetryProvider, MockTelemetryProvider)):
            raise GovernorPostureError(
                f"enforcing posture {enforcing.value!r} with causal tier enabled "
                f"forbids {type(tp).__name__} (F-92 / R-11)"
            )


def _extract_parameter_property_schemas(
    action_schemas: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Extract parameter JSON-Schema property mappings from declared action schemas."""
    field_schemas: dict[str, Mapping[str, Any]] = {}
    for key, schema_obj in action_schemas.items():
        if hasattr(schema_obj, "model_json_schema") and callable(
            schema_obj.model_json_schema
        ):
            json_schema = schema_obj.model_json_schema()
            props = (
                json_schema.get("properties", {})
                if isinstance(json_schema, Mapping)
                else {}
            )
            if isinstance(props, Mapping):
                for prop_name, prop_schema in props.items():
                    if isinstance(prop_schema, Mapping):
                        field_schemas[str(prop_name)] = prop_schema
        elif isinstance(schema_obj, Mapping):
            props = schema_obj.get("properties")
            if isinstance(props, Mapping):
                for prop_name, prop_schema in props.items():
                    if isinstance(prop_schema, Mapping):
                        field_schemas[str(prop_name)] = prop_schema
            else:
                field_schemas[str(key)] = schema_obj
    return field_schemas


def _is_schema_property_bounded(prop_schema: Mapping[str, Any]) -> bool:
    """Return True iff ``prop_schema`` bounds the parameter against free-text injection."""
    any_of = prop_schema.get("anyOf")
    if isinstance(any_of, Sequence) and not isinstance(any_of, (str, bytes)):
        branches = [
            b for b in any_of if isinstance(b, Mapping) and b.get("type") != "null"
        ]
    else:
        branches = [prop_schema]

    if not branches:
        return False

    for branch in branches:
        branch_type = branch.get("type")
        if branch_type in ("number", "integer", "boolean"):
            continue
        if (
            "enum" in branch
            or "const" in branch
            or "enum" in prop_schema
            or "const" in prop_schema
        ):
            continue
        if branch_type == "string":
            pattern = branch.get("pattern") or prop_schema.get("pattern")
            max_len = branch.get(
                "maxLength",
                prop_schema.get(
                    "maxLength",
                    branch.get("max_length", prop_schema.get("max_length")),
                ),
            )
            has_pattern = isinstance(pattern, str) and bool(pattern.strip())
            has_max_len = (
                isinstance(max_len, int)
                and not isinstance(max_len, bool)
                and max_len > 0
            )
            if has_pattern and has_max_len:
                continue
            return False
        return False

    return True


def _candidate_requested_non_advisory(candidate: object) -> bool:
    """Return True when ``candidate`` explicitly requested ``advisory_only=False``."""
    if isinstance(candidate, ConsensusContribution):
        return candidate.advisory_only is False
    sentinel = object()
    explicit = getattr(candidate, "_explicit_advisory_only", sentinel)
    if explicit is not sentinel:
        return explicit is False
    advisory = getattr(candidate, "advisory_only", sentinel)
    if advisory is not sentinel:
        return advisory is False
    return False


def _enforce_consensus_advisory_posture(
    raw_consensus: object | None,
    tiers: Sequence[GovernanceTier],
    posture: DeploymentPosture,
) -> object | None:
    """Refuse non-advisory consensus critics and enforce ``advisory_only=True`` under enforcing postures (F-54..F-56)."""
    enforcing = _effective_enforcing_posture(posture)
    if enforcing is None:
        return raw_consensus

    from src.gateway.governance.feature_flags import consensus_advisory_only_override

    if consensus_advisory_only_override() is False:
        raise GovernorPostureError(
            f"enforcing posture {enforcing.value!r} refuses "
            "CAGE_CONSENSUS_ADVISORY_ONLY=false: consensus critics must run with "
            "advisory_only=True so LLM critics never substitute for human escalation "
            "(F-54..F-56 / R-11)"
        )

    candidates: list[object] = []
    if raw_consensus is not None:
        candidates.append(raw_consensus)
    for tier in tiers:
        tier_engine = getattr(tier, "consensus", None) or getattr(
            tier, "consensus_engine", None
        )
        if tier_engine is not None and tier_engine not in candidates:
            candidates.append(tier_engine)

    for cand in candidates:
        if _candidate_requested_non_advisory(cand):
            raise GovernorPostureError(
                f"enforcing posture {enforcing.value!r} refuses consensus "
                "advisory_only=False: consensus critics must run with "
                "advisory_only=True so LLM critics never substitute for human "
                "escalation (F-54..F-56 / R-11)"
            )

    if (
        isinstance(raw_consensus, ConsensusContribution)
        and raw_consensus.advisory_only is not True
    ):
        return dataclasses.replace(raw_consensus, advisory_only=True)
    return raw_consensus


def _enforce_resolved_consensus_advisory_posture(
    resolved_consensus: ConsensusProvider,
    tiers: Sequence[GovernanceTier],
    posture: DeploymentPosture,
) -> None:
    """Ensure resolved consensus engines strictly enforce ``advisory_only=True`` in enforcing postures (F-54..F-56)."""
    enforcing = _effective_enforcing_posture(posture)
    if enforcing is None:
        return

    engines: list[object] = [resolved_consensus]
    for tier in tiers:
        tier_engine = getattr(tier, "consensus", None) or getattr(
            tier, "consensus_engine", None
        )
        if tier_engine is not None and tier_engine not in engines:
            engines.append(tier_engine)

    for engine in engines:
        if _candidate_requested_non_advisory(engine):
            raise GovernorPostureError(
                f"enforcing posture {enforcing.value!r} refuses consensus "
                "advisory_only=False (F-54..F-56 / R-11)"
            )
        if hasattr(engine, "advisory_only"):
            cast("Any", engine).advisory_only = True


def _reject_unbounded_consensus_critics(
    raw_consensus: object | None,
    resolved_consensus: ConsensusProvider,
    tiers: Sequence[GovernanceTier],
) -> None:
    """Fail closed when consensus critics are enabled without bounded context_keys or advisory_only (F-53..F-56)."""
    from src.gateway.governance.feature_flags import (
        consensus_advisory_only,
        consensus_critics_enabled,
    )

    critics_active = consensus_critics_enabled() or bool(
        getattr(resolved_consensus, "_critics_enabled", False)
    )
    for tier in tiers:
        tier_engine = getattr(tier, "consensus", None) or getattr(
            tier, "consensus_engine", None
        )
        if getattr(tier_engine, "_critics_enabled", False):
            critics_active = True

    if not critics_active:
        return

    candidates: list[object] = []
    if raw_consensus is not None:
        candidates.append(raw_consensus)
    if resolved_consensus is not None and resolved_consensus is not raw_consensus:
        candidates.append(resolved_consensus)
    for tier in tiers:
        tier_engine = getattr(tier, "consensus", None) or getattr(
            tier, "consensus_engine", None
        )
        if tier_engine is not None and tier_engine not in candidates:
            candidates.append(tier_engine)

    critics = ()
    for cand in candidates:
        cand_critics = tuple(getattr(cand, "critics", ()) or ())
        if cand_critics:
            critics = cand_critics
            break

    if not critics:
        return

    advisory_only = consensus_advisory_only() or any(
        bool(getattr(cand, "advisory_only", False)) for cand in candidates
    )
    if advisory_only:
        return

    merged_schemas: dict[str, Any] = {}
    for cand in candidates:
        cand_schemas = getattr(cand, "action_schemas", None)
        if isinstance(cand_schemas, Mapping):
            merged_schemas.update(cand_schemas)

    field_schemas = _extract_parameter_property_schemas(merged_schemas)
    for critic in critics:
        role = getattr(critic, "role", "<unknown>")
        rendered_keys = [
            k
            for k in getattr(critic, "context_keys", ())
            if k not in _RESERVED_CRITIC_CONTEXT_KEYS
        ]
        if not rendered_keys:
            raise GovernorAssemblyError(
                f"consensus critic {role!r} declares no context_keys while "
                "CAGE_CONSENSUS_CRITICS_ENABLED=true and advisory_only=False "
                "(F-53..F-56 / R-11)"
            )
        for key in rendered_keys:
            prop_schema = field_schemas.get(key)
            if prop_schema is None:
                raise GovernorAssemblyError(
                    f"consensus critic {role!r} renders context_key {key!r} "
                    "which has no declared schema in ConsensusContribution.action_schemas "
                    "(F-53..F-56 / R-11)"
                )
            if not _is_schema_property_bounded(prop_schema):
                raise GovernorAssemblyError(
                    f"consensus critic {role!r} renders context_key {key!r} "
                    "without pattern and maxLength schema bounds; set "
                    "advisory_only=True or bound the parameter in the action schema "
                    "(F-53..F-56 / R-11)"
                )
