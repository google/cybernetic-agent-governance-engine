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
  actions is unknown or claimed by no domain tier (it would never be gated).

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
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import (
    CagePlugin,
    ConsensusContribution,
    ConsensusProvider,
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
)
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
from src.gateway.governance.warrant.cache import WarrantCache

if TYPE_CHECKING:
    from src.gateway.governance.schemas.thresholds import GovernanceThresholds
    from src.gateway.governance.seams.warrant import WarrantSource
    from src.gateway.governance.stpa_validator import STPAValidator

logger = logging.getLogger(__name__)


class GovernorAssemblyError(ValueError):
    """The plugin contributions cannot form a safe governor."""


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

    def __post_init__(self) -> None:
        if self.classifier is None:
            raise TypeError("GovernorComponents requires a classifier")  # fail closed
        for name in (
            "core_stages",
            "domain_tiers",
            "narrowers",
            "invariants",
            "uca_rules",
            "saga_compensators",
            "contributions",
            "norm_bindings",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(
            self, "ground_truth_providers", dict(self.ground_truth_providers)
        )
        object.__setattr__(
            self, "server_inputs", MappingProxyType(dict(self.server_inputs))
        )
        object.__setattr__(self, "execution_verbs", frozenset(self.execution_verbs))

    @property
    def jurisdiction_tiers(self) -> tuple[GovernanceTier, ...]:
        return self.jurisdiction.tiers if self.jurisdiction is not None else ()

    @property
    def plugin_tiers(self) -> tuple[GovernanceTier, ...]:
        """Every non-kernel tier: the domain's, then the jurisdiction's."""
        return (*self.domain_tiers, *self.jurisdiction_tiers)

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
) -> SymbolicGovernor:
    """Collect every plugin's contribution, validate them together, build the governor.

    ``opa`` and ``stpa_validator`` default to the production clients;
    ``jurisdiction`` defaults to the active region's contribution
    (:func:`~src.gateway.governance.jurisdiction.resolve_jurisdiction`).
    ``warrant_source`` supplies warrants for norms the region marks
    ``requires_warrant``; it is never defaulted here (the composition root,
    :func:`~src.gateway.governance.governor.bootstrap.bootstrap_governor`,
    resolves it from ``CAGE_WARRANT_SOURCE``).

    Raises:
        GovernorAssemblyError: The contributions collide, leave an
            irreversible action ungoverned, declare a warranted norm the
            governor cannot gate, or the jurisdiction's region is not the
            region the effective thresholds were resolved for.
        ValueError: A contributed invariant fails V1-V4, or two tiers share a
            ``tier_name``.
    """
    # ``jurisdiction=None`` means "the active region", never "no jurisdiction":
    # every governor built here has one, so the region check always runs.
    jurisdiction = jurisdiction if jurisdiction is not None else resolve_jurisdiction()
    _reject_region_mismatch(jurisdiction)
    contributions = tuple(_contribution_of(plugin) for plugin in plugins)
    _reject_duplicates("domain", (c.domain for c in contributions))
    _reject_duplicates(
        "threshold section", (s for c in contributions for s in c.threshold_sections)
    )
    _validate_threshold_sections(contributions)
    tiers = tuple(t for c in contributions for t in c.tiers)
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

    core_stages = kernel_stages(
        opa,
        stpa_validator,
        metrics=metrics,
        magnitude_extractor=magnitude_extractor,
    )
    if warranted and warrant_source is not None:  # else refused above
        core_stages = (
            *core_stages,
            WarrantStage(
                warranted,
                _warrant_cache(warrant_source),
                jurisdiction=jurisdiction.region,
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


def _warrant_cache(source: WarrantSource) -> WarrantCache:
    """Wrap ``source`` in the freshness cache the validated thresholds define.

    One cache per governor: the governor (and so the cache) is built only
    here, never at import time.
    """
    window = _effective_thresholds().warrant
    return WarrantCache(
        source,
        max_age_seconds=window.max_age_seconds,
        fetch_timeout_seconds=window.fetch_timeout_seconds,
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


def _effective_thresholds() -> GovernanceThresholds:
    """The process's effective thresholds — the object every reader resolves.

    Read through the module attribute at call time (not bound at import) so the
    governor is validated against exactly what its tiers and plugins read.
    """
    from src.gateway.governance.schemas import thresholds as thresholds_module

    return thresholds_module.THRESHOLDS


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
