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
* a contributed invariant fails V1-V4 (``invariants.validate_invariant``).

Engine slots no plugin fills get the deny-by-default null objects, so a
governor assembled with no plugins denies by construction.
"""

from __future__ import annotations

import dataclasses
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import (
    CagePlugin,
    ConsensusContribution,
    ConsensusProvider,
    GovernanceTierPlugin,
    InvariantModel,
    Narrower,
    PluginContribution,
    PolicyClient,
    SafetyFilter,
)
from src.gateway.governance.env_posture import (
    DeploymentPosture,
    is_cage_defer_enabled,
    is_cage_narrow_enabled,
    is_cage_pause_enabled,
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
from src.gateway.governance.governor.verdicts import default_standing_projector
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.null_components import (
    NullConsensusProvider,
    NullSafetyFilter,
)

logger = logging.getLogger(__name__)


class GovernorAssemblyError(ValueError):
    """The plugin contributions cannot form a safe governor."""


@dataclass(frozen=True)
class GovernorComponents:
    """Everything a :class:`SymbolicGovernor` runs on. Immutable."""

    opa: PolicyClient
    core_stages: tuple[Stage, ...]
    classifier: ClassificationEngine
    domain_tiers: tuple[GovernanceTierPlugin, ...] = ()
    narrowers: tuple[Narrower, ...] = ()
    invariants: tuple[InvariantModel, ...] = ()
    uca_rules: tuple[object, ...] = ()
    saga_compensators: tuple[object, ...] = ()
    ground_truth_providers: Mapping[str, object] = field(default_factory=dict)
    safety_filter: SafetyFilter = field(default_factory=NullSafetyFilter)
    consensus: ConsensusProvider = field(default_factory=NullConsensusProvider)
    standing_projector: Callable[[dict[str, Any]], dict[str, Any]] = default_standing_projector
    execution_verbs: frozenset[str] = field(default_factory=frozenset)
    contributions: tuple[PluginContribution, ...] = ()
    posture: DeploymentPosture = DeploymentPosture.PRODUCTION

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
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "ground_truth_providers", dict(self.ground_truth_providers))
        object.__setattr__(self, "execution_verbs", frozenset(self.execution_verbs))

    @property
    def unfilled_slots(self) -> tuple[str, ...]:
        """Engine slots still holding a deny-by-default null object."""
        nulls = (("safety_filter", NullSafetyFilter), ("consensus", NullConsensusProvider))
        return tuple(name for name, null in nulls if isinstance(getattr(self, name), null))


@dataclass(frozen=True)
class DecisionFlags:
    """Which non-DENY verdict paths the classifier may take."""

    defer: bool
    narrow: bool
    pause: bool

    @classmethod
    def from_env(cls) -> DecisionFlags:
        return cls(defer=is_cage_defer_enabled(), narrow=is_cage_narrow_enabled(), pause=is_cage_pause_enabled())


def kernel_stages(
    opa: PolicyClient,
    stpa_validator: object | None,
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
    stpa_validator: object | None = None,
    flags: DecisionFlags | None = None,
    metrics: GovernorMetrics | None = None,
) -> SymbolicGovernor:
    """Collect every plugin's contribution, validate them together, build the governor.

    ``opa`` and ``stpa_validator`` default to the production clients.

    Raises:
        GovernorAssemblyError: The contributions collide or leave an
            irreversible action ungoverned.
        ValueError: A contributed invariant fails V1-V4, or two tiers share a
            ``tier_name``.
    """
    contributions = tuple(_contribution_of(plugin) for plugin in plugins)
    _reject_duplicates("domain", (c.domain for c in contributions))
    _reject_duplicates("threshold section", (s for c in contributions for s in c.threshold_sections))
    _validate_threshold_sections(contributions)
    tiers = tuple(t for c in contributions for t in c.tiers)
    _reject_slot_collisions(tiers, _known_actions(plugins, contributions))
    _reject_ungoverned_irreversible(plugins, tiers)

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

    narrowers = tuple(n for c in contributions for n in c.narrowers)
    flags = flags or DecisionFlags.from_env()
    if opa is None:
        from src.gateway.core.policy import OPAClient

        opa = OPAClient()
    if stpa_validator is None:
        from src.gateway.governance.stpa_validator import STPAValidator

        stpa_validator = STPAValidator(rules=uca_rules)
    from src.gateway.governance.schemas.thresholds import get_agent_confidence_threshold

    standing_projector = _single_slot("standing_projector", contributions) or default_standing_projector
    execution_verbs = frozenset(v for c in contributions for v in c.execution_verbs)
    raw_consensus = _single_slot("consensus", contributions)
    magnitude_extractor = _single_slot("magnitude_extractor", contributions)
    if isinstance(raw_consensus, ConsensusContribution):
        from src.gateway.governance.consensus.engine import ConsensusGate

        if raw_consensus.magnitude_extractor is None and magnitude_extractor is not None:
            raw_consensus = dataclasses.replace(
                raw_consensus, magnitude_extractor=magnitude_extractor
            )
        resolved_consensus: ConsensusProvider = ConsensusGate.from_contribution(raw_consensus)
    elif raw_consensus is not None:
        resolved_consensus = raw_consensus  # type: ignore[assignment]
    else:
        resolved_consensus = NullConsensusProvider()

    components = GovernorComponents(
        opa=opa,
        core_stages=kernel_stages(
            opa,
            stpa_validator,
            metrics=metrics,
            magnitude_extractor=magnitude_extractor,  # type: ignore[arg-type]
        ),
        classifier=ClassificationEngine(
            narrower_registry=NarrowerRegistry(narrowers=list(narrowers)),
            confidence_threshold=get_agent_confidence_threshold(),
            defer_enabled=flags.defer,
            narrow_enabled=flags.narrow,
            pause_enabled=flags.pause,
        ),
        domain_tiers=tiers,
        narrowers=narrowers,
        invariants=tuple(invariants),
        uca_rules=uca_rules,
        saga_compensators=saga_compensators,
        ground_truth_providers=ground_truth_providers,
        safety_filter=_single_slot("safety_filter", contributions) or NullSafetyFilter(),
        consensus=resolved_consensus,
        standing_projector=standing_projector,  # type: ignore[arg-type]
        execution_verbs=execution_verbs,
        contributions=contributions,
        posture=posture,
    )
    governor = SymbolicGovernor(components)
    logger.info(
        "governor assembled: domains=%s tiers=%s posture=%s unfilled=%s",
        [c.domain for c in contributions], governor.registered_tier_names(),
        posture.value, components.unfilled_slots,
    )
    return governor


def _contribution_of(plugin: CagePlugin) -> PluginContribution:
    contribution = plugin.contribute()
    if not isinstance(contribution, PluginContribution):
        raise GovernorAssemblyError(f"plugin {plugin.name!r}: contribute() must return a PluginContribution")
    if contribution.domain != plugin.name:
        raise GovernorAssemblyError(
            f"plugin {plugin.name!r} contributed domain {contribution.domain!r}; they must match"
        )
    return contribution


def _reject_duplicates(what: str, names: Iterable[str]) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise GovernorAssemblyError(f"duplicate {what}: {name!r} is contributed twice")
        seen.add(name)


def _validate_threshold_sections(contributions: Sequence[PluginContribution]) -> None:
    from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds

    domains = load_and_validate_thresholds().domains
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


def _single_slot(slot: str, contributions: Sequence[PluginContribution]) -> object | None:
    filled = [(c.domain, getattr(c, slot)) for c in contributions if getattr(c, slot) is not None]
    if len(filled) > 1:
        raise GovernorAssemblyError(f"slot collision: {slot} contributed by {[d for d, _ in filled]}")
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


def _known_actions(plugins: Sequence[CagePlugin], contributions: Sequence[PluginContribution]) -> set[str]:
    actions = {a for c in contributions for a in c.registered_actions}
    for plugin in plugins:
        actions.update(_registry_of(plugin))
    return actions


def _reject_slot_collisions(tiers: Sequence[GovernanceTierPlugin], actions: Iterable[str]) -> None:
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


def _reject_ungoverned_irreversible(plugins: Sequence[CagePlugin], tiers: Sequence[GovernanceTierPlugin]) -> None:
    from src.gateway.governance.ftra.models import TerminalClassification

    irreversible = TerminalClassification.IRREVERSIBLE_TERMINAL.value
    for plugin in plugins:
        for action, classification in sorted(_registry_of(plugin).items()):
            if classification == irreversible and not any(t.claims_action(action, {}) for t in tiers):
                raise GovernorAssemblyError(
                    f"domain {plugin.name!r}: irreversible action {action!r} in its FTRA registry "
                    "is claimed by no tier (ungoverned irreversible action)"
                )
