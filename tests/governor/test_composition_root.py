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

"""PR 4a: the composition root (``assemble_governor``) and the immutable governor.

Every rejection path of :func:`assemble_governor` is observed failing here.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass
from typing import Any

import pytest

from src.gateway.governance.contracts import (
    GovernanceTierPlugin,
    InvariantModel,
    PluginContribution,
    Violation,
)
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorAssemblyError,
    GovernorComponents,
    assemble_governor,
)
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.null_components import (
    NullConsensusProvider,
    NullSafetyFilter,
)
from tests.fixtures.governor import allow_opa, clean_stpa

pytestmark = [pytest.mark.unit, pytest.mark.local]

_POSTURE = DeploymentPosture.TEST
_FLAGS = DecisionFlags(defer=False, narrow=False, pause=False)


class _Tier(GovernanceTierPlugin):
    def __init__(self, name: str, actions: tuple[str, ...], phase: int = 1, order: int = 1) -> None:
        self._name, self._phase, self._order, self._actions = name, phase, order, actions

    @property
    def tier_name(self) -> str:
        return self._name

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def order(self) -> int:
        return self._order

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in self._actions

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []


class _Plugin:
    api_version = "1.0"

    def __init__(self, name: str, domain_config: Any = None, **contribution: Any) -> None:
        self.name = name
        self.domain_config = domain_config
        self._contribution = {"domain": name, **contribution}

    def contribute(self) -> PluginContribution:
        return PluginContribution(**self._contribution)


class _Registry:
    """A DomainConfig stand-in: only ``ftra_registry_path`` is read at assembly."""

    def __init__(self, path: Any) -> None:
        self.ftra_registry_path = path


@dataclass(frozen=True)
class _Barrier:
    """A declarative affine barrier (see ``contracts.InvariantModel``)."""

    invariant_id: str
    state_key: str = "safety:test_cash"
    threshold_key: str = "cbf.min_cash_balance"
    gamma: float = 0.5


def _barrier(invariant_id: str = "test.cash_floor", **overrides: Any) -> InvariantModel:
    return _Barrier(invariant_id, **overrides)


def _assemble(*plugins: Any) -> Any:
    return assemble_governor(list(plugins), posture=_POSTURE, opa=allow_opa(), stpa_validator=clean_stpa(), flags=_FLAGS)


# ── Rejections ────────────────────────────────────────────────────────────────


def test_rejects_slot_collision() -> None:
    plugin = _Plugin(
        "alpha",
        tiers=(_Tier("a1", ("move",)), _Tier("a2", ("move",))),
        registered_actions=("move",),
    )
    with pytest.raises(GovernorAssemblyError, match="slot collision"):
        _assemble(plugin)


def test_same_action_in_different_slots_is_allowed() -> None:
    plugin = _Plugin(
        "alpha",
        tiers=(_Tier("a1", ("move",), order=1), _Tier("a2", ("move",), order=2)),
        registered_actions=("move",),
    )
    assert _assemble(plugin).registered_tier_names() == ["a1", "a2"]


def test_rejects_duplicate_domain() -> None:
    with pytest.raises(GovernorAssemblyError, match="duplicate domain"):
        _assemble(_Plugin("alpha"), _Plugin("alpha"))


def test_rejects_domain_that_is_not_the_plugin_name() -> None:
    plugin = _Plugin("alpha")
    plugin._contribution["domain"] = "beta"
    with pytest.raises(GovernorAssemblyError, match="must match"):
        _assemble(plugin)


def test_rejects_non_contribution() -> None:
    plugin = _Plugin("alpha")
    plugin.contribute = lambda: {"domain": "alpha"}  # type: ignore[method-assign]
    with pytest.raises(GovernorAssemblyError, match="PluginContribution"):
        _assemble(plugin)


def test_rejects_duplicate_threshold_section() -> None:
    with pytest.raises(GovernorAssemblyError, match="duplicate threshold section"):
        _assemble(
            _Plugin("alpha", threshold_sections={"limits": object}),
            _Plugin("beta", threshold_sections={"limits": object}),
        )


def test_rejects_ungoverned_irreversible_action(tmp_path: Any) -> None:
    registry = tmp_path / "registry.json"
    registry.write_text('{"domain": "alpha", "terminals": {"wire": "IRREVERSIBLE_TERMINAL", "peek": "READ_ONLY"}}')
    plugin = _Plugin("alpha", domain_config=_Registry(registry), tiers=(_Tier("t", ("other",)),))
    with pytest.raises(GovernorAssemblyError, match="ungoverned irreversible action"):
        _assemble(plugin)


def test_claimed_irreversible_and_unclaimed_reversible_actions_assemble(tmp_path: Any) -> None:
    registry = tmp_path / "registry.json"
    registry.write_text('{"domain": "alpha", "terminals": {"wire": "IRREVERSIBLE_TERMINAL", "peek": "READ_ONLY"}}')
    plugin = _Plugin("alpha", domain_config=_Registry(registry), tiers=(_Tier("t", ("wire",)),))
    assert _assemble(plugin).registered_tier_names() == ["t"]


def test_rejects_two_contributions_filling_one_engine_slot() -> None:
    with pytest.raises(GovernorAssemblyError, match="safety_filter"):
        _assemble(_Plugin("alpha", safety_filter=object()), _Plugin("beta", safety_filter=object()))


def test_rejects_invalid_invariant() -> None:
    bad = _barrier(state_key="unnamespaced")  # V2: state_key must contain ':'
    with pytest.raises(ValueError, match="namespaced"):
        _assemble(_Plugin("alpha", invariants=(bad,)))


def test_rejects_duplicate_invariant_across_domains() -> None:
    with pytest.raises(ValueError, match="duplicate invariant"):
        _assemble(_Plugin("alpha", invariants=(_barrier(),)), _Plugin("beta", invariants=(_barrier(),)))


def test_valid_invariants_are_recorded_on_components() -> None:
    governor = _assemble(_Plugin("alpha", invariants=(_barrier("alpha.a"),)), _Plugin("beta", invariants=(_barrier("beta.b"),)))
    assert [i.invariant_id for i in governor.components.invariants] == ["alpha.a", "beta.b"]


# ── Immutability ──────────────────────────────────────────────────────────────


def test_governor_rejects_setattr_and_delattr() -> None:
    governor = _assemble()
    with pytest.raises(AttributeError, match="immutable"):
        governor.stages = ()  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        del governor._components


def test_components_are_frozen() -> None:
    governor = _assemble()
    with pytest.raises(FrozenInstanceError):
        governor.components.domain_tiers = ()  # type: ignore[misc]


def test_components_require_a_classifier() -> None:
    with pytest.raises(TypeError, match="classifier"):
        GovernorComponents(opa=allow_opa(), core_stages=(), classifier=None)  # type: ignore[arg-type]


# ── Empty governor ────────────────────────────────────────────────────────────


def test_no_plugins_leaves_null_engines_and_reports_unfilled_slots() -> None:
    components = _assemble().components
    assert isinstance(components.safety_filter, NullSafetyFilter)
    assert isinstance(components.consensus, NullConsensusProvider)
    assert components.unfilled_slots == ("safety_filter", "consensus")


_IRREVERSIBLE = ("execute_trade", {"symbol": "AAPL", "amount": 100.0, "confidence": 0.99})


async def test_empty_governor_denies_govern() -> None:
    with pytest.raises(GovernanceError):
        await _assemble().govern(*_IRREVERSIBLE)


async def test_empty_governor_denies_validate_action() -> None:
    try:
        result = await _assemble().validate_action(*_IRREVERSIBLE)
    except GovernanceError:
        return
    assert result["verdict"] != "ALLOW" and not result.get("seal")


async def test_empty_governor_denies_verify() -> None:
    result = await _assemble().verify(*_IRREVERSIBLE)
    assert result["violations"]


async def test_empty_governor_denies_revalidate_post_hitl() -> None:
    with pytest.raises(GovernanceError):
        await _assemble().revalidate_post_hitl(*_IRREVERSIBLE)


# ── Bootstrap ─────────────────────────────────────────────────────────────────


def test_bootstrap_registers_the_domain_overlays(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.gateway.governance import constants
    from src.gateway.governance.governor.bootstrap import bootstrap_governor

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", [])
    governor = bootstrap_governor(opa=allow_opa(), stpa_validator=clean_stpa())
    expected = {d.resolve() for c in governor.components.contributions for d in c.compliance_overlay_dirs}
    assert expected and expected <= set(constants._OVERLAY_DIRS)


def test_bootstrap_refuses_unfilled_engine_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.gateway.governance import plugin_loader
    from src.gateway.governance.governor.bootstrap import bootstrap_governor

    monkeypatch.setattr(plugin_loader, "load_domain_plugin", lambda: _Plugin("alpha"))
    monkeypatch.setattr(plugin_loader, "domain_config_of", lambda plugin: None)
    with pytest.raises(RuntimeError, match="unfilled"):
        bootstrap_governor(opa=allow_opa(), stpa_validator=clean_stpa())


def test_registering_an_overlay_reloads_a_loaded_registry(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    from src.gateway.governance import constants

    monkeypatch.setattr(constants, "_OVERLAY_DIRS", list(constants._OVERLAY_DIRS))
    loaded = constants.ControlRegistry()
    constants.register_overlay_dir(tmp_path)
    assert constants.ControlRegistry() is not loaded
