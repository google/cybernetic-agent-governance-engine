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

"""Domain tiers installed after construction must reach the pipeline.

Regression: plugins assigned ``governor._domain_tiers`` after construction,
but ``self.stages`` was frozen in ``__init__``, so in the server wiring no
domain tier (CBF, fiscal, consensus, dose/kinematic barrier, ...) ever ran.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from src.cage_finance import plugin as finance_plugin
from src.cage_healthcare import plugin as healthcare_plugin
from src.cage_physical_ai import plugin as physical_ai_plugin
from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation, ViolationKind
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import Profile, StageContext, run_pipeline
from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
from src.integrations.nemo import action_registry

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _StubTier(GovernanceTierPlugin):
    def __init__(self, name: str, *, phase: int = 1, deny: bool = False) -> None:
        self._name, self._phase, self._deny = name, phase, deny

    @property
    def tier_name(self) -> str:
        return self._name

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def order(self) -> int:
        return 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "stub_action"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        if self._deny:
            return [Violation(tier=self._name, code="STUB_DENY", message="deny", kind=ViolationKind.HARD)]
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return await self.evaluate(action, params)

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        return None


def _governor(**kwargs: Any) -> SymbolicGovernor:
    return SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        classification_engine=MagicMock(),
        stpa_validator=MagicMock(),
        **kwargs,
    )


def _domain_stage_names(governor: SymbolicGovernor) -> list[str]:
    return [s.name for s in governor.stages if isinstance(s, DomainTierStage)]


def _ctx(action: str) -> StageContext:
    return StageContext(action=action, params={}, profile=Profile.FULL)


# --- classification_engine is required -------------------------------------


def test_missing_classification_engine_fails_at_construction() -> None:
    with pytest.raises(TypeError, match="classification_engine"):
        SymbolicGovernor(opa_client=MagicMock(), safety_filter=MagicMock(), consensus_engine=MagicMock())


# --- add_domain_tiers() -----------------------------------------------------


def test_tiers_added_after_construction_reach_the_pipeline() -> None:
    governor = _governor()
    assert _domain_stage_names(governor) == []

    governor.add_domain_tiers((_StubTier("stub_b"), _StubTier("stub_a")))

    assert _domain_stage_names(governor) == ["stub_a", "stub_b"]
    assert [t.tier_name for t in governor.domain_tiers] == ["stub_a", "stub_b"]


@pytest.mark.asyncio
async def test_tier_added_after_construction_blocks() -> None:
    governor = _governor()
    governor.add_domain_tiers((_StubTier("stub_deny", deny=True),))
    domain_stages = [s for s in governor.stages if isinstance(s, DomainTierStage)]

    result = await run_pipeline(domain_stages, _ctx("stub_action"), profile=Profile.FULL)

    assert [v.code for v in result.violations] == ["STUB_DENY"]


def test_tiers_from_several_domains_accumulate() -> None:
    governor = _governor(domain_tiers=(_StubTier("first"),))
    governor.add_domain_tiers((_StubTier("second"),))
    assert _domain_stage_names(governor) == ["first", "second"]


def test_duplicate_tier_name_across_calls_is_rejected() -> None:
    governor = _governor()
    governor.add_domain_tiers((_StubTier("dup"),))
    with pytest.raises(ValueError, match="duplicate tier registration"):
        governor.add_domain_tiers((_StubTier("dup"),))
    assert _domain_stage_names(governor) == ["dup"]  # state unchanged on rejection


def test_empty_tier_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one tier"):
        _governor().add_domain_tiers(())


# --- real plugins against a real governor -----------------------------------


@pytest.fixture
def isolated_plugin_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep plugin.register() from mutating process-global registries."""
    monkeypatch.setattr(action_registry, "register_rail_provider", lambda _p: None)
    for mod in (finance_plugin, healthcare_plugin, physical_ai_plugin):
        monkeypatch.setattr(mod, "register_overlay_dir", lambda _p: None)
    monkeypatch.setattr(finance_plugin, "install_domain_components", lambda **_k: None)
    monkeypatch.setattr(finance_plugin, "register_background_task", lambda *_a: None)


@pytest.mark.usefixtures("isolated_plugin_side_effects")
def test_all_default_plugins_install_their_tiers_into_the_pipeline() -> None:
    governor = _governor()
    for plugin in (
        finance_plugin.FinanceCagePlugin(),
        healthcare_plugin.HealthcareCagePlugin(),
        physical_ai_plugin.PhysicalAICagePlugin(),
    ):
        plugin.register(governor)

    assert set(_domain_stage_names(governor)) == {
        "bounding", "consensus", "causal", "cbf", "fiscal",
        "clinical_consensus", "dose_barrier",
        "kinematic_barrier", "physical_safety_consensus",
    }


@pytest.mark.usefixtures("isolated_plugin_side_effects")
def test_registering_a_plugin_twice_fails_closed() -> None:
    governor = _governor()
    healthcare_plugin.HealthcareCagePlugin().register(governor)
    with pytest.raises(ValueError, match="duplicate"):
        healthcare_plugin.HealthcareCagePlugin().register(governor)


# --- KinematicBarrierTier without a CBF -------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("hook", ["evaluate", "commit"])
async def test_kinematic_barrier_without_cbf_refuses(hook: str) -> None:
    tier = KinematicBarrierTier(cbf=None)
    violations = await getattr(tier, hook)("dispatch_trajectory", {})
    assert [(v.code, v.kind) for v in violations] == [("KINEMATIC_BARRIER_UNCONFIGURED", ViolationKind.HARD)]


@pytest.mark.asyncio
@pytest.mark.usefixtures("isolated_plugin_side_effects")
async def test_physical_ai_plugin_denies_governed_action_end_to_end() -> None:
    governor = _governor()
    physical_ai_plugin.PhysicalAICagePlugin().register(governor)
    kinematic = [s for s in governor.stages if isinstance(s, DomainTierStage) and s.name == "kinematic_barrier"]

    result = await run_pipeline(kinematic, _ctx("dispatch_trajectory"), profile=Profile.FULL)

    assert "KINEMATIC_BARRIER_UNCONFIGURED" in {v.code for v in result.violations}
