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

"""Domain tiers contributed at assembly must reach the pipeline.

Regression: plugins once assigned ``governor._domain_tiers`` after
construction while ``self.stages`` was frozen in ``__init__``, so in the
server wiring no domain tier (CBF, fiscal, consensus, dose/kinematic barrier,
...) ever ran. The governor is now immutable: tiers arrive only through
``GovernorComponents`` and every one becomes a pipeline stage.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_healthcare.plugin import HealthcareCagePlugin
from src.cage_physical_ai.plugin import PhysicalAICagePlugin
from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation, ViolationKind
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import DecisionFlags, GovernorComponents, assemble_governor
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import Profile, StageContext, run_pipeline
from src.gateway.governance.governor.reservation import ReservationScope
from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
from tests.fixtures.governor import allow_opa, clean_stpa, make_governor

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


def _assemble(*plugins: Any) -> SymbolicGovernor:
    return assemble_governor(
        list(plugins),
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False, pause=False),
    )


def _domain_stage_names(governor: SymbolicGovernor) -> list[str]:
    return [s.name for s in governor.stages if isinstance(s, DomainTierStage)]


def _ctx(action: str) -> StageContext:
    return StageContext(action=action, params={}, profile=Profile.FULL)


# --- classifier is required -------------------------------------------------


def test_missing_classifier_fails_at_construction() -> None:
    with pytest.raises(TypeError, match="classifier"):
        GovernorComponents(opa=allow_opa(), core_stages=(), classifier=None)  # type: ignore[arg-type]


# --- tiers supplied through GovernorComponents -------------------------------


def test_constructed_tiers_reach_the_pipeline_in_order() -> None:
    governor = make_governor(domain_tiers=(_StubTier("stub_b"), _StubTier("stub_a")))
    assert _domain_stage_names(governor) == ["stub_a", "stub_b"]
    assert [t.tier_name for t in governor.domain_tiers] == ["stub_a", "stub_b"]


def test_governor_without_tiers_has_no_domain_stages() -> None:
    assert _domain_stage_names(make_governor()) == []


@pytest.mark.asyncio
async def test_constructed_tier_blocks() -> None:
    governor = make_governor(domain_tiers=(_StubTier("stub_deny", deny=True),))
    domain_stages = [s for s in governor.stages if isinstance(s, DomainTierStage)]

    async with ReservationScope() as scope:
        result = await run_pipeline(domain_stages, _ctx("stub_action"), profile=Profile.FULL, scope=scope)

    assert [v.code for v in result.violations] == ["STUB_DENY"]


def test_tiers_cannot_be_installed_after_construction() -> None:
    governor = make_governor(domain_tiers=(_StubTier("first"),))
    with pytest.raises(AttributeError, match="immutable"):
        governor._stages = ()  # type: ignore[misc]
    assert _domain_stage_names(governor) == ["first"]  # state unchanged on rejection


def test_duplicate_tier_name_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="duplicate tier registration"):
        make_governor(domain_tiers=(_StubTier("dup"), _StubTier("dup")))


# --- real plugins through the composition root -------------------------------


@pytest.mark.parametrize(
    ("plugin_cls", "expected"),
    [
        (FinanceCagePlugin, {"bounding", "consensus", "causal", "cbf", "fiscal"}),
        (HealthcareCagePlugin, {"clinical_consensus", "dose_barrier"}),
        (PhysicalAICagePlugin, {"kinematic_barrier", "physical_safety_consensus"}),
    ],
)
def test_each_plugin_contributes_its_tiers_into_the_pipeline(plugin_cls, expected) -> None:
    governor = _assemble(plugin_cls())
    assert set(_domain_stage_names(governor)) == expected


def test_contribution_is_data_and_does_not_mutate_a_governor() -> None:
    """contribute() hands back tiers; nothing reaches a governor outside assembly."""
    governor = make_governor()
    FinanceCagePlugin().contribute()
    assert _domain_stage_names(governor) == []


# --- KinematicBarrierTier without a CBF -------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("hook", ["evaluate", "commit"])
async def test_kinematic_barrier_without_cbf_refuses(hook: str) -> None:
    tier = KinematicBarrierTier(cbf=None)
    out = await getattr(tier, hook)("dispatch_trajectory", {})
    violations, receipt = (out, None) if hook == "evaluate" else out
    assert receipt is None  # nothing mutated
    assert [(v.code, v.kind) for v in violations] == [("KINEMATIC_BARRIER_UNCONFIGURED", ViolationKind.HARD)]


@pytest.mark.asyncio
async def test_physical_ai_plugin_denies_governed_action_end_to_end() -> None:
    governor = _assemble(PhysicalAICagePlugin())
    kinematic = [s for s in governor.stages if isinstance(s, DomainTierStage) and s.name == "kinematic_barrier"]

    async with ReservationScope() as scope:
        result = await run_pipeline(kinematic, _ctx("dispatch_trajectory"), profile=Profile.FULL, scope=scope)

    assert "KINEMATIC_BARRIER_UNCONFIGURED" in {v.code for v in result.violations}
