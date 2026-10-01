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

"""Fail-closed assembly checks for contributed declarative safety barriers (V1-V4).

``assemble_governor`` validates every contributed invariant. The basic
rejection paths (one invalid invariant, a duplicate across domains) live in
``test_composition_root.py``; this module covers each V1-V4 rule in detail and
the real domain plugins' barriers against the real THRESHOLDS tree.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest
from pydantic import ValidationError

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_healthcare.plugin import HealthcareCagePlugin
from src.cage_physical_ai.plugin import PhysicalAICagePlugin
from src.cage_physical_ai.thresholds import PhysicalAIThresholds
from src.gateway.governance.contracts import PluginContribution
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorAssemblyError,
    assemble_governor,
)
from src.gateway.governance.governor.governor import SymbolicGovernor
from tests.fixtures.governor import allow_opa, clean_stpa

pytestmark = [pytest.mark.unit, pytest.mark.local]

_FLAGS = DecisionFlags(defer=False, narrow=False)


@dataclass(frozen=True)
class _Barrier:
    invariant_id: str = "test.serum"
    state_key: str = "safety:test_serum"
    threshold_key: str = "domains.healthcare.min_therapeutic_concentration"
    gamma: float = 0.5


class _Plugin:
    api_version = "1.0"
    domain_config = None

    def __init__(self, name: str, *invariants: Any) -> None:
        self.name = name
        self._invariants = invariants

    def contribute(self) -> PluginContribution:
        return PluginContribution(domain=self.name, invariants=tuple(self._invariants))


def _assemble(*plugins: Any) -> SymbolicGovernor:
    return assemble_governor(
        list(plugins), posture=DeploymentPosture.TEST, opa=allow_opa(), stpa_validator=clean_stpa(), flags=_FLAGS
    )


def test_valid_barrier_is_recorded_on_components() -> None:
    barrier = _Barrier()
    assert _assemble(_Plugin("alpha", barrier)).components.invariants == (barrier,)


def test_v1_duplicate_invariant_id_within_one_domain_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate invariant registration: test.serum"):
        _assemble(_Plugin("alpha", _Barrier(), _Barrier(state_key="safety:other")))


@pytest.mark.parametrize("state_key", ["serum", "", "safety.serum"])
def test_v2_unnamespaced_state_key_is_rejected(state_key: str) -> None:
    with pytest.raises(ValueError, match="state_key must be namespaced"):
        _assemble(_Plugin("alpha", _Barrier(state_key=state_key)))


@pytest.mark.parametrize(
    "threshold_key",
    [
        "domains.healthcare.no_such_threshold",  # KeyError at leaf
        "domains.no_such_domain.value",  # KeyError at domain
        "no_such_root.value",  # KeyError at root
        "domains.healthcare.min_therapeutic_concentration.deeper",  # KeyError: scalar indexed
        "",
    ],
)
def test_v3_unresolvable_threshold_key_is_rejected(threshold_key: str) -> None:
    with pytest.raises(ValueError, match="does not resolve in THRESHOLDS tree"):
        _assemble(_Plugin("alpha", _Barrier(threshold_key=threshold_key)))


@pytest.mark.parametrize("gamma", [0.0, -0.1, 1.0001, 2.0, float("nan")])
def test_v4_gamma_out_of_range_is_rejected(gamma: float) -> None:
    with pytest.raises(ValueError, match=r"gamma must be in \(0, 1\]"):
        _assemble(_Plugin("alpha", _Barrier(gamma=gamma)))


def test_v4_gamma_upper_bound_is_inclusive() -> None:
    assert len(_assemble(_Plugin("alpha", replace(_Barrier(), gamma=1.0))).components.invariants) == 1


def test_one_invalid_invariant_rejects_the_whole_assembly() -> None:
    """A valid domain does not survive alongside an invalid one: no partial governor."""
    with pytest.raises(ValueError, match="gamma"):
        _assemble(_Plugin("alpha", _Barrier()), _Plugin("beta", _Barrier("beta.x", gamma=0.0)))


def test_real_finance_barrier_is_validated_and_recorded() -> None:
    governor = _assemble(FinanceCagePlugin())
    assert [i.invariant_id for i in governor.components.invariants] == ["finance.cash_balance"]


def test_real_healthcare_barriers_validate_against_real_thresholds() -> None:
    governor = _assemble(HealthcareCagePlugin())
    assert [i.invariant_id for i in governor.components.invariants] == ["healthcare.serum_concentration"]


def test_real_physical_ai_barriers_validate_against_real_thresholds() -> None:
    governor = _assemble(PhysicalAICagePlugin())
    assert [i.invariant_id for i in governor.components.invariants] == [
        "physical_ai.spatial_separation",
        "physical_ai.kinematic_velocity",
        "physical_ai.torque_saturation",
    ]


def test_contributing_same_plugin_twice_fails_closed() -> None:
    with pytest.raises(GovernorAssemblyError, match="duplicate domain"):
        _assemble(HealthcareCagePlugin(), HealthcareCagePlugin())


def test_invariant_colliding_with_a_real_plugin_barrier_fails_closed() -> None:
    """V1 spans every domain: a second plugin cannot shadow a real barrier id."""
    shadow = _Barrier("healthcare.serum_concentration")
    with pytest.raises(ValueError, match="duplicate invariant registration"):
        _assemble(HealthcareCagePlugin(), _Plugin("shadow", shadow))


@pytest.mark.parametrize(
    "field", ["min_separation_distance_mm", "max_velocity_mm_s", "max_joint_torque_nm"]
)
@pytest.mark.parametrize("value", [0.0, -1.0])
def test_physical_ai_thresholds_reject_non_positive_limits(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        PhysicalAIThresholds(**{field: value})
