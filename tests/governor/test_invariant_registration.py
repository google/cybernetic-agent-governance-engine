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

"""Fail-closed registration checks for declarative safety barriers (V1–V4)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src.cage_healthcare import plugin as healthcare_plugin
from src.cage_physical_ai import plugin as physical_ai_plugin
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.schemas.thresholds import PhysicalAIThresholds
from src.integrations.nemo import action_registry

pytestmark = [pytest.mark.unit, pytest.mark.local]


@dataclass(frozen=True)
class _Barrier:
    invariant_id: str = "test.serum"
    state_key: str = "safety:test_serum"
    threshold_key: str = "healthcare.min_therapeutic_concentration"
    gamma: float = 0.5


@pytest.fixture
def governor() -> SymbolicGovernor:
    # Same construction shape as tests/governor/golden/fixtures.py; the
    # collaborators are irrelevant to registration.
    return SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        classification_engine=MagicMock(),
        stpa_validator=MagicMock(),
    )


def test_valid_barrier_is_accepted(governor: SymbolicGovernor) -> None:
    barrier = _Barrier()
    governor.register_invariant(barrier)
    assert governor._invariants == [barrier]


def test_v1_duplicate_invariant_id_is_rejected(governor: SymbolicGovernor) -> None:
    governor.register_invariant(_Barrier())
    with pytest.raises(ValueError, match="duplicate invariant registration: test.serum"):
        governor.register_invariant(_Barrier(state_key="safety:other"))
    assert len(governor._invariants) == 1


@pytest.mark.parametrize("state_key", ["serum", "", "safety.serum"])
def test_v2_unnamespaced_state_key_is_rejected(
    governor: SymbolicGovernor, state_key: str
) -> None:
    with pytest.raises(ValueError, match="state_key must be namespaced"):
        governor.register_invariant(_Barrier(state_key=state_key))
    assert governor._invariants == []


@pytest.mark.parametrize(
    "threshold_key",
    [
        "healthcare.no_such_threshold",  # KeyError at leaf
        "no_such_domain.value",  # KeyError at root
        "healthcare.min_therapeutic_concentration.deeper",  # TypeError: scalar indexed
        "",
    ],
)
def test_v3_unresolvable_threshold_key_is_rejected(
    governor: SymbolicGovernor, threshold_key: str
) -> None:
    with pytest.raises(ValueError, match="does not resolve in THRESHOLDS tree"):
        governor.register_invariant(_Barrier(threshold_key=threshold_key))
    assert governor._invariants == []


@pytest.mark.parametrize("gamma", [0.0, -0.1, 1.0001, 2.0, float("nan")])
def test_v4_gamma_out_of_range_is_rejected(
    governor: SymbolicGovernor, gamma: float
) -> None:
    with pytest.raises(ValueError, match=r"gamma must be in \(0, 1\]"):
        governor.register_invariant(_Barrier(gamma=gamma))
    assert governor._invariants == []


def test_v4_gamma_upper_bound_is_inclusive(governor: SymbolicGovernor) -> None:
    governor.register_invariant(replace(_Barrier(), gamma=1.0))
    assert len(governor._invariants) == 1


@pytest.fixture
def isolated_plugin_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep plugin.register() from mutating process-global registries."""
    monkeypatch.setattr(action_registry, "register_rail_provider", lambda _p: None)
    monkeypatch.setattr(healthcare_plugin, "register_overlay_dir", lambda _p: None)
    monkeypatch.setattr(physical_ai_plugin, "register_overlay_dir", lambda _p: None)


@pytest.mark.usefixtures("isolated_plugin_side_effects")
def test_real_healthcare_barriers_register_against_real_thresholds(
    governor: SymbolicGovernor,
) -> None:
    healthcare_plugin.HealthcareCagePlugin().register(governor)
    assert [i.invariant_id for i in governor._invariants] == [
        "healthcare.serum_concentration"
    ]


@pytest.mark.usefixtures("isolated_plugin_side_effects")
def test_real_physical_ai_barriers_register_against_real_thresholds(
    governor: SymbolicGovernor,
) -> None:
    physical_ai_plugin.PhysicalAICagePlugin().register(governor)
    assert [i.invariant_id for i in governor._invariants] == [
        "physical_ai.spatial_separation",
        "physical_ai.kinematic_velocity",
        "physical_ai.torque_saturation",
    ]


@pytest.mark.usefixtures("isolated_plugin_side_effects")
def test_registering_same_plugin_twice_fails_closed(governor: SymbolicGovernor) -> None:
    healthcare_plugin.HealthcareCagePlugin().register(governor)
    with pytest.raises(ValueError, match="duplicate invariant registration"):
        healthcare_plugin.HealthcareCagePlugin().register(governor)


@pytest.mark.parametrize(
    "field", ["min_separation_distance_mm", "max_velocity_mm_s", "max_joint_torque_nm"]
)
@pytest.mark.parametrize("value", [0.0, -1.0])
def test_physical_ai_thresholds_reject_non_positive_limits(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        PhysicalAIThresholds(**{field: value})
