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

"""Physical AI plugin tests (unit & local markers).

Validates that the Physical AI domain plugin adheres to CAGE's Layer 2
plugin architecture and declarative invariant specification.
"""

from unittest.mock import MagicMock

import pytest

from src.cage_physical_ai import create_physical_ai_tiers
from src.cage_physical_ai.constants import (
    CTRL_PHYS_001,
    CTRL_PHYS_002,
    CTRL_PHYS_003,
    CTRL_PHYS_004,
    PHYSICAL_AI_GOVERNED_ACTIONS,
)
from src.cage_physical_ai.invariants import (
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
    physical_cost_resolver,
)
from src.cage_physical_ai.plugin import PhysicalAICagePlugin, get_plugin
from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier
from src.cage_physical_ai.tiers.physical_consensus_tier import (
    PhysicalSafetyConsensusTier,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestPhysicalAIPlugin:
    """Physical AI plugin and invariant tests."""

    def test_plugin_metadata(self):
        """Plugin has expected metadata."""
        plugin = PhysicalAICagePlugin()
        assert plugin.name == "physical_ai"
        assert plugin.api_version == "1.0"
        assert isinstance(get_plugin(), PhysicalAICagePlugin)

    def test_control_constants(self):
        """Physical AI controls are defined."""
        assert CTRL_PHYS_001 == "CTRL_PHYS_001"
        assert CTRL_PHYS_002 == "CTRL_PHYS_002"
        assert CTRL_PHYS_003 == "CTRL_PHYS_003"
        assert CTRL_PHYS_004 == "CTRL_PHYS_004"
        assert "dispatch_trajectory" in PHYSICAL_AI_GOVERNED_ACTIONS
        assert "actuate_joint" in PHYSICAL_AI_GOVERNED_ACTIONS

    def test_spatial_barrier_declarative(self):
        """Spatial separation barrier is purely declarative."""
        barrier = SpatialSeparationBarrier()
        assert barrier.invariant_id == "physical_ai.spatial_separation"
        assert barrier.state_key == "safety:separation_distance_mm"
        assert barrier.threshold_key == "physical_ai.min_separation_distance_mm"
        assert barrier.gamma == 0.5

    def test_kinematic_velocity_barrier_declarative(self):
        """Kinematic velocity barrier is purely declarative."""
        barrier = KinematicVelocityBarrier()
        assert barrier.invariant_id == "physical_ai.kinematic_velocity"
        assert barrier.state_key == "safety:end_effector_velocity_mm_s"
        assert barrier.threshold_key == "physical_ai.max_velocity_mm_s"
        assert barrier.gamma == 0.4

    def test_torque_saturation_barrier_declarative(self):
        """Torque saturation barrier is purely declarative."""
        barrier = TorqueSaturationBarrier()
        assert barrier.invariant_id == "physical_ai.torque_saturation"
        assert barrier.state_key == "safety:joint_torque_nm"
        assert barrier.threshold_key == "physical_ai.max_joint_torque_nm"
        assert barrier.gamma == 0.3

    def test_physical_cost_resolver(self):
        """Physical cost resolver parses velocity and rejects invalid inputs."""
        assert physical_cost_resolver("unrelated_action", {}) == 0.0

        cost = physical_cost_resolver(
            "dispatch_trajectory", {"target_velocity_mm_s": 250.0}
        )
        assert cost == 250.0

        with pytest.raises(ValueError, match="invalid target velocity"):
            physical_cost_resolver(
                "dispatch_trajectory", {"target_velocity_mm_s": -10.0}
            )

        with pytest.raises(ValueError, match="invalid target velocity"):
            physical_cost_resolver(
                "dispatch_trajectory", {"target_velocity_mm_s": float("nan")}
            )

    def test_tier_factory(self):
        """Tier factory creates kinematic and consensus tiers."""
        tiers = create_physical_ai_tiers()
        assert len(tiers) == 2
        assert isinstance(tiers[0], KinematicBarrierTier)
        assert isinstance(tiers[1], PhysicalSafetyConsensusTier)

        kinematic_tier = tiers[0]
        assert kinematic_tier.tier_name == "kinematic_barrier"
        assert kinematic_tier.phase == 2
        assert kinematic_tier.order == 3
        assert kinematic_tier.claims_action("dispatch_trajectory", {}) is True
        assert kinematic_tier.claims_action("unknown_action", {}) is False

        consensus_tier = tiers[1]
        assert consensus_tier.tier_name == "physical_safety_consensus"
        assert consensus_tier.phase == 1
        assert consensus_tier.order == 5
        assert consensus_tier.claims_action("actuate_joint", {}) is True

    def test_plugin_registration(self):
        """Plugin registers invariants and tiers with governor."""
        plugin = PhysicalAICagePlugin()
        mock_governor = MagicMock()
        mock_governor._domain_tiers = None
        mock_server = MagicMock()

        plugin.register(mock_governor, tool_server=mock_server)

        # Invariants registered
        assert mock_governor.register_invariant.call_count == 3
        # Tiers assigned
        assert mock_governor._domain_tiers is not None
        assert len(mock_governor._domain_tiers) == 2
