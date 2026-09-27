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
        """Plugin contributes invariants and tiers; assembly installs them on the governor."""
        from src.gateway.governance.env_posture import DeploymentPosture
        from src.gateway.governance.governor.assembly import (
            DecisionFlags,
            assemble_governor,
        )
        from tests.fixtures.governor import allow_opa, clean_stpa

        plugin = PhysicalAICagePlugin()
        contribution = plugin.contribute()

        assert contribution.domain == "physical_ai"
        # Invariants contributed
        assert len(contribution.invariants) == 3
        # Tiers contributed
        assert len(contribution.tiers) == 2

        # Assembly validates the invariants (V1-V4) and installs the tiers.
        governor = assemble_governor(
            [plugin],
            posture=DeploymentPosture.DEV,
            opa=allow_opa(),
            stpa_validator=clean_stpa(),
            flags=DecisionFlags(defer=True, narrow=False, pause=False),
        )
        assert len(governor.components.invariants) == 3
        assert len(governor.components.ground_truth_providers) == 3
        assert {"kinematic_barrier", "physical_safety_consensus"} <= set(
            governor.registered_tier_names()
        )

    @pytest.mark.asyncio
    async def test_physical_ai_barriers_enforced_end_to_end_via_governor(self):
        """SpatialSeparationBarrier, KinematicVelocityBarrier, and TorqueSaturationBarrier enforce limits via SymbolicGovernor."""
        from unittest.mock import AsyncMock, MagicMock, patch

        fakeredis_sync = pytest.importorskip("fakeredis")
        fakeredis = pytest.importorskip("fakeredis.aioredis")

        from src.gateway.governance.env_posture import DeploymentPosture
        from src.gateway.governance.governor.assembly import (
            DecisionFlags,
            assemble_governor,
        )
        from src.gateway.governance.governor.pipeline import (
            Profile,
            StageContext,
            run_pipeline,
        )
        from src.gateway.governance.governor.reservation import ReservationScope
        from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
        from tests.fixtures.governor import allow_opa, clean_stpa

        server = fakeredis_sync.FakeServer()
        sync_redis = fakeredis_sync.FakeRedis(server=server, decode_responses=True)
        fake_redis = fakeredis.FakeRedis(server=server, decode_responses=True)
        await fake_redis.set("safety:separation_distance_mm", "1200.0")
        await fake_redis.set("safety:end_effector_velocity_mm_s", "450.0")
        await fake_redis.set("safety:joint_torque_nm", "85.0")
        await fake_redis.set("safety:fence_epoch", "0")

        mock_redis_mod = MagicMock()
        mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", False),
            patch(
                "src.gateway.governance.governor.sealing.issue_seal",
                AsyncMock(return_value="sealed-token"),
            ),
        ):
            governor = assemble_governor(
                [PhysicalAICagePlugin()],
                posture=DeploymentPosture.DEV,
                opa=allow_opa(),
                stpa_validator=clean_stpa(),
                flags=DecisionFlags(defer=False, narrow=False, pause=False),
            )
            assert len(governor._components.ground_truth_providers) == 3
            for stage in governor.stages:
                if stage.name == "ftra":
                    stage.run = AsyncMock(return_value=[])  # type: ignore[method-assign]
            for tier in governor.domain_tiers:
                if tier.tier_name == "physical_safety_consensus":
                    tier.consensus_engine = MagicMock(
                        check_consensus=AsyncMock(return_value={"status": "APPROVED"})
                    )

            # 1. Safe trajectory within spatial, velocity, and torque envelopes -> ALLOW via governor.validate_action
            safe_res = await governor.validate_action(
                "dispatch_trajectory",
                {
                    "approach_distance_mm": 100.0,
                    "target_velocity_mm_s": 50.0,
                    "torque_nm": 5.0,
                    "confidence": 0.95,
                },
            )
            assert safe_res["verdict"] == "ALLOW"
            assert safe_res["violations"] == []

            # 2. Spatial separation breach -> KINEMATIC_BARRIER_VIOLATED via governor.verify
            spatial_breach = await governor.verify(
                "dispatch_trajectory",
                {
                    "approach_distance_mm": 900.0,
                    "target_velocity_mm_s": 20.0,
                    "confidence": 0.95,
                },
            )
            assert any(
                "KINEMATIC_BARRIER_VIOLAT" in v.code
                for v in spatial_breach["violations"]
            )

            # 3. Kinematic velocity breach -> KINEMATIC_BARRIER_VIOLATED via governor.verify
            velocity_breach = await governor.verify(
                "dispatch_trajectory",
                {
                    "approach_distance_mm": 10.0,
                    "target_velocity_mm_s": 300.0,
                    "confidence": 0.95,
                },
            )
            assert any(
                "KINEMATIC_BARRIER_VIOLAT" in v.code
                for v in velocity_breach["violations"]
            )

            # 4. Joint torque saturation breach -> KINEMATIC_BARRIER_VIOLATED via governor.verify
            torque_breach = await governor.verify(
                "actuate_joint",
                {
                    "torque_nm": 60.0,
                    "confidence": 0.95,
                },
            )
            assert any(
                "KINEMATIC_BARRIER_VIOLAT" in v.code
                for v in torque_breach["violations"]
            )
