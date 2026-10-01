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

"""Physical AI / Robotics domain capability plugin.

Demonstrates CAGE's generality: physical agent AI is just another regulated
domain alongside finance and healthcare.

Note what is absent: no Lua scripts, no fence-epoch logic, no KMS verification,
no quota reserver, no consensus algorithm, no causal refutation engine. Every one
of those is a single kernel copy shared across all domains. This plugin only
names things.
"""

from pathlib import Path

from src.cage_physical_ai import create_physical_ai_tiers
from src.cage_physical_ai.ground_truth import (
    SimulatedSpatialSensorProvider,
    SimulatedTorqueSensorProvider,
    SimulatedVelocitySensorProvider,
    spatial_cost_resolver,
    torque_cost_resolver,
    velocity_cost_resolver,
)
from src.cage_physical_ai.invariants import (
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
)
from src.cage_physical_ai.thresholds import PhysicalAIThresholds
from src.cage_physical_ai.tiers.physical_consensus_tier import (
    build_physical_consensus_contribution,
)
from src.cage_physical_ai.tools.tool_provider import PhysicalAIToolProvider
from src.gateway.governance.consensus.engine import extract_field_magnitude
from src.gateway.governance.contracts import (
    CagePlugin,
    DomainConfig,
    PluginContribution,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction


class PhysicalAICagePlugin(CagePlugin):
    """Physical AI / Robotics domain capability plugin.

    A purely declarative plugin defining physical safety invariants,
    collaborative robotics compliance overlays, and embodied tools.
    """

    name: str = "physical_ai"
    api_version: str = "1.0"
    # No physical-AI FTRA registry yet: the domain refuses to start (POAM-2026-077).
    domain_config: DomainConfig | None = None

    def contribute(self) -> PluginContribution:
        overlay_dir = Path(__file__).parent / "config" / "compliance"
        spatial_barrier = SpatialSeparationBarrier()
        velocity_barrier = KinematicVelocityBarrier()
        torque_barrier = TorqueSaturationBarrier()

        spatial_cbf = ControlBarrierFunction(
            cost_resolver=spatial_cost_resolver,
            invariant=spatial_barrier,
            skip_epoch_seed=True,
        )
        velocity_cbf = ControlBarrierFunction(
            cost_resolver=velocity_cost_resolver,
            invariant=velocity_barrier,
            skip_epoch_seed=True,
        )
        torque_cbf = ControlBarrierFunction(
            cost_resolver=torque_cost_resolver,
            invariant=torque_barrier,
            skip_epoch_seed=True,
        )

        spatial_provider = SimulatedSpatialSensorProvider()
        velocity_provider = SimulatedVelocitySensorProvider()
        torque_provider = SimulatedTorqueSensorProvider()

        return PluginContribution(
            domain=self.name,
            tiers=create_physical_ai_tiers(
                cbf=(spatial_cbf, velocity_cbf, torque_cbf),
            ),
            invariants=(spatial_barrier, velocity_barrier, torque_barrier),
            magnitude_extractor=extract_field_magnitude("velocity_m_s"),
            safety_filter=spatial_cbf,
            ground_truth_providers={
                spatial_barrier.invariant_id: spatial_provider,
                velocity_barrier.invariant_id: velocity_provider,
                torque_barrier.invariant_id: torque_provider,
            },
            consensus=build_physical_consensus_contribution(),
            tool_provider=PhysicalAIToolProvider(),
            threshold_sections={"physical_ai": PhysicalAIThresholds},
            compliance_overlay_dirs=(overlay_dir,) if overlay_dir.exists() else (),
        )


def get_plugin() -> CagePlugin:
    return PhysicalAICagePlugin()
