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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from src.cage_physical_ai import create_physical_ai_tiers
from src.cage_physical_ai.invariants import (
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
)
from src.cage_physical_ai.tools.tool_provider import PhysicalAIToolProvider
from src.gateway.governance.constants import register_overlay_dir
from src.gateway.governance.contracts import CagePlugin
from src.gateway.governance.symbolic_governor import SymbolicGovernor


class PhysicalAICagePlugin(CagePlugin):
    """Physical AI / Robotics domain capability plugin.

    A purely declarative plugin defining physical safety invariants,
    collaborative robotics compliance overlays, and embodied tools.
    """

    name: str = "physical_ai"
    api_version: str = "1.0"

    def register(
        self,
        governor: SymbolicGovernor,
        tool_server: "FastMCP | None" = None,
    ) -> None:
        governor.register_invariant(SpatialSeparationBarrier())
        governor.register_invariant(KinematicVelocityBarrier())
        governor.register_invariant(TorqueSaturationBarrier())

        tiers = create_physical_ai_tiers()
        if not governor._domain_tiers:
            governor._domain_tiers = tiers

        overlay_dir = Path(__file__).parent / "config" / "compliance"
        if overlay_dir.exists():
            register_overlay_dir(overlay_dir)

        if tool_server:
            PhysicalAIToolProvider().register_tools(tool_server)


def get_plugin() -> CagePlugin:
    return PhysicalAICagePlugin()
