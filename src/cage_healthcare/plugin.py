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

"""Healthcare domain capability plugin.

Note what is absent: no Lua script, no fence-epoch logic, no KMS
verification, no quota reserver, no consensus algorithm, no causal
refutation engine. Every one of those is a single kernel copy shared
with finance. This plugin only names things.

T-D5: The complete healthcare plugin — a list of declarations.
"""

from pathlib import Path

from src.cage_healthcare import create_healthcare_tiers
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.rails.provider import HealthcareRailProvider
from src.cage_healthcare.tools.tool_provider import ClinicalToolProvider
from src.gateway.governance.contracts import (
    CagePlugin,
    DomainConfig,
    PluginContribution,
)


class HealthcareCagePlugin(CagePlugin):
    """Healthcare domain capability plugin.

    ~40 lines. Zero Lua, zero KMS, zero fence-epoch, zero quota arithmetic.
    The adopter question: does this read as a list of declarations?
    """

    name = "healthcare"
    api_version = "1.0"
    # No healthcare FTRA registry yet: the domain refuses to start (POAM-2026-077).
    domain_config: DomainConfig | None = None

    def contribute(self) -> PluginContribution:
        return PluginContribution(
            domain=self.name,
            tiers=create_healthcare_tiers(),
            invariants=(SerumConcentrationBarrier(),),  # declarative, no logic
            tool_provider=ClinicalToolProvider(),
            compliance_overlay_dirs=(Path(__file__).parent / "config" / "compliance",),
            rail_providers=(HealthcareRailProvider(),),  # CheckContraindicationAction
        )


def get_plugin() -> CagePlugin:
    return HealthcareCagePlugin()
