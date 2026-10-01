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

from src.cage_healthcare.constants import REGISTERED_ACTIONS
from src.cage_healthcare.ground_truth import (
    SimulatedSerumAssayProvider,
    healthcare_cost_resolver,
)
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.rails.provider import HealthcareRailProvider
from src.cage_healthcare.thresholds import HealthcareThresholds
from src.cage_healthcare.tiers.clinical_consensus_tier import (
    ClinicalConsensusTier,
    build_healthcare_consensus_contribution,
)
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.cage_healthcare.tools.tool_provider import ClinicalToolProvider
from src.gateway.governance.consensus import extract_field_magnitude
from src.gateway.governance.contracts import (
    CagePlugin,
    DomainConfig,
    PluginContribution,
)
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

_CONFIG_DIR = Path(__file__).resolve().parent / "config"


class HealthcareCagePlugin(CagePlugin):
    """Healthcare domain capability plugin.

    ~40 lines. Zero Lua, zero KMS, zero fence-epoch, zero quota arithmetic.
    The adopter question: does this read as a list of declarations?
    """

    name = "healthcare"
    api_version = "1.0"
    domain_config = DomainConfig(
        ftra_registry_path=_CONFIG_DIR / "ftra" / "terminal_registry.json",
        opa_package="dosing.governance",
        opa_required_rules=("allow",),
        causal_graph_path=_CONFIG_DIR / "causal_graph.yaml",
    )

    def contribute(self) -> PluginContribution:
        barrier = SerumConcentrationBarrier()
        cbf = ControlBarrierFunction(
            invariant=barrier,
            cost_resolver=healthcare_cost_resolver,
            skip_epoch_seed=True,
        )
        assay_provider = SimulatedSerumAssayProvider(
            invariant_id=barrier.invariant_id,
            state_key=barrier.state_key,
        )
        return PluginContribution(
            domain=self.name,
            tiers=(
                DoseBarrierTier(cbf),
                ClinicalConsensusTier(),
            ),
            invariants=(barrier,),  # declarative, no logic
            ground_truth_providers={barrier.invariant_id: assay_provider},
            registered_actions=REGISTERED_ACTIONS,
            magnitude_extractor=extract_field_magnitude("dose_mg"),
            safety_filter=cbf,
            consensus=build_healthcare_consensus_contribution(),
            tool_provider=ClinicalToolProvider(),
            threshold_sections={"healthcare": HealthcareThresholds},
            compliance_overlay_dirs=(Path(__file__).parent / "config" / "compliance",),
            rail_providers=(HealthcareRailProvider(),),  # CheckContraindicationAction
        )


def get_plugin() -> CagePlugin:
    return HealthcareCagePlugin()
