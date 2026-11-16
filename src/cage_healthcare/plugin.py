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

"""Healthcare domain capability plugin (T-D5 declarative plugin)."""

from pathlib import Path

from src.cage_healthcare import create_healthcare_tiers
from src.cage_healthcare.constants import CONSEQUENCE_MAGNITUDES, REGISTERED_ACTIONS
from src.cage_healthcare.ground_truth import (
    SimulatedSerumAssayProvider,
    healthcare_cost_resolver,
)
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.rails.provider import HealthcareRailProvider
from src.cage_healthcare.thresholds import HealthcareThresholds
from src.cage_healthcare.tiers.clinical_consensus_tier import (
    build_healthcare_consensus_contribution,
)
from src.cage_healthcare.tools.tool_provider import ClinicalToolProvider
from src.gateway.governance import contracts
from src.gateway.governance.consensus import extract_field_magnitude
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

_CONFIG_DIR = Path(__file__).resolve().parent / "config"


_DOSE_EVALUATED_PARAM_SPECS: dict[str, contracts.EvaluatedParamSpec] = {
    "dose_mg": contracts.EvaluatedParamSpec.number(),
    "confidence": contracts.EvaluatedParamSpec.number(),
    "route": contracts.EvaluatedParamSpec.enum(
        "oral", "iv", "im", "sc", "topical", "inhaled"
    ),
}

HEALTHCARE_EVALUATED_PARAM_SPECS: dict[str, dict[str, contracts.EvaluatedParamSpec]] = {
    "administer_dose": _DOSE_EVALUATED_PARAM_SPECS,
    "dose_order": _DOSE_EVALUATED_PARAM_SPECS,
}


# A reference domain, not a production one. It wires clinical consensus, the
# SerumConcentrationBarrier CBF, FTRA terminal classification and the
# dosing.governance OPA policy, and runs in permissive postures (dev, test, ci).
# ``maturity = "stub"`` makes assemble_governor() refuse it in every enforcing
# posture: the domain has no STPA hazard file or compiled uca_rules (only the
# Layer 1 core UCAs apply), its ground truth is simulated, and no Gate W run
# has exercised it. Raise the maturity only together with that evidence.
class HealthcareCagePlugin(contracts.CagePlugin):
    """Healthcare reference domain plugin (stub maturity)."""

    name, api_version, maturity = "healthcare", "2.0", "stub"
    domain_config = contracts.DomainConfig(
        ftra_registry_path=_CONFIG_DIR / "ftra" / "terminal_registry.json",
        opa_package="dosing.governance",
        opa_required_rules=("allow",),
        canary_probe=contracts.CanaryProbe(
            "/governance/policy-precheck", "administer_dose", {"dose_mg": 10.0}
        ),
    )

    def contribute(self) -> contracts.PluginContribution:
        barrier = SerumConcentrationBarrier()
        cbf = ControlBarrierFunction(
            barrier, cost_resolver=healthcare_cost_resolver, skip_epoch_seed=True
        )
        return contracts.PluginContribution(
            domain=self.name,
            maturity=self.maturity,
            tiers=create_healthcare_tiers(cbf),
            invariants=(barrier,),  # declarative, no logic
            ground_truth_providers={
                barrier.invariant_id: SimulatedSerumAssayProvider()
            },
            registered_actions=REGISTERED_ACTIONS,
            consequence_magnitudes=CONSEQUENCE_MAGNITUDES,
            magnitude_extractor=extract_field_magnitude("dose_mg"),
            safety_filter=cbf,
            consensus=build_healthcare_consensus_contribution(),
            tool_provider=ClinicalToolProvider(),
            threshold_sections={"healthcare": HealthcareThresholds},
            compliance_overlay_dirs=(_CONFIG_DIR / "compliance",),
            rail_providers=(HealthcareRailProvider(),),  # CheckContraindicationAction
            evaluated_param_specs=HEALTHCARE_EVALUATED_PARAM_SPECS,
        )


def get_plugin() -> contracts.CagePlugin:
    return HealthcareCagePlugin()
