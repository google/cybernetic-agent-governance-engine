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
from src.cage_healthcare import ground_truth as _gt
from src.cage_healthcare.constants import CONSEQUENCE_MAGNITUDES, REGISTERED_ACTIONS
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.rails.provider import HealthcareRailProvider
from src.cage_healthcare.thresholds import HealthcareThresholds
from src.cage_healthcare.tiers import clinical_consensus_tier as _cct
from src.cage_healthcare.tools.tool_provider import ClinicalToolProvider
from src.gateway.governance import contracts
from src.gateway.governance.consensus import extract_field_magnitude
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

_CONFIG_DIR = Path(__file__).resolve().parent / "config"
_NUM, _ENUM = contracts.EvaluatedParamSpec.number(), contracts.EvaluatedParamSpec.enum
_ROUTES = _ENUM("oral", "iv", "im", "sc", "topical", "inhaled")
_DOSE_SPECS = {"dose_mg": _NUM, "confidence": _NUM, "route": _ROUTES}
_DOSE_ACTIONS = ("administer_dose", "dose_order")
HEALTHCARE_EVALUATED_PARAM_SPECS = dict.fromkeys(_DOSE_ACTIONS, _DOSE_SPECS)


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
        barrier, cost = SerumConcentrationBarrier(), _gt.healthcare_cost_resolver
        cbf = ControlBarrierFunction(barrier, cost, skip_epoch_seed=True)
        gt_providers = {barrier.invariant_id: _gt.SimulatedSerumAssayProvider()}
        return contracts.PluginContribution(
            domain=self.name,
            maturity=self.maturity,
            tiers=create_healthcare_tiers(cbf),
            invariants=(barrier,),  # declarative, no logic
            ground_truth_providers=gt_providers,
            registered_actions=REGISTERED_ACTIONS,
            consequence_magnitudes=CONSEQUENCE_MAGNITUDES,
            magnitude_extractor=extract_field_magnitude("dose_mg"),
            safety_filter=cbf,
            consensus=_cct.build_healthcare_consensus_contribution(),
            tool_provider=ClinicalToolProvider(),
            threshold_sections={"healthcare": HealthcareThresholds},
            compliance_overlay_dirs=(_CONFIG_DIR / "compliance",),
            rail_providers=(HealthcareRailProvider(),),  # CheckContraindicationAction
            evaluated_param_specs=HEALTHCARE_EVALUATED_PARAM_SPECS,
        )


def get_plugin() -> contracts.CagePlugin:
    return HealthcareCagePlugin()
