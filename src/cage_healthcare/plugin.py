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

from pathlib import Path
from typing import Any

from src.cage_healthcare import create_healthcare_tiers
from src.cage_healthcare import ground_truth as _gt
from src.cage_healthcare.constants import CONSEQUENCE_MAGNITUDES, REGISTERED_ACTIONS
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.rails.provider import HealthcareRailProvider
from src.cage_healthcare.thresholds import HealthcareThresholds
from src.cage_healthcare.tiers import clinical_consensus_tier as _cct
from src.cage_healthcare.tools import tool_provider as _tp
from src.gateway.governance import contracts
from src.gateway.governance.consensus import extract_field_magnitude
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

_CFG = Path(__file__).resolve().parent / "config"
_NUM, _ENUM = contracts.EvaluatedParamSpec.number(), contracts.EvaluatedParamSpec.enum
_ROUTES = ("oral", "iv", "im", "sc", "topical", "inhaled")
_DOSE_SPECS = {"dose_mg": _NUM, "confidence": _NUM, "route": _ENUM(*_ROUTES)}
HEALTHCARE_EVALUATED_PARAM_SPECS = dict.fromkeys(
    ("administer_dose", "dose_order"), _DOSE_SPECS
)


class HealthcareCagePlugin(contracts.CagePlugin):
    name, api_version, maturity = "healthcare", "2.0", "stub"
    domain_config = contracts.DomainConfig(
        ftra_registry_path=_CFG / "ftra" / "terminal_registry.json",
        opa_package="dosing.governance",
        opa_required_rules=("allow",),
        canary_probe=contracts.CanaryProbe(
            "/governance/policy-precheck", "administer_dose", {"dose_mg": 10.0}
        ),
    )

    def contribute(self) -> contracts.PluginContribution:
        b, assay = SerumConcentrationBarrier(), _gt.SimulatedSerumAssayProvider()
        cbf = ControlBarrierFunction(
            b, _gt.healthcare_cost_resolver, skip_epoch_seed=True
        )
        _tp._clinical_actuator._ledger = assay
        kw: dict[str, Any] = {"domain": self.name, "maturity": self.maturity}
        kw.update(
            tiers=create_healthcare_tiers(cbf), invariants=(b,), safety_filter=cbf
        )
        kw.update(ground_truth_providers={b.invariant_id: assay})
        kw.update(registered_actions=REGISTERED_ACTIONS)
        kw.update(consequence_magnitudes=CONSEQUENCE_MAGNITUDES)
        kw.update(magnitude_extractor=extract_field_magnitude("dose_mg"))
        kw.update(tool_provider=_tp.ClinicalToolProvider())
        kw.update(consensus=_cct.build_healthcare_consensus_contribution())
        kw.update(rail_providers=(HealthcareRailProvider(),))
        kw.update(threshold_sections={"healthcare": HealthcareThresholds})
        kw.update(compliance_overlay_dirs=(_CFG / "compliance",))
        kw.update(evaluated_param_specs=HEALTHCARE_EVALUATED_PARAM_SPECS)
        return contracts.PluginContribution(**kw)


def get_plugin() -> contracts.CagePlugin:
    return HealthcareCagePlugin()
