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

"""Healthcare domain capability plugin."""

from typing import Any

from src.cage_healthcare.ground_truth import healthcare_cost_resolver
from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.tiers.clinical_consensus_tier import ClinicalConsensusTier
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.gateway.governance.contracts import GovernanceTier
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction


def create_healthcare_tiers(
    cbf: Any = None,
) -> tuple[GovernanceTier, ...]:
    """Create healthcare domain governance tiers for construction-time registration."""
    barrier = SerumConcentrationBarrier()
    engine = (
        cbf
        if cbf is not None
        else ControlBarrierFunction(
            invariant=barrier,
            cost_resolver=healthcare_cost_resolver,
            skip_epoch_seed=True,
        )
    )

    return (
        DoseBarrierTier(engine),
        ClinicalConsensusTier(),
    )
