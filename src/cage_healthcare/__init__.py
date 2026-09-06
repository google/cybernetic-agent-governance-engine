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

from src.cage_healthcare.invariants import SerumConcentrationBarrier
from src.cage_healthcare.tiers.clinical_consensus_tier import ClinicalConsensusTier
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.gateway.governance.consensus.engine import ConsensusGate
from src.gateway.governance.contracts import GovernanceTierPlugin
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction


def create_healthcare_tiers() -> tuple[GovernanceTierPlugin, ...]:
    """Create healthcare domain governance tiers for construction-time registration.
    
    Task 2.1 (ARCH-2): Tier registration is now immutable at construction time.
    This factory returns a tuple of tiers that must be passed to
    SymbolicGovernor.__init__() via the domain_tiers parameter.
    
    Returns:
        Tuple of healthcare domain tiers in (phase, order, tier_name) order.
        The tiers are:
        - DoseBarrierTier (phase=2, order=3) — Serum concentration CBF validation
        - ClinicalConsensusTier (phase=1, order=5) — Multi-model clinical consensus
    """
    barrier = SerumConcentrationBarrier()
    
    return (
        DoseBarrierTier(ControlBarrierFunction(barrier)),
        ClinicalConsensusTier(ConsensusGate()),
    )
