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

"""CAGE Physical AI Domain Plugin."""

from typing import Any

from src.cage_physical_ai.tiers.kinematic_barrier_tier import KinematicBarrierTier
from src.cage_physical_ai.tiers.physical_consensus_tier import (
    PhysicalSafetyConsensusTier,
)
from src.gateway.governance.contracts import GovernanceTierPlugin


def create_physical_ai_tiers(
    cbf: Any = None,
    consensus_engine: Any = None,
) -> tuple[GovernanceTierPlugin, ...]:
    """Create physical AI domain governance tiers.

    Returns:
        Tuple containing KinematicBarrierTier (phase=2, order=3) and
        PhysicalSafetyConsensusTier (phase=1, order=5).
    """
    return (
        KinematicBarrierTier(cbf=cbf),
        PhysicalSafetyConsensusTier(consensus_engine=consensus_engine),
    )


__all__ = [
    "create_physical_ai_tiers",
]
