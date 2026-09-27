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

"""Healthcare domain simulated serum-assay ground-truth provider and cost resolver."""

from __future__ import annotations

from src.cage_healthcare.invariants import (
    DoseCeilingBarrier,
    SerumConcentrationBarrier,
    healthcare_cost_resolver,
)
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    GroundTruthProvider,
    GroundTruthSnapshot,
    SimulatedSource,
)


class SimulatedSerumAssayProvider(GroundTruthProvider):
    """Deterministic simulated laboratory serum-assay provider for healthcare CBF."""

    def __init__(
        self,
        *,
        invariant_id: str = SerumConcentrationBarrier.invariant_id,
        state_key: str = SerumConcentrationBarrier.state_key,
        initial_scalar: float = 15.0,
        barrier_floor: float = 5.0,
        patient_id: str = "patient-sim-01",
        seed: int | None = None,
    ) -> None:
        self.invariant_id = invariant_id
        self.state_key = state_key
        self.patient_id = patient_id
        self.barrier_floor = float(barrier_floor)
        self.source_id = "simulated:serum_assay_lab"
        self._source = SimulatedSource(
            invariant_id=invariant_id,
            state_key=state_key,
            initial_scalar=float(initial_scalar),
            barrier_floor=float(barrier_floor),
            source_id=self.source_id,
            seed=seed,
        )
        self.source = self._source

    @property
    def fault_mode(self) -> FaultMode:
        return self._source.fault_mode

    def inject_fault(self, mode: FaultMode | str) -> None:
        self._source.inject_fault(mode)

    def clear_fault(self) -> None:
        self._source.clear_fault()

    def record_debit(self, delta_mg_l: float) -> None:
        self._source.record_debit(delta_mg_l)

    def reset(self, *, scalar: float | None = None) -> None:
        self._source.reset(scalar=scalar)

    def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
        return self._source.next_snapshot(
            extra_metadata={"patient_id": self.patient_id, "unit": "mg/L"}
        )

    async def fetch_snapshot(self) -> GroundTruthSnapshot:
        return self.fetch_snapshot_sync()


__all__ = [
    "DoseCeilingBarrier",
    "SimulatedSerumAssayProvider",
    "healthcare_cost_resolver",
]
