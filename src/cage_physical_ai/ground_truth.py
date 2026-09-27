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

"""Physical-AI domain ground-truth providers and barrier cost resolvers."""

from __future__ import annotations

from src.cage_physical_ai.invariants import (
    KinematicVelocityBarrier,
    SpatialSeparationBarrier,
    TorqueSaturationBarrier,
    spatial_cost_resolver,
    torque_cost_resolver,
    velocity_cost_resolver,
)
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    GroundTruthProvider,
    GroundTruthSnapshot,
    SimulatedSource,
)


class _SimulatedPhysicalSensorProvider(GroundTruthProvider):
    """Base simulated ground-truth sensor provider for physical-AI barriers."""

    invariant_id: str
    state_key: str

    def __init__(
        self,
        *,
        invariant_id: str,
        state_key: str,
        initial_scalar: float,
        barrier_floor: float,
        source_id: str,
        drift_sigma: float = 0.0,
        seed: int | None = None,
        source: SimulatedSource | None = None,
    ) -> None:
        self.invariant_id = invariant_id
        self.state_key = state_key
        self.barrier_floor = float(barrier_floor)
        self.source_id = source_id
        self._source = source or SimulatedSource(
            invariant_id=invariant_id,
            state_key=state_key,
            initial_scalar=initial_scalar,
            barrier_floor=barrier_floor,
            source_id=source_id,
            jitter_amplitude=drift_sigma,
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

    def record_debit(self, magnitude: float) -> None:
        self._source.record_debit(magnitude)

    def reset(self, *, scalar: float | None = None) -> None:
        self._source.reset(scalar=scalar)

    def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
        return self._source.next_snapshot()

    async def fetch_snapshot(self) -> GroundTruthSnapshot:
        return self.fetch_snapshot_sync()


class SimulatedSpatialSensorProvider(_SimulatedPhysicalSensorProvider):
    """Simulated separation-distance sensor for ``SpatialSeparationBarrier``."""

    def __init__(
        self,
        *,
        initial_scalar: float = 500.0,
        barrier_floor: float = 150.0,
        drift_sigma: float = 0.0,
        seed: int | None = None,
        source: SimulatedSource | None = None,
    ) -> None:
        super().__init__(
            invariant_id=SpatialSeparationBarrier.invariant_id,
            state_key=SpatialSeparationBarrier.state_key,
            initial_scalar=initial_scalar,
            barrier_floor=barrier_floor,
            source_id="simulated:spatial_lidar_sensor",
            drift_sigma=drift_sigma,
            seed=seed,
            source=source,
        )


class SimulatedVelocitySensorProvider(_SimulatedPhysicalSensorProvider):
    """Simulated velocity-margin sensor for ``KinematicVelocityBarrier``."""

    def __init__(
        self,
        *,
        initial_scalar: float = 700.0,
        barrier_floor: float = 250.0,
        drift_sigma: float = 0.0,
        seed: int | None = None,
        source: SimulatedSource | None = None,
    ) -> None:
        super().__init__(
            invariant_id=KinematicVelocityBarrier.invariant_id,
            state_key=KinematicVelocityBarrier.state_key,
            initial_scalar=initial_scalar,
            barrier_floor=barrier_floor,
            source_id="simulated:kinematic_velocity_encoder",
            drift_sigma=drift_sigma,
            seed=seed,
            source=source,
        )


class SimulatedTorqueSensorProvider(_SimulatedPhysicalSensorProvider):
    """Simulated joint-torque margin sensor for ``TorqueSaturationBarrier``."""

    def __init__(
        self,
        *,
        initial_scalar: float = 150.0,
        barrier_floor: float = 45.0,
        drift_sigma: float = 0.0,
        seed: int | None = None,
        source: SimulatedSource | None = None,
    ) -> None:
        super().__init__(
            invariant_id=TorqueSaturationBarrier.invariant_id,
            state_key=TorqueSaturationBarrier.state_key,
            initial_scalar=initial_scalar,
            barrier_floor=barrier_floor,
            source_id="simulated:joint_torque_cell",
            drift_sigma=drift_sigma,
            seed=seed,
            source=source,
        )


__all__ = [
    "SimulatedSpatialSensorProvider",
    "SimulatedTorqueSensorProvider",
    "SimulatedVelocitySensorProvider",
    "spatial_cost_resolver",
    "torque_cost_resolver",
    "velocity_cost_resolver",
]
