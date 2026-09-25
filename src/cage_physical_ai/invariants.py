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

"""Physical AI domain barrier declarations and cost resolvers.

In accordance with CAGE architectural standards (PR C §7.4), barriers are declarative,
not executable. The kernel compiles (state_key, threshold_key, gamma) into the atomic
Redis Lua script at runtime.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpatialSeparationBarrier:
    """Spatial separation barrier: h(x) = distance_to_human - min_separation_distance.

    Enforces collaborative workspace safety per ISO 10218-1/2 and ISO 3691-4.
    The barrier algebra ensures the distance margin remains forward-invariant:
    h(S(t+1)) >= (1 - gamma) * h(S(t)) >= 0.
    """

    invariant_id: str = "physical_ai.spatial_separation"
    state_key: str = "safety:separation_distance_mm"
    threshold_key: str = "physical_ai.min_separation_distance_mm"
    gamma: float = 0.5


@dataclass(frozen=True)
class KinematicVelocityBarrier:
    """Kinematic velocity barrier: h(v) = max_admissible_velocity - current_velocity.

    Clamps peak end-effector and mobile base velocity in shared human workspaces.
    """

    invariant_id: str = "physical_ai.kinematic_velocity"
    state_key: str = "safety:end_effector_velocity_mm_s"
    threshold_key: str = "physical_ai.max_velocity_mm_s"
    gamma: float = 0.4


@dataclass(frozen=True)
class TorqueSaturationBarrier:
    """Torque saturation barrier: h(tau) = max_permissible_torque - current_torque.

    Prevents motor over-torque conditions, mechanical damage, and crushing hazards.
    """

    invariant_id: str = "physical_ai.torque_saturation"
    state_key: str = "safety:joint_torque_nm"
    threshold_key: str = "physical_ai.max_joint_torque_nm"
    gamma: float = 0.3


def physical_cost_resolver(
    action_name: str, payload: dict[str, Any]
) -> float:
    if action_name not in ("dispatch_trajectory", "actuate_joint"):
        return 0.0

    velocity = float(payload.get("target_velocity_mm_s", 0.0))
    if not math.isfinite(velocity) or velocity < 0:
        raise ValueError(
            f"invalid target velocity {velocity!r} — must be a finite, non-negative number"
        )
    return velocity
