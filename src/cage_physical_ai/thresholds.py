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

"""Physical-AI domain threshold schema (`domains.physical_ai` in `governance_thresholds.json`)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PhysicalAIThresholds(BaseModel):
    """Physical-AI domain threshold configuration.

    REFERENCE-ONLY values. Real limits must come from a cell-specific
    ISO/TS 15066 risk assessment; these exist so the declarative barriers in
    src/cage_physical_ai/invariants.py resolve at registration (V3).
    """

    min_separation_distance_mm: float = Field(
        default=500.0,
        gt=0,
        description="Minimum human-robot separation distance (mm) for the spatial separation barrier",
    )
    max_velocity_mm_s: float = Field(
        default=250.0,
        gt=0,
        description="Maximum end-effector velocity (mm/s) for the kinematic velocity barrier",
    )
    max_joint_torque_nm: float = Field(
        default=50.0,
        gt=0,
        description="Maximum joint torque (N·m) for the torque saturation barrier",
    )


__all__ = ["PhysicalAIThresholds"]
