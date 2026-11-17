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

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HealthcareThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    min_therapeutic_concentration: float = Field(5.0, gt=0, allow_inf_nan=False)
    toxic_ceiling_concentration: float = Field(20.0, gt=0, allow_inf_nan=False)
    gamma: float = Field(0.4, gt=0, lt=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def _check(self) -> "HealthcareThresholds":
        if self.toxic_ceiling_concentration <= self.min_therapeutic_concentration:
            raise ValueError("toxic_ceiling_concentration <= min_therapeutic")
        return self


def load_healthcare_thresholds() -> HealthcareThresholds:
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    raw = THRESHOLDS.domains.get("healthcare", {})
    clean = {k: v for k, v in raw.items() if not str(k).startswith("_")}
    return HealthcareThresholds.model_validate(clean)
