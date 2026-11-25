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

import math
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.gateway.governance.execution_idempotency import is_valid_idempotency_key


class DoseOrder(BaseModel):
    patient_id: str = Field(..., min_length=1)
    medication: str = Field(..., min_length=1)
    dose_mg: float = Field(..., gt=0, allow_inf_nan=False)
    idempotency_key: str = Field(..., min_length=1)
    route: str = Field(default="oral")
    indication: str = Field(default="")

    @field_validator("dose_mg", mode="before")
    @classmethod
    def _validate_dose_mg(cls, v: Any) -> float:
        ok = not isinstance(v, bool) and isinstance(v, (int, float))
        if not ok or not math.isfinite(v) or v <= 0.0:
            raise ValueError(f"dose_mg must be a finite positive number, got {v!r}")
        return float(v)

    @field_validator("idempotency_key", mode="before")
    @classmethod
    def _validate_idempotency_key(cls, v: Any) -> str:
        if not is_valid_idempotency_key(v):
            raise ValueError("Invalid idempotency_key. Must be a UUID v4 or v5.")
        return str(v)
