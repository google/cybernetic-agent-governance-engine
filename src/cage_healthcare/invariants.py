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

"""Healthcare domain barrier declarations."""

import math
from typing import Any

from src.cage_healthcare.constants import REGISTERED_ACTIONS


class SerumConcentrationBarrier:
    """Declarative serum concentration barrier: h(x) = concentration - min_therapeutic."""

    invariant_id = "healthcare.serum_concentration"
    state_key = "safety:serum_concentration"
    threshold_key = "domains.healthcare.min_therapeutic_concentration"
    gamma, initial_state, requires_external_ground_truth = 0.4, 15.0, True


DoseCeilingBarrier = SerumConcentrationBarrier


def _parse_dose(raw: Any) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise ValueError(f"Invalid clinical dose {raw!r}")
    val = float(raw)
    if not math.isfinite(val) or val < 0.0:
        raise ValueError(f"Invalid clinical dose {raw!r}")
    return val


_DOSE_KEYS = ("concentration_delta", "dose_mg", "dose", "amount")


def healthcare_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
    """Resolve serum concentration headroom cost for clinical dosing actions."""
    if action_name not in REGISTERED_ACTIONS:
        return 0.0
    unit = payload.get("unit", payload.get("dose_unit"))
    if unit is not None and (not isinstance(unit, str) or unit.strip().lower() != "mg"):
        raise ValueError(f"Invalid clinical dose unit {unit!r}")
    vals = [_parse_dose(payload[k]) for k in _DOSE_KEYS if payload.get(k) is not None]
    if any(abs(v - vals[0]) > 1e-9 for v in vals[1:]):
        raise ValueError(f"Conflicting clinical dose fields in {payload!r}")
    return vals[0] if vals else 0.0


resolve_healthcare_dose_cost = healthcare_cost_resolver
