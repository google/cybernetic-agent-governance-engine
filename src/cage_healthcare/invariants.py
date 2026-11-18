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
from dataclasses import dataclass, field
from typing import Any

from src.cage_healthcare.constants import REGISTERED_ACTIONS
from src.cage_healthcare.thresholds import load_healthcare_thresholds as _cfg


def _ok(v: Any) -> bool:
    return not isinstance(v, bool) and isinstance(v, (int, float)) and math.isfinite(v)


def _tkey() -> str:
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    hc, alt = THRESHOLDS.domains.get("healthcare", {}), "toxic_safety_margin"
    return f"domains.healthcare.{alt if alt in hc else 'min_therapeutic_concentration'}"


# Toxic-ceiling headroom: state = ceiling - concentration (dose reduces headroom).
@dataclass(frozen=True)
class SerumConcentrationBarrier:
    gamma: float = field(default_factory=lambda: _cfg().gamma)
    toxic_ceiling_mg_l: float = field(
        default_factory=lambda: _cfg().toxic_ceiling_concentration
    )
    baseline_concentration_mg_l: float = field(
        default_factory=lambda: _cfg().min_therapeutic_concentration
    )
    invariant_id: str = "healthcare.serum_concentration"
    state_key: str = "safety:serum_concentration"
    threshold_key: str = field(default_factory=_tkey)
    initial_state: float = field(init=False)
    requires_external_ground_truth: bool = True

    def __post_init__(self) -> None:
        c, b, g = self.toxic_ceiling_mg_l, self.baseline_concentration_mg_l, self.gamma
        if not (_ok(g) and 0.0 < g < 1.0 and _ok(c) and _ok(b) and 0.0 <= b < c):
            raise ValueError("Invalid SerumConcentrationBarrier parameters")
        object.__setattr__(self, "initial_state", float(c - b))


DoseCeilingBarrier = SerumConcentrationBarrier
_DOSE_KEYS = ("concentration_delta", "dose_mg", "dose", "amount")


def _parse_dose(raw: Any) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise ValueError(f"Invalid clinical dose {raw!r}")
    val = float(raw)
    if not math.isfinite(val) or val <= 0.0:
        raise ValueError(f"Invalid clinical dose {raw!r}")
    return val


def healthcare_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
    if action_name not in REGISTERED_ACTIONS:
        return 0.0
    u = payload.get("unit", payload.get("dose_unit"))
    if u is not None and (not isinstance(u, str) or u.strip().lower() != "mg"):
        raise ValueError(f"Invalid clinical dose unit {u!r}")
    vals = [_parse_dose(payload[k]) for k in _DOSE_KEYS if payload.get(k) is not None]
    if any(abs(v - vals[0]) > 1e-9 for v in vals[1:]):
        raise ValueError(f"Conflicting clinical dose fields in {payload!r}")
    return vals[0] if vals else 0.0


resolve_healthcare_dose_cost = healthcare_cost_resolver
