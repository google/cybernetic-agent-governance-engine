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

"""Healthcare domain barrier declarations.

Note what is absent: no Lua script, no executable barrier logic, no KMS
verification, no fence-epoch. This is pure data — the kernel compiles it
into the atomic Redis Lua hop.
"""


import math
from typing import Any

from src.cage_healthcare.constants import HEALTHCARE_GOVERNED_ACTIONS


class SerumConcentrationBarrier:
    """Serum concentration barrier: h(x) = concentration - min_therapeutic.

    Declarative affine barrier (PR C, Stage 2). The kernel's CBF engine
    compiles (state_key, threshold_key, gamma) into KEYS/ARGV passed to
    the atomic Lua hop (proof/DistributedCBF.tla).
    """

    invariant_id = "healthcare.serum_concentration"
    state_key = "safety:serum_concentration"
    threshold_key = "domains.healthcare.min_therapeutic_concentration"
    gamma = 0.4
    initial_state = 15.0
    requires_external_ground_truth = True


DoseCeilingBarrier = SerumConcentrationBarrier

_HEALTHCARE_DOSE_ACTIONS: frozenset[str] = HEALTHCARE_GOVERNED_ACTIONS | frozenset(
    {"administer_medication", "dose_order"}
)


def healthcare_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
    """Resolve serum concentration headroom cost for clinical dosing actions."""
    if action_name not in _HEALTHCARE_DOSE_ACTIONS:
        return 0.0
    raw = payload.get(
        "concentration_delta",
        payload.get("dose_mg", payload.get("dose", payload.get("amount", 0.0))),
    )
    if isinstance(raw, bool):
        raise ValueError(f"Invalid clinical dose {raw!r}: bool is not a valid numeric dose")
    value = float(raw)
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(
            f"Invalid clinical dose {raw!r}: must be a finite non-negative number"
        )
    return value
