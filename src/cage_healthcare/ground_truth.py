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

from __future__ import annotations

from typing import Any

from src.cage_healthcare import invariants as _inv
from src.cage_healthcare.thresholds import load_healthcare_thresholds
from src.gateway.governance.seams import ground_truth as _gt

DoseCeilingBarrier = _inv.DoseCeilingBarrier
SerumConcentrationBarrier = _inv.SerumConcentrationBarrier
healthcare_cost_resolver = _inv.healthcare_cost_resolver


class SimulatedSerumAssayProvider(_gt.GroundTruthProvider):
    source_id = "simulated:serum_assay_lab"

    def __init__(self, *, seed: int | None = None, **kw: Any) -> None:
        cfg = load_healthcare_thresholds()
        inv = kw.pop("invariant_id", SerumConcentrationBarrier.invariant_id)
        skey = kw.pop("state_key", SerumConcentrationBarrier.state_key)
        ceil = float(kw.pop("toxic_ceiling_mg_l", cfg.toxic_ceiling_concentration))
        b_def = cfg.min_therapeutic_concentration
        base = float(kw.pop("baseline_concentration_mg_l", b_def))
        head = float(kw.pop("initial_scalar", ceil - base))
        flr = float(kw.pop("barrier_floor", b_def))
        self.patient_id = str(kw.pop("patient_id", "patient-sim-01"))
        j, lag = kw.pop("journal", None), float(kw.pop("settlement_lag_s", 0.0))
        if kw:
            raise TypeError(f"Unexpected kwargs: {sorted(kw)}")
        self.invariant_id, self.state_key = inv, skey
        self.toxic_ceiling_mg_l, self.barrier_floor = ceil, flr
        s_kw: dict[str, Any] = {"invariant_id": inv, "state_key": skey, "seed": seed}
        s_kw.update(initial_scalar=head, barrier_floor=flr, source_id=self.source_id)
        s_kw.update(journal=j, settlement_lag_s=lag)
        self._source = self.source = _gt.SimulatedSource(**s_kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._source, name)

    def fetch_snapshot_sync(self) -> _gt.GroundTruthSnapshot:
        conc = max(0.0, self.toxic_ceiling_mg_l - self._source.current_scalar)
        m: dict[str, Any] = {"patient_id": self.patient_id, "unit": "mg/L"}
        m["serum_concentration_mg_l"] = conc
        return self._source.next_snapshot(extra_metadata=m)

    async def fetch_snapshot(self) -> _gt.GroundTruthSnapshot:
        return self.fetch_snapshot_sync()
