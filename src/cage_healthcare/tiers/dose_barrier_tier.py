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

from typing import Any

from src.cage_healthcare.constants import REGISTERED_ACTIONS
from src.gateway.governance import contracts as _ct
from src.gateway.governance.safety import barrier_tier as _bt

_CODE = "DOSE_BARRIER_VIOLATED"


class DoseBarrierTier(_ct.MutatingTier):
    tier_name: str = "dose_barrier"
    order: int = 3

    def __init__(self, cbf: Any = None) -> None:
        self.cbf = cbf

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in REGISTERED_ACTIONS

    def _unconfigured(self) -> _ct.Violation:
        m = "no control barrier function configured; refusing governed clinical action"
        return _ct.Violation(
            self.tier_name, "DOSE_BARRIER_UNCONFIGURED", m, _ct.ViolationKind.HARD
        )

    async def evaluate(
        self, action: str, params: dict[str, Any]
    ) -> list[_ct.Violation]:
        if self.cbf is None:
            return [self._unconfigured()]
        return await _bt.preview_barrier(
            self.cbf, action=action, params=params, tier=self.tier_name, code=_CODE
        )

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[_ct.Violation], _ct.CommitReceipt | None]:
        if self.cbf is None:
            return [self._unconfigured()], None
        return await _bt.commit_barrier(
            self.cbf, action=action, params=params, tier=self.tier_name, code=_CODE
        )

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: _ct.CommitReceipt
    ) -> None:
        if self.cbf is not None:
            await _bt.rollback_barrier(self.cbf, receipt)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: _ct.CommitReceipt
    ) -> None:
        if self.cbf is not None:
            await _bt.confirm_barrier(self.cbf, receipt)
