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

"""Dose barrier tier — serum concentration CBF (phase 2, order 3)."""

from typing import Any

from src.cage_healthcare.constants import HEALTHCARE_GOVERNED_ACTIONS
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class DoseBarrierTier(GovernanceTierPlugin):
    """Serum-concentration barrier tier (phase 2, order 3).

    Note what is absent: no Lua script, no fence-epoch logic, no KMS call,
    no quota arithmetic. The kernel's ControlBarrierFunction engine owns
    all of that. This tier only names the action and delegates to the engine.
    """

    def __init__(self, cbf: Any) -> None:  # cbf: ControlBarrierFunction
        self.cbf = cbf

    @property
    def tier_name(self) -> str:
        return "dose_barrier"

    @property
    def phase(self) -> int:
        return 2

    @property
    def order(self) -> int:
        return 3

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in HEALTHCARE_GOVERNED_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 1: read-only check (no state mutation)
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 2: atomic verify-and-commit via kernel CBF engine
        ok, reason = await self.cbf.atomic_verify_and_commit(action, params)
        if not ok:
            return [
                Violation(
                    tier=self.tier_name,
                    code="DOSE_BARRIER_VIOLATED",
                    message=reason,
                    recoverable=True,
                )
            ]
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        # LIFO rollback: restore serum concentration state
        await self.cbf.rollback_state(magnitude=float(params.get("dose_mg", 0.0)))
