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

from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class CBFTierPlugin(GovernanceTierPlugin):
    """CBF guard tier (phase 2, order 3)."""

    def __init__(self, cbf: ControlBarrierFunction):
        self.cbf = cbf

    @property
    def tier_name(self) -> str:
        return "cbf"

    @property
    def phase(self) -> int:
        return 2

    @property
    def order(self) -> int:
        return 3

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        success, reason = await self.cbf.atomic_verify_and_commit(action, params)
        if not success:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CBF_BARRIER_VIOLATED",
                    message=reason,
                    recoverable=True,
                )
            ]
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        amount = float(params.get("amount", 0.0))
        await self.cbf.rollback_state(magnitude=amount)
