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

"""Kinematic barrier tier — physical AI / robotics CBF (phase 2, order 3)."""

from typing import Any

from src.cage_physical_ai.constants import PHYSICAL_AI_GOVERNED_ACTIONS
from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierPlugin,
    Violation,
    ViolationKind,
)
from src.gateway.governance.safety.barrier_tier import (
    commit_barrier,
    preview_barrier,
    rollback_barrier,
)


class KinematicBarrierTier(GovernanceTierPlugin):
    """Kinematic barrier tier for physical AI (phase 2, order 3).

    Delegates state-space evaluation to the kernel's ControlBarrierFunction engine.
    Ensures that commanded actions cannot deplete spatial or velocity margins.
    """

    def __init__(self, cbf: Any = None) -> None:
        self.cbf = cbf

    @property
    def tier_name(self) -> str:
        return "kinematic_barrier"

    @property
    def phase(self) -> int:
        return 2

    @property
    def order(self) -> int:
        return 3

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in PHYSICAL_AI_GOVERNED_ACTIONS

    def _unconfigured(self) -> Violation:
        # Fail closed: no CBF means no barrier was checked, which must refuse,
        # never allow. Physical-AI barriers have no cost resolver yet (POAM).
        return Violation(
            tier=self.tier_name,
            code="KINEMATIC_BARRIER_UNCONFIGURED",
            message="no control barrier function configured; refusing governed physical action",
            kind=ViolationKind.HARD,
        )

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Read-only preview of commit() (DRY_RUN); mirrors commit()'s no-CBF case."""
        if self.cbf is None:
            return [self._unconfigured()]
        return await preview_barrier(
            self.cbf, tier=self.tier_name, code="KINEMATIC_BARRIER_VIOLATED", action=action, params=params
        )

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        if self.cbf is None:
            return [self._unconfigured()], None  # fail closed; nothing mutated
        return await commit_barrier(
            self.cbf, tier=self.tier_name, code="KINEMATIC_BARRIER_VIOLATED", action=action, params=params
        )

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        await rollback_barrier(self.cbf, receipt)
