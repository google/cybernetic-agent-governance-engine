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

from collections.abc import Sequence
from typing import Any

from src.cage_physical_ai.constants import PHYSICAL_AI_GOVERNED_ACTIONS
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.safety.barrier_tier import (
    commit_barrier,
    preview_barrier,
    rollback_barrier,
)

_CLAIMED_PHYSICAL_ACTIONS = PHYSICAL_AI_GOVERNED_ACTIONS | frozenset(
    {"move_arm", "move_effector"}
)


class KinematicBarrierTier(MutatingTier):
    """Kinematic barrier tier for physical AI (phase 2, order 3).

    Delegates state-space evaluation to the kernel's ControlBarrierFunction engine.
    Ensures that commanded actions cannot deplete spatial, velocity, or torque margins.
    """

    def __init__(self, cbf: Any = None) -> None:
        self.cbf = cbf
        if cbf is None:
            self._cbfs: tuple[Any, ...] = ()
        elif isinstance(cbf, Sequence) and not isinstance(cbf, (str, bytes)):
            self._cbfs = tuple(cbf)
        else:
            self._cbfs = (cbf,)

    @property
    def tier_name(self) -> str:
        return "kinematic_barrier"

    @property
    def order(self) -> int:
        return 3

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in _CLAIMED_PHYSICAL_ACTIONS

    def _unconfigured(self) -> Violation:
        return Violation(
            tier=self.tier_name,
            code="KINEMATIC_BARRIER_UNCONFIGURED",
            message="no control barrier function configured; refusing governed physical action",
            kind=ViolationKind.HARD,
        )

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Read-only preview of commit() (DRY_RUN); mirrors commit()'s no-CBF case."""
        if not self._cbfs:
            return [self._unconfigured()]
        violations: list[Violation] = []
        for engine in self._cbfs:
            violations.extend(
                await preview_barrier(
                    engine,
                    tier=self.tier_name,
                    code="KINEMATIC_BARRIER_VIOLATED",
                    action=action,
                    params=params,
                )
            )
        return violations

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        if not self._cbfs:
            return [self._unconfigured()], None  # fail closed; nothing mutated
        if len(self._cbfs) == 1:
            return await commit_barrier(
                self._cbfs[0],
                tier=self.tier_name,
                code="KINEMATIC_BARRIER_VIOLATED",
                action=action,
                params=params,
            )

        committed_steps: list[tuple[Any, CommitReceipt]] = []
        try:
            for engine in self._cbfs:
                violations, receipt = await commit_barrier(
                    engine,
                    tier=self.tier_name,
                    code="KINEMATIC_BARRIER_VIOLATED",
                    action=action,
                    params=params,
                )
                if violations:
                    for prev_engine, prev_receipt in reversed(committed_steps):
                        await rollback_barrier(prev_engine, prev_receipt)
                    return violations, None
                if receipt is not None:
                    committed_steps.append((engine, receipt))
        except Exception:
            for prev_engine, prev_receipt in reversed(committed_steps):
                await rollback_barrier(prev_engine, prev_receipt)
            raise

        first_mag = committed_steps[0][1].magnitude if committed_steps else 0.0
        return [], CommitReceipt(
            tier=self.tier_name,
            magnitude=first_mag,
            token=tuple(
                (eng, rec.magnitude) for eng, rec in committed_steps
            ),
        )

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        if isinstance(receipt.token, tuple):
            for engine, magnitude in reversed(receipt.token):
                await rollback_barrier(
                    engine, CommitReceipt(tier=self.tier_name, magnitude=magnitude)
                )
            return
        if self._cbfs:
            await rollback_barrier(self._cbfs[0], receipt)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        """The debit is final at commit; nothing expires, so nothing to confirm."""
