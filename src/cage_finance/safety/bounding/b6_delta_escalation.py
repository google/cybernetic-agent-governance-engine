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

"""
B6 - High-Impact Delta Escalation

Validates: position_delta ≤ high_impact_threshold
Enforcement: Mandatory HITL trigger

Escalates high-impact position changes to human oversight. When position
delta exceeds threshold, the trade is flagged for human-in-the-loop (HITL)
review before execution. Uses inclusive boundary math (≤).
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B6DeltaEscalation(BoundingContract):
    """B6 - High-Impact Delta Escalation contract."""

    @property
    def contract_id(self) -> str:
        return "B6"

    def get_enforcement_action(self) -> str:
        return "ESCALATION"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate position delta against HITL threshold.

        Args:
            trade_params: Must contain:
                - position_delta: float (absolute change in position)
                - limits: dict with high_impact_threshold: float

        Returns:
            (PASSED, None) if position_delta ≤ threshold
            (ESCALATED, violation) if position_delta > threshold (triggers HITL)
        """
        position_delta = abs(trade_params.get("position_delta", 0.0))
        limits = trade_params.get("limits", {})
        threshold = limits.get("high_impact_threshold", float("inf"))

        # Inclusive boundary: ≤ not <
        if position_delta <= threshold:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="position_delta",
            limit=threshold,
            actual=position_delta,
            severity=self.get_enforcement_action(),
            message=f"B6: Delta {position_delta:.2f} exceeds HITL threshold {threshold:.2f}",
        )

        return (BoundingContractResult.ESCALATED, violation)
