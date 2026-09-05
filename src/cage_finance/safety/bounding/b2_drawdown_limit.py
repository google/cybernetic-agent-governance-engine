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
B2 - Daily Portfolio Drawdown Limit

Validates: current_drawdown ≤ max_daily_drawdown
Enforcement: Circuit breaker trip (halt all trading)

Protects portfolio from cascading losses by halting trading when daily
drawdown exceeds risk tolerance. Uses inclusive boundary math (≤).
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B2DrawdownLimit(BoundingContract):
    """B2 - Daily Portfolio Drawdown Limit contract."""

    @property
    def contract_id(self) -> str:
        return "B2"

    def get_enforcement_action(self) -> str:
        return "CIRCUIT_BREAKER"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate current drawdown against daily limit.

        Args:
            trade_params: Must contain:
                - current_drawdown: float (percentage, 0.0-1.0)
                - limits: dict with max_daily_drawdown: float

        Returns:
            (PASSED, None) if current_drawdown ≤ limit
            (FAILED, violation) if current_drawdown > limit (triggers circuit breaker)
        """
        current_drawdown = trade_params.get("current_drawdown", 0.0)
        limits = trade_params.get("limits", {})
        max_drawdown = limits.get("max_daily_drawdown", 1.0)

        # Inclusive boundary: ≤ not <
        if current_drawdown <= max_drawdown:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="current_drawdown",
            limit=max_drawdown,
            actual=current_drawdown,
            severity=self.get_enforcement_action(),
            message=f"B2: Drawdown {current_drawdown:.4f} exceeds limit {max_drawdown:.4f}",
        )

        return (BoundingContractResult.FAILED, violation)
