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
B8 - TWAP Slippage Bound

Validates: execution_price - benchmark_price ≤ max_slippage
Enforcement: Halt execution on slip limit

Protects against excessive execution slippage by comparing actual execution
price against TWAP (Time-Weighted Average Price) benchmark. Uses inclusive
boundary math (≤) for slippage tolerance.
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B8SlippageBound(BoundingContract):
    """B8 - TWAP Slippage Bound contract."""

    @property
    def contract_id(self) -> str:
        return "B8"

    def get_enforcement_action(self) -> str:
        return "HARD_BLOCK"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate execution slippage against TWAP benchmark.

        Args:
            trade_params: Must contain:
                - execution_price: float (actual or expected execution price)
                - benchmark_price: float (TWAP or reference price)
                - side: str ("buy" or "sell" - determines slippage direction)
                - limits: dict with max_slippage: float (percentage, 0.0-1.0)

        Returns:
            (PASSED, None) if slippage ≤ limit
            (FAILED, violation) if slippage > limit
        """
        execution_price = trade_params.get("execution_price", 0.0)
        benchmark_price = trade_params.get("benchmark_price", 0.0)
        side = trade_params.get("side", "buy")
        limits = trade_params.get("limits", {})
        max_slippage = limits.get("max_slippage", 0.05)  # Default 5%

        if benchmark_price <= 0:
            violation = ContractViolation(
                contract_id=self.contract_id,
                parameter="benchmark_price",
                limit=max_slippage,
                actual=0.0,
                severity=self.get_enforcement_action(),
                message=f"B8: Invalid benchmark price ({benchmark_price})",
            )
            return (BoundingContractResult.FAILED, violation)

        # Calculate slippage based on trade side
        if side == "buy":
            # For buys: negative slippage = better price (paid less)
            # positive slippage = worse price (paid more)
            slippage = (execution_price - benchmark_price) / benchmark_price
        else:
            # For sells: negative slippage = worse price (received less)
            # positive slippage = better price (received more)
            slippage = (benchmark_price - execution_price) / benchmark_price

        # Only check if slippage is unfavorable (positive)
        # Inclusive boundary: ≤ not <
        if slippage <= max_slippage:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="slippage",
            limit=max_slippage,
            actual=slippage,
            severity=self.get_enforcement_action(),
            message=f"B8: Slippage {slippage:.4f} exceeds limit {max_slippage:.4f}",
        )

        return (BoundingContractResult.FAILED, violation)
