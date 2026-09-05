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
B3 - Liquidity Depth Ratio

Validates: order_size / order_book_depth ≤ max_depth_ratio
Enforcement: Reject trade (insufficient liquidity)

Prevents market impact by ensuring order size doesn't exceed a threshold
percentage of available liquidity in the order book. Uses inclusive boundary math (≤).
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B3LiquidityDepth(BoundingContract):
    """B3 - Liquidity Depth Ratio contract."""

    @property
    def contract_id(self) -> str:
        return "B3"

    def get_enforcement_action(self) -> str:
        return "HARD_BLOCK"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate order size against order book depth.

        Args:
            trade_params: Must contain:
                - order_size: float (number of shares/units)
                - order_book_depth: float (available liquidity)
                - limits: dict with max_depth_ratio: float

        Returns:
            (PASSED, None) if depth_ratio ≤ limit
            (FAILED, violation) if depth_ratio > limit
        """
        order_size = trade_params.get("order_size", 0.0)
        order_book_depth = trade_params.get("order_book_depth", float("inf"))
        limits = trade_params.get("limits", {})
        max_depth_ratio = limits.get("max_depth_ratio", 1.0)

        # Avoid division by zero
        if order_book_depth <= 0:
            violation = ContractViolation(
                contract_id=self.contract_id,
                parameter="order_book_depth",
                limit=max_depth_ratio,
                actual=float("inf"),
                severity=self.get_enforcement_action(),
                message=f"B3: Order book depth is zero or negative ({order_book_depth})",
            )
            return (BoundingContractResult.FAILED, violation)

        depth_ratio = order_size / order_book_depth

        # Inclusive boundary: ≤ not <
        if depth_ratio <= max_depth_ratio:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="depth_ratio",
            limit=max_depth_ratio,
            actual=depth_ratio,
            severity=self.get_enforcement_action(),
            message=f"B3: Depth ratio {depth_ratio:.4f} exceeds limit {max_depth_ratio:.4f}",
        )

        return (BoundingContractResult.FAILED, violation)
