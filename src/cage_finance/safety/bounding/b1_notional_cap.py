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
B1 - Single-Order Notional Cap

Validates: order_notional ≤ max_single_order_notional
Enforcement: Hard block (reject immediately)

Prevents oversized individual orders that could cause market impact or
concentration risk. Uses inclusive boundary math (≤) per implementation constraints.
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B1NotionalCap(BoundingContract):
    """B1 - Single-Order Notional Cap contract."""

    @property
    def contract_id(self) -> str:
        return "B1"

    def get_enforcement_action(self) -> str:
        return "HARD_BLOCK"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate order notional against single-order cap.

        Args:
            trade_params: Must contain:
                - order_notional: float (order size * price)
                - limits: dict with max_single_order_notional: float

        Returns:
            (PASSED, None) if order_notional ≤ limit
            (FAILED, violation) if order_notional > limit
        """
        order_notional = trade_params.get("order_notional", 0.0)
        limits = trade_params.get("limits", {})
        max_notional = limits.get("max_single_order_notional", float("inf"))

        # Inclusive boundary: ≤ not <
        if order_notional <= max_notional:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="order_notional",
            limit=max_notional,
            actual=order_notional,
            severity=self.get_enforcement_action(),
            message=f"B1: Order notional {order_notional:.2f} exceeds cap {max_notional:.2f}",
        )

        return (BoundingContractResult.FAILED, violation)
