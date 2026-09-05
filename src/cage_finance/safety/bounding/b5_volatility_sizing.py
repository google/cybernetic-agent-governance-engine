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
B5 - Volatility-Adjusted Sizing

Validates: order_size ≤ base_size / (1 + ATR_multiplier * current_volatility)
Enforcement: Scale down or reject

Dynamically adjusts position sizing based on market volatility (ATR).
Higher volatility reduces maximum allowed order size to manage risk.
Uses inclusive boundary math (≤).
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B5VolatilitySizing(BoundingContract):
    """B5 - Volatility-Adjusted Sizing contract."""

    @property
    def contract_id(self) -> str:
        return "B5"

    def get_enforcement_action(self) -> str:
        return "SCALE_DOWN"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate order size against volatility-adjusted limit.

        Args:
            trade_params: Must contain:
                - requested_size: float (requested order size)
                - base_order_size: float (baseline size in calm markets)
                - current_volatility: float (ATR or similar metric)
                - atr_multiplier: float (volatility sensitivity factor)

        Returns:
            (PASSED, None) if requested_size ≤ volatility-adjusted limit
            (SCALED, violation) with scaled_size if requested_size > limit
        """
        requested_size = trade_params.get("requested_size", 0.0)
        base_size = trade_params.get("base_order_size", 100.0)
        volatility = trade_params.get("current_volatility", 0.0)
        atr_multiplier = trade_params.get("atr_multiplier", 1.0)

        # Calculate volatility-adjusted maximum size
        volatility_factor = 1.0 + (atr_multiplier * volatility)
        max_allowed_size = base_size / volatility_factor

        # Inclusive boundary: ≤ not <
        if requested_size <= max_allowed_size:
            return (BoundingContractResult.PASSED, None)

        # Return SCALED result with the violation containing the scaled size
        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="order_size",
            limit=max_allowed_size,
            actual=requested_size,
            severity=self.get_enforcement_action(),
            message=f"B5: Requested size {requested_size:.2f} exceeds volatility-adjusted limit {max_allowed_size:.2f} (scaled)",
        )

        return (BoundingContractResult.SCALED, violation)
