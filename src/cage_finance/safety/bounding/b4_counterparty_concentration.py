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
B4 - Counterparty Concentration Limit

Validates: exposure_to_counterparty / total_exposure ≤ max_concentration
Enforcement: Reject trade (concentration risk)

Prevents over-concentration with any single counterparty by limiting the
percentage of total exposure. Uses inclusive boundary math (≤).
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B4CounterpartyConcentration(BoundingContract):
    """B4 - Counterparty Concentration Limit contract."""

    @property
    def contract_id(self) -> str:
        return "B4"

    def get_enforcement_action(self) -> str:
        return "HARD_BLOCK"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate counterparty concentration against limit.

        Args:
            trade_params: Must contain:
                - counterparty_exposure: float (exposure to specific counterparty)
                - total_exposure: float (total portfolio exposure)
                - limits: dict with max_concentration: float

        Returns:
            (PASSED, None) if concentration ≤ limit
            (FAILED, violation) if concentration > limit
        """
        counterparty_exposure = trade_params.get("counterparty_exposure", 0.0)
        total_exposure = trade_params.get("total_exposure", float("inf"))
        limits = trade_params.get("limits", {})
        max_concentration = limits.get("max_concentration", 1.0)

        # Avoid division by zero
        if total_exposure <= 0:
            # If no total exposure, any counterparty exposure is 100% concentration
            if counterparty_exposure > 0:
                violation = ContractViolation(
                    contract_id=self.contract_id,
                    parameter="concentration",
                    limit=max_concentration,
                    actual=1.0,
                    severity=self.get_enforcement_action(),
                    message=f"B4: Total exposure is zero or negative ({total_exposure})",
                )
                return (BoundingContractResult.FAILED, violation)
            else:
                # Both zero - pass
                return (BoundingContractResult.PASSED, None)

        concentration = counterparty_exposure / total_exposure

        # Inclusive boundary: ≤ not <
        if concentration <= max_concentration:
            return (BoundingContractResult.PASSED, None)

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="concentration",
            limit=max_concentration,
            actual=concentration,
            severity=self.get_enforcement_action(),
            message=f"B4: Concentration {concentration:.4f} exceeds limit {max_concentration:.4f}",
        )

        return (BoundingContractResult.FAILED, violation)
