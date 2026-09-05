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
B10 - Rollback Window Validation

Validates: Settlement window has verifiable rollback capability
Enforcement: Re-classify to IRREVERSIBLE_TERMINAL on failure (strict fail-closed)

Validates that trades classified as EXTERNALLY_REVERSIBLE actually have a
verified rollback mechanism in the settlement window. If rollback is not
available, the terminal classification is escalated to IRREVERSIBLE_TERMINAL
to trigger maximum governance scrutiny.
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B10RollbackWindow(BoundingContract):
    """B10 - Rollback Window Validation contract."""

    @property
    def contract_id(self) -> str:
        return "B10"

    def get_enforcement_action(self) -> str:
        return "TERMINAL_RECLASSIFY"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate rollback capability for EXTERNALLY_REVERSIBLE trades.

        Args:
            trade_params: Must contain:
                - settlement_window_seconds: int (time window for rollback)
                - rollback_supported: bool (broker supports cancel/amend)
                - terminal_classification: str (current classification)

        Returns:
            (PASSED, None) if rollback is verified
            (FAILED, violation) if rollback not available (re-classify to IRREVERSIBLE)
        """
        settlement_window = trade_params.get("settlement_window_seconds", 0)
        rollback_supported = trade_params.get("rollback_supported", False)
        terminal_class = trade_params.get(
            "terminal_classification", "EXTERNALLY_REVERSIBLE"
        )

        # Only validate for EXTERNALLY_REVERSIBLE classification
        if terminal_class != "EXTERNALLY_REVERSIBLE":
            return (BoundingContractResult.PASSED, None)

        # Check if rollback is supported with adequate settlement window
        min_rollback_window = 60  # 60 seconds minimum for safe rollback

        if rollback_supported and settlement_window >= min_rollback_window:
            return (BoundingContractResult.PASSED, None)

        # Fail-closed: If rollback not verifiable, re-classify as IRREVERSIBLE
        if not rollback_supported:
            reason = "Broker does not support cancel/amend operations"
        else:
            reason = f"Settlement window ({settlement_window}s) below minimum ({min_rollback_window}s)"

        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="rollback_capability",
            limit=float(min_rollback_window),
            actual=float(settlement_window) if rollback_supported else 0.0,
            severity=self.get_enforcement_action(),
            message=f"B10: {reason} - re-classifying to IRREVERSIBLE_TERMINAL",
        )

        return (BoundingContractResult.FAILED, violation)
