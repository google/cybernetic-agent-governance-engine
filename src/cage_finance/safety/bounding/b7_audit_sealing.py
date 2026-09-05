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
B7 - Audit Trail Sealing

Action: Append to Evidence Stream v3.0
Enforcement: Seal & hash-chain (fail-closed if Evidence Stream unavailable)

All trade decisions are cryptographically sealed in the Evidence Stream
with hash-chained records. This contract doesn't validate trade parameters
but ensures all decisions are immutably recorded for compliance.
"""

from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation


class B7AuditSealing(BoundingContract):
    """B7 - Audit Trail Sealing contract."""

    @property
    def contract_id(self) -> str:
        return "B7"

    def get_enforcement_action(self) -> str:
        return "AUDIT_SEAL"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate Evidence Stream availability.

        B7 is a special contract - it doesn't validate trade parameters but
        ensures the Evidence Stream is available for sealing. The actual
        sealing happens in execute_trade_bounded after all contracts validate.

        Args:
            trade_params: Must contain:
                - evidence_stream_available: bool (Evidence Stream health check)

        Returns:
            (PASSED, None) if Evidence Stream is available
            (FAILED, violation) if Evidence Stream is unavailable (fail-closed)
        """
        evidence_available = trade_params.get("evidence_stream_available", False)

        if evidence_available:
            return (BoundingContractResult.PASSED, None)

        # Fail-closed: If Evidence Stream is down, block trading
        violation = ContractViolation(
            contract_id=self.contract_id,
            parameter="evidence_stream_available",
            limit=1.0,
            actual=0.0,
            severity="FAIL_CLOSED",
            message="B7: Evidence Stream unavailable - trading halted (fail-closed)",
        )

        return (BoundingContractResult.FAILED, violation)
