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

"""Approval contract for human-in-the-loop decisions."""

from pydantic import BaseModel, model_validator


class ApprovalDecision(BaseModel):
    """Resume payload for human-in-the-loop approval interrupt().

    Attributes:
        ticket_id: Unique defer ticket ID for atomic idempotency enforcement.
        approved:  Whether the trade is approved or rejected.
        reviewer:  Identity of the human reviewer (email or employee ID).
                   Used for ISO 42001 A.7.2 accountability attribution.
        rationale: Mandatory free-text justification.  The auditor's reason
                   for this decision is hashed directly into the evidence chain —
                   an unexplained resume is a compliance gap (ISO 42001 §6.1,
                   NIST AI RMF GOVERN-5).
        comment:   Optional supplementary note (legacy field — prefer rationale).
        max_slippage_pct: Reviewer's execution price tolerance (%).
    """

    ticket_id: str | None = None
    approved: bool
    reviewer: str
    rationale: str  # mandatory — cannot be empty string
    comment: str = ""  # kept for backwards compatibility
    max_slippage_pct: float = 2.0  # reviewer's execution price tolerance (%)

    @staticmethod
    def _validate_rationale(value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "rationale is required and must be a non-empty string. "
                "Provide the business justification for this approval decision "
                "so it can be hashed into the compliance evidence chain."
            )
        return value

    @model_validator(mode="after")
    def _check_rationale_not_empty(self) -> "ApprovalDecision":
        self._validate_rationale(self.rationale)
        return self
