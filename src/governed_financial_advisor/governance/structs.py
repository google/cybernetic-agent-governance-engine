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

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# ExecutionPlan — structured LLM plan schema with gateway-controlled flags
# ---------------------------------------------------------------------------


class ExecutionPlan(BaseModel):
    """Schema for the structured execution plan produced by the Execution Analyst.

    Most fields are populated by the LLM (action, amount, symbol, etc.).
    ``claimed_authorization`` is the sole exception: it is ALWAYS set
    programmatically by the gateway layer's structural detector
    (``authorization_claim_detector.py``).  The LLM must never be instructed
    to populate this field — doing so would allow adversarial inputs to
    self-assert elevated authorization.

    Cross-region impact:
      - US_FED (NIST SP 800-53 AC-3 / IA-3): authorization-claim detection
        is an access-control integrity control.
      - EU_ECB (EU AI Act Art 9): structural input-validation gate.
      - APAC_MAS (MAS TRM / MAS Notice 655): system-integrity guard.
    """

    action: str = Field(
        description="Action to perform (e.g. 'execute_trade', 'market_analysis')"
    )
    amount: float = Field(default=0.0, description="Trade amount in the specified currency")
    symbol: str = Field(default="UNKNOWN", description="Trading instrument symbol")
    currency: str = Field(default="USD", description="ISO 4217 currency code")
    trader_role: str = Field(
        default="junior", description="RBAC role of the requesting trader"
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Plan confidence score (deterministic gate: always 1.0)",
    )

    # -----------------------------------------------------------------------
    # Gateway-controlled flag — set by authorization_claim_detector.py only.
    # Never derived from or populated by LLM-generated content.
    # See: src/gateway/governance/authorization_claim_detector.py
    # -----------------------------------------------------------------------
    claimed_authorization: bool = Field(
        default=False,
        description=(
            "True when the gateway's structural detector found an authorization-claim "
            "escalation pattern in the raw user message. "
            "Set programmatically; never LLM-sourced."
        ),
    )

# ---------------------------------------------------------------------------
# Governance-block detection sentinels (canonical single source of truth)
# ---------------------------------------------------------------------------

# Sentinel substrings that indicate the backend issued a governance refusal
# rather than a real financial-advisory answer.  Matching is case-insensitive.
# Import this constant in test files and evaluation scripts instead of
# duplicating the tuple locally.
GOVERNANCE_BLOCK_SENTINELS: tuple[str, ...] = (
    # Core governance-block phrases — match with/without auxiliary verbs so
    # both "manual justification required" and "manual justification is required"
    # (the phrasing emitted by the SymbolicGovernor) are detected correctly.
    "manual justification required",
    "manual justification is required",
    "justification is required",
    "governance blocked",
    "blocked by governance",
    "manual review required",
    "requires human approval",
    "requires manual approval",
    "policy violation",
    "governance refusal",
    "action blocked",
    "compliance block",
    "trade was rejected by the governance",
    "rejected by the governance policy",
    # STPA validator output — emitted when a UCA (Unsafe Control Action) is matched.
    # Format: "STPA Violation UCA-N: <description>" — prefix is sufficient.
    "STPA Violation",
    # Internal governance error path — emitted when the governance pipeline
    # raises an exception before producing a substantive response.
    "Validation failed due to internal governance error",
    "internal governance error",
)

# Predetermined scores for a governance-blocked response.
#   governance_compliance = 1.0 — the system did the right thing by blocking
#   response_quality      = 0.0 — the user received no substantive answer
#   risk_appropriateness  = 1.0 — blocking is the most risk-appropriate action
GOVERNANCE_BLOCK_SCORES: dict[str, float] = {
    "governance_compliance": 1.0,
    "response_quality": 0.0,
    "risk_appropriateness": 1.0,
}


class ConstraintLogic(BaseModel):
    """Structured logic for the transpiler"""

    variable: str = Field(
        description="The variable to check (e.g., 'order_size', 'drawdown', 'latency')"
    )
    operator: str = Field(description="Comparison operator (e.g., '<', '>', '==')")
    threshold: str = Field(
        description="Threshold value or reference (e.g., '0.01 * daily_volume', '200')"
    )
    condition: str | None = Field(
        default=None, description="Pre-condition (e.g., 'order_type == MARKET')"
    )


class ProposedUCA(BaseModel):
    """
    Proposed Unsafe Control Action identified by Risk Analysis.
    Used by PolicyTranspiler.
    """

    category: str = Field(
        description="STPA Category: Unsafe Action, Wrong Timing, Not Provided, Stopped Too Soon"
    )
    hazard: str = Field(
        description="The specific financial hazard (e.g., 'H-4: Slippage > 1%')"
    )
    description: str = Field(description="Description of the unsafe control action")
    constraint_logic: ConstraintLogic = Field(
        description="Structured logic for the transpiler"
    )
