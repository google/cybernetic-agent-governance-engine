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
provider_07 Wire Protocol Schema Models (Bayesian Causal Suitability Oracle)

Defines strict Pydantic v2 models mapping to the canonical JSON wire contract for
Bayesian belief network inference over financial suitability constraints (SEC Reg BI,
FINRA Rule 2111, EU AI Act Art. 29a).

Key Invariants:
- Tri-state decision mapping: ALLOW/REFUSE/ESCALATE → admitted bool
- Ed25519 signature verification via out-of-band JWKS (kid resolution)
- authority_record_id mandatory when decision == "ALLOW"
- Fail-closed on unknown kid, signature failure, or schema validation errors

See: docs/partners/INFERTHETA_CANONICAL_SCHEMA.md
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

# ============================================================================
# Inference Request Models
# ============================================================================


class ProposedTrade(BaseModel):
    """
    Proposed trade order for suitability validation.

    Attributes:
        asset: Instrument ticker or fund identifier (e.g., "VANGUARD_TOTAL_BOND_INDEX")
        side: Trade direction ("BUY" or "SELL")
        amount: Notional value or share count
        currency: ISO 4217 currency code (default: "USD")
    """

    asset: str
    side: str  # "BUY" | "SELL"
    amount: float
    currency: str = "USD"


class ClientProfile(BaseModel):
    """
    Client suitability profile for regulatory compliance assessment.

    Attributes:
        risk_tolerance: Risk appetite classification ("CONSERVATIVE", "MODERATE", "AGGRESSIVE")
        investment_horizon_years: Time until expected withdrawal (0-50 years)
        liquidity_need: Liquidity requirement level ("HIGH", "MEDIUM", "LOW")
    """

    risk_tolerance: str  # "CONSERVATIVE" | "MODERATE" | "AGGRESSIVE"
    investment_horizon_years: int
    liquidity_need: str  # "HIGH" | "MEDIUM" | "LOW"


class InferThetaInferenceRequest(BaseModel):
    """
    Request payload for Bayesian inference over portfolio suitability.

    Maps to: POST /infer

    Attributes:
        scenario_id: Unique thread/conversation identifier (UUID format)
        action: Canonical action verb (e.g., "rebalance_portfolio", "execute_trade")
        target: Resource URN for the portfolio/account under governance
        actor_id: Identity URN of the requesting agent or human operator
        portfolio_vector: Current asset allocations as {asset_class: weight} (sum ≈ 1.0)
        proposed_trade: Trade order to validate
        client_profile: Client suitability constraints
        market_volatility_index: VIX or equivalent volatility measure (0.0-1.0+)
        context: Auxiliary metadata for logging (not used in inference)
    """

    scenario_id: str
    action: str
    target: str
    actor_id: str
    portfolio_vector: dict[str, float]
    proposed_trade: ProposedTrade
    client_profile: ClientProfile
    market_volatility_index: float = 0.0
    context: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Inference Response Models
# ============================================================================


class ActionUtility(BaseModel):
    """
    Decision-theoretic utility score for an action alternative.

    Attributes:
        action: Alternative action identifier (e.g., "defer_to_human", "reject_trade")
        expected_utility: Utility score under posterior distribution (higher = preferred)
    """

    action: str
    expected_utility: float


class InferThetaInferenceResponse(BaseModel):
    """
    Response payload from Bayesian suitability inference.

    Maps to: POST /infer (response)

    Attributes:
        decision: Tri-state gate verdict ("ALLOW", "REFUSE", "ESCALATE")
        confidence_score: Model certainty in the decision (0.0-1.0, entropy-derived)
        posterior_risk_score: Aggregate risk metric from Bayesian posterior (0.0-1.0)
        marginal_probabilities: Per-risk-factor posterior probabilities (e.g., drawdown_gt_15pct)
        utility_rankings: Ordered list of action alternatives with expected utility scores
        authority_record_id: Mandatory authorization token if decision == "ALLOW" (else None)
        kid: Key Identifier resolving against out-of-band JWKS manifest
        signature: Base64url Ed25519 signature over canonical JCS response (excluding this field)
        findings: Structured compliance assessments mapping to regulatory citations
    """

    decision: Literal["ALLOW", "REFUSE", "ESCALATE"]
    confidence_score: float = Field(ge=0.0, le=1.0)
    posterior_risk_score: float = Field(ge=0.0, le=1.0)
    marginal_probabilities: dict[str, float] = Field(default_factory=dict)
    utility_rankings: list[ActionUtility] = Field(default_factory=list)
    authority_record_id: str | None = None
    kid: str
    signature: str
    findings: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# Baseline Request/Response Models
# ============================================================================


class NormativeRule(BaseModel):
    """
    Regulatory rule definition from regional baseline.

    Attributes:
        rule_id: Canonical regulatory citation or internal rule code
        description: Human-readable obligation summary
        threshold: Minimum posterior probability or compliance score (0.0-1.0)
    """

    rule_id: str
    description: str
    threshold: float


class InferThetaBaselineResponse(BaseModel):
    """
    Regional normative ruleset and configuration.

    Maps to: GET /baseline/{region}

    Attributes:
        region: Geographic/regulatory region identifier (e.g., "us-east-1", "eu-central-1")
        rules: Normative rule definitions for this region
        baseline_hash: SHA-256 digest of the rule content for tamper detection
        issued_at: UNIX timestamp of baseline generation
    """

    region: str
    rules: list[NormativeRule]
    baseline_hash: str
    issued_at: int
