# InferTheta Canonical Wire Contract & Normative Seam Specification

**Audience**: Integration engineers, compliance auditors, security architects  
**Status**: Step 1 Validated (Staging Live) — Dedicated Graph Calibrated  
**Last Updated**: 2026-09-23  
**Adapter Package**: [`src/integrations/provider_07/`](../../src/integrations/provider_07/)

---

## Executive Summary

InferTheta provides **Bayesian belief network inference** for discretionary wealth advisory and portfolio rebalancing under **SEC Regulation Best Interest (Reg BI)**, **FINRA Rule 2111**, and **EU AI Act Article 29a**. The service executes **junction tree inference** over causal graphs encoding client suitability constraints, market conditions, and regulatory thresholds to emit tri-state decisions (`ALLOW`, `REFUSE`, `ESCALATE`) with **posterior probabilities** and **utility rankings** for alternative actions.

This document specifies the **canonical wire contract** between CAGE Layer 1 Kernel ([`NormativeProvider`](../../src/gateway/governance/normative_provider.py) seam) and the InferTheta external API, ensuring:
- **Cryptographic verifiability** via out-of-band JWKS and Ed25519 signatures
- **Fail-closed enforcement** on unknown keys, network failures, and schema violations
- **Tamper-evident audit chain** for DENY and PAUSE receipts alongside ALLOW approvals

---

## 1. Context & Regulatory Scope

### 1.1 Use Case
InferTheta operates as a **normative gating oracle** for high-stakes financial advisory scenarios:
- **Portfolio rebalancing**: Validate proposed asset allocation shifts against client risk tolerance and investment horizon
- **Trade execution**: Pre-flight suitability checks for individual trades (buy/sell orders)
- **Margin expansion**: Assess liquidity risk before authorizing leveraged positions

### 1.2 Regulatory Alignment
| Regulation | Obligation | InferTheta Signal |
|---|---|---|
| **SEC Reg BI** | Broker-dealers must act in client's best interest | `posterior_risk_score`, client profile compliance |
| **FINRA Rule 2111** | Suitability obligation (reasonable basis, customer-specific) | `marginal_probabilities` for drawdown, volatility |
| **EU AI Act Art. 29a** | High-risk AI transparency and human oversight | `utility_rankings` for alternative actions, `ESCALATE` triggers |

### 1.3 Causal Inference Model
InferTheta encodes domain knowledge as a **directed acyclic graph (DAG)**:
- **Evidence nodes**: `market_volatility_index`, `portfolio_vector`, `client_profile.risk_tolerance`
- **Latent variables**: `drawdown_probability`, `liquidity_stress`, `regulatory_threshold_breach`
- **Decision node**: `action_suitability` (maps to `ALLOW`/`REFUSE`/`ESCALATE`)

Junction tree algorithms compute **exact marginal posteriors** conditioned on observed evidence, avoiding Monte Carlo approximation error in safety-critical contexts.

---

## 2. Wire Protocol Specification

### 2.1 Inference Endpoint: `POST /infer`

**Request Schema** (`InferThetaInferenceRequest`):
```json
{
  "scenario_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "rebalance_portfolio",
  "target": "urn:account:client-12345:portfolio-main",
  "actor_id": "urn:agent:financial-advisor-bot-v2",
  "portfolio_vector": {
    "US_EQUITY": 0.60,
    "INTL_EQUITY": 0.20,
    "FIXED_INCOME": 0.15,
    "CASH": 0.05
  },
  "proposed_trade": {
    "asset": "VANGUARD_TOTAL_BOND_INDEX",
    "side": "BUY",
    "amount": 25000.00,
    "currency": "USD"
  },
  "client_profile": {
    "risk_tolerance": "MODERATE",
    "investment_horizon_years": 15,
    "liquidity_need": "LOW"
  },
  "market_volatility_index": 0.18,
  "context": {
    "session_id": "advise-session-789",
    "timestamp_utc": "2026-09-15T20:00:00Z"
  }
}
```

**Field Definitions**:
- `scenario_id` (string, UUID): Unique thread/conversation identifier for correlation
- `action` (string): Canonical action verb (e.g., `rebalance_portfolio`, `execute_trade`, `expand_margin`)
- `target` (string, URN): Resource identifier for the portfolio/account under governance
- `actor_id` (string, URN): Identity of the requesting agent or human operator
- `portfolio_vector` (object): Current asset allocations as `{asset_class: weight}` (weights sum to ≈1.0)
- `proposed_trade` (object):
  - `asset` (string): Instrument ticker or fund identifier
  - `side` (string): `"BUY"` or `"SELL"`
  - `amount` (float): Notional value or share count
  - `currency` (string): ISO 4217 currency code (default: `"USD"`)
- `client_profile` (object):
  - `risk_tolerance` (string): `"CONSERVATIVE"`, `"MODERATE"`, `"AGGRESSIVE"`
  - `investment_horizon_years` (int): Time until expected withdrawal (0–50)
  - `liquidity_need` (string): `"HIGH"`, `"MEDIUM"`, `"LOW"`
- `market_volatility_index` (float): VIX or equivalent volatility measure (0.0–1.0+)
- `context` (object, optional): Auxiliary metadata for logging (not used in inference)

---

**Response Schema** (`InferThetaInferenceResponse`):
```json
{
  "decision": "ALLOW",
  "confidence_score": 0.92,
  "posterior_risk_score": 0.14,
  "marginal_probabilities": {
    "drawdown_gt_15pct": 0.08,
    "volatility_spike": 0.12,
    "liquidity_stress": 0.03
  },
  "utility_rankings": [
    {
      "action": "rebalance_to_proposed",
      "expected_utility": 0.87
    },
    {
      "action": "defer_to_human",
      "expected_utility": 0.65
    },
    {
      "action": "reject_trade",
      "expected_utility": 0.42
    }
  ],
  "authority_record_id": "infertheta-auth-20260915-183722-a3f9c2",
  "kid": "infertheta-prod-ed25519-2026q3",
  "signature": "dGhpcyBpcyBhIGJhc2U2NHVybCBlZDI1NTE5IHNpZ25hdHVyZQ",
  "findings": [
    {
      "rule_id": "FINRA-2111-CUSTOMER-SPECIFIC",
      "status": "COMPLIANT",
      "evidence": "Client risk tolerance matches proposed allocation shift"
    },
    {
      "rule_id": "SEC-REGBI-BEST-INTEREST",
      "status": "COMPLIANT",
      "evidence": "Expected utility exceeds status quo by 0.22"
    }
  ]
}
```

**Field Definitions**:
- `decision` (string, enum): **Tri-state gate verdict**
  - `"ALLOW"`: Action meets all suitability thresholds (posterior risk within bounds)
  - `"REFUSE"`: Action violates regulatory or suitability constraints (posterior risk too high)
  - `"ESCALATE"`: Ambiguous or edge case requiring human judgment (low confidence)
- `confidence_score` (float, 0.0–1.0): Model certainty in the decision (entropy-derived)
- `posterior_risk_score` (float, 0.0–1.0): Aggregate risk metric from Bayesian posterior (higher = riskier)
- `marginal_probabilities` (object): Per-risk-factor posterior probabilities (e.g., `P(drawdown > 15% | evidence)`)
- `utility_rankings` (array): Ordered list of action alternatives with expected utility scores
  - `action` (string): Alternative action identifier
  - `expected_utility` (float): Decision-theoretic utility under posterior distribution
- `authority_record_id` (string | null): **Mandatory if `decision == "ALLOW"`**. Unique authorization token for audit trail. Absence when `ALLOW` triggers `TOKEN_MINT_FAILED` error.
- `kid` (string): **Key Identifier** resolving against out-of-band JWKS manifest (never an embedded key)
- `signature` (string): **Base64url-encoded Ed25519 signature** over canonical JCS serialization of the response body **excluding** the `signature` field itself
- `findings` (array): Structured compliance assessments mapping to regulatory citations

---

### 2.2 Baseline Endpoint: `GET /baseline/{region}`

Retrieves the **normative ruleset** and configuration for a specific regulatory region.

**Request**: `GET https://api.infertheta.example/baseline/us-east-1`

**Response Schema** (`InferThetaBaselineResponse`):
```json
{
  "region": "us-east-1",
  "rules": [
    {
      "rule_id": "FINRA-2111-REASONABLE-BASIS",
      "description": "Broker must have reasonable basis to believe recommendation is suitable",
      "threshold": 0.85
    },
    {
      "rule_id": "SEC-REGBI-CONFLICT-DISCLOSURE",
      "description": "Disclose material conflicts of interest",
      "threshold": 1.0
    }
  ],
  "baseline_hash": "sha256:a3f9c2d8e1b4567890abcdef1234567890abcdef1234567890abcdef12345678",
  "issued_at": 1726432800
}
```

**Field Definitions**:
- `region` (string): Geographic/regulatory region identifier (e.g., `us-east-1`, `eu-central-1`)
- `rules` (array): Normative rule definitions
  - `rule_id` (string): Canonical regulatory citation or internal rule code
  - `description` (string): Human-readable obligation summary
  - `threshold` (float): Minimum posterior probability or compliance score (0.0–1.0)
- `baseline_hash` (string): SHA-256 digest of the rule content for tamper detection
- `issued_at` (int): UNIX timestamp of baseline generation

---

## 3. Cryptographic Verification Scheme

### 3.1 Trust Anchor Resolution (Fail-Closed)

**Invariant**: **Never verify a signature against an embedded public key supplied by the signed document.**

**Protocol**:
1. Extract `kid` from `InferThetaInferenceResponse`.
2. Fetch JWKS manifest from **out-of-band** endpoint (cached, independently resolved):
   ```
   GET {PROVIDER_07_JWKS_URL}
   ```
   Example JWKS response:
   ```json
   {
     "keys": [
       {
         "kid": "infertheta-prod-ed25519-2026q3",
         "kty": "OKP",
         "crv": "Ed25519",
         "x": "base64url_encoded_public_key"
       }
     ]
   }
   ```
3. Resolve public key by `kid`:
   - **If `kid` unknown**: Reject with `INFERTHETA_UNKNOWN_KEY`, set `admitted=False`.
   - **If `kid` found**: Proceed to signature verification.

### 3.2 Signature Verification

1. **Canonical Serialization**: Serialize the response body **excluding** the `signature` field using **JCS (RFC 8785)** to produce a deterministic byte sequence.
2. **Verify Ed25519 Signature**:
   ```python
   from cryptography.hazmat.primitives.asymmetric import ed25519

   public_key.verify(signature_bytes, canonical_body_bytes)
   ```
3. **On Failure**: Reject with `SIGNATURE_VERIFICATION_FAILED`, set `admitted=False`.

### 3.3 Resolution vs. Verification Status

**Critical Distinction**:
- **Resolution Status**: Whether the HTTP request to InferTheta succeeded and returned parseable JSON.
- **Verification Status**: Whether the cryptographic signature is valid.

**A successful fetch (200 OK) proves receipt exists, NOT signature validity.**  
Always return `verification_status=UNVERIFIED` until Ed25519 verification succeeds, then upgrade to `VERIFIED`.

---

## 4. Fail-Closed Behavior Matrix

| Failure Mode | HTTP Status | Error Code | `admitted` | Rationale |
|---|---|---|---|---|
| Network timeout | N/A | `HTTP_TIMEOUT` | `False` | Cannot confirm safety → fail closed |
| HTTP 500/502/503 | 5xx | `PROVIDER_ERROR` | `False` | Provider instability → default deny |
| HTTP 404 on baseline | 404 | `BASELINE_NOT_FOUND` | `False` | Cannot validate without normative anchor |
| Unknown `kid` | 200 | `INFERTHETA_UNKNOWN_KEY` | `False` | Untrusted signing key → reject |
| Invalid Ed25519 signature | 200 | `SIGNATURE_VERIFICATION_FAILED` | `False` | Tampered response → reject |
| Malformed JSON | 200 | `SCHEMA_VALIDATION_ERROR` | `False` | Cannot parse → cannot trust |
| Missing `authority_record_id` on `ALLOW` | 200 | `TOKEN_MINT_FAILED` | `False` | Authorization without audit token is invalid |
| `decision == "REFUSE"` | 200 | (none) | `False` | Normative refusal (legitimate deny) |
| `decision == "ESCALATE"` | 200 | (none) | `False` | Deferred to human → block autonomous execution |
| `decision == "ALLOW"` + valid signature + `authority_record_id` present | 200 | (none) | `True` | All safety gates passed |

**Refusals Are Primary Evidence**: `REFUSE` and `ESCALATE` responses must enter the tamper-evident audit chain with the same cryptographic rigor as `ALLOW` approvals.

---

## 5. Integration Touchpoints

### 5.1 NormativeProvider Seam Mapping

The InferTheta adapter ([`src/integrations/provider_07/adapter.py`](../../src/integrations/provider_07/adapter.py), Phase 2) must implement:

```python
class NormativeProvider(Protocol):
    async def fetch_baseline(self, region: str) -> BaselineResponse:
        """Map to GET /baseline/{region}"""
        ...

    async def validate_fria(self, request: FRIARequest) -> FRIAResponse:
        """Map to POST /infer, transform tri-state decision to admitted bool"""
        ...

    async def submit_evidence(self, evidence: EvidencePayload) -> SubmissionReceipt:
        """(Future) POST /evidence — archive findings for retrospective audit"""
        ...
```

**Canonical Transform**:
```python
if response.decision == "ALLOW" and response.authority_record_id:
    admitted = True
else:
    admitted = False  # REFUSE, ESCALATE, or missing token
```

### 5.2 Environment Variables (Layer 3)

Defined in [`src/integrations/provider_07/README.md`](../../src/integrations/provider_07/README.md):
- `PROVIDER_07_ENDPOINT`: Base URL (default: `http://localhost:8087`)
- `PROVIDER_07_API_KEY`: Bearer token
- `PROVIDER_07_JWKS_URL`: Out-of-band JWKS manifest URL
- `PROVIDER_07_TIMEOUT_SECONDS`: Request timeout (default: `5.0`)

---

## 6. Bayesian Posterior Interpretation

### 6.1 Risk Score Aggregation
`posterior_risk_score` is computed as a **weighted sum** of marginal probabilities for adverse events:
```python
posterior_risk_score = (
    0.5 * P(drawdown_gt_15pct) + 0.3 * P(volatility_spike) + 0.2 * P(liquidity_stress)
)
```
Thresholds (configured per region in baseline):
- `posterior_risk_score < 0.20`: Low risk → likely `ALLOW`
- `0.20 ≤ posterior_risk_score < 0.40`: Moderate risk → may `ESCALATE`
- `posterior_risk_score ≥ 0.40`: High risk → likely `REFUSE`

### 6.2 Utility Rankings
Expected utility scores guide **counterfactual recommendations**:
- If `action="rebalance_to_proposed"` has highest utility → `ALLOW`
- If `action="defer_to_human"` dominates → `ESCALATE`
- If `action="reject_trade"` dominates → `REFUSE`

---

## 7. Open Questions & Future Work

1. **Baseline Versioning**: How to handle rolling updates to regional rulesets without breaking in-flight requests?
2. **Batch Inference**: Support for multi-action validation in a single API call?
3. **Confidence Threshold Tuning**: Should `ESCALATE` trigger at `confidence_score < 0.70` or `< 0.80`?
4. **Causality Audit Trails**: Embedding DAG structure snapshots in `findings` for explainability?

---

## 8. References

- [NormativeProvider Protocol](../../src/gateway/governance/normative_provider.py)
- [Secure Plugin & Adapter Architecture](../../architecture/EXTENSIBILITY_ARCHITECTURE.md)
- [Gate G8: Vendor Brand Isolation](../../AGENTS.md#architecture--design-standards)
- [InferTheta Adapter README](../../src/integrations/provider_07/README.md)
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [SEC Regulation Best Interest](https://www.sec.gov/rules/final/2019/34-86031.pdf)
- [FINRA Rule 2111: Suitability](https://www.finra.org/rules-guidance/rulebooks/finra-rules/2111)
- [EU AI Act Article 29a (Draft)](https://artificialintelligenceact.eu/)

---

**Document Status**: ✅ Step 1 Complete — Wire Contract, Dedicated Graph & Staging Validated  
**Next Phase**: Step 2 — Cryptographic Hardening (Ed25519 signature enforcement, out-of-band JWKS endpoint, minted `authority_record_id`)
