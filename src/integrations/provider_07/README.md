# provider_07 — Bayesian Causal Suitability Adapter (Layer 3)

**Adapter Type**: Normative Gating Oracle  
**Inference Model**: Junction Tree / Belief Propagation  
**Regulatory Scope**: SEC Reg BI, FINRA Rule 2111, EU AI Act Art. 29a  
**Architecture Layer**: Layer 3 (Integrations & Rails)  
**Phase**: Phase 1 — Schema Definition & Documentation  

---

## Overview

The `provider_07` adapter integrates a **Bayesian belief network inference service** (InferTheta) as a normative gating oracle for high-stakes financial advisory scenarios. The service executes **junction tree algorithms** over causal graphs encoding:
- Client suitability constraints (risk tolerance, investment horizon, liquidity needs)
- Market conditions (volatility indices, sector correlations)
- Regulatory thresholds (SEC Reg BI best interest, FINRA suitability obligations)

The adapter maps InferTheta's tri-state decision model (`ALLOW`, `REFUSE`, `ESCALATE`) to CAGE's [`NormativeProvider`](../../gateway/governance/normative_provider.py) seam contract, ensuring:
- **Cryptographic verifiability** via out-of-band JWKS and Ed25519 signatures
- **Fail-closed enforcement** on network failures, schema violations, and unknown signing keys
- **Tamper-evident audit chain** for DENY and PAUSE receipts alongside ALLOW approvals

---

## Architecture Position

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Kernel (src/gateway/)                                 │
│  └─ NormativeProvider seam (fetch_baseline, validate_fria)     │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ Layer 3: Integrations (src/integrations/provider_07/)          │
│  ├─ schema.py          ← Wire protocol models (Pydantic v2)    │
│  ├─ adapter.py         ← NormativeProvider implementation       │
│  ├─ jwks_client.py     ← Out-of-band key resolution            │
│  └─ signature.py       ← Ed25519 verification (JCS canonical)  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ HTTPS + Bearer Auth
                         ▼
              ┌──────────────────────┐
              │ InferTheta API       │
              │ (External Service)   │
              └──────────────────────┘
```

**Key Invariants**:
- Layer 1 Kernel **NEVER** imports `provider_07` directly (enforced by Gate G3: [`scripts/check_import_boundaries.py`](../../../scripts/check_import_boundaries.py))
- Generic package naming (`provider_07`) enforces Gate G8 (Vendor Brand Isolation)
- Vendor brand name "InferTheta" appears **only** in this README and [`docs/partners/INFERTHETA_CANONICAL_SCHEMA.md`](../../../docs/partners/INFERTHETA_CANONICAL_SCHEMA.md)

---

## Environment Variables

Configure the adapter via environment variables (injected via Kubernetes ConfigMap or local `.env`):

| Variable | Default | Description | Sensitivity |
|---|---|---|---|
| `PROVIDER_07_ENDPOINT` | `http://localhost:8087` | Base URL for InferTheta API | Public |
| `PROVIDER_07_API_KEY` | *(required)* | Bearer token for authentication | **Secret** |
| `PROVIDER_07_JWKS_URL` | *(required)* | Out-of-band JWKS manifest URL | Public |
| `PROVIDER_07_TIMEOUT_SECONDS` | `5.0` | Request timeout (seconds) | Public |

**Secret Management**:
- `PROVIDER_07_API_KEY` must be stored in a Kubernetes Secret and mounted via `secretKeyRef`
- **Never** hardcode API keys or embed them in configuration files
- Mask credentials in logs: `api_key[:4] + "****"`

**Example Kubernetes Secret**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: provider-07-credentials
  namespace: cage-prod
type: Opaque
stringData:
  api-key: "pk-lf-REDACTED"  # Example format (actual format may differ)
  jwks-url: "https://keys.infertheta.example/v1/jwks.json"
```

**Example Deployment Manifest**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cage-gateway
spec:
  template:
    spec:
      containers:
      - name: gateway
        env:
        - name: PROVIDER_07_ENDPOINT
          value: "https://api.infertheta.example"
        - name: PROVIDER_07_API_KEY
          valueFrom:
            secretKeyRef:
              name: provider-07-credentials
              key: api-key
        - name: PROVIDER_07_JWKS_URL
          valueFrom:
            secretKeyRef:
              name: provider-07-credentials
              key: jwks-url
        - name: PROVIDER_07_TIMEOUT_SECONDS
          value: "5.0"
```

---

## Fail-Closed Behavior Specification

The adapter enforces **strict fail-closed semantics** on all error conditions:

| Failure Mode | HTTP Status | Error Code | `admitted` | Audit Evidence | Rationale |
|---|---|---|---|---|---|
| **Network timeout** | N/A | `HTTP_TIMEOUT` | `False` | Empty response body | Cannot confirm safety → default deny |
| **HTTP 5xx errors** | 500/502/503 | `PROVIDER_ERROR` | `False` | Server error message | Provider instability → fail closed |
| **HTTP 404 on baseline** | 404 | `BASELINE_NOT_FOUND` | `False` | Empty baseline | Cannot validate without normative anchor |
| **Unknown `kid`** | 200 | `INFERTHETA_UNKNOWN_KEY` | `False` | Unresolved key ID | Untrusted signing key → reject |
| **Invalid Ed25519 signature** | 200 | `SIGNATURE_VERIFICATION_FAILED` | `False` | Signature mismatch | Tampered response → reject |
| **Malformed JSON** | 200 | `SCHEMA_VALIDATION_ERROR` | `False` | Parsing error | Cannot parse → cannot trust |
| **Missing `authority_record_id` on `ALLOW`** | 200 | `TOKEN_MINT_FAILED` | `False` | Missing audit token | Authorization without token is invalid |
| **`decision == "REFUSE"`** | 200 | *(none)* | `False` | Full response body | Normative refusal (legitimate deny) |
| **`decision == "ESCALATE"`** | 200 | *(none)* | `False` | Full response body | Deferred to human → block autonomous execution |
| **`decision == "ALLOW"` + valid signature + token** | 200 | *(none)* | `True` | Full response + signature | All safety gates passed |

**Canonical Transform** (from tri-state to binary):
```python
def map_decision_to_admitted(response: InferThetaInferenceResponse) -> bool:
    """
    Map tri-state decision to binary admission flag.
    
    Fail-closed invariant: Only ALLOW with authority_record_id admits the action.
    """
    if response.decision == "ALLOW" and response.authority_record_id:
        return True
    else:
        return False  # REFUSE, ESCALATE, or missing authorization token
```

**Refusals Are Primary Evidence**: `REFUSE` and `ESCALATE` responses enter the tamper-evident audit chain with full cryptographic verification, identical to `ALLOW` approvals. This ensures regulatory auditors can trace *denials* as rigorously as approvals.

---

## Wire Protocol Summary

### Inference Endpoint: `POST /infer`

**Request**: [`InferThetaInferenceRequest`](schema.py)  
**Response**: [`InferThetaInferenceResponse`](schema.py)

**Key Fields**:
- **Input**: `portfolio_vector`, `proposed_trade`, `client_profile`, `market_volatility_index`
- **Output**: `decision` (ALLOW/REFUSE/ESCALATE), `posterior_risk_score`, `marginal_probabilities`, `utility_rankings`
- **Audit**: `authority_record_id` (mandatory for ALLOW), `kid` + `signature` (Ed25519 over JCS canonical body)

### Baseline Endpoint: `GET /baseline/{region}`

**Response**: [`InferThetaBaselineResponse`](schema.py)

**Key Fields**:
- **Output**: `region`, `rules` (normative thresholds), `baseline_hash` (SHA-256), `issued_at` (UNIX timestamp)

---

## Cryptographic Verification Workflow

### 1. Trust Anchor Resolution (Out-of-Band JWKS)

**Invariant**: **Never verify a signature against an embedded public key supplied by the signed document.**

**Protocol**:
1. Extract `kid` from `InferThetaInferenceResponse.kid`
2. Fetch JWKS manifest from `PROVIDER_07_JWKS_URL` (cached with TTL)
3. Resolve public key by `kid`:
   - **If `kid` unknown**: Fail with `INFERTHETA_UNKNOWN_KEY`, set `admitted=False`
   - **If `kid` found**: Extract Ed25519 public key (`x` parameter from JWK)

**Example JWKS Response**:
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

### 2. Signature Verification

1. **Canonical Serialization**: Serialize the response body **excluding** the `signature` field using **JCS (RFC 8785)** to produce a deterministic byte sequence.
2. **Verify Ed25519 Signature**:
   ```python
   from cryptography.hazmat.primitives.asymmetric import ed25519

   public_key.verify(signature_bytes, canonical_body_bytes)
   ```
3. **On Failure**: Fail with `SIGNATURE_VERIFICATION_FAILED`, set `admitted=False`

### 3. Resolution vs. Verification Status

**Critical Distinction**:
- **Resolution Status**: Whether the HTTP request succeeded (200 OK) and returned parseable JSON
- **Verification Status**: Whether the cryptographic signature is valid

**A successful fetch proves receipt exists, NOT signature validity.**  
Always return `verification_status=UNVERIFIED` until Ed25519 verification succeeds, then upgrade to `VERIFIED`.

---

## Bayesian Posterior Interpretation

### Risk Score Aggregation

The `posterior_risk_score` is a **weighted sum** of marginal probabilities for adverse events:

```python
posterior_risk_score = (
    0.5 * marginal_probabilities["drawdown_gt_15pct"]
    + 0.3 * marginal_probabilities["volatility_spike"]
    + 0.2 * marginal_probabilities["liquidity_stress"]
)
```

**Threshold Bands** (configured per region in baseline):
- `< 0.20`: Low risk → likely `ALLOW`
- `0.20–0.40`: Moderate risk → may `ESCALATE`
- `≥ 0.40`: High risk → likely `REFUSE`

### Utility Rankings

Expected utility scores guide **counterfactual recommendations**:
- If `action="rebalance_to_proposed"` has highest utility → `ALLOW`
- If `action="defer_to_human"` dominates → `ESCALATE`
- If `action="reject_trade"` dominates → `REFUSE`

---

## Testing Strategy

### Unit Tests (Hermetic, `pytest.mark.unit + pytest.mark.local`)
- Schema validation: Valid/invalid request/response payloads
- Tri-state decision mapping: `ALLOW`/`REFUSE`/`ESCALATE` → `admitted` bool
- Fail-closed error handling: Missing `authority_record_id`, unknown `kid`, malformed JSON

### Integration Tests (`pytest.mark.integration`)
- Mock HTTP server returning synthetic InferTheta responses
- JWKS resolution and Ed25519 signature verification
- Timeout and retry behavior

### Live External Tests (`pytest.mark.live_external`, CI-gated)
- Real InferTheta staging environment (requires `PROVIDER_07_API_KEY`)
- End-to-end baseline fetch, inference request, signature verification

---

## File Structure

```
src/integrations/provider_07/
├── README.md                   ← This file
├── __init__.py                 ← Package exports
├── schema.py                   ← Pydantic v2 wire protocol models
├── adapter.py                  ← NormativeProvider implementation (Phase 2)
├── jwks_client.py              ← Out-of-band JWKS fetcher (Phase 2)
└── signature.py                ← Ed25519 verification (Phase 2)
```

---

## References

- **Canonical Schema**: [`docs/partners/INFERTHETA_CANONICAL_SCHEMA.md`](../../../docs/partners/INFERTHETA_CANONICAL_SCHEMA.md)
- **NormativeProvider Seam**: [`src/gateway/governance/normative_provider.py`](../../gateway/governance/normative_provider.py)
- **Adapter Architecture**: [`docs/technical-report/11-ADAPTER-ARCHITECTURE.md`](../../../docs/technical-report/11-ADAPTER-ARCHITECTURE.md)
- **Import Boundary Enforcement**: [`scripts/check_import_boundaries.py`](../../../scripts/check_import_boundaries.py)
- **Vendor Brand Isolation**: [`scripts/check_vendor_brands.py`](../../../scripts/check_vendor_brands.py)
- **RFC 8785**: [JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- **SEC Reg BI**: [Regulation Best Interest](https://www.sec.gov/rules/final/2019/34-86031.pdf)
- **FINRA Rule 2111**: [Suitability](https://www.finra.org/rules-guidance/rulebooks/finra-rules/2111)

---

**Phase 1 Status**: ✅ Complete — Schema Definition & Documentation  
**Next Phase**: Phase 2 — Adapter Implementation ([`adapter.py`](adapter.py), [`jwks_client.py`](jwks_client.py), [`signature.py`](signature.py))
