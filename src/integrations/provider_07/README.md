# provider_07 — Bayesian Causal Suitability Adapter (Layer 3)

**Adapter Type**: Normative Gating Oracle (`NormativeProvider`)  
**Inference Model**: Junction Tree / Belief Propagation  
**Regulatory Scope**: SEC Reg BI, FINRA Rule 2111, EU AI Act Art. 27  
**Architecture Layer**: Layer 3 (Integrations & Rails)  
**Verification Status**: Hermetically verified (`tests/integrations/provider_07/test_provider_07_adapter.py`); live CI harness unprovisioned (see [`docs/partners/README.md`](../../../docs/partners/README.md#live-verification-status))

---

## Overview

The `provider_07` adapter integrates a **Bayesian belief network inference service** (InferTheta) as a normative gating oracle for high-stakes financial advisory scenarios. The service executes **junction tree algorithms** over causal graphs encoding:
- Client suitability constraints (risk tolerance, investment horizon, liquidity needs)
- Market conditions (volatility indices, sector correlations)
- Regulatory thresholds (SEC Reg BI best interest, FINRA suitability obligations)

The adapter maps InferTheta's tri-state decision model (`ALLOW`, `REFUSE`, `ESCALATE`) to CAGE's [`NormativeProvider`](../../gateway/governance/seams/normative.py) seam contract (registered in [`normative_provider.py`](../../gateway/governance/normative_provider.py) as `"provider_07"` / alias `"p07"`), ensuring:
- **Cryptographic verifiability** via out-of-band JWKS (`Ed25519KeyManifestClient`) and Ed25519 signatures over RFC 8785 JCS
- **Fail-closed enforcement** on HTTP/parse failures, JWKS fetch failures, unknown signing keys, invalid signatures, and invalid `authority_record_id` state
- **Primary refusal evidence** — `REFUSE` and `ESCALATE` decisions yield `admitted=False` with structured findings (`PROVIDER_07_UNSUITABLE` / `PROVIDER_07_ESCALATE`) alongside verified `ALLOW` approvals

---

## Architecture Position

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Kernel (src/gateway/)                                         │
│  ├─ seams/normative.py        ← NormativeProvider Protocol             │
│  └─ normative_provider.py     ← Factory ("provider_07" / "p07")        │
└───────────────────────────────┬────────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────────┐
│ Layer 3: Integrations (src/integrations/)                              │
│  ├─ provider_07/schema.py     ← Wire protocol models (Pydantic v2)     │
│  ├─ provider_07/adapter.py    ← Provider07NormativeProvider            │
│  ├─ trust/key_manifest.py     ← Shared Ed25519KeyManifestClient        │
│  └─ provider_07/signature.py  ← Ed25519 verification (JCS canonical)   │
└───────────────────────────────┬────────────────────────────────────────┘
                                │
                                │ HTTPS + Bearer Auth
                                ▼
                     ┌──────────────────────┐
                     │ InferTheta API       │
                     │ (External Service)   │
                     └──────────────────────┘
```

**Key Invariants**:
- Layer 1 Kernel **never** imports `provider_07` at module scope (permitted only via function-scoped factory lazy import in [`normative_provider.py`](../../gateway/governance/normative_provider.py), enforced by Gate G3 [`scripts/check_import_boundaries.py`](../../../scripts/check_import_boundaries.py))
- Package paths, Python identifiers, finding codes, and environment variable names use the anonymized `provider_07` namespace per Gate G8 ([`scripts/check_vendor_brands.py`](../../../scripts/check_vendor_brands.py))
- External wire-protocol constants containing the partner prefix (such as the staging key ID `"infertheta-provider07-2026-01"`, authority-record prefix `"infertheta-ar-"`, and signed Step 2 vector ID `"infertheta-ar-09b99a87-66ff-4791-9f31-f453841d2e8a"`) are explicitly registered in `LAYER3_WIRE_PROTOCOL_PROVENANCE` in [`scripts/check_vendor_brands.py`](../../../scripts/check_vendor_brands.py); vendor brand names belong strictly in prose/docstrings and never in non-wire identifiers or literals

---

## Environment Variables

Configure `Provider07NormativeProvider.from_env()` via environment variables:

| Variable | Default | Description | Sensitivity |
|---|---|---|---|
| `PROVIDER_07_ENDPOINT` | `http://localhost:8087` | Base URL for InferTheta API (partner-documented endpoints: prod `https://infertheta-cage-prod.onrender.com`, staging `https://infertheta-cage-staging.onrender.com`) | Public |
| `PROVIDER_07_API_KEY` | `""` *(empty)* | Bearer token sent as `Authorization: Bearer <token>`. Optional in `from_env()` / constructor (for local unauthenticated `/health` checks or fail-closed auth tests), **required** for authenticated provider endpoints (`/baseline/{region}`, `/infer`, `/evidence-chain/{thread_id}`) which otherwise return HTTP `401` | **Secret** |
| `PROVIDER_07_JWKS_URL` | `{endpoint}/.well-known/jwks.json` | Out-of-band JWKS manifest URL passed to `Ed25519KeyManifestClient` (restricted to `http` / `https` schemes) | Public |
| `PROVIDER_07_TIMEOUT_SECONDS` | `5.0` | HTTP request and JWKS fetch timeout in seconds | Public |
| `PROVIDER_07_ALLOW_STEP1_UNSIGNED` | `false` | Dev/testing only (`"true"`, `"1"`, `"yes"`). Skips Ed25519 verification only when `signature == "unsigned-placeholder"`. Raises `RuntimeError` during `__init__()` whenever `is_enforcing()` is true | Internal |
| `PROVIDER_07_EXPECTED_KID` | *(test harness only)* | Read by [`tests/integrations/provider_07/test_provider_07_live.py`](../../../tests/integrations/provider_07/test_provider_07_live.py), not by `Provider07NormativeProvider.from_env()`. Overrides expected `kid` (defaults to `infertheta-provider07-2026-01` if `"staging"` is in `PROVIDER_07_ENDPOINT`, else `infertheta-provider07-prod-2026-01`) | Public |

**Secret Management (No GKE Wiring Committed)**:
- **Current repo state:** No `provider-07-credentials` Kubernetes `Secret` or Terraform env wiring exists under [`infra/`](../../../infra/). `PROVIDER_07_*` variables are not provisioned in GitHub Actions or GKE staging at this time.
- If a deployer wires `provider_07` into Kubernetes, `PROVIDER_07_API_KEY` must be stored in Secret Manager / Kubernetes `Secret` and mounted via `secretKeyRef` (never plain `value:` literals), and credentials must be masked in logs (`api_key[:4] + "****"`).

**Illustrative Kubernetes `secretKeyRef` Pattern (not provisioned in `infra/`):**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: provider-07-credentials
type: Opaque
stringData:
  endpoint: "https://infertheta-cage-prod.onrender.com"
  jwks-url: "https://infertheta-cage-prod.onrender.com/.well-known/jwks.json"
  api-key: "<INFERTHETA_BEARER_TOKEN>"
```

```yaml
env:
- name: PROVIDER_07_ENDPOINT
  valueFrom:
    secretKeyRef:
      name: provider-07-credentials
      key: endpoint
      optional: true
- name: PROVIDER_07_API_KEY
  valueFrom:
    secretKeyRef:
      name: provider-07-credentials
      key: api-key
      optional: true
- name: PROVIDER_07_JWKS_URL
  valueFrom:
    secretKeyRef:
      name: provider-07-credentials
      key: jwks-url
      optional: true
- name: PROVIDER_07_TIMEOUT_SECONDS
  value: "5.0"
```

---

## Fail-Closed Behavior Specification

None of `fetch_baseline()`, `validate_fria()`, or `submit_evidence()` raise runtime exceptions on network, parsing, or cryptographic errors; every failure is converted into a fail-closed return object ([`src/gateway/governance/seams/normative.py`](../../gateway/governance/seams/normative.py)).

### `validate_fria(payload)` → `ValidationResult`

| Condition / Failure Mode | Finding Code (`findings[0]["code"]`) | `admitted` | `status` / Notes |
|---|---|---|---|
| `httpx.HTTPError` (network timeout, connection failure, HTTP 4xx/5xx from `/infer`) | `PROVIDER_07_HTTP_ERROR` | `False` | `status: "error"` |
| Request/response schema error or unexpected exception during `/infer` call | `PROVIDER_07_PARSE_ERROR` | `False` | `status: "error"` |
| Exception fetching or parsing out-of-band JWKS manifest | `PROVIDER_07_JWKS_ERROR` | `False` | `status: "error"` |
| `kid` missing from JWKS manifest (`get_key(kid)` returns `None`) | `PROVIDER_07_UNKNOWN_KEY` | `False` | `status: "fail"` |
| Ed25519 JCS signature invalid (`verify_inference_signature()` returns `False`) | `PROVIDER_07_SIGNATURE_INVALID` | `False` | `status: "fail"` |
| `decision == "ALLOW"` with missing/empty `authority_record_id` | `TOKEN_MINT_FAILED` | `False` | `status: "fail"` |
| `decision in ("REFUSE", "ESCALATE")` with non-`None` `authority_record_id` | `TOKEN_MINT_FAILED` | `False` | `status: "fail"`; `ValidationResult.error` set |
| `decision == "ALLOW"` + valid signature (or dev-only placeholder when `!is_enforcing()`) + non-empty `authority_record_id` | `PROVIDER_07_ALLOW` | `True` | `status: "pass"`; includes `authority_record_id`, `posterior_risk_score`, `marginal_probabilities` |
| `decision == "REFUSE"` (`authority_record_id is None`) | `PROVIDER_07_UNSUITABLE` | `False` | `status: "fail"`; includes `posterior_risk_score` |
| `decision == "ESCALATE"` (`authority_record_id is None`) | `PROVIDER_07_ESCALATE` | `False` | `status: "fail"`, `needs_human_review: True`; includes `posterior_risk_score` |
| Unexpected `decision` value | `PROVIDER_07_UNKNOWN_DECISION` | `False` | `status: "error"` |

Decision admission is evaluated inline inside [`Provider07NormativeProvider.validate_fria()`](adapter.py): only an explicit `"ALLOW"` with verified signature and non-empty `authority_record_id` yields `ValidationResult(admitted=True, ...)`.

### `fetch_baseline(region)` → `NormativeBaseline` & `submit_evidence(thread_id, evidence_hash)` → `EvidenceSeal`

- **`fetch_baseline(region)`**: On any `httpx.HTTPError` (including HTTP `404` on unpopulated/reserved regions `EU_ECB` and `APAC_MAS`, timeouts, or `401`/`5xx`) or parse error, returns `NormativeBaseline(region=region, profile={}, error=<message>)` (`is_valid == False`).
- **`submit_evidence(thread_id, evidence_hash)`**: On any `httpx.HTTPError`, echoed `thread_id` mismatch (`ValueError`), or timestamp/schema parse error, returns `EvidenceSeal(thread_id=thread_id, error=<message>)` (`seal_hash == ""`).

---

## Wire Protocol Summary

### Inference Endpoint: `POST /infer`

**Request**: [`Provider07InferenceRequest`](schema.py)  
**Response**: [`Provider07InferenceResponse`](schema.py)

- **Input**: `scenario_id`, `action`, `target`, `actor_id`, `portfolio_vector`, `proposed_trade`, `client_profile`, `market_volatility_index`, `context`
- **Output**: `decision` (`ALLOW` / `REFUSE` / `ESCALATE`), `confidence_score`, `posterior_risk_score`, `marginal_probabilities`, `utility_rankings`, `findings`
- **Cryptographic & Token Fields**: `authority_record_id` (non-empty for `ALLOW`, e.g. prefix `infertheta-ar-`; `None` for `REFUSE` / `ESCALATE`), `kid`, `signature` (base64url Ed25519 over JCS canonical body excluding `"signature"`)

### Baseline Endpoint: `GET /baseline/{region}`

**Response**: [`Provider07BaselineResponse`](schema.py)

- **Output**: `region`, `rules` (normative thresholds), content-addressed `baseline_hash` (`sha256:...` aligned with HTTP `ETag`), `issued_at` (UNIX timestamp)
- **Regional Semantics**: Documented with `US_FED` populated; reserved identifiers such as `EU_ECB` and `APAC_MAS` fail closed when returning HTTP `404` (`NormativeBaseline(..., error=...)`), never falling back to `US_FED`.

### Evidence Chain Endpoint: `POST /evidence-chain/{thread_id}`

**Response**: [`Provider07EvidenceResponse`](schema.py)

- **Input**: `{"evidence_hash": "sha256:..."}` with optional `Authorization: Bearer <api_key>` header (required by live authenticated endpoints)
- **Output**: `thread_id` (must match submitted `thread_id`), `seal_hash`, `timestamp` (ISO-8601 UTC string or UNIX epoch numeric timestamp)

---

## Cryptographic Verification Workflow

### 1. Trust Anchor Resolution (Out-of-Band JWKS)

**Invariant**: Never verify a signature against an embedded public key supplied by the signed document.

1. Extract `kid` from `Provider07InferenceResponse.kid`.
2. Resolve the Ed25519 public key via [`Ed25519KeyManifestClient`](../trust/key_manifest.py) from `PROVIDER_07_JWKS_URL` (HTTP/HTTPS only, cached with 3600s TTL, performing at most one warm-cache refresh on an unknown `kid` to handle key rotation).
3. If JWKS fetch fails → `ValidationResult(admitted=False)` with `PROVIDER_07_JWKS_ERROR`.
4. If `kid` is still absent (`None`) → `ValidationResult(admitted=False)` with `PROVIDER_07_UNKNOWN_KEY`.

**Example JWKS Response (staging key ID)**:
```json
{
  "keys": [
    {
      "kid": "infertheta-provider07-2026-01",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url_encoded_32_byte_public_key>"
    }
  ]
}
```

### 2. Signature Verification

In [`signature.py`](signature.py) (`verify_inference_signature()`):
1. Remove the `"signature"` field from the response dict and canonicalize via [`jcs_canonicalize_plan()`](../../gateway/governance/jcs_canonicalizer.py) (RFC 8785 JCS).
2. Base64url-decode `signature` and require an exact 64-byte Ed25519 signature.
3. Verify using `public_key.verify(signature_bytes, canonical_bytes)` (`InvalidSignature` or decode errors return `False`).
4. On `False`, `validate_fria()` returns `ValidationResult(admitted=False)` with finding code `PROVIDER_07_SIGNATURE_INVALID`.

An HTTP `200 OK` parseable response proves only transport receipt, not admission: `validate_fria()` admits only after key resolution, Ed25519 verification, and `authority_record_id` validation all succeed.

---

## Bayesian Posterior Interpretation

- **Risk Score Aggregation**:
  `posterior_risk_score = 0.5 * marginal_probabilities["drawdown_gt_15pct"] + 0.3 * marginal_probabilities["volatility_spike"] + 0.2 * marginal_probabilities["liquidity_stress"]`
- **Documented Threshold Bands**: `< 0.20` (`ALLOW`), `0.20–0.40` (`ESCALATE`), `>= 0.40` (`REFUSE`).
- **Utility Rankings**: `rebalance_to_proposed` (`ALLOW`), `defer_to_human` (`ESCALATE`), `reject_trade` (`REFUSE`).

---

## Testing Strategy & Current Coverage

### Unit Tests (`pytest.mark.unit`, `pytest.mark.local`, `pytest.mark.partner`)
Located in [`tests/integrations/provider_07/test_provider_07_adapter.py`](../../../tests/integrations/provider_07/test_provider_07_adapter.py) (uses mocked `httpx.AsyncClient` and test keypairs; there is no separate `pytest.mark.integration` suite for `provider_07`):
- Protocol compliance against the 3-endpoint `NormativeProvider` seam
- Schema validation and `from_env()` / `allow_step1_unsigned` posture enforcement
- Out-of-band JWKS resolution, caching, rotation refresh, and unknown-`kid` fail-closed tests via `Ed25519KeyManifestClient`
- RFC 8785 JCS + Ed25519 signature verification and tampering rejection (including Step 2 signed staging vectors for `kid = "infertheta-provider07-2026-01"` and `authority_record_id = "infertheta-ar-09b99a87-66ff-4791-9f31-f453841d2e8a"`)
- Tri-state decision mapping (`ALLOW` with/without `authority_record_id`, `REFUSE`, `ESCALATE`, invalid authority token on `REFUSE`/`ESCALATE`) and fail-closed HTTP/parse/JWKS error codes

### Live External Tests (`pytest.mark.partner_integration`, `pytest.mark.live_external`, `pytest.mark.partner`)
Located in [`tests/integrations/provider_07/test_provider_07_live.py`](../../../tests/integrations/provider_07/test_provider_07_live.py):
- Tests `/health`, `GET /baseline/US_FED`, fail-closed `404` on reserved regions (`EU_ECB`, `APAC_MAS`), out-of-band JWKS resolution (`infertheta-provider07-2026-01` / `infertheta-provider07-prod-2026-01`), signed `POST /infer` contract vectors, enforcing `validate_fria`, and `POST /evidence-chain/{thread_id}` persistence/idempotency + unauthenticated `401`.
- **Current Live Status:** `provider_07` is listed under `UNPROVISIONED_PARTNER_REASONS` in [`scripts/partner_harness.py`](../../../scripts/partner_harness.py) because `PROVIDER_07_API_KEY` and sandbox secrets are not provisioned in GitHub Actions. In the last recorded local live check, unauthenticated `/health` and JWKS resolution (`2 of 8` tests) passed while the `6` authenticated tests returned `HTTP 401 Invalid API key.` ([`docs/partners/README.md`](../../../docs/partners/README.md#live-verification-status)).

---

## File Structure

```text
src/integrations/
├── provider_07/
│   ├── README.md        ← This file
│   ├── __init__.py      ← Package exports
│   ├── schema.py        ← Pydantic v2 wire protocol models
│   ├── adapter.py       ← Provider07NormativeProvider (NormativeProvider seam)
│   └── signature.py     ← RFC 8785 JCS + Ed25519 verification
└── trust/
    └── key_manifest.py  ← Shared Ed25519KeyManifestClient (replaced retired jwks_client.py)
```

---

## References

- **Canonical Schema (partner material)**: [`docs/partners/provider_07/INFERTHETA_CANONICAL_SCHEMA.md`](../../../docs/partners/provider_07/INFERTHETA_CANONICAL_SCHEMA.md)
- **Live Partner Verification Status**: [`docs/partners/README.md`](../../../docs/partners/README.md#live-verification-status)
- **NormativeProvider Seam & Factory**: [`seams/normative.py`](../../gateway/governance/seams/normative.py), [`normative_provider.py`](../../gateway/governance/normative_provider.py)
- **Shared Key Manifest Client**: [`trust/key_manifest.py`](../trust/key_manifest.py)
- **Adapter Architecture**: [`EXTENSIBILITY_ARCHITECTURE.md`](../../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md)
- **Import Boundary Enforcement**: [`check_import_boundaries.py`](../../../scripts/check_import_boundaries.py)
- **Vendor Brand Isolation**: [`check_vendor_brands.py`](../../../scripts/check_vendor_brands.py)
- **RFC 8785**: [JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
