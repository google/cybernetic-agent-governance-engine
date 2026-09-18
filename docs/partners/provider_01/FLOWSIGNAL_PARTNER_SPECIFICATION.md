# FlowSignal (provider_01) Partner Integration Specification & Runbook

**Document Version:** 1.0  
**Status:** CANONICAL SPECIFICATION — PHASE 3 PRE-STAGING & HOSTILE VALIDATION  
**Integration Slot:** `provider_01` (External Normative Authority Provider)  
**Last Updated:** 2026-09-16  

---

## Executive Summary

This document is the **single canonical specification** governing the integration between Google CAGE and FlowSignal (provider_01). It defines:
1. The **37-field wire protocol** for runtime authority determination (`POST /cage/validate`).
2. The **Cloud Run Domain Restricted Sharing (DRS) dual-header authentication protocol** (`X-Serverless-Authorization` + `Authorization: Bearer`).
3. The **composition safety invariant** and decision-mapping semantics.
4. The **7-vector hostile validation test plan**, smoke test sequence, and production gating criteria.

This specification supersedes all prior preliminary drafts, correspondence memos, and fragmented test plans.

---

## §1 — Composition Safety Invariant

The core security invariant governing the CAGE $\leftrightarrow$ FlowSignal boundary is:

$$\mathbf{EXECUTED} \implies \mathbf{CAGE\_GOVERNANCE\_ALLOW} \land \mathbf{FLOWSIGNAL\_RUNTIME\_AUTHORITY\_ALLOW}$$

No governed action can reach downstream actuators without dual-key authorization:
1. **CAGE Internal Governance:** Symbolic governor, OPA policy evaluation, and Control Barrier Function (CBF) engine must all yield `ALLOW`.
2. **FlowSignal Runtime Authority:** External normative validation must explicitly yield `ALLOW`.

On FlowSignal `ALLOW`, CAGE mints a short-TTL (60s), single-use, KMS-signed **ConsequenceToken** (RFC 7515 JWS). Downstream actuators atomically consume this token from a distributed Redis store (`SET NX EX 90`) before triggering physical side effects.

---

## §2 — Canonical Wire Contract (`POST /cage/validate`)

### 2.1 Endpoint Specification
* **HTTP Method:** `POST`
* **Path:** `/cage/validate` (configured via `CAGE_NORMATIVE_VALIDATE_PATH`, defaulting to `/cage/validate`)
* **Content-Type:** `application/json`

### 2.2 Complete 37-Field Request Schema (`CageAuthorityDetermineRequest`)
All requests submitted by CAGE to FlowSignal strictly conform to the 37-field model:

```python
class CageAuthorityDetermineRequest(BaseModel):
    """CAGE v3-facing request model (37 fields: 35 required + 2 optional)."""

    # Core Request Identifiers (3 fields)
    approval_id: str
    platform: str  # Always "GOOGLE-CAGE-REFERENCE"
    execution_id: str
    
    # Scenario & Action Context (4 fields)
    scenario_id: str  # Bound from CAGE envelope thread_id (correlation metadata)
    action: str
    target: str
    context: str  # Descriptive metadata: symbol / purpose (audit memo only)
    
    # Actor Identity & Authorization (5 fields)
    actor_id: str
    actor_type: str  # Default: "autonomous_agent"
    actor_role: str
    actor_authenticated: bool  # Default: True (pre-authenticated by CAGE)
    kya_status: str  # Default: "VERIFIED"
    
    # Principal (Institutional Context) (2 fields)
    principal_id: str
    principal_name: str
    
    # Mandate Boundary & Limits (7 fields)
    mandate_id: str
    mandate_status: str  # Default: "ACTIVE"
    mandate_max_amount: float
    mandate_currency: str  # ISO 4217 (e.g., "USD")
    permitted_source_accounts: list[str]
    permitted_counterparty_class: str
    mandate_valid_until: datetime  # ISO 8601
    
    # Proposed Transaction Details (5 fields)
    magnitude: float  # Authority-bearing numeric threshold
    currency: str  # Authority-bearing ISO 4217 currency code (e.g., "USD", "GBP")
    source_account: str
    beneficiary: str
    purpose: str
    
    # Runtime State & Risk Context (4 fields)
    counterparty_status: str
    account_status: str
    risk_state: str
    approval_required: bool
    
    # Mutable Evidence Freshness (4 fields)
    screening_status: str
    screening_captured_at: datetime  # ISO 8601
    screening_max_age_seconds: int
    screening_source: str
    
    # Execution Timing (1 field)
    requested_execution_time: datetime  # ISO 8601
    
    # Optional Fields (2 fields)
    authority_resolution_path: str | None = None
    evidence_references: list[dict[str, Any]] = Field(default_factory=list)
```

### 2.3 Field Semantics & Boundary Invariants
1. **`magnitude` and `currency` are the Authority-Bearing Inputs:**
   - Determination logic must evaluate the numeric `magnitude` combined with the distinct `currency` field against policy rules.
   - `currency` is transmitted as an independent ISO 4217 string (e.g. `"USD"`, `"GBP"`), never concatenated into strings.
2. **`context` is Audit Correlation Metadata:**
   - `context` carries human-readable annotations (e.g., `"Invoice 78431"` or `"Large equity purchase: AAPL 500 shares"`).
   - Equivalent to a memo field on a bank wire: it provides business context for human operators and audit logs, but **must not algorithmically influence ALLOW/REFUSE/ESCALATE decisions**.
3. **`scenario_id` (`thread_id`) is Correlation Metadata:**
   - CAGE maps its internal governance `thread_id` to `scenario_id` on the wire.
   - Used for audit stitching and evidence chain anchoring (`/evidence-chain/{thread_id}`). It does not alter policy bounds.
4. **GovernanceEnvelope v3.0 Sealing is Internal to CAGE:**
   - CAGE internally seals envelopes using RFC 8785 (JCS) SHA-256 digests over `SubjectMetadata`.
   - FlowSignal communicates via standard JSON REST and **does not unpack or verify CAGE GovernanceEnvelopes in Phase 3**.

---

## §3 — Authentication, Transport & Cloud Run Ingress

### 3.1 Cloud Run Domain Restricted Sharing (DRS)
When FlowSignal is hosted on Google Cloud Run within an enterprise organization with Domain Restricted Sharing (`constraints/iam.allowedPolicyMemberDomains`), unauthenticated (`allUsers`) invocation is prohibited. 

To bridge the Google Cloud IAM perimeter without conflicting with FlowSignal's application API key, CAGE and FlowSignal operate a **Dual-Header Ingress Protocol**:

```
┌────────────────────────────────────────────────────────┐
│ CAGE Gateway (provider_01)                             │
│                                                        │
│ Headers:                                               │
│   X-Serverless-Authorization: Bearer <Google ID Token> │
│   Authorization: Bearer <FlowSignal API Key>           │
│   Content-Type: application/json                       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Google Cloud Run Infrastructure Ingress                │
│                                                        │
│ 1. Intercepts X-Serverless-Authorization               │
│ 2. Validates Google OIDC ID token signature & audience │
│ 3. Asserts caller holds 'roles/run.invoker' IAM role   │
│ 4. Forwards request with standard Authorization intact │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ FlowSignal Application Container                       │
│                                                        │
│ 1. Receives standard 'Authorization: Bearer <API-Key>' │
│ 2. Validates application credentials                   │
│ 3. Processes POST /cage/validate determination         │
└────────────────────────────────────────────────────────┘
```

### 3.2 Header Specifications

| Header | Value | Purpose | Consumer |
|---|---|---|---|
| `X-Serverless-Authorization` | `Bearer <Google-OIDC-Token>` | Cloud Run IAM Invocation Clearance | Google Cloud Run Proxy |
| `Authorization` | `Bearer <FLOWSIGNAL_API_KEY>` | Application-level credential verification | FlowSignal App Container |
| `Content-Type` | `application/json` | Request payload format | FlowSignal App Container |

### 3.3 Google Cloud IAM Configuration Runbook

FlowSignal GCP administrators grant invocation permission to CAGE's testing identity:

```bash
# Grant Cloud Run invoker role to CAGE service account
gcloud run services add-iam-policy-binding <FLOWSIGNAL_SERVICE_NAME> \
  --member="serviceAccount:cage-partner-testing@<cage-project-id>.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region=<REGION>
```

In CAGE local and testing environments, the Google ID token is supplied via:
```bash
export CAGE_NORMATIVE_ENDPOINT="https://<flowsignal-service-url>"
export CAGE_NORMATIVE_API_KEY_SECRET="<flowsignal-application-key>"
export CAGE_NORMATIVE_GCP_ID_TOKEN=$(gcloud auth print-identity-token --audiences="https://<flowsignal-service-url>")
```

---

## §4 — Decision Mapping Rules

FlowSignal returns a tri-state determination in `POST /cage/validate`:

```json
{
  "decision": "ALLOW | REFUSE | ESCALATE",
  "authority_record_id": "rec-12345",
  "authority_state_version": 1,
  "message": "Optional decision explanation"
}
```

### 4.1 Tri-State Mapping Table

| FlowSignal `decision` | CAGE `ValidationResult` | CAGE Internal Action | Consequence Enforcement |
|---|---|---|---|
| **`ALLOW`** | `admitted = True` | Mint `ConsequenceToken` finding | Token signed via KMS; downstream actuator executes IFF unconsumed in Redis. |
| **`REFUSE`** | `admitted = False` | Emit `FLOWSIGNAL_REFUSE` finding | Hard denial. Zero ConsequenceTokens minted; execution aborted. Refusal logged to audit chain. |
| **`ESCALATE`** | `admitted = False` | Emit `EXTERNAL_HOLD` finding (`needs_human_review = True`) | Action suspended. Parked in `DeferQueue` with 300s TTL. Autonomous execution strictly blocked ($\neg\text{EXECUTED}$). |
| **Missing / Malformed** | `admitted = False` | Emit `PARSE_ERROR` / `cage.endpoint_error` | **Fail-Closed.** Missing `decision` key or unrecognized string immediately aborts with `severity="blocked"`. |

### 4.2 Response Preservations
* **Mandatory Response Fields:** `decision`
* **Optional ALLOW Response Fields:** `authority_record_id`, `authority_state_version`
* **Optional REFUSE / ESCALATE Response Fields:** `message`
* **FlowSignal does NOT return `thread_id`, `scenario_id`, or `actor_id`:** CAGE mints its `ConsequenceToken` using its own local pre-request context (`action_payload`).

---

## §5 — Hostile Validation Test Plan

Hostile testing deliberately attacks the composition boundary across 7 vectors to prove fail-closed guarantees.

### Vector 1: Timeout & Network Partition
* **1.1 FlowSignal Timeout (> 5.0s):**
  * FlowSignal delays response $> 5.0\text{s}$.
  * CAGE catches `httpx.TimeoutException`, emits `ENDPOINT_ERROR` (`severity="blocked"`), fails closed.
* **1.2 Network Partition:**
  * Egress blocked via firewall or network failure.
  * CAGE catches `httpx.RequestError`, fails closed.

### Vector 2: Malformed & Schema Invariance
* **2.1 Missing `decision` field:** Response lacks `decision` key $\to$ emits `cage.endpoint_error`, fails closed.
* **2.2 Unrecognized Enum:** Response returns `{"decision": "MAYBE"}` $\to$ `ValueError` caught $\to$ emits `FINDING_CODE_PARSE_ERROR`, fails closed.
* **2.3 Non-JSON Response:** HTML/502 Bad Gateway $\to$ JSON decode error caught $\to$ emits `ENDPOINT_ERROR`, fails closed.

### Vector 3: Replay Protection
* **3.1 Immediate Replay (< 1s):** Resubmitting identical `authority_record_id` fails Redis `SET NX` $\to$ emits `ALREADY_CONSUMED`, execution blocked.
* **3.2 Delayed Replay (< 90s):** Within the 90s TTL window, Redis retains the consumption key $\to$ second execution blocked.

### Vector 4: Stale Authority & TOCTOU
* **4.1 Token Expiry (> 60s):** ConsequenceToken expires after 60 seconds. Actuator verifies `now <= exp` $\to$ raises `TOKEN_INVALID`, blocks execution.
* **4.2 Clock Skew Attack:** Token with `iat` $> \text{now} + 5\text{s}$ rejected immediately.
* **4.3 Parameter Tampering:** Modifying any payload field (e.g. `amount: 100` $\to$ `amount: 1000`) changes RFC 8785 JCS SHA-256 digest $\to$ token `act` claim mismatch $\to$ emits `ACTION_BINDING_MISMATCH`, blocks execution.

### Vector 5: Fencing & Monotonic Epoch Integrity
* **5.1 Evidence Stream Fence:** Evidence hashes appended to durable storage (`/evidence-chain/{thread_id}`); cold store is append-only and immutable across pod restarts.
* **5.2 Monotonic Epochs:** Redis consensus epoch counters increment monotonically (`INCR`) and never roll back.

### Vector 6: Non-Bypassability & Provider Binding
* **6.1 Direct Execution Bypass:** Calling actuators without an unconsumed KMS-signed `ConsequenceToken` seal raises `SymbolicGovernorViolation`.
* **6.2 Provider Outage Fallback Prevention:** If FlowSignal fails or returns 500s, CAGE **does not fall back to static admission**. System fails closed.

### Vector 7: ESCALATE Boundary & Human-in-the-Loop
* **7.1 Autonomous Scope:** `ESCALATE` returns `needs_human_review=True`, parks thread in `DeferQueue` (300s TTL). Asserts $\neg\text{EXECUTED}$.
* **7.2 Dual-Control Step-Up:** If configured for human review, releasing hold requires two distinct supervisor approvals ($Q=2$).

---

## §6 — Verification Runbook & Production Gates

### 6.1 Baseline Smoke Test Sequence
Before running hostile vectors, execute the baseline health suite:
```bash
# 1. Baseline fetch
curl -H "Authorization: Bearer $CAGE_NORMATIVE_API_KEY_SECRET" \
     -H "X-Serverless-Authorization: Bearer $CAGE_NORMATIVE_GCP_ID_TOKEN" \
     $CAGE_NORMATIVE_ENDPOINT/legal-baseline/US_FED

# 2. Hermetic unit tests
uv run pytest tests/test_provider_01.py -v

# 3. Phase 3 37-field schema tests
uv run pytest tests/test_provider_01_phase3_schema.py -v

# 4. Live partner integration harness
uv run pytest tests/test_provider_01_live.py -v
```

### 6.2 Quantitative Production Gates

| Gate Metric | Requirement | Enforcement |
|---|---|---|
| **Fail-Closed Rate (Vectors 1-2)** | **100%** | Zero executions on timeout, network failure, or malformed JSON |
| **Replay Block Rate (Vector 3)** | **100%** | Zero duplicate executions within 90s Redis window |
| **TOCTOU Protection (Vector 4)** | **100%** | Zero executions on mutated parameters or expired tokens |
| **Bypass Prevention (Vector 6)** | **100%** | Zero executions without valid KMS-signed ConsequenceToken |
| **ESCALATE Parking Rate (Vector 7)** | **100%** | 100% of ESCALATE verdicts parked; 0% autonomous executions |
| **False Positive Rate** | **0%** | Valid ALLOW determinations execute without spurious blocks |

---
**End of Specification**

