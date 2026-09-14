# FlowSignal Response vs. Hostile Test Plan — Alignment Analysis

**Date:** 2026-09-14  
**Status:** COMPLETE ALIGNMENT + EXTENDED COVERAGE

---

## Executive Summary

Lars's proposed response to Graham Brimage is **fully aligned** with the hostile test plan and accurately reflects CAGE's codebase implementation. The test plan provides **extended coverage** beyond Lars's 5 stated vectors, adding detailed execution commands, verification scripts, and a 4-phase runbook.

---

## Point-by-Point Alignment

### 1. Staging Endpoint Setup ✅

| Requirement | Lars's Response | Test Plan Section | Status |
|-------------|-----------------|-------------------|--------|
| Hosting | Publicly routable HTTPS (port 443) | "Test Environment Setup" → Prerequisites #1 | ✅ Exact match |
| TLS | Valid publicly trusted certificate | "Test Environment Setup" → Prerequisites #1 | ✅ Exact match |
| Authentication | `Authorization: Bearer <FLOWSIGNAL_STAGING_API_KEY>` | "Test Environment Setup" → Prerequisites #2 | ✅ Exact match |
| Endpoints | 3 endpoints: `/legal-baseline/{region}`, `/validate/fria`, `/evidence-chain/{thread_id}` | "Test Environment Setup" → Prerequisites #1 | ✅ Exact match |
| CAGE Config | `CAGE_NORMATIVE_ENDPOINT`, `CAGE_NORMATIVE_API_KEY_SECRET`, `CAGE_NORMATIVE_PROVIDER=provider_01` | "Test Environment Setup" → Prerequisites #2 | ✅ Exact match, includes kubectl commands |

**Assessment:** Lars's setup requirements are fully executable via the test plan's Prerequisites section.

---

### 2. Target Invariant ✅

**Lars's Formulation:**
```
EXECUTED ⟹ CAGE_GOVERNANCE_ALLOW ∧ FLOWSIGNAL_RUNTIME_AUTHORITY_ALLOW
```

**Test Plan Formulation:**
```
EXECUTED ⟹ CAGE_GOVERNANCE_ALLOW ∧ FLOWSIGNAL_RUNTIME_AUTHORITY_ALLOW
```

**Assessment:** Character-for-character identical. Test plan Executive Summary states this as the primary attack target.

---

### 3. ESCALATE Boundary Condition ✅

**Lars's Position:**
> "When FlowSignal returns ESCALATE, CAGE maps this to an EXTERNAL_HOLD finding (needs_human_review=True) and parks the request in our Redis-backed DeferQueue with a 300s TTL. For this initial hostile run, let's keep it strictly autonomous so any ESCALATE verdict asserts ¬EXECUTED."

**Test Plan Coverage:**
- **Vector 7: ESCALATE & Human-in-the-Loop Boundary**
  - Test Case 7.1: ESCALATE Verdict Handling
    - Expected: `admitted=False`, `findings=[{"code": "EXTERNAL_HOLD", "needs_human_review": True, "hold_ttl_seconds": 300}]`
    - DeferQueue parking verified
    - ✅ "Action MUST NOT execute autonomously"
  - Test Case 7.2: Dual-Control Step-Up Resolution (optional extension)
    - Invariant precision: `EXECUTED ⟹ (FLOWSIGNAL_ALLOW ∨ DUAL_SUPERVISOR_OVERRIDE)`

**Assessment:** Test plan fully implements Lars's autonomous-only testing scope, with 7.2 as an optional extension.

---

### 4. Hostile Test Vectors — Coverage Matrix

| Vector | Lars's Description | Test Plan Section | Code References | Alignment Status |
|--------|-------------------|-------------------|-----------------|------------------|
| **1. Timeout & Network Partition** | "Simulate latency > 5.0s, CAGE must catch `httpx.TimeoutException`, emit `ENDPOINT_ERROR` (severity="blocked"), fail closed" | Vector 1.1 (FlowSignal timeout), 1.2 (Network partition) | [`provider.py:260`](src/integrations/provider_01/provider.py:260), [`provider.py:318-360`](src/integrations/provider_01/provider.py:318-360) | ✅ **EXACT MATCH** — includes pytest commands + Langfuse verification |
| **2. Malformed & Schema Invariance** | "Missing decision fields, invalid enums, non-JSON payloads → emit `cage.endpoint_error` or `PARSE_ERROR`, fail closed" | Vector 2.1 (Missing decision), 2.2 (Unrecognized value), 2.3 (Non-JSON) | [`provider.py:303-317`](src/integrations/provider_01/provider.py:303-317), [`provider.py:285-301`](src/integrations/provider_01/provider.py:285-301) | ✅ **EXACT MATCH** — 3 test cases vs. Lars's general description |
| **3. Replay Protection** | "Re-submit identical `authority_record_id`, Redis `SET NX EX 90` → second attempt blocked with `ALREADY_CONSUMED`" | Vector 3.1 (Immediate replay), 3.2 (Delayed replay <90s), 3.3 (Post-TTL >90s) | [`consequence_authority_store.py:120-177`](src/gateway/governance/consequence_authority_store.py:120-177) | ✅ **EXACT MATCH** — extends with 3 timing scenarios + Redis verification |
| **4. Stale Authority & TOCTOU** | "(a) Expired token >60s → `TOKEN_INVALID`, (b) Parameter mutation → recompute RFC 8785 JCS SHA-256 digest → `ACTION_BINDING_MISMATCH`" | Vector 4.1 (Token expiry), 4.2 (Clock skew), 4.3 (Parameter mutation) | [`consequence_token.py:294-301`](src/gateway/governance/consequence_token.py:294-301), [`jcs_canonicalizer.py:24`](src/gateway/governance/jcs_canonicalizer.py:24) | ✅ **EXACT MATCH** — adds 4.2 (clock skew attack) as bonus coverage |
| **5. Fencing & Monotonic Epochs** | *(Not mentioned by Lars)* | Vector 5.1 (Evidence stream fence), 5.2 (Consensus epoch rollback) | [`distributed_cbf_model.py`](proof/distributed_cbf_model.py), GCS/S3 cold store | ⚠️ **EXTENDED COVERAGE** — Not in Lars's response, but architecturally sound |
| **6. Non-Bypassability** | "No downstream ExecutionActuator can trigger without valid, unconsumed KMS-signed ConsequenceToken from FlowSignal ALLOW" | Vector 6.1 (Direct execution bypass), 6.2 (Provider fallback), 6.3 (Seal verification) | [`tool_provider.py:105-110`](src/cage_finance/tools/tool_provider.py:105-110), [`execution_actuator.py`](src/gateway/governance/execution_actuator.py) | ✅ **EXACT MATCH** — extends with provider fallback test (6.2) |
| **7. ESCALATE Handling** | "ESCALATE → EXTERNAL_HOLD → DeferQueue parking (300s TTL) → ¬EXECUTED (autonomous scope)" | Vector 7.1 (ESCALATE verdict), 7.2 (Dual-control step-up) | [`provider.py:149-160`](src/integrations/provider_01/provider.py:149-160), [`defer_queue.py:166-231`](src/gateway/governance/defer_queue.py:166-231) | ✅ **EXACT MATCH** — 7.2 is optional extension |

**Summary:**
- Lars mentions **5 vectors** explicitly (1-4, 6)
- Test plan provides **7 vectors** (adds 5, 7)
- All of Lars's assertions map to specific test cases with pytest commands
- Test plan extends coverage with fencing (Vector 5) and explicit ESCALATE testing (Vector 7)

---

## Extended Coverage in Test Plan (Beyond Lars's Response)

### 1. Vector 5: Fencing & Monotonic Epoch Integrity
**Rationale:** While Lars focuses on live request flows, the test plan adds coverage for operational failure scenarios (Redis flush, pod restart) to prove evidence immutability and epoch monotonicity. This aligns with CAGE's safety-critical posture but isn't strictly necessary for initial FlowSignal integration validation.

**Recommendation:** Mark Vector 5 as **optional** for initial hostile run; defer to post-production hardening phase.

### 2. Executable Commands & Verification Scripts
Lars's response states expected behaviors in prose. The test plan translates every assertion into:
- Exact pytest invocations: `uv run pytest tests/test_provider_01.py::test_validate_fria_timeout -v`
- Redis verification: `redis-cli GET "flowsignal:token:replay-test-001"`
- Langfuse trace validation: `uv run python scripts/evaluate_langfuse_traces.py --filter "thread_id=..." --assert "admitted == false"`

**Value:** Zero ambiguity on how to execute and verify each vector.

### 3. Four-Phase Execution Runbook
Test plan adds operational scaffolding:
- **Phase 1:** Environment prep + smoke tests
- **Phase 2:** Sequential hostile vector execution
- **Phase 3:** Result aggregation + analysis
- **Phase 4:** Remediation loop

**Value:** Provides clear cadence for Graham's team to coordinate with CAGE.

### 4. Success Criteria Table
Test plan quantifies gate-to-production thresholds:
- Fail-closed rate: **100%** (Vectors 1-2)
- Replay block rate: **100%** (Vector 3)
- TOCTOU protection: **100%** (Vector 4)
- Bypass attempts blocked: **100%** (Vector 6)
- ESCALATE parking rate: **100%** (Vector 7)
- False positive rate: **0%**

**Value:** Objective pass/fail criteria for hostile validation completion.

---

## Gap Analysis

### Minor Discrepancies (None Critical)

1. **Vector Numbering**
   - Lars doesn't number his vectors; test plan assigns 1-7
   - **Impact:** None — cosmetic only
   - **Resolution:** N/A

2. **Smoke Test Sequencing**
   - Lars mentions "initial live smoke test" but doesn't specify test cases
   - Test plan provides 5-step smoke test sequence
   - **Impact:** Low — prevents ambiguous "does it work?" validation
   - **Resolution:** Use test plan's Smoke Test Sequence section

3. **FlowSignal-Side Responsibilities**
   - Lars doesn't explicitly state what FlowSignal must implement to support hostile testing
   - Test plan implies FlowSignal needs dynamic response configuration (e.g., "Configure FlowSignal to delay responses by 6 seconds")
   - **Impact:** Medium — Graham's team needs test harness capabilities
   - **Resolution:** Add to Lars's response: "For hostile testing, we'll need FlowSignal to support dynamic response injection (configurable delays, malformed payloads, etc.) for specific test `thread_id` values."

---

## Recommendations for Lars's Response

### 1. Add Test Harness Requirement ⚠️
Insert after "Configuration on our side" section:

> **Test Harness Requirement:** For hostile validation (Vectors 1-4), we'll need FlowSignal's staging endpoint to support dynamic response injection based on request parameters (e.g., `thread_id` or custom header). Specifically:
> - **Timeout tests:** Configurable response delays (e.g., 6-second hold for `thread_id=timeout-test-001`)
> - **Malformed response tests:** Ability to return missing `decision` fields, invalid enums, or non-JSON payloads
> - **Replay tests:** Reissue same `authority_record_id` on demand
>
> If FlowSignal's staging environment doesn't support dynamic injection, we can simulate these scenarios using a proxy layer on CAGE's side (e.g., mitmproxy with custom scripts).

### 2. Reference Test Plan Document (Optional)
Add at end of Lars's response:

> I've also prepared a comprehensive hostile test plan with detailed pytest commands, verification scripts, and a 4-phase execution runbook. I'll share the doc via Slack so your team can review the full scope ahead of our kickoff call.

### 3. Clarify Smoke Test Expectations (Optional)
Add after "Send over the staging URL..." paragraph:

> Before the hostile run, let's execute a 5-step smoke test sequence to confirm integration health:
> 1. FlowSignal connectivity check (`GET /legal-baseline/US_FED`)
> 2. End-to-end ALLOW flow
> 3. End-to-end REFUSE flow
> 4. ConsequenceToken minting
> 5. Full execution with FlowSignal gate
>
> Once these pass, we'll proceed to hostile validation.

---

## Final Assessment

### Alignment Score: **98/100**

| Category | Score | Notes |
|----------|-------|-------|
| Technical Accuracy | 100/100 | All code references verified, line numbers correct |
| Vector Coverage | 95/100 | Lars covers 5 vectors; test plan adds 2 more (acceptable) |
| Executable Clarity | 100/100 | Test plan translates prose into exact commands |
| Operational Readiness | 100/100 | 4-phase runbook + success criteria table |
| Coordination Friction | 95/100 | Minor: lacks test harness requirement for FlowSignal |

### Recommendation: **APPROVE Lars's Response with Minor Additions**

The response is production-ready and accurately reflects CAGE's codebase. Recommend adding:
1. Test harness requirement for FlowSignal (dynamic response injection)
2. Reference to detailed test plan document
3. Optional: 5-step smoke test sequence

The hostile test plan is **fully aligned** and provides extended rigor beyond Lars's response, making it an ideal artifact to share with Graham's team for coordination.

---

**End of Alignment Analysis**
