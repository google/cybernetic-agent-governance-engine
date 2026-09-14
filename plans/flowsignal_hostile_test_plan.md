# FlowSignal Integration Hostile Test Plan

**Status:** READY FOR EXECUTION  
**Target Invariant:** `EXECUTED ⟹ CAGE_GOVERNANCE_ALLOW ∧ FLOWSIGNAL_RUNTIME_AUTHORITY_ALLOW`  
**Phase:** 3 (Hostile Interoperability Validation)  
**Last Updated:** 2026-09-14

---

## Executive Summary

This test plan attacks the composition invariant between CAGE's governance kernel and FlowSignal's external normative provider across seven hostile vectors. The goal is to prove that no action can reach execution without dual approval from both CAGE's internal governance pipeline AND FlowSignal's runtime authority.

---

## Test Environment Setup

### Prerequisites

1. **FlowSignal Staging Endpoint**
   - Base URL: `https://<flowsignal-staging-host>` (TBD by FlowSignal team)
   - Valid TLS certificate (publicly trusted or known CA bundle)
   - Reachable via standard HTTPS (port 443) from CAGE GKE dev/staging cluster

2. **CAGE Configuration**
   ```bash
   # Deploy to GKE dev cluster with provider_01 enabled
   kubectl create secret generic flowsignal-config \
     --from-literal=CAGE_NORMATIVE_ENDPOINT="https://<flowsignal-staging-host>" \
     --from-literal=CAGE_NORMATIVE_API_KEY_SECRET="<bearer-token>" \
     --from-literal=CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS="5" \
     -n cage-dev
   
   # Patch gateway deployment
   kubectl set env deployment/gateway-service \
     CAGE_NORMATIVE_PROVIDER=provider_01 \
     -n cage-dev
   ```

3. **Test Instrumentation**
   - Langfuse trace collection enabled (`LANGFUSE_ENABLED=true`)
   - Redis connection to shared dev instance for replay detection
   - KMS key active for ConsequenceToken signing

4. **Test Scope Boundary**
   - **Autonomous execution paths only** (no human step-up approval)
   - FlowSignal `ESCALATE` verdicts MUST result in `¬EXECUTED` (DeferQueue parking)

---

## Test Vectors

### Vector 1: Timeout & Network Partition

**Objective:** Prove CAGE fails closed when FlowSignal endpoint becomes unavailable or unresponsive.

#### Test Cases

##### 1.1: FlowSignal Timeout (> 5.0s response time)
**Setup:**
- Configure FlowSignal staging to delay responses by 6 seconds for specific test `thread_id`

**Execution:**
```bash
uv run pytest tests/test_provider_01.py::test_validate_fria_timeout -v
```

**Expected CAGE Behavior:**
- [`validate_fria()`](src/integrations/provider_01/provider.py:260) catches `httpx.TimeoutException`
- Returns `ValidationResult(admitted=False, findings=[{"code": "ENDPOINT_ERROR", "severity": "blocked", ...}])`
- Action MUST NOT execute

**Verification:**
```bash
# Check Langfuse trace for ENDPOINT_ERROR finding
uv run python scripts/evaluate_langfuse_traces.py \
  --filter "thread_id=timeout-test-001" \
  --assert "findings.code == ENDPOINT_ERROR" \
  --assert "admitted == false"
```

##### 1.2: Network Partition (DNS/connection failure)
**Setup:**
- Temporarily block egress to FlowSignal staging host via Cilium NetworkPolicy

**Execution:**
```bash
kubectl apply -f tests/fixtures/network-partition.yaml
uv run pytest tests/test_provider_01.py::test_validate_fria_connection_error -v
kubectl delete -f tests/fixtures/network-partition.yaml
```

**Expected CAGE Behavior:**
- [`validate_fria()`](src/integrations/provider_01/provider.py:335-347) catches `httpx.RequestError`
- Returns `ValidationResult(admitted=False, findings=[{"code": "ENDPOINT_ERROR", ...}])`
- Action MUST NOT execute

**Success Criteria:**
- ✅ Zero executions during network partition window
- ✅ All requests emit `ENDPOINT_ERROR` finding with `severity="blocked"`
- ✅ Langfuse traces show fail-closed behavior

---

### Vector 2: Malformed & Schema Invariance

**Objective:** Prove CAGE fails closed on malformed FlowSignal responses.

#### Test Cases

##### 2.1: Missing `decision` Field
**Setup:**
- Configure FlowSignal to return `{"message": "Processing", "authority_record_id": "rec-001"}` (no `decision`)

**Execution:**
```bash
uv run pytest tests/test_provider_01.py::test_validate_fria_missing_decision -v
```

**Expected CAGE Behavior:**
- [`validate_fria()`](src/integrations/provider_01/provider.py:303-317) detects missing `decision`
- Returns `ValidationResult(admitted=False, findings=[{"code": "cage.endpoint_error", "severity": "blocked", ...}])`
- Action MUST NOT execute

##### 2.2: Unrecognized Decision Value
**Setup:**
- Configure FlowSignal to return `{"decision": "MAYBE", ...}`

**Expected CAGE Behavior:**
- [`_map_flowsignal_decision()`](src/integrations/provider_01/provider.py:163) raises `ValueError`
- [`validate_fria()`](src/integrations/provider_01/provider.py:285-301) catches exception
- Returns `ValidationResult(admitted=False, findings=[{"code": "FINDING_CODE_PARSE_ERROR", ...}])`

##### 2.3: Non-JSON Response
**Setup:**
- Configure FlowSignal to return plain text or HTML error page

**Expected CAGE Behavior:**
- JSON decode fails, triggers exception handler at [lines 348-360](src/integrations/provider_01/provider.py:348-360)
- Returns `ValidationResult(admitted=False, findings=[{"code": "ENDPOINT_ERROR", ...}])`

**Success Criteria:**
- ✅ Zero executions across all malformed response scenarios
- ✅ All failures emit structured findings with `severity="blocked"`
- ✅ No silent admits (every failure path logged)

---

### Vector 3: Replay Protection

**Objective:** Prove that re-submitting an identical `authority_record_id` blocks the second execution attempt.

#### Test Cases

##### 3.1: Immediate Replay (< 1s delay)
**Setup:**
1. Submit action `A1` with FlowSignal returning `{"decision": "ALLOW", "authority_record_id": "replay-test-001", ...}`
2. Execute action successfully (first attempt)
3. Re-submit identical action `A1` with same `authority_record_id` within 1 second

**Execution:**
```bash
uv run pytest tests/test_consequence_gateway_integration.py::test_replay_immediate -v
```

**Expected CAGE Behavior:**
1. First execution: [`ConsequenceAuthorityStore.consume_once()`](src/gateway/governance/consequence_authority_store.py:120) returns `True` → execution proceeds
2. Second execution: Redis `SET NX` fails (key exists) → `consume_once()` returns `False`
3. ConsequenceGateway emits `ALREADY_CONSUMED` finding → action blocked

**Verification:**
```bash
# Check Redis for consumed token
redis-cli -h <redis-host> GET "flowsignal:token:replay-test-001"
# Should return binding hash from first consumption
```

##### 3.2: Delayed Replay (within 90s TTL)
**Setup:**
- Execute action at T=0
- Wait 45 seconds
- Attempt replay at T=45

**Expected CAGE Behavior:**
- Token still exists in Redis (TTL=90s)
- Second attempt blocked with `ALREADY_CONSUMED`

##### 3.3: Post-TTL Replay (> 90s delay)
**Setup:**
- Execute action at T=0
- Wait 95 seconds (beyond 90s Redis TTL)
- Attempt replay at T=95

**Expected CAGE Behavior:**
- **This is a boundary case**: Token expired from Redis
- However, FlowSignal MUST NOT return the same `authority_record_id` after 90s (FlowSignal responsibility)
- If FlowSignal does return same ID, CAGE treats it as fresh authority (NOT a CAGE defect)

**Success Criteria:**
- ✅ 100% block rate for replays within 90s window
- ✅ Redis atomic consumption verified via `SET NX` logs
- ✅ Langfuse traces show `ALREADY_CONSUMED` finding on replay attempts

---

### Vector 4: Stale Authority & Parameter Mutation (TOCTOU)

**Objective:** Prove that expired tokens and parameter tampering both fail closed.

#### Test Cases

##### 4.1: Token Expiry (> 60s age)
**Setup:**
1. FlowSignal returns `ALLOW` with `authority_record_id="stale-001"` at T=0
2. CAGE mints ConsequenceToken with `exp` = T+60
3. Attempt execution at T=65 (after 60s TTL)

**Execution:**
```bash
uv run pytest tests/test_consequence_token.py::test_verify_expired_token -v
```

**Expected CAGE Behavior:**
- [`ConsequenceToken.verify()`](src/gateway/governance/consequence_token.py:294-301) detects `now > exp`
- Raises `ConsequenceTokenError("Token expired: exp=..., now=...")`
- ConsequenceGateway blocks execution with `TOKEN_INVALID` finding

##### 4.2: Issued-at Clock Skew Attack
**Setup:**
- Craft malicious token with `iat` = T+120 (2 minutes in future)

**Expected CAGE Behavior:**
- [`ConsequenceToken.verify()`](src/gateway/governance/consequence_token.py:304-311) detects `iat > now + 5s`
- Raises `ConsequenceTokenError("Token iat too far in future...")`

##### 4.3: Parameter Mutation After Authority Grant
**Setup:**
1. FlowSignal approves action: `{"action": "execute_trade", "symbol": "AAPL", "amount": 100}`
2. CAGE mints token with `act` = SHA-256(JCS(`action_payload`))
3. Attacker modifies payload to: `{"action": "execute_trade", "symbol": "AAPL", "amount": 1000}`
4. Attempt execution with modified payload + original token

**Execution:**
```bash
uv run pytest tests/test_consequence_gateway_integration.py::test_parameter_mutation -v
```

**Expected CAGE Behavior:**
1. ConsequenceGateway recomputes action digest: `act_computed = SHA-256(JCS(modified_payload))`
2. Compares `act_computed` vs. token claim `act_original`
3. Mismatch detected → emits `ACTION_BINDING_MISMATCH` finding → blocks execution

**Verification:**
```python
# Verify JCS canonicalization is deterministic
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
import hashlib

payload_original = {"action": "execute_trade", "symbol": "AAPL", "amount": 100}
payload_modified = {"action": "execute_trade", "symbol": "AAPL", "amount": 1000}

act_original = hashlib.sha256(jcs_canonicalize_plan(payload_original)).hexdigest()
act_modified = hashlib.sha256(jcs_canonicalize_plan(payload_modified)).hexdigest()

assert act_original != act_modified  # Must differ
```

**Success Criteria:**
- ✅ 100% block rate for expired tokens (> 60s age)
- ✅ 100% block rate for parameter mutations (any field change)
- ✅ Clock skew attacks blocked (future-dated `iat`)
- ✅ Action digest computed via RFC 8785 JCS (no canonicalization drift)

---

### Vector 5: Fencing & Monotonic Epoch Integrity

**Objective:** Prove that operational state rollbacks cannot rewind monotonic governance markers.

#### Test Cases

##### 5.1: Evidence Stream Fence Bypass Attempt
**Setup:**
1. Execute action `A1` → evidence hash `H1` appended to cold store at epoch `E1`
2. Simulate Redis flush (operational state loss)
3. Attempt to re-execute `A1` with same `authority_record_id`

**Expected CAGE Behavior:**
- Evidence cold store (GCS/S3) retains `H1` with timestamp `T1` (immutable)
- Even if Redis loses consumption marker, FlowSignal MUST NOT reissue same `authority_record_id`
- If FlowSignal does reissue, it's a FlowSignal defect, not CAGE defect

**Verification:**
```bash
# Check evidence cold store
gsutil cat gs://<evidence-bucket>/evidence-chain/<thread_id>.jsonl | grep "H1"
# Must show original timestamp, unaffected by Redis flush
```

##### 5.2: Consensus Epoch Rollback Resistance
**Setup:**
- Execute action at consensus epoch `E=100`
- Simulate Kubernetes pod restart (in-memory state loss)
- Verify epoch counter resumes from durable storage, not reset to `E=0`

**Expected CAGE Behavior:**
- Epoch counter stored in Redis with `INCR` (atomic monotonic increment)
- Pod restart fetches current epoch from Redis → continues from `E=101`

**Success Criteria:**
- ✅ Evidence hashes persist across operational failures
- ✅ Epoch counters never decrement (monotonic property)
- ✅ Cold store writes are append-only (no overwrites)

---

### Vector 6: Non-Bypassability & Provider Binding

**Objective:** Prove that execution cannot bypass the FlowSignal gate or fall back to static admission.

#### Test Cases

##### 6.1: Direct Execution Bypass Attempt
**Setup:**
- Attempt to call [`ExecutionActuator.actuate()`](src/gateway/governance/execution_actuator.py) directly without routing through ConsequenceGateway

**Execution:**
```bash
uv run pytest tests/test_execution_actuator.py::test_direct_execution_blocked -v
```

**Expected CAGE Behavior:**
- [`ExecutionClearance`](src/cage_finance/tools/tool_provider.py:192) requires `governance_decision_digest` (seal)
- Actuator validates clearance structure before execution
- Missing seal → `SymbolicGovernorViolation` exception raised

##### 6.2: Provider Fallback Disable
**Setup:**
- Configure `CAGE_NORMATIVE_PROVIDER=provider_01`
- Simulate FlowSignal endpoint returning 500 errors for 30 seconds
- Verify CAGE does NOT fall back to static/mock provider

**Expected CAGE Behavior:**
- All requests fail closed with `ENDPOINT_ERROR`
- Zero executions during FlowSignal outage window
- No automatic fallback to `StaticNormativeProvider`

**Verification:**
```bash
# Check logs for fallback attempts (should be zero)
kubectl logs -l app=gateway-service -n cage-dev | grep "Falling back to static provider"
# Expected: no matches
```

##### 6.3: Seal Verification at Execution Boundary
**Setup:**
- Execute action with valid FlowSignal approval
- Verify seal is validated at [`tool_provider.py:105-110`](src/cage_finance/tools/tool_provider.py:105-110)

**Expected CAGE Behavior:**
1. [`enforce_governance()`](src/cage_finance/tools/tool_provider.py:101) returns routing seal
2. Seal validation at [line 106](src/cage_finance/tools/tool_provider.py:106) checks for non-empty string
3. [`verify_and_consume_seal()`](src/cage_finance/tools/tool_provider.py:178) burns single-use nonce in Redis
4. Invalid/missing/consumed seal → `SymbolicGovernorViolation` raised

**Success Criteria:**
- ✅ Zero bypass executions (100% gate coverage)
- ✅ No fallback to static provider during FlowSignal outage
- ✅ Every execution validated against single-use seal

---

### Vector 7: ESCALATE & Human-in-the-Loop Boundary

**Objective:** Prove that FlowSignal `ESCALATE` verdicts correctly park transactions in DeferQueue without autonomous execution.

#### Test Cases

##### 7.1: ESCALATE Verdict Handling
**Setup:**
- Configure FlowSignal to return `{"decision": "ESCALATE", "message": "Requires compliance review", ...}`

**Execution:**
```bash
uv run pytest tests/test_provider_01.py::test_validate_fria_escalate -v
```

**Expected CAGE Behavior:**
1. [`_map_flowsignal_decision()`](src/integrations/provider_01/provider.py:149-160) maps `ESCALATE` to `EXTERNAL_HOLD`
2. Returns `ValidationResult(admitted=False, findings=[{"code": "EXTERNAL_HOLD", "needs_human_review": True, "hold_ttl_seconds": 300}])`
3. LangGraph defer node parks transaction in [`DeferQueue`](src/gateway/governance/defer_queue.py:166-231)
4. Action MUST NOT execute autonomously

**Verification:**
```bash
# Check DeferQueue for parked transaction
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8081/v1/defer/pending | jq '.tokens[] | select(.defer_reason == "EXTERNAL_HOLD")'
```

##### 7.2: Dual-Control Step-Up Resolution
**Setup:**
1. Transaction parked with `defer_id="escalate-001"`
2. Two distinct operators submit approvals via `POST /v1/defer/escalate-001/escalate`
3. After quorum=2 reached, verify execution proceeds

**Expected CAGE Behavior:**
- First approval: DeferQueue increments `approvals` list
- Second approval: Quorum reached → transaction released from hold
- Execution proceeds WITHOUT re-consulting FlowSignal (human override)

**Invariant Precision:**
- For autonomous paths: `EXECUTED ⟹ FLOWSIGNAL_ALLOW`
- For step-up paths: `EXECUTED ⟹ (FLOWSIGNAL_ALLOW ∨ DUAL_SUPERVISOR_OVERRIDE)`

**Success Criteria:**
- ✅ Zero autonomous executions on `ESCALATE` verdicts
- ✅ DeferQueue parking verified (TTL=300s)
- ✅ Dual-control step-up flow functional (quorum=2)

---

## Smoke Test Sequence

Before hostile validation, execute this baseline happy-path sequence to confirm integration health:

```bash
# 1. FlowSignal connectivity check
curl -H "Authorization: Bearer $FLOWSIGNAL_API_KEY" \
  https://<flowsignal-staging-host>/legal-baseline/US_FED

# 2. End-to-end ALLOW flow
uv run pytest tests/test_provider_01.py::test_validate_fria_allow -v

# 3. End-to-end REFUSE flow
uv run pytest tests/test_provider_01.py::test_validate_fria_refuse -v

# 4. ConsequenceToken minting
uv run pytest tests/test_consequence_token_service.py::test_mint_and_verify -v

# 5. Full execution with FlowSignal gate
uv run pytest tests/test_consequence_gateway_integration.py::test_execute_with_flowsignal_allow -v
```

**Expected Results:**
- All 5 tests pass
- Langfuse shows complete trace chains (FRIA → ConsequenceToken → Execution)
- Zero timeout errors, zero malformed responses

---

## Execution Runbook

### Phase 1: Environment Preparation (Day 1)
1. FlowSignal team provisions staging endpoint, shares URL + API key
2. CAGE team creates `flowsignal-config` Secret in GKE dev cluster
3. Deploy gateway with `CAGE_NORMATIVE_PROVIDER=provider_01`
4. Execute smoke test sequence (5 tests)
5. Confirm Langfuse trace collection

### Phase 2: Hostile Vector Execution (Days 2-3)
Execute test vectors in sequence:
1. Vector 1: Timeout & Network Partition
2. Vector 2: Malformed Responses
3. Vector 3: Replay Protection
4. Vector 4: Stale Authority & TOCTOU
5. Vector 5: Fencing (optional, requires evidence cold store setup)
6. Vector 6: Non-Bypassability
7. Vector 7: ESCALATE Handling

### Phase 3: Result Analysis (Day 4)
1. Aggregate Langfuse traces for all test runs
2. Verify 100% fail-closed rate across vectors 1-4, 6-7
3. Generate hostile validation report
4. Share findings with FlowSignal team

### Phase 4: Remediation Loop (Days 5-7)
- If any test vector fails: root-cause analysis, patch, re-test
- Continue until 100% pass rate achieved

---

## Success Criteria (Gate to Production)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Fail-closed rate (Vectors 1-2) | 100% | Zero executions on timeout/malformed responses |
| Replay block rate (Vector 3) | 100% | Zero duplicate executions within 90s window |
| TOCTOU protection (Vector 4) | 100% | Zero executions on expired tokens or mutated params |
| Bypass attempts blocked (Vector 6) | 100% | Zero direct executions without FlowSignal approval |
| ESCALATE parking rate (Vector 7) | 100% | All `ESCALATE` verdicts → DeferQueue, no autonomous execution |
| Langfuse trace completeness | 100% | All test runs emit structured traces |
| False positive rate | 0% | No legitimate requests blocked erroneously |

---

## Rollback Plan

If hostile validation uncovers critical defects:

1. **Immediate:** Revert to `CAGE_NORMATIVE_PROVIDER=static` in dev cluster
2. **Root Cause:** Triage failing test vector, identify code path
3. **Patch:** Apply fix to either CAGE or FlowSignal (coordinate via Slack)
4. **Re-test:** Re-run failing vector until green
5. **Resume:** Continue hostile validation sequence

---

## Test Artifacts

All test runs must generate:
1. **Pytest JUnit XML:** `pytest --junit-xml=results/hostile-validation.xml`
2. **Langfuse Trace Exports:** `uv run python scripts/evaluate_langfuse_traces.py --export results/traces.jsonl`
3. **Redis Dump (Replay Evidence):** `redis-cli --rdb results/redis-snapshot.rdb`
4. **Hostile Validation Report:** Markdown summary of all vector results

Store in: `results/flowsignal-hostile-validation-<YYYY-MM-DD>/`

---

## Contact & Coordination

- **CAGE Team Lead:** Lars (lars@example.com)
- **FlowSignal Integration Lead:** Graham Brimage (graham@flowsignal.example)
- **Slack Channel:** `#cage-flowsignal-integration`
- **Status Cadence:** Daily standup during hostile validation window

---

**End of FlowSignal Hostile Test Plan**
