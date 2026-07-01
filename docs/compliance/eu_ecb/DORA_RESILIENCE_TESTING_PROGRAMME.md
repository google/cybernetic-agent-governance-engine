# DORA Art. 12 — Digital Operational Resilience Testing Programme

**Document:** EU-002 / DORA (Reg. 2022/2554) Art. 12 / ISO 42001 §A.8.4
**Date:** 2026-06-24
**Status:** Draft — testing not yet executed; programme design pending ECB supervisor notification
**POAM:** EU-002 (POAM_EU_ECB.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only

---

## 1. Purpose and Legal Basis

DORA Art. 12 requires financial entities to establish, maintain, and review a **digital operational resilience testing programme**. This document defines the CAGE EU_ECB resilience testing programme, covering:

1. **Advanced threat-led penetration testing** of the governance enforcement path (DORA Art. 12(3))
2. **WAL LIFO rollback failure injection** tests (DORA Art. 12(1)(c) — self-assessment)
3. **Redis unavailability / fail-closed verification** (DORA Art. 12(1)(d))
4. **Governance bypass attempt testing** (DORA Art. 12(1)(b))

---

## 2. Scope

**In scope:** All CAGE components in the EU_ECB deployment:
- Gateway (governance enforcement, NeMo, OPA, HITL)
- Compliance bridge (Langfuse audit, OSCAL evidence)
- LangGraph supervisor + governed financial advisor agents
- Redis checkpoint store
- vLLM inference endpoint

**Out of scope for this programme:** Network-layer resilience (GKE node failures, GCP regional outages) — those are addressed by GKE regional cluster design.

---

## 3. Test Scenarios

### Test 1: WAL LIFO Rollback Failure Injection

**DORA Art. 12(1)(c):** Scenario-based testing of the WAL rollback mechanism.

**Objective:** Verify that when a trade action fails after WAL write, the LIFO rollback restores the previous state correctly.

**Procedure:**
1. Submit a trade action that succeeds at the WAL write stage
2. Inject a failure at the post-WAL execution stage (mock `execute_trade` to raise)
3. Verify: LIFO rollback fires and ledger state is restored
4. Verify: Langfuse trace records `wal.rollback=true` and `wal.rollback_reason=execution_failure`
5. Verify: `/health` endpoint returns healthy after rollback

**Pass criteria:** Ledger state identical to pre-trade state; Langfuse trace present.

**Target execution date:** Q3 2026

---

### Test 2: Redis Unavailability — Fail-Closed Verification

**DORA Art. 12(1)(d):** Continuity testing of critical dependencies.

**Objective:** Verify that CAGE fails closed when Redis becomes unavailable (no governance bypass via resource exhaustion).

**Procedure:**
1. With CAGE running normally, kill the Redis pod: `kubectl delete pod -n governance-stack -l app=redis-stack`
2. Attempt 10 trade actions via the governed financial advisor
3. Verify: `TokenQuotaProxy` returns 503 (quota unavailable) for all requests
4. Verify: Gateway logs `[ISO-001] Redis token quota unavailable` warning
5. Verify: OPA policy falls back to RBAC-only gate (no quota bypass)
6. Restore Redis: wait for `redis-stack` StatefulSet to become Ready
7. Verify: All governance controls resume normal operation within 5 minutes

**Pass criteria:** Zero governance bypasses during Redis outage; full recovery within 5 minutes.

**Target execution date:** Q3 2026

---

### Test 3: Governance Enforcement Path Penetration Test

**DORA Art. 12(3):** Threat-led penetration testing (TLPT).

**Objective:** Verify that the three-tier semantic shielding cannot be bypassed by adversarial prompt injection.

**Procedure (to be conducted by an accredited TLPT provider):**
1. Tier 1 bypass attempts: Aho-Corasick filter evasion (character substitution, encoding tricks)
2. Tier 2 bypass attempts: SLM semantic similarity evasion (paraphrase attacks)
3. Tier 3 bypass attempts: OPA policy bypass (malformed input, type coercion)
4. Indirect injection via MCP tool responses (see `docs/PII_SCRUBBING_POLICY.md`)
5. HITL bypass attempts (TOCTOU attack simulation)

**Pass criteria:** All adversarial inputs blocked or escalated to MANUAL_REVIEW. Zero governance violations reaching the trade execution layer.

**TLPT provider requirements:** EBA-accredited TLPT provider required for DORA Art. 12(3) compliance.

**Target execution date:** Q4 2026

---

### Test 4: HITL SLA Resilience Test

**DORA Art. 12(1)(b):** End-to-end resilience testing.

**Objective:** Verify that HITL escalations remain serviceable when the compliance bridge is under load.

**Procedure:**
1. Generate 50 concurrent HITL escalations (inject confidence scores 0.70–0.94)
2. Measure time-to-first-HITL-notification for each escalation
3. Verify: All 50 escalations receive operator notification within 1 hour (APAC_MAS SLA) or 4 hours (default SLA)
4. Verify: No escalations are dropped (Redis checkpoint persistence)

**Pass criteria:** 100% of HITL escalations delivered within SLA; zero dropped escalations.

**Target execution date:** Q3 2026

---

## 4. Testing Schedule

| Test | Scenario | Frequency | Target Date | Status |
|---|---|---|---|---|
| Test 1 | WAL rollback failure injection | Annual + post-release | Q3 2026 | Planned |
| Test 2 | Redis unavailability fail-closed | Semi-annual | Q3 2026 | Planned |
| Test 3 | Governance TLPT | Annual (DORA Art. 12(3)) | Q4 2026 | Planned |
| Test 4 | HITL SLA resilience | Quarterly | Q3 2026 | Planned |

---

## 5. Result Reporting

All test results must be:
1. Documented in a test report and archived to `gs://$CAGE_AUDIT_BUCKET/dora-resilience/YYYY-QN/`
2. Reported to the designated ECB supervisor contact within 10 business days of test completion
3. Used to update POAM EU-002 milestone status

---

## Related Documents

- `docs/POAM_EU_ECB.md` — EU-002 POAM item
- `docs/FRIA_ATTESTATION.md` — EU-001 FRIA document
- `docs/HUMAN_OVERSIGHT_SCOPE.md` — HITL SLA definitions
- `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` — Audit evidence retention
