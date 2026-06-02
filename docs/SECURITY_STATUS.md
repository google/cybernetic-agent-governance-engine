# Security & Compliance Status — CAGE v2.0.0

**Date:** 2026-05-17  
**Status:** Public disclosure of current security posture and compliance implementation state

---

## Summary

CAGE v2.0.0 provides a **production-grade AI governance enforcement runtime**. The AI-layer controls (NeMo Guardrails, OPA policy enforcement, Cloud KMS asymmetric signing with HMAC-SHA256 dev/CI fallback, HITL, LangGraph safety nodes) are fully implemented and tested. However, the full **NIST Risk Management Framework (RMF) authorization process has not been completed**, and several infrastructure-level security controls have known gaps documented in [`docs/POAM.md`](POAM.md).

> [!IMPORTANT]
> This system has **not received an Authorization to Operate (ATO)** from a NIST-designated Authorizing Official. It has not undergone a formal Security Assessment. Deployers in regulated environments must complete their own risk assessment before production use.

---

## What Is Fully Implemented

### AI Governance Enforcement (Strong)

| Control                          | Implementation                                                            | Status                  |
| -------------------------------- | ------------------------------------------------------------------------- | ----------------------- |
| NeMo Guardrails input gate       | Mandatory first LangGraph node; fail-closed on exception                  | ✅ Implemented & tested |
| NeMo Guardrails output rail      | Mandatory final LangGraph node; in-process Presidio PII egress filter    | ✅ Implemented & tested |
| OPA policy enforcement           | Direct REST; circuit breaker defaults to DENY on failure                  | ✅ Implemented & tested |
| STPA-to-Policy Compiler          | UCAs compiled from YAML to Rego + Colang + Python; no hand-edited policy  | ✅ Implemented & tested |
| Cloud KMS governance signature   | HSM-backed asymmetric signing via `kms_signer.py`; HMAC-SHA256 fallback in dev/CI | ✅ Implemented & tested |
| Human-in-the-loop gate           | `interrupt_before=["governed_trader"]`; Redis-persisted checkpoint        | ✅ Implemented & tested |
| Safety check node                | Explicit OPA gate between evaluator and governed trader                   | ✅ Implemented & tested |
| Control Barrier Function         | Redis-backed cash/drawdown invariant enforcement                          | ✅ Implemented & tested |
| Aho-Corasick keyword scan        | O(n) prompt-injection detection; 14+ patterns                             | ✅ Implemented & tested |
| Multi-agent consensus            | Unanimity required for trades > $10k                                      | ✅ Implemented & tested |
| Presidio PII detection           | 15 entity types; input and output (in-process within NeMo Guardrails)      | ✅ Implemented & tested |
| W3C traceparent propagation      | Full OTel trace waterfall; 100% sampling for governance spans             | ✅ Implemented & tested |
| Recursion guard                  | `loop_count >= 3 → explainer` escape hatch                                | ✅ Implemented & tested |
| Linkerd mTLS (SC-8 / IA-3)       | SPIFFE/SVID identity; gateway↔OPA, gateway↔NeMo; closes POAM-007          | ✅ Implemented (v1.1.0) |
| Cilium L7 egress lockdown (SC-7) | FQDN allowlist (gateway); internal-only (agent pods); closes POAM-011     | ✅ Implemented (v1.1.0) |
| Cryptographic evidence chain     | SHA-256 hash-chained NDJSON; MiFID II / GDPR view-access log             | ✅ Implemented (v1.1.0) |

### Compliance Automation (4 Controls)

Automated continuous compliance assessment is active for **8 ISO 42001 / NIST SP 800-53 controls** via Lula CronJob (every 6 hours) and the OSCAL compliance bridge:

| Control   | Description                                       | Threshold            | Lula Validation            |
| --------- | ------------------------------------------------- | -------------------- | -------------------------- |
| ISO A.5.2 | Social impact — hate speech / bias prevention     | `safety_rate ≥ 99%`  | `lula-validation-a52.yaml` |
| ISO A.5.3 | Logging and monitoring — audit event completeness | `safety_rate ≥ 98%`  | `lula-validation-a53.yaml` |
| ISO A.9.2 | Data privacy — no PII sent to external APIs       | `safety_rate = 100%` | `lula-validation-a92.yaml` |
| SC-4      | Fiscal limits — human approval for trades > $10k  | OPA policy active    | `lula-validation-sc4.yaml` |
| SC-7      | Boundary protection — Cilium L7 egress lockdown   | CiliumNetworkPolicy  | `lula-validation-sc7.yaml` |
| SC-8      | Transmission integrity — Linkerd mTLS active       | Linkerd mTLS active  | `lula-validation-sc8.yaml` |
| A.8.4     | STPA compiler — UCAs enforced at runtime           | Compiler artifacts   | Inline OTel spans          |
| SA-11     | Developer security testing — evidence chain        | Evidence chain valid | `verify_chain()`           |

Findings are expressed as OSCAL Assessment Results and ingested into Langfuse. **Additional ISO 42001 Annex A controls and the full NIST SP 800-53 control baseline are not yet mapped or assessed.**

---

## What Is Not Yet Complete

### NIST RMF Authorization Process

The NIST RMF is a six-step process. The table below reflects the current state:

| RMF Step              | Status         | Notes                                                                                              |
| --------------------- | -------------- | -------------------------------------------------------------------------------------------------- |
| **1 — Prepare**       | 🟡 In Progress | FIPS 199 categorization document created but unsigned (POAM-009)                                   |
| **2 — Categorize**    | 🟡 In Progress | Informal categorization only; no System Owner / AO signature                                       |
| **3 — Select**        | 🟡 Partial     | Controls selected per NIST SP 800-53 HIGH baseline; not formally documented in an SSP              |
| **4 — Implement**     | 🟡 Partial     | AI governance controls implemented (see above); infrastructure-layer controls have gaps (see POAM) |
| **5 — Assess**        | ❌ Not started | No Security Assessment Report (SAR); no independent Control Assessor engaged                       |
| **6 — Authorize**     | ❌ Not started | No Authorization to Operate (ATO) letter issued (POAM-005, Critical)                               |
| **Ongoing — Monitor** | 🟡 Partial     | Lula CronJob active for 4 controls; broader continuous monitoring not yet operational              |

### Infrastructure Security Gaps (from POA&M)

The following weaknesses are documented in [`docs/POAM.md`](POAM.md). Items marked **Closed** were resolved in v1.1.0–v2.0.0:

| ID       | Control | Weakness                                                              | Severity     | Status      | Target Date |
| -------- | ------- | --------------------------------------------------------------------- | ------------ | ----------- | ----------- |
| POAM-001 | AC-2    | No account management procedures                                      | High         | Open        | 2026-04-30  |
| POAM-002 | AC-6    | Overly broad IAM role bindings in Terraform                           | High         | Open        | 2026-05-15  |
| POAM-003 | AU-12   | `automated_auditor.py` uses synthetic mock traces, not live OTLP      | High         | Open        | 2026-04-15  |
| POAM-005 | CA-6    | **No Authorization to Operate (ATO) letter**                          | **Critical** | Open        | 2026-06-30  |
| POAM-006 | CM-8    | No SBOM in CI/CD pipeline                                             | High         | Open        | 2026-05-01  |
| POAM-007 | IA-3    | ~~No intra-cluster mTLS~~ **✅ Closed** — Linkerd SPIFFE/SVID deployed | High         | **Closed**  | 2026-05-17  |
| POAM-008 | IR-1    | No formal Incident Response Plan                                      | High         | Open        | 2026-04-30  |
| POAM-009 | RA-2    | FIPS 199 categorization unsigned                                      | **Critical** | Open        | 2026-03-31  |
| POAM-010 | RA-5    | No vulnerability scanning in CI pipeline                              | High         | Open        | 2026-04-15  |
| POAM-011 | SC-8    | ~~No TLS enforcement~~ **✅ Closed** — Linkerd mTLS + Cilium L7 active  | Moderate     | **Closed**  | 2026-05-17  |
| POAM-012 | SC-12   | ~~`CAGE_ROUTING_SEAL_SECRET` unset silently disables seal~~ **✅ Closed** — Module-level startup validation in `governance_middleware.py`; RuntimeError in non-dev   | High         | **Closed** | 2026-05-28  |
| POAM-013 | SI-2    | Unpinned `>=` version specifiers across Python dependencies           | High         | Open        | 2026-04-15  |
| POAM-014 | SC-28   | ~~No CMEK validation~~ **✅ Closed** — `cmek_guard.py` validates CMEK key + GCS bucket at startup; RuntimeError in non-dev | Moderate     | **Closed**  | 2026-05-28  |
| POAM-015 | PL-2    | ~~**No System Security Plan (SSP)**~~ **✅ Closed** — `compliance/oscal/system-security-plan.yaml` (1300+ lines, OSCAL 1.0.4)  | **Critical** | **Closed** | 2026-05-17  |
| POAM-016 | SI-2    | ~~CVE-2025-69872 (diskcache) RCE~~ **✅ Closed** — Removed `outlines` from gateway deps; `diskcache` no longer in dependency tree | Moderate     | **Closed**  | 2026-05-29  |

### Testing Gaps

- **`automated_auditor.py` uses synthetic mock traces** — the continuous audit invariant checker (POAM-003) does not connect to a live OTLP source; its evidence does not reflect actual system behavior.
- **No vulnerability scanning** — container images and Python dependencies are not scanned for CVEs in CI (POAM-010).
- **No SBOM** — no Software Bill of Materials is generated per build (POAM-006).

---

## Deployment Guidance for Regulated Environments

Before deploying CAGE in a regulated financial environment:

1. **Complete the NIST RMF steps 1–6** — obtain an ATO from an Authorizing Official before processing live customer data
2. **Draft and sign the SSP** — use `compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md` as the scaffold
3. **Set `CAGE_ROUTING_SEAL_SECRET`** — failure to set this in production silently disables governance routing seal enforcement (POAM-012)
4. **Add TLS enforcement** — verify all REST and gRPC endpoints require TLS 1.2+
5. **Enable vulnerability scanning** — add Trivy and pip-audit to your CI pipeline before deploying
4. **Pin all dependencies** — replace `>=` specifiers with exact pinned versions to prevent uncontrolled updates (POAM-013)

---

## References

| Document                            | Location                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Plan of Action & Milestones (POA&M) | [`docs/POAM.md`](POAM.md)                                                                                                                                          |
| NIST RMF Current-State Inventory    | [`docs/NIST_RMF_CHUNK1_CURRENT_STATE.md`](NIST_RMF_CHUNK1_CURRENT_STATE.md)                                                                                        |
| NIST RMF Gap Analysis (Steps 2–5)   | [`docs/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md`](NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md) — [`NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](NIST_RMF_CHUNK5_MONITOR_ROADMAP.md) |
| ISO 42001 Compliance Detail         | [`docs/ISO_42001_COMPLIANCE.md`](ISO_42001_COMPLIANCE.md)                                                                                                          |
| Security Assessment Plan            | [`docs/SECURITY_ASSESSMENT_PLAN.md`](SECURITY_ASSESSMENT_PLAN.md)                                                                                                  |
| Governance Crosswalk                | [`docs/GOVERNANCE_CROSSWALK.md`](GOVERNANCE_CROSSWALK.md)                                                                                                          |
