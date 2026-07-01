# Incident Response Plan — CAGE v0.1.0

**Document:** POAM-008 / NIST SP 800-61r2 / IR-1
**Date:** 2026-06-23
**Status:** Draft — requires AO review and sign-off before POAM-008 closure
**POAM:** POAM-008

---

> [!IMPORTANT]
> This IRP is a **draft** and has not been formally approved by the Authorizing Official (AO). POAM-008 will remain **In Progress** until AO signature is obtained.

---

## 1. Purpose and Scope

This Incident Response Plan (IRP) documents the procedures for detecting, reporting, containing, eradicating, and recovering from security incidents affecting the Cybernetic AI Governance Engine (CAGE). It satisfies NIST SP 800-53 IR-1 (Incident Response Policy and Procedures) and NIST SP 800-61r2.

**In scope:** All CAGE system components including the gateway, compliance bridge, governed financial advisor, vLLM inference service, Langfuse, GKE cluster, and supporting GCP infrastructure.

---

## 2. Incident Categories

### Category A — Governance Bypass

**Description:** A request passes through CAGE governance controls without proper validation (e.g., routing seal bypass, OPA policy skip, CausalGatekeeper unavailability).

**Detection sources:**
- AgentSight eBPF monitoring — process-level policy bypass detection
- Langfuse safety_rate drops below 0.90 threshold
- OTel span missing `iso_control.A.5.2.outcome=PASS` attribute
- `CAGE_SEAL_ENFORCEMENT=disabled` set in non-dev environment

**Severity:** CRITICAL

### Category B — Prompt Injection Attack

**Description:** A user or MCP tool response attempts to override CAGE's governance instructions via prompt injection.

**Detection sources:**
- `detect_prompt_injection()` or `detect_indirect_injection()` alerts in gateway logs
- Langfuse `injection_detected=true` score
- Pattern: `indirect:authority_claim_injection` or `indirect:context_smuggling` in audit trail

**Severity:** HIGH

### Category C — PII Exfiltration Attempt

**Description:** A user or model response attempts to extract PII from the system or transmit customer PII outside the authorized data perimeter.

**Detection sources:**
- `detect_indirect_injection()` `data_exfiltration_probe` pattern match
- Presidio detection score spike in Langfuse traces
- Cilium egress lockdown alert (unauthorized external connection attempt)

**Severity:** HIGH

### Category D — Model Manipulation

**Description:** A supply chain attack targeting model weights, or runtime manipulation of model outputs (e.g., jailbreak sequences bypassing NeMo Guardrails).

**Detection sources:**
- `mirror_models.py` SHA-256 integrity check failure (`supply_chain.model_integrity_verified=false`)
- AgentSight eBPF model weight file modification detection
- Unexpected Lula validation failure for `lula-validation-ai600-confabulation.yaml`

**Severity:** CRITICAL

### Category E — CVE Exploitation

**Description:** Exploitation of a known vulnerability in CAGE dependencies (e.g., CVE-2026-4810 in google-adk, CVE-2025-13462 in libpython3.11).

**Detection sources:**
- Trivy CI scan alert (POAM-006 SBOM workflow)
- GCP Security Command Center vulnerability finding
- pip-audit alert in security-scan.yml

**Severity:** HIGH–CRITICAL depending on CVE CVSS score

### Category F — Compliance Evidence Loss

**Description:** Langfuse compliance project credentials fail, audit traces are dropped, or the OSCAL artifact chain is broken.

**Detection sources:**
- `/health` endpoint returns `langfuse_compliance_configured: false`
- POAM-018 RuntimeError at compliance bridge startup
- `chain_integrity_valid: false` in audit workflow result
- Lula validation failure for any AI600 manifest

**Severity:** HIGH

---

## 3. Incident Response Procedures

### 3.1 Detection and Reporting

| Step | Action | Owner | SLA |
|---|---|---|---|
| 1 | Incident detected by automated monitoring (Lula, AgentSight, Langfuse, Trivy) | Automated | Immediate |
| 2 | Alert fires to PagerDuty / Slack `#cage-incidents` channel | On-call engineer | < 15 min |
| 3 | On-call engineer assesses severity and opens incident ticket | On-call engineer | < 30 min |
| 4 | Incident commander assigned for CRITICAL incidents | Engineering lead | < 1 hr |
| 5 | AO notified for CRITICAL incidents | Incident commander | < 2 hr |

### 3.2 Containment

| Category | Containment Action |
|---|---|
| A (Governance Bypass) | Set `CAGE_SEAL_ENFORCEMENT=enforce`; restart gateway pod; verify routing seal |
| B (Prompt Injection) | Enable `PROMPT_INJECTION_DETECTION_ENABLED=true` if disabled; block source IP via Cilium |
| C (PII Exfiltration) | Enable `LANGFUSE_PII_SCRUBBING_ENABLED=true`; audit recent traces for PII exposure |
| D (Model Manipulation) | Halt model downloads; delete affected model weights; re-download from HuggingFace with verification |
| E (CVE Exploitation) | Apply available patch; if no patch: enable network isolation via Cilium; suppress in `.trivyignore` with documented justification |
| F (Compliance Evidence Loss) | Restart compliance bridge; verify Langfuse credentials; check `/health` endpoint |

### 3.3 Eradication

1. Identify root cause via AgentSight eBPF traces and OTel spans
2. Apply code fix, patch, or configuration remediation
3. Update POAM document with new item if a new weakness is identified
4. Verify fix via Lula validation run

### 3.4 Recovery

1. Restore normal operations after fix is verified
2. Verify Lula audit passes for all AI600 and SC-8 manifests
3. Confirm `chain_integrity_valid: true` in next compliance bridge audit run
4. Close incident ticket with root cause analysis

### 3.5 Post-Incident Review

1. Conduct post-incident review within 5 business days
2. Document lessons learned in `docs/INCIDENT_LOG.md` (create if absent)
3. Update POAM document if a new weakness was identified
4. Brief AO on CRITICAL incidents within 10 business days

---

## 4. Contact Tree

| Role | Contact | Escalation |
|---|---|---|
| On-call engineer | PagerDuty rotation — TBD | Incident commander |
| Incident commander | TBD | AO |
| Authorizing Official (AO) | TBD | N/A |
| Compliance officer | TBD | AO |

> [!NOTE]
> Contact names and PagerDuty policies are organizational information that must be populated before this IRP is signed by the AO.

---

## 5. References

- NIST SP 800-61r2 — Computer Security Incident Handling Guide
- NIST SP 800-53 Rev. 5 IR family controls (IR-1 through IR-10)
- `docs/POAM_US_FED.md` — POAM-008 tracking item
- `deployment/k8s/cilium-egress-lockdown.yaml` — Cilium network policy
- `deployment/agentsight/agentsight-config.yaml` — eBPF monitoring configuration

---

## Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Incident Response Owner | TBD | TBD | TBD |
| Authorizing Official (AO) | TBD | TBD | TBD |
