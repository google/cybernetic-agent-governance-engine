# Security Posture Statement — Plan of Action and Milestones (POAM)

**System:** Cybernetic AI Governance Engine (CAGE)
**Document:** Public Security Posture Statement
**Frameworks:** NIST SP 800-53 Rev. 5, NIST AI 600-1, ISO 42001, EU AI Act, DORA, GDPR, MAS FEAT, MAS TRM, MAS Notice 655
**Last Updated:** 2026-07-27

---

## Purpose

This document is a public transparency statement about the security posture of the Cybernetic Governance Engine (CAGE). It describes the compliance controls being addressed, the frameworks they map to, and the general remediation timeline.

CAGE is an open-source AI governance platform for financial services. It enforces governance policies over multi-agent LLM workflows via a layered pipeline (NeMo Guardrails → OPA → STPA → Control Barrier Function → Consensus → Causal/FRIA). The system is designed for deployment across three regulatory regions: US Federal (`US_FED`), EU ECB (`EU_ECB`), and APAC MAS (`APAC_MAS`).

---

## Compliance Frameworks

| Framework | Scope |
|-----------|-------|
| NIST SP 800-53 Rev. 5 (HIGH baseline) | US Federal deployment |
| NIST AI 600-1 | AI-specific risk controls (all regions) |
| ISO 42001:2023 | AI management system (all regions) |
| EU AI Act | EU ECB deployment |
| DORA (Digital Operational Resilience Act) | EU ECB deployment |
| GDPR Art. 22 | EU ECB deployment |
| MAS FEAT Principles | APAC MAS deployment |
| MAS Notice 655 | APAC MAS deployment |
| MAS TRM Guidelines §6.3 | APAC MAS deployment |

---

## Security Strengths

The following controls are fully implemented and validated via automated Lula compliance assertions:

| Control | Framework | Status |
|---------|-----------|--------|
| AC-2 — Account Management | NIST SP 800-53 | ✅ Implemented |
| AC-3 — Access Enforcement (OPA + NeMo Guardrails) | NIST SP 800-53 | ✅ Implemented |
| AU-12 — Audit Record Generation (OpenTelemetry + Langfuse) | NIST SP 800-53 | ✅ Implemented |
| IA-3 — Device Identification (Linkerd mTLS) | NIST SP 800-53 | ✅ Implemented |
| CM-6 — Configuration Settings (schema-validated thresholds) | NIST SP 800-53 | ✅ Implemented |
| IR-6 — Incident Reporting | NIST SP 800-53 | ✅ Implemented |
| SC-4 — Fiscal Limits / RBAC | NIST SP 800-53 | ✅ Implemented |
| ISO 42001 A.5.2 — Social Impact Assessment | ISO 42001 | ✅ Implemented |
| ISO 42001 A.5.3 — Logging and Monitoring | ISO 42001 | ✅ Implemented |
| ISO 42001 A.9.2 — Data Transfer to Suppliers | ISO 42001 | ✅ Implemented |
| CSA AARM — All 11 threat vectors | CSA AARM | ✅ Implemented |
| NIST AI 600-1 §2.1 — Confabulation controls | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.2 — Data Privacy | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.3 — Prompt Injection | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.5 — Human-AI Configuration | NIST AI 600-1 | ✅ Implemented |

---

## Open Findings

The following findings are tracked as open items with target remediation dates. All findings are captured in the automated Lula compliance validation suite in `compliance/lula/`.

### US Federal Region (US_FED)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| POAM-2026-010 | RA-5 | In-cluster vulnerability scanning CronJob not yet deployed | High | 2026-09-30 |
| POAM-2026-011 | SC-8 | TLS enforcement assertion absent from gateway test suite | Moderate | 2026-09-30 |
| POAM-2026-012 | SC-12 / IA-5 | Cryptographic key rotation schedule not yet documented for routing seal secret | High | 2026-09-30 |
| POAM-2026-013 | SI-2 | Container image tags not yet pinned to digests in all deployment manifests | High | 2026-09-30 |
| POAM-2026-016 | RA-5 / SI-2 | `torch` dev-only dependency carries PYSEC-2026-139; no upstream fix available; dev-only scope, not in production images | Low | 2026-12-31 |
| POAM-2026-023 | RA-5 | CVE-2025-13462 in `libpython3.11` base layer; no Debian bookworm fix available; network egress locked down via Cilium | Critical | 2026-09-08 |
| POAM-2026-024 | CM-6 | Staging environment compliance posture not yet verified against Lula validation suite | Moderate | 2026-09-30 |
| POAM-2026-025 | NIST AI 600-1 §2.6 | CBRN / harmful content Lula validation is a stub pending AO pre-approval for NeMo CBRN rail deployment | High | 2026-12-31 |
| POAM-2026-026 | ISO 42001 A.8.4 | Standalone `token-quota-proxy` Deployment not yet created; TokenQuotaProxy runs inline in gateway | Moderate | 2026-09-30 |
| POAM-2026-029 | CA-7 | `src/compliance_bridge/sla_monitor.py` imports the deprecated flat `EVIDENCE_SLA_SECONDS` alias instead of the region-aware `get_sla_seconds(region)` accessor added to `types.py`; jurisdictional SLA controls (SC-7/SC-8 for US_FED, Article 12 for EU_ECB, MAS-FEAT-1 for APAC_MAS) are not yet monitored for evidence staleness in any region (tracked as FINDING-05 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md`) | Moderate | 2026-09-30 |

### EU ECB Region (EU_ECB)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| EU-DORA-001 | DORA Art. 10 | Compliance bridge endpoint for DORA ICT operational resilience evidence not yet implemented | High | 2026-12-31 |
| EU-AI-ACT-001 | EU AI Act Art. 9 | Compliance bridge endpoint for EU AI Act risk management system evidence not yet implemented | High | 2026-12-31 |
| EU-GDPR-001 | GDPR Art. 22 | Compliance bridge endpoint for GDPR human oversight of automated decisions not yet implemented | High | 2026-12-31 |
| EU-001 | EU AI Act Art. 29a | FRIA gating normative provider is in stub mode; external compliance validation provider not yet configured for EU_ECB | High | 2026-12-31 |

### APAC MAS Region (APAC_MAS)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| APAC-MAS-FEAT-001 | MAS FEAT | Compliance bridge endpoint for MAS FEAT fairness/ethics/accountability/transparency evidence not yet implemented | High | 2026-12-31 |
| APAC-MAS-N655-001 | MAS Notice 655 | Compliance bridge endpoint for MAS Notice 655 technology risk management audit logging not yet implemented | High | 2026-12-31 |
| APAC-MAS-TRM-001 | MAS TRM §6.3 | Compliance bridge endpoint for MAS TRM AI/ML controls evidence not yet implemented | High | 2026-12-31 |

---

## Closed Findings

The following findings have been remediated and verified via Lula validation:

| ID | Control | Description | Closed |
|----|---------|-------------|--------|
| POAM-2026-001 | AC-2 | Account management procedures gap — remediated via named ServiceAccount pattern with `cage.io/account-purpose` labels | 2026-06-08 |
| POAM-2026-007 | IA-3 | No intra-cluster mTLS — remediated via Linkerd service mesh deployment across all `governance-stack` services | 2026-05-17 |
| POAM-2026-023 | CBF / SI-2 | External CBF state reconciliation not implemented — remediated by `src/compliance_bridge/reconciliation_worker.py` (v2.1.0); reconciled balances are KMS-signed before Redis write; CBF fails closed on TTL expiry | 2026-07-27 |
| POAM-2026-027 | Structural | POAM tracking document absent from repository — remediated by creating this document | 2026-06-30 |
| POAM-2026-028 | RA-5 / SI-2 | `langchain` GHSA-gr75-jv2w-4656 and related transitive CVEs — remediated by upgrading to `langchain==1.3.11`, `langsmith==0.9.5`, `python-multipart==0.0.32` | 2026-07-02 |

---

## Lula Validation Coverage

CAGE uses [Lula](https://github.com/defenseunicorns/lula) for compliance-as-code validation. The following manifests are maintained in `compliance/lula/`:

| Manifest | Framework | Control | Region |
|----------|-----------|---------|--------|
| `lula-validation-a52.yaml` | ISO 42001 | A.5.2 Social Impact Assessment | Universal |
| `lula-validation-a53.yaml` | ISO 42001 | A.5.3 Logging and Monitoring | Universal |
| `lula-validation-a92.yaml` | ISO 42001 | A.9.2 Data Transfer to Suppliers | Universal |
| `lula-validation-aarm-vectors.yaml` | CSA AARM | All 11 threat vectors | Universal |
| `lula-validation-iso001-token-quota.yaml` | ISO 42001 | A.4 Token Quota OPA Injection | Universal |
| `lula-validation-tqp007.yaml` | ISO 42001 | A.8.4 TokenQuotaProxy fail-closed | Universal |
| `lula-validation-ac2.yaml` | NIST SP 800-53 | AC-2 Account Management | US_FED |
| `lula-validation-ac3.yaml` | NIST SP 800-53 | AC-3 Access Enforcement | US_FED |
| `lula-validation-au12.yaml` | NIST SP 800-53 | AU-12 Audit Record Generation | US_FED |
| `lula-validation-cm6.yaml` | NIST SP 800-53 | CM-6 Configuration Settings | US_FED |
| `lula-validation-ia3.yaml` | NIST SP 800-53 | IA-3 Device Identification | US_FED |
| `lula-validation-ia5.yaml` | NIST SP 800-53 | IA-5 Authenticator Management | US_FED |
| `lula-validation-ir6.yaml` | NIST SP 800-53 | IR-6 Incident Reporting | US_FED |
| `lula-validation-ra5.yaml` | NIST SP 800-53 | RA-5 Vulnerability Scanning | US_FED |
| `lula-validation-sc4.yaml` | NIST SP 800-53 | SC-4 Fiscal Limits / RBAC | US_FED |
| `lula-validation-sc8.yaml` | NIST SP 800-53 | SC-8 Transmission Confidentiality | US_FED |
| `lula-validation-si2.yaml` | NIST SP 800-53 | SI-2 Flaw Remediation | US_FED |
| `lula-validation-ai600-cbrn.yaml` | NIST AI 600-1 | §2.6 CBRN / Harmful Content | US_FED |
| `lula-validation-ai600-confabulation.yaml` | NIST AI 600-1 | §2.1 Confabulation | US_FED |
| `lula-validation-ai600-data-privacy.yaml` | NIST AI 600-1 | §2.2 Data Privacy | US_FED |
| `lula-validation-ai600-human-ai-config.yaml` | NIST AI 600-1 | §2.5 Human-AI Configuration | US_FED |
| `lula-validation-ai600-prompt-injection.yaml` | NIST AI 600-1 | §2.3 Prompt Injection | US_FED |
| `lula-validation-dora-art10.yaml` | DORA | Art. 10 ICT Resilience | EU_ECB |
| `lula-validation-eu-ai-act-art9.yaml` | EU AI Act | Art. 9 Risk Management | EU_ECB |
| `lula-validation-eu-fria.yaml` | EU AI Act | Art. 29a FRIA Gating | EU_ECB |
| `lula-validation-gdpr-art22.yaml` | GDPR | Art. 22 Automated Decisions | EU_ECB |
| `lula-validation-mas-feat.yaml` | MAS FEAT | Fairness/Ethics/Accountability/Transparency | APAC_MAS |
| `lula-validation-mas-notice655.yaml` | MAS Notice 655 | Technology Risk Management | APAC_MAS |
| `lula-validation-mas-trm-s6.yaml` | MAS TRM | §6.3 AI/ML Controls | APAC_MAS |

---

## Contributing to Remediation

Contributors who wish to help close open findings should:

1. Reference the POAM ID in the commit message (e.g., `fix(compliance): add vulnerability scan CronJob [POAM-2026-010]`)
2. Run `lula validate` against the relevant manifest on a live cluster
3. Update this document with the closure date and commit SHA
4. Update the corresponding OSCAL component in `compliance/oscal/` within 2 business days of merge

See [CONTRIBUTING.md](../CONTRIBUTING.md) and the compliance validation guide in `compliance/lula/` for details.
