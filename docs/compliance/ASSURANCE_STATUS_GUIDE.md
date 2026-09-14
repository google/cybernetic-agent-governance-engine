# CAGE Assurance Status Guide

**Version:** 3.1.5  
**Status:** Authoritative  
**Last Modified:** 2026-09-14

## Purpose

This document establishes the **single source of truth** for CAGE's legal and audit boundaries. It defines the four-stage assurance lifecycle, regulatory disclaimers, and attestation boundaries applicable to all OSCAL SSP exports.

## Executive Summary

**CAGE is an illustrative reference architecture for AI governance systems.** It demonstrates governance patterns, control structures, and compliance frameworks for adopters to adapt to their own production environments.

CAGE does **NOT** constitute:
- A formal FedRAMP Authority to Operate (ATO)
- An EU CE Mark conformity assessment
- A BSI ISO/IEC 42001:2023 certification
- A Monetary Authority of Singapore (MAS) approval

Organizations adopting this architecture must conduct their own conformity assessments and obtain applicable regulatory approvals for production deployments.

## Four-Stage Assurance Lifecycle

### Stage 1: `ILLUSTRATIVE_REFERENCE` (Current)

**Definition:** No production deployment exists. CAGE is a reference implementation demonstrating governance patterns for adopters to customize.

**Attestation Boundary:** `CODEBASE_SYNTHETIC_EVALUATION`
- Evidence derived from test suites, Lula validations, and synthetic workloads
- No live user traffic or operational telemetry
- Suitable for architecture review and pre-deployment planning

**Regulatory Context:**
- No FedRAMP ATO claimed or implied (US_FED)
- No CE Mark conformity assessment completed (EU_ECB)
- No MAS approval granted (APAC_MAS)
- No UK DSIT registration active (UK_DSIT, future)

**OSCAL SSP Metadata:**
```yaml
props:
  - name: assurance_status
    value: ILLUSTRATIVE_REFERENCE
  - name: attestation_boundary
    value: CODEBASE_SYNTHETIC_EVALUATION
  - name: disclaimer
    value: "This System Security Plan represents an illustrative reference architecture for AI governance systems..."
```

**Permitted Claims:**
- ✅ "Demonstrates control implementation patterns aligned with ISO/IEC 42001:2023"
- ✅ "Provides reference OSCAL artifacts for FedRAMP SSP construction"
- ✅ "Illustrates EU AI Act technical compliance pathways"
- ❌ "Certified to ISO/IEC 42001:2023" (requires BSI audit)
- ❌ "FedRAMP Moderate ATO granted" (requires 3PAO assessment + FedRAMP PMO authorization)
- ❌ "CE Mark conformity assessment complete" (requires Notified Body audit for high-risk AI systems)

---

### Stage 2: `SELF_ASSESSED_PRE_DEPLOYMENT`

**Definition:** Internal self-assessment complete; no live deployment. Suitable for pre-deployment verification and internal staging environments.

**Attestation Boundary:** `CODEBASE_SYNTHETIC_EVALUATION`
- All Stage 1 evidence sources remain valid
- Internal security review and control testing completed
- No third-party assessment initiated

**Transition Requirements:**
1. Complete internal security review against target framework (FedRAMP, ISO 42001, EU AI Act, MAS FEAT)
2. Generate full OSCAL SSP with implemented controls documented
3. Execute Lula validation suite with 100% pass rate
4. Document all POAM items with remediation timelines

**OSCAL SSP Metadata:**
```yaml
props:
  - name: assurance_status
    value: SELF_ASSESSED_PRE_DEPLOYMENT
  - name: attestation_boundary
    value: CODEBASE_SYNTHETIC_EVALUATION
  - name: self_assessment_date
    value: "YYYY-MM-DDTHH:MM:SSZ"
```

---

### Stage 3: `OPERATIONAL_STAGING`

**Definition:** Live staging deployment with operational telemetry, but not yet subject to third-party assessment. Suitable for beta environments and pre-production validation.

**Attestation Boundary:** `OPERATIONAL_DEPLOYMENT`
- Live Langfuse traces from staging environment
- Real-time control telemetry (A.5.2, A.5.3, A.9.2, SC-4)
- SLA breach monitoring active
- No production user data; synthetic or test workloads only

**Transition Requirements:**
1. Deploy to staging environment (GKE dev cluster, staging namespace)
2. Configure Langfuse telemetry with regional data residency
3. Establish SLA monitoring and alerting
4. Collect 30+ days of operational telemetry
5. Demonstrate control effectiveness with live metrics

**OSCAL SSP Metadata:**
```yaml
props:
  - name: assurance_status
    value: OPERATIONAL_STAGING
  - name: attestation_boundary
    value: OPERATIONAL_DEPLOYMENT
  - name: staging_deployment_date
    value: "YYYY-MM-DDTHH:MM:SSZ"
  - name: telemetry_window_days
    value: "30"
```

**Regulatory Context:**
- US_FED: Suitable for pre-ATO readiness assessment (3PAO readiness review)
- EU_ECB: Suitable for internal Article 13 transparency validation (pre-Notified Body)
- APAC_MAS: Suitable for MAS FEAT Principle 1-4 self-assessment (pre-submission)

---

### Stage 4: `THIRD_PARTY_ASSESSED`

**Definition:** Production deployment with completed third-party assessment. Requires attestation evidence and certificate URL.

**Attestation Boundary:** `OPERATIONAL_DEPLOYMENT`
- All Stage 3 evidence sources
- Third-party assessment report (3PAO SAR, BSI audit, Notified Body opinion, MAS validation)
- Certificate of compliance or authorization letter
- Continuous monitoring and annual re-assessment commitment

**Transition Requirements:**

**US_FED (FedRAMP ATO):**
1. Engage FedRAMP-accredited 3PAO
2. Complete Security Assessment Report (SAR)
3. Obtain FedRAMP PMO Authorization to Operate (ATO)
4. Publish ATO letter to FedRAMP Marketplace
5. Implement continuous monitoring (AU-2, SI-7, monthly POA&M updates)

**EU_ECB (EU AI Act High-Risk AI System):**
1. Engage EU Notified Body for conformity assessment
2. Complete technical documentation per Annex IV
3. Obtain EU Declaration of Conformity
4. Affix CE Mark to system documentation
5. Register with EU AI Office database (Art. 49)

**APAC_MAS (MAS FEAT Compliance):**
1. Complete MAS FEAT self-assessment toolkit
2. Submit to MAS for validation (if applicable under Notice 655)
3. Obtain MAS approval letter (for regulated financial institutions)
4. Implement MAS TRM Section 14 controls

**UK_DSIT (Future):**
1. Register with UK AI Safety Institute (AISI)
2. Complete UK AI Assurance Roadmap requirements
3. Obtain DSIT attestation (when framework published)

**OSCAL SSP Metadata:**
```yaml
props:
  - name: assurance_status
    value: THIRD_PARTY_ASSESSED
  - name: attestation_boundary
    value: OPERATIONAL_DEPLOYMENT
  - name: third_party_certificate_url
    value: "https://marketplace.fedramp.gov/products/PRXXXXXXXX" # Example for US_FED
  - name: assessment_date
    value: "YYYY-MM-DDTHH:MM:SSZ"
  - name: assessor
    value: "[3PAO Name] / [Notified Body Name] / [MAS]"
  - name: certificate_expiry
    value: "YYYY-MM-DDTHH:MM:SSZ"
```

---

## Regulatory Context by Jurisdiction

### US_FED: FedRAMP / NIST SP 800-53

**Applicable Frameworks:**
- FedRAMP HIGH baseline (325 controls)
- NIST SP 800-53 Rev 5
- NIST AI 600-1 (Artificial Intelligence Risk Management Framework)

**Assurance Pathway:**
1. ILLUSTRATIVE_REFERENCE → document SSP against FedRAMP HIGH
2. SELF_ASSESSED_PRE_DEPLOYMENT → internal security review complete
3. OPERATIONAL_STAGING → 3PAO readiness assessment
4. THIRD_PARTY_ASSESSED → FedRAMP ATO granted by PMO

**Key Controls:**
- AC-2, AC-4, AU-2, IR-1, SA-11, SC-7, SC-8, SI-7, SI-10

**Evidence Sources:**
- Lula OSCAL validations ([`compliance/lula/`](../../compliance/lula/))
- STPA compiler output ([`config/stpa_control_structure.yaml`](../../config/stpa_control_structure.yaml))
- Langfuse traces (control telemetry)
- AgentSight syscall audits (AU-2, SI-7)

---

### EU_ECB: EU AI Act / GDPR / DORA

**Applicable Frameworks:**
- EU AI Act (Regulation 2024/1689) — High-Risk AI System (Annex III)
- GDPR (Regulation 2016/679) — Data Protection
- DORA (Regulation 2022/2554) — Digital Operational Resilience (financial sector)

**Assurance Pathway:**
1. ILLUSTRATIVE_REFERENCE → document technical file per Annex IV
2. SELF_ASSESSED_PRE_DEPLOYMENT → internal FRIA (Fundamental Rights Impact Assessment)
3. OPERATIONAL_STAGING → beta deployment with Article 13 transparency
4. THIRD_PARTY_ASSESSED → Notified Body conformity assessment + CE Mark

**Key Controls:**
- Article 12 (Record-Keeping), Article 13 (Transparency & Human Oversight)
- ISO/IEC 42001:2023 A.5.2, A.5.3, A.9.2 (universal)

**Evidence Sources:**
- FRIA attestation ([`docs/compliance/eu_ecb/FRIA_ATTESTATION.md`](eu_ecb/FRIA_ATTESTATION.md))
- GDPR DPIA ([`docs/compliance/eu_ecb/GDPR_DPIA.md`](eu_ecb/GDPR_DPIA.md))
- DORA resilience testing ([`docs/compliance/eu_ecb/DORA_RESILIENCE_TESTING_PROGRAMME.md`](eu_ecb/DORA_RESILIENCE_TESTING_PROGRAMME.md))

---

### APAC_MAS: MAS FEAT / MAS Notice 655

**Applicable Frameworks:**
- MAS FEAT (Fairness, Ethics, Accountability, Transparency)
- MAS Notice 655 (Technology Risk Management)
- MAS TRM Section 14 (AI/ML Governance)

**Assurance Pathway:**
1. ILLUSTRATIVE_REFERENCE → document MAS FEAT self-assessment
2. SELF_ASSESSED_PRE_DEPLOYMENT → complete FEAT toolkit
3. OPERATIONAL_STAGING → pilot deployment with fairness monitoring
4. THIRD_PARTY_ASSESSED → MAS validation (if regulated entity)

**Key Controls:**
- MAS-FEAT-1 (Fairness Assessment)
- ISO/IEC 42001:2023 A.5.2, A.5.3, A.9.2 (universal)

**Evidence Sources:**
- MAS FEAT transparency report ([`docs/compliance/apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md`](apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md))
- Notice 655 certification ([`docs/compliance/apac_mas/MAS_NOTICE_655_CERTIFICATION.md`](apac_mas/MAS_NOTICE_655_CERTIFICATION.md))

---

### UK_DSIT: UK AI Safety Institute (Future)

**Status:** Placeholder. UK AI Assurance Roadmap not yet published.

**Anticipated Framework:**
- UK AI Regulation (expected 2027)
- UK AI Safety Institute (AISI) registration
- UK DSIT attestation framework

**Assurance Pathway:** TBD (to be populated in Sprint 2)

---

## Implementation Notes

### OSCAL SSP Exporter Integration

The [`oscal_ssp_exporter`](../../src/gateway/governance/oscal_ssp_exporter.py) module injects `AssurancePosture` metadata into every SSP export via `_build_metadata()`:

```python
from src.compliance_bridge.types import AssurancePosture

posture = AssurancePosture()  # Defaults to ILLUSTRATIVE_REFERENCE
metadata = _build_metadata(region="US_FED")
# metadata["props"] includes assurance_status, attestation_boundary, disclaimer
```

### Transition Checklist

Before advancing to the next assurance stage:

- [ ] Review current stage exit criteria
- [ ] Update OSCAL SSP metadata props
- [ ] Re-export SSPs for all active regions (`make oscal-export`)
- [ ] Run Lula validation suite (`make lula-validate`)
- [ ] Update POAM with new assurance status
- [ ] Notify stakeholders of status change

---

## References

- [ISO/IEC 42001:2023 Compliance](universal/ISO_42001_COMPLIANCE.md)
- [NIST AI 600-1 Implementation Plan](us_fed/AI_600_1_IMPLEMENTATION_PLAN.md)
- [EU AI Office Registration](eu_ecb/EU_AI_OFFICE_REGISTRATION.md)
- [MAS FEAT Transparency Report](apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md)
- [CAGE Architecture Overview](../architecture/ARCHITECTURE.md)
- [POAM Index](cross-region/POAM_INDEX.md)

---

**Document Control:**
- **Owner:** CAGE Compliance Team
- **Review Cycle:** Quarterly or upon assurance status change
- **Next Review:** 2026-12-14
