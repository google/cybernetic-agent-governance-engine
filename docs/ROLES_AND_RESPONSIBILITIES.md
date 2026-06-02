# Roles and Responsibilities

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
**Reference:** NIST SP 800-37 Rev. 2, NIST SP 800-53 Rev. 5  
**Version:** 1.0 (Draft)  
**Date:** 2026-03-06  
**Status:** DRAFT — Pending AO Approval

---

## 1. Purpose

This document defines the roles and responsibilities for personnel involved in the security authorization and ongoing operation of the Cybernetic AI Governance Engine (CAGE). Role assignments ensure clear accountability for implementing, assessing, and maintaining security controls per the NIST Risk Management Framework (RMF).

---

## 2. Role Definitions

### 2.1 Authorizing Official (AO)

**Role Title:** Authorizing Official  
**Incumbent:** [AO NAME — TBD]  
**Reference:** NIST SP 800-37 Rev. 2 §2.5, Appendix D

**Responsibilities:**

- Accept or deny the risk associated with operating the CAGE system based on the Security Assessment Report (SAR), Plan of Action and Milestones (POA&M), and supporting authorization package artifacts
- Issue or revoke the Authorization to Operate (ATO) letter for the CAGE system
- Approve deviations from the approved security baseline and accept residual risks documented in the POA&M
- Review and approve the System Security Plan (SSP) to confirm it accurately represents system security posture
- Establish and review Ongoing Authorization criteria including frequency of continuous monitoring reviews
- Coordinate with the Common Control Provider (GCP/GKE platform team) on inherited control status
- Make final risk-based decisions when security assessors identify HIGH or CRITICAL findings
- Ensure the system complies with applicable laws, regulations, and organizational policies (SEC Rule 17a-4, FINRA 4511, SR 11-7)

**Accountability:** The AO is personally accountable for the risk decision to authorize CAGE operations. This accountability cannot be delegated.

**Required Qualifications:** Senior organizational official with the authority to accept risk on behalf of the organization; understanding of information security risk management; familiarity with financial services regulatory requirements.

---

### 2.2 Information System Security Officer (ISSO)

**Role Title:** Information System Security Officer  
**Incumbent:** [ISSO NAME — TBD]  
**Reference:** NIST SP 800-37 Rev. 2 §2.5

**Responsibilities:**

- Serve as the primary security point of contact for the CAGE system and coordinate all security activities
- Maintain the System Security Plan (SSP), ensuring it remains current and accurate as the system evolves
- Manage and update the Plan of Action and Milestones (POA&M), tracking remediation of identified security weaknesses
- Coordinate and support security control assessments conducted by the Security Control Assessor (SCA)
- Monitor system security posture through continuous monitoring activities including log review, vulnerability scan triage, and compliance checks
- Report security incidents and coordinate with incident response personnel per the Incident Response Plan (IRP)
- Review and approve configuration changes with security implications; coordinate with Change Management
- Ensure personnel with system access complete required security awareness training
- Maintain the security authorization package (SSP, SAR, POA&M, ATO letter) and track document expiration

**Accountability:** The ISSO is accountable to the System Owner and AO for maintaining the security posture of the CAGE system between authorization cycles.

**Required Qualifications:** Experience with NIST RMF; familiarity with NIST SP 800-53 controls; understanding of financial services security requirements (SEC, FINRA, SR 11-7); preferred certifications: CISSP, CISM, or equivalent.

---

### 2.3 System Owner

**Role Title:** System Owner  
**Incumbent:** [SYSTEM OWNER NAME — TBD]  
**Reference:** NIST SP 800-37 Rev. 2 §2.5

**Responsibilities:**

- Have overall responsibility for the procurement, development, integration, modification, operation, maintenance, and disposal of the CAGE system
- Develop and maintain the System Security Plan (SSP) in coordination with the ISSO
- Ensure the system is operated, maintained, and disposed of in accordance with security policies and procedures
- Coordinate with the ISSO to ensure that security controls are implemented and assessed
- Ensure that system users and support personnel receive required security training
- Authorize and control connections to external systems and information sharing agreements
- Develop and implement a configuration management plan and procedures
- Report security incidents and weaknesses to the ISSO and, as appropriate, to organizational officials

**Accountability:** The System Owner is accountable for ensuring the CAGE system operates within the approved security authorization boundary and that resources are allocated for security activities.

**Required Qualifications:** Understanding of the CAGE system's mission and technical architecture; familiarity with financial services operations and regulatory obligations; authority to commit organizational resources.

---

### 2.4 Common Control Provider — GKE/GCP Platform

**Role Title:** Common Control Provider (CCP)  
**Incumbent:** Google Cloud Platform / GKE Platform Team  
**Reference:** NIST SP 800-37 Rev. 2 §2.5

**Responsibilities:**

- Document, assess, authorize, and monitor security controls that are inherited by the CAGE system (infrastructure-level controls)
- Provide CAGE system owners with access to documentation of inherited controls including control implementation statements, assessment results, and any inherited weaknesses
- Notify CAGE system owners of changes to inherited controls that may impact CAGE's security posture
- Maintain GCP/GKE platform Authorization artifacts (e.g., FedRAMP authorization package) and provide evidence upon request
- Ensure availability of the GKE cluster, Cloud SQL, Cloud Storage, and GCP networking infrastructure per agreed SLAs
- Implement platform-level controls including physical security, hypervisor security, network isolation, and encryption at rest (CMEK) for GCP services
- Provide audit log feeds (Cloud Audit Logs) that supplement CAGE application-level logging

**Accountability:** Google Cloud is accountable for platform-level controls through its FedRAMP authorization and contractual commitments. CAGE inherits these controls and is responsible for system-level controls layered on top.

**Required Qualifications:** GCP-certified infrastructure engineers; familiarity with FedRAMP and NIST SP 800-53 control frameworks.

---

### 2.5 System Administrator

**Role Title:** System Administrator  
**Incumbent:** [SYSADMIN NAME — TBD]  
**Reference:** NIST SP 800-53 Rev. 5 CM, IA control families

**Responsibilities:**

- Manage user accounts, access credentials, and service account configurations for the CAGE system in accordance with AC-2 account management procedures
- Apply operating system, container base image, and Kubernetes patches within required timeframes per the patching policy
- Implement and maintain system configuration baselines; enforce CIS Kubernetes Benchmark and GKE hardening guidelines
- Monitor system health, resource utilization, and availability metrics; respond to infrastructure alerts
- Execute backup and recovery procedures; test disaster recovery capabilities per the Continuity of Operations Plan (COOP)
- Support security control assessments by providing access to configuration artifacts, audit logs, and system inventories
- Maintain the system inventory (CM-8) including container images, Kubernetes manifests, Terraform state, and dependency lockfiles
- Escalate anomalous system behavior to the ISSO per the Incident Response Plan

**Accountability:** The System Administrator is accountable to the System Owner and ISSO for the secure configuration and availability of the CAGE infrastructure.

**Required Qualifications:** GKE/Kubernetes administration experience; familiarity with Terraform IaC; understanding of CIS Benchmarks and container security; preferred: GCP Professional Cloud DevOps Engineer certification.

---

### 2.6 AI Model Operator

**Role Title:** AI Model Operator  
**Incumbent:** [AI OPS NAME — TBD]  
**Reference:** NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE); SR 11-7

**Responsibilities:**

- Monitor AI model performance metrics including inference accuracy, hallucination rates, governance verdict distributions, and STPA validation pass rates via Langfuse dashboards
- Manage model versioning and track model changes; ensure model changes trigger re-assessment per the SR 11-7 model validation process
- Review and tune NeMo Guardrails Colang rail definitions and OPA Rego governance policies in response to observed model behavior
- Investigate and respond to AI model incidents including unexpected governance bypasses, anomalous outputs, and adversarial inputs detected by red-team monitoring
- Maintain documentation of AI model intended use, limitations, and known failure modes as required by SR 11-7
- Coordinate with the ISSO when model changes have security implications (e.g., changes to PII detection thresholds, governance enforcement logic)
- Ensure AI model outputs are traceable to specific model versions via OTel span metadata for audit trail continuity
- Review red-team adversarial test results and coordinate remediation of identified prompt injection or governance bypass vulnerabilities

**Accountability:** The AI Model Operator is accountable to the System Owner for the safe and compliant behavior of AI components within CAGE, aligned with SR 11-7 model risk management requirements.

**Required Qualifications:** Experience with LLM deployment and monitoring; understanding of AI governance frameworks (NIST AI RMF, ISO 42001, SR 11-7); familiarity with Langfuse, OpenTelemetry, and NeMo Guardrails.

---

### 2.7 Compliance Engineer

**Role Title:** Compliance Engineer  
**Incumbent:** [COMPLIANCE ENG NAME — TBD]  
**Reference:** NIST SP 800-53 Rev. 5 CA control family; OSCAL

**Responsibilities:**

- Maintain and update the OSCAL (Open Security Controls Assessment Language) component definition and system security plan artifacts in `compliance/oscal/`
- Operate and maintain the Lula compliance-as-code pipeline; author and update Lula validation specifications for automated control testing
- Generate and review SBOM (Software Bill of Materials) using Trivy; track and report on known vulnerabilities in dependencies
- Maintain the information type registry (`compliance/oscal/information-type-registry.yaml`) and ensure it remains current as the system evolves
- Run automated compliance scans (pip-audit, Trivy, OPA policy tests) and triage findings for POA&M entry
- Coordinate with the ISSO to update the SSP control implementation statements when system changes affect control implementation
- Track regulatory changes (SEC, FINRA, NIST publications) and assess their impact on CAGE compliance posture
- Produce compliance evidence packages for annual assessments and regulatory examinations

**Accountability:** The Compliance Engineer is accountable to the ISSO for maintaining the technical compliance infrastructure and ensuring that the OSCAL/Lula pipeline accurately reflects the system's security posture.

**Required Qualifications:** Experience with OSCAL, NIST SP 800-53, and compliance automation tools; familiarity with SAST/DAST and vulnerability management; Python proficiency for Lula/compliance tooling; knowledge of financial services regulatory requirements.

---

## 3. RACI Matrix

The following RACI matrix defines Responsible (R), Accountable (A), Consulted (C), and Informed (I) roles for key security activities.

**Role Abbreviations:**

- **AO** — Authorizing Official
- **ISSO** — Information System Security Officer
- **SO** — System Owner
- **CCP** — Common Control Provider (GCP/GKE)
- **SA** — System Administrator
- **AMO** — AI Model Operator
- **CE** — Compliance Engineer

| Security Activity                         | AO  | ISSO | SO  | CCP | SA  | AMO | CE  |
| ----------------------------------------- | --- | ---- | --- | --- | --- | --- | --- |
| **Security Categorization** (FIPS 199)    | A   | R    | C   | I   | I   | I   | C   |
| **SSP Maintenance**                       | A   | R    | C   | C   | C   | C   | R   |
| **Control Assessment** (CA-2, CA-7)       | A   | C    | I   | C   | C   | C   | R   |
| **POA&M Management** (CA-5)               | I   | A    | C   | I   | R   | R   | R   |
| **Incident Response** (IR-1 through IR-9) | I   | A    | C   | C   | R   | R   | C   |
| **Continuous Monitoring** (CA-7)          | A   | R    | I   | C   | R   | R   | R   |
| **Change Management** (CM-3)              | I   | C    | A   | I   | R   | R   | C   |
| **ATO Decision**                          | A   | C    | C   | I   | I   | I   | I   |
| **Vulnerability Scanning** (RA-5)         | I   | A    | I   | C   | R   | I   | R   |
| **AI Model Risk Management** (SR 11-7)    | I   | C    | A   | I   | I   | R   | C   |
| **SBOM Generation** (CM-8)                | I   | I    | I   | I   | R   | I   | R   |
| **OSCAL/Lula Pipeline**                   | I   | C    | I   | I   | I   | I   | A/R |
| **User Access Reviews** (AC-2)            | I   | A    | C   | I   | R   | I   | I   |
| **Patch Management** (SI-2)               | I   | A    | C   | C   | R   | I   | I   |
| **Security Awareness Training** (AT-2)    | I   | A    | R   | I   | I   | I   | I   |

**RACI Key:**

- **R** = Responsible (does the work)
- **A** = Accountable (ultimately answerable; signs off)
- **C** = Consulted (provides input)
- **I** = Informed (kept in the loop)

---

