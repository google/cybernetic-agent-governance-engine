# Incident Response Plan (IRP)

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Document Number:** IRP-CAGE-2026-001
**Reference:** ISO/IEC 42001:2023 §A.10.1 (Universal Baseline); NIST SP 800-61 Rev. 2 (US_FED); DORA Art. 17–23 (EU_ECB); MAS TRM §11 (APAC_MAS)
**Version:** 1.2 (Draft)
**Date:** 2026-06-15
**Classification:** UNCLASSIFIED
**Status:** DRAFT — Pending AO Approval
**Resolves:** POAM-008 (IR-1: No Incident Response Plan)

> **v0.1.0 Release Note (2026-06-08):** CAGE v0.1.0 has been released as a stable tag. All IRT role incumbents remain `[TBD]` pending organizational action. The ATO process has been initiated (Sprint 3). This IRP remains in DRAFT status until the AO approves it and role incumbents are named. The `docs/POAM.md` reference in the table below has been superseded — see [`docs/POAM_INDEX.md`](../compliance/cross-region/POAM_INDEX.md) for the current multi-posture POAM structure.

| Field                     | Value                                                                                                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System Name               | Cybernetic AI Governance Engine (CAGE)                                                                                                                                                |
| System Abbreviation       | CAGE                                                                                                                                                                                  |
| ISSO                      | [ISSO NAME — TBD]                                                                                                                                                                     |
| IRT Lead                  | [IRT LEAD NAME — TBD]                                                                                                                                                                 |
| Authorizing Official (AO) | [AO NAME — TBD]                                                                                                                                                                       |
| Related Documents         | `docs/POAM_INDEX.md` (supersedes `docs/POAM.md`), `compliance/sar/SAR_2026Q1.md`, `compliance/rar/RISK_ASSESSMENT_REPORT.md`, `docs/ROLES_AND_RESPONSIBILITIES.md`, `compliance/continuous-monitoring/ISCM_STRATEGY.md` |

---

## 1. Purpose and Scope

### 1.1 Universal Baseline (ISO 42001 A.10.1)

> **Scope: Universal — applies to ALL `CAGE_DEPLOYMENT_REGION` values (US_FED, EU_ECB, APAC_MAS)**

This Incident Response Plan (IRP) is grounded in **ISO/IEC 42001:2023 §A.10.1** (AI management system — continual improvement and incident management) as the universal baseline applicable to all CAGE deployments regardless of jurisdiction. All three regional deployments share the same core incident lifecycle: Detect → Analyze → Contain → Eradicate → Recover → Learn.

The universal baseline requires:
- Documented incident categories and severity levels (Section 2)
- Defined roles and responsibilities for incident response (Section 3)
- Detection sources covering AI-specific incident types (Section 4)
- Containment, eradication, and recovery procedures (Section 5)
- Post-incident review and continual improvement (Section 7)

### 1.2 Jurisdictional Extensions

The following jurisdiction-specific frameworks extend the universal baseline. Each adds notification obligations and regulatory reporting requirements **on top of** the ISO 42001 foundation:

#### US_FED (CAGE_DEPLOYMENT_REGION=US_FED)

> **Scope: US_FED only**

- **NIST SP 800-61 Rev. 2** — Computer Security Incident Handling Guide
- **NIST SP 800-53 Rev. 5** — IR Control Family (IR-1 through IR-9)
- **NIST SP 800-37 Rev. 2** — Risk Management Framework
- **SR 26-2** (Federal Reserve) — AI model risk governance escalation

#### EU_ECB (CAGE_DEPLOYMENT_REGION=EU_ECB)

> **Scope: EU_ECB only**

- **DORA Art. 17–23** — ICT-related incident classification, reporting, and management
- **DORA Art. 19** — Major ICT incident notification to competent authority within 4 hours
- **GDPR Art. 33** — Personal data breach notification to supervisory authority within 72 hours
- **EU AI Act Art. 62** — Serious incident reporting for high-risk AI systems

#### APAC_MAS (CAGE_DEPLOYMENT_REGION=APAC_MAS)

> **Scope: APAC_MAS only**

- **MAS TRM §11** — Technology risk incident management
- **MAS TRM §11.3** — MAS notification within 1 hour for P1 incidents
- **MAS Notice 655** — Audit logging and incident record retention requirements

### 1.3 Purpose

This IRP establishes the policies, procedures, and responsibilities for detecting, analyzing, containing, eradicating, and recovering from security incidents affecting the Cybernetic AI Governance Engine (CAGE).

This document directly resolves POAM-008 (IR-1: No Incident Response Plan) identified in `docs/POAM.md` and the associated finding FIND-006 in `compliance/sar/SAR_2026Q1.md`.

### 1.2 Scope

This IRP applies to:

- All components within the CAGE authorization boundary (see `compliance/boundary/AUTHORIZATION_BOUNDARY.md`)
- All personnel with access to CAGE system components, data, or infrastructure
- All security incidents that affect the confidentiality, integrity, or availability of CAGE information types (IT-001 through IT-005)
- AI/ML-specific incidents unique to the CAGE architecture, including governance bypass events, prompt injection attacks, model manipulation, and PII exfiltration via AI outputs

### 1.5 Scope

This IRP applies to:

- All components within the CAGE authorization boundary (see `compliance/boundary/AUTHORIZATION_BOUNDARY.md`)
- All personnel with access to CAGE system components, data, or infrastructure
- All security incidents that affect the confidentiality, integrity, or availability of CAGE information types (IT-001 through IT-005)
- AI/ML-specific incidents unique to the CAGE architecture, including governance bypass events, prompt injection attacks, model manipulation, and PII exfiltration via AI outputs

### 1.6 AI-Specific Incident Considerations

CAGE presents incident response challenges not covered by traditional IR frameworks:

- **Governance Bypass Events:** Adversarial inputs may circumvent the 5-tier neuro-symbolic governance pipeline, resulting in unauthorized trade recommendations or disabled safety controls
- **Prompt Injection Attacks:** Malicious inputs may manipulate LLM behavior to exfiltrate data, produce harmful outputs, or subvert governance policies
- **Model Manipulation:** Changes to LLM model versions, NeMo Guardrails rails, or OPA Rego policies may introduce undetected behavioral changes
- **AI Evidence Chain Integrity:** Incidents may involve tampering with ISO 42001 audit trail evidence (Langfuse traces), complicating post-incident analysis

### 1.7 HITL SLA by Jurisdiction

> **US_FED Only:** The SR 26-2 §3.2 Human-in-the-Loop (HITL) SLA of **4 hours** applies exclusively to `CAGE_DEPLOYMENT_REGION=US_FED` deployments. This is a US Federal Reserve supervisory requirement with no legal force in EU or APAC jurisdictions (see `.clinerules` §12.4).

| Jurisdiction | HITL SLA Authority | Maximum HITL Response Time |
| ------------ | ------------------ | -------------------------- |
| **US_FED** | SR 26-2 §3.2 | **4 hours** |
| **EU_ECB** | DORA Art. 10 (ICT risk management) | Per DORA operational resilience requirements |
| **APAC_MAS** | MAS FEAT §3.2 | Per MAS FEAT accountability requirements |

### 1.4 Regulatory Context

Incident response for CAGE is subject to the following regulatory notification requirements, organized by jurisdiction:

#### Universal (ISO 42001 A.10.1 — all regions)

| Regulation | Incident Type | Notification Requirement |
| ---------- | ------------- | ------------------------ |
| ISO 42001 A.10.1 | Any AI system incident affecting governance controls | Internal incident log; post-incident review within 15 business days |

#### US_FED (CAGE_DEPLOYMENT_REGION=US_FED)

> **Scope: US_FED only**

| Regulation                | Incident Type                                              | Notification Requirement                                                         |
| ------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------- |
| SEC Reg S-P               | PII breach affecting customer financial data (IT-004)      | Timely notification to affected individuals; regulatory notification as required |
| FINRA Rules               | Broker-dealer operational incident affecting trade records | Notification per FINRA Rule 4370 Business Continuity requirements                |
| SR 11-7 (Federal Reserve) | AI model failure or material governance breach             | Escalation to model risk management governance                                   |
| SEC Rule 17a-4            | Destruction or loss of required audit records (IT-003)     | Preservation obligation; report to SEC if records cannot be recovered            |
| CISA                      | Significant cyber incident                                 | Notification within 72 hours per CIRCIA requirements                             |

#### EU_ECB (CAGE_DEPLOYMENT_REGION=EU_ECB)

> **Scope: EU_ECB only**

| Regulation | Incident Type | Notification Requirement | Timeframe |
| ---------- | ------------- | ------------------------ | --------- |
| DORA Art. 19 | Major ICT-related incident | Notify competent authority (ECB/NCA) | **Within 4 hours** of classification as major |
| DORA Art. 19 | Major ICT-related incident — intermediate report | Update to competent authority | **Within 72 hours** of initial notification |
| DORA Art. 19 | Major ICT-related incident — final report | Root cause analysis to competent authority | **Within 1 month** of incident closure |
| GDPR Art. 33 | Personal data breach | Notify supervisory authority (DPA) | **Within 72 hours** of becoming aware |
| GDPR Art. 34 | High-risk personal data breach | Notify affected data subjects | **Without undue delay** |
| EU AI Act Art. 62 | Serious incident involving high-risk AI system | Notify market surveillance authority | **Immediately upon becoming aware** |

#### APAC_MAS (CAGE_DEPLOYMENT_REGION=APAC_MAS)

> **Scope: APAC_MAS only**

| Regulation | Incident Type | Notification Requirement | Timeframe |
| ---------- | ------------- | ------------------------ | --------- |
| MAS TRM §11.3 | P1 technology incident (system unavailability or data breach) | Notify MAS | **Within 1 hour** of discovery |
| MAS TRM §11.3 | P2 technology incident | Notify MAS | **Within 24 hours** of discovery |
| MAS Notice 655 | Audit log integrity incident | Preserve all records; notify MAS if records cannot be recovered | **Immediately** |
| MAS FEAT | AI fairness or accountability incident | Internal escalation to model risk committee | **Within 24 hours** |

---

## 2. Incident Categories and Severity Levels

### 2.1 Incident Category Definitions

| Category       | Severity     | Description                                                                                                                                           | Examples                                                                                                                                                                                                                       |
| -------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Category 1** | **Critical** | Incidents with actual or imminent catastrophic impact to CAGE mission, data integrity, or regulatory posture; immediate executive escalation required | AI governance pipeline bypass confirmed; active data exfiltration of PII (IT-004) in progress; system-wide compromise; ransomware; complete loss of governance enforcement                                                     |
| **Category 2** | **High**     | Incidents with significant impact to security controls or data; AO notification within 24 hours; IRT immediate activation                             | OPA policy engine failure resulting in unenforced governance; authentication bypass (mTLS/HMAC compromise); confirmed PII leak from AI output; unauthorized modification of governance policies; Loss of AgentSight monitoring |
| **Category 3** | **Moderate** | Incidents with meaningful operational impact but no confirmed data breach; remediation required within 72 hours                                       | System performance degradation affecting governance SLA; configuration drift detected by Lula; anomalous AI output patterns without confirmed exfiltration; single component failure with failover active                      |
| **Category 4** | **Low**      | Minor anomalies, non-critical alerts, or informational events requiring documentation but no immediate action                                         | Non-critical Lula validation failures; minor performance degradation; informational AgentSight alerts; single failed login attempt                                                                                             |

### 2.2 AI-Specific Incident Categories

| AI Incident Type                | Severity      | Detection Source                                                          | Description                                                                                   |
| ------------------------------- | ------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Governance Pipeline Bypass      | Critical      | AgentSight eBPF; OTel traces; Langfuse anomalies                          | AI output bypasses NeMo → OPA → STPA → OFAC chain; governance verdict absent from audit trail |
| Prompt Injection Attack         | High–Critical | NeMo Guardrails alerts; Langfuse trace analysis; output anomaly detection | Adversarial input manipulates LLM to produce unauthorized output or extract protected data    |
| PII Exfiltration via LLM Output | Critical      | NeMo PII detection events; Langfuse output analysis                       | PII (IT-004) present in AI-generated response that should have been scrubbed                  |
| OPA Policy Tampering            | High          | Git audit; OSCAL validation; Lula CI failures                             | Unauthorized modification to Rego policies (`.rego` files) in `governance/policy/`            |
| Model Version Drift             | Moderate      | Langfuse model version tracking; SR 11-7 model audit                      | Production LLM model version changed without documented change management                     |
| Audit Trail Compromise          | High          | Compliance Bridge; Langfuse integrity checks                              | ISO 42001 evidence stamps missing, corrupted, or inconsistent with inference events           |

---

## 3. Roles and Responsibilities

### 3.1 Incident Response Team (IRT)

| IRT Role                    | Incumbent         | Primary Responsibilities                                                                                    | Notification Priority              |
| --------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **IRT Lead**                | [IRT LEAD — TBD]  | Overall incident coordination; escalation decisions; AO notification; media/legal coordination              | 1st (always notified)              |
| **ISSO**                    | [ISSO NAME — TBD] | Security analysis and containment decisions; POA&M updates; regulatory coordination; evidence preservation  | 1st (always notified)              |
| **CISO**                    | [CISO NAME — TBD] | Executive escalation; regulatory notification decisions; external communications authorization              | Category 1 & 2 incidents           |
| **System Administrator**    | [SYSADMIN — TBD]  | Technical containment (isolate components, revoke credentials); system recovery; log preservation           | Category 1, 2, 3 incidents         |
| **AI Model Operator**       | [AI OPS — TBD]    | AI-specific incident analysis; governance pipeline investigation; NeMo/OPA policy integrity verification    | AI-specific incidents              |
| **Legal / Compliance**      | [LEGAL — TBD]     | Regulatory notification decisions (SEC Reg S-P, FINRA); legal hold on evidence; external counsel engagement | Category 1 incidents; PII breaches |
| **Cloud/Platform Engineer** | [CLOUD ENG — TBD] | GKE/GCP infrastructure isolation; IAM credential revocation; network policy enforcement                     | Category 1 & 2 incidents           |

### 3.2 IRT Activation Criteria

The IRT is activated when:

- A Category 1 or Category 2 incident is confirmed or credibly suspected
- AgentSight eBPF generates a Critical-severity alert
- Lula compliance validation reports a Critical control failure
- Any unauthorized modification to OPA Rego policies or NeMo Guardrails rails is detected
- Any confirmed or suspected PII exfiltration event occurs

For Category 3 and 4 incidents, the ISSO may handle the response without full IRT activation, escalating if the incident severity increases.

---

## 4. Detection and Analysis Procedures

### 4.1 Detection Sources

The CAGE system employs the following detection sources, aligned with the monitoring strategy in `compliance/continuous-monitoring/ISCM_STRATEGY.md`:

| Detection Source               | Component                    | Incident Types Detected                                                                              | Alert Mechanism                                   |
| ------------------------------ | ---------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **AgentSight eBPF**            | `deployment/agentsight/`     | Container escape; unauthorized system calls; kernel-level anomalies; process injection               | eBPF alert → Slack/PagerDuty                      |
| **OpenTelemetry / Langfuse**   | Compliance Bridge → Langfuse | Governance verdict anomalies; missing audit stamps; AI output anomalies; trace integrity failures    | Langfuse alert rules → Slack                      |
| **Lula Compliance Validation** | `compliance/lula/`           | Control validation failures (AU-12, AC-3, RA-5, CM-6); policy drift                                  | CI pipeline failure → GitHub Actions notification |
| **OPA Policy Engine**          | `COMP-003`                   | Policy enforcement failures; unauthorized access attempts; governance bypass attempts                | OPA decision log → Langfuse                       |
| **NeMo Guardrails**            | `COMP-002`                   | Prompt injection attempts; PII detection events; rail violations                                     | NeMo event log → OTel pipeline                    |
| **Cloud Audit Logs (GCP)**     | GCP platform                 | Unauthorized IAM changes; secret access; resource modification; admin activity                       | Cloud Logging alerts → Slack                      |
| **GitHub Actions CI/CD**       | `COMP-012`                   | Pipeline failures; security scan failures (Trivy, pip-audit); unauthorized PR merges to policy files | GitHub Actions notification                       |
| **Kubernetes Events**          | GKE cluster                  | Pod failures; OOM kills; scheduling anomalies; unauthorized namespace access                         | GKE monitoring → Cloud Logging                    |

### 4.2 Detection Thresholds

| Alert Level  | AgentSight                                   | Langfuse                                    | Lula                                      | Action Required                                      |
| ------------ | -------------------------------------------- | ------------------------------------------- | ----------------------------------------- | ---------------------------------------------------- |
| **Critical** | Kernel exploit attempt; privilege escalation | Governance bypass confirmed; PII in output  | HIGH/CRITICAL control failure             | Immediate IRT activation; AO notification            |
| **High**     | Anomalous syscall pattern                    | Missing audit stamps; trace integrity error | Moderate control failure with HIGH impact | ISSO assessment within 1 hour; IRT activation likely |
| **Moderate** | Elevated resource consumption                | Output anomaly pattern                      | Minor validation failure                  | ISSO review within 4 hours; document in POA&M        |
| **Low**      | Informational telemetry                      | Performance metric deviation                | Informational finding                     | Log and review in next daily review cycle            |

### 4.3 Incident Analysis Checklist

Upon receiving an alert or incident report, the ISSO or IRT Lead shall perform the following analysis:

**Step 1: Initial Triage (within 15 minutes)**

- [ ] Verify alert authenticity (rule out false positive)
- [ ] Identify affected CAGE component(s) and information types
- [ ] Assign preliminary incident category (1–4)
- [ ] Log incident in incident tracker with timestamp, description, and initial category
- [ ] Activate IRT if Category 1 or 2

**Step 2: Scope Determination (within 1 hour)**

- [ ] Identify all affected systems within the CAGE boundary
- [ ] Determine if external systems (Langfuse, vLLM, market data provider) are affected
- [ ] Identify affected information types (IT-001 through IT-005) — is PII (IT-004) involved?
- [ ] Determine if governance pipeline integrity is compromised
- [ ] Collect initial evidence (logs, OTel traces, AgentSight captures)
- [ ] Determine if audit trail (IT-003) is intact or compromised

**Step 3: Impact Assessment (within 2 hours)**

- [ ] Assess confidentiality impact: Is PII or financial data exposed?
- [ ] Assess integrity impact: Are trade data or AI outputs corrupted?
- [ ] Assess availability impact: Is governance enforcement disabled?
- [ ] Determine if incident triggers regulatory notification (SEC Reg S-P, FINRA)
- [ ] Update incident category based on analysis
- [ ] Document preliminary findings in incident report

**Step 4: AI-Specific Analysis (if AI incident suspected)**

- [ ] Review Langfuse trace for governance pipeline execution completeness
- [ ] Verify NeMo Guardrails verdict log for the affected inference session
- [ ] Verify OPA policy evaluation log for the affected request
- [ ] Check ISO 42001 evidence stamps for completeness and integrity
- [ ] Review AgentSight eBPF data for anomalous process behavior during incident window
- [ ] Verify OPA Rego policy files against last known-good Git commit hash
- [ ] Verify NeMo Guardrails Colang rails against last known-good state

---

## 5. Containment, Eradication, and Recovery Procedures

### 5.1 Containment Strategies by Category

#### Category 1 (Critical) — Containment

**Objective:** Immediately stop ongoing harm; preserve evidence; prevent lateral movement.

**Actions (within 30 minutes of Category 1 determination):**

1. **Network Isolation:** Apply emergency NetworkPolicy to isolate affected pods:
   ```bash
   kubectl apply -f deployment/k8s/network-policy-hardening.yaml
   # If insufficient, apply zero-egress/ingress emergency policy
   ```
2. **IAM Credential Revocation:** Immediately revoke GCP service account keys for compromised accounts:
   ```bash
   gcloud iam service-accounts disable SERVICE_ACCOUNT_EMAIL
   ```
3. **Secret Rotation:** Rotate `CAGE_ROUTING_SEAL_SECRET` and all API keys immediately
4. **AI Pipeline Suspension:** Disable LangGraph financial advisor from accepting new inference requests
5. **Evidence Preservation:** Capture pod logs, OTel traces, and AgentSight eBPF data before any remediation:
   ```bash
   kubectl logs -n governance-stack --all-containers --timestamps > /incident/logs-$(date +%Y%m%d%H%M).txt
   ```
6. **External Notification:** IRT Lead notifies AO within 1 hour; ISSO prepares regulatory notification assessment

#### Category 2 (High) — Containment

**Objective:** Stop ongoing impact; limit blast radius; preserve evidence.

**Actions (within 2 hours of Category 2 determination):**

1. **Component Isolation:** Isolate affected component(s) via targeted NetworkPolicy or pod termination
2. **Credential Review:** Review and rotate credentials associated with the affected component
3. **Traffic Routing:** Route traffic around affected component if failover capability exists
4. **Policy Freeze:** Freeze OPA/NeMo policy changes pending investigation
5. **Evidence Collection:** Collect logs, traces, and configuration snapshots for affected component

#### Category 3 (Moderate) — Containment

**Objective:** Prevent escalation; document; initiate controlled remediation.

**Actions (within 24 hours):**

1. **Monitoring Enhancement:** Increase monitoring granularity on affected component
2. **Configuration Review:** Verify configuration against last known-good state via Git diff
3. **Lula Re-validation:** Run `lula validate` against affected control specifications
4. **Document:** Create POA&M entry if control weakness identified

#### Category 4 (Low) — Containment

**Actions (within 72 hours):**

1. Document in security log
2. Review at next daily/weekly security review
3. Escalate if pattern indicates higher-severity incident

### 5.2 Eradication Steps

After containment is confirmed, eradication removes the root cause:

1. **Root Cause Identification:**
   - Review all evidence collected during containment
   - Trace incident timeline using Langfuse OTel data and AgentSight eBPF captures
   - Identify the initial attack vector or failure mode

2. **Malicious Artifact Removal:**
   - Remove any unauthorized code, containers, or configuration from GKE namespace
   - Delete compromised container images from container registry
   - Remove unauthorized IAM bindings from GCP project

3. **Vulnerability Remediation:**
   - Apply patches for exploited vulnerabilities
   - Update unpinned dependencies if supply chain compromise occurred (POAM-013)
   - Remediate misconfigured IAM if credential abuse identified (POAM-002)

4. **AI Component Reset (if AI incident):**
   - Roll back OPA Rego policies to last known-good version via Git revert
   - Roll back NeMo Guardrails Colang rails to verified state
   - Verify LangGraph financial advisor policy state matches expected configuration
   - Re-run Lula validation suite to confirm policy integrity:
     ```bash
     lula validate -f compliance/lula/lula-validation-ac3.yaml
     lula validate -f compliance/lula/lula-validation-au12.yaml
     lula validate -f compliance/lula/lula-validation-ra5.yaml
     lula validate -f compliance/lula/lula-validation-cm6.yaml
     ```

5. **System Re-hardening:**
   - Rotate all credentials and secrets involved in the incident
   - Re-apply CIS Kubernetes Benchmark configurations
   - Re-apply security context hardening (`deployment/k8s/security-context-patch.yaml`)

### 5.3 Recovery Validation

Before returning to full operation, the following validation steps must be completed:

1. **Security Validation Checklist:**
   - [ ] All compromised credentials rotated and verified
   - [ ] Lula compliance validation suite passes for all affected controls
   - [ ] AgentSight eBPF confirms no anomalous process activity
   - [ ] OPA policy evaluation producing correct governance decisions (verified via test suite)
   - [ ] NeMo Guardrails PII detection tested and confirmed operational
   - [ ] Langfuse audit trail producing valid ISO 42001 evidence stamps from live traces
   - [ ] NetworkPolicy posture restored to default-deny baseline
   - [ ] ISSO approves return to operations

2. **Operational Validation:**
   - [ ] Run full test suite: `pytest tests/ -v`
   - [ ] Verify gRPC and REST gateway endpoint availability and TLS enforcement
   - [ ] Run integration test for end-to-end governance pipeline
   - [ ] Verify market data ingestion and trade recommendation flow
   - [ ] Confirm Langfuse traces are flowing from live inference

3. **Documentation:**
   - [ ] Incident report completed and filed
   - [ ] POA&M updated with any new findings
   - [ ] ISSO signs off on recovery
   - [ ] AO notified of recovery completion (Category 1 and 2 incidents)

---

## 6. Notification and Reporting Procedures

### 6.1 Internal Notification Matrix

| Incident Category         | IRT Lead          | ISSO              | CISO           | System Owner   | AO                  | Legal           |
| ------------------------- | ----------------- | ----------------- | -------------- | -------------- | ------------------- | --------------- |
| **Category 1 (Critical)** | Immediate         | Immediate         | Within 1 hour  | Within 1 hour  | **Within 1 hour**   | Within 2 hours  |
| **Category 2 (High)**     | Immediate         | Immediate         | Within 4 hours | Within 4 hours | **Within 24 hours** | If PII involved |
| **Category 3 (Moderate)** | Within 4 hours    | Within 4 hours    | If escalated   | If escalated   | If escalated        | No              |
| **Category 4 (Low)**      | Next business day | Next business day | No             | No             | No                  | No              |

**Notification Methods:**

- **Immediate/Critical:** Phone call + Slack DM to IRT channel (`#cage-incident-response`)
- **Within hours:** Slack notification + Email
- **Scheduled:** Email with incident report attachment

### 6.2 External Notification Requirements

| Scenario                                                 | Authority                                   | Notification Requirement                                                             | Timeframe                                                                           |
| -------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| PII breach affecting customer financial records (IT-004) | SEC (Reg S-P); State regulators             | Notify SEC; notify affected individuals                                              | **SEC: As soon as practicable; Individuals: No later than 30 days after discovery** |
| Loss of required audit records (IT-003)                  | SEC Rule 17a-4                              | Preserve all remaining records; notify SEC of inability to maintain required records | **Immediate upon discovery**                                                        |
| Material operational incident                            | FINRA Rule 4370                             | Document in Business Continuity Plan; notify FINRA if material impact to operations  | **Within 24 hours of material impact**                                              |
| Critical AI model governance failure                     | Internal AO + SR 11-7 model risk governance | Escalate to model risk management committee                                          | **Within 24 hours**                                                                 |
| GCP infrastructure incident                              | Google Cloud Support                        | Open P1 support ticket                                                               | **Immediate**                                                                       |

### 6.3 Standard Notification Timeframes

| Notification                         | Timeframe                                                   | Method                           | Recipient                 |
| ------------------------------------ | ----------------------------------------------------------- | -------------------------------- | ------------------------- |
| Internal IRT activation              | **Immediate** (within 15 min of Category 1/2 determination) | Phone + Slack                    | IRT Lead, ISSO            |
| AO notification (Category 1)         | **Within 1 hour** of incident determination                 | Phone + Email                    | AO                        |
| AO notification (Category 2)         | **Within 24 hours** of incident determination               | Email + Incident Report          | AO                        |
| Regulatory notification (PII breach) | **Per SEC Reg S-P** requirements                            | Formal letter + SEC notification | SEC, affected individuals |
| System Owner notification            | **Within 4 hours** (Category 1/2)                           | Email + Phone                    | System Owner              |
| Post-incident report to AO           | **Within 10 business days** of incident closure             | Formal report                    | AO, ISSO                  |

---

## 7. Post-Incident Activity

### 7.1 Lessons Learned Process

A lessons learned review shall be conducted within **15 business days** of incident closure for all Category 1, 2, and 3 incidents.

**Lessons Learned Meeting Agenda:**

1. Incident timeline review (detection → containment → eradication → recovery)
2. Root cause analysis
3. Effectiveness of detection sources (AgentSight, Langfuse, Lula)
4. Effectiveness of containment and eradication procedures
5. Gaps identified in this IRP or supporting security controls
6. Action items and responsible parties with target dates
7. POA&M updates required

**Participants:** IRT Lead, ISSO, affected system/component owners, AI Model Operator (if AI incident)

### 7.2 POA&M Updates

Following each incident, the ISSO shall:

1. Review `docs/POAM.md` for existing items that contributed to the incident
2. Add new POA&M entries for root causes not previously tracked
3. Update milestone dates for affected items
4. Report POA&M updates to AO at next scheduled briefing

### 7.3 IRP Updates

This IRP shall be reviewed and updated:

- **Annually** (minimum) per the review cadence in `docs/ROLES_AND_RESPONSIBILITIES.md`
- **After any Category 1 or 2 incident** — incorporate lessons learned within 30 days
- **After any significant system change** affecting detection sources or incident categories
- **After any regulatory change** affecting notification requirements

---

## 8. Contact List

All contacts are role-based. Incumbents shall be maintained in a separate, access-controlled contact roster. The following roles must have confirmed contact information on file with the ISSO before this IRP is activated.

| Role                      | Organization         | Contact Method                   | Primary        | Alternate       |
| ------------------------- | -------------------- | -------------------------------- | -------------- | --------------- |
| IRT Lead                  | [ORGANIZATION — TBD] | Phone + Slack                    | [TBD]          | [TBD]           |
| ISSO                      | [ORGANIZATION — TBD] | Phone + Slack                    | [TBD]          | [TBD]           |
| CISO                      | [ORGANIZATION — TBD] | Phone + Email                    | [TBD]          | [TBD]           |
| System Owner              | [ORGANIZATION — TBD] | Phone + Email                    | [TBD]          | [TBD]           |
| Authorizing Official (AO) | [ORGANIZATION — TBD] | Phone + Email                    | [TBD]          | [TBD]           |
| System Administrator      | [ORGANIZATION — TBD] | Phone + Slack                    | [TBD]          | [TBD]           |
| AI Model Operator         | [ORGANIZATION — TBD] | Phone + Slack                    | [TBD]          | [TBD]           |
| Cloud/Platform Engineer   | [ORGANIZATION — TBD] | Phone + Slack                    | [TBD]          | [TBD]           |
| Legal / Compliance        | [ORGANIZATION — TBD] | Phone + Email                    | [TBD]          | [TBD]           |
| Google Cloud Support (P1) | Google Cloud         | https://cloud.google.com/support | 1-800-xxx-xxxx | Support ticket  |
| US-CERT / CISA            | Federal Government   | https://www.cisa.gov/report      | 1-888-282-0870 | report@cisa.gov |
| SEC (Regulatory)          | SEC                  | https://www.sec.gov/tcr          | [TBD]          | [TBD]           |

---

## 9. Approval and Signatures

### IRT Lead Acknowledgment

I acknowledge my responsibilities as IRT Lead under this Incident Response Plan and confirm I have reviewed the procedures herein.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | IRT Lead                                   |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### ISSO Approval

I have reviewed and approve this Incident Response Plan as accurately reflecting incident response procedures for the CAGE system.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Information System Security Officer        |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### Authorizing Official Approval

I approve this Incident Response Plan for the Cybernetic AI Governance Engine (CAGE). This approval partially satisfies POAM-008 (IR-1: No Incident Response Plan).

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Authorizing Official                       |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

---

## Appendix A: Incident Report Template

```
═══════════════════════════════════════════════════════════════════════
CAGE SECURITY INCIDENT REPORT
═══════════════════════════════════════════════════════════════════════
Report Number:        IR-CAGE-[YEAR]-[SEQUENCE]
Report Date:          [YYYY-MM-DD]
Report Prepared By:   [NAME, TITLE]
Classification:       UNCLASSIFIED

────────────────────────────────────────────────────────────────────
SECTION 1: INCIDENT IDENTIFICATION
────────────────────────────────────────────────────────────────────
Incident Title:       _______________________________________________
Incident Category:    [ ] Category 1 (Critical)  [ ] Category 2 (High)
                      [ ] Category 3 (Moderate)   [ ] Category 4 (Low)
Detection Date/Time:  [YYYY-MM-DD HH:MM UTC]
Detection Source:     [ ] AgentSight eBPF   [ ] Langfuse/OTel
                      [ ] Lula Validation   [ ] Cloud Audit Logs
                      [ ] User Report       [ ] NeMo Guardrails
                      [ ] Other: ____________________________________
Incident Status:      [ ] Active  [ ] Contained  [ ] Eradicated  [ ] Closed

────────────────────────────────────────────────────────────────────
SECTION 2: AFFECTED SYSTEMS AND DATA
────────────────────────────────────────────────────────────────────
Affected Components (from AUTHORIZATION_BOUNDARY.md):
  [ ] COMP-001 CAGE Gateway      [ ] COMP-002 NeMo Guardrails
  [ ] COMP-003 OPA Engine        [ ] COMP-004 LangGraph Advisor
  [ ] COMP-005 AgentSight eBPF   [ ] COMP-006 Compliance Bridge
  [ ] COMP-007 Redis Cache       [ ] COMP-008 Cloud SQL
  [ ] COMP-009 GCS Buckets       [ ] COMP-010 KernelDashboard

Information Types Affected:
  [ ] IT-001 Financial Trade Data  [ ] IT-002 AI Inference Outputs
  [ ] IT-003 Audit Records         [ ] IT-004 PII/Financial Records
  [ ] IT-005 Governance Configs

PII Involved:         [ ] Yes — trigger SEC Reg S-P assessment
                      [ ] No
                      [ ] Unknown — investigation ongoing

────────────────────────────────────────────────────────────────────
SECTION 3: INCIDENT TIMELINE
────────────────────────────────────────────────────────────────────
Initial Detection:    [YYYY-MM-DD HH:MM UTC] — [Event description]
IRT Activation:       [YYYY-MM-DD HH:MM UTC]
AO Notification:      [YYYY-MM-DD HH:MM UTC]
Containment Start:    [YYYY-MM-DD HH:MM UTC]
Containment Complete: [YYYY-MM-DD HH:MM UTC]
Eradication Start:    [YYYY-MM-DD HH:MM UTC]
Eradication Complete: [YYYY-MM-DD HH:MM UTC]
Recovery Start:       [YYYY-MM-DD HH:MM UTC]
Recovery Complete:    [YYYY-MM-DD HH:MM UTC]
Incident Closed:      [YYYY-MM-DD HH:MM UTC]

────────────────────────────────────────────────────────────────────
SECTION 4: INCIDENT DESCRIPTION
────────────────────────────────────────────────────────────────────
Summary (2-3 sentences):
___________________________________________________________________
___________________________________________________________________

Root Cause:
___________________________________________________________________

Attack Vector (if adversarial):
  [ ] Prompt Injection      [ ] Supply Chain Compromise
  [ ] Credential Theft      [ ] Insider Threat
  [ ] Misconfiguration      [ ] Container Escape
  [ ] Other: ____________________________________________________

────────────────────────────────────────────────────────────────────
SECTION 5: IMPACT ASSESSMENT
────────────────────────────────────────────────────────────────────
Confidentiality Impact: [ ] None  [ ] Low  [ ] Moderate  [ ] High
Integrity Impact:       [ ] None  [ ] Low  [ ] Moderate  [ ] High
Availability Impact:    [ ] None  [ ] Low  [ ] Moderate  [ ] High

Records Affected:       [NUMBER or "Unknown"]
Duration of Impact:     [HOURS]
Governance Pipeline:    [ ] Fully Operational  [ ] Degraded  [ ] Offline

────────────────────────────────────────────────────────────────────
SECTION 6: CONTAINMENT AND ERADICATION ACTIONS
────────────────────────────────────────────────────────────────────
Containment Actions Taken:
1. _______________________________________________________________
2. _______________________________________________________________
3. _______________________________________________________________

Eradication Actions Taken:
1. _______________________________________________________________
2. _______________________________________________________________
3. _______________________________________________________________

Credentials Rotated:    [ ] Yes  [ ] No  [ ] N/A
Policies Reverted:      [ ] Yes  [ ] No  [ ] N/A
Lula Validation Run:    [ ] Yes — Result: ______  [ ] No

────────────────────────────────────────────────────────────────────
SECTION 7: REGULATORY NOTIFICATIONS
────────────────────────────────────────────────────────────────────
SEC Reg S-P Assessment: [ ] Required  [ ] Not Required  [ ] TBD
FINRA Notification:     [ ] Required  [ ] Not Required  [ ] TBD
AO Notified:            [ ] Yes — [Date/Time]  [ ] No
Notifications Sent:     [ ] Yes  [ ] No  [ ] Pending

────────────────────────────────────────────────────────────────────
SECTION 8: LESSONS LEARNED
────────────────────────────────────────────────────────────────────
What went well:
___________________________________________________________________

What could be improved:
___________________________________________________________________

Action Items (add to POA&M if applicable):
| Action | Owner | Target Date | POAM Entry |
|---|---|---|---|
| | | | |

────────────────────────────────────────────────────────────────────
SECTION 9: APPROVALS
────────────────────────────────────────────────────────────────────
IRT Lead:    _________________________________ Date: _______________
ISSO:        _________________________________ Date: _______________
AO:          _________________________________ Date: _______________ (Cat 1/2 only)

═══════════════════════════════════════════════════════════════════════
```

---

## Appendix B: Evidence Collection Checklist

The following checklist shall be completed during the evidence collection phase of any Category 1 or 2 incident. Evidence must be collected before any remediation actions that could alter system state.

### B.1 Kubernetes / GKE Evidence

- [ ] Pod logs for all components in `governance-stack` namespace:
  ```bash
  kubectl logs -n governance-stack --all-containers --timestamps --since=24h > evidence/pod-logs-$(date +%Y%m%d%H%M).txt
  ```
- [ ] Pod describe output for affected pods:
  ```bash
  kubectl describe pods -n governance-stack > evidence/pod-describe-$(date +%Y%m%d%H%M).txt
  ```
- [ ] NetworkPolicy snapshot:
  ```bash
  kubectl get networkpolicy -n governance-stack -o yaml > evidence/netpol-$(date +%Y%m%d%H%M).yaml
  ```
- [ ] Kubernetes events from the incident window:
  ```bash
  kubectl get events -n governance-stack --sort-by='.lastTimestamp' > evidence/k8s-events-$(date +%Y%m%d%H%M).txt
  ```
- [ ] GKE audit log export from Cloud Logging (Admin Activity, Data Access logs)

### B.2 AgentSight eBPF Evidence

- [ ] AgentSight eBPF event captures for incident time window
- [ ] AgentSight alert records exported from dashboard
- [ ] eBPF process tree for affected pods during incident window
- [ ] System call anomaly reports

### B.3 OpenTelemetry / Langfuse Evidence

- [ ] OTel trace data for affected inference sessions from Langfuse
- [ ] Governance pipeline execution traces (NeMo → OPA → STPA → OFAC verdict chain)
- [ ] ISO 42001 evidence stamp records for incident window
- [ ] Langfuse alert history and anomaly reports
- [ ] Inference output logs with PII detection events

### B.4 GCP Cloud Logging Evidence

- [ ] Cloud Audit Logs (Admin Activity) for incident window
- [ ] Cloud Audit Logs (Data Access) for Cloud SQL and GCS access
- [ ] IAM policy change logs
- [ ] GCP Secret Manager access logs
- [ ] Cloud SQL PostgreSQL query logs (if database access suspected)

### B.5 Application and Policy Evidence

- [ ] OPA policy evaluation decision logs for incident window
- [ ] NeMo Guardrails event logs (rail violations, PII detections)
- [ ] Git commit history for `governance/policy/*.rego` and NeMo Colang files
- [ ] Current state of OPA policies vs. last known-good Git commit:
  ```bash
  git diff HEAD~1 src/governed_financial_advisor/governance/policy/
  ```
- [ ] Lula validation results at time of incident:
  ```bash
  lula validate -f compliance/lula/ > evidence/lula-results-$(date +%Y%m%d%H%M).txt
  ```

### B.6 Network Evidence

- [ ] Cloud Flow Logs for incident time window
- [ ] GKE network policy enforcement logs
- [ ] External connection attempts (inbound to CAGE gateway)
- [ ] Outbound connection attempts from `governance-stack` namespace

### B.7 Evidence Preservation Requirements

- [ ] All evidence files compressed and stored in access-controlled GCS bucket: `gs://cage-incident-evidence/IR-CAGE-[YEAR]-[SEQ]/`
- [ ] Evidence files are write-protected (WORM) upon collection
- [ ] Evidence inventory manifest created and signed by ISSO
- [ ] Chain of custody documented for all evidence files
- [ ] Evidence retained for minimum **3 years** per organizational policy (SEC Rule 17a-4 mandates 6 years for trade records)

---

