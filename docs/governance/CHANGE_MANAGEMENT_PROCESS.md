# Change Management Process

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Reference:** NIST SP 800-128 (Security-Focused Configuration Management for Information Systems); NIST SP 800-53 Rev 5 CM-3, CM-4, CM-5
**Version:** 1.2 (Draft)
**Date:** 2026-06-14
**ISSO:** [ISSO NAME — TBD]
**System Owner:** [SYSTEM OWNER — TBD]
**Status:** DRAFT — PENDING AO APPROVAL

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Change Categories](#2-change-categories)
3. [Change Request Process](#3-change-request-process)
4. [Change Advisory Board (CAB)](#4-change-advisory-board-cab)
5. [Security Impact Assessment](#5-security-impact-assessment)
6. [Re-authorization Triggers](#6-re-authorization-triggers)
7. [Emergency Change Procedures](#7-emergency-change-procedures)
8. [Change Rollback Procedures](#8-change-rollback-procedures)
9. [Change Tracking and Audit](#9-change-tracking-and-audit)
10. [Appendix A: Change Request Form Template](#appendix-a-change-request-form-template)
11. [Appendix B: Security Impact Assessment Checklist](#appendix-b-security-impact-assessment-checklist)

---

## 1. Purpose and Scope

### 1.1 Purpose

This Change Management Process establishes the procedures, controls, and accountability structures for managing all changes to the CAGE production system. It implements the security-focused configuration management requirements of NIST SP 800-128 and the CM-3 (Configuration Change Control), CM-4 (Impact Analyses), and CM-5 (Access Restrictions for Change) controls from NIST SP 800-53 Rev 5.

The process ensures that:

- All changes are formally requested, assessed, approved, implemented, and verified
- Security implications of changes are analyzed before implementation
- Changes that affect the system's authorization boundary trigger re-authorization assessment
- An immutable audit trail of all production changes is maintained
- Rollback procedures are defined and tested for all changes

### 1.2 Scope

This process applies to **all changes** to the CAGE production system, including but not limited to:

| Scope Area                 | Examples                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------- |
| **Infrastructure**         | GKE cluster configuration, node pool changes, GCP resource provisioning (Terraform)   |
| **Container Images**       | Docker image builds, base image updates, container registry pushes                    |
| **Kubernetes Resources**   | Deployments, Services, ConfigMaps, Secrets, NetworkPolicies, ServiceAccounts          |
| **Application Code**       | Python source changes to gateway, compliance bridge, governance agents                |
| **OPA/Rego Policies**      | Changes to `deployment/system_authz.rego`, `finance_policy.rego`, `trade_policy.rego` |
| **AI Model Configuration** | vLLM model updates, NeMo Guardrails configuration, LangGraph workflow changes         |
| **Compliance Artifacts**   | OSCAL component updates, Lula validation changes, SSP updates                         |
| **Security Configuration** | TLS certificates, IAM roles, Secret Manager entries, encryption keys                  |
| **Monitoring/Telemetry**   | Langfuse settings, alerting rules, OTLP pipeline configuration                        |
| **CI/CD Pipeline**         | GitHub Actions workflow changes (`.github/workflows/`)                                |

### 1.3 Exclusions

The following are excluded from this process (handled by separate procedures):

- **Emergency security patches** for actively exploited CRITICAL CVEs: Follow §7 Emergency Change Procedures
- **Development environment changes**: No CAB approval required; standard Git pull request process applies
- **Documentation updates** (no code or configuration change): Streamlined review via PR

### 1.4 Applicable NIST Controls

| Control | Description                        | Process Section                                |
| ------- | ---------------------------------- | ---------------------------------------------- |
| CM-3    | Configuration Change Control       | §3 (Change Request Process), §4 (CAB)          |
| CM-4    | Impact Analyses                    | §5 (Security Impact Assessment)                |
| CM-5    | Access Restrictions for Change     | §3.4 (Implementation Authorization)            |
| CM-6    | Configuration Settings             | §5.1 (Security Control Impact)                 |
| CM-9    | Configuration Management Plan      | This document                                  |
| CA-7    | Continuous Monitoring              | §9 (Change Tracking and Audit)                 |
| SA-10   | Developer Configuration Management | §3 (applies to development-originated changes) |

---

## 2. Change Categories

All changes are classified into one of four categories at the time of request. The category determines the approval path, lead time, and required documentation.

| Category             | Code  | Definition                                                                                                                                | Approval Window               | Lead Time                    | AO Notification                                      |
| -------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ---------------------------- | ---------------------------------------------------- |
| **Emergency Change** | Cat-E | Unplanned change required to restore service availability, remediate an actively exploited vulnerability, or prevent imminent data breach | **2 hours**                   | Immediate                    | **Required** (within 1 hour of implementation)       |
| **Standard Change**  | Cat-S | Pre-approved, repeatable change that follows a defined procedure with known, low risk                                                     | No individual approval needed | Varies (per standard)        | Not required                                         |
| **Normal Change**    | Cat-N | New or unique change not covered by a Standard Change; requires CAB review and risk assessment                                            | **CAB cycle**                 | **5 business days** minimum  | Required only if change affects HIGH-impact controls |
| **Major Change**     | Cat-M | Architectural, boundary, or AI model change that may alter the authorization scope                                                        | **CAB + AO review**           | **30 calendar days** minimum | **Required** (pre-implementation)                    |

### 2.1 Change Category Decision Tree

```
Is the change required within 4 hours to prevent imminent impact?
  YES → Cat-E (Emergency Change) → See §7
  NO  ↓

Does the change follow a documented, pre-approved Standard Change procedure?
  YES → Cat-S (Standard Change) → Implement per standard; log completion
  NO  ↓

Does the change affect the authorization boundary, introduce new PII categories,
add external interconnections, or modify HIGH-impact security controls?
  YES → Cat-M (Major Change) → 30-day AO review process
  NO  ↓

Default: Cat-N (Normal Change) → Full CAB review; 5-day lead time
```

### 2.2 Pre-Approved Standard Changes (Cat-S)

The following repeatable changes are pre-approved as Standard Changes and do not require individual CAB approval:

| Standard ID | Change Description                                        | Procedure Reference                       |
| ----------- | --------------------------------------------------------- | ----------------------------------------- |
| STD-001     | Secret rotation (existing secrets only, no new secrets)   | `deployment/update_langfuse_secret.py`    |
| STD-002     | Lula validation YAML updates (no new controls)            | `compliance/lula/` + PR review            |
| ~~STD-003~~ | ~~OTel Collector configuration tuning (sampling rates)~~  | **Retired** — standalone OTel Collector deprecated 2026-05-31; Langfuse integrated OTLP ingestion used directly. Sampling rate tuning now via `OTEL_EXPORTER_OTLP_ENDPOINT` env var. |
| STD-004     | HPA (Horizontal Pod Autoscaler) replica count adjustments | `deployment/k8s/langfuse-worker-hpa.yaml` |
| STD-005     | Documentation updates (no code/config change)             | PR review by ISSO                         |
| STD-006     | Security scan result review and POAM milestone updates    | `docs/POAM_INDEX.md` + ISSO sign-off (see [`docs/POAM_INDEX.md`](POAM_INDEX.md) for the multi-posture POAM structure) |

### 2.3 Category Examples for CAGE

| Example Change                                                     | Category | Rationale                                                                       |
| ------------------------------------------------------------------ | -------- | ------------------------------------------------------------------------------- |
| Update `finance_policy.rego` to add new trade limit tier           | Cat-N    | Modifies OPA policy; security impact assessment required                        |
| Upgrade vLLM model from Llama-3-8B to Llama-3-70B                  | Cat-M    | Major AI model change; may alter governance behavior and output characteristics |
| Add new GCP external interconnection (third-party market data API) | Cat-M    | Extends authorization boundary                                                  |
| Rotate `cage-routing-seal` HMAC secret (scheduled)                 | Cat-S    | Pre-approved STD-001; documented rotation procedure                             |
| Patch critical CVE in Python base image (actively exploited)       | Cat-E    | Imminent security risk; 2-hour approval window                                  |
| Update NeMo Guardrails PII detection thresholds                    | Cat-N    | Affects privacy controls; SIA required                                          |
| Modify NetworkPolicy to allow new internal service port            | Cat-N    | Security-relevant configuration change                                          |
| Add new Kubernetes namespace with Deployment                       | Cat-M    | Potential boundary change; re-authorization assessment required                 |

---

## 3. Change Request Process

### 3.1 Process Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CHANGE REQUEST LIFECYCLE                         │
│                                                                       │
│  1. REQUEST    2. ASSESS    3. APPROVE    4. IMPLEMENT    5. VERIFY  │
│      ↓              ↓           ↓              ↓             ↓       │
│   Submit CR    Security    CAB / AO       Deploy to     Post-impl    │
│   (Form App-A) Impact      Review &       Production    testing &    │
│                Analysis    Decision                     validation   │
│                                                              ↓       │
│                                                         6. CLOSE     │
│                                                         Update POAM  │
│                                                         & OSCAL      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Step 1: Change Request Submission

**Who:** Any team member (Change Initiator)  
**How:** Submit a Change Request using the template in [Appendix A](#appendix-a-change-request-form-template)  
**Where:** GitHub Issues (labeled `change-request`) OR ITSM system (if implemented)

**Required Information:**

- Change title and description
- Change category (Cat-E / Cat-S / Cat-N / Cat-M)
- Proposed implementation date/window
- Risk assessment (initial — initiator's perspective)
- Rollback plan
- CAGE components affected (see Appendix A)
- OSCAL/Lula update required? (Y/N)

### 3.3 Step 2: Security Impact Assessment (SIA)

**Who:** ISSO (with input from Change Initiator)  
**When:** Within 2 business days of submission (Cat-N); within 1 business day (Cat-M)

The ISSO completes the SIA checklist (see [Appendix B](#appendix-b-security-impact-assessment-checklist) and §5). SIA determines:

- Whether the change affects any NIST SP 800-53 security controls
- Whether the change modifies the authorization boundary
- Whether the change affects PII handling (triggers PIA review)
- Whether OSCAL component updates are required
- Whether Lula validation updates are required

### 3.4 Step 3: Approval

**Cat-S:** No individual approval required. Change Initiator logs implementation in change log (§9).

**Cat-N:** CAB quorum approval required (see §4). Change is approved, deferred, or rejected.

**Cat-M:** CAB approval + AO written concurrence required. AO concurrence must be documented before implementation.

**Cat-E:** Expedited approval per §7. ISSO + System Owner verbal authorization within 2 hours; AO notification required.

**Implementation Authorization (CM-5):** Only individuals with the following roles may implement approved changes to production:

- **Infrastructure changes (GCP/GKE/Terraform):** Cloud Engineering team + System Owner approval
- **Application/policy changes:** Backend Engineering team + ISSO security review
- **Security configuration changes:** ISSO or Security Engineering team only
- **OSCAL/compliance artifact changes:** ISSO

### 3.5 Step 4: Implementation

**Who:** Authorized implementer (per CM-5 role list in §3.4)  
**Requirements:**

- Implementation only during approved maintenance window (Cat-N: business hours preferred; Cat-M: scheduled maintenance window required)
- A second authorized team member must be available to observe or assist (four-eyes principle)
- Implementation steps must be documented in the change record before execution
- All implementation commands must be executed from the authorized GitOps pipeline where possible (not ad-hoc `kubectl` commands)

### 3.6 Step 5: Verification

**Who:** Change Initiator + ISSO (for Cat-N/Cat-M)  
**When:** Immediately after implementation

Verification must confirm:

1. All Lula validations pass (`kubectl apply` and Lula CronJob result)
2. Relevant functional tests pass (`pytest tests/`)
3. Langfuse is receiving spans via integrated OTLP ingestion (Langfuse traces visible)
4. No new CRITICAL alerts triggered in Cloud Monitoring
5. Rollback is confirmed as available (not yet invoked)

### 3.7 Step 6: Change Closure

**Who:** ISSO  
**When:** Within 2 business days of successful verification

Closure actions:

1. Update POAM (if change remediates a POAM item — mark as closed or update milestone)
2. Update OSCAL component definition (if security control implementation changed)
3. Archive change record with evidence (Lula output, test results, git commit SHA)
4. Notify AO if Cat-M change has been fully implemented and verified
5. Update `CHANGELOG.md` with change summary

### 3.8 Environment Promotion Order

The standard promotion path for all changes is:

```
dev  →  prod
```

> **Note (v0.1.0 — POAM-024):** A `staging` pre-production environment is defined in the Terraform schema (`infra/targets/gcp-gke/variables.tf`) and is architecturally planned as an intermediate tier between `dev` and `prod`. However, the staging environment is **not yet provisioned** for v0.1.0. The intended three-tier promotion path (`dev → staging → prod`) is deferred to v2.1.0 (target: 2026-12-31). For v0.1.0, the promotion path is **dev → prod** with AO acknowledgement. The `deploy_all.sh` script rejects `--env staging` with an explicit error until staging is provisioned. See [`docs/POAM_ISO42001.md#POAM-024`](POAM_ISO42001.md).

No change may be promoted directly from `dev` to `prod` without passing all CI gates on the source branch. Each promotion requires:

1. All Lula validations pass
2. `pytest` suite passes with zero failures
3. STPA freshness check passes
4. Langfuse posture verified

---

## 4. Change Advisory Board (CAB)

### 4.1 CAB Membership

| Role                         | Member | Voting?  | Notes                               |
| ---------------------------- | ------ | -------- | ----------------------------------- |
| **CAB Chair**                | ISSO   | Yes      | Facilitates; casting vote on ties   |
| **System Owner**             | [TBD]  | Yes      | Final authority for Cat-M changes   |
| **Cloud Engineering Lead**   | [TBD]  | Yes      | Infrastructure change expertise     |
| **Backend Engineering Lead** | [TBD]  | Yes      | Application/policy change expertise |
| **Security Engineer**        | [TBD]  | Yes      | Security control impact assessment  |
| **Compliance Officer**       | [TBD]  | Yes      | Regulatory compliance impact        |
| **Privacy Officer**          | [TBD]  | Advisory | Required for PII-impacting changes  |
| **Authorizing Official**     | [TBD]  | Advisory | Votes only on Cat-M changes         |

### 4.2 Quorum Requirements

| Change Category | Quorum                                           | Notes                                     |
| --------------- | ------------------------------------------------ | ----------------------------------------- |
| Cat-N           | 3 voting members including ISSO                  | CAB Chair (ISSO) + 2 others               |
| Cat-M           | 5 voting members including System Owner and ISSO | AO concurrence required separately        |
| Cat-E           | ISSO + System Owner (verbal)                     | Retroactive full CAB review within 5 days |

### 4.3 Meeting Cadence

| Meeting Type            | Frequency                   | Purpose                                                                |
| ----------------------- | --------------------------- | ---------------------------------------------------------------------- |
| **Regular CAB Meeting** | Weekly (Tuesdays, 10:00 ET) | Review pending Cat-N change requests; retrospective on recent changes  |
| **Emergency CAB**       | As needed (ad-hoc)          | Cat-M changes requiring expedited review; post-Emergency Change review |
| **Annual CAB Review**   | Annually (Q4)               | Review Standard Change library; update procedures; AO briefing         |

### 4.4 CAB Decision Options

| Decision                     | Meaning                                                  | Next Step                                                                 |
| ---------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Approved**                 | Change proceeds as proposed                              | Implement per approved plan                                               |
| **Approved with Conditions** | Change proceeds with documented modifications            | Update CR with conditions; implement modified plan                        |
| **Deferred**                 | Change requires additional information or more lead time | Initiator provides additional information; resubmit                       |
| **Rejected**                 | Change does not proceed                                  | Document rationale; initiator may resubmit with significant modifications |

---

## 5. Security Impact Assessment

A Security Impact Assessment (SIA) is **required** for all Cat-N and Cat-M changes. The ISSO completes the SIA using the checklist in Appendix B.

### 5.1 Does the Change Affect Security Controls?

The ISSO reviews the change against the CAGE control baseline (`compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md`) and determines:

- Which NIST SP 800-53 controls are potentially affected
- Whether the implementation statement for affected controls changes
- Whether Lula validation results may change (pass → fail or fail → pass)
- Whether the change introduces new compensating controls or removes existing ones

**Decision:** If security controls are affected → OSCAL update required; Lula re-run required post-implementation.

### 5.2 Does the Change Modify the Authorization Boundary?

Changes that potentially modify the authorization boundary include:

- Adding new GCP services (new Terraform resources not in current `infra/targets/gcp-gke/`)
- Adding new Kubernetes namespaces or external-facing Services
- Adding external API integrations or interconnections
- Deploying new AI models or inference services
- Adding new data stores (databases, object storage buckets)

**Decision:** If authorization boundary is modified → Cat-M required; AO re-authorization assessment required.

### 5.3 Does the Change Affect PII Handling?

Changes that potentially affect PII handling include:

- Modifying NeMo Guardrails PII detection configuration (`config/rails/config.yml`)
- Adding new OTel span attributes that may capture user data
- Changing Langfuse trace retention or storage configuration
- Modifying GCP logging exclusion filters
- Changing Cloud SQL schema to add new user data fields
- Adding new data exports or sharing arrangements

**Decision:** If PII handling is affected → Privacy Officer review required; PIA update may be required.

### 5.4 OSCAL Component Update Required?

An OSCAL component update is required when:

- A control implementation statement changes
- A new control is implemented or retired
- The responsible role for a control changes
- Evidence artifacts (Lula validation files) are created, modified, or removed

**Process:** Update the relevant component in `compliance/oscal/` and ensure Lula validations reflect the updated implementation.

### 5.5 Lula Validation Update Required?

A Lula validation update is required when:

- New Kubernetes resources are deployed that should be checked by automated compliance
- Existing resources change in a way that alters Lula assertion outcomes
- New controls are implemented that warrant automated validation
- Existing Lula validations reference resources that are renamed or removed

**Process:** Create or update the relevant file in `compliance/lula/` and run a Lula compliance check post-implementation (`deployment/k8s/lula-cron.yaml`).

---

## 6. Re-authorization Triggers

Certain changes require a formal re-authorization assessment with the Authorizing Official (AO). The following changes **must not proceed** without AO pre-approval or concurrence on re-authorization:

| Trigger                                      | Examples                                                                                                           | Re-authorization Scope                                                |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| **New boundary components**                  | New GCP services, new Kubernetes namespaces, new external APIs                                                     | Full boundary re-assessment; SSP update; new Lula validations         |
| **New PII categories**                       | Adding new PII entity types to NeMo detection, new user data fields in Cloud SQL                                   | PIA update; privacy control re-assessment                             |
| **New external interconnections**            | Third-party market data API, external authentication provider, new cloud region                                    | Interconnection Agreement; data flow documentation; SC-8/SC-28 review |
| **Changes to HIGH-impact controls**          | Modifying OPA policy deny logic, disabling NetworkPolicy, modifying encryption configuration                       | Control-specific assessment; AO written concurrence                   |
| **Major AI model change**                    | Upgrading to significantly larger model, switching model provider, adding new AI capability (e.g., code execution) | AI risk assessment; AI bias/safety re-evaluation; AO briefing         |
| **Significant security architecture change** | Adopting Istio mTLS (Phase 3), migrating to different identity provider, new secrets management approach           | Security architecture review; control re-implementation assessment    |
| **Production incident with boundary impact** | Data breach, governance bypass, confirmed PII exfiltration                                                         | Emergency re-authorization; IR Plan activation (`docs/IR_PLAN.md`)    |

### 6.1 Re-authorization Assessment Process

1. **ISSO submits Cat-M Change Request** with re-authorization trigger identified
2. **Security Control Assessor (SCA) conducts targeted assessment** of affected controls
3. **ISSO updates SSP** with new control implementation statements
4. **ISSO prepares updated authorization package** (SSP + POA&M + PIA if applicable)
5. **AO reviews package** and issues one of: ATO continuation, Interim ATO, or Denial
6. **Change proceeds** only upon AO written concurrence
7. **ISSO updates OSCAL** and Lula validations post-implementation

---

## 7. Emergency Change Procedures

Emergency changes (Cat-E) are invoked when an unplanned change is required within 4 hours to:

- Restore critical service availability (P1 incident)
- Remediate an actively exploited vulnerability (CVSS ≥ 9.0)
- Prevent imminent data breach or PII exfiltration
- Comply with a regulatory emergency directive

### 7.1 Emergency Change Approval

1. **Change Initiator contacts ISSO immediately** (phone/Signal — not email)
2. **ISSO and System Owner verbally authorize** within 2 hours
3. **AO is notified within 1 hour of implementation** (not for approval — for situational awareness)
4. **Documentation is completed within 4 hours post-implementation** (not before — speed takes precedence)

### 7.2 Emergency Implementation

Emergency changes must:

- Be limited in scope to the minimum change necessary to address the emergency
- Be implemented by the most senior available authorized implementer
- Be observed by a second authorized team member where possible
- Be implemented from documented runbook steps where they exist

### 7.3 Post-Emergency Review

Within **5 business days** of an Emergency Change:

1. **Full CAB retrospective** reviews the emergency change and its outcome
2. **ISSO documents the full change record** (using Appendix A template)
3. **Root cause analysis** completed and documented
4. **POAM item created** if the emergency revealed a systemic gap
5. **Standard Change consideration:** If the emergency is likely to recur, evaluate whether a Standard Change procedure should be created
6. **AO briefing** if the emergency involved a security incident or boundary-impacting change

---

## 8. Change Rollback Procedures

All changes must have a documented rollback plan before implementation is authorized. The following procedures define rollback for common CAGE change types.

### 8.1 Kubernetes Deployment Rollback

For application Deployment changes:

```bash
# View rollout history
kubectl rollout history deployment/<deployment-name> -n governance-stack

# Roll back to previous revision
kubectl rollout undo deployment/<deployment-name> -n governance-stack

# Roll back to a specific revision
kubectl rollout undo deployment/<deployment-name> -n governance-stack --to-revision=<N>

# Verify rollback status
kubectl rollout status deployment/<deployment-name> -n governance-stack
kubectl get pods -n governance-stack -l app=<app-label>
```

**Post-rollback:** Run Lula validations (`kubectl apply -f deployment/k8s/lula-cron.yaml`) and confirm functional tests pass.

### 8.2 Terraform Infrastructure Rollback

For GCP infrastructure changes:

```bash
# View current state
terraform show infra/

# Plan the rollback to previous state
# (Revert the Terraform .tf file change in git, then:)
git revert <commit-sha>  # or git checkout HEAD~1 infra/<file>.tf

# Preview rollback impact
terraform plan -chdir=infra/targets/gcp-gke/

# Apply rollback (requires Cloud Engineering Lead approval)
terraform apply -chdir=infra/targets/gcp-gke/
```

**Critical:** Terraform state file must not be manually edited. Always use `terraform plan` → `terraform apply` workflow. State is stored in GCS backend (`infra/targets/gcp-gke/backend.tf`). The legacy `deployment/terraform/` directory is retained as historical reference only — all active IaC is under `infra/`.

### 8.3 OPA Policy Rollback

For Rego policy changes (`deployment/system_authz.rego`, `finance_policy.rego`):

```bash
# Revert policy file in git
git revert <commit-sha>  # Reverts the policy change commit

# Re-deploy policy to cluster (policy is mounted as ConfigMap/Secret)
kubectl create secret generic finance-policy-rego \
  --from-file=finance_policy.rego=src/governed_financial_advisor/governance/policy/finance_policy.rego \
  --dry-run=client -o yaml | kubectl apply -f - -n governance-stack

# Restart OPA sidecar pods to reload policy
kubectl rollout restart deployment/governed-financial-advisor -n governance-stack

# Verify OPA policy is loaded correctly
kubectl exec -n governance-stack deployment/governed-financial-advisor -c opa -- \
  opa eval --data /policies/finance_policy.rego --stdin-input 'data.finance.allow'
```

### 8.4 NetworkPolicy Rollback

For NetworkPolicy changes:

```bash
# Revert NetworkPolicy manifest in git
git revert <commit-sha>

# Re-apply previous NetworkPolicy
kubectl apply -f deployment/k8s/network-policy.yaml -n governance-stack

# Verify connectivity is restored
kubectl exec -n governance-stack <pod-name> -- curl -s http://opa:8181/health
```

**Warning:** Incorrect NetworkPolicy rollback can either restore a security gap (if rolling back a tightening change) or disrupt service (if the rollback removes required egress allowances). Always verify both security and connectivity after NetworkPolicy rollback.

### 8.5 Secret Rotation Rollback

Secret rotations generally cannot be rolled back (old secret values should be invalidated). Instead:

1. **Identify the impact:** Determine which services are using the new (failed) secret value
2. **Re-rotate the secret** to a new known-good value via `deployment/update_langfuse_secret.py` or GCP Secret Manager console
3. **Restart affected workloads** to pick up the new secret value
4. **Document the double-rotation** in the change record

### 8.6 Rollback Decision Criteria

| Outcome                                     | Action                                                |
| ------------------------------------------- | ----------------------------------------------------- |
| All verification checks pass                | Close change; no rollback required                    |
| Minor issues (non-security)                 | Attempt targeted fix before rollback                  |
| Lula validation failure on security control | Immediate rollback required; ISSO notification        |
| Service unavailability (P1 impact)          | Immediate rollback; Cat-E post-rollback if fix needed |
| Security incident detected                  | Immediate rollback; activate `docs/IR_PLAN.md`        |

---

## 9. Change Tracking and Audit

### 9.1 Git Commit Audit Trail

All production changes must be traceable to a git commit in the CAGE repository. Requirements:

- **Every change is implemented via a git commit** (no ad-hoc `kubectl edit` or console changes without a corresponding git commit)
- **Commit messages include Change Request ID** (format: `[CR-YYYY-NNN] <description>`)
- **Commits are signed** with GPG keys for authorized implementers (CM-5 compliance)
- **Main branch is protected:** No direct pushes to `main`; all changes via Pull Request with required reviews

### 9.2 POAM Updates

When a change remediates a POA&M item:

1. Update the relevant POAM file with the implementation evidence (commit SHA, Lula result, date). The POAM is now structured as a multi-posture framework — update the correct file per the region scope:
   - Universal ISO 42001 weaknesses → [`docs/POAM_ISO42001.md`](POAM_ISO42001.md)
   - US_FED / NIST SP 800-53 weaknesses → [`docs/POAM_US_FED.md`](POAM_US_FED.md)
   - EU_ECB / EU AI Act / DORA weaknesses → [`docs/POAM_EU_ECB.md`](POAM_EU_ECB.md)
   - APAC_MAS / MAS FEAT weaknesses → [`docs/POAM_APAC_MAS.md`](POAM_APAC_MAS.md)
   - Cross-region traceability index → [`docs/POAM_INDEX.md`](POAM_INDEX.md)
   - `docs/POAM.md` is a redirect notice only — do not add new entries there
2. Update POA&M item status: `Open` → `In Progress` → `Closed`
3. Archive supporting evidence (Lula output, test results) in `compliance/` directory
4. Notify ISSO for HIGH/CRITICAL POAM item closures; notify AO for CRITICAL closures

### 9.3 OSCAL Component Updates

When a change alters a security control implementation:

1. Update the relevant component in `compliance/oscal/` with the new implementation statement
2. Update the control's evidence pointer (Lula validation file reference)
3. Commit the OSCAL update in the same PR or as a follow-on PR within 2 business days
4. Note: OSCAL updates to HIGH-impact controls must be reviewed by the ISSO before merge

### 9.4 Change Log

The `CHANGELOG.md` file at the repository root is updated for every Cat-N and Cat-M change:

```markdown
## [Unreleased]

### Changed

- [CR-2026-001] Updated finance_policy.rego to add $1M trade limit tier for Principal Traders
  - Implements: OPA policy update
  - Reviewed by: [CAB Chair], [Security Engineer]
  - Approved: 2026-03-10
  - Implemented: 2026-03-12
  - Lula validation: PASS (post-implementation run)
```

### 9.5 Continuous Monitoring Integration

Change management integrates with the CAGE Continuous Monitoring strategy (`compliance/continuous-monitoring/ISCM_STRATEGY.md`):

- Lula validations run on a CronJob schedule (`deployment/k8s/lula-cron.yaml`) — any change that causes a Lula failure triggers an ISSO alert
- GCP Cloud Monitoring alerts are configured to detect unexpected configuration drift
- GitHub Actions security scans (`.github/workflows/security-scan.yml`) run on every PR — no PR merges if Trivy HIGH/CRITICAL CVEs detected

---

## Appendix A: Change Request Form Template

```
======================================================================
CAGE CHANGE REQUEST FORM
======================================================================
CR ID:          CR-YYYY-NNN (assigned by ISSO)
Date Submitted: YYYY-MM-DD
Submitted By:   [Name, Role]
Change Category: [ ] Cat-E  [ ] Cat-S  [ ] Cat-N  [ ] Cat-M

----------------------------------------------------------------------
1. CHANGE DESCRIPTION
----------------------------------------------------------------------
Title: [Brief descriptive title]

Description:
[Detailed description of what is changing, why, and what the expected
outcome is. Include specific files, resources, or services affected.]

Justification:
[Business or security justification for the change.]

----------------------------------------------------------------------
2. CHANGE SCOPE
----------------------------------------------------------------------
Components Affected (check all that apply):
[ ] GCP Infrastructure (Terraform)
[ ] GKE Kubernetes Resources (Deployments, Services, etc.)
[ ] Application Code (Python services)
[ ] OPA/Rego Policies
[ ] AI Model / NeMo Guardrails Configuration
[ ] NetworkPolicy / Security Configuration
[ ] Secrets / IAM / Encryption Keys
[ ] OSCAL / Lula Compliance Artifacts
[ ] CI/CD Pipeline (.github/workflows/)
[ ] Monitoring / Telemetry Configuration
[ ] Documentation Only

Specific Files/Resources Changed:
[List specific files, Kubernetes resource names, GCP resources]

----------------------------------------------------------------------
3. IMPLEMENTATION PLAN
----------------------------------------------------------------------
Proposed Implementation Date: YYYY-MM-DD
Proposed Maintenance Window:  [Time range, e.g., 09:00-11:00 ET]
Implementer:                  [Name, Role]
Observer:                     [Name, Role — four-eyes principle]

Step-by-Step Implementation Plan:
1. [Step 1]
2. [Step 2]
3. [Step 3]

----------------------------------------------------------------------
4. RISK ASSESSMENT
----------------------------------------------------------------------
Risk Level (initial):  [ ] LOW  [ ] MODERATE  [ ] HIGH  [ ] CRITICAL

Risk Description:
[Describe the risk if the change fails or causes unintended impact.]

Affected Users / Services:
[Who/what is impacted if the change causes an outage or security issue?]

----------------------------------------------------------------------
5. ROLLBACK PLAN
----------------------------------------------------------------------
Rollback Trigger (when to invoke rollback):
[E.g., "If Lula validation fails post-implementation" or
"If P1 alert fires within 30 minutes of implementation"]

Rollback Steps:
1. [Step 1 — see §8 for standard rollback procedures]
2. [Step 2]
3. [Step 3]

Estimated Rollback Time: [Minutes]

----------------------------------------------------------------------
6. SECURITY IMPACT ASSESSMENT (completed by ISSO)
----------------------------------------------------------------------
SIA Completed By: [ISSO Name]
SIA Date:         YYYY-MM-DD

[ ] Change affects NIST SP 800-53 security controls (specify):
    Controls: ___________________________________________

[ ] Change modifies authorization boundary
[ ] Change affects PII handling → Privacy Officer review required
[ ] OSCAL component update required
[ ] Lula validation update required

SIA Conclusion: [ ] APPROVED FOR CAB  [ ] REQUIRES CAB REVIEW  [ ] CAB NOT REQUIRED (Cat-S)

----------------------------------------------------------------------
7. CAB DECISION (completed by CAB Chair)
----------------------------------------------------------------------
CAB Meeting Date: YYYY-MM-DD
Decision: [ ] APPROVED  [ ] APPROVED WITH CONDITIONS  [ ] DEFERRED  [ ] REJECTED

Conditions (if any):
[Document any conditions of approval]

Approving Members:
- [Name, Role] — [Vote]
- [Name, Role] — [Vote]
- [Name, Role] — [Vote]

CAB Chair Signature: ___________________ Date: ___________

----------------------------------------------------------------------
8. AO CONCURRENCE (Cat-M only)
----------------------------------------------------------------------
AO Name: ___________________________
Decision: [ ] CONCUR  [ ] NON-CONCUR
Signature: _________________________  Date: ___________
Notes: ___________________________________________________

----------------------------------------------------------------------
9. IMPLEMENTATION RECORD
----------------------------------------------------------------------
Implemented By: [Name]
Implementation Date: YYYY-MM-DD  Time: HH:MM ET
Git Commit SHA: [SHA]
Implementation Notes: [Any deviations from plan; issues encountered]

----------------------------------------------------------------------
10. VERIFICATION RECORD
----------------------------------------------------------------------
Verified By: [Name]  Date: YYYY-MM-DD

[ ] Lula validations pass (output attached)
[ ] Functional tests pass (pytest results attached)
[ ] OTel spans visible in Langfuse
[ ] No new CRITICAL alerts in Cloud Monitoring
[ ] Rollback confirmed as available (not invoked)

Verification Notes: _____________________________________________

----------------------------------------------------------------------
11. CLOSURE
----------------------------------------------------------------------
Closed By (ISSO): _______________  Date: ___________

[ ] POAM updated (if applicable): POAM-___
[ ] OSCAL updated (if applicable)
[ ] CHANGELOG.md updated
[ ] AO notified (Cat-M): Date: ___________

CHANGE STATUS: [ ] SUCCESSFULLY IMPLEMENTED  [ ] ROLLED BACK  [ ] PARTIALLY IMPLEMENTED
======================================================================
```

---

## Appendix B: Security Impact Assessment Checklist

This checklist is completed by the ISSO for all Cat-N and Cat-M change requests.

```
======================================================================
CAGE SECURITY IMPACT ASSESSMENT (SIA) CHECKLIST
======================================================================
CR ID: CR-YYYY-NNN
ISSO: [Name]
Date: YYYY-MM-DD

----------------------------------------------------------------------
PART 1: SECURITY CONTROL IMPACT
----------------------------------------------------------------------

1.1 Access Control (AC)
[ ] Does the change modify user roles, permissions, or ServiceAccounts?
[ ] Does the change affect OPA policy logic or Rego rules?
[ ] Does the change add or remove Kubernetes RBAC resources?
    → If YES to any: Review AC-2, AC-3, AC-6 control statements
    → Lula: lula-validation-ac2.yaml, lula-validation-ac3.yaml

1.2 Audit and Accountability (AU)
[ ] Does the change affect OTel instrumentation or span attributes?
[ ] Does the change modify Langfuse configuration or trace storage?
[ ] Does the change affect Cloud Logging configuration?
    → If YES to any: Review AU-2, AU-12 control statements
    → Lula: lula-validation-au12.yaml

1.3 Configuration Management (CM)
[ ] Does the change modify baseline configuration settings?
[ ] Does the change affect container image versions or registries?
    → If YES to any: Review CM-6, CM-7 control statements
    → Lula: lula-validation-cm6.yaml, lula-validation-si2.yaml

1.4 Identification and Authentication (IA)
[ ] Does the change affect secret management or rotation?
[ ] Does the change affect service-to-service authentication?
[ ] Does the change affect HMAC routing seals or JWT handling?
    → If YES to any: Review IA-3, IA-5 control statements
    → Lula: lula-validation-ia3.yaml, lula-validation-ia5.yaml

1.5 Risk Assessment (RA)
[ ] Does the change introduce new dependencies or third-party components?
[ ] Does the change affect vulnerability scanning coverage?
    → If YES to any: Review RA-5 control statement
    → Lula: lula-validation-ra5.yaml

1.6 System and Communications Protection (SC)
[ ] Does the change affect NetworkPolicy rules or TLS configuration?
[ ] Does the change affect encryption at rest or in transit?
[ ] Does the change expose new network endpoints?
    → If YES to any: Review SC-8, SC-12, SC-28 control statements
    → Lula: lula-validation-sc8.yaml

1.7 System and Information Integrity (SI)
[ ] Does the change update container images or Python dependencies?
[ ] Does the change affect the flaw remediation process?
    → If YES to any: Review SI-2 control statement
    → Lula: lula-validation-si2.yaml

----------------------------------------------------------------------
PART 2: AUTHORIZATION BOUNDARY IMPACT
----------------------------------------------------------------------

2.1 Does the change add a new GCP service not in current Terraform? [ ] YES [ ] NO
2.2 Does the change add a new Kubernetes namespace?                  [ ] YES [ ] NO
2.3 Does the change add an external API or data source?              [ ] YES [ ] NO
2.4 Does the change add a new data store (DB, bucket, cache)?        [ ] YES [ ] NO
2.5 Does the change deploy a new AI model or inference service?      [ ] YES [ ] NO

If YES to any in 2.1-2.5: Change must be escalated to Cat-M.
Re-authorization assessment required. AO concurrence required.

----------------------------------------------------------------------
PART 3: PII IMPACT
----------------------------------------------------------------------

3.1 Does the change affect NeMo Guardrails PII detection?            [ ] YES [ ] NO
3.2 Does the change add new OTel span attributes with user data?     [ ] YES [ ] NO
3.3 Does the change alter Langfuse trace retention or storage?       [ ] YES [ ] NO
3.4 Does the change add new user data fields to Cloud SQL?           [ ] YES [ ] NO
3.5 Does the change create new data sharing arrangements?            [ ] YES [ ] NO

If YES to any in 3.1-3.5: Privacy Officer review required.
PIA update may be required. Reference: compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md

----------------------------------------------------------------------
PART 4: COMPLIANCE ARTIFACT UPDATES
----------------------------------------------------------------------

4.1 OSCAL Update Required?          [ ] YES [ ] NO
    If YES, component(s) to update: ________________________________

4.2 Lula Validation Update Required? [ ] YES [ ] NO
    If YES, validation file(s):      ________________________________

4.3 SSP Update Required?            [ ] YES [ ] NO
    If YES, sections affected:       ________________________________

4.4 POAM Update Required?           [ ] YES [ ] NO
    If YES, POAM item(s):            POAM-___

----------------------------------------------------------------------
PART 5: SIA CONCLUSION
----------------------------------------------------------------------

SIA Risk Rating:  [ ] LOW  [ ] MODERATE  [ ] HIGH  [ ] CRITICAL

Risk Rationale:
[Explain the risk rating based on SIA findings]

Required Actions Before Implementation:
1. [Action 1]
2. [Action 2]

SIA Recommendation:
[ ] Proceed — no significant security impact identified
[ ] Proceed with conditions (document in Change Request)
[ ] Escalate to Cat-M — boundary or re-authorization impact identified
[ ] Reject — unacceptable security risk

ISSO Signature: _____________________  Date: ___________
======================================================================
```

---

_This Change Management Process document is subject to annual review. Changes to this process itself require ISSO review and AO notification._

**Document Control:**

| Version     | Date       | Author | Change Summary                                                            |
| ----------- | ---------- | ------ | ------------------------------------------------------------------------- |
| 1.0 (Draft) | 2026-03-06 | ISSO   | Initial change management process per NIST SP 800-128 / NIST RMF Phase 2A |
| 1.1 (Draft) | 2026-06-03 | ISSO   | Added POAM-024 staging environment note (§3.8); retired STD-003 (OTel Collector deprecated 2026-05-31) |
| 1.2 (Draft) | 2026-06-14 | ISSO   | Updated STD-006 POAM reference to multi-posture POAM_INDEX.md; updated §9.2 POAM update procedure to reflect five-file POAM structure (POAM_INDEX, POAM_ISO42001, POAM_US_FED, POAM_EU_ECB, POAM_APAC_MAS); aligned with v0.1.0 tagged commit (tag applied, merged to main; stability not declared as of 2026-07-01) |
