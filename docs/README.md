# CAGE Documentation Index

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
**Last updated:** 2026-06-24

This directory is organised using a **hybrid layout**: function-based top-level sections, with compliance artefacts further sub-divided by jurisdiction. This mirrors the system's own architectural principle: ISO 42001 as the universal baseline, with jurisdiction-specific addenda for US_FED, EU_ECB, and APAC_MAS.

```
docs/
├── compliance/
│   ├── universal/      ← ISO 42001, CSA AARM, FIPS — applies to ALL regions
│   ├── us_fed/         ← NIST SP 800-53, NIST AI 600-1, FedRAMP, SR 26-2
│   ├── eu_ecb/         ← EU AI Act, GDPR, DORA
│   ├── apac_mas/       ← MAS FEAT, MAS Notice 655, MAS TRM
│   └── cross-region/   ← Multi-jurisdiction artefacts & analysis
├── governance/         ← Policies, oversight, roles (cross-cutting)
├── security/           ← Threat models, IR plans, audits
├── architecture/       ← System design & component architecture
├── operations/         ← Runbooks, deployment guides, process
├── project/            ← Roadmaps, analysis, release planning
└── technical-report/   ← Sequentially numbered technical report
```

---

## Jurisdiction Key

| Scope label | Meaning |
|---|---|
| **Universal** | Applies to all deployment regions (`US_FED`, `EU_ECB`, `APAC_MAS`) |
| **US_FED** | Applies only when `CAGE_DEPLOYMENT_REGION=US_FED` |
| **EU_ECB** | Applies only when `CAGE_DEPLOYMENT_REGION=EU_ECB` |
| **APAC_MAS** | Applies only when `CAGE_DEPLOYMENT_REGION=APAC_MAS` |

See [GOVERNANCE_CROSSWALK.md](compliance/cross-region/GOVERNANCE_CROSSWALK.md) for the full framework applicability table.

---

## `compliance/` — Regulatory & Audit Artefacts

### `compliance/universal/` — Universal (all regions)

| File | Description |
|---|---|
| [ISO_42001_COMPLIANCE.md](compliance/universal/ISO_42001_COMPLIANCE.md) | ISO/IEC 42001:2023 compliance statement |
| [ISO42001_MANAGEMENT_REVIEW.md](compliance/universal/ISO42001_MANAGEMENT_REVIEW.md) | Management review record |
| [SYSTEM_DESCRIPTION_ISO_42001.md](compliance/universal/SYSTEM_DESCRIPTION_ISO_42001.md) | System description for ISO 42001 scope |
| [AI_FAIRNESS_ASSESSMENT.md](compliance/universal/AI_FAIRNESS_ASSESSMENT.md) | AI fairness & bias assessment |
| [AUDIT_LOG_RETENTION_SCHEDULE.md](compliance/universal/AUDIT_LOG_RETENTION_SCHEDULE.md) | Audit log retention schedule |
| [PII_SCRUBBING_POLICY.md](compliance/universal/PII_SCRUBBING_POLICY.md) | PII scrubbing policy |
| [POAM_ISO42001.md](compliance/universal/POAM_ISO42001.md) | Plan of Action & Milestones — ISO 42001 (universal) |

### `compliance/us_fed/` — US Federal (NIST / FedRAMP / SR 26-2)

| File | Description |
|---|---|
| [NIST_AI_600_1_US_FED_ANALYSIS.md](compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md) | NIST AI 600-1 gap analysis |
| [AI_600_1_IMPLEMENTATION_PLAN.md](compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md) | NIST AI 600-1 implementation plan |
| [NIST_RMF_CHUNK1_CURRENT_STATE.md](compliance/us_fed/NIST_RMF_CHUNK1_CURRENT_STATE.md) | NIST RMF — current state |
| [NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md](compliance/us_fed/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md) | NIST RMF — Prepare & Categorise |
| [NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md](compliance/us_fed/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md) | NIST RMF — Select & Implement |
| [NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md](compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md) | NIST RMF — Assess & Authorise |
| [NIST_RMF_CHUNK5_MONITOR_ROADMAP.md](compliance/us_fed/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md) | NIST RMF — Monitor & Roadmap |
| [POAM_US_FED.md](compliance/us_fed/POAM_US_FED.md) | Plan of Action & Milestones — US Federal |
| [PHASE4_LULA_VALIDATION_PLAN.md](compliance/us_fed/PHASE4_LULA_VALIDATION_PLAN.md) | Lula validation plan (US_FED phase 4) |

### `compliance/eu_ecb/` — EU (EU AI Act / GDPR / DORA)

| File | Description |
|---|---|
| [GDPR_DPIA.md](compliance/eu_ecb/GDPR_DPIA.md) | GDPR Data Protection Impact Assessment |
| [EU_AI_OFFICE_REGISTRATION.md](compliance/eu_ecb/EU_AI_OFFICE_REGISTRATION.md) | EU AI Office registration record |
| [FRIA_ATTESTATION.md](compliance/eu_ecb/FRIA_ATTESTATION.md) | Fundamental Rights Impact Assessment |
| [DORA_RESILIENCE_TESTING_PROGRAMME.md](compliance/eu_ecb/DORA_RESILIENCE_TESTING_PROGRAMME.md) | DORA digital resilience testing programme |
| [POAM_EU_ECB.md](compliance/eu_ecb/POAM_EU_ECB.md) | Plan of Action & Milestones — EU |

### `compliance/apac_mas/` — APAC (MAS FEAT / Notice 655 / TRM)

| File | Description |
|---|---|
| [MAS_FEAT_T1_TRANSPARENCY_REPORT.md](compliance/apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md) | MAS FEAT Tier-1 transparency report |
| [MAS_NOTICE_655_CERTIFICATION.md](compliance/apac_mas/MAS_NOTICE_655_CERTIFICATION.md) | MAS Notice 655 certification |
| [POAM_APAC_MAS.md](compliance/apac_mas/POAM_APAC_MAS.md) | Plan of Action & Milestones — APAC |

### `compliance/cross-region/` — Multi-jurisdiction

| File | Description |
|---|---|
| [POAM_INDEX.md](compliance/cross-region/POAM_INDEX.md) | **Master POAM index** — cross-region traceability matrix |
| [GOVERNANCE_CROSSWALK.md](compliance/cross-region/GOVERNANCE_CROSSWALK.md) | Crosswalk: law → engineering artefacts |
| [JURISDICTIONAL_SEPARATION_ANALYSIS.md](compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) | Full jurisdictional separation audit (66 findings) |
| [ACCOUNT_MANAGEMENT_PROCEDURES.md](compliance/cross-region/ACCOUNT_MANAGEMENT_PROCEDURES.md) | Account management procedures |
| [POAM.md](compliance/cross-region/POAM.md) | Legacy POAM summary |
| [banking_regs.md](compliance/cross-region/banking_regs.md) | Banking regulation quick-reference |

---

## `governance/` — Policies, Oversight & Roles

| File | Description |
|---|---|
| [GOVERNANCE_OVERVIEW.md](governance/GOVERNANCE_OVERVIEW.md) | CAGE governance framework overview |
| [AGENTIC_SCOPE_STATEMENT.md](governance/AGENTIC_SCOPE_STATEMENT.md) | Agentic system scope statement |
| [HUMAN_OVERSIGHT_SCOPE.md](governance/HUMAN_OVERSIGHT_SCOPE.md) | Human oversight scope definition |
| [ROLES_AND_RESPONSIBILITIES.md](governance/ROLES_AND_RESPONSIBILITIES.md) | Roles and responsibilities |
| [CHANGE_MANAGEMENT_PROCESS.md](governance/CHANGE_MANAGEMENT_PROCESS.md) | Change management process |
| [MODEL_CARD_REVIEW.md](governance/MODEL_CARD_REVIEW.md) | AI model card review |
| [CAUSAL_AND_CBF_GOVERNANCE.md](governance/CAUSAL_AND_CBF_GOVERNANCE.md) | Causal & CBF governance |
| [NEURO_SYMBOLIC_GOVERNANCE.md](governance/NEURO_SYMBOLIC_GOVERNANCE.md) | Neuro-symbolic governance layer |

---

## `security/` — Threat Models, IR Plans & Audits

| File | Description |
|---|---|
| [SECURITY_AUDIT_REPORT.md](security/SECURITY_AUDIT_REPORT.md) | Security audit report |
| [SECURITY_ASSESSMENT_PLAN.md](security/SECURITY_ASSESSMENT_PLAN.md) | Security assessment plan |
| [SECURITY_STATUS.md](security/SECURITY_STATUS.md) | Current security status |
| [INCIDENT_RESPONSE_PLAN.md](security/INCIDENT_RESPONSE_PLAN.md) | Incident response plan (summary) |
| [IR_PLAN.md](security/IR_PLAN.md) | Full incident response plan |
| [HITL_TOCTOU_REMEDIATION.md](security/HITL_TOCTOU_REMEDIATION.md) | HITL TOCTOU vulnerability remediation |
| [STPA_ANALYSIS.md](security/STPA_ANALYSIS.md) | STPA (Systems Theoretic Process Analysis) |
| [SECRET_MANAGEMENT_OPTIONS.md](security/SECRET_MANAGEMENT_OPTIONS.md) | Secret management options analysis |

---

## `architecture/` — System Design

| File | Description |
|---|---|
| [ARCHITECTURE.md](architecture/ARCHITECTURE.md) | Full system architecture |
| [DUAL_PROJECT_ARCHITECTURE.md](architecture/DUAL_PROJECT_ARCHITECTURE.md) | Dual-project architecture |
| [EXTENSIBILITY_ARCHITECTURE.md](architecture/EXTENSIBILITY_ARCHITECTURE.md) | Extensibility architecture |
| [AGENT_OPS_ARCHITECTURE.md](architecture/AGENT_OPS_ARCHITECTURE.md) | Agent operations architecture |
| [GATEWAY_ARCHITECTURE.md](architecture/GATEWAY_ARCHITECTURE.md) | Inference gateway architecture (overview) |
| [INFERENCE_GATEWAY_ARCHITECTURE.md](architecture/INFERENCE_GATEWAY_ARCHITECTURE.md) | Inference gateway architecture (detail) |
| [LATENCY_STRATEGY.md](architecture/LATENCY_STRATEGY.md) | Latency strategy |
| [AUDIT_LOG_SCHEMA.md](architecture/AUDIT_LOG_SCHEMA.md) | Audit log schema |

---

## `operations/` — Runbooks, Deployment & Process

| File | Description |
|---|---|
| [RELEASE_RUNBOOK.md](operations/RELEASE_RUNBOOK.md) | Release runbook |
| [DEPLOYMENT_RULES.md](operations/DEPLOYMENT_RULES.md) | Deployment rules & constraints |
| [DEPLOYMENT_DECISION_RECORD.md](operations/DEPLOYMENT_DECISION_RECORD.md) | Deployment decision record |
| [DEPLOYMENT_FIX_REPORT_2026Q2.md](operations/DEPLOYMENT_FIX_REPORT_2026Q2.md) | Q2 2026 deployment fix report |
| [GIT_WORKFLOW_STANDARDS.md](operations/GIT_WORKFLOW_STANDARDS.md) | Git workflow standards |
| [HOW_TO_DEMO_OBSERVABILITY.md](operations/HOW_TO_DEMO_OBSERVABILITY.md) | Observability demo guide |
| [MCP_INTEGRATION_GUIDE.md](operations/MCP_INTEGRATION_GUIDE.md) | MCP integration guide |

---

## `project/` — Roadmaps, Analysis & Release Planning

| File | Description |
|---|---|
| [RELEASE_PLAN.md](project/RELEASE_PLAN.md) | Release plan |
| [V2_ROADMAP.md](project/V2_ROADMAP.md) | V2 roadmap |
| [PRODUCTION_READINESS_REPORT.md](project/PRODUCTION_READINESS_REPORT.md) | Production readiness report |
| [REPOSITORY_CLEANUP_PLAN.md](project/REPOSITORY_CLEANUP_PLAN.md) | Repository cleanup plan |
| [PROJECT_ANALYSIS.md](project/PROJECT_ANALYSIS.md) | Project analysis |
| [CODE_QUALITY_ANALYSIS.md](project/CODE_QUALITY_ANALYSIS.md) | Code quality analysis |
| [PRESENTATION_PROMPTS.md](project/PRESENTATION_PROMPTS.md) | Presentation prompts |
| [CAGE_ONE_PAGER.md](project/CAGE_ONE_PAGER.md) | CAGE executive one-pager |

---

## `technical-report/` — Technical Report Series

The `technical-report/` directory contains the sequentially numbered technical report.  
See [technical-report/README.md](technical-report/README.md) for the full index.

| File | Description |
|---|---|
| [01-SYSTEM-OVERVIEW.md](technical-report/01-SYSTEM-OVERVIEW.md) | System overview |
| [02-ARCHITECTURE.md](technical-report/02-ARCHITECTURE.md) | Architecture |
| [03-TECHNOLOGY-STACK.md](technical-report/03-TECHNOLOGY-STACK.md) | Technology stack |
| [04-AGENT-SYSTEM.md](technical-report/04-AGENT-SYSTEM.md) | Agent system |
| [05-AI-GOVERNANCE-POLICY-ENGINE.md](technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md) | AI governance & policy engine |
| [06-COMPLIANCE-STANDARDS.md](technical-report/06-COMPLIANCE-STANDARDS.md) | Compliance standards |
| [07-SECURITY-INFRASTRUCTURE.md](technical-report/07-SECURITY-INFRASTRUCTURE.md) | Security infrastructure |
| [08-DEPLOYMENT-INFRASTRUCTURE.md](technical-report/08-DEPLOYMENT-INFRASTRUCTURE.md) | Deployment infrastructure |
| [09-OPERATIONAL-RUNBOOK.md](technical-report/09-OPERATIONAL-RUNBOOK.md) | Operational runbook |
| [10-FORMAL-VERIFICATION.md](technical-report/10-FORMAL-VERIFICATION.md) | Formal verification |
