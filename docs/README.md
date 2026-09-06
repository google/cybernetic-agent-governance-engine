# CAGE Documentation Index

**System:** Cybernetic Agent Governance Engine (CAGE) — Domain-Agnostic Agentic AI Governance Platform

> **Domain-agnostic by design:** The governance kernel (`src/gateway/`) owns all enforcement *mechanism* and holds no domain knowledge. Domain semantics arrive exclusively through optional `cage.plugins` packages. Two **example domains of equal standing** ship in-tree — finance ([`src/cage_finance/`](../src/cage_finance/)) and healthcare ([`src/cage_healthcare/`](../src/cage_healthcare/)) — and adopters add their own under `src/cage_<domain>/` for manufacturing, logistics, energy, critical infrastructure, or any other vertical. Neither shipped plugin is privileged, and neither is required: `CAGE_ACTIVE_PLUGINS=""` runs the bare substrate.
>
> Some domain-flavoured identifiers appear in older documents and in the finance reference application (e.g. `safety:current_cash`, `execute_trade`, `FiscalLimitGuard`). These belong to the **finance example domain**, not to the kernel. See [EXTENSIBILITY_ARCHITECTURE.md](architecture/EXTENSIBILITY_ARCHITECTURE.md).
>
> **Jurisdictional compliance is likewise configuration.** `US_FED`, `EU_ECB`, and `APAC_MAS` are configurable postures selected with `CAGE_DEPLOYMENT_REGION`, layered over the universal ISO 42001 baseline. Adding a jurisdiction is a config-only operation — see the Jurisdiction Key below.
**Last updated:** 2026-08-28

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
| **Universal** | Applies to all deployment regions — ISO 42001 baseline, always active |
| **US_FED** | Applies only when `CAGE_DEPLOYMENT_REGION=US_FED` |
| **EU_ECB** | Applies only when `CAGE_DEPLOYMENT_REGION=EU_ECB` |
| **APAC_MAS** | Applies only when `CAGE_DEPLOYMENT_REGION=APAC_MAS` |
| **LOCAL** | Development default — universal baseline only, no jurisdictional extension |
| **Custom** | Any adopter-defined region added under `config/thresholds/` and `config/compliance/` |

Jurisdictional postures are **configuration, not code**. Select one at deploy time:

```bash
export CAGE_DEPLOYMENT_REGION=US_FED    # or EU_ECB, APAC_MAS, LOCAL, or your own
```

To add a jurisdiction, create `config/thresholds/<REGION>_BASELINE.json` and `config/compliance/<REGION>_BASELINE.json` following the existing schema, register region-specific Rego under `config/opa/` and Lula assertions under `compliance/lula/`, then ship a `<REGION>_OVERLAY.json` inside each active domain plugin. No Python changes are required.

See [GOVERNANCE_CROSSWALK.md](compliance/cross-region/GOVERNANCE_CROSSWALK.md) for the full framework applicability table and [REGION_GUARD_AUDIT.md](compliance/REGION_GUARD_AUDIT.md) for region-guard enforcement.

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

## Mathematical Formalism Reference Index

| Document | Mathematical Formalism | Source Code Reference |
|---|---|---|
| [technical-report/10-FORMAL-VERIFICATION.md](technical-report/10-FORMAL-VERIFICATION.md) | CBF safe-set definition, routing seal asymmetric proof, provenance chain integrity, fiscal limit invariant | [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py), [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) |
| [governance/CAUSAL_AND_CBF_GOVERNANCE.md](governance/CAUSAL_AND_CBF_GOVERNANCE.md) | Discrete-time CBF condition `h(S(t+1)) ≥ (1−γ)·h(S(t))`, causal SCM, confabulation scoring, consensus protocol | [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py), [`src/gateway/governance/causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py) |
| [governance/GOVERNANCE_OVERVIEW.md](governance/GOVERNANCE_OVERVIEW.md) | 8-tier symbolic governor pipeline (FTRA + 7 in-pipeline tiers), STPA UCAs (FIN-1, FIN-2, UCA-5, UCA-6), mathematical invariants | [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py), [`src/gateway/governance/ontology.py`](../src/gateway/governance/ontology.py) |
| [governance/NEURO_SYMBOLIC_GOVERNANCE.md](governance/NEURO_SYMBOLIC_GOVERNANCE.md) | Formal safety properties, FRIA zone thresholds (`get_fria_zone_allow()=0.95`, `get_fria_zone_defer()=0.70`), regional compliance invariants | [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py), [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py) |
| [architecture/GATEWAY_ARCHITECTURE.md](architecture/GATEWAY_ARCHITECTURE.md) | CBF layer integration, routing seal enforcement, governance pipeline data-flow | [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py), [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) |

### Key Named Constants & Thresholds (source: [`config/thresholds/`](../config/thresholds/), [`src/gateway/governance/schemas/thresholds.py`](../src/gateway/governance/schemas/thresholds.py))

| Accessor Function | Default Baseline | Role |
|---|---|---|
| `get_causal_lock_p_value_threshold()` | `0.05` | Significance threshold for PlaceboTreatmentRefuter (Tier 6) |
| `get_causal_lock_placebo_effect_magnitude()` | `0.2` | Maximum tolerated placebo effect magnitude |
| `get_causal_lock_risk_boundary()` | `0.95` | Risk boundary above which causal lock is enforced |
| `get_fria_zone_allow()` | `0.95` | Confidence floor for autonomous approval (Tier 6b) |
| `get_fria_zone_defer()` | `0.70` | Confidence floor for deferred human review (Tier 6b) |
| `get_agent_confidence_threshold()` | `0.95` | Fast-fail confidence threshold (Tier 1) |

---

## `governance/` — Policies, Oversight & Roles

| File | Description |
|---|---|
| [GOVERNANCE_OVERVIEW.md](governance/GOVERNANCE_OVERVIEW.md) | CAGE governance framework overview — **8-tier pipeline (FTRA + 7 in-pipeline tiers), STPA UCAs, mathematical invariants** |
| [AGENTIC_SCOPE_STATEMENT.md](governance/AGENTIC_SCOPE_STATEMENT.md) | Agentic system scope statement |
| [HUMAN_OVERSIGHT_SCOPE.md](governance/HUMAN_OVERSIGHT_SCOPE.md) | Human oversight scope definition |
| [CAUSAL_AND_CBF_GOVERNANCE.md](governance/CAUSAL_AND_CBF_GOVERNANCE.md) | Causal & CBF governance — **CBF condition, causal SCM, confabulation, consensus** |
| [NEURO_SYMBOLIC_GOVERNANCE.md](governance/NEURO_SYMBOLIC_GOVERNANCE.md) | Neuro-symbolic governance layer — **formal safety properties, FRIA zones, regional compliance** |
| [OPA_MIGRATION_PROCESS.md](governance/OPA_MIGRATION_PROCESS.md) | OPA policy migration process |

> **Note:** Organizational process templates (change management, incident response,
> roles & responsibilities, security assessment) previously lived under
> `docs/governance/` and `docs/security/`. They have been removed — this is a
> reference architecture, not an operating organization, and fictional
> role-incumbent placeholders (`[TBD]`) provided no engineering value. Adopters
> deploying CAGE in a real regulated environment should author their own
> process documents using `docs/compliance/` as the control-mapping reference.

---

## `security/` — Threat Models, IR Plans & Audits

| File | Description |
|---|---|
| [SECURITY_STATUS.md](security/SECURITY_STATUS.md) | Current security status |
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
| [GATEWAY_ARCHITECTURE.md](architecture/GATEWAY_ARCHITECTURE.md) | Inference gateway architecture (overview) — **CBF layer, routing seal, governance pipeline** |
| [INFERENCE_GATEWAY_ARCHITECTURE.md](architecture/INFERENCE_GATEWAY_ARCHITECTURE.md) | Inference gateway architecture (detail) |
| [LATENCY_STRATEGY.md](architecture/LATENCY_STRATEGY.md) | Latency strategy |
| [AUDIT_LOG_SCHEMA.md](architecture/AUDIT_LOG_SCHEMA.md) | Audit log schema |
| [SUBSTRATE_MOAT_STRATEGY.md](architecture/SUBSTRATE_MOAT_STRATEGY.md) | Competitive positioning — CAGE vs MXC/ACS, AAIF, Google AGW |

---

## `operations/` — Runbooks, Deployment & Process

| File | Description |
|---|---|
| [DEPLOYMENT_RULES.md](operations/DEPLOYMENT_RULES.md) | Deployment rules & constraints |
| [DEPLOYMENT_DECISION_RECORD.md](operations/DEPLOYMENT_DECISION_RECORD.md) | Deployment decision record |
| [GIT_WORKFLOW_STANDARDS.md](operations/GIT_WORKFLOW_STANDARDS.md) | Git workflow standards |
| [HOW_TO_DEMO_OBSERVABILITY.md](operations/HOW_TO_DEMO_OBSERVABILITY.md) | Observability demo guide |

---

## `project/` — Roadmaps, Analysis & Release Planning

| File | Description |
|---|---|
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
| [10-FORMAL-VERIFICATION.md](technical-report/10-FORMAL-VERIFICATION.md) | Formal verification — **CBF, routing seal, provenance chain, fiscal limit** |
