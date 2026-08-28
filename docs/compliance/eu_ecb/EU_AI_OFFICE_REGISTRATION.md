# EU AI Office Registration Runbook — CAGE Governed Financial Advisor

**Document:** EU-003 / EU AI Act Art. 6 + Annex III §5(b) / Art. 11 (Technical Documentation)
**Date:** 2026-06-24
**Status:** Draft — registration not yet initiated
**POAM:** EU-003 (POAM_EU_ECB.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only

---

> [!IMPORTANT]
> EU AI Office registration is **mandatory** before production deployment of CAGE in any EU_ECB context. The registration portal is accessible at [https://digital-strategy.ec.europa.eu/en/activities/eu-ai-office](https://digital-strategy.ec.europa.eu/en/activities/eu-ai-office). This runbook describes the steps; a designated EU compliance officer must execute them.

---

## 1. Classification Assessment

### High-Risk AI Determination

Under EU AI Act **Art. 6 + Annex III §5(b)**, AI systems used by financial institutions to:
- Evaluate the creditworthiness of natural persons
- Assess credit risks
- Gate access to financial resources or credit

...are classified as **High-Risk AI systems** and must be registered in the EU AI Office database.

**CAGE classification:** The Governed Financial Advisor pipeline makes credit-adjacent financial recommendations that influence access to financial resources. Under the precautionary principle, CAGE is classified as **High-Risk AI** for EU_ECB deployments.

**Legal basis for classification:**
- EU AI Act Art. 6(2): AI systems listed in Annex III are high-risk
- Annex III, Point 5(b): "AI systems intended to be used to evaluate the creditworthiness of natural persons or establish their credit score, with the exception of AI systems used for the purpose of detecting financial fraud"

---

## 2. EU AI Office Registration Procedure

### Step 1: Designate EU-Based Authorised Representative

**If CAGE's deployer is NOT established in the EU**, an EU-based authorised representative must be designated under Art. 22.

**Action:** Legal team to identify and designate EU-based authorised representative. Contact: [TBD]

### Step 2: Prepare Technical Documentation (Art. 11)

Art. 11 requires technical documentation covering:

| Requirement | CAGE Reference | Status |
|---|---|---|
| General description of the AI system | `docs/GOVERNANCE_OVERVIEW.md` | ✅ Available |
| Description of elements and development process | `docs/AGENT_OPS_ARCHITECTURE.md` | ✅ Available |
| Monitoring, functioning and control | `docs/HUMAN_OVERSIGHT_SCOPE.md` | ✅ Available |
| Risk management system | `docs/POAM_EU_ECB.md` + `docs/POAM_ISO42001.md` | ✅ Available |
| Data governance and data management practices | `docs/GDPR_DPIA.md`, `docs/PII_SCRUBBING_POLICY.md` | ✅ Available |
| Description of human oversight measures | `docs/HUMAN_OVERSIGHT_SCOPE.md` | ✅ Available |
| Description of changes throughout lifecycle | `CHANGELOG.md` | ✅ Available |
| Fundamental Rights Impact Assessment | `docs/FRIA_ATTESTATION.md` | 🟡 Draft |
| Post-market monitoring system | `docs/ISO42001_MANAGEMENT_REVIEW.md` | 🟡 Draft |

**Action:** Consolidate technical documentation into a single Art. 11 Technical Documentation Package. Recommended location: `compliance/eu_ai_act/technical_documentation/`

### Step 3: Conformity Assessment

Under Art. 43, conformity assessment for Annex III §5 systems may be:
- **Self-assessment** (internal control per Annex VI) — permitted for most Annex III §5 systems
- **Third-party assessment** — required if the system processes biometric data or is used in critical infrastructure (not applicable to CAGE)

**CAGE path:** Self-assessment under Annex VI (internal control procedure).

**Action:** Compliance officer to complete Annex VI self-assessment checklist and produce Declaration of Conformity.

### Step 4: CE Marking

For EU_ECB deployments where CAGE is considered an AI product (not a service), CE marking may be required under Art. 49. Legal review required.

**Action:** Legal team to determine whether CE marking is required for CAGE EU_ECB deployment.

### Step 5: Register in EU AI Office Database

**Portal:** [EU AI Office — AI Systems Registration](https://digital-strategy.ec.europa.eu/en/activities/eu-ai-office)

**Information required for registration:**
- Name and contact information of the provider/deployer
- Trade name of the AI system: "CAGE Governed Financial Advisor"
- Version: v3.0.0
- Purpose: Financial advisory and investment recommendation
- Classification: High-Risk AI (Annex III §5(b))
- Member states where deployed: [TBD — all EU_ECB deployment regions]
- EU AI Office registration number: [to be assigned]

---

## 3. Post-Registration Obligations

After registration, the following obligations apply under the EU AI Act:

| Obligation | Article | Cadence | Owner |
|---|---|---|---|
| Annual post-market monitoring report | Art. 61 | Annual | AI System Owner |
| Serious incident reporting | Art. 73 | Within 15 days of incident | Incident commander |
| Notify EU AI Office of significant changes | Art. 47 | Within 30 days of change | AI System Owner |
| FRIA update on material system changes | Art. 29a | On each material change | DPO + Compliance |

---

## 4. Timeline

| Step | Owner | Target Date | Status |
|---|---|---|---|
| Designate EU authorised representative | Legal | 2026-07-31 | Pending |
| Prepare Art. 11 technical documentation package | Compliance + Engineering | 2026-08-15 | Pending |
| Complete Annex VI self-assessment | Compliance | 2026-08-31 | Pending |
| Register in EU AI Office database | Compliance | 2026-09-15 | Pending |
| Obtain EU AI Office registration number | EU AI Office | 2026-09-30 | Pending |

---

## Related Documents

- `docs/FRIA_ATTESTATION.md` — EU AI Act Art. 29a FRIA
- `docs/GDPR_DPIA.md` — GDPR Art. 35 DPIA
- `docs/POAM_EU_ECB.md` — EU-003 POAM item
- `docs/GOVERNANCE_OVERVIEW.md` — Art. 11 general description
