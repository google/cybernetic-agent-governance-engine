# CAGE Jurisdictional Separation Refactoring Analysis

**Report Date:** 2026-06-15  
**Scope:** Full codebase — source code, deployment scripts, documentation, compliance artifacts  
**Authority (at time of report):** `.roo/rules` Sections 1–14, `docs/GIT_WORKFLOW_STANDARDS.md`, `docs/DEPLOYMENT_RULES.md`
**Status:** FINDINGS ONLY — historical record; most HIGH/CRITICAL findings have since been remediated (see closure notes inline) or superseded by the current [`AGENTS.md`](../../../AGENTS.md), [`docs/operations/GIT_WORKFLOW_STANDARDS.md`](../../operations/GIT_WORKFLOW_STANDARDS.md), and [`docs/operations/DEPLOYMENT_RULES.md`](../../operations/DEPLOYMENT_RULES.md)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architectural Principles Under Review](#2-architectural-principles-under-review)
3. [Source Code Findings (Phase 1)](#3-source-code-findings-phase-1)
4. [Deployment & Infrastructure Findings (Phase 2)](#4-deployment--infrastructure-findings-phase-2)
5. [Documentation Findings (Phase 3)](#5-documentation-findings-phase-3)
6. [Compliance Artifacts Findings (Phase 4)](#6-compliance-artifacts-findings-phase-4)
7. [Cross-Cutting Systemic Patterns](#7-cross-cutting-systemic-patterns)
8. [Remediation Roadmap](#8-remediation-roadmap)
9. [Correct Reference Implementations](#9-correct-reference-implementations)

---

## 1. Executive Summary

This report presents the findings of a comprehensive jurisdictional separation analysis conducted across all layers of the CAGE (Cybernetic AI Governance Engine) codebase. The analysis examined source code, deployment scripts, Kubernetes manifests, Terraform infrastructure, CI/CD pipelines, documentation, and compliance artifacts.

### Finding Totals

| Phase | Scope | Findings | Critical | High | Medium | Low |
|-------|-------|----------|----------|------|--------|-----|
| Phase 1 | Source Code | 10 | 2 | 3 | 5 | 1 |
| Phase 2 | Deployment & Infrastructure | 27 | 0 | 13 | 9 | 5 |
| Phase 3 | Documentation | 21 | 0 | 7 | 9 | 5 |
| Phase 4 | Compliance Artifacts | 8 | 0 | 3 | 4 | 1 |
| **TOTAL** | **All Layers** | **66** | **2** | **26** | **27** | **12** |

### Root Cause

The dominant root cause across all 66 findings is a single architectural drift: **NIST SP 800-53 / US_FED has been used as the implicit universal baseline** throughout the codebase, when the mandated architecture requires **ISO 42001 as the sole universal standard**. This manifests as:

- NIST controls annotated on universal Kubernetes resources
- `cage_deployment_region` defaulting to `US_FED` in Terraform
- `enable_nist_compliance` as the only infrastructure hardening toggle
- NIST control references in shared utility functions without region guards
- Missing EU_ECB and APAC_MAS CI compliance gates (the US_FED gate exists and is correctly implemented)
- Zero Lula validation files for EU_ECB or APAC_MAS jurisdictions

### Immediate Risk

Two **CRITICAL** findings require immediate remediation before any production deployment:

1. **FINDING-01** (`src/compliance_bridge/types.py:122`) — `CONTROL_META` flat dict exposes all frameworks (NIST, EU AI Act) to all regions via the `/v1/controls`, `/v1/metrics`, and `/v1/oscal` endpoints.
2. **FINDING-02** (`src/gateway/governance/iso_control.py:109`) — Inverted region guard in `stamp_iso_control()` silences the entire ISO 42001 audit trail for EU_ECB and APAC_MAS deployments.

---

## 2. Architectural Principles Under Review

The following principles are mandated by `.roo/rules` and must be enforced at every layer:

### 2.1 The Jurisdictional Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    UNIVERSAL LAYER                          │
│              ISO 42001 (applies to ALL regions)             │
│   Controls: A.5.2, A.5.3, A.9.2, A.10.1, A.6.1, A.8.4    │
└──────────────┬──────────────┬──────────────────────────────┘
               │              │              │
    ┌──────────▼──┐  ┌────────▼──┐  ┌───────▼──────┐
    │   US_FED    │  │  EU_ECB   │  │  APAC_MAS    │
    │ NIST SP     │  │ EU AI Act │  │ MAS FEAT     │
    │ 800-53      │  │ GDPR      │  │ MAS Notice   │
    │ NIST AI     │  │ DORA      │  │ 655          │
    │ 600-1       │  │ MiFID II  │  │ MAS TRM      │
    │ FedRAMP     │  │           │  │ §4.2, §6.3   │
    └─────────────┘  └───────────┘  └──────────────┘
    CAGE_DEPLOYMENT_REGION=US_FED | EU_ECB | APAC_MAS
```

### 2.2 Enforcement Rules

| Rule | Requirement |
|------|-------------|
| **R-1** | ISO 42001 controls MUST be active in all regions with no `CAGE_DEPLOYMENT_REGION` guard |
| **R-2** | NIST SP 800-53 / AI 600-1 logic MUST be gated on `CAGE_DEPLOYMENT_REGION == "US_FED"` |
| **R-3** | EU AI Act / GDPR / DORA logic MUST be gated on `CAGE_DEPLOYMENT_REGION == "EU_ECB"` |
| **R-4** | MAS FEAT / MAS Notice 655 / MAS TRM logic MUST be gated on `CAGE_DEPLOYMENT_REGION == "APAC_MAS"` |
| **R-5** | Shared utilities MUST contain only ISO 42001 constructs; jurisdictional extensions via override/extension mechanisms only |
| **R-6** | Data structures MUST namespace universal vs. jurisdictional fields explicitly |
| **R-7** | Deployment scripts MUST propagate `CAGE_DEPLOYMENT_REGION` and gate jurisdictional components on it |
| **R-8** | Documentation MUST label every requirement as Universal, US_FED, EU_ECB, or APAC_MAS |
| **R-9** | Lula validation files MUST carry `cage.region` metadata annotations |
| **R-10** | OSCAL profiles MUST declare their jurisdictional scope explicitly |

---

## 3. Source Code Findings (Phase 1)

> **Scope:** `src/compliance_bridge/`, `src/gateway/governance/`, `src/gateway/server/`, `src/governed_financial_advisor/governance/`, `src/governed_financial_advisor/graph/nodes/`, `src/governed_financial_advisor/utils/`

---

### FINDING-01 🔴 CRITICAL — Flat `CONTROL_META` dict mixes all frameworks universally

| Attribute | Value |
|-----------|-------|
| **File** | `src/compliance_bridge/types.py:122` |
| **Violation** | Type 1 — Jurisdictional Intermixing |
| **Severity** | CRITICAL |
| **Rule Violated** | R-2, R-3, R-5, R-6 |

**Issue:** `CONTROL_META` is a flat dict that mixes ISO 42001 controls (universal) with NIST SA-11/SC-7/SC-8/IR-1, FedRAMP AC-2 (US_FED only), and EU AI Act Article 12/13 (EU_ECB only) in a single structure with no `CAGE_DEPLOYMENT_REGION` guard. Every downstream consumer — the `/v1/controls` endpoint, `/v1/metrics`, `/v1/oscal` export, and the SLA monitor — exposes all frameworks to all regions.

**Impact:** An EU_ECB deployment's `/v1/controls` API response includes NIST FedRAMP controls. An APAC_MAS deployment's compliance metrics include EU AI Act assertions. This constitutes misleading compliance evidence that could invalidate an audit.

**Remediation:**

```python
# BEFORE (violation):
CONTROL_META = {
    "A.5.2": {"framework": "ISO 42001", "title": "AI policy"},
    "SC-7":  {"framework": "NIST SP 800-53", "title": "Boundary Protection"},  # US_FED only
    "Art.12": {"framework": "EU AI Act", "title": "Transparency"},              # EU_ECB only
}

# AFTER (correct):
_UNIVERSAL_CONTROLS = {
    "A.5.2": {"framework": "ISO 42001", "title": "AI policy"},
    "A.5.3": {"framework": "ISO 42001", "title": "AI roles"},
}

_JURISDICTIONAL_CONTROLS: dict[str, dict] = {
    "US_FED": {
        "SC-7":  {"framework": "NIST SP 800-53", "title": "Boundary Protection"},
        "AC-2":  {"framework": "NIST SP 800-53 / FedRAMP", "title": "Account Management"},
    },
    "EU_ECB": {
        "Art.12": {"framework": "EU AI Act", "title": "Transparency"},
        "Art.13": {"framework": "EU AI Act", "title": "Information provision"},
    },
    "APAC_MAS": {
        "MAS-FEAT-1": {"framework": "MAS FEAT", "title": "Fairness"},
    },
}

def get_control_meta(region: str) -> dict:
    """Return controls applicable to the given deployment region."""
    return {
        **_UNIVERSAL_CONTROLS,
        **_JURISDICTIONAL_CONTROLS.get(region, {}),
    }
```

---

### FINDING-02 🔴 CRITICAL — Inverted region guard silences ISO 42001 audit trail

| Attribute | Value |
|-----------|-------|
| **File** | `src/gateway/governance/iso_control.py:109` |
| **Violation** | Type 2 — Missing Region Guard (inverted) |
| **Severity** | CRITICAL |
| **Rule Violated** | R-1 |

**Issue:** `stamp_iso_control()` has an inverted region guard: it returns immediately for any region that is not `US_FED`. The intent was to suppress NIST-specific span attributes in EU/APAC, but the implementation silences the **entire function**, producing zero OTel compliance evidence for EU_ECB and APAC_MAS deployments. The ISO 42001 audit trail is completely broken for those regions.

**Impact:** EU_ECB and APAC_MAS deployments produce no ISO 42001 compliance telemetry. Any audit relying on OTel spans for ISO 42001 evidence will find zero evidence for non-US deployments.

**Remediation:**

```python
# BEFORE (violation — inverted guard kills universal ISO 42001 stamping):
def stamp_iso_control(span, control_id: str, region: str) -> None:
    if region != "US_FED":
        return  # BUG: silences ALL regions except US_FED
    span.set_attribute("cage.iso_control", control_id)
    span.set_attribute("cage.nist_control", NIST_MAP.get(control_id, ""))

# AFTER (correct — ISO 42001 always stamped; NIST only for US_FED):
def stamp_iso_control(span, control_id: str, region: str) -> None:
    # Universal: ISO 42001 evidence always produced
    span.set_attribute("cage.iso_control", control_id)
    span.set_attribute("cage.iso_framework", "ISO/IEC 42001:2023")
    # Jurisdictional extension: NIST mapping only for US_FED
    if region == "US_FED":
        span.set_attribute("cage.nist_control", NIST_MAP.get(control_id, ""))
    elif region == "EU_ECB":
        span.set_attribute("cage.eu_ai_act_control", EU_MAP.get(control_id, ""))
    elif region == "APAC_MAS":
        span.set_attribute("cage.mas_feat_control", MAS_MAP.get(control_id, ""))
```

---

### FINDING-03 🟠 HIGH — `validate_cmek_configuration()` cites NIST universally

| Attribute | Value |
|-----------|-------|
| **File** | `src/compliance_bridge/cmek_guard.py:73` |
| **Violation** | Type 1 — Jurisdictional Intermixing |
| **Severity** | HIGH |
| **Rule Violated** | R-2, R-3, R-4 |

**Issue:** `validate_cmek_configuration()` runs unconditionally in all regions and cites `NIST SC-28 / FedRAMP HIGH` as the universal encryption requirement. EU_ECB deployments should cite GDPR Art. 32; APAC_MAS should cite MAS TRM §9.1.

**Remediation:** Add a `region` parameter. Emit the correct regulatory citation based on `CAGE_DEPLOYMENT_REGION`. The underlying CMEK validation logic is universal (ISO 42001 A.8.4); only the citation label is jurisdictional.

---

### FINDING-04 🟠 HIGH — `TradingKnowledgeGraph.ISO_CONTROL_MAP` embeds EU controls as class attributes

| Attribute | Value |
|-----------|-------|
| **File** | `src/gateway/governance/ontology.py:162` |
| **Violation** | Type 1 — Jurisdictional Intermixing |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-6 |

**Issue:** `TradingKnowledgeGraph.ISO_CONTROL_MAP` embeds `GDPR Art. 22`, `EU AI Act Art. 10`, and `EU AI Act Art. 29a` as class attributes alongside universal ISO controls. A comment notes EU-only scope but no runtime guard enforces it. Also contains `FISCAL_CONTROLS → SC-4` (NIST) as a universal entry.

**Remediation:** Move EU-specific entries to a `_EU_ECB_CONTROL_MAP` class attribute. Move NIST entries to `_US_FED_CONTROL_MAP`. Expose a `get_control_map(region: str)` classmethod that merges universal + jurisdictional maps.

---

### FINDING-05 ✅ REMEDIATED — `EVIDENCE_SLA_SECONDS` mixes ISO and NIST SLA targets

| Attribute | Value |
|-----------|-------|
| **File** | `src/compliance_bridge/types.py:285` |
| **Violation** | Type 1 — Jurisdictional Intermixing |
| **Severity** | HIGH |
| **Rule Violated** | R-2, R-6 |

**Issue:** `EVIDENCE_SLA_SECONDS` mixes ISO and NIST SLA targets in a flat dict. The SLA monitor iterates all entries in all regions, generating spurious breach alerts for NIST SA-11/SC-7/SC-8 in EU_ECB and APAC_MAS deployments.

**Remediation:** Apply the same split pattern as FINDING-01: `_UNIVERSAL_SLA` (ISO 42001 controls only) + `_JURISDICTIONAL_SLA` per region. The SLA monitor must call `get_sla_seconds(region)` rather than iterating the flat dict.

**Status: ✅ REMEDIATED.** `src/compliance_bridge/types.py` defines `_UNIVERSAL_SLA`, `_JURISDICTIONAL_SLA`, and the `get_sla_seconds(region)` accessor exactly as recommended above. `src/compliance_bridge/sla_monitor.py` now calls `get_sla_seconds(CAGE_DEPLOYMENT_REGION)` via the `_active_sla_seconds()` helper (resolved fresh on every poll cycle, defaulting to `""` → universal-only when unset, mirroring the `active_region` resolution pattern in `main.py`). Jurisdictional SLA targets (`SC-7`/`SC-8` for `US_FED`, `Article 12` for `EU_ECB`, `MAS-FEAT-1` for `APAC_MAS`) are now correctly monitored for staleness only in their applicable region, with no cross-region spurious alerts. Covered by 6 dedicated tests in `tests/test_compliance_bridge_tier2.py::TestSlaMonitor`. See also `docs/technical-report/06-COMPLIANCE-STANDARDS.md` §5.3.1.

---

### FINDING-06 🟡 MEDIUM — `/v1/controls` endpoint returns all frameworks to all regions

| Attribute | Value |
|-----------|-------|
| **File** | `src/compliance_bridge/main.py:332` |
| **Violation** | Type 2 — Missing Region Guard |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2, R-3, R-4 |

**Issue:** The `/v1/controls` endpoint returns all entries from `SUPPORTED_CONTROLS` (which includes NIST/FedRAMP/EU AI Act) without filtering by `CAGE_DEPLOYMENT_REGION`.

**Remediation:** Read `CAGE_DEPLOYMENT_REGION` from environment at startup. Filter `SUPPORTED_CONTROLS` through `get_control_meta(region)` before returning. Add a `X-CAGE-Deployment-Region` response header so API consumers know which region's controls are being returned.

---

### FINDING-07 🟡 MEDIUM — `pii_audit_retention_days` hardcodes FISMA AU-11 as universal default

| Attribute | Value |
|-----------|-------|
| **File** | `src/gateway/governance/schemas/thresholds.py:129` |
| **Violation** | Type 3 — Insufficient Namespacing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2, R-6 |

**Issue:** `pii_audit_retention_days: int = 90  # FISMA AU-11` hardcodes a US federal retention requirement as the universal Pydantic default. EU_ECB deployments are subject to GDPR Art. 5(1)(e) storage limitation; APAC_MAS to MAS Notice 655.

**Remediation:** Remove the hardcoded default. Load retention days from the appropriate baseline JSON (`US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json`) based on `CAGE_DEPLOYMENT_REGION`. Add a `pii_audit_retention_authority: str` field that carries the applicable regulatory citation.

---

### FINDING-08 🟡 MEDIUM — `pii_audit_log()` cites FISMA AU-11 universally

| Attribute | Value |
|-----------|-------|
| **File** | `src/gateway/governance/pii_sanitizer.py:201` |
| **Violation** | Type 1 — Jurisdictional Intermixing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2, R-3, R-4 |

**Issue:** `pii_audit_log()` cites `FISMA AU-11` as the universal retention authority with no `CAGE_DEPLOYMENT_REGION` guard.

**Remediation:** Add `region: str` parameter. Emit the correct citation: `FISMA AU-11` for US_FED, `GDPR Art. 5(1)(e)` for EU_ECB, `MAS Notice 655 §4.3` for APAC_MAS.

---

### FINDING-09 🟡 MEDIUM — HITL and prompt injection modules declare US_FED scope in docstrings only

| Attribute | Value |
|-----------|-------|
| **Files** | `src/gateway/governance/hitl_escalator.py:15`, `src/gateway/governance/prompt_injection_detector.py:15` |
| **Violation** | Type 2 — Missing Region Guard |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2 |

**Issue:** Both modules declare `Region: US_FED` in their docstrings but contain no runtime `CAGE_DEPLOYMENT_REGION` check. The HITL SLA of 4 hours (SR 26-2 §3.2) is a US Federal Reserve requirement applied universally.

**Remediation:** Add runtime guards: `if os.environ.get("CAGE_DEPLOYMENT_REGION") == "US_FED":` around SR 26-2-specific SLA enforcement. For EU_ECB, apply DORA Art. 10 HITL requirements. For APAC_MAS, apply MAS FEAT §3.2 requirements.

---

### FINDING-10 🟢 LOW — `scrub_pii()` lacks GDPR Art. 17 and MAS Notice 655 audit trails

| Attribute | Value |
|-----------|-------|
| **File** | `src/governed_financial_advisor/utils/privacy.py:25` |
| **Violation** | Type 4 — Shared Utility Contamination (by omission) |
| **Severity** | LOW |
| **Rule Violated** | R-3, R-4 |

**Issue:** `scrub_pii()` performs universal PII scrubbing with no GDPR Art. 17 (right to erasure) logging or MAS Notice 655-specific audit trail for EU_ECB and APAC_MAS deployments.

**Remediation:** Add an optional `emit_jurisdiction_audit: bool = False` parameter. When `CAGE_DEPLOYMENT_REGION` is EU_ECB or APAC_MAS, emit a structured audit log entry citing the applicable regulation.

---

## 4. Deployment & Infrastructure Findings (Phase 2)

> **Scope:** `deploy_all.sh`, `scripts/`, `deployment/k8s/`, `deployment/opa_config.yaml`, `infra/`, `.github/workflows/`

---

### DEP-01 🟠 HIGH — `enable_nist_compliance` activated by `--env prod`, not by `CAGE_DEPLOYMENT_REGION`

| Attribute | Value |
|-----------|-------|
| **File** | `deploy_all.sh:238` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | HIGH |
| **Rule Violated** | R-2, R-7 |

**Issue:** `enable_nist_compliance=true` is injected into Terraform whenever `--env prod` is passed, regardless of `CAGE_DEPLOYMENT_REGION`. A `prod` deployment to EU_ECB or APAC_MAS activates NIST-specific infrastructure hardening (SC-7, AC-3, deletion protection, Redis replication, PDB creation) for non-US deployments.

**Remediation:**
```bash
# BEFORE (violation):
if [[ "$env" == "prod" ]]; then
  tf_args+=("-var=enable_nist_compliance=true")
fi

# AFTER (correct):
_cage_region="${CAGE_DEPLOYMENT_REGION:-}"
if [[ "$env" == "prod" && "$_cage_region" == "US_FED" ]]; then
  tf_args+=("-var=enable_nist_compliance=true")
fi
```

---

### DEP-02 🟠 HIGH — `load_env()` does not propagate `CAGE_DEPLOYMENT_REGION` to Terraform

| Attribute | Value |
|-----------|-------|
| **File** | `deploy_all.sh:100` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | HIGH |
| **Rule Violated** | R-7 |

**Issue:** `load_env()` reads and exports many infrastructure variables from `.env` as `TF_VAR_*`, but does not read or export `CAGE_DEPLOYMENT_REGION`. If the operator forgets to pass `--var-file=eu-dev.tfvars`, the Terraform default (`US_FED`) silently applies to any deployment.

**Remediation:** Add to `load_env()`:
```bash
_cage_region=$(_read_env_var CAGE_DEPLOYMENT_REGION)
[[ -n "$_cage_region" ]] && export TF_VAR_cage_deployment_region="$_cage_region"
```

---

### DEP-03 🟠 HIGH — `scripts/automated_auditor.py` defaults to SaaS Langfuse for all regions

| Attribute | Value |
|-----------|-------|
| **File** | `scripts/automated_auditor.py:56` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-7 |

**Issue:** `_LANGFUSE_HOST = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")` defaults to the SaaS endpoint. For EU_ECB deployments, all Langfuse traffic must remain within `europe-west1` (GDPR Art. 44). Routing audit traces to the SaaS endpoint constitutes a cross-border data transfer without a legal basis.

**Remediation:**
```python
_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "")
_langfuse_host = os.environ.get("LANGFUSE_HOST", "")
if not _langfuse_host:
    if _region in ("EU_ECB", "APAC_MAS"):
        raise RuntimeError(
            f"LANGFUSE_HOST must be explicitly set for {_region} deployments "
            "to ensure data residency compliance. Do not use cloud.langfuse.com."
        )
    _langfuse_host = "https://cloud.langfuse.com"  # US_FED only fallback
```

---

### DEP-04 🟠 HIGH — `deployment/k8s/gateway.yaml` hardcodes `us-central1` and `CAGE_ENV: dev`

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/gateway.yaml:38` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | HIGH |
| **Rule Violated** | R-7 |

**Issue:** `GOOGLE_CLOUD_LOCATION: "us-central1"` and `CAGE_ENV: "dev"` are hardcoded. An EU_ECB deployment using this manifest would have its gateway pod routing GCP SDK calls to the wrong region. `CAGE_ENV: "dev"` prevents production-mode enforcement regardless of actual environment.

**Remediation:** Convert to `deployment/k8s/gateway.yaml.tpl` with `${GOOGLE_CLOUD_LOCATION}` and `${CAGE_ENV}` substituted at deploy time from `CAGE_DEPLOYMENT_REGION`.

---

### DEP-05 🟠 HIGH — `deployment/k8s/financial-advisor.yaml` hardcodes `us-central1`

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/financial-advisor.yaml:98` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | HIGH |
| **Rule Violated** | R-7 |

**Issue:** Same as DEP-04 — `GOOGLE_CLOUD_LOCATION: "us-central1"` hardcoded. Financial advisor pod would route GCP SDK calls to the wrong region in EU_ECB and APAC_MAS deployments.

**Remediation:** Convert to `.yaml.tpl` template or inject from `advisor-secrets`.

---

### DEP-06 🟠 HIGH — `deployment/k8s/agentsight-daemon.yaml` deploys to wrong namespace; no GDPR guard

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/agentsight-daemon.yaml:15` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-7 |

**Issue:** The DaemonSet is deployed to `governance-stack` namespace but its own comment states "Deploy to agentsight namespace, not governance-stack." Additionally, `hostPID: true`, `hostNetwork: true`, and `privileged: true` are not gated on any `CAGE_DEPLOYMENT_REGION`. For EU_ECB deployments, privileged host-level SSL interception raises GDPR Art. 32 concerns.

**Remediation:** Move to `agentsight` namespace. Add documentation note for EU_ECB/APAC_MAS deployments regarding data minimisation implications of SSL interception.

---

### DEP-07 🟠 HIGH — `deployment/k8s/compliance-bridge.yaml` sets `OSCAL_S3_REGION: "auto"`

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/compliance-bridge.yaml:88` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-4, R-7 |

**Issue:** `OSCAL_S3_REGION: "auto"` delegates bucket location to GCS defaults, which may not respect data residency requirements. OSCAL compliance evidence must be stored within `europe-west1` for EU_ECB and `asia-southeast1` for APAC_MAS.

**Remediation:** Set `OSCAL_S3_REGION` from `CAGE_DEPLOYMENT_REGION` at deploy time. Add startup validation that the bucket's actual location matches the expected region.

---

### DEP-08 🟠 HIGH — `infra/targets/gcp-gke/variables.tf` defaults `region` to `us-central1`

| Attribute | Value |
|-----------|-------|
| **File** | `infra/targets/gcp-gke/variables.tf:22` |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-4, R-7 |

**Issue:** `variable "region" { default = "us-central1" }` and `variable "zone" { default = "us-central1-a" }`. Without a var-file, all GCP resources are provisioned in `us-central1` regardless of `CAGE_DEPLOYMENT_REGION`, silently violating GDPR Art. 44 and MAS TRM §4.2.

**Remediation:** Remove defaults. Require explicit setting. Add cross-validation `locals` block.

---

### DEP-09 🟠 HIGH — `cage_deployment_region` defaults to `"US_FED"` in Terraform

| Attribute | Value |
|-----------|-------|
| **File** | `infra/targets/gcp-gke/variables.tf:546` |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | HIGH |
| **Rule Violated** | R-7 |

**Issue:** `variable "cage_deployment_region" { default = "US_FED" }`. Any deployment that does not explicitly set this variable silently deploys with US_FED compliance posture. Combined with `region` defaulting to `us-central1`, a misconfigured EU or APAC deployment would provision infrastructure in the wrong GCP region AND apply the wrong compliance posture.

**Remediation:** Remove the `"US_FED"` default. Add a Terraform `validation` block cross-checking `cage_deployment_region` against `region`.

---

### DEP-10 🟠 HIGH — `langfuse_events` GCS bucket has no region/jurisdiction precondition

| Attribute | Value |
|-----------|-------|
| **File** | `infra/targets/gcp-gke/main.tf:129` |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-4 |

**Issue:** The `langfuse_events` GCS bucket is created with `location = var.region` but there is no `precondition` validating that `var.region` is consistent with `var.cage_deployment_region`. A misconfigured deployment could create the compliance evidence bucket in the wrong region without any Terraform-level error.

**Remediation:**
```hcl
lifecycle {
  precondition {
    condition = (
      (var.cage_deployment_region == "EU_ECB"   && startswith(var.region, "europe-")) ||
      (var.cage_deployment_region == "APAC_MAS" && startswith(var.region, "asia-"))   ||
      (var.cage_deployment_region == "US_FED"   && startswith(var.region, "us-"))
    )
    error_message = "GCS bucket region must match cage_deployment_region data residency requirements."
  }
}
```

---

### DEP-11 🟠 HIGH — `infra/modules/app_secrets/main.tf` hardcodes `AWS_REGION = "us-east-1"`

| Attribute | Value |
|-----------|-------|
| **File** | `infra/modules/app_secrets/main.tf:77` |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-4 |

**Issue:** The `gcs_credentials` Kubernetes Secret hardcodes `AWS_REGION = "us-east-1"` in all deployments. For EU_ECB deployments, any S3-compatible client reading this secret would attempt to route to `us-east-1`, violating GDPR Art. 44.

**Remediation:** Derive `AWS_REGION` from `var.cage_deployment_region`: EU_ECB → `eu-west-1`, APAC_MAS → `ap-southeast-1`, US_FED → `us-east-1`.

---

### DEP-12 🟠 HIGH — No `eu-prod.tfvars` or `apac-prod.tfvars` exist

| Attribute | Value |
|-----------|-------|
| **File** | [`infra/targets/gcp-gke/prod.tfvars`](../../../infra/targets/gcp-gke/prod.tfvars) |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | HIGH |
| **Rule Violated** | R-7 |

**Issue:** `prod.tfvars` hardcodes `region = "us-central1"` and does not set `cage_deployment_region`. There are no `eu-prod.tfvars` or `apac-prod.tfvars` files. EU_ECB and APAC_MAS production deployments are architecturally undefined at the Terraform layer.

**Remediation:** Create `eu-prod.tfvars` and `apac-prod.tfvars`. Update `prod.tfvars` to explicitly set `cage_deployment_region = "US_FED"`.

---

### DEP-13 🟠 HIGH — Missing EU_ECB and APAC_MAS CI compliance gate workflows

| Attribute | Value |
|-----------|-------|
| **File** | `.github/workflows/security-scan.yml:17` |
| **Violation** | Type D — CI/CD Pipeline Conflation |
| **Severity** | HIGH |
| **Rule Violated** | R-3, R-4 |

**Issue:** The `security-scan.yml` workflow header explicitly states "EU_ECB: EU AI Act / GDPR (separate workflow)" and "APAC_MAS: MAS FEAT / MAS Notice 655 (separate workflow)" — but these separate workflows **do not exist**. The US_FED `nist-compliance-gate` job is correctly implemented and gated on `CAGE_DEPLOYMENT_REGION == 'US_FED'`, but the equivalent gates for EU_ECB and APAC_MAS are entirely absent.

**Remediation:** Create `.github/workflows/eu-ecb-compliance.yml` and `.github/workflows/apac-mas-compliance.yml` with jurisdiction-specific gates.

---

### DEP-14 🟡 MEDIUM — `deploy_all.sh` usage text describes `prod` as "NIST compliance"

| Attribute | Value |
|-----------|-------|
| **File** | `deploy_all.sh:49` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** Usage documentation describes `prod` as "NIST compliance, full security" universally, embedding a US_FED-centric assumption into the script's public interface.

**Remediation:** Update usage text to clarify that `--env prod` activates baseline hardening, and that jurisdiction-specific compliance posture is controlled by `--var-file` combined with `CAGE_DEPLOYMENT_REGION`.

---

### DEP-15 🟡 MEDIUM — `scripts/verify_remote.py` hardcodes `us-central1` fallback URL

| Attribute | Value |
|-----------|-------|
| **File** | `scripts/verify_remote.py:31` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | MEDIUM |
| **Rule Violated** | R-7 |

**Issue:** `_FALLBACK_URL = "https://governed-financial-advisor-bhsafl7fda-uc.a.run.app"` hardcodes a `us-central1` endpoint. If `CAGE_GATEWAY_URL` is not set and this script is run against an EU_ECB or APAC_MAS deployment, it silently verifies the wrong (US) endpoint.

**Remediation:** Remove the hardcoded fallback. Require `CAGE_GATEWAY_URL` to be explicitly set and fail with a clear error if absent.

---

### DEP-16 🟡 MEDIUM — NIST SP 800-53 annotations on all K8s NetworkPolicy resources

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/network-policy-hardening.yaml:27` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2, R-8 |

**Issue:** All five NetworkPolicy resources carry `compliance.nist.gov/control: "SC-7,AC-4,SC-23"` and `compliance.nist.gov/standard: "SP-800-53-Rev5"` unconditionally. For EU_ECB and APAC_MAS deployments, these annotations create misleading compliance evidence.

**Remediation:** Use jurisdiction-neutral labels (e.g., `cage.io/control: "boundary-protection"`) and map to framework-specific controls in the compliance bridge, or generate jurisdiction-specific manifests from templates.

---

### DEP-17 🟡 MEDIUM — NIST SC-39 labels on all Namespace definitions in `pod-security-admission.yaml`

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/pod-security-admission.yaml:33` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2, R-8 |

**Issue:** The Namespace definitions for `governance-stack`, `langfuse`, and `vllm` all carry NIST SP 800-53 compliance labels unconditionally. Pod Security Standards are a universal Kubernetes security control, not NIST-specific.

**Remediation:** Use ISO 42001 labels for PSS controls; add NIST labels only in US_FED-specific manifest overlays.

---

### DEP-18 🟡 MEDIUM — `deployment/k8s/lula-cron.yaml` does not read `CAGE_DEPLOYMENT_REGION`

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/k8s/lula-cron.yaml:214` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-7 |

**Issue:** The Lula CronJob hardcodes `SUPPORTED_CONTROLS = ["A.5.2", "A.5.3", "A.9.2", "SC-4"]` and has no mechanism to add jurisdiction-specific controls based on `CAGE_DEPLOYMENT_REGION`.

**Remediation:** Inject `CAGE_DEPLOYMENT_REGION` into the CronJob pod environment and extend `SUPPORTED_CONTROLS` conditionally per jurisdiction.

---

### DEP-19 🟡 MEDIUM — OPA policy bundle has no jurisdiction-specific overlay mechanism

| Attribute | Value |
|-----------|-------|
| **File** | `deployment/opa_config.yaml:64` |
| **Violation** | Type B — K8s Manifests Without Jurisdictional Namespacing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-7 |

**Issue:** The OPA policy bundle (`trade_governance.rego`) is universal and does not vary by `CAGE_DEPLOYMENT_REGION`. There is no mechanism to load jurisdiction-specific OPA policy overlays (EU AI Act Art. 22, MAS FEAT fairness rules) based on the deployment region.

**Remediation:** Add a `cage_deployment_region` label to OPA status output. Implement a bundle-loading mechanism that conditionally loads jurisdiction-specific Rego overlays based on `CAGE_DEPLOYMENT_REGION`.

---

### DEP-20 🟡 MEDIUM — `infra/targets/gcp-gke/main.tf` Redis/PostgreSQL hardening only via `enable_nist_compliance`

| Attribute | Value |
|-----------|-------|
| **File** | `infra/targets/gcp-gke/main.tf:210` |
| **Violation** | Type C — Terraform Missing Region Guards |
| **Severity** | MEDIUM |
| **Rule Violated** | R-3 |

**Issue:** Redis, PostgreSQL, and ClickHouse hardening is controlled exclusively by `enable_nist_compliance`. For EU_ECB deployments, DORA Art. 10 mandates HA and GDPR Art. 32 mandates encryption at rest — these EU-specific requirements are not activated by any EU_ECB-specific flag.

**Remediation:** Introduce `enable_eu_ecb_compliance` variable (or derive HA/encryption requirements from `cage_deployment_region`) so EU_ECB deployments can independently activate DORA-required HA.

---

### DEP-21 🟡 MEDIUM — `.github/workflows/ci.yml` runs AI 600-1 Lula validation universally

| Attribute | Value |
|-----------|-------|
| **File** | `.github/workflows/ci.yml:119` |
| **Violation** | Type D — CI/CD Pipeline Conflation |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2 |

**Issue:** The `lula-ai600-validation` CI job runs unconditionally on all branches and PRs. AI 600-1 is a US federal framework. Running it as a universal CI gate implies it is a prerequisite for all deployments, contradicting the principle that only ISO 42001 is the universal standard.

**Remediation:** Add `if: vars.CAGE_DEPLOYMENT_REGION == 'US_FED' || vars.CAGE_DEPLOYMENT_REGION == ''` to the job, or move it to a US_FED-specific workflow.

---

### DEP-22 🟡 MEDIUM — CBRN keyword check asserts `tier1_keywords_cbrn_enabled == True` universally

| Attribute | Value |
|-----------|-------|
| **File** | `.github/workflows/ci.yml:245` |
| **Violation** | Type D — CI/CD Pipeline Conflation |
| **Severity** | MEDIUM |
| **Rule Violated** | R-2 |

**Issue:** The CBRN keyword check asserts `cfg.get('tier1_keywords_cbrn_enabled') == True` with a comment "for US_FED deployment", but this check runs unconditionally on all branches. If `tier1_keywords_cbrn_enabled` is `False` for an EU_ECB or APAC_MAS deployment, this CI job would fail for non-US deployments even though the configuration is intentionally different.

**Remediation:** Gate the `tier1_keywords_cbrn_enabled == True` assertion on `CAGE_DEPLOYMENT_REGION == 'US_FED'`.

---

### DEP-23 🟢 LOW — `scripts/verify_all.py` runs OPA checks without region awareness

| Attribute | Value |
|-----------|-------|
| **File** | `scripts/verify_all.py:43` |
| **Violation** | Type A — Missing Region Flags |
| **Severity** | LOW |
| **Rule Violated** | R-7 |

**Remediation:** Add `CAGE_DEPLOYMENT_REGION` check and conditionally run jurisdiction-specific OPA test suites. Document clearly that this script covers only universal ISO 42001 controls.

---

### DEP-24 🟢 LOW — `.github/workflows/ci.yml` Langfuse posture check hardcodes `us-central1`

| Attribute | Value |
|-----------|-------|
| **File** | `.github/workflows/ci.yml:99` |
| **Violation** | Type D — CI/CD Pipeline Conflation |
| **Severity** | LOW |
| **Rule Violated** | R-7 |

**Remediation:** Parameterise `GOOGLE_CLOUD_LOCATION` from `CAGE_DEPLOYMENT_REGION` in the CI job, or add separate posture check jobs for each jurisdiction.

---

### DEP-25 🟢 LOW — Universal CI security jobs reference NIST control identifiers in names

| Attribute | Value |
|-----------|-------|
| **File** | `.github/workflows/security-scan.yml:47` |
| **Violation** | Type D — CI/CD Pipeline Conflation |
| **Severity** | LOW |
| **Rule Violated** | R-8 |

**Remediation:** Add jurisdiction-aware reporting labels. When `CAGE_DEPLOYMENT_REGION != 'US_FED'`, suppress NIST control references in job names and substitute the applicable framework's control identifiers.

---

### Phase 2 Summary

| File | Findings | Highest Severity |
|------|----------|-----------------|
| `deploy_all.sh` | 3 | 🟠 HIGH |
| `scripts/automated_auditor.py` | 1 | 🟠 HIGH |
| `scripts/verify_remote.py` | 1 | 🟡 MEDIUM |
| `scripts/verify_all.py` | 1 | 🟢 LOW |
| `deployment/k8s/gateway.yaml` | 1 | 🟠 HIGH |
| `deployment/k8s/financial-advisor.yaml` | 1 | 🟠 HIGH |
| `deployment/k8s/agentsight-daemon.yaml` | 1 | 🟠 HIGH |
| `deployment/k8s/compliance-bridge.yaml` | 1 | 🟠 HIGH |
| `deployment/k8s/network-policy-hardening.yaml` | 1 | 🟡 MEDIUM |
| `deployment/k8s/pod-security-admission.yaml` | 1 | 🟡 MEDIUM |
| `deployment/k8s/lula-cron.yaml` | 1 | 🟡 MEDIUM |
| `deployment/opa_config.yaml` | 1 | 🟡 MEDIUM |
| `infra/targets/gcp-gke/variables.tf` | 2 | 🟠 HIGH |
| `infra/targets/gcp-gke/main.tf` | 2 | 🟠 HIGH |
| `infra/modules/app_secrets/main.tf` | 1 | 🟠 HIGH |
| `infra/targets/gcp-gke/prod.tfvars` | 1 | 🟠 HIGH |
| `.github/workflows/security-scan.yml` | 2 | 🟠 HIGH |
| `.github/workflows/ci.yml` | 3 | 🟡 MEDIUM |

---

## 5. Documentation Findings (Phase 3)

> **Scope:** `docs/`, `infra/modules/*/README.md`, `README.md`, `COMPLIANCE.md`, `CONTRIBUTING.md`, `compliance/lula/README.md`

---

### DOC-01 🟠 HIGH — `README.md` presents NIST as co-equal with ISO 42001 in badge row

| Attribute | Value |
|-----------|-------|
| **File** | `README.md:1` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | HIGH |
| **Rule Violated** | R-8 |

**Issue:** The README badge row displays NIST SP 800-53, EU AI Act, and MAS FEAT badges at the same visual level as ISO 42001, implying all four are co-equal universal standards. This is the first thing every reader sees and sets an incorrect mental model.

**Remediation:** Restructure the badge row into two tiers: (1) Universal: ISO 42001 badge; (2) Jurisdictional: NIST SP 800-53 (US_FED), EU AI Act (EU_ECB), MAS FEAT (APAC_MAS) badges with a "Jurisdictional Extensions" label.

---

### DOC-02 🟠 HIGH — `README.md` compliance table has no "Jurisdiction" column

| Attribute | Value |
|-----------|-------|
| **File** | `README.md:133` |
| **Violation** | Type H — Missing Explicit Labeling |
| **Severity** | HIGH |
| **Rule Violated** | R-8 |

**Issue:** The compliance standards table lists ISO 42001, NIST SP 800-53, EU AI Act, GDPR, DORA, MAS FEAT, and MAS Notice 655 without a "Jurisdiction" or "Scope" column. A reader cannot determine which standards are universal versus regional.

**Remediation:** Add a "Scope" column with values: `Universal`, `US_FED only`, `EU_ECB only`, `APAC_MAS only`. Add a footnote explaining the ISO 42001 universal baseline architecture.

---

### DOC-03 ✅ CLOSED — `docs/IR_PLAN.md` presented NIST SP 800-61 as the universal IRP foundation

> **Closed 2026-07:** `docs/security/IR_PLAN.md` (and the duplicate `docs/security/INCIDENT_RESPONSE_PLAN.md`) were deleted as part of a documentation-scope cleanup. CAGE is a reference architecture, not an operating organization — a fictional Incident Response Plan with placeholder `[TBD]` role incumbents and no real Authorizing Official provided no engineering value. Adopters deploying CAGE in a real regulated environment should author their own jurisdiction-aware IRP, using the compliance mapping in `docs/compliance/` as the control-traceability reference.

**Original finding (for historical record):** The Incident Response Plan opened with NIST SP 800-61 as the foundational framework with no ISO 42001 baseline section. NIST SP 800-61 is a US federal standard. EU_ECB deployments are subject to DORA Art. 17-23 incident reporting; APAC_MAS to MAS TRM §11. A real IRP should add a "Universal Baseline (ISO 42001 A.10.1)" section as the opening section, and restructure with explicit `### US_FED (NIST SP 800-61)`, `### EU_ECB (DORA Art. 17-23)`, and `### APAC_MAS (MAS TRM §11)` subsections.

---

### DOC-04 ✅ CLOSED — `docs/IR_PLAN.md` had no multi-jurisdiction incident notification structure

> **Closed 2026-07:** See DOC-03 — the source file was deleted.

**Original finding (for historical record):** The incident notification procedures section did not distinguish between US_FED (CISA notification within 72 hours), EU_ECB (DORA Art. 19 — competent authority notification within 4 hours for major ICT incidents), and APAC_MAS (MAS TRM §11.3 — MAS notification within 1 hour for P1 incidents). All three have different timelines and recipients. A real IRP should create jurisdiction-specific notification tables with timelines, recipients, and regulatory citations for each of the three jurisdictions.

---

### DOC-05 🟠 HIGH — `infra/modules/gcp_gke_cluster/NIST_CONTROLS.md` has no ISO 42001 universal baseline

| Attribute | Value |
|-----------|-------|
| **File** | `infra/modules/gcp_gke_cluster/NIST_CONTROLS.md:1` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | HIGH |
| **Rule Violated** | R-8 |

**Issue:** The GKE cluster module's compliance documentation is titled "NIST Controls" and contains only NIST SP 800-53 control mappings. There is no ISO 42001 universal baseline section. Developers using this module for EU_ECB or APAC_MAS deployments would apply NIST controls universally.

**Remediation:** Rename to `COMPLIANCE_CONTROLS.md`. Add an "ISO 42001 Universal Controls" section first. Retitle the NIST section as "US_FED Additional Controls (NIST SP 800-53)". Add "EU_ECB Additional Controls" and "APAC_MAS Additional Controls" sections.

---

### DOC-06 🟠 HIGH — `infra/modules/gcp_gke_cluster/README.md` uses "NIST Compliance" as synonym for "production"

| Attribute | Value |
|-----------|-------|
| **File** | `infra/modules/gcp_gke_cluster/README.md:57` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | HIGH |
| **Rule Violated** | R-8 |

**Issue:** The README uses the heading "Production Environment (NIST Compliance)" implying that NIST compliance is the definition of production-readiness for all regions. EU_ECB and APAC_MAS production environments have different compliance requirements.

**Remediation:** Change heading to "Production Environment (ISO 42001 Baseline + Jurisdictional Hardening)". Add a table showing which `enable_*_compliance` flags apply to which region.

---

### DOC-07 🟠 HIGH — `docs/INFERENCE_GATEWAY_ARCHITECTURE.md` presents SR 26-2 as primary architectural driver

| Attribute | Value |
|-----------|-------|
| **File** | `docs/INFERENCE_GATEWAY_ARCHITECTURE.md:3` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | HIGH |
| **Rule Violated** | R-8 |

**Issue:** SR 26-2 (Federal Reserve supervisory guidance) is presented as a primary architectural driver without US_FED qualification. SR 26-2 has "no legal force" outside the US Federal Reserve system (per `.roo/rules` Section 12.4). Presenting it as a universal architectural driver contradicts the "no legal force" sentinel requirement.

**Remediation:** Add a `> **US_FED Only:** SR 26-2 applies exclusively to CAGE_DEPLOYMENT_REGION=US_FED deployments.` callout wherever SR 26-2 is referenced. Add an ISO 42001 section as the primary architectural driver.

---

### DOC-08 🟡 MEDIUM — `docs/AUDIT_LOG_SCHEMA.md` regulatory mapping table has no jurisdiction column

| Attribute | Value |
|-----------|-------|
| **File** | `docs/AUDIT_LOG_SCHEMA.md:180` |
| **Violation** | Type E — Ambiguous Universal vs. Jurisdictional Scope |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** The regulatory compliance mapping table lists MiFID II, GDPR, NIST AI RMF, and DORA alongside each other with no jurisdiction column. A reader cannot determine which regulations apply to their deployment region.

**Remediation:** Add a "Jurisdiction" column: MiFID II → EU_ECB, GDPR → EU_ECB, NIST AI RMF → US_FED, DORA → EU_ECB. Add ISO 42001 rows for universal controls.

---

### DOC-09 🟡 MEDIUM — `docs/LATENCY_STRATEGY.md` presents NIST as universal latency authority

| Attribute | Value |
|-----------|-------|
| **File** | `docs/LATENCY_STRATEGY.md:1` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** The latency strategy document opens with NIST SP 800-53 AU-12 as the universal latency and audit logging authority. AU-12 is a US federal control. EU_ECB deployments are subject to DORA Art. 10 audit logging requirements; APAC_MAS to MAS Notice 655.

**Remediation:** Add ISO 42001 A.9.2 as the universal audit logging baseline. Add jurisdiction-specific latency SLA tables for each region citing the applicable regulation.

---

### DOC-10 🟡 MEDIUM — `docs/SECURITY_AUDIT_REPORT.md` NIST SP 800-53 controls table has no US_FED label

| Attribute | Value |
|-----------|-------|
| **File** | `docs/SECURITY_AUDIT_REPORT.md:758` |
| **Violation** | Type G — Incorrect Hierarchy Presentation |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** The NIST SP 800-53 controls table in the security audit report has no "US_FED only" label. The ISO 42001 table has no "Universal" label. A reader cannot distinguish which findings apply to their deployment.

**Remediation:** Add `> **Scope: US_FED only** (CAGE_DEPLOYMENT_REGION=US_FED)` above the NIST table. Add `> **Scope: Universal** (all CAGE_DEPLOYMENT_REGION values)` above the ISO 42001 table.

---

### DOC-11 🟡 MEDIUM — `docs/DEPLOYMENT_RULES.md` deployment commands lack jurisdiction labels

| Attribute | Value |
|-----------|-------|
| **File** | `docs/DEPLOYMENT_RULES.md:168` |
| **Violation** | Type H — Missing Explicit Labeling |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** Deployment command examples do not indicate which jurisdiction they target. A reader cannot determine whether a given command is appropriate for their region.

**Remediation:** Add jurisdiction labels to all command examples: `# US_FED deployment`, `# EU_ECB deployment`, `# APAC_MAS deployment`. Add a prerequisite table showing which `--var-file` and `CAGE_DEPLOYMENT_REGION` value to use for each jurisdiction.

---

### DOC-12 🟡 MEDIUM — `COMPLIANCE.md` mixes universal and jurisdictional compliance items without delineation

| Attribute | Value |
|-----------|-------|
| **File** | `COMPLIANCE.md:70` |
| **Violation** | Type E — Ambiguous Universal vs. Jurisdictional Scope |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** The compliance checklist mixes ISO 42001 universal items with NIST, EU AI Act, and MAS FEAT items without clear section headers distinguishing universal from jurisdictional requirements.

**Remediation:** Restructure into four sections: "Universal (ISO 42001 — all deployments)", "US_FED only (NIST SP 800-53 / AI 600-1)", "EU_ECB only (EU AI Act / GDPR / DORA)", "APAC_MAS only (MAS FEAT / MAS Notice 655 / MAS TRM)".

---

### DOC-13 🟡 MEDIUM — `infra/modules/k8s_namespace/README.md` PSA labels documented as NIST SC-39

| Attribute | Value |
|-----------|-------|
| **File** | `infra/modules/k8s_namespace/README.md:84` |
| **Violation** | Type H — Missing Explicit Labeling |
| **Severity** | MEDIUM |
| **Rule Violated** | R-8 |

**Issue:** Pod Security Admission labels are documented as implementing NIST SC-39 universally. PSA is a universal Kubernetes security control; NIST SC-39 is a US_FED-specific citation.

**Remediation:** Document PSA labels as implementing ISO 42001 A.8.4 (universal). Add a note that for US_FED deployments, this also satisfies NIST SC-39.

---

### DOC-14 ✅ CLOSED — `docs/IR_PLAN.md` SR 26-2 HITL SLA presented as universal

> **Closed 2026-07:** See DOC-03 — the source file was deleted. The correct universal-vs-regional HITL SLA callout pattern is preserved and enforced in [`docs/governance/HUMAN_OVERSIGHT_SCOPE.md`](../../governance/HUMAN_OVERSIGHT_SCOPE.md#sla-requirements-by-region).

---

### Phase 3 Summary

| File | Findings | Highest Severity |
|------|----------|-----------------|
| `README.md` | 2 | 🟠 HIGH |
| `docs/IR_PLAN.md` | 3 | ✅ CLOSED (file deleted) |
| `infra/modules/gcp_gke_cluster/NIST_CONTROLS.md` | 1 | 🟠 HIGH |
| `infra/modules/gcp_gke_cluster/README.md` | 1 | 🟠 HIGH |
| `docs/INFERENCE_GATEWAY_ARCHITECTURE.md` | 1 | 🟠 HIGH |
| `docs/AUDIT_LOG_SCHEMA.md` | 1 | 🟡 MEDIUM |
| `docs/LATENCY_STRATEGY.md` | 1 | 🟡 MEDIUM |
| `docs/SECURITY_AUDIT_REPORT.md` | 1 | 🟡 MEDIUM |
| `docs/DEPLOYMENT_RULES.md` | 1 | 🟡 MEDIUM |
| `COMPLIANCE.md` | 1 | 🟡 MEDIUM |
| `infra/modules/k8s_namespace/README.md` | 1 | 🟡 MEDIUM |
| `docs/IR_PLAN.md` (SR 26-2) | 1 | ✅ CLOSED (file deleted) |

---

## 6. Compliance Artifacts Findings (Phase 4)

> **Scope:** `compliance/lula/`, `compliance/oscal/`, `config/thresholds/`, `src/governed_financial_advisor/governance/policy/trade_governance.rego`

---

### CA-01 🟠 HIGH — `lula-validation-sc4.yaml` has three incompatible jurisdictional identities

| Attribute | Value |
|-----------|-------|
| **File** | [`compliance/lula/lula-validation-sc4.yaml`](../../../compliance/lula/lula-validation-sc4.yaml) |
| **Violation** | Type I — Lula Validation Scope Ambiguity |
| **Severity** | HIGH |
| **Rule Violated** | R-9 |

**Issue:** This file simultaneously claims: (1) `cage.compliance-posture: nist-sp800-53` in Lula metadata, (2) `source: https://www.iso.org/standard/81230.html` (ISO 42001) in `component-definition.yaml`, and (3) "System Constraint SC-4" (CAGE custom) in the file header. NIST SP 800-53 Rev 5 `SC-4` is "Information in Shared System Resources" — a completely different control from the CAGE-internal fiscal limits control.

**Remediation:** Rename to a CAGE-internal namespace (e.g., `CAGE-SC-4`). Remove `nist-sp800-53` posture annotation. In `component-definition.yaml`, move it to a `cage-custom` source URI. In the Lula README, list it under "CAGE Custom Controls," not NIST SP 800-53.

---

### CA-02 🟠 HIGH — Five AI 600-1 Lula stubs lack machine-readable `cage.region: US_FED` metadata

| Attribute | Value |
|-----------|-------|
| **Files** | [`compliance/lula/lula-validation-ai600-cbrn.yaml`](../../../compliance/lula/lula-validation-ai600-cbrn.yaml), [`lula-validation-ai600-confabulation.yaml`](../../../compliance/lula/lula-validation-ai600-confabulation.yaml), [`lula-validation-ai600-data-privacy.yaml`](../../../compliance/lula/lula-validation-ai600-data-privacy.yaml), [`lula-validation-ai600-human-ai-config.yaml`](../../../compliance/lula/lula-validation-ai600-human-ai-config.yaml), [`lula-validation-ai600-prompt-injection.yaml`](../../../compliance/lula/lula-validation-ai600-prompt-injection.yaml) |
| **Violation** | Type I — Lula Validation Scope Ambiguity |
| **Severity** | HIGH |
| **Rule Violated** | R-9 |

**Issue:** All five AI 600-1 stub files declare `Region: US_FED` only in a comment but have no `metadata.annotations` block with `cage.region: US_FED`. Without machine-readable metadata, automated tooling cannot programmatically skip these files for non-US_FED deployments.

**Remediation:** Add a `metadata.annotations` block to all five files:
```yaml
metadata:
  annotations:
    cage.region: US_FED
    cage.compliance-posture: nist-ai-600-1
    cage.posture-note: "NIST AI 600-1 is a US Federal posture requirement. This validation MUST NOT run for EU_ECB or APAC_MAS deployments."
```

---

### CA-03 🟠 HIGH — Zero Lula validation files exist for EU_ECB or APAC_MAS jurisdictions

| Attribute | Value |
|-----------|-------|
| **File** | [`compliance/lula/README.md`](../../../README.md) |
| **Violation** | Type I — Lula Validation Scope Ambiguity |
| **Severity** | HIGH |
| **Rule Violated** | R-9 |

**Issue:** The entire Lula validation suite contains zero validation files for EU_ECB-specific controls (EU AI Act Art. 9, GDPR Art. 22, DORA Art. 10) and zero validation files for APAC_MAS-specific controls (MAS FEAT, MAS Notice 655, MAS TRM §6.3). The `.roo/rules` Sections 5.3 and 5.4 list EU_ECB and APAC_MAS release gates, but there are no Lula files to satisfy them.

**Remediation:** Create the following Lula validation files:

**EU_ECB:**
- `lula-validation-eu-ai-act-art9.yaml` — EU AI Act Art. 9 risk management system
- `lula-validation-gdpr-art22.yaml` — GDPR Art. 22 human oversight of automated decisions
- `lula-validation-dora-art10.yaml` — DORA Art. 10 ICT audit logging

**APAC_MAS:**
- `lula-validation-mas-feat.yaml` — MAS FEAT fairness assessment
- `lula-validation-mas-notice655.yaml` — MAS Notice 655 audit logging
- `lula-validation-mas-trm-s6.yaml` — MAS TRM §6.3 AI controls

Each file must carry `cage.region: EU_ECB` or `cage.region: APAC_MAS` in `metadata.annotations`.

---

### CA-04 🟡 MEDIUM — `lula-validation-aarm-vectors.yaml` universal scope cross-references NIST controls in notes

| Attribute | Value |
|-----------|-------|
| **File** | [`compliance/lula/lula-validation-aarm-vectors.yaml`](../../../compliance/lula/lula-validation-aarm-vectors.yaml) |
| **Violation** | Type I — Lula Validation Scope Ambiguity |
| **Severity** | MEDIUM |
| **Rule Violated** | R-9 |

**Issue:** This file has `cage.region: ALL` (universal scope) but its `notes` section cross-references US_FED-only NIST SP 800-53 controls as the mitigating evidence: `AARM-V2 → SC-4`, `AARM-V3 → SC-4, A.8.4`, `AARM-V4 → SC-4, SC-8`, etc. An EU_ECB or APAC_MAS deployment running this universal validation sees NIST control references that have no legal or regulatory standing in those jurisdictions.

**Remediation:** Replace NIST control references in `notes` with ISO 42001 or CAGE-internal identifiers for the universal section. Add a US_FED-only subsection for NIST mappings. Provide EU AI Act and MAS FEAT equivalent mappings for the same AARM vectors.

---

### CA-05 🟡 MEDIUM — `lula-validation-aarm-vectors.yaml` listed as both "Stub" and "Active" in README

| Attribute | Value |
|-----------|-------|
| **File** | [`compliance/lula/README.md`](../../../README.md) |
| **Violation** | Type I — Lula Validation Scope Ambiguity |
| **Severity** | MEDIUM |
| **Rule Violated** | R-9 |

**Issue:** The README table lists `lula-validation-aarm-vectors.yaml` as `Status: 🔶 Stub` but the Posture Architecture Alignment section counts it as `1 Active (ALL scope)`. A stub that always returns `true` provides no real compliance assurance, yet it is listed as a universal release gate in `.roo/rules` Section 5.1.

**Remediation:** Reconcile the status. If the AARM validation is a stub, remove it from the "Active" count and from the release gate list until it has real assertions.

---

### CA-06 🟡 MEDIUM — `compliance/oscal/component-definition.yaml` mixes ISO 42001 and NIST in same component

| Attribute | Value |
|-----------|-------|
| **File** | [`compliance/oscal/component-definition.yaml`](../../../compliance/oscal/component-definition.yaml) |
| **Violation** | Type J — OSCAL Schema Jurisdictional Mixing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-6, R-9 |

**Issue:** The OSCAL component definition mixes ISO 42001 controls with NIST SP 800-53 controls in the same component without clear framework separation. A component implementing both ISO 42001 A.5.2 and NIST AC-2 in the same `control-implementations` block makes it impossible to filter by jurisdiction.

**Remediation:** Separate into two `control-implementations` blocks: one for ISO 42001 (universal) and one for NIST SP 800-53 (US_FED only), with explicit `framework-id` references. Add `props` with `name: cage-deployment-region` and `value: US_FED` to all NIST control implementations.

---

### CA-07 🟡 MEDIUM — Missing OSCAL profiles for EU_ECB (EU AI Act) and APAC_MAS (MAS FEAT)

| Attribute | Value |
|-----------|-------|
| **File** | `compliance/oscal/` |
| **Violation** | Type J — OSCAL Schema Jurisdictional Mixing |
| **Severity** | MEDIUM |
| **Rule Violated** | R-9 |

**Issue:** The `compliance/oscal/` directory contains `sp800053-profile.yaml` (US_FED), `eu-ai-act-profile.yaml` (EU_ECB), and `mas-feat-profile.yaml` (APAC_MAS). However, the `system-security-plan.yaml` only imports the `sp800053-profile.yaml` and `common-controls-catalog.yaml`. The EU AI Act and MAS FEAT profiles exist but are not integrated into the SSP, making them orphaned artifacts.

**Remediation:** Create jurisdiction-specific SSPs: `system-security-plan-us-fed.yaml`, `system-security-plan-eu-ecb.yaml`, `system-security-plan-apac-mas.yaml`. Each should import the universal `common-controls-catalog.yaml` plus the applicable jurisdictional profile.

---

### CA-08 🟢 LOW — `config/thresholds/` baseline files lack explicit `jurisdiction` field

| Attribute | Value |
|-----------|-------|
| **Files** | [`config/thresholds/US_FED_BASELINE.json`](../../../config/thresholds/US_FED_BASELINE.json), [`EU_ECB_BASELINE.json`](../../../config/thresholds/EU_ECB_BASELINE.json), [`APAC_MAS_BASELINE.json`](../../../config/thresholds/APAC_MAS_BASELINE.json) |
| **Violation** | Type K — Threshold Configuration Inconsistency |
| **Severity** | LOW |
| **Rule Violated** | R-6 |

**Issue:** The three baseline JSON files are correctly named and separated by jurisdiction, but none contains an explicit `"jurisdiction"` or `"cage_deployment_region"` field at the root level. A consumer loading the wrong file would have no self-describing metadata to detect the error.

**Remediation:** Add a root-level `"jurisdiction": "US_FED"` (or `"EU_ECB"`, `"APAC_MAS"`) field to each baseline file. Add a `"iso_42001_baseline": true` field to indicate that all three files extend the universal ISO 42001 baseline.

---

### Phase 4 Summary

| File | Findings | Highest Severity |
|------|----------|-----------------|
| `compliance/lula/lula-validation-sc4.yaml` | 1 | 🟠 HIGH |
| `compliance/lula/lula-validation-ai600-*.yaml` (5 files) | 1 | 🟠 HIGH |
| `compliance/lula/README.md` | 2 | 🟠 HIGH |
| `compliance/lula/lula-validation-aarm-vectors.yaml` | 2 | 🟡 MEDIUM |
| `compliance/oscal/component-definition.yaml` | 1 | 🟡 MEDIUM |
| `compliance/oscal/system-security-plan.yaml` | 1 | 🟡 MEDIUM |
| `config/thresholds/*.json` (3 files) | 1 | 🟢 LOW |

---

### Phase 1 Summary

| File | Findings | Highest Severity |
|------|----------|-----------------|
| `src/compliance_bridge/types.py` | 2 | 🔴 CRITICAL |
| `src/gateway/governance/iso_control.py` | 1 | 🔴 CRITICAL |
| `src/compliance_bridge/cmek_guard.py` | 1 | 🟠 HIGH |
| `src/gateway/governance/ontology.py` | 1 | 🟠 HIGH |
| `src/compliance_bridge/main.py` | 1 | 🟡 MEDIUM |
| `src/gateway/governance/schemas/thresholds.py` | 1 | 🟡 MEDIUM |
| `src/gateway/governance/pii_sanitizer.py` | 1 | 🟡 MEDIUM |
| `src/gateway/governance/hitl_escalator.py` | 1 | 🟡 MEDIUM |
| `src/gateway/governance/prompt_injection_detector.py` | 1 | 🟡 MEDIUM |
| `src/governed_financial_advisor/utils/privacy.py` | 1 | 🟢 LOW |

**Correct reference implementations** (use as templates for all Phase 1 remediations):
- [`src/gateway/governance/constants.py`](../../../src/gateway/governance/constants.py) — `ControlRegistry` with region-specific JSON profile loading
- [`src/gateway/governance/oscal_ssp_exporter.py`](../../../src/gateway/governance/oscal_ssp_exporter.py) — `REGIONAL_PROFILES` + `FrameworkRouter`
- [`src/gateway/governance/causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py) — `_NO_LEGAL_FORCE_MARKER` data-driven citation suppression
- [`src/gateway/governance/uca_logger.py`](../../../src/gateway/governance/uca_logger.py) — `_get_worm_bucket()` with explicit regional routing

---

## 7. Cross-Cutting Systemic Patterns

The 66 findings across all four phases are not isolated defects — they reflect five systemic architectural drift patterns that must be addressed at the root level.

---

### PATTERN-1: NIST/US_FED as the Implicit Universal Default

**Manifestation across all layers:**
- Source code: `CONTROL_META` flat dict, `EVIDENCE_SLA_SECONDS`, `pii_audit_retention_days` all default to NIST/FISMA values
- Deployment: `cage_deployment_region` Terraform variable defaults to `"US_FED"`; `enable_nist_compliance` is the only hardening toggle
- Kubernetes: NIST SP 800-53 annotations on all NetworkPolicy and Namespace resources
- CI/CD: NIST control identifiers in universal CI job names; AI 600-1 Lula validation runs unconditionally
- Documentation: NIST SP 800-53 presented as the primary compliance framework in IR Plan, Latency Strategy, GKE README
- Compliance artifacts: 10 NIST Lula validation files vs. 3 ISO 42001 files vs. 0 EU_ECB files vs. 0 APAC_MAS files

**Root cause:** The codebase was initially built for a US_FED deployment context. ISO 42001 was added as a universal layer later, but the NIST-as-default assumption was never systematically purged.

**Systemic fix:** Establish ISO 42001 as the explicit default at every layer. Replace all `cage_deployment_region = "US_FED"` defaults with no-default (required) values. Replace all NIST annotations on universal resources with ISO 42001 or jurisdiction-neutral labels.

---

### PATTERN-2: Missing `CAGE_DEPLOYMENT_REGION` Propagation in the Deployment Pipeline

**Manifestation:**
- `deploy_all.sh` `load_env()` does not propagate `CAGE_DEPLOYMENT_REGION` to Terraform as `TF_VAR_cage_deployment_region`
- Static K8s manifests (`gateway.yaml`, `financial-advisor.yaml`) do not receive `CAGE_DEPLOYMENT_REGION` from any source
- `scripts/automated_auditor.py` has no `CAGE_DEPLOYMENT_REGION` awareness
- CI jobs do not read `CAGE_DEPLOYMENT_REGION` to gate jurisdiction-specific checks

**Root cause:** `CAGE_DEPLOYMENT_REGION` is correctly defined as a Terraform variable and correctly injected into the `advisor-secrets` Kubernetes Secret (meaning running pods receive it at runtime). However, the deployment pipeline itself does not propagate it from `.env` to Terraform automatically, and static manifests are not templated.

**Systemic fix:** Create a single source of truth for `CAGE_DEPLOYMENT_REGION` in `.env`. Propagate it automatically through `load_env()` → `TF_VAR_cage_deployment_region` → Terraform → K8s manifests (via templates). All scripts must read it from environment.

---

### PATTERN-3: Static K8s Manifests with Hardcoded US Region Values

**Manifestation:**
- `deployment/k8s/gateway.yaml`: `GOOGLE_CLOUD_LOCATION: "us-central1"`, `CAGE_ENV: "dev"`
- `deployment/k8s/financial-advisor.yaml`: `GOOGLE_CLOUD_LOCATION: "us-central1"`
- `deployment/k8s/compliance-bridge.yaml`: `OSCAL_S3_REGION: "auto"`
- `infra/modules/app_secrets/main.tf`: `AWS_REGION = "us-east-1"`

**Root cause:** The codebase has a pattern of using `.yaml.tpl` templates for some resources (e.g., `vllm-reasoning.yaml.tpl`, `compliance-bridge-deployment.yaml.tpl`) but not for the most critical ones. This creates a two-tier system where some manifests are region-aware and others are not.

**Systemic fix:** Convert all static K8s manifests that contain region-specific values to `.yaml.tpl` templates. Add a manifest generation step to `deploy_all.sh` that substitutes `CAGE_DEPLOYMENT_REGION`-derived values before `kubectl apply`.

---

### PATTERN-4: Missing Production Var-Files for Non-US Jurisdictions

**Manifestation:**
- Only `prod.tfvars` exists for production deployments (hardcodes `us-central1`)
- `eu-dev.tfvars` and `apac-dev.tfvars` exist for dev, but no production equivalents
- EU_ECB and APAC_MAS production deployments are architecturally undefined at the Terraform layer

**Root cause:** The production deployment path was only defined for US_FED. EU_ECB and APAC_MAS were added as dev-only configurations.

**Systemic fix:** Create `eu-prod.tfvars` and `apac-prod.tfvars`. Update `prod.tfvars` to explicitly set `cage_deployment_region = "US_FED"`. Add Terraform validation blocks that cross-check region/jurisdiction consistency.

---

### PATTERN-5: Absent EU_ECB and APAC_MAS CI Compliance Gates

**Manifestation:**
- `security-scan.yml` documents "EU_ECB: separate workflow" and "APAC_MAS: separate workflow" — but these workflows do not exist
- The US_FED `nist-compliance-gate` job is correctly implemented and gated on `CAGE_DEPLOYMENT_REGION == 'US_FED'`
- EU_ECB and APAC_MAS deployments have zero CI-enforced compliance verification

**Root cause:** The US_FED compliance gate was implemented first. The EU_ECB and APAC_MAS gates were planned (documented in comments) but never created.

**Systemic fix:** Create `.github/workflows/eu-ecb-compliance.yml` and `.github/workflows/apac-mas-compliance.yml`. These workflows must be created before any EU_ECB or APAC_MAS production deployment is attempted.

---

## 8. Remediation Roadmap

Findings are grouped into four priority tiers based on severity and deployment risk.

### Tier 0 — Immediate (Block any non-US_FED production deployment)

| ID | Finding | File | Effort |
|----|---------|------|--------|
| FINDING-02 | Inverted region guard silences ISO 42001 audit trail | `src/gateway/governance/iso_control.py` | S |
| FINDING-01 | `CONTROL_META` exposes all frameworks to all regions | `src/compliance_bridge/types.py` | M |
| DEP-09 | `cage_deployment_region` defaults to `"US_FED"` | `infra/targets/gcp-gke/variables.tf` | S |
| DEP-08 | `region` defaults to `us-central1` | `infra/targets/gcp-gke/variables.tf` | S |
| DEP-10 | No region/jurisdiction precondition on GCS bucket | `infra/targets/gcp-gke/main.tf` | S |
| DEP-13 | Missing EU_ECB and APAC_MAS CI compliance gates | `.github/workflows/` | L |
| CA-03 | Zero Lula validation files for EU_ECB or APAC_MAS | `compliance/lula/` | L |

### Tier 1 — Sprint 1 (Within 2 weeks)

| ID | Finding | File | Effort |
|----|---------|------|--------|
| DEP-01 | `enable_nist_compliance` activated by `--env prod` | `deploy_all.sh` | S |
| DEP-02 | `load_env()` does not propagate `CAGE_DEPLOYMENT_REGION` | `deploy_all.sh` | S |
| DEP-03 | `automated_auditor.py` defaults to SaaS Langfuse | `scripts/automated_auditor.py` | S |
| DEP-04 | `gateway.yaml` hardcodes `us-central1` and `CAGE_ENV: dev` | `deployment/k8s/gateway.yaml` | M |
| DEP-05 | `financial-advisor.yaml` hardcodes `us-central1` | `deployment/k8s/financial-advisor.yaml` | M |
| DEP-07 | `compliance-bridge.yaml` sets `OSCAL_S3_REGION: "auto"` | `deployment/k8s/compliance-bridge.yaml` | S |
| DEP-11 | `app_secrets/main.tf` hardcodes `AWS_REGION = "us-east-1"` | `infra/modules/app_secrets/main.tf` | S |
| DEP-12 | No `eu-prod.tfvars` or `apac-prod.tfvars` | `infra/targets/gcp-gke/` | M |
| FINDING-05 | ✅ Remediated — `sla_monitor.py` now calls region-aware `get_sla_seconds()` instead of the deprecated flat `EVIDENCE_SLA_SECONDS` | `src/compliance_bridge/sla_monitor.py` | S |
| CA-02 | AI 600-1 Lula stubs lack `cage.region: US_FED` metadata | `compliance/lula/` | S |
| CA-01 | `lula-validation-sc4.yaml` has three incompatible identities | `compliance/lula/` | S |

### Tier 2 — Sprint 2 (Within 4 weeks)

| ID | Finding | File | Effort |
|----|---------|------|--------|
| FINDING-03 | `validate_cmek_configuration()` cites NIST universally | `src/compliance_bridge/cmek_guard.py` | S |
| FINDING-04 | `TradingKnowledgeGraph.ISO_CONTROL_MAP` embeds EU controls | `src/gateway/governance/ontology.py` | M |
| FINDING-07 | `pii_audit_retention_days` hardcodes FISMA AU-11 | `src/gateway/governance/schemas/thresholds.py` | S |
| FINDING-08 | `pii_audit_log()` cites FISMA AU-11 universally | `src/gateway/governance/pii_sanitizer.py` | S |
| FINDING-09 | HITL/prompt injection modules lack runtime region guards | `src/gateway/governance/hitl_escalator.py` | S |
| DEP-16 | NIST annotations on all K8s NetworkPolicy resources | `deployment/k8s/network-policy-hardening.yaml` | M |
| DEP-17 | NIST SC-39 labels on all Namespace definitions | `deployment/k8s/pod-security-admission.yaml` | S |
| DEP-19 | OPA policy bundle has no jurisdiction-specific overlay | `deployment/opa_config.yaml` | L |
| DEP-21 | AI 600-1 Lula validation runs universally in CI | `.github/workflows/ci.yml` | S |
| DEP-22 | CBRN keyword check asserts `True` universally | `.github/workflows/ci.yml` | S |
| CA-06 | OSCAL component definition mixes ISO 42001 and NIST | `compliance/oscal/component-definition.yaml` | M |
| CA-07 | EU AI Act and MAS FEAT OSCAL profiles not integrated in SSP | `compliance/oscal/` | M |

### Tier 3 — Sprint 3 (Within 6 weeks)

| ID | Finding | File | Effort |
|----|---------|------|--------|
| FINDING-06 | `/v1/controls` returns all frameworks to all regions | `src/compliance_bridge/main.py` | S |
| FINDING-10 | `scrub_pii()` lacks GDPR Art. 17 audit trail | `src/governed_financial_advisor/utils/privacy.py` | S |
| DEP-06 | AgentSight DaemonSet in wrong namespace; no GDPR guard | `deployment/k8s/agentsight-daemon.yaml` | M |
| DEP-14 | `deploy_all.sh` usage text describes `prod` as "NIST compliance" | `deploy_all.sh` | S |
| DEP-15 | `verify_remote.py` hardcodes `us-central1` fallback URL | `scripts/verify_remote.py` | S |
| DEP-18 | Lula CronJob does not read `CAGE_DEPLOYMENT_REGION` | `deployment/k8s/lula-cron.yaml` | S |
| DEP-20 | Redis/PostgreSQL hardening only via `enable_nist_compliance` | `infra/targets/gcp-gke/main.tf` | M |
| DOC-01 | `README.md` badge row presents NIST as co-equal with ISO 42001 | `README.md` | S |
| DOC-02 | `README.md` compliance table has no "Jurisdiction" column | `README.md` | S |
| DOC-03 | `docs/IR_PLAN.md` presents NIST SP 800-61 as universal IRP | `docs/IR_PLAN.md` | M |
| DOC-04 | `docs/IR_PLAN.md` has no multi-jurisdiction notification structure | `docs/IR_PLAN.md` | M |
| DOC-05 | `NIST_CONTROLS.md` has no ISO 42001 universal baseline | `infra/modules/gcp_gke_cluster/NIST_CONTROLS.md` | M |
| DOC-06 | GKE README uses "NIST Compliance" as synonym for "production" | `infra/modules/gcp_gke_cluster/README.md` | S |
| DOC-07 | SR 26-2 presented as primary architectural driver | `docs/INFERENCE_GATEWAY_ARCHITECTURE.md` | S |
| DOC-08–13 | Remaining documentation labeling gaps | Various `docs/` files | S each |
| CA-04 | AARM vectors universal file cross-references NIST in notes | `compliance/lula/lula-validation-aarm-vectors.yaml` | S |
| CA-05 | AARM validation listed as both "Stub" and "Active" | `compliance/lula/README.md` | S |
| CA-08 | Baseline JSON files lack explicit `jurisdiction` field | `config/thresholds/*.json` | S |

**Effort key:** S = Small (< 2 hours), M = Medium (2–8 hours), L = Large (> 8 hours)

---

## 9. Correct Reference Implementations

The following existing implementations in the codebase correctly enforce jurisdictional separation and should be used as templates for all remediations.

### 9.1 Regional Profile Loading — `src/gateway/governance/constants.py`

[`ControlRegistry`](../../../src/gateway/governance/constants.py) demonstrates the correct pattern for loading region-specific control profiles from external JSON files. Use this pattern for `CONTROL_META` and `EVIDENCE_SLA_SECONDS` refactoring.

### 9.2 Framework Router — `src/gateway/governance/oscal_ssp_exporter.py`

[`REGIONAL_PROFILES`](../../../src/gateway/governance/oscal_ssp_exporter.py) and [`FrameworkRouter`](../../../src/gateway/governance/oscal_ssp_exporter.py) demonstrate the correct pattern for routing compliance evidence to the correct framework based on `CAGE_DEPLOYMENT_REGION`. Use this pattern for all compliance bridge endpoint filtering.

### 9.3 Data-Driven Citation Suppression — `src/gateway/governance/causal_gatekeeper.py`

[`_NO_LEGAL_FORCE_MARKER`](../../../src/gateway/governance/causal_gatekeeper.py) demonstrates the correct pattern for suppressing jurisdiction-specific regulatory citations in non-applicable regions without hardcoded conditionals. Use this pattern for SR 26-2 references in EU_ECB and APAC_MAS deployments.

### 9.4 Regional WORM Bucket Routing — `src/gateway/governance/uca_logger.py`

[`_get_worm_bucket()`](../../../src/gateway/governance/uca_logger.py) demonstrates the correct pattern for routing storage operations to the correct regional GCS bucket based on `CAGE_DEPLOYMENT_REGION`. Use this pattern for `OSCAL_S3_REGION` and `langfuse_events` bucket routing.

### 9.5 Correctly Gated CI Job — `.github/workflows/security-scan.yml`

The `nist-compliance-gate` job demonstrates the correct pattern for a jurisdiction-specific CI gate:
```yaml
nist-compliance-gate:
  if: vars.CAGE_DEPLOYMENT_REGION == 'US_FED'
  # ... NIST-specific checks
```
Use this pattern as the template for the missing `eu-ecb-compliance-gate` and `apac-mas-compliance-gate` jobs.

### 9.6 Correctly Scoped POAM — `docs/POAM_US_FED.md`

[`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md) demonstrates the correct pattern for jurisdiction-scoped documentation with explicit `region_scope: US_FED` frontmatter. Use this pattern as the template for all jurisdiction-specific documentation.

---

## Appendix: Finding Index

| ID | Severity | Phase | File | Rule |
|----|----------|-------|------|------|
| FINDING-01 | 🔴 CRITICAL | Source Code | `src/compliance_bridge/types.py:122` | R-2,R-3,R-5,R-6 |
| FINDING-02 | 🔴 CRITICAL | Source Code | `src/gateway/governance/iso_control.py:109` | R-1 |
| FINDING-03 | 🟠 HIGH | Source Code | `src/compliance_bridge/cmek_guard.py:73` | R-2,R-3,R-4 |
| FINDING-04 | 🟠 HIGH | Source Code | `src/gateway/governance/ontology.py:162` | R-3,R-6 |
| FINDING-05 | 🟠 HIGH | Source Code | `src/compliance_bridge/types.py:285` | R-2,R-6 |
| FINDING-06 | 🟡 MEDIUM | Source Code | `src/compliance_bridge/main.py:332` | R-2,R-3,R-4 |
| FINDING-07 | 🟡 MEDIUM | Source Code | `src/gateway/governance/schemas/thresholds.py:129` | R-2,R-6 |
| FINDING-08 | 🟡 MEDIUM | Source Code | `src/gateway/governance/pii_sanitizer.py:201` | R-2,R-3,R-4 |
| FINDING-09 | 🟡 MEDIUM | Source Code | `src/gateway/governance/hitl_escalator.py:15` | R-2 |
| FINDING-10 | 🟢 LOW | Source Code | `src/governed_financial_advisor/utils/privacy.py:25` | R-3,R-4 |
| DEP-01 | 🟠 HIGH | Deployment | `deploy_all.sh:238` | R-2,R-7 |
| DEP-02 | 🟠 HIGH | Deployment | `deploy_all.sh:100` | R-7 |
| DEP-03 | 🟠 HIGH | Deployment | `scripts/automated_auditor.py:56` | R-3,R-7 |
| DEP-04 | 🟠 HIGH | Deployment | `deployment/k8s/gateway.yaml:38` | R-7 |
| DEP-05 | 🟠 HIGH | Deployment | `deployment/k8s/financial-advisor.yaml:98` | R-7 |
| DEP-06 | 🟠 HIGH | Deployment | `deployment/k8s/agentsight-daemon.yaml:15` | R-3,R-7 |
| DEP-07 | 🟠 HIGH | Deployment | `deployment/k8s/compliance-bridge.yaml:88` | R-3,R-4,R-7 |
| DEP-08 | 🟠 HIGH | Deployment | `infra/targets/gcp-gke/variables.tf:22` | R-3,R-4,R-7 |
| DEP-09 | 🟠 HIGH | Deployment | `infra/targets/gcp-gke/variables.tf:546` | R-7 |
| DEP-10 | 🟠 HIGH | Deployment | `infra/targets/gcp-gke/main.tf:129` | R-3,R-4 |
| DEP-11 | 🟠 HIGH | Deployment | `infra/modules/app_secrets/main.tf:77` | R-3,R-4 |
| DEP-12 | 🟠 HIGH | Deployment | `infra/targets/gcp-gke/prod.tfvars` | R-7 |
| DEP-13 | 🟠 HIGH | Deployment | `.github/workflows/security-scan.yml:17` | R-3,R-4 |
| DEP-14 | 🟡 MEDIUM | Deployment | `deploy_all.sh:49` | R-8 |
| DEP-15 | 🟡 MEDIUM | Deployment | `scripts/verify_remote.py:31` | R-7 |
| DEP-16 | 🟡 MEDIUM | Deployment | `deployment/k8s/network-policy-hardening.yaml:27` | R-2,R-8 |
| DEP-17 | 🟡 MEDIUM | Deployment | `deployment/k8s/pod-security-admission.yaml:33` | R-2,R-8 |
| DEP-18 | 🟡 MEDIUM | Deployment | `deployment/k8s/lula-cron.yaml:214` | R-7 |
| DEP-19 | 🟡 MEDIUM | Deployment | `deployment/opa_config.yaml:64` | R-7 |
| DEP-20 | 🟡 MEDIUM | Deployment | `infra/targets/gcp-gke/main.tf:210` | R-3 |
| DEP-21 | 🟡 MEDIUM | Deployment | `.github/workflows/ci.yml:119` | R-2 |
| DEP-22 | 🟡 MEDIUM | Deployment | `.github/workflows/ci.yml:245` | R-2 |
| DEP-23 | 🟢 LOW | Deployment | `scripts/verify_all.py:43` | R-7 |
| DEP-24 | 🟢 LOW | Deployment | `.github/workflows/ci.yml:99` | R-7 |
| DEP-25 | 🟢 LOW | Deployment | `.github/workflows/security-scan.yml:47` | R-8 |
| DOC-01 | 🟠 HIGH | Documentation | `README.md:1` | R-8 |
| DOC-02 | 🟠 HIGH | Documentation | `README.md:133` | R-8 |
| DOC-03 | 🟠 HIGH | Documentation | `docs/IR_PLAN.md:27` | R-8 |
| DOC-04 | 🟠 HIGH | Documentation | `docs/IR_PLAN.md:313` | R-8 |
| DOC-05 | 🟠 HIGH | Documentation | `infra/modules/gcp_gke_cluster/NIST_CONTROLS.md:1` | R-8 |
| DOC-06 | 🟠 HIGH | Documentation | `infra/modules/gcp_gke_cluster/README.md:57` | R-8 |
| DOC-07 | 🟠 HIGH | Documentation | `docs/INFERENCE_GATEWAY_ARCHITECTURE.md:3` | R-8 |
| DOC-08 | 🟡 MEDIUM | Documentation | `docs/AUDIT_LOG_SCHEMA.md:180` | R-8 |
| DOC-09 | 🟡 MEDIUM | Documentation | `docs/LATENCY_STRATEGY.md:1` | R-8 |
| DOC-10 | 🟡 MEDIUM | Documentation | `docs/SECURITY_AUDIT_REPORT.md:758` | R-8 |
| DOC-11 | 🟡 MEDIUM | Documentation | `docs/DEPLOYMENT_RULES.md:168` | R-8 |
| DOC-12 | 🟡 MEDIUM | Documentation | `COMPLIANCE.md:70` | R-8 |
| DOC-13 | 🟡 MEDIUM | Documentation | `infra/modules/k8s_namespace/README.md:84` | R-8 |
| DOC-14 | 🟢 LOW | Documentation | `docs/IR_PLAN.md:55` | R-8 |
| CA-01 | 🟠 HIGH | Compliance | `compliance/lula/lula-validation-sc4.yaml` | R-9 |
| CA-02 | 🟠 HIGH | Compliance | `compliance/lula/lula-validation-ai600-*.yaml` | R-9 |
| CA-03 | 🟠 HIGH | Compliance | `compliance/lula/README.md` | R-9 |
| CA-04 | 🟡 MEDIUM | Compliance | `compliance/lula/lula-validation-aarm-vectors.yaml` | R-9 |
| CA-05 | 🟡 MEDIUM | Compliance | `compliance/lula/README.md` | R-9 |
| CA-06 | 🟡 MEDIUM | Compliance | `compliance/oscal/component-definition.yaml` | R-6,R-9 |
| CA-07 | 🟡 MEDIUM | Compliance | `compliance/oscal/system-security-plan.yaml` | R-9 |
| CA-08 | 🟢 LOW | Compliance | `config/thresholds/*.json` | R-6 |

---

*Report generated: 2026-06-15. This document is a findings-only analysis; it is retained as a historical record. No source files were modified during the original analysis. Remediation work follows [`docs/operations/GIT_WORKFLOW_STANDARDS.md`](../../operations/GIT_WORKFLOW_STANDARDS.md) and the standards in [`AGENTS.md`](../../../AGENTS.md).*
