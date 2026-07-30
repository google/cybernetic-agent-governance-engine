# Lula Compliance Validations

## What is Lula?

[Lula](https://docs.lula.dev/) is a compliance-as-code tool that evaluates OSCAL (Open Security Controls Assessment Language) component definitions against live system state. It supports multiple **domain** backends (Kubernetes, API, file) and uses **OPA Rego** as the policy evaluation engine.

In this project, Lula is run as a Kubernetes CronJob (`deployment/k8s/lula-cron.yaml`) that periodically validates that compliance controls are satisfied against the live cluster state and running services.

---

> **Note:** Draft/incomplete manifests are stored in [`drafts/`](drafts/README.md) and are excluded from the authoritative count below.

## Validation Coverage

### Universal Controls (ISO 42001 — ALL regions)

| Validation File                                          | Control | Standard             | Region Scope | Status    | Description                                                        |
| -------------------------------------------------------- | ------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-a52.yaml`](lula-validation-a52.yaml)   | A.5.2   | ISO 42001            | ALL          | ✅ Active | Social Impact Assessment — NeMo Guardrails toxicity blocking ≥ 99% |
| [`lula-validation-a53.yaml`](lula-validation-a53.yaml)   | A.5.3   | ISO 42001            | ALL          | ✅ Active | Logging and Monitoring — Langfuse safety rate ≥ 98%                |
| [`lula-validation-a92.yaml`](lula-validation-a92.yaml)   | A.9.2   | ISO 42001            | ALL          | ✅ Active | Data Transfer to Suppliers — Presidio PII leak rate = 0%           |
| [`lula-validation-aarm-vectors.yaml`](lula-validation-aarm-vectors.yaml) | CSA AARM v1.0 | CSA AARM | ALL | 🔶 Stub | CSA AARM v1.0 11-vector threat coverage validation |
| [`lula-validation-tqp007.yaml`](lula-validation-tqp007.yaml)             | A.8.4         | ISO 42001 | ALL | ✅ Active | TokenQuotaProxy fail-closed (CTRL_TQP_007) — asserts tqp_running, tqp_has_redis_url, tqp_fail_closed |
| [`lula-validation-iso001-token-quota.yaml`](lula-validation-iso001-token-quota.yaml) | A.4 | ISO 42001 | ALL | ✅ Active | Token Quota OPA Injection (ISO-001) — asserts advisor_running, advisor_has_redis_url, advisor_has_quota_markers |

### US_FED Controls (NIST SP 800-53 / NIST AI 600-1 — US_FED only)

| Validation File                                          | Control | Standard             | Region Scope | Status    | Description                                                        |
| -------------------------------------------------------- | ------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-sc4.yaml`](lula-validation-sc4.yaml)   | SC-4    | NIST SP 800-53       | US_FED       | ✅ Active | Fiscal Limits and RBAC — OPA ConfigMap label present in `governance-stack` namespace |
| [`lula-validation-ac2.yaml`](lula-validation-ac2.yaml)   | AC-2    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Account Management — ServiceAccount lifecycle in `governance-stack` |
| [`lula-validation-ac3.yaml`](lula-validation-ac3.yaml)   | AC-3    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Access Enforcement — OPA Deployment + ConfigMap check              |
| [`lula-validation-au12.yaml`](lula-validation-au12.yaml) | AU-12   | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Audit Record Generation — Langfuse OTLP ingestion availability (standalone OTel Collector deprecated 2026-05-31; validation needs update) |
| [`lula-validation-cm6.yaml`](lula-validation-cm6.yaml)   | CM-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Configuration Settings — Governance ConfigMaps present             |
| [`lula-validation-ia3.yaml`](lula-validation-ia3.yaml)   | IA-3    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Device Identification — Linkerd mTLS SPIFFE identity               |
| [`lula-validation-ia5.yaml`](lula-validation-ia5.yaml)   | IA-5    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Authenticator Management — KMS HSM key lifecycle                   |
| [`lula-validation-ir6.yaml`](lula-validation-ir6.yaml)   | IR-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Incident Reporting — compliance-bridge Deployment check            |
| [`lula-validation-ra5.yaml`](lula-validation-ra5.yaml)   | RA-5    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Vulnerability Scanning — Security scan CronJob check               |
| [`lula-validation-sc8.yaml`](lula-validation-sc8.yaml)   | SC-8    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Transmission Confidentiality — TLS enforcement                     |
| [`lula-validation-si2.yaml`](lula-validation-si2.yaml)   | SI-2    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Flaw Remediation — CVE patching (pip-audit CI)                     |
| [`lula-validation-ai600-confabulation.yaml`](lula-validation-ai600-confabulation.yaml) | SI-10, AU-3 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.2 Confabulation — asserts `confabulation_rate < 0.02` over 24h window (POAM AI600-001). Requires `confabulation_rate` metric in Langfuse compliance project. |
| [`lula-validation-ai600-data-privacy.yaml`](lula-validation-ai600-data-privacy.yaml) | SI-19, SC-28 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.3 Data Privacy — asserts PII audit log retention ≥ 90 days and Presidio score threshold ≥ 0.5 (POAM AI600-002). |
| [`lula-validation-ai600-prompt-injection.yaml`](lula-validation-ai600-prompt-injection.yaml) | SI-3, SI-10, CA-8 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.4 Prompt Injection — asserts injection detector ConfigMap present and deflection score ≥ 4 (POAM AI600-003). |
| [`lula-validation-ai600-human-ai-config.yaml`](lula-validation-ai600-human-ai-config.yaml) | AC-5, AU-3, CA-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.5 Human-AI Configuration — asserts DEFER queue SLA ≤ 4h for CRITICAL escalations and HITL audit trail present (POAM AI600-005). |
| [`lula-validation-ai600-cbrn.yaml`](lula-validation-ai600-cbrn.yaml) | SA-12, SR-3, SI-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.6 / §2.12 CBRN & Value Chain — asserts CBRN keyword list ≥ 10 terms enabled and NeMo CBRN rail deployed (POAM AI600-007). **Cat-M: requires AO pre-approval before activation.** |

### EU_ECB Controls (EU AI Act / GDPR / DORA — EU_ECB only)

| Validation File                                                          | Control         | Standard             | Region Scope | Status    | Description                                                        |
| ------------------------------------------------------------------------ | --------------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-eu-fria.yaml`](lula-validation-eu-fria.yaml)           | Art. 29a        | EU AI Act            | EU_ECB       | ✅ Active | FRIA Gating (EU-001) — asserts gateway_running, normative_provider_not_static, normative_endpoint_set |
| [`lula-validation-eu-ai-act-art9.yaml`](lula-validation-eu-ai-act-art9.yaml) | Art. 9     | EU AI Act            | EU_ECB       | 🔶 Stub   | Risk Management System — compliance-bridge endpoint check          |
| [`lula-validation-gdpr-art22.yaml`](lula-validation-gdpr-art22.yaml)     | Art. 22         | GDPR                 | EU_ECB       | 🔶 Stub   | Automated Decision-Making — human oversight endpoint check         |
| [`lula-validation-dora-art10.yaml`](lula-validation-dora-art10.yaml)     | Art. 10         | DORA                 | EU_ECB       | 🔶 Stub   | ICT Resilience Testing — audit logging endpoint check              |

**Legend:**

- ✅ **Active** — Validation is production-ready and enabled in the Lula CronJob
- 🔶 **Stub** — Validation logic is complete but requires cluster-specific namespace/resource name configuration before activation (see `# TODO:` comments in each file)
- **Region Scope:** `ALL` = applies to US_FED, EU_ECB, and APAC_MAS deployments; `US_FED` = applies only when `CAGE_DEPLOYMENT_REGION=US_FED`; `EU_ECB` = applies only when `CAGE_DEPLOYMENT_REGION=EU_ECB`; `APAC_MAS` = applies only when `CAGE_DEPLOYMENT_REGION=APAC_MAS`

### Posture Architecture Alignment

The active/stub split is **intentional and aligned with the posture architecture**:

- **3 Active (ALL scope):** ISO 42001 universal controls (A.5.2, A.5.3, A.9.2) — production-ready across all deployment regions
- **1 Active (US_FED scope):** SC-4 fiscal limits — production-ready for US Federal deployments
- **1 Stub (ALL scope):** CSA AARM vectors — universal but requires cluster configuration. **Note:** This validation is listed as `Status: 🔶 Stub` and counted as 1 stub (ALL scope). It is NOT counted as an active validation for release gate purposes until real assertions replace the stub. See CA-05 remediation note below.
- **10 Stub (US_FED scope):** NIST SP 800-53 controls — US Federal only; require cluster-specific namespace/resource configuration before activation
- **5 Stub (US_FED scope):** NIST AI 600-1 controls — phases 0–3 implemented in v2.1.0 (runtime enforcement active); Lula manifests are stub-ready and require Langfuse metric availability and cluster-specific configuration before activation

The 10 US_FED NIST SP 800-53 stubs represent an **implementation gap** tracked as open POAM items in [`docs/POAM.md`](../../docs/POAM.md) (see POAM-2026-010, POAM-2026-011, POAM-2026-012, POAM-2026-013): activating all 10 would raise NIST SP 800-53 Lula coverage from 1/11 to 11/11 controls, directly supporting the US_FED release gate. The CSA AARM stub (1 manifest, ALL scope) is a separate gap affecting all regions.

The 5 US_FED NIST AI 600-1 stubs correspond to **phases 0–3 of the AI 600-1 implementation** (v2.1.0). Runtime enforcement is active for all phases via `confabulation_scorer.py`, `pii_sanitizer.py`, `prompt_injection_detector.py`, `hitl_escalator.py`, and `text_filter.py`. The Lula manifests are scaffolding-ready and will be hardened to full live-cluster assertions once Langfuse metric endpoints are configured. The CBRN stub (`lula-validation-ai600-cbrn.yaml`) remains a **Cat-M change** requiring AO pre-approval before cluster activation in a real deployment's own change-management process.

### Three-Region OSCAL SSPs

Each deployment region has a dedicated OSCAL System Security Plan:

| Region | SSP File | Frameworks |
|--------|----------|------------|
| **US_FED** | [`compliance/oscal/system-security-plan.yaml`](../oscal/system-security-plan.yaml) | NIST SP 800-53 Rev 5 HIGH + NIST AI 600-1 |
| **EU_ECB** | [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../oscal/system-security-plan-eu-ecb.yaml) | EU AI Act / GDPR Art. 22 / DORA |
| **APAC_MAS** | [`compliance/oscal/system-security-plan-apac-mas.yaml`](../oscal/system-security-plan-apac-mas.yaml) | MAS FEAT / MAS Notice 655 / MAS TRM §6.3 |

Region selection is controlled exclusively by `CAGE_DEPLOYMENT_REGION`. The Lula CronJob (`deployment/k8s/lula-cron.yaml`) reads this variable to determine which jurisdiction-specific manifests to include in each run.

---

## Running Validations

### Run a single validation

```bash
lula validate -f compliance/lula/lula-validation-a53.yaml
```

### Run all active validations (ALL regions)

```bash
for f in compliance/lula/lula-validation-a52.yaml \
          compliance/lula/lula-validation-a53.yaml \
          compliance/lula/lula-validation-a92.yaml; do
  echo "=== Validating $f ==="
  lula validate -f "$f"
done
```

### Run US_FED active validations

```bash
# Only run when CAGE_DEPLOYMENT_REGION=US_FED
for f in compliance/lula/lula-validation-a52.yaml \
          compliance/lula/lula-validation-a53.yaml \
          compliance/lula/lula-validation-a92.yaml \
          compliance/lula/lula-validation-sc4.yaml; do
  echo "=== Validating $f ==="
  lula validate -f "$f"
done
```

### Run EU_ECB validations (when stubs are activated)

```bash
# Only run when CAGE_DEPLOYMENT_REGION=EU_ECB
for f in compliance/lula/lula-validation-a52.yaml \
          compliance/lula/lula-validation-a53.yaml \
          compliance/lula/lula-validation-a92.yaml \
          compliance/lula/lula-validation-eu-ai-act-art9.yaml \
          compliance/lula/lula-validation-gdpr-art22.yaml \
          compliance/lula/lula-validation-dora-art10.yaml; do
  echo "=== Validating $f ==="
  lula validate -f "$f"
done
```

### Run APAC_MAS validations (when stubs are activated)

```bash
# Only run when CAGE_DEPLOYMENT_REGION=APAC_MAS
for f in compliance/lula/lula-validation-a52.yaml \
          compliance/lula/lula-validation-a53.yaml \
          compliance/lula/lula-validation-a92.yaml \
          compliance/lula/lula-validation-mas-feat.yaml \
          compliance/lula/lula-validation-mas-notice655.yaml \
          compliance/lula/lula-validation-mas-trm-s6.yaml; do
  echo "=== Validating $f ==="
  lula validate -f "$f"
done
```

### Run against a specific Kubernetes context

```bash
lula validate -f compliance/lula/lula-validation-sc4.yaml --kubeconfig ~/.kube/config
```

### In-cluster (via CronJob)

The Lula CronJob at `deployment/k8s/lula-cron.yaml` runs all **Active** validations on the schedule defined in the ISCM Strategy. Results are logged to stdout and monitored via the AgentSight observability stack.

---

## Activating Stub Validations

Each stub file contains `# TODO:` comments with the specific steps required. The general process is:

1. **Confirm the resource name** — check the relevant `deployment/k8s/*.yaml` manifest
2. **Confirm the namespace** — check `deployment/k8s/NAMESPACE-GUIDE.md`
3. **Update the validation file** — replace placeholder names and `# TODO:` namespace values
4. **Test locally** — `lula validate -f compliance/lula/lula-validation-<control>.yaml`
5. **Add to the CronJob** — update `deployment/k8s/lula-cron.yaml` to include the new file
6. **Update this table** — change status from 🔶 Stub to ✅ Active

### Activating EU_ECB Stubs

The three EU_ECB stubs require the compliance-bridge service to expose the following endpoints:

- `GET /v1/compliance/eu-ai-act/art9` — EU AI Act Art. 9 risk management status
- `GET /v1/compliance/gdpr/art22` — GDPR Art. 22 human oversight status
- `GET /v1/compliance/dora/art10` — DORA Art. 10 ICT audit logging status

These endpoints must only be active when `CAGE_DEPLOYMENT_REGION=EU_ECB`. See `src/compliance_bridge/main.py` for the endpoint registration pattern.

### Activating APAC_MAS Stubs

The three APAC_MAS stubs require the compliance-bridge service to expose the following endpoints:

- `GET /v1/compliance/mas/feat` — MAS FEAT fairness assessment status
- `GET /v1/compliance/mas/notice655` — MAS Notice 655 audit logging status
- `GET /v1/compliance/mas/trm-s6` — MAS TRM §6.3 AI controls status

These endpoints must only be active when `CAGE_DEPLOYMENT_REGION=APAC_MAS`. See `src/compliance_bridge/main.py` for the endpoint registration pattern.

---

## Adding New Validations

New Lula validation files should follow the structure of the existing files in this directory:

```yaml
# lula-validation-<control-id>.yaml
# <Standard> — <Control ID>: <Control Name>
#
# Description of what this validation checks.

metadata:
  annotations:
    cage.region: <ALL|US_FED|EU_ECB|APAC_MAS>
    cage.compliance-posture: <iso-42001|nist-sp800-53|nist-ai-600-1|eu-ai-act|gdpr|dora|mas-feat|mas-notice-655|mas-trm>
    cage.posture-note: "<Explanation of jurisdiction scope>"

domain:
  type: kubernetes # or: api, file
  kubernetes-spec:
    resources:
      - name: <resource-alias>
        resource: <k8s-resource-type> # e.g. deployments, configmaps, cronjobs
        namespace: <namespace>

provider:
  type: opa
  opa-spec:
    rego: |
      package lula
      import future.keywords.if
      validate if {
        # Rego assertion
      }

notes: >
  <Standard> <Control ID>: <Control Name>.
  Explanation of what is being validated and why.
  Jurisdiction: <ALL|US_FED only|EU_ECB only|APAC_MAS only> (CAGE_DEPLOYMENT_REGION=<value>).
```

Key naming conventions:

- File name: `lula-validation-<control-id-lowercase-no-hyphen>.yaml` (e.g., `lula-validation-ac3.yaml`)
- Rego package: always `package lula`
- Validate rule: always named `validate`
- **`metadata.annotations` block is REQUIRED** — all new files must carry `cage.region` for machine-readable jurisdiction filtering (R-9)
- Add `# STUB:` and `# TODO:` comments for any values requiring cluster-specific configuration

---

## Monitoring Cadence

Validation frequencies are defined in the ISCM Strategy:

| Control Tier      | Cadence       | Controls                 |
| ----------------- | ------------- | ------------------------ |
| Critical (Tier 1) | Every 6 hours | A.5.2, A.9.2, SC-4       |
| High (Tier 2)     | Daily         | A.5.3, AC-3, AU-12, IR-6 |
| Medium (Tier 3)   | Weekly        | CM-6, RA-5               |

EU_ECB and APAC_MAS jurisdiction-specific controls will be added to the monitoring cadence table once their stubs are activated.

See [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../continuous-monitoring/ISCM_STRATEGY.md) for the full continuous monitoring plan including escalation procedures and evidence retention requirements.

---

## Related Documentation

- [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../continuous-monitoring/ISCM_STRATEGY.md) — Information System Continuous Monitoring Strategy
- [`docs/POAM.md`](../../docs/POAM.md) — Plan of Action and Milestones (POAM items for stub activation)
- [`deployment/k8s/lula-cron.yaml`](../../deployment/k8s/lula-cron.yaml) — Kubernetes CronJob for automated validation
- [`deployment/k8s/lula-rbac.yaml`](../../deployment/k8s/lula-rbac.yaml) — RBAC for Lula cluster access
- [`deployment/docker/Dockerfile.lula`](../../deployment/docker/Dockerfile.lula) — Lula container image
- [`compliance/oscal/system-security-plan.yaml`](../oscal/system-security-plan.yaml) — US_FED SSP (NIST SP 800-53 Rev 5 HIGH)
- [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../oscal/system-security-plan-eu-ecb.yaml) — EU_ECB SSP (EU AI Act / GDPR / DORA)
- [`compliance/oscal/system-security-plan-apac-mas.yaml`](../oscal/system-security-plan-apac-mas.yaml) — APAC_MAS SSP (MAS FEAT / Notice 655 / TRM)
- [`docs/JURISDICTIONAL_SEPARATION_ANALYSIS.md`](../../docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) — Phase 4 compliance artifact findings (CA-01 through CA-08)
