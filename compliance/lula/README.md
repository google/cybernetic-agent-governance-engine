# Lula Compliance Validations

## What is Lula?

[Lula](https://docs.lula.dev/) is a compliance-as-code tool that evaluates OSCAL (Open Security Controls Assessment Language) component definitions against live system state. It supports multiple **domain** backends (Kubernetes, API, file) and uses **OPA Rego** as the policy evaluation engine.

In this project, Lula is run as a Kubernetes CronJob (`deployment/k8s/lula-cron.yaml`) that periodically validates that compliance controls are satisfied against the live cluster state and running services.

---

## Validation Coverage

| Validation File                                          | Control | Standard             | Region Scope | Status    | Description                                                        |
| -------------------------------------------------------- | ------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-a52.yaml`](lula-validation-a52.yaml)   | A.5.2   | ISO 42001            | ALL          | ✅ Active | Social Impact Assessment — NeMo Guardrails toxicity blocking ≥ 99% |
| [`lula-validation-a53.yaml`](lula-validation-a53.yaml)   | A.5.3   | ISO 42001            | ALL          | ✅ Active | Logging and Monitoring — Langfuse safety rate ≥ 98%                |
| [`lula-validation-a92.yaml`](lula-validation-a92.yaml)   | A.9.2   | ISO 42001            | ALL          | ✅ Active | Data Transfer to Suppliers — Presidio PII leak rate = 0%           |
| [`lula-validation-sc4.yaml`](lula-validation-sc4.yaml)   | SC-4    | NIST SP 800-53       | US_FED       | ✅ Active | Fiscal Limits and RBAC — OPA ConfigMap label present in `governance-stack` namespace |
| [`lula-validation-aarm-vectors.yaml`](lula-validation-aarm-vectors.yaml) | CSA AARM v1.0 | CSA AARM | ALL | 🔶 Stub | CSA AARM v1.0 11-vector threat coverage validation |
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

**Legend:**

- ✅ **Active** — Validation is production-ready and enabled in the Lula CronJob
- 🔶 **Stub** — Validation logic is complete but requires cluster-specific namespace/resource name configuration before activation (see `# TODO:` comments in each file)
- **Region Scope:** `ALL` = applies to US_FED, EU_ECB, and APAC_MAS deployments; `US_FED` = applies only when `CAGE_DEPLOYMENT_REGION=US_FED`

### Posture Architecture Alignment

The active/stub split is **intentional and aligned with the posture architecture**:

- **3 Active (ALL scope):** ISO 42001 universal controls (A.5.2, A.5.3, A.9.2) — production-ready across all deployment regions
- **1 Active (US_FED scope):** SC-4 fiscal limits — production-ready for US Federal deployments
- **1 Stub (ALL scope):** CSA AARM vectors — universal but requires cluster configuration
- **10 Stub (US_FED scope):** NIST SP 800-53 controls — US Federal only; require cluster-specific namespace/resource configuration before activation

The 10 US_FED NIST stubs represent an **implementation gap** tracked as an open POAM item: activating all 10 would raise NIST SP 800-53 Lula coverage from 1/11 to 11/11 controls, directly supporting the US_FED release gate requirement (F-01 in [`docs/PRODUCTION_READINESS_REPORT.md`](../../docs/PRODUCTION_READINESS_REPORT.md)). The CSA AARM stub (1 manifest, ALL scope) is a separate gap affecting all regions.

---

## Running Validations

### Run a single validation

```bash
lula validate -f compliance/lula/lula-validation-a53.yaml
```

### Run all active validations

```bash
for f in compliance/lula/lula-validation-a52.yaml \
          compliance/lula/lula-validation-a53.yaml \
          compliance/lula/lula-validation-a92.yaml \
          compliance/lula/lula-validation-sc4.yaml; do
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

---

## Adding New Validations

New Lula validation files should follow the structure of the existing files in this directory:

```yaml
# lula-validation-<control-id>.yaml
# <Standard> — <Control ID>: <Control Name>
#
# Description of what this validation checks.

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
```

Key naming conventions:

- File name: `lula-validation-<control-id-lowercase-no-hyphen>.yaml` (e.g., `lula-validation-ac3.yaml`)
- Rego package: always `package lula`
- Validate rule: always named `validate`
- Add `# STUB:` and `# TODO:` comments for any values requiring cluster-specific configuration

---

## Monitoring Cadence

Validation frequencies are defined in the ISCM Strategy:

| Control Tier      | Cadence       | Controls                 |
| ----------------- | ------------- | ------------------------ |
| Critical (Tier 1) | Every 6 hours | A.5.2, A.9.2, SC-4       |
| High (Tier 2)     | Daily         | A.5.3, AC-3, AU-12, IR-6 |
| Medium (Tier 3)   | Weekly        | CM-6, RA-5               |

See [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../continuous-monitoring/ISCM_STRATEGY.md) for the full continuous monitoring plan including escalation procedures and evidence retention requirements.

---

## Related Documentation

- [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../continuous-monitoring/ISCM_STRATEGY.md) — Information System Continuous Monitoring Strategy
- [`docs/POAM.md`](../../docs/POAM.md) — Plan of Action and Milestones (POAM items for stub activation)
- [`docs/ROLES_AND_RESPONSIBILITIES.md`](../../docs/ROLES_AND_RESPONSIBILITIES.md) — ISSO/ISSM roles for validation review
- [`deployment/k8s/lula-cron.yaml`](../../deployment/k8s/lula-cron.yaml) — Kubernetes CronJob for automated validation
- [`deployment/k8s/lula-rbac.yaml`](../../deployment/k8s/lula-rbac.yaml) — RBAC for Lula cluster access
- [`deployment/docker/Dockerfile.lula`](../../deployment/docker/Dockerfile.lula) — Lula container image
