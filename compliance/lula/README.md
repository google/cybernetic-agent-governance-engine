# Lula Compliance Validations

## What is Lula?

[Lula](https://docs.lula.dev/) is a compliance-as-code tool that evaluates OSCAL (Open Security Controls Assessment Language) component definitions against live system state. It supports multiple **domain** backends (Kubernetes, API, file) and uses **OPA Rego** as the policy evaluation engine.

In this project, Lula validations (`compliance/lula/lula-validation-*.yaml`) evaluate compliance controls against the live cluster state and running services. In the cluster they run from `CronJob/lula-audit`, which Terraform manages in [`infra/modules/lula_cron/`](../../infra/modules/lula_cron/main.tf). It replaced `385e502e:src/compliance_bridge/lula_scheduler.py` and the unmanaged `de5534ac:deployment/k8s/lula-cron.yaml`.

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
| [`lula-validation-tqp007.yaml`](lula-validation-tqp007.yaml)             | A.8.4         | ISO 42001 | ALL | ✅ Active | TokenQuotaProxy (CTRL_TQP_007) — asserts `tqp_running` and `tqp_has_redis_url`: the gateway is ready and has a non-empty `REDIS_URL`. It does not check fail-closed behaviour |
| [`lula-validation-iso001-token-quota.yaml`](lula-validation-iso001-token-quota.yaml) | A.4 | ISO 42001 | ALL | ✅ Active | Token Quota OPA Injection (ISO-001) — asserts `gateway_has_redis_url` and `opa_policy_present`: the gateway or advisor has a non-empty `REDIS_URL` and the `opa-policies` ConfigMap is non-empty. It checks no quota markers |
| [`lula-validation-ftra.yaml`](lula-validation-ftra.yaml)                 | CTRL_FTRA_001 | ISO 42001 / NIST | ALL | ✅ Active | FTRA Tier 0.5 Gate (CTRL_FTRA_001) — asserts only `gateway_exists`: a gateway Deployment with a `gateway` container. It does not exercise FTRA |
| [`lula-validation-flowsignal.yaml`](lula-validation-flowsignal.yaml)     | A.8.4         | ISO 42001 | ALL | ✅ Active | FlowSignal Integration (FLOWSIGNAL-001) — asserts the gateway has `REDIS_URL` and a KMS setting, and that any `FLOWSIGNAL_*` credential variables come from `secretKeyRef` (true when none are set). Its Redis-prefix check compares constants, and nothing checks the normative provider |

### US_FED Controls (NIST SP 800-53 / NIST AI 600-1 — US_FED only)

| Validation File                                          | Control | Standard             | Region Scope | Status    | Description                                                        |
| -------------------------------------------------------- | ------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-sc4.yaml`](lula-validation-sc4.yaml)   | SC-4    | NIST SP 800-53       | US_FED       | ✅ Active | Fiscal Limits and RBAC — Gateway OPA UDS sidecar & ISO 42001 `opa-policies`/`opa-system-authz` ConfigMaps in `governance-stack` |
| [`lula-validation-cilium-dpv2.yaml`](lula-validation-cilium-dpv2.yaml) | SC-7 | NIST SP 800-53 | US_FED | ✅ Active | Boundary Protection — GKE Dataplane V2 anetd DaemonSet health in `kube-system` |
| [`lula-validation-ac2.yaml`](lula-validation-ac2.yaml)   | AC-2    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Account Management — ServiceAccount lifecycle in `governance-stack` |
| [`lula-validation-ac3.yaml`](lula-validation-ac3.yaml)   | AC-3    | NIST SP 800-53 Rev 5 | US_FED       | ✅ Active | Access Enforcement — Gateway OPA UDS sidecar + read-only ConfigMap check |
| [`lula-validation-au12.yaml`](lula-validation-au12.yaml) | AU-12   | NIST SP 800-53 Rev 5 | US_FED       | ✅ Active | Audit Record Generation — verifies gateway blocking hash-chain (`EVIDENCE_CHAIN_BLOCKING=true`) and `compliance-bridge` durable WORM cold-store (`EVIDENCE_COLD_STORE`) |
| [`lula-validation-metrics.yaml`](lula-validation-metrics.yaml) | AU-12 | NIST SP 800-53 Rev 5 | US_FED | ✅ Active | Prometheus Metrics Scrape — verifies Terraform-reconciled `gateway-metrics` GMP `PodMonitoring` (`infra/modules/gateway/metrics-monitors/`) targeting `app=gateway` on port `metrics` (`/metrics`) in `governance-stack` |
| [`lula-validation-cm6.yaml`](lula-validation-cm6.yaml)   | CM-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Configuration Settings — Governance ConfigMaps present             |
| [`lula-validation-ia3.yaml`](lula-validation-ia3.yaml)   | IA-3    | NIST SP 800-53       | US_FED       | ✅ Active | Device Identification — the gateway names its trusted Linkerd client identities (`CAGE_TRUSTED_CLIENT_IDENTITIES`), runs the OPA UDS sidecar, one of three named `NetworkPolicy` objects exists, and neither `gateway` nor `compliance-bridge` skips inbound mesh ports |
| [`lula-validation-ia5.yaml`](lula-validation-ia5.yaml)   | IA-5    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Authenticator Management — KMS HSM key lifecycle                   |
| [`lula-validation-ir6.yaml`](lula-validation-ir6.yaml)   | IR-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Incident Reporting — compliance-bridge Deployment check            |
| [`lula-validation-ra5.yaml`](lula-validation-ra5.yaml)   | RA-5    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Vulnerability Scanning (`planned`, `POAM-010`) — in-cluster `CronJob/security-scanner` check |
| [`lula-validation-sc8.yaml`](lula-validation-sc8.yaml)   | SC-8    | NIST SP 800-53       | US_FED       | ✅ Active | Transmission Confidentiality — `gateway` and `compliance-bridge` pin the Memorystore server CA (`POAM-2026-086`). It checks neither Linkerd mTLS nor Service or Ingress TLS |
| [`lula-validation-si2.yaml`](lula-validation-si2.yaml)   | SI-2    | NIST SP 800-53       | US_FED       | ✅ Active | Flaw Remediation — immutable `@sha256:` image digests across `governance-stack` |
| [`lula-validation-ai600-confabulation.yaml`](lula-validation-ai600-confabulation.yaml) | SI-10, AU-3 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.2 Confabulation — asserts `confabulation_rate < 0.02` over 24h window (POAM AI600-001). Requires `confabulation_rate` metric in Langfuse compliance project. |
| [`lula-validation-ai600-data-privacy.yaml`](lula-validation-ai600-data-privacy.yaml) | SI-19, SC-28 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.3 Data Privacy — asserts PII audit log retention ≥ 90 days and Presidio score threshold ≥ 0.5 (POAM AI600-002). |
| [`lula-validation-ai600-prompt-injection.yaml`](lula-validation-ai600-prompt-injection.yaml) | SI-3, SI-10, CA-8 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.4 Prompt Injection — asserts injection detector ConfigMap present and deflection score ≥ 4 (POAM AI600-003). |
| [`lula-validation-ai600-human-ai-config.yaml`](lula-validation-ai600-human-ai-config.yaml) | AC-5, AU-3, CA-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.5 Human-AI Configuration — asserts DEFER queue SLA ≤ 4h for CRITICAL escalations and HITL audit trail present (POAM AI600-005). |
| [`lula-validation-ai600-cbrn.yaml`](lula-validation-ai600-cbrn.yaml) | SA-12, SR-3, SI-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.6 / §2.12 CBRN & Value Chain — asserts CBRN keyword list ≥ 10 terms enabled and NeMo CBRN rail deployed (POAM AI600-007). **Cat-M: requires AO pre-approval before activation.** |

### EU_ECB Controls (EU AI Act / GDPR / DORA — EU_ECB only)

| Validation File                                                          | Control         | Standard             | Region Scope | Status    | Description                                                        |
| ------------------------------------------------------------------------ | --------------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-eu-fria.yaml`](lula-validation-eu-fria.yaml)           | Art. 27        | EU AI Act            | EU_ECB       | ✅ Active | FRIA Gating (EU-001) — asserts `gateway_running` and `region_from_configmap`: the gateway is ready and reads `CAGE_DEPLOYMENT_REGION` from the `cage-deployment` ConfigMap, which may hold any of the three regions. It checks neither the `fria` tier nor the normative provider |
| [`lula-validation-eu-ai-act-art9.yaml`](lula-validation-eu-ai-act-art9.yaml) | Art. 9     | EU AI Act            | EU_ECB       | ⚪ Adopter-Operated (`not-applicable`) | Institutional Risk Management System — illustrative template for adopters wiring a GRC endpoint |
| [`lula-validation-gdpr-art22.yaml`](lula-validation-gdpr-art22.yaml)     | Art. 22         | GDPR                 | EU_ECB       | 🔶 Stub   | Automated Decision-Making (`planned` `EU-006`) — runtime `REQUIRE_APPROVAL` dual-control oversight is `implemented`; Art. 22(3) subject contestation & `/v1/compliance/gdpr/art22` endpoint check remain `planned` |
| [`lula-validation-dora-art10.yaml`](lula-validation-dora-art10.yaml)     | Art. 10         | DORA                 | EU_ECB       | ⚪ Adopter-Operated (`not-applicable`) | Institutional ICT Detection & Incident Classification — illustrative template for supervised financial-entity SOC integration |

### APAC_MAS Controls (MAS FEAT / MAS Notice 655 / MAS TRM — APAC_MAS only)

| Validation File                                                              | Control          | Standard             | Region Scope | Status  | Description                                                                |
| ---------------------------------------------------------------------------- | ---------------- | -------------------- | ------------ | ------- | -------------------------------------------------------------------------- |
| [`lula-validation-mas-feat.yaml`](lula-validation-mas-feat.yaml)             | MAS FEAT         | MAS FEAT Principles  | APAC_MAS     | ⚪ Adopter-Operated (`not-applicable`) | Institutional Fairness, Ethics, Accountability, Transparency — illustrative template (`demographic_parity_gap ≤ 0.08`, 180-day report) |
| [`lula-validation-mas-notice655.yaml`](lula-validation-mas-notice655.yaml)   | MAS Notice 655   | MAS Notice 655       | APAC_MAS     | ⚪ Adopter-Operated (`not-applicable`) | Institutional Technology Risk Management — illustrative template (`data_residency_region = "asia-southeast1"`) |
| [`lula-validation-mas-trm-s6.yaml`](lula-validation-mas-trm-s6.yaml)         | MAS TRM §6.3     | MAS TRM              | APAC_MAS     | ⚪ Adopter-Operated (`not-applicable`) | Institutional AI/ML MRM Boundary — illustrative template (`0.96` runtime floor enforced under `ctrl-agt-001`) |

**Legend:**

- ✅ **Active** — Rated production-ready. Only a manifest marked Active here may be cited as evidence for closing a POA&M item ([`check_poam_lula_divergence.py`](../../scripts/check_poam_lula_divergence.py) reads this column). The rating does not re-verify the Rego; the Description column says what each manifest checks
- 🔶 **Stub** — Validation logic is complete but requires cluster-specific namespace/resource name configuration or a planned endpoint (`ra5`, `gdpr-art22`) before activation
- ⚪ **Adopter-Operated (`not-applicable`)** — Institutional governance/GRC/SOC obligation outside the standalone CAGE software boundary (`# cage-status: not-applicable`); retained as an illustrative reference template for deploying institutions
- **Region Scope:** `ALL` = applies to US_FED, EU_ECB, and APAC_MAS deployments; `US_FED` = applies only when `CAGE_DEPLOYMENT_REGION=US_FED`; `EU_ECB` = applies only when `CAGE_DEPLOYMENT_REGION=EU_ECB`; `APAC_MAS` = applies only when `CAGE_DEPLOYMENT_REGION=APAC_MAS`

### Two Counts: 26 Evaluated, 16 Rated Active

This directory is described by two numbers, and they answer different questions.

- **26 evaluated.** A manifest is evaluated unless it carries a `# cage-status: planned` or `# cage-status: not-applicable` header. The in-cluster audit CronJob ([`infra/modules/lula_cron/main.tf`](../../infra/modules/lula_cron/main.tf)) and Gate W ([`staging_lifecycle.sh`](../../scripts/staging_lifecycle.sh)) select on that header, and [`check_lula_stub_count.py`](../../scripts/check_lula_stub_count.py) holds the 26 / 7 split equal to the SSPs. This is the "26 of 26 satisfied" in [`gate_w_certification.json`](../gate_w_certification.json).
- **16 rated Active.** The Status column above is a quality rating, not a schedule. It is stricter on purpose: it is the allowlist of manifests that may back a POA&M closure.

| Status column | Count | Evaluated by the CronJob and Gate W | May back a POA&M closure |
|---|---|---|---|
| Rated Active | 16 | Yes | Yes |
| Stub, no `cage-status` header | 10 | Yes | No |
| Stub, `planned` (`ra5`, `gdpr-art22`) | 2 | No | No |
| Adopter-operated, `not-applicable` | 5 | No | No |
| **Total** | **33** | **26** | **16** |

The ten evaluated stubs are the five AI 600-1 manifests that the stub ratchet flags as placeholders (`ai600-confabulation`, `ai600-data-privacy`, `ai600-prompt-injection`, `ai600-human-ai-config`, `ai600-cbrn`; their own metadata says they always pass) and five more that this README rates Stub and the ratchet does not flag (`aarm-vectors`, `ac2`, `cm6`, `ia5`, `ir6`).

So a result of "26 of 26 satisfied" is true and is weaker than it sounds: ten of the 26 are manifests this README does not accept as evidence, and a placeholder can be satisfied without asserting anything about the control. Read it as "16 manifests rated Active satisfied, and no evaluated manifest failed". Rated Active is narrower than it sounds too. Checked against their Rego on 2026-11-14, six Active rows described checks the Rego does not make (`ftra`, `eu-fria`, `tqp007`, `iso001-token-quota`, `flowsignal` and `sc8`); the rows above now say what each asserts, and `ftra` asserts only that a gateway container exists. Their ratings are unchanged. For the certified `8956f505` run the figure is narrower still: 12 manifests were rated Active in the certified tree, and the commit that recorded the certification (`84f39e21`) promoted four more (`ac3`, `ia3`, `sc8`, `si2`). Those four already met the Active criteria in the certified tree, so the rating had lagged the manifests, but the description that commit gave `sc8` claimed more than its Rego checks. [`gate_w_certification.json`](../gate_w_certification.json) carries this breakdown as `lula_result_breakdown`. Gate W runs from now on write it with [`lula_rating_breakdown.py`](../../scripts/lula_rating_breakdown.py) to `<archive>/lula/rating-breakdown.json` and into the archive manifest as `lula.rating_breakdown`, and the Lula phase fails if it cannot. [`test_lula_rating_breakdown.py`](../../tests/unit/test_lula_rating_breakdown.py) holds the counts in this section to the tree.

### Posture Architecture Alignment

The active/stub/adopter-operated split is **intentional and aligned with the posture architecture**:

- **7 Active (ALL scope):** ISO 42001 universal controls (A.5.2, A.5.3, A.9.2) + TokenQuotaProxy (A.8.4 / CTRL_TQP_007) + Token Quota OPA Injection (A.4 / ISO-001) + FTRA Tier 0.5 Gate (CTRL_FTRA_001) + FlowSignal Integration (A.8.4 / FLOWSIGNAL-001) — rated Active in every region; the rows above say how little some of them check
- **8 Active (US_FED scope):** AC-3 access enforcement (`lula-validation-ac3.yaml`), IA-3 workload identity configuration (`lula-validation-ia3.yaml`), SC-4 fiscal limits (`lula-validation-sc4.yaml`), SC-7 GKE Dataplane V2 boundary protection (`lula-validation-cilium-dpv2.yaml`), SC-8 transmission confidentiality (`lula-validation-sc8.yaml`), SI-2 digest pinning (`lula-validation-si2.yaml`), AU-12 audit record generation (`lula-validation-au12.yaml`), and AU-12 Prometheus metrics scrape (`lula-validation-metrics.yaml`) — rated Active for US Federal deployments
- **1 Active (EU_ECB scope):** EU AI Act Art. 27 FRIA gating (`lula-validation-eu-fria.yaml`) — rated Active for EU_ECB deployments, although its Rego checks neither the `fria` tier nor that the region is `EU_ECB`
- **1 Stub (ALL scope):** CSA AARM vectors — universal but requires cluster configuration. **Note:** This validation is listed as `Status: 🔶 Stub` and counted as 1 stub (ALL scope). It is NOT counted as an active validation for release gate purposes until real assertions replace the stub. See CA-05 remediation note below.
- **5 Remaining Unverified / Planned (US_FED scope):** NIST SP 800-53 controls (`ac2`, `cm6`, `ia5`, `ir6`, plus `ra5` `# cage-status: planned` under `POAM-2026-010`)
- **5 Stub (US_FED scope):** NIST AI 600-1 controls — Phase-0 placeholder Rego stubs tracked by `compliance/lula/.stub-baseline` (`5`, downward-only ratchet in `scripts/check_lula_stub_count.py`)
- **1 Stub + 2 Adopter-Operated (EU_ECB scope):** GDPR Art. 22 (`planned` under `EU-006` for subject-initiated Art. 22(3) contestation & `/v1/compliance/gdpr/art22`, while runtime `REQUIRE_APPROVAL` dual-control oversight is `implemented`), plus illustrative adopter-operated templates for EU AI Act Art. 9 and DORA Art. 10 (`not-applicable`)
- **3 Adopter-Operated (APAC_MAS scope):** Illustrative adopter-operated templates for MAS FEAT, MAS Notice 655, and MAS TRM §6.3 (`not-applicable`; runtime `0.96` trade-confidence floor enforced under `ctrl-agt-001`)

The remaining US_FED NIST SP 800-53 items represent **open POAM gaps** tracked in [`docs/POAM.md`](../../docs/POAM.md) (see POAM-2026-010, POAM-2026-011, POAM-2026-012, POAM-2026-151). The CSA AARM stub (1 manifest, ALL scope) is a separate gap affecting all regions.

The 5 US_FED NIST AI 600-1 stubs correspond to **phases 0–3 of the AI 600-1 implementation** (v3.0.0). Runtime enforcement is active for all phases via `confabulation_scorer.py`, `pii_sanitizer.py`, `prompt_injection_detector.py`, and `text_filter.py`. The Lula manifests are scaffolding-ready and will be hardened to full live-cluster assertions once Langfuse metric endpoints are configured. The CBRN stub (`lula-validation-ai600-cbrn.yaml`) remains a **Cat-M change** requiring AO pre-approval before cluster activation in a real deployment's own change-management process.

### Three-Region OSCAL SSPs

Each deployment region has a dedicated OSCAL System Security Plan:

| Region | SSP File | Frameworks |
|--------|----------|------------|
| **US_FED** | [`compliance/oscal/system-security-plan.yaml`](../oscal/system-security-plan.yaml) | NIST SP 800-53 Rev 5 HIGH + NIST AI 600-1 |
| **EU_ECB** | [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../oscal/system-security-plan-eu-ecb.yaml) | EU AI Act / GDPR Art. 22 / DORA |
| **APAC_MAS** | [`compliance/oscal/system-security-plan-apac-mas.yaml`](../oscal/system-security-plan-apac-mas.yaml) | MAS FEAT / MAS Notice 655 / MAS TRM §6.3 |

`CAGE_DEPLOYMENT_REGION` selects which SSP applies. It does not select manifests: `CronJob/lula-audit` ([`infra/modules/lula_cron/`](../../infra/modules/lula_cron/main.tf)) mounts every manifest that carries no `# cage-status: planned` or `# cage-status: not-applicable` header, whatever the region.

---

## Running Validations

### Run a single validation

```bash
lula validate -f compliance/lula/lula-validation-a53.yaml
```

### Run the evaluated validations from a workstation

The in-cluster CronJob and Gate W evaluate every manifest without a `planned` or `not-applicable` header, whatever `CAGE_DEPLOYMENT_REGION` is. API-domain manifests (`type: api`) call in-cluster service URLs, so run those in the cluster (see [In-cluster](#in-cluster-via-cronjob) below). This loop runs the rest, as Gate W's host phase does:

```bash
for f in compliance/lula/lula-validation-*.yaml; do
  grep -Eq '^#[[:space:]]*cage-status:[[:space:]]*(planned|not-applicable)([[:space:]]|$)' "$f" && continue
  grep -Eq '^[[:space:]]*type:[[:space:]]*api([[:space:]]|$)' "$f" && continue
  echo "=== Validating $f ==="
  lula validate -f "$f"
done
```

A satisfied manifest is evidence for its control only if the tables above rate it Active.

### Run against a specific Kubernetes context

```bash
lula validate -f compliance/lula/lula-validation-sc4.yaml --kubeconfig ~/.kube/config
```

### In-cluster (via CronJob)

Gate W runs the CronJob on demand the same way (`governance-stack` is the default namespace):

```bash
kubectl create job lula-manual --from=cronjob/lula-audit -n governance-stack
```

`#664` (`372daad2`) migrated all 33 `compliance/lula/lula-validation-*.yaml` files to the Lula v0.16.0 `resource-rule` / `requests` schema (`tests/test_lula_v0160_schema.py`). The unmanaged `de5534ac:deployment/k8s/lula-cron.yaml` and `de5534ac:deployment/k8s/lula-rbac.yaml` were retired with the shadow manifest tree, and the auditor `CronJob` and its read-only RBAC are now in Terraform state ([`infra/modules/lula_cron/`](../../infra/modules/lula_cron/main.tf)). The certified Gate W run found it active and evaluated its 26 manifests ([`gate_w_certification.json`](../gate_w_certification.json)). 5 validations carry `.stub-baseline` stub markers (`scripts/check_lula_stub_count.py`), and the AgentSight eBPF collector is not in force (`POAM-021` reopened, `POAM-2026-193`).

---

## Activating Stub Validations

Each stub file contains `# TODO:` comments with the specific steps required. The general process is:

1. **Confirm the resource name** — check the relevant Terraform workload module in `infra/modules/` and `infra/targets/gcp-gke/`
2. **Confirm the namespace** — check `infra/modules/k8s_namespace/main.tf` and `infra/targets/gcp-gke/main.tf`
3. **Update the validation file** — replace placeholder names and `# TODO:` namespace values
4. **Test locally** — `lula validate -f compliance/lula/lula-validation-<control>.yaml`
5. **Register for scheduled execution** — nothing to register: `CronJob/lula-audit` picks up every manifest without a `planned` or `not-applicable` header. A stub is already scheduled; what it lacks is the rating in the next step
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
- [`deployment/docker/Dockerfile.lula`](../../deployment/docker/Dockerfile.lula) — Lula container image
- [`compliance/oscal/system-security-plan.yaml`](../oscal/system-security-plan.yaml) — US_FED SSP (NIST SP 800-53 Rev 5 HIGH)
- [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../oscal/system-security-plan-eu-ecb.yaml) — EU_ECB SSP (EU AI Act / GDPR / DORA)
- [`compliance/oscal/system-security-plan-apac-mas.yaml`](../oscal/system-security-plan-apac-mas.yaml) — APAC_MAS SSP (MAS FEAT / Notice 655 / TRM)
- [`compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md`](../../docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) — Phase 4 compliance artifact findings (CA-01 through CA-08)
