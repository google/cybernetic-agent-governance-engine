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
| [`lula-validation-a52.yaml`](lula-validation-a52.yaml)   | A.5.2   | ISO 42001            | ALL          | ✅ Active | Social Impact Assessment (NeMo Guardrails toxicity blocking) — reads `metrics_doc` from the compliance bridge (`/v1/metrics/A.5.2`, under 48 hours old) and asserts `rate_or_grace_ok`: a safety rate ≥ 0.99 over at least one trace, or startup grace with no traces yet |
| [`lula-validation-a53.yaml`](lula-validation-a53.yaml)   | A.5.3   | ISO 42001            | ALL          | ✅ Active | Logging and Monitoring (Langfuse safety rate) — reads `metrics_doc` from the compliance bridge (`/v1/metrics/A.5.3`, under 48 hours old) and asserts `rate_or_grace_ok`: a safety rate ≥ 0.98 over at least one trace, or startup grace with no traces yet |
| [`lula-validation-a92.yaml`](lula-validation-a92.yaml)   | A.9.2   | ISO 42001            | ALL          | ✅ Active | Data Transfer to Suppliers (Presidio PII leak rate) — reads `metrics_doc` from the compliance bridge (`/v1/metrics/A.9.2`, under 48 hours old) and asserts `rate_or_grace_ok`: a safety rate of exactly 1.0 over at least one trace, or startup grace with no traces yet |
| [`lula-validation-aarm-vectors.yaml`](lula-validation-aarm-vectors.yaml) | CSA AARM v1.0 | CSA AARM | ALL | 🔶 Stub | CSA AARM v1.0 11-vector threat coverage validation |
| [`lula-validation-tqp007.yaml`](lula-validation-tqp007.yaml)             | A.8.4         | ISO 42001 | ALL | 🔶 Stub | TokenQuotaProxy (CTRL_TQP_007) — asserts `tqp_running` and `tqp_has_redis_url`: the gateway is ready and has a non-empty `REDIS_URL`. It does not check fail-closed behaviour; `#664` removed a fail-closed check on a variable nothing sets (POAM-2026-219) |
| [`lula-validation-iso001-token-quota.yaml`](lula-validation-iso001-token-quota.yaml) | A.4 | ISO 42001 | ALL | ✅ Active | Token Quota OPA Injection (ISO-001) — asserts `gateway_has_redis_url` and `opa_policy_has_quota_rules`: the gateway or advisor has a non-empty `REDIS_URL`, and a policy file in the `opa-policies` ConfigMap contains the strings quota_available and token_quota, as the finance bundle's `trade_governance.rego` does. `#664` had reduced the second to a non-empty check; restored 2026-11-14 (POAM-2026-219) |
| [`lula-validation-ftra.yaml`](lula-validation-ftra.yaml)                 | CTRL_FTRA_001 | ISO 42001 / NIST | ALL | 🔶 Stub | FTRA Tier 0.5 Gate (CTRL_FTRA_001) — asserts only `gateway_exists`: a gateway Deployment with a `gateway` container. It does not exercise FTRA; [`test_ftra_package.py`](../../tests/test_ftra_package.py) does (POAM-2026-219) |
| [`lula-validation-flowsignal.yaml`](lula-validation-flowsignal.yaml)     | A.8.4         | ISO 42001 | ALL | 🔶 Stub | FlowSignal Integration (FLOWSIGNAL-001) — asserts the gateway has `REDIS_URL` and a KMS setting, and that any `FLOWSIGNAL_*` credential variables come from `secretKeyRef` (true when none are set). Its Redis-prefix check compares constants, and nothing checks the normative provider since `#664` removed that check (POAM-2026-219) |

### US_FED Controls (NIST SP 800-53 / NIST AI 600-1 — US_FED only)

| Validation File                                          | Control | Standard             | Region Scope | Status    | Description                                                        |
| -------------------------------------------------------- | ------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-sc4.yaml`](lula-validation-sc4.yaml)   | SC-4    | NIST SP 800-53       | US_FED       | ✅ Active | Fiscal Limits and RBAC — asserts `gateway_opa_sidecar_ready` (the gateway is ready and runs the OPA sidecar on its Unix socket with `--authorization=basic`), `session_isolation_policy_loaded` (the `opa-policies` ConfigMap holds a non-empty `.rego` file) and `system_authz_immutable` (`opa-system-authz` declares `package system.authz`), in `governance-stack` |
| [`lula-validation-cilium-dpv2.yaml`](lula-validation-cilium-dpv2.yaml) | SC-7 | NIST SP 800-53 | US_FED | ✅ Active | Boundary Protection — the GKE Dataplane V2 `anetd` DaemonSet in `kube-system` has every desired pod ready (an inline `validate` with no named rules) |
| [`lula-validation-ac2.yaml`](lula-validation-ac2.yaml)   | AC-2    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Account Management — ServiceAccount lifecycle in `governance-stack` |
| [`lula-validation-ac3.yaml`](lula-validation-ac3.yaml)   | AC-3    | NIST SP 800-53 Rev 5 | US_FED       | ✅ Active | Access Enforcement — asserts `gateway_opa_uds_sidecar_ready` (the gateway reaches OPA over its Unix socket, and the sidecar runs with `--authorization=basic`, a read-only root filesystem and no ports), `opa_policies_loaded` (a non-empty `.rego` file in `opa-policies`) and `opa_system_authz_loaded` (`opa-system-authz` declares `default allow := false`) |
| [`lula-validation-au12.yaml`](lula-validation-au12.yaml) | AU-12   | NIST SP 800-53 Rev 5 | US_FED       | ✅ Active | Audit Record Generation — asserts `gateway_blocking_evidence_ready` (a ready gateway sets `EVIDENCE_STREAM_ENABLED=true` and `EVIDENCE_CHAIN_BLOCKING=true`) and `bridge_cold_store_ready` (a ready `compliance-bridge` sets `EVIDENCE_COLD_STORE` to `gcs` or `s3`) |
| [`lula-validation-metrics.yaml`](lula-validation-metrics.yaml) | AU-12 | NIST SP 800-53 Rev 5 | US_FED | ✅ Active | Prometheus Metrics Scrape — asserts `pod_monitoring_valid`: the Terraform-reconciled `gateway-metrics` GMP `PodMonitoring` (`infra/modules/gateway/metrics-monitors/`) selects `app=gateway` and scrapes port `metrics` at `/metrics`, in `governance-stack` |
| [`lula-validation-cm6.yaml`](lula-validation-cm6.yaml)   | CM-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Configuration Settings — Governance ConfigMaps present             |
| [`lula-validation-ia3.yaml`](lula-validation-ia3.yaml)   | IA-3    | NIST SP 800-53       | US_FED       | ✅ Active | Device Identification — asserts `gateway_mtls_identity_enforced` (the gateway names its trusted Linkerd client identities in `CAGE_TRUSTED_CLIENT_IDENTITIES`), `opa_uds_sidecar_running` (a ready gateway runs the OPA sidecar on its Unix socket with no ports), `network_isolation_present` (one of three named `NetworkPolicy` objects exists) and `no_inbound_mesh_port_bypass` (neither `gateway` nor `compliance-bridge` skips inbound mesh ports) |
| [`lula-validation-ia5.yaml`](lula-validation-ia5.yaml)   | IA-5    | NIST SP 800-53       | US_FED       | 🔶 Stub   | Authenticator Management — KMS HSM key lifecycle                   |
| [`lula-validation-ir6.yaml`](lula-validation-ir6.yaml)   | IR-6    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Incident Reporting — compliance-bridge Deployment check            |
| [`lula-validation-ra5.yaml`](lula-validation-ra5.yaml)   | RA-5    | NIST SP 800-53 Rev 5 | US_FED       | 🔶 Stub   | Vulnerability Scanning (`planned`, `POAM-010`) — in-cluster `CronJob/security-scanner` check |
| [`lula-validation-sc8.yaml`](lula-validation-sc8.yaml)   | SC-8    | NIST SP 800-53       | US_FED       | ✅ Active | Transmission Confidentiality — asserts `redis_ca_pinned`: `gateway` and `compliance-bridge` mount the Memorystore server CA read-only, point `REDIS_CA_CERT_PATH` at it and carry its hash annotation (`POAM-2026-086`). It checks neither Linkerd mTLS nor Service, Ingress or NetworkPolicy TLS; `#664` removed four such checks (POAM-2026-219) |
| [`lula-validation-si2.yaml`](lula-validation-si2.yaml)   | SI-2    | NIST SP 800-53       | US_FED       | ✅ Active | Flaw Remediation — asserts `cage_images_pinned` (`gateway` and `agentsight-ui` exist and every image is pinned by `@sha256:` digest with no `:latest` tag), `optional_images_pinned` (the same for any of five optional Deployments that is present) and `all_containers_pull_policy_valid` (every container and init container in `governance-stack` is digest-pinned with pull policy `Always` or `IfNotPresent`) |
| [`lula-validation-ai600-confabulation.yaml`](lula-validation-ai600-confabulation.yaml) | SI-10, AU-3 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.2 Confabulation — asserts `confabulation_rate < 0.02` over 24h window (POAM AI600-001). Requires `confabulation_rate` metric in Langfuse compliance project. |
| [`lula-validation-ai600-data-privacy.yaml`](lula-validation-ai600-data-privacy.yaml) | SI-19, SC-28 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.3 Data Privacy — asserts PII audit log retention ≥ 90 days and Presidio score threshold ≥ 0.5 (POAM AI600-002). |
| [`lula-validation-ai600-prompt-injection.yaml`](lula-validation-ai600-prompt-injection.yaml) | SI-3, SI-10, CA-8 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.4 Prompt Injection — asserts injection detector ConfigMap present and deflection score ≥ 4 (POAM AI600-003). |
| [`lula-validation-ai600-human-ai-config.yaml`](lula-validation-ai600-human-ai-config.yaml) | AC-5, AU-3, CA-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.5 Human-AI Configuration — asserts DEFER queue SLA ≤ 4h for CRITICAL escalations and HITL audit trail present (POAM AI600-005). |
| [`lula-validation-ai600-cbrn.yaml`](lula-validation-ai600-cbrn.yaml) | SA-12, SR-3, SI-7 | NIST AI 600-1 | US_FED | 🔶 Stub | AI 600-1 §2.6 / §2.12 CBRN & Value Chain — asserts CBRN keyword list ≥ 10 terms enabled and NeMo CBRN rail deployed (POAM AI600-007). **Cat-M: requires AO pre-approval before activation.** |

### EU_ECB Controls (EU AI Act / GDPR / DORA — EU_ECB only)

| Validation File                                                          | Control         | Standard             | Region Scope | Status    | Description                                                        |
| ------------------------------------------------------------------------ | --------------- | -------------------- | ------------ | --------- | ------------------------------------------------------------------ |
| [`lula-validation-eu-fria.yaml`](lula-validation-eu-fria.yaml)           | Art. 27        | EU AI Act            | EU_ECB       | 🔶 Stub | FRIA Gating (EU-001) — asserts `gateway_running` and `region_from_configmap`: the gateway is ready and reads `CAGE_DEPLOYMENT_REGION` from the `cage-deployment` ConfigMap, which may hold any of the three regions. It checks neither the `fria` tier, nor the normative provider, nor that the region is `EU_ECB`; `#664` removed the provider, endpoint and region checks (POAM-2026-219). [`test_jurisdiction_wiring.py`](../../tests/governor/test_jurisdiction_wiring.py) verifies the `fria` tier (POAM-2026-099) |
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

- ✅ **Active** — Rated production-ready. Only a manifest marked Active here may be cited as evidence for closing a POA&M item ([`check_poam_lula_divergence.py`](../../scripts/check_poam_lula_divergence.py) reads this column). An Active row names in backticks every rule its `validate` composes, and every backticked snake_case name in it is a rule the manifest defines; [`test_lula_description_parity.py`](../../tests/unit/test_lula_description_parity.py) holds the rows to the Rego (POAM-2026-219). That test compares rule names, not what the rules check. [`check_k8s_terraform_parity.py`](../../scripts/check_k8s_terraform_parity.py) holds what they select: every object an Active manifest selects by name must be one a Terraform resource, `locals` manifest or Helm template in `infra/` creates, or the `anetd` DaemonSet GKE creates while Terraform enables Dataplane V2. Whether a rule checks enough of what it selects still rests on reading it
- 🔶 **Stub** — Not accepted as closure evidence: the manifest asserts too little to evidence its control, needs cluster-specific configuration, or waits on a planned endpoint (`ra5`, `gdpr-art22`)
- ⚪ **Adopter-Operated (`not-applicable`)** — Institutional governance/GRC/SOC obligation outside the standalone CAGE software boundary (`# cage-status: not-applicable`); retained as an illustrative reference template for deploying institutions
- **Region Scope:** `ALL` = applies to US_FED, EU_ECB, and APAC_MAS deployments; `US_FED` = applies only when `CAGE_DEPLOYMENT_REGION=US_FED`; `EU_ECB` = applies only when `CAGE_DEPLOYMENT_REGION=EU_ECB`; `APAC_MAS` = applies only when `CAGE_DEPLOYMENT_REGION=APAC_MAS`

### Two Counts: 26 Evaluated, 12 Rated Active

This directory is described by two numbers, and they answer different questions.

- **26 evaluated.** A manifest is evaluated unless it carries a `# cage-status: planned` or `# cage-status: not-applicable` header. The in-cluster audit CronJob ([`infra/modules/lula_cron/main.tf`](../../infra/modules/lula_cron/main.tf)) and Gate W ([`staging_lifecycle.sh`](../../scripts/staging_lifecycle.sh)) select on that header, and [`check_lula_stub_count.py`](../../scripts/check_lula_stub_count.py) holds the 26 / 7 split equal to the SSPs. This is the "26 of 26 satisfied" in [`gate_w_certification.json`](../gate_w_certification.json).
- **12 rated Active.** The Status column above is a quality rating, not a schedule. It is stricter on purpose: it is the allowlist of manifests that may back a POA&M closure.

| Status column | Count | Evaluated by the CronJob and Gate W | May back a POA&M closure |
|---|---|---|---|
| Rated Active | 12 | Yes | Yes |
| Stub, no `cage-status` header | 14 | Yes | No |
| Stub, `planned` (`ra5`, `gdpr-art22`) | 2 | No | No |
| Adopter-operated, `not-applicable` | 5 | No | No |
| **Total** | **33** | **26** | **12** |

The fourteen evaluated stubs are the five AI 600-1 manifests that the stub ratchet flags as placeholders (`ai600-confabulation`, `ai600-data-privacy`, `ai600-prompt-injection`, `ai600-human-ai-config`, `ai600-cbrn`; their own metadata says they always pass), five more that this README rates Stub and the ratchet does not flag (`aarm-vectors`, `ac2`, `cm6`, `ia5`, `ir6`), and four that were rated Active until 2026-11-14 (`ftra`, `eu-fria`, `tqp007`, `flowsignal`).

So a result of "26 of 26 satisfied" is true and is weaker than it sounds: fourteen of the 26 are manifests this README does not accept as evidence, and a placeholder can be satisfied without asserting anything about the control. Read it as "12 manifests rated Active satisfied, and no evaluated manifest failed".

**Why four Active ratings were withdrawn on 2026-11-14 (POAM-2026-219).** Checked against their Rego, six Active rows described checks the Rego does not make. All six lost those checks in one commit: `#664` (`372daad2`), the Lula v0.16 schema migration of all 33 manifests, whose message describes a schema migration and no removed assertions. In three of them the removed assertions checked configuration the committed Terraform did not set (`eu-fria`'s normative provider, endpoint and `EU_ECB` region; `flowsignal`'s provider; `tqp007`'s fail-closed variable), so each would have failed once Lula ran against the cluster. `ftra`'s removed rules each passed whenever the gateway existed, so it asserted no more before `#664` than after. The ratings were decided manifest by manifest: `ftra`, `eu-fria`, `tqp007` and `flowsignal` are rated Stub; `iso001-token-quota` has its policy-content check back and stays Active; `sc8` makes one real check, Memorystore CA pinning, and stays Active with its header corrected. Every Active row now names the rules its `validate` composes, and [`test_lula_description_parity.py`](../../tests/unit/test_lula_description_parity.py) fails when a row names a rule the Rego no longer defines or omits one it composes. That is the before-and-after comparison `#664` never got, and replaying `#664`'s removals against it reports all six. Rule names cannot show what a rule selects, so [`check_k8s_terraform_parity.py`](../../scripts/check_k8s_terraform_parity.py) now also fails an Active manifest that selects an object `infra/` does not create. Replayed against what the manifests selected before `#664`, it reports `ftra`'s four objects (a `cage-gateway` Deployment, a terminal-registry ConfigMap and two NetworkPolicies), the `cage-gateway` Deployment of `eu-fria` and `flowsignal`, `tqp007`'s `token-quota-proxy` Deployment and `iso001-token-quota`'s `opa-policy` ConfigMap: each manifest selected something no cluster Terraform builds contains. `#664` also wrote `stera-gateway`, which nothing creates, into eleven manifests' Deployment match. The check removed it from `au12`, and `opa-policy` from `iso001-token-quota`, the two Active manifests that still carried a dead name; eleven of the fourteen evaluated stubs still select one and would fail it on promotion.

For the certified `8956f505` run, 12 manifests were rated Active in the certified tree, and the commit that recorded the certification (`84f39e21`) promoted four more (`ac3`, `ia3`, `sc8`, `si2`). Those four already met the Active criteria in the certified tree, so the rating had lagged the manifests, but the description that commit gave `sc8` claimed more than its Rego checks. Under the ratings above, 11 of the 12 manifests now rated Active were satisfied in that run with the `validate` logic they have today, counting `au12`, whose Deployment match has since dropped `stera-gateway`, which cannot change its result on a cluster Terraform builds; `iso001-token-quota` was satisfied in its weaker `#664` form, and its restored check has not yet been through a Gate W run. [`gate_w_certification.json`](../gate_w_certification.json) carries this breakdown as `lula_result_breakdown`. Gate W runs from now on write it with [`lula_rating_breakdown.py`](../../scripts/lula_rating_breakdown.py) to `<archive>/lula/rating-breakdown.json` and into the archive manifest as `lula.rating_breakdown`, and the Lula phase fails if it cannot. [`test_lula_rating_breakdown.py`](../../tests/unit/test_lula_rating_breakdown.py) holds the counts in this section to the tree.

### Posture Architecture Alignment

The active/stub/adopter-operated split is **intentional and aligned with the posture architecture**:

- **4 Active (ALL scope):** ISO 42001 universal controls (A.5.2, A.5.3, A.9.2) + Token Quota OPA Injection (A.4 / ISO-001) — rated Active in every region
- **8 Active (US_FED scope):** AC-3 access enforcement (`lula-validation-ac3.yaml`), IA-3 workload identity configuration (`lula-validation-ia3.yaml`), SC-4 fiscal limits (`lula-validation-sc4.yaml`), SC-7 GKE Dataplane V2 boundary protection (`lula-validation-cilium-dpv2.yaml`), SC-8 Memorystore CA pinning (`lula-validation-sc8.yaml`), SI-2 digest pinning (`lula-validation-si2.yaml`), AU-12 audit record generation (`lula-validation-au12.yaml`), and AU-12 Prometheus metrics scrape (`lula-validation-metrics.yaml`) — rated Active for US Federal deployments
- **0 Active (EU_ECB scope):** EU AI Act Art. 27 FRIA gating (`lula-validation-eu-fria.yaml`) is rated Stub because its Rego checks neither the `fria` tier, the normative provider nor that the region is `EU_ECB`. No Lula manifest evidences an EU_ECB control; the `fria` tier is verified by [`test_jurisdiction_wiring.py`](../../tests/governor/test_jurisdiction_wiring.py)
- **4 Stub (ALL scope):** CSA AARM vectors (universal but requires cluster configuration; see CA-05 remediation note below), plus TokenQuotaProxy (A.8.4 / CTRL_TQP_007), FTRA Tier 0.5 Gate (CTRL_FTRA_001) and FlowSignal Integration (A.8.4 / FLOWSIGNAL-001), which assert too little to evidence their controls (POAM-2026-219). None counts as an active validation for release gate purposes
- **5 Remaining Unverified / Planned (US_FED scope):** NIST SP 800-53 controls (`ac2`, `cm6`, `ia5`, `ir6`, plus `ra5` `# cage-status: planned` under `POAM-2026-010`)
- **5 Stub (US_FED scope):** NIST AI 600-1 controls — Phase-0 placeholder Rego stubs tracked by `compliance/lula/.stub-baseline` (`5`, downward-only ratchet in `scripts/check_lula_stub_count.py`)
- **2 Stub + 2 Adopter-Operated (EU_ECB scope):** EU AI Act Art. 27 FRIA gating (above) and GDPR Art. 22 (`planned` under `EU-006` for subject-initiated Art. 22(3) contestation & `/v1/compliance/gdpr/art22`, while runtime `REQUIRE_APPROVAL` dual-control oversight is `implemented`), plus illustrative adopter-operated templates for EU AI Act Art. 9 and DORA Art. 10 (`not-applicable`)
- **3 Adopter-Operated (APAC_MAS scope):** Illustrative adopter-operated templates for MAS FEAT, MAS Notice 655, and MAS TRM §6.3 (`not-applicable`; runtime `0.96` trade-confidence floor enforced under `ctrl-agt-001`)

The remaining US_FED NIST SP 800-53 items represent **open POAM gaps** tracked in [`docs/POAM.md`](../../docs/POAM.md) (see POAM-2026-010, POAM-2026-011, POAM-2026-012, POAM-2026-151). The four ALL-scope stubs are a separate gap affecting all regions.

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

`#664` (`372daad2`) migrated all 33 `compliance/lula/lula-validation-*.yaml` files to the Lula v0.16.0 `resource-rule` / `requests` schema (`tests/test_lula_v0160_schema.py`). The same commit removed assertions from six manifests then rated Active, as the Two Counts section above describes (POAM-2026-219). The unmanaged `de5534ac:deployment/k8s/lula-cron.yaml` and `de5534ac:deployment/k8s/lula-rbac.yaml` were retired with the shadow manifest tree, and the auditor `CronJob` and its read-only RBAC are now in Terraform state ([`infra/modules/lula_cron/`](../../infra/modules/lula_cron/main.tf)). The certified Gate W run found it active and evaluated its 26 manifests ([`gate_w_certification.json`](../gate_w_certification.json)). 5 validations carry `.stub-baseline` stub markers (`scripts/check_lula_stub_count.py`), and the AgentSight eBPF collector is not in force (`POAM-021` reopened, `POAM-2026-193`).

---

## Activating Stub Validations

Each stub file contains `# TODO:` comments with the specific steps required. The general process is:

1. **Confirm the resource name** — check the relevant Terraform workload module in `infra/modules/` and `infra/targets/gcp-gke/`. Every name the Rego selects must be one `infra/` creates, including each alternate in a set; [`check_k8s_terraform_parity.py`](../../scripts/check_k8s_terraform_parity.py) fails an Active manifest that selects any other
2. **Confirm the namespace** — check `infra/modules/k8s_namespace/main.tf` and `infra/targets/gcp-gke/main.tf`
3. **Update the validation file** — replace placeholder names and `# TODO:` namespace values
4. **Test locally** — `lula validate -f compliance/lula/lula-validation-<control>.yaml`
5. **Register for scheduled execution** — nothing to register: `CronJob/lula-audit` picks up every manifest without a `planned` or `not-applicable` header. A stub is already scheduled; what it lacks is the rating in the next step
6. **Update this table** — change status from 🔶 Stub to ✅ Active, and name in backticks every rule the manifest's `validate` composes; [`test_lula_description_parity.py`](../../tests/unit/test_lula_description_parity.py) fails an Active row that omits one

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
