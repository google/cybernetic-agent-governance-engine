# Serverless Container Architecture: Cloud Run Implementation Plan

> **Status:** Revised after security-parity forensic audit. Supersedes the initial
> scaffold plan. Sections 5–9 are new and are **blocking** — the target must not be
> applied to any environment until Phase A completes.

## Executive Verdict & Architectural Posture

This plan refactors CAGE to support a first-class **Google Cloud Run deployment target** (`infra/targets/gcp-cloudrun`) while keeping the underlying workload contract cloud-agnostic across **AWS ECS on Fargate** and **Azure Container Apps**.

Per [`AGENTS.md`](../../AGENTS.md):
> *"Reference Architecture — Clean Architecture Over Operational Continuity... The optimization target is clean code structure, modularity, and architectural clarity."*

**Security verdict:** Cloud Run is *capable* of meeting or exceeding the GKE posture across NIST SP 800-53 Rev 5, ISO 42001, EU DORA, and MAS TRM. The currently scaffolded target does **not** yet meet it. A forensic audit identified five blocking defects, one defect inherited from the GKE baseline, three inaccurate control narratives, and four entirely missing workloads. All are enumerated in §5–§8 and sequenced in §9.

### Validated Codebase Baseline
1. **Zero K8s API Dependencies**: Verified across [`src/gateway/`](../../src/gateway/), [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/), [`src/compliance_bridge/`](../../src/compliance_bridge/).
2. **Environment Variable Decoupling**: All services consume dynamic configuration (`REDIS_URL`, `GATEWAY_URL`, `OPA_URL`, `VLLM_BASE_URL`, `LANGFUSE_HOST`).
3. **Stateful Services**: In-cluster StatefulSets (Redis, PostgreSQL) migrate to Cloud Memorystore and Cloud SQL.
4. **Dual K8s Filesystem References to Address**:
   - [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) reads `/var/run/secrets/kubernetes.io/serviceaccount/namespace`.
   - [`src/gateway/governance/ingress/lula_adapter.py`](../../src/gateway/governance/ingress/lula_adapter.py) parses `kubernetes-spec`.

---

## User Review Required

> [!IMPORTANT]
> **Parallel Target Coexistence:**
> `gcp-cloudrun` is provisioned without disrupting `gcp-gke` or `agnostic`. Both remain fully supported until Cloud Run reaches feature and compliance parity.

> [!WARNING]
> **Do Not Apply Before Phase A.**
> The scaffolded target contains a fail-open policy decision point and an evidence
> bucket without WORM retention. Applying it to any environment that produces
> compliance evidence would generate artifacts that cannot be relied upon.

> [!WARNING]
> **Lula Compliance Validation Phasing:**
> The repository contains **132 Lula validation files** asserting against `kubernetes-spec` manifests.
> - **Phase 1 & 2**: Extend [`lula_adapter.py`](../../src/gateway/governance/ingress/lula_adapter.py) to support `cloud-spec`/`gcp-api-spec`, and update baseline controls (SC-7, SC-8, SC-39) in [`oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py).
> - **Phase 3**: Progressively port the full 132-manifest suite to dual schemas.

---

## 1. Application-Layer K8s Decoupling

### [MODIFY] [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py)
Update `_is_dev_environment()`:
- Kubernetes: preserve the existing namespace-file check.
- Cloud Run: inspect `K_SERVICE` / `K_REVISION`.
- ECS / Container Apps: inspect `ECS_CONTAINER_METADATA_URI_V4` / `CONTAINER_APP_NAME`.
- Prevent environment spoofing without requiring a mounted filesystem secret.

### [NEW] Layer 1 Outbound Authentication Seam
See §6 (Defect B4). This is the largest application-layer consequence of leaving Kubernetes and was absent from the original plan.

---

## 2. Multi-Cloud Serverless Specification

### [NEW] [`docs/architecture/SERVERLESS_CONTAINER_ARCHITECTURE.md`](SERVERLESS_CONTAINER_ARCHITECTURE.md)
- **Serverless Workload Contract**: port 8080, non-root UID 1000, 12-factor config, HTTP health probes.
- **Tri-Cloud Equivalence Matrix**: Cloud Run v2 ↔ ECS Fargate ↔ Container Apps; sidecars via `localhost`; managed Redis/Postgres; GCS ↔ S3 ↔ Blob; Cloud KMS ↔ AWS KMS ↔ Key Vault.
- **Zero-Trust IAM**: platform cryptographic identity replacing service-mesh sidecars — with the explicit caveat that this shifts work from infrastructure into application code (§6).

---

## 3. Infrastructure as Code: `infra/targets/gcp-cloudrun`

Files: [`providers.tf`](../../infra/targets/gcp-cloudrun/providers.tf), [`variables.tf`](../../infra/targets/gcp-cloudrun/variables.tf), [`main.tf`](../../infra/targets/gcp-cloudrun/main.tf), [`outputs.tf`](../../infra/targets/gcp-cloudrun/outputs.tf), plus regional tfvars for `dev`, `staging`, `prod` (US_FED `us-central1`), `eu-prod` (EU_ECB `europe-west1`), `apac-prod` (APAC_MAS `asia-southeast1`).

**Implemented and verified correct:**
1. Direct VPC Egress on all services (`vpc_access.network_interfaces`, `egress = "ALL_TRAFFIC"`).
2. Dedicated least-privilege service accounts for `gateway`, `governed_advisor`, `agentsight_ui`, `compliance_bridge`, `langfuse`.
3. Secret Manager via `value_source.secret_key_ref` — no plaintext, satisfying [`AGENTS.md`](../../AGENTS.md) Secret Hygiene.
4. Cloud SQL private IP (`ipv4_enabled = false`) with `require_ssl = true`.

**Not yet implemented** — see §5–§8.

---

## 4. Control Parity Matrix (Corrected)

| Control | GKE Implementation | Cloud Run | Honest Status |
| :--- | :--- | :--- | :--- |
| **SC-39** Process Isolation | Pod Security Standards `restricted`, cgroups, namespaces | gVisor (`runsc`) **Gen1 only**; Gen2 uses a Linux microVM | **Conditional.** Gen2 is mandatory for GPU workloads. Execution environment must be pinned explicitly, and the narrative conditioned on it. |
| **Workload Identity** | K8s SA annotation | Native `template.service_account` | **Identical** |
| **SI-7 / CM-7** Binary Authorization | `PROJECT_SINGLETON_POLICY_ENFORCE` | Cloud Run Binary Authorization | **Gap.** `use_default = true` attaches the project default, which is `ALWAYS_ALLOW` unless attestors exist. A no-op that renders green. |
| **SC-7** Boundary Protection | Cilium eBPF per-workload L3/L4/L7 microsegmentation | Ingress controls + VPC egress | **Compensating, not equivalent.** `INTERNAL_ONLY` is a coarse perimeter admitting any in-VPC resource. The real replacement is IAM invoker identity. Microsegmentation is lost. |
| **SC-8 / IA-3** Transmission & Mutual Auth | Linkerd mTLS sidecars | GFE TLS 1.3 + IAM OIDC bearer tokens | **Superior — once implemented.** Not implemented today (§6). |
| **SC-12/13/28** CMEK | FIPS 140-2 L3 KMS on node disks and secrets | CMEK on Cloud Run, Cloud SQL, GCS, Memorystore | **Gap** (§7). |
| **AU-2/3/12** Audit Telemetry | GKE audit + workload logs | Native request, admin-activity, system logs | **Identical** |
| **AU-9** Immutable Evidence | `lifecycle_rule` delete at 2555 days | *(same construct copied)* | **Defective in both targets** (§5, Defect B5). |
| **POAM-019** Telemetry Isolation | `terraform_data` precondition on key distinctness | *(absent)* | **Gap.** Had no remediation assigned. |
| **SI-3** Malicious Code Protection | `readOnlyRootFilesystem`, `drop: ["ALL"]` | Writable in-memory overlay; non-root UID 1000 | **Control genuinely lost.** Downgraded to compensating. Not "identical." |
| **Secret Hygiene** | K8s Secrets in etcd | Secret Manager, resolved in memory | **Superior in Cloud Run** |
| **Edge DDoS / WAF** | Ingress + Cloud Armor via [`ingress.yaml`](../../deployment/k8s/ingress.yaml) | *(none — no LB exists)* | **Regression.** Cloud Armor attaches to a load balancer, not to `*.run.app`. |

---

## 5. Blocking Defect Register

### B1 — OPA sidecar as specified is a fail-open policy decision point (CRITICAL)
Starting OPA with `run --server --addr=localhost:8181` and **no bundle, policy volume, or config** yields `undefined` for every query — not `deny`. Any caller treating `undefined` as permissive has a total governance bypass that is invisible in logs and green in every smoke test.

GKE loads real policy via [`deployment/opa_config.yaml`](../../deployment/opa_config.yaml) and [`deployment/system_authz.rego`](../../deployment/system_authz.rego). Cloud Run has no ConfigMap primitive. Policy must arrive by an explicitly chosen mechanism. Violates the [`AGENTS.md`](../../AGENTS.md) *Fail-Closed Execution Boundary* invariant.

Structurally, Cloud Run v2 requires **every** container to be named once a second exists, and exactly one to declare `ports`. Startup ordering via `depends_on` is required, otherwise the gateway serves traffic before OPA listens — a policy-less cold-start window.

### B2 — `INTERNAL_LOAD_BALANCER` ingress severs production
That ingress mode admits traffic only from a Google Cloud external HTTPS Load Balancer. No `google_compute_global_forwarding_rule`, `google_compute_backend_service`, or serverless NEG exists in the target. Applying it to `prod` removes all external access with no replacement path. Ingress tightening is therefore **ordered after** the LB exists.

### B3 — CMEK placement is invalid HCL and materially incomplete
`encryption_key_name` is a **top-level** argument on `google_sql_database_instance`, not a member of `settings`; nesting it fails `terraform validate`. Missing surfaces: `google_storage_bucket.default_kms_key_name` (absent in **both** targets — the evidence store itself is on Google-managed keys), `google_redis_instance.customer_managed_key` (consequence-authority state, db=1), and the `roles/cloudkms.cryptoKeyEncrypterDecrypter` grants to the Cloud SQL and Cloud Run service agents without which `apply` fails. Cloud SQL CMEK is **create-time only and forces replacement**.

### B4 — `roles/run.invoker` alone produces a 403 on every inter-service call
Linkerd supplied caller identity transparently at the transport layer; application code sent plain HTTP. Cloud Run requires the *caller* to mint and attach an OIDC ID token with `audience = <callee URL>` from the metadata server. No token provider exists in the codebase and none was scoped. See §6.

### B5 — AU-9 parity would be achieved against a defective baseline
`lifecycle_rule { condition { age = 2555 } action { type = "Delete" } }` is a **scheduled deletion primitive, not immutable retention.** It imposes no floor on object lifetime — nothing prevents deletion on day 1. Repository-wide search confirms **neither target** defines `retention_policy` or `is_locked`. Compounding this, the compliance bridge holds `roles/storage.objectAdmin` on the evidence bucket, which includes `storage.objects.delete`: the component that writes evidence can erase it.

Required in **both** targets:
```hcl
retention_policy {
  retention_period = 220752000  # 2555 days, in seconds
  is_locked        = true       # irreversible; also blocks bucket deletion
}
```
with the writer SA downgraded from `objectAdmin` to `objectCreator` + `legacyBucketReader`.

Fixing only Cloud Run creates divergence; copying GKE forward propagates the flaw. Tracked as a cross-target POAM item (§10), not folded silently into the Cloud Run branch.

### B6 — Dead VPC Access Connector
Services `depends_on` `google_vpc_access_connector.connector` while using Direct VPC Egress via `network_interfaces`. These are mutually exclusive `vpc_access` modes. The connector is unreachable infrastructure: standing cost, standing attack surface, zero function. Delete it.

---

## 6. Layer 1 Outbound Authentication Seam (New Workstream)

Removing the service mesh moves an infrastructure concern into application code. This requires a first-class seam, not an ad-hoc helper.

- **Layer 1 (`src/gateway/`)**: a vendor-neutral outbound credential protocol. Must not import `google.auth` or any vendor SDK — Gate G3 ([`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py)) forbids it.
- **Layer 3 (`src/integrations/`)**: the GCP implementation minting metadata-server OIDC ID tokens, audience-scoped per callee, with caching honouring token expiry.
- **Selection**: runtime adapter loading through the existing factory allowlist pattern, consistent with `INTEGRATIONS_FACTORY_ALLOWLIST`.
- **Tests**: a caller with no token and a caller with a wrong-audience token must both be observed receiving 403. Per [`AGENTS.md`](../../AGENTS.md), *"every fail-closed path needs a test observing it fail."*

The same seam serves ECS Task Roles and Azure Managed Identity, keeping the tri-cloud contract intact.

---

## 7. Missing Workloads

Absent from the target despite being in scope in §3 of the original plan:

- **NeMo Guardrails + Presidio** multi-container service — input rails and PII redaction. The `nemo-freshness-check` CI gate has no Cloud Run analogue, so the ConfigMap ↔ [`config/rails/actions.py`](../../config/rails/actions.py) contract silently lapses.
- **`lula_job` + Cloud Scheduler** — continuous control monitoring (CA-7). Without it the 132 Lula validations never execute against this target.
- **`sbom_job` / `security_scan_job`** — SR-4 supply-chain and RA-5 vulnerability scanning.
- **`reconciliation_daemon`** — requires `min_instance_count = 1` with CPU always allocated. Under default request-scoped CPU the daemon freezes between requests; the reconciliation loop stalls in a way that presents as a hang, not a failure.

A posture missing its input rails, continuous monitoring, and supply-chain scanners is not at parity regardless of how the network controls score.

---

## 8. Lula Adapter & OSCAL Exporter

### [MODIFY] [`src/gateway/governance/ingress/lula_adapter.py`](../../src/gateway/governance/ingress/lula_adapter.py)
Generalize `_extract_kubernetes_resources()` into `_extract_domain_resources()` supporting `kubernetes-spec` and `cloud-spec`/`gcp-spec`, enabling Lula/OPA validation of Cloud Run resource models, IAM invoker policies, and VPC firewall rules.

### [MODIFY] [`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py)
Update SC-7, SC-8, SC-39 narratives — **written last**, against what actually shipped, and corrected per §4:
- **SC-39**: cite gVisor **only** where Gen1 is pinned; cite microVM isolation for Gen2.
- **SC-8**: cite IAM invoker OIDC identity plus GFE TLS.
- **SC-7**: cite identity-based authorization as the primary control and label the loss of per-workload microsegmentation as compensating.
- **SI-3**: label as compensating, not equivalent.

Compensating controls must be marked as such. Asserting "Identical" where a control is lost is a misstatement in a regulatory artifact.

---

## 9. Corrected Implementation Sequence

Each phase lands on its own branch and merges by squash per [`AGENTS.md`](../../AGENTS.md).

### Phase A — Fail-closed correctness (blocks any `apply`)
Branch: `feat/cloud-run-phase-a-failclosed`
1. OPA bundle delivery contract (GCS bundle service or baked image layer), named containers, `depends_on` ordering, and a gateway test asserting **deny** when OPA is unreachable.
2. `retention_policy { is_locked = true }` on evidence buckets in **both** targets; writer SA downgraded to `objectCreator` + `legacyBucketReader`.
3. Layer 1 outbound OIDC seam with the GCP adapter isolated under `src/integrations/` per Gate G3.
4. Remove the dead VPC Access Connector (B6).

### Phase B — Boundary hardening (strictly after A3)
Branch: `feat/cloud-run-phase-b-boundary`
5. Serverless NEG + external HTTPS LB + Cloud Armor, **then** `INTERNAL_LOAD_BALANCER` ingress for `gateway` in prod.
6. `INGRESS_TRAFFIC_INTERNAL_ONLY` on `governed_advisor`, `compliance_bridge`, `langfuse_web`, `langfuse_worker`, paired with `roles/run.invoker` bindings.

### Phase C — Cryptography and attestation
Branch: `feat/cloud-run-phase-c-crypto`
7. CMEK across Cloud Run templates, Cloud SQL (top-level `encryption_key_name`), GCS `default_kms_key_name`, Memorystore, plus service-agent KMS grants.
8. `google_binary_authorization_policy` with attestors; `breakglass_justification` prohibited in prod.

### Phase D — Restore missing posture
Branch: `feat/cloud-run-phase-d-workloads`
9. NeMo + Presidio multi-container service and a Cloud Run freshness-check analogue.
10. `lula_job`, `sbom_job`, `security_scan_job`, Cloud Scheduler triggers.
11. `reconciliation_daemon` with `min_instance_count = 1` and CPU always allocated.
12. POAM-019 `terraform_data` precondition on Langfuse key distinctness.

### Phase E — Compliance narratives
Branch: `docs/cloud-run-ssp-narratives`
13. SSP narratives per §8, written against shipped configuration only.

**Gate:** Do not begin Phase E and do not close any POAM item until [`tests/test_oscal_ssp_exporter.py`](../../tests/test_oscal_ssp_exporter.py) passes against the shipped configuration, per the [`AGENTS.md`](../../AGENTS.md) pre-closure verification rule.

---

## 10. Compliance Artifact Obligations

- **New POAM item — AU-9 WORM retention (cross-target).** Evidence buckets in `gcp-gke` and `gcp-cloudrun` rely on a lifecycle delete rule that imposes no minimum retention, and the writer service account holds delete permission. Remediation: locked `retention_policy` plus `objectCreator` downgrade. Closure date must be the actual calendar date of verification — never backdated.
- **POAM-019** telemetry isolation must be carried to the Cloud Run target.
- OSCAL component updates in `compliance/oscal/` within 2 business days of each phase merge that changes a NIST control.
- Lula validations in `compliance/lula/` updated as Cloud Run resources are added.

---

## 11. Deployment Orchestration & Tooling

### [MODIFY] [`deploy_all.sh`](../../deploy_all.sh)
```bash
Targets:
  agnostic     Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
  gcp-gke      Provision and deploy to Google Cloud GKE cluster
  gcp-cloudrun Deploy to Google Cloud Run (serverless, managed services)
```
Wire `gcp-cloudrun` into the Terraform plan/apply logic and pre-build pipeline. GKE image builds remain Cloud Build only per [`docs/operations/DEPLOYMENT_RULES.md`](../operations/DEPLOYMENT_RULES.md).

### [MODIFY] [`scripts/gen_tfvars.py`](../../scripts/gen_tfvars.py)
Support writing `infra/targets/gcp-cloudrun/terraform.auto.tfvars`.

### [NEW] [`scripts/test_live_cloudrun_services.py`](../../scripts/test_live_cloudrun_services.py)
Replaces `kubectl port-forward` diagnostics: resolve service URLs via `gcloud run services describe`, mint audience-scoped identity tokens, verify `/health` over authenticated HTTPS. Must assert URL scheme validity before any `urlopen` (Bandit B310).

---

## 12. Verification Plan

### Automated
```bash
uv run pytest tests/infrastructure/test_cloudrun_target.py -v
uv run pytest tests/test_lula_adapter.py -v
CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/infrastructure/test_data_residency.py -v -m eu_ecb
CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/infrastructure/test_data_residency_apac_mas.py -v -m apac_mas
uv run python scripts/check_import_boundaries.py --verbose
make test-fast
```

### [NEW] [`tests/infrastructure/test_cloudrun_target.py`](../../tests/infrastructure/test_cloudrun_target.py)
Beyond HCL syntax, residency, and secret hygiene, the suite must assert the fail-closed properties:
1. Evidence buckets declare `retention_policy` with `is_locked = true`.
2. No service account holds `roles/storage.objectAdmin` on an evidence bucket.
3. The OPA sidecar declares a bundle source; a bare `run --server` is rejected.
4. The gateway **denies** when OPA is unreachable.
5. No `google_vpc_access_connector` coexists with `network_interfaces`.
6. `INTERNAL_LOAD_BALANCER` ingress is only present when a backend service and serverless NEG also exist.
7. Multi-container port bindings: gateway 8080, OPA 8181, NeMo 8000, Presidio 5001/5002.

All tests carry `pytestmark = [pytest.mark.unit, pytest.mark.local]`.

### Manual
```bash
terraform -chdir=infra/targets/gcp-cloudrun init -backend=false
terraform -chdir=infra/targets/gcp-cloudrun validate
./deploy_all.sh --target gcp-cloudrun --help
```
