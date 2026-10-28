# GKE Evaluator Guide — What to Provision and What You Will See

> [!WARNING]
> **Status as of 2026-10-27: the GKE path has not been run end to end.** Nobody has
> run `deploy_all.sh --target gcp-gke` from a clean project at `origin/main`
> (`9d6cc922`), and the GEAP agent runtime path has not been exercised against a
> live gateway either. This guide comes from reading the Terraform, the scripts and
> the source at that commit. On 2026-10-27 we also looked, read-only, at one
> existing staging cluster (`cage-staging`, `us-central1-a`). That cluster runs images
> built from `4872e017` (2026-10-24), 21 commits behind `origin/main`. It is not a
> deployment of this commit, and looking at it is not an end-to-end run. Every
> statement in this guide is marked **VERIFIED** (we read the code or saw it in the
> live cluster) or **INFERRED** (reasoned from code, not seen running).

CAGE is a reference architecture, not a production service (see
[`AGENTS.md`](../../AGENTS.md)). This guide is for an evaluator who wants to
deploy it on Google Cloud. It covers what you must provision, roughly what it costs,
and how to tell a **designed refusal** from **breakage** once it is up.

## 1. Topology in one paragraph

CAGE itself (the gateway with `SymbolicGovernor`, OPA, NeMo Guardrails, the compliance
bridge, the reconciliation worker, Langfuse, ClickHouse and vLLM) runs **only on
GKE**, in namespace `governance-stack`
([`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)). The
**governed agent**, the Governed Financial Advisor, is not part of CAGE. It is
selected by `advisor_runtime` in
[`infra/targets/gcp-gke/variables.tf`](../../infra/targets/gcp-gke/variables.tf)
(default `"geap"`, line 1241, VERIFIED):

- `advisor_runtime = "geap"` (default): the agent runs on the GEAP Agent Runtime
  (Vertex AI Agent Engine `ReasoningEngine`), provisioned by
  [`infra/modules/gcp_geap_advisor/main.tf`](../../infra/modules/gcp_geap_advisor/main.tf)
  through [`scripts/deploy_geap_runtime.py`](../../scripts/deploy_geap_runtime.py).
  Its governed calls go to the GKE gateway through
  [`gateway_client.py`](../../src/governed_financial_advisor/infrastructure/gateway_client.py).
- `advisor_runtime = "gke"`: the agent runs as the in-cluster Deployment
  `governed-financial-advisor` under KSA `cage-advisor-sa`
  ([`infra/modules/governed_advisor/main.tf`](../../infra/modules/governed_advisor/main.tf)).

> [!IMPORTANT]
> Section 7 explains why the default `"geap"` mode cannot reach the gateway's gated
> routes at `9d6cc922`. Two things are missing: a network path, and ID-2 token
> validation. Until those are fixed, evaluate with `-var advisor_runtime=gke`. The
> existing staging cluster also runs the in-cluster advisor: its gateway has no
> `CAGE_TRUSTED_GEAP_AGENT_PRINCIPALS` variable (VERIFIED, 2026-10-27).

## 2. Which deployment documents to trust

| Document | Last changed | Use it for | Known stale parts |
|---|---|---|---|
| [`DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md) | 2026-10-25 | Policy: Cloud Build only, DNS zone lifecycle, Terraform rules | Says the GCS backend is "optional, configure in `providers.tf`"; that file has no `backend` block (VERIFIED) |
| [`GKE_TEST_RUNBOOK.md`](GKE_TEST_RUNBOOK.md) | 2026-10-22 | Live test commands, port-forwards, workload identity table | Written for `advisor_runtime = "gke"`; claims Valkey 8.0 and IAM+TLS on the app Memorystore; claims `vllm_replicas = 0` in staging (all contradicted, see section 6) |
| [`infra/QUICK_START.md`](../../infra/QUICK_START.md) | 2026-09-28 | Tool versions | API list too short; IAM role list too narrow; "~10 minutes" understates the time; no mention of GEAP |
| [`infra/DEPLOYMENT_GUIDE.md`](../../infra/DEPLOYMENT_GUIDE.md) | 2026-09-28 | Nothing on GKE | Describes MinIO, in-cluster Redis and a `minio_root_password` variable that does not exist in the GKE target (VERIFIED: none of its 147 variables has that name) |
| [`infra/targets/gcp-gke/README.md`](../../infra/targets/gcp-gke/README.md) | 2026-07-08 | Nothing current | Costs based on `e2-medium` and T4 GPUs; lists MinIO and Redis cache |
| [`deploy_all.sh`](../../deploy_all.sh) | 2026-10-01 | The actual entry point | Accepts `--env staging` but its `--help` lists only `dev` and `prod`; never applies the reconciliation worker (section 3) |

The README deployment-target table was deleted in #538 (`a3082bf9`, 2026-10-25,
VERIFIED). No `DEPLOYMENT_PROFILES.md` exists at `9d6cc922` or anywhere in git
history (VERIFIED with `git log --all`).

## 3. Prerequisites

Each row names the Terraform variable or manifest field that controls the item, and
says whether `deploy_all.sh --target gcp-gke` provisions it.

| Prerequisite | Variable / manifest field | Provisioned by `deploy_all.sh`? | Notes |
|---|---|---|---|
| GCP project in an **Organization** | `project_id`; `gcp_organization_id` (GEAP); `organization_id` (VPC-SC only) | No | `gcp_organization_id` defaults to the placeholder `"cage-sovereign"`, and no tfvars file overrides it (VERIFIED). Set it to your numeric org ID or the GEAP principal is wrong |
| Region and zone | `region`, `zone` (no defaults, DEP-08); `cage_deployment_region` | Taken from tfvars | GEAP is restricted to `us-central1`, `europe-west1`, `asia-southeast1` (DEP-10 precondition, VERIFIED) |
| APIs | Only `privateca.googleapis.com` is enabled by Terraform ([`service_mesh`](../../infra/modules/service_mesh/main.tf), VERIFIED) | **No** | Enable by hand: `container`, `compute`, `cloudkms`, `memorystore`, `sqladmin`, `servicenetworking`, `privateca`, `aiplatform` (GEAP), `cloudbuild`, `artifactregistry`, `containerregistry`, `containeranalysis`, `binaryauthorization`, `dns`, `iamcredentials`, `storage`, `containerfilesystem`. The QUICK_START list misses at least `memorystore`, `sqladmin`, `servicenetworking`, `aiplatform`, `binaryauthorization` and `dns` (VERIFIED against the live project's enabled list) |
| Deployer IAM | (operator) | No | Terraform creates service accounts, project and KMS IAM bindings, KMS keyrings and HSM keys, a CAS pool, Memorystore, Cloud SQL, a VPC and Binary Authorization policy. The four roles in QUICK_START are not enough. In practice you need `roles/owner`, or an equivalent set covering those resource types (INFERRED) |
| Cloud KMS signing keys | [`kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf); `kms_signing_protection_level` (default `"HSM"`; `dev.tfvars` and `us-dev.tfvars` set `"SOFTWARE"`) | Yes | Keyring `cage-signing-<env>`, keys `gateway-seal`, `reconciler-snapshot`, `compliance-evidence`, `benchmark-signing`, `binauthz-attestor` (VERIFIED on staging: all `EC_SIGN_P256_SHA256`, HSM). KMS keyrings cannot be deleted; key versions are destroyed only after a scheduled-destruction delay |
| CMEK | `enable_cmek`; keyring `cage-keyring-<env>` | Yes when `enable_cmek = true` | Off in `dev` |
| Memorystore with TLS (governance) | `enable_memorystore_tls` (default `true`), `enable_memorystore_iam_auth` (default `true`), `memorystore_governance_psc_cidr`, `memorystore_governance_instance_id` | Yes | `SERVER_AUTHENTICATION` + `IAM_AUTH`. The CA is pinned into the gateway and compliance bridge through `redis_ca_pem` (POAM-2026-086). Replicas: 0 in `dev`, 1 in `staging`, 2 in `prod` |
| Memorystore (app) | `memorystore_app_psc_cidr`, `memorystore_app_instance_id` | Yes | Hard-coded `AUTH_DISABLED` and `TRANSIT_ENCRYPTION_DISABLED` (main.tf lines 413–414, VERIFIED; same on live staging) |
| GroundTruthReconciler | [`deployment/k8s/reconciliation-worker.yaml`](../../deployment/k8s/reconciliation-worker.yaml) and its KSA in [`deployment/k8s/service-account.yaml`](../../deployment/k8s/service-account.yaml); secret `reconciliation-worker-secrets` (`reconciler-kms-key`, Redis URL) | **No** | No Terraform module deploys it ([`iam.tf`](../../infra/targets/gcp-gke/iam.tf) lines 320–321, VERIFIED). The manifest image is `${REGISTRY_URL}/compliance-bridge:latest`. The gateway runs with `RECONCILIATION_PROVIDER=simulated` (main.tf line 901) |
| Linkerd mTLS identity | [`service_mesh`](../../infra/modules/service_mesh/main.tf) (CAS `ENTERPRISE` pool `cage-mesh-<env>`); gateway `trusted_client_identities` → `CAGE_TRUSTED_CLIENT_IDENTITIES` = `cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local` | Yes | Only the in-cluster advisor's identity is trusted (main.tf lines 888–890) |
| GEAP principal | `trusted_geap_principals` → `CAGE_TRUSTED_GEAP_AGENT_PRINCIPALS` = `principal://agents.global.org-<gcp_organization_id>/governed-financial-advisor` | Set only when `advisor_runtime = "geap"` | See section 7 |
| DNS | `enable_cloud_dns` (default `false`), `dns_managed_zone_name`, `dns_domain_name` | Record set only | The zone is read through `data "google_dns_managed_zone"` and never created or destroyed by the stack ([`perimeter.tf`](../../infra/targets/gcp-gke/perimeter.tf) lines 319–344, VERIFIED). This matches the rule in [`DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md): create the zone, and any upstream NS delegation, as persistent foundational infrastructure before you set these |
| Terraform state | `providers.tf` | **No backend** | No `backend` block exists, so state is local to `infra/targets/gcp-gke/` (VERIFIED). `terraform init -backend-config=bucket=...` from QUICK_START has nothing to configure |
| Images | `image_digests` map; [`scripts/build_images.sh`](../../scripts/build_images.sh) | Yes (Cloud Build) | Images must be built by Cloud Build, not locally ([`DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md)) |
| Secrets in `.env` | `GOVERNANCE_SALT`, `LANGFUSE_*`, `KMS_GOVERNANCE_KEY` → `terraform.auto.tfvars` via [`scripts/gen_tfvars.py`](../../scripts/gen_tfvars.py) | Generated | Never commit `terraform.auto.tfvars` |
| GPU quota | `gpu_node_pool_machine_type = "g2-standard-8"`, `gpu_type = "nvidia-l4"`, `gpu_node_pool_max_count = 2` | Requested | You need L4 quota in the region, at least 2 GPUs (INFERRED) |

### Is an Argolis project required?

No. Nothing in the repository mentions Argolis, and no Terraform depends on it
(VERIFIED by reading every hit of an `argolis|altostrat|constraints/` search).
You do need a project that **belongs to an Organization**: the GEAP principal is
org-scoped (`agents.global.org-<id>`), and VPC-SC (`enable_vpc_sc`) needs an access
policy. The tfvars also assume the org policy `constraints/compute.vmExternalIpAccess`
may be enforced, which is why `enable_private_nodes = true` everywhere. The existing
staging project belongs to an organization and its DNS zones are under
`altostrat.com`, which suggests an Argolis-style environment (INFERRED). That is a
fact about one project, not a requirement.

## 4. Cost estimate (INFERRED)

These figures are approximate `us-central1` on-demand list prices applied to the
`staging.tfvars` / `dev.tfvars` and `prod.tfvars` sizing. Check them with the Google
Cloud pricing calculator before you rely on them.

| Component (staging/dev sizing) | Basis | Approx. monthly if left running |
|---|---|---|
| GKE zonal cluster fee | 1 cluster (the free-tier credit may offset it) | ~$0–75 |
| `general` pool | 1× `e2-standard-4` (`primary_node_pool_min_count = 1`) | ~$100 |
| `gpu-l4` pool | 2× `g2-standard-8` + L4 (`vllm_replicas = 1` for each of 2 vLLM deployments) | ~$1,200–1,300 while up; $0 when scaled to zero |
| `clickhouse` pool | 1× `n2-standard-4` + local SSD | ~$170 |
| Memorystore for Valkey | 3 `SHARED_CORE_NANO` nodes (governance primary + 1 replica, app primary) | ~$50–100 |
| Cloud SQL | `db-g1-small` (staging) / `db-f1-micro` (dev) | ~$10–30 |
| CAS | 1 `ENTERPRISE` CA pool and CA | ~$200 |
| KMS HSM keys, NAT, LB, Cloud Armor, GCS, logging | — | ~$50–100 |
| GEAP Agent Runtime | `min_instances = 1`, 4 vCPU / 8 GiB always warm | ~$300–400 |
| **Total, GPUs scaled to zero** | | **~$900–1,200 / month** |
| **Total, GPUs up** | | **~$2,100–2,500 / month** |

`prod.tfvars` (3× `e2-standard-8`, 2–5 GPU nodes always on, 3 ClickHouse nodes,
regional cluster, `HIGHMEM_MEDIUM` Memorystore, regional Cloud SQL) is several times
higher. The "$2–4 per validation cycle" figure in
[`DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md) assumes provision → test → destroy
within 30 minutes. Three things make that unlikely: provisioning alone takes longer
(Memorystore, Cloud SQL, GKE and the CAS CA each take minutes), HSM key versions keep
billing until their scheduled destruction, and a CAS CA has a deletion grace period
(INFERRED).

## 5. Deploy (unchanged entry point)

```bash
# Pick advisor_runtime=gke until the GEAP gaps in section 7 are closed.
./deploy_all.sh --target gcp-gke --env staging --var advisor_runtime=gke
# Then, by hand, the reconciler (not applied by deploy_all.sh):
kubectl apply -f deployment/k8s/service-account.yaml
kubectl apply -f deployment/k8s/reconciliation-worker.yaml   # after creating reconciliation-worker-secrets
```

`deploy_all.sh` runs `terraform plan` before `apply`, then builds the images with
Cloud Build before applying (VERIFIED, lines 440–484).

## 6. What you should expect to see on GKE

Use this table to sort what you observe. **Correct?** means CAGE is doing what it was
designed to do (a refusal that fails closed). **Defect** means something is broken or
unfinished. Every refusal surfaces either as a `DENY` / `DEFER` / `REQUIRE_APPROVAL`
verdict with a `violations[].code`, or as an HTTP status.

| # | Symptom | Cause | POA&M | Correct? | How to confirm |
|---|---|---|---|---|---|
| 1 | **Every** `execute_trade` is denied, even a small benign one; `opa_results: ALLOW` but `violations: [{tier: "causal", code: "CAUSAL_TELEMETRY_UNAVAILABLE", kind: "hard"}]` | Enforcing postures (`staging`, `prod`) refuse synthetic causal telemetry, and no live source produces the causal columns (`market_volatility` is a constant stub; nothing records a `risk_score` outcome) | [POAM-2026-094](../POAM.md) (see also closed POAM-2026-088) | **Designed fail-closed refusal.** The missing data source is the open gap | **VERIFIED live:** gateway logs on `cage-staging`, 2026-10-22T16:05:32Z, show exactly this verdict. Run `gcloud logging read 'resource.labels.container_name="gateway" AND "CAUSAL_TELEMETRY_UNAVAILABLE"'`. With 1–49 live rows the code becomes `CAUSAL_INSUFFICIENT_SAMPLES` (INFERRED from POAM text; not seen live) |
| 2 | In `--env dev` the causal tier allows trades that a $9,144 boundary should refuse, and evidence records the causal stage as `PASS` | The marginal risk boundary divided by the normalization scale twice, and the placebo refuter always passed | [POAM-2026-114](../POAM.md) | **Defect.** Fixed on `main` (`d5354eb8`, #550), but images built before that commit, such as `4872e017` on `cage-staging`, still behave this way | Compare the gateway image tag with `git merge-base --is-ancestor d5354eb8 <tag>` |
| 3 | Trades above $10,000 return `REQUIRE_APPROVAL` / `DEFER` with `classification_reason: hitl_required` | FTRA human-in-the-loop threshold | — | **Designed** | **VERIFIED live:** `[defer_queue] Parked deferral ... reason=HITL_REQUIRED` at 2026-10-22T17:05:15Z |
| 4 | `403 {"detail": "Forbidden: caller workload identity is not authorized for this route."}` and gateway log `INGRESS_IDENTITY_REFUSED path=... identity=<0 headers>` when you `curl` gated routes through `kubectl port-forward` | `WorkloadIdentityMiddleware` admits only the Linkerd identity of `cage-advisor-sa`; a port-forward carries no `l5d-client-id` | POAM-2026-080 (closed) | **Designed.** Use the advisor endpoint or the open routes (`/health`, `/healthz`, `/metrics`, JWKS) | **VERIFIED live:** three such lines on 2026-10-25 for `/tools/execute`, `/governance/validate-action` and `/inference/v1/chat/completions` |
| 5 | Every gated call from a **GEAP-hosted** agent gets the same 403 | See section 7: no network path, no `AGW_OIDC_ISSUER`, no JWKS and no `l5d-client-id` for off-mesh callers | Not tracked (the string "GEAP" does not occur in [`POAM.md`](../POAM.md)) | **Defect** | Code reading (VERIFIED); not observed live |
| 6 | Gateway `0/1` Ready, `start_evidence_sink()` fails with `SSLCertVerificationError` | Memorystore server CA not mounted | [POAM-2026-086](../POAM.md) | **Defect**, remediated in IaC (`redis_ca_pem` → `gateway-redis-ca` ConfigMap). Closure waits on PR-4 (`fix/redis-tls-one-rule`) and a live Lula SC-8 run | `kubectl get cm gateway-redis-ca -n governance-stack`; the live deployment mounts it at `/etc/cage/tls/redis` (VERIFIED). No `SSLCertVerificationError` in 14 days of gateway logs (VERIFIED) |
| 7 | **All** meshed pods, including `linkerd-destination`, `linkerd-identity` and `linkerd-proxy-injector`, sit in `Init:CrashLoopBackOff`; `linkerd-network-validator` exits 95 with `Failed to validate networking configuration` | After a GKE node auto-upgrade the Linkerd CNI redirect does not work on the new node | Not tracked | **Defect (platform/operations)**. Nothing in CAGE refused anything | **VERIFIED live 2026-10-27:** `primary-node-pool` auto-upgraded at 05:11–05:17Z to `1.35.8-gke.1796000`; since then 118+ restarts of every meshed pod and the last gateway log line is at 05:13:31Z. Root cause (CNI chaining under Dataplane V2) is INFERRED. Check with `kubectl logs <pod> -c linkerd-network-validator` and `gcloud container operations list` |
| 8 | `CAGE_DOMAIN=physical_ai` refuses to start; any physical action is denied with `KINEMATIC_BARRIER_UNCONFIGURED` | No FTRA registry or cost resolver for physical AI | [POAM-2026-076](../POAM.md), POAM-2026-077, POAM-2026-078 | **Designed fail-closed** for an unfinished domain. Finance and healthcare run | Not observed live (the GKE target sets `cage_domain = "finance"`) |
| 9 | No in-cluster vulnerability-scan CronJob | Not built | [POAM-2026-010](../POAM.md) | **Defect** (missing control) | **VERIFIED live:** `kubectl get cronjob -n governance-stack` lists none |
| 10 | No `token-quota-proxy` Deployment; token quotas are enforced inside the gateway | Not split out | [POAM-2026-026](../POAM.md) | **Known gap, behaviour correct.** Quotas still apply | **VERIFIED live:** no such Deployment in `governance-stack` |
| 11 | Images that are not attested are admitted on staging | `binary_authorization_enforcement_mode = "DRYRUN_AUDIT_LOG_ONLY"` in `staging.tfvars`; the reconciler manifest uses `:latest` | [POAM-2026-083](../POAM.md) | **By configuration** on staging (audit only); enforced in `prod.tfvars` | Read `staging.tfvars` (VERIFIED) |
| 12 | Evidence attestations missing or unsigned in the WORM bucket | Live verification of signed custody is pending | [POAM-2026-084](../POAM.md) | **Open.** Fails closed when enforcing | `GET /v1/evidence/verify` on the compliance bridge (INFERRED path from POAM text) |
| 13 | Partner actuation receipts recorded as `UNVERIFIED` | Partner has not adopted the signed-receipt format | [POAM-2026-098](../POAM.md) | **Designed:** resolution status is not verification status | — |
| 14 | `EU_ECB`: FRIA-related refusals or self-asserted provider_01 facts | FRIA tier pending merge; provider facts self-asserted | [POAM-2026-099](../POAM.md), [POAM-2026-113](../POAM.md) | 099: remediation pending merge; 113: **defect** | Only with `cage_deployment_region = "EU_ECB"` |
| 15 | CBRN content rail behaves as a stub | Awaiting AO pre-approval | [POAM-2026-025](../POAM.md) | **Known gap** | — |
| 16 | `ImagePullBackOff`, or OOM while vLLM loads weights | Images not built by Cloud Build, or GPU node too small | — | **Deployment error** | [`DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md) |
| 17 | vLLM-backed tests skip with "GPU pod likely Pending" | GPU pool scaled to zero | — | **Designed** cost behaviour | `bash scripts/dev_gpu_toggle.sh status` |
| 18 | `execute_trade_bounded` gets real `ALLOW` / `DENY` decisions while `execute_trade` is always denied | The causal tier claims only `execute_trade` (`CausalTierPlugin.claims_action`, [`causal_tier.py`](../../src/cage_finance/tiers/causal_tier.py) lines 171–172). `execute_trade_bounded` is governed by bounding, CBF, fiscal limits and OPA ([`src/cage_finance/__init__.py`](../../src/cage_finance/__init__.py) lines 69–70) | — | **Designed.** But bounding uses `StubMarketDataProvider`, which returns constant permissive market data, so only the CBF, fiscal, OPA and allowlist (instrument, venue, counterparty) checks really discriminate | Code reading (VERIFIED). We found no `execute_trade_bounded` line in 14 days of `cage-staging` gateway logs (VERIFIED), so this has not been observed live |
| 19 | With `--env prod` the gateway fails while assembling the governor: `StubMarketDataProvider cannot be used when CAGE_ENV=production` | `environment = "prod"` sets `CAGE_ENV=prod` on the gateway (main.tf line 866 → [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) line 353). `FinanceCagePlugin.contribute()` builds `StubMarketDataProvider()` ([`plugin.py`](../../src/cage_finance/plugin.py) line 121), which raises for `prod` / `production` ([`providers.py`](../../src/cage_finance/safety/bounding/providers.py) lines 163–166) | Not tracked | **Designed fail-closed** for a stub, but it means the finance domain **cannot start in the prod posture** until a real market-data provider exists | Code reading (VERIFIED); startup not observed |

### Seeing real discrimination despite row 1

Row 1 denies every `execute_trade`, so on its own it tells you nothing about whether
the other tiers work. To see the pipeline make real decisions in `staging`:

1. Send `execute_trade_bounded` instead. The causal tier does not claim it, so the
   decision comes from CBF (cash barrier against the reconciled ledger), fiscal
   limits, OPA (`trade_policy.rego`) and the bounding allowlists.
2. Vary one thing at a time:
   - amount against `safety:current_cash` (CBF);
   - instrument outside `AAPL` / `MSFT` / `GOOGL` / `AMZN` (bounding allowlist);
   - amount above the OPA ceiling.
3. Expect market-volatility-based bounding never to refuse: the stub returns
   constants (row 18).
4. Do not run this in `--env prod`, because of row 19.

`StubMarketDataProvider.__init__` reads raw `CAGE_ENV` with default `"dev"`, while
`resolve_posture()` defaults to production. With `CAGE_ENV` unset, the posture is
therefore enforcing but the stub is still allowed (VERIFIED by code reading).

**Rule of thumb:** a response with a `violations[].code` and an evidence record is a
governance decision, so look it up in rows 1–4, 8 and 18. A pod that is not Ready, a
TLS error, a startup failure or a 403 from an agent that should be trusted is
breakage, so look at rows
5–7, 16 and 19.

## 7. GEAP agent runtime (`advisor_runtime = "geap"`)

### 7.1 What must be provisioned

| Item | Where | Status at `9d6cc922` |
|---|---|---|
| `aiplatform.googleapis.com` | Manual | Not enabled by Terraform (VERIFIED) |
| Reasoning engine | `terraform_data.geap_reasoning_engine` → `local-exec` → [`scripts/deploy_geap_runtime.py`](../../scripts/deploy_geap_runtime.py) (REST `v1beta1 .../reasoningEngines`, uses `gcloud auth print-access-token`) | The source is uploaded as an **inline archive** built from your local working tree (`config/`, `src/governed_financial_advisor`, `src/gateway`, `src/integrations`, `src/cage_finance`, 8 MB limit). The `image` digest input is **not** used (VERIFIED) |
| Staging bucket | — | Not needed: the deployer uses `inlineSource`, not a GCS staging bucket (VERIFIED) |
| Agent identity | `identityType: AGENT_IDENTITY`; principal `principal://agents.global.org-${gcp_organization_id}/governed-financial-advisor` | `gcp_organization_id` defaults to `"cage-sovereign"`, which is not an org ID (VERIFIED) |
| Gateway trust | `CAGE_TRUSTED_GEAP_AGENT_PRINCIPALS` on the gateway; `AGW_OIDC_ISSUER`, `AGW_OIDC_AUDIENCE` (default `cage-gateway`) read by [`agw_adapter.py`](../../src/gateway/governance/ingress/agw_adapter.py) | `AGW_OIDC_ISSUER` is set by **no** Terraform or manifest file (VERIFIED by `git grep` over `*.tf`, `*.yaml`, `*.tfvars`) |
| ID-2 token on the agent | `CAGE_GEAP_ID2_OIDC_TOKEN`, read by `GatewayClient._build_headers` | Set only in a unit test; no runtime code or IaC mints it (VERIFIED) |
| ID-1 end-user token | `CAGE_USER_OIDC_ISSUER`, `CAGE_USER_OIDC_JWKS_JSON` / `CAGE_USER_OIDC_TRUST_ANCHORS_FILE` ([`auth.py`](../../src/governed_financial_advisor/infrastructure/auth.py)) | Not in `runtime_env_vars`. In enforcing postures the agent raises `Verified end-user principal required` unless a token verifies (VERIFIED in `geap_app.py`; outcome not observed live) |
| Network path to the gateway | Module inputs `vpc_network`, `vpc_subnetwork`, `psc_network_attachment` (default `""`), `dns_peering_configs` (default `[]`) | **Not sent to the API.** `build_reasoning_engine_payload()` builds no `pscInterfaceConfig`, no VPC egress and no `encryptionSpec` (VERIFIED). The `vpc_egress_setting = "ALL_TRAFFIC"` output exists only in Terraform state. `GATEWAY_URL` is `http://gateway.governance-stack.svc.cluster.local:8080`, a cluster-internal name |
| CMEK | `kms_key_name` | Not sent (VERIFIED) |

**Live check (VERIFIED, 2026-10-27, read-only REST `GET`):** the project that hosts
`cage-staging` has one `ReasoningEngine`, display name
`governed-financial-advisor`, created 2026-10-13 and last updated 2026-10-14. Its spec
is `identityType = AGENT_IDENTITY` and `agentFramework = custom`, with **no PSC
interface config and no encryption spec**. That matches the payload builder.

### 7.2 What the evaluator will observe

The agent holds no governance state. It forwards every governed call (trade
validation and execution, content-safety checks, deferral, post-HITL revalidation) to
the GKE gateway, so **every refusal in section 6 reaches the user through the agent**.
At `9d6cc922`, however, the GEAP agent is expected to fail before it reaches any
governance tier:

1. **No route (INFERRED).** Without a PSC interface and DNS peering, the Agent
   Engine container cannot resolve or reach `gateway.governance-stack.svc.cluster.local`.
   Expect connection or DNS errors in the agent, not governance verdicts.
2. **403 at ingress even with a route (VERIFIED by code reading).**
   `WorkloadIdentityMiddleware.__call__` requires a trusted `l5d-client-id`. An
   off-mesh caller cannot present one, because the Linkerd inbound proxy sets that
   header only for meshed mTLS clients (INFERRED from Linkerd behaviour). When `trusted_geap_principals` is non-empty, the middleware **also** requires
   `_verify_geap_id2_principal()`. That calls `AgwAdapter.validate_oidc_token(token)`
   with no key resolver on an adapter built with no JWKS cache, and it returns `False`
   whenever `AGW_OIDC_ISSUER` is unset or no key is configured. Every gated call
   therefore returns 403 `INGRESS_IDENTITY_REFUSED`. This is a **defect**, not a
   designed refusal: no configuration at this commit can satisfy the check.
3. **ID-1 refusal (VERIFIED by code reading).** In `staging`/`prod` a query without a
   verifiable end-user OIDC token fails with `Verified end-user principal required`.
   That part is designed, but no issuer or JWKS is configured, so it cannot succeed
   either.
4. **App Memorystore.** `REDIS_URL=redis://<psc-ip>:6379` points at the app instance
   with TLS and auth disabled. Like the gateway, it is reachable only on the VPC
   (INFERRED).

### 7.3 Applicable POA&Ms and documents

- POAM-2026-079 (closed): zero signing authority. `validate_runtime_env_vars()` and
  `assert_no_signing_identity()` refuse signing-key variables (VERIFIED in code).
- POAM-2026-080 (closed): two-layer ingress. The GEAP half of that design is the
  defect in 7.2 (2).
- All the governance refusals in section 6 (094, 114, HITL) apply unchanged once
  connectivity and identity work.
- [`GEAP_INTEGRATION_ARCHITECTURE.md`](../architecture/GEAP_INTEGRATION_ARCHITECTURE.md)
  §4.6 item 3 says the module "enforces `vpc_egress_setting = "ALL_TRAFFIC"` … regional
  CMEK". The deployer does not send either (see 7.1). §4.6 item 4 cites an
  `enable_gvisor_sandbox` variable that the GKE target does not declare (VERIFIED).

## 8. Read-only checks you can run on any deployment

```bash
gcloud config list && kubectl config current-context
kubectl get pods -n governance-stack -o wide        # expect 2/2 (3/3 for langfuse) Ready
kubectl get pods -n linkerd                          # control plane must be Running
kubectl get deploy gateway -n governance-stack \
  -o jsonpath='{.spec.template.spec.containers[0].image}'   # compare with the commit you evaluate
gcloud container images list-tags gcr.io/<project>/gateway --filter="digest=<sha256:...>"
gcloud logging read 'resource.labels.container_name="gateway" AND "violations"' --freshness=1d --limit=20
```

Do not read secret values (`kubectl get secret -o yaml`). Listing secret names is
enough to check that a secret exists.
