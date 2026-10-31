# CAGE Deployment Rules & Best Practices

> **Reference architecture only.** CAGE demonstrates governance patterns for AI systems;
> it is not deployed to production. The deployment rules below are **illustrative**
> patterns for adopters.

> **Critical Policy:** This document defines mandatory deployment rules that all
> contributors (human and AI agent) must follow. The canonical source for the
> summary of these rules is [`AGENTS.md`](../../AGENTS.md) §Deployment Rules.

---

## 🚨 GKE Deployment Policy — Cloud Build Mandatory

**When deploying to Google Kubernetes Engine (GKE), you MUST use Cloud Build.
Local `docker build` is prohibited for GKE-targeted images.**

### Why This Matters

| Issue | Local Docker Build | Cloud Build |
|-------|-------------------|-------------|
| **Platform consistency** | ❌ May produce ARM64 on M-series Macs; GKE nodes run AMD64 | ✅ Always AMD64 |
| **Build reproducibility** | ❌ Depends on local environment | ✅ Controlled environment |
| **Security scanning** | ❌ Manual/optional | ✅ Integrated via Cloud Logging |
| **Audit trail** | ❌ No automated logs | ✅ Full build provenance in GCP |
| **Team collaboration** | ❌ "Works on my machine" | ✅ Consistent across developers |

---

## 🌐 DNS & Custom Domain Lifecycle Separation (Architecture Invariant)

When provisioning custom domains and external load balancers across any deployment target:

- **Decoupled Zone Lifecycle**: DNS managed zones must be treated as foundational, persistent infrastructure managed independently from ephemeral application stacks. Never provision or destroy the parent managed zone within ephemeral application lifecycles.
- **Subdomain Takeover Prevention**: Deleting a managed zone while upstream parent delegations exist creates an orphaned zone vulnerability. Workload Terraform modules must only manage record sets (`A` / `AAAA` records), leaving the parent zone intact during teardown.
- **Sandbox & Staging Environments**: When deploying to managed cloud sandbox environments, configure upstream NS delegation against a persistent Cloud DNS managed zone before provisioning ingress certificates.

---

## Deployment Entry Point

All deployments are driven by [`deploy_all.sh`](../../deploy_all.sh) at the
repository root. Direct use of `terraform apply` or `gcloud builds submit` is
supported for advanced scenarios but `deploy_all.sh` is the approved entry point
for end-to-end deployment.

### ✅ Approved Methods for GKE

```bash
# Full deployment to GKE staging (the maintained GKE profile)
./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID> --auto-approve

# Full deployment to GKE staging (background — survives terminal closure)
make deploy-bg TARGET=gcp-gke ENV=staging EXTRA_ARGS="--var project_id=<PROJECT_ID> --auto-approve"

# Direct Cloud Build submit (single service via generic template + dedicated SA)
gcloud builds submit \
  --config deployment/docker/cloudbuild.image.yaml \
  --service-account="projects/<PROJECT_ID>/serviceAccounts/cage-cloudbuild-staging@<PROJECT_ID>.iam.gserviceaccount.com" \
  --substitutions="_IMAGE_NAME=gateway,_DOCKERFILE=src/gateway/Dockerfile,_SHORT_SHA=$(git rev-parse --short HEAD)" .
```

### ✅ Approved Methods for Local / Agnostic

```bash
# Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
./deploy_all.sh --target agnostic --env dev
```

### ❌ Prohibited for GKE

```bash
# NEVER — architecture mismatch crashes GKE pods
docker build -t gcr.io/PROJECT/image:tag .
docker push gcr.io/PROJECT/image:tag
kubectl apply -f deployment.yaml   # without a preceding Cloud Build step

# NEVER
docker-compose build && docker-compose push
--platform linux/amd64   # local/BuildKit cross-compilation
```

---

## `deploy_all.sh` Options

```
Usage: ./deploy_all.sh --target TARGET --env ENV [OPTIONS]

Targets:
  agnostic     Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
  gcp-gke      Provision and deploy to Google Cloud GKE cluster

Environments:
  dev          Development (fast iteration, reduced security posture)
  prod         Production (ISO 42001 baseline hardening; jurisdiction-specific
               posture controlled by CAGE_DEPLOYMENT_REGION)

Options:
  --auto-approve          Skip Terraform confirmation prompts
  --var-file=PATH         Additional .tfvars file (e.g. prod.tfvars)
  --skip-build            Skip container image builds (Cloud Build step)
  --kubeconfig=PATH       Kubeconfig path (agnostic target only)
  --var KEY=VALUE         Override any Terraform variable
```

### `staging` environment

**Status**: Provisioned (POAM-024 closed 2026-08-29)

The `staging` environment is an ephemeral pre-production validation tier that
proves full security posture at dev-scale cost:

- **Purpose**: Validate all Lula gates, region postures, and cluster-scoped
  controls (Binary Authorization, PSS, CMEK, audit logs) at 1-replica scale
  before promoting to production.
- **Cost**: ~$2-4 per validation cycle (20-30 minutes runtime, sub-hour usage).
- **Lifecycle**: Provision → Validate → Destroy (automated via `scripts/staging_lifecycle.sh`).
- **Hardware**: Dev-scale (e2-standard-4 nodes, pd-standard disks, GPU scale-to-zero).
- **Security**: Full prod posture (enable_nist_compliance=true for US_FED,
  Binary Authorization, audit logging, CMEK, PSS restricted, scoped authorized_networks).
- **HA**: Decoupled (`enable_high_availability=false`, 1 replica per service).
- **Deletion protection**: Disabled (`enable_deletion_protection=false`, allows teardown).

**Deployment** (project from `GOOGLE_CLOUD_PROJECT` in `.env`, or `--var project_id=<PROJECT_ID>`):
```bash
# Automated lifecycle (recommended)
./scripts/staging_lifecycle.sh

# Manual deployment: builds the images staging deploys, renders their digests, then plans
./deploy_all.sh --target gcp-gke --env staging --auto-approve

# Manual teardown: the same inputs as the plan, including the rendered digests file
cd infra/targets/gcp-gke
terraform destroy -var-file=staging.tfvars \
  -var-file=image_digests.<short_sha>.tfvars.json -var project_id=<PROJECT_ID> -auto-approve
```

See [`infra/targets/gcp-gke/staging.tfvars`](../../infra/targets/gcp-gke/staging.tfvars)
for full configuration and [`scripts/staging_lifecycle.sh`](../../scripts/staging_lifecycle.sh)
for automated validation workflow.

#### Langfuse event bucket retention (POAM-2026-159)

The Langfuse event-upload bucket and the evidence WORM bucket take their retention
lock from one pair of locals in [`main.tf`](../../infra/targets/gcp-gke/main.tf),
`local.retention_period_seconds` and `local.retention_locked`, which the tier
(`environment`) selects:

| Tier | Retention period | Locked |
|---|---|---|
| `dev` (the variable default) | 220752000 s (2555 days) | Only while a compliance flag is set (`eu-dev`, `apac-dev`) |
| `staging` | 86400 s (1 day) | Always |
| `prod` | 220752000 s (2555 days) | Always |

Only the exact tier `staging` gets the short period.
[`retention_posture.tftest.hcl`](../../infra/targets/gcp-gke/tests/retention_posture.tftest.hcl)
plans every committed profile from its file and holds each prod profile to 2555
days. Locking a policy places a Cloud Storage lien on the project, and no object
in either bucket can be deleted before it is a day old.

**One-time migration for a staging project applied before this change.** Its
Langfuse bucket is `google_storage_bucket.langfuse_events`
(`langfuse-events-<project>-<suffix>`), locked at 220752000 s whenever a
compliance flag was set, which `deploy_all.sh` does for US_FED staging. GCS
refuses to shorten a locked retention period, so that bucket can never take the
one-day lock. On the live staging project it was locked on 2026-09-29 and holds
35,639 objects (read-only check, 2026-10-30): **the old bucket and the project's
storage lien stay until at least 2033-09-27**, the lock date plus 2555 days, and
the bucket stays longer if anything was written to it after the lock.

1. Before any teardown, plan and apply once with Terraform 1.7 or later, without
   `--auto-approve` so that `deploy_all.sh` stops for review after the plan:
   `./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID>`.
   The plan shows
   `google_storage_bucket.langfuse_events will no longer be managed by Terraform,
   but will not be destroyed`; a new
   `google_storage_bucket.langfuse_event_upload`
   (`langfuse-event-upload-<project>-<suffix>`, 86400 s, locked); the three
   `google_storage_bucket_iam_member.langfuse_gcs_*` bindings replaced on the new
   bucket; and the Langfuse deployments and application secret updated to the new
   name. If it shows the old bucket destroyed or replaced, do not apply it.
2. Record the old bucket outside Terraform, which no longer tracks it:
   `gcloud storage buckets describe gs://langfuse-events-<project>-<suffix> --format="value(retention_policy)"`.
   Langfuse stops writing to it, and its lifecycle rule moves its objects to the
   ARCHIVE storage class after 365 days.

A destroy plan ignores the `removed` block (verified on Terraform 1.15.8): run
before step 1, it would try to delete the old bucket. The provider refuses to
delete a locked bucket whose objects are still under retention, so no data would
be lost, but the destroy would fail. After step 1, Terraform no longer knows the
old bucket and cannot try to destroy it.

The same apply moves every other deployment made before this change to a new
`langfuse-event-upload-*` bucket and leaves the old one in place. A prod
project's old bucket keeps its events under its 2555-day lock. A `dev` project's
old bucket is unlocked unless a compliance flag was set (`eu-dev`, `apac-dev`),
and can be removed by hand: `gcloud storage buckets update gs://<old-bucket> --clear-retention-period`,
then `gcloud storage rm --recursive gs://<old-bucket>`.

**What a full staging teardown still meets.** A walk project created after this
change needs no migration, and objects in both buckets become deletable a day
after they are written. `terraform destroy -var-file=staging.tfvars` still does
not complete, for reasons this change leaves alone:

- The five signing keys in [`kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf)
  set `prevent_destroy = true`, so Terraform rejects any destroy plan that
  includes them.
- In staging, neither retention-locked bucket sets `force_destroy`, so the
  provider refuses to delete either one while it holds objects; the WORM bucket
  also keeps noncurrent versions. Once the lock has expired, empty both first:
  `gcloud storage rm --all-versions "gs://<bucket>/**"`.
- Google documents removing a project lien as a step for a project owner or an
  organization administrator (`gcloud alpha resource-manager liens list`, then
  `gcloud alpha resource-manager liens delete`). Check for the lien once the
  buckets are gone.

---

## Deployment Target Matrix

> **Jurisdiction prerequisite:** Set `CAGE_DEPLOYMENT_REGION` in `.env` (or as
> an environment variable) before running any `prod` deployment. The script
> propagates it to `TF_VAR_cage_deployment_region`. The `--env prod` flag
> activates ISO 42001 baseline hardening; NIST SP 800-53 hardening
> (`enable_nist_compliance`) is additionally activated only for `US_FED`.

| `CAGE_DEPLOYMENT_REGION` | `--var-file` | GCP region |
|--------------------------|-------------|------------|
| `US_FED` | `infra/targets/gcp-gke/prod.tfvars` | `us-central1` |
| `EU_ECB` | `infra/targets/gcp-gke/eu-prod.tfvars` | `europe-west1` |
| `APAC_MAS` | `infra/targets/gcp-gke/apac-prod.tfvars` | `asia-southeast1` |

| Target | Env | Jurisdiction | Command |
|--------|-----|-------------|---------|
| `gcp-gke` | `prod` | US_FED | `CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/prod.tfvars` |
| `gcp-gke` | `prod` | EU_ECB | `CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/eu-prod.tfvars` |
| `gcp-gke` | `prod` | APAC_MAS | `CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/apac-prod.tfvars` |
| `gcp-gke` | `staging` | Any | `CAGE_DEPLOYMENT_REGION=<REGION> ./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID> --auto-approve` |
| `agnostic` | `dev` | Any | `./deploy_all.sh --target agnostic --env dev` |

---

## Cloud Build Configuration Files & Attestation Contract

All Cloud Build configs live under `deployment/docker/`.
[`scripts/build_images.sh`](../../scripts/build_images.sh) submits [`deployment/docker/cloudbuild.image.yaml`](../../deployment/docker/cloudbuild.image.yaml) in parallel across `name|dockerfile` pairs (`governed-financial-advisor`, `gateway`, `agentsight-ui`, `compliance-bridge`, `nemo-guardrails`) plus [`deployment/docker/cloudbuild.vllm.yaml`](../../deployment/docker/cloudbuild.vllm.yaml) (`E2_HIGHCPU_32`, 40-minute timeout) under the dedicated least-privilege service account `cage-cloudbuild-<env>@<PROJECT_ID>.iam.gserviceaccount.com` ([`infra/targets/gcp-gke/iam.tf`](../../infra/targets/gcp-gke/iam.tf)).

| Config / Script | Scope | Required Substitutions / Args |
|---------|------------|---------------|
| [`deployment/docker/cloudbuild.image.yaml`](../../deployment/docker/cloudbuild.image.yaml) | Generic build → push → attest template (`gateway`, `governed-financial-advisor`, `compliance-bridge`, `nemo-guardrails`, `agentsight-ui`, `cage-opa`) | `_IMAGE_NAME`, `_DOCKERFILE`, `_SHORT_SHA` (optional: `_ENVIRONMENT=staging`, `_KMS_LOCATION=us-central1`, `_KMS_KEY_VERSION=1`) |
| [`deployment/docker/cloudbuild.vllm.yaml`](../../deployment/docker/cloudbuild.vllm.yaml) | vLLM streamer (`E2_HIGHCPU_32`, `2400s` timeout) | `_SHORT_SHA` (optional: `_ENVIRONMENT`, `_KMS_LOCATION`, `_KMS_KEY_VERSION`) |
| [`deployment/docker/cloudbuild.lula.yaml`](../../deployment/docker/cloudbuild.lula.yaml) | Lula validation runner (`0.9.5`) | Optional: `_ENVIRONMENT`, `_KMS_LOCATION`, `_KMS_KEY_VERSION` |
| [`scripts/attest_image.sh`](../../scripts/attest_image.sh) | Canonical Binary Authorization attestation step | `<image:tag> [environment] [kms_location] [kms_key_version]` (`PROJECT_ID` env); runs `gcloud beta container binauthz attestations sign-and-create` and fails closed if `binauthz attestations list` returns no occurrence |
| [`scripts/render_image_digests.sh`](../../scripts/render_image_digests.sh) | Resolves each image built for a git SHA (and each mirrored third-party image) to its `@sha256:` digest and writes the `image_digests` var file Terraform reads. No fallback to another build's image: an image not built for that SHA is left out and named, and the plan refuses a map missing an image the profile deploys | `[--output PATH\|-] [short_sha]` (`PROJECT_ID` env); default output `infra/targets/gcp-gke/image_digests.<short_sha>.tfvars.json` (gitignored) |

`scripts/build_images.sh` builds and attests, in parallel via Cloud Build, the images named in `IMAGES` (default: all six). `deploy_all.sh` passes the images the profile deploys, so staging under `inference_backend = "none"` builds no vLLM, advisor or NeMo image:
1. `governed-financial-advisor` (root `Dockerfile`; both the `geap` and `gke` advisor runtimes consume it)
2. `gateway` (`src/gateway/Dockerfile`)
3. `agentsight-ui` (`src/agentsight-ui/Dockerfile`)
4. `compliance-bridge` (`src/compliance_bridge/Dockerfile`)
5. `nemo-guardrails` (`deployment/docker/Dockerfile.nemo`)
6. `vllm-streamer` (`deployment/docker/cloudbuild.vllm.yaml`)

All images are tagged strictly with immutable `:<short-sha>` tags (never `:latest` or fallback `"v1"`), pushed to `gcr.io/<PROJECT_ID>/<image-name>`, and attested via [`scripts/attest_image.sh`](../../scripts/attest_image.sh). No digest, registry path or project ID is committed (POAM-2026-131): a digest names an image in one registry, so `deploy_all.sh` builds, then renders the digests with [`scripts/render_image_digests.sh`](../../scripts/render_image_digests.sh), and only then plans. The saved plan pins exactly what was built. `var.image_digests` has no default, so a plan without the rendered file stops with `No value for required variable`, quoting the render command from the declaration line. To deploy an earlier build without rebuilding, pass `--image-sha=<sha>`. To reuse one image across builds (for example the 40-minute vLLM image), pass its digest-pinned reference through the matching override, such as `--var vllm_image=gcr.io/<PROJECT_ID>/vllm-streamer@sha256:<digest>`.

---

## Background Deployment (Makefile Targets)

For long-running deployments that must survive terminal/tool closure, use the
`scripts/deploy_bg.sh`-backed Makefile targets:

```bash
# Launch full deployment in background
make deploy-bg TARGET=gcp-gke ENV=staging EXTRA_ARGS="--var project_id=<PROJECT_ID> --auto-approve"

# Launch image builds only (no Terraform)
make build-bg

# Check status of in-progress deployment
make deploy-status

# Tail live log output
make deploy-logs

# Cancel in-progress deployment
make deploy-kill
```

Background deployments write logs to `/tmp/cage-deploy-*.log` and their PIDs to
`/tmp/cage-deploy.pid`.

---

## Terraform Rules

- `terraform plan` must **always** precede `terraform apply`. `deploy_all.sh`
  enforces this automatically.
- Never edit Terraform state directly.
- Secret values belong in `terraform.auto.tfvars` (gitignored via
  `scripts/gen_tfvars.py`) — never in committed `.tf` files.
- Active IaC lives under `infra/targets/`. The removed `deployment/terraform/`
  directory is historical reference only (see
  ``deployment/TERRAFORM_MIGRATION.md``).

### Terraform state backends

| Target | Backend | State path |
|--------|---------|-----------|
| `gcp-gke` | GCS (optional, configure in `infra/targets/gcp-gke/providers.tf`) | `cage/gcp-gke` |
| `agnostic` | Kubernetes Secret | namespace `terraform-state`, suffix `tfstate-agnostic` |

For the agnostic target, ensure the namespace exists before the first deploy:

```bash
kubectl create namespace terraform-state
```

---

## Pre-Deployment Checklist

- [ ] `CAGE_DEPLOYMENT_REGION` set correctly (`US_FED` / `EU_ECB` / `APAC_MAS`)
- [ ] `.env` populated (copy `.env.example` to `.env` if needed)
- [ ] `infra/targets/gcp-gke/terraform.auto.tfvars` will be generated by
      `scripts/gen_tfvars.py` (gcp-gke target only — do not commit this file)
- [ ] GCP credentials available: `gcloud auth application-default login`
- [ ] `kubectl` context correct: `kubectl config current-context`
- [ ] For GKE: Cloud Build API enabled, `google_service_account.cloudbuild` (`cage-cloudbuild-<env>`) provisioned by Terraform

---

## Post-Deployment Verification

```bash
# Check Cloud Build history
gcloud builds list --limit=5 --project=<PROJECT_ID>

# Check pod status (default namespace)
kubectl get pods -n governance-stack

# Verify key services
kubectl get deployments -n governance-stack

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack
# Open: http://localhost:9001

# Port-forward all dev services (auto-reconnecting)
bash scripts/port_forward_dev.sh
```

### Make targets for ongoing operations

```bash
# vLLM diagnostics
make vllm-status          # pod status for vLLM
make vllm-verify-models   # query /v1/models on each vLLM service

# Financial advisor diagnostics
make advisor-status        # pod status
make advisor-health        # curl /health via port-forward
make advisor-rollback      # kubectl rollout undo
make advisor-watch         # live pod watch
make advisor-verify-env    # env dump (no secrets)
make advisor-port-forward  # port-forward to localhost:8080

# Recovery checklist
make recovery             # prints ordered recovery steps
```

---

## Exception Process for Cloud Build Unavailability

If Cloud Build is unavailable:

1. **Do not** proceed with local Docker builds for GKE.
2. Investigate:
   - GCP Console → Cloud Build → History
   - Verify Cloud Build service account permissions
   - Check GCP quotas and billing status
3. Fix the Cloud Build issue.
4. Only if Cloud Build is permanently unavailable: escalate to a senior
   engineer for written approval before any local build path is used.

---

## Troubleshooting

### Cloud Build: "Permission denied"

Verify Terraform has provisioned `google_service_account.cloudbuild` (`cage-cloudbuild-<env>@<PROJECT_ID>.iam.gserviceaccount.com`) and its bindings in [`infra/targets/gcp-gke/iam.tf`](../../infra/targets/gcp-gke/iam.tf), [`infra/targets/gcp-gke/kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf), and [`infra/targets/gcp-gke/perimeter.tf`](../../infra/targets/gcp-gke/perimeter.tf):

```bash
cd infra/targets/gcp-gke && terraform plan -var-file=staging.tfvars
```

### Cloud Build: "Quota exceeded"

```bash
gcloud compute project-info describe --project=<PROJECT_ID>
# Request quota increase in GCP Console if needed
```

### Terraform: "terraform-state namespace not found" (agnostic)

```bash
kubectl create namespace terraform-state
```

### Terraform: "Storage class not found" (k3s)

```bash
kubectl get storageclass
# Update infra/targets/agnostic/dev.tfvars with correct storage_class value
```

### Pods in CrashLoopBackOff after deployment

```bash
make advisor-rollback   # rolls back governed-financial-advisor
make advisor-watch      # monitors recovery
```

### Linkerd Network Validator CrashLoopBackOff (Mitigation vs. Root Cause)

If pods (e.g., `gateway`, `compliance-bridge`, or the advisor) stay in `Init:CrashLoopBackOff` because the `linkerd-network-validator` init container exits with code 95 (`Failed to validate networking configuration`):
- **Mitigation**: Delete the affected pods so their controllers reschedule them (`kubectl delete pod -l app=gateway -n governance-stack`; use `app=compliance-bridge` and so on for other workloads), and/or cordon and cycle the node pool. In staging, deleting pods and scaling the node pools ended a 31-hour crash loop.
- **Root cause: not established.** The leading hypothesis is a race during node initialization, in which application pods schedule before `linkerd2-cni` (installed by [`infra/modules/service_mesh`](../../infra/modules/service_mesh/main.tf)) has chained its plugin into the node's CNI configuration in `/etc/cni/net.d`. That a restart clears the loop is consistent with this hypothesis but does not prove it. **This is a mitigation, not a structural fix**: the condition can recur on node restarts, pool scaling, or cluster upgrades. If it does, deleting the pods or cycling the node clears it; do not spend a day rediscovering that a restart resolves the condition.

### Unverified Deployer Service Account (`sa-cage-deployer`)

Successful staging deployments have run under personal human credentials (Owner / ADC).
- **The gap**: The headless, automated deployment path under a dedicated deployer service account (`sa-cage-deployer` in the staging probe) remains **unverified end-to-end**. This repository's Terraform does not create that account.
- **Known blocker (remediated in staging project IAM; full apply still unverified)**: Terraform reads the attestor key's public key (`data.google_kms_crypto_key_version.binauthz_attestor` in [`perimeter.tf`](../../infra/targets/gcp-gke/perimeter.tf)), which needs `cloudkms.cryptoKeyVersions.viewPublicKey`. Neither `roles/cloudkms.admin` nor `roles/editor` includes `viewPublicKey` (whereas `roles/owner` does, which is why human Owner ADC succeeded while `sa-cage-deployer` failed). `roles/cloudkms.publicKeyViewer` has now been granted to `sa-cage-deployer` at the project level. Evaluators or CI pipelines deploying under a service account must grant `roles/cloudkms.publicKeyViewer` at the **project** (or keyring) level — **not** on the `binauthz-attestor` key itself, because `google_kms_crypto_key_iam_policy.signing_key["binauthz_attestor"]` in [`kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf) is authoritative on the key and will overwrite out-of-band key-level bindings on `terraform apply`. Treat the service-account path as unverified until an automated CI deploy is proven end-to-end over the wire.

### Authorized Networks Lockout (POAM-2026-126)

With a compliance posture active, `terraform_data.control_plane_access_guard` in [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf) (POAM-2026-126, AC-3 / SC-7) refuses a plan whose `authorized_networks` list is empty or contains a `/0`. The GKE control plane's public endpoint then accepts only the listed CIDRs, plus the cluster's own node, Pod and Service ranges. Committed profiles such as `staging.tfvars` deliberately set no operator address.
- **Plan refused**: An empty list fails the plan with `[POAM-2026-126] AC-3 control-plane access: ...` before anything changes.
- **Lockout symptom**: From an address that is not on the list, `kubectl` and Terraform's `kubernetes` / `helm` providers cannot reach the endpoint; the connection typically times out (`dial tcp <endpoint>:443: i/o timeout`) rather than being refused or rejected as unauthorized. A deployer whose egress address has changed (new network, VPN on or off) hits this on the next apply.
- **Deploy prerequisite**: Pass the public egress CIDR of the deployer's workstation or CI runner to `deploy_all.sh`, which applies `--var` after the profile, or export it as `TF_VAR_authorized_networks`:
  ```bash
  ./deploy_all.sh --target gcp-gke --env staging \
    --var project_id=<PROJECT_ID> \
    --var 'authorized_networks=[{cidr="<DEPLOYER_EGRESS_IP>/32",display_name="deployer egress"}]'
  ```

### POAM-019 Telemetry Isolation vs. Environment Loading Diagnostic

With a compliance posture active (`enable_nist_compliance`, `enable_eu_ecb_compliance` or `enable_apac_mas_compliance`), the plan refuses missing or shared Langfuse compliance keys with one of two errors. Each headline names the condition detected, not a cause:

```text
[POAM-019] Compliance telemetry keys are empty under compliance hardening.
```

`langfuse_compliance_public_key` or `langfuse_compliance_secret_key` is empty (`terraform_data.poam_019_empty_key_guard`). Likely causes: the environment was not loaded (`terraform` run directly, without `deploy_all.sh`, which maps `LANGFUSE_COMPLIANCE_*` from `.env`, or `infra/load_env.sh`, which needs bash), or `.env` has no `LANGFUSE_COMPLIANCE_*` entries. The plan stops before anything is deployed. This error does **not** indicate a defect in CAGE's telemetry isolation.

```text
[POAM-019] Compliance telemetry keys equal the application project keys.
```

A compliance key is set and equal to its application-project counterpart (`terraform_data.poam_019_shared_key_guard`). This is the AU-9 dual-project isolation breach the guard exists to stop: supply the cage-compliance project's own keys. An empty compliance key is reported only by the first error, so unset variables (`"" == ""`) cannot pose as shared keys. [`poam_019.tftest.hcl`](../../infra/targets/gcp-gke/tests/poam_019.tftest.hcl) tests each guard on its own.

### Diagnostic Hygiene: The Misleading Error Pattern

Error messages and guard assertions must describe the mechanical condition detected rather than a speculative downstream root cause. Three investigations were prolonged by misleading diagnostics:
1. **POAM-019 Key Guard**: Unset variables (`"" == ""`) tripped a guard headlined as an AU-9 dual-project isolation breach when `.env` had simply not been loaded. The guard is now two resources, each headlined with the condition it detects ([above](#poam-019-telemetry-isolation-vs-environment-loading-diagnostic)).
2. **Linkerd Network Validator**: The exit-95 message (`Failed to validate networking configuration`) pointed investigators at iptables and network validation. The cause is still unestablished; a CNI-chaining race on new or scaling nodes is the leading hypothesis ([above](#linkerd-network-validator-crashloopbackoff-mitigation-vs-root-cause)).
3. **Project ID Mismatches**: Applying against a placeholder or stale `project_id` returned GCP `403 Forbidden` API errors that appeared to indicate broken deployer IAM permissions rather than an invalid target project. (#594 removes the committed placeholders.)

Engineers adding validation guards must name the immediate unfulfilled precondition, not the highest-severity hypothetical failure mode. A likely cause belongs in the remediation text, labelled as likely.

---

## Assurance Status & Legal Boundaries

**CAGE is an illustrative reference architecture.** See [`docs/compliance/ASSURANCE_STATUS_GUIDE.md`](../compliance/ASSURANCE_STATUS_GUIDE.md) for:
- Four-stage assurance lifecycle (ILLUSTRATIVE_REFERENCE → THIRD_PARTY_ASSESSED)
- Regulatory disclaimers (no FedRAMP ATO, CE Mark, ISO/IEC 42001 certification, or MAS approval claimed)
- Attestation boundaries and compliance framework context

All GKE deployments via Cloud Build are automatically logged to Cloud Logging for audit trail purposes.

---

## Related Documentation

- [`AGENTS.md`](../../AGENTS.md) — canonical source for deployment rules summary
- [`docs/operations/DEPLOYMENT_DECISION_RECORD.md`](DEPLOYMENT_DECISION_RECORD.md) — ADRs
- [`infra/QUICK_START.md`](../../infra/QUICK_START.md) — 5-minute quick start
