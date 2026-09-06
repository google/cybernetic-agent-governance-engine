# Option B: CNI Abstraction Layer — Implementation Plan

**Goal:** Restore CAGE's cloud-agnostic claim while giving GKE Dataplane V2 clusters
real L7 Cilium enforcement. All `apiVersion: cilium.io/v2` resources move from the
always-applied base layer into an explicit GKE Dataplane V2 overlay that is layered
*on top of* portable `networking.k8s.io/v1 NetworkPolicy` resources.
The agnostic Terraform target (EKS, AKS, k3s, minikube, OpenShift) continues to work
with zero changes; GKE adopters enabling Dataplane V2 get the stronger L7 path.

**Phasing:**
- **Step 1** — Staging: restructure manifests + enable GKE Dataplane V2 on `cage-staging`
- **Step 2** — Prod: blue/green cluster migration for all three prod regions (US, EU, APAC)

---

## Proposed Changes

---

### Infrastructure: GKE Cluster Module

#### [MODIFY] [`variables.tf`](infra/modules/gcp_gke_cluster/variables.tf)

Add one variable at the end of the Security & Compliance block (after `enable_private_nodes`):

```hcl
variable "enable_dataplane_v2" {
  description = <<-EOT
    Enable GKE Dataplane V2 (Cilium/eBPF via anetd). Required for CiliumNetworkPolicy
    L7 FQDN enforcement. When true, the legacy Calico network_policy addon is removed
    (they are mutually exclusive). CANNOT be changed on existing clusters — requires
    cluster replacement.
  EOT
  type    = bool
  default = false  # false = backwards-compatible default; new clusters set true
}
```

#### [MODIFY] [`main.tf`](infra/modules/gcp_gke_cluster/main.tf)

Inside `resource "google_container_cluster" "primary"`, replace the Calico block with
the Dataplane V2 block, conditioned on the variable:

```hcl
# ─── CNI: Dataplane V2 (Cilium) or Calico ───────────────────────────────────
# Dataplane V2 (Cilium/eBPF) — enables CiliumNetworkPolicy L7 enforcement.
# Cannot coexist with network_policy (Calico); only one must be active.
datapath_provider = var.enable_dataplane_v2 ? "ADVANCED_DATAPATH" : "DATAPATH_PROVIDER_UNSPECIFIED"

# Legacy Calico addon — only when Dataplane V2 is disabled.
# Disabled automatically when dataplane_v2_enabled=true (GKE removes it).
network_policy {
  enabled  = !var.enable_dataplane_v2
  provider = var.enable_dataplane_v2 ? "PROVIDER_UNSPECIFIED" : "CALICO"
}

addons_config {
  http_load_balancing        { disabled = false }
  horizontal_pod_autoscaling { disabled = false }
  network_policy_config {
    disabled = var.enable_dataplane_v2  # must be disabled when DPv2 is active
  }
  gcs_fuse_csi_driver_config       { enabled = var.enable_gcs_fuse_csi }
  gce_persistent_disk_csi_driver_config { enabled = true }
}
```

---

### Manifest Restructuring: CNI Abstraction Layer

The core structural change: split `deployment/k8s/` into a portable base layer and
an optional Cilium overlay subdirectory.

#### [NEW] `deployment/k8s/cilium/` (directory)

Move all `apiVersion: cilium.io/v2` resources here. This directory is applied **in
addition to** the base `networking.k8s.io/v1` policies — never instead of them.

#### [NEW] [`deployment/k8s/cilium/README.md`](deployment/k8s/cilium/README.md)

Documents:
- These resources require GKE Dataplane V2 (`enable_dataplane_v2=true` in Terraform)
  or self-managed open-source Cilium on EKS/AKS/OpenShift.
- Apply order: base `NetworkPolicy` resources first, then this overlay.
- On GKE without Dataplane V2: `kubectl apply` will succeed (GKE may register CRDs),
  but no enforcement occurs. Do not apply this directory on non-Cilium clusters.
- Evidence commands (`cilium monitor --type l7`) only return data when `anetd` is running.

#### [MODIFY → MOVE] [`deployment/k8s/cilium-egress-lockdown.yaml`](deployment/k8s/cilium-egress-lockdown.yaml) → [`deployment/k8s/cilium/egress-lockdown.yaml`](deployment/k8s/cilium/egress-lockdown.yaml)

Move the file. No content changes to the CNP policies themselves — they are already
correct. Update the comment at line 248–252 (the "kube-proxy + Cilium coexistence"
comment) to reflect the correct GKE model:

```yaml
# GKE Dataplane V2 replaces kube-proxy and Calico entirely.
# These CiliumNetworkPolicies layer L7 FQDN enforcement on top of the
# networking.k8s.io/v1 NetworkPolicies in ../network-policy.yaml
# and ../network-policy-hardening.yaml (which enforce L3/L4 baseline).
# Both sets of policies are required; this directory is the L7 overlay.
```

#### [MODIFY → MOVE] [`deployment/k8s/trivy-egress-policy.yaml`](deployment/k8s/trivy-egress-policy.yaml) → [`deployment/k8s/cilium/trivy-egress-fqdn.yaml`](deployment/k8s/cilium/trivy-egress-fqdn.yaml)

Move file unchanged.

#### [MODIFY] [`deployment/k8s/reconciliation-worker.yaml`](deployment/k8s/reconciliation-worker.yaml)

Extract only the `CiliumNetworkPolicy` resource (lines 252–326) into:

#### [NEW] [`deployment/k8s/cilium/reconciliation-worker-egress.yaml`](deployment/k8s/cilium/reconciliation-worker-egress.yaml)

Replace the extracted CNP in `reconciliation-worker.yaml` with a comment:

```yaml
# L7 FQDN overlay for this worker is in deployment/k8s/cilium/reconciliation-worker-egress.yaml
# Apply that file separately on GKE Dataplane V2 clusters.
# On non-Cilium clusters, the networking.k8s.io/v1 NetworkPolicies above provide L3/L4 isolation.
```

---

### tfvars Changes

#### [MODIFY] [`staging.tfvars`](infra/targets/gcp-gke/staging.tfvars)

Add (Step 1):
```hcl
# Step 1: Enable GKE Dataplane V2 for staging — activates CiliumNetworkPolicy enforcement.
# Staging is ephemeral, so this is a zero-migration-cost change (new cluster per cycle).
# Validates DPv2 + Cilium overlay before any prod migration.
enable_dataplane_v2 = true
```

#### [MODIFY] [`prod.tfvars`](infra/targets/gcp-gke/prod.tfvars) (Step 2)
#### [MODIFY] [`eu-prod.tfvars`](infra/targets/gcp-gke/eu-prod.tfvars) (Step 2)
#### [MODIFY] [`apac-prod.tfvars`](infra/targets/gcp-gke/apac-prod.tfvars) (Step 2)

Each gets `enable_dataplane_v2 = true` — but **these clusters require the blue/green
migration procedure** (existing prod clusters cannot be hot-upgraded).

#### No change to dev/agnostic tfvars

`dev.tfvars`, `us-dev.tfvars`, `eu-dev.tfvars`, `apac-dev.tfvars` all default to
`enable_dataplane_v2 = false` (the variable default) until their clusters are next
replaced. The agnostic target (`infra/targets/agnostic/`) has no `dataplane_v2_config`
— it does not provision GKE clusters and is unaffected.

---

### Documentation

#### [MODIFY] [`README.md`](README.md) — Platform Compatibility table (line 68–86)

Update the Governance Gateway capability description (line 170) from:
> "Combined with network and runtime hardening (Linkerd mTLS, Cilium L7, eBPF telemetry)"

to:
> "Combined with network and runtime hardening (Linkerd mTLS, standard Kubernetes
> NetworkPolicy L3/L4 baseline). **Optional GKE Dataplane V2 overlay** adds Cilium
> L7 FQDN enforcement and eBPF telemetry (see `deployment/k8s/cilium/`)."

Add a new row in the "Optional GCP Integrations" table:

| Feature | Requirement | Alternative |
|---|---|---|
| Cilium L7 FQDN enforcement | GKE Dataplane V2 (`enable_dataplane_v2=true`) | Open-source Cilium on EKS/AKS; or L3/L4 `NetworkPolicy` baseline only |

---

### OSCAL / Lula: No changes required for Step 1

The existing Lula gates check `networking.k8s.io/v1 NetworkPolicy` resources
(`default-deny-ingress` in SC-8, ConfigMap labels in SC-4). They do **not** assert
the existence of `CiliumNetworkPolicy` resources — so moving CNPs to the overlay
directory does not cause any Lula gate to regress.

A new Lula validation (`lula-validation-cilium-dpv2.yaml`) asserting that the
`anetd` daemonset exists and is running would be the correct follow-up to close the
evidence gap on GKE Dataplane V2 clusters — but that is explicitly out of scope for
this plan and would be a separate PR.

---

## Step 1 — Staging Execution Sequence

> Staging clusters are ephemeral: provision → validate → destroy. A new cluster
> is created each cycle, so no migration is needed — just add `enable_dataplane_v2=true`
> before the next provision run.

1. **Restructure manifests** (all file moves/edits above)
2. **Update GKE cluster module** (`variables.tf` + `main.tf`)
3. **Add `enable_dataplane_v2 = true` to `staging.tfvars`**
4. **Provision staging cluster:**
   ```bash
   ./deploy_all.sh --target gcp-gke --env staging --auto-approve
   ```
5. **Apply base NetworkPolicy layer:**
   ```bash
   kubectl apply -f deployment/k8s/network-policy.yaml
   kubectl apply -f deployment/k8s/network-policy-hardening.yaml
   kubectl apply -f deployment/k8s/ftra-network-policy.yaml
   kubectl apply -f deployment/k8s/lula-network-policy.yaml
   kubectl apply -f deployment/k8s/linkerd-mtls-policy.yaml
   ```
6. **Apply Cilium L7 overlay** (only after verifying `anetd` is running):
   ```bash
   kubectl get ds -n kube-system anetd  # must be Running
   kubectl apply -f deployment/k8s/cilium/
   ```
7. **Verify CNP enforcement:**
   ```bash
   kubectl get ciliumnetworkpolicies -n governance-stack
   # Spot-check L7 DNS proxy:
   cilium monitor --type l7 --from-label app=gateway
   ```
8. **Run Lula validation gates:**
   ```bash
   lula validate -f compliance/lula/lula-validation-sc8.yaml
   lula validate -f compliance/lula/lula-validation-sc4.yaml
   # ... full 31-gate suite
   ```
9. **Destroy staging** (ephemeral lifecycle):
   ```bash
   terraform destroy -var-file=staging.tfvars -auto-approve
   ```

---

## Step 2 — Prod Blue/Green Migration Sequence

> All three prod clusters (`cage-prod`, `cage-eu-prod`, `cage-apac-prod`) have
> `enable_deletion_protection=true` — they cannot be hot-upgraded. A parallel
> blue/green cluster is required for each.

### Per-region procedure (US, EU, APAC):

1. **Provision new cluster** (e.g. `cage-prod-v2`) with `enable_dataplane_v2=true`:
   ```bash
   # US_FED
   terraform apply -var-file=prod.tfvars \
     -var="cluster_name=cage-prod-v2" \
     -var="enable_dataplane_v2=true"
   ```
   *(EU and APAC: equivalent with `eu-prod.tfvars` / `apac-prod.tfvars`)*

2. **Deploy all CAGE manifests to new cluster** (base + Cilium overlay):
   ```bash
   kubectl apply -f deployment/k8s/   # base layer
   kubectl apply -f deployment/k8s/cilium/  # L7 overlay
   ```

3. **Validate Cilium enforcement:**
   ```bash
   kubectl get ds -n kube-system anetd
   kubectl get ciliumnetworkpolicies -n governance-stack
   cilium monitor --type l7
   ```

4. **Run full Lula gate suite against new cluster:**
   ```bash
   lula validate -f compliance/lula/  # all 31 gates must pass
   ```

5. **Cut over ingress (zero-downtime):**
   - Point the external DNS / GCP Load Balancer at the new cluster's ingress
   - Monitor error rate for one full request cycle window

6. **Decommission old cluster:**
   ```bash
   # Lower deletion protection first
   terraform apply -var-file=prod.tfvars \
     -var="cluster_name=cage-prod" \
     -var="enable_deletion_protection=false"
   terraform destroy -var-file=prod.tfvars \
     -var="cluster_name=cage-prod"
   ```

7. **Update tfvars** — rename `cluster_name` back to canonical (`cage-prod`) and
   commit `enable_dataplane_v2 = true` permanently.

---

## Open Questions

> [!IMPORTANT]
> **AgentSight eBPF compatibility**: [`agentsight-daemon.yaml`](deployment/k8s/agentsight-daemon.yaml)
> must be audited for eBPF program injection before enabling Dataplane V2. GKE
> prohibits third-party eBPF programs that conflict with `anetd`'s managed Cilium
> datapath. If AgentSight uses eBPF for pod-level syscall tracing, it must be
> verified compatible or replaced with a kernel-module / perf-based approach.

> [!IMPORTANT]
> **`gpu_node_pool_name` variable**: `staging.tfvars` and several other profiles
> set `gpu_node_pool_name` but `variables.tf` in the GKE module does not declare it.
> Before adding `enable_dataplane_v2`, confirm this variable is wired through or the
> `terraform plan` will error.

> [!NOTE]
> **Lula gate for `anetd`**: A follow-on PR should add
> `compliance/lula/lula-validation-cilium-dpv2.yaml` that asserts the `anetd`
> DaemonSet is running and ready on all nodes. Without this, Lula cannot distinguish
> a cluster that has CNPs applied (resource exists) from one where Cilium is actually
> enforcing them (`anetd` running). This closes the false-positive risk described in
> Part 2.4 of the analysis.

---

## Verification Plan

### Automated

```bash
# Manifest restructuring sanity — no CiliumNetworkPolicy in base layer:
grep -r "cilium.io/v2" deployment/k8s/ --exclude-dir=cilium
# Expected: no output

# All CNPs present in overlay:
ls deployment/k8s/cilium/
# Expected: egress-lockdown.yaml, trivy-egress-fqdn.yaml,
#           reconciliation-worker-egress.yaml, README.md

# Terraform plan for staging (must show dataplane_v2_config block):
terraform plan -var-file=staging.tfvars | grep dataplane_v2

# All 31 Lula gates pass on staging cluster
# No gates should regress — SC-8 checks NetworkPolicy, not CNPs
```

### Manual

- `kubectl get ciliumnetworkpolicies -n governance-stack` returns 4+ resources on staging
- `kubectl get ds -n kube-system anetd` shows `DESIRED == READY`
- `cilium monitor --type l7 --from-label app=gateway` shows traffic when gateway makes an outbound AI API call
- `kubectl apply -f deployment/k8s/` on a minikube cluster succeeds without CRD errors (agnostic target unchanged)

---

## Commit Strategy

All changes ship as a single squash-merge PR on branch `feat/cilium-cni-abstraction-layer`.

**Commit message:**
```
feat(infra)!: add CNI abstraction layer for Cilium L7 overlay

Move CiliumNetworkPolicy resources to deployment/k8s/cilium/ overlay
directory. Add enable_dataplane_v2 variable to GKE cluster module.
Enable DPv2 on staging. Base networking.k8s.io/v1 NetworkPolicy
resources remain cloud-agnostic; Cilium L7 enforcement is now an
explicit GKE-Dataplane-V2-only opt-in. Resolves README cloud-agnostic
claim contradiction and eliminates Lula false-positive risk on staging.

BREAKING CHANGE: cilium-egress-lockdown.yaml and trivy-egress-policy.yaml
moved to deployment/k8s/cilium/. Adopters applying manifests with
`kubectl apply -f deployment/k8s/` must additionally apply
`kubectl apply -f deployment/k8s/cilium/` on Cilium-enabled clusters.
```

