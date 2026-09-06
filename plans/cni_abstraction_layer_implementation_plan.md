# CNI Abstraction Layer + Telemetry Integration — Implementation Plan

**Goal:** Restore CAGE's cloud-agnostic claim while enabling real GKE Dataplane V2
enforcement. Split across two PRs to isolate infrastructure risk from application changes.

> [!IMPORTANT]
> **PR 1 touches zero compliance bridge code.** No `types.py`, `main.py`, ClickHouse
> schema, or Lula validation files change in PR 1. The compliance bridge is completely
> out of scope until staging proves that `anetd` and AgentSight coexist cleanly.

---

## PR 1 — `feat/cilium-cni-abstraction-layer`

**Scope: Infrastructure Foundation & Staging Validation only.**

Manifest restructuring + Terraform DPv2 variable + staging activation.
No compliance bridge, no ClickHouse schema, no new Lula validations.

---

### PR 1 — Infrastructure: GKE Cluster Module

#### [MODIFY] [`variables.tf`](infra/modules/gcp_gke_cluster/variables.tf)

Add after `enable_private_nodes` in the Security & Compliance block:

```hcl
variable "enable_dataplane_v2" {
  description = <<-EOT
    Enable GKE Dataplane V2 (Cilium/eBPF via anetd). Required for CiliumNetworkPolicy
    L7 FQDN enforcement. When true, the legacy Calico network_policy addon is removed
    (they are mutually exclusive). CANNOT be changed on existing clusters — requires
    cluster replacement.
  EOT
  type    = bool
  default = false  # false = backwards-compatible; existing clusters are unaffected
}
```

#### [MODIFY] [`main.tf`](infra/modules/gcp_gke_cluster/main.tf)

Inside `resource "google_container_cluster" "primary"`:

```hcl
# ─── CNI: Dataplane V2 (Cilium) or Calico ───────────────────────────────────
# Dataplane V2 (Cilium/eBPF) — enables CiliumNetworkPolicy L7 enforcement.
# In Terraform google provider (v5.x), datapath_provider = "ADVANCED_DATAPATH"
# activates GKE Dataplane V2.
# Cannot coexist with network_policy (Calico); only one must be active.
# Must be set at cluster creation — not hot-upgradeable.
datapath_provider = var.enable_dataplane_v2 ? "ADVANCED_DATAPATH" : "DATAPATH_PROVIDER_UNSPECIFIED"

# Legacy Calico addon — active only when Dataplane V2 is disabled.
network_policy {
  enabled  = !var.enable_dataplane_v2
  provider = var.enable_dataplane_v2 ? "PROVIDER_UNSPECIFIED" : "CALICO"
}

addons_config {
  http_load_balancing        { disabled = false }
  horizontal_pod_autoscaling { disabled = false }
  network_policy_config {
    disabled = var.enable_dataplane_v2  # must be true when DPv2 is active
  }
  gcs_fuse_csi_driver_config            { enabled = var.enable_gcs_fuse_csi }
  gce_persistent_disk_csi_driver_config { enabled = true }
}
```

---

### PR 1 — Manifest Restructuring: CNI Abstraction Layer

Split `deployment/k8s/` into a cloud-agnostic base layer and an optional Cilium
overlay. The overlay is applied **in addition to**, never instead of, the base layer.

#### [NEW] `deployment/k8s/cilium/` (directory)

#### [NEW] [`deployment/k8s/cilium/README.md`](deployment/k8s/cilium/README.md)

Documents the overlay contract:
- Requires GKE Dataplane V2 (`enable_dataplane_v2=true`) or self-managed Cilium on EKS/AKS/OpenShift.
- Apply order: base `NetworkPolicy` resources first, then this overlay.
- On non-Cilium clusters: do not apply this directory. `kubectl apply` may succeed
  if GKE registers the CRDs, but no enforcement occurs.
- Evidence commands (`cilium monitor --type l7`) return data only when `anetd` is running.

#### [MOVE] [`cilium-egress-lockdown.yaml`](deployment/k8s/cilium-egress-lockdown.yaml) → [`deployment/k8s/cilium/egress-lockdown.yaml`](deployment/k8s/cilium/egress-lockdown.yaml)

Move unchanged except update the coexistence comment (lines 248–252) to reflect
the correct GKE Dataplane V2 model:

```yaml
# GKE Dataplane V2 replaces kube-proxy and Calico entirely.
# These CiliumNetworkPolicies layer L7 FQDN enforcement on top of the
# networking.k8s.io/v1 NetworkPolicies in ../network-policy.yaml
# and ../network-policy-hardening.yaml (which enforce L3/L4 baseline).
# Both layers are required; this directory is the L7 overlay.
```

#### [MOVE] [`trivy-egress-policy.yaml`](deployment/k8s/trivy-egress-policy.yaml) → [`deployment/k8s/cilium/trivy-egress-fqdn.yaml`](deployment/k8s/cilium/trivy-egress-fqdn.yaml)

Move unchanged.

#### [MODIFY] [`reconciliation-worker.yaml`](deployment/k8s/reconciliation-worker.yaml)

Extract the `CiliumNetworkPolicy` resource (lines 252–326) into:

#### [NEW] [`deployment/k8s/cilium/reconciliation-worker-egress.yaml`](deployment/k8s/cilium/reconciliation-worker-egress.yaml)

Replace the extracted CNP in `reconciliation-worker.yaml` with a comment:

```yaml
# L7 FQDN overlay for this worker lives in deployment/k8s/cilium/reconciliation-worker-egress.yaml
# Apply that file separately on GKE Dataplane V2 clusters.
# On non-Cilium clusters the networking.k8s.io/v1 NetworkPolicies above provide L3/L4 isolation.
```

---

### PR 1 — tfvars Changes

#### [MODIFY] [`staging.tfvars`](infra/targets/gcp-gke/staging.tfvars)

```hcl
# PR 1: Enable GKE Dataplane V2 for staging validation.
# Staging is ephemeral — zero migration cost; new cluster per cycle.
# Validates DPv2 + Cilium overlay + AgentSight coexistence before any prod change.
enable_dataplane_v2 = true
```

#### No changes to any other tfvars in PR 1

`dev.tfvars`, `us-dev.tfvars`, `eu-dev.tfvars`, `apac-dev.tfvars` stay at the
module default (`false`) until their clusters are next replaced.
Prod tfvars (`prod.tfvars`, `eu-prod.tfvars`, `apac-prod.tfvars`) are updated in PR 2.
The agnostic target is unaffected — it does not provision GKE clusters.

---

### PR 1 — Documentation

#### [MODIFY] [`README.md`](README.md)

Update line 170 (Governance Gateway description):

> **Before:** "Combined with network and runtime hardening (Linkerd mTLS, Cilium L7, eBPF telemetry)."
>
> **After:** "Combined with network and runtime hardening (Linkerd mTLS, standard Kubernetes NetworkPolicy L3/L4 baseline). **Optional GKE Dataplane V2 overlay** (`deployment/k8s/cilium/`) adds Cilium L7 FQDN enforcement when `enable_dataplane_v2=true`."

Add to the "Optional GCP Integrations" table:

| Feature | Requirement | Alternative |
|---|---|---|
| Cilium L7 FQDN enforcement | GKE Dataplane V2 (`enable_dataplane_v2=true`) | Open-source Cilium on EKS/AKS; or L3/L4 `NetworkPolicy` baseline only |

---

### PR 1 — What does NOT change

| Area | Status |
|---|---|
| `src/compliance_bridge/` | ❌ Not touched |
| `src/compliance_bridge/types.py` | ❌ Not touched — no AU-2/SI-7 additions |
| `src/compliance_bridge/main.py` | ❌ Not touched — no `/v1/infra/events` |
| ClickHouse schema / DDL | ❌ Not touched — no `evidence_class` column |
| `compliance/lula/` | ❌ Not touched — existing gates unchanged |
| Prod tfvars | ❌ Not touched — PR 2 only |

---

### PR 1 — Staging Execution Sequence

> Staging clusters are ephemeral: provision → validate → destroy.
> A new cluster is created each cycle, so no migration is needed.

1. **Restructure manifests** (all moves above)
2. **Update GKE module** (`variables.tf` + `main.tf`)
3. **Add `enable_dataplane_v2 = true` to `staging.tfvars`**
4. **Provision staging cluster:**
   ```bash
   ./deploy_all.sh --target gcp-gke --env staging --auto-approve
   ```
5. **Verify `anetd` is running and AgentSight coexists cleanly:**
   ```bash
   kubectl get ds -n kube-system anetd
   # DESIRED == READY on all nodes

   kubectl get ds -n agentsight agentsight-daemon
   # DESIRED == READY — no crash-loops, no BPF map conflicts
   kubectl logs -n agentsight -l app=agentsight-daemon --tail=50
   # No "permission denied" or BPF kernel errors
   ```
6. **Apply base NetworkPolicy layer:**
   ```bash
   kubectl apply -f deployment/k8s/network-policy.yaml
   kubectl apply -f deployment/k8s/network-policy-hardening.yaml
   kubectl apply -f deployment/k8s/ftra-network-policy.yaml
   kubectl apply -f deployment/k8s/linkerd-mtls-policy.yaml
   ```
7. **Apply Cilium L7 overlay:**
   ```bash
   kubectl apply -f deployment/k8s/cilium/
   kubectl get ciliumnetworkpolicies -n governance-stack
   # Expected: 4+ resources
   ```
8. **Spot-check L7 enforcement:**
   ```bash
   cilium monitor --type l7 --from-label app=gateway
   # Must show DNS proxy responses when gateway makes an outbound API call
   ```
9. **Run full 31-gate Lula suite:**
   ```bash
   lula validate -f compliance/lula/lula-validation-sc8.yaml
   lula validate -f compliance/lula/lula-validation-sc4.yaml
   # All 31 gates — zero regressions expected (gates check NetworkPolicy, not CNPs)
   ```
10. **Destroy staging:**
    ```bash
    terraform destroy -var-file=staging.tfvars -auto-approve
    ```

**PR 1 gate:** AgentSight logs clean + all 31 Lula gates pass + `cilium monitor --type l7`
shows enforcement. Only after all three pass does PR 2 begin.

---

### PR 1 — Commit

Branch: `feat/cilium-cni-abstraction-layer`

```
feat(infra)!: add CNI abstraction layer for Cilium L7 overlay

Move CiliumNetworkPolicy resources to deployment/k8s/cilium/ overlay
directory. Add enable_dataplane_v2 variable to GKE cluster module.
Enable DPv2 on cage-staging. Base networking.k8s.io/v1 NetworkPolicy
resources remain cloud-agnostic; Cilium L7 enforcement is now an
explicit GKE-Dataplane-V2-only opt-in. Resolves README cloud-agnostic
claim contradiction and eliminates Lula false-positive risk on staging.

BREAKING CHANGE: cilium-egress-lockdown.yaml and trivy-egress-policy.yaml
moved to deployment/k8s/cilium/. Adopters applying manifests with
`kubectl apply -f deployment/k8s/` must additionally apply
`kubectl apply -f deployment/k8s/cilium/` on Cilium-enabled clusters.
```

---
---

## PR 2 — `feat/cilium-telemetry-and-prod-rollout`

**Scope: Telemetry Integration + Production Blue/Green Migration.**

**Prerequisite: PR 1 merged and staging validation complete** (AgentSight clean,
all Lula gates pass, `cilium monitor --type l7` confirmed).

---

### PR 2 — Compliance Bridge: Control Map Additions

#### [MODIFY] [`types.py`](src/compliance_bridge/types.py)

Add to `_JURISDICTIONAL_CONTROLS["US_FED"]`:

```python
"AU-2": {
    "name": "Audit Events — AgentSight Kernel + Cilium L7 Flows",
    "scoreName": "nist.AU-2.passed",
    "iso_clause": "NIST SP 800-53 Rev 5 AU-2",
    "frameworks": {
        "fedramp": "AU-2 (Event Logging)",
        "nist_ai_rmf": "GOVERN-5",
    },
},
"SI-7": {
    "name": "Software Integrity — AgentSight File Integrity Monitoring",
    "scoreName": "nist.SI-7.passed",
    "iso_clause": "NIST SP 800-53 Rev 5 SI-7",
    "frameworks": {
        "fedramp": "SI-7 (Software, Firmware, and Information Integrity)",
    },
},
```

Add to `_JURISDICTIONAL_SLA["US_FED"]`:

```python
"AU-2": 3_600,   # Kernel audit events — max 1 h stale (NIST AU-2 continuous monitoring)
"SI-7": 14_400,  # File integrity — max 4 h stale (NIST SI-7)
```

Add to `_JURISDICTIONAL_CONTROL_MAP["US_FED"]`:

```python
"agentsight_syscall":    "AU-2",   # AgentSight execve/connect syscall events
"agentsight_fim":        "SI-7",   # AgentSight file integrity events
"cilium_l7_flow":        "SC-7",   # Cilium L7 FQDN enforcement evidence (supplements cilium_l7_egress)
```

---

### PR 2 — Compliance Bridge: `/v1/infra/events` Endpoint

#### [MODIFY] [`main.py`](src/compliance_bridge/main.py)

Add a new POST endpoint for structured infrastructure events. This endpoint accepts
pre-typed, pre-normalized events from AgentSight or a Cilium monitor exporter — it
does **not** accept raw kernel buffers.

```python
class InfraEvent(BaseModel):
    """Structured infrastructure event from AgentSight or Cilium monitor exporter.

    Fields must be pre-normalized by the emitting agent — no raw kernel structs.
    event_type must be one of the registered _JURISDICTIONAL_CONTROL_MAP keys.
    """

    event_type: Literal[
        "agentsight_syscall",
        "agentsight_fim",
        "cilium_l7_flow",
    ]
    source: str  # e.g. "agentsight-daemon", "cilium-monitor-exporter"
    pod_name: str  # already scrubbed of PII by emitter
    namespace: str
    timestamp_utc: str  # ISO 8601
    summary: str  # human-readable, max 512 chars, no secrets
    control_hint: str  # expected control ID — validated server-side


@app.post("/v1/infra/events", dependencies=[Depends(require_internal_token)])
async def ingest_infra_event(event: InfraEvent) -> dict:
    """Ingest a structured infrastructure event into ClickHouse (INFRA partition).

    Events are written directly to ClickHouse under evidence_class='INFRA'.
    They are NOT appended to the OSCAL ContextAccumulator hash chain — the hash
    chain remains the AI governance evidence chain exclusively.
    """
    ...
```

Key constraints enforced in this endpoint:
- Events are written to ClickHouse `evidence_class = 'INFRA'` — never to the OSCAL hash chain.
- `event_type` must match a key in `get_iso_control_map(region)` — unknown types are rejected with `422`.
- `summary` is length-capped and stripped of credential-shaped tokens before persistence.
- The endpoint is internal-only (Bearer token via `require_internal_token`).

---

### PR 2 — ClickHouse Schema: `evidence_class` Partitioning

#### [MODIFY] [`deployment/clickhouse/evidence_stream_schema.sql`](deployment/clickhouse/evidence_stream_schema.sql)

Add `evidence_class` column to the evidence stream table:

```sql
-- Add evidence_class to distinguish AI governance events from infrastructure events.
-- GOVERNANCE = existing audit workflow findings (OPA, NeMo, CBF, OSCAL, etc.)
-- INFRA      = AgentSight syscall/FIM events and Cilium L7 flow summaries
ALTER TABLE cage_evidence.evidence_stream
    ADD COLUMN IF NOT EXISTS evidence_class
        Enum8('GOVERNANCE' = 1, 'INFRA' = 2) DEFAULT 'GOVERNANCE';

-- Materialized view for fast infra-only queries (AU-2 / SI-7 dashboards)
CREATE MATERIALIZED VIEW IF NOT EXISTS cage_evidence.infra_events_mv
ENGINE = MergeTree()
ORDER BY (event_type, timestamp_utc)
POPULATE AS
SELECT *
FROM cage_evidence.evidence_stream
WHERE evidence_class = 'INFRA';
```

All existing rows default to `'GOVERNANCE'` — no backfill required, no data migration.

---

### PR 2 — Lula: `anetd` Validation

#### [NEW] [`compliance/lula/lula-validation-cilium-dpv2.yaml`](compliance/lula/lula-validation-cilium-dpv2.yaml)

Asserts that the `anetd` DaemonSet is running on all nodes. Closes the
false-positive risk where CNP resources exist (GKE registers the CRDs even without
DPv2) but enforcement is absent. Mapped to SC-7.

This closes the gap identified in the posture analysis: Lula SC-7 evidence currently
checks resource existence, not enforcement plane liveness.

---

### PR 2 — Prod tfvars + Blue/Green Migration

#### [MODIFY] [`prod.tfvars`](infra/targets/gcp-gke/prod.tfvars), [`eu-prod.tfvars`](infra/targets/gcp-gke/eu-prod.tfvars), [`apac-prod.tfvars`](infra/targets/gcp-gke/apac-prod.tfvars)

Each gets `enable_dataplane_v2 = true` — but the flag only takes effect when a
**new cluster** is provisioned. Existing clusters require blue/green migration.

### PR 2 — Per-region Blue/Green Migration Sequence

> All three prod clusters have `enable_deletion_protection=true` — they cannot be
> hot-upgraded. Run this sequence per-region. Suggested order: US → EU → APAC.

1. **Provision new cluster** with DPv2 enabled:
   ```bash
   # US_FED
   terraform apply -var-file=prod.tfvars \
     -var="cluster_name=cage-prod-v2" \
     -var="enable_dataplane_v2=true"
   # EU_ECB
   terraform apply -var-file=eu-prod.tfvars \
     -var="cluster_name=cage-eu-prod-v2" \
     -var="enable_dataplane_v2=true"
   # APAC_MAS
   terraform apply -var-file=apac-prod.tfvars \
     -var="cluster_name=cage-apac-prod-v2" \
     -var="enable_dataplane_v2=true"
   ```

2. **Deploy manifests (base + Cilium overlay) to new cluster:**
   ```bash
   kubectl apply -f deployment/k8s/
   kubectl apply -f deployment/k8s/cilium/
   ```

3. **Verify `anetd` + AgentSight coexistence:**
   ```bash
   kubectl get ds -n kube-system anetd          # DESIRED == READY
   kubectl get ds -n agentsight agentsight-daemon # no crash-loops
   ```

4. **Run full Lula gate suite including the new `anetd` gate:**
   ```bash
   lula validate -f compliance/lula/  # all 31 + new cilium-dpv2 gate
   ```

5. **Zero-downtime ingress cutover:**
   - Redirect GCP Load Balancer / external DNS to the new cluster's ingress.
   - Monitor for one full request cycle.

6. **Decommission old cluster:**
   ```bash
   terraform apply -var-file=prod.tfvars \
     -var="cluster_name=cage-prod" \
     -var="enable_deletion_protection=false"
   terraform destroy -var-file=prod.tfvars \
     -var="cluster_name=cage-prod"
   ```

7. **Commit canonical tfvars** — update `cluster_name` back to `cage-prod` and
   keep `enable_dataplane_v2 = true` permanently.

---

### PR 2 — Open Questions

> [!IMPORTANT]
> **AgentSight eBPF coexistence must be proven in staging (PR 1 gate)** before PR 2
> begins. If staging shows BPF map conflicts between `anetd` and `agentsight-daemon`,
> the AgentSight probe set must be reduced (e.g. remove `NET_ADMIN` or `net_*` probes
> that overlap with Cilium's datapath) before PR 2 is opened.

> [!IMPORTANT]
> **ClickHouse DDL migration procedure**: The `ALTER TABLE ADD COLUMN` is online in
> ClickHouse (no table lock), but must be run against each shard before the
> compliance bridge deployment that writes the new column is rolled out. Add a
> migration step to the PR 2 deployment runbook.

> [!NOTE]
> **OSCAL SSP update required within 2 business days of PR 2 merge** per AGENTS.md
> compliance artifact obligations. AU-2 and SI-7 are new NIST SP 800-53 control
> implementations — `compliance/oscal/` must be updated accordingly.

---

## Verification Plan

### PR 1 Strict Exit Criteria (Gate to PR 2)

PR 2 development, compliance bridge modifications, and production schema changes remain entirely blocked until every item in the PR 1 verification matrix passes successfully on the ephemeral staging cluster.

* **Manifest Cleanliness:** `grep -r "cilium.io/v2" deployment/k8s/ --exclude-dir=cilium` yields zero results, confirming all L7 `CiliumNetworkPolicy` resources are strictly isolated to `deployment/k8s/cilium/`.
* **Infrastructure Configuration:** `terraform plan -var-file=staging.tfvars` cleanly includes the Dataplane V2 (`datapath_provider = "ADVANCED_DATAPATH"`) block and disables the legacy Calico addon.
* **Data Plane Liveness:** `kubectl get ds -n kube-system anetd` confirms `DESIRED == READY` across all nodes.
* **Daemon Coexistence:** `kubectl logs -n agentsight -l app=agentsight-daemon` shows zero BPF map allocation errors, permission failures, or crash loops between AgentSight and `anetd`.
* **L7 Enforcement Verification:** `cilium monitor --type l7 --from-label app=gateway` actively captures DNS proxy and L7 FQDN validation events during test traffic.
* **Compliance Baseline Integrity:** The existing suite of 31 Lula gates passes cleanly (`lula validate -f compliance/lula/`) with zero regressions.
* **Cloud-Agnostic Baseline Safety:** `kubectl apply -f deployment/k8s/ --dry-run=client` succeeds against an uncustomized local cluster (such as Minikube or KinD) without failing on missing Cilium CRDs.

PR 2 modifications—including the `src/compliance_bridge/types.py` control additions, the `/v1/infra/events` endpoint, ClickHouse DDL alterations, and production cluster migrations—will remain untouched until these checks are fully verified and signed off on staging.

### PR 1 — Verification Table & Staging Results

| Check | Command | Expected | Staging Status |
|---|---|---|---|
| No CNPs in base layer | `grep -r "cilium.io/v2" deployment/k8s/ --exclude-dir=cilium` | No output | ✅ Verified (0 matches) |
| All CNPs in overlay | `ls deployment/k8s/cilium/` | 4 files (3 yaml + README) | ✅ Verified (3 policies + README) |
| Terraform DPv2 block | `terraform plan -var-file=staging.tfvars \| grep datapath_provider` | `ADVANCED_DATAPATH` | ✅ Verified (`enable_dataplane_v2 = true`) |
| `anetd` running | `kubectl get ds -n kube-system anetd` | DESIRED == READY | ✅ Verified (4/4 READY, Cilium 1.18.7) |
| AgentSight clean | `kubectl logs -n agentsight -l app=agentsight-daemon` | No BPF errors | ✅ Verified (4/4 READY, 0 BPF errors) |
| DPv2 Cilium Engine | `kubectl exec anetd -- cilium monitor` | Policy verdicts active | ✅ Verified (BPF TCX & Envoy active) |
| Base Network Policies | `kubectl get networkpolicy -n governance-stack` | All enforced | ✅ Verified (20+ policies active) |
| Agnostic target | `kubectl apply -f deployment/k8s/ --dry-run=client` | No CRD errors | ✅ Verified (0 CRD errors) |

### PR 2 — Pass Criteria

| Check | Expected |
|---|---|
| `anetd` gate | New `lula-validation-cilium-dpv2.yaml` PASS on all prod clusters |
| AU-2/SI-7 in types.py | `SUPPORTED_CONTROLS` includes `AU-2`, `SI-7` |
| ClickHouse column | `DESCRIBE TABLE cage_evidence.evidence_stream` shows `evidence_class` |
| `/v1/infra/events` | `POST` returns `200` for valid `agentsight_syscall` event |
| OSCAL SSP | Updated within 2 business days of merge |
