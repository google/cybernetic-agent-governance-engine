# GKE Dataplane V2 NetworkPolicy & FQDNNetworkPolicy Overlay

This directory contains Kubernetes `networking.k8s.io/v1` (`NetworkPolicy`) and GKE `networking.gke.io/v1alpha1` (`FQDNNetworkPolicy`) resources enforced by **GKE Dataplane V2** (Cilium/eBPF via `anetd`).

---

## Requirements & Architecture (§5.3)

- **GKE Dataplane V2 & FQDN Network Policy**: Both `enable_dataplane_v2 = true` and `enable_fqdn_network_policy = true` are enabled by default in `infra/modules/gcp_gke_cluster/` across all postures (`dev`, `staging`, `prod`). The cluster pins `release_channel = "REGULAR"` and `min_master_version = "1.28"` (≥ `1.27.1-gke.400`).
- **L3/L4 + DNS-Snooped FQDN Enforcement**: GKE's managed Cilium dataplane does not enforce L7 `CiliumNetworkPolicy` HTTP-method or DNS-pattern rules. Instead, `FQDNNetworkPolicy` (`networking.gke.io/v1alpha1`) intercepts DNS responses from `kube-dns` or Cloud DNS and programs the resolved IPs into Cilium's eBPF policy map at L3/L4.
- **Restricted DNS Egress**: Because `FQDNNetworkPolicy` relies on DNS snooping at `kube-dns` or Cloud DNS (`169.254.169.254/32`), port 53 egress is strictly restricted to `kube-system` (`k8s-app: kube-dns`) and `169.254.169.254/32` — never open to `0.0.0.0/0`. Custom CoreDNS, external resolvers, and DoH/DoT are prohibited.
- **Single-Label Prefix Wildcards**: `FQDNNetworkPolicy` wildcards use single-label prefixes only (`*.googleapis.com`, `*.ghcr.io`, `*.pkg.dev`).
- **Memorystore PSC Egress**: Egress from `reconciliation-worker` to managed Memorystore for Valkey uses an `ipBlock` for the Private Service Connect (PSC) endpoint CIDR on TLS port `6379`.
- **Connection Re-Evaluation on Policy Change**: Pre-existing connections opened before a policy change are not re-evaluated by `FQDNNetworkPolicy`. Terraform (`infra/targets/gcp-gke/network_policy.tf`) computes a SHA-256 hash (`local.network_policy_spec_hash`) across all policy specs and injects it into `cage.io/network-policy-hash` on pod templates to trigger a rolling restart whenever egress policy specs change.

---

## Apply Order

Always apply the base `NetworkPolicy` and `FQDNNetworkPolicy` resources before workload Deployments (or trigger a rollout restart after policy changes):

```bash
# 1. Base L3/L4 NetworkPolicy layer
kubectl apply -f deployment/k8s/network-policy.yaml
kubectl apply -f deployment/k8s/network-policy-hardening.yaml
kubectl apply -f deployment/k8s/ftra-network-policy.yaml
kubectl apply -f deployment/k8s/lula-network-policy.yaml
kubectl apply -f deployment/k8s/linkerd-mtls-policy.yaml

# 2. GKE Dataplane V2 FQDNNetworkPolicy + Egress Lockdown layer
kubectl get ds -n kube-system anetd
kubectl apply -f deployment/k8s/cilium/

# 3. Restart governance workloads if policies were updated on a running cluster
kubectl rollout restart deployment/gateway -n governance-stack
```

---

## Manifest Inventory

| Manifest | Kind(s) | Description |
|---|---|---|
| `egress-lockdown.yaml` | `FQDNNetworkPolicy`, `NetworkPolicy` | FQDN allowlist for Gateway (external LLM APIs, `*.googleapis.com`, `metadata.google.internal`, Langfuse, OFAC); restricted DNS egress (`kube-dns` + `169.254.169.254/32`); internal-only lockdown for `governed-financial-advisor` and `sovereign-agent` pods; cluster-wide external egress default-deny. |
| `trivy-egress-fqdn.yaml` | `FQDNNetworkPolicy`, `NetworkPolicy` | FQDN egress allowlist for Trivy vulnerability scanner (`ghcr.io`, `*.ghcr.io`, `pkg.dev`, `*.pkg.dev`) + restricted DNS egress. |
| `reconciliation-worker-egress.yaml` | `FQDNNetworkPolicy`, `NetworkPolicy` | Egress isolation for the ground-truth reconciler Deployment (`cloudkms.googleapis.com` via `FQDNNetworkPolicy`, Memorystore for Valkey PSC CIDR via `ipBlock` on TLS port `6379`, Langfuse OTLP on port `3000`, and restricted DNS). |

---

## Verification

```bash
# Verify NetworkPolicies and FQDNNetworkPolicies are registered:
kubectl get networkpolicy,fqdnnetworkpolicy -n governance-stack
```
