# Cilium L7 NetworkPolicy Overlay

This directory contains `apiVersion: cilium.io/v2` (`CiliumNetworkPolicy`) resources that form an **optional L7 security overlay** on top of CAGE's portable Kubernetes `networking.k8s.io/v1` NetworkPolicy baseline.

---

## Requirements

- **GKE Clusters**: GKE Dataplane V2 must be enabled (`enable_dataplane_v2 = true` in Terraform). GKE Dataplane V2 runs Cilium and eBPF via the `anetd` DaemonSet in `kube-system`.
- **Non-GKE Clusters (EKS, AKS, k3s, OpenShift)**: Requires self-managed open-source Cilium CNI (v1.12+) installed on the cluster.
- **Agnostic / Default Posture**: On standard Kubernetes clusters without Cilium/Dataplane V2 (e.g. running Calico, Flannel, AWS VPC CNI, Azure CNI), **do not apply this directory**. The base `networking.k8s.io/v1` policies in `../network-policy.yaml`, `../network-policy-hardening.yaml`, and `../ftra-network-policy.yaml` provide complete L3/L4 isolation (default deny, namespace segmentation, port restrictions) across all conformant Kubernetes environments.

> [!WARNING]
> On GKE clusters where Dataplane V2 is disabled (standard Calico addon), `kubectl apply -f deployment/k8s/cilium/` may succeed if CRDs are registered, but **no enforcement occurs**. Only apply this directory on clusters running active Cilium (`anetd`).

---

## Apply Order

Always apply the portable base layer first, followed by the Cilium overlay:

```bash
# 1. Base L3/L4 NetworkPolicy layer (portable across all conformant K8s clusters)
kubectl apply -f deployment/k8s/network-policy.yaml
kubectl apply -f deployment/k8s/network-policy-hardening.yaml
kubectl apply -f deployment/k8s/ftra-network-policy.yaml
kubectl apply -f deployment/k8s/lula-network-policy.yaml
kubectl apply -f deployment/k8s/linkerd-mtls-policy.yaml

# 2. Cilium L7 FQDN Overlay (GKE Dataplane V2 or Cilium-enabled clusters only)
# Verify anetd / cilium daemon is running first:
kubectl get ds -n kube-system anetd
kubectl apply -f deployment/k8s/cilium/
```

---

## Manifest Inventory

| Manifest | Kind | Description |
|---|---|---|
| `egress-lockdown.yaml` | `CiliumNetworkPolicy` | FQDN allowlist for Gateway (external LLM APIs: OpenAI, Anthropic, Gemini); internal-only lockdown for `governed-financial-advisor` and `sovereign-agent` pods; explicit cluster-wide external egress default-deny. |
| `trivy-egress-fqdn.yaml` | `CiliumNetworkPolicy` | FQDN egress allowlist for Trivy vulnerability scanner (`ghcr.io`, `pkg.dev`) via DNS proxy interception. |
| `reconciliation-worker-egress.yaml` | `CiliumNetworkPolicy` | Egress isolation for the external ledger reconciliation CronJob (Cloud KMS, GCS/S3, Redis, and internal DNS). |

---

## Verification & Observability

Evidence commands return live stream data only when `anetd` is running and enforcing policies:

```bash
# Verify CiliumNetworkPolicies are registered:
kubectl get ciliumnetworkpolicies -n governance-stack

# Stream real-time L7 DNS proxy and egress flow inspection:
cilium monitor --type l7 --from-label app=gateway

# Monitor sovereign agent lockdown (should show zero external egress):
cilium monitor --type l7 --from-label role=sovereign-agent
```

