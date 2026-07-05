# GKE-Specific Kubernetes Resources

This directory contains Kubernetes manifests that use GKE-proprietary APIs and are **only compatible with Google Kubernetes Engine (GKE)**.

| File | GKE Feature Used | Standard Alternative |
|---|---|---|
| `ingress-gke.yaml` | GCE L7 Ingress + ManagedCertificate CRD | `../ingress.yaml` (nginx ingress) |

For deployments on EKS, AKS, OpenShift, or vanilla Kubernetes, use the standard manifests in `deployment/k8s/` instead.
