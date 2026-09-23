# GKE-Specific Kubernetes Resources

This directory contains Kubernetes manifests that use GKE-proprietary APIs and are **only compatible with Google Kubernetes Engine (GKE)**.

| File | GKE Feature Used | Standard Alternative |
|---|---|---|
| `ingress-gke.yaml.tpl` | GCE L7 Ingress + ManagedCertificate CRD Template | `../ingress.yaml` (nginx ingress) |
| `ingress-gke.yaml` | Rendered GCE Ingress manifest (default `gateway.example.com`) | `../ingress.yaml` (nginx ingress) |

## Custom Domain Templating

To render `ingress-gke.yaml` with your custom domain:

```bash
export GATEWAY_DOMAIN="gateway.your-domain.com"
envsubst < deployment/k8s/gcp/ingress-gke.yaml.tpl > deployment/k8s/gcp/ingress-gke.yaml
kubectl apply -f deployment/k8s/gcp/ingress-gke.yaml
```

Once applied, obtain the external load balancer ingress VIP:

```bash
kubectl get ingress gateway-ingress -n governance-stack -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Then create an `A` record in your DNS provider (or Google Cloud DNS) mapping `$GATEWAY_DOMAIN` to the ingress IP.

For deployments on EKS, AKS, OpenShift, or vanilla Kubernetes, use the standard manifests in `deployment/k8s/` instead.

