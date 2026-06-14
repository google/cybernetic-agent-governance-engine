# Kubernetes Namespace Guide — Cybernetic Governance Engine

> **Reference:** See `deployment/k8s/opa.yaml` for the OPA deployment that
> this document covers. See `ARCHITECTURE.md` for the broader service map.

---

## Namespace Inventory

| Service                   | Namespace          | Type      | Notes                          |
| ------------------------- | ------------------ | --------- | ------------------------------ |
| OPA (`opa-service`)       | `governance-stack` | ClusterIP | Migrated from `default` (R-24) |
| Financial Advisor backend | `governance-stack` | ClusterIP | Canonical app namespace        |
| NeMo Guardrails           | `governance-stack` | —         | Integrated into gateway process (in-process, not a standalone service) |
| vLLM inference (fast)     | `governance-stack` | ClusterIP | Qwen2.5-7B-Instruct            |
| vLLM reasoning            | `governance-stack` | ClusterIP | QwQ-32B reasoning model        |
| Compliance Bridge         | `governance-stack` | ClusterIP | OSCAL/audit workflow           |
| Redis (db 0)              | `governance-stack` | ClusterIP | LangGraph checkpoint store     |
| Redis (db 1)              | `governance-stack` | ClusterIP | Evidence state store (noeviction) |
| Langfuse web              | `governance-stack` | ClusterIP | Observability UI               |
| AgentSight daemon         | `governance-stack` | DaemonSet | Node-level telemetry           |

---

## OPA namespace — `governance-stack`

OPA (`deployment/k8s/opa.yaml`) was originally deployed in `default` before the
`governance-stack` namespace was created (Rev1 → Rev2 restructuring). It has
now been migrated to `governance-stack` as part of the R-24 remediation.

All three OPA Kubernetes objects — Deployment, Service, and the
`opa-compliance-status` ConfigMap — now reside in `governance-stack`.

---

## In-cluster ClusterIP connectivity

Kubernetes ClusterIP services are reachable from any namespace using the
fully-qualified DNS name:

```
<service-name>.<namespace>.svc.cluster.local:<port>
```

OPA is now reachable at:

```
http://opa-service.governance-stack.svc.cluster.local:8181
```

The shorter form `opa-service:8181` works within `governance-stack` itself.

Check `config/settings.py` / `OPA_URL` env var to verify the current OPA URL
used by the backend.

---

## Related files

- [`deployment/k8s/opa.yaml`](opa.yaml) — OPA Deployment, ConfigMap, Service
- [`deployment/opa_config.yaml`](../opa_config.yaml) — OPA runtime configuration
- [`deployment/system_authz.rego`](../system_authz.rego) — System authorisation policy
- [`tests/test_opa_client.py`](../../tests/test_opa_client.py) — OPA integration tests
