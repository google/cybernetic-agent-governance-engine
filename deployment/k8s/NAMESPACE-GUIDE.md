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
| Redis (`redis-master`)    | `governance-stack` | ClusterIP | Write-only endpoint pinned to Sentinel primary (`redis-node-1`) |
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

## `redis-master` ClusterIP Service — `governance-stack`

### Problem

The existing `redis` Service selects **all** `redis-node` pods (primary + replicas)
and load-balances across them. When an in-cluster client or `kubectl port-forward`
lands on a replica, every write command (`SET`, `INCRBY`, `DEL`, …) fails with:

```
redis.exceptions.ReadOnlyError: You can't write against a read only replica.
```

This caused intermittent failures in the fiscal limit guard
([`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py))
and the LangGraph checkpointer, both of which issue write operations.

### Solution

[`deployment/k8s/redis-master-service.yaml`](redis-master-service.yaml) adds a
dedicated `redis-master` ClusterIP Service that uses the
`statefulset.kubernetes.io/pod-name` label — automatically applied by Kubernetes
to every StatefulSet pod — to pin traffic exclusively to the current Sentinel
primary pod (`redis-node-1` as of 2026-06-15).

```yaml
selector:
  statefulset.kubernetes.io/pod-name: redis-node-1
```

### Connection endpoints

| Endpoint | Port | Use for |
| -------- | ---- | ------- |
| `redis-master:6379` | 6379 | **Write operations** — `SET`, `INCRBY`, `DEL`, LangGraph checkpoints, fiscal counters |
| `redis:6379` | 6379 | **Read operations** — load-balanced across all nodes; suitable for read-only queries |

Within `governance-stack`, the short form `redis-master:6379` resolves correctly.
From other namespaces use the FQDN:

```
redis-master.governance-stack.svc.cluster.local:6379
```

### Sentinel failover — manual selector update required

The Bitnami Redis Sentinel chart does **not** add a dynamic role label to pods
after a failover. If Sentinel elects a new primary, the Service selector must be
patched to match the new primary pod name:

```bash
# 1. Find the current primary via Sentinel:
kubectl exec -n governance-stack redis-node-0 -c sentinel -- \
  redis-cli -p 26379 -a "$(kubectl get secret redis -n governance-stack \
    -o jsonpath='{.data.redis-password}' | base64 -d)" \
  SENTINEL masters | grep -A1 '^ip$'

# 2. Map the IP to a pod name:
kubectl get pods -n governance-stack -o wide | grep redis-node

# 3. Patch the selector to the new primary:
kubectl patch svc redis-master -n governance-stack \
  -p '{"spec":{"selector":{"statefulset.kubernetes.io/pod-name":"redis-node-X"}}}'
```

> **Current primary (2026-06-15):** `redis-node-1`

---

## Related files

- [`deployment/k8s/opa.yaml`](opa.yaml) — OPA Deployment, ConfigMap, Service
- [`deployment/k8s/redis-master-service.yaml`](redis-master-service.yaml) — `redis-master` ClusterIP Service (write endpoint)
- [`deployment/opa_config.yaml`](../opa_config.yaml) — OPA runtime configuration
- [`deployment/system_authz.rego`](../system_authz.rego) — System authorisation policy
- [`tests/test_opa_client.py`](../../tests/test_opa_client.py) — OPA integration tests
- [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py) — INCRBY fiscal counter (write path)
- [`src/gateway/infrastructure/redis_client.py`](../../src/gateway/infrastructure/redis_client.py) — Redis client configuration
