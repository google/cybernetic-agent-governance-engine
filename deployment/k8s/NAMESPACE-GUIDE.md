# Kubernetes Namespace Guide — Cybernetic Governance Engine

> **Reference:** See `deployment/k8s/pod-security-admission.yaml` for namespace PSA labels,
> `deployment/k8s/opa.yaml` for the OPA deployment, and `deployment/k8s/vllm-namespace.yaml`
> for the vLLM namespace. See `docs/architecture/ARCHITECTURE.md` for the broader service map.

---

## Namespace Inventory

| Namespace | PSA Level | Description |
|-----------|-----------|-------------|
| `governance-stack` | `restricted` | All application workloads |
| `vllm-inference` | `baseline` | vLLM GPU inference workloads |
| `agentsight` | `privileged` | AgentSight eBPF DaemonSet |

---

## `governance-stack` — Application Namespace

All CAGE application services run in `governance-stack`. The namespace enforces Pod Security Standards `restricted:latest` (ISO 42001 A.6.1 / A.8.2):

- No privileged containers
- No host namespaces or host paths
- No root user (`runAsNonRoot: true`)
- No privilege escalation
- Requires `RuntimeDefault` or `Localhost` seccomp profile

### Service inventory

| Service | K8s Kind | K8s Name | Port(s) | Notes |
|---------|----------|----------|---------|-------|
| Gateway (HTTP) | Deployment + NodePort Service | `gateway` | 8080 (http), 50051 (grpc), NodePort 30080 | Exposes NodePort for GCE Ingress backend |
| Gateway HPA | HPA | `gateway-hpa` | — | 1–5 replicas at 50% CPU |
| Governed Financial Advisor | Deployment + ClusterIP Service | `governed-financial-advisor` | 80 → 8080 | ServiceAccount: `financial-advisor-sa` |
| OPA policy engine | Deployment + ClusterIP Service | `opa-service` | 8181 (policy), 8282 (diagnostics) | Package: `trade.governance` |
| NeMo Guardrails | Deployment + ClusterIP Service | `nemo-service` | 8000 | |
| Compliance Bridge | Deployment + ClusterIP Service | `compliance-bridge` | 80 → 3001 | 150s startup delay (dowhy/matplotlib) |
| Langfuse Web | Deployment + ClusterIP Service | `langfuse-web` | 80 → 3000 | 2 replicas; avoids Spot nodes |
| Langfuse Worker | Deployment | `langfuse-worker` | — | |
| Langfuse Worker HPA | HPA | `langfuse-worker-hpa` | — | 2–15 replicas (70% CPU / 80% memory) |
| ClickHouse | StatefulSet + Service | `clickhouse` | 8123 (http), 9000 (native) | Required by Langfuse v3 |
| MinIO | Deployment + Service | `minio` | 9000 (api), 9001 (console) | Langfuse event storage |
| Redis (Bitnami Sentinel) | StatefulSet (3 pods) + Services | `redis-node-{0,1,2}` | 6379 (redis), 26379 (sentinel) | Active Sentinel-mode cluster |
| Redis write endpoint | ClusterIP Service | `redis-master` | 6379 | Pinned to current Sentinel primary |
| vLLM fast proxy | ExternalName Service | `vllm-service` | 8000 | Proxies → `vllm-service.vllm-inference` |
| vLLM reasoning proxy | ExternalName Service | `vllm-reasoning` | 8000 | Proxies → `vllm-reasoning.vllm-inference` |
| AgentSight UI | Deployment + ClusterIP Service | `agentsight-ui` | 80 | Visualization frontend |

---

## `vllm-inference` — GPU Inference Namespace

vLLM workloads require GPU/CUDA access, which is incompatible with the `restricted` PSS profile. This namespace uses `baseline` to permit the required elevated privileges.

**PSA label:** `pod-security.kubernetes.io/enforce: baseline`  
**Compliance label:** `cage.io/iso42001-control: A.8.4`, `cage.io/pss-exception: gpu-cuda-access`

US_FED deployments additionally satisfy NIST SC-39 via the same PSS controls.

### Services in `vllm-inference`

| K8s Name | Port | Description |
|----------|------|-------------|
| `vllm-service` | 8000 | Fast-path inference (Qwen2.5-7B-Instruct) |
| `vllm-reasoning` | 8000 | Reasoning inference (QwQ-32B or DeepSeek R1) |

Cross-namespace service discovery: pods in `governance-stack` reach vLLM via `ExternalName` Services defined in `deployment/k8s/vllm-services.yaml`. These ExternalName Services proxy `vllm-service.governance-stack` → `vllm-service.vllm-inference.svc.cluster.local`, so existing env vars (`VLLM_BASE_URL`, `VLLM_FAST_API_BASE`, `VLLM_REASONING_API_BASE`) require no changes.

---

## `agentsight` — eBPF Observability Namespace

The AgentSight DaemonSet (`deployment/k8s/agentsight-daemon.yaml`) requires:
- `hostPID: true`
- `hostNetwork: true`
- `privileged: true`

These are blocked by `governance-stack`'s `restricted` PSA profile. The `agentsight` namespace must be labelled `privileged`:

```bash
kubectl create namespace agentsight
kubectl label namespace agentsight \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged
```

---

## In-cluster ClusterIP Connectivity

Kubernetes ClusterIP services are reachable from any namespace using the fully-qualified DNS name:

```
<service-name>.<namespace>.svc.cluster.local:<port>
```

### Key in-cluster endpoints

| Service | FQDN | Port |
|---------|------|------|
| OPA | `opa-service.governance-stack.svc.cluster.local` | 8181 |
| Gateway | `gateway.governance-stack.svc.cluster.local` | 8080 |
| Governed FA | `governed-financial-advisor.governance-stack.svc.cluster.local` | 80 |
| Langfuse Web | `langfuse-web.governance-stack.svc.cluster.local` | 3000 (or :80 via Service) |
| Redis (read) | `redis.governance-stack.svc.cluster.local` | 6379 |
| Redis (write) | `redis-master.governance-stack.svc.cluster.local` | 6379 |
| vLLM fast | `vllm-service.governance-stack.svc.cluster.local` | 8000 |
| vLLM reasoning | `vllm-reasoning.governance-stack.svc.cluster.local` | 8000 |
| Compliance Bridge | `compliance-bridge.governance-stack.svc.cluster.local` | 80 |
| ClickHouse | `clickhouse.governance-stack.svc.cluster.local` | 8123 |

The short form `<service-name>:<port>` works from within `governance-stack` itself.

---

## OPA — `governance-stack`

OPA (`deployment/k8s/opa.yaml`) was originally deployed in `default` before the `governance-stack` namespace was created (Rev1 → Rev2 restructuring). It was migrated to `governance-stack` as part of the R-24 remediation.

All three OPA Kubernetes objects — Deployment (`opa-service`), Service (`opa-service`), and the `opa-compliance-status` ConfigMap — reside in `governance-stack`.

OPA is reachable at:

```
http://opa-service.governance-stack.svc.cluster.local:8181
```

The shorter form `opa-service:8181` works within `governance-stack` itself.

The gateway uses a different URL for OPA (appending the data path):

```
http://opa.governance-stack.svc.cluster.local:8181/v1/data/trade/governance
```

Check `config/settings.py` / `OPA_URL` env var to verify the current OPA URL used by each service.

---

## Redis Topology

### Active cluster: Bitnami Sentinel (`redis-node`)

The active Redis cluster is the Bitnami Helm-managed `redis-node` StatefulSet (3 pods) running in Sentinel mode:

- `redis-node-0` — pod 0 (replica or primary depending on Sentinel election)
- `redis-node-1` — pod 1 (Sentinel primary as of 2026-06-15)
- `redis-node-2` — pod 2 (replica)

> **DEPRECATED:** `deployment/k8s/redis-statefulset.yaml` defines a conflicting single-node `redis` StatefulSet. This file is retained for reference only — do **NOT** apply it to the cluster. The active cluster is `redis-node` (3/3 Running, Sentinel mode).

### Dual-use: db 0 and db 1

| Database | Purpose |
|----------|---------|
| db 0 | LangGraph checkpoint store |
| db 1 | Evidence stream + deferred gating tokens (`noeviction` policy) |

### `redis-master` ClusterIP — write endpoint

**Problem:** The existing `redis` Service selects all `redis-node` pods (primary + replicas) and load-balances across them. When a write command (`SET`, `INCRBY`, `DEL`, …) lands on a replica, it fails with:

```
redis.exceptions.ReadOnlyError: You can't write against a read only replica.
```

This caused intermittent failures in the fiscal limit guard (`src/gateway/governance/fiscal_limit_guard.py`) and the LangGraph checkpointer.

**Solution:** `deployment/k8s/redis-master-service.yaml` adds a dedicated `redis-master` ClusterIP Service that uses the `statefulset.kubernetes.io/pod-name` label to pin traffic exclusively to the current Sentinel primary pod (`redis-node-1` as of 2026-06-15).

```yaml
selector:
  statefulset.kubernetes.io/pod-name: redis-node-1
```

### Connection endpoints

| Endpoint | Port | Use for |
|----------|------|---------|
| `redis-master:6379` | 6379 | **Write operations** — `SET`, `INCRBY`, `DEL`, LangGraph checkpoints, fiscal counters |
| `redis:6379` | 6379 | **Read operations** — load-balanced across all nodes |

Within `governance-stack`, the short form resolves correctly. From other namespaces use the FQDN:

```
redis-master.governance-stack.svc.cluster.local:6379
```

### Sentinel failover — manual selector update required

The Bitnami Redis Sentinel chart does **not** add a dynamic role label to pods after failover. If Sentinel elects a new primary, the `redis-master` Service selector must be patched:

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

## Langfuse Observability Stack

Langfuse v3 runs entirely within `governance-stack`. It requires:

- **PostgreSQL** (`langfuse-db`) for relational metadata
- **ClickHouse** (`clickhouse`) for trace/event storage (new in v3)
- **Redis** (`redis`) for queuing and caching
- **MinIO** (`minio`) for S3-compatible event blob storage

Telemetry from all CAGE services is sent directly to Langfuse's native OTLP endpoint:

```
http://langfuse-web.governance-stack.svc.cluster.local:3000/api/public/otel/v1/traces
```

No standalone OpenTelemetry Collector is deployed.

---

## Related Files

| File | Description |
|------|-------------|
| [`deployment/k8s/pod-security-admission.yaml`](pod-security-admission.yaml) | PSA labels for `governance-stack`, `langfuse`, `vllm` namespaces |
| [`deployment/k8s/vllm-namespace.yaml`](vllm-namespace.yaml) | `vllm-inference` namespace (PSA: baseline) |
| [`deployment/k8s/agentsight-daemon.yaml`](agentsight-daemon.yaml) | AgentSight DaemonSet (namespace: `agentsight`) |
| [`deployment/k8s/opa.yaml`](opa.yaml) | OPA Deployment, ConfigMaps, Service |
| [`deployment/k8s/redis-master-service.yaml`](redis-master-service.yaml) | `redis-master` write-only ClusterIP |
| [`deployment/k8s/redis-stack-fresh.yaml`](redis-stack-fresh.yaml) | Active Bitnami Redis Sentinel StatefulSet |
| [`deployment/k8s/redis-statefulset.yaml`](redis-statefulset.yaml) | **DEPRECATED** — do not apply |
| [`deployment/k8s/vllm-services.yaml`](vllm-services.yaml) | ExternalName Services proxying vLLM into `governance-stack` |
| [`deployment/k8s/langfuse-web.yaml`](langfuse-web.yaml) | Langfuse Web Deployment + Service |
| [`deployment/opa_config.yaml`](../opa_config.yaml) | OPA runtime configuration |
| [`deployment/system_authz.rego`](../system_authz.rego) | System authorisation policy |
| [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py) | INCRBY fiscal counter (Redis write path) |
| [`src/gateway/infrastructure/redis_client.py`](../../src/gateway/infrastructure/redis_client.py) | Redis client configuration |
