# Redis Cache Module

Deploys Redis using the Bitnami Helm chart for caching, session storage, and state management.

## Features

- ✅ Cloud-agnostic (works on any Kubernetes cluster)
- ✅ Automated password generation
- ✅ Standalone or replicated architecture
- ✅ Optional Redis Sentinel for HA
- ✅ Persistent storage with configurable size
- ✅ Kubernetes Secret with connection details
- ✅ Optional Redis Stack Server (JSON, Search, etc.)

## Usage

### Basic Deployment (Development)

```hcl
module "redis" {
  source = "../../modules/redis_cache"
  
  namespace           = "my-namespace"
  enable_persistence  = false  # Ephemeral for dev
}
```

### Production Deployment (HA)

```hcl
module "redis" {
  source = "../../modules/redis_cache"
  
  namespace               = "my-namespace"
  architecture            = "replication"
  replica_count           = 3
  enable_sentinel         = true
  storage_size            = "20Gi"
  storage_class           = "fast-ssd"
  resources_limits_memory = "2Gi"
  resources_limits_cpu    = "1000m"
}
```

### Redis Stack (with JSON support)

```hcl
module "redis" {
  source = "../../modules/redis_cache"
  
  namespace       = "my-namespace"
  use_redis_stack = true  # Includes RedisJSON, RedisSearch, etc.
}
```

### Custom Password

```hcl
module "redis" {
  source = "../../modules/redis_cache"
  
  namespace = "my-namespace"
  password  = var.redis_password  # From sensitive variable
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| namespace | Kubernetes namespace | string | - | yes |
| release_name | Helm release name | string | "redis" | no |
| chart_version | Redis Helm chart version | string | "19.6.4" | no |
| password | Redis password (auto-generated if empty) | string | "" | no |
| enable_auth | Enable Redis authentication | bool | true | no |
| architecture | standalone or replication | string | "standalone" | no |
| replica_count | Number of replicas (for replication) | number | 3 | no |
| enable_sentinel | Enable Redis Sentinel for HA | bool | false | no |
| enable_persistence | Enable persistent storage | bool | true | no |
| storage_size | PVC storage size | string | "10Gi" | no |
| storage_class | Storage class for PVC | string | "" | no |
| resources_limits_memory | Memory limit | string | "" | no |
| resources_limits_cpu | CPU limit | string | "" | no |
| use_redis_stack | Use Redis Stack Server | bool | false | no |
| create_credentials_secret | Create credentials Secret | bool | true | no |
| credentials_secret_name | Secret name | string | "redis-credentials" | no |

## Outputs

| Name | Description |
|------|-------------|
| release_name | Helm release name |
| service_name | Kubernetes service FQDN |
| redis_host | Redis host address |
| redis_port | Redis port (6379) |
| redis_url | Redis connection URL (sensitive) |
| password | Redis password (sensitive) |
| credentials_secret_name | Kubernetes Secret name |

## Accessing Redis

### From Another Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      env:
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: REDIS_URL
```

### Port-Forward for Local Access

```bash
kubectl port-forward svc/redis-master 6379:6379 -n <namespace>
redis-cli -a <password>
```

### Test Connection

```bash
# Get password
kubectl get secret redis-credentials -n <namespace> -o jsonpath='{.data.REDIS_PASSWORD}' | base64 -d

# Connect
kubectl run redis-test --rm -it --image=redis -- redis-cli -h redis-master -a <password> ping
# Should return: PONG
```

## Architecture Options

### Standalone (Default)

Single Redis instance. Suitable for development or non-critical workloads.

```hcl
architecture = "standalone"
```

### Replication (HA)

Master-replica setup with multiple read replicas.

```hcl
architecture   = "replication"
replica_count  = 3
enable_sentinel = true  # Automatic failover
```

---

## Redis Sentinel Topology & Primary Routing

### Topology Overview

When `enable_sentinel = true` and `architecture = "replication"`, the Bitnami
chart deploys a StatefulSet of Redis nodes (e.g. `redis-node-0`,
`redis-node-1`, `redis-node-2`) each running both a Redis server and a
Sentinel sidecar. Sentinel monitors the cluster and elects one pod as the
**primary**; the remaining pods become **read-only replicas**.

```
┌─────────────────────────────────────────────────────────┐
│  governance-stack namespace                             │
│                                                         │
│  redis-node-0  ──┐                                      │
│  redis-node-1  ──┼──► svc/redis (ClusterIP, all pods)  │
│  redis-node-2  ──┘                                      │
│                                                         │
│  redis-node-1 (current primary)                         │
│       └──────────► svc/redis-master (ClusterIP, pinned) │
└─────────────────────────────────────────────────────────┘
```

### Service Endpoints

| Service | Selector | Use for |
|---------|----------|---------|
| `redis:6379` | All `redis-node-*` pods (load-balanced) | Reads, general queries |
| `redis-master:6379` | Single primary pod only (pinned) | **Writes** (SET, INCRBY, DEL, …) |

The `redis-master` Service is defined in
[`deployment/k8s/redis-master-service.yaml`](../../../deployment/k8s/redis-master-service.yaml)
and uses the `statefulset.kubernetes.io/pod-name` label — automatically
applied by Kubernetes to every StatefulSet pod — to pin traffic to the
current Sentinel primary.

### The `ReadOnlyError` Problem

The standard `svc/redis` ClusterIP load-balances across **all** pods
(primary + replicas). When a client connection is routed to a replica, any
write command fails immediately:

```
redis.exceptions.ReadOnlyError: You can't write against a read only replica.
```

This affected components such as
[`fiscal_limit_guard.py`](../../../src/gateway/governance/fiscal_limit_guard.py)
(which issues `INCRBY` on a daily fiscal counter) and
[`redis_client.py`](../../../src/gateway/infrastructure/redis_client.py).

**Fix:** route all write traffic through `redis-master:6379` instead of
`redis:6379`. The `redis-master` Service selector pins connections to the
single primary pod, so writes never land on a replica.

### Configuring Clients

```python
# Writes — always use redis-master
write_client = redis.Redis(host="redis-master", port=6379, password=...)

# Reads — use the standard service (load-balanced across all nodes)
read_client  = redis.Redis(host="redis", port=6379, password=...)
```

In pod environment variables:

```yaml
env:
  - name: REDIS_WRITE_HOST
    value: "redis-master"          # pinned to primary
  - name: REDIS_READ_HOST
    value: "redis"                 # load-balanced
  - name: REDIS_PORT
    value: "6379"
  - name: REDIS_PASSWORD
    valueFrom:
      secretKeyRef:
        name: redis-credentials
        key: REDIS_PASSWORD
```

### Sentinel Failover Procedure

> ⚠️ **Manual step required after every Sentinel-elected failover.**
>
> The Bitnami Redis Sentinel chart does **not** add a dynamic role label to
> pods after a failover. When Sentinel elects a new primary, the
> `redis-master` Service selector must be updated to point to the new primary
> pod name.

**Step 1 — Identify the current primary via Sentinel:**

```bash
kubectl exec -n governance-stack redis-node-0 -c sentinel -- \
  redis-cli -p 26379 \
  -a "$(kubectl get secret redis -n governance-stack \
        -o jsonpath='{.data.redis-password}' | base64 -d)" \
  SENTINEL masters | grep -A1 '^ip$'
```

**Step 2 — Map the IP to a pod name:**

```bash
kubectl get pods -n governance-stack -o wide | grep redis-node
```

**Step 3 — Patch the `redis-master` selector:**

```bash
# Replace redis-node-X with the new primary pod name
kubectl patch svc redis-master -n governance-stack \
  -p '{"spec":{"selector":{"statefulset.kubernetes.io/pod-name":"redis-node-X"}}}'
```

**Step 4 — Verify writes succeed:**

```bash
kubectl run redis-write-test --rm -it --image=redis -- \
  redis-cli -h redis-master -p 6379 \
  -a "$(kubectl get secret redis-credentials -n governance-stack \
        -o jsonpath='{.data.REDIS_PASSWORD}' | base64 -d)" \
  SET cage:failover-test ok
# Expected: OK
```

> 💡 **Automation note:** A future improvement is to run a small controller
> (or a post-failover hook in Sentinel) that automatically patches the
> `redis-master` selector when the primary changes. Until then, this is a
> manual operational step that must be included in any runbook for Sentinel
> failover events.

---

## Persistence

### Development (No Persistence)

```hcl
enable_persistence = false
```

Data is lost on pod restart.

### Production (Persistent)

```hcl
enable_persistence = true
storage_size       = "20Gi"
storage_class      = "fast-ssd"
```

Data survives pod restarts.

## Redis Stack

Redis Stack Server includes:
- RedisJSON - Native JSON support
- RediSearch - Full-text search
- RedisGraph - Graph database
- RedisTimeSeries - Time series data
- RedisBloom - Probabilistic data structures

```hcl
use_redis_stack = true
```

## Monitoring

The Bitnami Redis chart includes:
- Liveness and readiness probes
- Optional Prometheus metrics exporter
- StatefulSet for data persistence

## Security

- Password authentication enabled by default
- TLS can be configured via Helm values
- Network policies can restrict access

## Troubleshooting

### Check Redis Status

```bash
kubectl get pods -l app.kubernetes.io/name=redis -n <namespace>
```

### View Logs

```bash
kubectl logs -l app.kubernetes.io/name=redis -n <namespace>
```

### Check Persistence

```bash
kubectl get pvc -l app.kubernetes.io/name=redis -n <namespace>
```
