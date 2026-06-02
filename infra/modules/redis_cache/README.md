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
