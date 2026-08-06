# Langfuse Stack Module

Deploys the Langfuse v3 observability platform for LLM application monitoring, tracing, and compliance audit logging.

## Architecture

Langfuse v3 requires four backing services:

| Component | Purpose |
|-----------|---------|
| PostgreSQL | Relational metadata store |
| ClickHouse | Trace/event columnar store (new in v3) |
| Redis | Queue and cache |
| S3-compatible blob store | Raw event uploads (MinIO or GCS) |

CAGE uses Langfuse as the **native OTLP ingestion target** — no standalone OpenTelemetry Collector is deployed. All services send traces directly to:

```
http://langfuse-web.<namespace>.svc.cluster.local:3000/api/public/otel/v1/traces
```

---

## Features

- Langfuse Web UI (`langfuse/langfuse:3`) with configurable replica count
- Langfuse Worker (`langfuse/langfuse-worker:3`) with configurable replica count
- Automated secret generation (NextAuth secret, salt, encryption key)
- PostgreSQL integration (connection string via `database_url`)
- ClickHouse integration (required for Langfuse v3)
- Redis integration (required for Langfuse v3 queuing/caching)
- S3-compatible blob storage (MinIO or GCS via HMAC keys)
- Headless project/org/user initialisation (no manual UI setup required)
- Configurable resource requests/limits
- Health checks (`/api/public/health`)

---

## Usage

### Basic (dev)

```hcl
module "langfuse" {
  source = "../../modules/langfuse_stack"

  namespace    = "governance-stack"
  database_url = module.postgres.connection_string

  clickhouse_url            = "http://clickhouse:8123"
  clickhouse_migration_url  = "clickhouse://default:password@clickhouse:9000/langfuse"
  clickhouse_password       = "your-clickhouse-password"

  redis_connection_string = "redis://:password@redis:6379"
  redis_host              = "redis.governance-stack.svc.cluster.local"

  nextauth_url = "http://localhost:3000"
}
```

### Production (with S3/GCS and headless init)

```hcl
module "langfuse" {
  source = "../../modules/langfuse_stack"

  namespace    = "governance-stack"
  database_url = module.postgres.connection_string

  # ClickHouse (required for Langfuse v3)
  clickhouse_url           = "http://clickhouse.governance-stack.svc.cluster.local:8123"
  clickhouse_migration_url = "clickhouse://default:${var.clickhouse_password}@clickhouse.governance-stack.svc.cluster.local:9000/langfuse"
  clickhouse_user          = "default"
  clickhouse_password      = var.clickhouse_password

  # Redis
  redis_connection_string = "redis://:${var.redis_password}@redis.governance-stack.svc.cluster.local:6379"
  redis_host              = "redis.governance-stack.svc.cluster.local"
  redis_port              = "6379"

  # S3-compatible blob storage (GCS via HMAC or MinIO)
  s3_endpoint    = "https://storage.googleapis.com"   # or "http://minio:9000"
  s3_bucket      = "my-project-langfuse-events"
  s3_access_key  = var.gcs_hmac_access_key
  s3_secret_key  = var.gcs_hmac_secret_key
  s3_region      = "us-central1"                      # must match GCS bucket region; not "auto"

  # External URL (for NextAuth callbacks)
  nextauth_url = "https://langfuse.example.com"

  # Replicas
  web_replicas    = 2
  worker_replicas = 2

  # Headless project/org init (no manual UI setup required)
  langfuse_public_key          = var.langfuse_public_key
  langfuse_secret_key          = var.langfuse_secret_key
  langfuse_init_user_email     = "admin@example.com"
  langfuse_init_project_name   = "cybernetic-governance"
  langfuse_init_project_id     = "cybernetic-governance"
  langfuse_init_org_id         = "CAGE"
  langfuse_init_org_name       = "CAGE"
}
```

---

## Inputs

### Core

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `namespace` | Kubernetes namespace | string | — | yes |
| `database_url` | PostgreSQL connection URL | string (sensitive) | — | yes |
| `nextauth_url` | External URL of Langfuse | string | `"http://localhost:3000"` | no |
| `langfuse_image` | Langfuse web container image | string | `"langfuse/langfuse:3"` | no |
| `langfuse_worker_image` | Langfuse worker container image | string | `"langfuse/langfuse-worker:3"` | no |

### ClickHouse (required for Langfuse v3)

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `clickhouse_url` | ClickHouse HTTP URL | string (sensitive) | `""` |
| `clickhouse_migration_url` | ClickHouse migration URL (golang-migrate) | string (sensitive) | `""` |
| `clickhouse_user` | ClickHouse user | string | `"default"` |
| `clickhouse_password` | ClickHouse password | string (sensitive) | `""` |

### Redis (required for Langfuse v3)

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `redis_connection_string` | Full Redis connection string | string (sensitive) | `""` |
| `redis_host` | Redis host | string | `""` |
| `redis_port` | Redis port | string | `"6379"` |

### S3-compatible blob storage

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `s3_endpoint` | S3 endpoint URL (MinIO or `https://storage.googleapis.com` for GCS) | string | `""` |
| `s3_bucket` | Bucket name for event uploads | string | `""` |
| `s3_access_key` | S3 access key (or GCS HMAC access key) | string (sensitive) | `""` |
| `s3_secret_key` | S3 secret key (or GCS HMAC secret key) | string (sensitive) | `""` |
| `s3_region` | S3 region — must match GCS bucket region; must not be `"auto"` | string | `"us-east-1"` |

### Replicas and resources

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `web_replicas` | Number of web replicas | number | `2` |
| `worker_replicas` | Number of worker replicas | number | `1` |
| `service_type` | Kubernetes service type | string | `"ClusterIP"` |
| `web_memory_request` | Web memory request | string | `"512Mi"` |
| `web_cpu_request` | Web CPU request | string | `"100m"` |
| `web_memory_limit` | Web memory limit | string | `"2Gi"` |
| `web_cpu_limit` | Web CPU limit | string | `"1000m"` |
| `worker_memory_request` | Worker memory request | string | `"512Mi"` |
| `worker_cpu_request` | Worker CPU request | string | `"100m"` |
| `worker_memory_limit` | Worker memory limit | string | `"2Gi"` |
| `worker_cpu_limit` | Worker CPU limit | string | `"1000m"` |

### Headless initialisation

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `langfuse_public_key` | Pre-existing Langfuse public key | string (sensitive) | `""` |
| `langfuse_secret_key` | Pre-existing Langfuse secret key | string (sensitive) | `""` |
| `langfuse_init_user_email` | Initial admin user email | string | `""` |
| `langfuse_init_user_password` | Initial admin user password | string (sensitive) | `""` |
| `langfuse_init_project_name` | Initial project name | string | `""` |
| `langfuse_init_project_id` | Initial project ID | string | `""` |
| `langfuse_init_org_id` | Initial org ID | string | `""` |
| `langfuse_init_org_name` | Initial org name | string | `""` |

---

## Outputs

| Name | Description |
|------|-------------|
| `web_url` | Internal web URL (ClusterIP) |
| `public_key` | Langfuse API public key |
| `secret_key` | Langfuse API secret key (sensitive) |

---

## OTLP Integration

All CAGE services send traces to Langfuse's native OTLP HTTP endpoint. No standalone collector is required.

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://langfuse-web.<namespace>.svc.cluster.local:3000/api/public/otel/v1/traces
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic <base64(public_key:secret_key)>
```

The `LANGFUSE_BASIC_AUTH_B64` secret in `advisor-secrets` carries the pre-encoded header value.

---

## GCS as S3-compatible Store

Langfuse event uploads work with GCS via HMAC keys (S3 interoperability):

```
s3_endpoint = "https://storage.googleapis.com"
s3_region   = "us-central1"   # must match actual GCS bucket region
```

> **Data residency note (DEP-07):** `s3_region` must not be `"auto"`. Set it to the GCS bucket region that matches `CAGE_DEPLOYMENT_REGION`:
> - `US_FED` → `us-central1`
> - `EU_ECB` → `europe-west1`
> - `APAC_MAS` → `asia-southeast1`

---

## HPA (autoscaling)

The worker HPA (`langfuse-worker-hpa.yaml`) scales 2–15 replicas at 70% CPU / 80% memory utilisation. It is applied separately from this Terraform module via `deployment/k8s/langfuse-worker-hpa.yaml`.

---

## See Also

- [`deployment/k8s/langfuse-web.yaml`](../../../deployment/k8s/langfuse-web.yaml) — static Langfuse Web manifest
- [`deployment/k8s/langfuse-worker.yaml`](../../../deployment/k8s/langfuse-worker.yaml) — static Langfuse Worker manifest
- [`deployment/k8s/langfuse-worker-hpa.yaml`](../../../deployment/k8s/langfuse-worker-hpa.yaml) — HPA
- [`infra/modules/postgres_db/README.md`](../postgres_db/README.md) — PostgreSQL module
- [`infra/modules/clickhouse/README.md`](../clickhouse/README.md) — ClickHouse module
