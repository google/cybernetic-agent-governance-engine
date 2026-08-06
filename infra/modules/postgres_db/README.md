# PostgreSQL Database Module

Deploys PostgreSQL using the Bitnami Helm chart. Cloud-agnostic and suitable for Langfuse metadata storage, audit logs, and general application persistence.

## Features

- Cloud-agnostic (works on any Kubernetes cluster)
- Automated password generation via `random_password`
- Persistent storage with configurable size and storage class
- Kubernetes Secret created with all connection details
- Optional automated backups (CronJob-based)
- Configurable resource requests and limits

---

## Usage

### Basic deployment (dev)

```hcl
module "postgres" {
  source    = "../../modules/postgres_db"
  namespace = "governance-stack"
}
```

### Production deployment

```hcl
module "postgres" {
  source = "../../modules/postgres_db"

  namespace               = "governance-stack"
  storage_size            = "100Gi"
  storage_class           = "pd-ssd"
  enable_backup           = true
  backup_schedule         = "0 2 * * *"    # 2 AM daily
  resources_limits_memory = "4Gi"
  resources_limits_cpu    = "2000m"
  resources_requests_memory = "1Gi"
  resources_requests_cpu    = "500m"
}
```

### Custom database name and user

```hcl
module "postgres" {
  source = "../../modules/postgres_db"

  namespace     = "governance-stack"
  database_name = "langfuse"
  database_user = "langfuse"
  release_name  = "postgresql"
}
```

---

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `namespace` | Kubernetes namespace | string | — | yes |
| `release_name` | Helm release name | string | `"postgresql"` | no |
| `chart_version` | Bitnami PostgreSQL Helm chart version | string | `"18.5.6"` | no |
| `database_name` | Database name | string | `"langfuse"` | no |
| `database_user` | Database user | string | `"langfuse"` | no |
| `storage_size` | PVC storage size | string | `"50Gi"` | no |
| `storage_class` | Storage class for PVC (`""` = cluster default) | string | `""` | no |
| `enable_persistence` | Enable persistent storage | bool | `true` | no |
| `enable_backup` | Enable automated backups | bool | `false` | no |
| `backup_schedule` | Cron schedule for backups | string | `"0 2 * * *"` | no |
| `resources_requests_cpu` | CPU request | string | `"100m"` | no |
| `resources_requests_memory` | Memory request | string | `"256Mi"` | no |
| `resources_limits_cpu` | CPU limit (`""` = none) | string | `""` | no |
| `resources_limits_memory` | Memory limit (`""` = none) | string | `""` | no |
| `credentials_secret_name` | Kubernetes Secret name for credentials | string | `"langfuse-db-credentials"` | no |

---

## Outputs

| Name | Description |
|------|-------------|
| `release_name` | Helm release name |
| `service_name` | Kubernetes service FQDN |
| `connection_string` | PostgreSQL connection string (sensitive) |
| `database_url_secret_name` | Kubernetes Secret name |
| `database_name` | Database name |
| `database_user` | Database user |
| `password` | Generated password (sensitive) |

---

## Accessing PostgreSQL

### From another pod (via Secret)

```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: langfuse-db-credentials
        key: DATABASE_URL
```

### Port-forward for local access

```bash
kubectl port-forward svc/postgresql 5432:5432 -n governance-stack
psql postgresql://langfuse:<password>@localhost:5432/langfuse
```

### Get the generated password

```bash
kubectl get secret langfuse-db-credentials -n governance-stack \
  -o jsonpath='{.data.DATABASE_URL}' | base64 -d
```

---

## Storage Class Reference

Choose the appropriate storage class for your platform:

| Platform | Dev | Prod |
|----------|-----|------|
| k3s | `local-path` | `local-path` |
| minikube | `standard` | `standard` |
| kind | `standard` | `standard` |
| EKS | `gp2` | `gp3` |
| AKS | `default` | `managed-premium` |
| GKE | `standard-rwo` | `premium-rwo` (pd-ssd) |

---

## Backups

Enable automated backups for production:

```hcl
enable_backup   = true
backup_schedule = "0 2 * * *"   # Daily at 2 AM UTC
```

Backups are stored in the PostgreSQL PVC. For external backup solutions (e.g., Cloud Storage), configure an additional backup sidecar or CronJob separately.

---

## Upgrading

To upgrade the PostgreSQL Helm chart version:

1. Update `chart_version` in the module call
2. Run `terraform plan` to review changes
3. Run `terraform apply`

> **Note:** Major PostgreSQL version upgrades (e.g., 15 → 16) require a data dump/restore or pgupgrade procedure. Review the Bitnami chart release notes before upgrading major versions.

---

## See Also

- [`infra/modules/langfuse_stack/README.md`](../langfuse_stack/README.md) — Langfuse (primary consumer of this module)
- [`infra/modules/redis_cache/README.md`](../redis_cache/README.md) — Redis cache (required by Langfuse v3)
- [`infra/modules/clickhouse/README.md`](../clickhouse/README.md) — ClickHouse (required by Langfuse v3)
