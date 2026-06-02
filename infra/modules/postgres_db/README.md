# PostgreSQL Database Module

Deploys PostgreSQL database using the Bitnami Helm chart. Cloud-agnostic and suitable for Langfuse trace storage, audit logs, and general application use.

## Features

- ✅ Cloud-agnostic (works on any Kubernetes cluster)
- ✅ Automated password generation
- ✅ Persistent storage with configurable size
- ✅ Kubernetes Secret with connection details
- ✅ Optional automated backups
- ✅ Configurable resource limits

## Usage

### Basic Deployment

```hcl
module "postgres" {
  source = "../../modules/postgres_db"
  
  namespace = "my-namespace"
}
```

### Production Deployment

```hcl
module "postgres" {
  source = "../../modules/postgres_db"
  
  namespace               = "my-namespace"
  storage_size            = "100Gi"
  storage_class           = "pd-ssd"
  enable_backup           = true
  backup_schedule         = "0 2 * * *"  # 2 AM daily
  resources_limits_memory = "4Gi"
  resources_limits_cpu    = "2000m"
}
```

### Custom Database

```hcl
module "postgres" {
  source = "../../modules/postgres_db"
  
  namespace     = "my-namespace"
  database_name = "my_app"
  database_user = "app_user"
  release_name  = "my-postgres"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| namespace | Kubernetes namespace | string | - | yes |
| release_name | Helm release name | string | "postgresql" | no |
| chart_version | PostgreSQL Helm chart version | string | "15.5.38" | no |
| database_name | Database name | string | "langfuse" | no |
| database_user | Database user | string | "langfuse" | no |
| storage_size | PVC storage size | string | "50Gi" | no |
| storage_class | Storage class for PVC | string | "" | no |
| enable_persistence | Enable persistent storage | bool | true | no |
| enable_backup | Enable automated backups | bool | false | no |
| backup_schedule | Cron schedule for backups | string | "0 2 * * *" | no |
| resources_limits_memory | Memory limit | string | "" | no |
| resources_limits_cpu | CPU limit | string | "" | no |
| credentials_secret_name | Secret name for credentials | string | "langfuse-db-credentials" | no |

## Outputs

| Name | Description |
|------|-------------|
| release_name | Helm release name |
| service_name | Kubernetes service FQDN |
| connection_string | PostgreSQL connection string (sensitive) |
| database_url_secret_name | Kubernetes Secret name |
| database_name | Database name |
| database_user | Database user |
| password | Generated password (sensitive) |

## Accessing the Database

### From Another Pod

The module creates a Kubernetes Secret with all connection details:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: langfuse-db-credentials
              key: DATABASE_URL
```

### Port-Forward for Local Access

```bash
kubectl port-forward svc/postgresql 5432:5432 -n <namespace>
psql postgresql://langfuse:<password>@localhost:5432/langfuse
```

## Backups

Enable automated backups for production:

```hcl
enable_backup = true
backup_schedule = "0 2 * * *"  # Daily at 2 AM
```

Backups are stored in the PVC. For external backup solutions, configure separately.

## Monitoring

The Bitnami PostgreSQL chart includes:
- Liveness and readiness probes
- Metrics exporter (can be enabled)
- StatefulSet for data persistence

## Upgrading

To upgrade PostgreSQL version:

1. Update `chart_version` variable
2. Run `terraform plan` to review changes
3. Run `terraform apply`

Note: Major version upgrades may require data migration.
