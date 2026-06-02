# ClickHouse Module

Deploys ClickHouse OLAP database using the Bitnami Helm chart.

## Purpose

ClickHouse is **required** for Langfuse v3, which uses a split database architecture:
- **PostgreSQL**: Transactional data (users, projects, API keys, settings, prompts)
- **ClickHouse**: Observability data (traces, observations, scores) - OLAP workloads

## Usage

```hcl
module "clickhouse" {
  source = "../../modules/clickhouse"
  
  namespace    = "governance-stack-dev"
  storage_size = "20Gi"
  replicas     = 1
  
  # Production settings
  enable_persistence  = true
  enable_pdb         = true
  storage_class      = "pd-ssd"
}
```

## Outputs

- `connection_string`: Full connection URL for Langfuse (sensitive)
- `service_name`: K8s service DNS name
- `http_port`: HTTP API port (8123)
- `tcp_port`: Native TCP port (9000)

## Langfuse v3 Integration

Langfuse v3 requires both databases:
- Set `DATABASE_URL` to PostgreSQL connection string
- Set `CLICKHOUSE_URL` to this module's `connection_string` output
