# Deploying Langfuse v3 on Kubernetes

This directory contains the configuration for deploying a self-hosted Langfuse v3 stack on Kubernetes.

## Architecture

The Langfuse v3 deployment on Kubernetes consists of:

- **Langfuse Web**: Next.js frontend and API server (`langfuse-web`).
- **Langfuse Worker**: Asynchronous event processor (`langfuse-worker`).
- **Langfuse OTLP Ingestion**: Langfuse v3 exposes a native OTLP/HTTP endpoint — services export traces directly to Langfuse without a standalone OpenTelemetry Collector. (The standalone `otel-collector` sidecar was deprecated 2026-05-31.)
- **ClickHouse**: OLAP database for high-volume trace data (Single-node statefulset).
- **MinIO**: S3-compatible object storage for raw event ingestion (Required for v3).
- **Redis**: Queue and caching (shared with other services).
- **PostgreSQL**: Metadata storage (Cloud SQL on GCP, or any PostgreSQL for other Kubernetes providers).

> **Note on Deployment Strategy:** CAGE deploys Langfuse v3 in-cluster alongside the governance stack via [`infra/modules/langfuse_stack/`](../../infra/modules/langfuse_stack/main.tf) (backed by Cloud SQL PostgreSQL in [`infra/modules/cloudsql_postgres/`](../../infra/modules/cloudsql_postgres/main.tf), ClickHouse in [`infra/modules/clickhouse_operator/`](../../infra/modules/clickhouse_operator/main.tf), and regional GCS/S3 storage) rather than a disjoint cluster/VPC, preserving low-latency trace export inside `governance-stack`.

## Prerequisites

1.  **Kubernetes Cluster**: A GKE cluster provisioned via `deploy_all.sh --target gcp-gke`.
2.  **Secret Manager**: Secrets populated via Terraform (`module.app_secrets` / `module.langfuse`).
3.  **kubectl**: Configured to point to your cluster.

## Deployment

The Langfuse v3 stack is reconciled automatically by Terraform (`module.langfuse` in [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)):

```bash
./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID>
```

## Object Storage Configuration

Langfuse v3 requires S3-compatible object storage for raw event ingestion (`LANGFUSE_S3_*` configured in `infra/modules/langfuse_stack/main.tf` against regional GCS HMAC or local MinIO in Compose).

## Accessing Langfuse

Port-forward the web service to access the UI:

```bash
kubectl port-forward svc/langfuse-web 3001:80 -n governance-stack
```

Visit `http://localhost:3001`.

## Troubleshooting

- **500 Errors on Startup**: Check `REDIS_HOST` and `REDIS_PORT` env vars.
- **Ingestion Hangs**: Verify MinIO connectivity and that the `langfuse-events` bucket exists.
- **ClickHouse Connection**: Ensure `advisor-secrets` has the correct `CLICKHOUSE_PASSWORD`.
