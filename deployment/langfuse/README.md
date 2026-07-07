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

> **Note on Deployment Strategy:** We explicitly use custom Kubernetes manifests deployed via `deploy_sw.py` rather than the official Langfuse Terraform Module. Deploying the official Terraform module would provision a completely disjointed Kubernetes cluster and VPC, leading to cross-cluster latency, cloud egress fees, and duplicated infrastructure costs. Co-locating Langfuse with our vLLM stack in the `governance-stack` namespace is required for our high-performance Agentic Gateway pattern.

## Prerequisites

1.  **Kubernetes Cluster**: A running Kubernetes cluster (GKE recommended for GCP deployments).
2.  **Secret Manager**: Secrets must be populated in `advisor-secrets`.
3.  **kubectl**: Configured to point to your cluster.

## Deployment

The deployment is managed via the main `deployment/deploy_sw.py` script, but can be applied manually:

```bash
kubectl apply -f deployment/k8s/minio.yaml
kubectl apply -f deployment/k8s/langfuse-db.yaml
kubectl apply -f deployment/k8s/langfuse-web.yaml
kubectl apply -f deployment/k8s/langfuse-worker.yaml
```

## MinIO Configuration

Langfuse v3 **requires** S3-compatible storage. We use a self-hosted MinIO instance for this purpose to keep costs low and avoid external dependencies for development environments.

- **Bucket**: `langfuse-events` (Automatically created by `mc-setup` job or manual setup).
- **Access**: Cluster-internal only via `http://minio.governance-stack.svc.cluster.local:9000`.

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
