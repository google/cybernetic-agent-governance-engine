# Langfuse Stack Module

Deploys Langfuse observability platform for LLM application monitoring and tracing.

## Features

- ✅ Langfuse Web UI
- ✅ Langfuse Worker (background jobs)
- ✅ Automated secret generation
- ✅ PostgreSQL integration
- ✅ Configurable replicas
- ✅ Health checks

## Usage

```hcl
module "langfuse" {
  source = "../../modules/langfuse_stack"
  
  namespace    = "my-namespace"
  database_url = module.postgres.connection_string
  nextauth_url = "https://langfuse.example.com"
}
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| namespace | Kubernetes namespace | - |
| langfuse_image | Container image | "langfuse/langfuse:3" |
| database_url | PostgreSQL URL | - |
| nextauth_url | External URL | "http://localhost:3000" |
| web_replicas | Web replicas | 2 |
| worker_replicas | Worker replicas | 1 |

## Outputs

| Name | Description |
|------|-------------|
| web_url | Internal web URL |
| public_key | API public key |
| secret_key | API secret key |
