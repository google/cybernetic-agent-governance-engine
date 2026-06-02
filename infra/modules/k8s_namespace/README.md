# Kubernetes Namespace Module

Creates a Kubernetes namespace with standard labels and optional Pod Security Standards.

## Features

- Standardized labeling (managed-by, component, environment)
- Optional Pod Security Standards enforcement
- Flexible additional labels and annotations

## Usage

### Basic Usage

```hcl
module "namespace" {
  source = "../../modules/k8s_namespace"
  
  name        = "governance-stack"
  environment = "dev"
}
```

### With Pod Security Standards (Production)

```hcl
module "namespace" {
  source = "../../modules/k8s_namespace"
  
  name                         = "governance-stack"
  environment                  = "prod"
  enable_pod_security_standards = true
  pod_security_level           = "restricted"
  
  labels = {
    "compliance.nist.gov/control"  = "SC-39"
    "compliance.nist.gov/standard" = "SP-800-53-Rev5"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| name | Namespace name | string | - | yes |
| environment | Environment (dev, staging, prod) | string | "dev" | no |
| labels | Additional labels | map(string) | {} | no |
| annotations | Namespace annotations | map(string) | {} | no |
| enable_pod_security_standards | Enable Pod Security Standards | bool | false | no |
| pod_security_level | PSS level (privileged, baseline, restricted) | string | "baseline" | no |

## Outputs

| Name | Description |
|------|-------------|
| name | The created namespace name |
| id | The namespace resource ID |

## Pod Security Standards

When `enable_pod_security_standards = true`, the module applies Pod Security labels:

- **privileged**: No restrictions (dev only)
- **baseline**: Minimal restrictions (staging)
- **restricted**: Strict security (production)

See [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) for details.

## Examples

### Dev Environment (Permissive)

```hcl
module "namespace_dev" {
  source = "../../modules/k8s_namespace"
  
  name        = "governance-stack-dev"
  environment = "dev"
  # No Pod Security Standards for easier debugging
}
```

### Production Environment (Strict)

```hcl
module "namespace_prod" {
  source = "../../modules/k8s_namespace"
  
  name                         = "governance-stack"
  environment                  = "prod"
  enable_pod_security_standards = true
  pod_security_level           = "restricted"
  
  annotations = {
    "compliance.iso42001/classification" = "high"
  }
}
```
