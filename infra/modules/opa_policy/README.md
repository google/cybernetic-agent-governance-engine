# OPA Policy Module

Deploys Open Policy Agent for policy-as-code enforcement.

## Features

- ✅ OPA deployment with configurable replicas
- ✅ Policy ConfigMap support
- ✅ Configuration ConfigMap support
- ✅ Health checks and diagnostics
- ✅ ISO 42001 compliance annotations

## Usage

### Basic Deployment

```hcl
module "opa" {
  source = "../../modules/opa_policy"
  
  namespace = "my-namespace"
}
```

### With Policies

```hcl
module "opa" {
  source = "../../modules/opa_policy"
  
  namespace = "my-namespace"
  
  policy_files = {
    "authz.rego" = file("${path.module}/policies/authz.rego")
    "trade.rego" = file("${path.module}/policies/trade.rego")
  }
}
```

### With Configuration

```hcl
module "opa" {
  source = "../../modules/opa_policy"
  
  namespace               = "my-namespace"
  create_config_configmap = true
  opa_config              = <<-EOT
    decision_logs:
      console: true
    status:
      console: true
  EOT
}
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| namespace | Kubernetes namespace | - |
| image | OPA image | "openpolicyagent/opa:latest-static" |
| replicas | Replicas | 1 |
| create_policy_configmap | Create policy ConfigMap | true |
| create_config_configmap | Create config ConfigMap | false |
| policy_files | Policy files map | {} |
| opa_config | OPA config YAML | "" |

## Outputs

| Name | Description |
|------|-------------|
| endpoint_url | OPA API URL |
| diagnostics_url | Diagnostics URL |

## Testing Policies

```bash
# Check policy loaded
curl http://opa:8181/v1/policies

# Test decision
curl -X POST http://opa:8181/v1/data/authz/allow \
  -d '{"input": {"user": "alice", "action": "read"}}'
```
