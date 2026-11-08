# OPA Policy Bundle Module

Provisions the read-only Kubernetes `ConfigMap` bundle consumed by the gateway pod's
in-pod Open Policy Agent (OPA) Unix-domain-socket sidecar (`infra/modules/gateway`):

- `opa-policies` — immutable domain Rego policy bundle (e.g. `trade_governance.rego`)
- `opa-system-authz` — built-in `package system.authz` module enforced via
  `--authorization=basic`, denying runtime `PUT`, `PATCH`, and `DELETE` mutations on
  `/v1/policies` and `/v1/data` while permitting health checks, gateway startup
  `GET /v1/policies` verification, and read-only `GET`/`POST /v1/data/<package>`
  decision queries
- `opa-config` — OPA runtime configuration with `decision_logs.console: true` enabled
  by default so structured decision records reach Cloud Logging via container stdout

OPA exposes **no Kubernetes `Service`, no standalone `Deployment`, and zero TCP listener
ports**; only the gateway container inside the same pod can reach `/var/run/opa/opa.sock`
via `OPA_URL=http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock`.

## Usage

```hcl
module "opa" {
  source = "../../modules/opa_policy"

  namespace               = "cage"
  create_config_configmap = true

  policy_files = {
    "trade_governance.rego" = file("${path.module}/../../../src/cage_finance/opa/trade_governance.rego")
  }
}
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `namespace` | Kubernetes namespace | — |
| `create_policy_configmap` | Create read-only domain policy `ConfigMap` (`opa-policies`) | `true` |
| `create_config_configmap` | Create OPA config `ConfigMap` (`opa-config`) | `true` |
| `policy_files` | Map of Rego filename to content | `{}` |
| `opa_config` | OPA configuration YAML (`decision_logs.console: true`) | `decision_logs:\n  console: true\n` |

## Outputs

| Name | Description |
|------|-------------|
| `policies_config_map_name` | Name of the read-only domain policy `ConfigMap` |
| `system_authz_config_map_name` | Name of the `system.authz` immutability `ConfigMap` |
| `config_config_map_name` | Name of the OPA runtime configuration `ConfigMap` |
| `uds_socket_path` | Shared Unix socket path (`/var/run/opa/opa.sock`) |
| `uds_url` | URL-encoded `http+unix://` value for the gateway's `OPA_URL` |
| `bundle_sha256` | SHA-256 digest of policy, authz, and config inputs for pod rollout |
| `policy_files_data` | Mounted OPA policy files map in the `opa-policies` `ConfigMap` |
