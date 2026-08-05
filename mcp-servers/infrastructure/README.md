# CAGE Infrastructure Management MCP Server

A Model Context Protocol (MCP) server that provides infrastructure management capabilities for the Cybernetic Governance Engine (CAGE). This server enables AI assistants (Roo Code, Gemini CLI, etc.) to directly manage deployments, check cluster status, and interact with CAGE infrastructure from within your IDE.

---

## Tools

### 🔍 `check_cluster_status`

Check Kubernetes cluster health and status.

**Parameters:**
- `context` (optional): kubectl context to check. Uses current context if not specified.

**Returns:**
```json
{
  "healthy": true,
  "nodes": 3,
  "context": "<your-cluster-context>",
  "message": "Cluster has 3 nodes, 3 healthy"
}
```

---

### 🚀 `deploy_environment`

Deploy CAGE to a specific infrastructure target and environment.

**Parameters:**
- `target` (required): Infrastructure target — `agnostic`, `gcp-gke`, or `docker-compose`
- `environment` (optional, default: `dev`): `dev` or `prod`
- `dry_run` (optional, default: `false`): Print the command without executing

**Returns:**
- Deployment status
- Command output
- Any errors encountered

---

### 📊 `get_deployment_info`

Get current deployment status and Terraform state information.

**Parameters:**
- `target` (required): Infrastructure target to check
- `environment` (optional, default: `dev`): Environment to check

**Returns:**
- Deployment status
- Terraform state summary
- Whether a deployment exists

---

### ✅ `validate_terraform`

Validate Terraform configurations without applying changes.

**Parameters:**
- `target` (required): Infrastructure target to validate (`agnostic` or `gcp-gke`)

**Returns:**
- Validation status
- Terraform validation output
- Any errors found

---

### 📋 `list_available_targets`

List all available infrastructure deployment targets.

**Parameters:** None

**Returns:**
- List of available targets (`agnostic`, `gcp-gke`)
- Deployment status for each target
- Target directory paths

---

### 🛠️ `run_deployment_script`

Execute `deploy_all.sh` with custom arguments (advanced use).

**Parameters:**
- `args` (required): Array of arguments to pass to `deploy_all.sh`

**Returns:**
- Command executed
- Exit status
- stdout and stderr

---

## Installation

### Prerequisites

- Python ≥ 3.11
- `kubectl` configured with cluster access
- `terraform` ≥ 1.5.0
- `deploy_all.sh` accessible at `PROJECT_ROOT/deploy_all.sh`

### Install the package

```bash
cd mcp-servers/infrastructure
pip install -e .
```

Or with `uv`:

```bash
uv pip install -e mcp-servers/infrastructure
```

### Verify

```bash
python -m mcp_servers.infrastructure --help
```

---

## Configuration

### For Roo Code (`.roo/mcp.json`)

Create or update `.roo/mcp.json` in the repository root:

```json
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "/usr/bin/python3",
      "args": ["-m", "mcp_servers.infrastructure"],
      "env": {
        "PROJECT_ROOT": "/absolute/path/to/cybernetic-governance-engine"
      }
    }
  }
}
```

**Important:**
- Use the absolute path returned by `which python3` (not a relative path)
- Replace `PROJECT_ROOT` with the absolute path to your local clone (the output of `pwd` from the project root)
- See `mcp-servers/infrastructure/mcp.json.example` for a template

### For Gemini CLI (`~/.gemini/mcp_config.json`)

```json
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "/usr/bin/python3",
      "args": ["-m", "mcp_servers.infrastructure"],
      "env": {
        "PROJECT_ROOT": "/absolute/path/to/cybernetic-governance-engine"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROJECT_ROOT` | Absolute path to CAGE repository root | Current working directory |

---

## Usage Examples

### Check cluster status

**Prompt:** "Check the status of my Kubernetes cluster"  
**Tool called:** `check_cluster_status`

### Deploy to development

**Prompt:** "Deploy CAGE to the agnostic target in dev environment"  
**Tool called:** `deploy_environment` with `{"target": "agnostic", "environment": "dev"}`

### Deploy to GCP GKE

**Prompt:** "Deploy CAGE to GCP GKE in production with US_FED compliance"  
**Tool called:** `run_deployment_script` with:
```json
{
  "args": [
    "--target", "gcp-gke",
    "--env", "prod",
    "--var-file=infra/targets/gcp-gke/prod.tfvars",
    "--auto-approve"
  ]
}
```

### Validate Terraform

**Prompt:** "Validate the Terraform configuration for GCP GKE"  
**Tool called:** `validate_terraform` with `{"target": "gcp-gke"}`

### List targets

**Prompt:** "What infrastructure targets are available?"  
**Tool called:** `list_available_targets`

---

## Project Structure

```
mcp-servers/infrastructure/
├── mcp.json.example             # MCP configuration template
├── pyproject.toml               # Package configuration (Python ≥ 3.11, mcp ≥ 0.9.0)
├── README.md                    # This file
└── mcp_servers/
    ├── __init__.py
    └── infrastructure/
        ├── __init__.py
        └── __main__.py          # MCP server implementation (6 tools)
```

---

## Development

### Install dev dependencies

```bash
pip install -e "mcp-servers/infrastructure[dev]"
```

### Run tests

```bash
cd mcp-servers/infrastructure
pytest
```

### Debugging

1. **Check that the module imports cleanly:**
   ```bash
   python -c "from mcp_servers.infrastructure import __main__"
   ```

2. **Verify kubectl is available:**
   ```bash
   kubectl version --client
   kubectl config current-context
   ```

3. **Verify PROJECT_ROOT is set:**
   ```bash
   export PROJECT_ROOT=/path/to/cybernetic-governance-engine
   python -m mcp_servers.infrastructure
   ```

4. **Check Roo Code MCP logs:**
   - Output Panel → Roo Code (MCP)

---

## Security Considerations

This MCP server executes system commands and has access to:
- Kubernetes clusters (via `kubectl`)
- Cloud provider credentials (for GCP deployments via `gcloud`)
- Terraform state files
- `deploy_all.sh` (which reads `.env` secrets)

**Best practices:**

1. **Use absolute paths** — never relative paths in the MCP configuration
2. **Review tool calls** before agents execute them — especially `run_deployment_script`
3. **Use separate kubeconfig contexts** for dev and prod
4. **Limit RBAC permissions** on the configured kubectl context
5. **Never commit credentials** to the MCP configuration

### Commands executed by the server

| Tool | Commands |
|------|----------|
| `check_cluster_status` | `kubectl get nodes`, `kubectl config current-context` |
| `deploy_environment` | `./deploy_all.sh --target ... --env ...` |
| `get_deployment_info` | `terraform -chdir=... show -json` |
| `validate_terraform` | `terraform -chdir=... init`, `terraform -chdir=... validate` |
| `list_available_targets` | filesystem traversal of `infra/targets/` |
| `run_deployment_script` | `./deploy_all.sh <args>` |

All commands run within `PROJECT_ROOT` with a configurable timeout.

---

## Troubleshooting

### Server not appearing in Roo Code

1. **Verify installation:**
   ```bash
   python -m mcp_servers.infrastructure --help
   ```

2. **Check MCP configuration syntax:**
   ```bash
   cat .roo/mcp.json | python3 -m json.tool
   ```

3. **Restart VS Code** (Cmd+R on macOS, Ctrl+R on Windows/Linux)

### `kubectl` commands failing

```bash
kubectl version --client
kubectl config current-context
kubectl cluster-info
kubectl get nodes
```

### Terraform commands failing

```bash
terraform version

# Initialize the target first
cd infra/targets/agnostic
terraform init -backend-config="config_path=~/.kube/config"

# Check state file
ls -la infra/targets/*/terraform.tfstate
```

### `PROJECT_ROOT` not set or wrong

```bash
echo $PROJECT_ROOT
# Should be the absolute path to the repo root
# e.g. /Users/yourname/Code/cybernetic-governance-engine
```

---

## Integration with CAGE Architecture

This MCP server wraps the same entry points used by human operators:

| MCP Tool | Underlying mechanism |
|----------|---------------------|
| `deploy_environment` | `deploy_all.sh --target ... --env ...` |
| `validate_terraform` | `terraform validate` in `infra/targets/<target>/` |
| `get_deployment_info` | `terraform show -json` in `infra/targets/<target>/` |
| `check_cluster_status` | `kubectl get nodes` with current context |
| `run_deployment_script` | `deploy_all.sh` with arbitrary args |

---

## Contributing

When adding new tools:

1. Add the tool definition to `list_tools()` in `__main__.py`
2. Implement the handler in `call_tool()` in `__main__.py`
3. Add a usage example to this README
4. Update [`docs/MCP_SETUP.md`](../../docs/MCP_SETUP.md)

---

## Related Documentation

- [`docs/MCP_SETUP.md`](../../docs/MCP_SETUP.md) — full MCP setup guide
- [`infra/QUICK_START.md`](../../infra/QUICK_START.md) — infrastructure quick start
- [`infra/DEPLOYMENT_GUIDE.md`](../../infra/DEPLOYMENT_GUIDE.md) — deployment reference
- [`deploy_all.sh`](../../deploy_all.sh) — underlying deployment orchestration script
- [Model Context Protocol specification](https://modelcontextprotocol.io/)
