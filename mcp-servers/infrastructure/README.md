# CAGE Infrastructure Management MCP Server

A Model Context Protocol (MCP) server that provides infrastructure management capabilities for the Cybernetic Governance Engine (CAGE). This server enables both Google Antigravity agents and Roo Code to directly manage deployments, check cluster status, and interact with infrastructure from within your IDE.

## Features

This MCP server provides the following tools:

### 🔍 `check_cluster_status`
Check Kubernetes cluster health and status.

**Parameters:**
- `context` (optional): kubectl context to check. Uses current context if not specified.

**Returns:**
- Cluster health status
- Number of nodes and healthy nodes
- Current kubectl context

**Example:**
```json
{
  "healthy": true,
  "nodes": 3,
  "context": "cage-dev",
  "message": "Cluster has 3 nodes, 3 healthy"
}
```

### 🚀 `deploy_environment`
Deploy CAGE to a specific infrastructure target and environment.

**Parameters:**
- `target` (required): Infrastructure target (`agnostic`, `gcp-gke`, or `docker-compose`)
- `environment` (optional, default: `dev`): Deployment environment (`dev` or `prod`)
- `dry_run` (optional, default: `false`): Perform a dry run without actually deploying

**Returns:**
- Deployment status
- Command output
- Any errors encountered

### 📊 `get_deployment_info`
Get current deployment status and information.

**Parameters:**
- `target` (required): Infrastructure target to check
- `environment` (optional, default: `dev`): Environment to check

**Returns:**
- Deployment status
- Terraform state information
- Whether deployment exists

### ✅ `validate_terraform`
Validate Terraform configurations without applying changes.

**Parameters:**
- `target` (required): Infrastructure target to validate

**Returns:**
- Validation status
- Terraform validation output
- Any errors found

### 📋 `list_available_targets`
List all available infrastructure deployment targets.

**Parameters:** None

**Returns:**
- List of available targets
- Deployment status for each target
- Target paths

### 🛠️ `run_deployment_script`
Execute the deployment script with custom arguments (advanced).

**Parameters:**
- `args` (required): Array of arguments to pass to `deploy_all.sh`

**Returns:**
- Command executed
- Exit status
- Output and errors

## Installation

### Quick Start (Recommended)

Run the automated setup script to install and configure globally for both agents:

```bash
cd mcp-servers/infrastructure
./setup.sh
```

This script will:
- ✅ Install the MCP server package
- ✅ Configure Google Antigravity globally (`~/.gemini/antigravity/mcp_config.json`)
- ✅ Configure Roo Code globally (via symlink)
- ✅ Use absolute paths for universal availability
- ✅ Make the server available across ALL your projects

### Manual Installation

If you prefer manual setup:

```bash
# 1. Install the package
cd mcp-servers/infrastructure
pip install -e .

# 2. Get absolute path to Python
PYTHON_PATH=$(which python3)

# 3. Configure manually (see Configuration section)
```

## Configuration

### Automated Setup (Recommended)

The [`setup.sh`](./setup.sh) script automatically configures both agents globally. After running it, the MCP server will be available in ALL your projects, not just this one.

**Key Benefits:**
- ✅ Uses absolute paths to Python executable
- ✅ Single source of truth via symlinks
- ✅ Available across all workspaces
- ✅ No per-project configuration needed

### Manual Configuration

If you ran the automated setup, skip this section. For manual configuration:

#### For Google Antigravity

Add to `~/.gemini/antigravity/mcp_config.json` using **absolute paths**:

```json
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "/usr/bin/python3",
      "args": ["-m", "mcp_servers.infrastructure"],
      "env": {
        "PROJECT_ROOT": "/Users/yourusername/Code/cybernetic-governance-engine"
      }
    }
  }
}
```

**Important:** 
- Use `which python3` to get the absolute path to Python
- Replace PROJECT_ROOT with your actual project path

### For Roo Code

The automated setup script creates a **global symlink** at:
```
~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json
```

This symlink points to the Antigravity config, ensuring both agents share the same configuration.

#### Manual Symlink Setup

If needed, create the symlink manually:

```bash
mkdir -p ~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings
ln -sf ~/.gemini/antigravity/mcp_config.json \
  ~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROJECT_ROOT` | Path to CAGE repository root | Current working directory |

## Usage Examples

Once configured, both Antigravity and Roo Code agents can use these tools:

### Example 1: Check Cluster Status

**User prompt:**
> "Check the status of my Kubernetes cluster"

**Agent will use:** `check_cluster_status` tool

### Example 2: Deploy to Development

**User prompt:**
> "Deploy CAGE to the agnostic target in dev environment"

**Agent will use:** `deploy_environment` with `{"target": "agnostic", "environment": "dev"}`

### Example 3: Validate Terraform

**User prompt:**
> "Validate the Terraform configuration for GCP GKE"

**Agent will use:** `validate_terraform` with `{"target": "gcp-gke"}`

### Example 4: List Targets

**User prompt:**
> "What infrastructure targets are available?"

**Agent will use:** `list_available_targets`

## Development

### Project Structure

```
mcp-servers/infrastructure/
├── pyproject.toml           # Package configuration
├── README.md                # This file
└── mcp_servers/
    ├── __init__.py
    └── infrastructure/
        ├── __init__.py
        └── __main__.py      # Main MCP server implementation
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (when implemented)
pytest
```

### Debugging

To debug the MCP server:

1. **Check logs in Antigravity:**
   - Agent Panel > ... > View Logs

2. **Check logs in Roo Code:**
   - Output Panel > Roo Code

3. **Test the server manually:**
   ```bash
   # Test that the module can be imported
   python -c "from mcp_servers.infrastructure import __main__"
   
   # Check if kubectl is available
   kubectl version --client
   
   # Verify PROJECT_ROOT is set
   export PROJECT_ROOT=/path/to/cage
   python -m mcp_servers.infrastructure
   ```

## Security Considerations

### Credential Management

This MCP server executes system commands and may have access to:
- Kubernetes clusters (via kubectl)
- Cloud provider credentials (for GCP deployments)
- Terraform state files

**Best Practices:**

1. ✅ **Use workspace-scoped paths** where possible:
   ```json
   "PROJECT_ROOT": "${workspaceFolder}"
   ```

2. ✅ **Review tool calls** before agents execute them
   
3. ✅ **Use separate kubeconfig contexts** for dev/prod:
   ```bash
   kubectl config use-context cage-dev
   ```

4. ✅ **Limit permissions** via Kubernetes RBAC

5. ❌ **Never commit credentials** to the MCP configuration

### Command Execution

The server executes:
- `kubectl` commands (for cluster status)
- `terraform` commands (for validation and state)
- `deploy_all.sh` (for deployments)

All commands are executed within the `PROJECT_ROOT` directory with configurable timeouts.

## Troubleshooting

### Server Not Appearing

1. **Verify installation:**
   ```bash
   python -m mcp_servers.infrastructure --help
   ```

2. **Check MCP configuration syntax:**
   ```bash
   # For Antigravity
   cat ~/.gemini/antigravity/mcp_config.json | jq .
   
   # For Roo Code
   cat .roo/mcp.json | jq .
   ```

3. **Restart VS Code:**
   - Cmd+R (macOS) or Ctrl+R (Windows/Linux)

### kubectl Commands Failing

1. **Verify kubectl is installed:**
   ```bash
   kubectl version --client
   ```

2. **Check kubeconfig:**
   ```bash
   kubectl config current-context
   kubectl cluster-info
   ```

3. **Verify cluster access:**
   ```bash
   kubectl get nodes
   ```

### Terraform Commands Failing

1. **Verify Terraform is installed:**
   ```bash
   terraform version
   ```

2. **Check Terraform initialization:**
   ```bash
   cd infra/targets/agnostic
   terraform init
   ```

3. **Verify state files exist:**
   ```bash
   ls -la infra/targets/*/terraform.tfstate
   ```

### PROJECT_ROOT Not Set

If you see errors about missing files:

1. **Check environment variable:**
   ```bash
   echo $PROJECT_ROOT
   ```

2. **Update MCP configuration** to use absolute path or `${workspaceFolder}`

## Integration with CAGE Architecture

This MCP server is designed to work with CAGE's infrastructure architecture:

- **Monorepo targets:** Supports both `agnostic` (k3d/kind) and `gcp-gke` targets
- **Terraform modules:** Validates and checks state from `infra/targets/`
- **Deployment script:** Wraps `deploy_all.sh` for consistent deployments
- **Kubernetes integration:** Works with deployed clusters via kubectl

## Contributing

When adding new tools:

1. Add tool definition to `list_tools()`
2. Implement handler in `call_tool()`
3. Add usage example to this README
4. Update the MCP Integration Guide in `docs/MCP_INTEGRATION_GUIDE.md`

## License

Apache License 2.0 - See [LICENSE](../../LICENSE) file.

## Related Documentation

- [MCP Integration Guide](../../docs/MCP_INTEGRATION_GUIDE.md) - How to share configs between Antigravity and Roo Code
- [Infrastructure Deployment Guide](../../infra/DEPLOYMENT_GUIDE.md) - General deployment instructions
- [Model Context Protocol](https://modelcontextprotocol.io/) - Official MCP specification
