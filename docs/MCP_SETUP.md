# MCP Server Setup

CAGE exposes an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that allows AI assistants and development tools to interact with the governance infrastructure.

## Overview

The MCP server is located at [`mcp-servers/infrastructure/`](../mcp-servers/infrastructure/) and provides tools for:

- Querying governance policy decisions
- Inspecting compliance posture
- Triggering Lula validation runs
- Accessing OSCAL artifacts

## Prerequisites

- Python 3.11+
- `uv` package manager (`pip install uv`)
- A running CAGE gateway (see [Quick Start](../infra/QUICK_START.md))

## Installation

```bash
cd mcp-servers/infrastructure
uv sync
```

## Configuration

The MCP server requires the following environment variables:

```bash
# Gateway connection
CAGE_GATEWAY_URL=http://localhost:8080

# Authentication (if enabled)
CAGE_API_KEY=<your-api-key>

# Optional: Langfuse observability
LANGFUSE_PUBLIC_KEY=<your-langfuse-public-key>
LANGFUSE_SECRET_KEY=<your-langfuse-secret-key>
LANGFUSE_HOST=https://cloud.langfuse.com
```

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your values
```

## Running the MCP Server

```bash
cd mcp-servers/infrastructure
uv run python -m mcp_servers.infrastructure
```

The server starts on `stdio` by default (for use with MCP-compatible clients).

## Connecting Your AI Assistant

### VS Code / Cursor / Windsurf

Add the following to your MCP configuration file (location varies by tool — check your tool's documentation):

```json
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/cybernetic-governance-engine/mcp-servers/infrastructure",
        "run",
        "python",
        "-m",
        "mcp_servers.infrastructure"
      ],
      "env": {
        "CAGE_GATEWAY_URL": "http://localhost:8080"
      }
    }
  }
}
```

Replace `/path/to/cybernetic-governance-engine` with the absolute path to your local clone.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/cybernetic-governance-engine/mcp-servers/infrastructure",
        "run",
        "python",
        "-m",
        "mcp_servers.infrastructure"
      ]
    }
  }
}
```

## Available Tools

Once connected, your AI assistant can use the following MCP tools:

| Tool | Description |
|---|---|
| `get_compliance_posture` | Returns current Lula validation results |
| `query_opa_policy` | Evaluates an OPA policy decision |
| `get_oscal_component` | Retrieves an OSCAL component definition |
| `list_governance_controls` | Lists active governance controls |

## Troubleshooting

**Server fails to start:** Ensure `uv sync` completed successfully and all dependencies are installed.

**Connection refused:** Verify the CAGE gateway is running at the configured `CAGE_GATEWAY_URL`.

**Authentication errors:** Check that `CAGE_API_KEY` matches the value configured in the gateway.

For additional help, see [SUPPORT.md](../SUPPORT.md).
