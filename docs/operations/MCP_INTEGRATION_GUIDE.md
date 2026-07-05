# Google Antigravity MCP Integration Guide

This guide describes how to configure, run, and manage **Model Context Protocol (MCP)** servers natively within **Google Antigravity**.

The Model Context Protocol (MCP) is an open standard that allows AI engines and agentic systems to securely connect to external tools, APIs, and local resources.

---

## 1. Antigravity MCP Architecture

Google Antigravity includes deep, built-in support for MCP. Unlike proprietary extension-specific custom instructions, MCP servers provide standard, type-safe, and executable tools that the agent can interact with fluidly.

### Configuration File Path

Antigravity stores its MCP server definitions in a global configuration file:

```
~/.gemini/antigravity-ide/mcp_config.json
```

---

## 2. Configuration Options

Antigravity supports both **local subprocess** and **secure cloud-based** MCP servers.

### A. Local Python Subprocesses (Virtual Environment Isolation)

For local custom tools (e.g. CAGE infrastructure management or GPU orchestrators), always use the absolute path to your project's virtual environment python executable. This ensures all python dependencies are found and loaded cleanly:

> **Note:** Replace `<path-to-project>` with the absolute path to your local clone of this repository (e.g. the output of `pwd` from the project root).

```json
"cage-infrastructure": {
  "command": "<path-to-project>/.venv/bin/python",
  "args": [
    "-m",
    "mcp_servers.infrastructure"
  ],
  "env": {
    "PROJECT_ROOT": "<path-to-project>"
  }
}
```

### B. Secure Cloud-based Services (Native Auth Integration)

For official cloud-based MCP endpoints (e.g. Google Developer Knowledge), Antigravity integrates directly with Google Cloud and your IDE's active session credentials using `authProviderType`:

```json
"google-developer-knowledge": {
  "serverUrl": "https://developerknowledge.googleapis.com/mcp",
  "authProviderType": "google_credentials"
}
```

This secure, native schema eliminates the need to run local commands or shell scripts (like `gcloud` subprocesses) and automatically handles credentials securely.

### C. Node.js Local Executables

For servers installed under your local `~/.mcp` directory, you can run them using the system's `node` executable directly:

```json
"langfuse": {
  "command": "node",
  "args": [
    "<path-to-mcp-node-modules>/.bin/melt-langfuse-mcp"
  ],
  "env": {
    "LANGFUSE_PUBLIC_KEY": "${env:LANGFUSE_PUBLIC_KEY}",
    "LANGFUSE_SECRET_KEY": "${env:LANGFUSE_SECRET_KEY}",
    "LANGFUSE_HOST": "${env:LANGFUSE_HOST}"
  }
}
```

---

## 3. Custom CAGE Infrastructure Server

This repository contains a custom CAGE infrastructure manager located at `mcp-servers/infrastructure`.

### Installation

1. Install it inside the workspace's virtual environment:
   ```bash
   cd mcp-servers/infrastructure
   ../../.venv/bin/pip install -e .
   ```
2. Verify that the CLI executes cleanly:
   ```bash
   ../../.venv/bin/python -m mcp_servers.infrastructure --help
   ```

---

## 4. Security Best Practices

1. **Keep Secrets Out of Version Control**: Never commit active API keys, database passwords, or personal project paths to configuration files. Use environment variable substitution (`${env:VARIABLE}`) inside the `mcp_config.json` file.
2. **Review Code First**: Before enabling any community or third-party MCP server locally, review its source code and setup requirements to prevent security issues.
3. **Use Isolated Runtimes**: Always use virtual environment-bound runtimes (`.venv/bin/python`) for custom tools rather than system-wide global interpreters.
