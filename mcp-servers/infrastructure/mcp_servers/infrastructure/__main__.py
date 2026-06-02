#!/usr/bin/env python3
"""
Infrastructure Management MCP Server

Provides tools for managing CAGE infrastructure deployments across
different environments and platforms.
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field


# Configuration
PROJECT_ROOT = Path(os.getenv("PROJECT_ROOT", os.getcwd()))
DEPLOY_SCRIPT = PROJECT_ROOT / "deploy_all.sh"


class ClusterStatusResult(BaseModel):
    """Result of cluster status check."""
    healthy: bool
    nodes: int
    context: str
    message: str


class DeploymentInfo(BaseModel):
    """Information about a deployment."""
    target: str
    environment: str
    status: str
    terraform_state: Optional[str] = None
    message: str


# Create server instance
app = Server("cage-infrastructure")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available infrastructure management tools."""
    return [
        Tool(
            name="check_cluster_status",
            description="Check Kubernetes cluster health and status. Returns node count, cluster context, and health status.",
            inputSchema={
                "type": "object",
                "properties": {
                    "context": {
                        "type": "string",
                        "description": "Optional kubectl context to check. Uses current context if not specified.",
                    }
                },
            },
        ),
        Tool(
            name="deploy_environment",
            description="Deploy CAGE to a specific infrastructure target and environment. Supports both new monorepo targets (agnostic, gcp-gke) and legacy deployment modes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Infrastructure target: 'agnostic' for k3d/kind, 'gcp-gke' for GKE, 'docker-compose' for local development",
                        "enum": ["agnostic", "gcp-gke", "docker-compose"],
                    },
                    "environment": {
                        "type": "string",
                        "description": "Deployment environment",
                        "enum": ["dev", "prod"],
                        "default": "dev",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Perform a dry run without actually deploying",
                        "default": False,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="get_deployment_info",
            description="Get current deployment status and information for a specific target and environment.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Infrastructure target to check",
                        "enum": ["agnostic", "gcp-gke"],
                    },
                    "environment": {
                        "type": "string",
                        "description": "Environment to check",
                        "enum": ["dev", "prod"],
                        "default": "dev",
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="validate_terraform",
            description="Validate Terraform configurations for a specific target without applying changes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Infrastructure target to validate",
                        "enum": ["agnostic", "gcp-gke"],
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="list_available_targets",
            description="List all available infrastructure deployment targets and their current status.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_deployment_script",
            description="Execute the deployment script with custom arguments. Use for advanced deployment scenarios.",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Arguments to pass to deploy_all.sh",
                    },
                },
                "required": ["args"],
            },
        ),
    ]


async def run_command(
    cmd: list[str],
    cwd: Optional[Path] = None,
    capture_output: bool = True,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """Run a shell command asynchronously."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            cwd=cwd or PROJECT_ROOT,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        
        return (
            process.returncode or 0,
            stdout.decode() if stdout else "",
            stderr.decode() if stderr else "",
        )
    except asyncio.TimeoutError:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", f"Error running command: {str(e)}"


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "check_cluster_status":
        context = arguments.get("context")
        
        # Build kubectl command
        cmd = ["kubectl", "get", "nodes", "-o", "json"]
        if context:
            cmd.extend(["--context", context])
        
        returncode, stdout, stderr = await run_command(cmd)
        
        if returncode != 0:
            result = ClusterStatusResult(
                healthy=False,
                nodes=0,
                context=context or "current",
                message=f"Failed to get cluster status: {stderr}",
            )
        else:
            try:
                nodes_data = json.loads(stdout)
                nodes = nodes_data.get("items", [])
                healthy_nodes = sum(
                    1 for node in nodes
                    if any(
                        condition.get("type") == "Ready" and condition.get("status") == "True"
                        for condition in node.get("status", {}).get("conditions", [])
                    )
                )
                
                # Get current context
                _, ctx_out, _ = await run_command(["kubectl", "config", "current-context"])
                current_context = ctx_out.strip() or "unknown"
                
                result = ClusterStatusResult(
                    healthy=healthy_nodes == len(nodes) and len(nodes) > 0,
                    nodes=len(nodes),
                    context=context or current_context,
                    message=f"Cluster has {len(nodes)} nodes, {healthy_nodes} healthy",
                )
            except json.JSONDecodeError:
                result = ClusterStatusResult(
                    healthy=False,
                    nodes=0,
                    context=context or "current",
                    message="Failed to parse cluster status",
                )
        
        return [TextContent(type="text", text=result.model_dump_json(indent=2))]
    
    elif name == "deploy_environment":
        target = arguments["target"]
        environment = arguments.get("environment", "dev")
        dry_run = arguments.get("dry_run", False)
        
        # Build deployment command
        if target == "docker-compose":
            cmd = [str(DEPLOY_SCRIPT)]
        else:
            cmd = [str(DEPLOY_SCRIPT), "--target", target, "--env", environment]
        
        if dry_run:
            message = f"Dry run: Would execute: {' '.join(cmd)}"
            result = {"status": "dry_run", "command": " ".join(cmd), "message": message}
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        # Actually run deployment
        returncode, stdout, stderr = await run_command(cmd, timeout=600)
        
        result = {
            "target": target,
            "environment": environment,
            "status": "success" if returncode == 0 else "failed",
            "returncode": returncode,
            "output": stdout,
            "errors": stderr if returncode != 0 else None,
        }
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "get_deployment_info":
        target = arguments["target"]
        environment = arguments.get("environment", "dev")
        
        # Check if terraform state exists
        terraform_dir = PROJECT_ROOT / "infra" / "targets" / target
        tfstate_file = terraform_dir / "terraform.tfstate"
        
        if not terraform_dir.exists():
            result = DeploymentInfo(
                target=target,
                environment=environment,
                status="not_found",
                message=f"Target directory not found: {terraform_dir}",
            )
        elif not tfstate_file.exists():
            result = DeploymentInfo(
                target=target,
                environment=environment,
                status="not_deployed",
                terraform_state="no_state",
                message=f"No terraform state found. Deployment may not exist.",
            )
        else:
            # Run terraform show to get current state
            cmd = ["terraform", "show", "-json"]
            returncode, stdout, stderr = await run_command(cmd, cwd=terraform_dir)
            
            if returncode == 0:
                result = DeploymentInfo(
                    target=target,
                    environment=environment,
                    status="deployed",
                    terraform_state="active",
                    message=f"Deployment exists and terraform state is valid",
                )
            else:
                result = DeploymentInfo(
                    target=target,
                    environment=environment,
                    status="unknown",
                    terraform_state="error",
                    message=f"Failed to read terraform state: {stderr}",
                )
        
        return [TextContent(type="text", text=result.model_dump_json(indent=2))]
    
    elif name == "validate_terraform":
        target = arguments["target"]
        terraform_dir = PROJECT_ROOT / "infra" / "targets" / target
        
        if not terraform_dir.exists():
            result = {
                "target": target,
                "valid": False,
                "message": f"Target directory not found: {terraform_dir}",
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        # Run terraform validate
        cmd = ["terraform", "validate", "-json"]
        returncode, stdout, stderr = await run_command(cmd, cwd=terraform_dir)
        
        try:
            validation_result = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            validation_result = {"error": "Failed to parse validation output"}
        
        result = {
            "target": target,
            "valid": returncode == 0 and validation_result.get("valid", False),
            "validation_output": validation_result,
            "errors": stderr if returncode != 0 else None,
        }
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "list_available_targets":
        targets_dir = PROJECT_ROOT / "infra" / "targets"
        
        targets = []
        if targets_dir.exists():
            for target_dir in targets_dir.iterdir():
                if target_dir.is_dir() and (target_dir / "main.tf").exists():
                    tfstate_file = target_dir / "terraform.tfstate"
                    targets.append({
                        "name": target_dir.name,
                        "path": str(target_dir),
                        "deployed": tfstate_file.exists(),
                    })
        
        result = {
            "available_targets": targets,
            "total": len(targets),
        }
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "run_deployment_script":
        args = arguments.get("args", [])
        cmd = [str(DEPLOY_SCRIPT)] + args
        
        returncode, stdout, stderr = await run_command(cmd, timeout=600)
        
        result = {
            "command": " ".join(cmd),
            "status": "success" if returncode == 0 else "failed",
            "returncode": returncode,
            "output": stdout,
            "errors": stderr if returncode != 0 else None,
        }
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Main entry point for the MCP server."""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
