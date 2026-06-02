# AgentSight Implementation Guide

This directory contains the deployment configuration for the **AgentSight** observability dashboard, which replaces our legacy "Tiered Observability" stack.

## Architecture

AgentSight operates as a **sidecar daemon** that uses eBPF to monitor your application from the kernel level. It bridges the gap between:

1.  **Intent (High Level):** It intercepts SSL/TLS traffic (OpenSSL boundaries) to see the decrypted LLM prompts and completions.
2.  **Action (Low Level):** It monitors kernel syscalls (e.g., `execve`, `openat`, `connect`) to see what the agent actually *did*.

By moving this heavy lifting out of the Python application, we reduce latency and CPU usage.

## Deployment Instructions

### Prerequisites

*   **Linux Host:** eBPF requires a Linux kernel (v5.10+ recommended).
*   **Docker:** With privileged capabilities.
*   **Kernel Headers:** Must be available on the host (usually installed via `linux-headers-$(uname -r)`).

### Running the Dashboard

1.  **Start the AgentSight Stack:**

    ```bash
    cd deployment/agentsight
    docker-compose -f docker-compose.agentsight.yaml up -d
    ```

    *   This starts the `agentsight-daemon` (privileged eBPF collector).
    *   This starts the `agentsight-dashboard` (UI).
    *   This starts your `governed-advisor` application.

2.  **Access the Dashboard:**
    Open your browser to `http://localhost:3000`.

3.  **Verify Observability:**
    Interact with your agent (e.g., trigger a trade). You should see:
    *   **Intent:** The LLM prompt asking to trade.
    *   **Action:** The system call or network request to the broker API.
    *   **Correlation:** A linked trace showing how the prompt *caused* the action.

## Configuration

The daemon is configured via `agentsight-config.yaml` (mounted in `docker-compose.agentsight.yaml`). Ensure it targets the correct process ID or container name.

## Troubleshooting

*   **"eBPF probe failed":** Ensure your Docker host allows privileged containers and has kernel headers mounted.
*   **"No traces":** Check if your application is using OpenSSL (standard Python `ssl` module works). Statically linked binaries (like Go) might need uprobes adjustment.
