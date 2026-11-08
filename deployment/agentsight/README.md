# AgentSight Deployment Guide

AgentSight is a kernel-level observability tool that uses eBPF probes to intercept SSL/TLS traffic and monitor system calls made by Python agent processes — without modifying application code.

CAGE deploys AgentSight via:

1. **Local Docker Compose** — `docker-compose.agentsight.yaml` (this directory)
2. **AgentSight UI on GKE** — [`infra/modules/agentsight_ui/main.tf`](../../infra/modules/agentsight_ui/main.tf) (the unmanaged eBPF DaemonSet `de5534ac:deployment/k8s/agentsight-daemon.yaml` was retired with `deployment/k8s/` pending Terraform module `POAM-2026-193`)

---

## Architecture

AgentSight correlates two planes of observability:

| Plane | Mechanism | What it captures |
|-------|-----------|-----------------|
| **Intent** | OpenSSL uprobes | Decrypted LLM prompts and completions at SSL boundary |
| **Action** | syscall tracepoints | `execve`, `openat`, `connect`, `socket`, `bind` — what the agent actually did |

The daemon exports correlated traces to an AgentSight UI backend over HTTP.

**Target pattern:** `python3` (matches all CAGE Python agent processes).

---

## Prerequisites

- **Linux kernel ≥ 5.10** (eBPF CO-RE support)
- **Kernel headers** installed on the host: `linux-headers-$(uname -r)`
- **Root / privileged container** (eBPF program loading requires `SYS_ADMIN`)
- **OpenSSL ≥ 3.x** on the target host (library path: `/usr/lib/x86_64-linux-gnu/libssl.so.3`)

> **EU_ECB / APAC_MAS note:** SSL interception captures all pod-level network traffic, which may include personal data. A DPIA (GDPR Art. 35) or equivalent privacy impact assessment is required before deploying to EU_ECB or APAC_MAS (originally noted as DEP-06 in retired `de5534ac:deployment/k8s/agentsight-daemon.yaml`).

---

## Local Docker Compose

### Start the AgentSight stack

```bash
cd deployment/agentsight
docker-compose -f docker-compose.agentsight.yaml up -d
```

This starts three services:

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `agentsight-daemon` | `ghcr.io/agent-sight/agentsight-daemon:latest` | host network | eBPF collector (privileged) |
| `agentsight-dashboard` | `ghcr.io/agent-sight/agentsight-dashboard:latest` | 3000 | Visualization UI |
| `governed-advisor` | built from `Dockerfile` (repo root) | 8080 | Your governed agent |

### Access the dashboard

Open `http://localhost:3000` in your browser.

### Verify observability

Interact with the agent (e.g., trigger a trade request). The dashboard should show:

- **Intent:** The LLM prompt requesting the trade
- **Action:** The syscall or network request executed
- **Correlation:** Linked trace connecting prompt → action

### Configuration

The daemon reads `agentsight-config.yaml` (mounted at `/etc/agentsight/config.yaml`):

```yaml
daemon:
  log_level: "info"
  target_pattern: "python3"   # monitors all processes matching this pattern

probes:
  ssl:
    enabled: true
    library_path: "/usr/lib/x86_64-linux-gnu/libssl.so.3"  # adjust for your base image
  syscalls:
    enabled: true
    events:
      - execve
      - openat
      - connect
      - socket
      - bind

exporter:
  type: "remote"          # sends events to Dashboard backend
  endpoint: "http://agentsight-dashboard:8080"
  # Use "console" for local debugging only
```

### Required Docker privileges

The daemon container **must** run with:

```yaml
privileged: true   # required for eBPF program loading
pid: host          # required to see processes across PID namespaces
network_mode: host # required to monitor network interfaces
```

Volume mounts required:

| Host path | Container path | Mode | Purpose |
|-----------|---------------|------|---------|
| `/sys/kernel/debug` | `/sys/kernel/debug` | `rw` | eBPF tracing filesystem |
| `/lib/modules` | `/lib/modules` | `ro` | Kernel module metadata |
| `/usr/src` | `/usr/src` | `ro` | Kernel headers (CO-RE) |

### Telemetry routing

The `governed-advisor` service in this Compose file sends traces directly to Langfuse's native OTLP ingestion endpoint (Langfuse v3):

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://langfuse-web:3000/api/public/otel/v1/traces
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

No standalone Jaeger or OpenTelemetry Collector is deployed.

---

## Kubernetes DaemonSet (`POAM-2026-193`)

The unmanaged `de5534ac:deployment/k8s/agentsight-daemon.yaml` DaemonSet was retired with `deployment/k8s/`; first-class Terraform provisioning of the eBPF DaemonSet is tracked under `POAM-2026-193`. The AgentSight UI frontend is reconciled by Terraform via [`infra/modules/agentsight_ui/main.tf`](../../infra/modules/agentsight_ui/main.tf).

### Namespace Requirements (`POAM-2026-193`)

When provisioned in-cluster, the DaemonSet runs in an isolated `agentsight` namespace (not `governance-stack`) with PSA label `privileged` (`hostPID=true`, `hostNetwork=true`, `privileged=true`) and exports to:

```
endpoint: "http://agentsight-ui.governance-stack.svc.cluster.local:8080"
```

---

## Troubleshooting

### "eBPF probe failed" / permission denied

The daemon requires `privileged: true` and the following Linux capabilities:
- `SYS_ADMIN` — eBPF program loading, perf events
- `NET_ADMIN` — network socket/interface manipulation
- `SYS_PTRACE` — process inspection across PID namespaces
- `SYS_RESOURCE` — raise rlimits for eBPF map memory

Ensure Docker or the container runtime allows privileged containers.

### "No traces appearing"

1. Verify the application uses OpenSSL (standard Python `ssl` module does; statically linked Go binaries may not).
2. Confirm `library_path` in `agentsight-config.yaml` matches the actual libssl location on the host:
   ```bash
   find /usr/lib -name "libssl.so*"
   ```
3. Check daemon logs:
   ```bash
   docker-compose -f docker-compose.agentsight.yaml logs agentsight-daemon
   # or in Kubernetes:
   kubectl logs -n agentsight -l app=agentsight-daemon
   ```

### Kernel headers not found

Install kernel headers on the host (required for eBPF CO-RE):

```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install kernel-devel-$(uname -r)
```

---

## Related Files

- [`infra/modules/agentsight_ui/main.tf`](../../infra/modules/agentsight_ui/main.tf) — AgentSight UI Terraform Deployment
- [`deployment/agentsight/agentsight-config.yaml`](agentsight-config.yaml) — daemon configuration
- [`deployment/agentsight/docker-compose.agentsight.yaml`](docker-compose.agentsight.yaml) — local Compose stack
- [`docs/operations/HOW_TO_DEMO_OBSERVABILITY.md`](../../docs/operations/HOW_TO_DEMO_OBSERVABILITY.md) — observability demo guide
