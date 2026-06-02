# agentsight-ui

React + TypeScript + Vite SPA that serves as the **Kernel Dashboard** for the Cybernetic Governance Engine. It connects to the [`compliance-bridge-ts`](../compliance_bridge_ts/) service via **Server-Sent Events (SSE)** and displays real-time governance telemetry, ISO 42001 compliance metrics, and kernel-level observability data from the AgentSight eBPF DaemonSet.

---

## Architecture

```
agentsight-ui (React SPA)
    │
    ├── SSE  GET /v1/events/stream   ──▶  compliance-bridge-ts (port 3001)
    ├── REST GET /v1/metrics/:id     ──▶  compliance-bridge-ts (port 3001)
    └── REST GET /health             ──▶  compliance-bridge-ts (port 3001)
```

The Vite dev server proxies `/v1/` → `http://localhost:3001` (see [`vite.config.ts`](vite.config.ts)), so no CORS configuration is required during local development.

---

## Key Component: `KernelDashboard.tsx`

[`src/KernelDashboard.tsx`](src/KernelDashboard.tsx) is the primary view, implementing:

### SSE Integration

Opens a persistent `EventSource` to `GET /v1/events/stream` on mount. Each SSE message carries a `GovernanceEvent` payload (mirrored from [`src/compliance_bridge_ts/src/events.ts`](../compliance_bridge_ts/src/events.ts)):

```typescript
interface GovernanceEvent {
  type: "AUDIT_FINDING" | "GOVERNANCE_VIOLATION";
  traceId: string;
  controlId: string; // e.g. "A.5.2", "A.9.2", "SC-4"
  result: "PASS" | "FAIL" | "NOT_APPLICABLE";
  safetyRate: number | null;
  auditId: string;
  timestamp: string; // ISO 8601 UTC
}
```

### Connection Status Dot

A colored dot in the header tracks the SSE connection state:

| State        | Color  | Meaning                    |
| ------------ | ------ | -------------------------- |
| `CONNECTING` | Yellow | EventSource opening        |
| `OPEN`       | Green  | Live events streaming      |
| `CLOSED`     | Red    | Connection lost (retrying) |

### `GOVERNANCE_VIOLATION` Modal

When a `GovernanceEvent` with `type: 'GOVERNANCE_VIOLATION'` arrives, the dashboard renders a blocking alert modal with:

- Control ID that failed (e.g., `A.9.2`)
- `safetyRate` at the time of violation
- `traceId` for cross-referencing in Langfuse

### Compliance Metrics Panel

Polls `GET /v1/metrics/:controlId?window_hours=24` to display the `ComplianceMetrics` shape:

```typescript
interface ComplianceMetrics {
  control_id: string;
  safety_rate: number; // e.g. 0.99 = 99%
  total_traces: number;
  blocked_traces: number;
  passed_traces: number;
  window_hours: number;
  last_event_utc: string;
  evidence_age_seconds: number;
  startup_grace_active: boolean;
  startup_grace_remaining_hours: number;
}
```

---

## Source Structure

```
src/agentsight-ui/
├── Dockerfile                    # node:22-alpine, serves dist/ via nginx
├── vite.config.ts                # Vite proxy: /v1/ → localhost:3001
├── .env.example                  # VITE_COMPLIANCE_BRIDGE_URL
├── README.md                     # This file
└── src/
    ├── main.tsx                  # React entrypoint
    ├── App.tsx                   # Root component (renders KernelDashboard)
    ├── App.css
    ├── index.css
    ├── KernelDashboard.tsx       # Primary dashboard component (SSE + metrics)
    ├── KernelDashboard.css       # Dashboard styles
    └── assets/
```

---

## Quick Start (Local Development)

```bash
# 1. Install dependencies
cd src/agentsight-ui
npm install

# 2. Configure environment
cp .env.example .env
# Default: VITE_COMPLIANCE_BRIDGE_URL=http://localhost:3001

# 3. Start compliance-bridge-ts first (SSE source)
cd ../compliance_bridge_ts && npm run dev &

# 4. Start Vite dev server
cd ../agentsight-ui
npm run dev
# → http://localhost:5173
```

The Vite proxy automatically forwards `/v1/*` requests to `http://localhost:3001`, so the dashboard will connect to the local compliance bridge without CORS issues.

---

## Environment Variables

| Variable                     | Default                 | Description                                                                                         |
| ---------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------- |
| `VITE_COMPLIANCE_BRIDGE_URL` | `http://localhost:3001` | Base URL of the compliance-bridge-ts service (dev only — in production, Vite proxy handles routing) |

---

## Docker / Production

```bash
# Build production image
docker build -t agentsight-ui .

# Run (expects compliance-bridge-ts reachable at /v1/ via nginx upstream)
docker run -p 80:80 agentsight-ui
```

In Kubernetes, the UI is deployed via [`deployment/k8s/frontend-deployment.yaml.tpl`](../../deployment/k8s/frontend-deployment.yaml.tpl). The nginx ingress routes:

- `/` → `agentsight-ui` service (port 80)
- `/v1/` → `compliance-bridge-ts` service (port 3001)

Port-forward for local access:

```bash
kubectl port-forward svc/agentsight-ui 8080:80 -n governance-stack
```

---

## AgentSight eBPF Integration

The dashboard displays kernel-level telemetry captured by the **AgentSight eBPF DaemonSet** (see [`deployment/agentsight/`](../../deployment/agentsight/)). AgentSight correlates kernel events (process creation, file access, network connections) with Langfuse traces via the `X-Trace-Id` HTTP header injected by the gateway.

The dashboard renders this data alongside Langfuse compliance metrics, providing a unified view of:

- **Application-level** governance events (from compliance-bridge-ts SSE)
- **Kernel-level** system call traces (from AgentSight eBPF)

---

## License

Apache 2.0 — See [`LICENSE`](../../LICENSE)
