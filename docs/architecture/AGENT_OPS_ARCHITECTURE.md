# Agent Ops Architecture: Defense-in-Depth for AI Governance — v0.1.0

> **Core Principle:** Separate the control plane (policy) from the data plane (execution capability) to create enforceable AI governance.

**Version:** v2.0.0-rc.2 (promoted 2026-06-03)
**Universal Compliance Baseline:** ISO/IEC 42001:2023 · CSA AARM v1.0 *(all deployment regions)*
**Jurisdiction-Specific Addenda:** SR 26-2 / NIST AI 600-1 / NIST SP 800-53 *(US_FED only)* · EU AI Act / GDPR / DORA *(EU_ECB only)* · MAS FEAT / MAS Notice 655 *(APAC_MAS only)*

## Architecture Pattern

CAGE implements a **two-layer agent governance architecture** that combines policy with capability:

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (Antigravity / Roo Code)        │
└─────────────────────┬───────────────────────┬───────────────┘
                      │                       │
              ┌───────▼────────┐     ┌────────▼────────┐
              │  Policy Layer  │     │ Capability Layer│
              │   (The Brain)  │     │  (The Muscle)   │
              └───────┬────────┘     └────────┬────────┘
                      │                       │
              ┌───────▼────────┐     ┌────────▼────────┐
              │  .clinerules   │     │  MCP Server     │
              │  docs/*.md     │     │  Tools API      │
              └────────────────┘     └─────────────────┘
                      │                       │
                      └───────┬───────────────┘
                              ▼
                    Infrastructure Action
```

## Layer 1: Policy (The Brain)

### Purpose
Define **why** and **when** agents should take actions. Establish cognitive boundaries that prevent agents from violating compliance requirements even when technically capable.

### Implementation

| Component | Purpose | Example |
|-----------|---------|---------|
| **`.clinerules`** | Roo Code workspace rules | GKE deployment policy |
| **`docs/DEPLOYMENT_RULES.md`** | Shared knowledge artifact | Comprehensive deployment matrix |
| **`docs/*.md`** | Domain-specific policies | Security, compliance, architecture |

### Example Policy
```markdown
**CRITICAL: When deploying to GKE, ALWAYS use Cloud Build.**

❌ Never use local Docker builds for GKE
✅ Always use ./deploy_all.sh --target gcp-gke
```

### Why This Matters

Without policy, an agent facing a deployment failure might:
1. Try local `docker build` to "see if it works"
2. Bypass Cloud Build to "save time"
3. Push untested images to production

**The policy acts as a hard cognitive boundary**, forcing the agent to say:
> "I am not allowed to do that because it violates our Cloud Build compliance policy."

## Layer 2: Capability (The Muscle)

### Purpose
Provide **safe, typed execution** of approved actions. Prevent hallucinated commands and ensure consistent execution across all agents.

### Implementation

| Component | Purpose | Example |
|-----------|---------|---------|
| **MCP Server** | Typed tool API | `cage-infrastructure` server |
| **Tool Schema** | Input validation | `deploy_environment` schema |
| **Execution Sandbox** | Safe command execution | Absolute paths, timeouts |

### Example Capability
```json
{
  "tool": "deploy_environment",
  "arguments": {
    "target": "gcp-gke",
    "environment": "dev"
  }
}
```

### Why This Matters

Without the MCP server, an agent would have to:
1. Type out bash commands manually
2. Remember correct flag syntax
3. Handle errors inconsistently
4. Potentially hallucinate dangerous commands

**The MCP server provides a strictly typed, safe sandbox** that:
- Validates inputs before execution
- Uses absolute paths (no environment sensitivity)
- Enforces timeouts
- Returns structured errors
- Logs all operations for audit

## The Synergy: Defense-in-Depth

Neither layer is sufficient alone. Together, they create enforceable governance:

### Scenario: Agent Asked to Deploy to GKE

#### Without Either Layer ❌
```
Agent: *executes arbitrary bash commands*
Result: Unpredictable, potentially dangerous
```

#### With Policy Only ⚠️
```
Agent: "I should use Cloud Build..."
Agent: *types out command with hallucinated flags*
Result: May work, may fail, inconsistent
```

#### With Capability Only ⚠️
```
Agent: *uses deploy_environment tool*
Agent: "Should I use target=gcp-gke or target=agnostic?"
Result: Technically safe, but no governance context
```

#### With Both Layers ✅
```
Agent: "Deployment policy requires Cloud Build for GKE"
Agent: *uses deploy_environment(target="gcp-gke")*
MCP Server: *validates, executes with Cloud Build*
Result: Safe, compliant, auditable
```

## AgentSight UI — Kernel-Level Observability

AgentSight is a React/Vite frontend (port 5173) backed by an eBPF DaemonSet that provides kernel-level observability for the governance pipeline.

### Phase 1 Features (`src/agentsight-ui/`)

| Feature | Description |
|---------|-------------|
| **`KernelDashboard`** | Primary dashboard component (`src/agentsight-ui/src/KernelDashboard.tsx`) |
| **Slippage Slider** | Real-time slippage tolerance control for trade execution monitoring |
| **Price Drift Badges** | Visual indicators for price drift events detected at the kernel level |
| **HITL TTL Countdown** | Live countdown timer for Human-in-the-Loop approval windows |

### eBPF DaemonSet

The eBPF DaemonSet runs on every node in the `governance-stack` namespace and intercepts:
- **Encrypted Traffic (OpenSSL):** Captures raw LLM payloads at the network boundary before encryption.
- **System Calls (Kernel):** Monitors `execve` (process creation), `openat` (file access), `connect` (network connections).
- **Correlation:** The Gateway injects `X-Trace-Id` into every LLM request; AgentSight links kernel events to Langfuse traces.

### Telemetry Path (Post-2026-05-31)

The OTel Collector sidecar was **deprecated 2026-05-31**. All telemetry now flows via **direct Langfuse OTLP ingestion**:
- Endpoint: `http://langfuse-web:3000/api/public/otel/v1/traces`
- No intermediate collector hop — reduces latency and eliminates a failure point.

---

## DEFER Queue — Operational Details (AARM-V7)

The DEFER queue handles confidence-starved contexts that cannot be immediately approved or denied.

### Configuration
- **Redis:** `db=1`, `noeviction` policy (contexts are never evicted — human review is mandatory).
- **Trigger:** Confidence score in the DEFER zone: below `min_trade_confidence: 0.95` but at or above the hard-deny threshold of `0.70`. Three-zone model: ALLOW (≥0.95), DEFER (0.70–0.95), DENY (<0.70).
- **Implementation:** `src/gateway/governance/defer_queue.py`.

### Operational Flow
```
Agent generates plan
        ↓
SymbolicGovernor Tier 2 — confidence check
        ↓ (confidence < 0.95, not hard-denied)
DEFER queue push → Redis db=1 (noeviction)
        ↓
Human review notification
        ↓
Operator approves/denies via AgentSight UI
        ↓
Re-evaluation with updated context
```

### Monitoring
- DEFER queue depth is exposed as an OTel metric and visible in the AgentSight `KernelDashboard`.
- Alerts fire when queue depth exceeds configurable thresholds (prevents silent accumulation).

---

## HITL TOCTOU Remediation — Operational Flow

Human-in-the-Loop (HITL) interrupts are subject to Time-of-Check/Time-of-Use (TOCTOU) races: the market state at approval time may differ from the state at check time.

### Trigger Conditions
- Trade amount > $10,000 USD
- `risk_score` > 0.7

### Remediation Nodes

| Node | Purpose |
|------|---------|
| `hitl_gate` | Interrupts the LangGraph StateGraph; waits for human approval |
| `post_hitl_rehydrate` | Fetches a live market quote at actuation time (yfinance `fast_info["last_price"]`); computes price drift vs. stale approval price |
| `post_hitl_revalidate` | Re-runs **Tier 2 (CBF)** and **Tier 4 (OPA)** only with fresh market data and live cash balance; checks drift against reviewer's `max_slippage_pct` |

### Operational Flow
```
hitl_gate interrupt
        ↓
Human reviews in AgentSight UI (HITL TTL countdown visible)
        ↓
Human approves (with max_slippage_pct tolerance)
        ↓
post_hitl_rehydrate — fetch live price; compute drift_pct
        ↓ (if drift_pct > max_slippage_pct → drift_blocked_node)
post_hitl_revalidate — re-run Tier 2 (CBF) + Tier 4 (OPA) with fresh params
        ↓ (if governance violation → drift_blocked_node)
executor_node — execute trade
```

If `post_hitl_revalidate` fails (market conditions changed), the trade is blocked and the operator is notified.

---

## Compliance Mapping

This architecture directly supports regulatory requirements. Controls are grouped by jurisdiction to make regional applicability explicit.

### Universal Controls (All Deployment Regions)

| Requirement | Policy Layer | Capability Layer |
|-------------|--------------|------------------|
| **ISO 42001 A.5.2** (AI deployment control) | Documents approved deployment methods | Enforces approved methods via typed API |
| **CSA AARM v1.0** (AI agent threat model) | 11-vector threat coverage documented | DEFER queue (V7), context accumulator (V1), consensus (V10) |

### US_FED Jurisdiction Controls (`CAGE_DEPLOYMENT_REGION=US_FED`)

| Requirement | Policy Layer | Capability Layer |
|-------------|--------------|------------------|
| **SR 26-2 §IV** (Agentic AI MRM, Federal Reserve, April 17, 2026) | Defines model risk management for agentic systems | HITL TOCTOU remediation; DEFER queue; KMS signing |
| **NIST AI RMF** (Controlled deployment) | Defines when/why to use each method | Ensures consistent execution |
| **NIST SP 800-53 CM-2** (Baseline configuration) | Documents infrastructure patterns | Prevents configuration drift |
| **SOC 2 CC8.1** (Change management) | Establishes change procedures | Logs all deployment actions |

## Real-World Example: GKE Deployment

### The Problem
An agent needs to deploy CAGE to GKE. Without governance, it might:
- Use local Docker builds (platform inconsistency)
- Push untested images (security risk)
- Bypass Cloud Build (no audit trail)
- Mix deployment methods (configuration drift)

### The Solution

**Policy Layer (.clinerules):**
```markdown
When deploying to GKE, ALWAYS use Cloud Build.
- Rationale: Platform consistency, security scanning, audit trail
- Command: ./deploy_all.sh --target gcp-gke
- Prohibited: docker build && docker push
```

**Capability Layer (MCP Server):**
```python
@app.call_tool()
async def deploy_environment(target: str, environment: str):
    if target == "gcp-gke":
        # Automatically uses Cloud Build
        cmd = ["./deploy_all.sh", "--target", "gcp-gke", "--env", environment]
    elif target == "agnostic":
        # Uses local Docker
        cmd = ["./deploy_all.sh", "--target", "agnostic", "--env", environment]
    return await safe_execute(cmd, timeout=600)
```

**Result:**
1. Agent reads policy → knows it must use Cloud Build for GKE
2. Agent calls MCP tool → `deploy_environment(target="gcp-gke")`
3. MCP server validates → ensures correct deployment method
4. System executes → uses Cloud Build automatically
5. Action logged → full audit trail for compliance

## Benefits of This Architecture

### For Security
- **Least privilege:** Agents only have access to approved tools
- **Input validation:** All parameters validated before execution
- **Audit trail:** All actions logged with context

### For Compliance
- **Enforceability:** Policy is technically enforced, not just documented
- **Consistency:** Same execution path every time
- **Auditability:** Structured logs for compliance reviews

### For Operations
- **Reliability:** No hallucinated commands
- **Maintainability:** Update MCP server, all agents benefit
- **Debuggability:** Clear separation between policy and execution

### For AI Safety
- **Cognitive boundaries:** Agents understand limitations
- **Fail-safe defaults:** MCP server prevents dangerous operations
- **Graceful degradation:** Clear error messages guide agents

## Implementation Checklist

When adding new agent capabilities:

- [ ] **Define policy** in `.clinerules` or `docs/*.md`
  - [ ] What is allowed
  - [ ] What is prohibited
  - [ ] Why (rationale)
  - [ ] When (conditions)

- [ ] **Implement capability** in MCP server
  - [ ] Define tool schema
  - [ ] Validate inputs
  - [ ] Safe execution (absolute paths, timeouts)
  - [ ] Structured error handling
  - [ ] Audit logging

- [ ] **Test both layers**
  - [ ] Agent understands policy
  - [ ] Agent uses correct tool
  - [ ] Tool validates correctly
  - [ ] Tool executes safely
  - [ ] Errors are clear

- [ ] **Document**
  - [ ] Policy rationale
  - [ ] Tool usage examples
  - [ ] Compliance mapping

## Extending This Pattern

This architecture can be applied to any agent operation:

| Operation | Policy Document | MCP Tool |
|-----------|----------------|----------|
| **Deployments** | `docs/DEPLOYMENT_RULES.md` | `deploy_environment` |
| **Infrastructure changes** | `docs/INFRASTRUCTURE_POLICY.md` | `validate_terraform` |
| **Security scanning** | `docs/SECURITY_POLICY.md` | `run_security_scan` |
| **Compliance checks** | `docs/COMPLIANCE_POLICY.md` | `check_compliance` |
| **Data access** | `docs/DATA_GOVERNANCE.md` | `query_data` |

## Related Documentation

- [Deployment Rules](../operations/DEPLOYMENT_RULES.md) - Specific policies for CAGE deployment
- [MCP Integration Guide](../operations/MCP_INTEGRATION_GUIDE.md) - Setting up MCP servers
- [Infrastructure MCP Server](../mcp-servers/infrastructure/README.md) - Tool reference

## Conclusion

**You have successfully boxed in the LLMs.**

They know the rules of the road (policy), and they have a safe vehicle to drive (MCP server).

This is the gold standard for Agent Ops in regulated environments. The control plane and data plane are separated, making AI governance not just documented, but technically enforced.
