# Agent Ops Architecture: Defense-in-Depth for AI Governance — v3.0.1

> **Core Principle:** Separate the control plane (policy) from the data plane (execution capability) to create enforceable AI governance.

**Version:** v3.0.1
**Universal Compliance Baseline:** ISO/IEC 42001:2023 · CSA AARM v1.0 *(all deployment regions)*
**Jurisdiction-Specific Addenda:** SR 26-2 / NIST AI 600-1 / NIST SP 800-53 *(US_FED only)* · EU AI Act / GDPR / DORA *(EU_ECB only)* · MAS FEAT / MAS Notice 655 *(APAC_MAS only)*

**Last Updated:** 2026-09-22

## Architecture Pattern

CAGE implements a **two-layer agent governance architecture** that combines policy with capability:

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (your MCP environment / your AI assistant)        │
└─────────────────────┬───────────────────────┬───────────────┘
                      │                       │
              ┌───────▼────────┐     ┌────────▼────────┐
              │  Policy Layer  │     │ Capability Layer│
              │   (The Brain)  │     │  (The Muscle)   │
              └───────┬────────┘     └────────┬────────┘
                      │                       │
              ┌───────▼────────┐     ┌────────▼────────┐
              │  AGENTS.md     │     │  MCP Server     │
              │  .roomodes     │     │  Tools API      │
              │  docs/*.md     │     │                 │
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
| **[`AGENTS.md`](../../AGENTS.md)** | Tool-agnostic agent + contributor standards ingested natively by AI assistants | GKE deployment policy, merge strategy, test invariants |
| **[`.roomodes`](../../.roomodes)** | Roo/Zoo Code mode definitions and cost guardrails | `orchestrator` / `ask` / `code` / `debug` mode boundaries |
| **`docs/operations/DEPLOYMENT_RULES.md`** | Shared knowledge artifact | Comprehensive deployment matrix |
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
| `approval` ([`approval_node`](../../src/governed_financial_advisor/graph/nodes/approval_node.py)) | Suspends the LangGraph StateGraph by calling the dynamic `interrupt()` primitive (`langgraph.types.interrupt`) and surfaces the trade payload to a reviewer |
| `post_hitl_rehydrate` | Fetches a live market quote at actuation time (yfinance `fast_info["last_price"]`); computes price drift vs. stale approval price |
| `post_hitl_revalidate` | Re-runs **Tier 2 (CBF)** and **Tier 4 (OPA)** with fresh market data and live cash balance; checks drift against reviewer's `max_slippage_pct` |
| `drift_blocked` | Fail-closed terminal node reached when drift or re-validation blocks the trade |

> [!IMPORTANT]
> The graph is compiled **without** `interrupt_before`. Suspension is a runtime decision made inside `approval_node` via `interrupt()`, and resumption uses the LangGraph SDK `Command(resume={...})` pattern — there is no HTTP resume endpoint.

### Operational Flow
```
approval_node calls interrupt(trade_payload) → graph suspends
        ↓
Human reviews in AgentSight UI (HITL TTL countdown visible)
        ↓
Reviewer resumes the thread: Command(resume={"approved": true, "max_slippage_pct": ...})
        ↓ (if not approved → rejection_node → END)
post_hitl_rehydrate — fetch live price; compute drift_pct
        ↓ (if drift_pct > max_slippage_pct → drift_blocked)
post_hitl_revalidate — re-run Tier 2 (CBF) + Tier 4 (OPA) with fresh params
        ↓ (if governance violation → drift_blocked)
executor — execute trade
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

**Policy Layer ([`AGENTS.md`](../../AGENTS.md) → Deployment Rules):**
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

- [ ] **Define policy** in `AGENTS.md`, `.roomodes`, or `docs/*.md`
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

Each agent operation pairs a policy document with a typed MCP tool. The rows below
are the pairings that exist today in [`mcp-servers/infrastructure`](../../mcp-servers/infrastructure/README.md);
new operations follow the same shape.

| Operation | Policy Document | MCP Tool |
|-----------|----------------|----------|
| **Deployments** | [`docs/operations/DEPLOYMENT_RULES.md`](../operations/DEPLOYMENT_RULES.md) | `deploy_environment` |
| **Deployment target selection** | [`docs/operations/DEPLOYMENT_DECISION_RECORD.md`](../operations/DEPLOYMENT_DECISION_RECORD.md) | `list_available_targets` |
| **Terraform validation** | [`AGENTS.md`](../../AGENTS.md) → Terraform Invariants | `validate_terraform` |
| **Cluster inspection** | [`docs/operations/GKE_TEST_RUNBOOK.md`](../operations/GKE_TEST_RUNBOOK.md) | `check_cluster_status`, `get_deployment_info` |
| **Scripted operations** | [`docs/operations/DEPLOYMENT_RULES.md`](../operations/DEPLOYMENT_RULES.md) | `run_deployment_script` |

## Related Documentation

- [Deployment Rules](../operations/DEPLOYMENT_RULES.md) — Specific policies for CAGE deployment
- [MCP Setup Guide](../MCP_SETUP.md) — Setting up MCP servers
- [Infrastructure MCP Server](../../mcp-servers/infrastructure/README.md) — Tool reference
- [Agent Identity Binding Spec](AGENT_IDENTITY_BINDING_SPEC.md) — Native SPIFFE/SVID identity extraction ([`spiffe_extractor.py`](../../src/gateway/governance/spiffe_extractor.py)), which replaced the `X-Agent-ID` request header
- [Git Workflow Standards](../operations/GIT_WORKFLOW_STANDARDS.md) — Branch lifecycle and squash-merge policy

## Conclusion

**You have successfully boxed in the LLMs.**

They know the rules of the road (policy), and they have a safe vehicle to drive (MCP server).

This is the gold standard for Agent Ops in regulated environments. The control plane and data plane are separated, making AI governance not just documented, but technically enforced.
