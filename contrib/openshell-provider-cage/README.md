# openshell-provider-cage

`openshell-provider-cage` is an upstream plugin for the **NVIDIA OpenShell** platform that integrates OpenShell sandboxes with **CAGE (Cybernetic Agent Governance Engine v3.0.1)**.

It enables NVIDIA OpenShell supervisors to consult CAGE's **STERA Admissibility Engine** (`SymbolicGovernor`) before permitting dynamic sandbox operations, enforcing formal STPA constraints, OPA Rego policies, FTRA irreversibility boundaries, and dual-control human-in-the-loop (HITL) approval queues.

---

## Architecture Overview

```
                      +-----------------------------------+
                      |         Agent in Sandbox          |
                      | (Autonomous Tool / MCP Execution) |
                      +-----------------+-----------------+
                                        | (Requests tool/route)
                                        v
                      +-----------------+-----------------+
                      |       OpenShell Supervisor        |
                      |   (Landlock, Network NS, seccomp) |
                      +-----------------+-----------------+
                                        |
                      [ PolicyProvider SPI Delegation ]
                                        v
                 +----------------------+----------------------+
                 |        openshell-provider-cage               |
                 | (Evaluates proposal against CAGE Governor)   |
                 +----------------------+----------------------+
                                        |
                  HTTPS / Linkerd mTLS  | (Profile.DRY_RUN)
                                        v
       +--------------------------------+--------------------------------+
       |                         CAGE Gateway                            |
       |  - SymbolicGovernor (STPA + OPA + FTRA Admissibility Engine)   |
       |  - DeferQueue (Four-Eyes WebAuthn HITL Approval Queue)          |
       |  - EvidenceStreamSink (OCSF v1.1.0 WORM Audit Trail)           |
       +-----------------------------------------------------------------+
```

---

## Features

1. **Pre-Execution STERA Validation**:
   - Every dynamic policy proposal (`SubmitPolicyAnalysis`, `ApproveDraftChunk`, outbound network request, MCP tool invocation) is evaluated against CAGE's `validate_action()` in `DRY_RUN` mode.
   - Deterministically prevents STPA Unsafe Control Actions (UCAs) and out-of-bounds agent actions without committing state changes.

2. **Dual-Control HITL Deferrals (`DeferQueue`)**:
   - When CAGE classifies an action as `REQUIRE_APPROVAL` or `DEFER`, `openshell-provider-cage` parks a `DeferToken` in CAGE's secure `DeferQueue` with quorum requirement (`required_quorum >= 2`, four-eyes principle).
   - Holds sandbox execution until operators review and sign WebAuthn approvals.

3. **STPA Sandbox Policy Ingestion**:
   - Directly ingests policies compiled by CAGE's `stpa_compiler.py` (`generated_sandbox_policy.yaml`).
   - Translates formal STPA safety constraints into OpenShell Landlock filesystem restrictions, pre-credentials, allowed binary sets, and MCP tool boundaries.

4. **Normalized OCSF v1.1.0 Telemetry**:
   - Emits standardized OCSF security event classes (`3001` File Activity, `4001` Network Activity, `6003` API Activity) back to CAGE's evidence stream with sensitive credential sanitization.

---

## Installation

```bash
pip install openshell-provider-cage
```

Or configure inside OpenShell runtime:

```yaml
# openshell.yaml
policy_providers:
  cage:
    module: openshell_provider_cage
    endpoint: "https://cage-gateway.internal:8080"
    mTLS:
      client_cert: "/etc/openshell/certs/client.pem"
      client_key: "/etc/openshell/certs/client-key.pem"
      ca_cert: "/etc/openshell/certs/ca.pem"
    sandbox_policy_path: "/etc/openshell/generated_sandbox_policy.yaml"
    quarantine_on_hard_breach: true
```

---

## Quickstart

```python
from openshell_provider_cage import CagePolicyProvider, PolicyProposal

provider = CagePolicyProvider(
    endpoint="https://cage-gateway.internal:8080",
    client_identity="spiffe://cluster.local/ns/cage/sa/openshell-supervisor",
)

proposal = PolicyProposal(
    sandbox_id="sbx-advisor-42",
    thread_id="thread-session-109",
    action="execute_market_order",
    requested_endpoint="https://broker.internal/api/order",
    requested_http_verb="POST",
    params={"symbol": "NVDA", "quantity": 100},
)

outcome = await provider.evaluate(proposal)
if outcome.allowed:
    print("Execution clearance granted with routing seal:", outcome.routing_seal)
elif outcome.deferred:
    print(f"Parked for dual-control HITL approval (Defer ID: {outcome.defer_id})")
else:
    print(f"Rejected by STERA safety constraint: {outcome.rejection_reason}")
```

---

## License

Apache License 2.0. Copyright 2026 Google LLC / CAGE Contributors.
