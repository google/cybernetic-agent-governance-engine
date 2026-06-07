# NeMo Guardrails — Integration Overview

> **Last updated:** 2026-06-07 (v2.0.0-rc.3)

This package (`src/gateway/governance/nemo/`) contains everything the
Cybernetic Governance Engine needs to run NVIDIA NeMo Guardrails as a
governed inference rail inside the LangGraph pipeline.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Diagram](#architecture-diagram)
3. [File Reference](#file-reference)
4. [Which path must graph nodes use?](#which-path-must-graph-nodes-use)
5. [Warning — do not route graph nodes through gRPC](#warning--do-not-route-graph-nodes-through-grpc)
6. [Related documents](#related-documents)

---

## Overview

NeMo Guardrails is integrated at **two boundaries** of every inference request:

| Boundary       | Graph node              | Direction                                                   |
| -------------- | ----------------------- | ----------------------------------------------------------- |
| **Entry rail** | `nemo_guardrail_node`   | User message → checked before the LLM sees it               |
| **Exit rail**  | `nemo_output_rail_node` | LLM output → checked and PII-masked before the user sees it |

Both nodes execute NeMo **in-process** — inside the same Python interpreter as
the LangGraph runner — by calling functions in `manager.py`. No network call
is made.

A separate gRPC sidecar process (`server.py`) also exists for external
callers, but it is **not part of the graph's critical path**.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                   LangGraph Graph Runner                      │
│                                                              │
│  User Request                                                │
│      │                                                       │
│      ▼                                                       │
│  ┌─────────────────────────┐                                 │
│  │  nemo_guardrail_node    │  ◄─── ENTRY RAIL               │
│  │  (input validation)     │                                 │
│  └──────────┬──────────────┘                                 │
│             │  calls in-process (no network)                 │
│             ▼                                                │
│  ┌─────────────────────────┐                                 │
│  │      manager.py         │  ◄─── AUTHORITATIVE PATH       │
│  │  validate_with_nemo()   │       create_nemo_manager()     │
│  │  verify_input()         │       builds LLMRails singleton │
│  │  verify_and_mask_output()│      in this process           │
│  └──────────┬──────────────┘                                 │
│             │                                                │
│             ▼                                                │
│        [LLM inference]                                       │
│             │                                                │
│             ▼                                                │
│  ┌─────────────────────────┐                                 │
│  │  nemo_output_rail_node  │  ◄─── EXIT RAIL                │
│  │  (output validation     │                                 │
│  │   + PII masking)        │                                 │
│  └──────────┬──────────────┘                                 │
│             │  calls in-process (no network)                 │
│             ▼                                                │
│          Response to user                                    │
└──────────────────────────────────────────────────────────────┘

                    ╔════════════════════════════╗
                    ║  server.py (gRPC sidecar)  ║  ◄── SEPARATE PROCESS
                    ║  NeMoGuardrails.Verify()   ║      Not used by graph nodes
                    ║  (external callers only)   ║
                    ╚════════════════════════════╝
                         │
                         │  also calls create_nemo_manager()
                         │  (owns its own LLMRails instance —
                         │   NOT shared with the graph runner)
                         ▼
                    [compliance-bridge,
                     red-team harnesses,
                     external microservices]
```

---

## File Reference

| File                                                                   | Role                                                                                                                                                                   |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`manager.py`](manager.py)                                             | **Authoritative in-process path.** `create_nemo_manager()` builds an `LLMRails` instance. `validate_with_nemo()`, `verify_input()`, and `verify_and_mask_output()` are called directly by graph nodes. |
| [`server.py`](server.py)                                               | **gRPC sidecar (external callers only).** Implements `governance.NeMoGuardrails.Verify` over the network. NOT used by graph nodes. Runs as a separate process.                                         |
| [`actions.py`](actions.py)                                             | Gateway-internal NeMo action implementations (`CheckApprovalTokenAction`, `CheckDataLatencyAction`, etc.). Delegates to the `SymbolicGovernor` singleton.                                              |
| [`prompt_fetcher.py`](prompt_fetcher.py)                               | **v2.0.0:** Fetches Langfuse prompts for NeMo rail configuration. Used by the human-gated refinement workflow (`POST /v1/nemo/propose-refinement`) to stage config proposals before human approval.    |
| [`vllm_client.py`](vllm_client.py)                                     | `VLLMLLM` — a LangChain `BaseChatModel` wrapper around the vLLM inference service via LiteLLM. Registered as the `vllm_llama` LLM provider and used by NeMo for any LLM calls within Colang flows.     |
| [`__init__.py`](__init__.py)                                           | Package init (currently empty; kept for Python package resolution).                                                                                                                                    |
| [`../../../../src/gateway/protos/nemo.proto`](../../protos/nemo.proto) | Protobuf definition for the gRPC sidecar: `NeMoGuardrails.Verify(VerifyRequest) → VerifyResponse`.                                                                                                     |
| [`../../../../config/rails/`](../../../../config/rails/)               | Colang flow definitions and `config.yml` consumed by both the in-process manager and the gRPC sidecar.                                                                                                 |

---

## Which path must graph nodes use?

Graph nodes **must always** call manager functions directly:

```python
# CORRECT — in-process, no network, fail-closed
from src.gateway.governance.nemo.manager import validate_with_nemo, verify_input

rails = create_nemo_manager()          # called once at startup, result cached
is_safe, response = await validate_with_nemo(user_input, rails)
result = await verify_input(rails, text)
masked = await verify_and_mask_output(rails, text)
```

**Never** open a gRPC channel to `server.py` from inside a graph node:

```python
# WRONG — introduces network latency + availability risk in the critical path
channel = grpc.aio.insecure_channel("localhost:8000")
stub = NeMoGuardrailsStub(channel)
resp = await stub.Verify(VerifyRequest(input=user_input))  # DO NOT DO THIS
```

---

## ⚠️ Warning — do not route graph nodes through gRPC

Routing `nemo_guardrail_node` or `nemo_output_rail_node` through the gRPC
sidecar would introduce four problems:

1. **Latency** — every request incurs a 10–100 ms+ network round-trip per rail
   check (two checks per request = 20–200 ms+ added to the critical path).

2. **Hard availability dependency** — if the sidecar pod is unavailable or
   slow, every inference request fails or hangs. The in-process path has no
   such dependency.

3. **Fail-open risk** — a `grpc.StatusCode.UNAVAILABLE` error from the sidecar
   is easily mishandled as a pass-through; the in-process path raises a Python
   exception which is caught and converted deterministically to
   `guardrail_blocked=True` (fail-closed).

4. **Audit-trail drift** — network timeouts vs. in-process exceptions produce
   different OTel / Langfuse span shapes, making compliance traces
   non-deterministic across deployments.

---

## Related Documents

- [`plans/nemo_guardrails_architectural_analysis.md`](../../../../plans/nemo_guardrails_architectural_analysis.md) — full architectural analysis and decision record
- [`docs/GATEWAY_ARCHITECTURE.md`](../../../../docs/GATEWAY_ARCHITECTURE.md) — gateway architecture overview
- [`docs/LATENCY_STRATEGY.md`](../../../../docs/LATENCY_STRATEGY.md) — latency strategy and budget
- [`src/gateway/governance/nemo/server.py`](server.py) — module docstring with full sidecar rationale
- [`src/gateway/governance/nemo/manager.py`](manager.py) — module docstring and comment block above `create_nemo_manager()`
