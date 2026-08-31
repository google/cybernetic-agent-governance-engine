# NeMo Guardrails — Integration Overview

> **Last updated:** 2026-08-06 (v2.1.1-post)
>
> **2026-08-06 update:** The GFA (Governed Financial Advisor) pod's `LLMRails`
> lifecycle was consolidated to a single singleton. See
> [§3 GFA Pod — Singleton Consolidation](#gfa-pod--singleton-consolidation-2026-08-06)
> below for what changed and why.

This package (`src/gateway/governance/nemo/`) contains everything the
Cybernetic Governance Engine needs to run NVIDIA NeMo Guardrails as a
governed inference rail inside the LangGraph pipeline.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Diagram](#architecture-diagram)
3. [GFA Pod — Singleton Consolidation (2026-08-06)](#gfa-pod--singleton-consolidation-2026-08-06)
4. [File Reference](#file-reference)
5. [Colang Rails](#colang-rails)
   - [cbrn_rails.co — CBRN Safety Rail \[US\_FED only\]](#cbrn_railsco--cbrn-safety-rail-us_fed-only)
6. [Which path must graph nodes use?](#which-path-must-graph-nodes-use)
7. [Warning — do not route graph nodes through gRPC](#warning--do-not-route-graph-nodes-through-grpc)
8. [Related documents](#related-documents)

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

## GFA Pod — Singleton Consolidation (2026-08-06)

> **Scope note:** This section describes the `LLMRails` lifecycle inside the
> **Governed Financial Advisor (GFA) pod**
> (`src/governed_financial_advisor/`), which is a *consumer* of this package
> via `src/gateway/governance/langgraph_harness/nemo_node_factory.py`. It is
> distinct from the gRPC sidecar (`server.py`, documented below), which runs
> as its own separate process/pod and is unaffected by this change.

**Before 2026-08-06**, the GFA pod instantiated up to **three independent
`LLMRails` objects**, each built by its own call to `create_nemo_manager()`:

1. The LangGraph guardrail nodes, via `nemo_node_factory.get_nemo_rails()`.
2. `src/governed_financial_advisor/server.py`, via a module-level
   `rails = load_rails()` global used by the hot-reload endpoints.
3. `src/governed_financial_advisor/tools/api.py`, via its own
   `_rails` singleton and `get_rails()` helper.

Because each instance was constructed independently, a hot-reload issued
against one of them (e.g. via `POST /v1/nemo/approve-refinement/{id}`) did
**not** propagate to the other two — the graph nodes and the tools router
could keep enforcing a stale rail configuration after an approved refinement.

**As of 2026-08-06**, all three call sites share the **single**
module-level `_nemo_rails` singleton defined in `nemo_node_factory.py`:

- `get_nemo_rails()` returns the shared singleton, lazily initializing it on
  first call (fail-closed if NeMo is unavailable).
- `reload_nemo_rails(config_path="config/rails")` is the **canonical
  hot-reload entry point**. It is an `async def`, guarded by an
  `asyncio.Lock` (`_get_reload_lock()`), and atomically replaces the
  module-level singleton with a freshly built `LLMRails` instance. Both
  `POST /v1/nemo/propose-refinement` → `approve-refinement/{id}` and the
  legacy `NEMO_AUTO_APPLY_ENABLED=true` dev/test path in `server.py` call
  `reload_nemo_rails()` — there is no code path left that builds a
  second, un-synchronized `LLMRails` instance inside the GFA pod.
- `tools/api.py` no longer defines `_rails` / `get_rails()`; it imports
  `get_nemo_rails()` from `nemo_node_factory.py` directly.
- `server.py` no longer declares a module-level `rails` global or any
  `global rails` statements; it imports `reload_nemo_rails()` from the
  harness on demand inside the two hot-reload endpoints.

**Net result:** one `LLMRails` instance per GFA pod (down from three). A
single approved refinement propagates to every consumer simultaneously.

**Related quarantine / CI notes:**

- [`infra/modules/nemo_guardrails/main.tf`](../../../../infra/modules/nemo_guardrails/main.tf)
  carries a `HISTORICAL-ONLY — DO NOT APPLY` banner. It defines an inline
  Colang configuration that predates and diverges from the canonical
  `config/rails/` source and must never be `terraform apply`'d — see
  [`AGENTS.md`](../../../../AGENTS.md#deployment-rules).
- The `.github/workflows/ci.yml` `nemo-freshness-check` job diffs
  `config/rails/actions.py` against the embedded snapshot in
  `deployment/k8s/nemo-rails-configmap.yaml`, failing the build if the
  ConfigMap drifts from the canonical action source.

---

## File Reference

| File                                                                                   | Role                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`manager.py`](manager.py)                                                             | **Authoritative in-process path.** `create_nemo_manager()` builds an `LLMRails` instance. `validate_with_nemo()`, `verify_input()`, and `verify_and_mask_output()` are called directly by graph nodes. |
| [`server.py`](server.py)                                                               | **gRPC sidecar (external callers only).** Implements `governance.NeMoGuardrails.Verify` over the network. NOT used by graph nodes. Runs as a separate process.                                         |
| [`actions.py`](actions.py)                                                             | Gateway-internal NeMo action implementations (`CheckApprovalTokenAction`, `CheckDataLatencyAction`, etc.). Delegates to the `SymbolicGovernor` singleton.                                              |
| [`prompt_fetcher.py`](prompt_fetcher.py)                                               | **v2.0.0:** Fetches Langfuse prompts for NeMo rail configuration. Used by the human-gated refinement workflow (`POST /v1/nemo/propose-refinement`) to stage config proposals before human approval.    |
| [`vllm_client.py`](vllm_client.py)                                                     | `VLLMLLM` — a LangChain `BaseChatModel` wrapper around the vLLM inference service via LiteLLM. Registered as the `vllm_llama` LLM provider and used by NeMo for any LLM calls within Colang flows.   |
| [`__init__.py`](__init__.py)                                                           | Package init (currently empty; kept for Python package resolution).                                                                                                                                    |
| [`colang/cbrn_rails.co`](colang/cbrn_rails.co)                                         | **\[US\_FED only\]** CBRN safety rail (NIST AI 600-1 §2.6/§2.12). Blocks synthesis/weaponisation queries across Chemical, Biological, Radiological, and Nuclear categories. Loaded only when `CAGE_DEPLOYMENT_REGION=US_FED`. |
| [`../../../../src/gateway/protos/nemo.proto`](../../protos/nemo.proto)                 | Protobuf definition for the gRPC sidecar: `NeMoGuardrails.Verify(VerifyRequest) → VerifyResponse`.                                                                                                     |
| [`../../../../config/rails/`](../../../../config/rails/)                               | Colang flow definitions and `config.yml` consumed by both the in-process manager and the gRPC sidecar.                                                                                                 |

---

## Colang Rails

This section documents the Colang (`.co`) files under [`colang/`](colang/) that
define NeMo Guardrails flows. Each file is loaded by `create_nemo_manager()` at
startup via the `config.yml` rail configuration.

> **Jurisdiction note:** ISO/IEC 42001:2023 and CSA AARM are the universal
> compliance baselines that apply to **all** deployment regions (US\_FED,
> EU\_ECB, APAC\_MAS). Framework-specific rails documented below are additive
> layers that activate only for their designated jurisdiction.

---

### `cbrn_rails.co` — CBRN Safety Rail **\[US\_FED only\]**

**File:** [`colang/cbrn_rails.co`](colang/cbrn_rails.co)
**Compliance authority:** NIST AI 600-1 §2.6 (Dual-Use Foundation Model Risks) and §2.12 (CBRN Uplift Prevention) — **US\_FED jurisdiction only**
**POAM reference:** AI600-007
**Change category:** Cat-M — requires AO pre-approval before production deployment (Phase 3)

#### What it does

`cbrn_rails.co` implements a NeMo Guardrails **entry rail** that intercepts user
messages before they reach the LLM. When a message matches any of the defined
CBRN intent patterns, the flow short-circuits and returns a fixed refusal
response — the LLM is never invoked for that request.

The rail defines three Colang constructs:

| Construct | Name | Purpose |
| --------- | ---- | ------- |
| `define user` | `ask cbrn synthesis` | Intent pattern — matches CBRN-related queries |
| `define bot` | `refuse cbrn` | Fixed refusal message returned to the caller |
| `define flow` | `cbrn safety check` | Wires the intent to the refusal: `user ask cbrn synthesis → bot refuse cbrn` |

#### Blocked keywords and patterns

The `ask cbrn synthesis` intent matches the following 15 literal phrases
(case-insensitive substring match, applied by the NeMo intent classifier):

| Category | Blocked phrases |
| -------- | --------------- |
| **Chemical** | `synthesize nerve agent`, `VX precursor`, `sarin production`, `chemical weapon synthesis` |
| **Biological** | `weaponize pathogen`, `ricin synthesis`, `anthrax spore`, `smallpox culture`, `biological weapon` |
| **Radiological** | `enrich uranium`, `dirty bomb construction`, `radiological dispersal` |
| **Nuclear** | `nuclear device construction` |
| **Cross-category / general** | `improvised explosive device`, `CBRN attack` |

#### Activation gate

This rail is **only loaded** when both conditions are met:

1. `CAGE_DEPLOYMENT_REGION=US_FED` — the region guard in the file header
   prevents the Colang file from being included in EU\_ECB or APAC\_MAS
   `config.yml` rail lists.
2. `tier1_keywords_cbrn_enabled: true` — the governance thresholds flag in
   [`config/thresholds/`](../../../../config/thresholds/) (key:
   `tier1_keywords_cbrn_enabled`). When this flag is `false` the rail file is
   present on disk but `create_nemo_manager()` skips loading it.

> **Do not remove the region guard comment** at the top of `cbrn_rails.co`.
> It is the machine-readable signal used by the deployment tooling to exclude
> this file from non-US\_FED `config.yml` manifests.

#### Pipeline integration

```
User message
    │
    ▼
nemo_guardrail_node  (entry rail)
    │
    ├─► [cbrn safety check flow]  ← cbrn_rails.co (US_FED only)
    │       │
    │       ├─ MATCH  → bot refuse cbrn → 403 / blocked response returned
    │       │            (LLM never called)
    │       │
    │       └─ NO MATCH → continue to next rail / LLM inference
    │
    ▼
[LLM inference + exit rail]
```

The refusal message (`"I cannot provide information on that topic."`) is
intentionally generic — it does not confirm or deny that a CBRN keyword was
matched, which prevents adversarial enumeration of the block-list.

#### Companion artifacts

| Artifact | Path | Purpose |
| -------- | ---- | ------- |
| Lula validation | [`compliance/lula/lula-validation-ai600-cbrn.yaml`](../../../../compliance/lula/lula-validation-ai600-cbrn.yaml) | Asserts the CBRN rail is loaded and active in US\_FED deployments; run as part of the US\_FED release gate |
| Unit test — rail | [`tests/test_nemo_cbrn_rails.py`](../../../../tests/test_nemo_cbrn_rails.py) | Exercises all 15 blocked phrases and verifies the refusal response; also verifies benign queries pass through |
| Unit test — text filter | [`tests/test_text_filter_cbrn.py`](../../../../tests/test_text_filter_cbrn.py) | Tests the `text_filter.py` CBRN keyword layer that runs **before** NeMo as a fast pre-screen |

> **Note:** The Lula validation (`lula-validation-ai600-cbrn.yaml`) is a
> **US\_FED release gate only** (see `.roo/rules` §5.2). It must not be listed
> as a prerequisite for the global stable tag or for EU\_ECB / APAC\_MAS
> deployments.

---

## Which path must graph nodes use?

Graph nodes **must always** call manager functions directly:

```python
# CORRECT — in-process, no network, fail-closed
from src.gateway.governance.nemo.manager import validate_with_nemo, verify_input

rails = create_nemo_manager()  # called once at startup, result cached
is_safe, response = await validate_with_nemo(user_input, rails)
result = await verify_input(rails, text)
masked = await verify_and_mask_output(rails, text)
```

> **GFA pod note (2026-08-06):** the code sketch above shows the low-level
> `manager.py` contract. Inside the **GFA pod**, callers should not call
> `create_nemo_manager()` directly — they must go through the harness
> singleton accessors in
> [`nemo_node_factory.py`](../../langgraph_harness/nemo_node_factory.py)
> instead, so that the same `LLMRails` instance is shared across every
> consumer in the pod:
>
> ```python
> from src.gateway.governance.langgraph_harness.nemo_node_factory import (
>     get_nemo_rails,      # returns the shared singleton (lazy-init)
>     reload_nemo_rails,   # canonical hot-reload entry point (async, lock-guarded)
> )
>
> rails = get_nemo_rails()
> is_safe, reason, deterministic = await validate_with_nemo(user_input, rails)
>
> # After an approved refinement:
> await reload_nemo_rails(config_path="config/rails")
> ```
>
> This is exactly what `create_nemo_guardrail_node()` /
> `create_nemo_output_rail_node()` do internally, and what
> `src/governed_financial_advisor/tools/api.py` and
> `src/governed_financial_advisor/server.py`'s hot-reload endpoints now call
> — see [§3 GFA Pod — Singleton Consolidation](#gfa-pod--singleton-consolidation-2026-08-06).

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

- `plans/nemo_guardrails_architectural_analysis.md` — full architectural analysis and decision record
- [`docs/GATEWAY_ARCHITECTURE.md`](../../../../docs/architecture/GATEWAY_ARCHITECTURE.md) — gateway architecture overview
- [`docs/LATENCY_STRATEGY.md`](../../../../docs/architecture/LATENCY_STRATEGY.md) — latency strategy and budget
- [`src/gateway/governance/nemo/server.py`](server.py) — module docstring with full sidecar rationale
- [`src/gateway/governance/nemo/manager.py`](manager.py) — module docstring and comment block above `create_nemo_manager()`
- [`src/gateway/governance/langgraph_harness/nemo_node_factory.py`](../../langgraph_harness/nemo_node_factory.py) — GFA pod singleton (`_nemo_rails`), `get_nemo_rails()`, and the canonical `reload_nemo_rails()` hot-reload entry point (see [§3](#gfa-pod--singleton-consolidation-2026-08-06))
- [`infra/modules/nemo_guardrails/main.tf`](../../../../infra/modules/nemo_guardrails/main.tf) — **HISTORICAL-ONLY, DO NOT APPLY**; quarantined inline Colang config predating `config/rails/`
