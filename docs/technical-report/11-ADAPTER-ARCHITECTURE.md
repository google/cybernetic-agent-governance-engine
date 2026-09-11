# Secure Plugin & Adapter Architecture Specification

> **Classification:** Specification & Architectural Analysis  
> **Target Systems:** Cybernetic Agent Governance Engine (CAGE), Extension Runtimes, & High-Assurance Gateways  
> **Status:** Approved Reference Specification  

---

## 1. Executive Summary & Architectural Overview

Running third-party, vendor-specific, or untrusted code in-process (via dynamic imports, C/C++ FFI, or direct library bindings) introduces critical reliability, security, and governance risks into high-assurance runtime platforms. A single memory corruption bug, unhandled panic, blocking I/O call, or malicious exploit in an adapter can compromise the entire host application, violate safety envelopes, and corrupt audit-grade evidence chains.

This specification defines a comprehensive architecture for **secure, capability-negotiated, and latency-optimized plugin and adapter integration**. It enforces strict isolation boundaries, defines performance and transport trade-offs, establishes capability-based interface contracts, and maps directly to the deterministic invariant requirements of the [Cybernetic Agent Governance Engine (CAGE)](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md).

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 HOST PLATFORM                                   │
│                                                                                 │
│   ┌────────────────────────────────┐     ┌──────────────────────────────────┐   │
│   │   Kernel / Core Engine         │     │ Capability Dispatcher            │   │
│   │   - Deterministic Invariants   │◄───►│ - Runtime getCapabilities()      │   │
│   │   - Hard Guardrails & Quotas   │     │ - Graceful Fallback Orchestrator │   │
│   └────────────────┬───────────────┘     └──────────────────────────────────┘   │
└────────────────────┼────────────────────────────────────────────────────────────┘
                     │  Boundary Guardrails: Schema Validation, Timeouts, Quotas
      ┌──────────────┼──────────────────────────────┬──────────────────────┐
      ▼ (< 1 ms)     ▼ (100 µs – 1 ms)              ▼ (5 – 50 ms)          ▼ (100 ms+)
┌──────────────┐ ┌──────────────────────┐ ┌───────────────────┐ ┌─────────────────┐
│ WebAssembly  │ │ Unix Domain Socket   │ │ gRPC / Localhost  │ │ External SaaS / │
│ Sandbox      │ │ (UDS IPC / SHM Ring) │ │ TCP Sidecar       │ │ Remote Cloud    │
│ (Wasmtime)   │ │                      │ │ (K8s Pod / Envoy) │ │ (Normative API) │
│ - Filtering  │ │ - High-throughput    │ │ - Independent     │ │ - Async/Attest  │
│ - Transforms │ │   local adapters     │ │   lifecycle       │ │   only (OOB)    │
└──────────────┘ └──────────────────────┘ └───────────────────┘ └─────────────────┘
```

---

## 2. Isolation & Security Model

High-reliability platforms must treat all external adapters as untrusted entities. Enforcing hard process, memory, and capability boundaries guarantees that adapter faults cannot propagate into the core host engine.

### 2.1 Isolation Strategies

1. **WebAssembly (Wasm) Sandboxing (In-Process / Near-Native):**
   * Adapters are compiled into Wasm bytecode modules and executed via secure, embeddable runtimes (such as Wasmtime, Wasmer, or V8).
   * **Security Boundary:** Software-enforced linear memory sandboxing with zero access to host system calls, the filesystem, or network sockets unless explicitly bridged via capability imports.
   * **Primary Use Case:** High-frequency, sub-millisecond data transformation, policy pre-filtering, and stateless routing.

2. **Out-of-Process Sidecar Services (Unix Domain Sockets / IPC):**
   * The host engine communicates with adapters running as dedicated local processes over Unix Domain Sockets (UDS) or POSIX shared memory.
   * **Security Boundary:** Separate operating system process space. Crashes, memory leaks, and segmentation faults are strictly contained within the adapter process.
   * **Primary Use Case:** General out-of-process execution for proprietary vendor code requiring native performance without network overhead.

3. **Containerized Sidecars (gRPC / Localhost Network Interfaces):**
   * Adapters run in independent containers co-located in the same Kubernetes Pod or localhost network namespace, communicating via gRPC or HTTP/2.
   * **Security Boundary:** Container boundary with independent resource cgroups, separate filesystems, and distinct lifecycle management.
   * **Primary Use Case:** Complex third-party integrations with dedicated dependency graphs and polyglot runtime stacks.

4. **Capability-Based OS Micro-Sandboxing:**
   * Adapter micro-processes constrained directly via Linux Namespaces, Seccomp profiles (syscall filtering), and Landlock LSM (filesystem access policies).
   * **Security Boundary:** Kernel-enforced hardware privilege boundaries limiting syscall surface area.

### 2.2 Platform Boundary Guardrails

* **Strict I/O Sanitization:** Treat all adapter outputs as untrusted payloads. Perform strict JSON Schema or Protobuf validation on every inbound response before merging it into internal state.
* **Deadlines & Circuit Breakers:** Every adapter invocation must be wrapped in an immutable deadline (timeout) and monitored by a circuit breaker to prevent hung vendor code from exhausting thread pools or connection backlogs.
* **Resource Quotas & Cgroups:** Impose strict per-instance constraints on CPU time, resident memory (RSS), file descriptors, and network egress bandwidth.
* **Workload Identity & Bytecode Verification:** Enforce cryptographic verification on all adapters:
  * For Wasm modules: Verify cryptographic signatures (e.g., Sigstore / Cosign) prior to loading.
  * For out-of-process sidecars: Enforce mutual TLS (mTLS) with SPIFFE/SPIRE workload identities.

---

## 3. Performance & Latency Trade-Off Analysis

Crossing an execution boundary introduces latency overhead via context switches, memory serialization/deserialization, and kernel transitions. Choosing the correct boundary requires matching transport characteristics with invocation frequency.

### 3.1 Transport & Boundary Comparison Matrix

| Architecture | Per-Call Latency | Throughput / Overhead Profile | Isolation Mechanism | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **In-Process Native** *(Insecure)* | $\sim 0\text{ ns}$ | Zero context-switch overhead; zero serialization. | None (shared address space). | First-party, trusted core kernel logic only. |
| **Wasm Sandboxing** | $< 1\text{ ms}$ | $10\%\text{--}30\%$ CPU penalty; boundary memory copies for large buffers. | Linear memory sandbox via Wasm runtime. | High-frequency filtering, transformation, and lightweight logic. |
| **Unix Domain Sockets (UDS)** | $100\,\mu\text{s}\text{--}1\text{ ms}$ | Minimal OS context switching; single-machine IPC serialization. | OS process boundary + IPC sockets. | High-throughput local adapters up to tens of thousands of ops/sec. |
| **gRPC / Localhost TCP** | $5\text{--}50\text{ ms}$ | Full network stack traversal, HTTP/2 framing, and Protobuf encoding. | Container / Pod boundary (Kubernetes / Docker). | Complex vendor SDKs, polyglot runtimes with independent lifecycles. |
| **External Remote HTTP/SaaS** | $> 100\text{ ms}$ | Network transit latency, TLS handshakes, WAN jitter, and availability risk. | Remote network boundary. | Out-of-band normative baseline sync and async attestation logging. |

### 3.2 Overhead Mitigation Patterns

1. **Payload Batching:** Amortize IPC context switching and network framing costs by aggregating fine-grained operations into vectorized batch calls.
2. **POSIX Shared Memory (SHM):** Utilize memory-mapped ring buffers (`shm_open`, `mmap`) for high-bandwidth data transfers (e.g., telemetry streaming, large document verification) to eliminate socket memory copy overhead.
3. **Zero-Copy Binary Serialization:** Prefer FlatBuffers, Cap'n Proto, or Protocol Buffers over JSON to eliminate textual parsing and allocation bottlenecks.
4. **Hot-Path Decoupling:** Never place synchronous remote network calls on the critical decision path. Reserve synchronous gates strictly for sub-millisecond local evaluation, and handle remote validation asynchronously or adaptively.

---

## 4. Interface Design: Capability-Based Pattern

A frequent anti-pattern in plugin architectures is the **"Fat Interface"**, where every adapter is forced to implement the entire superset of platform methods—inevitably causing widespread `NotImplementedError` or stub methods that fail at runtime.

Instead, the architecture must decompose contracts into a **universal minimal base interface** combined with **runtime-discoverable capability interfaces**.

```text
┌────────────────────────────────────────────────────────┐
│                      BaseAdapter                       │
│  - id: string                                          │
│  - init(config): Promise<void>                         │
│  - healthCheck(): Promise<boolean>                     │
│  - getCapabilities(): Set<Capability>                  │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
┌──────────────┐   ┌─────────────────┐   ┌────────────────────────┐
│ BatchCapable │   │  StreamCapable  │   │   AttestationCapable   │
│ Adapter      │   │  Adapter        │   │   Adapter              │
└──────────────┘   └─────────────────┘   └────────────────────────┘
```

### 4.1 TypeScript Specification

```typescript
// 1. Universal Capability Flags
export type Capability = 
  | 'BATCHING' 
  | 'STREAMING' 
  | 'ENCRYPTED_STORAGE' 
  | 'ATTESTATION_SEAL';

// 2. Minimal Base Contract (Every adapter MUST implement this)
export interface BaseAdapter {
  readonly id: string;
  readonly version: string;
  init(config: Record<string, unknown>): Promise<void>;
  healthCheck(): Promise<boolean>;
  getCapabilities(): Set<Capability>;
  shutdown(): Promise<void>;
}

// 3. Granular Capability Interfaces
export interface BatchCapableAdapter extends BaseAdapter {
  executeBatch<TInput, TOutput>(items: TInput[]): Promise<TOutput[]>;
}

export interface StreamCapableAdapter extends BaseAdapter {
  openStream<TChunk>(channel: string): AsyncIterable<TChunk>;
}

export interface AttestationCapableAdapter extends BaseAdapter {
  signAttestation(evidenceDigest: string): Promise<{ signature: string; certificateChain: string[] }>;
}
```

### 4.2 Python Specification (CAGE Structural Protocols)

In Python-based runtimes like CAGE, capability contracts are implemented via structural subtyping ([PEP 544 `typing.Protocol`](../../src/gateway/governance/contracts.py)):

```python
from enum import Enum
from typing import Any, Protocol, runtime_checkable

class AdapterCapability(str, Enum):
    BATCHING = "BATCHING"
    STREAMING = "STREAMING"
    ATTESTATION = "ATTESTATION"
    ASYNC_VALIDATION = "ASYNC_VALIDATION"

@runtime_checkable
class BaseAdapterProtocol(Protocol):
    @property
    def adapter_id(self) -> str: ...
    
    async def initialize(self, config: dict[str, Any]) -> None: ...
    async def health_check(self) -> bool: ...
    def get_capabilities(self) -> set[AdapterCapability]: ...
    async def shutdown(self) -> None: ...

@runtime_checkable
class BatchExecutionProtocol(BaseAdapterProtocol, Protocol):
    async def execute_batch(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]: ...

@runtime_checkable
class AttestationProtocol(BaseAdapterProtocol, Protocol):
    async def seal_evidence(self, evidence_hash: str) -> dict[str, Any]: ...
```

### 4.3 Graceful Feature Handling & Orchestration

* **Runtime Capability Negotiation:** The platform queries `adapter.get_capabilities()` during container initialization or request dispatch. If an unsupported action is requested, the system raises a structured `UnsupportedCapabilityError` rather than failing mid-flight.
* **Platform-Level Orchestration Fallbacks:** If an adapter lacks an optional capability (such as native batch execution), the host platform automatically falls back to iterating single-item executions concurrently.
* **Extensible Typed Metadata:** Standard contracts include a typed `metadata?: Record<string, unknown>` escape hatch, allowing vendor-specific parameters without polluting common schemas.

---

## 5. Alignment with CAGE Reference Architecture

The principles of this specification directly reflect and extend the architectural invariants of the [Cybernetic Agent Governance Engine (CAGE)](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md).

### 5.1 Domain-Agnostic Kernel & Mathematical Invariants

* The CAGE execution engine is a domain-agnostic invariant state-space controller enforcing:
  $$\mathcal{C} = \{ x \in \mathbb{R}^n \mid h(x) \geq 0 \}$$
* Adapters provide domain-specific translations (e.g., mapping cash balance, drug concentration, or actuator torque to $x$), while the kernel evaluates $h(x) \geq 0$ without domain coupling.
* Compliance profiles are loaded dynamically into [`ControlRegistry`](../../src/gateway/governance/constants.py) without modifying kernel logic.

### 5.2 Vendor-Isolated Integration Boundary

* All third-party compliance and attestation providers reside under [`src/integrations/{vendor}/`](../../src/integrations/) (e.g., [`provider_01`](../../src/integrations/provider_01/), [`provider_02`](../../src/integrations/provider_02/), [`provider_05`](../../src/integrations/provider_05/)).
* Lazy import factories in `src/integrations/__init__.py` ensure vendor SDK dependencies are never loaded into memory unless explicitly activated via environment variables.

### 5.3 Deterministic Hot-Path Protection & Adaptive Gating

* **Hot-Path Guarantee:** The critical decision path (SymbolicGovernor 8-tier pipeline, CBF evaluation) runs strictly in sub-microseconds to low milliseconds and **never makes synchronous remote network calls**.
* **Adaptive Gating:** Under [`enforce_fria_boundary()`](../../src/gateway/governance/normative_provider.py), high-confidence transactions ($\ge 0.95$) trigger async fire-and-forget attestations (0ms overhead), ambiguous transactions ($[0.70, 0.95)$) route to the synchronous `DEFER` queue state machine, and low-confidence transactions ($< 0.70$) are denied locally without network calls.

### 5.4 State Concurrency & TOCTOU Resolution

* Out-of-process adapters must never execute uncoordinated read-then-write operations on shared state.
* CAGE eliminates Time-of-Check to Time-of-Use (TOCTOU) windows by executing atomic state transitions inside Redis via Lua scripts ([`LUA_ATOMIC_CBF`](../../src/gateway/governance/cbf.py)) and atomic pre-reservations ([`FiscalLimitGuard`](../../src/gateway/governance/fiscal_limit_guard.py)).

### 5.5 Compliance Assessment & Four-State Semantics

* Adapter outputs mapped into OSCAL evidence chains follow the strict four-state vocabulary defined in [`types.py`](../../src/compliance_bridge/types.py):
  * `PASS` (`satisfied`): Control evaluated; evidence meets criteria.
  * `FAIL` (`not-satisfied`): Control evaluated; evidence breached boundary.
  * `NOT_APPLICABLE` (`not-applicable`): Deliberate scoping exclusion by design.
  * `ERROR` (`error`): Adapter execution or data collection failure.
* **Critical Invariant:** An adapter communication or execution failure MUST be emitted as `ERROR`. It must never be silently masked or coerced to `NOT_APPLICABLE`.

### 5.6 Cryptographic Evidence & Non-Formation Proofs

* All adapter decisions, denials, and pauses are bound to deterministic cryptographic receipts ([`RefusalReceipt`](../../src/gateway/governance/contracts.py#L53-L131), [`PauseReceipt`](../../src/gateway/governance/contracts.py#L134-L177)).
* Receipts are canonicalized using RFC 8785 (JCS) via [`jcs_canonicalize_plan`](../../src/gateway/governance/jcs_canonicalizer.py) and sealed using Cloud KMS HSM signatures to guarantee non-repudiation.

---

## 6. Implementation & Integration Checklist

When developing or onboarding a new plugin or adapter into the CAGE ecosystem, verify the following requirements:

* [ ] **Boundary Isolation:** Adapter runs out-of-process (UDS / gRPC sidecar) or within a Wasm sandbox. No dynamic native in-process imports.
* [ ] **Contract Compliance:** Implements [`BaseAdapterProtocol`](../../src/gateway/governance/contracts.py) and declares explicit capabilities via `get_capabilities()`.
* [ ] **Strict I/O Validation:** Inbound and outbound payloads are validated against strict JSON schemas or Protobuf definitions.
* [ ] **Deadlines & Timeouts:** All asynchronous operations enforce strict timeouts ($< 50\text{ ms}$ for local sidecars, configurable for out-of-band syncs).
* [ ] **Fail-Closed Resiliency:** If the adapter fails or becomes unreachable, the host platform safely fails closed and records an `ERROR` finding.
* [ ] **Evidence Integrity:** Any governance evidence produced by the adapter is deterministic, RFC 8785 canonicalizable, and cryptographically signable.
