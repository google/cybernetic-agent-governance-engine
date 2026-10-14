# CAGE ⇄ ThreeLineage (Ky Nash) Technical Architecture Sync — Prep Brief

**Date:** Thursday, October 8, 2026  
**Time:** 10:00 – 10:30 EDT (15:00 – 15:30 BST / 14:00 – 14:30 UTC) · 30 minutes  
**Attendees:** Lars Ahlfors (CAGE, Google) · Ky Nash (Creator, ThreeLineage: Sigilith / TraceGuard / AXIOMOS)  
**Meeting Link:** [https://meet.google.com/vub-wzhn-qqr](https://meet.google.com/vub-wzhn-qqr)  
**Dial-in:** (US) +1 253-289-6880 · PIN: 635 985 533 91#  
**Objective:** Ratify the composition boundary between CAGE's distributed governance control plane and ThreeLineage's local host containment/evidence frameworks (AXIOMOS / TraceGuard). Evaluate the "Dual-Authority Containment" model where CAGE issues distributed cryptographic routing seals and AXIOMOS independently mediates local OS execution via Unix-domain sockets.

---

## 1. Executive Summary & Context

Ky Nash reached out following public work on CAGE’s formal verification models, specifically noting convergence across three technical pillars:
1. **Deterministic Runtime Containment (`No-Direct-Bind`)**
2. **AST-Level Policy & Boundary Enforcement**
3. **Immutable Cryptographic Audit Ledgers & Refusal Proofs**

Ahead of the sync, Ky clarified the ThreeLineage system boundaries and proposed an architectural composition:
> *"Rather than treating CAGE and AXIOMOS as interchangeable gates, I'd like to explore a model where a distributed CAGE routing seal arrives as an external authority assertion, AXIOMOS independently evaluates whether local execution is permitted, and TraceGuard records the resulting local evidence. In other words, neither side's classification automatically becomes the other's authority."*

This brief details the architectural mapping, prepares comparative analysis on durability and latency trade-offs, and structures a concise 30-minute agenda to exit with a clear interface boundary.

---

## 2. Terminology & Framework Architecture

To ensure high-bandwidth technical alignment, the ThreeLineage and CAGE component responsibilities are mapped below:

### ThreeLineage Architecture (Ky Nash)
ThreeLineage is the umbrella entity comprising three distinct frameworks with isolated authority domains:
- **Sigilith:** Structural decoding and AST analysis.
- **TraceGuard:** Audit, integrity, and execution evidence. Hash-chained tamper-evident provenance recording execution intents, parameter mutations, and denials.
- **AXIOMOS:** Governance, authority, and host runtime containment. Enforces strict default-deny boundaries at localized Unix-domain socket IPC mediation points prior to OS execution (file writes, process execution, external tool invocation). Features durable interlocks on interrupted sessions.
- **Current Integration Candidate (Frozen Post-Adversarial Testing):** Enforces a strict conjunction rule: `LOW_RISK` alone is insufficient to execute; the boundary requires `(AXIOMOS == ALLOW) ∧ (RiskScore == LOW_RISK)`. Unknown, malformed, and contradictory decision states fail closed.

### CAGE Architecture Mapping (v3.1.0)
- **Layer 1 Governance Kernel:** Strictly domain-agnostic, vendor-neutral STERA Admissibility Engine and [SymbolicGovernor](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/governor/symbolic_governor.py).
- **Actuation Seam:** Downstream [ExecutionActuator](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/seams/actuation.py#L41-L47) and [ExecutionClearance](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/seams/actuation.py#L51-L168) protocol where CAGE acts as the **issuer of authority**, not the consumer.
- **Single-Use Cryptographic Routing Seal:** Short-lived asymmetric JWS routing seal issued via [generate_seal_with_evidence()](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/routing_seal.py#L35-L52), verified and atomically consumed by [verify_and_consume_seal()](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/routing_seal.py#L1115-L1150) before actuation.
- **Evidence Pipeline:** Synchronous compare-and-append Lua commit (`_APPEND_SCRIPT`) to RFC 8785 (JCS) canonicalized SHA-256 hash stream (`cage-audit/3.0`), paired with `RefusalReceipt` non-formation proofs and out-of-band KMS batch signing via `EvidenceCustodian`.

---

## 3. The Core Discussion: Dual-Authority Composition

```
                                  DISTRIBUTED CLOUD / CLUSTER PLANE
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  Agent Intent / Request                                                                │
│         │                                                                              │
│         ▼                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ CAGE Gateway Replica (Stateless Pod)                                             │  │
│  │  ├─ STPA Compiled OPA Rego & NeMo Rails (compiled via stpa_compiler.py)           │  │
│  │  ├─ Distributed Control Barrier Functions (DistributedCBF.tla via Redis Lua)      │  │
│  │  └─ SymbolicGovernor: Two-Phase Admission (NoDirectBind BFS verified)            │  │
│  └────────────────────────────────────────┬─────────────────────────────────────────┘  │
│                                           │                                            │
│            ┌──────────────────────────────┴──────────────────────────────┐             │
│            ▼                                                             ▼             │
│     [DENY / REFUSE]                                              [ALLOW]               │
│            │                                                             │             │
│     RefusalReceipt                                         generate_seal_with_evidence │
│  (Non-Formation Proof)                                                   │             │
│            │                                             ExecutionClearance (JWS Seal) │
│            ▼                                                             │             │
│   Commit to cage-audit/3.0                                               │             │
└───────────────────────────────────────────┬──────────────────────────────┼─────────────┘
                                            │                              │
                                            │ (Network / Actuator Handoff) │
                                            ▼                              ▼
                                  LOCAL HOST / OS EXECUTION CONTAINER
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  Host Actuator / Sandbox Supervisor                                                    │
│         │                                                                              │
│         │  1. Transmit Clearance over Unix-Domain Socket                               │
│         ▼                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ AXIOMOS (Local IPC Mediation Boundary)                                           │  │
│  │  ├─ Ingest CAGE Routing Seal (External Authority Assertion)                       │  │
│  │  ├─ Sigilith Structural Decoding & AST-level Payload Policy Enforcement          │  │
│  │  ├─ Local Context & Risk Verification: (AXIOMOS == ALLOW) ∧ (Risk == LOW_RISK)   │  │
│  │  └─ Check Durable Interlocks (fail-closed if interrupted or unverified)          │  │
│  └────────────────────────────────────────┬─────────────────────────────────────────┘  │
│                                           │                                            │
│                     ┌─────────────────────┴─────────────────────┐                      │
│                     ▼                                           ▼                      │
│              [LOCAL REJECT]                              [LOCAL ALLOW]                 │
│                     │                                           │                      │
│                     │                                  Consume CAGE Seal Nonce         │
│                     │                                           │                      │
│                     │                                  Execute OS / Tool Call          │
│                     │                                  (File Write / Process Exec)     │
│                     │                                           │                      │
│                     ▼                                           ▼                      │
│             TraceGuard Evidence                         TraceGuard Evidence            │
│          (Local Denial Ledger)                       (Local Execution Ledger)          │
│                     │                                           │                      │
│                     └─────────────────────┬─────────────────────┘                      │
│                                           │                                            │
│                                    ActuationReceipt                                    │
│                                (ACCEPTED / REJECTED)                                   │
│                                           │                                            │
│         ▲                                 │                                            │
│         └─────────────────────────────────┴────────────────────────────────────────────┘
│                                           │ (Return across Seam)
│                                           ▼
│  CAGE Gateway: Ingest ActuationReceipt into cage-audit/3.0 & Net Reserves
```

### Invariants of the Proposed Composition:
1. **No Transitive Authority:** Neither system subordinates its invariants to the other.
   $$\text{Execute} \iff \text{CAGE}(\text{Seal}) = \text{VALID} \land \text{CAGE}(\text{Nonce}) = \text{CONSUMED} \land \text{AXIOMOS} = \text{ALLOW} \land \text{Risk} = \text{LOW\_RISK}$$
2. **Defense-in-Depth:**
   - CAGE enforces distributed multi-tenant limits, multi-replica linearizable state, cross-session CBF budgets, and regulatory compliance policies (NIST SP 800-53 / EU AI Act).
   - AXIOMOS enforces local host hypervisor isolation, AST payload invariants, OS system-call mediation (preventing subversion of local file writes/tools), and host-level crash recovery.
3. **Trace Ingestion:** TraceGuard records the low-level local OS execution proof; CAGE ingests the resulting signed `ActuationReceipt` into `cage-audit/3.0`, providing end-to-end provenance from intent to physical actuation.

---

## 4. Deep-Dive Comparison & Discussion Topics

| Dimension | CAGE v3.1.0 Approach | ThreeLineage / AXIOMOS Approach | Discussion Angle for Tomorrow |
|---|---|---|---|
| **Linearizability & Scope** | **Multi-Replica Horizontal:** Stateless pods serialized via atomic Redis Lua compare-and-append (`_APPEND_SCRIPT` checking `XREVRANGE ... COUNT 1` + `WAIT 1`). Verified via [DistributedCBF.tla](file:///Users/laah/Code/cybernetic-governance-engine/proof/DistributedCBF.tla). | **Single-Host Localized:** Localized IPC mediation and Unix-socket framing. Ky noted: local interlocks proven, but multi-replica linearizability intentionally out of scope. | How the distributed control plane (CAGE) hands off to single-host execution instances (AXIOMOS) without state split-brain. |
| **Hot Path Latency** | **~1–3 ms:** In-process JCS canonicalization + pod `asyncio.Lock` serialization + single-roundtrip Redis Lua script. Heavyweight Cloud KMS batch signing and WORM/ClickHouse persistence offloaded to `EvidenceCustodian`. | **Sub-millisecond IPC:** Local Unix domain sockets. | What are TraceGuard’s local durability semantics? (Synchronous `fsync()` vs WAL vs memory buffer with background flush)? |
| **AST Enforcement** | **Compile-Time & Boundary:** [stpa_compiler.py](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/stpa_compiler.py) compiles Unsafe Control Actions into Rego policies. CI Gate G3 ([check_import_boundaries.py](file:///Users/laah/Code/cybernetic-governance-engine/scripts/check_import_boundaries.py)) enforces kernel AST neutrality. | **Runtime Payload AST:** AXIOMOS traverses tool-calling payloads at the IPC boundary to ensure invocations cannot mutate execution flow outside authorized AST nodes. | How does AXIOMOS parse and validate tool payloads at the Unix socket? Is there a formal grammar or JSON-AST schema? |
| **Interlocks & Deferral** | **Multi-Turn Distributed Deferrals:** `SingleUseDeferralTicket` in [DeferQueue](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/defer_queue.py) ([LangGraphHarness.tla](file:///Users/laah/Code/cybernetic-governance-engine/proof/LangGraphHarness.tla)), monotonic fence epochs (`safety:fence_epoch`), `POST_HITL` revalidation. `ReservationScope` LIFO saga compensation with `[UNROLLED_COMMIT]` interlock on mid-flight failure. | **Durable Host Interlocks:** Interrupted sessions or broken transitions trigger durable interlocks; no unverified execution path can resume without manual reconciliation. | How do AXIOMOS durable interlocks persist across host crashes/reboots? How does AXIOMOS signal an interlock state back to CAGE? |
| **Refusal Semantics** | **First-Class Non-Formation:** `RefusalReceipt` emitted on `DENY`, hashed via JCS SHA-256, and chained to `cage-audit/3.0` stream. | **First-Class Cryptographic Denial:** TraceGuard hashes blocked/rejected actions, parameter mutations, and denials into the ledger. | Complete alignment: proving *why* an agent was intercepted is co-equal to proving what it executed. |

---

## 5. Proposed 30-Minute Agenda

| Time Window | Topic | Lead | Focus |
|---|---|---|---|
| **00:00 – 05:00** | **Framing & Architecture Alignment** | Lars / Ky | - Confirm Reference Architecture posture (clean structural clarity > operational legacy).<br>- Acknowledge ThreeLineage taxonomy (Sigilith vs TraceGuard vs AXIOMOS). |
| **05:00 – 15:00** | **The Dual-Authority Composition** | Ky / Lars | - Walk through the clearance handoff: CAGE JWS routing seal transmitted over Unix socket to AXIOMOS.<br>- Validate the conjunction: `(CAGE == ALLOW) ∧ (AXIOMOS == ALLOW) ∧ (LOW_RISK)`.<br>- Confirm neither side's classification overrides the other. |
| **15:00 – 22:00** | **Technical Mechanics & Trade-offs** | Lars / Ky | - **Durability vs Latency:** Compare Redis Lua compare-and-append with TraceGuard's local Unix socket / `fsync` model.<br>- **Runtime AST Policy:** Deep-dive into AXIOMOS's tool payload structural enforcement.<br>- **Interlock Coordination:** How AXIOMOS host interlocks interface with CAGE's `DeferQueue` and saga rollbacks. |
| **22:00 – 30:00** | **Concrete Next Steps & Collaboration** | Lars / Ky | - Define candidate interface: Could AXIOMOS be integrated as an `actuator_04` adapter under [src/integrations/](file:///Users/laah/Code/cybernetic-governance-engine/src/integrations/)?<br>- Agree on next steps (spec exchange, potential prototype seam). |

---

## 6. Targeted Questions & Probes for Ky

1. **On AXIOMOS Unix-Socket Framing:**
   - What wire format or framing protocol does AXIOMOS use over Unix domain sockets (e.g. length-prefixed protobuf, netstring JCS JSON, CBOR)?
   - How does AXIOMOS expect external clearance assertions (like CAGE's JWS routing seal) to be presented? Does it unpack JWT/JWS claims natively, or does it expect an envelope wrapper?
2. **On Runtime AST Payload Enforcement (Sigilith / AXIOMOS):**
   - When AXIOMOS enforces structural policy on tool payloads, does it validate against a declarative schema/grammar, or does it evaluate dynamic AST rewrite rules?
   - How does it handle polymorphic or free-form tool inputs (e.g. bash commands, SQL fragments, arbitrary code execution)?
3. **On TraceGuard Durability & Crash Recovery:**
   - In the event of an ungraceful host power kill or kernel panic, what durability guarantees does TraceGuard provide for the local hash chain? Is every entry synchronously `fsync`'d, or is there an epoch flush interval?
   - When an AXIOMOS durable interlock is tripped, what does the operator reconciliation workflow look like? Is it a signed cryptographic administrative token, or a CLI manual state mutation?
4. **On Composition with CAGE:**
   - If we constructed an `actuator_04` adapter implementing CAGE's [ExecutionActuator](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/seams/actuation.py#L41-L47) interface that forwards [ExecutionClearance](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/seams/actuation.py#L51-L168) over a local Unix domain socket to AXIOMOS, would you be interested in validating that against your frozen test suite?

---

## 7. Desired Meeting Outcomes

1. **Ratified Conceptual Seam:** Common agreement on the "Dual-Authority Containment" model (CAGE = distributed authority issuer; AXIOMOS = host IPC gate & OS containment; TraceGuard = host evidence sink).
2. **Protocol Interface Outline:** Defined wire contract for passing CAGE JWS routing seals into AXIOMOS via Unix domain socket.
3. **Follow-Up Action:** Decision on drafting an architectural blueprint or reference adapter specification (`actuator_04` in CAGE) demonstrating the composition.
