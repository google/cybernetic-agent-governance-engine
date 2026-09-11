# Acknowledgements & Theoretical Lineage

## Foundational Architecture

The Cybernetic Agent Governance Engine (CAGE) is an open-source reference implementation of the **Five-Plane Reference Architecture** introduced by **Krti Tallam** in:

> Tallam, K. (2026). *A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents*. arXiv:2606.12320.

CAGE directly grounds its runtime governance substrate and verification boundaries in the conceptual foundations established by that work:

- **Five-Plane Taxonomy:**
  1. *Governance / Reasoning Plane:* Implemented via `SymbolicGovernor`, multi-tier validation, and `ConfabulationScorer`.
  2. *Network Plane:* Enforced via Kubernetes NetworkPolicy L3/L4 baseline and Cilium L7 FQDN egress lockdown.
  3. *Identity Plane:* Enforced via GCP Workload Identity and Cloud KMS asymmetric signature suites (`kms_signer.py`).
  4. *Endpoint Plane:* Guarded by compiled OPA Rego policies and NeMo Colang safety rails.
  5. *Data Plane:* Enforced by discrete-time Control Barrier Functions (`cbf_engine.py`), `FiscalLimitGuard`, and `ContextAccumulator`.

- **Four Correctness Invariants:**
  - **Composed Authority:** Formal non-expansion of delegated tool permissions.
  - **Mediation Coverage:** Complete interception of actuation paths, machine-verified via exhaustive state-space model checking (`proof/model.py`).
  - **Bounded Composite Authority:** Global budget and rate bounds enforced via discrete-time Control Barrier Functions with synchronous replication fencing (`proof/distributed_cbf_model.py`).
  - **Evidence Sufficiency:** Guaranteed prior, immutable audit persistence before actuation clearance (`generate_seal_with_evidence()`).

- **Six Interruption Primitives:**
  First-class operational semantics for all six interruption primitives:
  - `BLOCK`: Direct pipeline halt with `GovernanceError`.
  - `DEFER`: Asynchronous parking in `DeferQueue` with HTTP 202 acceptance.
  - `REDACT`: Pre-execution PII and credential scrubbing (`pii_sanitizer.py`).
  - `TERMINATE`: Workflow termination with Saga WAL LIFO compensation rollback.
  - `AUDIT`: Cryptographically linked NDJSON hash-chain persistence.
  - `ESCALATE`: Quorum human-in-the-loop (HITL) routing (`hitl_escalator.py`, `ConsensusGate`).
  - *Authority Reduction:* Dedicated runtime branches for `PAUSE` and `NARROW` retaining workflow liveness while constraining execution scope.

---

## Architectural Review & Security Hardening

We express deep gratitude to **Krti Tallam** for her rigorous technical review and code audit of the CAGE codebase. Her analysis uncovered critical edge conditions that directly shaped the v3.0 and v3.1 hardening releases:

1. **Multi-Agent Redis Failover TOCTOU (Bounded Composite Authority):**
   - *Discovery:* Identified that while Lua `evalsha` ensures atomicity intra-primary, un-fenced replication allowed a promoted replica during managed Redis failover to serve stale balances, permitting concurrent agents to overspend the shared headroom before reconciliation.
   - *Remediation:* Enforced synchronous replication quorum (`CAGE_REDIS_WAIT_REPLICAS >= 1`), monotonic `safety:fence_epoch` rejection of stale replicas, and exhaustive multi-agent state verification (`proof/distributed_cbf_model.py`).

2. **Synchronous Evidence Commit (Evidence Sufficiency):**
   - *Discovery:* Caught that decoupling the cryptographic HMAC seal from durable hash-chain writes created a fail-open mediation vulnerability where actuation could proceed without durable evidence writes if the audit sink was unreachable.
   - *Remediation:* Changed `EVIDENCE_CHAIN_BLOCKING` default to `true`, integrated `generate_seal_with_evidence()` to synchronously block seal release on chain commit, and implemented fail-fast startup precondition checks (`validate_evidence_stream_preconditions()`).

3. **Formal Verification Model Scoping (Mediation Coverage):**
   - *Discovery:* Clarified that single-request automaton checks in `model.py` assume the actuator honors the seal and do not model distributed cross-agent Redis contention.
   - *Remediation:* Explicitly scoped `model.py` to the idealized governor automaton, established `distributed_cbf_model.py` for multi-agent contention proofs, and documented live execution refinement as a prioritized research boundary in the CAGE paper (§4.4, Appendix A).

4. **Interruption Primitive Operationalization:**
   - *Discovery:* Identified that runtime decisions were collapsing toward binary allow/deny, with `DEFER` falling back to `DENY` and `PAUSE`/`NARROW` lacking execution branches.
   - *Remediation:* Shipped complete execution paths for `DEFER` (HTTP 202 queue parking) and dedicated `PAUSE`/`NARROW` authority-reduction branches (`pause_primitive.py`).

---

## Community & Security Research Contributions

For additional acknowledgments of community contributors and security researchers who have strengthened CAGE's controls, please see [`docs/CONTRIBUTOR_ACKNOWLEDGMENTS.md`](docs/CONTRIBUTOR_ACKNOWLEDGMENTS.md).
