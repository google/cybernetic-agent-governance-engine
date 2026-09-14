# PROOF_CEILINGS.md — Test Proof Boundaries and Verification Scope

> **Document Status:** Canonical operational reference for test scope boundaries  
> **Last Updated:** 2026-09-14  
> **Applies To:** CAGE v3.0.1+

## Overview

CAGE enforces a **two-tier proof architecture** that separates hermetic local validation (proofs of correctness at the algorithmic layer) from live environment validation (proofs of enforcement at the kernel socket layer).

This document defines the **proof ceiling** — the maximum scope of what each test tier can prove about system behavior.

---

## 1. Local In-Memory Proof Ceiling

**Execution Context:** `make test-fast` / `uv run pytest tests/ -m "local or unit"`

**Environment:**
- In-memory Redis mock (fakeredis or custom MagicMock)
- No network sockets opened
- No live GKE cluster interaction
- No external API calls (OPA, Langfuse, Cloud KMS)

### 1.1 What Local Tests PROVE

#### ✅ JCS Canonicalization Correctness (RFC 8785)
- **Invariant:** Deterministic byte-for-byte JSON serialization
- **Proof Method:** SHA-256 digest comparison against frozen reference values
- **Example:** [`test_jcs_parameter_digest()`](../../tests/test_praxis_synthetic_reference_case.py:40)
  ```python
  canonical_bytes = jcs_canonicalize_plan(SYNTHETIC_PARAMS)
  computed_digest = hashlib.sha256(canonical_bytes).hexdigest()
  assert computed_digest == EXPECTED_PARAM_DIGEST  # Frozen reference
  ```
- **Guarantees:** Parameter hashes are stable across Python/Go/Rust implementations

#### ✅ NARROW Monotonicity (CBF Logic Structure)
- **Invariant:** Control Barrier Function (CBF) gradient never decreases for valid state transitions
- **Proof Method:** Symbolic gradient inspection on synthetic trajectories
- **Example:** [`test_cbf_narrow_monotonicity()`](../../tests/test_cbf_engine.py)
- **Guarantees:** Safety boundary logic is structurally sound (does not prove physical enforcement)

#### ✅ Authority Extinction (DEFER Immutability)
- **Invariant:** Authority-bound tokens (`upstream_permit_id` set) refuse all mutations
- **Proof Method:** Verify `approve()` and `replay_evaluate()` return `NOT_FOUND` for authority-bound tokens
- **Example:** [`test_case_b_defer_stale_evidence_authority_extinction()`](../../tests/test_praxis_synthetic_reference_case.py:145)
- **Guarantees:** Zero-authority parking principle holds (tokens expire naturally; no bypass path exists)

#### ✅ Envelope Schema v3.0 Tamper-Evident Sealing
- **Invariant:** GovernanceEnvelope v3.0 embeds external attestations under JCS canonical digest
- **Proof Method:** Construct envelope, serialize to JCS, verify digest includes attestation metadata
- **Example:** [`test_case_a_baseline_valid_permit()`](../../tests/test_praxis_synthetic_reference_case.py:62)
- **Guarantees:** Attestation metadata cannot be stripped without invalidating envelope digest

#### ✅ DEFER State Machine Transitions
- **Invariant:** Tokens transition PARKED → PARTIALLY_APPROVED → RESOLVED with quorum enforcement
- **Proof Method:** Mock Redis state verification across quorum approval sequence
- **Example:** [`test_non_authority_token_allows_approval()`](../../tests/test_defer_queue.py:823)
- **Guarantees:** Dual-control quorum logic is correct (Redis Lua script not validated)

### 1.2 What Local Tests CANNOT PROVE

#### ❌ Physical Socket Prevention
- **Gap:** `execution_state="NOT_EXECUTED"` is a string in a dict; no socket layer is instrumented
- **Reason:** Local tests mock out `ActuatorRegistry` and do not open TCP connections
- **Risk:** A logic bug in actuator dispatch could still emit network traffic despite `NOT_EXECUTED` state

#### ❌ Cilium L7 eBPF Network Policy Enforcement
- **Gap:** Kernel-level packet filtering rules are not exercised in local tests
- **Reason:** GKE cluster and Cilium CNI are not present in `pytest` runtime
- **Risk:** Misconfigured NetworkPolicy could allow egress despite governance DENY

#### ❌ Redis Lua Atomic Barriers
- **Gap:** In-memory mock does not execute Redis Lua scripts
- **Reason:** `fakeredis` or `MagicMock` simulate WATCH/MULTI/EXEC but skip Lua script evaluation
- **Risk:** Quorum race conditions in Redis Lua may not surface in local tests

#### ❌ KMS Signature Verification
- **Gap:** Envelope signature is `None` in local tests (KMS signer mocked out)
- **Reason:** Cloud KMS requires GCP project credentials and quota
- **Risk:** Signature algorithm drift or key rotation failures are not detected locally

---

## 2. Live GKE Staging Proof Ceiling

**Execution Context:** `scripts/test_live_gke_services.py` / Port-forwarded integration tests

**Environment:**
- Live GKE cluster (`cage-dev` or `cage-staging`)
- Redis at `redis-service.default.svc.cluster.local:6379`
- Cilium CNI with L7 NetworkPolicy active
- Cloud KMS, Langfuse, OPA Policy Decision Point running

### 2.1 What Live GKE Tests PROVE

#### ✅ Final Preventable Point at Kernel Socket Layer
- **Invariant:** Cilium L7 eBPF NetworkPolicy blocks egress before TCP SYN dispatch
- **Proof Method:** Issue governance-denied request; verify TCP connection refused at kernel layer (not application logic)
- **Example:** [`test_deny_blocks_network_egress()`](../../scripts/test_live_gke_services.py) (placeholder)
- **Guarantees:** Even if application logic is bypassed, kernel policy enforces deny

#### ✅ Redis Lua Atomic Barriers Under Concurrency
- **Invariant:** Quorum approval script executes atomically; no lost updates on concurrent approve calls
- **Proof Method:** Fire 10 concurrent approval requests; verify exactly N=quorum approvals recorded
- **Example:** Live load test with `scripts/run_gke_load_test.sh`
- **Guarantees:** Redis Lua script correctness under concurrency (requires live Redis instance)

#### ✅ KMS Signature Round-Trip
- **Invariant:** Governance envelope signed by Cloud KMS can be verified by public key in JWKS
- **Proof Method:** Build envelope → sign with KMS → verify signature → assert valid
- **Example:** [`test_envelope_kms_signature_verification()`](../../tests/test_governance_envelope.py)
- **Guarantees:** KMS signing algorithm matches verification algorithm (ES256 curve compatibility)

#### ✅ End-to-End Governance Decision Flow
- **Invariant:** Request → Gateway → OPA → CBF → Consensus → Envelope → Actuator → Evidence Stream
- **Proof Method:** Submit trade via `POST /v1/governed-advice`; verify evidence record in ClickHouse
- **Example:** [`docs/operations/GKE_TEST_RUNBOOK.md`](GKE_TEST_RUNBOOK.md)
- **Guarantees:** All governance tiers execute in sequence; evidence chain is unbroken

### 2.2 What Live GKE Tests CANNOT PROVE

#### ❌ Cross-Region Data Residency Enforcement
- **Gap:** Single-region staging cluster cannot validate data residency across `us-central1` / `europe-west1` / `asia-southeast1`
- **Reason:** Would require 3 parallel GKE clusters with cross-region traffic inspection
- **Mitigation:** Rely on GKE workload identity and region-scoped service accounts

#### ❌ Chaos Scenarios (Partial Network Partition, OPA Pod Crash)
- **Gap:** Controlled failure injection requires dedicated chaos environment
- **Reason:** Staging cluster runs production-grade deployments; killing pods risks operator disruption
- **Mitigation:** Separate `chaos` marker tests run on ephemeral test clusters only

---

## 3. Proof Ceiling Decision Matrix

| Property | Local Tests | GKE Staging | Production Monitoring |
|----------|-------------|-------------|----------------------|
| **JCS Canonicalization** | ✅ Proven | ✅ Proven | ✅ Monitored |
| **NARROW Monotonicity** | ✅ Proven | ⚠️ Sampled | ✅ Monitored |
| **Authority Extinction** | ✅ Proven | ✅ Proven | ✅ Monitored |
| **Envelope Schema v3.0** | ✅ Proven | ✅ Proven | ✅ Monitored |
| **Physical Socket Block** | ❌ Not Proven | ✅ Proven | ✅ Monitored |
| **Cilium eBPF Enforcement** | ❌ Not Proven | ✅ Proven | ✅ Monitored |
| **Redis Lua Atomicity** | ⚠️ Mocked | ✅ Proven | ✅ Monitored |
| **KMS Signature** | ❌ Skipped | ✅ Proven | ✅ Monitored |
| **Cross-Region Residency** | ❌ Not Proven | ❌ Not Proven | ⚠️ Inferred |
| **Chaos Resilience** | ❌ Not Proven | ❌ Not Proven | ✅ Monitored |

**Legend:**
- ✅ Proven: Test directly validates the property
- ⚠️ Sampled: Spot-checks on representative cases only
- ❌ Not Proven: Property is out of scope for this test tier

---

## 4. When to Escalate from Local to Live

**Trigger conditions for requiring live GKE validation:**

1. **New actuator integration** — Actuator dispatch code touches network sockets
2. **Cilium NetworkPolicy changes** — L7 policy rules modified in `deployment/k8s/`
3. **Redis Lua script changes** — DeferQueue approval logic or WATCH/MULTI/EXEC semantics
4. **KMS key rotation** — New signing key deployed; signature verification must pass
5. **OPA policy engine updates** — New Rego bundle deployed; decisions must match expected outcomes

**Safe to remain local-only:**
- Pure business logic changes (no network, no Redis, no KMS)
- STPA model regeneration (no runtime behavior change)
- Documentation updates

---

## 5. References

- [GKE Test Runbook](GKE_TEST_RUNBOOK.md) — Live cluster testing procedures
- [Deployment Rules](DEPLOYMENT_RULES.md) — Cloud Build vs. local Docker constraints
- [PRAXIS Synthetic Reference Case](../../tests/test_praxis_synthetic_reference_case.py) — Frozen JCS digest validation

---

**Document Changelog:**
- **2026-09-14:** Initial version (PRAXIS Alignment Phase 3)
