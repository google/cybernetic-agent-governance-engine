# Contributor Acknowledgments

This document recognizes external contributors who have identified security issues, correctness bugs, and improvements in the CAGE reference architecture.

---

## Security Research Contributions

### Nussaibah Shaikh (@nussaibah-shaikh)

**Contributions:** August 2026

#### PR #93: Zero Balance Masking Bug
**Severity:** CRITICAL correctness issue

Discovered that the truthiness test `if not balance_value` in [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py) treated legitimate `0.0` balances as missing data, causing drained accounts to receive fallback balances. This would have allowed the CBF barrier `h(x) = cash - min_cash` to clear trades against empty accounts, silently undermining POAM-2026-023 reconciliation enforcement.

**Fix:** Modified `GcsLedgerProvider` and `ObjectStoreLedgerProvider` to use explicit `is None` checks, ensuring accurate 0.0 balances are returned.

**Test Coverage:** 26 tests with regression tests proving the bug.

#### PR #94: SPIFFE ID Keying Collision
**Severity:** HIGH — permission confusion vulnerability

Discovered that [`src/gateway/governance/opa.py`](../src/gateway/governance/opa.py) keyed the agent catalog on the last path segment of SPIFFE IDs instead of full identities. Two agents with SPIFFE IDs sharing a trailing segment (e.g., `spiffe://trust-domain-a/sa/trader-agent` and `spiffe://trust-domain-b/sa/trader-agent`) would collapse onto the same key, allowing the second entry to overwrite the first agent's permissions.

**Attack Vector:** An attacker could register an agent with a carefully chosen SPIFFE ID suffix to inherit another agent's grants.

**Fix:** Changed keying to full SPIFFE identity, aligning with how [`config/opa/agent_catalog.rego`](../config/opa/agent_catalog.rego) consumes the data.

**Test Coverage:** 58 tests with regression test `test_parse_registry_response_keys_on_full_spiffe_identity`.

---

### Miracle Owolabi (External Security Researcher, OWASP AI Exchange Author)

**Contributions:** August 2026

#### POAM-2026-023: External Reconciliation Not Enforced on Atomic Commit Path
**Severity:** CRITICAL — bypassed five separate controls

Discovered that `LUA_ATOMIC_CBF` read `safety:current_cash` directly instead of KMS-signed reconciled balance from `reconciliation:verified_balance`, bypassing:
1. KMS signature verification
2. `_CBF_STRICT_MODE` fail-closed behavior
3. R-04 replay sequence defense
4. TTL staleness rejection
5. R-05 fence-epoch validation

**Additional Findings:**
- Fence-epoch regression detection (R-05) was implemented but never executed on commit path
- Local debit tracking gap allowed double-spend within reconciliation window

**Remediation:** Created `_resolve_ground_truth_balance()` seam for KMS-verified balance resolution, modified `LUA_ATOMIC_CBF` to accept ground truth balance, added fence-epoch validation and local debit tracking on commit path.

**Test Coverage:** 5 new test cases in [`tests/test_cbf_reconciliation.py`](../tests/test_cbf_reconciliation.py).

---

## Foundational Reference Architecture & Architectural Review

### Krti Tallam

**Contributions:** August 2026

#### Foundational Architecture: The Five-Plane Reference Model
Author of the foundational paper:
> Tallam, K. (2026). *A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents*. arXiv:2606.12320.

CAGE was created as a concrete open-source implementation of the architecture invited by this paper, adopting its five-plane taxonomy, four formal correctness invariants (*Composed Authority, Mediation Coverage, Bounded Composite Authority, Evidence Sufficiency*), and six-primitive interruption framework.

#### Architectural Code Review & Safety Boundary Audit
**Severity:** CRITICAL architectural & correctness findings across distributed concurrency, durability, and formal verification:

1. **Redis Failover Double-Spend TOCTOU (Bounded Composite Authority):**
   Discovered that Lua `evalsha` atomicity only holds intra-primary. Without synchronous replication or fencing, managed Redis primary failover allowed a promoted replica to serve stale balances within the reconciliation window, allowing concurrent agents to re-spend headroom.
   - **Remediation:** Enforced synchronous replication quorum (`CAGE_REDIS_WAIT_REPLICAS >= 1`), monotonic fence-epoch rejection of regressed replicas (`safety:fence_epoch`), and multi-agent model checking in [`proof/distributed_cbf_model.py`](../proof/distributed_cbf_model.py).

2. **Fail-Open Evidence Decoupling (Evidence Sufficiency):**
   Discovered that the audit sink was fail-open and uncoupled from routing seal issuance, meaning in-memory HMAC seals allowed tool actuation to proceed without durable evidence writes to the hash-chain.
   - **Remediation:** Defaulted `EVIDENCE_CHAIN_BLOCKING=true`, updated [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) to block seal release on chain commit (`generate_seal_with_evidence()`), and added fast-fail startup preconditions in [`src/compliance_bridge/evidence_stream.py`](../src/compliance_bridge/evidence_stream.py).

3. **Governor Automaton Proof Scoping (Mediation Coverage):**
   Identified that `model.py` verified single-request slot commutativity without modeling distributed cross-agent Redis contention or live actuator refinement.
   - **Remediation:** Reframed §4.4 and Appendix A of the CAGE paper to explicitly scope automaton proofs to the governor model, adding `distributed_cbf_model.py` and marking live execution refinement as an open research boundary.

4. **Six-Primitive Interruption Taxonomy Alignment:**
   Caught that the runtime vocabulary had collapsed toward binary allow/deny, with `DEFER` falling back to `DENY` and `PAUSE`/`NARROW` lacking execution branches.
   - **Remediation:** Implemented HTTP 202 parking for `DEFER` and added dedicated execution branches for `PAUSE` and `NARROW` in [`src/gateway/governance/pause_primitive.py`](../src/gateway/governance/pause_primitive.py) and [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py).

---

## Impact Summary

| Contributor | PRs/Findings | Severity Distribution | Test Coverage Added |
|-------------|--------------|----------------------|---------------------|
| Krti Tallam | Foundational Architecture + 4 Critical Architectural Audit Findings | Foundational Architecture, 4 CRITICAL Architectural Defects | Formal verification models (`proof/distributed_cbf_model.py`), failover & evidence test suites |
| Nussaibah Shaikh | 2 PRs | 1 CRITICAL, 1 HIGH | 84 tests |
| Miracle Owolabi | 1 finding (POAM-2026-023) | 1 CRITICAL | 5 tests |

**Total Security/Correctness Issues Identified:** 7  
**Controls Strengthened:** AC-2, SC-4, SI-2, AU-12, SC-12, IA-3, CM-6

---

## Recognition Policy

CAGE is a reference architecture with no production deployments to maintain. Contributors who identify security issues, correctness bugs, or architectural improvements are acknowledged here. This document serves as a record of community contributions to the reference design.

For questions about contributing security research, see [`SECURITY.md`](../SECURITY.md).
