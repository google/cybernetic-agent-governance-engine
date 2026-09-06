# CAGE Formal Verification Architecture

This directory contains the dual-layer formal verification suite for CAGE's governance architecture, providing exhaustive state-space proofs and TLA+ model checking for critical safety invariants.

## Overview

CAGE employs a **two-layer verification strategy**:

1. **Layer 1: Python BFS State-Space Enumeration** (`model.py`) — Exhaustive exploration of the governance pipeline state machine using breadth-first search
2. **Layer 2: TLA+ Model Checking** (`.tla` specs + `.cfg` configs) — Temporal logic verification of distributed consensus, CBF barriers, FTRA boundaries, and LangGraph harness integrity

This dual approach provides:
- **Completeness**: BFS enumerates every reachable state (no under-approximation)
- **Expressiveness**: TLA+ temporal logic captures liveness and concurrency properties
- **Independence**: Two distinct proof techniques reduce systematic error risk

## Layer 1: Python BFS Proof (`model.py`)

### What It Proves

The **No-Direct-Bind** invariant:

```
NoDirectBind ≜ (phase = "EXECUTED") ⇒ (resolvedAllow = TRUE)
```

**Informal**: Every action execution must be preceded by a valid routing seal issued only after all governance tiers pass.

### Scope

Models the 9-tier CAGE governance pipeline (updated for ARCH-1):

| Tier | Name | Role |
|------|------|------|
| 0.5 | FTRA | Action classification & reachability analysis |
| 1 | STPA | STAMP/STPA unsafe control action check |
| 2 | Confidence | Agent confidence threshold |
| 3a | CBF | Control Barrier Function (Redis cash barrier) |
| 3b | OPA | OPA Rego policy evaluation |
| 4 | Fiscal | Fiscal limit pre-reservation |
| 5 | Consensus | Multi-agent consensus gate |
| 6 | Causal | DoWhy causal gatekeeper |
| 7 | FRIA | FRIA normative boundary enforcement |

**Note**: Tier 3 (CBF/OPA) is split because these checks run concurrently via `asyncio.gather()`. The proof verifies the invariant holds under every interleaving.

### State Counts (Post-ARCH-1)

| Model Variant | Reachable States | Invariant Holds? |
|---------------|------------------|------------------|
| Gated (correct CAGE) | 44 | ✅ TRUE |
| Ungated (direct-bind) | 21 | ❌ FALSE (counterexample) |
| Concurrent CBF∥OPA | 49 | ✅ TRUE |
| Skipped tier (CBF/causal) | 43 | ✅ TRUE (structural) |

### Gap Proofs

The model proves four concrete CAGE gaps:

- **Gap 1**: Ungated architecture violates NoDirectBind (seal gate is load-bearing)
- **Gap 2**: `govern()` without seal issuance violates NoDirectBind
- **Gap 3**: `CBF_FAIL_OPEN` preserves structure but removes a mandatory check
- **Gap 4**: DoWhy `ImportError` (causal tier silently skipped) preserves structure but removes a mandatory check

### NARROW/PAUSE States (C1-sub Audit Remediation)

- **NARROW**: Soft threshold exceeded → seal issued on clamped parameters (ALLOW variant, `resolvedAllow=TRUE`)
- **PAUSE**: Transient condition (rate limit, circuit breaker) → no seal, retryable (`resolvedAllow=FALSE`)

### Running the Proof

```bash
# Standalone execution (no dependencies)
uv run python proof/model.py

# Regression tests (pins published state counts)
uv run pytest tests/test_no_direct_bind_proof.py -v
```

**Expected output**:
```
✅ All assertions passed.

PROVED:
  1. The gated CAGE architecture satisfies No-Direct-Bind over the
     entire reachable state space (44 states).
  2. The ungated (direct-bind) variant provably violates the invariant.
  ...
```

## Layer 2: TLA+ Model Checking

### TLA+ Specifications

| Spec File | Scope | Invariants |
|-----------|-------|------------|
| `DistributedCBF.tla` | Multi-agent Redis CBF barrier, fence epochs, split-brain scenarios | `SP1_NoDoubleSpend`, `SP2_ReserveNonNegative`, `SP3_AvailableNonNegative`, `SP4_FenceEpochMonotonic` |
| `FtraBoundary.tla` | FTRA action classification, controller boundary coverage, fail-closed semantics | `ControllerBoundaryCoversInGraphBypass`, `FailClosedOnUnknownAction`, `NetworkPolicyEnforced` |
| `LangGraphHarness.tla` | LangGraph state machine, evidence chain, seal issuance, HITL timeout safety | `NoDirectBind`, `EvidenceChainIntegrity`, `SealGateIntegrity`, `HITLTimeoutSafety`, `OutputRailCoverage` |

### TLA+ Config Files

Each `.tla` spec has a corresponding `.cfg` config file that defines:
- **Constants**: Model parameters (agent sets, thresholds, timeout bounds)
- **Invariants**: Safety properties to check
- **Deadlock checking**: Enabled for all specs

Example config (`DistributedCBF.cfg`):
```
SPECIFICATION Spec

CONSTANTS
    Agents = {a1, a2}
    InitialAvailable = 1000
    MaxAmount = 500

INVARIANTS
    TypeOK
    SP1_NoDoubleSpend
    SP2_ReserveNonNegative
    SP3_AvailableNonNegative
    SP4_FenceEpochMonotonic

CHECK_DEADLOCK TRUE
```

### Running TLC Model Checker

TLC (TLA+ model checker) requires manual installation of the TLA+ Toolbox.

**Installation**:
1. Download TLA+ Toolbox from: https://github.com/tlaplus/tlaplus/releases
2. Extract `tla2tools.jar` to a known path

**Verification commands**:

```bash
# Verify distributed CBF barrier
java -cp tla2tools.jar tlc2.TLC -config proof/DistributedCBF.cfg proof/DistributedCBF.tla

# Verify FTRA boundary enforcement
java -cp tla2tools.jar tlc2.TLC -config proof/FtraBoundary.cfg proof/FtraBoundary.tla

# Verify LangGraph harness integrity
java -cp tla2tools.jar tlc2.TLC -config proof/LangGraphHarness.cfg proof/LangGraphHarness.tla
```

**Make target** (prints instructions):
```bash
make verify-tla
```

### Expected TLC Output

For each spec, TLC should report:
```
TLC2 Version 2.XX ...
Checking XX states...
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = ...
```

If an invariant is violated, TLC produces a **counterexample trace** showing the sequence of states leading to the violation.

## Architectural Notes

### Why Dual-Layer Verification?

1. **Python BFS**:
   - ✅ Exhaustive (enumerates every reachable state)
   - ✅ No dependencies (runs in CI without TLA+ toolchain)
   - ✅ Pins published state counts (regression protection)
   - ❌ No liveness properties (safety only)
   - ❌ No temporal logic (hard to express distributed properties)

2. **TLA+ Model Checking**:
   - ✅ Temporal logic (liveness, fairness, eventually properties)
   - ✅ Mature distributed systems verification (Raft, Paxos, etc.)
   - ✅ Expressive language for concurrency and non-determinism
   - ❌ Manual installation (not in CI)
   - ❌ Requires TLA+ expertise to interpret traces

### Proof/Implementation Divergence (ARCH-1)

Prior to ARCH-1, the Python BFS model **excluded FTRA** (Tier 0.5) because it runs at the LangGraph graph level, not inside `SymbolicGovernor._run_checks()`. This created a proof/implementation divergence:

- **Production**: FTRA blocks irreversible actions before `_run_checks()` executes
- **Proof**: FTRA was not modeled, so the state-space omitted action classification barriers

**ARCH-1 resolution**: FTRA is now modeled as the first tier in the BFS state machine. While FTRA's implementation remains at the LangGraph level, the proof now covers its fail-closed semantics and routing seal enforcement.

### FTRA-Specific Invariants

From `FtraBoundary.tla`:

- **ControllerBoundaryCoversInGraphBypass**: Every action reachable via `in_graph` bypass must be covered by the FTRA controller boundary (no untracked capability escalation)
- **FailClosedOnUnknownAction**: Any action not in the registry must be blocked (no default-allow)
- **NetworkPolicyEnforced**: Irreversible terminal actions require routing seal verification before network egress

These are **not provable in the Python BFS model** (which abstracts FTRA as a binary PASS/FAIL tier) but are critical for FTRA's defense-in-depth boundary. The TLA+ spec models the full action registry, reachability analysis, and network policy enforcement.

## Integration with CI

### Python BFS (Always Runs)

```yaml
# .github/workflows/ci.yml
- name: no-direct-bind-proof
  run: uv run python proof/model.py

- name: pytest-logic
  run: uv run pytest tests/test_no_direct_bind_proof.py -v
```

Regression tests pin the exact state counts (44/21/49/43). Any change to tier logic that alters these numbers fails CI and triggers a review of `docs/paper/REVISION_TRACKER.md` (published figures must stay consistent with proof).

### TLA+ (Manual Validation)

TLC is **not** in the CI pipeline because:
1. TLA+ Toolbox installation is manual (not in `pyproject.toml`)
2. TLC runtime can exceed CI timeout for large state spaces
3. TLA+ specs are **illustrative reference models** — they document intended properties but are not gatekeepers for PR merges

**Recommended workflow**:
- Run `make verify-tla` locally before major releases
- Archive TLC output in `proof/tlc_results/` with version tags
- Update TLA+ specs when distributed consensus/CBF logic changes

## References

- **Python BFS Model**: `proof/model.py`
- **TLA+ Specs**: `proof/*.tla`
- **TLC Configs**: `proof/*.cfg`
- **Regression Tests**: `tests/test_no_direct_bind_proof.py`
- **Paper Citation**: CAGE_ARXIV.MD §4.4 "Formal Verification", Appendix A
- **Revision Tracker**: `docs/paper/REVISION_TRACKER.md` (published state counts)

## License

All proof artifacts in this directory are released under the Apache 2.0 License.

The Python BFS model (`model.py`) is adapted from the open-source implementation by LalaSkye (Apache 2.0), available at: https://github.com/LalaSkye/no-direct-bind

Modifications: Extended to CAGE's 9-tier architecture, added NARROW/PAUSE states, seal consumption semantics, and FTRA tier.
