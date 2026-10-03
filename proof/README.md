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

Models the 8-tier CAGE governance pipeline (`TIERS` in `proof/model.py`; ARCH-1 added FTRA, refactor/gateway-surface-cleanup removed the dead `fria` tier):

| Tier | Name | Role |
|------|------|------|
| 0.5 | FTRA | Action classification & reachability analysis |
| 1 | STPA | STAMP/STPA unsafe control action check |
| 3b | OPA | OPA Rego policy evaluation |
| 2 | Confidence | Agent confidence threshold |
| 5 | Consensus | Multi-agent consensus gate |
| 6 | Causal | DoWhy causal gatekeeper |
| 3a | CBF | Control Barrier Function (Redis cash barrier) — phase 2 |
| 4 | Fiscal | Fiscal limit pre-reservation — phase 2 |

The rows are in `run_pipeline()` execution order: the read-only kernel stages (`KERNEL_TIERS`), the phase-1 domain tiers, then the phase-2 (mutating) tiers. Tier numbers follow the paper.

Plugin tiers (finance's `bounding`, healthcare's `dose_barrier`) add no proof states; `PLUGIN_TIER_PHASE` keeps the POST_HITL predicate from skipping a plugin-named phase-2 tier. No pipeline stage named `fria` exists, so the model has none.

**Note**: Tier 3 is split into `opa` and `cbf` because each can block the action on its own. The model evaluates tiers in the pipeline's fixed order; it does not enumerate CBF/OPA interleavings (OPA is a phase-1 read-only stage and CBF a phase-2 mutating stage, so they never run concurrently).

### State Counts (post refactor/gateway-surface-cleanup)

| Model Variant | Reachable States | Invariant Holds? |
|---------------|------------------|------------------|
| Gated (correct CAGE) | 38 | ✅ TRUE |
| Ungated (direct-bind) | 19 | ❌ FALSE (counterexample) |
| Skipped tier (causal) | 35 | ✅ TRUE (structural) |

The former "Concurrent CBF∥OPA: 49" row is gone: no function in `proof/model.py` enumerates a concurrent state space, and no test pinned that number.

### Gap Proofs

The model proves four concrete CAGE gaps:

- **Gap 1**: Ungated architecture violates NoDirectBind (seal gate is load-bearing)
- **Gap 2**: `govern()` without seal issuance violates NoDirectBind
- **Gap 4**: DoWhy `ImportError` (causal tier silently skipped) preserves structure but removes a mandatory check

### Verdict Lattice and I-6

`verdict_of()` mirrors `ClassificationEngine.classify`: HARD → DENY; OPA `MANUAL_REVIEW` or HITL → REQUIRE_APPROVAL; every finding NARROWABLE with a narrower proposal → NARROW; DEFERRABLE with confidence below the floor → DEFER; otherwise DENY; no findings → ALLOW. `verdict_lattice_holds()` checks that only ALLOW and NARROW reach `SEAL_ISSUED`. I-6 is `narrow_valid`: `phase = NARROW ⇒ seal_present ∧ resolved_allow ∧ clamped_params_valid` (it replaces `EXECUTED_unmodified`, which no model defines). Parity with the real engine is pinned in `tests/test_distributed_cbf_proof.py`.

### NARROW State (C1-sub Audit Remediation)

- **NARROW**: Soft threshold exceeded → seal issued on clamped parameters (ALLOW variant, `resolvedAllow=TRUE`)
- There is no PAUSE state. The verdict lattice is `ALLOW | NARROW | REQUIRE_APPROVAL | DEFER | DENY`; a transient infrastructure fault is a DENIED terminal with a refusal receipt. `main()` asserts every reachable phase is in `PHASES`.

### Trace Conformance (`trace_conformance.py`)

The gateway publishes one `GOVERNANCE_TRACE` event per governor decision and one per actuation ([`governor/trace.py`](../src/gateway/governance/governor/trace.py)); `PipelineResult` carries the run's `plan` and per-stage `stage_outcomes`. [`trace_conformance.py`](trace_conformance.py) projects each decision onto a `State` and checks it against `reachable_over(plan, profile)`, the gated model instantiated over that run's own tiers. It also joins each `EXECUTED` event to its seal's issuance (`no_direct_bind`) and allows one execution per seal (`single_use`). The projection keeps the first `FAIL` and treats later tiers as `PENDING`, matching the model's fail-closed step. Unsealed REQUIRE_APPROVAL, DEFER and NARROW-candidate decisions with findings are outside the model's alphabet; for them the checker only enforces "no seal, phase `CHECKING`".

```bash
uv run python scripts/check_trace_conformance.py events.jsonl   # exit 1 on findings
```

`tests/test_governance_trace_conformance.py` drives the real `SymbolicGovernor` through `govern`, `validate_action` and `revalidate_post_hitl` over 265 single- and double-fault configurations (795 decisions plus a simulated actuation per seal), checks every trace, and includes a mutation control (a governor that seals over findings is caught) and one negative control per rule.

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
     entire reachable state space (38 states).
  2. The ungated (direct-bind) variant provably violates the invariant.
  ...
```

## Layer 2: TLA+ Model Checking

### TLA+ Specifications

| Spec File | Scope | Invariants |
|-----------|-------|------------|
| `DistributedCBF.tla` | Multi-process CBF admission under a lagging Redis replica: read → CAS write, stale failover, process restart, rollback; twin of `distributed_cbf_model.py` | `SP1_NoDoubleSpend`, `SP2_NoOvercommit`, `SP4_FenceEpochMonotonic` (action property) |
| `FtraBoundary.tla` | FTRA action classification, controller boundary coverage, fail-closed semantics — **not model-checked: its initial state violates `ControllerBoundaryCoversInGraphBypass` (POAM-2026-091)** | `ControllerBoundaryCoversInGraphBypass`, `FailClosedOnUnknownAction`, `NetworkPolicyEnforced` |
| `LangGraphHarness.tla` | LangGraph state machine, evidence chain, seal issuance, HITL timeout safety, client SDK session lifecycle — **not model-checked: most actions leave `consecutive_denials` / `deferral_resolved` unassigned (POAM-2026-091)** | `NoDirectBind`, `EvidenceChainIntegrity`, `SealGateIntegrity`, `HITLTimeoutSafety`, `OutputRailCoverage`, `SingleUseDeferralTicket`, `BudgetNeverExceededWithoutPause` |

### Distributed CBF: Results

One agent is one gateway process; Redis is one primary replicating asynchronously to one replica. `distributed_cbf_model.py` documents the mapping of every action to `cbf_engine.py`. Bounds: pool 2, one in-flight debit per process, epoch ≤ 4, one stale failover. TLC on each cfg (N = 2, `-continue`) reports exactly the BFS distinct-state count and verdicts (`scripts/verify_tla.py`).

| cfg | Posture | States (N=1 / 2 / 3) | SP-1 | SP-2 |
|-----|---------|----------------------|------|------|
| `DistributedCBF.cfg` | `WAIT 1` with strict rollback; reconciled (shipped staging/prod) and self-reported mode alike | 107 / 1811 / 23723 | ✅ | ✅ |
| `DistributedCBF_nosync.cfg` | No `WAIT N` (negative control) | 244 / 3972 / 49325 | ❌ | ❌ |
| `DistributedCBF_unfenced.cfg` | Shipped posture without the fence-epoch CAS | 110 / 2388 / 44261 | ✅ | ✅ |

What the counterexamples show:
- **`WAIT N` is load-bearing.** Without it a committed debit is lost at failover and another process — or the same one after a rollback or restart re-seeds `_last_seen_epoch` — spends the restored balance. The fence epoch and `_last_seen_epoch` do not prevent this; `safety:fence_epoch_hwm` regresses with the replica.
- **One model covers both modes.** `LUA_ATOMIC_CBF` checks the barrier against live primary state in reconciled mode (snapshot net of the live total, snapshot generation checked) and in self-reported mode (`GET` of the state key; Python's earlier read is only a seed for an unset key). `LUA_ROLLBACK_CBF` restores only a ledgered amount; a debit with no entry takes `ROLLED_BACK_UNLEDGERED` and credits nothing. This closed the self-reported fence-epoch ABA and rollback over-credit that the former `DistributedCBF_selfreported.cfg` demonstrated.
- **SP-1 does not rely on the fence CAS:** the script evaluates the barrier on live state.

### TLA+ Config Files

Each `.tla` spec has a corresponding `.cfg` config file that defines:
- **Constants**: Model parameters (agent sets, thresholds, timeout bounds)
- **Invariants**: Safety properties to check
- **Deadlock checking**: disabled — the models are bounded, so terminal states are expected

Example config (`DistributedCBF.cfg`; `tests/test_distributed_cbf_proof.py` checks every cfg's constants against the spec and the Python `CONFIGS`):
```
SPECIFICATION Spec

CONSTANTS
    AgentIDs = {a0, a1}
    InitialPool = 2
    ReserveAmount = 1
    MaxAgentReserve = 1
    MaxFenceEpoch = 4
    MaxStaleFailovers = 1
    SyncReplication = TRUE
    Reconciled = TRUE
    Fenced = TRUE
    AllowRestart = TRUE

INVARIANTS
    TypeOK
    SP1_NoDoubleSpend
    SP2_NoOvercommit

PROPERTIES
    SP4_FenceEpochMonotonic

CHECK_DEADLOCK FALSE
```

### LangGraph Harness Model Checker Parameters

The `LangGraphHarness.tla` specification extends the governance pipeline model to include client SDK session lifecycle and budget enforcement:

**Constants:**
- `MaxLoopCount = 3` — Safety breaker cap for re-planning loops
- `HITLTimeoutTicks = 5` — HITL TTL expiration countdown (abstract time units)
- `MaxConsecutiveDenials = 2` — Budget cap for consecutive DENY verdicts before pausing session

**Invariants:**
- `TypeOK` — Type safety for all state variables
- `NoDirectBind` — Core safety: `(phase = "RESPONSE") => resolved_allow`
- `EvidenceChainIntegrity` — Audit trail committed before response
- `SealGateIntegrity` — Routing seal issued and valid for ALLOW responses
- `HITLTimeoutSafety` — HITL timeout leads to ERROR, not RESPONSE
- `OutputRailCoverage` — All non-error paths pass through output rail
- `SingleUseDeferralTicket` — Deferral tickets cannot be resolved more than once
- `BudgetNeverExceededWithoutPause` — `consecutive_denials > MaxConsecutiveDenials` implies `phase = "PausedBudgetExceeded"`

**Client SDK State Transitions:**
- `TriggerDenial: Active → ParkedForReview` — Session parked after DENY verdict
- `TriggerDeferral: Active → DEFER_PENDING` — Session deferred for data hydration
- `ResumeApproval: ParkedForReview → Active` — Session resumes after manual approval
- `ExceedBudget: Active → PausedBudgetExceeded` — Budget exhausted after MaxConsecutiveDenials

**Model Configuration** ([`LangGraphHarness.cfg`](LangGraphHarness.cfg); `SingleUseDeferralTicket` and `BudgetNeverExceededWithoutPause` are defined but not yet checked — POAM-2026-091):
```
SPECIFICATION Spec

CONSTANTS
    MaxLoopCount = 3
    HITLTimeoutTicks = 5
    MaxConsecutiveDenials = 2

INVARIANTS
    TypeOK
    NoDirectBind
    EvidenceChainIntegrity
    SealGateIntegrity
    HITLTimeoutSafety
    OutputRailCoverage

CHECK_DEADLOCK FALSE
```

### Running TLC Model Checker

TLC needs Java 11+ and `tla2tools.jar` (https://github.com/tlaplus/tlaplus/releases; CI pins v1.7.4 by sha256).

```bash
# Python BFS, then TLC on every DistributedCBF*.cfg, compared with the BFS pins
TLA_TOOLS_JAR=/path/to/tla2tools.jar make verify-tla

# A single cfg
java -cp tla2tools.jar tlc2.TLC -config proof/DistributedCBF.cfg proof/DistributedCBF.tla
```

`DistributedCBF.cfg` reports `Model checking completed. No error has been found.` with 1811 distinct states. The negative-control cfgs report `Invariant SP1_NoDoubleSpend is violated` and a counterexample trace; `make verify-tla` treats that as the expected result and fails only on a count or verdict that differs from the BFS. Without `TLA_TOOLS_JAR`, `make verify-tla` runs the BFS only.

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
   - ❌ Needs Java and `tla2tools.jar` (manual `tlc-model-check` workflow, not per PR)
   - ❌ Requires TLA+ expertise to interpret traces

### Proof/Implementation Divergence (ARCH-1)

Prior to ARCH-1, the Python BFS model **excluded FTRA** (Tier 0.5) because it then ran at the LangGraph graph level, not inside the governor's per-call checks. This created a proof/implementation divergence:

- **Production**: FTRA blocked irreversible actions before the governor's per-call checks ran
- **Proof**: FTRA was not modeled, so the state-space omitted action classification barriers

**ARCH-1 resolution**: FTRA is now modeled as the first tier in the BFS state machine, and at runtime it is the first read-only stage of `run_pipeline()` (`src/gateway/governance/governor/stages/ftra.py`). The proof covers its fail-closed semantics and routing seal enforcement.

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

- name: pytest-logic   # includes tests/test_distributed_cbf_proof.py
  run: uv run pytest tests/test_no_direct_bind_proof.py -v
```

Regression tests pin the governance model counts — gated 38 / ungated 19 / DoWhy-absent 35 / EU_ECB 42 — and every distributed CBF count and verdict in the table above, plus the cfg ↔ spec ↔ Python constant parity. Any change that alters these numbers fails CI and triggers a review of `docs/paper/REVISION_TRACKER.md` (published figures must stay consistent with proof).

### TLA+ (TLC)

TLC runs in the manually dispatched [`tlc-model-check`](../.github/workflows/tlc-model-check.yml) workflow and locally via `make verify-tla`; it is not a per-PR gate because it needs Java and the jar. The PR gate still catches drift: `tests/test_distributed_cbf_proof.py` fails if a cfg names a constant or invariant the spec does not define, and runs TLC itself when `TLA_TOOLS_JAR` is set. Update both the spec and the Python twin whenever the CBF admission protocol changes (`LUA_ATOMIC_CBF`, `LUA_ROLLBACK`, `_check_fence_epoch`, `WAIT` handling).

## References

- **Python BFS Model**: `proof/model.py`
- **TLA+ Specs**: `proof/*.tla`
- **TLC Configs**: `proof/*.cfg`
- **Regression Tests**: `tests/test_no_direct_bind_proof.py`, `tests/test_distributed_cbf_proof.py`, `tests/test_governance_trace_conformance.py`
- **Trace checker**: `proof/trace_conformance.py`, `scripts/check_trace_conformance.py`
- **TLC runner**: `scripts/verify_tla.py`
- **Paper Citation**: CAGE_ARXIV.MD §4.4 "Formal Verification", Appendix A
- **Revision Tracker**: `docs/paper/REVISION_TRACKER.md` (published state counts)

## License

All proof artifacts in this directory are released under the Apache 2.0 License.

The Python BFS model (`model.py`) is adapted from the open-source implementation by LalaSkye (Apache 2.0), available at: https://github.com/LalaSkye/no-direct-bind

Modifications: Extended to CAGE's 8-tier architecture, added the NARROW state, seal consumption semantics, and FTRA tier.
