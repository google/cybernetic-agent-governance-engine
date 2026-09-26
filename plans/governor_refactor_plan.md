# SymbolicGovernor Refactor Plan — PRs 1–3

**Target:** [symbolic_governor.py](../src/gateway/governance/symbolic_governor.py) (2,968 lines).
**Related:** [STERA review](./stera_security_review.md).
**Posture:** Reference architecture. Breaking changes are allowed and there are no compatibility shims (AGENTS.md).

> [!IMPORTANT]
> **PR 0 lands first.** It contains the surgical fixes for C1, C2, H2 and H3 in the current file, each with a test that observes the failure. PRs 1–3 then keep those tests green, so the refactor cannot quietly reintroduce the fail-opens.

## Goals
1. **One way to classify.** Classification uses structured violation kinds, never substring matching.
2. **One pipeline.** Every entry point (`govern`, `validate_action`, `revalidate_post_hitl`, `verify`) runs the same staged pipeline under a named profile.
3. **Reservations are all-or-nothing.** Phase-2 mutations are rolled back on *any* failure before the seal is issued.
4. **Code matches the formal model.** The implementation agrees with [`proof/model.py`](../proof/model.py) `TIERS`/`PHASES`, including NARROW semantics (see §PR1.4).

## Non-goals (deferred to PR 4/5)
- Moving startup posture checks out of import time.
- Removing the leftover `safety_filter` / `fiscal_limit_guard` constructor args.
- Moving narrowing rules into Layer 2 (PR 1 only defines the seam).
- Fixes inside CBF, defer, pause or ConsequenceGateway (tracked separately in the review).

## Package layout (final state after PR 3)

```
src/gateway/governance/governor/
  __init__.py          # public: SymbolicGovernor, GovernanceError, Profile, PipelineResult
  errors.py            # GovernanceError
  kinds.py             # ViolationKind enum + KIND_PRECEDENCE          (PR1)
  classification.py    # classify(violations) -> Classification          (PR1)
  pipeline.py          # Stage protocol, Profile, run_pipeline()         (PR2)
  stages/
    ftra.py  stpa.py  confidence.py  opa.py  domain_tiers.py            (PR2)
  verdicts.py          # verdict handlers, receipt builder, seal issuer  (PR2)
  reservation.py       # ReservationScope async context manager          (PR3)
  governor.py          # SymbolicGovernor: thin entry points             (PR2)
src/gateway/governance/symbolic_governor.py   # DELETED in PR2
```

Importers need a one-line change: `symbolic_governor` → `governor`. That is 25 files in `src` and 39 in `tests`, and most import only `SymbolicGovernor` or `GovernanceError`. After each rename PR, run `rg -n 'symbolic_governor' src/ tests/` and require zero hits (per AGENTS.md "Grep after renaming"). Also update [check_import_boundaries.py](../scripts/check_import_boundaries.py) allowlists if any of them reference the old path.

---

## PR 1 — Structured violation classification
**Branch:** `refactor/violation-kinds` · **Title:** `refactor(governance)!: classify violations by structured kind`
**Closes:** H1, C3 (classification part), the "Unsafe Control Action" check that can never match, FTRA violations being counted as STPA, consensus ESCALATE being turned into DENY.

### 1.1 Contract change — [contracts.py](../src/gateway/governance/contracts.py#L190-L210)
```python
class ViolationKind(StrEnum):
    HARD = "HARD"              # non-negotiable → DENY
    HITL = "HITL"              # human sign-off → REQUIRE_APPROVAL
    DEFERRABLE = "DEFERRABLE"  # data starvation → DEFER
    TRANSIENT = "TRANSIENT"    # rate limit / breaker → PAUSE
    NARROWABLE = "NARROWABLE"  # soft threshold → NARROW candidate

@dataclass(frozen=True)
class Violation:
    tier: str
    code: str
    message: str               # human-readable ONLY; never parsed
    kind: ViolationKind        # REQUIRED — no default (fail-closed by construction)
    standing: Mapping[str, Any] = field(default_factory=dict)
```
- `recoverable` and `needs_human_review` are **removed**. `kind` replaces them, and removing them avoids having two sources of truth.
- `kind` has no default. Any tier that forgets to set it fails at construction, not at runtime.

### 1.2 Kernel-emitted violations become `Violation` objects too
Today the kernel appends raw strings. Each source switches to a typed violation:

| Source | code | kind |
|---|---|---|
| FTRA irreversible, semantics valid | `FTRA_IRREVERSIBLE` | HITL |
| FTRA semantic breach / classifier error | `FTRA_SEMANTIC_BREACH` / `FTRA_ERROR` | HARD |
| STPA UCA-n | `STPA_UCA_<n>` | HARD |
| Confidence below threshold (finite) | `CONFIDENCE_BELOW_THRESHOLD` | DEFERRABLE if `< FRIA_ZONE_DEFER`, else HITL |
| Confidence non-finite / out of range | `CONFIDENCE_INVALID` | HARD |
| OPA DENY / unknown verdict / error | `OPA_DENY` / `OPA_UNKNOWN_VERDICT` / `OPA_ERROR` | HARD |
| OPA MANUAL_REVIEW | `OPA_MANUAL_REVIEW` | HITL |
| POAM-TIER2-001 override | `TIER2_STRUCTURAL_OVERRIDE` | HITL |
| `TIER_EXCEPTION`, `ROLLBACK_FAILED` | unchanged codes | HARD |

`GeneratedSTPAValidator.validate()` gains a structured return type, `list[Violation]`. The generator template under `scripts/` must be updated too. **Run `uv run python scripts/check_stpa_freshness.py`** and commit the regenerated artifacts.

### 1.3 Domain tiers declare kinds
All 37 `Violation(` sites across the finance, healthcare and physical-AI tiers, plus `governance_middleware.py`, `routing_seal.py` and `state_contract.py`. Key mappings:
- **Finance bounding tier:**
  - `HARD_BLOCK` → HARD. This is the fix for C3: HARD_BLOCK messages were being turned into NARROW.
  - `HITL_ESCALATE` → HITL.
- **Finance consensus tier:**
  - `REJECT` / `ERROR` → HARD.
  - `ESCALATE` → HITL.
- **CBF, fiscal and causal (finance), dose/kinematic barriers (healthcare/physical AI):** HARD.

### 1.4 NARROW realigned with the formal model
[`proof/model.py:299`](../proof/model.py#L285-L310) defines NARROW as *all tiers PASS* + `soft_threshold_exceeded` → seal on clamped params. The code does something else: it issues NARROW **when tiers fail**, and skips Phase 2. PR 1 restores the model's semantics:
- New Layer-1 seam `Narrower(Protocol)` in `contracts.py` with one method: `propose(action, params, violations) -> NarrowProposal | None`. Implementations are domain-provided and passed via the `SymbolicGovernor(narrowers=...)` constructor.
- Classification returns `NARROW_CANDIDATE` only if **every** violation is NARROWABLE **and** a narrower returns a proposal with at least one constraint applied.
- The verdict handler then **re-runs the full pipeline on the clamped params**. NARROW is issued only if that run produces zero violations. Otherwise the verdict is DENY.
- **Removed:**
  - `_compute_narrowed_params` (it is domain logic sitting in Layer 1).
  - The `params["_threshold_config"]` read. Thresholds come from server config only, which fixes the caller-controlled ceiling in C3.
- PR 1 ships **no** narrower implementation. NARROW becomes unreachable until a domain opts in. `CAGE_NARROW_ENABLED` is deleted; having a narrower registered is the opt-in.

### 1.5 `classification.py`
```python
def classify(violations: Sequence[Violation], *, defer_enabled: bool, pause_enabled: bool,
             narrow_candidate: bool) -> Classification: ...
```
- Precedence: `HARD > HITL > NARROWABLE(only if narrow_candidate) > TRANSIENT > DEFERRABLE`.
- Disabled paths collapse to DENY.
- The input list is empty only on ALLOW. If `classify` is called with `[]`, it raises (programmer error).
- The function is pure and total. There is no free-text inspection anywhere, and `violation.message` is never read.
- `stpa_violation_count` and `confidence` are **removed** from the signature. Their effect is already expressed as the kind of each violation.

### 1.6 Tests
- Rewrite `tests/test_classify_violation.py` as a table-driven test over `ViolationKind` combinations × feature flags. Aim for exhaustive coverage: 5 kinds, all subsets.
- **Adversarial test:** a HARD violation whose message contains `"exceeds max"`, `"rate limit"` or `"Manual Review Required"` must still be classified DENY. This proves free text is ignored.
- **NARROW tests:**
  - A candidate whose re-run fails is DENY.
  - A proposal with no constraints is DENY.
  - A caller-supplied `_threshold_config` is ignored.
- **FTRA irreversible + semantically valid → REQUIRE_APPROVAL.** This is a regression test for the FTRA-as-STPA miscount.
- Update `test_narrow_transport.py`, `test_ftra_boundary_check.py`, `test_defer_e2e_flow.py` and `test_pause_primitive.py` to the new contract.
- Every new test gets `pytestmark = [pytest.mark.unit, pytest.mark.local]`.

### 1.7 Acceptance
- `make test-fast` is green.
- `rg -n 'recoverable=|needs_human_review=' src/` returns zero hits.
- `rg -n '_threshold_config|CAGE_NARROW_ENABLED' src/` returns zero hits.
- Docs updated in the same PR: [GATEWAY_ARCHITECTURE.md §2.2](../docs/architecture/GATEWAY_ARCHITECTURE.md#L88-L103) and the NARROW section of `decisions.py`.

---

## PR 2 — Single staged pipeline with profiles
**Branch:** `refactor/governor-pipeline` · **Title:** `refactor(governance)!: unify governor entry points on one pipeline`
**Closes:** C1 and C2 by construction, the 3× OPA-parsing duplication (keeping PR 0's allowlist), the 4× receipt/seal duplication, and the module split.

### 2.1 Stage protocol — `pipeline.py`
```python
class Stage(Protocol):
    name: str                       # must match proof/model.py TIERS entry
    mutating: bool                  # True → phase 2, participates in ReservationScope
    async def run(self, ctx: StageContext) -> list[Violation]: ...

class Profile(StrEnum):
    FULL = "FULL"            # all stages
    POST_HITL = "POST_HITL"  # {opa, cbf} (+ fiscal? — see Open Q1)
    DRY_RUN = "DRY_RUN"      # all stages, mutating stages call evaluate-only path

@dataclass(frozen=True)
class PipelineResult:
    violations: tuple[Violation, ...]
    tier_failures: tuple[GovernanceTierFailure, ...]
    opa_verdict: OpaVerdict | None
    ftra: FtraBoundaryResult
```
- **Stage order comes from data**, a single `STAGE_ORDER` tuple. Kernel stages are `ftra, stpa, confidence, opa`. Domain tiers are wrapped by an adapter `DomainTierStage(tier)` and sorted by `(phase, order, tier_name)` as they are today.
- **Execution rule (identical for every profile):**
  1. Read-only stages run in order. The first HARD violation short-circuits. Other kinds are collected until a HARD appears or the stages run out.
  2. Mutating stages run **only** if the read-only stages produced zero violations. They run inside `ReservationScope` (PR 3; PR 2 keeps the current LIFO rollback).
  3. OPA always runs **before** any mutating stage. This removes the `asyncio.gather` that caused C2.
- **CBF refusals come from `committed`, not from reason text.** The CBF stage emits a HARD violation whenever `committed is False`, whatever the reason string says. This removes the C1 bug class.
- **`POST_HITL` is a subset of the same stage list, not separate code.** `revalidate_post_hitl` becomes `return await self._run(action, params, Profile.POST_HITL)`.
- **Ungoverned actions** (no domain tier claims them) run `ftra, stpa, opa` only. This is the current `else` branch, made explicit. Log `governance.governed=false` on the span.

### 2.2 `stages/opa.py`
A single `decode_opa_verdict(raw) -> OpaVerdict` over `{ALLOW, DENY, MANUAL_REVIEW}`. Anything else becomes `DENY` with `OPA_UNKNOWN_VERDICT`. This is the only place OPA responses are interpreted.

### 2.3 `verdicts.py`
- `build_refusal_receipt(action, params, result) -> RefusalReceipt`: one implementation replacing 4 copies. It also publishes the receipt to the evidence stream, per AGENTS.md "Refusals are primary evidence".
- `issue_seal(action, params) -> str`: wraps `generate_seal_with_evidence`, with one span name and one attribute set.
- `resolve_thread_id(params) -> str`: replaces the 5 copies.
- `handle(classification, ...) -> VerdictResponse`: one function per verdict (ALLOW, DENY, DEFER, PAUSE, NARROW, REQUIRE_APPROVAL). `_park_defer_context` moves here unchanged; its Redis-fallback behaviour is out of scope.

### 2.4 `governor.py` — entry points
| Method | Body |
|---|---|
| `validate_action` | policy-version pin check → `run(FULL)` → `classify` → `verdicts.handle` |
| `govern` | `run(FULL)`; any violation → `GovernanceError(receipt)`; else seal |
| `revalidate_post_hitl` | `run(POST_HITL)`; same contract as `govern` |
| `verify` | `run(DRY_RUN)`; returns `PipelineResult`, never raises |
| `pre_check` | **removed from the governor.** NeMo callers (`inference_proxy.py:372`, `nemo_node_factory.py:405`) call `run(DRY_RUN)` restricted to `{stpa}` plus `cbf.verify_action`. A STPA exception becomes a HARD violation, not "no violations". |

Target size: `governor.py` under 300 lines, no file in the package over 400.

### 2.5 Tests
- **Profile parity test:** for a fixed set of fixtures, the POST_HITL violations must be a subset of the FULL violations restricted to POST_HITL stages. This catches semantic drift between entry points.
- **C1 regression:** CBF returns `(False, "RECONCILIATION_UNAVAILABLE: x")` and `(False, "Fence epoch regression: …")`. Both POST_HITL and FULL must refuse.
- **C2 regression:** OPA returns DENY → the CBF commit is **never called** (assert on the mock).
- **Formal parity:** [`tests/test_tier_registry_formal_parity.py`](../tests/test_tier_registry_formal_parity.py) must pass **unchanged**. A new assertion checks that `STAGE_ORDER` names ⊆ `proof.model.TIERS`.
- Migrate `test_symbolic_governor.py` → `tests/governor/test_*.py`, one file per module.
- Migrate `test_hitl_toctou_revalidation.py` to the profile API.

### 2.6 Acceptance
- `make test-fast` is green.
- `rg -n 'symbolic_governor' src/ tests/ docs/` returns zero hits outside `CHANGELOG.md`.
- `uv run python scripts/check_import_boundaries.py --verbose` passes.
- `make docs-check` (Gate G9) passes.

---

## PR 3 — Reservation scope covers seal issuance
**Branch:** `refactor/reservation-scope` · **Title:** `refactor(governance): roll back phase-2 commits on any pre-seal failure`
**Closes:** the leak when seal generation fails after commit, cancellation leaks (`CancelledError` is a `BaseException`), and the dead `_fiscal_token` path.

### 3.1 `reservation.py`
```python
class ReservationScope:
    """Async context manager. Commits mutating stages; on exit without
    .seal_issued(), LIFO-rolls back every committed stage."""
    async def __aenter__(self) -> "ReservationScope": ...
    async def commit(self, stage: Stage, ctx: StageContext) -> list[Violation]: ...
    def seal_issued(self, seal: str) -> None: ...   # marks success; disarms rollback
    async def __aexit__(self, exc_type, exc, tb) -> bool: ...
```
- **Rollback triggers:** any exception (including `BaseException` / cancellation, via `asyncio.shield` around the rollback), any violation, or exit without `seal_issued()`.
- **Rollback failures** produce a HARD `ROLLBACK_FAILED` violation. The existing semantics are kept, and every rollback is still attempted.
- **The pipeline owns the scope, not individual verdict handlers:**
  - **ALLOW:** seal issuance happens *inside* the scope.
  - **NARROW:** only the re-run on clamped params (PR 1 §1.4) commits, and it is sealed inside its own scope.
- **`GovernanceTierPlugin.rollback` changes signature.** It becomes `rollback(action, params, commit_receipt)`. `commit()` now returns `(violations, CommitReceipt)`, where `CommitReceipt` carries the exact committed magnitude. This fixes the rollback-amount mismatch in H5 at the contract level. The CBF-side fix (validating the magnitude) is still tracked separately.
- **Deleted:**
  - `_fiscal_token` and the post-pipeline release block.
  - The `fiscal_limit_guard` constructor arg, which becomes dead once fiscal is a domain tier.

### 3.2 Tests
- Seal generation raises → every committed stage is rolled back in LIFO order (mock assertion on the call order).
- Task cancelled between commit and seal → rollbacks run (use `asyncio.wait_for` with a tiny timeout on a slow seal mock).
- One rollback raises → the other rollbacks still run, and the result carries a `ROLLBACK_FAILED` HARD violation.
- The receipt magnitude is what gets rolled back, even when `params["amount"]` differs from the committed cost (regression for H5).
- DRY_RUN never enters a `ReservationScope` (assert that commit is never called).

### 3.3 Acceptance
- `make test-fast` is green.
- `rg -n '_fiscal_token|fiscal_limit_guard' src/` returns zero hits.
- All domain tiers (finance, healthcare, physical AI) are migrated to the `CommitReceipt` contract.
- The Lula/OSCAL impact has been checked. No K8s resources change, so no Lula update is expected. Note this in the PR description.

---

## Sequencing & risk

```mermaid
flowchart LR
  PR0["PR0 fail-open fixes"] --> PR1["PR1 ViolationKind"]
  PR1 --> PR2["PR2 single pipeline"]
  PR2 --> PR3["PR3 ReservationScope"]
```

| Risk | Mitigation |
|---|---|
| **The contract change in PR 1 touches 3 domain packages.** | `kind` is required, so type errors surface every missed site. Also add a CI grep for `Violation(` without `kind=`. |
| **Behaviour drift during the PR 2 split.** | Before PR 2, capture golden verdicts: run the current `validate_action` over a fixture corpus and freeze the verdicts. PR 2 must match them, except for documented intentional changes (C1, C2, H2, FTRA→REQUIRE_APPROVAL). |
| **The formal model says the confidence tier runs before cbf/opa, but `POST_HITL` skips it.** | Already true today. Record it explicitly as a profile in `proof/model.py` (Open Q2). |
| **Large diff to review.** | Each PR is mechanical after its contract commit. Structure each PR as commit 1 = contract + core, commit 2 = migrations, commit 3 = tests/docs. |

## Resolved design questions (from PR 1–5 planning)

1. **Re-run fiscal checks after human approval:** **Yes.** Add `fiscal` to the post-approval profile and test that an approved request is denied if the budget is used up while it waited.
2. **Add execution profiles to the formal model:** **Yes.** Add a `profile` field to `proof/model.py` to formally model subset paths like `POST_HITL`, and prove an allow requires every check in the profile to pass.
3. **Keep the NARROW seam:** **Keep the code's version; fix the model.** The model incorrectly defines NARROW as "every check passed, but soft threshold exceeded". Update the model to match the code's design (the domain plugin decides what is narrowable).
4. **Delete `CBF_FAIL_OPEN`:** **Yes.** Delete it entirely from the codebase (it was a dead development-mode switch with no test coverage).
5. **Delete `null_components.py`:** **No, but change how it's used.** Keep the deny-by-default null objects for when no plugin is present, but build the governor once after plugins load, passing everything in explicitly.
6. **STPA rules, one module per domain:** **Yes.** Remove the duplicate `GeneratedSTPAValidator` class, keep the generic compiler/validator in Layer 1, and move each domain's rule set into its own domain package.
