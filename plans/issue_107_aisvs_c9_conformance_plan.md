# Issue #107 — AISVS C9 Action-Class Conformance for FTRA Tier 0.5

**Issue:** [google/cybernetic-agent-governance-engine#107](https://github.com/google/cybernetic-agent-governance-engine/issues/107)
**Reporter:** Mayur Agnihotri (@Mayur021) — OWASP AISVS contributor
**Conformance suite:** `Mayur021/aisvs-c9-action-class-conformance` @ **v1.2.0** (`b697af3`)
**Control:** `CTRL_FTRA_001` — Forward-Looking Trajectory Reachability Analyzer (Tier 0.5)

> **Reference Architecture Note.** CAGE is an illustrative reference
> architecture. The remediations below are patterns adopters should adapt;
> the standards positions (MUST/SHOULD) are contributions to the AISVS C9
> profile debate, not operational obligations imposed on this repository.

---

## 1. Codebase Audit — What HEAD Actually Does

I audited the tree against the eight vectors before planning. Three findings
materially change the shape of the work relative to the draft plan.

### 1.1 `EXTERNALLY_REVERSIBLE` is already half-landed — and that is the danger

The enum member **already exists** at
[`models.py`](src/gateway/governance/ftra/models.py:48), and
[`FtraBoundaryResult.from_classification()`](src/gateway/governance/ftra/models.py:314)
already maps it to `score=0.8, requires_hitl=True`. The `Literal` in
[`stpa_compiler.py`](src/gateway/governance/stpa_compiler.py:143) also lists it.

But **two severity maps were never updated**, and both will raise `KeyError`
the moment the class is actually used:

| Location | Current keys | Missing |
|---|---|---|
| [`graph_analyzer.py:202`](src/gateway/governance/ftra/graph_analyzer.py:202) `_severity` | `READ_ONLY`, `REVERSIBLE`, `IRREVERSIBLE_TERMINAL` | `EXTERNALLY_REVERSIBLE` |
| [`stpa_compiler.py:1509`](src/gateway/governance/stpa_compiler.py:1509) `_SEVERITY_ORDER` | same three | `EXTERNALLY_REVERSIBLE` |

**This is worse than the class simply being absent.** In
[`_analyze_internal`](src/gateway/governance/ftra/graph_analyzer.py:212), the
lookup `_severity[classification]` sits inside the per-node classification loop,
which is wrapped by the broad `except Exception` in
[`analyze()`](src/gateway/governance/ftra/graph_analyzer.py:108). So an
`EXTERNALLY_REVERSIBLE` registry entry today produces a `KeyError`, is swallowed,
and returns `IRREVERSIBLE_TERMINAL` / `HITL_REQUIRED`.

That is a **fail-closed noise** result in Mayur's taxonomy — blocked, but for
entirely the wrong reason, with `critical_path=[]` and `reachable_terminals=[]`.
A partial implementation that produces a plausible-looking block is precisely
the failure mode the four-way partition exists to expose. **Landing the class
without fixing both severity maps would make VEC-004 appear to pass while
nothing traversed.**

### 1.2 The registry omission is confirmed on disk

[`config/ftra/terminal_registry.json`](config/ftra/terminal_registry.json:7)
carries exactly three entries — `write_db`, `execute_trade`,
`prompt_injection_check` — with **no `check_balance` and no `release_wire`**,
matching the issue verbatim. Anyone reproducing VEC-001 from a clean checkout
gets `critical_path=['s1']`.

The root cause is upstream: the registry is *generated* by
[`generate_terminal_registry()`](src/gateway/governance/stpa_compiler.py:1482)
from `unsafe_control_actions` only. An action with no UCA never appears.
`check_balance` is a benign read and has no UCA, so it can never be registered
by the current compiler. **Editing the JSON by hand would be overwritten on the
next `stpa_compiler compile`** — the fix must be in the STPA source YAML.

### 1.3 No signature verification exists anywhere in the load path

[`_load_registry()`](src/gateway/governance/ftra/classifier.py:74) does a bare
`json.load` with no integrity check, and
[`_get_registry()`](src/gateway/governance/ftra/classifier.py:104) re-reads from
disk on every `classify()` call when `FTRA_REGISTRY_RELOAD=true`. That is VEC-005
exactly: a writable file plus a hot-reload flag equals unattended `CLEAR` on
`execute_trade`.

**Good news for the open question:** a mature multi-cloud signer already exists
at [`kms_signer.py`](src/gateway/governance/kms_signer.py:391) with
GCP/AWS/Azure providers and, critically, working
[`verify()`](src/gateway/governance/kms_signer.py:880) and
[`verify_raw()`](src/gateway/governance/kms_signer.py:900) methods, plus an
`assert_kms_active_in_production` guard. There is no reason to introduce a
local HMAC path.

---

## 2. Resolving the Draft Plan's Open Question

The draft asked: local HMAC-SHA256 with `GOVERNANCE_SALT`, or `kms_signer`?

**Decision: `kms_signer`, asymmetric, no HMAC fallback.** Rationale:

- A shared-secret HMAC gives the *verifier* the power to *forge*. The gateway
  pod that validates the registry could equally mint a registry declaring
  `execute_trade: REVERSIBLE`. That defeats the control's purpose against the
  precise threat model in VEC-005 — a **compromised sidecar**. Asymmetric
  signing means the runtime holds only a public key.
- `GOVERNANCE_SALT` is already carried as a dev placeholder in the documented
  test env (`dev-only-insecure-placeholder-not-for-production-use`). Binding a
  security control to a value with a published dev default invites exactly the
  posture drift this issue is about.
- The repo already mandates KMS for governance artifacts and enforces it in
  production via `assert_kms_active_in_production`. A second, weaker signing
  path for the *action-class registry* would be an architectural inconsistency
  a CISO review would flag immediately.
- The reference-architecture concern (needing live cloud KMS for local dev) is
  handled the way the rest of the repo handles it: unsigned registries are
  permitted **only** when KMS is inactive AND the deployment region is `LOCAL`,
  and that path emits a loud WARN. It is never silently permitted.

---

## 3. Staleness — The Finding the Draft Plan Missed

Mayur's third point is the one with no line item in the draft, and it is the
subtlest:

> A signature attests that nobody altered the file, not that the file still
> describes the system.

Signing closes tampering and leaves **staleness** untouched, in two distinct
forms:

1. **Rollback.** An attacker replaces the current registry with an *older,
   validly signed* registry — one from before `execute_trade` was tightened.
   Signature verification passes. This needs a monotonic freshness check.
2. **Semantic divergence** (upstream [OWASP/AISVS#1126](https://github.com/OWASP/AISVS/issues/1126)).
   The declaration is untouched and correctly signed, but the action it names
   changed underneath it. AISVS 10.4.8 already carries snapshot-and-re-approve
   for MCP tool definitions; C9 has no equivalent.

The plan therefore adds **signed temporal validity** (`issued_at` / `expires_at`
inside the signed payload, so they cannot be edited independently of the
signature) and a **monotonic `serial`** to defeat rollback. Expiry forces
periodic re-attestation, which is the mechanism that converts a declaration
into something that must be *re-affirmed* against the system.

**Scope honesty:** expiry forces re-approval on a clock; it does not *observe*
behaviour. Genuine behavioural binding (comparing declared class against
observed side effects) is the `SHOULD`-tier corroboration control, and it is
explicitly **out of scope** here. We will document that boundary rather than
imply the staleness class is closed.

---

## 4. Composition (Variant A) — Explicitly Out of Scope

An export in N chunks where every per-step class is honestly `REVERSIBLE`, but
the boundary turns irreversible once enough chunks are out to reconstruct the
set. Max-of-declared folds to `REVERSIBLE` and admits every step.

CAGE's fold is exactly max-of-declared
([`graph_analyzer.py:212`](src/gateway/governance/ftra/graph_analyzer.py:212)),
so **CAGE is susceptible and none of the three changes above reach it.** Mayur
records it as an open research question — no known implementation computes that
threshold, including his own reference model.

**We will not claim to fix this.** The deliverable is a documented threat model
plus an `xfail`-marked vector that keeps it visible in CI. Landing the
conformance suite must not be read as covering composition.

---

## 5. The Four-Way Scoring Partition

The suite's `scenario.md` at v1.2.0 defines four categories. **Encoding only
three would report a reachability pass for every case the fail-closed default
catches** — the exact error Lars nearly made on VEC-001.

| Category | Meaning |
|---|---|
| `TRUE_PASS_REACHABILITY` | Worst-case assigned from T₀ **because traversal reached a terminal**. Requires a non-trivial `critical_path`. |
| `TRUE_PASS_FAIL_CLOSED` | Correctly blocked by the fail-closed default (unregistered action). Right reason, but **a different control** — nothing traversed. |
| `GENUINE_BYPASS` | Every step admitted; composed effect would be denied if requested directly. |
| `FAIL_CLOSED_NOISE` | Blocked for the **wrong** reason (e.g. unrelated unregistered step truncating the path). |

The discriminator between the first two is **`critical_path`**, not the verdict.
Any harness that scores on verdict alone cannot distinguish them. This must be
asserted structurally in the test suite.

---

## 6. Target Vector Matrix

Registry state is a **fixture parameter**, never a mutation of the shipped file.

| Vector | Scenario | Expected verdict | Expected category |
|---|---|---|---|
| VEC-001a | `check_balance → execute_trade`, shipped registry (pre-fix) | `HITL_REQUIRED`, `critical_path=['s1']` | `FAIL_CLOSED_NOISE` |
| VEC-001b | same, canonical registry (post-fix) | `HITL_REQUIRED`, `critical_path=['s1','s2']` | `TRUE_PASS_REACHABILITY` |
| VEC-002 | Disconnected/dead terminal `execute_trade` | `CLEAR` | `TRUE_PASS_REACHABILITY` (pruned) |
| VEC-003 | Branching DAG → `write_db` | `HITL_REQUIRED` | `TRUE_PASS_REACHABILITY` (fork hit) |
| VEC-004 | `release_wire` declared `EXTERNALLY_REVERSIBLE` | `HITL_REQUIRED` | `TRUE_PASS_REACHABILITY` — **closes bypass** |
| VEC-005 | `execute_trade` re-declared `REVERSIBLE`, unsigned/invalid sig | `HITL_REQUIRED` (sig fail → fail closed) | `TRUE_PASS_FAIL_CLOSED` — **closes bypass** |
| VEC-006 | `execute_trade`, confidence `0.45 < 0.70` | `BLOCKED` | `TRUE_PASS_REACHABILITY` (hard gate) |
| VEC-007 | `unregistered_custom_action` | `HITL_REQUIRED` | `TRUE_PASS_FAIL_CLOSED` — **the 4th category** |
| VEC-008 | Rollback: older validly-signed registry | `HITL_REQUIRED` | `TRUE_PASS_FAIL_CLOSED` (new) |
| VEC-009 | Composition Variant A, N-chunk export | `CLEAR` | `GENUINE_BYPASS` — **`xfail(strict=True)`** |

VEC-004 and VEC-005 move from `GENUINE_BYPASS` to passing. VEC-009 is recorded
as a known, unfixed bypass.

**Harness note (v1.2.0):** the release refuses naive datetimes at construction
and resolves unaccounted chain steps to the strongest tier. All timestamps in
fixtures must be timezone-aware — never `datetime.utcnow()`. Pin **v1.2.0**,
not `main`.

---

## 7. Architecture

```mermaid
graph TD
    A[stpa source YAML] --> B[stpa_compiler]
    B --> C[terminal_registry.json with issued_at expires_at serial]
    B --> D[KMSGovernanceSigner sign]
    D --> E[terminal_registry.json.sig]

    C --> F[RegistryVerifier]
    E --> F
    F -->|signature valid and not expired and serial not regressed| G[classifier serves registry]
    F -->|any check fails| H[fail closed all IRREVERSIBLE_TERMINAL]

    G --> I[PlanGraphAnalyzer DFS from step0]
    I --> J[four class severity fold]
    J --> K{worst case}
    K -->|IRREVERSIBLE_TERMINAL| L[HITL or BLOCKED by confidence]
    K -->|EXTERNALLY_REVERSIBLE| M[HITL_REQUIRED]
    K -->|REVERSIBLE or READ_ONLY| N[CLEAR]
```

### 7.1 Severity lattice

| Class | Severity | Routing |
|---|---|---|
| `READ_ONLY` | 0 | `CLEAR` |
| `REVERSIBLE` | 1 | `CLEAR` |
| `EXTERNALLY_REVERSIBLE` | 2 | `HITL_REQUIRED` |
| `IRREVERSIBLE_TERMINAL` | 3 | `HITL_REQUIRED` / `BLOCKED` by confidence |

`EXTERNALLY_REVERSIBLE` sits strictly between `REVERSIBLE` and
`IRREVERSIBLE_TERMINAL`, and is the **lowest** class that triggers HITL. It
routes to HITL but is *not* subject to the confidence hard-gate — a settlement
window means human review is meaningful even at lower confidence, whereas an
irreversible commit at low confidence warrants outright blocking. This
preserves `FtraBoundaryResult`'s existing `score=0.8, requires_hitl=True`.

**Both severity maps must be replaced by one shared, exhaustive mapping** so a
future fifth class cannot silently diverge again. A guard test must assert the
map covers every enum member.

### 7.2 Signed registry envelope

Temporal fields go **inside** the signed payload:

```json
{
  "version": "2.0",
  "serial": 42,
  "issued_at": "2026-09-01T20:30:47+00:00",
  "expires_at": "2026-12-01T20:30:47+00:00",
  "system": "CAGE Financial Advisor",
  "terminals": { "check_balance": "READ_ONLY", "...": "..." }
}
```

Verification is fail-closed on **every** branch: missing `.sig`, bad signature,
absent/naive/expired `expires_at`, or `serial` lower than the last-seen serial.
On any failure the classifier returns `IRREVERSIBLE_TERMINAL` for all actions —
never an empty registry, which would be indistinguishable from a clean load.

Canonicalisation must reuse the existing
[`jcs_canonicalizer`](src/gateway/governance/jcs_canonicalizer.py) so signing
and verification agree byte-for-byte.

### 7.3 Hardening the reload path

`FTRA_REGISTRY_RELOAD` re-reads on every `classify()`. Verification must run on
**every reload**, not once at import, or the flag re-opens VEC-005 behind a
valid initial signature. Verification results should be cached against the file
digest so the hot path does not re-verify unchanged bytes.

---

## 8. Implementation Steps

### PR sequencing (decided)

| PR | Scope | Vectors landed | Leaves open |
|---|---|---|---|
| **#1** | Taxonomy & noise reduction (Phases 1–2) + partial suite | VEC-001a/b, VEC-004, VEC-007 | VEC-005 |
| #2 | KMS attestation & freshness (Phase 3) + suite extension | VEC-005, VEC-008 | — |
| #3 | Remaining vectors, docs, OSCAL, POAM (Phases 4–5) | VEC-002, VEC-003, VEC-006, VEC-009 | VEC-009 (tracked `xfail`) |

PR #1 is scoped to the classification layer. Signing touches a different layer
(load path + compiler emission) and reviews far better in isolation.
**VEC-005 remains an open bypass until PR #2 merges** — state this plainly in
any interim status on the issue, since VEC-004 and VEC-005 were reported
together and a partial fix could otherwise read as both.

**Two framing corrections for PR #1:**

1. *The enum member already exists* at
   [`models.py:48`](src/gateway/governance/ftra/models.py:48), as does its
   `FtraBoundaryResult` mapping and the compiler `Literal`. PR #1 is not
   "adding the 4th class" — it is **repairing the two severity maps that were
   never updated when it was added**, which today throw `KeyError` into a
   swallowing handler. Describing it as an addition would misrepresent the
   diff to reviewers.
2. *VEC-007 is not closed by PR #1.* It already returns `HITL_REQUIRED`
   correctly at HEAD via the fail-closed default. Its value is as the
   **demonstrator for the 4th scoring category** — it is the vector that proves
   the partition needs `TRUE_PASS_FAIL_CLOSED`. PR #1 *encodes* it, it does not
   fix it. The issue reply should say so.

**Suite constraint for PR #1:** even though only three vectors land, the
`ScoringCategory` enum must be **four-way from the first commit**, pinned to
suite v1.2.0 / `b697af3`. Shipping a three-way partition and widening it later
would bake in precisely the defect Mayur raised — every fail-closed-default
catch reported as a reachability pass.

### Phase 1 — Fix the latent `KeyError` (highest priority)

1. Add a single exhaustive `CLASSIFICATION_SEVERITY` mapping in
   [`ftra/models.py`](src/gateway/governance/ftra/models.py) covering all four
   classes per §7.1.
2. Replace the local `_severity` dict in
   [`graph_analyzer.py:202`](src/gateway/governance/ftra/graph_analyzer.py:202)
   with the shared mapping; update the verdict branch at
   [`:244`](src/gateway/governance/ftra/graph_analyzer.py:244) so
   `EXTERNALLY_REVERSIBLE` routes `HITL_REQUIRED` without the confidence gate.
3. Replace `_SEVERITY_ORDER` in
   [`stpa_compiler.py:1509`](src/gateway/governance/stpa_compiler.py:1509) with
   the same mapping; update the docstring's restrictiveness chain.
4. **DECIDED — unified array.** Include `EXTERNALLY_REVERSIBLE` steps in the
   existing `reachable_terminals`. A terminal action remains a terminal action
   on the critical path regardless of whether its resolution requires an
   external settlement window; a parallel `reachable_external_terminals` field
   would fragment the traversal view for no analytical gain. This keeps
   `critical_path` non-empty for VEC-004, which the four-way partition relies
   on to separate `TRUE_PASS_REACHABILITY` from noise.

   Consequences to handle in the same PR — `reachable_terminals` no longer
   implies "irreversible":
   - Update the field description at
     [`ReachabilityResult.reachable_terminals`](src/gateway/governance/ftra/models.py:98)
     ("Step IDs of all reachable IRREVERSIBLE_TERMINAL nodes").
   - Update [`critical_path`](src/gateway/governance/ftra/models.py:103), whose
     description asserts "Empty when worst_case_classification !=
     IRREVERSIBLE_TERMINAL" — no longer true.
   - Audit consumers of `reachable_terminals` and the
     `cage.ftra.reachable_terminal_count` span attribute
     ([`node_factory.py:47`](src/gateway/governance/ftra/node_factory.py:47))
     for an implicit irreversibility assumption.
   - The terminal-collection branch at
     [`graph_analyzer.py:215`](src/gateway/governance/ftra/graph_analyzer.py:215)
     must append on both HITL-triggering classes.
5. Add a guard test asserting the severity map covers every
   `TerminalClassification` member.

### Phase 2 — Close the registry gap at the source

6. Add `check_balance` (`READ_ONLY`) and `release_wire`
   (`EXTERNALLY_REVERSIBLE`) to
   [`trade_hazards.yaml`](config/stpa/domains/finance/trade_hazards.yaml).
   Resolve how a benign read enters a UCA-derived registry — either a genuine
   UCA or a new `benign_control_actions` section in the compiler.
7. Regenerate the registry via the compiler; never hand-edit the JSON.
8. Run `scripts/check_stpa_freshness.py` — STPA source changed, so artifacts
   must be regenerated per AGENTS.md.

### Phase 3 — Cryptographic binding with temporal validity

9. New `src/gateway/governance/ftra/registry_verifier.py` — verification of
   signature, expiry, and serial monotonicity; fail-closed on every branch.
10. Extend the compiler to emit `serial` / `issued_at` / `expires_at` and write
    `terminal_registry.json.sig` via `KMSGovernanceSigner`.
11. Wire the verifier into
    [`_load_registry()`](src/gateway/governance/ftra/classifier.py:74) and the
    reload path per §7.3; add a digest-keyed verification cache.
12. Permit unsigned registries **only** when KMS is inactive and region is
    `LOCAL`, with a WARN. Add `assert_kms_active_in_production`-style
    enforcement.

### Phase 4 — Conformance suite in CI

13. New `tests/test_aisvs_c9_conformance.py` with a `ScoringCategory` enum
    encoding **all four** categories, pinned to suite **v1.2.0** / `b697af3`.
14. Parameterise all ten vectors from §6; assert on `(verdict, category,
    critical_path)` — never verdict alone.
15. Registry states as `tmp_path` fixtures with correctly signed variants;
    never mutate the shipped file. All timestamps timezone-aware.
16. Mark VEC-009 `xfail(strict=True)` with a docstring pointing at the
    composition threshold as an open research question.
17. Mark tests `unit`/`local` so they run in `pytest-logic` on every push.

### Phase 5 — Documentation & compliance

18. Update
    [`FTRA_COMPENSATING_CONTROLS.md`](docs/operations/FTRA_COMPENSATING_CONTROLS.md)
    with the four-class taxonomy, the signed-registry pattern, and an explicit
    "what this does not cover" section naming composition and semantic
    staleness.
19. Update OSCAL components in `compliance/oscal/` — this touches NIST SP
    800-53 control implementations (CM-5, SI-7 integrity), due within 2
    business days of merge per AGENTS.md.
20. Add a Lula validation for the signed registry if it introduces new
    Kubernetes-referenced resources.
21. Record the composition bypass as an **open POAM finding** with the
    `xfail` as its tracking artifact. Do not close what is not fixed.
22. Credit Mayur Agnihotri in
    [`CONTRIBUTOR_ACKNOWLEDGMENTS.md`](docs/CONTRIBUTOR_ACKNOWLEDGMENTS.md).

---

## 9. Standards Positions (Issue Response)

Empirically grounded in this run:

- **MUST — cryptographic binding.** An action-class registry as bare
  unauthenticated JSON makes Tier 0.5 decorative; one key change bypasses
  graph-level enforcement. Verified: no integrity check exists in
  [`_load_registry()`](src/gateway/governance/ftra/classifier.py:74).
- **MUST — binding is insufficient alone; require freshness.** Mayur is right
  that signing closes tampering, not staleness. The profile should require
  temporal validity *inside* the signed payload plus rollback resistance, and
  should adopt a C9 analogue of AISVS 10.4.8's snapshot-and-re-approve
  (OWASP/AISVS#1126).
- **MUST — four-class taxonomy (C9.2.3).** A 3-class model collapses unilateral
  rollback with external settlement windows. `release_wire` makes the
  dependency concrete: `CLEAR` is an oversight bypass, `IRREVERSIBLE_TERMINAL`
  is an operational lock. Neither is correct.
- **MUST — four-way scoring partition.** A three-way partition reports a
  reachability pass for every fail-closed-default catch. `critical_path`, not
  the verdict, is the discriminator. Conformance suites are unreadable without
  this.
- **SHOULD — continuous blast-radius corroboration.** Comparing observed
  side-effects against declared class detects undeclared mutation but cannot
  replace commencement-time gating.
- **OPEN — composition thresholds.** No known implementation computes the
  chunk-count at which composed reversible steps become irreversible. Named as
  a research question, not a profile requirement.

---

## 10. Verification

```bash
# Conformance suite
uv run pytest tests/test_aisvs_c9_conformance.py -v

# Full local/unit regression
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith --tb=short

# STPA freshness (source changed in Phase 2)
uv run python scripts/check_stpa_freshness.py --verbose

# Static analysis and types
uv run ruff check . && uv run ruff format --check .
uv run mypy src/
```

Manual checks:

1. Recompile STPA; confirm `terminal_registry.json` contains `check_balance`
   and `release_wire`, and that `.sig` is emitted.
2. Corrupt one byte of the registry; confirm the classifier fails closed to
   `IRREVERSIBLE_TERMINAL` rather than raising.
3. Set `expires_at` in the past; confirm fail-closed.
4. Restore an older validly-signed registry; confirm serial regression is
   rejected (VEC-008).
5. With `FTRA_REGISTRY_RELOAD=true`, swap in a tampered registry mid-process;
   confirm the reload re-verifies and fails closed.

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| `EXTERNALLY_REVERSIBLE` routing to HITL increases defer volume | Only `release_wire` adopts it initially; measure DeferQueue depth before broader adoption |
| Signature verification on the hot path adds latency | Digest-keyed verification cache; re-verify only on byte change |
| KMS unavailable in local dev blocks all classification | Explicit `LOCAL` + KMS-inactive escape hatch with WARN; never silent |
| Registry regeneration overwrites manual edits | Phase 2 fixes the STPA source, not the JSON; freshness check enforces |
| Landing the suite is read as covering composition | VEC-009 `xfail` + explicit scope statement in docs and issue reply |

---

## 12. Branch & Commits

Branch: `feat/aisvs-c9-conformance`

Suggested commit sequence (Conventional Commits, squash-merge only):

- `fix(governance): add EXTERNALLY_REVERSIBLE to FTRA severity maps`
- `fix(governance): register check_balance and release_wire in STPA source`
- `feat(governance): bind FTRA terminal registry with KMS signature and expiry`
- `test(tests): add AISVS C9 action-class conformance vectors`
- `docs(docs): document four-class taxonomy and FTRA scope boundaries`
