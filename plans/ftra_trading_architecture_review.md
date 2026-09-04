do a detailed archietcure review and verify that cgae can do automatic trading with FTRA (which stands for Formal Trust Registry Architecture (or alternatively referenced in safety modules as Fault Tree Risk Analysis). active based on this design. if correct then write a detaile implementation plan

**Verified: none of the eight findings are implemented in the current working tree.** Plan written to [`plans/enforcement_pipeline_implementation_plan.md`](plans/enforcement_pipeline_implementation_plan.md).

## What I checked

Each finding against source directly, not against status notes:

| ID | State | Evidence |
|---|---|---|
| **F1** | ❌ | All four tiers still hold the bare literal — [`consensus_tier.py:40`](src/cage_finance/tiers/consensus_tier.py:40), [`cbf_tier.py:40`](src/cage_finance/tiers/cbf_tier.py:40), [`fiscal_tier.py:42`](src/cage_finance/tiers/fiscal_tier.py:42), [`causal_tier.py:41`](src/cage_finance/tiers/causal_tier.py:41). No shared constant. |
| **F2** | ❌ | [`gatekeeper.py:600`](src/gateway/governance/causal/gatekeeper.py:600) — cache key still has no bucket. |
| **F3** | ❌ | [`fiscal_tier.py:65`](src/cage_finance/tiers/fiscal_tier.py:65) — `confirm()` still immediately after `reserve()`. |
| **F4** | ❌ | [`fiscal_tier.py:27`](src/cage_finance/tiers/fiscal_tier.py:27) — still `self._tokens = {}`. |
| **F5** | ❌ | [`symbolic_governor.py:1179`](src/gateway/governance/symbolic_governor.py:1179) unchanged. |
| **F6** | ❌ | [`symbolic_governor.py:1558`](src/gateway/governance/symbolic_governor.py:1558) still says *"Non-trade actions"*. |
| **F7** | ❌ | [`HUMAN_OVERSIGHT_SCOPE.md:222`](docs/governance/HUMAN_OVERSIGHT_SCOPE.md:222) still says tokens *"cannot be released"*. |
| **F8** | ❌ | [`AGENTIC_SCOPE_STATEMENT.md:20`](docs/governance/AGENTIC_SCOPE_STATEMENT.md:20) still *"NOT authorized — advisory only"*. |
| — | ❌ | `TIER_APPLICABILITY.md` absent from `docs/governance/`. |

The Stage 0 and Stage 1 work recorded in the review's §9 was done on `feat/pipeline-coherence` (off `feat/ftra-registry-signing`) — not this tree. §9 is a record of work done elsewhere, not the state here.

## Before implementing anything

**Check whether `feat/pipeline-coherence` still exists.** That branch has all of F1–F4 plus the S1–S5 rework, and four mutation checks were verified against it — including the M1 correction, which was the subtle one. `git branch -a` settles it in seconds. Recovering it beats reimplementing, and reimplementing risks losing the M1 fix.

The plan assumes reimplementation only as a fallback.

## Two of these are live bugs

Worth stating plainly, since they're independent of the autonomy work:

- **F4** — tokens in a per-instance dict: never evicted, not shared across replicas, lost on restart. A rollback on another pod hits `.get(None)` and silently no-ops, stranding fiscal capacity.
- **F3** — `confirm()` at approval time deletes the sentinel before execution, collapsing the documented two-phase protocol.

## Traps carried forward into the plan

Three things went wrong the first time and are called out explicitly:

1. **The F1 test cannot use a single-element set.** With one element, `==` and `in` are identical, so the mutation check passes vacuously. It must monkeypatch a synthetic second action into the source module **and all four tier modules** — each binds the name at import.
2. **F4's Redis access belongs on the guard**, not in the tier. A tier reaching into `guard._redis` will re-implement `_is_async_client()` — F1 again, introduced by the fix for F1. That happened.
3. **A store failure must fail closed**, returning a `Violation` *and* releasing the reservation. Logging and proceeding recreates the orphaned reservation F4 exists to fix.

Per your instruction, the plan records mutation pass/fail only — no suite-integer auditing.

## Note on the signing track

[`plans/ftra_registry_signing_pipeline.md`](plans/ftra_registry_signing_pipeline.md) is reconstructed and separate from this. S1 still needs the keyring name confirmed — [`KEY_ROTATION.md`](docs/operations/KEY_ROTATION.md) says `governance-keyring`, [`09-OPERATIONAL-RUNBOOK.md`](docs/technical-report/09-OPERATIONAL-RUNBOOK.md) says `cage-governance` — plus location and algorithm, before creating real key material. I also see [`scripts/provision_prod_kms.sh`](scripts/provision_prod_kms.sh) now open in your tabs, which may already answer those.</result>