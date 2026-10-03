# ADR-010: Settlement-Aware, O(1) Local-Debit Ledger for the Reconciled CBF

**Status:** Proposed (design approved 2026-10-02; implementation on `fix/recon-discrepancy-floor` and `fix/cbf-settlement-ledger`)  
**Date:** 2026-10-02  
**Decision Makers:** CAGE Core Architecture Team  
**Supersedes:** sequence-tagged pruning of the `cbf:local_debits` list  
**Compliance Mapping:** NIST SP 800-53 SI-10, `CTRL_MRM_004` | POAM-2026-087  
**Related:** [ADR-009](ADR-009-tier-protocol-split.md) (settlement after actuation); review decisions D4 and D6

---

## Context

The reconciled Control Barrier Function (CBF) enforces the cash invariant
against a custodian-attested balance rather than against the gateway's own
counter. Between two custodian snapshots the gateway must remember the trades
it has already committed, otherwise a second trade can be admitted against a
balance that has not yet absorbed the first. That memory is the *local-debit
ledger*. At HEAD it is a Redis LIST (`cbf:local_debits`) owned by
[`cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py) and
pruned by the reconciliation daemon
([`daemon.py`](../../src/gateway/governance/reconciliation/daemon.py)).

A line-by-line review found six defects in that design. All six were
re-verified against HEAD `d99b718b`.

1. **Pruning is not causally linked to settlement.** After every successful
   verified write the daemon trims all debits tagged with a sequence `<=` the
   snapshot sequence. That sequence is a local Redis `INCR` (or `0` when the
   counter is unavailable); nothing ties it to whether the custodian has
   actually reflected the debit in the reported balance.
2. **Netting uses sequence equality.** `atomic_verify_and_commit` sums only
   debits whose tag equals the *current* snapshot sequence. A debit committed
   under sequence *n* disappears from the effective balance as soon as snapshot
   *n+1* is readable, whether or not it has settled.
3. **Rollback matches by amount.** `rollback_state` removes the newest entry
   whose amount equals the rolled-back magnitude. With two equal trades in
   flight it can remove the wrong one, and a repeated rollback restores funds
   twice.
4. **Previews ignore debits.** `verify_action` and `admissible_cost` read the
   raw verified scalar; only the commit path nets. NARROW bounds and
   HITL barrier previews can therefore promise headroom the commit will refuse.
5. **The simulated custodian never settles.** `SimulatedSource.record_debit()`
   in [`seams/ground_truth.py`](../../src/gateway/governance/seams/ground_truth.py)
   has no caller, and its journal is an in-process list although the actuator
   (gateway pod) and the reconciler (compliance-bridge pod) are different
   processes. The reference backend therefore cannot exercise the lag window at
   all.
6. **Cost is O(L).** Commit and rollback `LRANGE` the entire list inside the
   Lua script; the hot path scales with the number of outstanding debits.

The only backstop is the daemon's discrepancy guard, which rejects a snapshot
whose delta from the previous baseline exceeds `0.5 * |baseline|` (or `100.0`
when the baseline is zero). With a 60-second poll interval the exposed window
is one poll, and the guard has no absolute floor, so for small balances it
refuses legitimate movements while for large balances it cannot see a
double-spend at all.

## Decision

### 1. Three keys replace the list

| Key | Type | Content | Written by |
|---|---|---|---|
| `cbf:debits` | HASH | `debit_id -> JSON{amount, submitted_at, snapshot_sequence, snapshot_observed_at}` | commit Lua |
| `cbf:debits:by_time` | ZSET | score `submitted_at`, member `debit_id` | commit Lua |
| `cbf:debits:total` | STRING (float) | running sum of outstanding debits | commit / rollback / settle Lua |

`_REDIS_KEY_LOCAL_DEBITS`, `LUA_TRIM_DEBITS_BY_SEQUENCE` and both
`trim_local_debits_through_sequence` helpers are deleted. No migration is
provided: this is a reference architecture, and the Redis key change is
recorded in [`BREAKING_CHANGES_v3.md`](../BREAKING_CHANGES_v3.md).

### 2. The commit script nets in-script, in O(1)

`LUA_ATOMIC_CBF` receives the **raw** verified scalar and a `mode` argument
(`"reconciled"` or `"self_reported"`). In reconciled mode it computes
`current = scalar - GET cbf:debits:total` inside the same script that performs
the fence-epoch compare-and-set, then applies the barrier check. On success it
writes the HASH entry, the ZSET member and `INCRBYFLOAT`s the total. Python no
longer pre-nets, and the `LRANGE` loop is gone. The substrings that
[`test_fence_epoch.py`](../../tests/test_fence_epoch.py) pins (`KEYS[3]`,
`safety:fence_epoch`, `INCR`, `new_epoch`, `return {1,` / `return {0,`) are
preserved.

### 3. Rollback is keyed by `debit_id`, exact and idempotent

- `commit_barrier` in
  [`barrier_tier.py`](../../src/gateway/governance/safety/barrier_tier.py)
  mints `debit_id = uuid4().hex`, passes it **down** as a keyword argument to
  `atomic_verify_and_commit`, and returns it in the existing `token` slot of
  `CommitReceipt` ([`contracts.py`](../../src/gateway/governance/contracts.py)).
  The `(bool, str, float)` return shape of `atomic_verify_and_commit` is
  unchanged, so the 28 test modules and the governor golden fixtures that mock
  it are untouched.
- `rollback_barrier` passes `debit_id=receipt.token`;
  `rollback_state` drops `reconciliation_sequence` in favour of `debit_id`.
- `LUA_ROLLBACK_CBF` does `HGET` by id. If the entry is absent it returns
  `NOOP` and touches nothing, so a second rollback cannot restore funds twice.
  If present it removes the HASH entry and ZSET member, decrements the total by
  the *recorded* amount, and restores the state scalar. The self-reported
  branch (`debit_id == ""`) keeps today's restore-by-magnitude behaviour.
- The WAIT-timeout rollback inside `atomic_verify_and_commit` passes the same
  `debit_id`; it was the second caller the original plan missed.

### 4. Settlement attestation drives pruning (D4)

- `GroundTruthSnapshot` gains `settled_through: float | None` — "every debit
  submitted at or before this instant is reflected in `scalar`".
- `ReconciliationResult` carries the field through `to_redis_payload` /
  `from_redis_payload` (`null` when absent, JCS-canonical), and
  `snapshot_signing_payload` in
  [`trust.py`](../../src/gateway/governance/reconciliation/trust.py) **includes
  it**, so a cutoff edited in Redis fails signature verification.
- In the success branch of the verified write the daemon replaces the trim
  with a settle call whose cutoff is

  ```text
  settled_through present:  cutoff = min(settled_through, verified_at) - skew
  otherwise:                cutoff = verified_at - settlement_lag_seconds - skew
  ```

  with `skew = reconciliation.settlement_clock_skew_seconds`.
- `LUA_SETTLE_DEBITS` (daemon only, off the hot path) removes every member of
  the ZSET with score `<= cutoff`, then **recomputes** `cbf:debits:total` from
  `HVALS cbf:debits`, which corrects `INCRBYFLOAT` drift on every poll.
- The R-04 snapshot-sequence logic is kept for replay defence only; it no
  longer drives pruning.

### 5. Previews become debit-aware (behaviour change)

`_read_cbf_state_atomic` returns `outstanding_debits` and
`current_cash = scalar - outstanding_debits` for the two `"reconciled"`
branches, keeping `state_scalar` raw. `verify_action` and `admissible_cost`
then agree with the commit path without further change. Today they
over-promise; after this ADR preview headroom equals commit headroom, which
tightens NARROW bounds and HITL previews. This is intended and is documented in
[`CAUSAL_AND_CBF_GOVERNANCE.md`](../governance/CAUSAL_AND_CBF_GOVERNANCE.md).

### 6. Discrepancy guard gains an absolute floor and a schema (D6)

A `ReconciliationThresholds` model is added to
[`thresholds.py`](../../src/gateway/governance/schemas/thresholds.py) and
[`governance_thresholds.json`](../../config/governance_thresholds.json):

| Key | Default | Use |
|---|---|---|
| `discrepancy_ratio` | `0.5` | relative guard |
| `discrepancy_abs_floor` | `100.0` | absolute guard |
| `settlement_lag_seconds` | `120.0` | cutoff fallback when `settled_through` is absent |
| `settlement_clock_skew_seconds` | `5.0` | margin subtracted from every cutoff |

The effective threshold becomes `max(ratio * |baseline|, floor)` (an explicit
constructor override still wins). Because the floor loosens the only backstop
that exists before the new ledger lands, the floor change (WS-B) and the ledger
(WS-A) merge in the **same release**, and POAM-2026-087 stays Open until the
ledger merges.

### 7. The reference custodian actually settles

`SimulatedSource` accepts a journal and a `settlement_lag_s`. A Redis-backed
journal (`sim:ledger:{invariant_id}`, ZSET by `submitted_at`) replaces the
in-process list so the gateway and the compliance bridge share it.
`next_snapshot()` reports `scalar = initial - sum(amount for submitted_at <=
now - lag)` and `settled_through = now - lag`. A new
`FaultMode.SETTLEMENT_STALL` freezes `settled_through`, so outstanding debits
accumulate and headroom shrinks to zero — a liveness cost that preserves
safety. On the finance side,
[`cage_finance/ground_truth.py`](../../src/cage_finance/ground_truth.py) builds
the Redis journal when `REDIS_URL` is set, and the broker actuator
([`broker_actuator.py`](../../src/cage_finance/actuators/broker_actuator.py))
calls `record_debit()` on its accepted path, giving that method its first
caller.

## Safety argument

- **Netting happens where it is enforced.** The effective balance is computed
  inside the Lua script that holds the fence-epoch CAS, so no Python-side read
  can be stale relative to the write it guards.
- **Only `settle` lowers the total, and never past the cutoff.** The cutoff is
  either the custodian's own attestation or a conservative lag window, both
  minus a skew margin, and the attestation is covered by the reconciler's
  signature.
- **Concurrent writers bump the epoch.** Any commit or rollback between a
  preview and its commit increments `safety:fence_epoch`; the stale commit
  fails CAS and is denied rather than retried (unchanged from today).
- **Rollback is exact and idempotent.** Removal is by id with the recorded
  amount; an absent id is a `NOOP`.
- **A concurrent settle only relaxes a preview.** A preview that observed a
  larger total than the commit sees is more conservative, never less.

Every failure mode over-restricts.

## Consequences

- Breaking for deployments: the Redis key set changes; running clusters must
  flush `cbf:local_debits` (runbook note in `BREAKING_CHANGES_v3.md`).
- Commit and rollback are O(1) in the number of outstanding debits; the
  per-poll settle is O(k) in the number of debits that settle.
- `GroundTruthProvider` implementations may now attest `settled_through`;
  those that do not fall back to the lag window and are therefore more
  conservative, not less.
- Preview headroom shrinks when debits are outstanding. Golden fixtures that
  pinned the old over-promising previews are regenerated in the WS-A PR.

### Known gaps

- **A custodian that attests early is a trust failure, not a ledger bug.**
  If `settled_through` claims settlement that has not happened, the ledger
  prunes correctly against a false attestation. Mitigation is the discrepancy
  guard and the signed provenance of the snapshot, not this design.
- **CAS denies the loser.** Two concurrent commits against the same epoch
  result in one denial, not a retry. Pre-existing; unchanged.
- **ADR-009 under-count after a crash between actuation and `confirm`.**
  Unchanged by this ADR; the fiscal reservation path is separate from the CBF
  ledger.
- **Float total.** `INCRBYFLOAT` drift is bounded by the per-poll recompute;
  between polls the drift is at most one `INCRBYFLOAT` rounding per commit.

## Verification

Every fail-closed path below has a test that observes it **fail**
(`pytestmark = [pytest.mark.unit, pytest.mark.local]`, fakeredis):

- `test_lagging_ledger_blocks_double_spend` — snapshot 100, commit 60, next
  snapshot still 100 with `settled_through` before the trade: a second 60 is
  denied; after settlement (snapshot 40) it is still denied.
- `test_settle_never_prunes_before_attestation` — a debit survives N polls
  while `settled_through < submitted_at`.
- `test_skew_margin_delays_settlement` — debit at `t`; `settled_through =
  t + 1` with skew 5 does not settle it; `t + 6` does.
- `test_rollback_by_debit_id_is_exact_and_idempotent` — two equal commits,
  roll back one, the other is intact; the second rollback returns `NOOP`.
- `test_wait_timeout_rollback_removes_its_own_debit` — strict replication with
  `_sync_to_replicas` patched to fail restores the HASH entry and the total.
- `test_total_drift_corrected_on_settle` — injected drift in
  `cbf:debits:total` is corrected by the next settle.
- `test_commit_is_constant_round_trips` — command count is independent of the
  number of outstanding debits (10 vs 1000).
- `test_preview_matches_commit_headroom` — `admissible_cost()` equals the
  largest cost the commit accepts with debits outstanding.
- `test_preview_never_writes_debits` — extends
  [`test_cbf_preview_purity.py`](../../tests/governor/test_cbf_preview_purity.py)
  to the three new keys.
- `test_settlement_stall_fails_closed` — `FaultMode.SETTLEMENT_STALL` drives
  headroom to zero and the CBF refuses.
- `test_tampered_settled_through_fails_signature` — editing
  `settled_through` in Redis fails `verify_snapshot_signature`; the strict CBF
  refuses.

Acceptance for the implementing PRs: the tests above green, `make test-fast`
green, Gate G3 green, and
`rg -n 'local_debits|trim_local_debits|reconciliation_sequence' src/` empty.
