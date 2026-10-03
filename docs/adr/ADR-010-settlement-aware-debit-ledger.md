# ADR-010: Settlement-Aware, O(1) Local-Debit Ledger for the Reconciled CBF

**Status:** Accepted (design approved 2026-10-02; implemented on `fix/recon-discrepancy-floor` and `fix/cbf-settlement-ledger`)  
**Date:** 2026-10-02  
**Decision Makers:** CAGE Core Architecture Team  
**Supersedes:** sequence-tagged pruning of the former `cbf:local_debits` list  
**Compliance Mapping:** NIST SP 800-53 SI-10, `CTRL_MRM_004` | POAM-2026-087  
**Related:** [ADR-009](ADR-009-tier-protocol-split.md) (settlement after actuation); review decisions D4 and D6

---

## Context

The reconciled Control Barrier Function (CBF) enforces the cash invariant
against a custodian-attested balance rather than against the gateway's own
counter. Between two custodian snapshots the gateway must remember the trades
it has already committed, otherwise a second trade can be admitted against a
balance that has not yet absorbed the first. That memory is the *local-debit
ledger*. Before this ADR it was a Redis LIST (`cbf:local_debits`) owned by
[`cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py) and
pruned by the reconciliation daemon
([`daemon.py`](../../src/gateway/governance/reconciliation/daemon.py)).

A line-by-line review found six defects in that design. All six were
re-verified against HEAD `d99b718b`.

1. **Pruning is not causally linked to settlement.** After every successful
   verified write the daemon trimmed all debits tagged with a sequence `<=` the
   snapshot sequence. That sequence is a local Redis `INCR`, or `0` when
   `REPLAY_DEFENSE_ENABLED` is off — which is the shipped default, so in the
   default configuration **every** debit was pruned on **every** poll. Nothing
   tied the trim to whether the custodian had actually reflected the debit.
2. **Netting used sequence equality.** `atomic_verify_and_commit` summed only
   debits whose tag equalled the *current* snapshot sequence. A debit committed
   under sequence *n* disappeared from the effective balance as soon as snapshot
   *n+1* was readable, whether or not it had settled.
3. **Rollback matched by amount.** `rollback_state` removed the newest entry
   whose amount equalled the rolled-back magnitude. With two equal trades in
   flight it could remove the wrong one, and a repeated rollback restored funds
   twice.
4. **Previews ignored debits.** `verify_action` and `admissible_cost` read the
   raw verified scalar; only the commit path netted. NARROW bounds and
   HITL barrier previews could therefore promise headroom the commit refused.
5. **The simulated custodian never settled.** `SimulatedSource.record_debit()`
   in [`seams/ground_truth.py`](../../src/gateway/governance/seams/ground_truth.py)
   had no caller, and its journal was an in-process list although the actuator
   (gateway pod) and the reconciler (compliance-bridge pod) are different
   processes. The reference backend could not exercise the lag window at all.
6. **Cost was O(L).** Commit and rollback `LRANGE`d the entire list inside the
   Lua script; the hot path scaled with the number of outstanding debits.

The only backstop was the daemon's discrepancy guard, which rejected a snapshot
whose delta from the previous baseline exceeded `0.5 * |baseline|`. With a
60-second poll interval the exposed window is one poll, and the guard had no
absolute floor, so for small balances it refused legitimate movements while for
large balances it could not see a double-spend at all. A stale key name
(`safety:cash_balance` instead of the barrier's `safety:current_cash`) had
also been making the guard compare against the provider's initial scalar
rather than the gateway's own state.

## Decision

### 1. Four keys replace the list

All four are owned by
[`debit_ledger.py`](../../src/gateway/governance/safety/debit_ledger.py):

| Key | Type | Content | Written by |
|---|---|---|---|
| `cbf:debits` | HASH | `debit_id -> JSON{amount, submitted_at, mode, snapshot_sequence, snapshot_verified_at}` | commit Lua |
| `cbf:debits:pending` | ZSET | score commit time (`submitted_at`), member `debit_id` — admitted, not yet confirmed | commit Lua; confirm, rollback and settle (orphan promotion) remove |
| `cbf:debits:by_time` | ZSET | score confirm time, member `debit_id` — confirmed, settleable | confirm Lua; settle (orphan promotion) |
| `cbf:debits:total` | STRING (float) | running sum of outstanding debits | commit / rollback / settle Lua |
| `cbf:debits:rolled_back` | HASH | `debit_id -> rolled_back_at` tombstones | rollback Lua; pruned by settle |

`_REDIS_KEY_LOCAL_DEBITS`, `LUA_TRIM_DEBITS_BY_SEQUENCE` and both
`trim_local_debits_through_sequence` helpers are deleted. No migration is
provided: this is a reference architecture, and the Redis key change is
recorded in [`BREAKING_CHANGES_v3.md`](../BREAKING_CHANGES_v3.md).

### 2. The commit script nets in-script, in O(1), against one snapshot generation

[`LUA_ATOMIC_CBF`](../../src/gateway/governance/safety/cbf_engine.py) receives
the **raw** verified scalar, a `mode` argument (`"reconciled"` or
`"self_reported"`), the `debit_id`, the debit entry, and — in reconciled mode —
the exact snapshot payload bytes Python verified. Inside the same script that
performs the fence-epoch compare-and-set it:

1. refuses with `SNAPSHOT_CHANGED` if `GET cage:ground_truth:{invariant_id}`
   no longer equals the payload Python read (a newer snapshot may already have
   been settled against; netting a stale scalar with a settled total would
   over-promise, and the local sequence cannot identify generations because it
   is `0` by default);
2. in reconciled mode computes `current = scalar - GET cbf:debits:total`;
3. applies the barrier check; and on success
4. writes the state scalar, bumps the fence epoch and HWM, and ledgers the debit
   (`HSET`, `ZADD`, `INCRBYFLOAT`).

Step 4 runs in **both** modes. A debit admitted against self-reported state
must still be netted once a reconciled snapshot that predates it appears;
only the *netting* (step 2) is skipped in self-reported mode, because the
self-reported key already reflects its own debits. Python no longer pre-nets
and the `LRANGE` loop is gone. The substrings pinned by
[`test_fence_epoch.py`](../../tests/test_fence_epoch.py) (`KEYS[3]`,
`safety:fence_epoch`, `INCR`, `new_epoch`, `return {1,` / `return {0,`) are
preserved.

### 3. Rollback is keyed by `debit_id`, exact and idempotent

- [`commit_barrier`](../../src/gateway/governance/safety/barrier_tier.py)
  mints `debit_id = uuid4().hex`, passes it **down** as a keyword argument to
  `atomic_verify_and_commit`, and returns it in the existing `token` slot of
  `CommitReceipt` ([`contracts.py`](../../src/gateway/governance/contracts.py)).
  The `(bool, str, float)` return shape of `atomic_verify_and_commit` is
  unchanged; test doubles only had to learn the new keyword.
- `rollback_barrier` passes `debit_id=receipt.token`; `rollback_state` drops
  `reconciliation_sequence` in favour of `debit_id`. Direct callers that pass
  no id still get a ledgered debit under a fresh one — nothing admitted goes
  unrecorded.
- [`LUA_ROLLBACK_CBF`](../../src/gateway/governance/safety/cbf_engine.py)
  distinguishes three cases by id. A tombstone in `cbf:debits:rolled_back`
  means the debit was already rolled back: return `NOOP`, touch nothing, do
  not bump the epoch. A live HASH entry: remove it and its ZSET member,
  decrement the total by the *recorded* amount, restore the state scalar
  (`ROLLED_BACK`). Neither: restore nothing and leave the total alone
  (`ROLLED_BACK_UNLEDGERED`, amended 2026-10-03). A missing entry means the
  debit settled (only confirmed debits settle, so the action executed and
  the custodian reflects it) or was lost when a lagging replica was
  promoted (this primary never deducted it). Restoring by the caller's
  magnitude, as the original `ROLLED_BACK_SETTLED` branch did, over-credits
  in both cases; the distributed CBF model showed the over-credit
  (`proof/README.md`). Every path that changes state writes the tombstone,
  so a retried rollback is a `NOOP`.
- The WAIT-timeout rollback inside `atomic_verify_and_commit` passes the same
  `debit_id`; it was the second caller the original plan missed.

### 4. Settlement attestation drives pruning (D4)

- `GroundTruthSnapshot` gains `settled_through: float | None` — "every debit
  submitted at or before this instant is reflected in `scalar`".
- `ReconciliationResult` carries the field through `to_redis_payload` /
  `from_redis_payload` (`null` when absent, JCS-canonical) and keeps the exact
  bytes it was parsed from in `raw_payload` for the generation check above.
  [`snapshot_signing_payload`](../../src/gateway/governance/reconciliation/trust.py)
  **includes `settled_through`**, so a cutoff edited in Redis fails signature
  verification.
- After — and only after — the verified snapshot has been published, the daemon
  calls `settle_debits_sync(redis, cutoff)` with
  [`settlement_cutoff`](../../src/gateway/governance/safety/debit_ledger.py):

  ```text
  settled_through present:  cutoff = min(settled_through, verified_at) - skew
  otherwise:                cutoff = verified_at - settlement_lag_seconds - skew
  ```

  with `skew = reconciliation.settlement_clock_skew_seconds`.
- **Only confirmed debits settle (amended 2026-10-03, POAM-2026-092).** The
  commit stamps `submitted_at` before the actuator has told the custodian
  about the fill, so a commit-time stamp compared against `settled_through`
  let a debit settle before the custodian carried it whenever the
  commit-to-custodian latency exceeded the skew margin. A commit therefore
  enters `cbf:debits:pending`. ADR-009 `confirm()` — which the governor runs
  only after the action executed — calls `confirm_barrier()` →
  `ControlBarrierFunction.confirm_debit()` (`LUA_CONFIRM_DEBIT`), moving the
  entry to `cbf:debits:by_time` stamped with the confirm time and recording
  `confirmed_at` in the entry. The confirm time is at or after the custodian's
  own receipt time, so the skew margin has to cover clock skew only. A
  debit whose confirm never arrives (the governor's settlement hold,
  `DEFAULT_HOLD_SECONDS`, expired) may still have executed, so the settle
  script promotes pending entries older than
  `reconciliation.pending_debit_max_age_seconds` (default 600 s, at least the
  settlement hold) to `by_time` stamped at promotion. The promotion stamp is
  after every snapshot cutoff, so a promoted debit never settles in the pass
  that promotes it.
- `LUA_SETTLE_DEBITS` (daemon only, off the hot path) first promotes orphaned
  pending debits, then removes every member of `cbf:debits:by_time` with score
  `<= cutoff`, **recomputes** `cbf:debits:total` from `HVALS cbf:debits`
  (pending and confirmed; correcting `INCRBYFLOAT` drift on every poll), and
  prunes tombstones with `rolled_back_at <= cutoff`. It never touches a
  pending entry otherwise. `LUA_UNSETTLED_TOTAL` (discrepancy guard) counts
  every pending debit plus confirmed debits stamped after the cutoff.
- The R-04 snapshot-sequence logic is kept for replay defence only; it no
  longer drives pruning.

### 5. Previews become debit-aware (behaviour change)

`_read_cbf_state_atomic` reads `cbf:debits:total` **before** the snapshot
(so a concurrent publish-and-settle can only make a preview more
conservative) and, for the reconciled branches, returns `outstanding_debits`
and `current_cash = scalar - outstanding_debits`, keeping `state_scalar` raw.
`verify_action` and `admissible_cost` then agree with the commit path without
further change. Previously they over-promised; now preview headroom equals
commit headroom, which tightens NARROW bounds and HITL previews. This is
intended and is documented in
[`CAUSAL_AND_CBF_GOVERNANCE.md`](../governance/CAUSAL_AND_CBF_GOVERNANCE.md).

### 6. Discrepancy guard gains a floor, a schema, and settlement awareness (D6)

A `ReconciliationThresholds` model is added to
[`thresholds.py`](../../src/gateway/governance/schemas/thresholds.py) and
[`governance_thresholds.json`](../../config/governance_thresholds.json):

| Key | Default | Use |
|---|---|---|
| `discrepancy_ratio` | `0.5` | relative guard |
| `discrepancy_abs_floor` | `100.0` | absolute guard |
| `settlement_lag_seconds` | `120.0` | cutoff fallback when `settled_through` is absent |
| `settlement_clock_skew_seconds` | `5.0` | margin subtracted from every cutoff |

The effective threshold is `max(ratio * |baseline|, floor)` (an explicit
constructor override still wins). The compared delta is no longer
`|scalar - baseline|`: with a lagging custodian that trips on every large
trade. The daemon reads `unsettled = unsettled_total_sync(redis, cutoff)`
(debits submitted strictly after the cutoff) and measures how far the
custodian sits outside the band `[baseline, baseline + unsettled]`:

```text
delta = max(baseline - scalar, scalar - (baseline + unsettled), 0)
```

A custodian that has not yet absorbed in-flight fills is inside the band; one
that moved for any other reason is not. The baseline is the barrier's own
state key (`safety:current_cash`). Because the floor loosens the only backstop
that existed before the ledger landed, the floor change (WS-B) and the ledger
(WS-A) merge in the **same release**, and POAM-2026-087 stays Open until the
ledger merges.

### 7. The reference custodian actually settles

`SimulatedSource` accepts a `LedgerJournal` and a `settlement_lag_s`.
`next_snapshot()` reports `scalar = initial - sum(amount for submitted_at <=
now - lag)` and `settled_through = now - lag`. A new
`FaultMode.SETTLEMENT_STALL` freezes `settled_through` while the feed stays
healthy, so outstanding debits accumulate and headroom shrinks until the CBF
refuses — a liveness cost that preserves safety.

The journal is selected by environment, not by the presence of `REDIS_URL`
(the test harness always sets one): `CAGE_SIM_LEDGER_BACKEND=redis` builds
`RedisLedgerJournal` (`sim:ledger:{invariant_id}`, ZSET by `submitted_at`),
which the gateway and the compliance bridge share;
`CAGE_SIM_SETTLEMENT_LAG_SECONDS` sets the lag. Both are set identically in
[`gateway.yaml`](../../deployment/k8s/gateway.yaml) and
[`reconciliation-worker.yaml`](../../deployment/k8s/reconciliation-worker.yaml).
Hermetic tests keep the default `InMemoryLedgerJournal`.

On the finance side,
[`SimulatedCashLedgerProvider`](../../src/cage_finance/ground_truth.py) wires
the journal through the kernel's lazily connecting sync Redis client, and
[`BrokerActuator`](../../src/cage_finance/actuators/broker_actuator.py)
journals `finance_cost_resolver(action, params)` — the same cost the CBF
debited — under `clearance.nonce` once `execute_trade` succeeds. A journal
failure after a successful fill is reported as `accepted=False,
retryable=True, CUSTODIAN_JOURNAL_FAILED` rather than silently dropped. This
gives `record_debit()` its first caller.

## Safety argument

- **Netting happens where it is enforced.** The effective balance is computed
  inside the Lua script that holds the fence-epoch CAS, so no Python-side read
  can be stale relative to the write it guards.
- **Netting is pinned to one snapshot generation.** The script refuses if the
  published snapshot is not byte-identical to the one Python verified, so a
  scalar can never be netted with a total that was settled against a newer
  snapshot.
- **Only `settle` lowers the total, and never past the cutoff.** The cutoff is
  either the custodian's own attestation or a conservative lag window, both
  minus a skew margin, the attestation is covered by the reconciler's
  signature, and settle runs only after that signature has been published.
- **Concurrent writers bump the epoch.** Any commit or rollback between a
  preview and its commit increments `safety:fence_epoch`; the stale commit
  fails CAS and is denied rather than retried (unchanged).
- **Rollback is exact and idempotent.** Removal is by id with the recorded
  amount; a tombstoned id is a `NOOP`.
- **A concurrent settle only relaxes a preview.** The total is read before the
  snapshot, so a preview that straddles a publish-and-settle sees a larger
  total than the commit will — more conservative, never less.

Every failure mode over-restricts.

## Consequences

- Breaking for deployments: the Redis key set changes; running clusters must
  delete `cbf:local_debits` (runbook note in `BREAKING_CHANGES_v3.md`). A
  snapshot replaced between read and commit now denies with
  `SNAPSHOT_CHANGED` instead of being netted against the wrong generation.
- Commit and rollback are O(1) in the number of outstanding debits; the
  per-poll settle is O(k) in the number of debits that settle plus the HASH
  walk for the recompute.
- `GroundTruthProvider` implementations may now attest `settled_through`;
  those that do not fall back to the lag window and are therefore more
  conservative, not less.
- Preview headroom shrinks when debits are outstanding. No golden fixture
  pinned the old over-promising previews; none needed regenerating.
- The simulated journal is append-only; its ZSET grows with every fill in a
  long-running demo. Compacting settled entries into the initial scalar is
  left to adopters.

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
- **The development-only `reconciled_unsigned` branch** takes the same
  script path as a signed snapshot (`mode="reconciled"`: in-script netting
  and the generation check); only the signature check is skipped. It is
  never admitted in an enforcing posture. Plain self-reported mode reads
  the state key inside the script (amended 2026-10-03).
- **A debit is counted twice for one skew window after confirm.** The
  custodian may reflect a fill before the cutoff passes its confirm stamp;
  until then the snapshot and the ledger both carry it. This errs toward less
  headroom.
- **Orphan promotion trusts the settlement hold.** If
  `pending_debit_max_age_seconds` were set below the governor's settlement
  hold, a debit could be promoted (and later settled) before a late confirm
  or rollback arrives; `test_pending_max_age_outlasts_the_governor_settlement_hold`
  pins the defaults.

## Verification

Every fail-closed path below has a test in
[`test_cbf_settlement_ledger.py`](../../tests/test_cbf_settlement_ledger.py)
that observes it **fail** (`pytestmark = [pytest.mark.unit, pytest.mark.local]`,
fakeredis, software Ed25519, one custodian + one reconciler + one CBF wired
through the same fakeredis server):

- `test_lagging_ledger_blocks_double_spend` — commit 40k against 100k; the
  custodian (lag 1 h) still reports 100k: a second 40k is denied; after
  settlement (snapshot 60k, ledger empty) it is still denied.
- `test_settle_never_prunes_before_attestation` — a debit survives five polls
  while `settled_through < submitted_at`.
- `test_skew_margin_delays_settlement` — debit at `t`; `settled_through =
  t + 1` with skew 5 does not settle it; `t + 6` does.
- `test_unconfirmed_debit_is_never_settled_however_late_the_actuator_runs` —
  under a frozen clock, an unconfirmed debit survives a reconcile ten skew
  margins after the commit; once confirmed it is stamped with the confirm time
  and leaves the ledger one skew window later, never before the custodian
  reflects it.
- `test_unconfirmed_debit_is_promoted_after_the_max_age` — with no confirm,
  the debit stays pending until it is `pending_debit_max_age_seconds` old, is
  then promoted (stamped at promotion), and settles a skew window later.
- `test_settle_never_prunes_pending_debits` — a pending debit survives any
  cutoff and counts as unsettled for the discrepancy guard.
- `test_rollback_by_debit_id_is_exact_and_idempotent` — two equal commits,
  roll back one, the other is intact; the second rollback is a `NOOP` and does
  not bump the epoch.
- `test_rollback_after_settlement_restores_fallback_state_exactly_once` —
  a rollback that arrives after settlement restores the state key once and
  leaves the total alone.
- `test_wait_timeout_rollback_removes_its_own_debit` — strict replication with
  `_sync_to_replicas` patched to fail restores the HASH entry, the total and
  the state key.
- `test_total_drift_corrected_on_settle_and_tombstones_pruned` — injected drift
  in `cbf:debits:total` is corrected by the next settle; old tombstones go.
- `test_commit_is_constant_round_trips` — Redis command count per commit is
  identical with 10 and 1000 outstanding debits.
- `test_preview_matches_commit_headroom` — `admissible_cost()` is the largest
  cost the commit accepts with debits outstanding (`bound` passes, `bound + 1`
  is denied).
- `test_previews_never_touch_the_ledger` — repeated previews leave all three
  ledger keys byte-identical (the counterpart of
  [`test_cbf_preview_purity.py`](../../tests/governor/test_cbf_preview_purity.py)).
- `test_settlement_stall_fails_closed` — `FaultMode.SETTLEMENT_STALL`: the feed
  stays healthy, nothing is pruned, and the third 30k trade is refused from the
  local ledger alone.
- `test_tampered_settled_through_fails_signature` — editing `settled_through`
  in Redis fails `verify_snapshot_signature`; the strict CBF refuses with
  `RECONCILIATION_UNAVAILABLE`.
- `test_snapshot_replaced_between_read_and_commit_is_refused` — a snapshot
  published between Python's read and the Lua hop denies with
  `SNAPSHOT_CHANGED`.
- `test_discrepancy_guard_tolerates_unsettled_debits_but_not_external_moves`
  — the band formula above, both sides.
- `test_broker_actuator_journals_the_fill_with_the_custodian` /
  `test_broker_actuator_refuses_when_the_custodian_journal_fails` — the
  actuator's accepted path journals the CBF cost under the clearance nonce and
  fails closed if it cannot.

The pre-existing durability, failover and reconciliation suites
([`test_cbf_durability.py`](../../tests/test_cbf_durability.py),
[`test_memorystore_failover.py`](../../tests/infrastructure/test_memorystore_failover.py),
[`test_cbf_reconciliation.py`](../../tests/cage_finance/test_cbf_reconciliation.py))
were rewritten against the new keys; the 1050-outstanding-debit case now also
proves that all 1050 are netted (a 49 000 trade that the raw scalar would admit
is refused).

Acceptance for the implementing PRs: the tests above green, `make test-fast`
green, Gate G3 green, and
`rg -n 'local_debits|trim_local_debits|reconciliation_sequence' src/` empty.
