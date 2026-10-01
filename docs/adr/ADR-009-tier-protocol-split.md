# ADR-009: Read-Only / Mutating Tier Protocol Split, and Settlement After Actuation

**Status:** Accepted (implemented in `refactor/ftra-scope`, Phase 7)  
**Date:** 2026-10-01  
**Decision Makers:** CAGE Core Architecture Team  
**Supersedes:** the single `GovernanceTierPlugin` protocol  
**Compliance Mapping:** NIST SP 800-53 AC-3, SC-5 (fiscal limits), SI-10 | ISO 42001 §A.6.2.6

---

## Context

Before this ADR every governance tier implemented one protocol,
`GovernanceTierPlugin`, with `evaluate()`, `commit()`, `rollback()` and a
`phase` integer. Two problems followed from that.

1. **Read-only tiers carried fake mutation hooks.** Seven phase-1 tiers
   (`consensus`, `causal`, `bounding`, `clinical_consensus`,
   `physical_safety_consensus`, the EU `fria` tier and test doubles) had
   no-op `commit()` / `rollback()` bodies. Whether a tier mutated was decided
   by the `phase` integer, which nothing tied to the hooks: a tier could
   declare `phase = 1` and still reserve state in `commit()`, and it would
   never be committed or rolled back.
2. **A reservation was made final before the action ran.** The fiscal tier
   called `guard.confirm(token)` inside `commit()`, that is, before the seal
   was issued and long before the broker answered. A failed or rejected trade
   left the spend counted (only the CBF was rolled back, ad hoc, in
   `execute_trade_action`). The guard's per-reservation TTL key was written
   but never read, so nothing reclaimed a reservation stranded by a crash.

## Decision

### 1. Two nominal tier kinds

[`contracts.py`](../../src/gateway/governance/contracts.py) defines three
abstract base classes:

| Class | `phase` | Hooks |
|---|---|---|
| `GovernanceTier` | — | `tier_name`, `order`, `claims_action`, `evaluate`, `runtime_requirements` |
| `ReadOnlyTier(GovernanceTier)` | 1 (derived) | none beyond `evaluate` |
| `MutatingTier(GovernanceTier)` | 2 (derived) | `commit`, `rollback`, `confirm` (all abstract) |

`ReadOnlyTier` and `MutatingTier` are siblings, so `isinstance(t,
ReadOnlyTier)` means "never mutates". `phase` is derived from the kind and is
no longer declared by tiers.

[`check_tier_kind()`](../../src/gateway/governance/governor/stages/domain_tiers.py)
runs when a `DomainTierStage` is built and fails closed at assembly:

- an object that is not a `GovernanceTier` raises `TypeError`;
- an object that is both kinds, or neither, raises `TypeError`;
- a read-only tier that defines `commit`, `rollback` or `confirm` raises
  `TypeError`, because it meant to reserve state and running it read-only
  would silently skip the reservation;
- a `phase` override that contradicts the kind raises `ValueError`.

Jurisdiction tiers must be `ReadOnlyTier` (`JurisdictionContribution` raises
`TypeError` otherwise). `CAGE_PLUGIN_API_VERSION` is `"2.0"`.

### 2. Settlement after actuation

A committing run now only *reserves*. The commits behind an issued seal are
handed by [`run_sealed`](../../src/gateway/governance/governor/sealing.py)
(via `ReservationScope.seal_issued()`, which returns them) to the governor's
[`SettlementLedger`](../../src/gateway/governance/governor/settlement.py).
The caller that actuates reports the outcome:

```python
failures = await governor.settle(seal, executed=receipt.accepted)
```

- `executed=True`: every mutating tier's `confirm(receipt)` runs, in commit order.
- `executed=False`: every `rollback(receipt)` runs, last in first out.
- Both run shielded; every hook is attempted; failures come back as HARD
  `CONFIRM_FAILED` / `ROLLBACK_FAILED` violations and are logged at CRITICAL.
- Settlement is idempotent per seal: the first call takes the commits.

[`execute_trade_action`](../../src/cage_finance/tools/tool_provider.py)
settles in a `finally` block, so every exit after the seal settles exactly
once: only a broker-accepted trade confirms; an invalid seal, a dry run, a
rejection, an actuation error or a missing actuator releases.

### 3. A real TTL reclaimer for the fiscal cap

[`FiscalLimitGuard`](../../src/cage_finance/safety/fiscal_limit_guard.py)
keeps open reservations in a Redis ZSET (`fiscal:pending`, score = expiry).
`reserve`, `confirm`, `release` and the reclaimer are each one Lua script, so
a reservation leaves the pending set exactly once. `reclaim_expired()` runs
lazily at the start of `reserve()`. The previews `would_accept()` and
`headroom_usd()` stay write-free (the tier contract): they subtract expired,
unreclaimed reservations from the counter they read. A
`confirm()` for a reservation already reclaimed counts the amount again
(the money was spent). The guard's un-ledgered `rollback_state()` and the
unread `fiscal:reservation:{id}` sentinel key are removed.

## Deviations from the Phase 7 plan

- **Siblings, not `MutatingTier(ReadOnlyTier)`.** The plan proposed
  inheritance. With inheritance, `isinstance(t, ReadOnlyTier)` is true for
  mutating tiers, which defeats the type as a guarantee.
- **ABCs, not `runtime_checkable` Protocols.** Structural detection fails
  open: a mutating tier missing one hook would be classified read-only and
  never committed. Nominal subclassing plus abstract methods refuses it at
  instantiation.
- **`confirm` is a third hook.** The plan only moved the fiscal confirm to
  "the actuation receipt path". Making it a tier hook keeps the kernel
  domain-agnostic: the actuator never names a tier.

## Consequences

- Breaking for plugin authors: subclass `ReadOnlyTier` or `MutatingTier`,
  drop `phase`, drop no-op hooks, and implement `confirm` on mutating tiers.
  Plugins must declare `api_version = "2.0"`.
- `ReservationScope.seal_issued()` returns the held commits;
  `run_sealed()` requires a `settlements` ledger.
- `execute_trade_action` and `FinancialToolProvider` no longer take a
  `safety_filter`.
- `FiscalLimitGuard.release()` now raises on a Redis error, so a failed
  release is visible as `ROLLBACK_FAILED` instead of being swallowed; the
  reservation stays pending and is reclaimed after its TTL.

### Known gaps

- **Crash after actuation, before `confirm`.** The reservation expires, so
  that spend is under-counted for the rest of the window. Closing this needs
  the actuation receipt itself (durable, keyed by seal) to drive the confirm.
- **The ledger is in-process.** Governance and actuation share one process
  today (`enforce_governance` returns the seal in-process). A split
  deployment would need a durable ledger keyed by seal.
- **Seals nothing actuates.** The LangGraph harness
  (`src/gateway/governance/langgraph_harness/opa_node_factory.py`) calls
  `governor.govern()` and discards the seal. Its fiscal reservation now
  expires after the TTL instead of counting for the day; its CBF debit is
  permanent, as before.
- **Ambiguous actuation errors release.** An exception from `actuate()` is
  treated as "not executed". If a broker can execute and then time out, a
  venue-side reconciliation is needed to confirm late.

## Verification

- `tests/governor/test_tier_kind.py`: every `check_tier_kind` failure path.
- `tests/governor/test_settlement.py`: confirm order, LIFO release,
  idempotence, failure reporting, cancellation, ledger expiry, and the fiscal
  crash-between-seal-and-actuation path on a real guard.
- `tests/cage_finance/test_trade_settlement.py`: every exit of
  `execute_trade_action` settles exactly once with the right outcome.
- `tests/cage_finance/test_fiscal_limit_guard.py`: reclaimer, exactly-once
  transitions, confirm after reclaim, sync and async clients.
