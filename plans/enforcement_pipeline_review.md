# Enforcement Pipeline Review — Consistency, Logic, Intent

> Review of CAGE's governance pipeline against its stated intent: *safe
> automatic action, deterministically vetted beforehand.*
>
> **Headline: the pipeline is sound as a blocking mechanism and incoherent as a
> graduated one. Every tier independently invented its own answer to "does this
> apply?", and nobody wrote the answers down together.**

---

## 1. Method

Traced each tier's **applicability gate** (does it run?) separately from its
**decision logic** (what does it do?). The two are conflated in the docs, and
that conflation is where the defects live.

Sources: [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py),
the four finance tiers in [`src/cage_finance/tiers/`](../src/cage_finance/tiers/),
[`causal/gatekeeper.py`](../src/gateway/governance/causal/gatekeeper.py),
[`resource_guard.py`](../src/gateway/governance/safety/resource_guard.py),
[`ftra/`](../src/gateway/governance/ftra/).

---

## 2. The applicability matrix

This table does not exist anywhere in the repo. It should.

| Tier | Claims when | Then runs when | Amount-aware? |
|---|---|---|---|
| **FTRA boundary** | Always — mandatory, no flag | Always | ❌ Name only |
| **STPA** | `stpa_validator is not None` | Per-UCA conditions | Partially |
| **Confidence** | `_is_governed_action()` | Always | ❌ |
| **OPA** | Always (both branches — §4.2) | Always | ✅ Bands by amount |
| **Consensus** | `action == "execute_trade"` | Always | ✅ Inside `check_consensus` |
| **Causal** | `action == "execute_trade"` | **Only on cache miss** | ✅ In risk formula |
| **CBF** | `action == "execute_trade"` | Phase 2, if no violations | ✅ Balance |
| **Fiscal** | `action == "execute_trade"` | Phase 2, if no violations | ✅ Daily cap |

Five distinct applicability idioms across eight tiers. Each defensible alone; as
a set, they mean **no one can state what governs a given action without reading
eight files.**

---

## 3. Findings

### F1 — Four tiers gate on a string literal (high)

[`consensus_tier.py:40`](../src/cage_finance/tiers/consensus_tier.py:40),
[`cbf_tier.py:40`](../src/cage_finance/tiers/cbf_tier.py:40),
[`fiscal_tier.py:42`](../src/cage_finance/tiers/fiscal_tier.py:42),
[`causal_tier.py:41`](../src/cage_finance/tiers/causal_tier.py:41) each contain
their own copy of:

```python
return action == "execute_trade"
```

Four independent copies of one policy decision. Any new trade verb must be added
to all four or governance silently narrows — no error, no warning, just fewer
tiers running. This is the identical failure mode to the `CLASSIFICATION_SEVERITY`
drift fixed in PR #1, where two copies of a severity map diverged into a latent
`KeyError`.

**Fix:** one shared `_TRADE_ACTIONS` frozenset, plus a test asserting every
registered finance tier claims every trade verb.

### F2 — Causal cache is amount-blind (high)

[`gatekeeper.py:600`](../src/gateway/governance/causal/gatekeeper.py:600):

```python
cache_key = f"causal_cache:{action_type}:{market_regime}"
```

No amount. Yet the verdict it caches is amount-dependent
([line 868](../src/gateway/governance/causal/gatekeeper.py:868)):

```python
estimated_risk = clamp(0.5 + β * amount / CAUSAL_NORMALIZATION_SCALE, 0.0, 1.0)
```

Within the TTL, a $9 000 trade inherits the verdict computed for a $100 one.
Tolerable today because a human reviews everything; **unsafe the moment
autonomy is enabled.**

### F3 — Fiscal tier reserves and confirms in the same breath (medium)

[`fiscal_tier.py:53-65`](../src/cage_finance/tiers/fiscal_tier.py:53):

```python
token = await self.guard.reserve(...)
if token.rejected: return [Violation(...)]
self._tokens[transaction_id] = token
await self.guard.confirm(token)      # ← immediately
```

`confirm()` means *"the reservation became a real spend"*
([`resource_guard.py:677`](../src/gateway/governance/safety/resource_guard.py:677)),
and it deletes the per-reservation sentinel key. But it is called at
**governance** time, before the trade has executed. The two-phase
reserve → confirm design collapses to single-phase, and the window the sentinel
exists to protect is closed before the risk it guards against has occurred.

`release()` still decrements the aggregate counter, so rollback is not fully
broken — but the confirm/release protocol no longer means what
[`resource_guard.py`](../src/gateway/governance/safety/resource_guard.py:63)
documents.

### F4 — Fiscal rollback keyed on in-memory dict (medium)

[`fiscal_tier.py:27`](../src/cage_finance/tiers/fiscal_tier.py:27) stores tokens
in `self._tokens = {}` on the plugin instance:

- **Never evicted** — unbounded growth over pod lifetime.
- **Not shared across replicas** — a rollback landing on a different pod finds
  nothing and silently no-ops.
- **Lost on restart** — reservations become unreleasable.

`rollback()` looks up `params.get("transaction_id")`; if absent, `.get(None)`
returns `None` and the release is skipped without complaint.

### F5 — `bypassed_ftra_node` fires on every trade (medium)

[`symbolic_governor.py:1165`](../src/gateway/governance/symbolic_governor.py:1165)
reduces to *"is this action irreversible?"*, so a WARN claiming *"possible direct
HTTP bypass"* is emitted on 100% of legitimate trades. The OTel attribute
`cage.ftra.bypassed_ftra_node` measures irreversibility, not bypass — any alert
built on it is misnamed. Detecting a real bypass needs evidence the in-graph node
*did not* run.

### F6 — The mislabelled `else` branch (low, latent)

[`symbolic_governor.py:1561`](../src/gateway/governance/symbolic_governor.py:1561)
is commented *"Non-trade actions: sequential OPA only"*, but the guard is
`_is_governed_action(...) and not violations` — so it is **also** the
trade-with-existing-violations path. OPA does still run (good, and it is why
OPA is not dead code under FTRA), but the comment actively misleads.

### F7 — FTRA defer deadlock (medium)

[`HUMAN_OVERSIGHT_SCOPE.md:222`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:222)
says FTRA-parked tokens *"cannot be released by a HITL reviewer"*.
[`defer_queue.py:252`](../src/gateway/governance/defer_queue.py:252) assigns them
a **quorum of 3**. One is wrong. Latent only because the mandatory boundary gate
returns `REQUIRE_APPROVAL` without touching the DeferQueue — it arms for any
adopter who wires the in-graph node as the docs encourage.

### F8 — Documentation describes three different products (high)

| Source | Claim |
|---|---|
| [`CAGE_ONE_PAGER.md:28`](../docs/project/CAGE_ONE_PAGER.md:28) | Pauses only above $10k → automatic below |
| [`HUMAN_OVERSIGHT_SCOPE.md:28`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:28) | Escalates above $10k → automatic below |
| [`AGENTIC_SCOPE_STATEMENT.md:20`](../docs/governance/AGENTIC_SCOPE_STATEMENT.md:20) | Trades ⛔ not authorized — advisory only |
| Code | Every trade → `REQUIRE_APPROVAL` |

---

## 4. What is genuinely well built

Worth stating, because the findings above are concentrated in one seam and could
give a misleading impression of the whole.

- **Two-phase ordering is correct.** Phase 2 mutations are guarded by
  `and not violations`, so a rejected action never debits CBF balance or
  consumes fiscal capacity. Zero budget leakage, and the comments explain why
  the latency trade-off was accepted.
- **Fail-closed discipline is consistent.** Tier exceptions become
  non-recoverable violations
  ([`symbolic_governor.py:1006`](../src/gateway/governance/symbolic_governor.py:1006));
  FTRA fails closed on any error; CBF fails closed on Redis loss; DoWhy absence
  blocks rather than skips.
- **LIFO rollback attempts every tier** even when one fails, and surfaces
  `ROLLBACK_FAILED` as non-recoverable rather than retrying silently
  ([`:934`](../src/gateway/governance/symbolic_governor.py:934)).
- **FTRA's whole-graph reachability** is a genuine contribution. No per-call
  authorisation can see `check_balance → transfer_funds → execute_trade`.
- **The five-way decision model** (`DENY`/`DEFER`/`NARROW`/`PAUSE`/
  `REQUIRE_APPROVAL`) is richer than most governance layers attempt.

The architecture is sound. The defects are in **applicability**, not in
enforcement.

---

## 5. Root cause

One sentence: **CAGE was built to block, and is now being asked to permit.**

Blocking is monotone — more gates is safer, so nobody had to reason about the
composition of applicability rules. Under that regime, five different idioms for
"does this apply?" cost nothing, an amount-blind cache is a latency win, and
`confirm()` at governance time is invisible because a human sees the trade
anyway.

Permitting is not monotone. Every one of those choices becomes load-bearing, and
their *composition* is what determines whether an autonomous action was actually
governed. F1–F4 are all the same defect wearing different clothes: **a local
decision that was safe under universal escalation and is not safe without it.**

This is why the fix is not "add a threshold". It is: make applicability explicit
and testable, then enable autonomy on top of it.

---

## 6. Recommendation

### Sequence

```mermaid
graph LR
    A[Stage 0<br/>Truth] --> B[Stage 1<br/>Coherence]
    B --> C[Stage 2<br/>Autonomy]
    C --> D[Stage 3<br/>Hygiene]
```

**Do not start at Stage 2.** Enabling autonomy over F1–F4 produces autonomous
execution with fewer controls than the reviewed path — strictly worse than
today.

### Stage 0 — Establish truth (before any code)

1. **Publish the §2 applicability matrix** as `docs/governance/TIER_APPLICABILITY.md`,
   generated from code where possible so it cannot drift.
2. **Resolve F8** — pick one product description and make all three documents
   say it.
3. **Resolve F7** — decide whether FTRA-parked tokens are releasable.

Cheap, unblocks everything, and F8 alone is the difference between an auditor
finding a documented ceiling and finding a broken promise.

### Stage 1 — Coherence (prerequisite for autonomy)

| Fix | Finding | Why first |
|---|---|---|
| Shared `_TRADE_ACTIONS` frozenset + tier-coverage test | F1 | Any new verb silently narrows governance without it |
| Bucket causal cache key by amount band | F2 | Amount-sensitive verdict served for wrong amount |
| Move `confirm()` to post-execution, or rename it | F3 | Two-phase protocol currently collapses to one phase |
| Redis-backed reservation tokens | F4 | Rollback silently no-ops across replicas |

Each is small, independently testable, and valuable **even if autonomy is never
enabled** — F3 and F4 are live correctness bugs today.

### Stage 2 — Bounded autonomy

Proceed with [`bounded_trade_autonomy_plan.md`](bounded_trade_autonomy_plan.md)
once Stage 1 lands. Unchanged in substance; Stage 1 removes its riskiest
dependencies.

### Stage 3 — Hygiene

F5 (`bypassed_ftra_node`) and F6 (mislabelled `else`). Neither blocks; both
mislead the next reader.

### Interaction with in-flight work

```
main
 └── feat/aisvs-c9-taxonomy          PR #123, open
      └── feat/ftra-registry-signing  PR #2, open — verification outstanding
           └── Stage 1
                └── Stage 2 (autonomy)
```

Land PR #2 first. Stage 2 adds a `REVERSIBLE` registry entry, and shipping the
autonomy-enabling entry before the registry is signed leaves it tamperable.

---

## 7. One structural suggestion

F1–F4 were all found by asking *"when does this tier actually apply?"* — a
question the `GovernanceTierPlugin` protocol lets each tier answer in prose,
privately, with no cross-checking.

Consider making applicability **declarative** rather than imperative:

```python
class GovernanceTierPlugin(Protocol):
    @property
    def applies_to(self) -> frozenset[str]: ...   # action names
```

A property can be **enumerated at startup**, so the matrix in §2 becomes
generated rather than archaeological, and CI can assert that every governed
action is claimed by the expected tier set. `claims_action(action, params)`
cannot be enumerated — it must be probed with a payload, which is precisely why
nobody has written the matrix down.

Tiers needing payload-dependent logic keep it *inside* `evaluate()`, where it
belongs, rather than in the applicability gate. That single change would have
made F1 a compile-time impossibility and F2 visible on inspection.

Not required for autonomy. Worth considering before a fifth tier or a third verb
arrives.

---

## 8. Bottom line

The enforcement machinery is **well built and internally consistent as a blocking
system**. Two-phase ordering, fail-closed discipline, LIFO rollback, and
whole-graph reachability are all genuinely good.

The applicability layer is **inconsistent, undocumented, and was never designed
to support permitting**. Eight tiers, five idioms, one matrix that exists nowhere.

Three of the four Stage 1 fixes are worth doing regardless of the autonomy
decision, because F3 and F4 are bugs today and F1 is an accident waiting for the
next contributor. Stage 0 costs almost nothing and stops the documentation
promising something the code cannot do.
