# Bounded Trade Autonomy — Implementation Plan

> **Decision (recorded):** Sub-threshold autonomous trade execution **is in
> scope**. CAGE's purpose is safe automatic action under deterministic
> pre-vetting; the current architecture cannot deliver it for trades.
>
> **Background:** [`cage_premise_analysis.md`](cage_premise_analysis.md) ·
> [`ftra_autonomy_ceiling_analysis.md`](ftra_autonomy_ceiling_analysis.md)
>
> **Approach:** Split the action verb. Keep the FTRA registry static and
> signable. Put the magnitude decision where magnitude decisions already live.

---

## 1. What is being fixed

FTRA classifies on action name alone:

```json
{ "terminals": { "execute_trade": "IRREVERSIBLE_TERMINAL" } }
```

Its Priority 0 boundary gate therefore escalates **every** trade before any
amount is read. Three graduated controls become unreachable as a result:

| Control | Configured | Reachable today |
|---|---|---|
| Consensus threshold | `$10,000` ([`governance_thresholds.json:60`](../config/governance_thresholds.json)) | ❌ |
| Junior RBAC allowance | `amount <= 5000` ([`generated_stpa_policy.rego:97`](../config/opa/generated_stpa_policy.rego)) | ❌ |
| FRIA three-zone model | `0.95 / 0.70` | ❌ for trades |

Every other tier in CAGE is magnitude-aware. FTRA alone is magnitude-blind.

## 2. The approach, and why not the obvious alternative

**Chosen: split the verb.**

```json
{
  "terminals": {
    "execute_trade_bounded": "REVERSIBLE",
    "execute_trade":         "IRREVERSIBLE_TERMINAL",
    "write_db":              "IRREVERSIBLE_TERMINAL"
  }
}
```

`execute_trade_bounded` folds to severity 1 → `CLEAR`, and the remaining seven
tiers run normally. `execute_trade` behaves exactly as today.

**Rejected: amount-conditional registry entries.** PR #2 cryptographically signs
[`terminal_registry.json`](../config/ftra/terminal_registry.json). A registry
whose meaning varies with request parameters is no longer static content — it is
a policy engine, and it cannot be sealed the way
[`issue_107_pr2_registry_signing_plan.md`](issue_107_pr2_registry_signing_plan.md)
assumes. Choosing this would mean re-opening a threat model that is nearly
closed.

## 3. The security-critical requirement

> **A verb the planner chooses is a verb an attacker can choose.**

Splitting the action is worthless — actively harmful — unless something the plan
cannot influence verifies that `execute_trade_bounded` really carries a
sub-threshold amount. Otherwise the "fix" is a bypass with extra steps:

```
step1: execute_trade_bounded(amount=50_000_000)   →  CLEAR  →  executed
```

This is the same failure mode as **D1** in PR #2 — untrusted input selecting its
own validation path — which is why it gets a dedicated section (§5) rather than
a bullet point.

The verification must be **server-side, in OPA, evaluated against the actual
payload**, and it must fail closed.

## 4. Threshold semantics — decide before coding

`$10,000` currently means *"trigger multi-agent consensus"*. It must not be
silently reused to mean *"autonomy ceiling"* — they are different questions
(*how much scrutiny?* vs *may a human be skipped entirely?*) and conflating them
buries a policy decision inside a config key.

Introduce a distinct, explicitly named threshold:

```json
"autonomy": {
  "max_autonomous_trade_usd": 5000.0,
  "_comment": "Trades at or below this USD amount may execute without human
               approval, subject to all seven governance tiers. Above this,
               FTRA escalates to REQUIRE_APPROVAL."
}
```

Defaulting to `5000` aligns with the existing junior RBAC band. Setting it to
`0` restores today's behaviour — a clean kill switch.

### 4.1 Correction — "autonomous trades never skip consensus" was wrong

An earlier draft of this plan justified the `5000` default by saying it sits
below the consensus threshold *"so autonomous trades never skip consensus."*
**That reasoning was incorrect and has been removed.** The correct position is
below; it is recorded rather than quietly deleted because the error would
otherwise recur.

**What actually happens.** The consensus *tier* is claimed on the action name
alone —
[`consensus_tier.py:40`](../src/cage_finance/tiers/consensus_tier.py:40):

```python
def claims_action(self, action: str, params: dict[str, Any]) -> bool:
    return action == "execute_trade"     # no amount test
```

So `ConsensusGate.check_consensus()` **runs for every trade at any amount**,
including $1. `$10,000` is not a gate on whether consensus *executes*; it is a
parameter *inside* consensus governing how it responds — and it is applied
strictly (`amount_usd > threshold_usd`,
[`hitl_escalator.py:261`](../src/gateway/governance/hitl_escalator.py:261)).

Three consequences my original sentence got wrong:

1. **A sub-$5 000 trade does not "skip" consensus today** — nothing to preserve.
   The claim implied a protection that was never conditional on the ceiling.
2. **The relative ordering of the two thresholds is irrelevant** to whether
   consensus runs. Setting the ceiling *above* $10 000 would not disable
   consensus either. My justification would have held equally for any value,
   which is a sign it was not a justification at all.
3. **Under the action split, the risk runs the other way.**
   `claims_action` matches the literal string `"execute_trade"`, so
   `execute_trade_bounded` **will not be claimed** — and consensus, CBF, fiscal
   and causal tiers will all silently stop running for bounded trades.

### 4.2 The real requirement this uncovered

Every finance tier gates on the same literal
([`cbf_tier.py:40`](../src/cage_finance/tiers/cbf_tier.py:40),
[`fiscal_tier.py:42`](../src/cage_finance/tiers/fiscal_tier.py:42),
[`causal_tier.py:41`](../src/cage_finance/tiers/causal_tier.py:41),
`consensus_tier.py:40`). Introducing a new verb without updating them would
produce the worst possible outcome: **autonomous execution with fewer controls
than the human-reviewed path.**

All four must be updated together:

```python
_TRADE_ACTIONS = frozenset({"execute_trade", "execute_trade_bounded"})

def claims_action(self, action: str, params: dict[str, Any]) -> bool:
    return action in _TRADE_ACTIONS
```

A shared frozenset — not four independent string comparisons — so a fifth tier
or a third verb cannot diverge. This is the same lesson as the
`CLASSIFICATION_SEVERITY` fix in PR #1, where two copies of a severity map
drifted and produced a latent `KeyError`.

**Test obligation (added to §7):** assert that all four tiers claim
`execute_trade_bounded`. Without it, the split silently removes governance
rather than relocating it — the exact failure the whole plan exists to prevent.

### 4.2b Related finding — DoWhy does not run per trade

The same question applied to the causal tier gives a different answer, and it
matters for the autonomy decision.

`CausalTierPlugin.claims_action` is unconditional like the others
([`causal_tier.py:41`](../src/cage_finance/tiers/causal_tier.py:41)), so
`causal_safety_check()` is *invoked* on every trade. But inside, DoWhy itself is
reached far less often
([`gatekeeper.py`](../src/gateway/governance/causal/gatekeeper.py)):

| Guard | Line | Effect |
|---|---|---|
| `amount <= 0` | 584 | `return True` — no causal evaluation |
| `not _DOWHY_AVAILABLE` | 588 | Fail **closed** — blocks without evaluating |
| Redis cache hit | 655 | Returns the cached verdict — **no DoWhy run** |

The cache key is:

```python
cache_key = f"causal_cache:{action_type}:{market_regime}"
```

**The key contains no amount.** Within the TTL
(`get_causal_cache_ttl_seconds()`, default 60s), every trade sharing an
`action_type` and `market_regime` reuses one verdict — so a *typical* trade
triggers a cache lookup, not a full DoWhy estimate plus 50-simulation placebo
refutation. That is a deliberate and reasonable latency decision.

**Why it matters here.** The cached verdict was computed for whatever amount
happened to miss the cache first, yet the risk formula is amount-dependent
([line 868](../src/gateway/governance/causal/gatekeeper.py:868)):

```python
estimated_risk = clamp(0.5 + β * amount / CAUSAL_NORMALIZATION_SCALE, 0.0, 1.0)
```

A $100 trade can therefore be admitted on a verdict computed for $100, and a
$9 000 trade admitted on that same verdict 30 seconds later. Today every such
trade still lands in `REQUIRE_APPROVAL`, so a human sees it regardless. **Under
bounded autonomy, that human disappears** — and the causal tier becomes the
amount-sensitive control most likely to be answering a question it was not
asked.

Two options, to be decided with the ceiling value:

- **Bucket the cache key by amount band** (e.g. `…:{amount_bucket}`), so a
  cached verdict only applies to comparable magnitudes. Cheap; preserves most
  of the latency benefit.
- **Bypass the cache for `execute_trade_bounded`**, accepting full DoWhy cost on
  the autonomous path. Strictest, and the latency lands precisely where no human
  is watching.

Either is defensible. Doing neither means the autonomous path's causal check is
weaker than it appears — worth stating explicitly rather than discovering later.

### 4.3 So why keep `5000`?

Not for the reason originally given. The honest justifications:

- It matches the existing `rbac_allow_junior_trade` band, so the OPA policy and
  the autonomy ceiling agree rather than encoding two different opinions.
- It is conservative: a value that is too low costs unnecessary human reviews;
  too high risks unreviewed loss. Start low, raise on evidence.

Both are weak reasons compared with an actual business risk appetite. **The
number should be set by whoever owns that appetite** — this plan's default is a
placeholder, not a recommendation.

---

## 5. Payload verification — the control that makes this safe

Two independent checks. Both must pass; either failing means the action is
treated as unbounded `execute_trade`.

### 5.1 OPA rule (authoritative)

In [`generated_stpa_policy.rego`](../config/opa/generated_stpa_policy.rego),
generated from STPA source so it cannot drift from the registry:

```rego
# Deny bounded-trade verb when the payload exceeds the autonomy ceiling.
deny_bounded_trade_over_ceiling if {
    input.action == "execute_trade_bounded"
    input.amount > data.thresholds.autonomy.max_autonomous_trade_usd
}

# Deny bounded-trade verb when amount is absent, non-numeric, or non-finite.
deny_bounded_trade_malformed if {
    input.action == "execute_trade_bounded"
    not is_number(input.amount)
}
```

OPA sees the **real payload**, not the planner's claim about it. A mismatch is a
hard `DENY`, not a downgrade to `REQUIRE_APPROVAL` — a plan that mislabels its
own magnitude is either broken or hostile, and neither deserves a human's time.

### 5.2 Boundary re-check (defence in depth)

[`_ftra_boundary_check()`](../src/gateway/governance/symbolic_governor.py:1113)
already receives `tool_input` and currently ignores it — the parameter is
documented as *"currently unused but available for future input-dependent
classification"*. Use it:

```python
if tool_name == "execute_trade_bounded":
    amount = tool_input.get("amount")
    if not isinstance(amount, (int, float)) or not math.isfinite(amount) \
       or amount > get_max_autonomous_trade_usd():
        # Re-classify as the unbounded verb — fail closed.
        classification = TerminalClassification.IRREVERSIBLE_TERMINAL
```

This runs at step -1, before OPA. If the two ever disagree, the stricter wins.

### 5.3 Non-negotiables

- **Reject non-finite values.** `float('inf') > 5000` is `True`, but `NaN > 5000`
  is `False` — a `NaN` amount would sail through a naive comparison. The repo
  already guards this at ingress
  ([`test_ingress_nan_rejection.py`](../tests/test_ingress_nan_rejection.py));
  the same discipline applies here.
- **Reject negative amounts** unless a negative is genuinely meaningful for the
  action; a `-1` amount trivially satisfies any `<=` ceiling.
- **Compare on a single canonical currency.** `amount: 5000` in one currency is
  not `5000` in another. Either restrict bounded trades to a base currency or
  normalise before comparison — and be explicit about which.
- **Never trust a client-supplied threshold.** The ceiling is read from
  server-side config only, never from `params`.

---

## 6. Change inventory

| # | File | Change |
|---|---|---|
| 1 | [`config/governance_thresholds.json`](../config/governance_thresholds.json) | Add `autonomy.max_autonomous_trade_usd` |
| 2 | `config/thresholds/*.json` + loader | Typed accessor `get_max_autonomous_trade_usd()`, per EV-1–EV-6 pattern |
| 3 | [`trade_hazards.yaml`](../config/stpa/domains/finance/trade_hazards.yaml) | New UCA for `execute_trade_bounded`, `terminal_classification: REVERSIBLE` |
| 4 | [`stpa_control_structure.yaml`](../config/stpa_control_structure.yaml) | Mirror #3 — **lexicographic UCA order**, see §8 |
| 5 | [`stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py) | Emit the two `deny_bounded_trade_*` Rego rules |
| 6 | Regenerated artifacts | `terminal_registry.json`, validator, rails, saga nodes, policy |
| 7 | [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py:1113) | Payload re-check (§5.2) |
| 7b | **All four finance tiers** — [`consensus_tier.py:40`](../src/cage_finance/tiers/consensus_tier.py:40), [`cbf_tier.py:40`](../src/cage_finance/tiers/cbf_tier.py:40), [`fiscal_tier.py:42`](../src/cage_finance/tiers/fiscal_tier.py:42), [`causal_tier.py:41`](../src/cage_finance/tiers/causal_tier.py:41) | **Claim `execute_trade_bounded` via a shared `_TRADE_ACTIONS` frozenset (§4.2). Omitting this silently removes four governance tiers from the autonomous path.** |
| 8 | Planner / advisor prompt | Emit `execute_trade_bounded` below ceiling |
| 9 | OSCAL framework mappings | NIST + ISO entries for the new UCA (CI enforces this) |
| 10 | Three governance docs | §9 |

**Note on #6:** the STPA compiler needs `PYTHONPATH=.` when run directly —
`uv run python src/gateway/governance/stpa_compiler.py compile --input
config/stpa_control_structure.yaml` fails with `No module named 'src'` otherwise.
Worth fixing separately.

---

## 7. Test strategy

New file `tests/test_bounded_trade_autonomy.py`.

### 7.1 The two tests that matter

| Test | Assertion |
|---|---|
| **Happy path** | `execute_trade_bounded(amount=1000)` → `verdict == ALLOW`, **seal issued**, no HITL |
| **Tier coverage** | All four finance tiers `claims_action("execute_trade_bounded", ...)` → `True` |

The first proves autonomy exists. The second proves it is still governed —
without it, the split could deliver autonomous execution with *fewer* controls
than the human-reviewed path, which is strictly worse than the status quo.

Assert tier coverage by iterating the registered tiers rather than naming four
classes, so a fifth tier added later is caught automatically.

### 7.2 Bypass attempts — all must fail closed

| Attack | Expected |
|---|---|
| `execute_trade_bounded(amount=50_000_000)` | `DENY` — ceiling exceeded |
| `execute_trade_bounded(amount=float('inf'))` | `DENY` — non-finite |
| `execute_trade_bounded(amount=float('nan'))` | `DENY` — **`NaN > ceiling` is `False`**; a naive comparison admits this |
| `execute_trade_bounded(amount=-1)` | `DENY` — negative trivially satisfies `<=` |
| `execute_trade_bounded` with `amount` absent | `DENY` — malformed |
| `amount` as string `"1000"` | `DENY` — type confusion |
| Client-supplied `max_autonomous_trade_usd` in `params` | Ignored; server config wins |
| Ceiling set to `0` | Every bounded trade escalates — kill switch works |

### 7.3 Boundary and regression

- `amount == ceiling` exactly → `ALLOW` (inclusive, matching `<=` in the OPA band)
- `amount == ceiling + 0.01` → escalates
- Unbounded `execute_trade` at any amount → `REQUIRE_APPROVAL`, unchanged
- `write_db` → `IRREVERSIBLE_TERMINAL`, unchanged
- Composed plan `check_balance → execute_trade_bounded → execute_trade` →
  escalates; the fold takes the **worst case**, and the bounded verb must not
  launder the unbounded one

### 7.4 Mutation checks — mandatory, not optional

Three defects in PR #2 (D1–D3) passed a green suite. The same failure mode is
available here, so each control gets falsified before the PR opens:

1. Delete the OPA ceiling rule → the `amount=50_000_000` test **must** fail.
2. Delete the §5.2 boundary re-check → an over-ceiling test **must** fail
   (proves defence-in-depth is real, not decorative).
3. Change `>` to `>=` in the ceiling comparison → the exact-boundary test
   **must** fail.
4. Revert one tier's `claims_action` to the bare `== "execute_trade"` literal →
   the §7.1 tier-coverage test **must** fail. This is the guard against silently
   ungoverned autonomous execution.

If any mutation leaves the suite green, that control is untested. Record the
results in the PR body.

### 7.5 Full-suite regression

`uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith --tb=short`

Baseline on `feat/aisvs-c9-taxonomy` is **1 failed / 3309 passed / 92 skipped**,
the single failure pre-existing on `main`. Any deviation needs explaining rather
than absorbing — a previously-failing test that silently starts passing is as
suspicious as a new failure.

---

## 8. Sequencing and known traps

### 8.1 Order

This work **depends on PR #2** ([`issue_107_pr2_registry_signing_plan.md`](issue_107_pr2_registry_signing_plan.md)),
which is unmerged and modifies the same registry and compiler.

```
main
 └── feat/aisvs-c9-taxonomy   (PR #123, open)
      └── feat/ftra-registry-signing   (PR #2, open)
           └── feat/bounded-trade-autonomy   ← this work
```

Branch from `feat/ftra-registry-signing`, rebase down the chain as each lands.
Branching from `main` would revert both PRs.

**Recommend landing PR #2 first.** This plan adds a `REVERSIBLE` entry to the
registry, and shipping that before the registry is signed leaves a window where
the autonomy-enabling entry is itself tamperable.

### 8.2 Lexicographic UCA ordering

Multi-source STPA merge sorts UCA IDs **as strings**: `UCA-1`, `UCA-10`,
`UCA-11`, `UCA-2`. The monolithic
[`stpa_control_structure.yaml`](../config/stpa_control_structure.yaml) must
match that order or
[`test_merge_union_of_single_file_matches_monolithic`](../tests/test_stpa_multi_source.py:76)
fails. This cost real time during PR #1.

### 8.3 OSCAL mappings are CI-enforced

A new UCA without NIST **and** ISO 42001 mappings fails
[`test_oscal_ssp_exporter.py::TestUcaMappings`](../tests/test_oscal_ssp_exporter.py).
This is correct behaviour — new controls must be mapped — but it will block the
build if forgotten.

### 8.4 Regenerate every artifact

Editing STPA source without recompiling leaves the generated validator, rails,
saga nodes and Rego stale. Symptoms are confusing and the root cause is not
obvious from the failure message.

---

## 9. Documentation reconciliation

Three documents currently describe three different products. All must state the
same thing once the code changes.

| Document | Required change |
|---|---|
| [`AGENTIC_SCOPE_STATEMENT.md:20`](../docs/governance/AGENTIC_SCOPE_STATEMENT.md:20) | *"Execute trades: ⛔ NOT authorized — advisory only"* → **conditionally authorized** below `max_autonomous_trade_usd`, subject to all seven tiers |
| [`HUMAN_OVERSIGHT_SCOPE.md`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:24) | Add the autonomy ceiling to the trigger table; make explicit that below-ceiling trades are **not** escalated |
| [`CAGE_ONE_PAGER.md:28`](../docs/project/CAGE_ONE_PAGER.md:28) | Already claims graduated behaviour — becomes true; state the ceiling explicitly |

Also settle the **FTRA defer deadlock** flagged in
[`ftra_autonomy_ceiling_analysis.md §0.2`](ftra_autonomy_ceiling_analysis.md):
`HUMAN_OVERSIGHT_SCOPE.md:222` says FTRA-parked tokens *"cannot be released by a
HITL reviewer"*, while
[`defer_queue.py:252`](../src/gateway/governance/defer_queue.py:252) assigns them
a **quorum of 3**. One is wrong. Until it is settled, nobody can say what happens
to an escalated trade.

---

## 10. Out of scope

- **Renaming** to *"governed financial trader"* — revisit once the behaviour
  ships. The name should follow the system, not lead it.
- **`bypassed_ftra_node` heuristic** firing on 100% of trades
  ([analysis §3](ftra_autonomy_ceiling_analysis.md)) — real, separate, fix
  independently.
- **Per-role autonomy ceilings** (junior $5k, senior $50k) — natural extension;
  land the single global ceiling first.
- **Composition attack (VEC-009)** — N-chunk exports below threshold summing
  above it. Explicitly *not* addressed here and tracked as `xfail` in PR #3.
  **This plan does not close it, and adding bounded autonomy makes it more
  reachable** — say so plainly in the PR rather than letting a reader infer
  coverage that does not exist.
