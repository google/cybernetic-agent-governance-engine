# CAGE's Basic Premise — Does FTRA Contradict It?

> **Question:** CAGE exists to allow safe automatic actions that are
> deterministically vetted beforehand. `governed-financial-advisor` should do
> that for trades. If FTRA prevents this, should FTRA be removed, or the product
> renamed?
>
> **Answer: your reading of the premise is right, and it is CAGE's own stated
> premise. Do not remove FTRA. The defect is a single registry line plus three
> documents that disagree with each other.**

---

## 1. The premise, in CAGE's own words

The framing *"safe automatic actions, deterministically vetted beforehand"* is
not an outside interpretation — it is what the project claims.

[`CAGE_ONE_PAGER.md`](../docs/project/CAGE_ONE_PAGER.md:13):

> a deterministic, **8-tier policy enforcement pipeline** — **without sacrificing
> production latency**

Latency only matters if actions execute automatically. Nobody optimises
milliseconds on a path that terminates in a human's inbox.

[`CAGE_ONE_PAGER.md:28`](../docs/project/CAGE_ONE_PAGER.md:28) is more specific:

> the LangGraph graph pauses via `interrupt_before=["governed_trader"]`
> **for all trades exceeding $10k or risk score > 0.7**

That sentence is only meaningful under a graduated model. *"For all trades
exceeding $10k"* presupposes that trades **under** $10k do not pause. The design
intent is explicit: **automatic execution below threshold, human review above.**

And the machinery to execute exists.
[`generated_saga_nodes.py:123`](../src/gateway/governance/generated_saga_nodes.py:123)
issues a real MCP call:

```python
_get_mcp_client().call_tool(name="execute_trade_action", ...)
```

with WAL-style PENDING → COMPLETED ledger writes and an idempotent compensating
node. Nobody builds a saga rollback for an action that never fires.

**Conclusion: CAGE was designed to execute trades automatically under
governance. Your premise is the project's premise.**

---

## 2. Three documents, three different products

| Source | Claim |
|---|---|
| [`CAGE_ONE_PAGER.md:28`](../docs/project/CAGE_ONE_PAGER.md:28) | Pauses **only** above $10k / risk 0.7 → **automatic below** |
| [`HUMAN_OVERSIGHT_SCOPE.md:28`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:28) | Escalates when amount **> $10,000** → **automatic below** |
| [`AGENTIC_SCOPE_STATEMENT.md:20`](../docs/governance/AGENTIC_SCOPE_STATEMENT.md:20) | Execute trades: ⛔ **NOT authorized — advisory only** |
| **Running code** | Every `execute_trade` → `REQUIRE_APPROVAL`, no exceptions |

Two documents describe a graduated auto-trader. One describes an advisory-only
system. The code implements a third thing: a trader that always asks permission.

My previous analysis cited `AGENTIC_SCOPE_STATEMENT.md` as authoritative and
concluded the behaviour was correct-by-design. **That was too quick.** Weighing
the one-pager, the oversight doc, the OPA thresholds, and the saga execution
machinery together, the advisory-only line is the outlier — it reads as a
narrowing that was written for a compliance audience and never reconciled with
the rest of the system.

---

## 3. Should FTRA be removed? No — and the reason is precise

FTRA is the only control that reasons over the **whole plan graph before step 1
executes**. Every other tier evaluates a single tool call in isolation. Remove
it and this becomes admissible:

```
step1: check_balance      →  step2: transfer_funds  →  step3: execute_trade
```

Each step passes its own gate; the composition is never assessed. FTRA exists
because per-call authorisation cannot see trajectories. That is the *"vetted
beforehand"* half of your premise, and it is the project's most defensible
technical contribution — the thing an external reviewer engaged with in
[issue #107](https://github.com/google/cybernetic-agent-governance-engine/issues/107).

Removing FTRA to regain autonomy would be discarding the mechanism that makes
autonomy *safe* in order to obtain autonomy. It also throws away the completed
PR #1 and the near-complete PR #2.

**The problem is not that FTRA vets trajectories. It is that its verdict
function is binary where the rest of the system is graduated.**

---

## 4. The actual defect — one line

```json
{ "terminals": { "execute_trade": "IRREVERSIBLE_TERMINAL" } }
```

Every other governance tier in CAGE is **magnitude-aware**: OPA bands by amount,
consensus triggers at $10k, CBF checks against balance, FiscalLimitGuard against
a daily cap. FTRA alone is **magnitude-blind** — reversibility is treated as a
property of the verb.

For most verbs that is correct. `write_db` is irreversible at any size. But a
trade's *consequence* scales with notional value, and CAGE's every other control
already knows this. FTRA is the one place where that knowledge was dropped.

The result: FTRA's Priority 0 gate fires before the amount is ever read, so the
$10k consensus threshold, the $5k junior RBAC allowance, and the three-zone
confidence model are all correct code and all unreachable policy.

---

## 5. The fix

**Split the action; keep the registry static.**

```json
{
  "terminals": {
    "execute_trade_bounded":   "REVERSIBLE",
    "execute_trade":           "IRREVERSIBLE_TERMINAL",
    "write_db":                "IRREVERSIBLE_TERMINAL"
  }
}
```

- Planner emits `execute_trade_bounded` for amounts below the autonomy threshold.
- FTRA classifies it `REVERSIBLE` → `CLEAR` → the remaining seven tiers run
  normally: STPA, confidence, OPA RBAC, CBF, fiscal, consensus, causal.
- Above threshold, or on any mismatch, the plain `execute_trade` path yields
  `REQUIRE_APPROVAL` exactly as today.

### Why not make the registry amount-conditional?

Because **PR #2 signs the registry**. A registry whose meaning varies with
attacker-controlled request parameters cannot be cryptographically sealed the
way [`plans/issue_107_pr2_registry_signing_plan.md`](issue_107_pr2_registry_signing_plan.md)
assumes — the artefact stops being static content and becomes a policy engine.
The action-split keeps the signed artefact fixed and puts the magnitude decision
in OPA, which is designed for exactly that and is already evaluated on the path.

### The load-bearing detail

**A verb the planner chooses is a verb an attacker can choose.** The split is
worthless unless something independently verifies that
`execute_trade_bounded` really carries a sub-threshold amount. That check must
live in a tier the plan cannot influence — an OPA rule that denies
`execute_trade_bounded` when `amount > threshold`, evaluated server-side against
the actual payload.

Without that, the "fix" is a bypass with extra steps. This is the same failure
mode as the D1 version-downgrade defect in PR #2: untrusted input selecting its
own validation path.

---

## 6. On renaming

Renaming to *"governed financial trader"* would be honest **if** the graduated
model is restored — the system would then do what the name says.

Renaming without the fix changes nothing about the behaviour and makes the
advisory-only line in the scope statement read as a retreat rather than a
decision.

**Recommendation: fix first, then decide the name.** The name follows the
behaviour, not the reverse.

---

## 7. Recommended sequence

1. **Settle the intent.** One sentence, one owner: *is sub-threshold autonomous
   execution in scope?* Everything below depends on the answer, and three
   documents currently answer differently.
2. **If yes:** implement the action-split with the server-side OPA amount check
   (§5). Reconcile all three documents to match.
3. **If no:** delete the graduated language from the one-pager and
   `HUMAN_OVERSIGHT_SCOPE.md`, remove or clearly mark the unreachable OPA RBAC
   bands, and state the ceiling plainly. This is defensible — but say it once,
   everywhere.
4. **Either way:** resolve the FTRA defer deadlock
   ([analysis §0.2](ftra_autonomy_ceiling_analysis.md)) — tokens documented as
   unreleasable by a reviewer yet assigned a quorum of 3.
5. **Either way:** fix the `bypassed_ftra_node` heuristic that fires on 100% of
   trades ([analysis §3](ftra_autonomy_ceiling_analysis.md)).

Do not remove FTRA. Do not rename yet. Fix the classification granularity, and
make the documents agree.
