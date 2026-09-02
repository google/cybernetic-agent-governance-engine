# FTRA and the Autonomy Ceiling — Analysis

> Assessment of the claim: *"FTRA implies no trade can happen autonomously
> without HITL approval first."*
>
> **Verdict: the conclusion holds. Four mechanism claims are wrong, and there is
> a larger finding immediately adjacent that the original analysis missed.**

---

## 0. Does this defeat CAGE's purpose? — No, but two documents are in conflict

The follow-up objection was: *"the objective of governed-financial-advisor is to
make safe automatic trades; if FTRA forces every trade to be manual, the system
defeats itself."*

**The premise is incorrect, and the authoritative document says so explicitly.**
[`AGENTIC_SCOPE_STATEMENT.md §1`](../docs/governance/AGENTIC_SCOPE_STATEMENT.md:20):

| Action | Authorization |
|---|---|
| Execute trades | ⛔ **NOT authorized** — *"No direct trade execution; advisory only"* |
| Transfer funds | ⛔ **NOT authorized** |
| Read market data, generate advisory text, query portfolio | ✅ Authorized |

Autonomous trade execution is **outside CAGE's authorized action space by
design**. The product is a *governed advisor*, not an autonomous trader. FTRA
blocking `execute_trade` from reaching `ALLOW` is therefore the system
**working as specified** — the demonstration is that an irreversible action
cannot slip through, which is the entire thesis.

So FTRA does not defeat the purpose. But the objection is not baseless, because
**two governance documents contradict each other.**

### 0.1 The contradiction

[`HUMAN_OVERSIGHT_SCOPE.md`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:24)
describes a **graduated, amount-conditional** escalation model:

> | Trigger | Threshold |
> |---|---|
> | Consensus threshold exceeded | Trade amount **> $10,000 USD** |
> | Model confidence low | Confidence **< 0.95** |

A threshold of "> $10,000" only means something if amounts **≤ $10,000 behave
differently**. The same graduated model appears in
[`AGENTIC_SCOPE_STATEMENT.md §2.1`](../docs/governance/AGENTIC_SCOPE_STATEMENT.md:48)
and is implemented in the OPA RBAC rules
([`rbac_allow_junior_trade`](../config/opa/generated_stpa_policy.rego:97),
`amount <= 5000`).

**In the running system that gradation is unreachable.** FTRA's Priority 0
boundary gate escalates every `execute_trade` before the amount is ever
consulted. The $10 000 consensus threshold, the $5 000 junior RBAC allowance,
and the three-zone confidence model are all correct as *code* and all
unreachable as *policy* for this action.

That is the real defect the objection is pointing at — not "FTRA defeats CAGE",
but **"CAGE's own documents promise a graduated model its architecture cannot
deliver."** An auditor reading `HUMAN_OVERSIGHT_SCOPE.md` would expect
sub-$10 000 trades to proceed without human review. They do not.

### 0.2 A harder problem: the deadlock

[`HUMAN_OVERSIGHT_SCOPE.md:222`](../docs/governance/HUMAN_OVERSIGHT_SCOPE.md:222)
lists, under *"Human oversight is **out of scope** for"*:

> `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` parked tokens — FTRA terminal-state
> tokens **cannot be released by a HITL reviewer**

Read alongside the FTRA gate, this composes badly:

1. Every `execute_trade` is escalated for human review by FTRA.
2. FTRA-parked tokens **cannot be released by a human reviewer**.

If both statements held on the same path, trades would be not merely manual but
**unresolvable** — parked forever, with the escape hatch explicitly closed.

The saving detail is the correction in §2.1 below: the mandatory boundary gate
returns `REQUIRE_APPROVAL`, which does **not** touch the DeferQueue. Only the
in-graph `ftra_node` produces `FTRA_IRREVERSIBLE_TERMINAL` tokens, and that node
is opt-in wiring. So the deadlock is **latent, not active** — it is armed for any
adopter who wires the in-graph node as the documentation encourages.

Note also that [`defer_queue.py:252`](../src/gateway/governance/defer_queue.py:252)
assigns `FTRA_IRREVERSIBLE_TERMINAL` a **quorum of 3**, which implies these
tokens *are* meant to be resolvable — by three reviewers. That directly
contradicts *"cannot be released by a HITL reviewer."* One of the two is wrong,
and until it is settled nobody can say what happens to a parked trade.

### 0.3 What to fix

The objection should be reframed and actioned as three items:

1. **Reconcile the documents.** Either `HUMAN_OVERSIGHT_SCOPE.md`'s graduated
   thresholds are aspirational for `execute_trade` and must say so, or the
   architecture must deliver them (§4, option B). Right now the docs overstate
   the system's autonomy.
2. **Resolve the quorum-vs-unreleasable contradiction** in the FTRA defer path
   before any adopter wires the in-graph node.
3. **State the ceiling plainly** wherever `rbac_allow_junior_trade` is
   documented — it currently reads as an active autonomy grant and is not one.

None of this requires abandoning FTRA. It requires the documentation to describe
the system that exists.

---

## 1. What is correct

**No `execute_trade` can reach `ALLOW` autonomously.** Confirmed by reading the
path end to end:

1. [`terminal_registry.json`](../config/ftra/terminal_registry.json) maps
   `execute_trade → IRREVERSIBLE_TERMINAL`. The mapping is action-name keyed
   with no parameter dimension — it is payload-agnostic *by construction*, not
   by oversight.
2. [`_run_checks()`](../src/gateway/governance/symbolic_governor.py:1298) runs
   the FTRA boundary gate at step **-1**, before every other tier. The comment
   is explicit: *"This check is MANDATORY — there is no flag to disable it."*
3. [`from_classification()`](../src/gateway/governance/ftra/models.py:359) sets
   `requires_hitl=True` for `IRREVERSIBLE_TERMINAL`, appending a violation
   string to the pipeline.
4. [`_classify_violation()`](../src/gateway/governance/symbolic_governor.py:471)
   gives that violation **Priority 0** — above OPA `MANUAL_REVIEW`, above
   everything.

The seal is never issued. The business intent *"junior traders may execute
below $5 000 autonomously"* is not achievable in the current architecture. That
part of the analysis is right and worth acting on.

---

## 2. Four corrections

### 2.1 It is `REQUIRE_APPROVAL`, not the DeferQueue

The analysis says the plan is *"parked in DeferQueue pending human approval."*
It is not. [Line 471](../src/gateway/governance/symbolic_governor.py:471)
returns `GovernanceDecision.REQUIRE_APPROVAL`, which yields HTTP 202 with no
seal and no queue entry.

`DEFER` is a **different verdict** reached at
[Priority 5](../src/gateway/governance/symbolic_governor.py:640), for soft
violations under confidence starvation, and *that* path calls
`_park_defer_context()`.

The distinction is operationally load-bearing: `DEFER` is designed for automated
data-hydration and retry; `REQUIRE_APPROVAL` waits on a human. Conflating them
would send someone looking for stalled trades in the wrong queue.

### 2.2 OPA is not dead code — only its *allow* path is neutralised

"Effectively dead code" overstates it. Tracing the control flow:

- FTRA appends its violation at
  [line 1316](../src/gateway/governance/symbolic_governor.py:1316).
- The Phase 1.1 OPA block at
  [line 1499](../src/gateway/governance/symbolic_governor.py:1499) is guarded by
  `and not violations`, so it is skipped.
- But the `else` branch at
  [line 1561](../src/gateway/governance/symbolic_governor.py:1561) — labelled
  *"Non-trade actions"* — **still runs OPA**, because the guard failed for the
  violation reason rather than the action-type reason.

So OPA evaluates regardless. If it returns `DENY`, that becomes a hard violation
and the verdict escalates `REQUIRE_APPROVAL → DENY`
([Priority 2](../src/gateway/governance/symbolic_governor.py:501)).

**OPA remains fully live as a deny gate. What it cannot do is grant autonomy.**
`rbac_allow_junior_trade` cannot lift the FTRA floor; it can only decline to add
a further violation. That is a materially different statement from "dead code",
and it matters for anyone reasoning about defence in depth.

Incidentally, that mislabelled `else` branch is a latent maintenance hazard: it
is documented as the non-trade path but is in fact also the
*trade-with-existing-violations* path.

### 2.3 Two different FTRA paths were conflated

The analysis merges two mechanisms with different semantics:

| | In-graph `ftra_node` | Boundary gate |
|---|---|---|
| Entry | [`PlanGraphAnalyzer.analyze()`](../src/gateway/governance/ftra/graph_analyzer.py:90) | [`_ftra_boundary_check()`](../src/gateway/governance/symbolic_governor.py:1113) |
| Scope | Whole `ExecutionPlan`, DFS reachability | Single action name |
| Confidence gate | **Yes** — `HITL_REQUIRED` vs `BLOCKED` at 0.70 | **No** — classification only |
| Verdict | `FTRAVerdict.HITL_REQUIRED` | `GovernanceDecision.REQUIRE_APPROVAL` |
| Wiring | Host must add it to their LangGraph | Mandatory, unconditional |

The `confidence ≥ 0.70 → HITL / < 0.70 → BLOCKED` split described in the
analysis exists **only in the in-graph analyzer**. The boundary gate — the one
that is actually mandatory — ignores confidence entirely.

### 2.4 "Tier 0.5 supersedes Phase 3 execution" is not the right frame

Both checks are pre-execution and live in the **same `_run_checks()` call**.
FTRA is at step -1, OPA at Phase 1.1. Nothing is being superseded across an
execution boundary; FTRA simply populates `violations` before OPA is consulted,
and Priority 0 outranks OPA's result during classification.

Worth noting the ordering is *beneficial* in one respect: because Phase 2
mutations are guarded by `and not violations`
([line 1714](../src/gateway/governance/symbolic_governor.py:1714)), an
FTRA-halted action never debits the CBF balance or reserves fiscal capacity. No
budget leakage.

---

## 3. The finding the analysis missed

**Every `execute_trade` request produces a WARN log claiming a possible security
bypass.** [`_ftra_boundary_check()`](../src/gateway/governance/symbolic_governor.py:1165):

```python
bypassed_ftra_node = (
    detect_bypass
    and classification == TerminalClassification.IRREVERSIBLE_TERMINAL
)
```

`detect_bypass` defaults `True` and is never overridden at the sole call site
([line 1309](../src/gateway/governance/symbolic_governor.py:1309)). The
heuristic therefore reduces to *"is this action irreversible?"* — and fires on
**100 % of trades**, including entirely normal ones that were correctly routed
through the in-graph node. The emitted warning reads:

> *"This may indicate direct HTTP bypass of in-graph ftra_node."*

Two consequences:

1. **Alert fatigue on a security signal.** A bypass warning that fires on every
   legitimate request trains operators to ignore it. The one time it means
   something, it will be indistinguishable from the noise.
2. **`bypassed_ftra_node` is not measuring what it claims.** It is emitted as
   the OTel attribute `cage.ftra.bypassed_ftra_node`
   ([line 1194](../src/gateway/governance/symbolic_governor.py:1194)), so any
   dashboard or alert built on it is measuring "action is irreversible", not
   "the graph node was bypassed".

This is the same class of defect as **D4 in PR #2** — a signal that appears
meaningful, is exercised constantly, and is never actually falsified. Detecting
a genuine bypass requires evidence that `ftra_node` *did not* run: a state flag
set by the node and checked at the boundary. The current heuristic cannot
distinguish the two cases even in principle.

---

## 4. Root cause and options

The registry is keyed on **action name only**:

```json
{ "terminals": { "execute_trade": "IRREVERSIBLE_TERMINAL" } }
```

Reversibility is treated as a static property of the verb. In finance it is
often a property of the **verb plus its magnitude and counterparty** — a $50
trade and a $50 M trade differ in consequence, not in reversibility mechanism,
but the governance response should differ.

| Option | Sketch | Trade-off |
|---|---|---|
| **A. Payload-conditional classification** | Registry entries gain predicates: `execute_trade` is `REVERSIBLE` below a threshold, `IRREVERSIBLE_TERMINAL` above | Most direct fit to intent. **But** it hands classification authority to attacker-controlled parameters — the registry stops being a static artefact and becomes a policy engine. Directly in tension with PR #2's signing model, which assumes fixed content |
| **B. Split the action** | `execute_trade_small` (`REVERSIBLE`) vs `execute_trade` (`IRREVERSIBLE_TERMINAL`); the amount gate lives in OPA, which already knows the thresholds | Keeps the registry static and signable. Requires the planner to choose the right verb, and something must verify the choice against the payload — otherwise the split is trivially gamed |
| **C. Accept the ceiling** | Document that all trades require human sign-off; treat it as the intended posture | Zero code change, honest. May be the correct answer for a regulated deployment, and unacceptable for a high-volume one |

**Recommendation: decide the business requirement before touching code.** If
sub-$5 000 autonomy is genuinely required, **B** is the safer construction —
it preserves the fail-closed default and the static, signable registry that PR
#2 depends on. **A** would need re-litigating the PR #2 threat model, since a
registry whose meaning varies with request content cannot be sealed the same way.

Note that **C is the current de facto state, undocumented.** Whichever option is
chosen, the ceiling should be written down: right now `rbac_allow_junior_trade`
reads as an active autonomy grant, and it is not one.

---

## 5. Suggested immediate action

Independent of the strategic choice, the §3 heuristic should be fixed or
removed. A permanently-firing bypass warning is worse than no warning, and it is
cheap to correct relative to the classification redesign.
