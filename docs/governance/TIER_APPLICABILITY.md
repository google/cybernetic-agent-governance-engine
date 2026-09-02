# Tier Applicability Matrix

> **Purpose:** a single authoritative answer to *"which governance tiers actually
> run for a given action?"*
>
> This document exists because that question previously required reading eight
> source files. See
> [`plans/enforcement_pipeline_review.md`](../../plans/enforcement_pipeline_review.md)
> for the review that produced it.

**Status:** describes the system as built. Where behaviour is surprising, it is
marked ⚠ and cross-referenced to the finding.

---

## 1. Two separate questions

Governance coverage is the composition of two independent gates. Conflating them
is the source of most confusion:

| Question | Mechanism |
|---|---|
| **Does the tier claim this action?** | `claims_action()` on the tier plugin, or an inline guard in `_run_checks()` |
| **Given it claimed, does its expensive logic run?** | Internal short-circuits — caches, availability flags, zero-amount guards |

A tier can claim an action and still perform no meaningful evaluation.

---

## 2. The matrix

For the reference financial deployment, action `execute_trade`:

| Tier | Order | Claims when | Expensive logic runs when | Amount-sensitive |
|---|---|---|---|---|
| **FTRA boundary** | −1 | **Always** — mandatory, no disable flag ([`symbolic_governor.py:1301`](../../src/gateway/governance/symbolic_governor.py:1301)) | Always | ❌ Action name only |
| **STPA / UCA** | 0 | `stpa_validator is not None` | Per-UCA condition match | Partially |
| **Confidence** | 1 | `_is_governed_action()` | Always | ❌ |
| **OPA** | 2b | **Always** — both pipeline branches ⚠ F6 | Always | ✅ RBAC bands by amount |
| **Consensus** | 5 | `action in _TRADE_ACTIONS` | Always | ✅ Inside `check_consensus()` |
| **Causal / DoWhy** | 6 | `action in _TRADE_ACTIONS` | Per-amount bucket | ✅ In risk formula |
| **CBF** | 3 (phase 2) | `action in _TRADE_ACTIONS` | Phase 1 produced zero violations | ✅ Cash balance |
| **Fiscal** | 4 (phase 2) | `action in _TRADE_ACTIONS` | Phase 1 produced zero violations | ✅ Daily cap |

---

## 3. Behaviour that surprises readers

### 3.1 Consensus runs on every trade, not only above $10 000

[`consensus_tier.py:40`](../../src/cage_finance/tiers/consensus_tier.py:40)
claims on action name with no amount test, so `check_consensus()` executes for a
$1 trade.

`consensus.threshold_usd = 10000` is **not** a gate on whether consensus runs. It
is a parameter *inside* consensus that governs how it responds, applied strictly
(`amount_usd > threshold_usd`,
[`hitl_escalator.py:261`](../../src/gateway/governance/hitl_escalator.py:261)).

### 3.2 DoWhy caches by amount bucket

`causal_safety_check()` is invoked every trade, but DoWhy is reached only past
three short-circuits
([`causal/gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)):

| Guard | Line | Effect |
|---|---|---|
| `amount <= 0` | 584 | Returns `True` — no evaluation |
| `not _DOWHY_AVAILABLE` | 588 | Fails **closed** — blocks without evaluating |
| Redis cache hit | 655 | Returns cached verdict — no DoWhy run |

The cache key is `causal_cache:{action_type}:{market_regime}:{bucket}` where
`bucket = _bucket_amount(amount)` groups trades into bands ([100, 1000, 5000,
10000, 50000]) per `causal.amount_bucket_boundaries` in
[`governance_thresholds.json`](../../config/governance_thresholds.json). This
prevents a large trade from inheriting a small-trade verdict.

### 3.3 Phase 2 tiers are conditional on Phase 1 passing

CBF and Fiscal are guarded by `and not violations`
([`symbolic_governor.py:1714`](../../src/gateway/governance/symbolic_governor.py:1714)).
This is deliberate and correct — it prevents budget leakage, since a rejected
action never debits balance or consumes fiscal capacity. But it means **a
Phase-1 rejection leaves Phase-2 tiers unevaluated**, so their absence from a
trace is not evidence they would have passed.

### 3.4 FTRA outranks everything

The boundary gate runs at step −1 and its violation is **Priority 0** in
[`_classify_violation()`](../../src/gateway/governance/symbolic_governor.py:471) —
above OPA `MANUAL_REVIEW`. Any action classified `IRREVERSIBLE_TERMINAL` or
`EXTERNALLY_REVERSIBLE` routes to `REQUIRE_APPROVAL` regardless of what later
tiers would have decided.

**Consequence:** `execute_trade` is `IRREVERSIBLE_TERMINAL` in
[`terminal_registry.json`](../../config/ftra/terminal_registry.json), so **no
trade currently reaches `ALLOW` autonomously**, and the graduated OPA RBAC bands
(`amount <= 5000` etc.) are unreachable for this action.

### 3.5 OPA runs even when FTRA has already objected

The branch at
[`symbolic_governor.py:1561`](../../src/gateway/governance/symbolic_governor.py:1561)
is commented *"Non-trade actions"*, but its guard is
`_is_governed_action(...) and not violations` — so it is **also** the
trade-with-existing-violations path ⚠ F6. OPA therefore remains a live deny gate
under FTRA escalation; what it cannot do is *grant* autonomy.

---

## 4. Adding a new governed action

Every item below is required. Omitting any one narrows governance **silently** —
no error is raised.

1. Add the UCA to the STPA source, **and** mirror it into
   [`stpa_control_structure.yaml`](../../config/stpa_control_structure.yaml) in
   **lexicographic** UCA-ID order (`UCA-1`, `UCA-10`, `UCA-11`, `UCA-2`).
2. Set `terminal_classification` — omitting it defaults to
   `IRREVERSIBLE_TERMINAL` (fail-closed, by design).
3. Add the action to `_TRADE_ACTIONS` in
   [`src/cage_finance/tiers/__init__.py`](../../src/cage_finance/tiers/__init__.py) —
   all four finance tiers import and claim this set.
4. Add NIST **and** ISO 42001 OSCAL mappings — CI enforces this
   ([`test_oscal_ssp_exporter.py`](../../tests/test_oscal_ssp_exporter.py)).
5. Regenerate all STPA artifacts (validator, rails, saga nodes, Rego, registry).
6. Update this matrix.

---

## 5. Open findings referenced here

| ID | Summary | Severity |
|---|---|---|
| F6 | `else` branch documented as "non-trade", also handles trades with violations | Low |

Full list and remediation sequence:
[`plans/enforcement_pipeline_review.md`](../../plans/enforcement_pipeline_review.md).
