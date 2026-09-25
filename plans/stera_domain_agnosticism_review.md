# STERA Pipeline — Domain-Agnosticism Review (Layer 1 Kernel)

**Scope:** `src/gateway/governance/**`, the STERA admissibility engine and the engines it hosts.
**Baseline:** HEAD `2618ab2` (`refactor/symbolic-governor`). The `governor/` package from PRs 1–3 isn't in the tree yet, so every finding refers to `symbolic_governor.py` as it stands.
**Method:** I grepped for domain vocabulary, then read each call site to decide whether it changes behaviour or is only prose.
**Cross-reference:** [governor_refactor_plan_pr4_5.md §4.4](../plans/governor_refactor_plan_pr4_5.md) already covers 4 items (P5). Items marked **NEW** are not in that plan.

> [!IMPORTANT]
> Kernel purity is more than cosmetic here. Several "generic" engines (CBF, consensus, causal) are **behaviourally finance-bound**. When a non-finance plugin reuses them (healthcare already does, for CBF and consensus), it silently gets finance semantics. Some of these paths **fail open**.

---

## A. Behavioural leaks: wrong semantics for non-finance domains

| # | Finding | Evidence | Impact | Plan? |
|---|---|---|---|---|
| A1 | **The CBF ignores the invariant's threshold.** `min_cash_balance` is always set from `THRESHOLDS.cbf.min_cash_balance`, and `resolved_threshold` prefers it unconditionally, so `InvariantModel.threshold_key` is never used. `get_h()` is hard-wired to cash. | [cbf_engine.py:415](../src/gateway/governance/safety/cbf_engine.py#L415), [L1199-1201](../src/gateway/governance/safety/cbf_engine.py#L1199-L1201), [L1745-1756](../src/gateway/governance/safety/cbf_engine.py#L1745-L1756) | Healthcare's `DoseBarrier` (`healthcare.min_therapeutic_concentration`, [invariants.py:33](../src/cage_healthcare/invariants.py#L33)) is enforced against the **cash floor**. | **NEW** |
| A2 | **CBF ground truth is always the cash ledger.** `_read_cbf_state_atomic()` and `_resolve_ground_truth_balance()` read the global `reconciliation:verified_balance` (USD) no matter what `state_key` is. The fallbacks seed or default to `100000.0`. | [L821-1127](../src/gateway/governance/safety/cbf_engine.py#L821-L1127), [L1129-1192](../src/gateway/governance/safety/cbf_engine.py#L1129-L1192), [L545](../src/gateway/governance/safety/cbf_engine.py#L545), [L557](../src/gateway/governance/safety/cbf_engine.py#L557) | When reconciliation is live, a serum-concentration barrier is evaluated against a **USD balance**. | **NEW** |
| A3 | **The generic barrier contains a drawdown check.** `verify_action()` applies `THRESHOLDS.drawdown.limit` whenever the payload has `drawdown_pct`. | [L1414-1421](../src/gateway/governance/safety/cbf_engine.py#L1414-L1421) | A finance rule runs inside every CBF instance. It should be a finance tier or UCA. | **NEW** |
| A4 | **The consensus prompt is always the finance one.** `_CRITICS_CONFIG` is declared `{}` and never loaded, so the hardcoded fallback always runs: "financial institution… trade proposal… Standard equity purchase". The engine extracts `amount` and `symbol` and gates on `threshold_usd`. | [consensus/engine.py:68](../src/gateway/governance/consensus/engine.py#L68), [L255-295](../src/gateway/governance/consensus/engine.py#L255-L295), [L401-413](../src/gateway/governance/consensus/engine.py#L401-L413) | Healthcare registers `ConsensusGate` ([cage_healthcare/\_\_init\_\_.py:20](../src/cage_healthcare/__init__.py#L20)), so its critic LLMs review clinical actions as equity trades. `critics.yaml` in `cage_finance/config/` is dead config. | **NEW** |
| A5 | **The causal tier fails open for domains without an `amount` field.** `amount <= 0 → return True`. The cache key uses `market_regime`. | [causal/gatekeeper.py:582-599](../src/gateway/governance/causal/gatekeeper.py#L582-L599) | Any non-finance action passes Tier 6 **without evaluation**. That's a fail-open path that no test observes. | **NEW** |
| A6 | **Hidden Layer 1 → Layer 2 dependency by filesystem path.** The causal gatekeeper opens `src/cage_finance/config/causal_graph.yaml` directly, and falls back to a hardcoded `market_volatility → trade_amount` graph. | [gatekeeper.py:70-82](../src/gateway/governance/causal/gatekeeper.py#L70-L82), [L602-617](../src/gateway/governance/causal/gatekeeper.py#L602-L617) | Gate G3 doesn't see it, because it isn't an `import`. | **NEW** |
| A7 | **Narrowing is finance-shaped.** It clamps `params["amount"]` (default `max_amount=100000.0`) and classifies narrowable violations by the substring `"amount exceeds"`. | [symbolic_governor.py:742-800](../src/gateway/governance/symbolic_governor.py#L742-L800), [L414-419](../src/gateway/governance/symbolic_governor.py#L414-L419) | Only partly covered. The plan's `Narrower` row only addresses "future" narrowers, not this existing one. | Partial |
| A8 | STPA UCA rules with `execute_trade` literals | [generated_stpa_validator.py:97-170](../src/gateway/governance/generated_stpa_validator.py#L97-L170) | | ✅ P5 |
| A9 | `PauseReceipt.standing_at_pause` with `symbol`/`amount` | [symbolic_governor.py:2638-2642](../src/gateway/governance/symbolic_governor.py#L2638-L2642) | | ✅ P5 |
| A10 | The message "Trade execution at confidence…" | [symbolic_governor.py:1500](../src/gateway/governance/symbolic_governor.py#L1500) | | ✅ P5 |
| A11 | `_legacy_finance_cost_resolver` | [cbf_engine.py:409](../src/gateway/governance/safety/cbf_engine.py#L409), [L1221-1255](../src/gateway/governance/safety/cbf_engine.py#L1221-L1255) | | ✅ P5 |

---

## B. Structural leaks: domain modules and config hosted in Layer 1

| # | Finding | Evidence | Recommendation | Plan? |
|---|---|---|---|---|
| B1 | **The threshold schema is closed and holds domain sections.** `GovernanceThresholds` requires `drawdown`, `stpa.uca5_drawdown…`/`uca6_max_order_volume…`/`max_sell_portfolio_fraction`, `consensus.threshold_usd`, `confidence.min_trade_confidence` and `cbf.min_cash_balance`. It also has a `healthcare` section. | [schemas/thresholds.py:87-359](../src/gateway/governance/schemas/thresholds.py#L87-L359) | The kernel schema keeps only core sections (FRIA, causal statistics, telemetry, KMS, confidence). Domain sections become namespaced plugin contributions validated at `assemble_governor`. | **NEW** |
| B2 | **`FiscalLimitGuard` lives in the kernel.** It uses USD/cents, `fiscal:*` keys and `FISCAL_DAILY_CAP_USD`. The governor carries a `fiscal_limit_guard` arg and classifies violations by the string `"Fiscal Limit Pre-Reservation REJECTED"`. | [safety/resource_guard.py](../src/gateway/governance/safety/resource_guard.py), [symbolic_governor.py:391](../src/gateway/governance/symbolic_governor.py#L391), [L838-853](../src/gateway/governance/symbolic_governor.py#L838-L853) | Either move it to `cage_finance/safety/`, or turn it into a generic `QuotaReservationGuard(unit, key_prefix, cap)` with finance configuring it. The PR 4.3 arg removal is partial overlap. | Partial |
| B3 | **The reconciliation daemon is a finance and vendor module.** It contains `LedgerProvider`, `balance_usd`, and the `PlaidLedgerProvider`/`AnchorageGrpcLedgerProvider` classes. | [reconciliation/daemon.py:148-1300](../src/gateway/governance/reconciliation/daemon.py#L148-L1300) | This also breaks "vendor-neutral" and "Generic in Code, Specific in Prose". The kernel should keep a generic `GroundTruthProvider → (state_key, value, signature, seq)`. Delete the commercial providers, since CAGE is a reference architecture and isn't deployed. Replace them with per-domain simulated providers that exercise every fail-closed path. This fixes A2. | **NEW** |
| B4 | **The STPA compiler emits finance Rego and saga code into the kernel.** It generates RBAC rules on `execute_trade`/`trader_role`/`currency`/`trade_limits`, a terminal registry hardcoded to `"domain": "finance"`, and `generated_saga_nodes.py` (`execute_trade`/`reverse_trade`). Its single input is the root [`config/stpa_control_structure.yaml`](../config/stpa_control_structure.yaml). | [stpa_compiler.py:660-695](../src/gateway/governance/stpa_compiler.py#L660-L695), [L1438-1460](../src/gateway/governance/stpa_compiler.py#L1438-L1460), [L1547](../src/gateway/governance/stpa_compiler.py#L1547), [generated_saga_nodes.py](../src/gateway/governance/generated_saga_nodes.py) | The plan only moves UCA rules. Extend it so the compiler takes `--domain` and `--spec`, and emits validator rules, saga nodes, Rego and the terminal registry into `src/cage_{domain}/`. RBAC field names come from the spec. | Partial |
| B5 | **`TradingKnowledgeGraph` is in the kernel.** It holds financial UCAs and appears unused in `src/`. It's referenced only in tests, comments and `compliance_bridge` docs. | [ontology.py:51-207](../src/gateway/governance/ontology.py#L51-L207) | Delete it, or move it to `cage_finance/`. | **NEW** |
| B6 | **FTRA `BoundingContract` uses a finance schema.** Its fields are instruments, venues and counterparties (e.g. NYSE/AAPL). | [ftra/bounding_contract.py:18-100](../src/gateway/governance/ftra/bounding_contract.py#L18-L100) | Generalise it to `allowlists: Mapping[param_name, frozenset]`, with finance supplying `instrument`, `venue` and `counterparty`. | **NEW** |
| B7 | **The LangGraph harness hardcodes finance params.** The NeMo fallback extracts `amount, symbol, drawdown_pct, order_size, daily_vol…`. The OPA node's span keys are `trader_role` and `amount`. The default router target is `"governed_trader"`, which contradicts the rule in [seams/graph_topology.py:24](../src/gateway/governance/seams/graph_topology.py#L24). | [nemo_node_factory.py:385-400](../src/gateway/governance/langgraph_harness/nemo_node_factory.py#L385-L400), [opa_node_factory.py:138](../src/gateway/governance/langgraph_harness/opa_node_factory.py#L138), [L262](../src/gateway/governance/langgraph_harness/opa_node_factory.py#L262) | Make these required config args (a `payload_extractor` already exists), with no finance defaults. [inference_proxy.py:352+](../src/gateway/server/inference_proxy.py#L352) has the same pattern. | **NEW** |
| B8 | **Claim detectors only know financial verbs.** Their regexes match `execute\|buy\|sell\|trade\|transfer`, so clinical or physical verbs (`administer`, `prescribe`, `actuate`) aren't covered. | [authorization_claim_detector.py:164-226](../src/gateway/governance/authorization_claim_detector.py#L164-L226), [confidence_claim_detector.py:69-72](../src/gateway/governance/confidence_claim_detector.py#L69-L72) | Keep a generic core lexicon and let domains contribute execution verbs. | **NEW** |
| B9 | **`HitlEscalator` is framed in `amount_usd`.** It uses a USD 10,000 consensus threshold. | [hitl_escalator.py:126-262](../src/gateway/governance/hitl_escalator.py#L126-L262) | Rename to `magnitude` and take the threshold from the domain. | **NEW** |
| B10 | **The AAIF adapter points at a Layer 2 module by string.** The tier map says `"module": "src.cage_finance.consensus.consensus"`. | [ingress/aaif_adapter.py:96](../src/gateway/governance/ingress/aaif_adapter.py#L96) | Point it at the kernel engine path. | **NEW** |
| B11 | **Legacy finance shims remain.** There's a `(action, amount, symbol)` consensus adapter and the `FiscalGuard = ResourceGuard` alias. | [contracts.py:499-524](../src/gateway/governance/contracts.py#L499-L524), [L672](../src/gateway/governance/contracts.py#L672) | Delete them; AGENTS.md allows the breaking change. | **NEW** |

---

## C. Vocabulary only (low priority, no behaviour change)

`execute_trade` / `"symbol": "AAPL"` appears in examples, docstrings and comments in these files:
- [routing_seal.py](../src/gateway/governance/routing_seal.py)
- [governance_envelope.py](../src/gateway/governance/governance_envelope.py) (also `HIGH_FINANCIAL`)
- [ftra/models.py](../src/gateway/governance/ftra/models.py)
- [ftra/classifier.py](../src/gateway/governance/ftra/classifier.py)
- [execution_actuator.py](../src/gateway/governance/execution_actuator.py)
- [decisions.py](../src/gateway/governance/decisions.py)
- [defer_queue.py:1238](../src/gateway/governance/defer_queue.py#L1238)
- [confabulation_scorer.py](../src/gateway/governance/confabulation_scorer.py)
- [token_quota_proxy.py](../src/gateway/governance/token_quota_proxy.py)
- the governor's own comments (≈40 uses of "trade" or "balance")

Replace them with neutral examples (`"example.irreversible_action"`). Otherwise the proposed G3 literal check (plan §4.4) will flag docstrings, unless it deliberately scans only code tokens.

---

## D. Suggested additions to PR 4 (§4.4 / §4.5)

1. **Make CBF genuinely invariant-parametric (A1–A3, B3).**
   - Delete `min_cash_balance`, `get_h(cash)` and the drawdown branch.
   - Compute `h = state[invariant.state_key] − threshold(invariant.threshold_key)`.
   - Ground truth comes from a per-invariant `GroundTruthProvider`, and is optional per invariant.
   - Test: a healthcare barrier with live cash reconciliation must use serum state and the healthcare threshold.
2. **Make consensus prompt-agnostic (A4).**
   - `ConsensusGate(critics: Sequence[CriticSpec], context_renderer: Callable)` becomes a **required** constructor argument.
   - Delete the hardcoded prompt.
   - Finance loads `critics.yaml`; healthcare supplies its own.
3. **Make the causal tier domain-injected (A5, A6).**
   - `CausalGatekeeper(graph, treatment, outcome, treatment_extractor, regime_key)`, passed in by the plugin.
   - No filesystem reads into `cage_*`.
   - Missing treatment → **fail closed**, with a test that watches it fail.
4. **Add a `Narrower` seam for the existing amount clamp (A7).** Move it to `cage_finance/narrowing.py` and classify by `ViolationKind`, not by substring.
5. **Open the threshold schema (B1).** Replace it with namespaced plugin threshold contributions.
6. **Make the STPA compiler per domain (B4).** It emits validator rules, saga nodes, Rego and the terminal registry into `src/cage_{domain}/`.
7. **Extend Gate G3:**
   - fail on `Path(...)` / string references to `cage_` inside `src/gateway/` (catches A6 and B10);
   - add a literal check that covers param keys (`"amount"`, `"symbol"`, `"drawdown"`), not just action names.
8. **Delete or move the remaining leftovers:** B5, B6, B9, B11.
9. **Update the acceptance grep** so it returns zero hits in `src/gateway/` code:
   ```bash
   grep -rnE '"(execute_trade|amount|symbol|drawdown(_pct)?|trader_role|market_regime)"|cage_finance|balance_usd|_usd\b' src/gateway --include='*.py'
   ```

> [!NOTE]
> Compliance knock-on: fixing A1, A2 and A5 changes the enforced behaviour of CBF and the causal tier. That affects OSCAL implementation statements, and POAM-023 is framed around cash reconciliation. So the §5.3 OSCAL and POAM updates need to cover these as well.
