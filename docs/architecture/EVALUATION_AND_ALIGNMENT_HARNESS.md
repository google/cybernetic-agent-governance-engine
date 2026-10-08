# Foundation Model Evaluation & Alignment Harness (RLVR / DPO / GRPO)

**Module:** [`src/gateway/governance/eval_harness.py`](../../src/gateway/governance/eval_harness.py)  
**Test Suite:** [`tests/unit/governance/test_eval_harness.py`](../../tests/unit/governance/test_eval_harness.py)  
**Layer:** Layer 1 (Domain-Neutral Governance Kernel)

---

## 1. Executive Summary: The Dual-Lifecycle Flywheel

Enterprise AI platforms and foundation model teams traditionally separate **offline model evaluation** (benchmarks, LLM-as-a-judge scripts, red-teaming) from **online runtime safety** (firewalls, RBAC, API gateways). This separation introduces two structural failure modes:

1. **Stochastic Blindness in Judge LLMs:** Evaluating foundation model tool trajectories with another probabilistic LLM suffers from shared cognitive biases, prompt injection susceptibility, and reward hacking.
2. **Eval-Prod Drift:** Aligning a model offline against synthetic heuristics that differ from production database invariants guarantees edge-case failures in live deployment.

CAGE eliminates both failure modes by operating as an **isomorphic Dual-Lifecycle Substrate**. The exact same [`SymbolicGovernor`](../../src/gateway/governance/governor/governor.py) pipeline, discrete-time Control Barrier Functions ([`cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py)), Fault-Tree Reachability Analyzer ([`PlanGraphAnalyzer`](../../src/gateway/governance/ftra/graph_analyzer.py)), and DoWhy causal refutation engine ([`gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)) execute in two modes:

```text
      PRE-DEPLOYMENT EVALUATION & POST-TRAINING                 LIVE ENTERPRISE RUNTIME
   ┌──────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
   │ CAGE Evaluation Harness (Profile.DRY_RUN)    │        │ CAGE Substrate Governor (Profile.FULL) │
   │ • FoundationModelEvalHarness (PRM Scoring)   │        │ • Linkerd mTLS + Single-Use JWS Seals  │
   │ • FTRA DAG & CBF Barrier Preview (Zero-Harm) │───────▶│ • 5-State Engine (ALLOW/NARROW/DEFER…) │
   │ • Counterfactual DPO Triplets via NARROW     │ Shared │ • Atomic Redis Lua CBFs & LIFO Undo    │
   └──────────────────────────────────────────────┘ Formal └────────────────────────────────────────┘
                          ▲                        Barriers                     │
                          │                                                     │
                          └─────────── Continuous Alignment Flywheel ───────────┘
                              (Live RefusalReceipts & NarrowReceipts → TRL JSONL)
```

---

## 2. Mathematical Formulation

### 2.1 Deterministic Process Reward Model (PRM / RLVR)

Rather than scoring only terminal outcomes, `FoundationModelEvalHarness.evaluate_trajectory()` evaluates each intermediate step $t \in \{1 \dots T\}$ of a proposed multi-turn trajectory via [`SymbolicGovernor.validate_action()`](../../src/gateway/governance/governor/governor.py) under `Profile.DRY_RUN`.

Each step is checked against the discrete-time Control Barrier Function condition:

$$h(S_{t+1}) \ge (1 - \gamma) \cdot h(S_t), \quad \gamma \in (0, 1]$$

and maps the canonical five-state [`GovernanceDecision`](../../src/gateway/governance/decisions.py) into a dense, verifiable step reward $r_t$:

| Verdict (`GovernanceDecision`) | Step Admissibility | Process Reward ($r_t$) | Alignment Role |
| :--- | :--- | :--- | :--- |
| `ALLOW` | Admissible ($u_t \in \mathcal{C}(S_t)$) | $+1.0$ | Positive trajectory exemplar |
| `NARROW` | Admissible after projection ($\Pi_{\mathcal{C}}(u_t)$) | $+0.5$ | Emits exact counterfactual DPO pair $(y_w, y_l)$ |
| `REQUIRE_APPROVAL` | Out-of-envelope (`ViolationKind.HITL`) | $-0.5$ | Boundary escalation signal |
| `DEFER` | Context starvation (`ViolationKind.DEFERRABLE`) | $-0.5$ | Epistemic uncertainty signal |
| `DENY` | Hard invariant violation (`ViolationKind.HARD`) | $-1.0$ | Hard negative exemplar ($y_l$) |

### 2.2 Counterfactual DPO Synthesis Without Rejection Sampling

Standard Direct Preference Optimization (DPO) and Group Relative Policy Optimization (GRPO) require sampling $K$ completions per prompt and hoping at least one clears the safety boundary ($y_w$) while another fails ($y_l$).

When a foundation model proposes a tool call $y_l = (a_t, u_t)$ that violates a narrowable constraint (`ViolationKind.NARROWABLE`), CAGE's [`NarrowerRegistry`](../../src/gateway/governance/narrower.py) deterministically computes the clamped parameter vector $u_t^* = \Pi_{\mathcal{C}}(u_t)$ and re-verifies under `Profile.DRY_RUN` ([`SymbolicGovernor._narrow_candidate()`](../../src/gateway/governance/governor/governor.py)) that $y_w = (a_t, u_t^*)$ yields zero violations across all governance stages.

This produces a minimal-edit contrastive preference triplet from a **single rollout**:

$$\tau_{\text{DPO}} = \bigl(x, \; s_t, \; y_w = (a_t, \Pi_{\mathcal{C}}(u_t)), \; y_l = (a_t, u_t)\bigr)$$

### 2.3 Stateful Multi-Turn Shadow-State Tracking

Stateless dry-run checks miss cumulative horizon violations (e.g., two sequential transfers that individually pass a \$100k barrier but cumulatively deplete a \$100k budget). `FoundationModelEvalHarness.evaluate_trajectory()` accepts an `initial_shadow_state` and a `ShadowStateReducer` callback (`state_reducer`), maintaining an isolated in-memory state trajectory $\hat{S}_0 \to \hat{S}_1 \to \dots \to \hat{S}_T$ across turns without mutating Redis or external ledgers.

### 2.4 Closing the Runtime-to-Alignment Loop (`harvest_refusal_receipts`)

In production (`Profile.FULL`), rejected actions emit a cryptographically hashed [`RefusalReceipt`](../../src/gateway/governance/contracts.py) containing `attempted_params` and `standing_snapshot`. `FoundationModelEvalHarness.harvest_refusal_receipts()` replays these production refusal receipts through the narrower pipeline under `Profile.DRY_RUN` and exports PII-scrubbed JSONL datasets via [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py) (`export_hf_trl_jsonl(sanitize_pii=True)`), turning live operational blocks into continuous post-training alignment data.
