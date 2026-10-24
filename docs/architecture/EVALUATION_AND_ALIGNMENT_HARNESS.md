# Foundation Model & Agent Skill Evaluation Harness (`src/eval_harness/`)

**Last Updated:** 2026-10-22  
**Package Root:** [`src/eval_harness/__init__.py`](../../src/eval_harness/__init__.py)  
**Core Modules:** [`src/eval_harness/harness.py`](../../src/eval_harness/harness.py) · [`src/eval_harness/runner.py`](../../src/eval_harness/runner.py) · [`src/eval_harness/static_linter.py`](../../src/eval_harness/static_linter.py) · [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) · [`src/eval_harness/gepa_optimizer.py`](../../src/eval_harness/gepa_optimizer.py) · [`src/eval_harness/cli.py`](../../src/eval_harness/cli.py)  
**Layer 3 GCP Eval & GEAP Plugin:** [`src/integrations/gcp_eval/`](../../src/integrations/gcp_eval/__init__.py) ([`vertex_evaluator.py`](../../src/integrations/gcp_eval/vertex_evaluator.py), [`bq_harvester.py`](../../src/integrations/gcp_eval/bq_harvester.py), [`cer_publisher.py`](../../src/integrations/gcp_eval/cer_publisher.py), [`gepa_governor.py`](../../src/integrations/gcp_eval/gepa_governor.py), [`synthetic_generator.py`](../../src/integrations/gcp_eval/synthetic_generator.py), [`pipelines.py`](../../src/integrations/gcp_eval/pipelines.py))  
**Test Suite:** [`tests/unit/governance/test_eval_harness.py`](../../tests/unit/governance/test_eval_harness.py) · [`tests/unit/governance/test_gepa_optimizer.py`](../../tests/unit/governance/test_gepa_optimizer.py) · [`tests/unit/governance/test_gcp_eval_plugin.py`](../../tests/unit/governance/test_gcp_eval_plugin.py)  
**System Plane:** Standalone Offline Evaluation & Skill Certification System (`src/eval_harness/`) — strictly decoupled from Online Enforcement (`src/gateway/`)

---

## 1. Executive Summary: Split-Plane Architecture & The Dual-Lifecycle Flywheel

Enterprise AI platforms and foundation model teams face two opposing requirements:
1. **Online Runtime Enforcement (`src/gateway/`)** must execute synchronously on the hot path in **$<10\text{ ms}$**, enforcing atomic state invariants (`FTRA`, `STPA`, `CBF`, `OPA`, `RoutingSeal`) with zero dependency on batch trajectory evaluators or dataset exporters.
2. **Offline Evaluation, Skill Certification & Post-Training Alignment (`src/eval_harness/`)** must inspect full multi-turn trajectories, orchestrate paired live rollouts (`baseline` vs. `with_skill`), score `SKILL.md` specifications, compute paired differential **Skill Lift** and tokenomics, calibrate evaluators against golden anchors, evolve native prompts / `SKILL.md` files / Presidio PII configs via **GEPA (Genetic-Pareto)** reflective optimization ([`gepa_optimizer.py`](../../src/eval_harness/gepa_optimizer.py)), and export counterfactual DPO datasets in CI or batch pipelines.

CAGE resolves this tension via a **Modular Monorepo with a Hard System Cut**:
- **Strict Non-Interference (Gate G3):** [`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py) enforces at the AST level (`OFFLINE_EVAL_PATTERN`) that `src/gateway/` **never** imports from `src/eval_harness/`. Furthermore, [`src/gateway/Dockerfile`](../../src/gateway/Dockerfile) does not copy `src/eval_harness/` into the production Gateway container.
- **Two Offline Execution Modes in [`FoundationModelEvalHarness`](../../src/eval_harness/harness.py):**
  - **Standalone Trace-Only Mode (`governor=None`):** Grades recorded or dynamically generated [`ATIFTrajectory`](../../src/eval_harness/harness.py) logs, lints `SKILL.md` files ([`lint_skill_markdown`](../../src/eval_harness/static_linter.py)), calibrates drawback detectors ([`calibrate_on_anchors`](../../src/eval_harness/harness.py)), and computes 4-bucket paired [`SkillLiftReport`](../../src/eval_harness/harness.py) with **zero** `SymbolicGovernor`, Redis, or OPA dependencies.
  - **Dry-Run Counterfactual Mode (`governor=<SymbolicGovernor>`):** Replays tool actions through [`SymbolicGovernor.validate_action()`](../../src/gateway/governance/governor/governor.py) (`Profile.DRY_RUN`) with isolated shadow-state tracking (`ShadowStateReducer`) to compute step-level Process Rewards (PRM), emit diagnostic [`ActionableSideInfo`](../../src/eval_harness/gepa_optimizer.py) (ASI) for GEPA reflective optimization, and synthesize minimal-edit counterfactual DPO pairs.

```text
      OFFLINE EVALUATION & CERTIFICATION PLANE                ONLINE RUNTIME ENFORCEMENT PLANE
         (src/eval_harness/ — Batch / CI)                      (src/gateway/ — <10ms Hot Path)
   ┌──────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
   │ • Stage 0 SKILL.md Linter (static_linter.py) │        │ CAGE Substrate Governor (Profile.FULL) │
   │ • Rollout Runner & Adapters (runner.py)      │ Static │ • Linkerd mTLS + Single-Use JWS Seals  │
   │ • ATIF Trace Adapters & Tokenomics Engine    │───────▶│ • 5-State Engine (ALLOW/NARROW/DEFER…) │
   │ • 4-Bucket Paired Skill Lift & Routing Prem. │ Config │ • Atomic Redis Lua CBFs & LIFO Undo    │
   │ • Double Ratchet Anchor Calibration Guard    │   &    │ • Emits RefusalReceipt JSONL Stream    │
   │ • GEPA Reflective Optimizer (gepa_optimizer) │  .cer  │                                        │
   │ • Optional DRY_RUN PRM & NARROW DPO Export   │        │                                        │
   └──────────────────────────────────────────────┘        └────────────────────────────────────────┘
                          ▲                                                     │
                          └─────────── Asynchronous Receipt Harvest ────────────┘
                                 (harvest_refusal_receipts → TRL JSONL)
```

---

## 2. Stage 0: Intrinsic `SKILL.md` Quality & Security Linter (`static_linter.py`)

Before running any LLM rollout, [`lint_skill_markdown()`](../../src/eval_harness/static_linter.py) and [`lint_skill_file()`](../../src/eval_harness/static_linter.py) evaluate a skill's `SKILL.md` specification at **zero LLM cost** across six intrinsic dimensions (synthesizing SkillEval `arXiv:2608.06891` and ACES `arXiv:2608.20614`):

1. **Structural Integrity (`structural_integrity`):** Validates YAML frontmatter (`name`, non-trivial `description`) and markdown section hierarchy.
2. **Routing Trigger Clarity (`routing_clarity`):** Checks for explicit positive activation conditions (`Use when...`) and negative restraint boundaries (`Do not use...`).
3. **Actionability & Parameter Specificity (`actionability`):** Requires ordered workflow steps (`1.`, `2.`) and concrete code blocks or CLI parameter flags.
4. **Tool Cohesiveness (`tool_cohesiveness`):** Verifies explicit references to helper scripts (`scripts/*.py`), tool arguments, or input/output schemas.
5. **Robustness & Error Recovery (`robustness_recovery`):** Checks for explicit fallback, retry, or fail-closed abort instructions when a tool call fails.
6. **Safety & Scope Restraint (`safety_restraint`):** Scans for leaked secrets/canaries, embedded PII via [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py), confidence-spoofing directives ([`detect_confidence_claim`](../../src/gateway/governance/confidence_claim_detector.py)), RBAC authorization claims ([`detect_authorization_claim`](../../src/gateway/governance/authorization_claim_detector.py)), prompt-injection/governance-bypass phrases (`_PROMPT_INJECTION_RE`), and destructive shell/SQL/disk commands ([`DESTRUCTIVE_COMMAND_PATTERN`](../../src/eval_harness/static_linter.py)). Destructive commands inside fenced code blocks are always flagged, whereas explicit prohibition/restraint prose outside code blocks (e.g., *"Never run `rm -rf` on user data"*) is exempted so safety guidance is not penalized. HTML comments (`<!-- ... -->`) are stripped prior to scoring positive rubric keywords while still being scanned for secrets and injections.

**Length-Bias Orthogonalization (`information_density_multiplier`):** To prevent verbose markdown dumps from inflating rubric scores, documents exceeding `optimal_max_words` (default `1800`) without proportional structural density receive a decaying multiplier (`length_adjusted_score = raw_mean_score * information_density_multiplier`), recorded on [`SkillStaticLintReport`](../../src/eval_harness/static_linter.py).

---

## 3. Cross-Harness ATIF Normalization, Live Rollout Runner & Drawback Calibration

### 3.1 Agent Trajectory Interchange Format (`ATIFTrajectory`), Trace Converters & Rollout Runner (`runner.py`)
[`ATIFTrajectory`](../../src/eval_harness/harness.py) and [`ATIFStep`](../../src/eval_harness/harness.py) provide a harness-agnostic representation of multi-turn agent rollouts, including intermediate tool calls, observations, `visible_skills`, and `intermediate_artifacts`. [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) ships static transcript converters:
- [`adk_session_to_atif()`](../../src/eval_harness/adapters.py): Normalizes Google ADK session/event payloads (`text`, `function_call`, `function_response`, artifacts) into `ATIFTrajectory`.
- [`langgraph_state_to_atif()`](../../src/eval_harness/adapters.py): Normalizes LangChain / LangGraph `StateGraph` message histories (`HumanMessage`, `AIMessage` with `tool_calls` and `usage_metadata`, `ToolMessage` paired by `tool_call_id`) into `ATIFTrajectory`.
- [`gemini_cli_jsonl_to_atif()`](../../src/eval_harness/adapters.py): Normalizes Gemini CLI / Antigravity JSONL step records into `ATIFTrajectory`.

To generate paired trajectories dynamically without cloud-locked dependencies, [`src/eval_harness/runner.py`](../../src/eval_harness/runner.py) provides [`AgentRolloutRunner`](../../src/eval_harness/runner.py) and the [`BaseRolloutAdapter`](../../src/eval_harness/runner.py) hierarchy (resolved via [`load_rollout_adapter()`](../../src/eval_harness/runner.py)):
- [`CallableRolloutAdapter`](../../src/eval_harness/runner.py): Wraps any sync/async Python callable, LangGraph runnable, or `"module:function"` target. Dynamic symbol resolution (`_resolve_symbol`) validates Python identifiers, blocks dangerous stdlib execution modules (`_FORBIDDEN_ROLLOUT_MODULES`, such as `os:system` or `subprocess:Popen`), and supports optional `allowed_module_prefixes` on [`load_rollout_adapter()`](../../src/eval_harness/runner.py). Because importing a Python module executes its top-level statements, only trusted adapter modules should be loaded.
- [`ADKSessionRolloutAdapter`](../../src/eval_harness/runner.py): Wraps Google ADK session runners and normalizes event payloads via [`adk_session_to_atif()`](../../src/eval_harness/adapters.py).
- [`LangGraphRolloutAdapter`](../../src/eval_harness/runner.py): Wraps compiled LangGraph `StateGraph` / `Runnable` objects (`.ainvoke` / `.invoke`), injects visible `SKILL.md` specifications as system messages, and normalizes output state via [`langgraph_state_to_atif()`](../../src/eval_harness/adapters.py).
- [`MultiAgentRolloutAdapter`](../../src/eval_harness/runner.py): Wraps hierarchical/sequential coordinator + specialist sub-agent topologies, recording sub-agent delegation edges in `ATIFStep.metadata["sub_agent"]` for unified skill and sub-agent routing evaluation.
- [`HttpRolloutAdapter`](../../src/eval_harness/runner.py): Invokes remote HTTP/REST/A2A agent endpoints with strict `http://` / `https://` scheme validation and a bounded response reader (`max_response_bytes`, default `10 MiB`).
- **Tokenomics & Multi-Turn Growth Engine:** [`compute_trajectory_tokenomics()`](../../src/eval_harness/runner.py) and [`compute_cost_savings_multiplier()`](../../src/eval_harness/runner.py) compute [`TrajectoryTokenomics`](../../src/eval_harness/runner.py) (`total_prompt_tokens`, `total_completion_tokens`, `estimated_cost_usd` via [`MODEL_PRICING_CATALOG`](../../src/eval_harness/runner.py), `multi_turn_growth_rate`, and `is_quadratic_bloat`). Super-linear multi-turn prompt token bloat (`growth_rate > 2.5`) is automatically penalized in [`SkillTrajectoryScorecard.skill_efficiency`](../../src/eval_harness/harness.py). Note that `ATIFTrajectory` step records and `metadata["prompt_tokens"]` are treated as trusted harness-recorded telemetry rather than untrusted agent-authored claims.

### 3.2 Composable Drawback Detectors & Fail-Closed Anchor Calibration
In accordance with Double Ratchet (`arXiv:2607.12790`), [`ComposedDrawbackEvaluator`](../../src/eval_harness/harness.py) evaluates trajectories through a disjunction of typed atomic [`DrawbackDetectorSpec`](../../src/eval_harness/harness.py) functions, each returning [`DrawbackVerdict`](../../src/eval_harness/harness.py) (`DRAWBACK`, `CLEAN`, or `ABSTAIN`). [`build_default_drawback_detectors()`](../../src/eval_harness/harness.py) provides five deterministic detectors:
1. `trace_security_and_canary_hygiene` (leaked secrets/canaries in responses or `intermediate_artifacts`, unsanitized PII across `final_response`, `intermediate_artifacts`, `ATIFStep.message`, and `ATIFStep.tool_calls` arguments with optional `check_observation_pii=True`, and destructive shell/SQL/Python/disk patterns via [`DESTRUCTIVE_COMMAND_PATTERN`](../../src/eval_harness/static_linter.py)),
2. `adversarial_claim_spoofing` (confidence and RBAC claim spoofing),
3. `governor_admissibility` (denies when dry-run `TrajectoryBenchmarkReport.trajectory_cleared` is `False`; abstains when `governor=None`),
4. `skill_routing_and_negative_control` (false-positive skill or sub-agent activation on `SkillPromptBucket.NEGATIVE_CONTROL`, decoy skill misrouting across file-read tools `view_file`/`read_file`/`Read`/`open_file`/`cat_file`, shell `cat`/`head`/`less` commands, case-insensitive `skill.md`, and POSIX/Windows path separators, or invocation of `forbidden_tools`), and
5. `required_output_contract` (missing or negated `required_output_tokens`, verified via `_token_present_affirmatively()` so negated substrings such as `"NOT OK"` do not satisfy `"OK"`).

Similarly, `_score_instruction_following()` requires corroborating tool-call or observation evidence when zero tool calls were executed in the trajectory or when an `expected_behaviors` item names a script or tool identifier.

To prevent **Evaluator Collapse** (graders degenerating into vacuous always-pass or always-fail functions), [`ComposedDrawbackEvaluator.calibrate_on_anchors()`](../../src/eval_harness/harness.py) validates the detector suite against a locked [`AnchorItem`](../../src/eval_harness/harness.py) set, returning [`AnchorCalibrationResult`](../../src/eval_harness/harness.py) and failing closed on class imbalance, any abstention (`ANCHOR_ABSTENTION`), `recall_fail == 0` (`VACUOUS_ALWAYS_PASS_COLLAPSE`), `recall_pass == 0` (`DEGENERATE_ALWAYS_FAIL_COLLAPSE`), or recall-weighted agreement below threshold ($w_{\text{fail}}=2.0, w_{\text{pass}}=1.0$).

---

## 4. Paired Differential Skill Lift & Group Routing Premium

[`FoundationModelEvalHarness.evaluate_paired_skill_lift()`](../../src/eval_harness/harness.py) (or [`AgentRolloutRunner.run_and_evaluate_skill_lift()`](../../src/eval_harness/runner.py) for live rollouts) implements paired differential evaluation across the four [`SkillPromptBucket`](../../src/eval_harness/harness.py) categories (`EXPLICIT`, `IMPLICIT`, `CONTEXTUAL`, `NEGATIVE_CONTROL`) defined in [`SkillEvalCase`](../../src/eval_harness/harness.py):

$$\Delta S_{\text{composite}} = S_{\text{with\_skill}} - S_{\text{baseline}}, \quad \text{RoutingPremium} = \Delta S_{\text{group}} - \Delta S_{\text{isolation}}$$

Each trajectory is graded into a [`SkillTrajectoryScorecard`](../../src/eval_harness/harness.py) (`security`, `skill_execution`, `skill_efficiency`, `instruction_following`, `goal_accuracy`, `admissibility_prm`, and `governor_evaluated`) and aggregated into a [`SkillLiftReport`](../../src/eval_harness/harness.py) with per-case [`PairedCaseLift`](../../src/eval_harness/harness.py) breakdowns. When `governor=None`, `governor_evaluated` is `False` and `goal_accuracy`, `outcome_score`, and `composite_score` are computed over the **five active trace-only dimensions** without averaging a vacuous `1.0` governor term into the score. When `governor` is provided, all six dimensions are active.

Partners and CI pipelines can execute the full Stage 0 + Stage 1 + Stage 2 certification gate via [`run_certification_gate()`](../../src/eval_harness/cli.py) (which accepts an optional `governor` and `state_reducer`) or the standalone CLI (`cage-skill-eval` in [`src/eval_harness/cli.py`](../../src/eval_harness/cli.py)), either against pre-recorded ATIF trace files or by driving a live rollout adapter (`--adapter`):

```bash
# Mode A: Offline certification from pre-recorded ATIF trace files
uv run cage-skill-eval \
  --skill-md path/to/SKILL.md \
  --evals path/to/evals.json \
  --baseline-traces path/to/baseline.json \
  --skill-traces path/to/with_skill.json \
  --model-id gemini-3.5-flash \
  --anchors path/to/anchors.json \
  --json

# Mode B: Dynamic paired rollout & certification via a live rollout adapter
uv run cage-skill-eval \
  --skill-md path/to/SKILL.md \
  --evals path/to/evals.json \
  --adapter my_package.agent:run_agent \
  --adapter-config '{"model_id": "gemini-3.5-flash"}' \
  --decoy-skills decoy-skill-a,decoy-skill-b \
  --json
```

Mode A requires `--model-id` (the model that produced the trace files); there is no default model. Mode B records the rollout bundle's model id, set through `--adapter-config`.

**Signed `.cer` receipts (`cage.skill.cer.v2`).** `--emit-cer <path>` signs a [`SkillCertificationReceipt`](../../src/eval_harness/harness.py) whose body binds `stages_run`, an `evidence_level` ([`CerEvidenceLevel`](../../src/eval_harness/harness.py): `STATIC_ONLY`, `PAIRED_TRACES`, or `LIVE_ROLLOUT`), and the SHA-256 digests of the evaluated evidence: `evals_sha256`, `anchors_sha256` (Stage 1), `baseline_traces_sha256` and `with_skill_traces_sha256` (Mode A, file bytes), or `adapter_ref` and `adapter_config_sha256` (Mode B, RFC 8785 JCS digest of the adapter config). `model_id` and the lift fields are `null` on `STATIC_ONLY` receipts (`--stage0-only`). [`GcsSkillCertificationVerifier`](../../src/integrations/gcp_eval/cer_publisher.py) refuses any other schema version (`unsupported_schema_version`), refuses `STATIC_ONLY` receipts unless constructed with `allow_static_only=True` (`static_only_receipt`), requires the `SKILL.md` bytes (`expected_skill_md_bytes`), and checks lift with [`lift_meets_threshold()`](../../src/eval_harness/harness.py), the same rule the gate applies (a `0.0` minimum requires strictly positive lift).

---

## 5. Mathematical Formulation for Dry-Run PRM & Counterfactual DPO (`governor != None`)

### 5.1 Deterministic Process Reward Model (PRM / RLVR) & Shadow State Isolation

When initialized with a [`SymbolicGovernor`](../../src/gateway/governance/governor/governor.py), `FoundationModelEvalHarness.evaluate_trajectory()` evaluates each intermediate step $t \in \{1 \dots T\}$ via `SymbolicGovernor.validate_action()` under `Profile.DRY_RUN` against the discrete-time Control Barrier Function condition:

$$h(S_{t+1}) \ge (1 - \gamma) \cdot h(S_t), \quad \gamma \in (0, 1]$$

and maps the canonical five-state [`GovernanceDecision`](../../src/gateway/governance/decisions.py) into a dense step reward $r_t$ on [`EvaluationStepResult`](../../src/eval_harness/harness.py):

| Verdict (`GovernanceDecision`) | Step Admissibility | Process Reward ($r_t$) | Alignment Role |
| :--- | :--- | :--- | :--- |
| `ALLOW` | Admissible ($u_t \in \mathcal{C}(S_t)$) | $+1.0$ | Positive trajectory exemplar |
| `NARROW` | Admissible after projection ($\Pi_{\mathcal{C}}(u_t)$) | $+0.5$ | Emits exact counterfactual DPO pair $(y_w, y_l)$ |
| `REQUIRE_APPROVAL` | Out-of-envelope (`ViolationKind.HITL`) | $-0.5$ | Boundary escalation signal |
| `DEFER` | Context starvation (`ViolationKind.DEFERRABLE`) | $-0.5$ | Epistemic uncertainty signal |
| `DENY` | Hard invariant violation (`ViolationKind.HARD`) | $-1.0$ | Hard negative exemplar ($y_l$) |

**Distinguishing Unmodified `ALLOW` vs. Clamped `NARROW` Steps:** [`TrajectoryBenchmarkReport`](../../src/eval_harness/harness.py) reports both admissible totals (`passed_steps`, `step_pass_rate`, `trajectory_cleared`) and unmodified-only metrics (`allow_steps`, `narrowed_steps`, `unmodified_pass_rate`, `strict_trajectory_cleared`). Passing `strict_narrow=True` to `evaluate_trajectory()` requires every step to clear as an unmodified `ALLOW` ($r_t = +1.0$) for `passed_steps` and `trajectory_cleared`.

**Multi-Turn Shadow State (`default_shadow_state_reducer`):** During `evaluate_trajectory()`, when `state_reducer=None`, [`default_shadow_state_reducer()`](../../src/eval_harness/harness.py) runs by default across turns—deducting step costs (`amount`, `notional_usd`, `cost_usd`) from seeded `_shadow_cash_balance_usd`, `remaining_headroom`, and `autonomous_headroom_usd` keys and automatically accumulating spend from `0.0` into `_shadow_daily_spend_usd` and `cumulative_notional` even when `initial_shadow_state` is `None`. Both [`CBFTierPlugin`](../../src/cage_finance/tiers/cbf_tier.py) and [`FiscalTierPlugin`](../../src/cage_finance/tiers/fiscal_tier.py) honor these shadow keys during `Profile.DRY_RUN` without mutating Redis state (`preview()` is side-effect-free on writes; note that if a governor tier is attached to a live Redis instance without shadow-key overrides, `preview()` still reads existing committed Redis state).

### 5.2 Counterfactual DPO Synthesis & Runtime Receipt Harvesting

When a tool call $y_l = (a_t, u_t)$ triggers a narrowable constraint (`ViolationKind.NARROWABLE`), CAGE's [`NarrowerRegistry`](../../src/gateway/governance/narrower.py) computes the clamped parameter vector $u_t^* = \Pi_{\mathcal{C}}(u_t)$ and re-verifies under `Profile.DRY_RUN` that $y_w = (a_t, u_t^*)$ yields zero violations, producing a [`DPOPreferenceTriplet`](../../src/eval_harness/harness.py) from a **single rollout**:

$$\tau_{\text{DPO}} = \bigl(x, \; s_t, \; y_w = (a_t, \Pi_{\mathcal{C}}(u_t)), \; y_l = (a_t, u_t)\bigr)$$

Similarly, `FoundationModelEvalHarness.harvest_refusal_receipts()` replays production [`RefusalReceipt`](../../src/gateway/governance/contracts.py) records offline and exports PII-scrubbed JSONL datasets via `export_hf_trl_jsonl(sanitize_pii=True)`:
- **Cryptographic Integrity Check (`verify_receipt_hash=True`):** Verifies each receipt's RFC 8785 JCS SHA-256 `proof_hash` via [`RefusalReceipt.verify_proof_hash()`](../../src/gateway/governance/contracts.py) before replay, failing closed (`ValueError`) on tampered or forged receipts.
- **Chosen-Target Argument Sanitization:** Strips prompt-injection, policy-override, claim-spoofing, and destructive command strings (as well as any keys outside optional `allowed_param_keys`) from `chosen["arguments"]` while retaining the raw `attempted_params` in `rejected["arguments"]`.
- **Standing Context Isolation (`trust_receipt_standing=False` by default):** Untrusted caller-supplied `standing_at_refusal` and `standing_snapshot` fields are ignored by default when re-evaluating narrowing bounds unless the caller supplies `trusted_standing_override` or explicitly opts in via `trust_receipt_standing=True`.

---

## 6. GEPA (Genetic-Pareto) Reflective Prompt, Skill & PII Rule Optimization (`gepa_optimizer.py`)

Standard prompt optimizers collapse multi-dimensional governance requirements into a single scalar reward—causing LLM mutators to trade away negative-control restraint or safety clauses for marginal task accuracy—and discard rich diagnostic failure traces during mutation. [`src/eval_harness/gepa_optimizer.py`](../../src/eval_harness/gepa_optimizer.py) implements the **GEPA (Genetic-Pareto)** reflective text evolution loop (Agrawal et al., `arXiv:2507.19457`, [`gepa-ai/gepa`](https://github.com/gepa-ai/gepa)) directly inside the standalone Offline Evaluation Plane (`src/eval_harness/`).

### 6.1 Four-Dimensional Pareto Objective Vector & Instance-Wise Frontier (`ParetoObjectives`)

Instead of scalarizing competing objectives prematurely, [`ParetoObjectives`](../../src/eval_harness/gepa_optimizer.py) preserves a 4D objective vector alongside per-case scores (`per_case_scores: Mapping[str, float]`):

$$\mathbf{J}(c) = \bigl(J_{\text{quality}}(c), \; J_{\text{admissibility}}(c), \; J_{\text{security}}(c), \; J_{\text{efficiency}}(c)\bigr) \in [0, 1]^4$$

- [`dominates(obj_a, obj_b)`](../../src/eval_harness/gepa_optimizer.py): Returns `True` iff candidate $a$ is $\ge b$ on all four dimensions (`quality_score`, `admissibility_score`, `security_score`, `token_efficiency_score`) and every shared `case_id` (`include_per_case=True`), and strictly $>$ on at least one.
- [`compute_pareto_frontier(candidates)`](../../src/eval_harness/gepa_optimizer.py): Computes the non-dominated Pareto front $\mathcal{F} \subseteq \mathcal{P}$ of [`ParetoCandidate`](../../src/eval_harness/gepa_optimizer.py) entries and retains specialists that achieve non-dominated scores on individual evaluation cases (`per_case_scores`), enabling **system-aware merge** (`enable_system_aware_merge=True` in [`GEPAEvolutionEngine.optimize()`](../../src/eval_harness/gepa_optimizer.py)) across complementary multi-component candidates.

### 6.2 `ActionableSideInfo` (ASI) Diagnostic Feedback & Anti-Reward-Hacking Gate

When [`CageGEPAAdapter.evaluate()`](../../src/eval_harness/gepa_optimizer.py) / [`CageGEPAAdapter.evaluate_async()`](../../src/eval_harness/gepa_optimizer.py) evaluates a candidate mapping (`Mapping[str, str]`) across a batch of [`SkillEvalCase`](../../src/eval_harness/harness.py) items, it returns a [`CageEvaluationBatch`](../../src/eval_harness/gepa_optimizer.py) containing structured [`ActionableSideInfo`](../../src/eval_harness/gepa_optimizer.py) (ASI) from CAGE's deterministic verifiers:
- **Dry-Run Governor Violations (`governor_violations`):** Exact STPA UCA IDs, OPA rule denials, FTRA reachability blocks, and CBF margin shortfalls from `SymbolicGovernor.validate_action()` (`Profile.DRY_RUN`).
- **Counterfactual `NARROW` Clamping Notes (`narrowed_notes`):** Exact parameter projections $\Pi_{\mathcal{C}}(u_t)$ showing the reflection LLM how a tool call exceeded the safe boundary and what value cleared.
- **Drawback & Tokenomics Diagnostics (`drawback_reasons`, `missing_output_tokens`, `forbidden_tools_called`, `token_growth_rate`, `is_quadratic_bloat`):** False-positive tool calls on `SkillPromptBucket.NEGATIVE_CONTROL`, missing or negated `required_output_tokens`, and super-linear multi-turn token growth (`growth_rate > 2.5`) from [`compute_trajectory_tokenomics()`](../../src/eval_harness/runner.py).
- **Mandatory PII Sanitization (`to_reflective_dict` / `to_reflective_text`):** Every ASI diagnostic string and `generated_output` is scrubbed through [`PIISanitizer.sanitize()`](../../src/gateway/governance/pii_sanitizer.py) inside [`CageGEPAAdapter.make_reflective_dataset()`](../../src/eval_harness/gepa_optimizer.py) before entering the reflection prompt.
- **Stage 0 Anti-Reward-Hacking Gate ([`screen_candidate_security()`](../../src/eval_harness/gepa_optimizer.py)):** Every initial seed and LLM-proposed mutation is screened prior to rollout via [`detect_prompt_injection()`](../../src/gateway/governance/prompt_injection_detector.py), [`detect_confidence_claim()`](../../src/gateway/governance/confidence_claim_detector.py), [`detect_authorization_claim()`](../../src/gateway/governance/authorization_claim_detector.py), [`DESTRUCTIVE_COMMAND_PATTERN`](../../src/eval_harness/static_linter.py), and [`lint_skill_markdown()`](../../src/eval_harness/static_linter.py). Any candidate attempting to game the evaluator (e.g., injecting `"confidence: 0.99"` or `"role: senior"`) fails with `CandidateSecurityReport.passed=False` and all 4 objectives zeroed.

### 6.3 Reflective Evolution Loop (`GEPAEvolutionEngine`), Presidio/spaCy Tuning & `optimize_anything` Bridge

1. **[`GEPAEvolutionEngine`](../../src/eval_harness/gepa_optimizer.py):** Executes the 5-step GEPA evolutionary loop over `max_iterations` on `trainset` (and optional held-out `valset`):
   - Screens and evaluates `seed_candidate`,
   - Selects a parent [`ParetoCandidate`](../../src/eval_harness/gepa_optimizer.py) from the non-dominated Pareto frontier,
   - Builds PII-scrubbed reflective records (`Inputs`, `Generated Outputs`, `Score`, `Feedback`) from `trainset` `ActionableSideInfo` via `CageGEPAAdapter.make_reflective_dataset()`,
   - Invokes the pluggable [`ReflectiveMutatorProtocol`](../../src/eval_harness/gepa_optimizer.py) (`propose_mutation()`) to synthesize a targeted child candidate,
   - Screens the child through `screen_candidate_security()`, evaluates its 4D `ParetoObjectives`, updates the Pareto frontier ([`GEPAOptimizationResult`](../../src/eval_harness/gepa_optimizer.py)), and performs system-aware component merge when $\ge 2$ frontier specialists exist across multi-component candidates.
2. **Optimizing Presidio + `spaCy` PII Configuration ([`PresidioPIIOptimizationEvaluator`](../../src/eval_harness/gepa_optimizer.py) & [`PIIRedactionEvalSample`](../../src/eval_harness/gepa_optimizer.py)):**
   - CAGE uses `spaCy` (`en_core_web_lg` / `en_core_web_sm`) solely as the NER backbone inside [`src/integrations/presidio/redactor.py`](../../src/integrations/presidio/redactor.py) ([`redact_pii()`](../../src/integrations/presidio/redactor.py), [`get_presidio_engines()`](../../src/integrations/presidio/redactor.py), and `_PII_ENTITIES = ["PHONE_NUMBER", "CREDIT_CARD", "EMAIL_ADDRESS", "PERSON", "CRYPTO", "US_SSN", "US_ITIN", "US_PASSPORT", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "IBAN_CODE", "IP_ADDRESS"]`).
   - Rather than fine-tuning `spaCy` statistical weights, `PresidioPIIOptimizationEvaluator` uses GEPA to optimize serialized JSON configurations (`score_threshold`, `active_entities`, `allow_list`) against labeled [`PIIRedactionEvalSample`](../../src/eval_harness/gepa_optimizer.py) corpora, balancing **PII Recall** (`admissibility_score` + `security_score` on `expected_entities` and `must_not_contain`) against **Financial/Clinical Text Preservation** (`quality_score` on `must_preserve`, preventing false-positive redaction of tickers, governance verdicts, and dates).
3. **Optional [`gepa.optimize_anything`](https://github.com/gepa-ai/gepa) Bridge ([`run_gepa_optimize_anything()`](../../src/eval_harness/gepa_optimizer.py)):**
   - Wraps a CAGE evaluator function returning `(score, side_infos)` and streams PII-scrubbed `ActionableSideInfo.to_reflective_text()` diagnostics into `gepa.optimize_anything.log()` when the optional `gepa` package is installed.
4. **Relationship to Layer 3 GCP GEAP [`GovernedGEPAOptimizer`](../../src/integrations/gcp_eval/gepa_governor.py):**
   - [`src/eval_harness/gepa_optimizer.py`](../../src/eval_harness/gepa_optimizer.py) is the **cloud-agnostic reflective evolution engine** in the standalone Offline Evaluation Plane (`src/eval_harness/`).
   - [`src/integrations/gcp_eval/gepa_governor.py`](../../src/integrations/gcp_eval/gepa_governor.py) is the **Layer 3 GCP integration adapter** that governs populations produced by Google Cloud GEAP's managed `AgentOptimizer` and signs the winning survivor into a `.cer` receipt via [`GcpSkillCertifier`](../../src/integrations/gcp_eval/cer_publisher.py) (see [`GEAP_INTEGRATION_ARCHITECTURE.md`](GEAP_INTEGRATION_ARCHITECTURE.md) §4.2).

