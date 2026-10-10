# Foundation Model & Agent Skill Evaluation Harness (`src/eval_harness/`)

**Package Root:** [`src/eval_harness/__init__.py`](../../src/eval_harness/__init__.py)  
**Core Modules:** [`src/eval_harness/harness.py`](../../src/eval_harness/harness.py) · [`src/eval_harness/static_linter.py`](../../src/eval_harness/static_linter.py) · [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) · [`src/eval_harness/cli.py`](../../src/eval_harness/cli.py)  
**Test Suite:** [`tests/unit/governance/test_eval_harness.py`](../../tests/unit/governance/test_eval_harness.py)  
**System Plane:** Standalone Offline Evaluation & Skill Certification System (`src/eval_harness/`) — strictly decoupled from Online Enforcement (`src/gateway/`)

---

## 1. Executive Summary: Split-Plane Architecture & The Dual-Lifecycle Flywheel

Enterprise AI platforms and foundation model teams face two opposing requirements:
1. **Online Runtime Enforcement (`src/gateway/`)** must execute synchronously on the hot path in **$<10\text{ ms}$**, enforcing atomic state invariants (`FTRA`, `STPA`, `CBF`, `OPA`, `RoutingSeal`) with zero dependency on batch trajectory evaluators or dataset exporters.
2. **Offline Evaluation, Skill Certification & Post-Training Alignment (`src/eval_harness/`)** must inspect full multi-turn trajectories, score `SKILL.md` specifications, compute paired differential **Skill Lift**, calibrate evaluators against golden anchors, and export counterfactual DPO datasets in CI or batch pipelines.

CAGE resolves this tension via a **Modular Monorepo with a Hard System Cut**:
- **Strict Non-Interference (Gate G3):** [`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py) enforces at the AST level (`OFFLINE_EVAL_PATTERN`) that `src/gateway/` **never** imports from `src/eval_harness/`. Furthermore, [`src/gateway/Dockerfile`](../../src/gateway/Dockerfile) does not copy `src/eval_harness/` into the production Gateway container.
- **Two Offline Execution Modes in [`FoundationModelEvalHarness`](../../src/eval_harness/harness.py):**
  - **Standalone Trace-Only Mode (`governor=None`):** Grades recorded [`ATIFTrajectory`](../../src/eval_harness/harness.py) logs, lints `SKILL.md` files ([`lint_skill_markdown`](../../src/eval_harness/static_linter.py)), calibrates drawback detectors ([`calibrate_on_anchors`](../../src/eval_harness/harness.py)), and computes 4-bucket paired [`SkillLiftReport`](../../src/eval_harness/harness.py) with **zero** `SymbolicGovernor`, Redis, or OPA dependencies.
  - **Dry-Run Counterfactual Mode (`governor=<SymbolicGovernor>`):** Replays tool actions through [`SymbolicGovernor.validate_action()`](../../src/gateway/governance/governor/governor.py) (`Profile.DRY_RUN`) with isolated shadow-state tracking (`ShadowStateReducer`) to compute step-level Process Rewards (PRM) and synthesize minimal-edit counterfactual DPO pairs.

```text
      OFFLINE EVALUATION & CERTIFICATION PLANE                ONLINE RUNTIME ENFORCEMENT PLANE
         (src/eval_harness/ — Batch / CI)                      (src/gateway/ — <10ms Hot Path)
   ┌──────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
   │ • Stage 0 SKILL.md Linter (static_linter.py) │        │ CAGE Substrate Governor (Profile.FULL) │
   │ • ATIF Trace Adapters (ADK & Gemini CLI)     │ Static │ • Linkerd mTLS + Single-Use JWS Seals  │
   │ • 4-Bucket Paired Skill Lift & Routing Prem. │───────▶│ • 5-State Engine (ALLOW/NARROW/DEFER…) │
   │ • Double Ratchet Anchor Calibration Guard    │ Config │ • Atomic Redis Lua CBFs & LIFO Undo    │
   │ • Optional DRY_RUN PRM & NARROW DPO Export   │        │ • Emits RefusalReceipt JSONL Stream    │
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
6. **Safety & Scope Restraint (`safety_restraint`):** Scans for leaked secrets/canaries, embedded PII via [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py), confidence-spoofing directives ([`detect_confidence_claim`](../../src/gateway/governance/confidence_claim_detector.py)), and RBAC authorization claims ([`detect_authorization_claim`](../../src/gateway/governance/authorization_claim_detector.py)).

**Length-Bias Orthogonalization (`information_density_multiplier`):** To prevent verbose markdown dumps from inflating rubric scores, documents exceeding `optimal_max_words` (default `1800`) without proportional structural density receive a decaying multiplier (`length_adjusted_score = raw_mean_score * information_density_multiplier`), recorded on [`SkillStaticLintReport`](../../src/eval_harness/static_linter.py).

---

## 3. Cross-Harness ATIF Normalization & Composable Drawback Calibration

### 3.1 Agent Trajectory Interchange Format (`ATIFTrajectory`) & Native Adapters
[`ATIFTrajectory`](../../src/eval_harness/harness.py) and [`ATIFStep`](../../src/eval_harness/harness.py) provide a harness-agnostic representation of multi-turn agent rollouts, including intermediate tool calls, observations, `visible_skills`, and `intermediate_artifacts`. [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) ships native converters:
- [`adk_session_to_atif()`](../../src/eval_harness/adapters.py): Normalizes Google ADK session/event payloads (`text`, `function_call`, `function_response`, artifacts) into `ATIFTrajectory`.
- [`gemini_cli_jsonl_to_atif()`](../../src/eval_harness/adapters.py): Normalizes Gemini CLI / Antigravity JSONL step records into `ATIFTrajectory`.

### 3.2 Composable Drawback Detectors & Fail-Closed Anchor Calibration
In accordance with Double Ratchet (`arXiv:2607.12790`), [`ComposedDrawbackEvaluator`](../../src/eval_harness/harness.py) evaluates trajectories through a disjunction of typed atomic [`DrawbackDetectorSpec`](../../src/eval_harness/harness.py) functions, each returning [`DrawbackVerdict`](../../src/eval_harness/harness.py) (`DRAWBACK`, `CLEAN`, or `ABSTAIN`). [`build_default_drawback_detectors()`](../../src/eval_harness/harness.py) provides five deterministic detectors:
1. `trace_security_and_canary_hygiene` (leaked secrets/canaries in responses or `intermediate_artifacts`, unsanitized PII, destructive shell patterns),
2. `adversarial_claim_spoofing` (confidence and RBAC claim spoofing),
3. `governor_admissibility` (denies when dry-run `TrajectoryBenchmarkReport.trajectory_cleared` is `False`; abstains when `governor=None`),
4. `skill_routing_and_negative_control` (false-positive skill activation on `SkillPromptBucket.NEGATIVE_CONTROL`, decoy skill misrouting, or invocation of `forbidden_tools`), and
5. `required_output_contract` (missing `required_output_tokens`).

To prevent **Evaluator Collapse** (graders degenerating into vacuous always-pass or always-fail functions), [`ComposedDrawbackEvaluator.calibrate_on_anchors()`](../../src/eval_harness/harness.py) validates the detector suite against a locked [`AnchorItem`](../../src/eval_harness/harness.py) set, returning [`AnchorCalibrationResult`](../../src/eval_harness/harness.py) and failing closed on class imbalance, any abstention (`ANCHOR_ABSTENTION`), `recall_fail == 0` (`VACUOUS_ALWAYS_PASS_COLLAPSE`), `recall_pass == 0` (`DEGENERATE_ALWAYS_FAIL_COLLAPSE`), or recall-weighted agreement below threshold ($w_{\text{fail}}=2.0, w_{\text{pass}}=1.0$).

---

## 4. Paired Differential Skill Lift & Group Routing Premium

[`FoundationModelEvalHarness.evaluate_paired_skill_lift()`](../../src/eval_harness/harness.py) implements paired differential evaluation across the four [`SkillPromptBucket`](../../src/eval_harness/harness.py) categories (`EXPLICIT`, `IMPLICIT`, `CONTEXTUAL`, `NEGATIVE_CONTROL`) defined in [`SkillEvalCase`](../../src/eval_harness/harness.py):

$$\Delta S_{\text{composite}} = S_{\text{with\_skill}} - S_{\text{baseline}}, \quad \text{RoutingPremium} = \Delta S_{\text{group}} - \Delta S_{\text{isolation}}$$

Each trajectory is graded into a six-metric [`SkillTrajectoryScorecard`](../../src/eval_harness/harness.py) (`security`, `skill_execution`, `skill_efficiency`, `instruction_following`, `goal_accuracy`, `admissibility_prm`) and aggregated into a [`SkillLiftReport`](../../src/eval_harness/harness.py) with per-case [`PairedCaseLift`](../../src/eval_harness/harness.py) breakdowns.

Partners and CI pipelines can execute the full Stage 0 + Stage 1 + Stage 2 certification gate via [`run_certification_gate()`](../../src/eval_harness/cli.py) or the standalone CLI (`cage-skill-eval` in [`src/eval_harness/cli.py`](../../src/eval_harness/cli.py)):

```bash
uv run cage-skill-eval \
  --skill-md path/to/SKILL.md \
  --evals path/to/evals.json \
  --baseline-traces path/to/baseline.json \
  --skill-traces path/to/with_skill.json \
  --anchors path/to/anchors.json \
  --json
```

---

## 5. Mathematical Formulation for Dry-Run PRM & Counterfactual DPO (`governor != None`)

### 5.1 Deterministic Process Reward Model (PRM / RLVR)

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

### 5.2 Counterfactual DPO Synthesis & Runtime Receipt Harvesting

When a tool call $y_l = (a_t, u_t)$ triggers a narrowable constraint (`ViolationKind.NARROWABLE`), CAGE's [`NarrowerRegistry`](../../src/gateway/governance/narrower.py) computes the clamped parameter vector $u_t^* = \Pi_{\mathcal{C}}(u_t)$ and re-verifies under `Profile.DRY_RUN` that $y_w = (a_t, u_t^*)$ yields zero violations, producing a [`DPOPreferenceTriplet`](../../src/eval_harness/harness.py) from a **single rollout**:

$$\tau_{\text{DPO}} = \bigl(x, \; s_t, \; y_w = (a_t, \Pi_{\mathcal{C}}(u_t)), \; y_l = (a_t, u_t)\bigr)$$

Similarly, `FoundationModelEvalHarness.harvest_refusal_receipts()` replays production [`RefusalReceipt`](../../src/gateway/governance/contracts.py) records offline and exports PII-scrubbed JSONL datasets via `export_hf_trl_jsonl(sanitize_pii=True)`.

