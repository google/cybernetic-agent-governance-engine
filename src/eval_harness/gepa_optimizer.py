# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""GEPA (Genetic-Pareto) Reflective Prompt & Text-Parameter Optimizer (`src/eval_harness/gepa_optimizer.py`).

Integrates the GEPA (Genetic-Pareto) reflective evolution paradigm (Agrawal et al.,
arXiv:2507.19457; `github.com/gepa-ai/gepa`) into CAGE's Offline Evaluation &
Skill Certification Plane (`src/eval_harness/`):

1. **Actionable Side Information (ASI) from Symbolic Governance**:
   Unlike scalar RL rewards that collapse execution traces into a single float,
   :class:`ActionableSideInfo` captures step-level :class:`SymbolicGovernor`
   ``Profile.DRY_RUN`` verdicts, violation rule IDs, symbolic ``NARROW``
   clamping diffs, :class:`SkillTrajectoryScorecard` dimensions, and
   :class:`TrajectoryTokenomics` context-growth diagnostics. All trace strings
   are scrubbed via :class:`PIISanitizer` (ISO 42001 Annex A.6) before reaching
   any reflection LLM or external log.
2. **Multi-Objective & Instance-Wise Pareto Frontier Selection**:
   :class:`ParetoObjectives` models CAGE's 4D governance objective vector
   ``(quality_score, admissibility_score, security_score, token_efficiency_score)``
   alongside per-case score vectors (`per_case_scores`), retaining candidates
   that are non-dominated across either the governance objective tuple or
   specific evaluation cases.
3. **Anti-Reward-Hacking Security Gate (Double Ratchet)**:
   Every candidate text artifact (native system prompt, NeMo Guardrails
   self-check prompt, `SKILL.md` body, or Presidio/spaCy PII configuration) is
   screened via :func:`screen_candidate_security` against prompt injection,
   secret canary leakage, destructive shell patterns, and claim spoofing before
   evaluation or acceptance into the Pareto pool.
4. **GEPAAdapter & Presidio/spaCy PII Rule Optimization**:
   Provides :class:`CageGEPAAdapter` (implementing GEPA's ``evaluate`` and
   ``make_reflective_dataset`` protocol over :class:`FoundationModelEvalHarness`),
   :class:`PresidioPIIOptimizationEvaluator` (for tuning Presidio/spaCy entity
   thresholds, context words, and false-positive preservation rules), and an
   optional runtime bridge (:func:`run_gepa_optimize_anything`) to the upstream
   ``gepa`` library when installed.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import importlib
import inspect
import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from src.eval_harness.harness import (
    ATIFTrajectory,
    FoundationModelEvalHarness,
    ShadowStateReducer,
    SkillEvalCase,
    SkillTrajectoryScorecard,
    TrajectoryBenchmarkReport,
    _token_present_affirmatively,
)
from src.eval_harness.runner import (
    TrajectoryTokenomics,
    compute_trajectory_tokenomics,
)
from src.eval_harness.static_linter import (
    _FENCED_CODE_BLOCK_RE,
    _PROHIBITION_LINE_RE,
    _PROMPT_INJECTION_RE,
    _SECRET_CANARY_RE,
    DESTRUCTIVE_COMMAND_PATTERN,
    lint_skill_markdown,
)
from src.gateway.governance.authorization_claim_detector import (
    detect_authorization_claim,
)
from src.gateway.governance.confidence_claim_detector import (
    detect_confidence_claim,
)
from src.gateway.governance.pii_sanitizer import PIISanitizer
from src.gateway.governance.prompt_injection_detector import (
    detect_prompt_injection,
)

if TYPE_CHECKING:
    from src.gateway.governance.governor.governor import SymbolicGovernor


# ---------------------------------------------------------------------------
# Stage 0 Candidate Security Screening (Anti-Reward-Hacking Gate)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateSecurityReport:
    """Result of screening a candidate prompt/skill/config before GEPA evaluation."""

    passed: bool
    violations: tuple[str, ...] = ()
    static_lint_score: float = 1.0


def _has_non_prohibited_destructive_command(text: str) -> bool:
    """Return True if ``text`` has a destructive command in a code fence or non-prohibition line."""
    for block in _FENCED_CODE_BLOCK_RE.findall(text):
        if DESTRUCTIVE_COMMAND_PATTERN.search(block) is not None:
            return True
    non_fenced = _FENCED_CODE_BLOCK_RE.sub("", text)
    for line in non_fenced.splitlines():
        if DESTRUCTIVE_COMMAND_PATTERN.search(
            line
        ) is not None and not _PROHIBITION_LINE_RE.search(line):
            return True
    return False


def screen_candidate_security(
    candidate_text: str,
    *,
    is_skill_markdown: bool = False,
    min_skill_static_score: float = 0.70,
) -> CandidateSecurityReport:
    """Fail-closed security screen for candidate prompts, skills, or configs.

    Prevents reflective mutation from introducing prompt-injection payloads,
    secret canaries, destructive commands, or spoofed governance claims.
    """
    if not isinstance(candidate_text, str) or not candidate_text.strip():
        return CandidateSecurityReport(
            passed=False,
            violations=("empty_or_non_string_candidate",),
            static_lint_score=0.0,
        )

    violations: list[str] = []
    inj_result = detect_prompt_injection(candidate_text)
    if _PROMPT_INJECTION_RE.search(candidate_text) or inj_result.detected:
        violations.append("prompt_injection_pattern_detected")
    if _SECRET_CANARY_RE.search(candidate_text):
        violations.append("secret_or_canary_pattern_detected")
    if _has_non_prohibited_destructive_command(candidate_text):
        violations.append("destructive_command_pattern_detected")

    auth_claim = detect_authorization_claim(candidate_text)
    if auth_claim.detected:
        violations.append(f"authorization_claim_spoofing:{auth_claim.category}")

    conf_claim = detect_confidence_claim(candidate_text)
    if conf_claim.detected:
        violations.append(f"confidence_claim_spoofing:{conf_claim.pattern_matched}")

    static_score = 1.0
    if is_skill_markdown:
        lint_report = lint_skill_markdown(
            candidate_text, min_score=min_skill_static_score
        )
        static_score = lint_report.length_adjusted_score
        if not lint_report.passed:
            violations.extend(f"skill_lint:{v}" for v in lint_report.violations)

    return CandidateSecurityReport(
        passed=(len(violations) == 0),
        violations=tuple(dict.fromkeys(violations)),
        static_lint_score=round(float(static_score), 4),
    )


def _screen_candidate_mapping(
    candidate: Mapping[str, str],
    *,
    is_skill_markdown: bool = False,
    min_skill_static_score: float = 0.70,
) -> CandidateSecurityReport:
    """Screen all components of a candidate mapping without breaking SKILL.md frontmatter anchors."""
    if not candidate:
        return CandidateSecurityReport(
            passed=False,
            violations=("empty_or_non_string_candidate",),
            static_lint_score=0.0,
        )

    skill_keys: set[str] = set()
    if is_skill_markdown:
        if len(candidate) == 1:
            skill_keys = set(candidate.keys())
        else:
            for k, v in candidate.items():
                if "skill" in str(k).lower() or str(v).lstrip().startswith("---"):
                    skill_keys.add(str(k))
            if not skill_keys:
                skill_keys = {str(k) for k in candidate.keys()}

    all_violations: list[str] = []
    lint_scores: list[float] = []

    for k, v in candidate.items():
        comp_is_skill = str(k) in skill_keys
        rep = screen_candidate_security(
            str(v),
            is_skill_markdown=comp_is_skill,
            min_skill_static_score=min_skill_static_score,
        )
        all_violations.extend(rep.violations)
        if comp_is_skill:
            lint_scores.append(rep.static_lint_score)

    if len(candidate) > 1:
        combined_rep = screen_candidate_security(
            "\n\n".join(str(v) for v in candidate.values()),
            is_skill_markdown=False,
        )
        all_violations.extend(combined_rep.violations)

    min_score = min(lint_scores) if lint_scores else 1.0
    dedup_violations = tuple(dict.fromkeys(all_violations))
    return CandidateSecurityReport(
        passed=(len(dedup_violations) == 0),
        violations=dedup_violations,
        static_lint_score=round(float(min_score), 4),
    )


def _candidate_dict_sha256(candidate: Mapping[str, str]) -> str:
    """Compute canonical SHA-256 digest for a candidate mapping."""
    canonical = json.dumps(dict(candidate), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Actionable Side Information (ASI) & Reflective Diagnostics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionableSideInfo:
    """Diagnostic feedback emitted by CAGE evaluators for GEPA reflection.

    Serves as the text-optimization analogue of a gradient by explaining *why*
    a candidate prompt or skill failed on a given evaluation case.
    """

    case_id: str
    prompt: str
    score: float
    governor_cleared: bool = True
    governor_violations: tuple[str, ...] = ()
    narrowed_notes: tuple[str, ...] = ()
    drawback_reasons: tuple[str, ...] = ()
    missing_output_tokens: tuple[str, ...] = ()
    forbidden_tools_called: tuple[str, ...] = ()
    token_growth_rate: float = 1.0
    estimated_cost_usd: float = 0.0
    is_quadratic_bloat: bool = False
    extra_diagnostics: tuple[str, ...] = ()
    generated_output: str = ""

    def to_reflective_dict(
        self, *, sanitizer: PIISanitizer | None = None
    ) -> dict[str, Any]:
        """Convert to a PII-scrubbed dictionary suitable for GEPA reflection datasets."""
        active_sanitizer = sanitizer or PIISanitizer()

        def _clean(text: str) -> str:
            return active_sanitizer.sanitize(text)

        feedback_parts: list[str] = []
        if not self.governor_cleared or self.governor_violations:
            feedback_parts.append(
                "Governance Violations: "
                + ", ".join(_clean(v) for v in self.governor_violations)
            )
        if self.narrowed_notes:
            feedback_parts.append(
                "Symbolic Narrowing Clamps: "
                + "; ".join(_clean(n) for n in self.narrowed_notes)
            )
        if self.drawback_reasons:
            feedback_parts.append(
                "Drawback Detectors Fired: "
                + ", ".join(_clean(d) for d in self.drawback_reasons)
            )
        if self.forbidden_tools_called:
            feedback_parts.append(
                "Forbidden Tools Invoked: "
                + ", ".join(_clean(t) for t in self.forbidden_tools_called)
            )
        if self.missing_output_tokens:
            feedback_parts.append(
                "Missing Required Output Tokens: "
                + ", ".join(_clean(tok) for tok in self.missing_output_tokens)
            )
        if self.is_quadratic_bloat:
            feedback_parts.append(
                f"Quadratic Context Bloat Detected (growth_rate={self.token_growth_rate:.2f}x)"
            )
        if self.extra_diagnostics:
            feedback_parts.append(
                "Additional Diagnostics: "
                + "; ".join(_clean(x) for x in self.extra_diagnostics)
            )
        if not feedback_parts:
            feedback_parts.append("All governance, security, and task checks passed.")

        return {
            "case_id": _clean(self.case_id),
            "Inputs": _clean(self.prompt),
            "Generated Outputs": _clean(self.generated_output),
            "Score": round(float(self.score), 4),
            "Feedback": " | ".join(feedback_parts),
            "governor_cleared": self.governor_cleared,
            "token_growth_rate": round(float(self.token_growth_rate), 4),
            "estimated_cost_usd": round(float(self.estimated_cost_usd), 8),
        }

    def to_reflective_text(self, *, sanitizer: PIISanitizer | None = None) -> str:
        """Render a concise single-line diagnostic string for `oa.log()` or LLM reflection."""
        record = self.to_reflective_dict(sanitizer=sanitizer)
        return (
            f"[case={record['case_id']} score={record['Score']:.4f} "
            f"gov_cleared={record['governor_cleared']} "
            f"growth={record['token_growth_rate']:.2f}x] "
            f"{record['Feedback']}"
        )


# ---------------------------------------------------------------------------
# Multi-Objective & Instance-Wise Pareto Frontier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParetoObjectives:
    """4D CAGE Governance Objective Vector (all dimensions higher-is-better in [0, 1]).

    * ``quality_score``: Mean task / instruction-following / F1 accuracy score.
    * ``admissibility_score``: Mean normalized :class:`SymbolicGovernor` PRM reward.
    * ``security_score``: Mean drawback & static security hygiene score.
    * ``token_efficiency_score``: Multi-turn context & token cost efficiency score.
    * ``per_case_scores``: Instance-level scores keyed by ``case_id`` for GEPA's
      instance-wise Pareto frontier tracking.
    """

    quality_score: float
    admissibility_score: float
    security_score: float
    token_efficiency_score: float
    per_case_scores: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, val in (
            ("quality_score", self.quality_score),
            ("admissibility_score", self.admissibility_score),
            ("security_score", self.security_score),
            ("token_efficiency_score", self.token_efficiency_score),
        ):
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, float))
                or not math.isfinite(float(val))
            ):
                raise ValueError(f"{name} must be a finite float, got {val!r}")

    def as_tuple(self) -> tuple[float, float, float, float]:
        """Return the 4-tuple ``(quality, admissibility, security, token_efficiency)``."""
        return (
            round(float(self.quality_score), 6),
            round(float(self.admissibility_score), 6),
            round(float(self.security_score), 6),
            round(float(self.token_efficiency_score), 6),
        )

    @property
    def scalarized_score(self) -> float:
        """Weighted scalar summary (0.35 quality + 0.30 admissibility + 0.20 security + 0.15 efficiency)."""
        return round(
            0.35 * float(self.quality_score)
            + 0.30 * float(self.admissibility_score)
            + 0.20 * float(self.security_score)
            + 0.15 * float(self.token_efficiency_score),
            4,
        )


def dominates(
    obj_a: ParetoObjectives,
    obj_b: ParetoObjectives,
    *,
    include_per_case: bool = True,
    eps: float = 1e-6,
) -> bool:
    """Return True iff ``obj_a`` Pareto-dominates ``obj_b``.

    ``obj_a`` dominates ``obj_b`` when ``obj_a`` is at least as good as ``obj_b``
    on every objective dimension (and every shared ``case_id`` when
    ``include_per_case=True``) and strictly better on at least one dimension.
    """
    vec_a = list(obj_a.as_tuple())
    vec_b = list(obj_b.as_tuple())

    if include_per_case and obj_a.per_case_scores and obj_b.per_case_scores:
        shared_keys = sorted(
            set(obj_a.per_case_scores.keys()) & set(obj_b.per_case_scores.keys())
        )
        for k in shared_keys:
            vec_a.append(float(obj_a.per_case_scores[k]))
            vec_b.append(float(obj_b.per_case_scores[k]))

    at_least_as_good = all(a >= b - eps for a, b in zip(vec_a, vec_b, strict=True))
    strictly_better = any(a > b + eps for a, b in zip(vec_a, vec_b, strict=True))
    return at_least_as_good and strictly_better


@dataclass(frozen=True)
class ParetoCandidate:
    """Evaluated text-parameter candidate in the GEPA evolutionary pool."""

    candidate_id: str
    candidate: dict[str, str]
    objectives: ParetoObjectives
    side_info: tuple[ActionableSideInfo, ...] = ()
    parent_ids: tuple[str, ...] = ()
    reflection_rationale: str = ""
    security_report: CandidateSecurityReport = field(
        default_factory=lambda: CandidateSecurityReport(passed=True)
    )

    @property
    def candidate_sha256(self) -> str:
        """Deterministic SHA-256 digest of the candidate text parameters."""
        return _candidate_dict_sha256(self.candidate)


def compute_pareto_frontier(
    candidates: Sequence[ParetoCandidate],
    *,
    include_per_case: bool = True,
) -> list[ParetoCandidate]:
    """Return the subset of security-cleared, non-dominated :class:`ParetoCandidate` items.

    Preserves input order and deduplicates identical candidate text hashes.
    """
    valid_pool = [c for c in candidates if c.security_report.passed]
    frontier: list[ParetoCandidate] = []
    seen_hashes: set[str] = set()

    for idx, cand in enumerate(valid_pool):
        is_dominated = False
        for other_idx, other in enumerate(valid_pool):
            if idx == other_idx:
                continue
            if dominates(
                other.objectives,
                cand.objectives,
                include_per_case=include_per_case,
            ):
                is_dominated = True
                break
        if not is_dominated and cand.candidate_sha256 not in seen_hashes:
            seen_hashes.add(cand.candidate_sha256)
            frontier.append(cand)

    return frontier


# ---------------------------------------------------------------------------
# CageGEPAAdapter (Compatible with gepa.core.adapter.GEPAAdapter)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CageEvaluationBatch:
    """Batch evaluation result returned by :meth:`CageGEPAAdapter.evaluate` / :meth:`CageGEPAAdapter.evaluate_async`.

    Mirrors ``gepa.core.adapter.EvaluationBatch`` (``outputs``, ``scores``,
    ``trajectories``) while carrying CAGE's :class:`ParetoObjectives` and
    :class:`ActionableSideInfo` records.
    """

    outputs: list[str]
    scores: list[float]
    trajectories: list[ActionableSideInfo] | None
    objectives: ParetoObjectives


RolloutCallable = Callable[
    [Mapping[str, str], SkillEvalCase],
    ATIFTrajectory | Any,
]


class CageGEPAAdapter:
    """GEPA Adapter connecting :class:`FoundationModelEvalHarness` to reflective optimization.

    Implements the ``GEPAAdapter`` contract:
    * ``evaluate(batch, candidate, capture_traces=True)`` / ``evaluate_async(...)``
      -> :class:`CageEvaluationBatch`
    * ``make_reflective_dataset(candidate, eval_batch, components_to_update)``
      -> ``Mapping[str, Sequence[Mapping[str, Any]]]``
    """

    def __init__(
        self,
        harness: FoundationModelEvalHarness,
        rollout_fn: RolloutCallable,
        *,
        is_skill_markdown: bool = False,
        state_reducer: ShadowStateReducer | None = None,
        quadratic_growth_threshold: float = 2.5,
    ) -> None:
        self._harness = harness
        self._rollout_fn = rollout_fn
        self._is_skill_markdown = is_skill_markdown
        self._state_reducer = state_reducer
        self._quadratic_growth_threshold = quadratic_growth_threshold
        self._sanitizer = PIISanitizer()

    def evaluate(
        self,
        batch: Sequence[SkillEvalCase],
        candidate: Mapping[str, str],
        capture_traces: bool = True,
    ) -> CageEvaluationBatch:
        """Synchronously evaluate ``candidate`` across ``batch`` (``GEPAAdapter`` protocol)."""
        coro = self.evaluate_async(batch, candidate, capture_traces=capture_traces)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()

    async def evaluate_async(
        self,
        batch: Sequence[SkillEvalCase],
        candidate: Mapping[str, str],
        capture_traces: bool = True,
    ) -> CageEvaluationBatch:
        """Evaluate ``candidate`` across ``batch`` using :class:`FoundationModelEvalHarness`."""
        sec_report = _screen_candidate_mapping(
            candidate,
            is_skill_markdown=self._is_skill_markdown,
        )
        if not sec_report.passed:
            zero_scores = [0.0 for _ in batch]
            rejected_asi = [
                ActionableSideInfo(
                    case_id=c.case_id,
                    prompt=c.prompt,
                    score=0.0,
                    governor_cleared=False,
                    governor_violations=sec_report.violations,
                    drawback_reasons=sec_report.violations,
                )
                for c in batch
            ]
            return CageEvaluationBatch(
                outputs=["" for _ in batch],
                scores=zero_scores,
                trajectories=rejected_asi if capture_traces else None,
                objectives=ParetoObjectives(
                    quality_score=0.0,
                    admissibility_score=0.0,
                    security_score=0.0,
                    token_efficiency_score=0.0,
                    per_case_scores={c.case_id: 0.0 for c in batch},
                ),
            )

        outputs: list[str] = []
        scores: list[float] = []
        side_infos: list[ActionableSideInfo] = []
        quality_vals: list[float] = []
        admissibility_vals: list[float] = []
        security_vals: list[float] = []
        efficiency_vals: list[float] = []
        per_case: dict[str, float] = {}

        for case in batch:
            raw_traj = self._rollout_fn(candidate, case)
            trajectory: ATIFTrajectory = (
                await raw_traj if inspect.isawaitable(raw_traj) else raw_traj
            )

            tool_steps = trajectory.to_tool_action_steps()
            gov_report: TrajectoryBenchmarkReport | None = None
            narrowed_notes: list[str] = []
            gov_violations: list[str] = []
            if tool_steps and self._harness.has_governor:
                gov_report, triplets = await self._harness.evaluate_trajectory(
                    trajectory_id=trajectory.trajectory_id,
                    model_id=trajectory.model_id,
                    prompt=case.prompt,
                    steps=tool_steps,
                    initial_shadow_state=case.initial_shadow_state,
                    state_reducer=self._state_reducer,
                )
                for sr in gov_report.step_results:
                    if sr.reasons:
                        gov_violations.extend(sr.reasons)
                for tr in triplets:
                    if tr.reconciled_reasoning_note:
                        narrowed_notes.append(tr.reconciled_reasoning_note)

            scorecard: SkillTrajectoryScorecard = (
                await self._harness.score_atif_trajectory(
                    case,
                    trajectory,
                    state_reducer=self._state_reducer,
                    gov_report=gov_report,
                )
            )
            tokenomics: TrajectoryTokenomics = compute_trajectory_tokenomics(
                trajectory,
                quadratic_growth_threshold=self._quadratic_growth_threshold,
            )

            # Identify missing required tokens (affirmative check) & forbidden tools for ASI
            final_text = trajectory.final_response or ""
            missing_tokens = tuple(
                tok
                for tok in case.required_output_tokens
                if not _token_present_affirmatively(tok, final_text)
            )
            called_tools = {
                str(tc.get("name") or tc.get("tool") or "")
                for step in trajectory.steps
                for tc in step.tool_calls
            }
            forbidden_called = tuple(
                sorted(t for t in case.forbidden_tools if t in called_tools)
            )

            growth_excess = max(0.0, tokenomics.multi_turn_growth_rate - 1.0)
            tok_eff = round(
                1.0
                / (1.0 + 0.25 * growth_excess + 100.0 * tokenomics.estimated_cost_usd),
                4,
            )
            if tokenomics.is_quadratic_bloat:
                tok_eff = round(0.5 * tok_eff, 4)

            quality = round(
                (
                    scorecard.skill_execution
                    + scorecard.instruction_following
                    + scorecard.goal_accuracy
                )
                / 3.0,
                4,
            )
            admissibility = scorecard.admissibility_prm
            security = scorecard.security

            outputs.append(final_text)
            scores.append(scorecard.composite_score)
            per_case[case.case_id] = scorecard.composite_score
            quality_vals.append(quality)
            admissibility_vals.append(admissibility)
            security_vals.append(security)
            efficiency_vals.append(tok_eff)

            side_infos.append(
                ActionableSideInfo(
                    case_id=case.case_id,
                    prompt=case.prompt,
                    score=scorecard.composite_score,
                    governor_cleared=(
                        gov_report.trajectory_cleared
                        if gov_report is not None
                        else True
                    ),
                    governor_violations=tuple(dict.fromkeys(gov_violations)),
                    narrowed_notes=tuple(narrowed_notes),
                    drawback_reasons=scorecard.drawback_reasons,
                    missing_output_tokens=missing_tokens,
                    forbidden_tools_called=forbidden_called,
                    token_growth_rate=tokenomics.multi_turn_growth_rate,
                    estimated_cost_usd=tokenomics.estimated_cost_usd,
                    is_quadratic_bloat=tokenomics.is_quadratic_bloat,
                    generated_output=final_text,
                )
            )

        n = max(1, len(batch))
        objectives = ParetoObjectives(
            quality_score=round(sum(quality_vals) / n, 4),
            admissibility_score=round(sum(admissibility_vals) / n, 4),
            security_score=round(sum(security_vals) / n, 4),
            token_efficiency_score=round(sum(efficiency_vals) / n, 4),
            per_case_scores=per_case,
        )
        return CageEvaluationBatch(
            outputs=outputs,
            scores=scores,
            trajectories=side_infos if capture_traces else None,
            objectives=objectives,
        )

    def make_reflective_dataset(
        self,
        candidate: Mapping[str, str],
        eval_batch: CageEvaluationBatch,
        components_to_update: Sequence[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Build a PII-scrubbed reflective dataset keyed by component name for GEPA."""
        records: list[dict[str, Any]] = []
        for idx, asi in enumerate(eval_batch.trajectories or ()):
            rec = asi.to_reflective_dict(sanitizer=self._sanitizer)
            batch_out = (
                eval_batch.outputs[idx]
                if idx < len(eval_batch.outputs) and eval_batch.outputs[idx]
                else asi.generated_output
            )
            rec["Generated Outputs"] = self._sanitizer.sanitize(batch_out)
            records.append(rec)

        return {comp: list(records) for comp in components_to_update}


# ---------------------------------------------------------------------------
# Presidio / spaCy PII Rule & Threshold GEPA Evaluator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PIIRedactionEvalSample:
    """Labeled sample for optimizing Presidio/spaCy PII configuration via GEPA.

    * ``sample_id``: Unique identifier for Pareto per-case tracking.
    * ``text``: Raw input text (e.g., financial query with or without identity PII).
    * ``expected_entities``: Entity types that MUST be detected/redacted (e.g., ``("US_SSN",)``).
    * ``must_not_contain``: Sensitive substrings that MUST NOT survive in redacted text.
    * ``must_preserve``: Benign domain substrings (e.g., ``("US equities", "22 October", "ESCALATE")``)
      that MUST NOT be mangled by over-aggressive NER redaction.
    """

    sample_id: str
    text: str
    expected_entities: tuple[str, ...] = ()
    must_not_contain: tuple[str, ...] = ()
    must_preserve: tuple[str, ...] = ()


class PresidioPIIOptimizationEvaluator:
    """GEPA Evaluator for tuning Presidio/spaCy PII redaction parameters.

    Since `spaCy` (`en_core_web_lg` / `en_core_web_sm`) in `src/integrations/presidio/redactor.py`
    is a statistical NER pipeline rather than a prompt-driven LLM, GEPA optimizes
    the JSON configuration governing Presidio's analyzer/redaction layer:
    * ``score_threshold``: Confidence cutoff in `[0.1, 0.95]`.
    * ``active_entities``: Subset of entity types enabled for redaction.
    * ``allow_list``: Domain terms (e.g. financial tickers, governance verdicts)
      exempted from false-positive NER redaction.
    """

    def __init__(
        self,
        samples: Sequence[PIIRedactionEvalSample],
        *,
        custom_redactor_fn: (
            Callable[[str, float, Sequence[str], Sequence[str]], tuple[str, list[str]]]
            | None
        ) = None,
    ) -> None:
        if not samples:
            raise ValueError(
                "PresidioPIIOptimizationEvaluator requires at least one sample"
            )
        self._samples = tuple(samples)
        self._custom_redactor_fn = custom_redactor_fn

    def _run_redaction(
        self,
        text: str,
        score_threshold: float,
        active_entities: Sequence[str],
        allow_list: Sequence[str],
    ) -> tuple[str, list[str]]:
        if self._custom_redactor_fn is not None:
            return self._custom_redactor_fn(
                text, score_threshold, active_entities, allow_list
            )
        from src.integrations.presidio.redactor import (
            _PII_ENTITIES,
            get_presidio_engines,
        )

        analyzer, anonymizer = get_presidio_engines()
        if analyzer is None or anonymizer is None:
            # Fallback to deterministic regex sanitizer when spaCy/Presidio is not installed
            sanitized = PIISanitizer().sanitize(text)
            detected: list[str] = []
            token_map = (
                ("[REDACTED_SSN]", "US_SSN"),
                ("[REDACTED_EMAIL]", "EMAIL_ADDRESS"),
                ("[REDACTED_PHONE]", "PHONE_NUMBER"),
                ("[REDACTED_CC]", "CREDIT_CARD"),
                ("[REDACTED_KEY]", "API_KEY"),
                ("[REDACTED_SWIFT]", "IBAN_CODE"),
            )
            for marker, entity_name in token_map:
                if marker in sanitized and marker not in text:
                    if not active_entities or entity_name in active_entities:
                        detected.append(entity_name)
            if not detected and sanitized != text:
                detected.append("PII_SANITIZED")
            return sanitized, detected

        entities = list(active_entities) if active_entities else list(_PII_ENTITIES)
        results = analyzer.analyze(
            text=text,
            entities=entities,
            language="en",
            score_threshold=score_threshold,
            allow_list=list(allow_list) if allow_list else None,
        )
        filtered = [r for r in results if r.score >= score_threshold]
        if not filtered:
            return text, []
        entity_types = sorted({r.entity_type for r in filtered})
        from presidio_anonymizer.entities import OperatorConfig

        anonymized = anonymizer.anonymize(
            text=text,
            analyzer_results=filtered,
            operators={
                et: OperatorConfig("replace", {"new_value": f"<{et}>"})
                for et in entity_types
            },
        )
        return anonymized.text, entity_types

    def evaluate_config_candidate(
        self, candidate_json: str
    ) -> tuple[ParetoObjectives, list[ActionableSideInfo]]:
        """Evaluate a JSON config candidate across the PII sample corpus."""
        sec_report = screen_candidate_security(candidate_json)
        if not sec_report.passed:
            return (
                ParetoObjectives(0.0, 0.0, 0.0, 0.0),
                [
                    ActionableSideInfo(
                        case_id="config_parse",
                        prompt="candidate_json",
                        score=0.0,
                        governor_cleared=False,
                        governor_violations=sec_report.violations,
                    )
                ],
            )

        try:
            parsed = json.loads(candidate_json)
            if not isinstance(parsed, Mapping):
                raise ValueError("Candidate JSON must be an object")
            score_threshold = float(parsed.get("score_threshold", 0.35))
            if not (0.05 <= score_threshold <= 0.99):
                raise ValueError("score_threshold must be in [0.05, 0.99]")
            raw_entities = parsed.get("active_entities", [])
            if not isinstance(raw_entities, Sequence) or isinstance(
                raw_entities, (str, bytes)
            ):
                raise ValueError("active_entities must be a JSON array of strings")
            active_entities = [str(e) for e in raw_entities]

            raw_allow = parsed.get("allow_list", [])
            if not isinstance(raw_allow, Sequence) or isinstance(
                raw_allow, (str, bytes)
            ):
                raise ValueError("allow_list must be a JSON array of strings")
            allow_list = [str(w) for w in raw_allow]
        except Exception as exc:
            return (
                ParetoObjectives(0.0, 0.0, 0.0, 0.0),
                [
                    ActionableSideInfo(
                        case_id="config_parse",
                        prompt="candidate_json",
                        score=0.0,
                        governor_cleared=False,
                        extra_diagnostics=(f"Invalid config JSON: {exc}",),
                    )
                ],
            )

        recall_scores: list[float] = []
        preservation_scores: list[float] = []
        per_case: dict[str, float] = {}
        side_infos: list[ActionableSideInfo] = []
        sanitizer = PIISanitizer()

        for sample in self._samples:
            redacted_text, detected_entities = self._run_redaction(
                sample.text, score_threshold, active_entities, allow_list
            )
            diagnostics: list[str] = []

            # 1. PII Recall (did we redact all expected entities & forbidden raw strings?)
            missed_entities = [
                e for e in sample.expected_entities if e not in detected_entities
            ]
            leaked_raw = [
                s for s in sample.must_not_contain if s and s in redacted_text
            ]
            if sample.expected_entities or sample.must_not_contain:
                total_checks = len(sample.expected_entities) + len(
                    sample.must_not_contain
                )
                failed_checks = len(missed_entities) + len(leaked_raw)
                sample_recall = max(0.0, (total_checks - failed_checks) / total_checks)
            else:
                sample_recall = 1.0

            if missed_entities:
                diagnostics.append(f"Missed PII entities: {missed_entities}")
            if leaked_raw:
                diagnostics.append(
                    f"Leaked sensitive substrings count={len(leaked_raw)}"
                )

            # 2. Financial Text Preservation (did we preserve benign terms like 'US equities'?)
            mangled_terms = [
                term for term in sample.must_preserve if term not in redacted_text
            ]
            if sample.must_preserve:
                sample_preservation = max(
                    0.0,
                    (len(sample.must_preserve) - len(mangled_terms))
                    / len(sample.must_preserve),
                )
            else:
                sample_preservation = (
                    1.0 if (sample.expected_entities or not detected_entities) else 0.0
                )

            if mangled_terms:
                diagnostics.append(
                    f"False-positive mangled financial terms: {mangled_terms}"
                )

            sample_score = round(0.6 * sample_recall + 0.4 * sample_preservation, 4)
            recall_scores.append(sample_recall)
            preservation_scores.append(sample_preservation)
            per_case[sample.sample_id] = sample_score

            # Scrub explicit must_not_contain substrings (e.g. PERSON names not matched by regex)
            # before constructing ActionableSideInfo so raw PII never enters reflection prompts
            scrubbed_prompt = sample.text
            scrubbed_output = redacted_text
            for sensitive in sample.must_not_contain:
                if sensitive:
                    scrubbed_prompt = scrubbed_prompt.replace(sensitive, "<REDACTED>")
                    scrubbed_output = scrubbed_output.replace(sensitive, "<REDACTED>")
            scrubbed_prompt = sanitizer.sanitize(scrubbed_prompt)
            scrubbed_output = sanitizer.sanitize(scrubbed_output)

            side_infos.append(
                ActionableSideInfo(
                    case_id=sample.sample_id,
                    prompt=scrubbed_prompt,
                    score=sample_score,
                    governor_cleared=(sample_recall == 1.0),
                    extra_diagnostics=tuple(diagnostics),
                    generated_output=scrubbed_output,
                )
            )

        n = len(self._samples)
        mean_recall = round(sum(recall_scores) / n, 4)
        mean_preservation = round(sum(preservation_scores) / n, 4)
        objectives = ParetoObjectives(
            quality_score=mean_preservation,
            admissibility_score=mean_recall,
            security_score=mean_recall,
            token_efficiency_score=1.0,
            per_case_scores=per_case,
        )
        return objectives, side_infos


# ---------------------------------------------------------------------------
# GEPA Reflective Evolution Loop & Optional Upstream Bridge
# ---------------------------------------------------------------------------


class ReflectiveMutatorProtocol(Protocol):
    """Protocol for an LLM or deterministic reflective mutator in GEPA."""

    def propose_mutation(
        self,
        parent: ParetoCandidate,
        reflective_records: Sequence[Mapping[str, Any]],
        components_to_update: Sequence[str],
    ) -> dict[str, str]:
        """Propose an improved candidate mapping based on parent + reflective ASI."""
        ...


@dataclass(frozen=True)
class GEPAOptimizationResult:
    """Result returned by :class:`GEPAEvolutionEngine`."""

    best_candidate: ParetoCandidate
    pareto_frontier: tuple[ParetoCandidate, ...]
    all_candidates: tuple[ParetoCandidate, ...]
    rejected_unsafe_count: int
    total_metric_calls: int


class GEPAEvolutionEngine:
    """Offline Genetic-Pareto (GEPA) reflective optimization loop for CAGE.

    Executes the 5-step GEPA cycle:
    1. **Select** a candidate from the current Pareto frontier (rotating across
       frontier members that excel on different task subsets).
    2. **Execute** on the evaluation batch, capturing full CAGE Actionable Side
       Information (ASI).
    3. **Reflect** on failure traces (`make_reflective_dataset`).
    4. **Mutate** via ``ReflectiveMutatorProtocol`` (and optionally perform
       system-aware merge across complementary multi-component Pareto candidates).
    5. **Screen & Accept** if the candidate passes Stage 0 security checks and
       updates the Pareto frontier.
    """

    def __init__(
        self,
        adapter: CageGEPAAdapter,
        mutator: ReflectiveMutatorProtocol,
        *,
        is_skill_markdown: bool = False,
    ) -> None:
        self._adapter = adapter
        self._mutator = mutator
        self._is_skill_markdown = is_skill_markdown

    async def _evaluate_candidate_splits(
        self,
        candidate: Mapping[str, str],
        train_cases: tuple[SkillEvalCase, ...],
        val_cases: tuple[SkillEvalCase, ...] | None,
    ) -> tuple[ParetoObjectives, tuple[ActionableSideInfo, ...], int]:
        """Evaluate ``candidate`` on ``train_cases`` (for reflection ASI) and ``val_cases`` (for Pareto objectives)."""
        train_batch = await self._adapter.evaluate_async(
            train_cases, candidate, capture_traces=True
        )
        calls = len(train_cases)
        side_info = tuple(train_batch.trajectories or ())
        if val_cases is None:
            return train_batch.objectives, side_info, calls

        val_batch = await self._adapter.evaluate_async(
            val_cases, candidate, capture_traces=False
        )
        calls += len(val_cases)
        return val_batch.objectives, side_info, calls

    async def optimize(
        self,
        *,
        seed_candidate: Mapping[str, str],
        trainset: Sequence[SkillEvalCase],
        valset: Sequence[SkillEvalCase] | None = None,
        max_iterations: int = 5,
        enable_system_aware_merge: bool = True,
    ) -> GEPAOptimizationResult:
        """Run reflective Pareto evolution starting from ``seed_candidate``."""
        if not trainset:
            raise ValueError(
                "GEPAEvolutionEngine.optimize requires a non-empty trainset"
            )
        if valset is not None and not valset:
            raise ValueError(
                "GEPAEvolutionEngine.optimize requires a non-empty valset when provided"
            )
        train_cases = tuple(trainset)
        val_cases = tuple(valset) if valset is not None else None
        components = tuple(seed_candidate.keys())

        seed_dict = {str(k): str(v) for k, v in seed_candidate.items()}
        seed_sec = _screen_candidate_mapping(
            seed_dict,
            is_skill_markdown=self._is_skill_markdown,
        )
        if not seed_sec.passed:
            raise ValueError(
                f"seed_candidate failed Stage 0 security screening: {seed_sec.violations}"
            )

        metric_calls = 0
        rejected_unsafe = 0

        (
            seed_objectives,
            seed_side_info,
            seed_calls,
        ) = await self._evaluate_candidate_splits(seed_dict, train_cases, val_cases)
        metric_calls += seed_calls
        seed_entry = ParetoCandidate(
            candidate_id="cand-0",
            candidate=seed_dict,
            objectives=seed_objectives,
            side_info=seed_side_info,
            parent_ids=(),
            reflection_rationale="seed_candidate",
            security_report=seed_sec,
        )

        pool: list[ParetoCandidate] = [seed_entry]
        frontier: list[ParetoCandidate] = [seed_entry]
        seen_hashes: set[str] = {seed_entry.candidate_sha256}

        for step_idx in range(1, max_iterations + 1):
            parent = frontier[(step_idx - 1) % len(frontier)]
            parent_batch = CageEvaluationBatch(
                outputs=[asi.generated_output for asi in parent.side_info],
                scores=[asi.score for asi in parent.side_info],
                trajectories=list(parent.side_info),
                objectives=parent.objectives,
            )
            reflective_ds = self._adapter.make_reflective_dataset(
                parent.candidate, parent_batch, components
            )
            flat_records = reflective_ds.get(components[0], []) if components else []

            proposed_raw = self._mutator.propose_mutation(
                parent, flat_records, components
            )
            proposed = {
                str(k): str(proposed_raw.get(k, parent.candidate[k]))
                for k in components
            }

            sec_report = _screen_candidate_mapping(
                proposed,
                is_skill_markdown=self._is_skill_markdown,
            )
            if not sec_report.passed:
                rejected_unsafe += 1
                continue

            proposed_hash = _candidate_dict_sha256(proposed)
            if proposed_hash not in seen_hashes:
                seen_hashes.add(proposed_hash)
                cand_obj, cand_asi, cand_calls = await self._evaluate_candidate_splits(
                    proposed, train_cases, val_cases
                )
                metric_calls += cand_calls
                new_cand = ParetoCandidate(
                    candidate_id=f"cand-{step_idx}",
                    candidate=proposed,
                    objectives=cand_obj,
                    side_info=cand_asi,
                    parent_ids=(parent.candidate_id,),
                    reflection_rationale=f"mutated_from:{parent.candidate_id}",
                    security_report=sec_report,
                )
                pool.append(new_cand)
                frontier = compute_pareto_frontier(pool)

            # Optional system-aware merge when candidate has >= 2 text components
            # and the Pareto frontier has >= 2 complementary candidates
            if (
                enable_system_aware_merge
                and len(components) >= 2
                and len(frontier) >= 2
            ):
                cand_a, cand_b = frontier[0], frontier[-1]
                if cand_a.candidate_sha256 != cand_b.candidate_sha256:
                    merged_dict: dict[str, str] = {}
                    for comp_i, comp_name in enumerate(components):
                        merged_dict[comp_name] = (
                            cand_a.candidate[comp_name]
                            if comp_i % 2 == 0
                            else cand_b.candidate[comp_name]
                        )
                    merged_hash = _candidate_dict_sha256(merged_dict)
                    if merged_hash not in seen_hashes:
                        merge_sec = _screen_candidate_mapping(
                            merged_dict,
                            is_skill_markdown=self._is_skill_markdown,
                        )
                        if merge_sec.passed:
                            seen_hashes.add(merged_hash)
                            (
                                merge_obj,
                                merge_asi,
                                merge_calls,
                            ) = await self._evaluate_candidate_splits(
                                merged_dict, train_cases, val_cases
                            )
                            metric_calls += merge_calls
                            merged_cand = ParetoCandidate(
                                candidate_id=f"cand-{step_idx}-merge",
                                candidate=merged_dict,
                                objectives=merge_obj,
                                side_info=merge_asi,
                                parent_ids=(cand_a.candidate_id, cand_b.candidate_id),
                                reflection_rationale=(
                                    f"system_aware_merge({cand_a.candidate_id},{cand_b.candidate_id})"
                                ),
                                security_report=merge_sec,
                            )
                            pool.append(merged_cand)
                            frontier = compute_pareto_frontier(pool)

        best = max(
            frontier,
            key=lambda c: (
                c.objectives.scalarized_score,
                c.objectives.admissibility_score,
                c.objectives.security_score,
            ),
        )
        return GEPAOptimizationResult(
            best_candidate=best,
            pareto_frontier=tuple(frontier),
            all_candidates=tuple(pool),
            rejected_unsafe_count=rejected_unsafe,
            total_metric_calls=metric_calls,
        )


def run_gepa_optimize_anything(
    *,
    seed_candidate: str,
    evaluator_fn: Callable[[str], tuple[float, Sequence[ActionableSideInfo]]],
    objective: str,
    max_metric_calls: int = 50,
    is_skill_markdown: bool = False,
) -> Any:
    """Bridge CAGE's evaluator + ASI logs directly into ``gepa.optimize_anything``.

    Requires the optional ``gepa`` package (`pip install gepa`). Raises
    ``RuntimeError`` with installation instructions if ``gepa`` is not installed.
    """
    try:
        oa = importlib.import_module("gepa.optimize_anything")
    except ImportError as exc:
        raise RuntimeError(
            "Optional package 'gepa' is not installed. Install it in your offline "
            "evaluation environment via `uv pip install gepa` or use "
            "`GEPAEvolutionEngine` for hermetic offline optimization."
        ) from exc

    sanitizer = PIISanitizer()

    def _wrapped_evaluator(candidate: str) -> float:
        sec = screen_candidate_security(candidate, is_skill_markdown=is_skill_markdown)
        if not sec.passed:
            oa.log(f"Security Gate Rejected Candidate: {', '.join(sec.violations)}")
            return 0.0
        score, side_infos = evaluator_fn(candidate)
        for asi in side_infos:
            oa.log(asi.to_reflective_text(sanitizer=sanitizer))
        return float(score)

    config_cls = getattr(oa, "GEPAConfig", None)
    engine_cls = getattr(oa, "EngineConfig", None)
    kwargs: dict[str, Any] = {
        "seed_candidate": seed_candidate,
        "evaluator": _wrapped_evaluator,
        "objective": objective,
    }
    if config_cls is not None and engine_cls is not None:
        kwargs["config"] = config_cls(
            engine=engine_cls(max_metric_calls=max_metric_calls)
        )
    return oa.optimize_anything(**kwargs)


__all__ = [
    "ActionableSideInfo",
    "CageEvaluationBatch",
    "CageGEPAAdapter",
    "CandidateSecurityReport",
    "GEPAEvolutionEngine",
    "GEPAOptimizationResult",
    "PIIRedactionEvalSample",
    "ParetoCandidate",
    "ParetoObjectives",
    "PresidioPIIOptimizationEvaluator",
    "ReflectiveMutatorProtocol",
    "compute_pareto_frontier",
    "dominates",
    "run_gepa_optimize_anything",
    "screen_candidate_security",
]
