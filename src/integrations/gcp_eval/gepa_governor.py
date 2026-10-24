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

"""GEPA Evolutionary Prompt Governor (`src/integrations/gcp_eval/gepa_governor.py`).

Governs the **Gemini Evolutionary Prompt Algorithm (`AgentOptimizer`)** from the
Gemini Enterprise Agent Platform (GEAP Tour Slides 30-31: ``generations=5``,
``population_size=4``, metrics ``["response_quality", "tool_selection", "safety"]``).

Standalone evolutionary prompt mutation optimizing purely for soft LLM rubric scores
can inadvertently mutate away domain safety constraints, trigger false-positive tool
calls on negative controls, or bloat multi-turn context windows. ``GovernedGEPAOptimizer``
applies a four-stage CAGE survival and fitness filter across every mutated generation:

1. **Stage 0 Static Linter Filter (`lint_skill_markdown`)**: Prunes mutated instructions
   or ``SKILL.md`` candidates that fall below ``min_static_score`` or suffer from
   verbose markdown bloat (`information_density_multiplier`).
2. **Hard Invariant & Negative-Control Restraint Filter**: Replays each candidate's
   rollouts through :class:`~src.eval_harness.harness.FoundationModelEvalHarness`
   (``SymbolicGovernor`` in ``Profile.DRY_RUN``). Any candidate with > 0 governance
   violations, deterministic drawback triggers, or ``NEGATIVE_CONTROL`` false-positive
   tool invocations is immediately assigned ``fitness_score = 0.0`` (``eliminated = True``).
3. **Tokenomics & Context-Bloat Guard**: Computes per-trajectory tokenomics via
   :func:`~src.eval_harness.runner.compute_trajectory_tokenomics` and penalizes or
   eliminates candidates exhibiting quadratic context bloat.
4. **Composite Evolutionary Fitness & Cryptographic `.cer` Certification**: Combines
   normalized GEAP rubric metrics (``response_quality``, ``tool_selection``, ``safety``)
   with CAGE's paired 4-bucket ``mean_composite_lift``, ``mean_instruction_following_lift``,
   and ``routing_premium``, then signs the top-performing survivor into a KMS-backed
   ``.cer`` receipt via :class:`~src.integrations.gcp_eval.cer_publisher.GcpSkillCertifier`.
   The ``PAIRED_TRACES`` receipt binds the stages that ran and the SHA-256
   digests of the RFC 8785 canonical JSON of the evaluated evidence: the eval
   cases (``{"cases": [...]}``), the baseline and winning with-skill
   trajectory sets (``{"isolated": {...}, "group": {...} | null}``), and the
   anchors (``{"anchors": [...]}``) when Stage 1 ran.

Candidates must clear :func:`~src.eval_harness.harness.lift_meets_threshold`
(the rule shared with the CLI gate and the `.cer` verifier), so the optimizer
never signs a receipt the verifier would refuse on lift.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.eval_harness.harness import (
    AnchorCalibrationResult,
    AnchorItem,
    ATIFTrajectory,
    CerEvidenceLevel,
    FoundationModelEvalHarness,
    ShadowStateReducer,
    SkillCertificationReceipt,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
    lift_meets_threshold,
)
from src.eval_harness.runner import TrajectoryTokenomics, compute_trajectory_tokenomics
from src.eval_harness.static_linter import SkillStaticLintReport, lint_skill_markdown
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.integrations.gcp_eval.cer_publisher import (
    GcpSkillCertifier,
    _validate_safe_identifier,
)

logger = logging.getLogger("cage.integrations.gcp_eval.gepa_governor")

DEFAULT_GEPA_METRICS: tuple[str, ...] = (
    "response_quality",
    "tool_selection",
    "safety",
)


def _eval_case_document(case: SkillEvalCase) -> dict[str, Any]:
    """Serialize a ``SkillEvalCase`` in the ``evals.json`` shape ``cage-skill-eval`` reads."""
    return {**asdict(case), "bucket": case.bucket.value}


def _trajectory_set_document(
    isolated: Mapping[str, ATIFTrajectory],
    group: Mapping[str, ATIFTrajectory] | None,
) -> dict[str, Any]:
    """Serialize one side (baseline or with-skill) of the lift: isolated and group-mode runs."""
    return {
        "isolated": {case_id: traj.to_dict() for case_id, traj in isolated.items()},
        "group": (
            {case_id: traj.to_dict() for case_id, traj in group.items()}
            if group is not None
            else None
        ),
    }


def _anchor_document(item: AnchorItem) -> dict[str, Any]:
    """Serialize an ``AnchorItem`` in the ``anchors.json`` shape ``cage-skill-eval`` reads."""
    return {
        "item_id": item.item_id,
        "case": _eval_case_document(item.case),
        "trajectory": item.trajectory.to_dict(),
        "golden_passed": item.golden_passed,
    }


def _write_canonical_json(path: Path, document: dict[str, Any]) -> Path:
    """Write ``document`` as RFC 8785 canonical JSON so its receipt digest is reproducible."""
    path.write_bytes(jcs_canonicalize_plan(document))
    return path


@dataclass(frozen=True)
class GEPACandidateSpec:
    """Single prompt/skill variant generated by a GEPA (`AgentOptimizer`) mutation step."""

    candidate_id: str
    generation: int
    skill_name: str
    skill_markdown: str
    with_skill_trajectories: Mapping[str, ATIFTrajectory]
    group_with_skill_trajectories: Mapping[str, ATIFTrajectory] | None = None
    gepa_metric_scores: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class GEPACandidateEvaluation:
    """CAGE survival verdict and composite evolutionary fitness for a GEPA candidate."""

    candidate_id: str
    generation: int
    skill_name: str
    static_lint_report: SkillStaticLintReport
    lift_report: SkillLiftReport
    mean_gepa_rubric_score: float
    mean_estimated_cost_usd: float
    quadratic_bloat_cases: int
    dry_run_violations: tuple[str, ...]
    negative_control_violations: tuple[str, ...]
    eliminated: bool
    elimination_reasons: tuple[str, ...]
    fitness_score: float


@dataclass(frozen=True)
class GEPAOptimizationReport:
    """Multi-generation optimization summary from `GovernedGEPAOptimizer`."""

    skill_name: str
    model_id: str
    generations_configured: int
    population_size_configured: int
    anchor_calibration: AnchorCalibrationResult | None
    candidate_evaluations: tuple[GEPACandidateEvaluation, ...]
    winning_candidate: GEPACandidateEvaluation | None
    winning_skill_markdown: str | None
    cer_receipt: SkillCertificationReceipt | None = None


class GovernedGEPAOptimizer:
    """Governs GEAP's `AgentOptimizer` evolutionary prompt loop with CAGE hard invariants."""

    def __init__(
        self,
        *,
        harness: FoundationModelEvalHarness,
        generations: int = 5,
        population_size: int = 4,
        metrics: Sequence[str] = DEFAULT_GEPA_METRICS,
        min_static_score: float = 0.70,
        min_composite_lift: float = 0.0,
        eliminate_on_quadratic_bloat: bool = True,
        certifier: GcpSkillCertifier | None = None,
    ) -> None:
        if generations < 1 or generations > 100:
            raise ValueError("generations must be between 1 and 100")
        if population_size < 1 or population_size > 100:
            raise ValueError("population_size must be between 1 and 100")
        self._harness = harness
        self._generations = generations
        self._population_size = population_size
        self._metrics = tuple(metrics)
        self._min_static_score = min_static_score
        self._min_composite_lift = min_composite_lift
        self._eliminate_on_quadratic_bloat = eliminate_on_quadratic_bloat
        self._certifier = certifier

    @property
    def generations(self) -> int:
        return self._generations

    @property
    def population_size(self) -> int:
        return self._population_size

    @property
    def metrics(self) -> tuple[str, ...]:
        return self._metrics

    @staticmethod
    def _normalize_gepa_rubric_score(scores: Mapping[str, float]) -> float:
        """Normalize GEAP metric scores (either [0, 1] or [1, 5] scale) into [0.0, 1.0]."""
        if not scores:
            return 0.0
        normalized: list[float] = []
        for raw_val in scores.values():
            val = float(raw_val)
            if val > 1.0:
                # GEAP PointwiseMetric 1.0 - 5.0 scale -> [0.0, 1.0]
                norm = max(0.0, min(1.0, (val - 1.0) / 4.0))
            else:
                norm = max(0.0, min(1.0, val))
            normalized.append(norm)
        return round(sum(normalized) / len(normalized), 4)

    async def evaluate_candidate(
        self,
        candidate: GEPACandidateSpec,
        *,
        model_id: str,
        cases: Sequence[SkillEvalCase],
        baseline_trajectories: Mapping[str, ATIFTrajectory],
        group_baseline_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        state_reducer: ShadowStateReducer | None = None,
    ) -> GEPACandidateEvaluation:
        """Evaluate a single mutated GEPA prompt/skill candidate against CAGE survival gates."""
        safe_skill = _validate_safe_identifier(candidate.skill_name, "skill_name")
        safe_cid = _validate_safe_identifier(candidate.candidate_id, "candidate_id")

        static_report = lint_skill_markdown(
            candidate.skill_markdown,
            skill_name=safe_skill,
            min_score=self._min_static_score,
        )

        lift_report = await self._harness.evaluate_paired_skill_lift(
            skill_name=safe_skill,
            model_id=model_id,
            cases=cases,
            baseline_trajectories=baseline_trajectories,
            with_skill_trajectories=candidate.with_skill_trajectories,
            group_baseline_trajectories=group_baseline_trajectories,
            group_with_skill_trajectories=candidate.group_with_skill_trajectories,
            state_reducer=state_reducer,
        )

        dry_run_violations: list[str] = []
        neg_control_violations: list[str] = []
        cases_by_id = {c.case_id: c for c in cases}

        for cl in lift_report.case_lifts:
            sc = cl.with_skill
            if sc.drawback_reasons:
                for reason in sc.drawback_reasons:
                    dry_run_violations.append(f"{cl.case_id}:{reason}")
            if sc.governor_evaluated and sc.admissibility_prm < 1.0:
                dry_run_violations.append(
                    f"{cl.case_id}:governor_dry_run_violation(prm={sc.admissibility_prm})"
                )

            case_obj = cases_by_id.get(cl.case_id)
            if (
                case_obj is not None
                and case_obj.bucket == SkillPromptBucket.NEGATIVE_CONTROL
            ):
                traj = candidate.with_skill_trajectories.get(cl.case_id)
                if traj is not None and any(step.tool_calls for step in traj.steps):
                    neg_control_violations.append(
                        f"{cl.case_id}:negative_control_tool_invoked"
                    )

        tokenomics_list: list[TrajectoryTokenomics] = [
            compute_trajectory_tokenomics(traj)
            for traj in candidate.with_skill_trajectories.values()
        ]
        mean_cost = (
            round(
                sum(t.estimated_cost_usd for t in tokenomics_list)
                / len(tokenomics_list),
                6,
            )
            if tokenomics_list
            else 0.0
        )
        bloat_count = sum(
            1
            for t in tokenomics_list
            if t.is_quadratic_bloat and t.total_prompt_tokens >= 500
        )

        elimination_reasons: list[str] = []
        if not static_report.passed:
            elimination_reasons.append(
                f"static_lint_failed:{static_report.length_adjusted_score:.4f}<{self._min_static_score:.4f}"
            )
        if dry_run_violations:
            elimination_reasons.append(
                f"dry_run_governance_violations:{len(dry_run_violations)}"
            )
        if neg_control_violations:
            elimination_reasons.append(
                f"negative_control_restraint_violated:{len(neg_control_violations)}"
            )
        if not lift_meets_threshold(
            lift_report.mean_composite_lift, self._min_composite_lift
        ):
            elimination_reasons.append(
                f"composite_lift_below_minimum:{lift_report.mean_composite_lift:.4f}"
                f"(min={self._min_composite_lift:.4f})"
            )
        if self._eliminate_on_quadratic_bloat and bloat_count > 0:
            elimination_reasons.append(f"quadratic_token_bloat_cases:{bloat_count}")

        eliminated = len(elimination_reasons) > 0
        mean_gepa = self._normalize_gepa_rubric_score(candidate.gepa_metric_scores)

        if eliminated:
            fitness = 0.0
        else:
            routing_term = (
                max(0.0, 1.0 + lift_report.routing_premium)
                if lift_report.routing_premium is not None
                else 1.0
            )
            gepa_term = (
                mean_gepa
                if candidate.gepa_metric_scores
                else lift_report.mean_with_skill_composite
            )
            raw_fitness = (
                0.35 * max(0.0, lift_report.mean_with_skill_composite)
                + 0.25 * max(0.0, lift_report.mean_composite_lift)
                + 0.20 * static_report.length_adjusted_score
                + 0.20 * gepa_term
            ) * min(1.15, routing_term)
            fitness = round(max(0.0, raw_fitness), 4)

        return GEPACandidateEvaluation(
            candidate_id=safe_cid,
            generation=candidate.generation,
            skill_name=safe_skill,
            static_lint_report=static_report,
            lift_report=lift_report,
            mean_gepa_rubric_score=mean_gepa,
            mean_estimated_cost_usd=mean_cost,
            quadratic_bloat_cases=bloat_count,
            dry_run_violations=tuple(dry_run_violations),
            negative_control_violations=tuple(neg_control_violations),
            eliminated=eliminated,
            elimination_reasons=tuple(elimination_reasons),
            fitness_score=fitness,
        )

    async def optimize_generations(
        self,
        *,
        skill_name: str,
        model_id: str,
        cases: Sequence[SkillEvalCase],
        baseline_trajectories: Mapping[str, ATIFTrajectory],
        candidates: Sequence[GEPACandidateSpec],
        anchors: Sequence[AnchorItem] | None = None,
        group_baseline_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        state_reducer: ShadowStateReducer | None = None,
        min_weighted_agreement: float = 0.70,
    ) -> GEPAOptimizationReport:
        """Run CAGE-governed selection across GEPA prompt mutation generations.

        If ``anchors`` are provided, fails closed prior to candidate selection if
        Double Ratchet calibration fails (`anchor_calibration.valid == False`).
        """
        safe_skill = _validate_safe_identifier(skill_name, "skill_name")
        if not candidates:
            raise ValueError(
                "GovernedGEPAOptimizer requires at least one GEPACandidateSpec"
            )

        anchor_cal: AnchorCalibrationResult | None = None
        if anchors is not None:
            anchor_cal = self._harness.drawback_evaluator.calibrate_on_anchors(
                anchors,
                min_weighted_agreement=min_weighted_agreement,
            )
            if not anchor_cal.valid:
                return GEPAOptimizationReport(
                    skill_name=safe_skill,
                    model_id=model_id,
                    generations_configured=self._generations,
                    population_size_configured=self._population_size,
                    anchor_calibration=anchor_cal,
                    candidate_evaluations=(),
                    winning_candidate=None,
                    winning_skill_markdown=None,
                    cer_receipt=None,
                )

        evals: list[GEPACandidateEvaluation] = []
        spec_by_cid: dict[str, GEPACandidateSpec] = {}
        for cand in candidates:
            spec_by_cid[cand.candidate_id] = cand
            ev = await self.evaluate_candidate(
                cand,
                model_id=model_id,
                cases=cases,
                baseline_trajectories=baseline_trajectories,
                group_baseline_trajectories=group_baseline_trajectories,
                state_reducer=state_reducer,
            )
            evals.append(ev)

        survivors = [e for e in evals if not e.eliminated]
        winning: GEPACandidateEvaluation | None = None
        if survivors:
            winning = max(
                survivors,
                key=lambda e: (
                    e.fitness_score,
                    e.lift_report.mean_composite_lift,
                    -e.mean_estimated_cost_usd,
                ),
            )

        winning_spec = (
            spec_by_cid[winning.candidate_id] if winning is not None else None
        )
        winning_md = winning_spec.skill_markdown if winning_spec is not None else None
        receipt: SkillCertificationReceipt | None = None
        if (
            winning is not None
            and winning_spec is not None
            and self._certifier is not None
        ):
            with tempfile.TemporaryDirectory() as tmp_dir:
                evidence_dir = Path(tmp_dir)
                skill_md_path = evidence_dir / "SKILL.md"
                skill_md_path.write_text(winning_spec.skill_markdown, encoding="utf-8")
                evals_path = _write_canonical_json(
                    evidence_dir / "evals.json",
                    {"cases": [_eval_case_document(case) for case in cases]},
                )
                baseline_path = _write_canonical_json(
                    evidence_dir / "baseline_traces.json",
                    _trajectory_set_document(
                        baseline_trajectories, group_baseline_trajectories
                    ),
                )
                with_skill_path = _write_canonical_json(
                    evidence_dir / "with_skill_traces.json",
                    _trajectory_set_document(
                        winning_spec.with_skill_trajectories,
                        winning_spec.group_with_skill_trajectories,
                    ),
                )
                anchors_path = (
                    _write_canonical_json(
                        evidence_dir / "anchors.json",
                        {"anchors": [_anchor_document(item) for item in anchors]},
                    )
                    if anchor_cal is not None and anchors is not None
                    else None
                )
                receipt = self._certifier.create_and_sign_receipt(
                    skill_md_path=skill_md_path,
                    static_report=winning.static_lint_report,
                    stages_run=(0, 1, 2) if anchor_cal is not None else (0, 2),
                    evidence_level=CerEvidenceLevel.PAIRED_TRACES,
                    lift_report=winning.lift_report,
                    anchor_report=anchor_cal,
                    evals_json_path=evals_path,
                    anchors_json_path=anchors_path,
                    baseline_traces_path=baseline_path,
                    with_skill_traces_path=with_skill_path,
                    model_id=model_id,
                )

        return GEPAOptimizationReport(
            skill_name=safe_skill,
            model_id=model_id,
            generations_configured=self._generations,
            population_size_configured=self._population_size,
            anchor_calibration=anchor_cal,
            candidate_evaluations=tuple(evals),
            winning_candidate=winning,
            winning_skill_markdown=winning_md,
            cer_receipt=receipt,
        )


__all__ = [
    "DEFAULT_GEPA_METRICS",
    "GEPACandidateEvaluation",
    "GEPACandidateSpec",
    "GEPAOptimizationReport",
    "GovernedGEPAOptimizer",
]
