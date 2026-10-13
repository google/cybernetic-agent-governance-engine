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

"""Vertex AI GenAI Evaluation Service Backend (`src/integrations/gcp_eval/vertex_evaluator.py`).

Maps CAGE's offline evaluation primitives directly onto Vertex AI GenAI
Evaluation Service (`vertexai.preview.evaluation`):
1. **AWS Double Ratchet (Computation-based Drawback AutoRaters & Golden Anchors)**:
   Wraps every :class:`~src.eval_harness.harness.DrawbackDetectorSpec` into a
   deterministic Vertex ``CustomMetric`` function and calibrates evaluators against
   Vertex Golden Anchor datasets fail-closed via ``calibrate_on_anchors()``.
2. **Tessl (Goal Completion vs. Process / Instruction-Following Split)**:
   Configures dual-dimension scoring separating final Goal Accuracy from
   tool-call Process / Instruction-Following Lift.
3. **NVIDIA ACES (4-Bucket Paired Skill Lift & Group Routing Premium)**:
   Evaluates paired `baseline` vs. `with_skill` trajectories in both isolation
   and group decoy modes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.eval_harness.harness import (
    AnchorCalibrationResult,
    AnchorItem,
    ATIFTrajectory,
    ComposedDrawbackEvaluator,
    DrawbackDetectorSpec,
    DrawbackVerdict,
    EvalBackendProtocol,
    FoundationModelEvalHarness,
    ShadowStateReducer,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
    _score_goal_accuracy,
    _score_instruction_following,
)

logger = logging.getLogger("cage.integrations.gcp_eval.vertex_evaluator")


@dataclass(frozen=True)
class VertexCustomMetricAdapter:
    """Deterministic computation-based AutoRater compatible with Vertex AI `CustomMetric`.

    Can be passed directly to ``vertexai.preview.evaluation.CustomMetric(name=..., metric_function=...)``
    or invoked in-memory when the Vertex SDK is running in offline/hermetic mode.
    """

    name: str
    description: str
    metric_fn: Callable[[Mapping[str, Any]], dict[str, Any]]

    def __call__(self, instance: Mapping[str, Any]) -> dict[str, Any]:
        return self.metric_fn(instance)

    def to_vertex_custom_metric(self) -> Any:
        """Convert to a `vertexai.preview.evaluation.CustomMetric` when Vertex SDK is installed."""
        try:
            from vertexai.preview.evaluation import (
                CustomMetric,  # type: ignore[import]
            )

            return CustomMetric(
                name=self.name,
                metric_function=self.metric_fn,
            )
        except ImportError:
            return self


@dataclass(frozen=True)
class VertexPointwiseRubricSpec:
    """Multi-criteria rubric specification for Tessl Goal vs. Instruction-Following split."""

    metric_name: str
    dimension: str
    prompt_template: str
    criteria: dict[str, str] = field(default_factory=dict)


def build_vertex_drawback_custom_metrics(
    detectors: Sequence[DrawbackDetectorSpec],
    cases_by_id: Mapping[str, SkillEvalCase],
) -> tuple[VertexCustomMetricAdapter, ...]:
    """Wrap CAGE atomic drawback detectors into Vertex AI computation-based CustomMetrics."""
    adapters: list[VertexCustomMetricAdapter] = []

    for spec in detectors:

        def _make_fn(
            detector_spec: DrawbackDetectorSpec,
        ) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
            def _eval_instance(instance: Mapping[str, Any]) -> dict[str, Any]:
                case_id = str(instance.get("case_id", ""))
                case = cases_by_id.get(case_id)
                if case is None:
                    raw_case = instance.get("case")
                    if isinstance(raw_case, SkillEvalCase):
                        case = raw_case
                    elif isinstance(raw_case, Mapping):
                        case = SkillEvalCase(
                            case_id=str(raw_case.get("case_id", case_id or "case-0")),
                            bucket=SkillPromptBucket(
                                str(raw_case.get("bucket", "explicit")).lower()
                            ),
                            prompt=str(raw_case.get("prompt", "")),
                            expected_skill=raw_case.get("expected_skill"),
                            expected_script=raw_case.get("expected_script"),
                            allowed_skills=tuple(raw_case.get("allowed_skills") or ()),
                            forbidden_tools=tuple(
                                raw_case.get("forbidden_tools") or ()
                            ),
                            required_output_tokens=tuple(
                                raw_case.get("required_output_tokens") or ()
                            ),
                            expected_behaviors=tuple(
                                raw_case.get("expected_behaviors") or ()
                            ),
                        )
                    else:
                        raise ValueError(
                            f"Missing SkillEvalCase for case_id={case_id!r}"
                        )

                raw_traj = instance.get("trajectory")
                if isinstance(raw_traj, ATIFTrajectory):
                    trajectory = raw_traj
                elif isinstance(raw_traj, Mapping):
                    trajectory = ATIFTrajectory.from_dict(raw_traj)
                else:
                    raise ValueError(
                        f"Missing ATIFTrajectory in Vertex eval instance for case_id={case.case_id!r}"
                    )

                verdict, detail = detector_spec.detect(case, trajectory, None)
                score = (
                    0.0
                    if verdict == DrawbackVerdict.DRAWBACK
                    else (1.0 if verdict == DrawbackVerdict.CLEAN else 0.5)
                )
                return {
                    detector_spec.name: score,
                    f"{detector_spec.name}_verdict": verdict.value,
                    f"{detector_spec.name}_explanation": detail,
                }

            return _eval_instance

        adapters.append(
            VertexCustomMetricAdapter(
                name=spec.name,
                description=spec.description,
                metric_fn=_make_fn(spec),
            )
        )

    return tuple(adapters)


def build_tessl_dual_rubric_specs() -> tuple[
    VertexPointwiseRubricSpec, VertexPointwiseRubricSpec
]:
    """Build Tessl multi-criteria rubrics splitting Goal Completion from Process / Instruction Following."""
    goal_rubric = VertexPointwiseRubricSpec(
        metric_name="tessl_goal_completion",
        dimension="goal_accuracy",
        prompt_template=(
            "Evaluate whether the agent's final output and state transitions "
            "satisfy the user's goal and required output contract without violating "
            "governance safety boundaries.\nPrompt: {prompt}\nResponse: {response}"
        ),
        criteria={
            "required_tokens_present": "All required output markers are affirmatively present.",
            "admissible_completion": "No step was denied by the governance boundary.",
        },
    )
    process_rubric = VertexPointwiseRubricSpec(
        metric_name="tessl_instruction_following_lift",
        dimension="instruction_following",
        prompt_template=(
            "Evaluate whether the agent's tool-call trajectory strictly followed "
            "the partner SDK conventions and workflow steps defined in SKILL.md, "
            "and avoided all forbidden or deprecated tools.\n"
            "Prompt: {prompt}\nTool Trajectory: {trajectory}"
        ),
        criteria={
            "workflow_conventions": "Executed expected scripts/flags in tool calls (not uncorroborated prose).",
            "forbidden_tool_restraint": "Never invoked any forbidden or deprecated tool.",
        },
    )
    return goal_rubric, process_rubric


class VertexGenAIEvalBackend(EvalBackendProtocol):
    """Vertex AI GenAI Evaluation Service backend implementing `EvalBackendProtocol`.

    Supports both live Vertex `EvalTask` execution (when `eval_task_factory` or
    Vertex credentials are provided) and deterministic hermetic execution of the
    registered `VertexCustomMetricAdapter` AutoRaters.
    """

    def __init__(
        self,
        *,
        project_id: str | None = None,
        location: str = "us-central1",
        experiment_name: str = "cage-skill-eval",
        eval_task_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._project_id = project_id
        self._location = location
        self._experiment_name = experiment_name
        self._eval_task_factory = eval_task_factory
        self._last_experiment_run_metrics: dict[str, Any] = {}

    @property
    def experiment_name(self) -> str:
        return self._experiment_name

    @property
    def last_experiment_run_metrics(self) -> dict[str, Any]:
        return dict(self._last_experiment_run_metrics)

    def calibrate_on_vertex_anchor_dataset(
        self,
        evaluator: ComposedDrawbackEvaluator,
        anchor_dataset: Sequence[AnchorItem | Mapping[str, Any]],
        *,
        min_weighted_agreement: float = 0.70,
    ) -> AnchorCalibrationResult:
        """Calibrate `evaluator` against a Vertex Dataset of Golden Anchors fail-closed."""
        normalized_anchors: list[AnchorItem] = []
        for idx, item in enumerate(anchor_dataset):
            if isinstance(item, AnchorItem):
                normalized_anchors.append(item)
            elif isinstance(item, Mapping):
                raw_case = item["case"]
                case = (
                    raw_case
                    if isinstance(raw_case, SkillEvalCase)
                    else SkillEvalCase(
                        case_id=str(raw_case["case_id"]),
                        bucket=SkillPromptBucket(
                            str(raw_case.get("bucket", "explicit")).lower()
                        ),
                        prompt=str(raw_case.get("prompt", "")),
                        expected_skill=raw_case.get("expected_skill"),
                        expected_script=raw_case.get("expected_script"),
                        allowed_skills=tuple(raw_case.get("allowed_skills") or ()),
                        forbidden_tools=tuple(raw_case.get("forbidden_tools") or ()),
                        required_output_tokens=tuple(
                            raw_case.get("required_output_tokens") or ()
                        ),
                        expected_behaviors=tuple(
                            raw_case.get("expected_behaviors") or ()
                        ),
                    )
                )
                raw_traj = item["trajectory"]
                traj = (
                    raw_traj
                    if isinstance(raw_traj, ATIFTrajectory)
                    else ATIFTrajectory.from_dict(raw_traj)
                )
                normalized_anchors.append(
                    AnchorItem(
                        item_id=str(item.get("item_id", f"vertex-anchor-{idx}")),
                        case=case,
                        trajectory=traj,
                        golden_passed=bool(item["golden_passed"]),
                    )
                )
        return evaluator.calibrate_on_anchors(
            normalized_anchors,
            min_weighted_agreement=min_weighted_agreement,
        )

    async def evaluate_paired_skill_lift(
        self,
        *,
        harness: FoundationModelEvalHarness,
        skill_name: str,
        model_id: str,
        cases: Sequence[SkillEvalCase],
        baseline_trajectories: Mapping[str, ATIFTrajectory],
        with_skill_trajectories: Mapping[str, ATIFTrajectory],
        group_baseline_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        group_with_skill_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        state_reducer: ShadowStateReducer | None = None,
    ) -> SkillLiftReport:
        """Execute Vertex AI CustomMetric AutoRaters + Tessl rubrics and compute 4-bucket Skill Lift."""
        cases_by_id = {c.case_id: c for c in cases}
        custom_metrics = build_vertex_drawback_custom_metrics(
            harness.drawback_evaluator.detectors,
            cases_by_id,
        )
        goal_rubric, process_rubric = build_tessl_dual_rubric_specs()

        eval_rows: list[dict[str, Any]] = []
        for case in cases:
            if case.case_id in with_skill_trajectories:
                traj = with_skill_trajectories[case.case_id]
                row: dict[str, Any] = {
                    "case_id": case.case_id,
                    "bucket": case.bucket.value,
                    "prompt": case.prompt,
                    "response": traj.final_response,
                    "trajectory": traj,
                    "case": case,
                    "tessl_goal_completion": _score_goal_accuracy(case, traj, None),
                    "tessl_instruction_following_lift": _score_instruction_following(
                        case, traj
                    ),
                }
                for cm in custom_metrics:
                    row.update(cm(row))
                eval_rows.append(row)

        if self._eval_task_factory is not None:
            task = self._eval_task_factory(
                dataset=eval_rows,
                metrics=[cm.to_vertex_custom_metric() for cm in custom_metrics],
                experiment=self._experiment_name,
            )
            task.evaluate()

        report = await harness.evaluate_paired_skill_lift(
            skill_name=skill_name,
            model_id=model_id,
            cases=cases,
            baseline_trajectories=baseline_trajectories,
            with_skill_trajectories=with_skill_trajectories,
            group_baseline_trajectories=group_baseline_trajectories,
            group_with_skill_trajectories=group_with_skill_trajectories,
            state_reducer=state_reducer,
        )

        self._last_experiment_run_metrics = {
            "experiment_name": self._experiment_name,
            "skill_name": skill_name,
            "model_id": model_id,
            "mean_composite_lift": report.mean_composite_lift,
            "mean_outcome_lift": report.mean_outcome_lift,
            "mean_process_lift": report.mean_process_lift,
            "mean_instruction_following_lift": report.mean_instruction_following_lift,
            "routing_premium": report.routing_premium,
            "rubrics": [goal_rubric.metric_name, process_rubric.metric_name],
            "custom_autoraters": [cm.name for cm in custom_metrics],
            "evaluated_rows": len(eval_rows),
        }
        return report

    async def run_simulated_cicd_gate(
        self,
        *,
        harness: FoundationModelEvalHarness,
        skill_name: str,
        model_id: str,
        cases: Sequence[SkillEvalCase],
        baseline_trajectories: Mapping[str, ATIFTrajectory],
        with_skill_trajectories: Mapping[str, ATIFTrajectory],
        anchor_dataset: Sequence[AnchorItem | Mapping[str, Any]],
        group_baseline_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        group_with_skill_trajectories: Mapping[str, ATIFTrajectory] | None = None,
        state_reducer: ShadowStateReducer | None = None,
        min_rubric_score: float = 3.0,
        min_composite_lift: float = 0.0,
        min_weighted_agreement: float = 0.70,
        explicit_rubric_scores: Mapping[str, float] | None = None,
    ) -> SimulatedEvalGateResult:
        """Execute GEAP's Simulated Evaluation CI/CD PR Gate (GEAP Tour Slides 24 & 31).

        Enforces three fail-closed gates before allowing a PR merge / production deploy:
        1. **Double Ratchet Anchor Calibration**: ``anchor_calibration.valid`` must be ``True``.
        2. **GEAP 1-5 PointwiseMetric Rubric & 4-Bucket Skill Lift**: Mean rubric score
           (1.0 to 5.0 scale, default threshold ``>= 3.0``) and ``mean_composite_lift >= min_composite_lift``.
        3. **Zero Eval-Prod Drift Invariant Gate**: Every ``with_skill`` trajectory must clear
           ``SymbolicGovernor`` (`Profile.DRY_RUN`) and deterministic drawback detectors with
           zero violations—even if the soft LLM rubric score is >= 3.0.
        """
        if min_rubric_score < 1.0 or min_rubric_score > 5.0:
            raise ValueError(
                "min_rubric_score must be on the GEAP 1.0-5.0 PointwiseMetric scale"
            )

        anchor_cal = self.calibrate_on_vertex_anchor_dataset(
            harness.drawback_evaluator,
            anchor_dataset,
            min_weighted_agreement=min_weighted_agreement,
        )

        lift_report = await self.evaluate_paired_skill_lift(
            harness=harness,
            skill_name=skill_name,
            model_id=model_id,
            cases=cases,
            baseline_trajectories=baseline_trajectories,
            with_skill_trajectories=with_skill_trajectories,
            group_baseline_trajectories=group_baseline_trajectories,
            group_with_skill_trajectories=group_with_skill_trajectories,
            state_reducer=state_reducer,
        )

        # Compute GEAP 1.0-5.0 PointwiseMetric score (either from explicit Vertex rubric scores
        # or mapped linearly from [0.0, 1.0] composite_score -> [1.0, 5.0])
        if explicit_rubric_scores:
            scores_1_to_5 = [float(v) for v in explicit_rubric_scores.values()]
            mean_rubric_score = (
                round(sum(scores_1_to_5) / len(scores_1_to_5), 4)
                if scores_1_to_5
                else 1.0
            )
        else:
            mean_rubric_score = round(
                1.0 + 4.0 * max(0.0, min(1.0, lift_report.mean_with_skill_composite)),
                4,
            )

        dry_run_violations: list[str] = []
        for cl in lift_report.case_lifts:
            sc = cl.with_skill
            if sc.drawback_reasons:
                for reason in sc.drawback_reasons:
                    dry_run_violations.append(f"{cl.case_id}:{reason}")
            if sc.governor_evaluated and sc.admissibility_prm < 1.0:
                dry_run_violations.append(
                    f"{cl.case_id}:governor_dry_run_violation(prm={sc.admissibility_prm})"
                )

        blocking_reasons: list[str] = []
        if not anchor_cal.valid:
            blocking_reasons.append(
                f"anchor_calibration_failed:{anchor_cal.rejection_reason or 'UNKNOWN'}"
            )
        if mean_rubric_score < min_rubric_score:
            blocking_reasons.append(
                f"rubric_score_below_threshold:{mean_rubric_score:.2f}<{min_rubric_score:.2f}"
            )
        if lift_report.mean_composite_lift < min_composite_lift:
            blocking_reasons.append(
                f"composite_lift_below_threshold:{lift_report.mean_composite_lift:.4f}<{min_composite_lift:.4f}"
            )
        if dry_run_violations:
            blocking_reasons.append(
                f"dry_run_governance_violations:{len(dry_run_violations)}"
            )

        passed = len(blocking_reasons) == 0
        return SimulatedEvalGateResult(
            passed=passed,
            skill_name=skill_name,
            model_id=model_id,
            mean_rubric_score=mean_rubric_score,
            min_rubric_score=min_rubric_score,
            anchor_calibration=anchor_cal,
            lift_report=lift_report,
            dry_run_violations=tuple(dry_run_violations),
            blocking_reasons=tuple(blocking_reasons),
        )


@dataclass(frozen=True)
class SimulatedEvalGateResult:
    """Verdict from GEAP's Simulated Evaluation CI/CD Gate hardened with CAGE invariants."""

    passed: bool
    skill_name: str
    model_id: str
    mean_rubric_score: float
    min_rubric_score: float
    anchor_calibration: AnchorCalibrationResult
    lift_report: SkillLiftReport
    dry_run_violations: tuple[str, ...] = ()
    blocking_reasons: tuple[str, ...] = ()


__all__ = [
    "SimulatedEvalGateResult",
    "VertexCustomMetricAdapter",
    "VertexGenAIEvalBackend",
    "VertexPointwiseRubricSpec",
    "build_tessl_dual_rubric_specs",
    "build_vertex_drawback_custom_metrics",
]
