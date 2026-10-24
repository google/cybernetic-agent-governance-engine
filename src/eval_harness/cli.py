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

"""Standalone Partner CI Gate CLI (`src/eval_harness/cli.py`).

Executes the 3P Partner Skill Evaluation & Certification Standard completely
offline (`governor=None`) with zero runtime dependencies on Redis, OPA, or the
online CAGE Gateway:
1. Stage 0 Static Quality & Security Gate (`SKILL.md` 6-dimension lint + length
   density check).
2. Optional Stage 1 Anchor Calibration Gate (`anchors.json` recall-weighted
   evaluator verification).
3. Stage 2 Paired Differential Skill Lift Gate (`evals.json` + baseline/skill
   ATIF trajectories across the 4 ACES prompt buckets).

`--emit-cer` signs a ``cage.skill.cer.v2`` receipt that binds the stages that
ran, the evidence level, and the digests of the evaluated evidence (the trace
files, or the rollout adapter reference and configuration digest).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.eval_harness.harness import (
    AnchorCalibrationResult,
    AnchorItem,
    ATIFTrajectory,
    CerEvidenceLevel,
    EvalBackendProtocol,
    FoundationModelEvalHarness,
    ShadowStateReducer,
    SkillCertificationReceipt,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
    lift_meets_threshold,
)
from src.eval_harness.runner import (
    AgentRolloutRunner,
    BaseRolloutAdapter,
    load_rollout_adapter,
)
from src.eval_harness.static_linter import SkillStaticLintReport, lint_skill_file

if TYPE_CHECKING:
    from src.gateway.governance.governor.governor import SymbolicGovernor


def _parse_eval_case(raw: Mapping[str, Any]) -> SkillEvalCase:
    bucket_str = str(raw.get("bucket", "explicit")).lower()
    raw_shadow = raw.get("initial_shadow_state")
    return SkillEvalCase(
        case_id=str(raw["case_id"]),
        bucket=SkillPromptBucket(bucket_str),
        prompt=str(raw.get("prompt", "")),
        expected_skill=(
            str(raw["expected_skill"])
            if raw.get("expected_skill") is not None
            else None
        ),
        expected_script=(
            str(raw["expected_script"])
            if raw.get("expected_script") is not None
            else None
        ),
        allowed_skills=tuple(str(s) for s in (raw.get("allowed_skills") or ())),
        forbidden_tools=tuple(str(t) for t in (raw.get("forbidden_tools") or ())),
        required_output_tokens=tuple(
            str(tok) for tok in (raw.get("required_output_tokens") or ())
        ),
        expected_behaviors=tuple(str(b) for b in (raw.get("expected_behaviors") or ())),
        initial_shadow_state=(
            dict(raw_shadow) if isinstance(raw_shadow, Mapping) else {}
        ),
    )


def _load_trajectories_map(path: Path) -> dict[str, ATIFTrajectory]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, Mapping):
        return {
            str(case_id): ATIFTrajectory.from_dict(traj_dict)
            for case_id, traj_dict in payload.items()
            if isinstance(traj_dict, Mapping)
        }
    if isinstance(payload, list):
        return {
            str(
                item.get("case_id") or item.get("trajectory_id")
            ): ATIFTrajectory.from_dict(item)
            for item in payload
            if isinstance(item, Mapping)
        }
    raise ValueError(f"Unsupported trajectory JSON structure in {path}")


def _parse_adapter_config(raw_config: str | None) -> dict[str, Any]:
    if not raw_config:
        return {}
    candidate = Path(raw_config)
    if candidate.exists() and candidate.is_file():
        return dict(json.loads(candidate.read_text(encoding="utf-8")))
    return dict(json.loads(raw_config))


def _select_stage2_evidence(
    *,
    evals_json_path: Path | None,
    baseline_traces_path: Path | None,
    with_skill_traces_path: Path | None,
    rollout_adapter: BaseRolloutAdapter | str | None,
) -> CerEvidenceLevel | None:
    """Return the evidence Stage 2 measures lift from, or ``None`` if inputs are incomplete.

    Pre-recorded paired traces take precedence over a rollout adapter. The gate
    and the CLI both use this selection so a `.cer` receipt binds exactly the
    evidence the gate evaluated.
    """
    if evals_json_path is None:
        return None
    if baseline_traces_path is not None and with_skill_traces_path is not None:
        return CerEvidenceLevel.PAIRED_TRACES
    if rollout_adapter is not None:
        return CerEvidenceLevel.LIVE_ROLLOUT
    return None


def _stages_run(
    anchor_report: AnchorCalibrationResult | None,
    lift_report: SkillLiftReport | None,
) -> tuple[int, ...]:
    """Return the certification stages that produced a report (Stage 0 always runs)."""
    stages = [0]
    if anchor_report is not None:
        stages.append(1)
    if lift_report is not None:
        stages.append(2)
    return tuple(stages)


def _resolve_eval_backend(
    eval_backend: EvalBackendProtocol | str | None,
) -> EvalBackendProtocol | None:
    if eval_backend is None or eval_backend == "local":
        return None
    if isinstance(eval_backend, str):
        if eval_backend.lower() == "vertex":
            from src.integrations.gcp_eval.vertex_evaluator import (
                VertexGenAIEvalBackend,
            )

            return VertexGenAIEvalBackend()
        raise ValueError(
            f"Unsupported eval_backend={eval_backend!r}; expected 'local' or 'vertex'"
        )
    return eval_backend


async def _evaluate_trace_files(
    *,
    harness: FoundationModelEvalHarness,
    resolved_backend: EvalBackendProtocol | None,
    skill_name: str,
    model_id: str,
    cases: Sequence[SkillEvalCase],
    baseline_traces_path: Path,
    with_skill_traces_path: Path,
    state_reducer: ShadowStateReducer | None,
) -> SkillLiftReport:
    """Measure paired Skill Lift over pre-recorded baseline/with-skill trace files."""
    base_map = _load_trajectories_map(baseline_traces_path)
    skill_map = _load_trajectories_map(with_skill_traces_path)
    if resolved_backend is not None:
        return await resolved_backend.evaluate_paired_skill_lift(
            harness=harness,
            skill_name=skill_name,
            model_id=model_id,
            cases=cases,
            baseline_trajectories=base_map,
            with_skill_trajectories=skill_map,
            state_reducer=state_reducer,
        )
    return await harness.evaluate_paired_skill_lift(
        skill_name=skill_name,
        model_id=model_id,
        cases=cases,
        baseline_trajectories=base_map,
        with_skill_trajectories=skill_map,
        state_reducer=state_reducer,
    )


async def run_certification_gate(
    *,
    skill_md_path: Path,
    evals_json_path: Path | None = None,
    baseline_traces_path: Path | None = None,
    with_skill_traces_path: Path | None = None,
    rollout_adapter: BaseRolloutAdapter | str | None = None,
    adapter_config: Mapping[str, Any] | None = None,
    decoy_skills: Sequence[str] = (),
    anchors_json_path: Path | None = None,
    min_static_score: float = 0.70,
    min_composite_lift: float = 0.0,
    model_id: str | None = None,
    governor: SymbolicGovernor | None = None,
    state_reducer: ShadowStateReducer | None = None,
    eval_backend: EvalBackendProtocol | str | None = None,
    allow_stage0_only: bool = False,
) -> tuple[
    bool,
    SkillStaticLintReport,
    AnchorCalibrationResult | None,
    SkillLiftReport | None,
    tuple[str, ...],
]:
    """Run the offline 3P Skill Certification Gate and return `(certified, ...)`.

    By default ``governor=None`` runs completely standalone over static lint,
    anchor calibration, and trace-level ACES metrics (with ``governor_evaluated=False``
    so no vacuous governor score is averaged into ``goal_accuracy``). Callers
    wishing to enforce ``SymbolicGovernor`` step-level admissibility during
    Stage 2 can pass ``governor=<SymbolicGovernor>`` (and an optional
    ``state_reducer``).

    Certification fails closed when Stage 2 paired evaluation is not executed
    unless ``allow_stage0_only=True`` (CLI ``--stage0-only``) is explicitly set.

    ``model_id`` names the model that produced pre-recorded traces and is
    required with ``baseline_traces_path``/``with_skill_traces_path`` (there is
    no default model). Rollout-adapter runs record the adapter's model id from
    the rollout bundle instead. Stage 2 lift must satisfy
    :func:`~src.eval_harness.harness.lift_meets_threshold`, the same rule the
    `.cer` verifier applies.
    """
    failures: list[str] = []

    # Stage 0: Static SKILL.md Lint
    static_report = lint_skill_file(skill_md_path, min_score=min_static_score)
    if not static_report.passed:
        failures.append(
            f"stage0_static_lint_failed(score={static_report.length_adjusted_score},violations={list(static_report.violations)})"
        )

    harness = FoundationModelEvalHarness(governor=governor)
    resolved_backend = _resolve_eval_backend(eval_backend)
    anchor_result: AnchorCalibrationResult | None = None
    lift_report: SkillLiftReport | None = None

    # Stage 1: Anchor Calibration (if anchors_json_path is provided)
    if anchors_json_path is not None:
        raw_anchors = json.loads(anchors_json_path.read_text(encoding="utf-8"))
        anchor_items: list[AnchorItem] = []
        for idx, entry in enumerate(raw_anchors):
            if not isinstance(entry, Mapping):
                continue
            anchor_items.append(
                AnchorItem(
                    item_id=str(entry.get("item_id", f"anchor-{idx}")),
                    case=_parse_eval_case(entry["case"]),
                    trajectory=ATIFTrajectory.from_dict(entry["trajectory"]),
                    golden_passed=bool(entry["golden_passed"]),
                )
            )
        anchor_result = harness.drawback_evaluator.calibrate_on_anchors(anchor_items)
        if not anchor_result.valid:
            failures.append(
                f"stage1_anchor_calibration_failed({anchor_result.rejection_reason})"
            )

    # Stage 2: Paired Differential Skill Lift (via pre-recorded traces OR live rollout adapter)
    has_any_stage2_input = any(
        x is not None
        for x in (
            evals_json_path,
            baseline_traces_path,
            with_skill_traces_path,
            rollout_adapter,
        )
    )
    stage2_evidence = _select_stage2_evidence(
        evals_json_path=evals_json_path,
        baseline_traces_path=baseline_traces_path,
        with_skill_traces_path=with_skill_traces_path,
        rollout_adapter=rollout_adapter,
    )
    has_complete_stage2_input = stage2_evidence is not None

    if has_any_stage2_input and not has_complete_stage2_input:
        failures.append(
            "stage2_incomplete_inputs(require evals_json_path plus either both "
            "baseline_traces_path and with_skill_traces_path or rollout_adapter)"
        )
    elif not has_complete_stage2_input and not allow_stage0_only:
        failures.append(
            "stage2_not_executed(provide evals_json_path with paired traces or "
            "rollout_adapter, or set allow_stage0_only=True / --stage0-only)"
        )

    if has_complete_stage2_input and evals_json_path is not None:
        raw_cases = json.loads(evals_json_path.read_text(encoding="utf-8"))
        cases = [_parse_eval_case(c) for c in raw_cases if isinstance(c, Mapping)]

        if (
            stage2_evidence is CerEvidenceLevel.LIVE_ROLLOUT
            and rollout_adapter is not None
        ):
            resolved_adapter = (
                load_rollout_adapter(rollout_adapter, adapter_config)
                if isinstance(rollout_adapter, str)
                else rollout_adapter
            )
            runner = AgentRolloutRunner(resolved_adapter)
            if resolved_backend is not None:
                bundle = await runner.run_paired_rollouts(
                    cases,
                    skill_name=static_report.skill_name,
                    skill_md_path=skill_md_path,
                    decoy_skills=decoy_skills,
                )
                lift_report = await resolved_backend.evaluate_paired_skill_lift(
                    harness=harness,
                    skill_name=static_report.skill_name,
                    model_id=bundle.model_id,
                    cases=cases,
                    baseline_trajectories=bundle.baseline_trajectories,
                    with_skill_trajectories=bundle.with_skill_trajectories,
                    group_baseline_trajectories=bundle.group_baseline_trajectories,
                    group_with_skill_trajectories=bundle.group_with_skill_trajectories,
                    state_reducer=state_reducer,
                )
            else:
                lift_report, _bundle = await runner.run_and_evaluate_skill_lift(
                    harness,
                    cases,
                    skill_name=static_report.skill_name,
                    skill_md_path=skill_md_path,
                    decoy_skills=decoy_skills,
                    state_reducer=state_reducer,
                )
        elif baseline_traces_path is not None and with_skill_traces_path is not None:
            if model_id is None or not model_id.strip():
                failures.append(
                    "stage2_missing_model_id(pre-recorded baseline/with-skill traces "
                    "require model_id naming the model that produced them)"
                )
            else:
                lift_report = await _evaluate_trace_files(
                    harness=harness,
                    resolved_backend=resolved_backend,
                    skill_name=static_report.skill_name,
                    model_id=model_id.strip(),
                    cases=cases,
                    baseline_traces_path=baseline_traces_path,
                    with_skill_traces_path=with_skill_traces_path,
                    state_reducer=state_reducer,
                )

        if lift_report is not None:
            for cl in lift_report.case_lifts:
                if cl.with_skill.security < 1.0:
                    failures.append(
                        f"stage2_security_violation(case={cl.case_id},reasons={list(cl.with_skill.drawback_reasons)})"
                    )
                if (
                    cl.bucket == SkillPromptBucket.NEGATIVE_CONTROL
                    and cl.with_skill.skill_execution < 1.0
                ):
                    failures.append(
                        f"stage2_negative_control_overtrigger(case={cl.case_id})"
                    )
                if cl.with_skill.drawback_reasons and cl.with_skill.security >= 1.0:
                    failures.append(
                        f"stage2_drawback_violation(case={cl.case_id},reasons={list(cl.with_skill.drawback_reasons)})"
                    )

            if not lift_meets_threshold(
                lift_report.mean_composite_lift, min_composite_lift
            ):
                required = (
                    "> 0.0" if min_composite_lift == 0.0 else f">= {min_composite_lift}"
                )
                failures.append(
                    f"stage2_insufficient_skill_lift(lift={lift_report.mean_composite_lift}, required {required})"
                )

    certified = len(failures) == 0
    return (
        certified,
        static_report,
        anchor_result,
        lift_report,
        tuple(failures),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `cage-skill-eval`."""
    parser = argparse.ArgumentParser(
        prog="cage-skill-eval",
        description="Standalone Offline 3P Partner Skill Evaluation & Certification CLI",
    )
    parser.add_argument(
        "--skill-md",
        type=Path,
        required=True,
        help="Path to the target skill's SKILL.md file.",
    )
    parser.add_argument(
        "--evals",
        type=Path,
        default=None,
        help="Optional path to evals.json defining 4-bucket SkillEvalCases.",
    )
    parser.add_argument(
        "--baseline-traces",
        type=Path,
        default=None,
        help="Optional path to baseline (no-skill) ATIF trajectories JSON.",
    )
    parser.add_argument(
        "--skill-traces",
        type=Path,
        default=None,
        help="Optional path to with-skill ATIF trajectories JSON.",
    )
    parser.add_argument(
        "--model-id",
        type=str,
        default=None,
        help=(
            "Model that produced --baseline-traces/--skill-traces (required with them). "
            "Adapter runs record the adapter's model_id instead."
        ),
    )
    parser.add_argument(
        "--adapter",
        type=str,
        default=None,
        help="Optional live rollout adapter ('module:ClassOrFn') to generate paired traces.",
    )
    parser.add_argument(
        "--adapter-config",
        type=str,
        default=None,
        help="Optional JSON string or JSON file path configuring --adapter.",
    )
    parser.add_argument(
        "--decoy-skills",
        type=str,
        default=None,
        help="Optional comma-separated decoy skill names for group Routing Premium evaluation.",
    )
    parser.add_argument(
        "--anchors",
        type=Path,
        default=None,
        help="Optional path to golden anchors.json for Double Ratchet calibration.",
    )
    parser.add_argument(
        "--eval-backend",
        type=str,
        default="local",
        choices=("local", "vertex"),
        help="Evaluation backend ('local' or 'vertex' GenAI Evaluation Service).",
    )
    parser.add_argument(
        "--emit-cer",
        type=Path,
        default=None,
        help="Optional output path to emit a signed .cer receipt when certified.",
    )
    parser.add_argument(
        "--kms-key-id",
        type=str,
        default="cage-dev-ed25519-k1",
        help="Key ID (kid) used when signing a .cer receipt via --emit-cer.",
    )
    parser.add_argument(
        "--min-static-score",
        type=float,
        default=0.70,
        help="Minimum Stage 0 length-adjusted SKILL.md score (default: 0.70).",
    )
    parser.add_argument(
        "--min-lift",
        type=float,
        default=0.0,
        help="Minimum mean composite Skill Lift required (default: 0.0).",
    )
    parser.add_argument(
        "--stage0-only",
        action="store_true",
        help="Explicitly allow Stage 0 static lint certification without Stage 2 paired lift.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON certification report.",
    )
    args = parser.parse_args(argv)
    uses_trace_files = args.baseline_traces is not None or args.skill_traces is not None
    if uses_trace_files and (args.model_id is None or not args.model_id.strip()):
        parser.error("--model-id is required with --baseline-traces/--skill-traces")
    if args.model_id is not None and not uses_trace_files:
        parser.error(
            "--model-id applies only to --baseline-traces/--skill-traces; "
            "adapter runs record the adapter's model_id"
        )
    adapter_config = _parse_adapter_config(args.adapter_config)
    decoy_list = (
        tuple(s.strip() for s in args.decoy_skills.split(",") if s.strip())
        if args.decoy_skills
        else ()
    )

    certified, static_rep, anchor_rep, lift_rep, failures = asyncio.run(
        run_certification_gate(
            skill_md_path=args.skill_md,
            evals_json_path=args.evals,
            baseline_traces_path=args.baseline_traces,
            with_skill_traces_path=args.skill_traces,
            rollout_adapter=args.adapter,
            adapter_config=adapter_config,
            decoy_skills=decoy_list,
            anchors_json_path=args.anchors,
            min_static_score=args.min_static_score,
            min_composite_lift=args.min_lift,
            model_id=args.model_id,
            eval_backend=args.eval_backend,
            allow_stage0_only=args.stage0_only,
        )
    )

    stages_run = _stages_run(anchor_rep, lift_rep)

    cer_receipt: SkillCertificationReceipt | None = None
    if certified and args.emit_cer is not None:
        from src.integrations.gcp_eval.cer_publisher import GcpSkillCertifier

        stage2_evidence = _select_stage2_evidence(
            evals_json_path=args.evals,
            baseline_traces_path=args.baseline_traces,
            with_skill_traces_path=args.skill_traces,
            rollout_adapter=args.adapter,
        )
        evidence_level = (
            stage2_evidence
            if lift_rep is not None and stage2_evidence is not None
            else CerEvidenceLevel.STATIC_ONLY
        )
        paired = evidence_level is CerEvidenceLevel.PAIRED_TRACES
        live = evidence_level is CerEvidenceLevel.LIVE_ROLLOUT
        certifier = GcpSkillCertifier(key_id=args.kms_key_id)
        cer_receipt = certifier.create_and_sign_receipt(
            skill_md_path=args.skill_md,
            static_report=static_rep,
            stages_run=stages_run,
            evidence_level=evidence_level,
            lift_report=lift_rep,
            anchor_report=anchor_rep,
            evals_json_path=args.evals,
            anchors_json_path=args.anchors,
            baseline_traces_path=args.baseline_traces if paired else None,
            with_skill_traces_path=args.skill_traces if paired else None,
            adapter_ref=args.adapter if live else None,
            adapter_config=adapter_config if live else None,
        )
        cer_target = args.emit_cer.resolve()
        cer_target.parent.mkdir(parents=True, exist_ok=True)
        cer_target.write_text(
            json.dumps(cer_receipt.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    if args.json:
        payload: dict[str, Any] = {
            "certified": certified,
            "stages_run": list(stages_run),
            "failures": list(failures),
            "stage0_static_lint": asdict(static_rep),
            "stage1_anchor_calibration": (
                asdict(anchor_rep) if anchor_rep is not None else None
            ),
            "stage2_paired_lift": (asdict(lift_rep) if lift_rep is not None else None),
            "cer_receipt": (cer_receipt.to_dict() if cer_receipt is not None else None),
        }
        print(json.dumps(payload, indent=2))
    else:
        status_str = "CERTIFIED" if certified else "REJECTED"
        print(f"=== CAGE 3P Skill Certification Gate [{status_str}] ===")
        print(
            f"Skill Name          : {static_rep.skill_name} ({static_rep.word_count} words)"
        )
        print(f"Stages Executed     : {list(stages_run)}")
        print(
            f"Stage 0 Static Score: {static_rep.length_adjusted_score:.4f} "
            f"(raw={static_rep.raw_mean_score:.4f}, density={static_rep.information_density_multiplier:.4f})"
        )
        if anchor_rep is not None:
            print(
                f"Stage 1 Anchors     : valid={anchor_rep.valid} "
                f"(agreement={anchor_rep.weighted_agreement:.4f}, r_fail={anchor_rep.recall_fail:.4f})"
            )
        if lift_rep is not None:
            print(
                f"Stage 2 Skill Lift  : {lift_rep.mean_composite_lift:+.4f} "
                f"(IF Lift={lift_rep.mean_instruction_following_lift:+.4f})"
            )
        if cer_receipt is not None:
            print(f"CER Receipt Digest  : {cer_receipt.receipt_digest}")
        if failures:
            print("Failures:")
            for f in failures:
                print(f"  - {f}")

    return 0 if certified else 1


if __name__ == "__main__":
    sys.exit(main())
