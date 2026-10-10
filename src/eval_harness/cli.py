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
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.eval_harness.harness import (
    AnchorCalibrationResult,
    AnchorItem,
    ATIFTrajectory,
    FoundationModelEvalHarness,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
)
from src.eval_harness.static_linter import SkillStaticLintReport, lint_skill_file


def _parse_eval_case(raw: Mapping[str, Any]) -> SkillEvalCase:
    bucket_str = str(raw.get("bucket", "explicit")).lower()
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


async def run_certification_gate(
    *,
    skill_md_path: Path,
    evals_json_path: Path | None = None,
    baseline_traces_path: Path | None = None,
    with_skill_traces_path: Path | None = None,
    anchors_json_path: Path | None = None,
    min_static_score: float = 0.70,
    min_composite_lift: float = 0.0,
    model_id: str = "gemini-3.5-flash",
) -> tuple[
    bool,
    SkillStaticLintReport,
    AnchorCalibrationResult | None,
    SkillLiftReport | None,
    tuple[str, ...],
]:
    """Run the offline 3P Skill Certification Gate and return `(certified, ...)`."""
    failures: list[str] = []

    # Stage 0: Static SKILL.md Lint
    static_report = lint_skill_file(skill_md_path, min_score=min_static_score)
    if not static_report.passed:
        failures.append(
            f"stage0_static_lint_failed(score={static_report.length_adjusted_score},violations={list(static_report.violations)})"
        )

    harness = FoundationModelEvalHarness(governor=None)
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

    # Stage 2: Paired Differential Skill Lift (if evals + paired traces provided)
    if (
        evals_json_path is not None
        and baseline_traces_path is not None
        and with_skill_traces_path is not None
    ):
        raw_cases = json.loads(evals_json_path.read_text(encoding="utf-8"))
        cases = [_parse_eval_case(c) for c in raw_cases if isinstance(c, Mapping)]
        base_map = _load_trajectories_map(baseline_traces_path)
        skill_map = _load_trajectories_map(with_skill_traces_path)

        lift_report = await harness.evaluate_paired_skill_lift(
            skill_name=static_report.skill_name,
            model_id=model_id,
            cases=cases,
            baseline_trajectories=base_map,
            with_skill_trajectories=skill_map,
        )

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

        if lift_report.mean_composite_lift < min_composite_lift:
            failures.append(
                f"stage2_insufficient_skill_lift({lift_report.mean_composite_lift} < {min_composite_lift})"
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
        "--anchors",
        type=Path,
        default=None,
        help="Optional path to golden anchors.json for Double Ratchet calibration.",
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
        "--json",
        action="store_true",
        help="Emit machine-readable JSON certification report.",
    )
    args = parser.parse_args(argv)

    certified, static_rep, anchor_rep, lift_rep, failures = asyncio.run(
        run_certification_gate(
            skill_md_path=args.skill_md,
            evals_json_path=args.evals,
            baseline_traces_path=args.baseline_traces,
            with_skill_traces_path=args.skill_traces,
            anchors_json_path=args.anchors,
            min_static_score=args.min_static_score,
            min_composite_lift=args.min_lift,
        )
    )

    if args.json:
        payload = {
            "certified": certified,
            "failures": list(failures),
            "stage0_static_lint": asdict(static_rep),
            "stage1_anchor_calibration": (
                asdict(anchor_rep) if anchor_rep is not None else None
            ),
            "stage2_paired_lift": (asdict(lift_rep) if lift_rep is not None else None),
        }
        print(json.dumps(payload, indent=2))
    else:
        status_str = "CERTIFIED" if certified else "REJECTED"
        print(f"=== CAGE 3P Skill Certification Gate [{status_str}] ===")
        print(
            f"Skill Name          : {static_rep.skill_name} ({static_rep.word_count} words)"
        )
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
        if failures:
            print("Failures:")
            for f in failures:
                print(f"  - {f}")

    return 0 if certified else 1


if __name__ == "__main__":
    sys.exit(main())
