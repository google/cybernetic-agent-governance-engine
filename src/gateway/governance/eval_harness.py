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

"""Evaluation and Alignment Harness for Foundation Models (RLVR / DPO / GRPO).

Bridges ``SymbolicGovernor.validate_action`` (which executes under
``Profile.DRY_RUN`` with zero persistent state mutation) and post-training
alignment pipelines:
1. Evaluates multi-turn tool trajectories side-effect-free as a deterministic
   Process Reward Model (PRM).
2. Uses reverified ``NARROW`` clamping to synthesize minimal-edit contrastive
   preference pairs ``(prompt, chosen=y_w, rejected=y_l)`` from a single rollout
   without rejection sampling.
3. Exports quantitative trajectory benchmark reports and HuggingFace TRL
   DPOTrainer-compatible JSONL datasets.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError

if TYPE_CHECKING:
    from src.gateway.governance.governor.governor import SymbolicGovernor


@dataclass(frozen=True)
class ToolActionStep:
    """Single proposed tool invocation in a multi-turn evaluation trajectory."""

    step_id: int
    tool_name: str
    arguments: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationStepResult:
    """Step-level process reward and admissibility outcome."""

    step_id: int
    tool_name: str
    decision: GovernanceDecision
    original_arguments: dict[str, Any]
    narrowed_arguments: dict[str, Any] | None
    reasons: tuple[str, ...]
    passed: bool
    process_reward: float


@dataclass(frozen=True)
class TrajectoryBenchmarkReport:
    """Quantitative multi-turn benchmark summary for a foundation model rollout."""

    trajectory_id: str
    model_id: str
    total_steps: int
    passed_steps: int
    step_pass_rate: float
    mean_process_reward: float
    trajectory_cleared: bool
    first_violating_step: int | None
    step_results: tuple[EvaluationStepResult, ...]


@dataclass(frozen=True)
class DPOPreferenceTriplet:
    """Contrastive preference triplet for DPO / GRPO post-training alignment."""

    prompt: str
    state_context: dict[str, Any]
    chosen: dict[str, Any]
    rejected: dict[str, Any]
    governance_decision: str
    violation_reasons: tuple[str, ...]


class FoundationModelEvalHarness:
    """Out-of-process RLVR & DPO evaluation harness backed by SymbolicGovernor."""

    def __init__(
        self,
        governor: SymbolicGovernor,
        *,
        include_denial_noop_pairs: bool = False,
    ) -> None:
        self._governor = governor
        self._include_denial_noop_pairs = include_denial_noop_pairs

    async def evaluate_trajectory(
        self,
        trajectory_id: str,
        model_id: str,
        prompt: str,
        steps: Sequence[ToolActionStep],
    ) -> tuple[TrajectoryBenchmarkReport, list[DPOPreferenceTriplet]]:
        """Evaluate a multi-turn trajectory in DRY_RUN mode and emit DPO pairs."""
        step_results: list[EvaluationStepResult] = []
        dpo_triplets: list[DPOPreferenceTriplet] = []
        first_failure: int | None = None

        for step in steps:
            merged_params = {**step.context, **step.arguments}
            narrowed_args: dict[str, Any] | None = None
            reasons: list[str] = []

            try:
                response = await self._governor.validate_action(
                    step.tool_name, merged_params
                )
                raw_verdict = response.get("verdict", GovernanceDecision.DENY)
                decision = GovernanceDecision(raw_verdict)
                for v in response.get("violations", ()):
                    msg = (
                        v.get("message")
                        if isinstance(v, dict)
                        else getattr(v, "message", str(v))
                    )
                    if msg:
                        reasons.append(str(msg))
                if decision == GovernanceDecision.NARROW:
                    candidate = response.get("narrowed_params")
                    if isinstance(candidate, dict):
                        narrowed_args = {
                            k: candidate[k]
                            for k in step.arguments
                            if k in candidate
                        }
            except GovernanceError as exc:
                decision = GovernanceDecision.DENY
                reasons.append(str(exc))

            is_pass = decision in (
                GovernanceDecision.ALLOW,
                GovernanceDecision.NARROW,
            )
            if not is_pass and first_failure is None:
                first_failure = step.step_id

            if decision == GovernanceDecision.ALLOW:
                reward = 1.0
            elif decision == GovernanceDecision.NARROW:
                reward = 0.5
            elif decision in (
                GovernanceDecision.DEFER,
                GovernanceDecision.REQUIRE_APPROVAL,
            ):
                reward = -0.5
            else:
                reward = -1.0

            step_results.append(
                EvaluationStepResult(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    decision=decision,
                    original_arguments=dict(step.arguments),
                    narrowed_arguments=narrowed_args,
                    reasons=tuple(reasons),
                    passed=is_pass,
                    process_reward=reward,
                )
            )

            if decision == GovernanceDecision.NARROW and narrowed_args is not None:
                dpo_triplets.append(
                    DPOPreferenceTriplet(
                        prompt=prompt,
                        state_context=dict(step.context),
                        chosen={"tool": step.tool_name, "arguments": narrowed_args},
                        rejected={
                            "tool": step.tool_name,
                            "arguments": dict(step.arguments),
                        },
                        governance_decision=decision.value,
                        violation_reasons=tuple(reasons),
                    )
                )
            elif self._include_denial_noop_pairs and decision in (
                GovernanceDecision.DENY,
                GovernanceDecision.REQUIRE_APPROVAL,
            ):
                dpo_triplets.append(
                    DPOPreferenceTriplet(
                        prompt=prompt,
                        state_context=dict(step.context),
                        chosen={"tool": "noop", "arguments": {}},
                        rejected={
                            "tool": step.tool_name,
                            "arguments": dict(step.arguments),
                        },
                        governance_decision=decision.value,
                        violation_reasons=tuple(reasons),
                    )
                )

        passed_count = sum(1 for r in step_results if r.passed)
        total = len(steps)
        mean_reward = (
            sum(r.process_reward for r in step_results) / total if total > 0 else 0.0
        )
        report = TrajectoryBenchmarkReport(
            trajectory_id=trajectory_id,
            model_id=model_id,
            total_steps=total,
            passed_steps=passed_count,
            step_pass_rate=(passed_count / total) if total > 0 else 0.0,
            mean_process_reward=round(mean_reward, 4),
            trajectory_cleared=(first_failure is None),
            first_violating_step=first_failure,
            step_results=tuple(step_results),
        )
        return report, dpo_triplets

    @staticmethod
    def export_hf_trl_jsonl(
        triplets: Sequence[DPOPreferenceTriplet], output_path: str | Path
    ) -> None:
        """Export preference triplets to JSONL format for HuggingFace TRL DPOTrainer."""
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as f:
            for item in triplets:
                row = {
                    "prompt": item.prompt,
                    "chosen": item.chosen,
                    "rejected": item.rejected,
                    "metadata": {
                        "decision": item.governance_decision,
                        "reasons": list(item.violation_reasons),
                        "context": item.state_context,
                    },
                }
                f.write(json.dumps(row) + "\n")


__all__ = [
    "DPOPreferenceTriplet",
    "EvaluationStepResult",
    "FoundationModelEvalHarness",
    "ToolActionStep",
    "TrajectoryBenchmarkReport",
]
