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

"""CAGE Offline Evaluation & Skill Certification System (`src/eval_harness/`).

Strictly separated from the online runtime enforcement plane (`src/gateway/`).
Can be deployed and executed standalone in CI/CD or batch pipelines without
instantiating `SymbolicGovernor` or shipping inside the online Gateway container.
"""

import sys as _sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT))

from src.eval_harness.adapters import (
    adk_session_to_atif,
    gemini_cli_jsonl_to_atif,
)
from src.eval_harness.cli import run_certification_gate
from src.eval_harness.harness import (
    AnchorCalibrationResult,
    AnchorItem,
    ATIFStep,
    ATIFTrajectory,
    ComposedDrawbackEvaluator,
    DPOPreferenceTriplet,
    DrawbackDetectorFn,
    DrawbackDetectorSpec,
    DrawbackVerdict,
    EvaluationStepResult,
    FoundationModelEvalHarness,
    PairedCaseLift,
    PRMRewardSchedule,
    ShadowStateReducer,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
    SkillTrajectoryScorecard,
    ToolActionStep,
    TrajectoryBenchmarkReport,
    build_default_drawback_detectors,
)
from src.eval_harness.runner import (
    MODEL_PRICING_CATALOG,
    ADKSessionRolloutAdapter,
    AgentRolloutRunner,
    BaseRolloutAdapter,
    CallableRolloutAdapter,
    HttpRolloutAdapter,
    MultiAgentRolloutAdapter,
    PairedRolloutBundle,
    RolloutWorkspaceContext,
    TrajectoryTokenomics,
    compute_cost_savings_multiplier,
    compute_trajectory_tokenomics,
    estimate_token_count,
    load_rollout_adapter,
)
from src.eval_harness.static_linter import (
    SkillStaticLintReport,
    lint_skill_file,
    lint_skill_markdown,
)

__all__ = [
    "MODEL_PRICING_CATALOG",
    "ADKSessionRolloutAdapter",
    "ATIFStep",
    "ATIFTrajectory",
    "AgentRolloutRunner",
    "AnchorCalibrationResult",
    "AnchorItem",
    "BaseRolloutAdapter",
    "CallableRolloutAdapter",
    "ComposedDrawbackEvaluator",
    "DPOPreferenceTriplet",
    "DrawbackDetectorFn",
    "DrawbackDetectorSpec",
    "DrawbackVerdict",
    "EvaluationStepResult",
    "FoundationModelEvalHarness",
    "HttpRolloutAdapter",
    "MultiAgentRolloutAdapter",
    "PRMRewardSchedule",
    "PairedCaseLift",
    "PairedRolloutBundle",
    "RolloutWorkspaceContext",
    "ShadowStateReducer",
    "SkillEvalCase",
    "SkillLiftReport",
    "SkillPromptBucket",
    "SkillStaticLintReport",
    "SkillTrajectoryScorecard",
    "ToolActionStep",
    "TrajectoryBenchmarkReport",
    "TrajectoryTokenomics",
    "adk_session_to_atif",
    "build_default_drawback_detectors",
    "compute_cost_savings_multiplier",
    "compute_trajectory_tokenomics",
    "estimate_token_count",
    "gemini_cli_jsonl_to_atif",
    "lint_skill_file",
    "lint_skill_markdown",
    "load_rollout_adapter",
    "run_certification_gate",
]
