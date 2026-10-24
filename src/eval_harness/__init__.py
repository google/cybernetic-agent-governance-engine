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
    langgraph_state_to_atif,
)
from src.eval_harness.cli import run_certification_gate
from src.eval_harness.gepa_optimizer import (
    ActionableSideInfo,
    CageEvaluationBatch,
    CageGEPAAdapter,
    CandidateSecurityReport,
    GEPAEvolutionEngine,
    GEPAOptimizationResult,
    ParetoCandidate,
    ParetoObjectives,
    PIIRedactionEvalSample,
    PresidioPIIOptimizationEvaluator,
    ReflectiveMutatorProtocol,
    compute_pareto_frontier,
    dominates,
    run_gepa_optimize_anything,
    screen_candidate_security,
)
from src.eval_harness.harness import (
    CER_SCHEMA_VERSION,
    AnchorCalibrationResult,
    AnchorItem,
    ATIFStep,
    ATIFTrajectory,
    CerEvidenceLevel,
    ComposedDrawbackEvaluator,
    DPOPreferenceTriplet,
    DrawbackDetectorFn,
    DrawbackDetectorSpec,
    DrawbackVerdict,
    EvalBackendProtocol,
    EvaluationStepResult,
    FoundationModelEvalHarness,
    PairedCaseLift,
    PRMRewardSchedule,
    ShadowStateReducer,
    SkillCertificationReceipt,
    SkillEvalCase,
    SkillLiftReport,
    SkillPromptBucket,
    SkillTrajectoryScorecard,
    ToolActionStep,
    TrajectoryBenchmarkReport,
    TrajectoryHarvesterProtocol,
    build_default_drawback_detectors,
    default_shadow_state_reducer,
    lift_meets_threshold,
)
from src.eval_harness.runner import (
    MODEL_PRICING_CATALOG,
    ADKSessionRolloutAdapter,
    AgentRolloutRunner,
    BaseRolloutAdapter,
    CallableRolloutAdapter,
    HttpRolloutAdapter,
    LangGraphRolloutAdapter,
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
    DESTRUCTIVE_COMMAND_PATTERN,
    SkillStaticLintReport,
    lint_skill_file,
    lint_skill_markdown,
)

__all__ = [
    "CER_SCHEMA_VERSION",
    "DESTRUCTIVE_COMMAND_PATTERN",
    "MODEL_PRICING_CATALOG",
    "ADKSessionRolloutAdapter",
    "ATIFStep",
    "ATIFTrajectory",
    "ActionableSideInfo",
    "AgentRolloutRunner",
    "AnchorCalibrationResult",
    "AnchorItem",
    "BaseRolloutAdapter",
    "CageEvaluationBatch",
    "CageGEPAAdapter",
    "CallableRolloutAdapter",
    "CandidateSecurityReport",
    "CerEvidenceLevel",
    "ComposedDrawbackEvaluator",
    "DPOPreferenceTriplet",
    "DrawbackDetectorFn",
    "DrawbackDetectorSpec",
    "DrawbackVerdict",
    "EvalBackendProtocol",
    "EvaluationStepResult",
    "FoundationModelEvalHarness",
    "GEPAEvolutionEngine",
    "GEPAOptimizationResult",
    "HttpRolloutAdapter",
    "LangGraphRolloutAdapter",
    "MultiAgentRolloutAdapter",
    "PIIRedactionEvalSample",
    "PRMRewardSchedule",
    "PairedCaseLift",
    "PairedRolloutBundle",
    "ParetoCandidate",
    "ParetoObjectives",
    "PresidioPIIOptimizationEvaluator",
    "ReflectiveMutatorProtocol",
    "RolloutWorkspaceContext",
    "ShadowStateReducer",
    "SkillCertificationReceipt",
    "SkillEvalCase",
    "SkillLiftReport",
    "SkillPromptBucket",
    "SkillStaticLintReport",
    "SkillTrajectoryScorecard",
    "ToolActionStep",
    "TrajectoryBenchmarkReport",
    "TrajectoryHarvesterProtocol",
    "TrajectoryTokenomics",
    "adk_session_to_atif",
    "build_default_drawback_detectors",
    "compute_cost_savings_multiplier",
    "compute_pareto_frontier",
    "compute_trajectory_tokenomics",
    "default_shadow_state_reducer",
    "dominates",
    "estimate_token_count",
    "gemini_cli_jsonl_to_atif",
    "langgraph_state_to_atif",
    "lift_meets_threshold",
    "lint_skill_file",
    "lint_skill_markdown",
    "load_rollout_adapter",
    "run_certification_gate",
    "run_gepa_optimize_anything",
    "screen_candidate_security",
]
