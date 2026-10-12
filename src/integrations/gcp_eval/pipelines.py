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

"""Vertex AI Pipelines 3-Tier Skill Certification Orchestrator (`src/integrations/gcp_eval/pipelines.py`).

Defines the declarative Vertex AI Pipelines (KFP v2) DAG specification and
in-process pipeline executor for the CAGE 3-Tier CI/CD Skill Certification
workflow:
1. ``stage0_lint_and_synthesize``: Static `SKILL.md` lint + Tessl synthetic
   4-bucket task generation.
2. ``stage1_anchor_calibration``: Fail-closed Double Ratchet calibration on
   Golden Anchor datasets.
3. ``stage2_tier1_isolation_eval``: Paired Skill Lift evaluation in isolation.
4. ``stage2_tier2_decoy_collision_eval``: Paired Skill Lift + Routing Premium
   with 15-20 decoy skills injected to guard against ACES 50-Skill Routing Collapse.
5. ``stage3_publish_or_export``: Conditional branch publishing a KMS-signed
   `.cer` receipt to GCS on pass, or exporting PII-sanitized DPO/RLVR JSONL
   datasets on failure/narrowing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

DEFAULT_DECOY_SKILLS: tuple[str, ...] = tuple(
    f"decoy-domain-skill-{i:02d}" for i in range(1, 16)
)


@dataclass(frozen=True)
class PipelineStepSpec:
    """Single step in the Vertex AI Pipelines skill certification DAG."""

    step_id: str
    component_entrypoint: str
    depends_on: tuple[str, ...]
    parameters: dict[str, Any]
    condition: str | None = None


@dataclass(frozen=True)
class VertexSkillPipelineSpec:
    """Declarative KFP v2 / Vertex AI Pipeline specification for 3-Tier skill certification."""

    pipeline_name: str
    project_id: str
    location: str
    gcs_handshake_bucket: str
    kms_key_id: str
    decoy_skills: tuple[str, ...]
    steps: tuple[PipelineStepSpec, ...]

    def to_kfp_dict(self) -> dict[str, Any]:
        """Serialize to a declarative KFP v2 pipeline specification dictionary."""
        return {
            "pipelineInfo": {"name": self.pipeline_name},
            "sdkVersion": "kfp-2.x-cage-bridge",
            "deploymentConfig": {
                "project": self.project_id,
                "location": self.location,
                "gcsHandshakeBucket": self.gcs_handshake_bucket,
                "kmsKeyId": self.kms_key_id,
            },
            "steps": [
                {
                    "stepId": s.step_id,
                    "componentEntrypoint": s.component_entrypoint,
                    "dependsOn": list(s.depends_on),
                    "parameters": dict(s.parameters),
                    "condition": s.condition,
                }
                for s in self.steps
            ],
        }


def build_skill_certification_pipeline_spec(
    *,
    skill_name: str,
    project_id: str = "cage-gcp-prod",
    location: str = "us-central1",
    gcs_handshake_bucket: str = "cage-certified-skills",
    kms_key_id: str = "projects/cage/locations/global/keyRings/cer/cryptoKeys/ed25519/cryptoKeyVersions/1",
    decoy_skills: Sequence[str] | None = None,
    synthetic_case_count: int = 1000,
    min_static_score: float = 0.70,
    min_isolation_lift: float = 0.0,
) -> VertexSkillPipelineSpec:
    """Build the 3-Tier Vertex AI Pipeline DAG specification for `skill_name`."""
    effective_decoys = (
        tuple(decoy_skills) if decoy_skills is not None else DEFAULT_DECOY_SKILLS
    )
    if len(effective_decoys) < 15:
        raise ValueError(
            "Tier 2 Group/Collision Mode requires at least 15 decoy skills to test against ACES routing collapse"
        )

    steps = (
        PipelineStepSpec(
            step_id="stage0_lint_and_synthesize",
            component_entrypoint="src.integrations.gcp_eval.synthetic_generator:VertexSyntheticEvalGenerator.generate_eval_suite",
            depends_on=(),
            parameters={
                "skill_name": skill_name,
                "num_cases": synthetic_case_count,
                "min_static_score": min_static_score,
            },
        ),
        PipelineStepSpec(
            step_id="stage1_anchor_calibration",
            component_entrypoint="src.integrations.gcp_eval.vertex_evaluator:VertexGenAIEvalBackend.calibrate_on_vertex_anchor_dataset",
            depends_on=("stage0_lint_and_synthesize",),
            parameters={
                "min_weighted_agreement": 0.70,
                "fail_closed": True,
            },
        ),
        PipelineStepSpec(
            step_id="stage2_tier1_isolation_eval",
            component_entrypoint="src.eval_harness.cli:run_certification_gate",
            depends_on=("stage1_anchor_calibration",),
            parameters={
                "skill_name": skill_name,
                "decoy_skills": [],
                "min_composite_lift": min_isolation_lift,
                "eval_backend": "vertex",
            },
        ),
        PipelineStepSpec(
            step_id="stage2_tier2_decoy_collision_eval",
            component_entrypoint="src.eval_harness.cli:run_certification_gate",
            depends_on=("stage2_tier1_isolation_eval",),
            parameters={
                "skill_name": skill_name,
                "decoy_skills": list(effective_decoys),
                "min_composite_lift": min_isolation_lift,
                "eval_backend": "vertex",
            },
        ),
        PipelineStepSpec(
            step_id="stage3_publish_cer_to_gcs",
            component_entrypoint="src.integrations.gcp_eval.cer_publisher:GcsArtifactHandshakePublisher.publish_cer_receipt",
            depends_on=("stage2_tier2_decoy_collision_eval",),
            parameters={
                "bucket_name": gcs_handshake_bucket,
                "kms_key_id": kms_key_id,
                "if_generation_match": 0,
            },
            condition="stage2_tier2_decoy_collision_eval.outputs.certified == true",
        ),
        PipelineStepSpec(
            step_id="stage3_export_dpo_rlvr_dataset",
            component_entrypoint="src.eval_harness.harness:FoundationModelEvalHarness.export_hf_trl_jsonl",
            depends_on=("stage2_tier2_decoy_collision_eval",),
            parameters={
                "sanitize_pii": True,
                "destination_bucket": gcs_handshake_bucket,
            },
            condition="stage2_tier2_decoy_collision_eval.outputs.certified == false",
        ),
    )

    return VertexSkillPipelineSpec(
        pipeline_name=f"cage-3tier-skill-cert-{skill_name}",
        project_id=project_id,
        location=location,
        gcs_handshake_bucket=gcs_handshake_bucket,
        kms_key_id=kms_key_id,
        decoy_skills=effective_decoys,
        steps=steps,
    )


__all__ = [
    "DEFAULT_DECOY_SKILLS",
    "PipelineStepSpec",
    "VertexSkillPipelineSpec",
    "build_skill_certification_pipeline_spec",
]
