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

"""Google Cloud Platform (GCP) Plugin for the Offline Agent Evaluation Harness (`src/integrations/gcp_eval/`).

Layer 3 cloud integration package that extends CAGE's vendor-generic Offline
Evaluation & Certification Plane (`src/eval_harness/`) with native GCP services:
* **Vertex AI GenAI Evaluation Service** (`vertex_evaluator.py`)
* **Vertex AI Pipelines 3-Tier CI/CD Orchestration** (`pipelines.py`)
* **Tessl Synthetic Task Generation on Vertex Gemini** (`synthetic_generator.py`)
* **Cloud KMS `.cer` Signing, GCS Atomic Handshake, and JWKS Verification** (`cer_publisher.py`)
* **BigQuery Asynchronous Refusal & Drift Anchor Harvesting** (`bq_harvester.py`)
"""

from __future__ import annotations

from src.integrations.gcp_eval.bq_harvester import (
    BigQueryQuerySpec,
    BigQueryTrajectoryHarvester,
)
from src.integrations.gcp_eval.cer_publisher import (
    GcpSkillCertifier,
    GcsArtifactHandshakePublisher,
    GcsSkillCertificationVerifier,
    compute_file_sha256,
)
from src.integrations.gcp_eval.pipelines import (
    DEFAULT_DECOY_SKILLS,
    PipelineStepSpec,
    VertexSkillPipelineSpec,
    build_skill_certification_pipeline_spec,
)
from src.integrations.gcp_eval.synthetic_generator import (
    VertexSyntheticEvalGenerator,
)
from src.integrations.gcp_eval.vertex_evaluator import (
    VertexCustomMetricAdapter,
    VertexGenAIEvalBackend,
    VertexPointwiseRubricSpec,
    build_tessl_dual_rubric_specs,
    build_vertex_drawback_custom_metrics,
)

__all__ = [
    "DEFAULT_DECOY_SKILLS",
    "BigQueryQuerySpec",
    "BigQueryTrajectoryHarvester",
    "GcpSkillCertifier",
    "GcsArtifactHandshakePublisher",
    "GcsSkillCertificationVerifier",
    "PipelineStepSpec",
    "VertexCustomMetricAdapter",
    "VertexGenAIEvalBackend",
    "VertexPointwiseRubricSpec",
    "VertexSkillPipelineSpec",
    "VertexSyntheticEvalGenerator",
    "build_skill_certification_pipeline_spec",
    "build_tessl_dual_rubric_specs",
    "build_vertex_drawback_custom_metrics",
    "compute_file_sha256",
]
