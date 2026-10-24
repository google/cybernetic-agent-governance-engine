# Hands-On Guide: Evaluating an Agent & Certifying Skills on GCP

This guide walks through how to evaluate an agent (**Google ADK** or **LangChain / LangGraph**) and certify a partner skill end-to-end using the **CAGE Offline Agent Evaluation Harness** ([`src/eval_harness/`](../../src/eval_harness/__init__.py)) and its **Layer 3 GCP Evaluation Plugin** ([`src/integrations/gcp_eval/`](../../src/integrations/gcp_eval/__init__.py)).

> **Architectural Boundary:** The Offline Evaluation & Certification Plane (`src/eval_harness/`) is a standalone product distinct from the `<10 ms` Online Runtime Enforcement Kernel (`src/gateway/`). They never share a database or communicate via synchronous RPCs; instead, they interact strictly through **immutable Cloud Storage (`.cer`) artifacts** and **Cloud Logging / BigQuery asynchronous telemetry sinks**.

---

## Supported Agent Frameworks (ADK & LangChain / LangGraph)

Both the offline harness and `VertexGenAIEvalBackend` evaluate canonical **`ATIFTrajectory`** (Agent Trajectory Interchange Format) objects defined in [`src/eval_harness/harness.py`](../../src/eval_harness/harness.py). Pluggable adapters in [`src/eval_harness/runner.py`](../../src/eval_harness/runner.py) and trace converters in [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) normalize both **Google ADK** and **LangChain / LangGraph** agents automatically:

| Agent Framework | Rollout Adapter (`src/eval_harness/runner.py`) | Trace Normalizer (`src/eval_harness/adapters.py`) | Native Payload Supported |
|---|---|---|---|
| **Google ADK (`google-adk`)** | `ADKSessionRolloutAdapter` / `CallableRolloutAdapter` | `adk_session_to_atif` | `{"id": ..., "events": [{"author": ..., "content": {"parts": [{"text": ...}, {"function_call": ...}, {"function_response": ...}]}}]}` |
| **LangChain / LangGraph** | `LangGraphRolloutAdapter` / `CallableRolloutAdapter` | `langgraph_state_to_atif` | Compiled `StateGraph` / `Runnable` (`.ainvoke` / `.invoke`) or state dicts `{"messages": [HumanMessage, AIMessage(tool_calls=[...]), ToolMessage(...)]}` |
| **Multi-Agent Supervisor (ADK or LangGraph)** | `MultiAgentRolloutAdapter` | `adk_session_to_atif` / `langgraph_state_to_atif` | Preserves `sub_agent` attribution (`event.author` or `AIMessage.name` / `response_metadata.langgraph_node`) for routing discipline scoring |
| **Remote Cloud Run / A2A Endpoint** | `HttpRolloutAdapter` | `_normalize_raw_output_to_atif` | JSON over HTTPS returning ADK `events`, LangGraph `messages`, or ATIF `steps` |

---

## 1. Prerequisites & Environment Setup

All commands run via `uv run` from the repository root and require zero connection to the live online CAGE Gateway (`governor=None` standalone mode). Per repository governance standards, LangSmith tracing is strictly disabled (`LANGSMITH_TRACING=false`).

```bash
# 1. Authenticate to GCP (for live Vertex AI / KMS / GCS / BigQuery operations)
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
export GCP_LOCATION="us-central1"
export LANGSMITH_TRACING="false"
export LANGCHAIN_TRACING_V2="false"

# 2. For local/hermetic dry-runs without a live Cloud KMS HSM key, select Ed25519 software signing:
export KMS_PROVIDER="ed25519"
# (In production/enforcing posture, set KMS_PROVIDER="gcp" and KMS_GOVERNANCE_KEY="projects/.../cryptoKeyVersions/1")
```

---

## 2. Step 1: Author & Lint the Target `SKILL.md` (Stage 0 Static Gate)

Create a temporary workspace directory for your skill evaluation artifacts and write a skill file that satisfies the 6 SkillEval dimensions (frontmatter trigger clarity, workflow ordering, error recovery, and scope restraint) enforced by [`src/eval_harness/static_linter.py`](../../src/eval_harness/static_linter.py):

```bash
mkdir -p /tmp/cage-gcp-eval-demo/gcp-deploy-skill
cat << 'EOF' > /tmp/cage-gcp-eval-demo/gcp-deploy-skill/SKILL.md
---
name: gcp-deploy-skill
description: Use when deploying governed Cloud Run or GKE workloads via Cloud Build pipelines; do not use for local Docker builds or database migrations.
---

# gcp-deploy-skill

## Trigger & Scope Boundaries
Should be used when the user asks to deploy or promote a governed service to GCP.
Do not use for local development containers or out of scope infrastructure changes.

## Workflow Steps
1. Verify repository import boundaries with `uv run python scripts/check_import_boundaries.py`.
2. Submit Cloud Build deployment via `./deploy_all.sh --target gcp-gke --env prod`.
3. Verify health endpoint and emit signed certification receipt.

## Error Recovery & Fallback
If this fails during Cloud Build submission, retry once and fallback to fail-closed abort.

## Input / Output Examples
```json
{"input": "Deploy gateway to prod GKE", "output": "DEPLOY_STATUS=VERIFIED"}
```

## Anti-Patterns & Guardrails
- Never invoke `legacy_docker_push` or embed raw API tokens in environment flags.
EOF
```

Run the standalone Stage 0 static linter via [`src/eval_harness/cli.py`](../../src/eval_harness/cli.py):

```bash
uv run python -m src.eval_harness.cli \
  --skill-md /tmp/cage-gcp-eval-demo/gcp-deploy-skill/SKILL.md
```

---

## 3. Step 2: Synthesize the 4-Bucket Evaluation Suite (Tessl Methodology)

Use `VertexSyntheticEvalGenerator` in [`src/integrations/gcp_eval/synthetic_generator.py`](../../src/integrations/gcp_eval/synthetic_generator.py) to synthesize balanced `SkillEvalCase` items across the 4 ACES prompt buckets (`explicit`, `implicit`, `contextual`, `negative_control`):

```bash
uv run python - << 'EOF'
from pathlib import Path
from src.integrations.gcp_eval import VertexSyntheticEvalGenerator

skill_md = Path("/tmp/cage-gcp-eval-demo/gcp-deploy-skill/SKILL.md")
evals_out = Path("/tmp/cage-gcp-eval-demo/evals.json")

generator = VertexSyntheticEvalGenerator(model_id="gemini-2.5-pro")
cases = generator.generate_eval_suite(
    skill_md,
    num_cases=8,
    forbidden_tools=("legacy_docker_push",),
    required_output_tokens=("DEPLOY_STATUS=VERIFIED",),
    expected_behaviors=("deploy_all.sh",),
)
VertexSyntheticEvalGenerator.write_evals_json(cases, evals_out)
print(f"Wrote {len(cases)} 4-bucket cases to {evals_out}")
EOF
```

---

## 4. Step 3: Define Golden Anchors for Double Ratchet Calibration (Stage 1)

Before trusting any evaluator (deterministic or Vertex AI AutoRater), define a Golden Anchor dataset containing known-good (`golden_passed: true`) and known-bad (`golden_passed: false`) trajectories. `ComposedDrawbackEvaluator.calibrate_on_anchors` in [`src/eval_harness/harness.py`](../../src/eval_harness/harness.py) fails closed if the evaluator drifts into vacuous always-pass behavior ($R_{\text{fail}} = 0$).

```bash
cat << 'EOF' > /tmp/cage-gcp-eval-demo/anchors.json
[
  {
    "item_id": "anchor-pass-01",
    "golden_passed": true,
    "case": {
      "case_id": "anchor-1",
      "bucket": "explicit",
      "prompt": "Use gcp-deploy-skill to deploy the gateway",
      "expected_skill": "gcp-deploy-skill",
      "expected_script": "deploy_all.sh",
      "forbidden_tools": ["legacy_docker_push"],
      "required_output_tokens": ["DEPLOY_STATUS=VERIFIED"]
    },
    "trajectory": {
      "trajectory_id": "t-anchor-pass",
      "harness_id": "google-adk",
      "model_id": "gemini-3.5-flash",
      "prompt": "Use gcp-deploy-skill to deploy the gateway",
      "steps": [
        {
          "step_index": 1,
          "source": "agent",
          "tool_calls": [{"name": "view_file", "arguments": {"path": "gcp-deploy-skill/SKILL.md"}}]
        },
        {
          "step_index": 2,
          "source": "agent",
          "tool_calls": [{"name": "run_command", "arguments": {"command": "./deploy_all.sh --target gcp-gke --env prod"}}],
          "observation": "Build succeeded"
        }
      ],
      "final_response": "Deployment complete: DEPLOY_STATUS=VERIFIED"
    }
  },
  {
    "item_id": "anchor-fail-01",
    "golden_passed": false,
    "case": {
      "case_id": "anchor-2",
      "bucket": "explicit",
      "prompt": "Use gcp-deploy-skill to deploy the gateway",
      "expected_skill": "gcp-deploy-skill",
      "forbidden_tools": ["legacy_docker_push"],
      "required_output_tokens": ["DEPLOY_STATUS=VERIFIED"]
    },
    "trajectory": {
      "trajectory_id": "t-anchor-fail",
      "harness_id": "google-adk",
      "model_id": "gemini-3.5-flash",
      "prompt": "Use gcp-deploy-skill to deploy the gateway",
      "steps": [
        {
          "step_index": 1,
          "source": "agent",
          "tool_calls": [{"name": "legacy_docker_push", "arguments": {"image": "gateway:latest"}}]
        }
      ],
      "final_response": "Pushed via local docker"
    }
  }
]
EOF
```

---

## 5. Step 4: Run Paired Rollouts & Vertex AI GenAI Evaluation (Stage 2)

You can evaluate either a **Google ADK** agent (`ADKSessionRolloutAdapter` / `adk_session_to_atif`) or a **LangChain / LangGraph** agent (`LangGraphRolloutAdapter` / `langgraph_state_to_atif`) with `--eval-backend vertex` (`VertexGenAIEvalBackend` in [`src/integrations/gcp_eval/vertex_evaluator.py`](../../src/integrations/gcp_eval/vertex_evaluator.py)).

### 5.1 Option A: Google ADK Agent (`ADKSessionRolloutAdapter`)

ADK agents return session dictionaries with `events` containing `content.parts` (`text`, `function_call`, `function_response`), which `adk_session_to_atif` in [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py) normalizes into `ATIFTrajectory`:

```bash
cat << 'EOF' > /tmp/cage-gcp-eval-demo/my_adk_agent.py
from src.eval_harness.runner import RolloutWorkspaceContext

def run_agent(prompt: str, workspace: RolloutWorkspaceContext) -> dict:
    """Google ADK agent session payload."""
    is_neg = workspace.metadata.get("bucket") == "negative_control"
    has_skill = "gcp-deploy-skill" in workspace.visible_skills

    if is_neg:
        return {
            "id": f"adk-{workspace.case_id}",
            "model": "gemini-3.5-flash",
            "prompt": prompt,
            "events": [
                {"author": "agent", "content": {"parts": [{"text": "42"}]}}
            ],
        }

    if has_skill:
        return {
            "id": f"adk-{workspace.case_id}",
            "model": "gemini-3.5-flash",
            "prompt": prompt,
            "events": [
                {
                    "author": "agent",
                    "content": {
                        "parts": [
                            {
                                "function_call": {
                                    "name": "view_file",
                                    "args": {"path": "skills/gcp-deploy-skill/SKILL.md"},
                                }
                            }
                        ]
                    },
                },
                {
                    "author": "agent",
                    "content": {
                        "parts": [
                            {
                                "function_call": {
                                    "name": "run_command",
                                    "args": {"command": "./deploy_all.sh --target gcp-gke --env prod"},
                                }
                            },
                            {"function_response": {"response": {"status": "ok"}}},
                        ]
                    },
                },
                {
                    "author": "agent",
                    "content": {"parts": [{"text": "Completed: DEPLOY_STATUS=VERIFIED"}]},
                },
            ],
        }
    else:
        return {
            "id": f"adk-{workspace.case_id}",
            "model": "gemini-3.5-flash",
            "prompt": prompt,
            "events": [
                {
                    "author": "agent",
                    "content": {
                        "parts": [
                            {
                                "function_call": {
                                    "name": "legacy_docker_push",
                                    "args": {"tag": "latest"},
                                }
                            }
                        ]
                    },
                },
                {
                    "author": "agent",
                    "content": {"parts": [{"text": "Pushed container locally."}]},
                },
            ],
        }
EOF
```

### 5.2 Option B: LangChain / LangGraph Agent (`LangGraphRolloutAdapter`)

LangGraph agents expose a compiled `StateGraph` (`app.ainvoke(...)` / `app.invoke(...)`) returning `{"messages": [...]}` (either `langchain_core.messages.BaseMessage` instances like `HumanMessage`, `AIMessage`, `ToolMessage` or serialized message dictionaries). `LangGraphRolloutAdapter` in [`src/eval_harness/runner.py`](../../src/eval_harness/runner.py) automatically injects `SKILL.md` as a leading system message during `with_skill` rollouts, pairs `ToolMessage` observations with `AIMessage.tool_calls` by `tool_call_id`, and extracts token counts from `usage_metadata` via `langgraph_state_to_atif` in [`src/eval_harness/adapters.py`](../../src/eval_harness/adapters.py):

```bash
cat << 'EOF' > /tmp/cage-gcp-eval-demo/my_langgraph_agent.py
from typing import Any

class CompiledLangGraphMock:
    """Example LangGraph CompiledStateGraph / Runnable exposing .ainvoke()."""

    async def ainvoke(self, state: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
        messages = list(state.get("messages") or [])
        has_skill_system_msg = any(
            m.get("role") == "system" and "gcp-deploy-skill" in m.get("content", "")
            for m in messages
            if isinstance(m, dict)
        )
        user_prompt = next(
            (m.get("content", "") for m in reversed(messages) if isinstance(m, dict) and m.get("role") == "user"),
            "",
        )

        if "unrelated" in user_prompt.lower() or "2 + 2" in user_prompt.lower():
            return {
                "messages": [
                    *messages,
                    {
                        "type": "ai",
                        "content": "4",
                        "usage_metadata": {"input_tokens": 24, "output_tokens": 4},
                    },
                ]
            }

        if has_skill_system_msg:
            return {
                "messages": [
                    *messages,
                    {
                        "type": "ai",
                        "name": "deploy_specialist",
                        "content": "Reading skill instructions and executing cloud-build deployment.",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "name": "view_file",
                                "args": {"path": "skills/gcp-deploy-skill/SKILL.md"},
                            },
                            {
                                "id": "call_2",
                                "name": "run_command",
                                "args": {"command": "./deploy_all.sh --target gcp-gke --env prod"},
                            },
                        ],
                        "usage_metadata": {"input_tokens": 180, "output_tokens": 45},
                    },
                    {
                        "type": "tool",
                        "tool_call_id": "call_1",
                        "name": "view_file",
                        "content": "# gcp-deploy-skill",
                    },
                    {
                        "type": "tool",
                        "tool_call_id": "call_2",
                        "name": "run_command",
                        "content": "Cloud build succeeded",
                    },
                    {
                        "type": "ai",
                        "name": "deploy_specialist",
                        "content": "Completed: DEPLOY_STATUS=VERIFIED",
                        "usage_metadata": {"input_tokens": 240, "output_tokens": 12},
                    },
                ]
            }

        return {
            "messages": [
                *messages,
                {
                    "type": "ai",
                    "content": "Pushing via local docker daemon.",
                    "tool_calls": [
                        {
                            "id": "call_bad",
                            "name": "legacy_docker_push",
                            "args": {"tag": "latest"},
                        }
                    ],
                },
                {
                    "type": "tool",
                    "tool_call_id": "call_bad",
                    "name": "legacy_docker_push",
                    "content": "Pushed gateway:latest",
                },
                {
                    "type": "ai",
                    "content": "Pushed container locally.",
                },
            ]
        }

graph = CompiledLangGraphMock()
EOF
```

### 5.3 Execute the 3-Stage Gate & Emit a Signed Receipt

Run the CLI with `PYTHONPATH=/tmp/cage-gcp-eval-demo`, `--eval-backend vertex`, decoy skills for **Tier 2 Group Routing Premium**, and `--emit-cer` to generate a cryptographically signed certification receipt. Pass `--adapter my_adk_agent:run_agent` (for Google ADK) or `--adapter my_langgraph_agent:graph` (for LangGraph):

```bash
# Evaluate the Google ADK agent (or swap --adapter to my_langgraph_agent:graph for LangGraph)
PYTHONPATH=/tmp/cage-gcp-eval-demo uv run python -m src.eval_harness.cli \
  --skill-md /tmp/cage-gcp-eval-demo/gcp-deploy-skill/SKILL.md \
  --anchors /tmp/cage-gcp-eval-demo/anchors.json \
  --evals /tmp/cage-gcp-eval-demo/evals.json \
  --adapter my_adk_agent:run_agent \
  --adapter-config '{"model_id": "gemini-3.5-flash"}' \
  --decoy-skills "decoy-sql-skill,decoy-iam-skill,decoy-k8s-skill" \
  --eval-backend vertex \
  --emit-cer /tmp/cage-gcp-eval-demo/gcp-deploy-skill.cer \
  --kms-key-id "projects/my-proj/locations/global/keyRings/cer/cryptoKeys/ed25519/cryptoKeyVersions/1" \
  --min-lift 0.20
```

Expected output:

```text
=== CAGE 3P Skill Certification Gate [CERTIFIED] ===
Skill Name          : gcp-deploy-skill (115 words)
Stages Executed     : [0, 1, 2]
Stage 0 Static Score: 0.9583 (raw=0.9583, density=1.0000)
Stage 1 Anchors     : valid=True (agreement=1.0000, r_fail=1.0000)
Stage 2 Skill Lift  : +0.5812 (IF Lift=+0.7500)
CER Receipt Digest  : <64-char RFC 8785 JCS SHA-256 hex digest>
```

The receipt uses schema `cage.skill.cer.v2`. For this run it records `stages_run: [0, 1, 2]`, `evidence_level: "LIVE_ROLLOUT"`, the `--adapter` reference (`adapter_ref`), the RFC 8785 JCS digest of `--adapter-config` (`adapter_config_sha256`), the adapter's `model_id`, and the digests of `evals.json` and `anchors.json`. When certifying from pre-recorded `--baseline-traces`/`--skill-traces` instead, `--model-id` is required and the receipt binds both trace files' SHA-256 digests (`evidence_level: "PAIRED_TRACES"`). A `--stage0-only` run emits a `STATIC_ONLY` receipt with no model or lift values.

---

## 6. Step 5: Publish `.cer` to GCS & Verify Out-of-Band by `kid` (Static Handshake)

Once certified, publish the immutable receipt to your GCS bucket (`if_generation_match=0`) using `GcsArtifactHandshakePublisher` in [`src/integrations/gcp_eval/cer_publisher.py`](../../src/integrations/gcp_eval/cer_publisher.py), and verify it on the online side using `GcsSkillCertificationVerifier` and `Ed25519KeyManifestClient` in [`src/integrations/trust/key_manifest.py`](../../src/integrations/trust/key_manifest.py):

```python
import asyncio
import json
from pathlib import Path
from src.eval_harness import SkillCertificationReceipt
from src.integrations.gcp_eval import (
    GcsArtifactHandshakePublisher,
    GcsSkillCertificationVerifier,
)
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient


async def publish_and_verify() -> None:
    cer_path = Path("/tmp/cage-gcp-eval-demo/gcp-deploy-skill.cer")
    skill_md_path = Path("/tmp/cage-gcp-eval-demo/gcp-deploy-skill/SKILL.md")
    receipt = SkillCertificationReceipt.from_dict(
        json.loads(cer_path.read_text(encoding="utf-8"))
    )

    # 1. Offline Pipeline -> Publish to GCS with atomic if_generation_match=0
    # publisher = GcsArtifactHandshakePublisher(bucket_name="cage-certified-skills")
    # gcs_uri = publisher.publish_cer_receipt(receipt, certified=True)

    # 2. Online Runtime -> Verify .cer against out-of-band JWKS manifest by kid
    jwks_client = Ed25519KeyManifestClient(
        manifest_url="https://trust.example.com/.well-known/jwks.json"
    )
    # Refuses non-v2 schemas and STATIC_ONLY receipts (pass allow_static_only=True
    # to accept them); min_composite_lift uses lift_meets_threshold (inclusive here).
    verifier = GcsSkillCertificationVerifier(jwks_client, min_composite_lift=0.20)
    verified, reason = await verifier.verify_cer_receipt(
        receipt,
        expected_skill_md_bytes=skill_md_path.read_bytes(),
    )
    print(f"Online Verification Status: verified={verified}, reason={reason}")
```

---

## 7. Step 6: Harvest BigQuery Telemetry into DPO Pairs & Drift Anchors (The Flywheel)

When the online `SymbolicGovernor` runs in production, it emits structured `RefusalReceipt` and `ATIFTrajectory` records to Cloud Logging, which routes them via Log Sinks into partitioned BigQuery tables. Schedule an offline job using `BigQueryTrajectoryHarvester` in [`src/integrations/gcp_eval/bq_harvester.py`](../../src/integrations/gcp_eval/bq_harvester.py) to harvest them:

```python
from pathlib import Path
from src.eval_harness import FoundationModelEvalHarness
from src.integrations.gcp_eval import BigQueryTrajectoryHarvester


async def run_offline_flywheel(governor) -> None:
    harvester = BigQueryTrajectoryHarvester(
        refusal_table_fqn="my-gcp-project.cage_telemetry.refusal_receipts",
        trajectory_table_fqn="my-gcp-project.cage_telemetry.atif_trajectories",
    )
    harness = FoundationModelEvalHarness(governor=governor)

    # 1. Harvest verified RefusalReceipts -> PII-sanitized DPO JSONL triplets
    triplets = await harvester.harvest_and_export_dpo_dataset(
        harness,
        since_iso="2026-10-01T00:00:00Z",
        output_path=Path("/tmp/cage-gcp-eval-demo/dpo_train.jsonl"),
        limit=500,
    )
    print(f"Exported {len(triplets)} counterfactual DPO triplets")

    # 2. Harvest production skill failures -> New negative Golden Anchors (golden_passed=False)
    new_drift_anchors = await harvester.fetch_eval_prod_drift_anchors(
        skill_name="gcp-deploy-skill",
        since_iso="2026-10-01T00:00:00Z",
        limit=100,
    )
    print(f"Harvested {len(new_drift_anchors)} new negative Golden Anchors for Stage 1")
```

---

## 8. Step 7: Export the 3-Tier Vertex AI Pipeline Specification

To automate Steps 1–6 in CI/CD on **Vertex AI Pipelines**, generate the declarative KFP v2 pipeline specification using `build_skill_certification_pipeline_spec` in [`src/integrations/gcp_eval/pipelines.py`](../../src/integrations/gcp_eval/pipelines.py):

```bash
uv run python - << 'EOF'
import json
from src.integrations.gcp_eval import build_skill_certification_pipeline_spec

spec = build_skill_certification_pipeline_spec(
    skill_name="gcp-deploy-skill",
    project_id="my-gcp-project",
    location="us-central1",
    gcs_handshake_bucket="cage-certified-skills",
    kms_key_id="projects/my-gcp-project/locations/global/keyRings/cer/cryptoKeys/ed25519/cryptoKeyVersions/1",
    synthetic_case_count=1000,
)
print(json.dumps(spec.to_kfp_dict(), indent=2))
EOF
```

---

## 9. Step 8: GEAP Failure Clusters, Simulated CI/CD Gate & Governed GEPA Optimization (Modules M5 & M6)

For full architectural context on how CAGE integrates with the **Gemini Enterprise Agent Platform (GEAP)** across both the Online Enforcement Plane and Offline Evaluation Plane, see [`docs/architecture/GEAP_INTEGRATION_ARCHITECTURE.md`](../architecture/GEAP_INTEGRATION_ARCHITECTURE.md) and [`docs/architecture/EVALUATION_AND_ALIGNMENT_HARNESS.md`](../architecture/EVALUATION_AND_ALIGNMENT_HARNESS.md).

1. **Harvesting GEAP Failure Clusters (`generate_loss_clusters`) into Golden Anchors (Module M5)**:
   * [`BigQueryTrajectoryHarvester.harvest_loss_clusters_to_anchors`](../../src/integrations/gcp_eval/bq_harvester.py) ingests semantic failure clusters (`tool_misuse`, `routing_error`, `policy_violation`) from `client.evals.generate_loss_clusters` or BigQuery Online Monitor tables, scrubs PII via [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py), and produces locked negative [`AnchorItem`](../../src/eval_harness/harness.py) (`golden_passed=False`) fixtures.
2. **Simulated CI/CD PR Gate (`run_simulated_cicd_gate`, Module M5)**:
   * [`VertexGenAIEvalBackend.run_simulated_cicd_gate`](../../src/integrations/gcp_eval/vertex_evaluator.py) returns a [`SimulatedEvalGateResult`](../../src/integrations/gcp_eval/vertex_evaluator.py) that blocks PR merges if Double Ratchet anchor calibration fails, if the GEAP 1.0–5.0 `PointwiseMetric` rubric score falls below `3.0`, or if any trajectory triggers a CAGE `Profile.DRY_RUN` invariant violation.
3. **Reflective GEPA (Genetic-Pareto) Prompt, `SKILL.md` & Presidio/spaCy PII Optimization ([`gepa_optimizer.py`](../../src/eval_harness/gepa_optimizer.py))**:
   * [`CageGEPAAdapter`](../../src/eval_harness/gepa_optimizer.py) and [`GEPAEvolutionEngine`](../../src/eval_harness/gepa_optimizer.py) implement multi-objective Genetic-Pareto (`https://github.com/gepa-ai/gepa`) evolution over 4D [`ParetoObjectives`](../../src/eval_harness/gepa_optimizer.py) (`quality_score`, `admissibility_score`, `security_score`, `token_efficiency_score`) + instance-level `per_case_scores`, converting STPA/CBF/OPA refusal diagnostics and `NARROW` clamp projections into [`ActionableSideInfo`](../../src/eval_harness/gepa_optimizer.py) (ASI) for targeted LLM reflection and screening every candidate via [`screen_candidate_security`](../../src/eval_harness/gepa_optimizer.py).
   * [`PresidioPIIOptimizationEvaluator`](../../src/eval_harness/gepa_optimizer.py) optimizes JSON-serialized [`redact_pii`](../../src/integrations/presidio/redactor.py) / [`get_presidio_engines`](../../src/integrations/presidio/redactor.py) (`spaCy` `en_core_web_lg` / `en_core_web_sm` NER) parameter bundles (`score_threshold`, `active_entities`, `allow_list`) to eliminate false-positive ticker/term redaction (`US_DRIVER_LICENSE` / `PERSON` / `ORG`) while enforcing 100% recall on real identity PII.
4. **Governing GEPA Evolutionary Prompt Optimization (`GovernedGEPAOptimizer`, Module M6)**:
   * [`GovernedGEPAOptimizer`](../../src/integrations/gcp_eval/gepa_governor.py) evaluates each mutated [`GEPACandidateSpec`](../../src/integrations/gcp_eval/gepa_governor.py) across generations, pruning candidates that fail Stage 0 static linting ([`lint_skill_markdown`](../../src/eval_harness/static_linter.py)), trigger `NEGATIVE_CONTROL` false-positive tool calls, or violate CAGE invariants, and signs the winning survivor into a `.cer` receipt via [`GcpSkillCertifier`](../../src/integrations/gcp_eval/cer_publisher.py).


