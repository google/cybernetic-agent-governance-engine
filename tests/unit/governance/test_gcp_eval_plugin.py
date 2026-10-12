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

"""Unit tests for the GCP Plugin of the Offline Agent Evaluation Harness (`src/integrations/gcp_eval/`)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.eval_harness import (
    AnchorItem,
    ATIFStep,
    ATIFTrajectory,
    ComposedDrawbackEvaluator,
    FoundationModelEvalHarness,
    SkillCertificationReceipt,
    SkillEvalCase,
    SkillPromptBucket,
    build_default_drawback_detectors,
)
from src.eval_harness.cli import main as cli_main
from src.eval_harness.static_linter import lint_skill_file
from src.gateway.governance.contracts import (
    NarrowingResult,
    ReadOnlyTier,
    RefusalReceipt,
    Violation,
    ViolationKind,
)
from src.gateway.governance.kms_signer import SoftwareEd25519Provider
from src.gateway.governance.narrower import NarrowerRegistry
from src.integrations.gcp_eval import (
    DEFAULT_DECOY_SKILLS,
    BigQueryTrajectoryHarvester,
    GcpSkillCertifier,
    GcsArtifactHandshakePublisher,
    GcsSkillCertificationVerifier,
    VertexGenAIEvalBackend,
    VertexSyntheticEvalGenerator,
    build_skill_certification_pipeline_spec,
    build_tessl_dual_rubric_specs,
    build_vertex_drawback_custom_metrics,
)
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient
from tests.fixtures.governor import default_classifier, make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _write_valid_skill_md(tmp_path: Path, name: str = "gcp-deploy-skill") -> Path:
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text(
        f"""---
name: {name}
description: Use when deploying governed Cloud Run or GKE workloads via Cloud Build pipelines; do not use for local Docker builds or database migrations.
---

# {name}

## Trigger & Scope Boundaries
Should be used when the user asks to deploy or promote a governed service to GCP.
Do not use for local development containers or out of scope infrastructure changes.

## Workflow Steps
1. Verify repository import boundaries with `uv run python scripts/check_import_boundaries.py`.
2. Submit Cloud Build deployment via `scripts/deploy_cloudbuild.py --env prod`.
3. Verify health endpoint and emit signed `.cer` receipt.

## Error Recovery & Fallback
If this fails during Cloud Build submission, retry once and fallback to fail-closed abort.

## Input / Output Examples
```json
{{"input": "Deploy gateway to prod GKE", "output": "DEPLOY_STATUS=VERIFIED"}}
```

## Anti-Patterns & Guardrails
- Never invoke `legacy_docker_push` or embed raw API tokens in environment flags.
""",
        encoding="utf-8",
    )
    return skill_md


def _make_ed25519_provider_and_jwks(
    tmp_path: Path, kid: str = "cage-cer-key-01"
) -> tuple[SoftwareEd25519Provider, Ed25519KeyManifestClient]:
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    pub_raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_b64 = base64.urlsafe_b64encode(pub_raw).decode("ascii").rstrip("=")

    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": kid,
                        "x": x_b64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    provider = SoftwareEd25519Provider(key_id=kid, private_key=priv_key)
    manifest_client = Ed25519KeyManifestClient(manifest_url=jwks_path.as_uri())
    return provider, manifest_client


class _FakeGcsBlob:
    def __init__(self, name: str, store: dict[str, dict[str, Any]]) -> None:
        self.name = name
        self._store = store

    def upload_from_string(
        self,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        if_generation_match: int | None = None,
    ) -> None:
        if if_generation_match == 0 and self.name in self._store:
            raise RuntimeError(
                f"PreconditionFailed: blob {self.name!r} already exists (if_generation_match=0)"
            )
        self._store[self.name] = {
            "data": data,
            "content_type": content_type,
            "if_generation_match": if_generation_match,
        }


class _FakeGcsBucket:
    def __init__(self, name: str, store: dict[str, dict[str, Any]]) -> None:
        self.name = name
        self._store = store

    def blob(self, object_key: str) -> _FakeGcsBlob:
        return _FakeGcsBlob(object_key, self._store)


class _FakeGcsClient:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}

    def bucket(self, name: str) -> _FakeGcsBucket:
        return _FakeGcsBucket(name, self.objects)


class _FakeBqClient:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.queries: list[str] = []

    def query(self, sql: str, **kwargs: Any) -> list[dict[str, Any]]:
        self.queries.append(sql)
        return list(self._rows)


@pytest.mark.asyncio
async def test_cer_signing_and_out_of_band_kid_verification(tmp_path: Path) -> None:
    """Verify KMS `.cer` receipt signing and fail-closed verification via JWKS `kid`."""
    skill_md = _write_valid_skill_md(tmp_path)
    static_report = lint_skill_file(skill_md)
    assert static_report.passed

    provider, jwks_client = _make_ed25519_provider_and_jwks(
        tmp_path, kid="cage-cer-key-01"
    )
    certifier = GcpSkillCertifier(
        key_id="cage-cer-key-01",
        kms_provider=provider,
    )
    receipt = certifier.create_and_sign_receipt(
        skill_md_path=skill_md,
        static_report=static_report,
    )

    verifier = GcsSkillCertificationVerifier(jwks_client)
    ok, reason = await verifier.verify_cer_receipt(
        receipt.to_dict(),
        expected_skill_md_bytes=skill_md.read_bytes(),
    )
    assert ok is True
    assert reason == "VERIFIED"

    # 1. Fail closed on SKILL.md SHA-256 mismatch
    ok_tampered_md, reason_md = await verifier.verify_cer_receipt(
        receipt.to_dict(),
        expected_skill_md_bytes=b"tampered skill markdown",
    )
    assert ok_tampered_md is False
    assert reason_md == "skill_md_sha256_mismatch"

    # 2. Fail closed on unknown kid
    unknown_kid_dict = receipt.to_dict()
    unknown_kid_dict["signature"]["keyId"] = "unknown-kid-999"
    # Recompute outer digest so signature check is reached
    tampered_receipt = SkillCertificationReceipt.from_dict(unknown_kid_dict)
    unknown_kid_dict["receiptDigest"] = tampered_receipt.compute_signed_digest()
    ok_kid, reason_kid = await verifier.verify_cer_receipt(unknown_kid_dict)
    assert ok_kid is False
    assert reason_kid == "unknown_kid:unknown-kid-999"

    # 3. Fail closed on payload tampering (mean_composite_lift modified after signing)
    forged_dict = receipt.to_dict()
    forged_dict["mean_composite_lift"] = 0.9999
    forged_receipt = SkillCertificationReceipt.from_dict(forged_dict)
    forged_dict["receiptDigest"] = forged_receipt.compute_signed_digest()
    ok_sig, reason_sig = await verifier.verify_cer_receipt(forged_dict)
    assert ok_sig is False
    assert reason_sig == "ed25519_signature_verification_failed"


def test_gcs_handshake_publisher_atomic_immutability_and_path_hygiene(
    tmp_path: Path,
) -> None:
    """Verify GCS publisher enforces `if_generation_match=0` and blocks uncertified or path-traversal uploads."""
    skill_md = _write_valid_skill_md(tmp_path)
    static_report = lint_skill_file(skill_md)
    provider, _ = _make_ed25519_provider_and_jwks(tmp_path)
    certifier = GcpSkillCertifier(key_id="cage-cer-key-01", kms_provider=provider)
    receipt = certifier.create_and_sign_receipt(
        skill_md_path=skill_md,
        static_report=static_report,
    )

    fake_gcs = _FakeGcsClient()
    publisher = GcsArtifactHandshakePublisher(
        "cage-certified-skills",
        storage_client=fake_gcs,
    )

    # Refuses when certified=False
    with pytest.raises(ValueError, match="certified=False"):
        publisher.publish_cer_receipt(receipt, certified=False)

    uri = publisher.publish_cer_receipt(receipt, certified=True)
    assert uri.startswith("gs://cage-certified-skills/skills/gcp-deploy-skill/")
    assert uri.endswith(".cer")

    # Second upload of same immutable receipt must fail closed via if_generation_match=0
    with pytest.raises(RuntimeError, match="if_generation_match=0"):
        publisher.publish_cer_receipt(receipt, certified=True)

    # Policy & terminal registry bundle upload
    reg_uri, rego_uri = publisher.publish_policy_and_registry_bundle(
        domain="finance",
        terminal_registry={"allowed_skills": ["gcp-deploy-skill"]},
        rego_policy_text="package cage.finance\ndefault allow = false\n",
    )
    assert reg_uri == "gs://cage-certified-skills/manifests/finance/terminal_registry.json"
    assert rego_uri == "gs://cage-certified-skills/policies/finance.rego"

    # Reject path traversal in domain identifier
    with pytest.raises(ValueError, match="Invalid domain"):
        publisher.publish_policy_and_registry_bundle(
            domain="../etc/passwd",
            terminal_registry={},
            rego_policy_text="",
        )


@pytest.mark.asyncio
async def test_vertex_genai_eval_backend_and_anchor_calibration() -> None:
    """Verify Vertex CustomMetric AutoRaters, Tessl dual rubrics, and fail-closed Anchor Calibration."""
    harness = FoundationModelEvalHarness(governor=None)
    backend = VertexGenAIEvalBackend(experiment_name="vertex-aces-exp")

    case_exp = SkillEvalCase(
        case_id="c-exp-1",
        bucket=SkillPromptBucket.EXPLICIT,
        prompt="Use gcp-deploy-skill to deploy gateway",
        expected_skill="gcp-deploy-skill",
        expected_script="deploy_cloudbuild.py",
        forbidden_tools=("legacy_docker_push",),
        required_output_tokens=("DEPLOY_STATUS=VERIFIED",),
        expected_behaviors=("deploy_cloudbuild.py",),
    )
    case_neg = SkillEvalCase(
        case_id="c-neg-1",
        bucket=SkillPromptBucket.NEGATIVE_CONTROL,
        prompt="What is 12 * 12?",
        expected_skill="gcp-deploy-skill",
    )

    good_traj = ATIFTrajectory(
        trajectory_id="t-good",
        harness_id="vertex-adk",
        model_id="gemini-3.5-flash",
        prompt=case_exp.prompt,
        steps=(
            ATIFStep(
                step_index=1,
                source="agent",
                tool_calls=(
                    {
                        "name": "view_file",
                        "arguments": {"path": "skills/gcp-deploy-skill/SKILL.md"},
                    },
                ),
            ),
            ATIFStep(
                step_index=2,
                source="agent",
                tool_calls=(
                    {
                        "name": "run_command",
                        "arguments": {
                            "command": "python scripts/deploy_cloudbuild.py --env prod"
                        },
                    },
                ),
                observation="Cloud build succeeded",
            ),
        ),
        final_response="Deployment finished: DEPLOY_STATUS=VERIFIED",
    )
    bad_traj = ATIFTrajectory(
        trajectory_id="t-bad",
        harness_id="vertex-adk",
        model_id="gemini-3.5-flash",
        prompt=case_exp.prompt,
        steps=(
            ATIFStep(
                step_index=1,
                source="agent",
                tool_calls=(
                    {
                        "name": "legacy_docker_push",
                        "arguments": {"tag": "latest"},
                    },
                ),
            ),
        ),
        final_response="Pushed without reading skill",
    )
    neg_clean_traj = ATIFTrajectory(
        trajectory_id="t-neg",
        harness_id="vertex-adk",
        model_id="gemini-3.5-flash",
        prompt=case_neg.prompt,
        steps=(),
        final_response="144",
    )

    # 1. Calibrate on Golden Anchor Dataset via Vertex backend
    anchor_res = backend.calibrate_on_vertex_anchor_dataset(
        harness.drawback_evaluator,
        [
            AnchorItem(
                item_id="a-pass",
                case=case_exp,
                trajectory=good_traj,
                golden_passed=True,
            ),
            AnchorItem(
                item_id="a-fail",
                case=case_exp,
                trajectory=bad_traj,
                golden_passed=False,
            ),
        ],
    )
    assert anchor_res.valid is True
    assert anchor_res.weighted_agreement == 1.0

    # 2. Evaluate Paired Skill Lift through VertexGenAIEvalBackend
    lift_report = await backend.evaluate_paired_skill_lift(
        harness=harness,
        skill_name="gcp-deploy-skill",
        model_id="gemini-3.5-flash",
        cases=[case_exp, case_neg],
        baseline_trajectories={"c-exp-1": bad_traj, "c-neg-1": neg_clean_traj},
        with_skill_trajectories={"c-exp-1": good_traj, "c-neg-1": neg_clean_traj},
    )
    assert lift_report.mean_composite_lift > 0.3
    assert lift_report.mean_instruction_following_lift >= 0.5
    assert backend.last_experiment_run_metrics["evaluated_rows"] == 2
    assert "tessl_goal_completion" in backend.last_experiment_run_metrics["rubrics"]

    # 3. Verify custom metric adapters directly
    custom_metrics = build_vertex_drawback_custom_metrics(
        build_default_drawback_detectors(),
        {"c-exp-1": case_exp},
    )
    assert len(custom_metrics) == 5
    goal_rubric, proc_rubric = build_tessl_dual_rubric_specs()
    assert goal_rubric.dimension == "goal_accuracy"
    assert proc_rubric.dimension == "instruction_following"


def test_synthetic_eval_generator_and_vertex_pipeline_spec(tmp_path: Path) -> None:
    """Verify Tessl 4-bucket synthetic task generation and 3-Tier Vertex AI Pipeline DAG spec."""
    skill_md = _write_valid_skill_md(tmp_path)
    gen = VertexSyntheticEvalGenerator(model_id="gemini-2.5-pro")
    cases = gen.generate_eval_suite(
        skill_md,
        num_cases=16,
        forbidden_tools=("legacy_docker_push",),
        required_output_tokens=("DEPLOY_STATUS=VERIFIED",),
    )
    assert len(cases) == 16
    buckets = [c.bucket for c in cases]
    assert buckets.count(SkillPromptBucket.EXPLICIT) == 4
    assert buckets.count(SkillPromptBucket.IMPLICIT) == 4
    assert buckets.count(SkillPromptBucket.CONTEXTUAL) == 4
    assert buckets.count(SkillPromptBucket.NEGATIVE_CONTROL) == 4

    out_evals = VertexSyntheticEvalGenerator.write_evals_json(
        cases, tmp_path / "evals.json"
    )
    assert out_evals.exists()

    pipeline_spec = build_skill_certification_pipeline_spec(
        skill_name="gcp-deploy-skill",
        decoy_skills=DEFAULT_DECOY_SKILLS,
    )
    kfp_dict = pipeline_spec.to_kfp_dict()
    assert len(kfp_dict["steps"]) == 6
    assert len(pipeline_spec.decoy_skills) == 15

    # Reject fewer than 15 decoys for Tier 2 collision mode
    with pytest.raises(ValueError, match="at least 15 decoy skills"):
        build_skill_certification_pipeline_spec(
            skill_name="gcp-deploy-skill",
            decoy_skills=("only-one-decoy",),
        )


class _SimpleCapTier(ReadOnlyTier):
    @property
    def tier_name(self) -> str:
        return "simple_cap_tier"

    @property
    def order(self) -> int:
        return 10

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_transfer"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        cap = float(params.get("remaining_headroom", 50_000.0))
        if amount > cap:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CAP_EXCEEDED",
                    message="Exceeds cap",
                    kind=ViolationKind.NARROWABLE,
                    bound=cap,
                )
            ]
        return []


class _SimpleCapNarrower:
    def can_narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> bool:
        return action == "execute_transfer" and violation.kind == ViolationKind.NARROWABLE

    def narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> NarrowingResult | None:
        clamped = dict(params)
        clamped["amount"] = violation.bound or 50_000.0
        return NarrowingResult(
            can_narrow=True,
            narrowed_params=clamped,
            constraints_applied=["amount<=cap"],
            narrowing_reason="Clamped transfer amount to cap",
        )


@pytest.mark.asyncio
async def test_bigquery_harvester_parameterized_queries_and_flywheel(
    tmp_path: Path,
) -> None:
    """Verify BigQueryTrajectoryHarvester uses parameterized queries, verifies proof_hash, and builds drift anchors."""
    # Reject SQL injection in table FQN
    with pytest.raises(ValueError, match="Invalid BigQuery table FQN"):
        BigQueryTrajectoryHarvester(
            refusal_table_fqn="project.dataset.table; DROP TABLE users--"
        )

    unsigned_receipt = RefusalReceipt(
        thread_id="t-bq-101",
        action="execute_transfer",
        violated_tier="simple_cap_tier",
        violated_rule="CAP_EXCEEDED",
        standing_at_refusal={"remaining_headroom": 25_000.0},
        timestamp=1710000000.0,
        attempted_params={"amount": 80_000.0, "memo": "Contact alice@example.com"},
    )
    valid_receipt = RefusalReceipt(
        **{
            **unsigned_receipt.__dict__,
            "proof_hash": unsigned_receipt.compute_proof_hash(),
        }
    )

    bq_refusal_row = {
        "thread_id": valid_receipt.thread_id,
        "action": valid_receipt.action,
        "violated_tier": valid_receipt.violated_tier,
        "violated_rule": valid_receipt.violated_rule,
        "standing_at_refusal": json.dumps(valid_receipt.standing_at_refusal),
        "timestamp": valid_receipt.timestamp,
        "proof_hash": valid_receipt.proof_hash,
        "schema_version": valid_receipt.schema_version,
        "attempted_params": json.dumps(valid_receipt.attempted_params),
        "standing_snapshot": "{}",
        "control_id": "",
        "protected_consequence": "",
        "non_formation_proof": "",
        "tier_failures": "[]",
        "reliance": "[]",
    }

    fake_bq = _FakeBqClient([bq_refusal_row])
    harvester = BigQueryTrajectoryHarvester(
        refusal_table_fqn="cage-prod.cage_telemetry.refusal_receipts",
        trajectory_table_fqn="cage-prod.cage_telemetry.atif_trajectories",
        bq_client=fake_bq,
    )

    reg = NarrowerRegistry([_SimpleCapNarrower()])
    classifier = default_classifier(narrower_registry=reg, narrow_enabled=True)
    gov = make_governor(
        core_stages=(),
        classifier=classifier,
        domain_tiers=(_SimpleCapTier(),),
    )
    harness = FoundationModelEvalHarness(governor=gov)

    dpo_path = tmp_path / "bq_dpo.jsonl"
    triplets = await harvester.harvest_and_export_dpo_dataset(
        harness,
        since_iso="2026-10-01T00:00:00Z",
        output_path=dpo_path,
    )
    assert len(triplets) == 1
    assert triplets[0].chosen["arguments"]["amount"] == 25_000.0
    assert "@ since_iso" not in harvester.executed_queries[0].sql
    assert "@since_iso" in harvester.executed_queries[0].sql
    assert harvester.executed_queries[0].parameters == (
        ("since_iso", "STRING", "2026-10-01T00:00:00Z"),
        ("row_limit", "INT64", 500),
    )

    # Confirm PII was scrubbed from exported JSONL
    exported_text = dpo_path.read_text(encoding="utf-8")
    assert "alice@example.com" not in exported_text

    # Tampered proof_hash in BigQuery must fail closed
    tampered_row = {**bq_refusal_row, "proof_hash": "0" * 64}
    bad_harvester = BigQueryTrajectoryHarvester(bq_client=_FakeBqClient([tampered_row]))
    with pytest.raises(ValueError, match="Tampered BigQuery RefusalReceipt"):
        await bad_harvester.fetch_refusal_receipts(since_iso="2026-10-01T00:00:00Z")

    # Eval-Prod Drift Anchor harvesting
    drift_row = {
        "trajectory_id": "prod-fail-77",
        "skill_name": "gcp-deploy-skill",
        "bucket": "explicit",
        "prompt": "Deploy service for user bob@example.com",
        "expected_script": "deploy_cloudbuild.py",
        "forbidden_tools": json.dumps(["legacy_docker_push"]),
        "required_output_tokens": json.dumps(["DEPLOY_STATUS=VERIFIED"]),
        "atif_payload": json.dumps(
            {
                "trajectory_id": "prod-fail-77",
                "harness_id": "gke-prod",
                "model_id": "gemini-3.5-flash",
                "prompt": "Deploy service for user bob@example.com",
                "steps": [
                    {
                        "step_index": 1,
                        "source": "agent",
                        "tool_calls": [
                            {"name": "legacy_docker_push", "arguments": {}}
                        ],
                    }
                ],
                "final_response": "Failed deployment",
            }
        ),
    }
    drift_harvester = BigQueryTrajectoryHarvester(bq_client=_FakeBqClient([drift_row]))
    drift_anchors = await drift_harvester.fetch_eval_prod_drift_anchors(
        skill_name="gcp-deploy-skill",
        since_iso="2026-10-01T00:00:00Z",
    )
    assert len(drift_anchors) == 1
    assert drift_anchors[0].golden_passed is False
    assert "bob@example.com" not in drift_anchors[0].case.prompt


def test_cli_emit_cer_with_vertex_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify `cage-skill-eval --eval-backend vertex --emit-cer ...` writes a signed `.cer` receipt."""
    monkeypatch.setenv("KMS_PROVIDER", "ed25519")
    skill_md = _write_valid_skill_md(tmp_path)
    cer_out = tmp_path / "gcp-deploy-skill.cer"

    exit_code = cli_main(
        [
            "--skill-md",
            str(skill_md),
            "--eval-backend",
            "vertex",
            "--emit-cer",
            str(cer_out),
            "--kms-key-id",
            "cage-cli-test-kid",
            "--json",
        ]
    )
    assert exit_code == 0
    assert cer_out.exists()
    cer_data = json.loads(cer_out.read_text(encoding="utf-8"))
    assert cer_data["skill_name"] == "gcp-deploy-skill"
    assert cer_data["signature"]["keyId"] == "cage-cli-test-kid"
    assert len(cer_data["receiptDigest"]) == 64
