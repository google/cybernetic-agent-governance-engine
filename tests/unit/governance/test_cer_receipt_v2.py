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

"""Issue #512 (reported by @danofairanks): `.cer` receipts bind evaluation stages.

``cage.skill.cer.v2`` receipts sign which stages ran, the evidence level, and
the digests of the evaluated evidence. Verifiers refuse v1 receipts,
``STATIC_ONLY`` receipts (unless explicitly allowed), receipts whose fields
contradict their evidence level, and lift that the certification gate itself
would reject, and they always require the ``SKILL.md`` bytes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from src.eval_harness import (
    CER_SCHEMA_VERSION,
    ATIFTrajectory,
    CerEvidenceLevel,
    FoundationModelEvalHarness,
    SkillCertificationReceipt,
    SkillEvalCase,
    SkillPromptBucket,
    lift_meets_threshold,
)
from src.eval_harness.cli import main as cli_main
from src.eval_harness.cli import run_certification_gate
from src.eval_harness.static_linter import lint_skill_file
from src.integrations.gcp_eval import (
    GcpSkillCertifier,
    GcsSkillCertificationVerifier,
    cer_publisher,
)
from src.integrations.gcp_eval.cer_publisher import compute_adapter_config_sha256
from tests.fixtures.skill_certification import (
    SAFE_OPS_EVALS,
    SAFE_OPS_SKILL_MD,
    SAFE_OPS_WEAK_BASELINE_TRACES,
    SAFE_OPS_WITH_SKILL_TRACES,
    make_ed25519_signer_and_jwks,
    make_lift_report,
    write_json,
    write_text,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

KID = "cer-v2-test-kid"
ADAPTER_SPEC = "tests.unit.governance.test_eval_harness:_sample_rollout_agent"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _Evidence:
    """On-disk Stage 2 evidence for the ``safe-ops`` skill."""

    def __init__(self, tmp_path: Path) -> None:
        self.skill_md = write_text(
            tmp_path / "safe-ops" / "SKILL.md", SAFE_OPS_SKILL_MD
        )
        self.evals = write_json(tmp_path / "evals.json", SAFE_OPS_EVALS)
        self.baseline = write_json(
            tmp_path / "baseline.json", SAFE_OPS_WEAK_BASELINE_TRACES
        )
        self.with_skill = write_json(
            tmp_path / "with_skill.json", SAFE_OPS_WITH_SKILL_TRACES
        )


@pytest.fixture
def evidence(tmp_path: Path) -> _Evidence:
    return _Evidence(tmp_path)


@pytest.fixture
def signer_and_jwks(tmp_path: Path) -> tuple[GcpSkillCertifier, Any]:
    provider, jwks = make_ed25519_signer_and_jwks(tmp_path, KID)
    return GcpSkillCertifier(key_id=KID, kms_provider=provider), jwks


def _sign_static_only(
    certifier: GcpSkillCertifier, evidence: _Evidence
) -> SkillCertificationReceipt:
    return certifier.create_and_sign_receipt(
        skill_md_path=evidence.skill_md,
        static_report=lint_skill_file(evidence.skill_md),
        stages_run=(0,),
        evidence_level=CerEvidenceLevel.STATIC_ONLY,
    )


def _sign_paired(
    certifier: GcpSkillCertifier,
    evidence: _Evidence,
    *,
    lift: float = 0.25,
) -> SkillCertificationReceipt:
    return certifier.create_and_sign_receipt(
        skill_md_path=evidence.skill_md,
        static_report=lint_skill_file(evidence.skill_md),
        stages_run=(0, 2),
        evidence_level=CerEvidenceLevel.PAIRED_TRACES,
        lift_report=make_lift_report(mean_composite_lift=lift),
        evals_json_path=evidence.evals,
        baseline_traces_path=evidence.baseline,
        with_skill_traces_path=evidence.with_skill,
    )


def _sign_live(
    certifier: GcpSkillCertifier, evidence: _Evidence
) -> SkillCertificationReceipt:
    return certifier.create_and_sign_receipt(
        skill_md_path=evidence.skill_md,
        static_report=lint_skill_file(evidence.skill_md),
        stages_run=(0, 2),
        evidence_level=CerEvidenceLevel.LIVE_ROLLOUT,
        lift_report=make_lift_report(model_id="rollout-model-x"),
        evals_json_path=evidence.evals,
        adapter_ref=ADAPTER_SPEC,
        adapter_config={"model_id": "rollout-model-x"},
    )


def _redigest(payload: dict[str, Any]) -> dict[str, Any]:
    """Recompute the outer receipt digest so verification reaches the signature."""
    payload["receiptDigest"] = SkillCertificationReceipt.from_dict(
        payload
    ).compute_signed_digest()
    return payload


# ---------------------------------------------------------------------------
# Receipt body
# ---------------------------------------------------------------------------


def test_receipt_body_binds_stages_evidence_level_and_digests(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, _ = signer_and_jwks
    paired = _sign_paired(certifier, evidence).to_unsigned_body()
    assert paired["schema_version"] == CER_SCHEMA_VERSION == "cage.skill.cer.v2"
    assert paired["stages_run"] == [0, 2]
    assert paired["evidence_level"] == "PAIRED_TRACES"
    assert paired["model_id"] == "gemini-test-model"
    assert paired["evals_sha256"] == _sha256(evidence.evals)
    assert paired["baseline_traces_sha256"] == _sha256(evidence.baseline)
    assert paired["with_skill_traces_sha256"] == _sha256(evidence.with_skill)
    assert paired["adapter_ref"] is None and paired["adapter_config_sha256"] is None

    live = _sign_live(certifier, evidence).to_unsigned_body()
    assert live["evidence_level"] == "LIVE_ROLLOUT"
    assert live["adapter_ref"] == ADAPTER_SPEC
    assert live["adapter_config_sha256"] == compute_adapter_config_sha256(
        {"model_id": "rollout-model-x"}
    )
    assert live["model_id"] == "rollout-model-x"
    assert live["baseline_traces_sha256"] is None
    assert live["with_skill_traces_sha256"] is None

    static = _sign_static_only(certifier, evidence).to_unsigned_body()
    assert static["stages_run"] == [0]
    assert static["evidence_level"] == "STATIC_ONLY"
    for unmeasured in (
        "model_id",
        "evals_sha256",
        "mean_composite_lift",
        "mean_instruction_following_lift",
        "routing_premium",
    ):
        assert static[unmeasured] is None, unmeasured


def test_adapter_config_digest_is_canonical() -> None:
    assert compute_adapter_config_sha256(
        {"b": 1, "a": "x"}
    ) == compute_adapter_config_sha256({"a": "x", "b": 1})
    assert compute_adapter_config_sha256({"a": "x"}) != compute_adapter_config_sha256(
        {"a": "y"}
    )


# ---------------------------------------------------------------------------
# Verifier refusals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_only_receipt_refused_by_default_and_accepted_when_allowed(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, jwks = signer_and_jwks
    receipt = _sign_static_only(certifier, evidence)
    skill_bytes = evidence.skill_md.read_bytes()

    refused = await GcsSkillCertificationVerifier(jwks).verify_cer_receipt(
        receipt.to_dict(), expected_skill_md_bytes=skill_bytes
    )
    assert refused == (False, "static_only_receipt")

    accepted = await GcsSkillCertificationVerifier(
        jwks, allow_static_only=True
    ).verify_cer_receipt(receipt.to_dict(), expected_skill_md_bytes=skill_bytes)
    assert accepted == (True, "VERIFIED")


@pytest.mark.asyncio
async def test_verify_requires_skill_md_bytes(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, jwks = signer_and_jwks
    verifier = GcsSkillCertificationVerifier(jwks)
    payload = _sign_paired(certifier, evidence).to_dict()

    with pytest.raises(TypeError):
        await verifier.verify_cer_receipt(payload)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        await verifier.verify_cer_receipt(payload, expected_skill_md_bytes=None)  # type: ignore[arg-type]

    ok, reason = await verifier.verify_cer_receipt(
        payload, expected_skill_md_bytes=b"tampered skill markdown"
    )
    assert (ok, reason) == (False, "skill_md_sha256_mismatch")
    assert await verifier.verify_cer_receipt(
        payload, expected_skill_md_bytes=evidence.skill_md.read_bytes()
    ) == (True, "VERIFIED")


@pytest.mark.asyncio
async def test_v1_and_unversioned_receipts_refused(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, jwks = signer_and_jwks
    verifier = GcsSkillCertificationVerifier(jwks)
    skill_bytes = evidence.skill_md.read_bytes()
    v1_payload = {
        "schema_version": "cage.skill.cer.v1",
        "skill_name": "safe-ops",
        "skill_sha256": hashlib.sha256(skill_bytes).hexdigest(),
        "evals_sha256": hashlib.sha256(b"").hexdigest(),
        "anchors_sha256": None,
        "model_id": "gemini-3.5-flash",
        "static_lint_score": 0.9,
        "anchor_weighted_agreement": None,
        "mean_composite_lift": 0.0,
        "mean_instruction_following_lift": 0.0,
        "routing_premium": None,
        "issued_at": "2026-01-01T00:00:00+00:00",
        "signature": {"algorithm": "Ed25519", "keyId": KID, "value": "AAAA"},
        "receiptDigest": "0" * 64,
    }
    assert await verifier.verify_cer_receipt(
        v1_payload, expected_skill_md_bytes=skill_bytes
    ) == (False, "unsupported_schema_version")
    with pytest.raises(ValueError, match="unsupported schema_version"):
        SkillCertificationReceipt.from_dict(v1_payload)

    relabelled = _sign_paired(certifier, evidence).to_dict()
    relabelled["schema_version"] = "cage.skill.cer.v1"
    assert await verifier.verify_cer_receipt(
        relabelled, expected_skill_md_bytes=skill_bytes
    ) == (False, "unsupported_schema_version")

    unversioned = _sign_paired(certifier, evidence).to_dict()
    del unversioned["schema_version"]
    assert await verifier.verify_cer_receipt(
        unversioned, expected_skill_md_bytes=skill_bytes
    ) == (False, "unsupported_schema_version")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sign", "field_name"),
    [
        (_sign_paired, "baseline_traces_sha256"),
        (_sign_paired, "with_skill_traces_sha256"),
        (_sign_paired, "evals_sha256"),
        (_sign_live, "adapter_config_sha256"),
    ],
)
async def test_tampered_evidence_digest_fails_ed25519_verification(
    evidence: _Evidence,
    signer_and_jwks: tuple[GcpSkillCertifier, Any],
    sign: Any,
    field_name: str,
) -> None:
    certifier, jwks = signer_and_jwks
    payload = sign(certifier, evidence).to_dict()
    payload[field_name] = hashlib.sha256(b"substituted evidence").hexdigest()
    ok, reason = await GcsSkillCertificationVerifier(jwks).verify_cer_receipt(
        _redigest(payload), expected_skill_md_bytes=evidence.skill_md.read_bytes()
    )
    assert (ok, reason) == (False, "ed25519_signature_verification_failed")


@pytest.mark.asyncio
async def test_tampered_stages_or_evidence_level_fails_closed(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, jwks = signer_and_jwks
    verifier = GcsSkillCertificationVerifier(jwks)
    skill_bytes = evidence.skill_md.read_bytes()

    # Claiming an extra (consistent) stage breaks the signature.
    upgraded = _sign_paired(certifier, evidence).to_dict()
    upgraded["stages_run"] = [0, 1, 2]
    upgraded["anchors_sha256"] = hashlib.sha256(b"anchors").hexdigest()
    upgraded["anchor_weighted_agreement"] = 0.95
    assert await verifier.verify_cer_receipt(
        _redigest(upgraded), expected_skill_md_bytes=skill_bytes
    ) == (False, "ed25519_signature_verification_failed")

    # Relabelling a stage-0 receipt as measured evidence contradicts its body.
    relabelled = _sign_static_only(certifier, evidence).to_dict()
    relabelled["evidence_level"] = "PAIRED_TRACES"
    ok, reason = await verifier.verify_cer_receipt(
        relabelled, expected_skill_md_bytes=skill_bytes
    )
    assert ok is False and reason.startswith("malformed_cer_receipt")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("baseline_traces_sha256", None),
        ("adapter_ref", ADAPTER_SPEC),
        ("model_id", None),
        ("mean_composite_lift", None),
        ("stages_run", [0]),
        ("stages_run", [2, 0]),
        ("evidence_level", "UNKNOWN"),
        ("status", "CERTIFIED"),
    ],
)
async def test_structurally_inconsistent_receipt_is_malformed(
    evidence: _Evidence,
    signer_and_jwks: tuple[GcpSkillCertifier, Any],
    field_name: str,
    value: Any,
) -> None:
    certifier, jwks = signer_and_jwks
    payload = _sign_paired(certifier, evidence).to_dict()
    payload[field_name] = value
    ok, reason = await GcsSkillCertificationVerifier(jwks).verify_cer_receipt(
        payload, expected_skill_md_bytes=evidence.skill_md.read_bytes()
    )
    assert ok is False
    assert reason.startswith("malformed_cer_receipt")


# ---------------------------------------------------------------------------
# Shared lift rule (gate == verifier)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lift", "minimum", "expected"),
    [
        (0.0, 0.0, False),
        (-0.1, 0.0, False),
        (1e-9, 0.0, True),
        (None, 0.0, False),
        (float("nan"), 0.0, False),
        (float("inf"), 0.0, False),
        (0.05, 0.05, True),
        (0.0499, 0.05, False),
        (-0.05, -0.1, True),
        (0.5, float("nan"), False),
    ],
)
def test_lift_meets_threshold(
    lift: float | None, minimum: float, expected: bool
) -> None:
    assert lift_meets_threshold(lift, minimum) is expected


@pytest.mark.asyncio
async def test_zero_lift_refused_by_gate_and_verifier(
    tmp_path: Path,
    evidence: _Evidence,
    signer_and_jwks: tuple[GcpSkillCertifier, Any],
) -> None:
    identical = write_json(tmp_path / "identical.json", SAFE_OPS_WITH_SKILL_TRACES)
    certified, _, _, lift_report, failures = await run_certification_gate(
        skill_md_path=evidence.skill_md,
        evals_json_path=evidence.evals,
        baseline_traces_path=identical,
        with_skill_traces_path=evidence.with_skill,
        model_id="trace-model",
    )
    assert lift_report is not None and lift_report.mean_composite_lift == 0.0
    assert certified is False
    assert any(f.startswith("stage2_insufficient_skill_lift") for f in failures)

    certifier, jwks = signer_and_jwks
    skill_bytes = evidence.skill_md.read_bytes()
    zero_lift = _sign_paired(certifier, evidence, lift=0.0)
    assert await GcsSkillCertificationVerifier(jwks).verify_cer_receipt(
        zero_lift.to_dict(), expected_skill_md_bytes=skill_bytes
    ) == (False, "composite_lift_below_threshold")

    at_minimum = _sign_paired(certifier, evidence, lift=0.05)
    strict = GcsSkillCertificationVerifier(jwks, min_composite_lift=0.05)
    assert await strict.verify_cer_receipt(
        at_minimum.to_dict(), expected_skill_md_bytes=skill_bytes
    ) == (True, "VERIFIED")
    below = _sign_paired(certifier, evidence, lift=0.0499)
    assert await strict.verify_cer_receipt(
        below.to_dict(), expected_skill_md_bytes=skill_bytes
    ) == (False, "composite_lift_below_threshold")


@pytest.mark.asyncio
async def test_gate_requires_model_id_for_trace_files(evidence: _Evidence) -> None:
    certified, _, _, lift_report, failures = await run_certification_gate(
        skill_md_path=evidence.skill_md,
        evals_json_path=evidence.evals,
        baseline_traces_path=evidence.baseline,
        with_skill_traces_path=evidence.with_skill,
    )
    assert certified is False
    assert lift_report is None
    assert any(f.startswith("stage2_missing_model_id") for f in failures)


# ---------------------------------------------------------------------------
# Signer refusals
# ---------------------------------------------------------------------------


def test_signer_refuses_stage2_without_model_id(
    evidence: _Evidence, signer_and_jwks: tuple[GcpSkillCertifier, Any]
) -> None:
    certifier, _ = signer_and_jwks
    with pytest.raises(ValueError, match="without a model id"):
        certifier.create_and_sign_receipt(
            skill_md_path=evidence.skill_md,
            static_report=lint_skill_file(evidence.skill_md),
            stages_run=(0, 2),
            evidence_level=CerEvidenceLevel.PAIRED_TRACES,
            lift_report=make_lift_report(model_id=""),
            evals_json_path=evidence.evals,
            baseline_traces_path=evidence.baseline,
            with_skill_traces_path=evidence.with_skill,
        )
    explicit = certifier.create_and_sign_receipt(
        skill_md_path=evidence.skill_md,
        static_report=lint_skill_file(evidence.skill_md),
        stages_run=(0, 2),
        evidence_level=CerEvidenceLevel.PAIRED_TRACES,
        lift_report=make_lift_report(model_id=""),
        evals_json_path=evidence.evals,
        baseline_traces_path=evidence.baseline,
        with_skill_traces_path=evidence.with_skill,
        model_id="explicit-model",
    )
    assert explicit.model_id == "explicit-model"


@pytest.mark.parametrize(
    ("overrides", "error", "match"),
    [
        ({"stages_run": (0,)}, ValueError, "stage 2 exactly when"),
        ({"lift_report": None}, ValueError, "stage 2 exactly when"),
        ({"model_id": "other-model"}, ValueError, "contradicts"),
        ({"baseline_traces_path": None}, ValueError, "baseline_traces_sha256"),
        (
            {"evidence_level": CerEvidenceLevel.LIVE_ROLLOUT},
            ValueError,
            "adapter_ref",
        ),
        ({"evidence_level": CerEvidenceLevel.STATIC_ONLY}, ValueError, "STATIC_ONLY"),
        ({"evals_json_path": None}, ValueError, "evals_sha256"),
        ({"adapter_config": {"model_id": "x"}}, ValueError, "without adapter_ref"),
        ({"stages_run": (2,)}, ValueError, "strictly increasing"),
        ({"evidence_level": "PARTIAL"}, ValueError, "PARTIAL"),
    ],
)
def test_signer_refuses_inconsistent_inputs(
    evidence: _Evidence,
    signer_and_jwks: tuple[GcpSkillCertifier, Any],
    overrides: dict[str, Any],
    error: type[Exception],
    match: str,
) -> None:
    certifier, _ = signer_and_jwks
    kwargs: dict[str, Any] = {
        "skill_md_path": evidence.skill_md,
        "static_report": lint_skill_file(evidence.skill_md),
        "stages_run": (0, 2),
        "evidence_level": CerEvidenceLevel.PAIRED_TRACES,
        "lift_report": make_lift_report(),
        "evals_json_path": evidence.evals,
        "baseline_traces_path": evidence.baseline,
        "with_skill_traces_path": evidence.with_skill,
    }
    kwargs.update(overrides)
    with pytest.raises(error, match=match):
        certifier.create_and_sign_receipt(**kwargs)


def test_signer_refuses_missing_evidence_file_and_static_model_id(
    tmp_path: Path,
    evidence: _Evidence,
    signer_and_jwks: tuple[GcpSkillCertifier, Any],
) -> None:
    certifier, _ = signer_and_jwks
    with pytest.raises(FileNotFoundError):
        certifier.create_and_sign_receipt(
            skill_md_path=evidence.skill_md,
            static_report=lint_skill_file(evidence.skill_md),
            stages_run=(0, 2),
            evidence_level=CerEvidenceLevel.PAIRED_TRACES,
            lift_report=make_lift_report(),
            evals_json_path=tmp_path / "missing-evals.json",
            baseline_traces_path=evidence.baseline,
            with_skill_traces_path=evidence.with_skill,
        )
    with pytest.raises(ValueError, match="STATIC_ONLY receipts name no model"):
        certifier.create_and_sign_receipt(
            skill_md_path=evidence.skill_md,
            static_report=lint_skill_file(evidence.skill_md),
            stages_run=(0,),
            evidence_level=CerEvidenceLevel.STATIC_ONLY,
            model_id="gemini-3.5-flash",
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_requires_model_id_with_trace_files(evidence: _Evidence) -> None:
    with pytest.raises(SystemExit) as missing:
        cli_main(
            [
                "--skill-md",
                str(evidence.skill_md),
                "--evals",
                str(evidence.evals),
                "--baseline-traces",
                str(evidence.baseline),
                "--skill-traces",
                str(evidence.with_skill),
            ]
        )
    assert missing.value.code == 2

    with pytest.raises(SystemExit) as stray:
        cli_main(
            [
                "--skill-md",
                str(evidence.skill_md),
                "--evals",
                str(evidence.evals),
                "--adapter",
                ADAPTER_SPEC,
                "--model-id",
                "ignored-model",
            ]
        )
    assert stray.value.code == 2


@pytest.fixture
def cli_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> GcsSkillCertificationVerifier:
    """Route `cage-skill-eval --emit-cer` signing through a key the test can verify."""
    provider, jwks = make_ed25519_signer_and_jwks(tmp_path, KID)
    monkeypatch.setattr(
        cer_publisher, "build_kms_provider", lambda provider_name=None: provider
    )
    return GcsSkillCertificationVerifier(jwks)


def test_cli_trace_files_receipt_binds_traces_and_verifies(
    tmp_path: Path,
    evidence: _Evidence,
    cli_signer: GcsSkillCertificationVerifier,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cer_out = tmp_path / "out" / "safe-ops.cer"
    exit_code = cli_main(
        [
            "--skill-md",
            str(evidence.skill_md),
            "--evals",
            str(evidence.evals),
            "--baseline-traces",
            str(evidence.baseline),
            "--skill-traces",
            str(evidence.with_skill),
            "--model-id",
            "trace-model",
            "--emit-cer",
            str(cer_out),
            "--kms-key-id",
            KID,
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0, report["failures"]
    assert report["stages_run"] == [0, 2]
    receipt = json.loads(cer_out.read_text(encoding="utf-8"))
    assert receipt["stages_run"] == [0, 2]
    assert receipt["evidence_level"] == "PAIRED_TRACES"
    assert receipt["model_id"] == "trace-model"
    assert receipt["evals_sha256"] == _sha256(evidence.evals)
    assert receipt["baseline_traces_sha256"] == _sha256(evidence.baseline)
    assert receipt["with_skill_traces_sha256"] == _sha256(evidence.with_skill)
    assert receipt["adapter_ref"] is None
    assert asyncio.run(
        cli_signer.verify_cer_receipt(
            receipt, expected_skill_md_bytes=evidence.skill_md.read_bytes()
        )
    ) == (True, "VERIFIED")


def test_cli_adapter_receipt_binds_adapter_and_bundle_model(
    tmp_path: Path,
    cli_signer: GcsSkillCertificationVerifier,
) -> None:
    skill_md = write_text(
        tmp_path / "transfer-skill" / "SKILL.md",
        "---\n"
        "name: transfer-skill\n"
        "description: Use when the user asks to execute a bounded transfer. Do not use for general queries.\n"
        "---\n"
        "# Transfer Skill\n\n"
        "## Workflow Steps\n"
        "1. Read `SKILL.md` and run `verify_limits.py --amount <usd>`.\n"
        "2. Call `execute_transfer` with bounded `amount`.\n\n"
        "```bash\npython scripts/verify_limits.py --amount 50000\n```\n\n"
        "## Error Recovery & Scope Restraint\n"
        "- If `verify_limits.py` returns an error, abort fail-closed.\n"
        "- Never call `legacy_transfer`. Do not use outside transfer workflows.\n",
    )
    evals = write_json(
        tmp_path / "evals.json",
        [
            {
                "case_id": "c1",
                "bucket": "explicit",
                "prompt": "Send $50k with transfer-skill",
                "expected_skill": "transfer-skill",
                "required_output_tokens": ["TRANSFER_OK"],
            },
            {
                "case_id": "c2",
                "bucket": "negative_control",
                "prompt": "Explain transfer-skill",
                "expected_skill": "transfer-skill",
                "required_output_tokens": ["explanation"],
            },
        ],
    )
    adapter_config = {"model_id": "rollout-model-x"}
    cer_out = tmp_path / "transfer-skill.cer"
    exit_code = cli_main(
        [
            "--skill-md",
            str(skill_md),
            "--evals",
            str(evals),
            "--adapter",
            ADAPTER_SPEC,
            "--adapter-config",
            json.dumps(adapter_config),
            "--emit-cer",
            str(cer_out),
            "--kms-key-id",
            KID,
        ]
    )
    assert exit_code == 0
    receipt = json.loads(cer_out.read_text(encoding="utf-8"))
    assert receipt["evidence_level"] == "LIVE_ROLLOUT"
    assert receipt["stages_run"] == [0, 2]
    assert receipt["model_id"] == "rollout-model-x"
    assert receipt["adapter_ref"] == ADAPTER_SPEC
    assert receipt["adapter_config_sha256"] == compute_adapter_config_sha256(
        adapter_config
    )
    assert receipt["baseline_traces_sha256"] is None
    assert receipt["evals_sha256"] == _sha256(evals)
    assert asyncio.run(
        cli_signer.verify_cer_receipt(
            receipt, expected_skill_md_bytes=skill_md.read_bytes()
        )
    ) == (True, "VERIFIED")


def test_cli_stage0_only_receipt_is_static_only_and_refused_by_default(
    tmp_path: Path,
    evidence: _Evidence,
    cli_signer: GcsSkillCertificationVerifier,
) -> None:
    cer_out = tmp_path / "stage0.cer"
    assert (
        cli_main(
            [
                "--skill-md",
                str(evidence.skill_md),
                "--stage0-only",
                "--emit-cer",
                str(cer_out),
                "--kms-key-id",
                KID,
            ]
        )
        == 0
    )
    receipt = json.loads(cer_out.read_text(encoding="utf-8"))
    assert receipt["evidence_level"] == "STATIC_ONLY"
    assert receipt["stages_run"] == [0]
    assert receipt["model_id"] is None
    assert receipt["mean_composite_lift"] is None
    assert asyncio.run(
        cli_signer.verify_cer_receipt(
            receipt, expected_skill_md_bytes=evidence.skill_md.read_bytes()
        )
    ) == (False, "static_only_receipt")


# ---------------------------------------------------------------------------
# GEPA optimizer uses the shared lift rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gepa_eliminates_zero_lift_candidate() -> None:
    from src.integrations.gcp_eval import GEPACandidateSpec, GovernedGEPAOptimizer

    case = SkillEvalCase(
        case_id="c1",
        bucket=SkillPromptBucket.EXPLICIT,
        prompt="Run safe_tool",
        expected_skill="safe-ops",
        forbidden_tools=("drop_prod",),
        required_output_tokens=("SAFE_OK",),
        allowed_skills=("safe-ops",),
    )
    trajectory = ATIFTrajectory.from_dict(SAFE_OPS_WITH_SKILL_TRACES[0])
    optimizer = GovernedGEPAOptimizer(harness=FoundationModelEvalHarness(governor=None))
    evaluation = await optimizer.evaluate_candidate(
        GEPACandidateSpec(
            candidate_id="no-op",
            generation=1,
            skill_name="safe-ops",
            skill_markdown=SAFE_OPS_SKILL_MD,
            with_skill_trajectories={"c1": trajectory},
        ),
        model_id="trace-model",
        cases=[case],
        baseline_trajectories={"c1": trajectory},
    )
    assert evaluation.lift_report.mean_composite_lift == 0.0
    assert evaluation.eliminated is True
    assert any(
        r.startswith("composite_lift_below_minimum")
        for r in evaluation.elimination_reasons
    )
