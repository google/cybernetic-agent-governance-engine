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

"""Conformance & Attributable Provenance Test Suite for packages/cage-conformance."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG_SRC = _REPO_ROOT / "packages" / "cage-conformance" / "src"
if str(_PKG_SRC) not in sys.path:
    sys.path.insert(0, str(_PKG_SRC))

from cage_conformance import (  # noqa: E402
    AdapterUnderTest,
    IdentityProofType,
    ProvenanceBlock,
    ProvenanceValidationError,
    RunnerProvenance,
    VerificationPosture,
    build_provenance_block,
    derive_verification_posture,
    inspect_oidc_jwt,
    load_vector_fixture,
    validate_conformance_report,
    verify_endpoint,
    verify_trace_events,
)
from cage_conformance.cli import main as cli_main  # noqa: E402

from scripts.check_conformance_sync import check_sync_and_isolation  # noqa: E402


def _make_jwt(claims: dict[str, Any]) -> str:
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode("ascii")
    )
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode())
        .rstrip(b"=")
        .decode("ascii")
    )
    sig = base64.urlsafe_b64encode(b"test-signature-bytes").rstrip(b"=").decode("ascii")
    return f"{header}.{payload}.{sig}"


def _sample_adapter() -> AdapterUnderTest:
    return AdapterUnderTest(
        provider_id="provider_01",
        adapter_author_org="Google LLC",
        counterparty_org="FlowSignal Ltd",
        adapter_version="0.2.0",
        adapter_commit="5595a82ef907fec25aec7ccc8ed5832303bd9f26",
        contract_profile="flowsignal-v0.2",
    )


def test_proof_sync_and_zero_src_isolation() -> None:
    """Verify proof/ files are byte-for-byte identical and cage-conformance has no src/ imports."""
    errors = check_sync_and_isolation()
    assert errors == [], f"Sync or isolation violations found: {errors}"


def test_partner_doc_headers_present() -> None:
    """Verify all partner documents under docs/partners/ carry mandatory status headers."""
    from scripts.check_partner_headers import check_partner_headers

    errors = check_partner_headers()
    assert errors == [], f"Partner header violations found: {errors}"


def test_four_posture_derivation_matrix() -> None:
    """Verify all four postures: AUTHOR_SELF_TEST, COUNTERPARTY_VERIFIED, INDEPENDENT_PARTY_VERIFIED, UNVERIFIED_LOCAL."""
    adapter = _sample_adapter()
    token_hash = hashlib.sha256(b"dummy-oidc").hexdigest()

    # 1. AUTHOR_SELF_TEST (author org matches runner org, even without OIDC)
    author_runner = RunnerProvenance(
        runner_org="Google",
        runner_identity="maintainer@google.com",
        identity_proof=IdentityProofType.NONE,
        cage_conformance_version="0.1.0",
        cage_commit="5595a82ef907",
        timestamp_utc="2026-10-25T12:00:00Z",
    )
    assert (
        derive_verification_posture(adapter, author_runner)
        == VerificationPosture.AUTHOR_SELF_TEST
    )
    author_block = build_provenance_block(
        adapter_under_test=adapter, runner=author_runner
    )
    assert author_block.independent_of_author is False
    assert author_block.third_party_independent is False

    # 2. UNVERIFIED_LOCAL (counterparty or third party claimed WITHOUT OIDC proof -> fails closed)
    unverified_counterparty = RunnerProvenance(
        runner_org="FlowSignal",
        runner_identity="graham-laptop",
        identity_proof=IdentityProofType.NONE,
        cage_conformance_version="0.1.0",
        cage_commit="5595a82ef907",
        timestamp_utc="2026-10-25T12:00:00Z",
    )
    assert (
        derive_verification_posture(adapter, unverified_counterparty)
        == VerificationPosture.UNVERIFIED_LOCAL
    )
    unverified_block = build_provenance_block(
        adapter_under_test=adapter, runner=unverified_counterparty
    )
    assert unverified_block.independent_of_author is False
    assert unverified_block.third_party_independent is False

    # 3. COUNTERPARTY_VERIFIED (counterparty org WITH verified OIDC proof)
    verified_counterparty = RunnerProvenance(
        runner_org="FlowSignal",
        runner_identity="repo:flowsignal/cage-qualification:ref:refs/heads/main",
        identity_proof=IdentityProofType.GITHUB_OIDC,
        oidc_issuer="https://token.actions.githubusercontent.com",
        oidc_subject="repo:flowsignal/cage-qualification:ref:refs/heads/main",
        oidc_token_sha256=token_hash,
        cage_conformance_version="0.1.0",
        cage_commit="5595a82ef907",
        timestamp_utc="2026-10-25T12:00:00Z",
    )
    assert (
        derive_verification_posture(adapter, verified_counterparty)
        == VerificationPosture.COUNTERPARTY_VERIFIED
    )
    cp_block = build_provenance_block(
        adapter_under_test=adapter, runner=verified_counterparty
    )
    assert cp_block.independent_of_author is True
    assert cp_block.third_party_independent is False

    # 4. INDEPENDENT_PARTY_VERIFIED (neither author nor counterparty, WITH verified OIDC proof)
    independent_runner = RunnerProvenance(
        runner_org="FCA AI Lab",
        runner_identity="sandbox-evaluator@fca.org.uk",
        identity_proof=IdentityProofType.SIGSTORE_OIDC,
        oidc_issuer="https://oauth2.sigstore.dev/auth",
        oidc_subject="sandbox-evaluator@fca.org.uk",
        oidc_token_sha256=token_hash,
        cage_conformance_version="0.1.0",
        cage_commit="5595a82ef907",
        timestamp_utc="2026-10-25T12:00:00Z",
    )
    assert (
        derive_verification_posture(adapter, independent_runner)
        == VerificationPosture.INDEPENDENT_PARTY_VERIFIED
    )
    ind_block = build_provenance_block(
        adapter_under_test=adapter, runner=independent_runner
    )
    assert ind_block.independent_of_author is True
    assert ind_block.third_party_independent is True


def test_provenance_tamper_and_missing_rejection() -> None:
    """Reports without provenance or with spoofed posture are rejected as malformed."""
    with pytest.raises(ProvenanceValidationError, match="mandatory 'provenance' block"):
        validate_conformance_report({"schema_version": "cage-conformance-report/1.0"})

    adapter = _sample_adapter()
    runner = RunnerProvenance(
        runner_org="FlowSignal",
        runner_identity="local-runner",
        identity_proof=IdentityProofType.NONE,
        cage_conformance_version="0.1.0",
        cage_commit="5595a82ef907",
        timestamp_utc="2026-10-25T12:00:00Z",
    )
    # Spoofing COUNTERPARTY_VERIFIED when identity_proof == NONE must fail validation
    with pytest.raises(ValueError, match="Posture mismatch"):
        ProvenanceBlock(
            adapter_under_test=adapter,
            runner=runner,
            verification_posture=VerificationPosture.COUNTERPARTY_VERIFIED,
            independent_of_author=True,
            third_party_independent=False,
        )


def test_flowsignal_step1_record_carries_valid_provenance() -> None:
    """Verify docs/partners/provider_01/CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json carries valid provenance."""
    record_path = (
        _REPO_ROOT
        / "docs"
        / "partners"
        / "provider_01"
        / "CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert "provenance" in record
    prov = ProvenanceBlock.model_validate(record["provenance"])
    assert prov.verification_posture == VerificationPosture.AUTHOR_SELF_TEST
    assert prov.independent_of_author is False
    assert prov.third_party_independent is False


def test_verify_trace_events_pass_and_fail() -> None:
    """Verify trace conformance runner passes conformant traces and catches single-use violations."""
    fixture = load_vector_fixture("trace_v1.json")
    events = fixture["conformant_trace"]
    prov = build_provenance_block(
        adapter_under_test=_sample_adapter(),
        runner=RunnerProvenance(
            runner_org="Google LLC",
            runner_identity="ci",
            identity_proof=IdentityProofType.NONE,
            cage_conformance_version="0.1.0",
            cage_commit="5595a82ef907",
            timestamp_utc="2026-10-25T12:00:00Z",
        ),
    )
    report = verify_trace_events(events, provenance=prov, target="trace_v1.json")
    assert report.summary.conformant is True
    assert report.summary.failed_assertions == 0

    # Duplicate the EXECUTED event to trigger a single_use violation
    replayed_events = [*events, copy.deepcopy(events[-1])]
    bad_report = verify_trace_events(
        replayed_events, provenance=prov, target="replayed.jsonl"
    )
    assert bad_report.summary.conformant is False
    failed_ids = [a.assertion_id for a in bad_report.assertions if not a.passed]
    assert "TRACE-SINGLE_USE" in failed_ids


def _mock_flowsignal_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path != "/cage/validate":
        return httpx.Response(404, json={"error": "not found"})
    body = json.loads(request.content.decode("utf-8"))
    # Reject malformed or injected payloads (missing approval_id / platform /actor_id or injected decision)
    if "decision" in body or "approval_id" not in body or "mandate_id" not in body:
        return httpx.Response(422, json={"detail": "Schema validation error"})
    if body.get("action") == "DELETE_ACCOUNT":
        return httpx.Response(
            200,
            json={
                "decision": "REFUSE",
                "authority_record_id": "MANDATE-TREASURY-001",
            },
        )
    if str(body.get("mandate_valid_until", "")).startswith("2020-"):
        return httpx.Response(
            200,
            json={
                "decision": "REFUSE",
                "authority_record_id": "MANDATE-TREASURY-001",
            },
        )
    if int(body.get("screening_max_age_seconds", 3600)) <= 60:
        return httpx.Response(
            200,
            json={
                "decision": "ESCALATE",
                "authority_record_id": "MANDATE-TREASURY-001",
            },
        )
    return httpx.Response(
        200,
        json={
            "decision": "ALLOW",
            "authority_record_id": "MANDATE-TREASURY-001",
            "authority_receipt": {
                "id": "fbf79b89-6de5-490c-a57e-fb6debe65f72",
            },
        },
    )


def test_verify_endpoint_flowsignal_v02_profile() -> None:
    """Verify flowsignal-v0.2 endpoint runner reproduces Step 1 cases against a wire responder."""
    jwt_token = _make_jwt(
        {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:flowsignal/cage-conformance-run:ref:refs/heads/main",
            "repository_owner": "FlowSignal",
        }
    )
    oidc_info = inspect_oidc_jwt(jwt_token)
    prov = build_provenance_block(
        adapter_under_test=_sample_adapter(),
        runner=RunnerProvenance(
            runner_org=oidc_info["inferred_org"],
            runner_identity=oidc_info["oidc_subject"],
            identity_proof=IdentityProofType(oidc_info["identity_proof"]),
            oidc_issuer=oidc_info["oidc_issuer"],
            oidc_subject=oidc_info["oidc_subject"],
            oidc_token_sha256=oidc_info["oidc_token_sha256"],
            cage_conformance_version="0.1.0",
            cage_commit="5595a82ef907",
            timestamp_utc="2026-10-25T12:00:00Z",
        ),
    )
    assert prov.verification_posture == VerificationPosture.COUNTERPARTY_VERIFIED

    transport = httpx.MockTransport(_mock_flowsignal_handler)
    report = verify_endpoint(
        "https://flowsignal-staging.example.run.app",
        provenance=prov,
        profile="flowsignal-v0.2",
        api_key="test-bearer",
        gcp_id_token="test-id-token",
        transport=transport,
    )
    assert report.summary.conformant is True
    assert report.summary.total_assertions == 14
    assert report.summary.passed_assertions == 14

    validated = validate_conformance_report(report.model_dump(mode="json"))
    assert (
        validated.provenance.verification_posture
        == VerificationPosture.COUNTERPARTY_VERIFIED
    )


def test_cli_verify_trace_and_verify_report_roundtrip(tmp_path: Path) -> None:
    """Verify CLI `verify --trace` writes a valid report and `verify-report` accepts it."""
    fixture = load_vector_fixture("trace_v1.json")
    trace_file = tmp_path / "events.jsonl"
    trace_file.write_text(
        "\n".join(json.dumps(ev) for ev in fixture["conformant_trace"]) + "\n",
        encoding="utf-8",
    )
    report_file = tmp_path / "report.json"
    jwt_token = _make_jwt(
        {
            "iss": "https://oauth2.sigstore.dev/auth",
            "sub": "auditor@fca.org.uk",
            "org": "FCA AI Lab",
        }
    )

    rc = cli_main(
        [
            "verify",
            "--trace",
            str(trace_file),
            "--provider-id",
            "provider_01",
            "--adapter-author-org",
            "Google LLC",
            "--counterparty-org",
            "FlowSignal",
            "--runner-org",
            "FCA AI Lab",
            "--oidc-token",
            jwt_token,
            "--output",
            str(report_file),
        ]
    )
    assert rc == 0
    assert report_file.is_file()

    rc_verify = cli_main(["verify-report", str(report_file)])
    assert rc_verify == 0
    saved = json.loads(report_file.read_text(encoding="utf-8"))
    assert (
        saved["provenance"]["verification_posture"]
        == VerificationPosture.INDEPENDENT_PARTY_VERIFIED.value
    )


def test_standalone_wheel_runs_without_repo_checkout(tmp_path: Path) -> None:
    """Verify cage-conformance runs from an isolated directory with no CAGE checkout on sys.path."""
    import shutil
    import subprocess

    isolated_site = tmp_path / "isolated_site"
    isolated_site.mkdir()
    shutil.copytree(
        _PKG_SRC / "cage_conformance",
        isolated_site / "cage_conformance",
    )

    work_dir = tmp_path / "clean_workspace"
    work_dir.mkdir()

    fixture = load_vector_fixture("trace_v1.json")
    trace_file = work_dir / "trace.jsonl"
    trace_file.write_text(
        "\n".join(json.dumps(ev) for ev in fixture["conformant_trace"]) + "\n",
        encoding="utf-8",
    )
    out_report = work_dir / "standalone_report.json"

    script = (
        "import sys; "
        f"assert {str(_REPO_ROOT)!r} not in sys.path; "
        "from cage_conformance.cli import main; "
        f"raise SystemExit(main(['verify', '--trace', {str(trace_file)!r}, '--output', {str(out_report)!r}]))"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=str(work_dir),
        env={"PYTHONPATH": str(isolated_site)},
        capture_output=True,
        text=True,
        check=False,
    )
    # Note: -I ignores PYTHONPATH, so pass isolated_site via sys.path.insert(0, ...)
    if proc.returncode != 0:
        script_isolated = (
            "import sys; "
            f"sys.path = [{str(isolated_site)!r}] + [p for p in sys.path if {str(_REPO_ROOT)!r} not in p or '.venv' in p]; "
            "from cage_conformance.cli import main; "
            f"raise SystemExit(main(['verify', '--trace', {str(trace_file)!r}, '--output', {str(out_report)!r}]))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script_isolated],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            check=False,
        )

    assert proc.returncode == 0, (
        f"Standalone execution failed: {proc.stderr}\n{proc.stdout}"
    )
    assert out_report.is_file()
    report_data = json.loads(out_report.read_text(encoding="utf-8"))
    assert report_data["summary"]["conformant"] is True


def test_entry_points_spi_discovery_and_fail_closed_protocol_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify external partner packages can register via importlib.metadata.entry_points without modifying kernel files."""
    import importlib.metadata

    from src.gateway.governance.normative_provider import get_normative_provider
    from src.gateway.governance.seams.normative import NormativeProvider

    example_src = _REPO_ROOT / "contrib" / "example-normative-provider" / "src"
    monkeypatch.syspath_prepend(str(example_src))

    class _FakeEntryPoint:
        def __init__(self, name: str, loader: Any) -> None:
            self.name = name
            self._loader = loader

        def load(self) -> Any:
            return self._loader()

    def _fake_entry_points(*, group: str | None = None) -> list[_FakeEntryPoint]:
        if group == "cage.normative_providers":
            from example_normative_provider import ExampleNormativeProvider

            return [
                _FakeEntryPoint("example_partner", lambda: ExampleNormativeProvider),
                _FakeEntryPoint("broken_partner", lambda: object),
            ]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_entry_points)

    provider = get_normative_provider("example_partner")
    assert isinstance(provider, NormativeProvider)

    with pytest.raises(TypeError, match="does not implement NormativeProvider"):
        get_normative_provider("broken_partner")
