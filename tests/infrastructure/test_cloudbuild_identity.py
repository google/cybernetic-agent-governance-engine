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

"""Static and hermetic guards for dedicated Cloud Build identity & single attestation step (POAM-2026-083)."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
DOCKER_DIR = REPO_ROOT / "deployment" / "docker"
SCRIPTS_DIR = REPO_ROOT / "scripts"


def test_cloudbuild_service_account_and_build_grants_declared() -> None:
    iam_tf = (GKE_TARGET_DIR / "iam.tf").read_text(encoding="utf-8")
    perimeter_tf = (GKE_TARGET_DIR / "perimeter.tf").read_text(encoding="utf-8")
    outputs_tf = (GKE_TARGET_DIR / "outputs.tf").read_text(encoding="utf-8")

    assert 'resource "google_service_account" "cloudbuild"' in iam_tf
    assert 'account_id   = "cage-cloudbuild-${var.environment}"' in iam_tf

    # Three build-time IAM bindings on google_service_account.cloudbuild
    assert 'resource "google_project_iam_member" "cloudbuild_log_writer"' in iam_tf
    assert (
        'resource "google_project_iam_member" "cloudbuild_artifactregistry_writer"'
        in iam_tf
    )
    assert (
        'resource "google_storage_bucket_iam_member" "cloudbuild_source_viewer"'
        in iam_tf
    )
    assert 'bucket = "${var.project_id}_cloudbuild"' in iam_tf

    # Note occurrences viewer & project occurrences editor required for binauthz sign-and-create + list
    assert (
        'resource "google_container_analysis_note_iam_member" "cloudbuild_note_occurrences_viewer"'
        in perimeter_tf
    )
    assert (
        'role    = "roles/containeranalysis.notes.occurrences.viewer"' in perimeter_tf
    )
    assert (
        'resource "google_project_iam_member" "cloudbuild_occurrences_editor"'
        in perimeter_tf
    )
    assert 'role    = "roles/containeranalysis.occurrences.editor"' in perimeter_tf

    assert 'output "cloudbuild_service_account_email"' in outputs_tf


def test_cloudbuild_member_references_dedicated_service_account() -> None:
    kms_tf = (GKE_TARGET_DIR / "kms_signing.tf").read_text(encoding="utf-8")
    assert (
        'cloudbuild_member        = "serviceAccount:${google_service_account.cloudbuild.email}"'
        in kms_tf
    )


def test_no_tf_file_contains_legacy_cloudbuild_gserviceaccount() -> None:
    tf_files = sorted((REPO_ROOT / "infra").rglob("*.tf"))
    assert tf_files
    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in tf_files
        if "@cloudbuild.gserviceaccount.com" in p.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"Legacy @cloudbuild.gserviceaccount.com must not appear in .tf files: {offenders}"
    )


def test_every_cloudbuild_yaml_declares_service_account_and_cloud_logging_only() -> (
    None
):
    for deleted in (
        "cloudbuild.advisor.yaml",
        "cloudbuild.compliance.yaml",
        "cloudbuild.gateway.yaml",
        "cloudbuild.nemo.yaml",
        "cloudbuild.opa.yaml",
        "cloudbuild.ui.yaml",
    ):
        assert not (DOCKER_DIR / deleted).exists(), (
            f"{deleted} should be folded into cloudbuild.image.yaml and deleted"
        )

    cloudbuild_files = sorted(DOCKER_DIR.glob("cloudbuild.*.yaml"))
    assert [p.name for p in cloudbuild_files] == [
        "cloudbuild.image.yaml",
        "cloudbuild.lula.yaml",
        "cloudbuild.vllm.yaml",
    ]

    for cb_path in cloudbuild_files:
        doc = yaml.safe_load(cb_path.read_text(encoding="utf-8"))
        sa = doc.get("serviceAccount", "")
        assert (
            sa
            == "projects/$PROJECT_ID/serviceAccounts/cage-cloudbuild-${_ENVIRONMENT}@$PROJECT_ID.iam.gserviceaccount.com"
        ), (
            f"{cb_path.name} must declare dedicated cage-cloudbuild serviceAccount (got {sa!r})"
        )
        options = doc.get("options") or {}
        assert options.get("logging") == "CLOUD_LOGGING_ONLY", (
            f"{cb_path.name} must set options.logging: CLOUD_LOGGING_ONLY"
        )
        text = cb_path.read_text(encoding="utf-8")
        assert "scripts/attest_image.sh" in text, (
            f"{cb_path.name} must delegate attestation to scripts/attest_image.sh"
        )
        assert "_SHORT_SHA" not in (doc.get("substitutions") or {}), (
            f"{cb_path.name} must not define a default _SHORT_SHA substitution"
        )


def test_sign_and_create_appears_in_exactly_one_script_as_gcloud_beta() -> None:
    matches: list[Path] = []
    for search_dir in (SCRIPTS_DIR, DOCKER_DIR):
        for path in sorted(search_dir.rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "sign-and-create" in text:
                matches.append(path)

    assert matches == [SCRIPTS_DIR / "attest_image.sh"], (
        f"sign-and-create must live exclusively in scripts/attest_image.sh, found in: "
        f"{[str(m.relative_to(REPO_ROOT)) for m in matches]}"
    )

    attest_text = (SCRIPTS_DIR / "attest_image.sh").read_text(encoding="utf-8")
    # Every non-comment invocation of sign-and-create must use `gcloud beta`
    code_lines = [
        line.strip()
        for line in attest_text.splitlines()
        if not line.lstrip().startswith("#") and "sign-and-create" in line
    ]
    assert len(code_lines) == 1
    assert code_lines[0].startswith(
        "gcloud beta container binauthz attestations sign-and-create"
    ), f"Expected gcloud beta sign-and-create, got: {code_lines[0]!r}"


def test_build_images_refuses_outside_git_checkout(tmp_path: Path) -> None:
    build_script = SCRIPTS_DIR / "build_images.sh"
    text = build_script.read_text(encoding="utf-8")
    assert 'echo "v1"' not in text

    res = subprocess.run(
        ["bash", str(build_script)],
        cwd=tmp_path,
        env={**os.environ, "PROJECT_ID": "test-proj"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode != 0
    assert "refusing to build outside a git checkout" in res.stderr


def test_attest_image_fails_closed_when_attestation_list_is_empty(
    tmp_path: Path,
) -> None:
    attest_script = SCRIPTS_DIR / "attest_image.sh"

    # 1. Refuses mutable :latest tag
    res_latest = subprocess.run(
        ["bash", str(attest_script), "gcr.io/test-proj/gateway:latest"],
        cwd=REPO_ROOT,
        env={**os.environ, "PROJECT_ID": "test-proj"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_latest.returncode != 0
    assert "refusing to attest mutable ':latest' tag" in res_latest.stderr

    # 2. Stub gcloud where sign-and-create exits 0 but `attestations list` returns empty -> fails closed
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gcloud = bin_dir / "gcloud"
    fake_gcloud.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$*" == *"images describe"* ]]; then\n'
        '  echo "sha256:' + ("a" * 64) + '"\n'
        "  exit 0\n"
        "fi\n"
        'if [[ "$*" == *"sign-and-create"* ]]; then\n'
        "  exit 0\n"
        "fi\n"
        'if [[ "$*" == *"attestations list"* ]]; then\n'
        '  echo "${FAKE_ATTESTATION_OUTPUT:-}"\n'
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    fake_gcloud.chmod(fake_gcloud.stat().st_mode | stat.S_IEXEC)

    base_env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "PROJECT_ID": "test-proj",
        "ATTESTATION_LIST_SLEEP_SECONDS": "0",
    }

    res_empty = subprocess.run(
        ["bash", str(attest_script), "gcr.io/test-proj/gateway:abc1234"],
        cwd=REPO_ROOT,
        env={**base_env, "FAKE_ATTESTATION_OUTPUT": ""},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_empty.returncode != 0
    assert "fail-closed attestation check failed" in res_empty.stderr

    # 3. Succeeds when `attestations list` returns a non-empty occurrence name
    res_ok = subprocess.run(
        ["bash", str(attest_script), "gcr.io/test-proj/gateway:abc1234"],
        cwd=REPO_ROOT,
        env={
            **base_env,
            "FAKE_ATTESTATION_OUTPUT": "projects/test-proj/occurrences/12345",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_ok.returncode == 0, res_ok.stderr
    assert re.search(r"Verified Binary Authorization attestation", res_ok.stdout)
