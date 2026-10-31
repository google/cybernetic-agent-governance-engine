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

"""Unit tests for clean-project GCP bootstrap (`scripts/bootstrap_gcp_project.sh` and `scripts/gen_tfvars.py`)."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from scripts import gen_tfvars

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SCRIPT = REPO_ROOT / "scripts" / "bootstrap_gcp_project.sh"

EXPECTED_APIS = {
    "container.googleapis.com",
    "compute.googleapis.com",
    "storage.googleapis.com",
    "artifactregistry.googleapis.com",
    "containerfilesystem.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com",
    "memorystore.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "networkconnectivity.googleapis.com",
    "privateca.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "dns.googleapis.com",
    "accesscontextmanager.googleapis.com",
}


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _make_stub_bins(
    tmp_path: Path,
    *,
    describe_exists: bool = False,
    state_list_entries: list[str] | None = None,
) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    log_file = tmp_path / "calls.log"
    log_file.write_text("", encoding="utf-8")

    describe_rc = "0" if describe_exists else "1"
    state_text = "\n".join(state_list_entries or [])

    _write_executable(
        bin_dir / "gcloud",
        f"""#!/usr/bin/env bash
echo "gcloud $*" >> "{log_file}"
if [[ "$*" == *"config get-value project"* ]]; then
  echo "${{STUB_DEFAULT_PROJECT:-}}"
  exit 0
fi
if [[ "$*" == *"config get-value account"* ]]; then
  echo "${{STUB_ACTIVE_ACCOUNT:-operator@example.com}}"
  exit 0
fi
if [[ "$*" == *"auth print-access-token"* ]]; then
  echo "stub-token"
  exit 0
fi
if [[ "$*" == *" describe "* ]]; then
  exit {describe_rc}
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "curl",
        f"""#!/usr/bin/env bash
echo "curl $*" >> "{log_file}"
if [[ "$*" == *"-w %{{http_code}}"* ]]; then
  if [[ "{describe_rc}" == "0" ]]; then
    printf "200"
  else
    printf "404"
  fi
fi
exit 0
""",
    )

    state_file = tmp_path / "state_list.txt"
    state_file.write_text(state_text, encoding="utf-8")

    _write_executable(
        bin_dir / "terraform",
        f"""#!/usr/bin/env bash
echo "terraform $*" >> "{log_file}"
if [[ "$*" == *" state list"* ]]; then
  cat "{state_file}"
  exit 0
fi
exit 0
""",
    )

    return bin_dir, log_file


def test_bootstrap_rejects_missing_project(tmp_path: Path) -> None:
    bin_dir, _ = _make_stub_bins(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "PROJECT_ID": "",
        "STUB_DEFAULT_PROJECT": "",
    }
    proc = subprocess.run(
        ["bash", str(BOOTSTRAP_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "--project or PROJECT_ID is required" in proc.stderr


def test_bootstrap_rejects_invalid_env(tmp_path: Path) -> None:
    bin_dir, _ = _make_stub_bins(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        ["bash", str(BOOTSTRAP_SCRIPT), "--project=demo-proj", "--env=invalid"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "--env must be one of: dev, staging, prod" in proc.stderr


def test_bootstrap_enables_all_21_required_apis_and_creates_foundational_resources(
    tmp_path: Path,
) -> None:
    bin_dir, log_file = _make_stub_bins(tmp_path, describe_exists=False)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        [
            "bash",
            str(BOOTSTRAP_SCRIPT),
            "--project=clean-proj-01",
            "--env=staging",
            "--region=us-central1",
            "--deployer-sa=sa-cage-deployer@clean-proj-01.iam.gserviceaccount.com",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    calls = log_file.read_text(encoding="utf-8")

    # W1: All 21 required APIs are enabled.
    for api in EXPECTED_APIS:
        assert api in calls, f"Missing required API in bootstrap: {api}"

    # W2: Remote Terraform state bucket created and versioned.
    assert "gcloud storage buckets create gs://clean-proj-01-tfstate" in calls
    assert (
        "gcloud storage buckets update gs://clean-proj-01-tfstate --project=clean-proj-01 --versioning"
        in calls
    )

    # W4: Artifact Registry gcr.io repository and Cloud Build bucket created.
    assert "gcloud artifacts repositories create gcr.io" in calls
    assert "gcloud storage buckets create gs://clean-proj-01_cloudbuild" in calls

    # W3: Dedicated Cloud Build SA, KMS keyring/key, Container Analysis note, and BinAuthz attestor created.
    assert "gcloud iam service-accounts create cage-cloudbuild-staging" in calls
    assert "gcloud kms keyrings create cage-signing-staging" in calls
    assert "gcloud kms keys create binauthz-attestor" in calls
    assert "--protection-level=hsm" in calls
    assert "notes?noteId=cage-build-attestor-note-staging" in calls
    assert (
        "gcloud container binauthz attestors create cage-build-attestor-staging"
        in calls
    )
    assert "gcloud container binauthz attestors public-keys add" in calls

    # W10: Deployer SA granted roles/cloudkms.publicKeyViewer on the project.
    assert (
        "gcloud projects add-iam-policy-binding clean-proj-01 "
        "--member=serviceAccount:sa-cage-deployer@clean-proj-01.iam.gserviceaccount.com "
        "--role=roles/cloudkms.publicKeyViewer"
    ) in calls


def test_bootstrap_import_state_imports_missing_and_skips_existing(
    tmp_path: Path,
) -> None:
    bin_dir, log_file = _make_stub_bins(
        tmp_path,
        describe_exists=True,
        state_list_entries=[
            "google_service_account.cloudbuild",
            "google_kms_key_ring.signing",
        ],
    )
    tf_dir = tmp_path / "tf"
    tf_dir.mkdir(parents=True, exist_ok=True)
    (tf_dir / "staging.tfvars").write_text(
        'environment = "staging"\n', encoding="utf-8"
    )

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        [
            "bash",
            str(BOOTSTRAP_SCRIPT),
            "--project=recycled-proj",
            "--env=staging",
            "--region=us-central1",
            f"--tf-dir={tf_dir}",
            "--import-state",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    calls = log_file.read_text(encoding="utf-8")
    # Already in state -> must NOT be re-imported.
    assert "import" in calls
    assert "google_service_account.cloudbuild" not in calls
    assert "google_kms_key_ring.signing " not in calls

    # Missing from state -> imported into Terraform state (W8 / W3).
    assert (
        "google_kms_crypto_key.binauthz_attestor "
        "projects/recycled-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/binauthz-attestor"
    ) in calls
    assert (
        "google_kms_crypto_key.gateway_seal "
        "projects/recycled-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal"
    ) in calls
    assert (
        "module.kms[0].google_kms_key_ring.keyring "
        "projects/recycled-proj/locations/us-central1/keyRings/cage-keyring-staging"
    ) in calls
    assert (
        "google_container_analysis_note.build_attestor_note[0] "
        "projects/recycled-proj/notes/cage-build-attestor-note-staging"
    ) in calls
    assert (
        "google_binary_authorization_attestor.build_attestor[0] "
        "projects/recycled-proj/attestors/cage-build-attestor-staging"
    ) in calls


def test_gen_tfvars_succeeds_without_kms_governance_key_and_omits_undeclared_var(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    out_file = tmp_path / "terraform.auto.tfvars"
    # Clean-project .env without KMS_GOVERNANCE_KEY (keys are created by kms_signing.tf).
    env_file.write_text(
        'OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic dGVzdDp0ZXN0"\n',
        encoding="utf-8",
    )

    rc = gen_tfvars.main(["--env", str(env_file), "--output", str(out_file)])
    assert rc == 0
    rendered = out_file.read_text(encoding="utf-8")
    assert "otel_exporter_otlp_headers" in rendered
    assert "kms_governance_key" not in rendered
