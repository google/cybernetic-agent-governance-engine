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

"""Unit tests for the fail-closed staging lifecycle release gate (`scripts/staging_lifecycle.sh`)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_SCRIPT = REPO_ROOT / "scripts" / "staging_lifecycle.sh"


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _setup_fake_repo(
    tmp_path: Path,
    *,
    kubectl_wait_rc: int = 0,
    ready_replicas: str = "1",
    lula_rc: int = 0,
    pytest_rc: int = 0,
    surviving_bucket: str = "",
) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True, exist_ok=True)
    (repo / "compliance" / "lula").mkdir(parents=True, exist_ok=True)
    tf_dir = repo / "infra" / "targets" / "gcp-gke"
    tf_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(LIFECYCLE_SCRIPT, repo / "scripts" / "staging_lifecycle.sh")
    (repo / "compliance" / "lula" / "lula-validation-sample.yaml").write_text(
        "kind: LulaValidation\n", encoding="utf-8"
    )
    (tf_dir / "staging.tfvars").write_text(
        'environment = "staging"\n', encoding="utf-8"
    )
    (tf_dir / "image_digests.abc1234.tfvars.json").write_text(
        '{"image_digests": {}}\n', encoding="utf-8"
    )

    log_file = tmp_path / "calls.log"
    log_file.write_text("", encoding="utf-8")

    _write_executable(
        repo / "deploy_all.sh",
        f"""#!/usr/bin/env bash
echo "deploy_all.sh $* | TF_VAR_authorized_networks=${{TF_VAR_authorized_networks:-}}" >> "{log_file}"
exit 0
""",
    )

    _write_executable(
        repo / "scripts" / "bootstrap_gcp_project.sh",
        f"""#!/usr/bin/env bash
echo "bootstrap_gcp_project.sh $*" >> "{log_file}"
exit 0
""",
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    _write_executable(
        bin_dir / "git",
        """#!/usr/bin/env bash
if [[ "$*" == *"rev-parse --short HEAD"* ]]; then
  echo "abc1234"
  exit 0
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "gcloud",
        f"""#!/usr/bin/env bash
echo "gcloud $*" >> "{log_file}"
if [[ "$*" == *"projects describe"* ]]; then
  exit 1
fi
if [[ "$*" == *"storage buckets list"* ]]; then
  echo "ephemeral-proj-99-tfstate"
  echo "ephemeral-proj-99_cloudbuild"
  if [[ -n "{surviving_bucket}" ]]; then
    echo "{surviving_bucket}"
  fi
  exit 0
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "kubectl",
        f"""#!/usr/bin/env bash
echo "kubectl $*" >> "{log_file}"
if [[ "$*" == *"wait --for=condition=Ready"* ]]; then
  exit {kubectl_wait_rc}
fi
if [[ "$*" == *"-o jsonpath="* ]]; then
  printf "{ready_replicas}"
  exit 0
fi
echo '{{}}'
exit 0
""",
    )

    _write_executable(
        bin_dir / "lula",
        f"""#!/usr/bin/env bash
echo "lula $*" >> "{log_file}"
exit {lula_rc}
""",
    )

    _write_executable(
        bin_dir / "uv",
        f"""#!/usr/bin/env bash
echo "uv $*" >> "{log_file}"
exit {pytest_rc}
""",
    )

    _write_executable(
        bin_dir / "terraform",
        f"""#!/usr/bin/env bash
echo "terraform $*" >> "{log_file}"
exit 0
""",
    )

    _write_executable(
        bin_dir / "jq",
        """#!/usr/bin/env bash
exit 0
""",
    )

    _write_executable(
        bin_dir / "curl",
        """#!/usr/bin/env bash
echo "203.0.113.42"
exit 0
""",
    )

    return repo, bin_dir, log_file


def test_staging_lifecycle_happy_path_passes_and_destroys_with_rendered_digests(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "GOOGLE_CLOUD_PROJECT": "demo-staging-proj",
    }
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    calls = log_file.read_text(encoding="utf-8")
    # PF5: Auto-populated deployer /32 authorized_networks
    assert (
        'TF_VAR_authorized_networks=[{"cidr":"203.0.113.42/32","display_name":"deployer-egress"}]'
        in calls
    )
    # PF8: Persistent KMS resources detached before destroy
    assert "state rm google_kms_key_ring.signing" in calls
    assert "state rm google_kms_crypto_key.binauthz_attestor" in calls
    assert "state rm module.kms" in calls
    # Phase 6: Destroy passes enable_nist_compliance=true, staging.tfvars, and rendered digests file
    assert "destroy -var=enable_nist_compliance=true -var-file=staging.tfvars" in calls
    assert "image_digests.abc1234.tfvars.json" in calls


def test_staging_lifecycle_fails_closed_when_workload_unready_after_teardown(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, ready_replicas="0")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "GOOGLE_CLOUD_PROJECT": "demo-staging-proj",
    }
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Workload readiness check failed" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    # Still runs Phase 6 teardown for cost containment before exiting non-zero
    assert "destroy -var=enable_nist_compliance=true" in calls


def test_staging_lifecycle_fails_closed_when_lula_or_posture_fails(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, lula_rc=1, pytest_rc=1)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "GOOGLE_CLOUD_PROJECT": "demo-staging-proj",
    }
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Staging lifecycle gate FAILED" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "destroy -var=enable_nist_compliance=true" in calls


def test_staging_lifecycle_fresh_project_bootstraps_and_verifies_zero_survivors(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--billing-account=012345-6789AB-CDEF01",
            "--skip-lula",
            "--skip-posture",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "gcloud projects create ephemeral-proj-99" in calls
    assert (
        "gcloud billing projects link ephemeral-proj-99 --billing-account=012345-6789AB-CDEF01"
        in calls
    )
    assert "bootstrap_gcp_project.sh --project=ephemeral-proj-99" in calls
    assert "gcloud storage buckets list --project=ephemeral-proj-99" in calls


def test_staging_lifecycle_fresh_project_fails_on_surviving_workload_bucket(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        surviving_bucket="langfuse-event-upload-ephemeral-proj-99-deadbeef",
    )
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Surviving workload GCS bucket(s) after destroy" in proc.stderr
