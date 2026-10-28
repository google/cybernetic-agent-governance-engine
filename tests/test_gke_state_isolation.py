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

"""Regression guard: one Terraform state per GKE cluster.

Every gcp-gke environment used to share one remote state file
(``cage/gcp-gke/default.tfstate``), and ``dev.tfvars`` named no cluster, so
the cluster name came from ``.env`` (the template set ``cage-staging``).
``./deploy_all.sh --target gcp-gke --env dev`` therefore planned dev settings
against whichever cluster the shared state held. The script also passed no
state bucket, so ``terraform init`` prompted or failed on its first step.

The fix names a cluster in every tfvars file and keys the remote state on that
name. These tests run the real ``deploy_all.sh`` against stub ``terraform`` and
``gcloud`` binaries and assert what ``terraform init`` receives.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import stat
import subprocess

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_GKE_DIR = _REPO_ROOT / "infra" / "targets" / "gcp-gke"
_CLUSTER_NAME = re.compile(r'^\s*cluster_name\s*=\s*"([^"]*)"', re.MULTILINE)

# Files that are deliberately two postures of one cluster. They share its state,
# so adding an entry here is a decision about state, not a convenience.
_SHARED_CLUSTERS = {"cage-dev": {"dev.tfvars", "us-dev.tfvars"}}

_TERRAFORM_STUB = """#!/bin/sh
echo "terraform $*" >> "$STUB_LOG"
"""
# `gcloud storage ls` succeeds only when the test plants the legacy state file.
_GCLOUD_STUB = """#!/bin/sh
echo "gcloud $*" >> "$STUB_LOG"
if [ "$1 $2" = "storage ls" ]; then
  [ "${LEGACY_STATE:-0}" = 1 ]
  exit $?
fi
exit 0
"""


def _tfvars_files() -> list[pathlib.Path]:
    return sorted(
        p for p in _GKE_DIR.glob("*.tfvars") if not p.name.endswith(".auto.tfvars")
    )


def test_every_environment_names_its_cluster() -> None:
    files = _tfvars_files()
    assert files, "no gcp-gke tfvars files found"
    missing = [p.name for p in files if not _CLUSTER_NAME.findall(p.read_text())]
    assert not missing, f"tfvars without an explicit cluster_name: {missing}"


def test_cluster_names_are_not_shared_by_accident() -> None:
    owners: dict[str, set[str]] = {}
    for path in _tfvars_files():
        names = _CLUSTER_NAME.findall(path.read_text())
        if names:
            owners.setdefault(names[-1], set()).add(path.name)
    shared = {name: files for name, files in owners.items() if len(files) > 1}
    assert shared == _SHARED_CLUSTERS


def test_backend_block_commits_no_shared_prefix() -> None:
    block = re.search(
        r'backend\s+"gcs"\s*\{([^}]*)\}', (_GKE_DIR / "main.tf").read_text()
    )
    assert block is not None, "gcs backend block not found in main.tf"
    assert "prefix" not in re.sub(r"#.*", "", block.group(1))


@pytest.fixture
def deploy(tmp_path: pathlib.Path):
    """Run a copy of deploy_all.sh with stub terraform/gcloud and no .env."""
    root = tmp_path / "repo"
    shutil.copytree(
        _GKE_DIR,
        root / "infra" / "targets" / "gcp-gke",
        ignore=shutil.ignore_patterns(
            ".terraform", "*.tfstate*", "*.auto.tfvars", "tfplan"
        ),
    )
    shutil.copy2(_REPO_ROOT / "deploy_all.sh", root / "deploy_all.sh")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("terraform", _TERRAFORM_STUB), ("gcloud", _GCLOUD_STUB)):
        stub = stubs / name
        stub.write_text(body)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "calls.log"

    def run(
        *args: str, legacy_state: bool = False, extra_env: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        log.write_text("")
        env = {
            "PATH": f"{stubs}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "HOME": str(tmp_path),
            "STUB_LOG": str(log),
            "LEGACY_STATE": "1" if legacy_state else "0",
            "TF_VAR_project_id": "proj-x",
            **(extra_env or {}),
        }
        result = subprocess.run(
            [
                "bash",
                str(root / "deploy_all.sh"),
                "--target",
                "gcp-gke",
                *args,
                "--skip-build",
                "--auto-approve",
            ],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result, log.read_text().splitlines()

    return root, run


def _init_args(calls: list[str]) -> str:
    inits = [c for c in calls if c.startswith("terraform ") and " init" in c]
    assert len(inits) == 1, calls
    return inits[0]


def test_dev_gets_its_own_state_and_a_bucket(deploy) -> None:
    _, run = deploy
    result, calls = run("--env", "dev")
    assert result.returncode == 0, result.stderr
    init = _init_args(calls)
    assert "-reconfigure" in init
    assert "-backend-config=bucket=proj-x-tfstate" in init
    assert "-backend-config=prefix=cage/gcp-gke/cage-dev" in init


def test_environments_never_share_a_prefix(deploy) -> None:
    _, run = deploy
    prefixes = set()
    for env in ("dev", "staging", "prod"):
        result, calls = run("--env", env)
        assert result.returncode == 0, result.stderr
        prefixes.add(re.search(r"prefix=(\S+)", _init_args(calls)).group(1))
    assert prefixes == {
        "cage/gcp-gke/cage-dev",
        "cage/gcp-gke/cage-staging",
        "cage/gcp-gke/cage-prod",
    }


def test_regional_overlay_and_cli_override_select_their_own_state(deploy) -> None:
    root, run = deploy
    result, calls = run(
        "--env", "prod", "--var-file=infra/targets/gcp-gke/eu-prod.tfvars"
    )
    assert result.returncode == 0, result.stderr
    assert "prefix=cage/gcp-gke/cage-eu-prod" in _init_args(calls)
    # terraform runs with -chdir, so the overlay must reach it as an absolute path
    overlay = root / "infra" / "targets" / "gcp-gke" / "eu-prod.tfvars"
    plan = next(c for c in calls if " plan " in c)
    assert f"-var-file={overlay.resolve()}" in plan

    result, calls = run("--env", "dev", "--var", "cluster_name=cage-x")
    assert result.returncode == 0, result.stderr
    assert "prefix=cage/gcp-gke/cage-x" in _init_args(calls)


def test_legacy_shared_state_blocks_before_init(deploy) -> None:
    _, run = deploy
    result, calls = run("--env", "dev", legacy_state=True)
    assert result.returncode != 0
    assert "Legacy shared state found" in result.stderr
    assert not [c for c in calls if c.startswith("terraform ")]


def test_unknown_environment_fails_closed(deploy) -> None:
    _, run = deploy
    result, calls = run("--env", "nonexistent")
    assert result.returncode != 0
    assert "Var file not found" in result.stderr
    assert not [c for c in calls if c.startswith("terraform ")]


def _plan_args(calls: list[str]) -> str:
    plans = [c for c in calls if c.startswith("terraform ") and " plan " in c]
    assert len(plans) == 1, calls
    return plans[0]


@pytest.mark.parametrize(
    ("args", "banner", "nist"),
    [
        (("--env", "staging"), "STAGING MODE", "true"),
        (("--env", "prod"), "PROD MODE", "true"),
        (("--env", "eu-prod"), "PROD MODE", "false"),
        (("--env", "apac-prod"), "PROD MODE", "false"),
        (("--env", "us-dev"), "DEV MODE", "false"),
        (("--env", "dev"), "DEV MODE", "false"),
        # The documented regional overlay keeps working: tier from prod.tfvars,
        # jurisdiction from the EU overlay.
        (
            ("--env", "prod", "--var-file=infra/targets/gcp-gke/eu-prod.tfvars"),
            "PROD MODE",
            "false",
        ),
    ],
)
def test_posture_comes_from_the_profile(
    deploy, args: tuple[str, ...], banner: str, nist: str
) -> None:
    """Tier and jurisdiction are read from the profile, not from the --env name.

    staging.tfvars and prod.tfvars declare US_FED, so they get NIST hardening
    with no CAGE_DEPLOYMENT_REGION set; eu-prod is a production profile.
    """
    root, run = deploy
    result, calls = run(*args)
    assert result.returncode == 0, result.stderr
    assert banner in result.stdout
    plan = _plan_args(calls)
    flag = f"-var=enable_nist_compliance={nist}"
    assert flag in plan
    # Injected ahead of the profile, so an explicit setting in it still wins.
    profile = (root / "infra" / "targets" / "gcp-gke" / f"{args[1]}.tfvars").resolve()
    assert plan.index(flag) < plan.index(f"-var-file={profile}")


def test_region_variable_cannot_override_the_profile(deploy) -> None:
    _, run = deploy
    result, calls = run(
        "--env", "eu-prod", extra_env={"CAGE_DEPLOYMENT_REGION": "US_FED"}
    )
    assert result.returncode == 0, result.stderr
    assert "CAGE_DEPLOYMENT_REGION=US_FED ignored" in result.stdout
    assert "-var=enable_nist_compliance=false" in _plan_args(calls)


def test_region_variable_is_the_fallback_without_a_profile_region(deploy) -> None:
    """dev.tfvars sets no jurisdiction, so CAGE_DEPLOYMENT_REGION still decides."""
    _, run = deploy
    result, calls = run(
        "--env",
        "dev",
        "--var",
        "environment=staging",
        extra_env={"CAGE_DEPLOYMENT_REGION": "US_FED"},
    )
    assert result.returncode == 0, result.stderr
    assert "STAGING MODE" in result.stdout
    assert "ignored" not in result.stdout
    assert "-var=enable_nist_compliance=true" in _plan_args(calls)
