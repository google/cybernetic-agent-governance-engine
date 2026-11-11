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

import json
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
if [ "$2 $3" = "state list" ] && [ "${CLUSTER_IN_STATE:-1}" = 1 ]; then
  echo "module.gke.google_container_cluster.primary"
  if [ "${LARGE_MANAGED_STATE:-0}" = 1 ]; then
    echo "module.cloudsql_postgres.google_sql_database_instance.postgres"
    awk 'BEGIN { for (i = 0; i < 2500; i++) printf "module.workload.kubernetes_config_map.item_%04d\n", i }'
  fi
fi
if [ "$2 $3" = "state show" ] && [ -n "${SQL_SUFFIX_HEX:-}" ]; then
  echo 'resource "random_id" "cloudsql_suffix" {'
  echo '  hex = "'"${SQL_SUFFIX_HEX}"'"'
  echo '}'
fi
if [ "$2" = "apply" ] && [ "$3" = "tfplan" ] && [ "${FAIL_FIRST_APPLY:-0}" = 1 ]; then
  if [ ! -f "$HOME/.first_apply_failed" ]; then
    touch "$HOME/.first_apply_failed"
    echo "Error: Error waiting for Create Instance:" >&2
    exit 1
  fi
fi
"""
# `gcloud storage ls` succeeds only when the test plants the legacy state file;
# `gcloud container images describe` answers every image with one fixed digest.
_GCLOUD_STUB = """#!/bin/sh
echo "gcloud $*" >> "$STUB_LOG"
if [ "$1 $2" = "storage ls" ]; then
  [ "${LEGACY_STATE:-0}" = 1 ]
  exit $?
fi
if [ "$1 $2 $3" = "container images describe" ]; then
  echo "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
fi
if [ "$1 $2 $3" = "sql instances describe" ] && [ -n "${SQL_DESCRIBE_STATE:-}" ]; then
  if [ "${SQL_DESCRIBE_STATE}" = "PENDING_THEN_RUNNABLE" ]; then
    if [ ! -f "$HOME/.sql_polled_once" ]; then
      touch "$HOME/.sql_polled_once"
      echo "PENDING_CREATE"
    else
      echo "RUNNABLE"
    fi
  else
    echo "${SQL_DESCRIBE_STATE}"
  fi
fi
exit 0
"""
_IMAGE_SHA = "abc1234"


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
    """Run a copy of deploy_all.sh with stub terraform/gcloud and no .env.

    The copy is not a git checkout, so runs name the image build with
    --image-sha (which skips the build) and render its digests through the
    stub gcloud before planning.
    """
    root = tmp_path / "repo"
    shutil.copytree(
        _GKE_DIR,
        root / "infra" / "targets" / "gcp-gke",
        ignore=shutil.ignore_patterns(
            ".terraform",
            "*.tfstate*",
            "*.auto.tfvars",
            "tfplan",
            "image_digests.*.tfvars.json",
        ),
    )
    shutil.copy2(_REPO_ROOT / "deploy_all.sh", root / "deploy_all.sh")
    (root / "scripts").mkdir()
    shutil.copy2(
        _REPO_ROOT / "scripts" / "render_image_digests.sh",
        root / "scripts" / "render_image_digests.sh",
    )
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("terraform", _TERRAFORM_STUB), ("gcloud", _GCLOUD_STUB)):
        stub = stubs / name
        stub.write_text(body)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "calls.log"

    def run(
        *args: str,
        legacy_state: bool = False,
        extra_env: dict[str, str] | None = None,
        build_args: tuple[str, ...] = (f"--image-sha={_IMAGE_SHA}",),
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
                *build_args,
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
    ("args", "banner", "region_log"),
    [
        (
            ("--env", "staging"),
            "STAGING MODE",
            "cage_deployment_region=US_FED — staging enforces",
        ),
        (
            ("--env", "prod"),
            "PROD MODE",
            "cage_deployment_region=US_FED — prod enforces",
        ),
        (
            ("--env", "eu-prod"),
            "PROD MODE",
            "cage_deployment_region=EU_ECB — prod enforces",
        ),
        (
            ("--env", "apac-prod"),
            "PROD MODE",
            "cage_deployment_region=APAC_MAS — prod enforces",
        ),
        (("--env", "us-dev"), "DEV MODE", ""),
        (("--env", "dev"), "DEV MODE", ""),
        # The documented regional overlay keeps working: tier from prod.tfvars,
        # jurisdiction from the EU overlay.
        (
            ("--env", "prod", "--var-file=infra/targets/gcp-gke/eu-prod.tfvars"),
            "PROD MODE",
            "cage_deployment_region=EU_ECB — prod enforces",
        ),
    ],
)
def test_posture_comes_from_the_profile(
    deploy, args: tuple[str, ...], banner: str, region_log: str
) -> None:
    """Tier and jurisdiction are read from the profile, not from the --env name.

    POAM-2026-130 removed enable_nist_compliance; deploy_all.sh no longer
    injects -var=enable_nist_compliance, and the profile's environment /
    enforce_in_dev decides local.enforcing_posture in main.tf directly.
    """
    root, run = deploy
    result, calls = run(*args)
    assert result.returncode == 0, result.stderr
    assert banner in result.stdout
    if region_log:
        assert region_log in result.stdout
    plan = _plan_args(calls)
    assert "enable_nist_compliance" not in plan
    profile = (root / "infra" / "targets" / "gcp-gke" / f"{args[1]}.tfvars").resolve()
    assert f"-var-file={profile}" in plan


def test_region_variable_cannot_override_the_profile(deploy) -> None:
    _, run = deploy
    result, calls = run(
        "--env", "eu-prod", extra_env={"CAGE_DEPLOYMENT_REGION": "US_FED"}
    )
    assert result.returncode == 0, result.stderr
    assert "CAGE_DEPLOYMENT_REGION=US_FED ignored" in result.stdout
    assert "cage_deployment_region=EU_ECB — prod enforces" in result.stdout
    assert "enable_nist_compliance" not in _plan_args(calls)


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
    assert "cage_deployment_region=US_FED — staging enforces" in result.stdout
    assert "enable_nist_compliance" not in _plan_args(calls)


# ── POAM-2026-131: images are rendered per deployment, before the plan ───────


def test_plan_reads_the_digests_rendered_before_it(deploy) -> None:
    root, run = deploy
    result, calls = run("--env", "staging")
    assert result.returncode == 0, result.stderr

    rendered = (
        root
        / "infra"
        / "targets"
        / "gcp-gke"
        / f"image_digests.{_IMAGE_SHA}.tfvars.json"
    )
    digests = json.loads(rendered.read_text())["image_digests"]
    assert digests["gateway"] == "gcr.io/proj-x/gateway@sha256:" + "a" * 64

    plan_at = next(
        i for i, c in enumerate(calls) if c.startswith("terraform ") and " plan " in c
    )
    describes = [
        i
        for i, c in enumerate(calls)
        if c.startswith("gcloud container images describe")
    ]
    assert describes and max(describes) < plan_at, (
        "digests must be rendered before the plan"
    )
    assert f"-var-file={rendered}" in calls[plan_at]
    assert f"gcr.io/proj-x/gateway:{_IMAGE_SHA}" in " ".join(
        calls[i] for i in describes
    )


@pytest.mark.parametrize(
    "env_name",
    ["staging", "prod", "eu-prod", "apac-prod", "us-dev", "eu-dev", "apac-dev"],
)
def test_every_profile_takes_its_project_from_the_environment(
    deploy, env_name: str
) -> None:
    # A committed placeholder project would outrank TF_VAR_project_id.
    _, run = deploy
    result, calls = run("--env", env_name)
    assert result.returncode == 0, result.stderr
    assert "-backend-config=bucket=proj-x-tfstate" in _init_args(calls)


def test_skip_build_outside_a_git_checkout_names_the_fix(deploy) -> None:
    _, run = deploy
    result, calls = run("--env", "staging", build_args=("--skip-build",))
    assert result.returncode != 0
    assert "--image-sha" in result.stderr
    assert not [c for c in calls if c.startswith("terraform ")]


def test_fresh_state_without_gke_runs_stage1_foundation_then_full_plan(deploy) -> None:
    _, run = deploy
    result, calls = run("--env", "staging", extra_env={"CLUSTER_IN_STATE": "0"})
    assert result.returncode == 0, result.stderr
    plans = [c for c in calls if c.startswith("terraform ") and " plan " in c]
    assert len(plans) == 2, calls
    assert "-var=bootstrap_without_cluster=true" in plans[0]
    assert "-target=module.gke" in plans[0]
    assert "-target=module.evidence_domain" in plans[0]
    assert "-target=module.worm_bucket" in plans[0]
    assert "-out=tfplan.stage1" in plans[0]
    assert "bootstrap_without_cluster" not in plans[1]
    assert "-out=tfplan" in plans[1]
    applies = [c for c in calls if c.startswith("terraform ") and " apply " in c]
    assert len(applies) == 2, calls
    assert applies[0].endswith(" apply tfplan.stage1")
    assert applies[1].endswith(" apply tfplan")
    assert "-parallelism=1" not in applies[1]


def test_cloudsql_lro_poll_drop_imports_runnable_instance_and_retries_apply(
    deploy,
) -> None:
    _, run = deploy
    result, calls = run(
        "--env",
        "staging",
        "--auto-approve",
        extra_env={
            "FAIL_FIRST_APPLY": "1",
            "SQL_SUFFIX_HEX": "60879e64",
            "SQL_DESCRIBE_STATE": "PENDING_THEN_RUNNABLE",
            "DEPLOY_CLOUDSQL_RETRY_SLEEP": "0",
        },
    )
    assert result.returncode == 0, result.stderr
    sql_describes = [c for c in calls if c.startswith("gcloud sql instances describe")]
    assert len(sql_describes) == 2
    imports = [c for c in calls if c.startswith("terraform ") and " import " in c]
    assert len(imports) == 1
    assert (
        "module.cloudsql_postgres.google_sql_database_instance.postgres "
        "projects/proj-x/instances/cage-postgres-staging-60879e64"
    ) in imports[0]
    applies = [c for c in calls if c.startswith("terraform ") and " apply " in c]
    assert len(applies) == 2


def test_large_state_list_does_not_trigger_sigpipe_false_import_or_stage1(
    deploy,
) -> None:
    """Ensure >128KB `terraform state list` never triggers SIGPIPE (141) under pipefail."""
    _, run = deploy
    result, calls = run(
        "--env",
        "staging",
        "--auto-approve",
        extra_env={
            "FAIL_FIRST_APPLY": "1",
            "LARGE_MANAGED_STATE": "1",
            "SQL_SUFFIX_HEX": "23719e04",
            "SQL_DESCRIBE_STATE": "RUNNABLE",
            "DEPLOY_CLOUDSQL_RETRY_SLEEP": "0",
        },
    )
    assert result.returncode == 0, result.stderr
    stage1_plans = [
        c for c in calls if c.startswith("terraform ") and "-out=tfplan.stage1" in c
    ]
    assert stage1_plans == []
    imports = [c for c in calls if c.startswith("terraform ") and " import " in c]
    assert imports == []
    applies = [c for c in calls if c.startswith("terraform ") and " apply " in c]
    assert len(applies) == 2
