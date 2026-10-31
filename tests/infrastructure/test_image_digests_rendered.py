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

"""POAM-2026-131: no image digest and no project placeholder is committed.

A digest names an image in one registry, so every deployment renders its own:
deploy_all.sh builds the images the profile deploys, renders their digests with
scripts/render_image_digests.sh into a gitignored var file, and only then plans.
The committed profiles once pinned every image to a registry nobody could pull
from, the renderer's output was never read, and the plan was saved before the
images were built. These tests fail if a committed value, a default, a renderer
fallback or that order comes back.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
VARIABLES_TF = GKE_TARGET_DIR / "variables.tf"
MAIN_TF = GKE_TARGET_DIR / "main.tf"
FIXTURE = GKE_TARGET_DIR / "tests" / "fixtures" / "image_digests.tfvars"
RENDER = REPO_ROOT / "scripts" / "render_image_digests.sh"
BUILD = REPO_ROOT / "scripts" / "build_images.sh"
DEPLOY_ALL = REPO_ROOT / "deploy_all.sh"
GITIGNORE = REPO_ROOT / ".gitignore"

# SHA-256 of empty input: no image manifest has it, so it is only ever a placeholder.
EMPTY_INPUT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _variable_block(name: str) -> str:
    text = VARIABLES_TF.read_text(encoding="utf-8")
    start = text.index(f'variable "{name}"')
    end = text.find('\nvariable "', start + 1)
    return text[start:] if end == -1 else text[start:end]


def _committed_profiles() -> list[Path]:
    # terraform.auto.tfvars is generated from .env and gitignored.
    return sorted(
        p for p in GKE_TARGET_DIR.glob("*.tfvars") if p.name != "terraform.auto.tfvars"
    )


def _bash_array(script: Path, name: str) -> list[str]:
    body = re.search(
        rf"^{name}=\((.*?)^\)", script.read_text(encoding="utf-8"), re.M | re.S
    )
    assert body, f"{name}=( ... ) not found in {script.name}"
    return [item.split("|", 1)[0] for item in re.findall(r'"([^"]+)"', body.group(1))]


def _required_image_names() -> set[str]:
    text = MAIN_TF.read_text(encoding="utf-8")
    body = re.search(r"required_image_digests = concat\((.*?)\n  \)", text, re.S)
    assert body, "local.required_image_digests not found in main.tf"
    return set(re.findall(r'\[\s*"([^"]+)"', body.group(1))) | set(
        re.findall(r'"([a-z0-9-]+)"(?=\s*[,\]])', body.group(1))
    )


def _fixture_entries() -> dict[str, str]:
    return dict(
        re.findall(
            r'^\s*"([^"]+)"\s*=\s*"([^"]+)"', FIXTURE.read_text(encoding="utf-8"), re.M
        )
    )


# ── Nothing deployable is committed ──────────────────────────────────────────


@pytest.mark.parametrize("name", ["image_digests", "project_id"])
def test_variable_has_no_default(name: str) -> None:
    assert not re.search(r"^\s*default\s*=", _variable_block(name), re.M), (
        f'variable "{name}" must have no default: a placeholder stands in for a '
        "deployable value (POAM-2026-131)"
    )


@pytest.mark.parametrize("profile", _committed_profiles(), ids=lambda p: p.name)
def test_no_profile_commits_digests_or_a_project(profile: Path) -> None:
    text = profile.read_text(encoding="utf-8")
    assert not re.search(r"^\s*image_digests\s*=", text, re.M), (
        f"{profile.name} commits image_digests; they are rendered per deployment"
    )
    assert not re.search(r"^\s*project_id\s*=", text, re.M), (
        f"{profile.name} commits project_id; a -var-file value outranks the "
        "TF_VAR_project_id deploy_all.sh maps from GOOGLE_CLOUD_PROJECT"
    )


def test_rendered_files_are_gitignored() -> None:
    assert (
        "image_digests.*.tfvars.json"
        in GITIGNORE.read_text(encoding="utf-8").splitlines()
    )


# ── The way to supply them is printed where people see it ────────────────────


def test_render_hint_reaches_both_error_channels() -> None:
    # terraform shows the description only in its interactive prompt; with
    # -input=false its error quotes the declaration line, so the hint is on both.
    block = _variable_block("image_digests")
    declaration, rest = block.split("\n", 1)
    assert "scripts/render_image_digests.sh" in declaration
    assert "scripts/render_image_digests.sh" in rest.split("type", 1)[0]
    assert "GOOGLE_CLOUD_PROJECT" in _variable_block("project_id").split("\n", 1)[0]


# ── What the variable accepts ────────────────────────────────────────────────


def test_validation_refuses_the_empty_input_digest() -> None:
    block = _variable_block("image_digests")
    assert f'endswith(ref, "@sha256:{EMPTY_INPUT_SHA256}")' in block


def test_validation_follows_the_images_the_profile_deploys() -> None:
    assert "local.required_image_digests" in _variable_block("image_digests")


def test_fixture_is_test_only_and_covers_every_requirable_image() -> None:
    entries = _fixture_entries()
    assert entries, "fixture map is empty"
    for name, ref in entries.items():
        assert ref.startswith(f"registry.invalid/cage-test/{name}@sha256:"), ref
        assert EMPTY_INPUT_SHA256 not in ref
    assert _required_image_names() <= set(entries)


# ── The renderer, the builder and Terraform agree ────────────────────────────


def test_renderer_can_render_every_image_terraform_can_require() -> None:
    catalogue = set(_bash_array(RENDER, "FIRST_PARTY_IMAGES")) | set(
        _bash_array(RENDER, "THIRD_PARTY_TAGGED_IMAGES")
    )
    missing = _required_image_names() - catalogue
    assert not missing, f"render_image_digests.sh cannot render {sorted(missing)}"


def test_builder_and_renderer_know_the_same_first_party_images() -> None:
    match = re.search(r'^ALL_IMAGES="([^"]+)"', BUILD.read_text(encoding="utf-8"), re.M)
    assert match, "ALL_IMAGES not found in build_images.sh"
    assert set(match.group(1).split()) == set(_bash_array(RENDER, "FIRST_PARTY_IMAGES"))


def test_renderer_never_falls_back_to_another_builds_image() -> None:
    # list-tags --limit=1 picked whatever was pushed last, not the SHA deployed.
    assert "list-tags" not in RENDER.read_text(encoding="utf-8")


def test_deploy_all_builds_then_renders_then_plans() -> None:
    text = DEPLOY_ALL.read_text(encoding="utf-8")
    build = text.index('bash "$REPO_ROOT/scripts/build_images.sh"')
    render = text.index('bash "$REPO_ROOT/scripts/render_image_digests.sh"')
    plan = text.index('plan "${plan_args[@]}" -out=tfplan')
    assert build < render < plan, (
        "the saved plan must pin images that were already built"
    )
    assert "TF_VAR_skip_build" not in text


# ── Renderer behaviour, against a stub gcloud ────────────────────────────────

_PROJECT = "demo-project-01"
_DIGEST = "sha256:" + "a" * 64


def _stub_gcloud(tmp_path: Path, resolvable: set[str]) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "gcloud.log"
    cases = "|".join(sorted(resolvable)) or "__none__"
    stub = bin_dir / "gcloud"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$*" >> "{log}"\n'
        'case "$4" in\n'
        f'  {cases}) echo "{_DIGEST}" ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["PROJECT_ID"] = _PROJECT
    env["STUB_LOG"] = str(log)
    return env


def _render(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(RENDER), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_render_writes_only_the_images_built_for_the_sha(tmp_path: Path) -> None:
    registry = f"gcr.io/{_PROJECT}"
    env = _stub_gcloud(
        tmp_path, {f"{registry}/gateway:abc1234", f"{registry}/opa:1.2.0-static"}
    )
    out = tmp_path / "digests.tfvars.json"

    result = _render(env, "--output", str(out), "abc1234")

    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text(encoding="utf-8")) == {
        "image_digests": {
            "gateway": f"{registry}/gateway@{_DIGEST}",
            "opa": f"{registry}/opa@{_DIGEST}",
        }
    }
    assert (
        f"{registry}/agentsight-ui:abc1234" in result.stderr
    )  # named, not substituted
    assert "list-tags" not in (tmp_path / "gcloud.log").read_text(encoding="utf-8")


def test_render_refuses_a_sha_with_no_first_party_build(tmp_path: Path) -> None:
    # Third-party tags resolve whatever the SHA; they must not mask a missing build.
    env = _stub_gcloud(tmp_path, {f"gcr.io/{_PROJECT}/opa:1.2.0-static"})
    result = _render(env, "--output", "-", "abc1234")
    assert result.returncode == 1
    assert "no first-party image is tagged abc1234" in result.stderr


@pytest.mark.parametrize("project", ['x"; rm -rf /', "Bad_Project", ""])
def test_render_refuses_a_malformed_project_id(tmp_path: Path, project: str) -> None:
    env = _stub_gcloud(tmp_path, set())
    env["PROJECT_ID"] = project
    assert _render(env, "--output", "-", "abc1234").returncode == 1


def test_render_refuses_a_ref_that_is_not_a_commit_sha(tmp_path: Path) -> None:
    env = _stub_gcloud(tmp_path, set())
    assert _render(env, "--output", "-", "HEAD~1").returncode == 1
