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

"""The pre-push hook that ``scripts/setup_git_hooks.sh`` installs.

Every test pushes from a scratch clone to a local bare repository, so git
itself runs the installed hook and hands it the refs being pushed on stdin.
The hook must judge those refs, never the checked-out branch: a tag push from
``main`` passes, and a push to ``main`` from any branch is refused.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "setup_git_hooks.sh"
PROTECTED_REFUSAL = "Direct push to 'main' is not allowed"


def _name_refusal(branch: str) -> str:
    return f"Branch name '{branch}' does not follow the project's naming convention"


@dataclass(frozen=True)
class Clone:
    """A scratch clone with the hooks installed and a bare ``origin``."""

    work: Path
    env: dict[str, str]

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.work,
            env=self.env,
            capture_output=True,
            text=True,
            check=check,
        )

    def push(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.git("push", "origin", *args, check=False)

    def remote_refs(self) -> set[str]:
        listing = self.git("ls-remote", "origin").stdout
        return {line.split("\t", 1)[1] for line in listing.splitlines()}


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


@pytest.fixture
def clone(tmp_path: Path) -> Clone:
    # Isolate git from the caller's configuration and repository: no global or
    # system config (signing, hooksPath), and no inherited GIT_DIR and the like.
    global_config = tmp_path / "gitconfig"
    global_config.write_text("")
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        HOME=str(tmp_path),
        GIT_CONFIG_GLOBAL=str(global_config),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Hook Test",
        GIT_AUTHOR_EMAIL="hook-test@example.com",
        GIT_COMMITTER_NAME="Hook Test",
        GIT_COMMITTER_EMAIL="hook-test@example.com",
    )
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    for args in (
        ["init", "--quiet", "--bare", "-b", "main", str(remote)],
        ["init", "--quiet", "-b", "main", str(work)],
    ):
        subprocess.run(["git", *args], env=env, check=True, capture_output=True)

    repo = Clone(work=work, env=env)
    repo.git("commit", "--quiet", "--allow-empty", "-m", "chore: initial commit")
    repo.git("tag", "-a", "v1.0.0", "-m", "release: v1.0.0")
    repo.git("remote", "add", "origin", str(remote))
    subprocess.run(
        ["bash", str(INSTALLER)],
        cwd=work,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert os.access(work / ".git" / "hooks" / "pre-push", os.X_OK)
    return repo


def test_tag_push_from_main_is_allowed(clone: Clone) -> None:
    assert clone.git("branch", "--show-current").stdout.strip() == "main"

    result = clone.push("v1.0.0")

    assert result.returncode == 0, _output(result)
    assert "refs/tags/v1.0.0" in clone.remote_refs()


def test_branch_push_from_main_checkout_is_allowed(clone: Clone) -> None:
    clone.git("branch", "feat/ref-checks")

    result = clone.push("feat/ref-checks")

    assert result.returncode == 0, _output(result)
    assert "refs/heads/feat/ref-checks" in clone.remote_refs()


def test_push_to_main_is_refused(clone: Clone) -> None:
    result = clone.push("main")

    assert result.returncode != 0
    assert PROTECTED_REFUSAL in _output(result)
    assert "refs/heads/main" not in clone.remote_refs()


def test_push_to_main_from_a_feature_branch_is_refused(clone: Clone) -> None:
    clone.git("switch", "--quiet", "-c", "feat/elsewhere")

    result = clone.push("HEAD:main")

    assert result.returncode != 0
    assert PROTECTED_REFUSAL in _output(result)
    assert "refs/heads/main" not in clone.remote_refs()


def test_one_refused_ref_refuses_the_whole_push(clone: Clone) -> None:
    result = clone.push("v1.0.0", "main")

    assert result.returncode != 0
    assert PROTECTED_REFUSAL in _output(result)
    assert clone.remote_refs() == set()


@pytest.mark.parametrize("branch", ["Bad_Name", "rc-v3.4.0", "feature/no-type-prefix"])
def test_remote_branch_name_outside_the_convention_is_refused(
    clone: Clone, branch: str
) -> None:
    clone.git("switch", "--quiet", "-c", "feat/valid-local-name")

    result = clone.push(f"HEAD:refs/heads/{branch}")

    assert result.returncode != 0
    assert _name_refusal(branch) in _output(result)
    assert f"refs/heads/{branch}" not in clone.remote_refs()


def test_name_check_reads_the_remote_name_not_the_local_one(clone: Clone) -> None:
    clone.git("switch", "--quiet", "-c", "Local_Only_Name")

    result = clone.push("HEAD:refs/heads/fix/valid-remote-name")

    assert result.returncode == 0, _output(result)
    assert "refs/heads/fix/valid-remote-name" in clone.remote_refs()


def test_deleting_a_branch_skips_the_name_check(clone: Clone) -> None:
    clone.git(
        "push", "--quiet", "--no-verify", "origin", "HEAD:refs/heads/legacy_branch"
    )

    result = clone.push("--delete", "legacy_branch")

    assert result.returncode == 0, _output(result)
    assert "refs/heads/legacy_branch" not in clone.remote_refs()


def test_deleting_main_from_a_feature_branch_is_refused(clone: Clone) -> None:
    clone.git("push", "--quiet", "--no-verify", "origin", "main")
    clone.git("switch", "--quiet", "-c", "chore/cleanup")

    result = clone.push("--delete", "main")

    assert result.returncode != 0
    assert PROTECTED_REFUSAL in _output(result)
    assert "refs/heads/main" in clone.remote_refs()
