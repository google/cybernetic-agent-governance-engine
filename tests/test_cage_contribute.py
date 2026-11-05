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

"""Unit tests for CAGE Contributor Automation CLI (`scripts/cage_contribute.py`).

Covers all subcommands, validation rules, error conditions, and architectural gates:
- setup: hook installation, template config, .env initialization
- branch: naming rules, length restrictions, protected branch refusal
- validate-commit: Conventional Commits v1.0.0, imperative mood, breaking changes
- commit: safe git invocation, pre-commit validation
- check: gate execution sequencing, --fast vs --all, error handling
- cloudbuild: immutable SHA tagging, dedicated SA, substitutions
- verify-service-sync: catalogue consistency across scripts and Terraform
- scaffold: ADR-009 Phase 1 (ReadOnlyTier) vs Phase 2 (MutatingTier), Layer 3 seams
- pr: branch readiness, clean tree, squash-merge guard, title validation
- release-tag: semver tag format, CHANGELOG verification
- doctor: toolchain diagnostics
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Marker contract enforcement (AGENTS.md)
pytestmark = [pytest.mark.unit, pytest.mark.local]

# Add scripts directory or working folder to sys.path
TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_DIR.parents[2] if "teamwork" in str(TEST_DIR) else TEST_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

# Import module under test
try:
    import cage_contribute
except ImportError:
    import proposed_cage_contribute as cage_contribute

sys.modules["cage_contribute"] = cage_contribute


# ===========================================================================
# 1. Platform & Git Utility Tests
# ===========================================================================


def test_get_git_executable_finds_git() -> None:
    """Verify get_git_executable returns a valid git binary."""
    git_bin = cage_contribute.get_git_executable()
    assert git_bin
    assert isinstance(git_bin, str)


def test_get_git_executable_windows_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Windows fallback candidate paths when shutil.which returns None."""
    monkeypatch.setattr(cage_contribute.sys, "platform", "win32")
    monkeypatch.setattr(cage_contribute.shutil, "which", lambda _: None)

    with (
        patch.object(Path, "is_file", return_value=True),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["git", "--version"], returncode=0, stdout="git version 2.56.0"
        )
        resolved = cage_contribute.get_git_executable()
        assert "git" in resolved.lower()


def test_run_cmd_zero_shell_and_process_scoped_env() -> None:
    """Verify run_cmd executes without shell=True and preserves process-scoped env."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["git", "status"], returncode=0, stdout="clean"
        )
        custom_env = {"CAGE_TEST_KEY": "12345"}
        res = cage_contribute.run_cmd(["git", "status"], env=custom_env)

        assert res.returncode == 0
        assert mock_run.call_count == 1
        call_kwargs = mock_run.call_args[1]
        assert "shell" not in call_kwargs or call_kwargs["shell"] is False
        assert call_kwargs["env"]["CAGE_TEST_KEY"] == "12345"


def test_find_repo_root(tmp_path: Path) -> None:
    """Verify find_repo_root discovers repository root upwards."""
    repo = tmp_path / "cage_repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    nested = repo / "src" / "gateway" / "deep"
    nested.mkdir(parents=True)

    found = cage_contribute.find_repo_root(nested)
    assert found == repo


# ===========================================================================
# 2. Branch Naming Validation Tests
# ===========================================================================


@pytest.mark.parametrize(
    "branch",
    [
        "feat/redis-rate-limiter",
        "fix/oscal-uuid-collision",
        "docs/stpa-control-diagram",
        "refactor/gateway-middleware",
        "ci/pin-actions-sha",
        "test/cbf-chaos-suite",
        "chore/update-deps",
        "spike/cbf-formal-proof",
        "hotfix/2.0.1-redis-timeout",
        "hotfix/v3.2.0-patch",
    ],
)
def test_validate_branch_name_valid(branch: str) -> None:
    """Verify compliant branch names pass validation."""
    valid, reason = cage_contribute.validate_branch_name(branch)
    assert valid is True
    assert reason == ""


@pytest.mark.parametrize(
    ("branch", "expected_err_part"),
    [
        ("Feat/redis-rate-limiter", "Invalid type prefix"),
        ("feat/RedisRateLimiter", "lowercase kebab-case"),
        ("feat/redis_rate_limiter", "lowercase kebab-case"),
        ("feature/new-feature", "Invalid type prefix"),
        ("bugfix/uuid-bug", "Invalid type prefix"),
        (
            "feat/this-description-is-way-too-long-exceeding-thirty-chars",
            "maximum allowed is 30 chars",
        ),
        ("feat/", "Does not match pattern"),
        ("invalid-branch-name", "Missing required '<type>/' prefix"),
    ],
)
def test_validate_branch_name_invalid(branch: str, expected_err_part: str) -> None:
    """Verify invalid branch names fail with informative diagnostic reasons."""
    valid, reason = cage_contribute.validate_branch_name(branch)
    assert valid is False
    assert expected_err_part.lower() in reason.lower()


def test_validate_branch_name_protected_refusal() -> None:
    """Verify working on main or rc-v* branches is explicitly refused per AGENTS.md."""
    valid, reason = cage_contribute.validate_branch_name("main")
    assert valid is False
    assert "Direct work on protected branch 'main' is not allowed" in reason

    valid_rc, reason_rc = cage_contribute.validate_branch_name("rc-v3.2.0")
    assert valid_rc is False
    assert "protected release prefix" in reason_rc


# ===========================================================================
# 3. Conventional Commits v1.0.0 Validation Tests
# ===========================================================================


def test_validate_commit_message_valid_standard() -> None:
    """Verify standard Conventional Commit format passes."""
    msg = "feat(gateway): add Redis-backed rate limiter for OPA policy calls"
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is True
    assert not errors


def test_validate_commit_message_valid_without_scope() -> None:
    """Verify type without scope is permitted."""
    msg = "docs: update STPA control diagram and verification gates"
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is True
    assert not errors


def test_validate_commit_message_valid_breaking_change() -> None:
    """Verify bidirectional breaking change format (bang + BREAKING CHANGE footer)."""
    msg = (
        "chore(ci)!: pin actions/checkout to SHA for supply-chain hardening\n\n"
        "BREAKING CHANGE: Workflow callers must update their local cache."
    )
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is True
    assert not errors


def test_validate_commit_message_merge_and_empty_exemption() -> None:
    """Verify git merge commits and comment-only messages are exempt."""
    assert (
        cage_contribute.validate_commit_message("Merge branch 'feat/foo' into main")[0]
        is True
    )
    assert cage_contribute.validate_commit_message("# Just a comment line")[0] is True
    assert cage_contribute.validate_commit_message("")[0] is True


def test_validate_commit_message_invalid_type() -> None:
    """Verify unapproved commit type fails."""
    msg = "update(gateway): add new feature"
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is False
    assert any("Invalid commit type" in e for e in errors)


def test_validate_commit_message_invalid_scope() -> None:
    """Verify unapproved scope fails."""
    msg = "feat(unsupported_scope): add new feature"
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is False
    assert any("Invalid commit scope" in e for e in errors)


def test_validate_commit_message_subject_length_limit() -> None:
    """Verify subject lines exceeding 72 characters fail."""
    long_msg = "feat(gateway): " + "a" * 60
    assert len(long_msg) > 72
    valid, errors = cage_contribute.validate_commit_message(long_msg)
    assert valid is False
    assert any("exceeds 72 characters" in e for e in errors)


def test_validate_commit_message_trailing_period() -> None:
    """Verify trailing period in subject line fails."""
    msg = "feat(gateway): add Redis-backed rate limiter."
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is False
    assert any("trailing period" in e for e in errors)


def test_validate_commit_message_non_imperative_mood() -> None:
    """Verify non-imperative verbs (past tense, third person, and continuous gerunds) are rejected."""
    for verb in [
        "added",
        "adds",
        "adding",
        "fixed",
        "fixes",
        "fixing",
        "updated",
        "updating",
        "cleaning",
        "refactored",
        "refactoring",
    ]:
        msg = f"feat(gateway): {verb} rate limiter"
        valid, errors = cage_contribute.validate_commit_message(msg)
        assert valid is False
        assert any("non-imperative verb" in e for e in errors)


def test_validate_commit_message_leading_newline_handling() -> None:
    """Verify leading newlines do not bypass validation for invalid subjects."""
    # 1. Invalid message with leading newline must be rejected (not bypassed)
    invalid_msg = "\nThis is completely invalid message with trailing period."
    valid, errors = cage_contribute.validate_commit_message(invalid_msg)
    assert valid is False
    assert len(errors) > 0

    # 2. Comments + leading newlines before invalid subject must be rejected
    invalid_comment_msg = "# comment\n\nThis is invalid."
    valid2, _errors2 = cage_contribute.validate_commit_message(invalid_comment_msg)
    assert valid2 is False

    # 3. Valid Conventional Commit with leading newlines should succeed
    valid_msg = "\n\nfeat(gateway): add test\n\nValid body."
    valid3, errors3 = cage_contribute.validate_commit_message(valid_msg)
    assert valid3 is True
    assert errors3 == []


def test_validate_commit_message_missing_blank_line() -> None:
    """Verify missing blank line between subject and body fails."""
    msg = (
        "feat(gateway): add Redis rate limiter\nThis body has no separating blank line."
    )
    valid, errors = cage_contribute.validate_commit_message(msg)
    assert valid is False
    assert any("blank line must separate" in e for e in errors)


def test_validate_commit_message_breaking_change_bidirectional_violations() -> None:
    """Verify breaking change rules require both '!' and 'BREAKING CHANGE:' footer."""
    # 1. Bang present, but missing footer
    msg_no_footer = (
        "feat(gateway)!: update rate limiter API\n\nSome body without footer."
    )
    valid1, errors1 = cage_contribute.validate_commit_message(msg_no_footer)
    assert valid1 is False
    assert any("BREAKING CHANGE:" in e for e in errors1)

    # 2. Footer present, but missing bang
    msg_no_bang = "feat(gateway): update rate limiter API\n\nBREAKING CHANGE: Token is now required."
    valid2, errors2 = cage_contribute.validate_commit_message(msg_no_bang)
    assert valid2 is False
    assert any("lacks the required '!'" in e for e in errors2)


# ===========================================================================
# 4. Setup Subcommand Tests
# ===========================================================================


def test_cmd_setup_creates_hooks_and_env(tmp_path: Path) -> None:
    """Verify 'setup' creates commit template, hooks, and initializes .env."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / ".env.example").write_text("TEST_VAR=123\n", encoding="utf-8")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        args = argparse.Namespace(sync=False)
        rc = cage_contribute.cmd_setup(args)

        assert rc == 0
        assert (repo / ".gitmessage").exists()
        assert (repo / ".git" / "hooks" / "commit-msg").exists()
        assert (repo / ".git" / "hooks" / "pre-push").exists()
        assert (repo / ".env").exists()
        assert (repo / ".env").read_text(encoding="utf-8") == "TEST_VAR=123\n"


def test_cmd_setup_preserves_existing_env(tmp_path: Path) -> None:
    """Verify 'setup' never overwrites an existing .env file."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / ".env.example").write_text("ORIGINAL=1\n", encoding="utf-8")
    (repo / ".env").write_text("PRESERVED=2\n", encoding="utf-8")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd"),
    ):
        args = argparse.Namespace(sync=False)
        cage_contribute.cmd_setup(args)
        assert (repo / ".env").read_text(encoding="utf-8") == "PRESERVED=2\n"


def test_cmd_setup_git_worktree_support(tmp_path: Path) -> None:
    """Verify setup handles git worktrees where .git is a file instead of a directory."""
    repo = tmp_path / "worktree_repo"
    repo.mkdir()
    main_git_dir = tmp_path / "main_repo" / ".git"
    main_git_dir.mkdir(parents=True)
    hooks_target = main_git_dir / "hooks"
    hooks_target.mkdir()

    # In a git worktree, .git is a file pointing to gitdir: <path>
    (repo / ".git").write_text(f"gitdir: {main_git_dir}\n", encoding="utf-8")
    (repo / ".env.example").write_text("TEST=1\n", encoding="utf-8")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        # Mock git rev-parse --git-path hooks returning the target hooks directory
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=str(hooks_target) + "\n"
        )
        args = argparse.Namespace(sync=False)
        rc = cage_contribute.cmd_setup(args)
        assert rc == 0
        assert (hooks_target / "commit-msg").exists()
        assert (hooks_target / "pre-push").exists()


def test_cmd_setup_git_worktree_fallback(tmp_path: Path) -> None:
    """Verify setup resolves hooks from .git gitdir file when git rev-parse fails."""
    repo = tmp_path / "worktree_repo_fb"
    repo.mkdir()
    common_git_dir = tmp_path / "common_repo" / ".git"
    common_git_dir.mkdir(parents=True)
    (common_git_dir / "hooks").mkdir()
    worktree_git_dir = common_git_dir / "worktrees" / "branch_wt"
    worktree_git_dir.mkdir(parents=True)

    (repo / ".git").write_text(f"gitdir: {worktree_git_dir}\n", encoding="utf-8")
    (repo / ".env.example").write_text("TEST=1\n", encoding="utf-8")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=""
        )
        args = argparse.Namespace(sync=False)
        rc = cage_contribute.cmd_setup(args)
        assert rc == 0
        assert (common_git_dir / "hooks" / "commit-msg").exists()


# ===========================================================================
# 5. Branch Subcommand Tests
# ===========================================================================


def test_cmd_branch_success(tmp_path: Path) -> None:
    """Verify 'branch' checks out a valid branch."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        args = argparse.Namespace(
            type="feat", description="redis-rate-limiter", base="main"
        )
        rc = cage_contribute.cmd_branch(args)

        assert rc == 0
        assert mock_run.call_count == 1
        call_args = mock_run.call_args[0][0]
        assert "checkout" in call_args
        assert "-b" in call_args
        assert "feat/redis-rate-limiter" in call_args


def test_cmd_branch_invalid_fails() -> None:
    """Verify 'branch' rejects invalid branch names with exit code 1."""
    args = argparse.Namespace(type="invalid_type", description="bad-name", base="main")
    rc = cage_contribute.cmd_branch(args)
    assert rc == 1


# ===========================================================================
# 6. Validate-Commit & Commit Subcommand Tests
# ===========================================================================


def test_cmd_validate_commit_cli_args() -> None:
    """Verify validate-commit handles direct string and file arguments."""
    args_valid = argparse.Namespace(
        message="feat(gateway): add Redis limiter",
        file=None,
        commit_msg_file=None,
        quiet=True,
    )
    assert cage_contribute.cmd_validate_commit(args_valid) == 0

    args_invalid = argparse.Namespace(
        message="bad commit",
        file=None,
        commit_msg_file=None,
        quiet=True,
    )
    assert cage_contribute.cmd_validate_commit(args_invalid) == 1


def test_cmd_commit_invokes_git(tmp_path: Path) -> None:
    """Verify commit validates message and invokes git commit safely."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        args = argparse.Namespace(
            message="feat(gateway): add Redis rate limiter",
            all=False,
            allow_empty=False,
            no_verify=False,
        )
        rc = cage_contribute.cmd_commit(args)
        assert rc == 0
        call_args = mock_run.call_args[0][0]
        assert "commit" in call_args
        assert "-m" in call_args


# ===========================================================================
# 7. Check Subcommand Tests
# ===========================================================================


def test_cmd_check_fast_mode(tmp_path: Path) -> None:
    """Verify check --fast executes architectural static checks."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scripts_dir = repo / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "patch_license.py").touch()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        args = argparse.Namespace(
            fast=True, all=False, raptor=False, security_audit=False
        )
        rc = cage_contribute.cmd_check(args)
        assert rc == 0


def test_cmd_check_failure_returns_one(tmp_path: Path) -> None:
    """Verify check returns 1 when a required gate fails."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scripts_dir = repo / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "patch_license.py").touch()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr="Import boundary violation detected"
        )
        args = argparse.Namespace(
            fast=True, all=False, raptor=False, security_audit=False
        )
        rc = cage_contribute.cmd_check(args)
        assert rc == 1


# ===========================================================================
# 8. CloudBuild & Verify-Service-Sync Subcommand Tests
# ===========================================================================


def test_cmd_cloudbuild_dry_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify cloudbuild --dry-run prints exact gcloud command with short SHA."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.get_short_sha", return_value="1a2b3c4d"),
    ):
        args = argparse.Namespace(
            image="gateway",
            dockerfile=None,
            env="staging",
            project="test-project",
            dry_run=True,
        )
        rc = cage_contribute.cmd_cloudbuild(args)
        assert rc == 0

        captured = capsys.readouterr().out
        assert "gcloud builds submit" in captured
        assert "_SHORT_SHA=1a2b3c4d" in captured
        assert "_IMAGE_NAME=gateway" in captured
        assert (
            "cage-cloudbuild-staging@test-project.iam.gserviceaccount.com" in captured
        )


def test_cmd_verify_service_sync_agreed(tmp_path: Path) -> None:
    """Verify verify-service-sync succeeds when catalogue files agree."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scripts_dir = repo / "scripts"
    scripts_dir.mkdir()
    infra_dir = repo / "infra" / "targets" / "gcp-gke"
    infra_dir.mkdir(parents=True)
    fixtures_dir = infra_dir / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True)

    # 1. build_images.sh
    (scripts_dir / "build_images.sh").write_text(
        'FIRST_PARTY_IMAGES=("gateway|src/Dockerfile" "ui|src/ui/Dockerfile")\nALL_IMAGES="gateway ui"\n',
        encoding="utf-8",
    )
    # 2. render_image_digests.sh
    (scripts_dir / "render_image_digests.sh").write_text(
        'FIRST_PARTY_IMAGES=("gateway" "ui")\nTHIRD_PARTY_TAGGED_IMAGES=("redis")\n',
        encoding="utf-8",
    )
    # 3. main.tf
    (infra_dir / "main.tf").write_text(
        'required_image_digests = concat(\n  ["gateway", "ui", "redis"]\n  )\n',
        encoding="utf-8",
    )
    # 4. image_digests.tfvars
    (fixtures_dir / "image_digests.tfvars").write_text(
        '"gateway" = "test"\n"ui" = "test"\n"redis" = "test"\n',
        encoding="utf-8",
    )

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_verify_service_sync(args)
        assert rc == 0


def test_cmd_verify_service_sync_drift_detected(tmp_path: Path) -> None:
    """Verify verify-service-sync detects discrepancies between existing catalogue files."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scripts_dir = repo / "scripts"
    scripts_dir.mkdir()
    infra_dir = repo / "infra" / "targets" / "gcp-gke"
    infra_dir.mkdir(parents=True)
    fixtures_dir = infra_dir / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True)

    # 1. Mismatched build_images.sh (contains extra_service)
    (scripts_dir / "build_images.sh").write_text(
        'FIRST_PARTY_IMAGES=("gateway|src/Dockerfile" "ui|src/ui/Dockerfile")\nALL_IMAGES="gateway ui extra_service"\n',
        encoding="utf-8",
    )
    # 2. render_image_digests.sh
    (scripts_dir / "render_image_digests.sh").write_text(
        'FIRST_PARTY_IMAGES=("gateway" "ui")\nTHIRD_PARTY_TAGGED_IMAGES=("redis")\n',
        encoding="utf-8",
    )
    # 3. main.tf
    (infra_dir / "main.tf").write_text(
        'required_image_digests = concat(\n  ["gateway", "ui", "redis"]\n  )\n',
        encoding="utf-8",
    )
    # 4. image_digests.tfvars
    (fixtures_dir / "image_digests.tfvars").write_text(
        '"gateway" = "test"\n"ui" = "test"\n"redis" = "test"\n',
        encoding="utf-8",
    )

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_verify_service_sync(args)
        assert rc == 1


def test_cmd_verify_service_sync_missing_catalogue_files(tmp_path: Path) -> None:
    """Verify verify-service-sync fails closed with rc=1 when any catalogue file is missing."""
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=empty_repo):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_verify_service_sync(args)
        assert rc == 1


# ===========================================================================
# 9. Scaffolding Subcommand Tests
# ===========================================================================


def _load_module_from_path(module_name: str, file_path: Path):
    """Dynamically load and execute a Python module from an arbitrary path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cmd_scaffold_phase_1_read_only_tier(tmp_path: Path) -> None:
    """Verify scaffold tier generates valid ADR-009 ReadOnlyTier without mutating hooks."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="tier",
            domain="finance",
            name="margin_check",
            phase=1,
            order=20,
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        target_file = repo / "src" / "cage_finance" / "tiers" / "margin_check_tier.py"
        assert target_file.exists()
        code = target_file.read_text(encoding="utf-8")

        # Parse AST to ensure valid python code
        tree = ast.parse(code)
        assert tree is not None
        assert "ReadOnlyTier" in code
        assert "def evaluate" in code
        # ADR-009 invariant: ReadOnlyTier must NEVER define commit/rollback/confirm
        assert "def commit" not in code
        assert "def rollback" not in code
        assert "def confirm" not in code

        # Dynamically instantiate and verify interface
        mod = _load_module_from_path("margin_check_tier", target_file)
        tier_cls = mod.MarginCheckTier
        tier = tier_cls()
        assert tier.tier_name == "margin_check"
        assert tier.order == 20
        assert tier.claims_action("trade", {}) is True
        violations = asyncio.run(tier.evaluate("trade", {}))
        assert violations == []


def test_cmd_scaffold_phase_2_mutating_tier(tmp_path: Path) -> None:
    """Verify scaffold tier generates valid ADR-009 MutatingTier with all hooks."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="tier",
            domain="finance",
            name="cbf_dose",
            phase=2,
            order=30,
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        target_file = repo / "src" / "cage_finance" / "tiers" / "cbf_dose_tier.py"
        assert target_file.exists()
        code = target_file.read_text(encoding="utf-8")

        # Must define all phase 2 mutation hooks
        assert "MutatingTier" in code
        assert "def commit" in code
        assert "def rollback" in code
        assert "def confirm" in code

        # Dynamically instantiate and verify interface
        mod = _load_module_from_path("cbf_dose_tier", target_file)
        tier_cls = mod.CbfDoseTier
        tier = tier_cls()
        assert tier.tier_name == "cbf_dose"
        assert tier.order == 30
        assert tier.claims_action("trade", {}) is True
        violations = asyncio.run(tier.evaluate("trade", {}))
        assert violations == []
        commit_violations, receipt = asyncio.run(tier.commit("trade", {}))
        assert commit_violations == []
        assert receipt is not None
        assert receipt.tier == "cbf_dose"
        assert receipt.token == "cbf_dose-reservation-001"
        asyncio.run(tier.rollback("trade", {}, receipt))
        asyncio.run(tier.confirm("trade", {}, receipt))


def test_cmd_scaffold_tier_kebab_case_normalization(tmp_path: Path) -> None:
    """Verify scaffold tier normalizes kebab-case domain and name into valid Python package identifiers."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="tier",
            domain="physical-ai",
            name="trade-limit",
            phase=1,
            order=15,
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        # Domain directory must use underscores, not hyphens
        target_file = (
            repo / "src" / "cage_physical_ai" / "tiers" / "trade_limit_tier.py"
        )
        assert target_file.exists()
        code = target_file.read_text(encoding="utf-8")

        # Parse AST to ensure valid python syntax (no syntax errors)
        tree = ast.parse(code)
        assert tree is not None
        assert "class TradeLimitTier(ReadOnlyTier):" in code
        assert 'return "trade_limit"' in code

        mod = _load_module_from_path("trade_limit_tier", target_file)
        tier_cls = mod.TradeLimitTier
        tier = tier_cls()
        assert tier.tier_name == "trade_limit"
        assert tier.order == 15
        assert asyncio.run(tier.evaluate("actuate", {})) == []


def test_cmd_scaffold_seam_package(tmp_path: Path) -> None:
    """Verify scaffold seam creates Layer 3 package with Apache 2.0 headers and valid ActuatorAdapter."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="seam",
            seam_type="actuator",
            name="actuator_09",
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        pkg_dir = repo / "src" / "integrations" / "actuator_09"
        assert (pkg_dir / "__init__.py").exists()
        assert (pkg_dir / "adapter.py").exists()
        assert (pkg_dir / "README.md").exists()

        adapter_code = (pkg_dir / "adapter.py").read_text(encoding="utf-8")
        assert "Copyright 2026 Google LLC" in adapter_code
        assert "ExecutionActuator" in adapter_code

        # Dynamically instantiate and verify actuator adapter
        mod = _load_module_from_path("actuator_09_adapter", pkg_dir / "adapter.py")
        adapter_cls = mod.ActuatorAdapter
        adapter = adapter_cls()
        assert adapter.actuator_id == "actuator_09"
        assert asyncio.run(adapter.health_check()) is True

        from src.gateway.governance.seams.actuation import (
            ActuationOutcome,
            ActuatorCapability,
            ExecutionClearance,
        )

        assert ActuatorCapability.SIGNED_RECEIPTS in adapter.get_capabilities()

        clearance = ExecutionClearance(
            thread_id="th-1",
            decision="ALLOW",
            decision_path="DIRECT",
            action="test_action",
            target="test_target",
            operator_urn="urn:cage:operator:test",
            issued_at=1700000000,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id="corr-1",
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest="0" * 64,
            opa_input_digest="1" * 64,
            nonce="n" * 32,
        )
        receipt = asyncio.run(adapter.actuate(clearance))
        assert receipt.accepted is True
        assert receipt.outcome == ActuationOutcome.ACCEPTED


def test_cmd_scaffold_attestation_seam(tmp_path: Path) -> None:
    """Verify scaffold seam attestation creates adapter implementing AttestationProvider."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="seam",
            seam_type="attestation",
            name="provider_08",
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        pkg_dir = repo / "src" / "integrations" / "provider_08"
        assert (pkg_dir / "__init__.py").exists()
        assert (pkg_dir / "adapter.py").exists()
        assert (pkg_dir / "README.md").exists()

        adapter_code = (pkg_dir / "adapter.py").read_text(encoding="utf-8")
        assert "from src.gateway.governance.seams.attestation import" in adapter_code
        assert "AttestationProvider" in adapter_code
        assert "class AttestationAdapter(AttestationProvider):" in adapter_code
        assert "def provider_name(self) -> str:" in adapter_code
        assert "def fetch_attestations(" in adapter_code

        # Parse AST to ensure valid python code
        tree = ast.parse(adapter_code)
        assert tree is not None

        # Dynamically instantiate and verify attestation adapter
        mod = _load_module_from_path("provider_08_adapter", pkg_dir / "adapter.py")
        adapter_cls = mod.AttestationAdapter
        adapter = adapter_cls()
        assert adapter.provider_name == "provider_08"
        attestations = asyncio.run(adapter.fetch_attestations({"action": "check"}))
        assert attestations == []


def test_cmd_scaffold_normative_seam(tmp_path: Path) -> None:
    """Verify scaffold seam normative generates valid NormativeAdapter matching data contracts."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="seam",
            seam_type="normative",
            name="provider_07",
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        pkg_dir = repo / "src" / "integrations" / "provider_07"
        adapter_file = pkg_dir / "adapter.py"
        assert adapter_file.exists()

        # Dynamically load and instantiate NormativeAdapter
        mod = _load_module_from_path("provider_07_adapter", adapter_file)
        adapter_cls = mod.NormativeAdapter
        adapter = adapter_cls()

        # 1. fetch_baseline must accept region and return NormativeBaseline with profile dict
        baseline = asyncio.run(adapter.fetch_baseline("US_FED"))
        assert baseline.region == "US_FED"
        assert baseline.profile == {}
        assert baseline.error is None

        # 2. validate_fria must return ValidationResult with admitted: bool
        result = asyncio.run(adapter.validate_fria({"action": "check_limits"}))
        assert result.admitted is True
        assert result.findings == []

        # 3. submit_evidence must return EvidenceSeal
        seal = asyncio.run(adapter.submit_evidence("thread-001", "hash-001"))
        assert seal.thread_id == "thread-001"
        assert seal.seal_hash == "SEAL_HASH_PLACEHOLDER"


def test_cmd_scaffold_quarantine_seam(tmp_path: Path) -> None:
    """Verify scaffold seam quarantine generates valid QuarantineAdapter matching QuarantineDirective."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="seam",
            seam_type="quarantine",
            name="quarantine_01",
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        pkg_dir = repo / "src" / "integrations" / "quarantine_01"
        adapter_file = pkg_dir / "adapter.py"
        assert adapter_file.exists()

        mod = _load_module_from_path("quarantine_01_adapter", adapter_file)
        adapter_cls = mod.QuarantineAdapter
        adapter = adapter_cls()

        assert adapter.actuator_id == "quarantine_01"
        assert asyncio.run(adapter.health_check()) is True

        from src.gateway.governance.seams.quarantine import (
            QuarantineDirective,
            QuarantineTriggerReason,
        )

        # Case A: directive with violation_codes
        directive_a = QuarantineDirective(
            thread_id="t1",
            agent_svid="spiffe://cage/agent/1",
            sandbox_id="sbx-01",
            reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
            violation_codes=("CRITICAL_EXPOSURE_01",),
            issued_at=1700000000,
            correlation_id="corr-1",
            nonce="nonce-1",
            governance_decision_digest="a" * 64,
        )
        receipt_a = asyncio.run(adapter.quarantine_workload(directive_a))
        assert receipt_a.quarantined is True
        assert receipt_a.enforcement_plane == "SIMULATED"
        assert receipt_a.rule_id == "CRITICAL_EXPOSURE_01"

        # Case B: directive with empty violation_codes falls back to reason.value
        directive_b = QuarantineDirective(
            thread_id="t2",
            agent_svid="spiffe://cage/agent/2",
            sandbox_id="sbx-02",
            reason=QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT,
            violation_codes=(),
            issued_at=1700000000,
            correlation_id="corr-2",
            nonce="nonce-2",
            refusal_proof_hash="b" * 64,
        )
        receipt_b = asyncio.run(adapter.quarantine_workload(directive_b))
        assert receipt_b.quarantined is True
        assert receipt_b.enforcement_plane == "SIMULATED"
        assert receipt_b.rule_id == "SANDBOX_ESCAPE_ATTEMPT"


def test_cmd_scaffold_evidence_seam(tmp_path: Path) -> None:
    """Verify scaffold seam evidence generates valid EvidenceAdapter implementing EvidenceCollector."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        args = argparse.Namespace(
            scaffold_type="seam",
            seam_type="evidence",
            name="evidence_01",
        )
        rc = cage_contribute.cmd_scaffold(args)
        assert rc == 0

        pkg_dir = repo / "src" / "integrations" / "evidence_01"
        adapter_file = pkg_dir / "adapter.py"
        assert adapter_file.exists()

        mod = _load_module_from_path("evidence_01_adapter", adapter_file)
        adapter_cls = mod.EvidenceAdapter
        adapter = adapter_cls()

        assert adapter.collector_name == "evidence_01"

        from src.gateway.governance.seams.evidence import (
            EvidenceCollector,
            EvidenceRecord,
        )

        assert isinstance(adapter, EvidenceCollector)

        record = EvidenceRecord(
            record_id="rec-001",
            event_type="DECISION",
            payload={"action": "test", "allowed": True},
        )
        receipt = asyncio.run(adapter.collect_evidence(record))
        assert receipt.stored is True
        assert receipt.receipt_id == "EVID_001"
        assert receipt.receipt_sha256 == "EVIDENCE_SHA256_PLACEHOLDER"

        flush_receipt = asyncio.run(adapter.flush_batch("batch-99"))
        assert flush_receipt.stored is True
        assert flush_receipt.receipt_id == "BATCH_batch-99"
        assert flush_receipt.receipt_sha256 == "BATCH_SHA256_PLACEHOLDER"


def test_cmd_scaffold_all_templates_instantiate_cleanly(tmp_path: Path) -> None:
    """Parametric stress test asserting all 5 seam types and 2 tier phases instantiate cleanly."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("cage_contribute.find_repo_root", return_value=repo):
        # 1. Test both tier phases
        for phase in [1, 2]:
            args = argparse.Namespace(
                scaffold_type="tier",
                domain="healthcare",
                name=f"phase_{phase}_check",
                phase=phase,
                order=10 * phase,
            )
            assert cage_contribute.cmd_scaffold(args) == 0
            tier_path = (
                repo
                / "src"
                / "cage_healthcare"
                / "tiers"
                / f"phase_{phase}_check_tier.py"
            )
            assert tier_path.exists()
            mod = _load_module_from_path(f"phase_{phase}_tier", tier_path)
            cls_name = f"Phase{phase}CheckTier"
            tier_cls = getattr(mod, cls_name)
            tier_inst = tier_cls()
            assert tier_inst.order == 10 * phase

        # 2. Test all 5 seam types
        seam_types = ["normative", "attestation", "actuator", "quarantine", "evidence"]
        for st in seam_types:
            seam_name = f"test_{st}_adapter"
            args = argparse.Namespace(
                scaffold_type="seam",
                seam_type=st,
                name=seam_name,
            )
            assert cage_contribute.cmd_scaffold(args) == 0
            adapter_path = repo / "src" / "integrations" / seam_name / "adapter.py"
            assert adapter_path.exists()
            mod = _load_module_from_path(f"mod_{st}", adapter_path)
            # Find the adapter class
            classes = [c for c in dir(mod) if c.endswith("Adapter")]
            assert len(classes) >= 1
            adapter_cls = getattr(mod, classes[0])
            adapter_inst = adapter_cls()
            assert adapter_inst is not None


# ===========================================================================
# 10. PR & Release-Tag Subcommand Tests
# ===========================================================================


def test_cmd_pr_squash_merge_guard_violation(tmp_path: Path) -> None:
    """Verify PR command enforces squash-merge-guard against two-parent commits."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.get_current_branch", return_value="feat/my-feature"),
        patch("cage_contribute.is_working_tree_clean", return_value=True),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        # Simulate rev-list --parents returning a commit with 2 parents (merge commit)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="commit_hash parent1 parent2\n"
        )
        args = argparse.Namespace(
            base="main",
            title="feat(gateway): add feature",
            body="desc",
            allow_dirty=False,
            dry_run=True,
        )
        rc = cage_contribute.cmd_pr(args)
        assert rc == 1


def test_cmd_release_tag_validation(tmp_path: Path) -> None:
    """Verify release-tag enforces format and CHANGELOG entry."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "CHANGELOG.md").write_text("## [v3.2.0] - 2026-11-03\n", encoding="utf-8")

    # 1. Invalid tag format
    args_invalid = argparse.Namespace(tag="3.2.0")
    assert cage_contribute.cmd_release_tag(args_invalid) == 1

    # 2. Valid tag format with CHANGELOG entry
    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        args_valid = argparse.Namespace(tag="v3.2.0")
        assert cage_contribute.cmd_release_tag(args_valid) == 0


# ===========================================================================
# 11. Doctor Subcommand Tests
# ===========================================================================


def test_cmd_doctor_healthy_environment(tmp_path: Path) -> None:
    """Verify doctor command diagnoses environment cleanly and returns 0 when healthy."""
    repo = tmp_path / "repo"
    repo.mkdir()
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "commit-msg").touch()
    (hooks_dir / "pre-push").touch()

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="git version 2.40.0\n"
            )
        if "rev-parse" in cmd and "--git-path" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=".git/hooks\n"
            )
        if "rev-parse" in cmd and "--abbrev-ref" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="feat/my-feature\n"
            )
        if "status" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd", side_effect=fake_run),
    ):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_doctor(args)
        assert rc == 0


def test_cmd_doctor_resilience_missing_git(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify doctor command does not crash with FileNotFoundError when git is missing, and returns exit code 1."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.get_git_executable", return_value="nonexistent-git"),
    ):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_doctor(args)
        assert rc == 1
        captured = capsys.readouterr().out
        assert "Git Executable:   ❌ Not found" in captured


def test_cmd_doctor_fails_on_missing_hooks(tmp_path: Path) -> None:
    """Verify doctor command returns exit code 1 when CAGE git hooks are missing."""
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="git version 2.40.0\n"
            )
        if "rev-parse" in cmd and "--git-path" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=".git/hooks\n"
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("cage_contribute.run_cmd", side_effect=fake_run),
    ):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_doctor(args)
        assert rc == 1


def test_cmd_doctor_fails_on_unsupported_python(tmp_path: Path) -> None:
    """Verify doctor command returns exit code 1 when Python version is incompatible."""
    repo = tmp_path / "repo"
    repo.mkdir()
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "commit-msg").touch()
    (hooks_dir / "pre-push").touch()

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="git version 2.40.0\n"
            )
        if "rev-parse" in cmd and "--git-path" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=".git/hooks\n"
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

    with (
        patch("cage_contribute.find_repo_root", return_value=repo),
        patch("sys.version_info", (3, 8, 0)),
        patch("cage_contribute.run_cmd", side_effect=fake_run),
    ):
        args = argparse.Namespace()
        rc = cage_contribute.cmd_doctor(args)
        assert rc == 1
