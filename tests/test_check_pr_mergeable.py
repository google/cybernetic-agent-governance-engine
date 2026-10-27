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

"""``scripts/check_pr_mergeable.sh``, the pre-merge check for POAM-2026-115.

GitHub enforces the required checks on ``main`` (ruleset 25966171, no bypass
actor); this script double-checks them on the exact head SHA and records the
result on the PR. These tests pin its fail-closed behaviour: a missing,
pending, shadowed or unreadable check must never come back as mergeable.

A stub ``gh`` on ``PATH`` serves canned API responses and records each call.
``--jq`` filters go through the real ``jq``, so the script's own filters run
against GitHub-shaped JSON. Nothing touches the network.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

JQ = shutil.which("jq")
BASH = shutil.which("bash")

pytestmark = [
    pytest.mark.unit,
    pytest.mark.local,
    pytest.mark.skipif(JQ is None or BASH is None, reason="needs bash and jq on PATH"),
]

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_pr_mergeable.sh"
REPO = "acme/widgets"
SHA = "0123456789abcdef0123456789abcdef01234567"
BASE = "main"
ACTIONS_APP = 15368
OPA = (
    "OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)"
)

# The required checks of ruleset 19769096 on this repository's main (2026-10-27).
LIVE_REQUIRED: tuple[tuple[str, int | None], ...] = (
    ("Lint", None),
    ("AI 600-1 Unit Tests", None),
    (OPA, None),
    ("Secret Scanning (Gitleaks)", None),
    ("license-check", None),
    ("Pytest Logic Tests", ACTIONS_APP),
)

RULES_KEY = f"api repos/{REPO}/rules/branches/{BASE}"
BRANCH_KEY = f"api repos/{REPO}/branches/{BASE}"
RUNS_KEY = f"api repos/{REPO}/commits/{SHA}/check-runs"
STATUS_KEY = f"api repos/{REPO}/commits/{SHA}/status"

STUB = """\
import json, os, subprocess, sys


def main(argv):
    with open(os.environ["GH_STUB_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(argv) + "\\n")
    with open(os.environ["GH_STUB_FIXTURE"], encoding="utf-8") as fh:
        fixture = json.load(fh)
    jq = None
    if "--jq" in argv:
        i = argv.index("--jq")
        jq = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if argv[:1] == ["api"]:
        endpoint = [a for a in argv[1:] if not a.startswith("--")][0]
        key = "api " + endpoint.split("?", 1)[0]
    elif argv[:2] in (["pr", "view"], ["pr", "comment"], ["repo", "view"]):
        key = " ".join(argv[:2])
    else:
        sys.stderr.write("stub gh: unexpected call %r\\n" % (argv,))
        return 99
    entry = fixture.get(key, {"_fail": 404})
    if isinstance(entry, dict) and "_fail" in entry:
        sys.stderr.write("HTTP %s (stub gh)\\n" % entry["_fail"])
        return 1
    if key == "pr comment":
        body = argv[argv.index("--body-file") + 1]
        with open(body, "rb") as src, open(os.environ["GH_STUB_COMMENT"], "wb") as dst:
            dst.write(src.read())
        return 0
    pages = entry["_pages"] if isinstance(entry, dict) and "_pages" in entry else [entry]
    for page in pages:
        data = json.dumps(page).encode()
        if jq is None:
            sys.stdout.buffer.write(data + b"\\n")
            continue
        out = subprocess.run(
            [os.environ["GH_STUB_JQ"], "-r", jq], input=data, capture_output=True
        )
        if out.returncode:
            sys.stderr.buffer.write(out.stderr)
            return 1
        sys.stdout.buffer.write(out.stdout)
    return 0


sys.exit(main(sys.argv[1:]))
"""


class Gh:
    """Runs the script against a stub ``gh`` that serves a fixture."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        stub = tmp_path / "gh_stub.py"
        stub.write_text(STUB, encoding="utf-8")
        wrapper = bin_dir / "gh"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{stub}" "$@"\n', encoding="utf-8"
        )
        wrapper.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GH_")}
        self.env.update(
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            GH_STUB_FIXTURE=str(tmp_path / "fixture.json"),
            GH_STUB_LOG=str(tmp_path / "calls.jsonl"),
            GH_STUB_COMMENT=str(tmp_path / "comment.md"),
            GH_STUB_JQ=str(JQ),
        )

    def run(self, fixture: dict, *args: str) -> subprocess.CompletedProcess[str]:
        (self.tmp / "fixture.json").write_text(json.dumps(fixture), encoding="utf-8")
        return subprocess.run(
            [str(BASH), str(SCRIPT), *args],
            env=self.env,
            capture_output=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        log = self.tmp / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text("utf-8").splitlines()]

    def comment(self) -> str:
        return (self.tmp / "comment.md").read_text("utf-8")


@pytest.fixture
def gh(tmp_path: Path) -> Gh:
    return Gh(tmp_path)


def check_run(
    run_id: int,
    name: str,
    conclusion: str = "success",
    *,
    status: str = "completed",
    suite: int = 1,
    app: int = ACTIONS_APP,
) -> dict:
    done = status == "completed"
    return {
        "id": run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion if done else None,
        "started_at": None if status == "queued" else "2026-10-27T12:00:00Z",
        "check_suite": {"id": suite},
        "app": {"id": app},
    }


def commit_status(context: str, state: str = "success") -> dict:
    return {"context": context, "state": state}


def green_runs() -> list[dict]:
    """Every live required check green; ``license-check`` reports twice."""
    return [
        check_run(101, "Lint"),
        check_run(102, "AI 600-1 Unit Tests"),
        check_run(103, OPA, suite=2),
        check_run(104, "Secret Scanning (Gitleaks)", suite=3),
        check_run(105, "license-check"),
        check_run(106, "license-check", suite=4),
        check_run(107, "Pytest Logic Tests"),
        check_run(108, "zizmor-scan", "skipped", suite=5),  # not required
    ]


def without(runs: list[dict], name: str) -> list[dict]:
    return [run for run in runs if run["name"] != name]


def fixture(
    *,
    required: tuple[tuple[str, int | None], ...] = LIVE_REQUIRED,
    runs: list[dict] | None = None,
    statuses: tuple[dict, ...] = (),
    review: str = "REVIEW_REQUIRED",
    state: str = "OPEN",
    classic: dict | None = None,
) -> dict:
    """GitHub's answers for PR #12, shaped like the REST responses."""
    runs = green_runs() if runs is None else runs
    rules: list[dict] = [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}
    ]
    if required:
        checks = [
            {"context": c} if app is None else {"context": c, "integration_id": app}
            for c, app in required
        ]
        rules.append(
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": checks,
                },
            }
        )
    protection = classic or {
        "enabled": False,
        "required_status_checks": {
            "enforcement_level": "off",
            "contexts": [],
            "checks": [],
        },
    }
    return {
        "pr view": {
            "headRefOid": SHA,
            "baseRefName": BASE,
            "state": state,
            "reviewDecision": review,
        },
        RULES_KEY: rules,
        BRANCH_KEY: {"name": BASE, "protected": True, "protection": protection},
        RUNS_KEY: {"total_count": len(runs), "check_runs": runs},
        STATUS_KEY: {"state": "success", "statuses": list(statuses)},
        "pr comment": {},
    }


def test_all_required_checks_green_exits_0(gh: Gh) -> None:
    result = gh.run(fixture(), "12", "--repo", REPO)
    assert result.returncode == 0, result.stderr
    assert "every required check passed on this exact SHA" in result.stdout
    assert "6 required check(s)" in result.stdout
    assert "| `license-check` | any | 2 | success |" in result.stdout
    assert f"--squash --admin --match-head-commit {SHA}" in result.stdout


def test_check_runs_are_fetched_unfiltered(gh: Gh) -> None:
    # GitHub's default filter could hide a queued re-run behind a finished run.
    gh.run(fixture(), "12", "--repo", REPO)
    assert any("check-runs?filter=all" in arg for call in gh.calls() for arg in call)


def test_approved_pr_merges_without_admin(gh: Gh) -> None:
    result = gh.run(fixture(review="APPROVED"), "12", "--repo", REPO)
    assert result.returncode == 0, result.stderr
    assert f"gh pr merge 12 --repo {REPO} --squash --match-head-commit {SHA}" in (
        result.stdout
    )
    assert "--admin" not in result.stdout


def test_missing_required_check_exits_1(gh: Gh) -> None:
    result = gh.run(fixture(runs=without(green_runs(), "Lint")), "12", "--repo", REPO)
    assert result.returncode == 1
    assert "| `Lint` | any | 0 | **NOT FOUND** |" in result.stdout
    assert "NOT MERGEABLE" in result.stdout
    assert "gh pr merge" not in result.stdout


@pytest.mark.parametrize("status", ["queued", "in_progress"])
def test_unfinished_required_check_exits_1(gh: Gh, status: str) -> None:
    runs = [*without(green_runs(), "Lint"), check_run(101, "Lint", status=status)]
    result = gh.run(fixture(runs=runs), "12", "--repo", REPO)
    assert result.returncode == 1
    assert f"**check-run 101: {status}**" in result.stdout


@pytest.mark.parametrize(
    "conclusion",
    [
        "failure",
        "cancelled",
        "timed_out",
        "action_required",
        "stale",
        "neutral",
        "skipped",
    ],
)
def test_only_success_passes(gh: Gh, conclusion: str) -> None:
    runs = [*without(green_runs(), "Lint"), check_run(101, "Lint", conclusion)]
    result = gh.run(fixture(runs=runs), "12", "--repo", REPO)
    assert result.returncode == 1
    assert f"**check-run 101: {conclusion}**" in result.stdout


def test_queued_rerun_supersedes_an_earlier_success(gh: Gh) -> None:
    # The re-run has no started_at yet; ordering by id still makes it the newest.
    runs = [*green_runs(), check_run(201, "Lint", status="queued")]
    result = gh.run(fixture(runs=runs), "12", "--repo", REPO)
    assert result.returncode == 1
    assert "**check-run 201: queued**" in result.stdout


def test_successful_rerun_supersedes_an_earlier_failure(gh: Gh) -> None:
    runs = [
        *without(green_runs(), "Lint"),
        check_run(101, "Lint", "failure"),
        check_run(201, "Lint"),
    ]
    assert gh.run(fixture(runs=runs), "12", "--repo", REPO).returncode == 0


def test_same_name_in_another_suite_cannot_hide_a_failure(gh: Gh) -> None:
    runs = [
        *without(green_runs(), "license-check"),
        check_run(106, "license-check", "failure", suite=4),
        check_run(301, "license-check", suite=1),  # newer, another workflow, green
    ]
    result = gh.run(fixture(runs=runs), "12", "--repo", REPO)
    assert result.returncode == 1
    assert "**check-run 106: failure**" in result.stdout


@pytest.mark.parametrize(
    ("state", "code"), [("success", 0), ("failure", 1), ("error", 1), ("pending", 1)]
)
def test_required_commit_status_is_verified(gh: Gh, state: str, code: int) -> None:
    f = fixture(
        required=(*LIVE_REQUIRED, ("ci/legacy", None)),
        statuses=(commit_status("ci/legacy", state),),
    )
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == code
    assert "| `ci/legacy` | any | 1 |" in result.stdout


def test_check_run_and_status_with_one_name_must_both_pass(gh: Gh) -> None:
    result = gh.run(
        fixture(statuses=(commit_status("Lint", "failure"),)), "12", "--repo", REPO
    )
    assert result.returncode == 1
    assert "| `Lint` | any | 2 | **status: failure** |" in result.stdout


def test_app_pinned_check_counts_only_that_app(gh: Gh) -> None:
    runs = [
        *without(green_runs(), "Pytest Logic Tests"),
        check_run(107, "Pytest Logic Tests", app=999),
    ]
    f = fixture(runs=runs, statuses=(commit_status("Pytest Logic Tests"),))
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == 1
    assert "| `Pytest Logic Tests` | app 15368 | 0 | **NOT FOUND** |" in result.stdout


def test_no_required_checks_exits_2(gh: Gh) -> None:
    result = gh.run(fixture(required=()), "12", "--repo", REPO)
    assert result.returncode == 2
    assert "no required status checks apply to 'main'" in result.stderr
    assert "every required check passed" not in result.stdout


def test_classic_branch_protection_checks_are_required(gh: Gh) -> None:
    classic = {
        "enabled": True,
        "required_status_checks": {
            "enforcement_level": "everyone",
            "contexts": ["legacy-ci"],
            "checks": [{"context": "legacy-ci", "app_id": None}],
        },
    }
    missing = gh.run(fixture(required=(), classic=classic), "12", "--repo", REPO)
    assert missing.returncode == 1
    assert "| `legacy-ci` | any | 0 | **NOT FOUND** |" in missing.stdout
    runs = [*green_runs(), check_run(401, "legacy-ci", suite=6, app=777)]
    present = gh.run(
        fixture(required=(), classic=classic, runs=runs), "12", "--repo", REPO
    )
    assert present.returncode == 0, present.stdout


def test_every_page_is_read(gh: Gh) -> None:
    f = fixture()
    runs = f[RUNS_KEY]["check_runs"]
    f[RUNS_KEY] = {
        "_pages": [
            {"total_count": len(runs), "check_runs": runs[:4]},
            {"total_count": len(runs), "check_runs": runs[4:]},
        ]
    }
    f[RULES_KEY] = {"_pages": [f[RULES_KEY][:1], f[RULES_KEY][1:]]}
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == 0, result.stdout
    assert "6 required check(s), verified against 8 check-run(s)" in result.stdout


@pytest.mark.parametrize(
    "key", ["pr view", RULES_KEY, BRANCH_KEY, RUNS_KEY, STATUS_KEY]
)
def test_any_api_failure_exits_2(gh: Gh, key: str) -> None:
    f = fixture()
    f[key] = {"_fail": 502}
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == 2
    assert "do not merge" in result.stderr
    assert "every required check passed" not in result.stdout


def test_rules_failure_is_not_masked_by_classic_protection(gh: Gh) -> None:
    # Classic protection alone would still yield a non-empty, all-green list.
    classic = {
        "enabled": True,
        "required_status_checks": {
            "enforcement_level": "everyone",
            "contexts": ["legacy-ci"],
            "checks": [],
        },
    }
    runs = [*green_runs(), check_run(401, "legacy-ci", suite=6)]
    f = fixture(classic=classic, runs=runs)
    f[RULES_KEY] = {"_fail": 502}
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == 2
    assert "could not read the rules for 'main'" in result.stderr


def test_comment_posts_the_report(gh: Gh) -> None:
    result = gh.run(fixture(), "12", "--repo", REPO, "--comment")
    assert result.returncode == 0, result.stderr
    posted = gh.comment()
    assert posted.startswith("## Pre-merge required-check verification")
    assert f"`{SHA}`" in posted
    assert "every required check passed on this exact SHA" in posted
    assert "Result posted to PR #12." in result.stdout


def test_failed_comment_fails_the_run(gh: Gh) -> None:
    f = fixture()
    f["pr comment"] = {"_fail": 502}
    result = gh.run(f, "12", "--repo", REPO, "--comment")
    assert result.returncode == 2
    assert "pre-merge record is missing" in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--repo"],
        ["abc"],
        ["0"],
        ["12", "13"],
        ["--bogus", "12"],
        ["12", "--repo", "not-a-repo"],
    ],
)
def test_usage_errors_exit_2_before_any_api_call(gh: Gh, args: list[str]) -> None:
    result = gh.run(fixture(), *args)
    assert result.returncode == 2
    assert gh.calls() == []


def test_unsupported_base_branch_name_exits_2(gh: Gh) -> None:
    f = fixture()
    f["pr view"]["baseRefName"] = "main;id"
    result = gh.run(f, "12", "--repo", REPO)
    assert result.returncode == 2
    assert "unsupported base branch name" in result.stderr


def test_repository_defaults_to_the_checkout(gh: Gh) -> None:
    f = fixture()
    f["repo view"] = {"nameWithOwner": REPO}
    assert gh.run(f, "12").returncode == 0


def test_merged_pr_is_verified_without_a_merge_command(gh: Gh) -> None:
    result = gh.run(fixture(state="MERGED"), "12", "--repo", REPO)
    assert result.returncode == 0
    assert "PR #12 is MERGED: nothing to merge." in result.stdout
    assert "gh pr merge" not in result.stdout


def test_help_prints_the_header_not_the_license(gh: Gh) -> None:
    result = gh.run(fixture(), "--help")
    assert result.returncode == 0
    assert result.stdout.startswith(
        "check_pr_mergeable.sh — verify every required status check"
    )
    assert "Exit codes" in result.stdout
    assert "Licensed under" not in result.stdout
    assert "set -euo pipefail" not in result.stdout
