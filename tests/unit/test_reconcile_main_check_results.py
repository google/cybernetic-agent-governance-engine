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

"""Unit and planted-defect tests for scripts/reconcile_main_check_results.py (POAM-2026-171)."""

from __future__ import annotations

import ast
import base64
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from scripts import check_repo_rules as repo_rules
from scripts import reconcile_main_check_results as reconciler
from scripts.reconcile_main_check_results import (
    DEFAULT_ISSUE_LABEL,
    GITHUB_HOST,
    MONITORING_HOST,
    PUBSUB_HOST,
    RECONCILER_HEARTBEAT_METRIC_TYPE,
    ReconcilerOperationalError,
    _HttpStatusError,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "reconcile_main_check_results.py"
REPO = "google/cybernetic-agent-governance-engine"
FIXED_NOW = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)
SHA_PASS = "a" * 40
SHA_FAIL = "b" * 40
SHA_GRACE = "c" * 40
SHA_FLOOR = "d" * 40
SHA_OLDER = "e" * 40


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _commit_obj(sha: str, committed_at: datetime) -> dict[str, Any]:
    return {
        "sha": sha,
        "commit": {
            "committer": {
                "date": _iso(committed_at),
            }
        },
    }


def _make_check_run(
    name: str,
    *,
    run_id: int,
    suite_id: int,
    status: str = "completed",
    conclusion: str | None = "success",
    app_id: int = repo_rules.GITHUB_ACTIONS_APP_ID,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "html_url": f"https://github.com/{REPO}/runs/{run_id}",
        "app": {"id": app_id},
        "check_suite": {"id": suite_id},
    }


def _all_passing_check_runs(*, include_ledger: bool = True) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    next_id = 1000
    suite_base = 5000
    checks, suite_counts = reconciler.expected_checks_for_run(
        require_ledger_check=include_ledger
    )
    for name, app_id in checks.items():
        for offset in range(suite_counts[name]):
            runs.append(
                _make_check_run(
                    name,
                    run_id=next_id,
                    suite_id=suite_base + offset,
                    status="completed",
                    conclusion="success",
                    app_id=app_id,
                )
            )
            next_id += 1
        suite_base += 10
    return runs


def test_script_is_pure_stdlib_with_apache_header() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "# Copyright 2026 Google LLC" in source
    assert "https://www.apache.org/licenses/LICENSE-2.0" in source

    tree = ast.parse(source, filename=str(SCRIPT_PATH))
    allowed_roots = set(sys.stdlib_module_names) | {"scripts", "check_repo_rules"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                assert root in allowed_roots, (
                    f"Third-party import forbidden: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            assert root in allowed_roots, f"Third-party import forbidden: {node.module}"


import sys  # noqa: E402


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://api.github.com/repos/o/r/commits",
        "file:///etc/passwd",
        "ftp://api.github.com/repos/o/r",
        "https://api.github.com.evil.example/repos/o/r",
        "https://user:pass@api.github.com/repos/o/r",
        "https://api.github.com:8443/repos/o/r",
        "https://evil.example/v1/projects/p/topics/t:publish",
    ],
)
def test_b310_url_validation_rejects_disallowed_schemes_and_hosts(
    bad_url: str,
) -> None:
    with pytest.raises(ReconcilerOperationalError, match="Refusing disallowed URL"):
        reconciler.validate_https_url(bad_url)


def test_b310_url_validation_enforces_expected_host_match() -> None:
    assert (
        reconciler.validate_https_url(
            "https://api.github.com/repos/o/r", expected_host=GITHUB_HOST
        )
        == "https://api.github.com/repos/o/r"
    )
    assert (
        reconciler.validate_https_url(
            "https://pubsub.googleapis.com/v1/projects/p/topics/t:publish",
            expected_host=PUBSUB_HOST,
        )
        == "https://pubsub.googleapis.com/v1/projects/p/topics/t:publish"
    )
    assert (
        reconciler.validate_https_url(
            "https://monitoring.googleapis.com/v3/projects/p/timeSeries",
            expected_host=MONITORING_HOST,
        )
        == "https://monitoring.googleapis.com/v3/projects/p/timeSeries"
    )
    with pytest.raises(
        ReconcilerOperationalError, match="does not match expected host"
    ):
        reconciler.validate_https_url(
            "https://pubsub.googleapis.com/v1/projects/p/topics/t:publish",
            expected_host=GITHUB_HOST,
        )


def test_evaluate_commit_passes_all_9_checks_and_selects_latest_rerun_per_suite() -> (
    None
):
    runs = _all_passing_check_runs()
    # Add an earlier failed attempt in the same check_suite for Pytest Logic Tests:
    # max(runs, key=lambda r: int(r["id"])) must select the newer green re-run.
    pytest_run = next(r for r in runs if r["name"] == "Pytest Logic Tests")
    runs.insert(
        0,
        _make_check_run(
            "Pytest Logic Tests",
            run_id=int(pytest_run["id"]) - 50,
            suite_id=int(pytest_run["check_suite"]["id"]),
            status="completed",
            conclusion="failure",
        ),
    )
    violations = reconciler.evaluate_commit_check_runs(
        sha=SHA_PASS,
        committed_at="2026-11-23T12:00:00Z",
        check_runs=runs,
    )
    assert violations == []


@pytest.mark.parametrize(
    "bad_conclusion",
    [
        "failure",
        "cancelled",
        "timed_out",
        "skipped",
        "neutral",
        "action_required",
        "stale",
        None,
    ],
)
def test_evaluate_commit_flags_every_non_success_conclusion(
    bad_conclusion: str | None,
) -> None:
    runs = _all_passing_check_runs()
    for r in runs:
        if r["name"] == "Lint":
            r["conclusion"] = bad_conclusion
    violations = reconciler.evaluate_commit_check_runs(
        sha=SHA_FAIL,
        committed_at="2026-11-23T12:00:00Z",
        check_runs=runs,
    )
    assert len(violations) == 1
    assert violations[0].check_name == "Lint"
    assert violations[0].reason == str(bad_conclusion)


@pytest.mark.parametrize("status", ["queued", "in_progress", "waiting", "pending"])
def test_evaluate_commit_flags_incomplete_status(status: str) -> None:
    runs = _all_passing_check_runs()
    for r in runs:
        if r["name"] == "Secret Scanning (Gitleaks)":
            r["status"] = status
            r["conclusion"] = None
    violations = reconciler.evaluate_commit_check_runs(
        sha=SHA_FAIL,
        committed_at="2026-11-23T12:00:00Z",
        check_runs=runs,
    )
    assert len(violations) == 1
    assert violations[0].check_name == "Secret Scanning (Gitleaks)"
    assert violations[0].reason == f"incomplete:{status}"


def test_evaluate_commit_flags_missing_and_missing_suite_and_ignores_wrong_app_id() -> (
    None
):
    runs = [r for r in _all_passing_check_runs() if r["name"] != "AI 600-1 Unit Tests"]
    # Add a spoofed check run from an unpinned third-party app (app.id != 15368).
    runs.append(
        _make_check_run(
            "AI 600-1 Unit Tests",
            run_id=9999,
            suite_id=9999,
            status="completed",
            conclusion="success",
            app_id=999999,
        )
    )
    # Drop one of the two required `license-check` suites (POAM-2026-172).
    license_runs = [r for r in runs if r["name"] == "license-check"]
    assert len(license_runs) == 2
    runs.remove(license_runs[1])

    violations = reconciler.evaluate_commit_check_runs(
        sha=SHA_FAIL,
        committed_at="2026-11-23T12:00:00Z",
        check_runs=runs,
    )
    by_check = {(v.check_name, v.reason): v for v in violations}
    assert ("AI 600-1 Unit Tests", "missing") in by_check
    assert ("license-check", "missing_suite") in by_check
    assert by_check[("license-check", "missing_suite")].observed_suites == 1
    assert by_check[("license-check", "missing_suite")].expected_suites == 2


def test_reconcile_commits_respects_grace_window_floor_sha_pagination_and_ledger_flag() -> (
    None
):
    commits_page = [
        _commit_obj(SHA_GRACE, FIXED_NOW - timedelta(minutes=20)),  # inside 45m grace
        _commit_obj(SHA_PASS, FIXED_NOW - timedelta(minutes=60)),  # checked -> pass
        _commit_obj(
            SHA_FLOOR, FIXED_NOW - timedelta(minutes=120)
        ),  # floor -> stop before!
        _commit_obj(SHA_OLDER, FIXED_NOW - timedelta(minutes=180)),  # never reached
    ]
    # Test multi-page check-runs (>100 runs on page 1) for SHA_PASS, without ledger check.
    filler_runs = [
        _make_check_run(
            f"non-required-{idx}",
            run_id=2000 + idx,
            suite_id=8000 + idx,
        )
        for idx in range(100)
    ]
    required_no_ledger = _all_passing_check_runs(include_ledger=False)

    requested_urls: list[str] = []

    def fake_http(
        method: str,
        url: str,
        _headers: Mapping[str, str],
        _payload: Mapping[str, Any] | None,
    ) -> Any:
        assert method == "GET"
        requested_urls.append(url)
        if "/commits?" in url:
            return commits_page
        if (
            f"/commits/{SHA_PASS}/check-runs?per_page=100"
            == url.split("/repos/" + REPO)[1]
        ):
            return {"total_count": 109, "check_runs": filler_runs}
        if (
            f"/commits/{SHA_PASS}/check-runs?per_page=100&page=2"
            == url.split("/repos/" + REPO)[1]
        ):
            return {"total_count": 109, "check_runs": required_no_ledger}
        raise AssertionError(f"Unexpected URL: {url}")

    report = reconciler.reconcile_commits(
        repo=REPO,
        ref="spike/probe-ref",
        max_commits=50,
        grace_minutes=45,
        floor_sha=SHA_FLOOR[:12],
        require_ledger_check=False,
        now=FIXED_NOW,
        http_json=fake_http,
    )
    assert report.head_sha == SHA_GRACE
    assert report.in_grace_commits == 1
    assert report.checked_commits == 1
    assert report.newest_checked_sha == SHA_PASS
    assert report.oldest_checked_sha == SHA_PASS
    assert report.require_ledger_check is False
    assert report.expected_check_count == 8
    assert report.stopped_at_floor_sha is True
    assert report.violations == ()
    assert not any(SHA_FLOOR in u or SHA_OLDER in u for u in requested_urls)
    assert not any(SHA_GRACE in u for u in requested_urls)


class _StatefulDualSinkHarness:
    """In-memory GitHub + GCP REST harness recording call sequence."""

    def __init__(
        self,
        *,
        commits: list[dict[str, Any]],
        check_runs_by_sha: dict[str, list[dict[str, Any]]],
        existing_issues: list[dict[str, Any]] | None = None,
        label_exists: bool = False,
        fail_gcp_pubsub: bool = False,
        fail_gcp_monitoring: bool = False,
        empty_pubsub_msg_ids: bool = False,
    ) -> None:
        self.commits = commits
        self.check_runs_by_sha = check_runs_by_sha
        self.issues: list[dict[str, Any]] = list(existing_issues or [])
        self.label_exists = label_exists
        self.fail_gcp_pubsub = fail_gcp_pubsub
        self.fail_gcp_monitoring = fail_gcp_monitoring
        self.empty_pubsub_msg_ids = empty_pubsub_msg_ids
        self.call_log: list[tuple[str, str, Any]] = []
        self.published_envelopes: list[dict[str, Any]] = []
        self.monitoring_writes: list[dict[str, Any]] = []

    def __call__(
        self,
        method: str,
        url: str,
        _headers: Mapping[str, str],
        payload: Mapping[str, Any] | None,
    ) -> Any:
        self.call_log.append((method, url, payload))

        if url.startswith(f"https://{GITHUB_HOST}/"):
            if "/commits?" in url and method == "GET":
                return self.commits
            for sha, runs in self.check_runs_by_sha.items():
                if f"/commits/{sha}/check-runs" in url and method == "GET":
                    return {"total_count": len(runs), "check_runs": runs}
            if "/labels/" in url and method == "GET":
                if not self.label_exists:
                    raise _HttpStatusError(404, method, url, "Not Found")
                return {"name": DEFAULT_ISSUE_LABEL}
            if url.endswith("/labels") and method == "POST":
                self.label_exists = True
                return {"name": (payload or {}).get("name", DEFAULT_ISSUE_LABEL)}
            if "/issues?" in url and method == "GET":
                return list(self.issues)
            if url.endswith("/issues") and method == "POST":
                assert payload is not None
                new_num = (
                    max((int(i.get("number", 0)) for i in self.issues), default=40) + 1
                )
                issue = {
                    "number": new_num,
                    "state": "open",
                    "title": payload["title"],
                    "body": payload["body"],
                    "html_url": f"https://github.com/{REPO}/issues/{new_num}",
                    "user": {"login": "github-actions[bot]"},
                    "author_association": "NONE",
                }
                self.issues.append(issue)
                return dict(issue)
            if "/issues/" in url and method == "PATCH":
                assert payload is not None
                num = int(url.rsplit("/", 1)[1])
                target = next(i for i in self.issues if i.get("number") == num)
                target.update(payload)
                return dict(target)

        if url.startswith(f"https://{PUBSUB_HOST}/"):
            if self.fail_gcp_pubsub:
                raise ReconcilerOperationalError(
                    "Simulated GCP teardown: Pub/Sub topic not found (404)"
                )
            if self.empty_pubsub_msg_ids:
                return {"messageIds": []}
            assert payload is not None
            for msg in payload["messages"]:
                decoded = json.loads(base64.b64decode(msg["data"]).decode("utf-8"))
                self.published_envelopes.append(decoded)
            return {"messageIds": [f"msg-{len(self.published_envelopes)}"]}

        if url.startswith(f"https://{MONITORING_HOST}/"):
            if self.fail_gcp_monitoring:
                raise ReconcilerOperationalError(
                    "Simulated GCP teardown: Cloud Monitoring project unavailable"
                )
            assert payload is not None
            self.monitoring_writes.append(dict(payload))
            return {}

        raise AssertionError(f"Unhandled request {method} {url}")


def test_green_run_ignores_spoofed_issues_creates_closed_issue_and_delivers_heartbeat() -> (
    None
):
    spoofed_external_issue = {
        "number": 11,
        "state": "open",
        "title": "Spoofed issue by untrusted user",
        "body": "spoof",
        "html_url": f"https://github.com/{REPO}/issues/11",
        "user": {"login": "random-attacker"},
        "author_association": "NONE",
    }
    pull_request_entry = {
        "number": 12,
        "state": "open",
        "pull_request": {"url": "https://api.github.com/..."},
        "user": {"login": "maintainer"},
        "author_association": "OWNER",
    }
    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_PASS, FIXED_NOW - timedelta(hours=2))],
        check_runs_by_sha={SHA_PASS: _all_passing_check_runs()},
        existing_issues=[spoofed_external_issue, pull_request_entry],
        label_exists=False,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--sync-github-issue",
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=harness,
    )
    assert rc == 0
    assert harness.label_exists is True
    # Spoofed issue #11 was untouched; a new trusted issue #13 was created and closed.
    assert spoofed_external_issue["body"] == "spoof"
    created = next(i for i in harness.issues if i["number"] == 13)
    assert created["state"] == "closed"
    assert f"last-checked: {_iso(FIXED_NOW)}" in created["body"]
    assert "status: PASS" in created["body"]
    assert f"head-sha: `{SHA_PASS}`" in created["body"]
    assert f"checked-sha-range: `{SHA_PASS}`..`{SHA_PASS}`" in created["body"]
    assert "require-ledger-check: true (expected-checks: 9)" in created["body"]

    # Step B delivered exactly 1 heartbeat message and 1 Cloud Monitoring sample.
    assert len(harness.published_envelopes) == 1
    hb = harness.published_envelopes[0]
    assert hb["source"] == "main_result_reconciler"
    assert hb["alert_type"] == "heartbeat"
    assert hb["head_sha"] == SHA_PASS
    assert hb["newest_checked_sha"] == SHA_PASS
    assert hb["oldest_checked_sha"] == SHA_PASS
    assert hb["floor_sha"] is None
    assert hb["stopped_at_floor_sha"] is False
    assert hb["require_ledger_check"] is True
    assert hb["expected_check_count"] == 9
    assert hb["violation_count"] == 0
    assert hb["checked_commits"] == 1
    assert len(harness.monitoring_writes) == 1
    ts = harness.monitoring_writes[0]["timeSeries"][0]
    assert ts["metric"]["type"] == RECONCILER_HEARTBEAT_METRIC_TYPE
    assert ts["resource"] == {
        "type": "global",
        "labels": {"project_id": "cage-test-proj"},
    }
    assert ts["points"][0]["value"] == {"int64Value": "1"}


def test_violation_run_reopens_closed_trusted_issue_and_publishes_critical_violation() -> (
    None
):
    trusted_closed_issue = {
        "number": 55,
        "state": "closed",
        "title": "Prior pass",
        "body": "last-checked: 2026-11-23T10:00:00Z\nstatus: PASS\n",
        "html_url": f"https://github.com/{REPO}/issues/55",
        "user": {"login": "github-actions[bot]"},
        "author_association": "NONE",
    }
    bad_runs = _all_passing_check_runs()
    for r in bad_runs:
        if r["name"] == "Pytest Logic Tests":
            r["conclusion"] = "cancelled"

    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_FAIL, FIXED_NOW - timedelta(hours=1))],
        check_runs_by_sha={SHA_FAIL: bad_runs},
        existing_issues=[trusted_closed_issue],
        label_exists=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--sync-github-issue",
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "projects/cage-test-proj/topics/cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=harness,
    )
    assert rc == 1
    assert trusted_closed_issue["state"] == "open"
    assert f"last-checked: {_iso(FIXED_NOW)}" in trusted_closed_issue["body"]
    assert "status: FAIL" in trusted_closed_issue["body"]
    assert f"head-sha: `{SHA_FAIL}`" in trusted_closed_issue["body"]
    assert "`Pytest Logic Tests`" in trusted_closed_issue["body"]
    assert "`cancelled`" in trusted_closed_issue["body"]

    assert [e["alert_type"] for e in harness.published_envelopes] == [
        "heartbeat",
        "main_check_violation",
    ]
    viol_env = harness.published_envelopes[1]
    assert viol_env["severity"] == "CRITICAL"
    assert viol_env["head_sha"] == SHA_FAIL
    assert viol_env["newest_checked_sha"] == SHA_FAIL
    assert viol_env["oldest_checked_sha"] == SHA_FAIL
    assert viol_env["require_ledger_check"] is True
    assert viol_env["expected_check_count"] == 9
    assert viol_env["violation_count"] == 1
    assert viol_env["issue_url"] == f"https://github.com/{REPO}/issues/55"
    assert viol_env["violations"][0]["reason"] == "cancelled"
    assert len(harness.monitoring_writes) == 1


def test_subsequent_green_run_closes_open_issue_and_updates_closed_issue_timestamp() -> (
    None
):
    open_issue = {
        "number": 77,
        "state": "open",
        "title": "Prior fail",
        "body": "old",
        "html_url": f"https://github.com/{REPO}/issues/77",
        "user": {"login": "maintainer"},
        "author_association": "OWNER",
    }
    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_PASS, FIXED_NOW - timedelta(hours=2))],
        check_runs_by_sha={SHA_PASS: _all_passing_check_runs()},
        existing_issues=[open_issue],
        label_exists=True,
    )
    args = reconciler._build_parser().parse_args(
        ["--repo", REPO, "--sync-github-issue"]
    )
    assert (
        reconciler.run_reconciler(
            args,
            github_token="ghs_test",
            now=FIXED_NOW,
            http_json=harness,
        )
        == 0
    )
    assert open_issue["state"] == "closed"
    assert f"last-checked: {_iso(FIXED_NOW)}" in open_issue["body"]

    # A second green run 2 hours later on the already-closed issue STILL stamps a
    # fresh `last-checked:` timestamp without reopening it.
    later = FIXED_NOW + timedelta(hours=2)
    assert (
        reconciler.run_reconciler(
            args,
            github_token="ghs_test",
            now=later,
            http_json=harness,
        )
        == 0
    )
    assert open_issue["state"] == "closed"
    assert f"last-checked: {_iso(later)}" in open_issue["body"]


def test_teardown_ordering_updates_durable_github_issue_before_gcp_failure_exits_2() -> (
    None
):
    """Step A MUST complete before Step B so GCP teardown never suppresses the GitHub issue."""
    bad_runs = _all_passing_check_runs()
    bad_runs[0]["conclusion"] = "failure"

    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_FAIL, FIXED_NOW - timedelta(hours=3))],
        check_runs_by_sha={SHA_FAIL: bad_runs},
        existing_issues=[],
        label_exists=True,
        fail_gcp_pubsub=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--sync-github-issue",
            "--gcp-project",
            "destroyed-project",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=harness,
    )
    assert rc == 2
    # Despite exit code 2 from GCP teardown, Step A already opened the GitHub issue!
    assert len(harness.issues) == 1
    assert harness.issues[0]["state"] == "open"
    assert f"last-checked: {_iso(FIXED_NOW)}" in harness.issues[0]["body"]
    assert "status: FAIL" in harness.issues[0]["body"]

    # Verify strict call ordering in call_log: GitHub issue POST occurred before Pub/Sub POST.
    issue_post_idx = next(
        idx
        for idx, (m, u, _) in enumerate(harness.call_log)
        if m == "POST" and u.endswith("/issues")
    )
    pubsub_post_idx = next(
        idx
        for idx, (m, u, _) in enumerate(harness.call_log)
        if m == "POST" and PUBSUB_HOST in u
    )
    assert issue_post_idx < pubsub_post_idx


def test_empty_pubsub_message_ids_and_invalid_inputs_fail_closed() -> None:
    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_PASS, FIXED_NOW - timedelta(hours=2))],
        check_runs_by_sha={SHA_PASS: _all_passing_check_runs()},
        label_exists=True,
        empty_pubsub_msg_ids=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    assert (
        reconciler.run_reconciler(
            args,
            github_token="ghs_test",
            gcp_token="ya29.test",
            now=FIXED_NOW,
            http_json=harness,
        )
        == 2
    )

    bad_floor_args = reconciler._build_parser().parse_args(
        ["--repo", REPO, "--floor-sha", "not-a-hex-sha!"]
    )
    assert (
        reconciler.run_reconciler(
            bad_floor_args,
            github_token="ghs_test",
            now=FIXED_NOW,
            http_json=harness,
        )
        == 2
    )


def test_empty_first_commits_page_fails_closed_without_issue_or_heartbeat() -> None:
    """An empty page-1 `/commits` response must fail closed (exit 2) without writing a heartbeat."""
    empty_harness = _StatefulDualSinkHarness(
        commits=[],
        check_runs_by_sha={},
        label_exists=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--sync-github-issue",
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=empty_harness,
    )
    assert rc == 2
    assert empty_harness.issues == []
    assert empty_harness.published_envelopes == []
    assert empty_harness.monitoring_writes == []

    # Conversely, when page 1 has 100 commits and page 2 returns `[]` (exact 100-commit
    # branch history with max_commits > 100), pagination terminates cleanly without raising.
    page1_commits = [
        _commit_obj(f"{idx:040x}", FIXED_NOW - timedelta(hours=2 + idx))
        for idx in range(1, 101)
    ]
    passing_runs = _all_passing_check_runs()

    def exact_100_http(
        method: str,
        url: str,
        _headers: Mapping[str, str],
        _payload: Mapping[str, Any] | None,
    ) -> Any:
        assert method == "GET"
        if "/commits?" in url:
            if "page=2" in url:
                return []
            return page1_commits
        if "/check-runs?" in url:
            return {"total_count": len(passing_runs), "check_runs": passing_runs}
        raise AssertionError(f"Unexpected URL: {url}")

    report = reconciler.reconcile_commits(
        repo=REPO,
        ref="main",
        max_commits=150,
        grace_minutes=45,
        now=FIXED_NOW,
        http_json=exact_100_http,
    )
    assert report.head_sha == page1_commits[0]["sha"]
    assert report.checked_commits == 100
    assert report.newest_checked_sha == page1_commits[0]["sha"]
    assert report.oldest_checked_sha == page1_commits[-1]["sha"]
    assert report.violations == ()


def test_quiet_period_at_floor_sha_attests_head_sha_with_zero_new_commits() -> None:
    """When tip matches floor_sha, reconciler positively attests head_sha and 0 new commits."""
    harness = _StatefulDualSinkHarness(
        commits=[_commit_obj(SHA_FLOOR, FIXED_NOW - timedelta(days=3))],
        check_runs_by_sha={},
        label_exists=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--floor-sha",
            SHA_FLOOR[:12],
            "--sync-github-issue",
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=harness,
    )
    assert rc == 0
    assert len(harness.issues) == 1
    body = harness.issues[0]["body"]
    assert "status: PASS" in body
    assert f"head-sha: `{SHA_FLOOR}`" in body
    assert "checked-sha-range: none" in body
    assert "checked-commits: 0" in body
    assert f"floor-sha: `{SHA_FLOOR[:12]}` (stopped-at-floor: true)" in body
    assert f"No new commits past floor `{SHA_FLOOR[:12]}` on `main`" in body

    assert len(harness.published_envelopes) == 1
    hb = harness.published_envelopes[0]
    assert hb["head_sha"] == SHA_FLOOR
    assert hb["newest_checked_sha"] is None
    assert hb["oldest_checked_sha"] is None
    assert hb["floor_sha"] == SHA_FLOOR[:12]
    assert hb["stopped_at_floor_sha"] is True
    assert hb["checked_commits"] == 0
    assert len(harness.monitoring_writes) == 1

    # Malformed commit timestamp on head_sha still fails closed even when head_sha matches floor_sha.
    bad_tip = {"sha": SHA_FLOOR, "commit": {"committer": {"date": ""}}}
    with pytest.raises(ReconcilerOperationalError, match="Empty commit timestamp"):
        reconciler.reconcile_commits(
            repo=REPO,
            floor_sha=SHA_FLOOR[:12],
            now=FIXED_NOW,
            http_json=lambda _m, _u, _h, _p: [bad_tip],
        )


def test_multi_commit_sha_range_attested_across_issue_pubsub_and_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Multi-commit scan records head_sha and newest..oldest checked SHA bounds everywhere."""
    harness = _StatefulDualSinkHarness(
        commits=[
            _commit_obj(SHA_GRACE, FIXED_NOW - timedelta(minutes=10)),
            _commit_obj(SHA_PASS, FIXED_NOW - timedelta(hours=1)),
            _commit_obj(SHA_OLDER, FIXED_NOW - timedelta(hours=3)),
            _commit_obj(SHA_FLOOR, FIXED_NOW - timedelta(hours=5)),
        ],
        check_runs_by_sha={
            SHA_PASS: _all_passing_check_runs(),
            SHA_OLDER: _all_passing_check_runs(),
        },
        label_exists=True,
    )
    args = reconciler._build_parser().parse_args(
        [
            "--repo",
            REPO,
            "--floor-sha",
            SHA_FLOOR[:12],
            "--sync-github-issue",
            "--gcp-project",
            "cage-test-proj",
            "--pubsub-topic",
            "cage-alerts",
            "--require-gcp-delivery",
        ]
    )
    rc = reconciler.run_reconciler(
        args,
        github_token="ghs_test",
        gcp_token="ya29.test",
        now=FIXED_NOW,
        http_json=harness,
    )
    assert rc == 0
    body = harness.issues[0]["body"]
    assert f"head-sha: `{SHA_GRACE}`" in body
    assert f"checked-sha-range: `{SHA_PASS}`..`{SHA_OLDER}`" in body
    assert "checked-commits: 2" in body
    assert "in-grace-commits: 1 (grace window: 45m)" in body

    hb = harness.published_envelopes[0]
    assert hb["head_sha"] == SHA_GRACE
    assert hb["newest_checked_sha"] == SHA_PASS
    assert hb["oldest_checked_sha"] == SHA_OLDER
    assert hb["checked_commits"] == 2
    assert hb["in_grace_commits"] == 1

    pubsub_call = next(
        payload
        for method, url, payload in harness.call_log
        if method == "POST" and PUBSUB_HOST in url
    )
    assert pubsub_call["messages"][0]["attributes"]["head_sha"] == SHA_GRACE

    stdout_json = json.loads(capsys.readouterr().out)
    assert stdout_json["head_sha"] == SHA_GRACE
    assert stdout_json["newest_checked_sha"] == SHA_PASS
    assert stdout_json["oldest_checked_sha"] == SHA_OLDER
    assert stdout_json["floor_sha"] == SHA_FLOOR[:12]
    assert stdout_json["require_ledger_check"] is True
    assert stdout_json["expected_check_count"] == 9


def test_workflow_distinguishes_exit_codes_with_error_annotations() -> None:
    """Workflow emits distinct ::error:: failure annotations for exit 1, 2, and 3."""
    wf_path = (
        Path(__file__).resolve().parents[2]
        / ".github/workflows/main-result-reconciler.yml"
    )
    wf_text = wf_path.read_text(encoding="utf-8")
    assert "::error::[POAM-2026-171] FOUND VIOLATIONS (exit 1)" in wf_text
    assert "exit 1" in wf_text
    assert "::error::[POAM-2026-171] DELIVERY BROKEN (exit 2)" in wf_text
    assert "exit 2" in wf_text
    assert "::error::[POAM-2026-171] NOT WIRED (exit 3)" in wf_text
    assert "exit 3" in wf_text
