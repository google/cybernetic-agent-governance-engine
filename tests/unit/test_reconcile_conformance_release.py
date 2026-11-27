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

"""Unit tests for ``scripts/reconcile_conformance_release.py`` and CI smoke/reconciler workflows."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import reconcile_conformance_release as rec

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _fake_git(
    *,
    tags: Sequence[str] = ("conformance-v0.4.2",),
    tag_sha: str = "a" * 40,
    log_lines: Sequence[str] = (),
) -> rec.GitRunner:
    def _run(args: Sequence[str]) -> str:
        if args[:2] == ["tag", "-l"]:
            return "\n".join(tags) + ("\n" if tags else "")
        if args[:3] == ["rev-list", "-n", "1"]:
            return f"{tag_sha}\n"
        if args[0] == "log":
            return "\n".join(log_lines) + ("\n" if log_lines else "")
        raise AssertionError(f"Unexpected git args: {args}")

    return _run


def _fake_http(
    *,
    version: str = "0.4.2",
    tag_sha: str = "a" * 40,
    latest_digest: str = "sha256:" + "1" * 64,
    version_digest: str = "sha256:" + "1" * 64,
    oci_revision: str | None = "a" * 40,
    release_assets: Sequence[str] | None = None,
    release_status: int = 200,
    issues_list: Sequence[Mapping[str, Any]] = (),
    recorded_calls: list[tuple[str, str, dict[str, Any] | None]] | None = None,
) -> rec.HttpClient:
    if release_assets is None:
        release_assets = (
            f"cage_conformance-{version}-py3-none-any.whl",
            f"cage_conformance-{version}.tar.gz",
        )
    config_digest = "sha256:" + "2" * 64

    def _client(
        method: str,
        url: str,
        _headers: Mapping[str, str],
        body: bytes | None,
    ) -> rec.HttpResult:
        parsed_body = json.loads(body.decode("utf-8")) if body else None
        if recorded_calls is not None:
            recorded_calls.append((method, url, parsed_body))

        if "/releases/tags/" in url:
            if release_status != 200:
                return rec.HttpResult(release_status, {}, b"{}")
            payload = {"assets": [{"name": name} for name in release_assets]}
            return rec.HttpResult(200, {}, json.dumps(payload).encode("utf-8"))

        if url.startswith("https://ghcr.io/token"):
            return rec.HttpResult(200, {}, json.dumps({"token": "tok"}).encode("utf-8"))

        if url.endswith(f"/manifests/{version}"):
            manifest = {"config": {"digest": config_digest}}
            return rec.HttpResult(
                200,
                {"docker-content-digest": version_digest},
                json.dumps(manifest).encode("utf-8"),
            )

        if url.endswith("/manifests/latest"):
            manifest = {"config": {"digest": config_digest}}
            return rec.HttpResult(
                200,
                {"docker-content-digest": latest_digest},
                json.dumps(manifest).encode("utf-8"),
            )

        if url.endswith(f"/blobs/{config_digest}"):
            labels: dict[str, str] = {}
            if oci_revision is not None:
                labels["org.opencontainers.image.revision"] = oci_revision
            cfg = {"config": {"Labels": labels}}
            return rec.HttpResult(200, {}, json.dumps(cfg).encode("utf-8"))

        if "/issues?" in url:
            return rec.HttpResult(
                200, {}, json.dumps(list(issues_list)).encode("utf-8")
            )

        if url.endswith("/labels"):
            return rec.HttpResult(201, {}, b"{}")

        if url.endswith("/issues") and method == "POST":
            return rec.HttpResult(201, {}, json.dumps({"number": 999}).encode("utf-8"))

        if "/issues/" in url and method == "PATCH":
            return rec.HttpResult(200, {}, b"{}")

        raise AssertionError(f"Unhandled HTTP request: {method} {url}")

    return _client


def test_select_latest_conformance_tag_picks_highest_semver() -> None:
    tag, semver = rec.select_latest_conformance_tag(
        [
            "conformance-v0.4.1",
            "conformance-v0.4.10",
            "conformance-v0.4.2",
            "conformance-vbad",
        ]
    )
    assert tag == "conformance-v0.4.10"
    assert semver == (0, 4, 10)

    with pytest.raises(rec.ReconcilerOperationalError, match="No semver"):
        rec.select_latest_conformance_tag(["client-v0.6.0"])


def test_clean_release_passes_with_matching_tag_assets_and_ghcr() -> None:
    findings, report = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        now_epoch=1_795_000_000,
        git_run=_fake_git(),
        http_client=_fake_http(),
    )
    assert findings == []
    assert report["latest_tag"] == "conformance-v0.4.2"
    assert report["behind_commit_count"] == 0
    assert report["ghcr"]["oci_revision"] == "a" * 40


def test_grace_window_and_stale_release_detection() -> None:
    now = 1_795_000_000
    fresh_ts = now - 3600  # 1 hour old (< 72h grace)
    findings_fresh, _ = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        grace_hours=72.0,
        now_epoch=now,
        git_run=_fake_git(log_lines=[f"{'b' * 40}\t{fresh_ts}\tfix(proof): recent"]),
        http_client=_fake_http(),
    )
    assert findings_fresh == []

    stale_ts = now - (80 * 3600)  # 80 hours old (>= 72h grace)
    findings_stale, report = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        grace_hours=72.0,
        now_epoch=now,
        git_run=_fake_git(log_lines=[f"{'b' * 40}\t{stale_ts}\tfix(proof): stale"]),
        http_client=_fake_http(),
    )
    assert [f.code for f in findings_stale] == ["STALE_CONFORMANCE_RELEASE"]
    assert report["behind_commit_count"] == 1


def test_ghcr_and_release_asset_mismatches_fail_closed() -> None:
    findings, _ = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        now_epoch=1_795_000_000,
        git_run=_fake_git(),
        http_client=_fake_http(
            latest_digest="sha256:" + "9" * 64,
            oci_revision="c" * 40,
            release_assets=("cage_conformance-0.4.2-py3-none-any.whl",),
        ),
    )
    assert {f.code for f in findings} == {
        "MISSING_RELEASE_ASSETS",
        "GHCR_LATEST_DIGEST_MISMATCH",
        "GHCR_REVISION_MISMATCH",
    }

    missing_label, _ = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        now_epoch=1_795_000_000,
        git_run=_fake_git(),
        http_client=_fake_http(oci_revision=None),
    )
    assert [f.code for f in missing_label] == ["GHCR_MISSING_REVISION_LABEL"]


def test_validate_https_url_rejects_unlisted_hosts() -> None:
    with pytest.raises(rec.ReconcilerOperationalError, match="non-allowlisted URL"):
        rec._validate_https_url("http://api.github.com/repos/a/b")
    with pytest.raises(rec.ReconcilerOperationalError, match="non-allowlisted URL"):
        rec._validate_https_url("https://evil.example.com/token")


def test_sync_github_issue_ignores_untrusted_issues_and_closes_when_clean() -> None:
    calls: list[tuple[str, str, dict[str, Any] | None]] = []
    untrusted_issue = {
        "number": 12,
        "state": "open",
        "user": {"login": "external-user"},
        "author_association": "NONE",
    }
    findings = [rec.DriftFinding("STALE_CONFORMANCE_RELEASE", "2 commits behind")]
    report = {
        "checked_at": "2026-11-27T12:00:00Z",
        "latest_tag": "conformance-v0.4.2",
        "latest_tag_sha": "a" * 40,
        "ref": "main",
        "behind_commit_count": 2,
        "grace_hours": 72.0,
        "unreleased_commits": [],
        "ghcr": {},
    }
    rec.sync_github_issue(
        _fake_http(issues_list=[untrusted_issue], recorded_calls=calls),
        repo=rec.DEFAULT_REPO,
        label=rec.DEFAULT_ISSUE_LABEL,
        github_token="tok",
        status_report=report,
        findings=findings,
    )
    post_issues = [c for c in calls if c[0] == "POST" and c[1].endswith("/issues")]
    assert len(post_issues) == 1

    calls.clear()
    trusted_issue = {
        "number": 55,
        "state": "open",
        "user": {"login": "github-actions[bot]"},
        "author_association": "NONE",
    }
    rec.sync_github_issue(
        _fake_http(issues_list=[trusted_issue], recorded_calls=calls),
        repo=rec.DEFAULT_REPO,
        label=rec.DEFAULT_ISSUE_LABEL,
        github_token="tok",
        status_report=report,
        findings=[],
    )
    patches = [c for c in calls if c[0] == "PATCH" and c[1].endswith("/issues/55")]
    assert len(patches) == 1
    assert patches[0][2] is not None
    assert patches[0][2]["state"] == "closed"


def test_real_repo_local_git_detects_post_041_commits() -> None:
    findings, report = rec.reconcile_conformance_release(
        repo_root=REPO_ROOT,
        ref="HEAD",
        grace_hours=0.0,
        check_release=False,
        check_ghcr=False,
    )
    assert report["latest_tag"] == "conformance-v0.4.1"
    assert report["behind_commit_count"] >= 7
    assert [f.code for f in findings] == ["STALE_CONFORMANCE_RELEASE"]


def test_conformance_workflows_follow_security_and_step_gating_invariants() -> None:
    rec_wf = yaml.safe_load(
        (WORKFLOWS_DIR / "conformance-release-reconciler.yml").read_text(
            encoding="utf-8"
        )
    )
    on_block = rec_wf.get("on", rec_wf.get(True, {}))
    assert "schedule" in on_block
    assert rec_wf["permissions"] == {}
    assert rec_wf["concurrency"]["cancel-in-progress"] is False
    job = rec_wf["jobs"]["reconcile-conformance-release"]
    assert job["permissions"] == {
        "contents": "read",
        "packages": "read",
        "issues": "write",
    }
    for step in job["steps"]:
        if "run" in step:
            assert "${{" not in step["run"]

    ci_wf = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    smoke_job = ci_wf["jobs"]["conformance-wheel-smoke"]
    assert "if" not in smoke_job, (
        "smoke job must report unconditionally with step gating"
    )
    assert smoke_job["permissions"] == {"contents": "read"}
    for step in smoke_job["steps"]:
        if "run" in step:
            assert "${{" not in step["run"]
    assert any(
        "smoke_test_conformance_wheel.sh" in str(step.get("run", ""))
        for step in smoke_job["steps"]
    )
    assert any(
        "packages/cage-conformance/Dockerfile" in str(step.get("run", ""))
        for step in smoke_job["steps"]
    )
