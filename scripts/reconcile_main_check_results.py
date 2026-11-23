#!/usr/bin/env python3
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

"""Post-merge `main` required-check result reconciler (POAM-2026-171).

Pure Python 3.12 stdlib script (zero third-party imports) safe to execute in
minimal OIDC-authenticated GitHub Actions jobs without installing PyPI
dependencies.

For every commit on ``--ref`` (default ``main``) older than grace window ``N``
(``--grace-minutes``, default ``45``), verifies that every expected post-merge
status check in ``EXPECTED_MAIN_PUSH_CHECKS`` (pinned to GitHub Actions app ID
``15368`` in ``scripts/check_repo_rules.py``) completed with ``conclusion ==
"success"`` across all expected check suites (``2`` suites for ``license-check``
per ``POAM-2026-172``, ``1`` suite for the remaining ``8`` checks).

``--require-ledger-check`` is ON by default on ``main`` (requiring
``Record an unreviewed merge`` from ``review-bypass-ledger.yml``). Pass
``--no-ledger-check`` (or ``--skip-ledger-check``) only when probing a
synthetic non-PR branch or historical commits predating ``d2a0b516``.

Dual-delivery ordering (teardown-resilient):
  1. **Step A — Durable GitHub Issue FIRST** (``--sync-github-issue``):
     Stamps ``last-checked: <YYYY-MM-DDTHH:MM:SSZ>`` into a durable GitHub issue
     keyed by ``--issue-label`` (default ``main-check-reconciliation``),
     matching only issues created by ``github-actions[bot]`` or repository
     ``OWNER`` / ``MEMBER`` / ``COLLABORATOR`` actors to prevent public-repo
     issue spoofing. Opens/reopens with a full violation table when violations
     exist; closes with ``status: PASS`` when clean.
  2. **Step B — Keyless WIF GCP Pub/Sub + Cloud Monitoring Heartbeat SECOND**:
     Publishes a JSON ``heartbeat`` envelope (and a ``CRITICAL``
     ``main_check_violation`` envelope when violations exist) to
     ``--pubsub-topic``, and writes ``1`` to
     ``custom.googleapis.com/cage/main_result_reconciler_heartbeat``
     (``resource.type = "global"``). Executing Step B after Step A guarantees
     that an alert about repository integrity never lives solely inside
     infrastructure that a teardown removes: if the GCP stack is destroyed,
     Step A has already updated the durable GitHub issue before Step B fails
     closed with exit code ``2``.

Exit codes:
  - ``0``: all checked commits passed and all configured sinks succeeded.
  - ``1``: one or more check violations found and delivered to configured sinks.
  - ``2``: API, configuration, or sink-delivery failure.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_repo_rules_module() -> Any:
    for mod_name in ("scripts.check_repo_rules", "check_repo_rules"):
        existing = sys.modules.get(mod_name)
        if existing is not None:
            return existing
    target = Path(__file__).resolve().with_name("check_repo_rules.py")
    spec = importlib.util.spec_from_file_location("check_repo_rules", target)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load shared pins from {target}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_repo_rules"] = mod
    spec.loader.exec_module(mod)
    return mod


_REPO_RULES = _load_repo_rules_module()
API_ROOT: str = _REPO_RULES.API_ROOT
DEFAULT_REPO: str = _REPO_RULES.DEFAULT_REPO
EXPECTED_MAIN_PUSH_CHECKS: Mapping[str, int] = _REPO_RULES.EXPECTED_MAIN_PUSH_CHECKS
EXPECTED_MAIN_CHECK_SUITE_COUNTS: Mapping[str, int] = (
    _REPO_RULES.EXPECTED_MAIN_CHECK_SUITE_COUNTS
)
REVIEW_BYPASS_LEDGER_CHECK: str = _REPO_RULES.REVIEW_BYPASS_LEDGER_CHECK

GITHUB_HOST = "api.github.com"
PUBSUB_HOST = "pubsub.googleapis.com"
MONITORING_HOST = "monitoring.googleapis.com"
ALLOWED_HTTPS_HOSTS: frozenset[str] = frozenset(
    {
        GITHUB_HOST,
        PUBSUB_HOST,
        MONITORING_HOST,
    }
)

PUBSUB_API_BASE = f"https://{PUBSUB_HOST}/v1"
MONITORING_API_BASE = f"https://{MONITORING_HOST}/v3"
RECONCILER_HEARTBEAT_METRIC_TYPE = (
    "custom.googleapis.com/cage/main_result_reconciler_heartbeat"
)

DEFAULT_REF = "main"
DEFAULT_MAX_COMMITS = 50
DEFAULT_GRACE_MINUTES = 45
DEFAULT_ISSUE_LABEL = "main-check-reconciliation"
DEFAULT_ISSUE_LABEL_COLOR = "b60205"
DEFAULT_ISSUE_LABEL_DESCRIPTION = (
    "Durable post-merge required-check reconciliation status on main (POAM-2026-171)"
)
HTTP_TIMEOUT_SECONDS = 30.0

TRUSTED_ISSUE_BOT_LOGINS: frozenset[str] = frozenset({"github-actions[bot]"})
TRUSTED_ISSUE_ASSOCIATIONS: frozenset[str] = frozenset(
    {"OWNER", "MEMBER", "COLLABORATOR"}
)

_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ReconcilerOperationalError(RuntimeError):
    """Raised on configuration, API, or sink-delivery failure (exit code 2)."""


@dataclass(frozen=True)
class CheckViolation:
    """Single post-merge required-check violation on a commit."""

    sha: str
    committed_at: str
    check_name: str
    reason: str
    observed_suites: int
    expected_suites: int
    suite_id: int | None = None
    run_id: int | None = None
    html_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "committed_at": self.committed_at,
            "check_name": self.check_name,
            "reason": self.reason,
            "observed_suites": self.observed_suites,
            "expected_suites": self.expected_suites,
            "suite_id": self.suite_id,
            "run_id": self.run_id,
            "html_url": self.html_url,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    """Outcome of scanning commits on a branch/ref."""

    repo: str
    ref: str
    head_sha: str
    last_checked: str
    grace_minutes: int
    max_commits: int
    floor_sha: str
    require_ledger_check: bool
    expected_check_count: int
    checked_commits: int
    in_grace_commits: int
    newest_checked_sha: str | None
    oldest_checked_sha: str | None
    stopped_at_floor_sha: bool
    violations: tuple[CheckViolation, ...]


HttpRequester = Callable[
    [str, str, Mapping[str, str], Mapping[str, Any] | None],
    Any,
]


def _format_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_utc(raw: str) -> datetime:
    cleaned = raw.strip()
    if not cleaned:
        raise ReconcilerOperationalError("Empty commit timestamp in GitHub response.")
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ReconcilerOperationalError(
            f"Unparseable ISO-8601 timestamp {raw!r}: {exc}"
        ) from exc
    if parsed.tzinfo is None:
        raise ReconcilerOperationalError(
            f"Naive timestamp without timezone offset rejected: {raw!r}"
        )
    return parsed.astimezone(timezone.utc)


def validate_https_url(url: str, *, expected_host: str | None = None) -> str:
    """Enforce HTTPS and exact allowlisted host before urllib.request.urlopen (B310)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or host not in ALLOWED_HTTPS_HOSTS
    ):
        raise ReconcilerOperationalError(
            f"Refusing disallowed URL {url!r} (scheme={parsed.scheme!r}, host={host!r})"
        )
    if expected_host is not None and host != expected_host:
        raise ReconcilerOperationalError(
            f"URL host {host!r} does not match expected host {expected_host!r}: {url!r}"
        )
    return url


def _default_http_json(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, Any] | None = None,
) -> Any:
    validated_url = validate_https_url(url)
    body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = dict(headers)
    if body_bytes is not None:
        req_headers.setdefault("Content-Type", "application/json; charset=utf-8")
    req = urllib.request.Request(
        validated_url,
        data=body_bytes,
        headers=req_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:  # nosec B310  # HTTPS scheme and exact host allowlist verified by validate_https_url
            raw = resp.read().decode("utf-8", errors="replace").strip()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:500]
        raise _HttpStatusError(exc.code, method, validated_url, err_body) from exc
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise ReconcilerOperationalError(
            f"Request failed for {method} {validated_url}: {exc}"
        ) from exc


class _HttpStatusError(ReconcilerOperationalError):
    """HTTP error carrying status code so 404/422 label checks can branch cleanly."""

    def __init__(self, status_code: int, method: str, url: str, body: str) -> None:
        super().__init__(f"HTTP {status_code} calling {method} {url}: {body}")
        self.status_code = status_code
        self.body = body


def _github_headers(token: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _gcp_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def resolve_gcp_access_token() -> str:
    """Resolve an OAuth2 Bearer token from GOOGLE_OAUTH_ACCESS_TOKEN or gcloud."""
    env_token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "").strip()
    if env_token:
        return env_token
    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except Exception as exc:
        raise ReconcilerOperationalError(
            "Unable to resolve GCP OAuth2 access token from GOOGLE_OAUTH_ACCESS_TOKEN "
            f"or `gcloud auth print-access-token`: {exc}"
        ) from exc
    token = proc.stdout.strip()
    if not token:
        raise ReconcilerOperationalError("Empty GCP OAuth2 access token.")
    return token


def expected_checks_for_run(
    *, require_ledger_check: bool = True
) -> tuple[dict[str, int], dict[str, int]]:
    """Return `(expected_checks, expected_suite_counts)` for reconciliation."""
    checks = dict(EXPECTED_MAIN_PUSH_CHECKS)
    suite_counts = dict(EXPECTED_MAIN_CHECK_SUITE_COUNTS)
    if not require_ledger_check:
        checks.pop(REVIEW_BYPASS_LEDGER_CHECK, None)
        suite_counts.pop(REVIEW_BYPASS_LEDGER_CHECK, None)
    return checks, suite_counts


def _quote_repo_path(repo: str) -> str:
    cleaned = repo.strip()
    if not _REPO_SLUG_RE.fullmatch(cleaned):
        raise ReconcilerOperationalError(
            f"Invalid --repo slug {repo!r}; expected OWNER/NAME."
        )
    owner, name = cleaned.split("/", 1)
    return f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"


def evaluate_commit_check_runs(
    *,
    sha: str,
    committed_at: str,
    check_runs: Sequence[Mapping[str, Any]],
    expected_checks: Mapping[str, int] = EXPECTED_MAIN_PUSH_CHECKS,
    expected_suite_counts: Mapping[str, int] = EXPECTED_MAIN_CHECK_SUITE_COUNTS,
) -> list[CheckViolation]:
    """Evaluate a commit's check runs against pinned app IDs and suite counts."""
    grouped: dict[str, dict[int, list[Mapping[str, Any]]]] = {
        name: {} for name in expected_checks
    }

    for run in check_runs:
        if not isinstance(run, Mapping):
            raise ReconcilerOperationalError(
                f"Malformed check_run entry on {sha}: expected object, got {type(run).__name__}"
            )
        name = str(run.get("name") or "")
        if name not in expected_checks:
            continue
        app = run.get("app")
        app_id = app.get("id") if isinstance(app, Mapping) else None
        if app_id != expected_checks[name]:
            continue
        raw_run_id = run.get("id")
        if not isinstance(raw_run_id, int) or isinstance(raw_run_id, bool):
            raise ReconcilerOperationalError(
                f"Check run for {name!r} on {sha} is missing integer `id`: {raw_run_id!r}"
            )
        suite = run.get("check_suite")
        raw_suite_id = suite.get("id") if isinstance(suite, Mapping) else None
        if isinstance(raw_suite_id, int) and not isinstance(raw_suite_id, bool):
            suite_id = raw_suite_id
        else:
            suite_id = -raw_run_id
        grouped[name].setdefault(suite_id, []).append(run)

    violations: list[CheckViolation] = []
    for name in expected_checks:
        suites = grouped[name]
        expected_count = int(expected_suite_counts.get(name, 1))
        observed_count = len(suites)

        if observed_count == 0:
            violations.append(
                CheckViolation(
                    sha=sha,
                    committed_at=committed_at,
                    check_name=name,
                    reason="missing",
                    observed_suites=0,
                    expected_suites=expected_count,
                )
            )
            continue

        for suite_id in sorted(suites):
            latest = max(suites[suite_id], key=lambda r: int(r["id"]))
            run_id = int(latest["id"])
            html_url = str(latest.get("html_url") or "")
            status = latest.get("status")
            conclusion = latest.get("conclusion")
            if status != "completed":
                violations.append(
                    CheckViolation(
                        sha=sha,
                        committed_at=committed_at,
                        check_name=name,
                        reason=f"incomplete:{status}",
                        observed_suites=observed_count,
                        expected_suites=expected_count,
                        suite_id=suite_id if suite_id > 0 else None,
                        run_id=run_id,
                        html_url=html_url,
                    )
                )
            elif conclusion != "success":
                violations.append(
                    CheckViolation(
                        sha=sha,
                        committed_at=committed_at,
                        check_name=name,
                        reason=str(conclusion),
                        observed_suites=observed_count,
                        expected_suites=expected_count,
                        suite_id=suite_id if suite_id > 0 else None,
                        run_id=run_id,
                        html_url=html_url,
                    )
                )

        if observed_count < expected_count:
            violations.append(
                CheckViolation(
                    sha=sha,
                    committed_at=committed_at,
                    check_name=name,
                    reason="missing_suite",
                    observed_suites=observed_count,
                    expected_suites=expected_count,
                )
            )

    return violations


def _fetch_commit_list(
    *,
    repo_path: str,
    ref: str,
    max_commits: int,
    floor_sha: str,
    github_token: str,
    http_json: HttpRequester,
) -> tuple[str, list[tuple[str, str]], bool]:
    head_sha = ""
    commits: list[tuple[str, str]] = []
    stopped_at_floor = False
    page = 1
    headers = _github_headers(github_token)

    while len(commits) < max_commits:
        query: dict[str, str] = {"sha": ref, "per_page": "100"}
        if page > 1:
            query["page"] = str(page)
        url = f"{API_ROOT}/repos/{repo_path}/commits?{urllib.parse.urlencode(query)}"
        validate_https_url(url, expected_host=GITHUB_HOST)
        resp = http_json("GET", url, headers, None)
        if not isinstance(resp, list):
            raise ReconcilerOperationalError(
                f"Unexpected commits API response shape on page {page}: {type(resp).__name__}"
            )
        if not resp:
            if page == 1:
                raise ReconcilerOperationalError(
                    f"GitHub commits API returned an empty first page for ref {ref!r}; "
                    "refusing vacuous PASS."
                )
            break

        for item in resp:
            if not isinstance(item, Mapping):
                raise ReconcilerOperationalError(
                    "Malformed commit entry in GitHub response."
                )
            sha = str(item.get("sha") or "").strip().lower()
            if not _HEX_SHA_RE.fullmatch(sha):
                raise ReconcilerOperationalError(
                    f"Invalid commit SHA in GitHub response: {sha!r}"
                )
            commit_obj = item.get("commit")
            committer = (
                commit_obj.get("committer") if isinstance(commit_obj, Mapping) else None
            )
            committed_at = (
                str(committer.get("date") or "").strip()
                if isinstance(committer, Mapping)
                else ""
            )
            _parse_iso_utc(committed_at)
            if not head_sha:
                head_sha = sha
            if floor_sha and sha.startswith(floor_sha):
                stopped_at_floor = True
                return head_sha, commits, stopped_at_floor
            commits.append((sha, committed_at))
            if len(commits) >= max_commits:
                return head_sha, commits, stopped_at_floor

        if len(resp) < 100:
            break
        page += 1

    if not head_sha:
        raise ReconcilerOperationalError(f"Unable to resolve head_sha for ref {ref!r}.")
    return head_sha, commits, stopped_at_floor


def _fetch_all_check_runs_for_sha(
    *,
    repo_path: str,
    sha: str,
    github_token: str,
    http_json: HttpRequester,
) -> list[Mapping[str, Any]]:
    runs: list[Mapping[str, Any]] = []
    page = 1
    headers = _github_headers(github_token)

    while True:
        query: dict[str, str] = {"per_page": "100"}
        if page > 1:
            query["page"] = str(page)
        url = (
            f"{API_ROOT}/repos/{repo_path}/commits/{urllib.parse.quote(sha, safe='')}"
            f"/check-runs?{urllib.parse.urlencode(query)}"
        )
        validate_https_url(url, expected_host=GITHUB_HOST)
        resp = http_json("GET", url, headers, None)
        if not isinstance(resp, Mapping) or not isinstance(
            resp.get("check_runs"), list
        ):
            raise ReconcilerOperationalError(
                f"Unexpected check-runs API response shape for {sha} on page {page}."
            )
        page_runs = resp["check_runs"]
        for entry in page_runs:
            if not isinstance(entry, Mapping):
                raise ReconcilerOperationalError(
                    f"Malformed check-run item for {sha} on page {page}."
                )
            runs.append(entry)
        if len(page_runs) < 100:
            break
        page += 1

    return runs


def reconcile_commits(
    *,
    repo: str,
    ref: str = DEFAULT_REF,
    max_commits: int = DEFAULT_MAX_COMMITS,
    grace_minutes: int = DEFAULT_GRACE_MINUTES,
    floor_sha: str = "",
    require_ledger_check: bool = True,
    github_token: str = "",
    now: datetime | None = None,
    http_json: HttpRequester = _default_http_json,
) -> ReconciliationReport:
    """Walk commits on ``ref`` and evaluate required check runs outside grace."""
    if max_commits < 1:
        raise ReconcilerOperationalError(
            f"--max-commits must be >= 1, got {max_commits}"
        )
    if grace_minutes < 0:
        raise ReconcilerOperationalError(
            f"--grace-minutes must be >= 0, got {grace_minutes}"
        )
    cleaned_ref = ref.strip()
    if not cleaned_ref:
        raise ReconcilerOperationalError("--ref must not be empty.")
    cleaned_floor = floor_sha.strip().lower()
    if cleaned_floor and not _HEX_SHA_RE.fullmatch(cleaned_floor):
        raise ReconcilerOperationalError(
            f"--floor-sha must be 7-40 lowercase hex digits, got {floor_sha!r}"
        )

    repo_path = _quote_repo_path(repo)
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    last_checked = _format_utc_iso(now_utc)
    grace_seconds = grace_minutes * 60.0

    head_sha, commits, stopped_at_floor = _fetch_commit_list(
        repo_path=repo_path,
        ref=cleaned_ref,
        max_commits=max_commits,
        floor_sha=cleaned_floor,
        github_token=github_token,
        http_json=http_json,
    )
    expected_checks, expected_suite_counts = expected_checks_for_run(
        require_ledger_check=require_ledger_check
    )

    checked_commits = 0
    in_grace_commits = 0
    newest_checked_sha: str | None = None
    oldest_checked_sha: str | None = None
    all_violations: list[CheckViolation] = []

    for sha, committed_at in commits:
        committed_dt = _parse_iso_utc(committed_at)
        age_seconds = (now_utc - committed_dt).total_seconds()
        if age_seconds < grace_seconds:
            in_grace_commits += 1
            continue

        if newest_checked_sha is None:
            newest_checked_sha = sha
        oldest_checked_sha = sha
        checked_commits += 1
        check_runs = _fetch_all_check_runs_for_sha(
            repo_path=repo_path,
            sha=sha,
            github_token=github_token,
            http_json=http_json,
        )
        all_violations.extend(
            evaluate_commit_check_runs(
                sha=sha,
                committed_at=committed_at,
                check_runs=check_runs,
                expected_checks=expected_checks,
                expected_suite_counts=expected_suite_counts,
            )
        )

    return ReconciliationReport(
        repo=repo.strip(),
        ref=cleaned_ref,
        head_sha=head_sha,
        last_checked=last_checked,
        grace_minutes=grace_minutes,
        max_commits=max_commits,
        floor_sha=cleaned_floor,
        require_ledger_check=require_ledger_check,
        expected_check_count=len(expected_checks),
        checked_commits=checked_commits,
        in_grace_commits=in_grace_commits,
        newest_checked_sha=newest_checked_sha,
        oldest_checked_sha=oldest_checked_sha,
        stopped_at_floor_sha=stopped_at_floor,
        violations=tuple(all_violations),
    )


def is_trusted_issue_author(issue: Mapping[str, Any]) -> bool:
    """Allow only github-actions[bot] or repository OWNER/MEMBER/COLLABORATOR."""
    if "pull_request" in issue:
        return False
    user = issue.get("user")
    login = str(user.get("login") or "") if isinstance(user, Mapping) else ""
    if login in TRUSTED_ISSUE_BOT_LOGINS:
        return True
    assoc = str(issue.get("author_association") or "")
    return assoc in TRUSTED_ISSUE_ASSOCIATIONS


def render_issue_body(report: ReconciliationReport) -> str:
    """Render the durable GitHub reconciliation issue body with `last-checked:`."""
    status = "FAIL" if report.violations else "PASS"
    checked_range = (
        f"`{report.newest_checked_sha}`..`{report.oldest_checked_sha}`"
        if report.newest_checked_sha and report.oldest_checked_sha
        else "none"
    )
    lines = [
        "## Post-Merge `main` Required-Check Reconciliation (`POAM-2026-171`)",
        "",
        f"last-checked: {report.last_checked}",
        f"status: {status}",
        f"ref: `{report.ref}`",
        f"head-sha: `{report.head_sha}`",
        f"checked-sha-range: {checked_range}",
        f"checked-commits: {report.checked_commits}",
        f"in-grace-commits: {report.in_grace_commits} (grace window: {report.grace_minutes}m)",
        f"require-ledger-check: {str(report.require_ledger_check).lower()} (expected-checks: {report.expected_check_count})",
        f"violation-count: {len(report.violations)}",
    ]
    if report.floor_sha:
        lines.append(
            f"floor-sha: `{report.floor_sha}` (stopped-at-floor: {str(report.stopped_at_floor_sha).lower()})"
        )
    lines.append("")

    if report.violations:
        lines.extend(
            [
                "### Commits in Violation",
                "",
                "| Commit | Committed (UTC) | Required Check | Suites (`obs/exp`) | Run ID | Violation |",
                "|---|---|---|---:|---|---|",
            ]
        )
        for v in report.violations:
            short_sha = f"`{v.sha[:12]}`"
            safe_check = v.check_name.replace("|", "\\|")
            run_cell = (
                f"[`{v.run_id}`]({v.html_url})"
                if v.run_id is not None and v.html_url.startswith("https://")
                else (f"`{v.run_id}`" if v.run_id is not None else "—")
            )
            lines.append(
                f"| {short_sha} | `{v.committed_at}` | `{safe_check}` | "
                f"`{v.observed_suites}/{v.expected_suites}` | {run_cell} | `{v.reason}` |"
            )
        lines.append("")
    elif report.checked_commits > 0:
        lines.extend(
            [
                "All checked commits outside the grace window have completed `success` check runs "
                "from GitHub Actions (`app.id == 15368`) across every expected suite.",
                "",
            ]
        )
    elif report.stopped_at_floor_sha and report.in_grace_commits == 0:
        lines.extend(
            [
                f"No new commits past floor `{report.floor_sha}` on `{report.ref}` "
                f"(`head-sha`: `{report.head_sha}`).",
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"No commits outside the {report.grace_minutes}m grace window were eligible "
                f"for evaluation on `{report.ref}` (`head-sha`: `{report.head_sha}`, "
                f"`in-grace-commits`: {report.in_grace_commits}).",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "_Durable repository layer of the `POAM-2026-171` 2-layer watcher chain "
            "(`.github/workflows/main-result-reconciler.yml` -> `scripts/reconcile_main_check_results.py`). "
            "If `last-checked:` above lags the 2-hour schedule, check whether the workflow was "
            "disabled, broken by a YAML syntax error, throttled by Actions quota/outage, or "
            "auto-disabled after 60 days of repository inactivity._",
        ]
    )
    return "\n".join(lines) + "\n"


def _ensure_github_label(
    *,
    repo_path: str,
    label: str,
    headers: Mapping[str, str],
    http_json: HttpRequester,
) -> None:
    label_url = (
        f"{API_ROOT}/repos/{repo_path}/labels/{urllib.parse.quote(label, safe='')}"
    )
    validate_https_url(label_url, expected_host=GITHUB_HOST)
    try:
        http_json("GET", label_url, headers, None)
        return
    except _HttpStatusError as exc:
        if exc.status_code != 404:
            raise

    create_url = f"{API_ROOT}/repos/{repo_path}/labels"
    validate_https_url(create_url, expected_host=GITHUB_HOST)
    try:
        http_json(
            "POST",
            create_url,
            headers,
            {
                "name": label,
                "color": DEFAULT_ISSUE_LABEL_COLOR,
                "description": DEFAULT_ISSUE_LABEL_DESCRIPTION,
            },
        )
    except _HttpStatusError as exc:
        # Tolerate concurrent creation race (422 already_exists).
        if exc.status_code != 422:
            raise


def sync_github_issue(
    report: ReconciliationReport,
    *,
    label: str = DEFAULT_ISSUE_LABEL,
    github_token: str = "",
    http_json: HttpRequester = _default_http_json,
) -> dict[str, Any]:
    """Step A: Create or update the durable GitHub reconciliation issue."""
    token = github_token.strip()
    if not token:
        raise ReconcilerOperationalError(
            "--sync-github-issue requires a non-empty GITHUB_TOKEN."
        )
    cleaned_label = label.strip()
    if not cleaned_label:
        raise ReconcilerOperationalError("--issue-label must not be empty.")

    repo_path = _quote_repo_path(report.repo)
    headers = _github_headers(token)

    _ensure_github_label(
        repo_path=repo_path,
        label=cleaned_label,
        headers=headers,
        http_json=http_json,
    )

    list_query = urllib.parse.urlencode(
        {"labels": cleaned_label, "state": "all", "per_page": "20"}
    )
    list_url = f"{API_ROOT}/repos/{repo_path}/issues?{list_query}"
    validate_https_url(list_url, expected_host=GITHUB_HOST)
    raw_issues = http_json("GET", list_url, headers, None)
    if not isinstance(raw_issues, list):
        raise ReconcilerOperationalError(
            f"Unexpected GitHub issues list response shape: {type(raw_issues).__name__}"
        )

    trusted_issues: list[Mapping[str, Any]] = []
    for item in raw_issues:
        if isinstance(item, Mapping) and is_trusted_issue_author(item):
            if isinstance(item.get("number"), int) and not isinstance(
                item.get("number"), bool
            ):
                trusted_issues.append(item)

    trusted_issues.sort(
        key=lambda item: (
            0 if item.get("state") == "open" else 1,
            -int(item["number"]),
        )
    )
    existing = trusted_issues[0] if trusted_issues else None

    has_violations = len(report.violations) > 0
    title = (
        f"[POAM-2026-171] Post-merge required-check reconciliation: "
        f"FAIL ({len(report.violations)} violation(s) on {report.ref})"
        if has_violations
        else f"[POAM-2026-171] Post-merge required-check reconciliation: PASS ({report.ref})"
    )
    body = render_issue_body(report)

    if existing is None:
        create_url = f"{API_ROOT}/repos/{repo_path}/issues"
        validate_https_url(create_url, expected_host=GITHUB_HOST)
        created = http_json(
            "POST",
            create_url,
            headers,
            {
                "title": title,
                "body": body,
                "labels": [cleaned_label],
            },
        )
        if not isinstance(created, Mapping) or not isinstance(
            created.get("number"), int
        ):
            raise ReconcilerOperationalError(
                "GitHub issue creation returned an unexpected response shape."
            )
        issue_number = int(created["number"])
        issue_url = str(created.get("html_url") or created.get("url") or "")
        final_state = "open"
        if not has_violations:
            patch_url = f"{API_ROOT}/repos/{repo_path}/issues/{issue_number}"
            validate_https_url(patch_url, expected_host=GITHUB_HOST)
            closed = http_json(
                "PATCH",
                patch_url,
                headers,
                {
                    "state": "closed",
                    "state_reason": "completed",
                },
            )
            if isinstance(closed, Mapping):
                issue_url = str(closed.get("html_url") or issue_url)
            final_state = "closed"
        return {
            "action": "created",
            "issue_number": issue_number,
            "issue_url": issue_url,
            "state": final_state,
        }

    issue_number = int(existing["number"])
    current_state = str(existing.get("state") or "")
    patch_payload: dict[str, Any] = {
        "title": title,
        "body": body,
    }
    if has_violations and current_state != "open":
        patch_payload["state"] = "open"
        final_state = "open"
    elif has_violations:
        final_state = "open"
    elif current_state == "open":
        patch_payload["state"] = "closed"
        patch_payload["state_reason"] = "completed"
        final_state = "closed"
    else:
        final_state = "closed"

    patch_url = f"{API_ROOT}/repos/{repo_path}/issues/{issue_number}"
    validate_https_url(patch_url, expected_host=GITHUB_HOST)
    updated = http_json("PATCH", patch_url, headers, patch_payload)
    if not isinstance(updated, Mapping):
        raise ReconcilerOperationalError(
            f"GitHub issue #{issue_number} PATCH returned an unexpected shape."
        )
    issue_url = str(
        updated.get("html_url")
        or existing.get("html_url")
        or updated.get("url")
        or existing.get("url")
        or ""
    )
    return {
        "action": "updated",
        "issue_number": issue_number,
        "issue_url": issue_url,
        "state": final_state,
    }


def _normalize_topic_path(project: str, topic: str) -> str:
    cleaned = topic.strip()
    if not cleaned:
        raise ReconcilerOperationalError("Empty --pubsub-topic.")
    if cleaned.startswith("projects/"):
        parts = cleaned.split("/")
        if len(parts) != 4 or parts[0] != "projects" or parts[2] != "topics":
            raise ReconcilerOperationalError(
                f"Malformed Pub/Sub topic resource path: {topic!r}"
            )
        return (
            f"projects/{urllib.parse.quote(parts[1], safe='')}"
            f"/topics/{urllib.parse.quote(parts[3], safe='')}"
        )
    if not project.strip():
        raise ReconcilerOperationalError(
            "--gcp-project is required when --pubsub-topic is a short topic name."
        )
    return (
        f"projects/{urllib.parse.quote(project.strip(), safe='')}"
        f"/topics/{urllib.parse.quote(cleaned, safe='')}"
    )


def _publish_pubsub_envelope(
    *,
    topic_path: str,
    token: str,
    envelope: Mapping[str, Any],
    attributes: Mapping[str, str],
    http_json: HttpRequester,
) -> str:
    encoded = base64.b64encode(
        json.dumps(envelope, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    url = f"{PUBSUB_API_BASE}/{topic_path}:publish"
    validate_https_url(url, expected_host=PUBSUB_HOST)
    resp = http_json(
        "POST",
        url,
        _gcp_headers(token),
        {
            "messages": [
                {
                    "data": encoded,
                    "attributes": dict(attributes),
                }
            ]
        },
    )
    msg_ids = resp.get("messageIds") if isinstance(resp, Mapping) else None
    if not isinstance(msg_ids, list) or not msg_ids or not str(msg_ids[0]).strip():
        raise ReconcilerOperationalError(
            f"Pub/Sub publish on {topic_path!r} returned no messageIds: {resp!r}"
        )
    return str(msg_ids[0])


def _write_reconciler_heartbeat_metric(
    *,
    project: str,
    repo: str,
    ref: str,
    last_checked: str,
    token: str,
    http_json: HttpRequester,
) -> None:
    cleaned_project = project.strip()
    if not cleaned_project:
        raise ReconcilerOperationalError(
            "--gcp-project is required to write the Cloud Monitoring heartbeat metric."
        )
    normalized_ref = ref.removeprefix("refs/heads/")
    url = (
        f"{MONITORING_API_BASE}/projects/"
        f"{urllib.parse.quote(cleaned_project, safe='')}/timeSeries"
    )
    validate_https_url(url, expected_host=MONITORING_HOST)
    payload = {
        "timeSeries": [
            {
                "metric": {
                    "type": RECONCILER_HEARTBEAT_METRIC_TYPE,
                    "labels": {
                        "repo": repo,
                        "ref": normalized_ref,
                    },
                },
                "resource": {
                    "type": "global",
                    "labels": {"project_id": cleaned_project},
                },
                "points": [
                    {
                        "interval": {"endTime": last_checked},
                        "value": {"int64Value": "1"},
                    }
                ],
            }
        ]
    }
    http_json("POST", url, _gcp_headers(token), payload)


def deliver_gcp_sinks(
    report: ReconciliationReport,
    *,
    gcp_project: str,
    pubsub_topic: str,
    issue_url: str = "",
    gcp_token: str | None = None,
    http_json: HttpRequester = _default_http_json,
) -> dict[str, Any]:
    """Step B: Publish heartbeat (+ violation alert) to Pub/Sub and write Cloud Monitoring gauge."""
    cleaned_project = gcp_project.strip()
    cleaned_topic = pubsub_topic.strip()
    if not cleaned_project or not cleaned_topic:
        raise ReconcilerOperationalError(
            "GCP delivery requires both --gcp-project and --pubsub-topic."
        )

    token = (
        gcp_token.strip()
        if gcp_token is not None and gcp_token.strip()
        else resolve_gcp_access_token()
    )
    topic_path = _normalize_topic_path(cleaned_project, cleaned_topic)

    heartbeat_envelope: dict[str, Any] = {
        "source": "main_result_reconciler",
        "alert_type": "heartbeat",
        "last_checked": report.last_checked,
        "repo": report.repo,
        "ref": report.ref,
        "head_sha": report.head_sha,
        "newest_checked_sha": report.newest_checked_sha,
        "oldest_checked_sha": report.oldest_checked_sha,
        "floor_sha": report.floor_sha or None,
        "stopped_at_floor_sha": report.stopped_at_floor_sha,
        "require_ledger_check": report.require_ledger_check,
        "expected_check_count": report.expected_check_count,
        "checked_commits": report.checked_commits,
        "in_grace_commits": report.in_grace_commits,
        "violation_count": len(report.violations),
    }
    if issue_url:
        heartbeat_envelope["issue_url"] = issue_url

    heartbeat_msg_id = _publish_pubsub_envelope(
        topic_path=topic_path,
        token=token,
        envelope=heartbeat_envelope,
        attributes={
            "source": "main_result_reconciler",
            "alert_type": "heartbeat",
            "ref": report.ref,
            "head_sha": report.head_sha,
        },
        http_json=http_json,
    )

    violation_msg_id: str | None = None
    if report.violations:
        violation_envelope: dict[str, Any] = {
            "source": "main_result_reconciler",
            "alert_type": "main_check_violation",
            "severity": "CRITICAL",
            "last_checked": report.last_checked,
            "repo": report.repo,
            "ref": report.ref,
            "head_sha": report.head_sha,
            "newest_checked_sha": report.newest_checked_sha,
            "oldest_checked_sha": report.oldest_checked_sha,
            "require_ledger_check": report.require_ledger_check,
            "expected_check_count": report.expected_check_count,
            "violation_count": len(report.violations),
            "violations": [v.to_dict() for v in report.violations],
            "issue_url": issue_url,
        }
        violation_msg_id = _publish_pubsub_envelope(
            topic_path=topic_path,
            token=token,
            envelope=violation_envelope,
            attributes={
                "source": "main_result_reconciler",
                "alert_type": "main_check_violation",
                "severity": "CRITICAL",
                "ref": report.ref,
                "head_sha": report.head_sha,
            },
            http_json=http_json,
        )

    _write_reconciler_heartbeat_metric(
        project=cleaned_project,
        repo=report.repo,
        ref=report.ref,
        last_checked=report.last_checked,
        token=token,
        http_json=http_json,
    )

    return {
        "pubsub_topic": topic_path,
        "heartbeat_message_id": heartbeat_msg_id,
        "violation_message_id": violation_msg_id,
        "monitoring_metric_written": True,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile post-merge required status check results on main and "
            "deliver heartbeats/violations to a durable GitHub issue and GCP sinks "
            "(POAM-2026-171)."
        )
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO,
        help=f"GitHub OWNER/NAME repository (default: {DEFAULT_REPO}).",
    )
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help=f"Git branch or ref to walk (default: {DEFAULT_REF}).",
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=DEFAULT_MAX_COMMITS,
        help=f"Maximum commits to walk on --ref (default: {DEFAULT_MAX_COMMITS}).",
    )
    parser.add_argument(
        "--grace-minutes",
        type=int,
        default=DEFAULT_GRACE_MINUTES,
        help=(
            "Skip commits whose committer timestamp is newer than N minutes "
            f"(default: {DEFAULT_GRACE_MINUTES})."
        ),
    )
    parser.add_argument(
        "--floor-sha",
        default=os.environ.get("CAGE_MAIN_RECONCILER_FLOOR_SHA", "").strip(),
        help=(
            "Optional exclusive lower-bound commit SHA (env: "
            "CAGE_MAIN_RECONCILER_FLOOR_SHA); commit walking stops before this SHA."
        ),
    )
    parser.add_argument(
        "--require-ledger-check",
        dest="require_ledger_check",
        action="store_true",
        default=True,
        help=(
            "Require post-merge review-bypass ledger check "
            "`Record an unreviewed merge` (default: ON)."
        ),
    )
    parser.add_argument(
        "--no-ledger-check",
        "--skip-ledger-check",
        dest="require_ledger_check",
        action="store_false",
        help=(
            "Omit `Record an unreviewed merge` when probing a synthetic non-PR "
            "branch or commits predating d2a0b516."
        ),
    )
    parser.add_argument(
        "--sync-github-issue",
        action="store_true",
        help="Step A: create/update/close the durable GitHub reconciliation issue.",
    )
    parser.add_argument(
        "--issue-label",
        default=DEFAULT_ISSUE_LABEL,
        help=f"GitHub issue label for reconciliation state (default: {DEFAULT_ISSUE_LABEL}).",
    )
    parser.add_argument(
        "--pubsub-topic",
        default="",
        help="Step B: Cloud Pub/Sub topic name or projects/<p>/topics/<t> path.",
    )
    parser.add_argument(
        "--gcp-project",
        default="",
        help="Step B: GCP project ID for Pub/Sub and Cloud Monitoring heartbeat.",
    )
    parser.add_argument(
        "--require-gcp-delivery",
        action="store_true",
        help="Fail closed (exit 2) unless both --gcp-project and --pubsub-topic deliver.",
    )
    return parser


def run_reconciler(
    args: argparse.Namespace,
    *,
    github_token: str | None = None,
    gcp_token: str | None = None,
    now: datetime | None = None,
    http_json: HttpRequester = _default_http_json,
) -> int:
    """Execute reconciliation, Step A GitHub issue sync, and Step B GCP delivery."""
    gh_tok = (
        github_token if github_token is not None else os.environ.get("GITHUB_TOKEN", "")
    )
    try:
        report = reconcile_commits(
            repo=args.repo,
            ref=args.ref,
            max_commits=args.max_commits,
            grace_minutes=args.grace_minutes,
            floor_sha=args.floor_sha,
            require_ledger_check=args.require_ledger_check,
            github_token=gh_tok,
            now=now,
            http_json=http_json,
        )

        # Step A MUST execute before Step B so that if GCP infrastructure is torn
        # down or unreachable, the durable GitHub issue is updated first.
        issue_summary: dict[str, Any] | None = None
        issue_url = ""
        if args.sync_github_issue:
            issue_summary = sync_github_issue(
                report,
                label=args.issue_label,
                github_token=gh_tok,
                http_json=http_json,
            )
            issue_url = str(issue_summary.get("issue_url") or "")

        gcp_summary: dict[str, Any] | None = None
        wants_gcp = (
            args.require_gcp_delivery
            or bool(args.pubsub_topic.strip())
            or bool(args.gcp_project.strip())
        )
        if wants_gcp:
            gcp_summary = deliver_gcp_sinks(
                report,
                gcp_project=args.gcp_project,
                pubsub_topic=args.pubsub_topic,
                issue_url=issue_url,
                gcp_token=gcp_token,
                http_json=http_json,
            )
    except ReconcilerOperationalError as exc:
        print(
            json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2

    output = {
        "status": "FAIL" if report.violations else "PASS",
        "repo": report.repo,
        "ref": report.ref,
        "head_sha": report.head_sha,
        "newest_checked_sha": report.newest_checked_sha,
        "oldest_checked_sha": report.oldest_checked_sha,
        "floor_sha": report.floor_sha or None,
        "require_ledger_check": report.require_ledger_check,
        "expected_check_count": report.expected_check_count,
        "last_checked": report.last_checked,
        "checked_commits": report.checked_commits,
        "in_grace_commits": report.in_grace_commits,
        "stopped_at_floor_sha": report.stopped_at_floor_sha,
        "violation_count": len(report.violations),
        "violations": [v.to_dict() for v in report.violations],
        "github_issue": issue_summary,
        "gcp_delivery": gcp_summary,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if report.violations else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_reconciler(args)


if __name__ == "__main__":
    sys.exit(main())
