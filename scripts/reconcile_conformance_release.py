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

"""Scheduled conformance release & GHCR artifact staleness reconciler.

Pure Python 3.12 stdlib script (zero third-party imports) safe to execute in
minimal GitHub Actions jobs without installing PyPI dependencies.

Detects drift between ``main`` and the published ``cage-conformance`` release
artifacts (GitHub Release wheels/sdists and GHCR container manifests):

1. **Tag vs. ``main`` watch-path divergence:** Finds the latest semver
   ``conformance-v<X.Y.Z>`` tag and checks whether any commits on ``--ref``
   (default ``main``) after that tag touch ``proof/`` or
   ``packages/cage-conformance/``. Fails once the oldest unreleased commit
   exceeds ``--grace-hours`` (default ``72``), unless the watched trees are
   unchanged apart from ``[tool.cage.release].status`` in the package's
   ``pyproject.toml`` (the post-tag flip to ``"published"``).
2. **GitHub Release asset parity:** Verifies the GitHub Release for the latest
   ``conformance-v*`` tag carries both the wheel and sdist artifacts.
3. **GHCR digest & OCI revision parity:** Compares ``cage-conformance:latest``
   against ``cage-conformance:<version>`` on ``ghcr.io`` and checks
   ``org.opencontainers.image.revision`` in the OCI image config (required on
   releases ``>= 0.4.2`` or with ``--require-oci-revision``).
4. **Durable GitHub issue sink (``--sync-github-issue``):** Opens/updates a
   trusted-actor issue keyed by ``--issue-label`` (default
   ``conformance-release-drift``) when findings exist and closes it when clean.

Exit codes:
  - ``0``: no drift or artifact violations detected.
  - ``1``: one or more release/artifact drift findings detected.
  - ``2``: git, API, or operational failure (fail-closed).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
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

import tomllib

DEFAULT_REPO = "google/cybernetic-agent-governance-engine"
DEFAULT_REF = "main"
DEFAULT_GRACE_HOURS = 72.0
DEFAULT_ISSUE_LABEL = "conformance-release-drift"
DEFAULT_ISSUE_LABEL_COLOR = "d93f0b"
DEFAULT_ISSUE_LABEL_DESCRIPTION = (
    "Durable conformance-v* tag, wheel, and GHCR release drift status"
)
CONFORMANCE_TAG_PREFIX = "conformance-v"
CONFORMANCE_WATCH_PATHS: tuple[str, ...] = ("proof/", "packages/cage-conformance/")
CONFORMANCE_PYPROJECT_PATH = "packages/cage-conformance/pyproject.toml"
OCI_REVISION_ENFORCED_MIN_SEMVER: tuple[int, int, int] = (0, 4, 2)

GITHUB_API_HOST = "api.github.com"
GHCR_HOST = "ghcr.io"
ALLOWED_HTTPS_HOSTS: frozenset[str] = frozenset({GITHUB_API_HOST, GHCR_HOST})
HTTP_TIMEOUT_SECONDS = 30.0
GIT_TIMEOUT_SECONDS = 20.0

TRUSTED_ISSUE_BOT_LOGINS: frozenset[str] = frozenset({"github-actions[bot]"})
TRUSTED_ISSUE_ASSOCIATIONS: frozenset[str] = frozenset(
    {"OWNER", "MEMBER", "COLLABORATOR"}
)

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class ReconcilerOperationalError(RuntimeError):
    """Raised on git, API, or configuration error (exit code 2)."""


@dataclass(frozen=True)
class WatchCommit:
    """A commit on ``--ref`` touching a conformance-watched path after the latest tag."""

    sha: str
    committed_at: int
    subject: str


@dataclass(frozen=True)
class DriftFinding:
    """A single release or artifact staleness finding."""

    code: str
    detail: str


@dataclass(frozen=True)
class HttpResult:
    """Minimal HTTP response returned by ``HttpClient``."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


HttpClient = Callable[[str, str, Mapping[str, str], bytes | None], HttpResult]
GitRunner = Callable[[Sequence[str]], str]


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    match = _SEMVER_RE.fullmatch(version.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _validate_https_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_HTTPS_HOSTS:
        raise ReconcilerOperationalError(
            f"Refusing non-allowlisted URL {url!r}; allowed hosts={sorted(ALLOWED_HTTPS_HOSTS)}"
        )
    return url


def _default_http_client(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None = None,
) -> HttpResult:
    _validate_https_url(url)
    req = urllib.request.Request(
        url=url,
        data=body,
        headers=dict(headers),
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(  # nosec B310  # https:// and host allowlist validated in _validate_https_url
            req, timeout=HTTP_TIMEOUT_SECONDS
        ) as resp:
            norm_headers = {k.lower(): v for k, v in resp.headers.items()}
            return HttpResult(
                status_code=int(resp.status),
                headers=norm_headers,
                body=resp.read(),
            )
    except urllib.error.HTTPError as exc:
        err_body = exc.read() if exc.fp is not None else b""
        norm_headers = (
            {k.lower(): v for k, v in exc.headers.items()}
            if exc.headers is not None
            else {}
        )
        return HttpResult(
            status_code=int(exc.code),
            headers=norm_headers,
            body=err_body,
        )
    except (OSError, urllib.error.URLError) as exc:
        raise ReconcilerOperationalError(f"HTTP {method} {url} failed: {exc}") from exc


def _make_git_runner(repo_root: Path) -> GitRunner:
    git_bin = shutil.which("git")
    if git_bin is None:
        raise ReconcilerOperationalError("git executable not found on PATH")

    def _run(args: Sequence[str]) -> str:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed git executable and argv
                [git_bin, *args],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReconcilerOperationalError(
                f"git {' '.join(args)} failed: {exc}"
            ) from exc
        if proc.returncode != 0:
            raise ReconcilerOperationalError(
                f"git {' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}"
            )
        return proc.stdout

    return _run


def select_latest_conformance_tag(
    tags: Sequence[str],
) -> tuple[str, tuple[int, int, int]]:
    """Return ``(tag_name, semver_tuple)`` for the highest ``conformance-v*`` semver tag."""
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for raw in tags:
        tag = raw.strip()
        if not tag.startswith(CONFORMANCE_TAG_PREFIX):
            continue
        parsed = _parse_semver(tag.removeprefix(CONFORMANCE_TAG_PREFIX))
        if parsed is not None:
            candidates.append((parsed, tag))
    if not candidates:
        raise ReconcilerOperationalError(
            f"No semver {CONFORMANCE_TAG_PREFIX}* tags found in repository"
        )
    best_semver, best_tag = max(candidates)
    return best_tag, best_semver


def list_watch_commits_since_tag(
    git_run: GitRunner,
    *,
    tag: str,
    ref: str,
    watch_paths: Sequence[str] = CONFORMANCE_WATCH_PATHS,
) -> list[WatchCommit]:
    """Return commits on ``ref`` after ``tag`` touching ``watch_paths``, oldest-last."""
    raw = git_run(
        [
            "log",
            "--format=%H\t%ct\t%s",
            f"{tag}..{ref}",
            "--",
            *watch_paths,
        ]
    )
    commits: list[WatchCommit] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3:
            raise ReconcilerOperationalError(f"Unexpected git log line: {line!r}")
        sha, ts_raw, subject = parts
        try:
            committed_at = int(ts_raw)
        except ValueError as exc:
            raise ReconcilerOperationalError(
                f"Invalid commit timestamp {ts_raw!r} for {sha}"
            ) from exc
        commits.append(WatchCommit(sha=sha, committed_at=committed_at, subject=subject))
    return commits


def _pyproject_without_release_status(raw: str) -> dict[str, Any]:
    """Parse a ``pyproject.toml`` and drop ``[tool.cage.release].status``."""
    data = tomllib.loads(raw)
    release = data.get("tool", {}).get("cage", {}).get("release")
    if isinstance(release, dict):
        release.pop("status", None)
    return data


def list_material_changed_paths(
    git_run: GitRunner,
    *,
    tag: str,
    ref: str,
    watch_paths: Sequence[str] = CONFORMANCE_WATCH_PATHS,
) -> list[str]:
    """Return watched paths whose content differs between ``tag`` and ``ref``.

    The package ``pyproject.toml`` is left out when the only difference is
    ``[tool.cage.release].status``: flipping it to ``"published"`` after the
    tag is cut changes nothing that ships. If either side cannot be read or
    parsed, the file counts as changed.
    """
    raw = git_run(["diff", "--name-only", "-z", tag, ref, "--", *watch_paths])
    paths = sorted(path for path in raw.split("\0") if path)
    if CONFORMANCE_PYPROJECT_PATH in paths:
        try:
            before = _pyproject_without_release_status(
                git_run(["show", f"{tag}:{CONFORMANCE_PYPROJECT_PATH}"])
            )
            after = _pyproject_without_release_status(
                git_run(["show", f"{ref}:{CONFORMANCE_PYPROJECT_PATH}"])
            )
        except (ReconcilerOperationalError, tomllib.TOMLDecodeError):
            return paths
        if before == after:
            paths.remove(CONFORMANCE_PYPROJECT_PATH)
    return paths


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cage-conformance-release-reconciler",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def check_release_assets(
    http_client: HttpClient,
    *,
    repo: str,
    tag: str,
    version: str,
    github_token: str | None,
) -> list[DriftFinding]:
    """Verify the GitHub Release for ``tag`` exists and attaches wheel + sdist."""
    url = f"https://{GITHUB_API_HOST}/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    resp = http_client("GET", url, _github_headers(github_token), None)
    if resp.status_code == 404:
        return [
            DriftFinding(
                "MISSING_GITHUB_RELEASE",
                f"GitHub Release for tag {tag!r} does not exist",
            )
        ]
    if resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"GitHub Release query for {tag!r} returned HTTP {resp.status_code}"
        )
    doc = resp.json()
    assets = doc.get("assets", []) if isinstance(doc, dict) else []
    names = {
        str(a.get("name", ""))
        for a in assets
        if isinstance(a, Mapping) and a.get("name")
    }
    expected_wheel = f"cage_conformance-{version}-py3-none-any.whl"
    expected_sdist = f"cage_conformance-{version}.tar.gz"
    missing = [name for name in (expected_wheel, expected_sdist) if name not in names]
    if missing:
        return [
            DriftFinding(
                "MISSING_RELEASE_ASSETS",
                f"GitHub Release {tag!r} is missing asset(s): {', '.join(missing)}",
            )
        ]
    return []


def _fetch_ghcr_pull_token(
    http_client: HttpClient,
    *,
    repo_lower: str,
    github_token: str | None,
) -> str:
    scope = urllib.parse.quote(
        f"repository:{repo_lower}/cage-conformance:pull", safe=""
    )
    url = f"https://{GHCR_HOST}/token?service={GHCR_HOST}&scope={scope}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if github_token:
        raw_basic = base64.b64encode(f"x-access-token:{github_token}".encode()).decode(
            "ascii"
        )
        headers["Authorization"] = f"Basic {raw_basic}"
    resp = http_client("GET", url, headers, None)
    if resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"GHCR token exchange failed with HTTP {resp.status_code}"
        )
    payload = resp.json()
    token = payload.get("token") if isinstance(payload, Mapping) else None
    if not isinstance(token, str) or not token.strip():
        raise ReconcilerOperationalError("GHCR token response missing 'token'")
    return token.strip()


def _fetch_ghcr_manifest(
    http_client: HttpClient,
    *,
    repo_lower: str,
    reference: str,
    bearer_token: str,
) -> tuple[str, dict[str, Any]]:
    url = f"https://{GHCR_HOST}/v2/{repo_lower}/cage-conformance/manifests/{urllib.parse.quote(reference, safe=':')}"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": _MANIFEST_ACCEPT,
    }
    resp = http_client("GET", url, headers, None)
    if resp.status_code == 404:
        raise KeyError(reference)
    if resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"GHCR manifest GET {reference!r} returned HTTP {resp.status_code}"
        )
    digest = resp.headers.get("docker-content-digest") or (
        "sha256:" + hashlib.sha256(resp.body).hexdigest()
    )
    doc = resp.json()
    if not isinstance(doc, dict):
        raise ReconcilerOperationalError(
            f"GHCR manifest {reference!r} is not a JSON object"
        )
    return str(digest), doc


def _resolve_config_digest(
    http_client: HttpClient,
    *,
    repo_lower: str,
    manifest_doc: Mapping[str, Any],
    bearer_token: str,
) -> str | None:
    if isinstance(manifest_doc.get("config"), Mapping):
        digest = manifest_doc["config"].get("digest")
        return str(digest) if isinstance(digest, str) and digest else None

    sub_manifests = manifest_doc.get("manifests")
    if not isinstance(sub_manifests, list):
        return None
    chosen_digest: str | None = None
    for entry in sub_manifests:
        if not isinstance(entry, Mapping):
            continue
        platform = entry.get("platform")
        if (
            isinstance(platform, Mapping)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
        ):
            chosen_digest = str(entry.get("digest") or "")
            break
    if not chosen_digest:
        for entry in sub_manifests:
            if not isinstance(entry, Mapping):
                continue
            ann = entry.get("annotations")
            if (
                isinstance(ann, Mapping)
                and ann.get("vnd.docker.reference.type") == "attestation-manifest"
            ):
                continue
            cand = str(entry.get("digest") or "")
            if cand:
                chosen_digest = cand
                break
    if not chosen_digest:
        return None
    _, child_doc = _fetch_ghcr_manifest(
        http_client,
        repo_lower=repo_lower,
        reference=chosen_digest,
        bearer_token=bearer_token,
    )
    cfg = child_doc.get("config")
    if isinstance(cfg, Mapping) and isinstance(cfg.get("digest"), str):
        return str(cfg["digest"])
    return None


def check_ghcr_image(
    http_client: HttpClient,
    *,
    repo: str,
    version: str,
    semver: tuple[int, int, int],
    tag_sha: str,
    github_token: str | None,
    require_oci_revision: bool = False,
) -> tuple[list[DriftFinding], dict[str, str]]:
    """Verify GHCR ``:latest`` matches ``:<version>`` and carries matching OCI revision."""
    repo_lower = repo.lower()
    bearer = _fetch_ghcr_pull_token(
        http_client, repo_lower=repo_lower, github_token=github_token
    )
    findings: list[DriftFinding] = []
    meta: dict[str, str] = {}

    try:
        version_digest, version_manifest = _fetch_ghcr_manifest(
            http_client,
            repo_lower=repo_lower,
            reference=version,
            bearer_token=bearer,
        )
        meta["version_digest"] = version_digest
    except KeyError:
        findings.append(
            DriftFinding(
                "MISSING_GHCR_VERSION_TAG",
                f"GHCR image ghcr.io/{repo_lower}/cage-conformance:{version} does not exist",
            )
        )
        return findings, meta

    try:
        latest_digest, _ = _fetch_ghcr_manifest(
            http_client,
            repo_lower=repo_lower,
            reference="latest",
            bearer_token=bearer,
        )
        meta["latest_digest"] = latest_digest
    except KeyError:
        findings.append(
            DriftFinding(
                "MISSING_GHCR_LATEST_TAG",
                f"GHCR image ghcr.io/{repo_lower}/cage-conformance:latest does not exist",
            )
        )
        return findings, meta

    if latest_digest != version_digest:
        findings.append(
            DriftFinding(
                "GHCR_LATEST_DIGEST_MISMATCH",
                f"GHCR :latest digest {latest_digest} != :{version} digest {version_digest}",
            )
        )

    config_digest = _resolve_config_digest(
        http_client,
        repo_lower=repo_lower,
        manifest_doc=version_manifest,
        bearer_token=bearer,
    )
    if config_digest is None:
        findings.append(
            DriftFinding(
                "GHCR_UNREADABLE_CONFIG",
                f"Unable to locate OCI config blob for ghcr.io/{repo_lower}/cage-conformance:{version}",
            )
        )
        return findings, meta

    blob_url = (
        f"https://{GHCR_HOST}/v2/{repo_lower}/cage-conformance/blobs/"
        f"{urllib.parse.quote(config_digest, safe=':')}"
    )
    blob_resp = http_client(
        "GET",
        blob_url,
        {"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        None,
    )
    if blob_resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"GHCR config blob GET returned HTTP {blob_resp.status_code}"
        )
    cfg_doc = blob_resp.json()
    labels = (
        cfg_doc.get("config", {}).get("Labels", {})
        if isinstance(cfg_doc, Mapping)
        and isinstance(cfg_doc.get("config"), Mapping)
        and isinstance(cfg_doc["config"].get("Labels"), Mapping)
        else {}
    )
    revision = str(labels.get("org.opencontainers.image.revision") or "").strip()
    meta["oci_revision"] = revision or "<unset>"

    enforce_label = require_oci_revision or semver >= OCI_REVISION_ENFORCED_MIN_SEMVER
    if not revision:
        if enforce_label:
            findings.append(
                DriftFinding(
                    "GHCR_MISSING_REVISION_LABEL",
                    f"GHCR :{version} is missing org.opencontainers.image.revision label",
                )
            )
    elif not (tag_sha.startswith(revision) or revision.startswith(tag_sha)):
        findings.append(
            DriftFinding(
                "GHCR_REVISION_MISMATCH",
                f"GHCR :{version} org.opencontainers.image.revision={revision!r} "
                f"does not match tag commit {tag_sha}",
            )
        )

    return findings, meta


def _find_trusted_issue(
    http_client: HttpClient,
    *,
    repo: str,
    label: str,
    github_token: str,
) -> dict[str, Any] | None:
    encoded_label = urllib.parse.quote(label, safe="")
    url = (
        f"https://{GITHUB_API_HOST}/repos/{repo}/issues"
        f"?labels={encoded_label}&state=all&sort=updated&direction=desc&per_page=100"
    )
    resp = http_client("GET", url, _github_headers(github_token), None)
    if resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"Failed to list GitHub issues for label {label!r}: HTTP {resp.status_code}"
        )
    issues = resp.json()
    if not isinstance(issues, list):
        return None
    for issue in issues:
        if not isinstance(issue, Mapping) or "pull_request" in issue:
            continue
        user = issue.get("user")
        login = str(user.get("login", "")) if isinstance(user, Mapping) else ""
        assoc = str(issue.get("author_association", ""))
        if login in TRUSTED_ISSUE_BOT_LOGINS or assoc in TRUSTED_ISSUE_ASSOCIATIONS:
            return dict(issue)
    return None


def _ensure_label(
    http_client: HttpClient,
    *,
    repo: str,
    label: str,
    github_token: str,
) -> None:
    url = f"https://{GITHUB_API_HOST}/repos/{repo}/labels"
    payload = json.dumps(
        {
            "name": label,
            "color": DEFAULT_ISSUE_LABEL_COLOR,
            "description": DEFAULT_ISSUE_LABEL_DESCRIPTION,
        }
    ).encode("utf-8")
    resp = http_client(
        "POST",
        url,
        {**_github_headers(github_token), "Content-Type": "application/json"},
        payload,
    )
    if resp.status_code not in (201, 422):
        raise ReconcilerOperationalError(
            f"Failed to create label {label!r}: HTTP {resp.status_code}"
        )


def sync_github_issue(
    http_client: HttpClient,
    *,
    repo: str,
    label: str,
    github_token: str,
    status_report: Mapping[str, Any],
    findings: Sequence[DriftFinding],
) -> None:
    """Create/update the durable drift issue on violations, or close it on PASS."""
    _ensure_label(http_client, repo=repo, label=label, github_token=github_token)
    existing = _find_trusted_issue(
        http_client, repo=repo, label=label, github_token=github_token
    )
    checked_at = status_report["checked_at"]
    latest_tag = status_report["latest_tag"]
    behind_count = status_report["behind_commit_count"]
    status = "FAIL" if findings else "PASS"

    lines = [
        f"<!-- conformance-release-reconciler status={status} -->",
        f"**Status:** `{status}`  ",
        f"**Last Checked (UTC):** `{checked_at}`  ",
        f"**Latest Tag:** `{latest_tag}` (`{status_report['latest_tag_sha'][:12]}`)  ",
        f"**Ref Checked:** `{status_report['ref']}`  ",
        f"**Watch-Path Commits Since Tag:** `{behind_count}` (grace: `{status_report['grace_hours']}h`)  ",
        "",
    ]
    if findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Code | Detail |")
        lines.append("|---|---|")
        for f in findings:
            lines.append(f"| `{f.code}` | {f.detail} |")
        lines.append("")

    unreleased = status_report.get("unreleased_commits", [])
    if unreleased:
        lines.append(
            "### Unreleased Commits Touching `proof/` or `packages/cage-conformance/`"
        )
        lines.append("")
        for commit in unreleased[:20]:
            lines.append(
                f"- `{commit['sha'][:8]}` ({commit['committed_at_utc']}): {commit['subject']}"
            )
        if len(unreleased) > 20:
            lines.append(f"- ... (+{len(unreleased) - 20} more)")
        lines.append("")

    ghcr_meta = status_report.get("ghcr", {})
    if ghcr_meta:
        lines.append("### GHCR Metadata")
        lines.append("")
        for key, val in sorted(ghcr_meta.items()):
            lines.append(f"- `{key}`: `{val}`")

    body = "\n".join(lines)
    title = f"[Conformance Release Drift] {latest_tag} behind {status_report['ref']}"

    if existing is None:
        if not findings:
            return
        create_url = f"https://{GITHUB_API_HOST}/repos/{repo}/issues"
        payload = json.dumps({"title": title, "body": body, "labels": [label]}).encode(
            "utf-8"
        )
        resp = http_client(
            "POST",
            create_url,
            {**_github_headers(github_token), "Content-Type": "application/json"},
            payload,
        )
        if resp.status_code not in (200, 201):
            raise ReconcilerOperationalError(
                f"Failed to create drift issue: HTTP {resp.status_code}"
            )
        return

    issue_number = existing["number"]
    issue_state = existing.get("state")
    if not findings and issue_state == "closed":
        return

    patch_payload: dict[str, Any] = {"body": body}
    if findings:
        patch_payload["title"] = title
        patch_payload["state"] = "open"
    else:
        patch_payload["state"] = "closed"

    patch_url = f"https://{GITHUB_API_HOST}/repos/{repo}/issues/{issue_number}"
    resp = http_client(
        "PATCH",
        patch_url,
        {**_github_headers(github_token), "Content-Type": "application/json"},
        json.dumps(patch_payload).encode("utf-8"),
    )
    if resp.status_code != 200:
        raise ReconcilerOperationalError(
            f"Failed to update drift issue #{issue_number}: HTTP {resp.status_code}"
        )


def reconcile_conformance_release(
    *,
    repo_root: Path,
    repo: str = DEFAULT_REPO,
    ref: str = DEFAULT_REF,
    grace_hours: float = DEFAULT_GRACE_HOURS,
    check_release: bool = True,
    check_ghcr: bool = True,
    require_oci_revision: bool = False,
    github_token: str | None = None,
    now_epoch: int | None = None,
    git_run: GitRunner | None = None,
    http_client: HttpClient | None = None,
) -> tuple[list[DriftFinding], dict[str, Any]]:
    """Run tag-vs-main, GitHub Release, and GHCR staleness checks."""
    if not _REPO_SLUG_RE.fullmatch(repo):
        raise ReconcilerOperationalError(f"Invalid repository slug {repo!r}")
    if grace_hours < 0:
        raise ReconcilerOperationalError(f"grace_hours must be >= 0, got {grace_hours}")

    effective_git = git_run or _make_git_runner(repo_root)
    effective_http = http_client or _default_http_client
    effective_now = (
        int(datetime.now(timezone.utc).timestamp())
        if now_epoch is None
        else int(now_epoch)
    )

    tags_raw = effective_git(["tag", "-l", f"{CONFORMANCE_TAG_PREFIX}*"]).splitlines()
    latest_tag, latest_semver = select_latest_conformance_tag(tags_raw)
    version = latest_tag.removeprefix(CONFORMANCE_TAG_PREFIX)
    tag_sha = effective_git(["rev-list", "-n", "1", latest_tag]).strip()
    if not tag_sha:
        raise ReconcilerOperationalError(
            f"Unable to resolve commit for tag {latest_tag!r}"
        )

    unreleased = list_watch_commits_since_tag(
        effective_git, tag=latest_tag, ref=ref, watch_paths=CONFORMANCE_WATCH_PATHS
    )

    material_paths = (
        list_material_changed_paths(
            effective_git,
            tag=latest_tag,
            ref=ref,
            watch_paths=CONFORMANCE_WATCH_PATHS,
        )
        if unreleased
        else []
    )

    findings: list[DriftFinding] = []
    if unreleased and material_paths:
        oldest = min(unreleased, key=lambda c: c.committed_at)
        oldest_age_hours = max(0.0, (effective_now - oldest.committed_at) / 3600.0)
        if oldest_age_hours >= grace_hours:
            findings.append(
                DriftFinding(
                    "STALE_CONFORMANCE_RELEASE",
                    f"{len(unreleased)} commit(s) touched proof/ or packages/cage-conformance/ "
                    f"since {latest_tag} ({tag_sha[:8]}); oldest unreleased commit "
                    f"{oldest.sha[:8]} is {oldest_age_hours:.1f}h old (>= {grace_hours:.1f}h grace)",
                )
            )

    if check_release:
        findings.extend(
            check_release_assets(
                effective_http,
                repo=repo,
                tag=latest_tag,
                version=version,
                github_token=github_token,
            )
        )

    ghcr_meta: dict[str, str] = {}
    if check_ghcr:
        ghcr_findings, ghcr_meta = check_ghcr_image(
            effective_http,
            repo=repo,
            version=version,
            semver=latest_semver,
            tag_sha=tag_sha,
            github_token=github_token,
            require_oci_revision=require_oci_revision,
        )
        findings.extend(ghcr_findings)

    report = {
        "checked_at": datetime.fromtimestamp(effective_now, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "repo": repo,
        "ref": ref,
        "grace_hours": grace_hours,
        "latest_tag": latest_tag,
        "latest_tag_sha": tag_sha,
        "behind_commit_count": len(unreleased),
        "material_changed_paths": material_paths,
        "unreleased_commits": [
            {
                "sha": c.sha,
                "committed_at": c.committed_at,
                "committed_at_utc": datetime.fromtimestamp(
                    c.committed_at, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "subject": c.subject,
            }
            for c in unreleased
        ],
        "ghcr": ghcr_meta,
        "findings": [{"code": f.code, "detail": f.detail} for f in findings],
    }
    return findings, report


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check conformance-v* tag, GitHub Release, and GHCR staleness."
    )
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--grace-hours", type=float, default=DEFAULT_GRACE_HOURS)
    parser.add_argument("--issue-label", default=DEFAULT_ISSUE_LABEL)
    parser.add_argument("--skip-release-assets", action="store_true")
    parser.add_argument("--skip-ghcr", action="store_true")
    parser.add_argument("--require-oci-revision", action="store_true")
    parser.add_argument("--sync-github-issue", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent
    github_token = os.environ.get("GITHUB_TOKEN", "").strip() or None

    try:
        findings, report = reconcile_conformance_release(
            repo_root=repo_root,
            repo=args.repo,
            ref=args.ref,
            grace_hours=args.grace_hours,
            check_release=not args.skip_release_assets,
            check_ghcr=not args.skip_ghcr,
            require_oci_revision=args.require_oci_revision,
            github_token=github_token,
        )
        if args.sync_github_issue:
            if not github_token:
                raise ReconcilerOperationalError(
                    "--sync-github-issue requires GITHUB_TOKEN in environment"
                )
            sync_github_issue(
                _default_http_client,
                repo=args.repo,
                label=args.issue_label,
                github_token=github_token,
                status_report=report,
                findings=findings,
            )
    except ReconcilerOperationalError as exc:
        print(f"❌ operational error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"conformance-release-reconciler: tag={report['latest_tag']} "
            f"ref={report['ref']} behind={report['behind_commit_count']} "
            f"findings={len(findings)}"
        )
        for finding in findings:
            print(f"❌ [{finding.code}] {finding.detail}", file=sys.stderr)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
