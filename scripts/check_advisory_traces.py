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

"""Verify published GitHub Security Advisory fix traces in ``SECURITY.md``.

Two invariants prevent silent drift between GitHub's published security
advisories and the in-repository fix-trace register in ``SECURITY.md``:

1. **Git ancestry (offline & CI):** Every row in the ``## Security Advisories``
   table of ``SECURITY.md`` carries a valid GHSA identifier, date, severity, and
   at least one commit SHA that resolves in git and is an ancestor of ``main``.
2. **Bidirectional GitHub parity (``--verify-github``):** Every advisory returned
   by ``GET /repos/{owner}/{repo}/security-advisories?state=published`` has a
   matching row in ``SECURITY.md`` (no missing advisories, no unpublished/withdrawn
   rows), with matching publication date, severity, and fix-commit SHA prefix in
   the GitHub advisory body.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_REPO = "google/cybernetic-agent-governance-engine"
MIN_PUBLISHED_ADVISORIES = 10

_GHSA_RE = re.compile(
    r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$"
)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA_TOKEN_RE = re.compile(r"\b([0-9a-f]{7,40})\b")
_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class AdvisoryTraceError(RuntimeError):
    """Raised when ``SECURITY.md`` advisory traces fail structural, git, or API checks."""


@dataclass(frozen=True)
class AdvisoryTableRow:
    """One parsed row from the ``## Security Advisories`` table in ``SECURITY.md``."""

    ghsa_id: str
    published: str
    severity: str
    fix_shas: tuple[str, ...]
    summary: str
    line_no: int


@dataclass(frozen=True)
class PublishedAdvisory:
    """One published advisory record returned by GitHub's REST API."""

    ghsa_id: str
    published_date: str
    severity: str
    description: str


def _strip_code_ticks(cell: str) -> str:
    val = cell.strip()
    if len(val) >= 2 and val.startswith("`") and val.endswith("`"):
        return val[1:-1].strip()
    return val


def _split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    cells: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in stripped:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "|":
            cells.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


def parse_security_md_advisories(
    security_md: Path,
    *,
    min_rows: int = MIN_PUBLISHED_ADVISORIES,
) -> list[AdvisoryTableRow]:
    """Parse and validate the ``## Security Advisories`` table in *security_md*."""
    if not security_md.is_file():
        raise AdvisoryTraceError(f"SECURITY.md not found at {security_md}")

    lines = security_md.read_text(encoding="utf-8").splitlines()
    in_section = False
    table_lines: list[tuple[int, str]] = []
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped == "## Security Advisories":
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if in_section and stripped.startswith("|"):
            table_lines.append((idx, stripped))

    if len(table_lines) < 3:
        raise AdvisoryTraceError(
            f"{security_md}: missing markdown advisory table under '## Security Advisories'"
        )

    header_line_no, header_raw = table_lines[0]
    headers = [c.replace("`", "").strip() for c in _split_markdown_row(header_raw)]
    expected_headers = ["Advisory", "Published", "Severity", "Fix on main", "Summary"]
    if headers != expected_headers:
        raise AdvisoryTraceError(
            f"{security_md}:{header_line_no}: expected table headers {expected_headers}, got {headers}"
        )

    rows: list[AdvisoryTableRow] = []
    seen_ids: set[str] = set()
    for line_no, raw_row in table_lines[2:]:
        cells = _split_markdown_row(raw_row)
        if len(cells) != 5:
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: expected 5 columns, got {len(cells)}"
            )
        ghsa_id = _strip_code_ticks(cells[0])
        published = _strip_code_ticks(cells[1])
        severity = _strip_code_ticks(cells[2]).lower()
        fix_cell = cells[3]
        summary = cells[4].strip()

        if not _GHSA_RE.match(ghsa_id):
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: invalid GHSA ID {ghsa_id!r}"
            )
        if ghsa_id in seen_ids:
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: duplicate GHSA row {ghsa_id}"
            )
        seen_ids.add(ghsa_id)

        if not _DATE_RE.match(published):
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: {ghsa_id} invalid published date {published!r}"
            )
        if severity not in _VALID_SEVERITIES:
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: {ghsa_id} invalid severity {cells[2]!r}"
            )
        shas = tuple(_SHA_TOKEN_RE.findall(fix_cell))
        if not shas:
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: {ghsa_id} 'Fix on main' cell carries no commit SHA: {fix_cell!r}"
            )
        if not summary:
            raise AdvisoryTraceError(
                f"{security_md}:{line_no}: {ghsa_id} summary column must not be empty"
            )
        rows.append(
            AdvisoryTableRow(
                ghsa_id=ghsa_id,
                published=published,
                severity=severity,
                fix_shas=shas,
                summary=summary,
                line_no=line_no,
            )
        )

    if len(rows) < min_rows:
        raise AdvisoryTraceError(
            f"{security_md}: parsed {len(rows)} advisory row(s), below non-vacuity floor of {min_rows}"
        )
    return rows


def _run_git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )


def resolve_main_commit(
    repo_root: Path, explicit_ref: str | None = None
) -> tuple[str, str]:
    """Resolve the canonical ``main`` commit OID in *repo_root*, failing closed on shallow clones."""
    shallow = _run_git(repo_root, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0:
        raise AdvisoryTraceError(
            f"Not a git repository or git failed in {repo_root}: {shallow.stderr.strip()}"
        )
    if shallow.stdout.strip() == "true":
        raise AdvisoryTraceError(
            "Shallow git clone detected; fetch full history (fetch-depth: 0) to verify main ancestry"
        )

    if explicit_ref:
        resolved = _run_git(
            repo_root, "rev-parse", "--verify", "--quiet", f"{explicit_ref}^{{commit}}"
        )
        if resolved.returncode != 0:
            raise AdvisoryTraceError(
                f"Cannot resolve explicit main ref {explicit_ref!r}"
            )
        return explicit_ref, resolved.stdout.strip()

    candidates: list[tuple[str, str]] = []
    for ref in ("refs/remotes/origin/main", "refs/heads/main"):
        res = _run_git(
            repo_root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"
        )
        if res.returncode == 0 and res.stdout.strip():
            candidates.append((ref, res.stdout.strip()))

    if not candidates:
        raise AdvisoryTraceError(
            "Neither refs/remotes/origin/main nor refs/heads/main exists; cannot verify main ancestry"
        )
    if len(candidates) == 1:
        return candidates[0]

    (ref_a, oid_a), (ref_b, oid_b) = candidates[0], candidates[1]
    if oid_a == oid_b:
        return ref_a, oid_a
    # If local main lags behind origin/main (or vice versa), select the newer tip on the same lineage.
    if _run_git(repo_root, "merge-base", "--is-ancestor", oid_b, oid_a).returncode == 0:
        return ref_a, oid_a
    if _run_git(repo_root, "merge-base", "--is-ancestor", oid_a, oid_b).returncode == 0:
        return ref_b, oid_b
    return ref_a, oid_a


def verify_git_ancestry(
    rows: list[AdvisoryTableRow],
    repo_root: Path,
    *,
    main_ref: str | None = None,
) -> tuple[str, dict[str, tuple[str, ...]]]:
    """Verify every SHA in *rows* resolves to a commit that is an ancestor of ``main``."""
    resolved_ref, main_oid = resolve_main_commit(repo_root, explicit_ref=main_ref)
    errors: list[str] = []
    resolved_by_ghsa: dict[str, tuple[str, ...]] = {}

    for row in rows:
        full_oids: list[str] = []
        for sha in row.fix_shas:
            rev = _run_git(
                repo_root, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"
            )
            if rev.returncode != 0 or not rev.stdout.strip():
                errors.append(
                    f"line {row.line_no} ({row.ghsa_id}): commit {sha!r} does not exist in git"
                )
                continue
            full_oid = rev.stdout.strip()
            anc = _run_git(repo_root, "merge-base", "--is-ancestor", full_oid, main_oid)
            if anc.returncode != 0:
                errors.append(
                    f"line {row.line_no} ({row.ghsa_id}): commit {sha} ({full_oid[:12]}) "
                    f"is NOT an ancestor of {resolved_ref} ({main_oid[:12]})"
                )
                continue
            full_oids.append(full_oid)
        resolved_by_ghsa[row.ghsa_id] = tuple(full_oids)

    if errors:
        raise AdvisoryTraceError(
            "Advisory fix-trace git ancestry check failed:\n  - "
            + "\n  - ".join(errors)
        )
    return resolved_ref, resolved_by_ghsa


def _validate_github_api_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise AdvisoryTraceError(
            f"Refusing non-GitHub-API URL {url!r} (scheme={parsed.scheme!r}, host={parsed.hostname!r})"
        )
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query = f"{path_and_query}?{parsed.query}"
    return path_and_query


def _extract_next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header)
    return match.group(1) if match else None


def fetch_published_advisories(
    repo: str = DEFAULT_REPO,
    *,
    timeout_s: float = 15.0,
) -> list[PublishedAdvisory]:
    """Fetch all ``state=published`` repository security advisories from GitHub's REST API."""
    if not _REPO_SLUG_RE.match(repo):
        raise AdvisoryTraceError(f"Invalid GitHub repository slug {repo!r}")

    token = (
        os.environ.get("GH_TOKEN", "").strip()
        or os.environ.get("GITHUB_TOKEN", "").strip()
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "cage-check-advisory-traces",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    next_url: str | None = (
        f"https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"
    )
    out: list[PublishedAdvisory] = []
    pages = 0

    while next_url is not None:
        pages += 1
        if pages > 20:
            raise AdvisoryTraceError(
                "Exceeded 20 pagination pages querying GitHub advisories"
            )
        request_target = _validate_github_api_url(next_url)
        conn = http.client.HTTPSConnection("api.github.com", timeout=timeout_s)
        try:
            conn.request("GET", request_target, headers=headers)
            resp = conn.getresponse()
            raw_body = resp.read().decode("utf-8")
            status_code = resp.status
            link_header = resp.getheader("Link")
        except OSError as exc:
            raise AdvisoryTraceError(
                f"Failed to reach GitHub Security Advisories API for {repo}: {exc}"
            ) from exc
        finally:
            conn.close()

        if status_code >= 400:
            raise AdvisoryTraceError(
                f"GitHub Security Advisories API returned HTTP {status_code} for {repo}"
            )

        try:
            payload: Any = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise AdvisoryTraceError(
                "Malformed JSON from GitHub Security Advisories API"
            ) from exc
        if not isinstance(payload, list):
            raise AdvisoryTraceError(
                "Expected JSON list from GitHub Security Advisories API"
            )

        for entry in payload:
            if not isinstance(entry, dict):
                raise AdvisoryTraceError(
                    "Expected JSON object advisory entry from GitHub API"
                )
            ghsa_id = str(entry.get("ghsa_id") or "").strip()
            published_at = str(entry.get("published_at") or "").strip()
            severity = str(entry.get("severity") or "").strip().lower()
            description = str(entry.get("description") or "")
            if not _GHSA_RE.match(ghsa_id) or len(published_at) < 10:
                raise AdvisoryTraceError(
                    f"Unexpected advisory record shape from GitHub API: ghsa_id={ghsa_id!r}"
                )
            out.append(
                PublishedAdvisory(
                    ghsa_id=ghsa_id,
                    published_date=published_at[:10],
                    severity=severity,
                    description=description,
                )
            )
        next_url = _extract_next_link(link_header)

    return out


def verify_github_parity(
    rows: list[AdvisoryTableRow],
    published: list[PublishedAdvisory],
) -> None:
    """Verify 1-to-1 parity and metadata/SHA agreement between ``SECURITY.md`` and GitHub."""
    by_table = {row.ghsa_id: row for row in rows}
    by_api = {adv.ghsa_id: adv for adv in published}

    errors: list[str] = []
    missing_in_table = sorted(by_api.keys() - by_table.keys())
    if missing_in_table:
        errors.append(
            "Published on GitHub but missing from SECURITY.md ## Security Advisories: "
            + ", ".join(missing_in_table)
        )

    extra_in_table = sorted(by_table.keys() - by_api.keys())
    if extra_in_table:
        errors.append(
            "Listed in SECURITY.md ## Security Advisories but not published on GitHub: "
            + ", ".join(extra_in_table)
        )

    for ghsa_id in sorted(by_table.keys() & by_api.keys()):
        row = by_table[ghsa_id]
        adv = by_api[ghsa_id]
        if row.published != adv.published_date:
            errors.append(
                f"{ghsa_id}: SECURITY.md Published={row.published!r} != GitHub published_at={adv.published_date!r}"
            )
        if row.severity != adv.severity:
            errors.append(
                f"{ghsa_id}: SECURITY.md Severity={row.severity!r} != GitHub severity={adv.severity!r}"
            )
        desc_lower = adv.description.lower()
        if not any(sha[:7].lower() in desc_lower for sha in row.fix_shas):
            errors.append(
                f"{ghsa_id}: none of SECURITY.md fix SHA(s) {list(row.fix_shas)} appear in the GitHub advisory description"
            )

    if errors:
        raise AdvisoryTraceError(
            "GitHub Security Advisory parity check failed:\n  - "
            + "\n  - ".join(errors)
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing SECURITY.md and .git",
    )
    parser.add_argument(
        "--main-ref",
        default=None,
        help="Explicit git ref to treat as main (default: origin/main or main)",
    )
    parser.add_argument(
        "--verify-github",
        action="store_true",
        help="Also query GitHub's security-advisories API and verify 1-to-1 parity",
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help=f"GitHub OWNER/REPO slug for --verify-github (default: {DEFAULT_REPO})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each verified advisory row",
    )
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    security_md = repo_root / "SECURITY.md"

    try:
        rows = parse_security_md_advisories(security_md)
        resolved_ref, resolved_oids = verify_git_ancestry(
            rows, repo_root, main_ref=args.main_ref
        )
        if args.verify_github:
            published = fetch_published_advisories(args.repo)
            verify_github_parity(rows, published)
    except AdvisoryTraceError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        for row in rows:
            oids = ", ".join(o[:12] for o in resolved_oids[row.ghsa_id])
            print(
                f"  • {row.ghsa_id} ({row.published}, {row.severity}): "
                f"ancestor of {resolved_ref} via [{oids}]"
            )
    mode = (
        f"git ancestry ({resolved_ref}) + live GitHub API ({args.repo})"
        if args.verify_github
        else f"git ancestry ({resolved_ref})"
    )
    print(
        f"✅ Advisory fix-trace check passed: {len(rows)} advisory row(s) verified via {mode}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
