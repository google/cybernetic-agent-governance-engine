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

"""Unit tests for ``scripts/check_advisory_traces.py``."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_advisory_traces.py"

_spec = importlib.util.spec_from_file_location("check_advisory_traces", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
sys.modules["check_advisory_traces"] = gate
_spec.loader.exec_module(gate)


def _init_git_repo(root: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    global_cfg = root / "gitconfig"
    global_cfg.write_text("", encoding="utf-8")
    env.update(
        HOME=str(root),
        GIT_CONFIG_GLOBAL=str(global_cfg),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Test",
        GIT_AUTHOR_EMAIL="test@example.com",
        GIT_COMMITTER_NAME="Test",
        GIT_COMMITTER_EMAIL="test@example.com",
    )
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], env=env, check=True)
    return env


def _git_commit(root: Path, env: dict[str, str], msg: str) -> str:
    subprocess.run(
        ["git", "commit", "-q", "--allow-empty", "-m", msg],
        cwd=root,
        env=env,
        check=True,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, env=env, text=True
    ).strip()


def _write_security_md(path: Path, rows: list[tuple[str, str, str, str, str]]) -> None:
    lines = [
        "# Security Policy",
        "",
        "## Security Advisories",
        "",
        "| Advisory | Published | Severity | Fix on `main` | Summary |",
        "|---|---|---|---|---|",
    ]
    for gid, pub, sev, fix_col, summary in rows:
        lines.append(f"| `{gid}` | `{pub}` | {sev} | {fix_col} | {summary} |")
    lines.extend(["", "## Reporting a Vulnerability", "", "Report privately."])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_real_repository_security_md_passes_ancestry_gate() -> None:
    """Committed SECURITY.md parses >=10 rows and every SHA is an ancestor of main/HEAD."""
    rows = gate.parse_security_md_advisories(REPO_ROOT / "SECURITY.md")
    assert len(rows) >= gate.MIN_PUBLISHED_ADVISORIES
    # Use HEAD when running inside a detached snapshot where main may lag or match HEAD
    _, resolved = gate.verify_git_ancestry(rows, REPO_ROOT, main_ref="HEAD")
    assert len(resolved) == len(rows)
    assert any(r.ghsa_id == "GHSA-c9j3-q7hh-p95m" for r in rows)


def test_non_ancestor_branch_commit_fails_closed(tmp_path: Path) -> None:
    """A commit that exists on a feature branch or orphan ref but NOT on main is rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = _init_git_repo(repo)
    main_sha = _git_commit(repo, env, "feat: baseline on main")

    subprocess.run(
        ["git", "checkout", "-q", "-b", "feat/unmerged"], cwd=repo, env=env, check=True
    )
    branch_only_sha = _git_commit(repo, env, "fix: not on main yet")

    sample_ids = [
        "GHSA-2222-3333-4444",
        "GHSA-3333-4444-5555",
        "GHSA-4444-5555-6666",
        "GHSA-5555-6666-7777",
        "GHSA-6666-7777-8888",
        "GHSA-7777-8888-9999",
        "GHSA-8888-9999-2222",
        "GHSA-9999-2222-3333",
        "GHSA-cccc-ffff-gggg",
        "GHSA-hhhh-jjjj-mmmm",
    ]
    sec_md = repo / "SECURITY.md"
    table_rows = [
        (gid, "2026-11-19", "Medium", f"`{main_sha[:8]}`", "Fixed issue")
        for gid in sample_ids[:-1]
    ]
    table_rows.append(
        (
            sample_ids[-1],
            "2026-11-20",
            "High",
            f"`{branch_only_sha[:8]}`",
            "Branch-only SHA",
        )
    )
    _write_security_md(sec_md, table_rows)

    parsed = gate.parse_security_md_advisories(sec_md)
    with pytest.raises(
        gate.AdvisoryTraceError, match="is NOT an ancestor of refs/heads/main"
    ):
        gate.verify_git_ancestry(parsed, repo)


def test_github_parity_catches_missing_extra_and_mismatched_rows(
    tmp_path: Path,
) -> None:
    """verify_github_parity fails on missing published GHSA, phantom row, or SHA/metadata drift."""
    sec_md = tmp_path / "SECURITY.md"
    gids = [
        "GHSA-2222-3333-4444",
        "GHSA-3333-4444-5555",
    ]
    _write_security_md(
        sec_md,
        [
            (gids[0], "2026-11-19", "Medium", "`dd27b66b` (`#815`)", "Summary A"),
            (gids[1], "2026-11-19", "High", "`c145a9cc` (`#813`)", "Summary B"),
        ],
    )
    rows = gate.parse_security_md_advisories(sec_md, min_rows=2)

    matching_api = [
        gate.PublishedAdvisory(
            ghsa_id=gids[0],
            published_date="2026-11-19",
            severity="medium",
            description="Fixed on main in dd27b66b (#815).",
        ),
        gate.PublishedAdvisory(
            ghsa_id=gids[1],
            published_date="2026-11-19",
            severity="high",
            description="Fixed on main in c145a9cc (#813).",
        ),
    ]
    gate.verify_github_parity(rows, matching_api)

    # 1. Published on GitHub, absent from SECURITY.md (exact GHSA-c9j3-q7hh-p95m failure mode)
    with pytest.raises(
        gate.AdvisoryTraceError, match="missing from SECURITY.md.*GHSA-c9j3-q7hh-p95m"
    ):
        gate.verify_github_parity(
            rows,
            [
                *matching_api,
                gate.PublishedAdvisory(
                    ghsa_id="GHSA-c9j3-q7hh-p95m",
                    published_date="2026-11-19",
                    severity="medium",
                    description="Fixed on main in dd27b66b (#815).",
                ),
            ],
        )

    # 2. Listed in SECURITY.md, absent from GitHub published advisories
    with pytest.raises(gate.AdvisoryTraceError, match="not published on GitHub"):
        gate.verify_github_parity(rows, matching_api[:1])

    # 3. GitHub advisory description does not corroborate the SECURITY.md SHA
    with pytest.raises(
        gate.AdvisoryTraceError, match="appear in the GitHub advisory description"
    ):
        gate.verify_github_parity(
            rows,
            [
                gate.PublishedAdvisory(
                    ghsa_id=gids[0],
                    published_date="2026-11-19",
                    severity="medium",
                    description="Fixed on main in deadbeef (#999).",
                ),
                matching_api[1],
            ],
        )


def test_fetch_published_advisories_follows_pagination_and_rejects_bad_url() -> None:
    """Pagination Link headers are followed and non-https / non-api.github.com URLs fail closed."""
    with pytest.raises(gate.AdvisoryTraceError, match="Refusing non-GitHub-API URL"):
        gate._validate_github_api_url("http://api.github.com/repos/foo/bar")
    with pytest.raises(gate.AdvisoryTraceError, match="Refusing non-GitHub-API URL"):
        gate._validate_github_api_url("https://evil.example.com/repos/foo/bar")

    class _FakeResp:
        def __init__(
            self, body: list[dict[str, Any]], link: str | None = None, status: int = 200
        ) -> None:
            self._raw = json.dumps(body).encode("utf-8")
            self._link = link
            self.status = status

        def read(self) -> bytes:
            return self._raw

        def getheader(self, name: str, default: str | None = None) -> str | None:
            if name.lower() == "link":
                return self._link
            return default

    responses = iter(
        [
            _FakeResp(
                [
                    {
                        "ghsa_id": "GHSA-2222-3333-4444",
                        "published_at": "2026-11-18T10:00:00Z",
                        "severity": "medium",
                        "description": "Fixed in 1aeed422",
                    }
                ],
                link='<https://api.github.com/repos/google/cybernetic-agent-governance-engine/security-advisories?state=published&per_page=100&after=cursor1>; rel="next"',
            ),
            _FakeResp(
                [
                    {
                        "ghsa_id": "GHSA-3333-4444-5555",
                        "published_at": "2026-11-19T13:13:29Z",
                        "severity": "high",
                        "description": "Fixed in c145a9cc",
                    }
                ],
                link=None,
            ),
        ]
    )

    class _FakeHTTPSConnection:
        def __init__(self, host: str, timeout: float = 15.0) -> None:
            assert host == "api.github.com"

        def request(
            self, method: str, url: str, headers: dict[str, str] | None = None
        ) -> None:
            assert method == "GET"
            assert url.startswith("/repos/")

        def getresponse(self) -> _FakeResp:
            return next(responses)

        def close(self) -> None:
            return None

    with patch.object(gate.http.client, "HTTPSConnection", _FakeHTTPSConnection):
        fetched = gate.fetch_published_advisories()
    assert [a.ghsa_id for a in fetched] == [
        "GHSA-2222-3333-4444",
        "GHSA-3333-4444-5555",
    ]


def test_advisory_trace_gate_is_wired_into_ci_hooks_and_makefile() -> None:
    """Ensure check_advisory_traces.py is wired into ci.yml (offline + --verify-github), hooks, and Makefile."""
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    hooks_text = (REPO_ROOT / "scripts" / "setup_git_hooks.sh").read_text(
        encoding="utf-8"
    )
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "scripts/check_advisory_traces.py --verbose" in ci_text
    assert "scripts/check_advisory_traces.py --verify-github" in ci_text
    assert "scripts/check_advisory_traces.py" in hooks_text
    assert "scripts/check_advisory_traces.py" in makefile_text
