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

"""scripts/check_repo_rules.py

Compare the repository protection GitHub enforces with the configuration
``.github/branch-protection-rules.md`` documents (POAM-2026-169, POAM-2026-170,
POAM-2026-171).

The documented configuration is pinned below. The live configuration is read
from two endpoints that need no credentials on a public repository:

* ``GET /repos/{repo}/rules/branches/{branch}``: every rule that applies to the
  branch, from every ruleset, with its parameters;
* ``GET /repos/{repo}/rulesets/{id}``: the release-tag ruleset.

In addition, ``workflow_guard_drift()`` checks the committed workflow invariants
that back post-merge check reconciliation on ``main`` (POAM-2026-171): PR-only
concurrency cancellation and per-SHA ``push`` concurrency groups across
``ci.yml``, ``security-scan.yml`` and ``license_guard.yml``, plus the scheduled
``main-result-reconciler.yml`` workflow.

Any difference fails the check: a rule removed, a check unpinned, a ruleset
disabled, a workflow concurrency guard weakened, and also a rule or check added.
An intended change updates this file, the document and the ruleset together. A
fetch error fails the check too.

Bypass actors are returned only to repository admins, so this check cannot
see one added to a ruleset (POAM-2026-170, residual risk).

Usage::

    python scripts/check_repo_rules.py [--repo OWNER/NAME] [--branch main]

``GITHUB_TOKEN``, when set, is sent to raise the API rate limit. Exit status:
0 when the live configuration and workflow guards match, 1 on any difference,
2 when the API cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
DEFAULT_REPO = "google/cybernetic-agent-governance-engine"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]
FETCH_TIMEOUT_SECONDS = 20

# GitHub Actions' app id. A required check pinned to it is satisfied only by a
# check run that GitHub Actions created.
GITHUB_ACTIONS_APP_ID = 15368

# Rules on `main`, by type (§1 of .github/branch-protection-rules.md).
EXPECTED_MAIN_RULE_TYPES = frozenset(
    {"pull_request", "required_status_checks", "non_fast_forward", "deletion"}
)

# The `pull_request` rule's parameters that the document states.
EXPECTED_PULL_REQUEST_PARAMETERS: Mapping[str, Any] = {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews_on_push": True,
    "require_code_owner_review": False,
    "required_review_thread_resolution": False,
}

# The check `.github/workflows/review-bypass-attestation.yml` reports on pull
# requests. It passes on an approving review or on a verified signed record of
# the unreviewed head, and a record is not a review (§3.1, POAM-2026-115).
REVIEW_BYPASS_CHECK = "Approved review or recorded bypass"

# The post-merge check `.github/workflows/review-bypass-ledger.yml` reports on
# `push` to `main` in place of the PR-only `REVIEW_BYPASS_CHECK` (§3.1,
# POAM-2026-115, POAM-2026-171).
REVIEW_BYPASS_LEDGER_CHECK = "Record an unreviewed merge"

# Required status checks on `main` and the app each is pinned to (§3).
EXPECTED_REQUIRED_CHECKS: Mapping[str, int] = {
    "Lint": GITHUB_ACTIONS_APP_ID,
    "AI 600-1 Unit Tests": GITHUB_ACTIONS_APP_ID,
    "OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)": (
        GITHUB_ACTIONS_APP_ID
    ),
    "Secret Scanning (Gitleaks)": GITHUB_ACTIONS_APP_ID,
    "license-check": GITHUB_ACTIONS_APP_ID,
    "Pytest Logic Tests": GITHUB_ACTIONS_APP_ID,
    "Terraform Tests (gcp-gke, mock providers)": GITHUB_ACTIONS_APP_ID,
    "Quickstart Bootstrap & First-DENY Smoke Gate": GITHUB_ACTIONS_APP_ID,
    REVIEW_BYPASS_CHECK: GITHUB_ACTIONS_APP_ID,
}

# Expected check contexts on each post-merge `push` commit on `main`: derived
# from `EXPECTED_REQUIRED_CHECKS` by replacing PR-only `REVIEW_BYPASS_CHECK`
# with `REVIEW_BYPASS_LEDGER_CHECK` (POAM-2026-171).
EXPECTED_MAIN_PUSH_CHECKS: Mapping[str, int] = {
    (REVIEW_BYPASS_LEDGER_CHECK if ctx == REVIEW_BYPASS_CHECK else ctx): (
        GITHUB_ACTIONS_APP_ID if ctx == REVIEW_BYPASS_CHECK else app_id
    )
    for ctx, app_id in EXPECTED_REQUIRED_CHECKS.items()
}

# Expected distinct GitHub Actions check_suite counts per push check on `main`.
# Both `ci.yml` (Apache 2.0 headers) and `license_guard.yml` (pip-licenses)
# report `license-check` on `main` (POAM-2026-172), so `main` reconciliation
# requires 2 passing suites for `license-check` and 1 for the other 8 checks.
EXPECTED_MAIN_CHECK_SUITE_COUNTS: Mapping[str, int] = {
    ctx: (2 if ctx == "license-check" else 1) for ctx in EXPECTED_MAIN_PUSH_CHECKS
}

# Workflows reporting required checks on both `pull_request` and `push` to `main`
# that must cancel superseded runs on `pull_request` only and isolate `push`
# concurrency groups by `github.sha` (POAM-2026-171).
REQUIRED_CHECK_CONCURRENCY_WORKFLOWS: tuple[str, ...] = (
    "ci.yml",
    "security-scan.yml",
    "license_guard.yml",
)
EXPECTED_PR_ONLY_CANCEL_IN_PROGRESS = "${{ github.event_name == 'pull_request' }}"
EXPECTED_PR_ONLY_CONCURRENCY_GROUP = (
    "${{ github.workflow }}-${{ github.event_name }}-"
    "${{ github.event_name == 'pull_request' && github.head_ref "
    "|| (github.event_name == 'push' && github.sha || github.run_id) }}"
)
MAIN_RESULT_RECONCILER_WORKFLOW = "main-result-reconciler.yml"
MAIN_RESULT_RECONCILER_SCRIPT = "scripts/reconcile_main_check_results.py"

# Branches need not be up to date before merging (§1).
EXPECTED_STRICT_STATUS_CHECKS = False

# The release-tag ruleset (§4).
TAG_RULESET_ID = 25965917
EXPECTED_TAG_INCLUDE = frozenset({"refs/tags/v*", "refs/tags/client-v*"})
EXPECTED_TAG_RULE_TYPES = frozenset({"deletion", "update", "non_fast_forward"})

Fetch = Callable[[str], Any]

_TOP_LEVEL_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):(?:\s*(.*))?$")
_INDENTED_KV_RE = re.compile(r"^(\s+)([A-Za-z0-9_-]+):(?:\s*(.*))?$")
_CRON_ITEM_RE = re.compile(r"^\s*-\s*cron:\s*(['\"]?)([^'\"]+)\1\s*$")


def _strip_yaml_comment(line: str) -> str:
    """Strip an unquoted YAML `#` comment while preserving `#` inside quotes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _unquote_yaml_scalar(raw: str) -> str:
    val = raw.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return val[1:-1]
    return val


def _top_level_yaml_sections(text: str) -> dict[str, tuple[str, list[str]]]:
    """Parse column-0 YAML keys into `(inline_value, indented_lines)` without PyYAML."""
    sections: dict[str, tuple[str, list[str]]] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        cleaned = _strip_yaml_comment(raw_line)
        if not cleaned.strip():
            continue
        top_match = _TOP_LEVEL_KEY_RE.match(cleaned)
        if top_match is not None:
            current_key = top_match.group(1)
            inline_val = (top_match.group(2) or "").strip()
            sections[current_key] = (inline_val, [])
        elif current_key is not None and cleaned[0].isspace():
            sections[current_key][1].append(cleaned)
    return sections


def _parse_direct_children(lines: Sequence[str]) -> dict[str, str]:
    """Return direct key-value children of a YAML mapping block."""
    if not lines:
        return {}
    min_indent = min(len(line) - len(line.lstrip(" ")) for line in lines)
    children: dict[str, str] = {}
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        if indent != min_indent:
            continue
        match = _INDENTED_KV_RE.match(line)
        if match is not None:
            children[match.group(2)] = _unquote_yaml_scalar(match.group(3) or "")
    return children


def _extract_yaml_run_blocks(lines: Sequence[str]) -> list[str]:
    """Extract all `run:` step script bodies from indented `jobs:` lines."""
    blocks: list[str] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = re.match(r"^(\s*(?:-\s+)?)run:(?:\s*(.*))?$", line)
        if match is None:
            idx += 1
            continue
        key_indent = len(line) - len(line.lstrip(" "))
        # If `run:` is on the `- run:` list item line, body lines indent past `- `.
        if line.lstrip(" ").startswith("- "):
            key_indent += 2
        inline = (match.group(2) or "").strip()
        if inline and inline not in ("|", "|-", "|+", ">", ">-", ">+"):
            blocks.append(_unquote_yaml_scalar(inline))
            idx += 1
            continue
        idx += 1
        body_lines: list[str] = []
        while idx < len(lines):
            candidate = lines[idx]
            cand_indent = len(candidate) - len(candidate.lstrip(" "))
            if cand_indent <= key_indent:
                break
            body_lines.append(candidate.strip())
            idx += 1
        blocks.append("\n".join(body_lines))
    return blocks


def workflow_guard_drift(repo_root: Path = DEFAULT_REPO_ROOT) -> list[str]:
    """Return any drift in POAM-2026-171 workflow concurrency or reconciler guards."""
    problems: list[str] = []
    workflows_dir = repo_root / ".github" / "workflows"

    for wf_name in REQUIRED_CHECK_CONCURRENCY_WORKFLOWS:
        wf_path = workflows_dir / wf_name
        if not wf_path.is_file():
            problems.append(f"workflow `{wf_name}` is missing")
            continue
        sections = _top_level_yaml_sections(wf_path.read_text(encoding="utf-8"))
        if "concurrency" not in sections:
            problems.append(f"{wf_name}: missing top-level `concurrency` block")
            continue
        _, conc_lines = sections["concurrency"]
        conc_map = _parse_direct_children(conc_lines)
        actual_cancel = conc_map.get("cancel-in-progress")
        if actual_cancel != EXPECTED_PR_ONLY_CANCEL_IN_PROGRESS:
            problems.append(
                f"{wf_name}: concurrency `cancel-in-progress` is {actual_cancel!r}, "
                f"expected {EXPECTED_PR_ONLY_CANCEL_IN_PROGRESS!r}"
            )
        actual_group = conc_map.get("group")
        if actual_group != EXPECTED_PR_ONLY_CONCURRENCY_GROUP:
            problems.append(
                f"{wf_name}: concurrency `group` is {actual_group!r}, "
                f"expected {EXPECTED_PR_ONLY_CONCURRENCY_GROUP!r} "
                "(push runs must isolate concurrency groups by `github.sha`)"
            )

        _, job_lines = sections.get("jobs", ("", []))
        for job_line in job_lines:
            kv = _INDENTED_KV_RE.match(job_line)
            if kv and kv.group(2) == "cancel-in-progress":
                job_cancel = _unquote_yaml_scalar(kv.group(3) or "")
                if job_cancel not in ("false", EXPECTED_PR_ONLY_CANCEL_IN_PROGRESS):
                    problems.append(
                        f"{wf_name}: job-level `cancel-in-progress` is {job_cancel!r}, "
                        "which would cancel post-merge runs on `main`"
                    )

    rec_path = workflows_dir / MAIN_RESULT_RECONCILER_WORKFLOW
    if not rec_path.is_file():
        problems.append(f"workflow `{MAIN_RESULT_RECONCILER_WORKFLOW}` is missing")
        return problems

    rec_text = rec_path.read_text(encoding="utf-8")
    rec_sections = _top_level_yaml_sections(rec_text)

    _, on_lines = rec_sections.get("on", ("", []))
    has_schedule_key = any(
        (m := _INDENTED_KV_RE.match(line)) is not None and m.group(2) == "schedule"
        for line in on_lines
    )
    has_cron_item = any(
        (cm := _CRON_ITEM_RE.match(line)) is not None and bool(cm.group(2).strip())
        for line in on_lines
    )
    if not (has_schedule_key and has_cron_item):
        problems.append(
            f"{MAIN_RESULT_RECONCILER_WORKFLOW}: missing `on.schedule` cron trigger"
        )

    if "concurrency" not in rec_sections:
        problems.append(
            f"{MAIN_RESULT_RECONCILER_WORKFLOW}: missing top-level `concurrency` block"
        )
    else:
        rec_conc = _parse_direct_children(rec_sections["concurrency"][1])
        if rec_conc.get("cancel-in-progress") != "false":
            problems.append(
                f"{MAIN_RESULT_RECONCILER_WORKFLOW}: concurrency `cancel-in-progress` "
                f"is {rec_conc.get('cancel-in-progress')!r}, expected 'false'"
            )
        if not rec_conc.get("group"):
            problems.append(
                f"{MAIN_RESULT_RECONCILER_WORKFLOW}: concurrency `group` is empty"
            )

    top_perm_inline, top_perm_lines = rec_sections.get("permissions", ("", []))
    if top_perm_inline != "{}" or top_perm_lines:
        problems.append(
            f"{MAIN_RESULT_RECONCILER_WORKFLOW}: top-level `permissions` must be `{{}}`"
        )

    _, rec_job_lines = rec_sections.get("jobs", ("", []))
    job_perms: dict[str, str] = {}
    idx = 0
    while idx < len(rec_job_lines):
        kv = _INDENTED_KV_RE.match(rec_job_lines[idx])
        if kv and kv.group(2) == "permissions":
            perm_indent = len(kv.group(1))
            idx += 1
            while idx < len(rec_job_lines):
                sub_line = rec_job_lines[idx]
                sub_indent = len(sub_line) - len(sub_line.lstrip(" "))
                if sub_indent <= perm_indent:
                    break
                sub_kv = _INDENTED_KV_RE.match(sub_line)
                if sub_kv:
                    job_perms[sub_kv.group(2)] = _unquote_yaml_scalar(
                        sub_kv.group(3) or ""
                    )
                idx += 1
            continue
        idx += 1

    for required_perm, expected_level in (
        ("contents", "read"),
        ("issues", "write"),
        ("id-token", "write"),
    ):
        actual_level = job_perms.get(required_perm)
        if actual_level != expected_level:
            problems.append(
                f"{MAIN_RESULT_RECONCILER_WORKFLOW}: job permission `{required_perm}` "
                f"is {actual_level!r}, expected {expected_level!r}"
            )

    run_blocks = _extract_yaml_run_blocks(rec_job_lines)
    invokes_reconciler = False
    for block in run_blocks:
        if "${{" in block:
            problems.append(
                f"{MAIN_RESULT_RECONCILER_WORKFLOW}: `run:` block contains `${{{{` "
                "template interpolation (pass untrusted inputs strictly via `env:`)"
            )
        for cmd_line in block.splitlines():
            stripped = cmd_line.strip()
            if MAIN_RESULT_RECONCILER_SCRIPT in stripped and not stripped.startswith(
                ("echo ", "printf ")
            ):
                invokes_reconciler = True
    if not invokes_reconciler:
        problems.append(
            f"{MAIN_RESULT_RECONCILER_WORKFLOW}: no job step invokes `{MAIN_RESULT_RECONCILER_SCRIPT}`"
        )

    return problems


def main_rule_drift(
    rules: Sequence[Mapping[str, Any]], branch: str = "main"
) -> list[str]:
    """Return every difference between the rules on ``branch`` and the pins."""
    problems: list[str] = []
    by_type: dict[str, list[Mapping[str, Any]]] = {}
    for rule in rules:
        by_type.setdefault(str(rule.get("type")), []).append(rule)

    present = frozenset(by_type)
    for missing in sorted(EXPECTED_MAIN_RULE_TYPES - present):
        problems.append(f"{branch}: rule `{missing}` does not apply")
    for extra in sorted(present - EXPECTED_MAIN_RULE_TYPES):
        problems.append(f"{branch}: rule `{extra}` applies but is not documented")

    for rule in by_type.get("pull_request", []):
        parameters = rule.get("parameters") or {}
        for key, expected in EXPECTED_PULL_REQUEST_PARAMETERS.items():
            actual = parameters.get(key)
            if actual != expected:
                problems.append(
                    f"{branch}: pull_request `{key}` is {actual!r}, documented {expected!r}"
                )

    for rule in by_type.get("required_status_checks", []):
        problems.extend(_required_check_drift(rule.get("parameters") or {}, branch))
    return problems


def _required_check_drift(parameters: Mapping[str, Any], branch: str) -> list[str]:
    problems: list[str] = []
    strict = parameters.get("strict_required_status_checks_policy")
    if strict != EXPECTED_STRICT_STATUS_CHECKS:
        problems.append(
            f"{branch}: strict_required_status_checks_policy is "
            f"{strict!r}, documented {EXPECTED_STRICT_STATUS_CHECKS!r}"
        )

    live: dict[str, Any] = {}
    for check in parameters.get("required_status_checks") or []:
        live[str(check.get("context"))] = check.get("integration_id")

    for context, app_id in EXPECTED_REQUIRED_CHECKS.items():
        if context not in live:
            problems.append(f"{branch}: required check `{context}` is not required")
        elif live[context] != app_id:
            problems.append(
                f"{branch}: required check `{context}` is pinned to "
                f"{live[context]!r}, documented {app_id}"
            )
    for context in sorted(set(live) - set(EXPECTED_REQUIRED_CHECKS)):
        problems.append(
            f"{branch}: required check `{context}` is required but not documented"
        )
    return problems


def tag_ruleset_drift(ruleset: Mapping[str, Any]) -> list[str]:
    """Return every difference between the release-tag ruleset and the pins."""
    problems: list[str] = []
    name = f"tag ruleset {TAG_RULESET_ID}"
    if ruleset.get("target") != "tag":
        problems.append(
            f"{name}: target is {ruleset.get('target')!r}, documented 'tag'"
        )
    if ruleset.get("enforcement") != "active":
        problems.append(
            f"{name}: enforcement is {ruleset.get('enforcement')!r}, documented 'active'"
        )

    ref_name = (ruleset.get("conditions") or {}).get("ref_name") or {}
    include = frozenset(ref_name.get("include") or [])
    if include != EXPECTED_TAG_INCLUDE:
        problems.append(
            f"{name}: includes {sorted(include)}, documented {sorted(EXPECTED_TAG_INCLUDE)}"
        )
    if ref_name.get("exclude"):
        problems.append(
            f"{name}: excludes {sorted(ref_name['exclude'])}, documented none"
        )

    rule_types = frozenset(str(rule.get("type")) for rule in ruleset.get("rules") or [])
    for missing in sorted(EXPECTED_TAG_RULE_TYPES - rule_types):
        problems.append(f"{name}: rule `{missing}` is missing")
    for extra in sorted(rule_types - EXPECTED_TAG_RULE_TYPES):
        problems.append(f"{name}: rule `{extra}` is not documented")
    return problems


def fetch_json(url: str) -> Any:
    """GET a GitHub API URL and decode the JSON body."""
    if not url.startswith(f"{API_ROOT}/"):
        # Bandit B310: only the GitHub API over https is ever opened.
        raise ValueError(f"refusing to fetch a non-GitHub-API URL: {url}")
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # nosec B310  # https GitHub API only, checked above
        return json.load(response)


def run(
    repo: str,
    branch: str,
    fetch: Fetch = fetch_json,
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> int:
    """Check the live configuration and workflow guards. Returns the exit status."""
    try:
        rules = fetch(f"{API_ROOT}/repos/{repo}/rules/branches/{branch}")
        ruleset = fetch(f"{API_ROOT}/repos/{repo}/rulesets/{TAG_RULESET_ID}")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"FAIL: cannot read the repository rules: {exc}", file=sys.stderr)
        return 2
    if not isinstance(rules, list) or not isinstance(ruleset, dict):
        print("FAIL: the GitHub API returned an unexpected shape", file=sys.stderr)
        return 2

    problems = (
        main_rule_drift(rules, branch)
        + tag_ruleset_drift(ruleset)
        + workflow_guard_drift(repo_root)
    )
    if problems:
        print(
            f"FAIL: {len(problems)} difference(s) from .github/branch-protection-rules.md:"
        )
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"OK: {repo} `{branch}` has the {len(EXPECTED_MAIN_RULE_TYPES)} documented rule types, "
        f"{len(EXPECTED_REQUIRED_CHECKS)} pinned required checks, tag ruleset {TAG_RULESET_ID}, "
        "and post-merge workflow guards."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the live repository rules with the documented configuration."
    )
    parser.add_argument(
        "--repo", default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO
    )
    parser.add_argument("--branch", default="main")
    args = parser.parse_args(argv)
    return run(args.repo, args.branch)


if __name__ == "__main__":
    sys.exit(main())
