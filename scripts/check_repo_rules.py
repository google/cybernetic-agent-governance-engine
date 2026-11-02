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
``.github/branch-protection-rules.md`` documents (POAM-2026-169, POAM-2026-170).

The documented configuration is pinned below. The live configuration is read
from two endpoints that need no credentials on a public repository:

* ``GET /repos/{repo}/rules/branches/{branch}``: every rule that applies to the
  branch, from every ruleset, with its parameters;
* ``GET /repos/{repo}/rulesets/{id}``: the release-tag ruleset.

Any difference fails the check: a rule removed, a check unpinned, a ruleset
disabled, and also a rule or check added. An intended change updates this
file, the document and the ruleset together. A fetch error fails the check too.

Bypass actors are returned only to repository admins, so this check cannot
see one added to a ruleset (POAM-2026-170, residual risk).

Usage::

    python scripts/check_repo_rules.py [--repo OWNER/NAME] [--branch main]

``GITHUB_TOKEN``, when set, is sent to raise the API rate limit. Exit status:
0 when the live configuration matches, 1 on any difference, 2 when the API
cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

API_ROOT = "https://api.github.com"
DEFAULT_REPO = "google/cybernetic-agent-governance-engine"
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
}

# Branches need not be up to date before merging (§1).
EXPECTED_STRICT_STATUS_CHECKS = False

# The release-tag ruleset (§4).
TAG_RULESET_ID = 25965917
EXPECTED_TAG_INCLUDE = frozenset({"refs/tags/v*", "refs/tags/client-v*"})
EXPECTED_TAG_RULE_TYPES = frozenset({"deletion", "update", "non_fast_forward"})

Fetch = Callable[[str], Any]


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


def run(repo: str, branch: str, fetch: Fetch = fetch_json) -> int:
    """Check the live configuration and print the result. Returns the exit status."""
    try:
        rules = fetch(f"{API_ROOT}/repos/{repo}/rules/branches/{branch}")
        ruleset = fetch(f"{API_ROOT}/repos/{repo}/rulesets/{TAG_RULESET_ID}")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"FAIL: cannot read the repository rules: {exc}", file=sys.stderr)
        return 2
    if not isinstance(rules, list) or not isinstance(ruleset, dict):
        print("FAIL: the GitHub API returned an unexpected shape", file=sys.stderr)
        return 2

    problems = main_rule_drift(rules, branch) + tag_ruleset_drift(ruleset)
    if problems:
        print(
            f"FAIL: {len(problems)} difference(s) from .github/branch-protection-rules.md:"
        )
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"OK: {repo} `{branch}` has the {len(EXPECTED_MAIN_RULE_TYPES)} documented rule types and "
        f"{len(EXPECTED_REQUIRED_CHECKS)} pinned required checks; tag ruleset {TAG_RULESET_ID} matches."
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
