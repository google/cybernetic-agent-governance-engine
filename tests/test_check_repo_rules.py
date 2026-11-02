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

"""Tests for scripts/check_repo_rules.py (POAM-2026-169, POAM-2026-170).

The fixtures are the API's responses on 2026-11-02, read without credentials,
after ruleset 26377312 was applied and all eight required checks were pinned.
Every planted defect below is a way the live configuration could drift from
.github/branch-protection-rules.md; each must be reported. The recorded
responses must report nothing, or the planted defects prove nothing.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "repo_rules"
DOC = REPO_ROOT / ".github" / "branch-protection-rules.md"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load_module():
    path = REPO_ROOT / "scripts" / "check_repo_rules.py"
    spec = importlib.util.spec_from_file_location("check_repo_rules", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_repo_rules"] = module
    spec.loader.exec_module(module)
    return module


rules_mod = _load_module()


def _main_rules() -> list[dict[str, Any]]:
    return json.loads((FIXTURES / "rules_branches_main.json").read_text())


def _tag_ruleset() -> dict[str, Any]:
    return json.loads((FIXTURES / "ruleset_tags.json").read_text())


def _rule(rules: list[dict[str, Any]], rule_type: str) -> dict[str, Any]:
    return next(rule for rule in rules if rule["type"] == rule_type)


def _checks(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _rule(rules, "required_status_checks")["parameters"][
        "required_status_checks"
    ]


def test_recorded_configuration_reports_nothing() -> None:
    assert rules_mod.main_rule_drift(_main_rules()) == []
    assert rules_mod.tag_ruleset_drift(_tag_ruleset()) == []


def _drop_rule(rule_type: str) -> Callable[[list[dict[str, Any]]], None]:
    def plant(rules: list[dict[str, Any]]) -> None:
        rules[:] = [rule for rule in rules if rule["type"] != rule_type]

    return plant


def _unpin_first_unpinned_before(rules: list[dict[str, Any]]) -> None:
    # "Lint" was one of the five checks that accepted any source until 2026-11-02.
    lint = next(check for check in _checks(rules) if check["context"] == "Lint")
    del lint["integration_id"]


def _repin_to_other_app(rules: list[dict[str, Any]]) -> None:
    _checks(rules)[0]["integration_id"] = 999999


def _drop_required_check(rules: list[dict[str, Any]]) -> None:
    params = _rule(rules, "required_status_checks")["parameters"]
    params["required_status_checks"] = [
        check
        for check in params["required_status_checks"]
        if check["context"] != "license-check"
    ]


def _add_required_check(rules: list[dict[str, Any]]) -> None:
    _checks(rules).append({"context": "Undocumented Check", "integration_id": 15368})


def _make_strict(rules: list[dict[str, Any]]) -> None:
    params = _rule(rules, "required_status_checks")["parameters"]
    params["strict_required_status_checks_policy"] = True


def _drop_review_count(rules: list[dict[str, Any]]) -> None:
    _rule(rules, "pull_request")["parameters"]["required_approving_review_count"] = 0


def _add_undocumented_rule(rules: list[dict[str, Any]]) -> None:
    rules.append({"type": "required_signatures", "ruleset_id": 1})


MAIN_PLANTS: dict[str, tuple[Callable[[list[dict[str, Any]]], None], str]] = {
    "force pushes allowed again": (
        _drop_rule("non_fast_forward"),
        "`non_fast_forward` does not apply",
    ),
    "deletion allowed again": (_drop_rule("deletion"), "`deletion` does not apply"),
    "review rule removed": (
        _drop_rule("pull_request"),
        "`pull_request` does not apply",
    ),
    "required checks removed": (
        _drop_rule("required_status_checks"),
        "`required_status_checks` does not apply",
    ),
    "a check unpinned": (_unpin_first_unpinned_before, "`Lint` is pinned to None"),
    "a check pinned to another app": (_repin_to_other_app, "pinned to 999999"),
    "a check no longer required": (
        _drop_required_check,
        "`license-check` is not required",
    ),
    "an undocumented check required": (
        _add_required_check,
        "`Undocumented Check` is required but not documented",
    ),
    "branches must be up to date": (
        _make_strict,
        "strict_required_status_checks_policy is True",
    ),
    "no approving review required": (
        _drop_review_count,
        "`required_approving_review_count` is 0",
    ),
    "an undocumented rule applies": (
        _add_undocumented_rule,
        "`required_signatures` applies but is not documented",
    ),
}


@pytest.mark.parametrize("name", sorted(MAIN_PLANTS))
def test_main_rule_drift_is_reported(name: str) -> None:
    plant, expected = MAIN_PLANTS[name]
    rules = copy.deepcopy(_main_rules())
    plant(rules)
    problems = rules_mod.main_rule_drift(rules)
    assert any(expected in problem for problem in problems), problems


def _disable(ruleset: dict[str, Any]) -> None:
    ruleset["enforcement"] = "disabled"


def _evaluate_only(ruleset: dict[str, Any]) -> None:
    ruleset["enforcement"] = "evaluate"


def _drop_update(ruleset: dict[str, Any]) -> None:
    ruleset["rules"] = [rule for rule in ruleset["rules"] if rule["type"] != "update"]


def _narrow_include(ruleset: dict[str, Any]) -> None:
    ruleset["conditions"]["ref_name"]["include"] = ["refs/tags/v*"]


def _retarget_to_branches(ruleset: dict[str, Any]) -> None:
    # The mistake POAM-2026-116 recorded: a "tag" ruleset that targeted branches.
    ruleset["target"] = "branch"


def _exclude_a_tag(ruleset: dict[str, Any]) -> None:
    ruleset["conditions"]["ref_name"]["exclude"] = ["refs/tags/v4.0.0"]


TAG_PLANTS: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "ruleset disabled": (_disable, "enforcement is 'disabled'"),
    "ruleset in evaluate mode": (_evaluate_only, "enforcement is 'evaluate'"),
    "tags may move": (_drop_update, "rule `update` is missing"),
    "client tags unprotected": (_narrow_include, "includes ['refs/tags/v*']"),
    "targets branches": (_retarget_to_branches, "target is 'branch'"),
    "a release tag excluded": (_exclude_a_tag, "excludes ['refs/tags/v4.0.0']"),
}


@pytest.mark.parametrize("name", sorted(TAG_PLANTS))
def test_tag_ruleset_drift_is_reported(name: str) -> None:
    plant, expected = TAG_PLANTS[name]
    ruleset = copy.deepcopy(_tag_ruleset())
    plant(ruleset)
    problems = rules_mod.tag_ruleset_drift(ruleset)
    assert any(expected in problem for problem in problems), problems


def _fake_fetch(responses: dict[str, Any]) -> Callable[[str], Any]:
    def fetch(url: str) -> Any:
        for suffix, body in responses.items():
            if url.endswith(suffix):
                return body
        raise AssertionError(f"unexpected URL {url}")

    return fetch


def test_run_exit_status_follows_the_drift(capsys: pytest.CaptureFixture[str]) -> None:
    clean = _fake_fetch(
        {"/rules/branches/main": _main_rules(), "/rulesets/25965917": _tag_ruleset()}
    )
    assert rules_mod.run("owner/repo", "main", fetch=clean) == 0

    planted = _main_rules()
    _drop_rule("non_fast_forward")(planted)
    drifted = _fake_fetch(
        {"/rules/branches/main": planted, "/rulesets/25965917": _tag_ruleset()}
    )
    assert rules_mod.run("owner/repo", "main", fetch=drifted) == 1
    assert "`non_fast_forward` does not apply" in capsys.readouterr().out


def test_unreadable_api_fails_closed() -> None:
    def broken(url: str) -> Any:
        raise OSError("network unreachable")

    assert rules_mod.run("owner/repo", "main", fetch=broken) == 2


def test_unexpected_api_shape_fails_closed() -> None:
    # An error body such as {"message": "Not Found"} is a dict, not a rule list.
    wrong = _fake_fetch(
        {
            "/rules/branches/main": {"message": "Not Found"},
            "/rulesets/25965917": _tag_ruleset(),
        }
    )
    assert rules_mod.run("owner/repo", "main", fetch=wrong) == 2


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/repos/o/r/rules/branches/main",
        "file:///etc/passwd",
        "https://api.github.com.evil.example/repos/o/r",
    ],
)
def test_fetch_refuses_anything_but_the_github_api(url: str) -> None:
    with pytest.raises(ValueError, match="refusing to fetch"):
        rules_mod.fetch_json(url)


def _section_3_rows() -> list[tuple[str, frozenset[str], int]]:
    """§3's rows as (check context, workflow files named, integration pin)."""
    text = DOC.read_text(encoding="utf-8")
    section = text.split("## 3. Required Status Checks", 1)[1].split("###", 1)[0]
    rows = re.findall(
        r"^\| `([^`]+)` \| ((?:`[^`]+`(?:, )?)+) \| `integration_id: (\d+)`",
        section,
        re.MULTILINE,
    )
    return [
        (context, frozenset(re.findall(r"`([^`]+)`", workflows)), int(app))
        for context, workflows, app in rows
    ]


def _reporting_workflows() -> dict[str, frozenset[str]]:
    """Every check name a workflow job reports, mapped to the files that report it.

    A job reports its ``name``, or its id when it has none.
    """
    reporters: dict[str, set[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (workflow.get("jobs") or {}).items():
            name = str((job or {}).get("name", job_id))
            reporters.setdefault(name, set()).add(path.name)
    return {name: frozenset(files) for name, files in reporters.items()}


def test_document_lists_exactly_the_pinned_required_checks() -> None:
    """§3 of the document and the checker's pins are one list, not two."""
    rows = _section_3_rows()
    assert {context: app for context, _, app in rows} == dict(
        rules_mod.EXPECTED_REQUIRED_CHECKS
    )


def test_document_names_every_workflow_that_reports_each_check() -> None:
    """§3's workflow column names exactly the workflows whose jobs report the check.

    A workflow the column omits reports the check where no reader of §3 looks,
    and a workflow the column names but that does not report it points the
    reader at the wrong file. §3 named ``ci.yml`` for a job in
    ``security-scan.yml`` until this test compared the column.
    """
    reporters = _reporting_workflows()
    wrong = {
        context: {
            "documented": sorted(named),
            "reported_by": sorted(reporters.get(context, ())),
        }
        for context, named, _ in _section_3_rows()
        if named != reporters.get(context, frozenset())
    }
    assert not wrong, wrong
