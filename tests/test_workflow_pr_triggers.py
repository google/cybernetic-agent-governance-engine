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

"""Contract tests for POAM-2026-153: stacked PR workflow triggers and Makefile lint parity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOWS_DIR = _REPO_ROOT / ".github" / "workflows"

_EXPECTED_PR_WORKFLOWS = frozenset(
    {
        "apac-mas-compliance.yml",
        "ci.yml",
        "dependency-review.yml",
        "eu-ecb-compliance.yml",
        "license_guard.yml",
        "lula-validate.yml",
        "lula2-pr-compliance.yml",
        "poam-drift.yml",
        "policy_compile.yml",
        "sbom.yml",
        "security-scan.yml",
        "test-hermetic.yml",
    }
)


def _load_on_block(path: Path) -> Any:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name} did not parse as a YAML mapping"
    # PyYAML (YAML 1.1) parses bare `on:` as boolean True unless quoted.
    if "on" in doc:
        return doc["on"]
    return doc.get(True)


def test_pull_request_workflows_do_not_filter_target_branches() -> None:
    """Every workflow with a pull_request trigger must run regardless of PR base branch (POAM-2026-153)."""
    workflow_files = sorted(_WORKFLOWS_DIR.glob("*.yml"))
    assert workflow_files, f"No workflow files found under {_WORKFLOWS_DIR}"

    seen_pr_workflows: set[str] = set()
    branch_filtered: list[str] = []

    for wf in workflow_files:
        on_block = _load_on_block(wf)
        has_pr = False
        pr_cfg: Any = None
        if isinstance(on_block, dict) and "pull_request" in on_block:
            has_pr = True
            pr_cfg = on_block["pull_request"]
        elif isinstance(on_block, list) and "pull_request" in on_block:
            has_pr = True
        elif on_block == "pull_request":
            has_pr = True

        if not has_pr:
            continue

        seen_pr_workflows.add(wf.name)
        if isinstance(pr_cfg, dict):
            forbidden = {"branches", "branches-ignore"} & set(pr_cfg.keys())
            if forbidden:
                branch_filtered.append(
                    f"{wf.name}: on.pull_request.{sorted(forbidden)}={ {k: pr_cfg[k] for k in sorted(forbidden)} }"
                )

    assert not branch_filtered, (
        "Stacked PRs skip required CI checks when pull_request triggers filter target branches "
        f"(POAM-2026-153): {branch_filtered}"
    )
    missing = sorted(_EXPECTED_PR_WORKFLOWS - seen_pr_workflows)
    assert not missing, (
        f"Expected pull_request trigger missing from workflow(s): {missing}"
    )


def test_makefile_lint_runs_mypy() -> None:
    """Makefile `lint` target must invoke `mypy src/` so local gates match CI Lint (POAM-2026-153)."""
    makefile = (_REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    lines = makefile.splitlines()
    in_lint = False
    recipe: list[str] = []
    for line in lines:
        if line.startswith("lint:"):
            in_lint = True
            continue
        if in_lint:
            if line.startswith("\t"):
                recipe.append(line.strip())
            elif line.strip() == "" or line.startswith("#"):
                continue
            else:
                break

    assert recipe, "Makefile has no recipe lines under `lint:`"
    assert any(
        not step.lstrip("@").startswith("echo") and "mypy src/" in step
        for step in recipe
    ), f"Makefile `lint` target must execute `mypy src/` (POAM-2026-153); got: {recipe}"


def test_required_check_workflows_trigger_on_stacked_pr_branches() -> None:
    """Workflows backing ruleset 25966171's 8 required checks must run unconditionally on every PR."""
    required_workflows = ("ci.yml", "security-scan.yml", "license_guard.yml")
    for wf_name in required_workflows:
        on_block = _load_on_block(_WORKFLOWS_DIR / wf_name)
        assert isinstance(on_block, dict) and "pull_request" in on_block, (
            f"{wf_name} must declare an `on.pull_request` trigger"
        )
        pr_cfg = on_block["pull_request"]
        if pr_cfg is not None:
            assert isinstance(pr_cfg, dict), (
                f"{wf_name}: unexpected on.pull_request={pr_cfg!r}"
            )
            forbidden = {
                "branches",
                "branches-ignore",
                "paths",
                "paths-ignore",
            } & set(pr_cfg.keys())
            assert not forbidden, (
                f"{wf_name} filters `on.pull_request` via {sorted(forbidden)}, which would "
                "prevent required checks from reporting on stacked PRs"
            )


def test_push_triggers_remain_scoped_on_unfiltered_pr_workflows() -> None:
    """Dropping `on.pull_request.branches` must not unscope `on.push` into double-running on feature pushes."""
    main_only_push_workflows = (
        "apac-mas-compliance.yml",
        "ci.yml",
        "eu-ecb-compliance.yml",
        "license_guard.yml",
        "sbom.yml",
        "security-scan.yml",
        "test-hermetic.yml",
    )
    for wf_name in main_only_push_workflows:
        on_block = _load_on_block(_WORKFLOWS_DIR / wf_name)
        assert isinstance(on_block, dict) and "push" in on_block, (
            f"{wf_name} expected an `on.push` trigger"
        )
        push_cfg = on_block["push"]
        assert isinstance(push_cfg, dict) and push_cfg.get("branches") == ["main"], (
            f"{wf_name} `on.push` must remain scoped to `branches: [main]`; got {push_cfg!r}"
        )
