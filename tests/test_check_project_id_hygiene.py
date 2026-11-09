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
# Closure regression guard for: POAM-2026-071

"""Behavioral tests for the project-ID hygiene gate (POAM-2026-071).

POAM-2026-071 closed on two remediations this gate now enforces on every commit
and in the CI ``lint`` job: Terraform state (with its provisioned credentials)
stays untracked, and maintainer cloud project IDs stay out of tracked files.
Each test plants a violation in a synthetic tree and observes the gate fail.
The maintainer identifier itself is read from the gate, never restated here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scripts import check_project_id_hygiene as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SYNTHETIC_ID = "example-maintainer-project-0000"


def _write(root: Path, rel: str, text: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return rel


def test_flags_prohibited_identifier_with_line_number(tmp_path: Path) -> None:
    rel = _write(
        tmp_path, "infra/targets/x/main.tf", f'a = 1\nproject = "{_SYNTHETIC_ID}"\n'
    )
    assert gate.scan_tracked_files(tmp_path, [rel], [_SYNTHETIC_ID]) == [
        (rel, 2, f'project = "{_SYNTHETIC_ID}"')
    ]


def test_default_identifiers_are_the_gate_denylist(tmp_path: Path) -> None:
    assert gate.PROHIBITED_IDENTIFIERS, "the gate must deny at least one identifier"
    rel = _write(
        tmp_path,
        "docs/runbook.md",
        f"gcloud --project {gate.PROHIBITED_IDENTIFIERS[0]}\n",
    )
    assert [v[0] for v in gate.scan_tracked_files(tmp_path, [rel])] == [rel]


@pytest.mark.parametrize(
    "rel",
    [
        "infra/targets/gcp-gke/terraform.tfstate",
        "infra/targets/gcp-gke/terraform.tfstate.backup",
        "infra/targets/gcp-gke/terraform.tfstate.1730000000.backup",
        "anywhere/else/prod.tfstate",
    ],
)
def test_tracked_terraform_state_is_a_violation_even_if_absent_on_disk(
    tmp_path: Path, rel: str
) -> None:
    assert gate.scan_tracked_files(tmp_path, [rel], [_SYNTHETIC_ID]) == [
        (rel, 0, "tracked Terraform state file (POAM-2026-071)")
    ]


@pytest.mark.parametrize("rel", ["infra/README.tfstate.md", "docs/tfstate-handling.md"])
def test_files_merely_naming_tfstate_are_not_state_files(
    tmp_path: Path, rel: str
) -> None:
    _write(tmp_path, rel, "Terraform state stays out of git.\n")
    assert not gate.is_terraform_state_path(rel)
    assert gate.scan_tracked_files(tmp_path, [rel], [_SYNTHETIC_ID]) == []


@pytest.mark.parametrize("prefix", gate.EXCLUDED_PATH_PREFIXES)
def test_historical_provenance_paths_are_not_scanned(
    tmp_path: Path, prefix: str
) -> None:
    rel = prefix if prefix.endswith(".py") else f"{prefix}record.md"
    _write(tmp_path, rel, f"measured on {_SYNTHETIC_ID}\n")
    assert gate.scan_tracked_files(tmp_path, [rel], [_SYNTHETIC_ID]) == []


def test_clean_tree_passes(tmp_path: Path) -> None:
    rel = _write(tmp_path, "infra/targets/x/main.tf", "project = var.project_id\n")
    assert gate.scan_tracked_files(tmp_path, [rel], [_SYNTHETIC_ID]) == []


@pytest.mark.parametrize(
    ("tracked", "expected_exit"),
    [(["infra/targets/gcp-gke/terraform.tfstate.backup"], 1), (["README.md"], 0)],
    ids=["tracked-state-fails", "clean-passes"],
)
def test_main_exit_code_reflects_violations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tracked: list[str],
    expected_exit: int,
) -> None:
    _write(tmp_path, "README.md", "no identifiers here\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(gate, "get_tracked_files", lambda: tracked)
    monkeypatch.setattr(sys, "argv", ["check_project_id_hygiene.py"])
    assert gate.main() == expected_exit
    if expected_exit:
        assert "terraform.tfstate.backup" in capsys.readouterr().out


def test_gitignore_keeps_terraform_state_untracked() -> None:
    patterns = {
        line.strip()
        for line in (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    assert {"*.tfstate", "*.tfstate.*"} <= patterns


def test_gate_runs_in_ci_lint_job() -> None:
    ci = (_REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/check_project_id_hygiene.py" in ci
