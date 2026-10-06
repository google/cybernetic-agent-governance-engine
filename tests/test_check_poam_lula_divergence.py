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

"""Contract tests for scripts/check_poam_lula_divergence.py."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_poam_lula_divergence",
    _REPO_ROOT / "scripts" / "check_poam_lula_divergence.py",
)
assert _SPEC is not None and _SPEC.loader is not None
drift = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(drift)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("SC-4", "sc4"),
        ("A.5.2", "a52"),
        ("`CTRL_MRM_004`", "ctrlmrm004"),
        ("CTRL-FTRA-001", "ctrlftra001"),
    ],
)
def test_normalise_control_strips_markdown_and_separators(raw, expected) -> None:
    assert drift.normalise_control(raw) == expected


def test_code_evidence_files_exist_at_head() -> None:
    for finding_id in drift.CODE_EVIDENCE_FINDINGS:
        assert drift.missing_code_evidence(finding_id, _REPO_ROOT) == [], finding_id


def test_code_evidence_findings_are_closed_in_poam() -> None:
    poam = (_REPO_ROOT / "docs" / "POAM.md").read_text(encoding="utf-8")
    closed = {f["id"] for f in drift.parse_closed_findings(poam)}
    assert set(drift.CODE_EVIDENCE_FINDINGS) <= closed


def test_missing_evidence_fails_closed(monkeypatch, tmp_path) -> None:
    monkeypatch.setitem(
        drift.CODE_EVIDENCE_FINDINGS, "POAM-TEST-001", ("tests/does_not_exist.py",)
    )
    assert drift.missing_code_evidence("POAM-TEST-001", tmp_path) == [
        "tests/does_not_exist.py"
    ]


def test_unlisted_finding_has_no_code_evidence() -> None:
    assert drift.missing_code_evidence("POAM-NOT-LISTED") is None


def test_repository_has_no_uncovered_closed_findings(monkeypatch, capsys) -> None:
    monkeypatch.chdir(_REPO_ROOT)
    assert drift.main() == 0
    assert "0 uncovered" in capsys.readouterr().out
