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

"""Unit tests for Gate G9 documentation reference and line-anchor checks."""

from pathlib import Path

import pytest

from scripts.check_doc_references import (
    audit_markdown_file,
    main,
    verify_file_path,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _write_sample_target(tmp_path: Path, lines: int = 10) -> Path:
    target = tmp_path / "sample.py"
    target.write_text(
        "\n".join(f"# line {i}" for i in range(1, lines + 1)) + "\n",
        encoding="utf-8",
    )
    return target


def test_verify_file_path_valid_line_anchor_passes(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L1-L10")
    assert valid is True
    assert reason == ""


def test_verify_file_path_anchor_past_eof_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L99999")
    assert valid is False
    assert "exceeds file length" in reason

    doc = tmp_path / "doc.md"
    doc.write_text("See [sample](sample.py#L99999).\n", encoding="utf-8")
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert issues[0].reference_type == "Markdown Link"
    assert "exceeds file length" in issues[0].reason


def test_verify_file_path_inverted_line_anchor_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=20)
    valid, reason = verify_file_path(tmp_path, "sample.py#L10-L5")
    assert valid is False
    assert "inverted range" in reason

    doc = tmp_path / "doc.md"
    doc.write_text("See [sample](sample.py#L10-L5).\n", encoding="utf-8")
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert "inverted range" in issues[0].reason


def test_verify_file_path_zero_start_line_anchor_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L0-L5")
    assert valid is False
    assert "< 1" in reason


def test_main_nonexistent_path_fails_closed() -> None:
    exit_code = main(["--path", "nonexistent_doc_scope_12345"])
    assert exit_code == 1


def test_main_explicit_markdown_file_outside_doc_roots(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid_doc = tmp_path / "external_plan.md"
    valid_doc.write_text("See [sample](sample.py#L1-L10).\n", encoding="utf-8")
    assert main(["--path", str(valid_doc)]) == 0

    broken_doc = tmp_path / "broken_plan.md"
    broken_doc.write_text("See [sample](sample.py#L99999).\n", encoding="utf-8")
    assert main(["--path", str(broken_doc)]) == 1
