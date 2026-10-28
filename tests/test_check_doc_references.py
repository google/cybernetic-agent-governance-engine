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

import subprocess
from pathlib import Path

import pytest

import scripts.check_doc_references as g9
from scripts.check_doc_references import (
    audit_markdown_file,
    main,
    verify_file_path,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO = Path(__file__).resolve().parents[1]


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


# ---------------------------------------------------------------------------
# Revision-pinned paths: `<sha>:<path>` / `<sha>^:<path>`
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    """Run git in a throwaway fixture repository (synthetic identity, no signing)."""
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=g9-fixture",
            "-c",
            "user.email=g9-fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture()
def history_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    """Two commits on main: `src/gone.py` is added, then deleted by the returned commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "src").mkdir()
    (repo / "src" / "gone.py").write_text("GONE = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add")
    _git(repo, "rm", "-q", "src/gone.py")
    (repo / "kept.md").write_text("kept\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "delete")
    monkeypatch.setattr(g9, "REPO_ROOT", repo)
    g9._history_unavailable.cache_clear()
    return repo, _git(repo, "rev-parse", "HEAD")


def _audit(repo: Path, text: str) -> list[g9.Issue]:
    doc = repo / "doc.md"
    doc.write_text(text + "\n", encoding="utf-8")
    return audit_markdown_file(doc)


def test_pinned_path_resolves_before_the_deleting_commit(
    history_repo: tuple[Path, str],
) -> None:
    repo, deleting = history_repo
    assert _audit(repo, f"`{deleting[:8]}^:src/gone.py` was removed.") == []


def test_pinned_path_absent_at_the_pinned_revision_fails(
    history_repo: tuple[Path, str],
) -> None:
    repo, deleting = history_repo
    issues = _audit(repo, f"`{deleting[:8]}:src/gone.py`")
    assert [i.reference_type for i in issues] == ["Pinned Path"]
    assert "does not exist at" in issues[0].reason


def test_pinned_unknown_commit_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    issues = _audit(repo, "`deadbeef^:src/gone.py`")
    assert len(issues) == 1
    assert "is not a commit" in issues[0].reason


def test_pinned_commit_off_the_mainline_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "side.py").write_text("SIDE = 1\n", encoding="utf-8")
    _git(repo, "add", "side.py")
    _git(repo, "commit", "-q", "-m", "side")
    side = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    issues = _audit(repo, f"`{side[:8]}:side.py`")
    assert len(issues) == 1
    assert "not an ancestor of HEAD" in issues[0].reason


def test_pinned_path_fails_closed_in_a_shallow_clone(
    history_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, deleting = history_repo
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow))
    monkeypatch.setattr(g9, "REPO_ROOT", shallow)
    g9._history_unavailable.cache_clear()
    issues = _audit(shallow, f"`{deleting[:8]}^:src/gone.py`")
    assert len(issues) == 1
    assert "shallow clone" in issues[0].reason


def test_unpinned_removed_path_still_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    issues = _audit(repo, "`src/gone.py` was removed.")
    assert [i.reference_type for i in issues] == ["File Path"]


# ---------------------------------------------------------------------------
# Terraform paths and link labels
# ---------------------------------------------------------------------------


def test_terraform_paths_are_checked(tmp_path: Path) -> None:
    (tmp_path / "infra" / "mod").mkdir(parents=True)
    (tmp_path / "infra" / "mod" / "main.tf").write_text("# tf\n", encoding="utf-8")
    doc = tmp_path / "doc.md"
    doc.write_text(
        "`infra/mod/main.tf` and `infra/no_such_g9/main.tf`\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert [i.target for i in issues] == ["infra/no_such_g9/main.tf"]


def test_local_link_label_is_display_text(tmp_path: Path) -> None:
    """The target of a local link is the reference; a short label is not re-checked."""
    (tmp_path / "infra" / "modules" / "app").mkdir(parents=True)
    (tmp_path / "infra" / "modules" / "app" / "main.tf").write_text(
        "# tf\n", encoding="utf-8"
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "[`app/main.tf`](infra/modules/app/main.tf)\n"
        "[`app/main.tf`](infra/modules/no_such_g9/main.tf)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in issues] == [(2, "Markdown Link")]


def test_external_link_label_is_still_checked(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "[`src/no_such_module_g9.py`](https://example.com/x)\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert [i.reference_type for i in issues] == ["File Path"]


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


def test_gate_scope_has_one_copy() -> None:
    """CI gate G9 and `make docs-check` pass no --path, so DOC_SCOPE is the only scope."""
    for config in (REPO / ".github" / "workflows" / "ci.yml", REPO / "Makefile"):
        calls = [
            line
            for line in config.read_text(encoding="utf-8").splitlines()
            if "uv run" in line and "check_doc_references.py" in line
        ]
        assert calls, f"{config.name} no longer runs the gate"
        for line in calls:
            assert "--path" not in line, f"{config.name} narrows the scope: {line}"
            assert not line.rstrip().endswith("\\"), f"{config.name}: {line}"
    assert "docs/POAM.md" in g9.DOC_SCOPE
