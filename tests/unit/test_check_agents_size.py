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

"""Unit tests for ``scripts/check_agents_size.py`` discovery, corpus floor, and 24KB cap."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_agents_size

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write(root: Path, rel: str, payload: bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def test_real_repository_discovers_all_injected_files_within_cap() -> None:
    """Live repository discovers AGENTS.md, .agents/rules/*.md, and .agents/workflows/*.md."""
    assert check_agents_size.MAX_BYTES == 24576
    files, violations = check_agents_size.check_injected_agent_files(REPO_ROOT)
    rel_paths = {item.rel_path for item in files}
    assert {
        "AGENTS.md",
        ".agents/rules/reasoning.md",
        ".agents/rules/security.md",
        ".agents/workflows/enforce_cloud_build.md",
    } <= rel_paths
    assert violations == []
    assert check_agents_size.main(["--verbose"]) == 0


def test_discovers_all_agent_customization_surfaces_and_ignores_non_injected_files(
    tmp_path: Path,
) -> None:
    """Discovery finds directory rules, workspace rules, skills, agents, workflows, and Copilot instructions."""
    _write(tmp_path, "AGENTS.md", b"# root\n")
    _write(tmp_path, "src/gateway/AGENTS.md", b"# subdir\n")
    _write(tmp_path, "CLAUDE.md", b"# claude\n")
    _write(tmp_path, "GEMINI.md", b"# gemini\n")
    _write(tmp_path, ".agents/rules/security.md", b"# sec\n")
    _write(tmp_path, "_agents/rules/style.mdc", b"# style\n")
    _write(tmp_path, ".agents/skills/review/SKILL.md", b"# skill\n")
    _write(tmp_path, ".claude/agents/auditor.md", b"# agent\n")
    _write(tmp_path, ".agents/workflows/deploy.md", b"# workflow\n")
    _write(tmp_path, ".github/copilot-instructions.md", b"# copilot\n")
    _write(tmp_path, ".github/instructions/python.instructions.md", b"# py\n")

    # Non-injected files and pruned vendor/scratch trees must NOT be collected:
    _write(tmp_path, ".agents/1_SCRATCH_NOTES.md", b"x" * 100_000)
    _write(tmp_path, ".agents/mcp_config.json.example", b"{}\n")
    _write(tmp_path, "docs/AGENTS_OVERVIEW.md", b"x" * 100_000)
    _write(tmp_path, "third_party/vendor/AGENTS.md", b"x" * 100_000)
    _write(tmp_path, "node_modules/pkg/CLAUDE.md", b"x" * 100_000)

    discovered = check_agents_size.discover_injected_agent_files(tmp_path)
    by_path = {item.rel_path: item.kind for item in discovered}
    assert by_path == {
        ".agents/rules/security.md": "workspace_rule",
        ".agents/skills/review/SKILL.md": "skill",
        ".agents/workflows/deploy.md": "workflow",
        ".claude/agents/auditor.md": "agent",
        ".github/copilot-instructions.md": "copilot_instruction",
        ".github/instructions/python.instructions.md": "copilot_instruction",
        "AGENTS.md": "directory_rule",
        "CLAUDE.md": "directory_rule",
        "GEMINI.md": "directory_rule",
        "_agents/rules/style.mdc": "workspace_rule",
        "src/gateway/AGENTS.md": "directory_rule",
    }


def test_exact_boundary_24576_passes_and_24577_in_nested_rule_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Oversized .agents/rules/*.md fails closed even when AGENTS.md is tiny."""
    _write(tmp_path, "AGENTS.md", b"# small\n")
    rule_path = _write(
        tmp_path, ".agents/rules/reasoning.md", b"a" * check_agents_size.MAX_BYTES
    )
    assert (
        check_agents_size.main(["--repo-root", str(tmp_path), "--min-files", "2"]) == 0
    )

    rule_path.write_bytes(b"a" * (check_agents_size.MAX_BYTES + 1))
    assert (
        check_agents_size.main(["--repo-root", str(tmp_path), "--min-files", "2"]) == 1
    )
    out = capsys.readouterr().out
    assert ".agents/rules/reasoning.md (workspace_rule)" in out
    assert "by 1 bytes" in out


def test_empty_injected_file_and_corpus_floor_breach_fail_closed(
    tmp_path: Path,
) -> None:
    """Both 0-byte injected rule files and corpus-floor breaches fail closed."""
    _write(tmp_path, "AGENTS.md", b"")
    assert (
        check_agents_size.main(["--repo-root", str(tmp_path), "--min-files", "1"]) == 1
    )

    _write(tmp_path, "AGENTS.md", b"# non-empty\n")
    with pytest.raises(check_agents_size.CorpusFloorError):
        check_agents_size.check_injected_agent_files(tmp_path, min_files=4)
    assert (
        check_agents_size.main(["--repo-root", str(tmp_path), "--min-files", "4"]) == 1
    )


def test_check_agents_size_wired_in_ci_hooks_and_makefile() -> None:
    """check_agents_size.py must be wired in ci.yml::lint, setup_git_hooks.sh, and Makefile."""
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    hooks_text = (REPO_ROOT / "scripts" / "setup_git_hooks.sh").read_text(
        encoding="utf-8"
    )
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "scripts/check_agents_size.py" in ci_text
    assert "scripts/check_agents_size.py" in hooks_text
    assert "scripts/check_agents_size.py" in makefile_text
