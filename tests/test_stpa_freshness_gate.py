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

"""STPA freshness gate: commit order in committed trees, stamps for local edits."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

pytestmark.append(
    pytest.mark.skipif(shutil.which("git") is None, reason="git required")
)

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_stpa_freshness.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_stpa_freshness", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


@pytest.fixture()
def gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    (repo / "config" / "stpa").mkdir(parents=True)
    source = repo / "config" / "stpa" / "core.yaml"
    artifact = repo / "generated.rego"
    source.write_text("hazards: []\n")
    # Stamp deliberately older than the commit: the old gate failed on this.
    artifact.write_text("# Generated: 2000-01-01T00:00:00+00:00\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "same commit", date="2026-01-01T12:00:00+00:00")

    module = _load_gate()
    monkeypatch.setattr(module, "_REPO_ROOT", repo)
    monkeypatch.setattr(module, "_SOURCE_DIR", repo / "config" / "stpa")
    monkeypatch.setattr(module, "_DOMAIN_STPA_DIRS", [])
    monkeypatch.setattr(module, "_SOURCE_LEGACY", repo / "missing.yaml")
    monkeypatch.setattr(module, "_GENERATED_ARTIFACTS", [artifact])
    return module, repo, source, artifact


def test_source_and_artifact_in_same_commit_is_fresh(gate) -> None:
    """Squash merges put both in one commit with a new committer time."""
    module, *_ = gate
    assert module.check_freshness() == []


def test_source_committed_after_artifact_is_stale(gate) -> None:
    module, repo, source, _ = gate
    source.write_text("hazards: [h1]\n")
    _git(repo, "commit", "-qam", "edit source only", date="2026-01-02T12:00:00+00:00")
    errors = module.check_freshness()
    assert len(errors) == 1
    assert "committed before newest STPA source change" in errors[0]


def test_regenerated_in_later_commit_is_fresh(gate) -> None:
    module, repo, source, artifact = gate
    source.write_text("hazards: [h1]\n")
    _git(repo, "commit", "-qam", "edit source", date="2026-01-02T12:00:00+00:00")
    artifact.write_text("# Generated: 2000-01-01T00:00:00+00:00\n# regen\n")
    _git(repo, "commit", "-qam", "regen", date="2026-01-03T12:00:00+00:00")
    assert module.check_freshness() == []


def test_uncommitted_source_edit_is_stale(gate) -> None:
    module, _, source, _ = gate
    source.write_text("hazards: [h2]\n")
    errors = module.check_freshness()
    assert len(errors) == 1
    assert "generated before source edit" in errors[0]


def test_uncommitted_regeneration_is_fresh(gate) -> None:
    module, _, source, artifact = gate
    source.write_text("hazards: [h2]\n")
    artifact.write_text("# Generated: 2999-01-01T00:00:00+00:00\n")
    assert module.check_freshness() == []


def test_missing_artifact_is_reported(gate) -> None:
    module, repo, _, artifact = gate
    _git(repo, "rm", "-q", str(artifact))
    _git(repo, "commit", "-qm", "drop", date="2026-01-02T12:00:00+00:00")
    errors = module.check_freshness()
    assert errors and errors[0].startswith("MISSING artifact")
