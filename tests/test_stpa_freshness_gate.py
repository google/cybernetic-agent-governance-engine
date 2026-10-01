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

"""STPA freshness gate: sha256 of a fresh compile first; commit order or stamps as fallback."""

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


# ---------------------------------------------------------------------------
# Content first (F-3): sha256 of a fresh compile beats commit order
# ---------------------------------------------------------------------------


def test_touched_source_with_identical_compile_is_fresh(gate) -> None:
    """Ordering alone calls this stale; the regenerated content says otherwise."""
    module, repo, source, artifact = gate
    source.write_text("hazards: []  # comment only\n")
    _git(repo, "commit", "-qam", "touch source", date="2026-01-02T12:00:00+00:00")
    assert module.check_freshness(regenerated={artifact: artifact.read_text()}) == []


def test_artifact_committed_later_but_differing_is_stale(gate) -> None:
    """Ordering alone calls this fresh; the content mismatch is caught."""
    module, repo, source, artifact = gate
    source.write_text("hazards: [h1]\n")
    _git(repo, "commit", "-qam", "edit source", date="2026-01-02T12:00:00+00:00")
    artifact.write_text("# Generated: 2000-01-01T00:00:00+00:00\n# hand edit\n")
    _git(repo, "commit", "-qam", "unrelated artifact edit", date="2026-01-03T12:00:00+00:00")

    errors = module.check_freshness(
        regenerated={artifact: "# Generated: 2026-01-03T00:00:00+00:00\n# from h1\n"}
    )

    assert len(errors) == 1
    assert "content differs from a fresh compile (sha256)" in errors[0]


def test_volatile_stamps_are_masked_before_hashing(gate) -> None:
    module, *_ = gate
    a = '# Generated: 2000-01-01T00:00:00+00:00\n{"generated_at": "2000-01-01T00:00:00Z",' \
        ' "issued_at": "2000-01-01T00:00:00Z", "expires_at": "2001-01-01T00:00:00Z"}\n'
    b = '# Generated: 2026-10-01T14:00:00.1+00:00\n{"generated_at": "2026-10-01T14:00:00Z",' \
        ' "issued_at": "2026-10-01T14:00:00Z", "expires_at": "2027-10-01T14:00:00Z"}\n'
    assert module.content_digest(a) == module.content_digest(b)
    assert module.content_digest(a) != module.content_digest(a + "rule\n")


def test_unregenerable_artifact_falls_back_to_commit_order(gate) -> None:
    module, repo, source, artifact = gate
    source.write_text("hazards: [h1]\n")
    _git(repo, "commit", "-qam", "edit source only", date="2026-01-02T12:00:00+00:00")
    errors = module.check_freshness(regenerated={artifact: None})
    assert len(errors) == 1
    assert "committed before newest STPA source change" in errors[0]


@pytest.mark.skipif(
    _load_gate()._ruff_binary() is None, reason="ruff formats the generated Python targets"
)
def test_every_committed_artifact_matches_a_fresh_compile() -> None:
    """The recipes are right: every real artifact regenerates byte-identically."""
    module = _load_gate()
    results = module.check_content()
    assert {a.name: r.value for a, r in results.items()} == {
        a.name: "match" for a in module._GENERATED_ARTIFACTS
    }
