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

"""Unit tests for ``scripts/check_conformance_sync.py`` parity and contract gates."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts import check_conformance_sync as sync

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]


def _seed_conformance_tree(tmp_path: Path) -> Path:
    shutil.copytree(REPO_ROOT / "proof", tmp_path / "proof")
    shutil.copytree(
        REPO_ROOT / "packages" / "cage-conformance",
        tmp_path / "packages" / "cage-conformance",
        ignore=shutil.ignore_patterns("__pycache__", "dist", "*.egg-info"),
    )
    return tmp_path


def test_real_repository_passes_all_conformance_sync_gates() -> None:
    assert sync.sync_violations(REPO_ROOT) == []
    assert sync.import_violations() == []
    assert sync.rule_coverage_violations(REPO_ROOT) == []
    assert sync.internal_contract_violations(REPO_ROOT) == []
    assert sync.release_state_violations(REPO_ROOT) == []


def test_rule_coverage_catches_missing_and_stale_rules(tmp_path: Path) -> None:
    root = _seed_conformance_tree(tmp_path)
    assert sync.rule_coverage_violations(root) == []

    runner_path = (
        root
        / "packages"
        / "cage-conformance"
        / "src"
        / "cage_conformance"
        / "runner.py"
    )
    original = runner_path.read_text(encoding="utf-8")

    # Missing rule: drop infrastructure_block from STREAM_RULES
    mutated = original.replace(
        '    "infrastructure_block": "Every GOVERNANCE_INFRASTRUCTURE_BLOCK carries dependency, failure_code, and params_hash without proof_hash, kms_signature, or attempted_params",\n',
        "",
    )
    assert mutated != original
    runner_path.write_text(mutated, encoding="utf-8")
    missing_errs = sync.rule_coverage_violations(root)
    assert any(
        "infrastructure_block" in err and "missing" in err for err in missing_errs
    )

    # Stale rule: add an unlisted key in TRACE_RULES
    stale = original.replace(
        '    "single_use": "No seal is executed more than once",\n',
        '    "single_use": "No seal is executed more than once",\n'
        '    "phantom_rule": "Never emitted in proof/",\n',
    )
    runner_path.write_text(stale, encoding="utf-8")
    stale_errs = sync.rule_coverage_violations(root)
    assert any("phantom_rule" in err and "not emitted" in err for err in stale_errs)


def test_internal_contracts_catch_version_parties_and_vector_drift(
    tmp_path: Path,
) -> None:
    root = _seed_conformance_tree(tmp_path)
    assert sync.internal_contract_violations(root) == []

    pkg_src = root / "packages" / "cage-conformance" / "src" / "cage_conformance"
    init_path = pkg_src / "__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    init_path.write_text(
        init_text.replace('__version__ = "', '__version__ = "9.9.9-drift-'),
        encoding="utf-8",
    )
    errs = sync.internal_contract_violations(root)
    assert any("__init__.py __version__" in err for err in errs)
    init_path.write_text(init_text, encoding="utf-8")

    parties_path = pkg_src / "parties.json"
    parties = json.loads(parties_path.read_text(encoding="utf-8"))
    parties["profiles"].pop("substrate-v1")
    parties_path.write_text(json.dumps(parties), encoding="utf-8")
    errs = sync.internal_contract_violations(root)
    assert any("parties.json is missing profile pin(s)" in err for err in errs)

    (pkg_src / "vectors" / "substrate_v1.json").unlink()
    errs = sync.internal_contract_violations(root)
    assert any("substrate_v1.json does not exist" in err for err in errs)


def _make_release_repo(tmp_path: Path, *, version: str, status: str | None) -> Path:
    pkg_root = tmp_path / "packages" / "cage-conformance"
    pkg = pkg_root / "src" / "cage_conformance"
    (pkg / "vectors").mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (pkg / "runner.py").write_text("RULES = {}\n", encoding="utf-8")
    (pkg / "vectors" / "trace_v1.json").write_text("{}\n", encoding="utf-8")
    release_table = (
        f'[tool.cage.release]\nstatus = "{status}"\n' if status is not None else ""
    )
    (pkg_root / "pyproject.toml").write_text(
        f'[project]\nname = "cage-conformance"\nversion = "{version}"\n{release_table}',
        encoding="utf-8",
    )
    return tmp_path


def test_release_state_unreleased_requires_no_tag_and_a_newer_version(
    tmp_path: Path,
) -> None:
    repo = _make_release_repo(tmp_path / "ok", version="0.4.2", status="unreleased")
    assert (
        sync.release_state_violations(
            repo, git_tags=["conformance-v0.4.0", "conformance-v0.4.1"]
        )
        == []
    )

    tagged = sync.release_state_violations(
        repo, git_tags=["conformance-v0.4.1", "conformance-v0.4.2"]
    )
    assert any("already exists" in err for err in tagged)

    stale = _make_release_repo(tmp_path / "old", version="0.4.1", status="unreleased")
    not_newer = sync.release_state_violations(
        stale, git_tags=["conformance-v0.4.0", "conformance-v0.4.2"]
    )
    assert any("strictly greater" in err for err in not_newer)


def test_release_state_cutting_tag_must_name_the_declared_version(
    tmp_path: Path,
) -> None:
    repo = _make_release_repo(tmp_path / "cut", version="0.4.2", status="unreleased")
    tags = ["conformance-v0.4.1", "conformance-v0.4.2"]
    assert (
        sync.release_state_violations(
            repo, cutting_release_tag="conformance-v0.4.2", git_tags=tags
        )
        == []
    )

    wrong = sync.release_state_violations(
        repo, cutting_release_tag="conformance-v0.4.1", git_tags=tags
    )
    assert any("does not match expected tag" in err for err in wrong)

    behind = sync.release_state_violations(
        repo,
        cutting_release_tag="conformance-v0.4.2",
        git_tags=["conformance-v0.4.2", "conformance-v0.5.0"],
    )
    assert any(
        "strictly greater than existing release '0.5.0'" in err for err in behind
    )


def test_release_state_published_requires_tag_and_byte_identical_tree(
    tmp_path: Path,
) -> None:
    repo = _make_release_repo(tmp_path / "pub", version="0.4.2", status="published")
    no_tag = sync.release_state_violations(repo, git_tags=["conformance-v0.4.1"])
    assert any("does not exist" in err for err in no_tag)

    pkg_dir = repo / sync.PACKAGE_REL
    matching_tree = {
        rel: full.read_bytes()
        for rel, full in sync.collect_package_files(pkg_dir).items()
    }
    tags = ["conformance-v0.4.1", "conformance-v0.4.2"]
    assert (
        sync.release_state_violations(
            repo, git_tags=tags, tagged_tree_files=matching_tree
        )
        == []
    )

    (pkg_dir / "runner.py").write_text("RULES = {'drift': 'x'}\n", encoding="utf-8")
    drifted = sync.release_state_violations(
        repo, git_tags=tags, tagged_tree_files=matching_tree
    )
    assert any(
        "runner.py" in err and "diverges from published tag 'conformance-v0.4.2'" in err
        for err in drifted
    )

    (pkg_dir / "runner.py").write_text("RULES = {}\n", encoding="utf-8")
    (pkg_dir / "extra.py").write_text("X = 1\n", encoding="utf-8")
    added = sync.release_state_violations(
        repo, git_tags=tags, tagged_tree_files=matching_tree
    )
    assert any("extra.py" in err and "added since" in err for err in added)

    (pkg_dir / "extra.py").unlink()
    (pkg_dir / "vectors" / "trace_v1.json").unlink()
    removed = sync.release_state_violations(
        repo, git_tags=tags, tagged_tree_files=matching_tree
    )
    assert any("trace_v1.json" in err and "removed since" in err for err in removed)


def test_release_state_rejects_missing_status_and_non_semver_version(
    tmp_path: Path,
) -> None:
    no_status = _make_release_repo(tmp_path / "nostatus", version="0.4.2", status=None)
    errs = sync.release_state_violations(no_status, git_tags=[])
    assert any("[tool.cage.release].status must be" in err for err in errs)

    unknown = _make_release_repo(tmp_path / "unknown", version="0.4.2", status="draft")
    errs = sync.release_state_violations(unknown, git_tags=[])
    assert any("got 'draft'" in err for err in errs)

    bad_version = _make_release_repo(
        tmp_path / "badver", version="0.4.2rc1", status="unreleased"
    )
    errs = sync.release_state_violations(bad_version, git_tags=[])
    assert any("strict MAJOR.MINOR.PATCH" in err for err in errs)


def test_release_state_scopes_tags_to_head_ancestry_on_historical_rerun(
    tmp_path: Path,
) -> None:
    """Issue #927: future conformance-v* tags must not break historical CI reruns."""
    import subprocess

    repo = _make_release_repo(tmp_path, version="0.4.2", status="unreleased")
    pkg_pyproject = repo / "packages" / "cage-conformance" / "pyproject.toml"

    def _git(*args: str) -> str:
        proc = subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        )
        return proc.stdout.strip()

    _git("init", "-q")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "Test")
    _git("add", ".")
    _git("commit", "-q", "-m", "v0.4.2 unreleased")
    _git("tag", "conformance-v0.4.1")
    historical_sha = _git("rev-parse", "HEAD")

    pkg_pyproject.write_text(
        '[project]\nname = "cage-conformance"\nversion = "0.5.0"\n'
        '[tool.cage.release]\nstatus = "published"\n',
        encoding="utf-8",
    )
    _git("add", ".")
    _git("commit", "-q", "-m", "release v0.5.0")
    _git("tag", "conformance-v0.5.0")

    _git("checkout", "-q", historical_sha)
    assert sync.release_state_violations(repo) == []

    cut_errs = sync.release_state_violations(
        repo, cutting_release_tag="conformance-v0.4.2"
    )
    assert any(
        "strictly greater than existing release '0.5.0'" in err for err in cut_errs
    )

    _git("checkout", "-q", "-")
    pkg_pyproject.write_text(
        '[project]\nname = "cage-conformance"\nversion = "0.5.0"\n'
        '[tool.cage.release]\nstatus = "unreleased"\n',
        encoding="utf-8",
    )
    unrel_errs = sync.release_state_violations(repo)
    assert any("already exists" in err for err in unrel_errs)
