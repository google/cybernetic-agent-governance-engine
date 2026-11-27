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
