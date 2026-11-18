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

"""Tests for ``scripts/lula_rating_breakdown.py``.

The breakdown names the satisfied Lula specs the README rates Active. That set
must be exactly the one ``scripts/check_poam_lula_divergence.py`` accepts as
POA&M closure evidence, so the parity tests give both parsers the same README.
The breakdown runs under the system ``python3`` and cannot import that module,
which needs PyYAML; these tests are what keeps the two copies equal.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LULA_DIR = REPO_ROOT / "compliance" / "lula"


def _load(name: str, relpath: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relpath)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


breakdown_mod = _load(
    "_lula_rating_breakdown_under_test", "scripts/lula_rating_breakdown.py"
)
divergence = _load(
    "_poam_lula_divergence_for_rating_parity", "scripts/check_poam_lula_divergence.py"
)
stub_count = _load(
    "_lula_stub_count_for_rating_parity", "scripts/check_lula_stub_count.py"
)


def _closure_allowlist(repo_root: Path) -> set[str]:
    active, errors = divergence._load_active_lula_set(repo_root)
    assert errors == []
    return {Path(rel).name for rel in active}


def _committed_split() -> tuple[list[str], list[str]]:
    evaluated: list[str] = []
    skipped: list[str] = []
    for path in sorted(LULA_DIR.glob("lula-validation-*.yaml")):
        status = stub_count.extract_cage_status(path.read_text(encoding="utf-8"))
        (evaluated if status == "active" else skipped).append(path.name)
    return evaluated, skipped


def test_rated_active_is_the_closure_allowlist_for_the_committed_readme() -> None:
    readme = (LULA_DIR / "README.md").read_text(encoding="utf-8")
    assert breakdown_mod.rated_active(readme) == _closure_allowlist(REPO_ROOT)


def test_rated_active_is_the_closure_allowlist_for_awkward_rows(
    tmp_path: Path,
) -> None:
    readme = (
        "- ✅ **Active** — a legend line, not a rating\n"
        "| [`lula-validation-a.yaml`](lula-validation-a.yaml) | x | ✅ Active | y |\n"
        "| [`lula-validation-b.yaml`](lula-validation-b.yaml) | x | 🔶 Stub | y |\n"
        "Prose that names `lula-validation-c.yaml` and rates nothing.\n"
        "| [`lula-validation-d_e.yaml`](lula-validation-d_e.yaml) | ✅ Active |\n"
    )
    lula_dir = tmp_path / "compliance" / "lula"
    lula_dir.mkdir(parents=True)
    (lula_dir / "README.md").write_text(readme, encoding="utf-8")

    rated = breakdown_mod.rated_active(readme)
    assert rated == {"lula-validation-a.yaml", "lula-validation-d_e.yaml"}
    assert rated == _closure_allowlist(tmp_path)


def test_committed_tree_breakdown_accounts_for_every_manifest() -> None:
    evaluated, skipped = _committed_split()
    result = breakdown_mod.build_breakdown(LULA_DIR, evaluated, skipped)
    allowlist = _closure_allowlist(REPO_ROOT)

    # A manifest rated Active that the run skips would be closure evidence
    # nothing evaluates.
    assert allowlist <= set(evaluated)
    assert set(result["evaluated_rated_active"]) == allowlist
    assert set(result["evaluated_not_rated_active"]) == set(evaluated) - allowlist
    assert set(result["not_evaluated_not_applicable"]) == {
        name
        for name in skipped
        if stub_count.has_not_applicable_header(
            (LULA_DIR / name).read_text(encoding="utf-8")
        )
    }
    assert result["counts"] == {
        "evaluated": len(evaluated),
        "evaluated_rated_active": len(result["evaluated_rated_active"]),
        "evaluated_not_rated_active": len(result["evaluated_not_rated_active"]),
        "not_evaluated_planned": len(result["not_evaluated_planned"]),
        "not_evaluated_not_applicable": len(result["not_evaluated_not_applicable"]),
    }
    assert sorted(
        result["not_evaluated_planned"] + result["not_evaluated_not_applicable"]
    ) == sorted(skipped)


def test_lula_readme_two_counts_section_matches_the_tree() -> None:
    """The README's 'Two Counts' section states the split in prose, which no
    other gate reads; hold its numbers to the tree."""
    evaluated, skipped = _committed_split()
    counts = breakdown_mod.build_breakdown(LULA_DIR, evaluated, skipped)["counts"]
    readme = (LULA_DIR / "README.md").read_text(encoding="utf-8")

    heading = re.search(
        r"^### Two Counts: (\d+) Evaluated, (\d+) Rated Active$", readme, re.M
    )
    assert heading, "compliance/lula/README.md lost its 'Two Counts' heading"
    assert (int(heading[1]), int(heading[2])) == (
        counts["evaluated"],
        counts["evaluated_rated_active"],
    )

    def row(label_pattern: str) -> int:
        match = re.search(rf"^\| {label_pattern} \| (\d+) \|", readme, re.M)
        assert match, f"no 'Two Counts' table row matching {label_pattern!r}"
        return int(match[1])

    assert row(r"Rated Active") == counts["evaluated_rated_active"]
    assert row(r"Stub, no `cage-status` header") == counts["evaluated_not_rated_active"]
    assert row(r"Stub, `planned` \([^)]*\)") == counts["not_evaluated_planned"]
    not_applicable = counts["not_evaluated_not_applicable"]
    assert row(r"Adopter-operated, `not-applicable`") == not_applicable


def test_skipped_manifest_without_a_header_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("", encoding="utf-8")
    (tmp_path / "lula-validation-x.yaml").write_text("kind: x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="lula-validation-x.yaml"):
        breakdown_mod.build_breakdown(tmp_path, [], ["lula-validation-x.yaml"])


def test_cli_writes_the_breakdown_and_refuses_without_a_readme(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "README.md").write_text(
        "| [`lula-validation-a.yaml`](lula-validation-a.yaml) | ✅ Active |\n",
        encoding="utf-8",
    )
    (tmp_path / "lula-validation-p.yaml").write_text(
        "# cage-status: planned\n", encoding="utf-8"
    )
    argv = [
        "--lula-dir",
        str(tmp_path),
        "--evaluated",
        "lula-validation-a.yaml",
        "lula-validation-b.yaml",
        "--not-evaluated",
        "lula-validation-p.yaml",
    ]
    assert breakdown_mod.main(argv) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["evaluated_rated_active"] == ["lula-validation-a.yaml"]
    assert out["evaluated_not_rated_active"] == ["lula-validation-b.yaml"]
    assert out["not_evaluated_planned"] == ["lula-validation-p.yaml"]

    (tmp_path / "README.md").unlink()
    assert breakdown_mod.main(argv) == 1
    assert "README.md" in capsys.readouterr().err
