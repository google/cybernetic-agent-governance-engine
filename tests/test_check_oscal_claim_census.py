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
"""Unit tests for scripts/check_oscal_claim_census.py."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from scripts import check_oscal_claim_census as census_mod

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_committed_census_passes_validation_and_counts() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()
    errors = census_mod.validate_census(rows, extracted)
    assert errors == [], f"Unexpected census validation errors: {errors}"

    assert len(extracted) == 207
    assert len(rows) == 208

    counts: dict[str, int] = {}
    for row in rows:
        v = str(row["verdict"])
        counts[v] = counts.get(v, 0) + 1

    assert counts == {
        "HOLDS": 39,
        "WEAKER": 51,
        "NOT_IN_FORCE": 24,
        "INHERITED": 45,
        "ROLLUP": 35,
        "NOT_A_CLAIM": 14,
    }


def test_evidence_store_provenance_registers_gmp_monarch_and_stdout_infra_events() -> (
    None
):
    by_store = {sp.store_id: sp for sp in census_mod.EVIDENCE_STORE_PROVENANCE}
    assert "gmp_monarch" in by_store
    gmp = by_store["gmp_monarch"]
    assert gmp.storage_custody == "PLANE"
    assert gmp.content_custody == "GOV_WRITABLE"
    assert gmp.retention == "24m"

    assert "infra_events" in by_store
    infra = by_store["infra_events"]
    assert infra.content_custody == "GOV_WRITABLE"
    assert "ClickHouse `INFRA` partition" not in infra.retention_and_integrity_detail
    assert "(`Cloud Logging _Default`, `30 d`)" in infra.retention_and_integrity_detail


def test_ungraded_oscal_claim_fails_closed() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()
    extra = copy.deepcopy(extracted)
    extra["system-security-plan.yaml#ungraded-9999"] = {
        "ring": 1,
        "file": "system-security-plan.yaml",
        "id": "system-security-plan.yaml#ungraded-9999",
        "level": "by-component",
        "control": "au-2",
        "component": "CAGE Gateway",
        "status": "implemented",
        "text": "New ungraded claim",
        "links": [],
        "description_sha256": "0" * 64,
    }
    errors = census_mod.validate_census(rows, extra)
    assert any(
        "Ungraded OSCAL claim missing from census: system-security-plan.yaml#ungraded-9999"
        in e
        for e in errors
    )


def test_description_or_status_drift_fails_closed() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()

    drifted_rows = copy.deepcopy(rows)
    drifted_rows[0]["description_sha256"] = "f" * 64
    drifted_rows[1]["status_extracted"] = "planned"

    errors = census_mod.validate_census(drifted_rows, extracted)
    assert any("description_sha256 drift" in e for e in errors)
    assert any("status drift" in e for e in errors)


def test_legacy_n_finding_id_and_missing_cited_or_read_back_paths_fail_closed() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()

    bad_rows = copy.deepcopy(rows)
    bad_rows[0]["refs"] = ["F-43", "N-15"]
    bad_rows[0]["cites"] = [
        "README.md:L1; src/gateway/nonexistent_module_xyz.py:L10",
        "00000000^:src/gateway/nonexistent_pinned.py",
    ]
    bad_rows[0]["read_back"] = {
        "grade": "OBSERVES",
        "check": "tests/test_hallucinated_nonexistent_suite.py:L12",
        "runs_in": "ci:pytest-logic",
    }

    errors = census_mod.validate_census(bad_rows, extracted)
    assert any("un-renumbered legacy finding ID(s) ['N-15']" in e for e in errors)
    assert any(
        "cited repository path does not exist: src/gateway/nonexistent_module_xyz.py"
        in e
        for e in errors
    )
    assert any(
        "pinned repository path does not resolve in git: 00000000^:src/gateway/nonexistent_pinned.py"
        in e
        for e in errors
    )
    assert any(
        "read_back.check repository path does not exist: tests/test_hallucinated_nonexistent_suite.py"
        in e
        for e in errors
    )


def test_render_register_markdown_table_integrity_and_committed_parity(
    tmp_path: Path,
) -> None:
    rows = census_mod.load_census()
    md = census_mod.render_register_markdown(rows)
    assert "file://" not in md, "Rendered register must never leak local file:// URIs"
    assert "gmp_monarch" in md

    assert (
        census_mod.main(["--verify-rendered", str(census_mod.DEFAULT_REGISTER_PATH)])
        == 0
    )

    out = tmp_path / "evidence_claim_register.md"
    out.write_text(md, encoding="utf-8")
    assert census_mod.main(["--verify-rendered", str(out)]) == 0

    out.write_text(md + "\n<!-- drift -->\n", encoding="utf-8")
    assert census_mod.main(["--verify-rendered", str(out)]) == 1

    in_table = False
    expected_cols: int | None = None
    for idx, line in enumerate(md.splitlines(), 1):
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cols = len(re.split(r"(?<!\\)\|", s)) - 2
            if not in_table:
                in_table = True
                expected_cols = cols
            else:
                assert cols == expected_cols, (
                    f"Line {idx}: expected {expected_cols} cols, got {cols}"
                )
        else:
            in_table = False
            expected_cols = None
