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
# Closure regression guard for: POAM-2026-235
"""Unit tests for scripts/check_oscal_claim_census.py."""

from __future__ import annotations

import copy
import re
import subprocess
from pathlib import Path

import pytest

from scripts import check_oscal_claim_census as census_mod

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_committed_census_passes_validation_and_counts() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()
    assert census_mod.validate_oscal_structure() == []
    errors = census_mod.validate_census(rows, extracted)
    assert errors == [], f"Unexpected census validation errors: {errors}"

    assert (
        "components/cage_client_sdk.yaml#1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
        in extracted
    )
    assert len(extracted) == 212
    assert len(rows) == 213

    counts: dict[str, int] = {}
    for row in rows:
        v = str(row["verdict"])
        counts[v] = counts.get(v, 0) + 1

    assert counts == {
        "HOLDS": 29,
        "WEAKER": 67,
        "NOT_IN_FORCE": 24,
        "INHERITED": 45,
        "ROLLUP": 35,
        "NOT_A_CLAIM": 13,
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


def test_poam_235_holds_rejects_meta_schema_test_and_oob_or_symbol_decay() -> None:
    rows = census_mod.load_census()
    extracted = census_mod.extract_all_oscal_claims()

    bad_rows = copy.deepcopy(rows)
    # 1. HOLDS row relying on tests/test_lula_v0160_schema.py fails closed
    holds_idx = next(i for i, r in enumerate(bad_rows) if r["verdict"] == "HOLDS")
    bad_rows[holds_idx]["read_back"]["check"] = (
        "tests/test_lula_v0160_schema.py:L56; tests/test_ftra_package.py"
    )
    # 2. WEAKER row with out-of-bounds line citation in custody.note and missing AST symbol fails closed
    bad_rows[0]["custody"]["note"] = (
        "Checked in src/gateway/governance/seams/credential_broker.py:L1-L9999 and "
        "deployment/k8s/deleted_unpinned_manifest.yaml:L10."
    )
    bad_rows[0]["evidence_named"] = [
        "src/gateway/governance/seams/credential_broker.py::NonExistentSymbolXYZ"
    ]

    errors = census_mod.validate_census(bad_rows, extracted)
    assert any(
        "HOLDS claim cannot rely on meta/schema test 'tests/test_lula_v0160_schema.py'"
        in e
        for e in errors
    ), errors
    assert any(
        "out-of-bounds line citation in custody.note: src/gateway/governance/seams/credential_broker.py:L1-L9999"
        in e
        for e in errors
    ), errors
    assert any(
        "custody.note repository path does not exist: deployment/k8s/deleted_unpinned_manifest.yaml"
        in e
        for e in errors
    ), errors
    assert any(
        "cited Python symbol does not exist: src/gateway/governance/seams/credential_broker.py::NonExistentSymbolXYZ"
        in e
        for e in errors
    ), errors


def test_poam_235_code_anchors_detect_planted_source_decay(tmp_path: Path) -> None:
    src_py = tmp_path / "src" / "compliance_bridge"
    src_py.mkdir(parents=True)
    target = src_py / "metrics.py"
    target.write_text(
        "def _is_control_effective_record(rec: dict) -> bool:\n"
        "    return rec.get('outcome') == 'PASSED'\n",
        encoding="utf-8",
    )
    row = {
        "id": "component-definition.yaml#synthetic-1",
        "verdict": "WEAKER",
        "disposition": "fix",
        "custody": {"grade": "PLANE", "note": "ok"},
        "read_back": {"grade": "NONE", "check": "none", "runs_in": "none"},
        "lifetime": {"grade": "REPO", "note": "ok"},
        "w_binding": {"value": False, "object": ""},
        "description_sha256": "a" * 64,
        "status_extracted": "partially-implemented",
        "code_anchors": [
            {
                "path": "src/compliance_bridge/metrics.py",
                "symbol": "_is_control_effective_record",
                "must_contain": ["PREVENTIVE_ENFORCEMENT_EVENT_TYPES"],
                "must_not_contain": ["outcome') == 'PASSED'"],
            }
        ],
    }
    sa11 = {
        "id": "SA11-SYSTEMIC",
        "verdict": "WEAKER",
        "disposition": "restate",
        "custody": {"grade": "CONFIG", "note": "ok"},
        "read_back": {"grade": "PRESENCE", "check": "none", "runs_in": "none"},
        "lifetime": {"grade": "REPO", "note": "ok"},
        "description_sha256": census_mod.hashlib.sha256(b"").hexdigest(),
    }
    extracted = {
        "component-definition.yaml#synthetic-1": {
            "id": "component-definition.yaml#synthetic-1",
            "control": "A.5.3",
            "status": "partially-implemented",
            "description_sha256": "a" * 64,
        }
    }
    errors = census_mod.validate_census([row, sa11], extracted, repo_root=tmp_path)
    assert any(
        "missing required snippet 'PREVENTIVE_ENFORCEMENT_EVENT_TYPES'" in e
        for e in errors
    ), errors
    assert any("found forbidden snippet" in e for e in errors), errors


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


def test_validate_oscal_structure_rejects_nested_component_in_control_implementations(
    tmp_path: Path,
) -> None:
    oscal_dir = tmp_path / "compliance" / "oscal"
    oscal_dir.mkdir(parents=True)
    (oscal_dir / "component-definition.yaml").write_text(
        "component-definition:\n"
        "  components:\n"
        "  - uuid: comp-parent\n"
        "    type: software\n"
        "    title: ParentEngine\n"
        "    control-implementations:\n"
        "    - uuid: ci-valid\n"
        "      source: sp800-53\n"
        "      implemented-requirements: []\n"
        "    - uuid: comp-misnested\n"
        "      type: software\n"
        "      title: MisnestedTokenQuotaProxy\n"
        "      control-implementations: []\n",
        encoding="utf-8",
    )
    struct_errs = census_mod.validate_oscal_structure(oscal_dir)
    assert len(struct_errs) == 1
    assert "MisnestedTokenQuotaProxy" in struct_errs[0]
    assert "ParentEngine" in struct_errs[0]


def test_pinned_path_exists_in_git_rejects_non_ancestor_commit(
    tmp_path: Path,
) -> None:
    def _git(*args: str) -> str:
        res = subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return res.stdout.strip()

    _git("init", "-b", "main")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "Test User")

    (tmp_path / "README.md").write_text("mainline\n", encoding="utf-8")
    _git("add", "README.md")
    _git("commit", "-m", "initial mainline")
    main_sha = _git("rev-parse", "HEAD")

    _git("checkout", "--orphan", "unmerged-side")
    _git("rm", "-rf", ".")
    (tmp_path / "retired.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "retired.py")
    _git("commit", "-m", "orphan commit")
    orphan_sha = _git("rev-parse", "HEAD")

    _git("checkout", "main")

    # Object exists in .git/objects, yet is NOT an ancestor of HEAD:
    assert census_mod._pinned_path_exists_in_git(main_sha, "README.md", tmp_path)
    assert not census_mod._pinned_path_exists_in_git(orphan_sha, "retired.py", tmp_path)


def test_poam_235_holds_rejects_missing_test_fn_and_fallback_seal_or_software_signer(
    tmp_path: Path,
) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_strict.py").write_text(
        "def test_strict_enforced() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    (tests_dir / "test_non_strict_seal.py").write_text(
        'import os\nos.environ.setdefault("CAGE_SEAL_STRICT_MODE", "false")\n'
        "def test_seal_fallback() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    (tests_dir / "test_sw_signer_only.py").write_text(
        "class SoftwareEd25519Provider:\n    pass\n"
        "def test_sw_roundtrip() -> None:\n    assert SoftwareEd25519Provider() is not None\n",
        encoding="utf-8",
    )

    sa11 = {
        "id": "SA11-SYSTEMIC",
        "verdict": "WEAKER",
        "disposition": "restate",
        "custody": {"grade": "CONFIG", "note": "ok"},
        "read_back": {"grade": "PRESENCE", "check": "none", "runs_in": "none"},
        "lifetime": {"grade": "REPO", "note": "ok"},
        "description_sha256": census_mod.hashlib.sha256(b"").hexdigest(),
    }

    def _base_holds_row(rid: str, control: str = "ac-3") -> dict[str, object]:
        return {
            "id": rid,
            "control": control,
            "claim": "Strict control claim",
            "verdict": "HOLDS",
            "disposition": "holds",
            "custody": {"grade": "PLANE", "note": "ok"},
            "read_back": {
                "grade": "OBSERVES",
                "check": "tests/test_strict.py:L1 (test_strict_enforced)",
                "runs_in": "ci:pytest-logic",
            },
            "lifetime": {"grade": "REPO", "note": "ok"},
            "w_binding": {"value": False, "object": ""},
            "cites": ["tests/test_strict.py:L1-L2"],
            "evidence_named": ["tests/test_strict.py"],
            "description_sha256": "b" * 64,
            "status_extracted": "implemented",
        }

    ext_ok = {
        "sp800-53-component-definition.yaml#ok-1": {
            "id": "sp800-53-component-definition.yaml#ok-1",
            "control": "ac-3",
            "status": "implemented",
            "text": "Verified by test_strict_enforced.",
            "description_sha256": "b" * 64,
        }
    }
    assert (
        census_mod.validate_census(
            [_base_holds_row("sp800-53-component-definition.yaml#ok-1"), sa11],
            ext_ok,
            repo_root=tmp_path,
        )
        == []
    )

    # (a) Missing test_* function in OSCAL text fails closed
    ext_ghost = copy.deepcopy(ext_ok)
    ext_ghost["sp800-53-component-definition.yaml#ok-1"]["text"] = (
        "Verified by test_deleted_ghost_function."
    )
    errs_ghost = census_mod.validate_census(
        [_base_holds_row("sp800-53-component-definition.yaml#ok-1"), sa11],
        ext_ghost,
        repo_root=tmp_path,
    )
    assert any(
        "HOLDS oscal.text cites missing test function 'test_deleted_ghost_function'"
        in e
        for e in errs_ghost
    ), errs_ghost

    # (b) CAGE_SEAL_STRICT_MODE="false" test suite fails closed on HOLDS
    row_seal = _base_holds_row("sp800-53-component-definition.yaml#ok-1")
    row_seal["read_back"] = {
        "grade": "OBSERVES",
        "check": "tests/test_non_strict_seal.py:L3",
        "runs_in": "ci:pytest-logic",
    }
    row_seal["cites"] = ["tests/test_non_strict_seal.py:L1-L4"]
    row_seal["evidence_named"] = ["tests/test_non_strict_seal.py"]
    errs_seal = census_mod.validate_census([row_seal, sa11], ext_ok, repo_root=tmp_path)
    assert any("setting CAGE_SEAL_STRICT_MODE=false" in e for e in errs_seal), errs_seal

    # (c) Implemented sc-13 HOLDS backed solely by SoftwareEd25519Provider fails closed
    row_sw = _base_holds_row("sp800-53-component-definition.yaml#ok-1", control="sc-13")
    row_sw["read_back"] = {
        "grade": "OBSERVES",
        "check": "tests/test_sw_signer_only.py:L3",
        "runs_in": "ci:pytest-logic",
    }
    row_sw["cites"] = ["tests/test_sw_signer_only.py:L1-L4"]
    row_sw["evidence_named"] = ["tests/test_sw_signer_only.py"]
    ext_sw = copy.deepcopy(ext_ok)
    ext_sw["sp800-53-component-definition.yaml#ok-1"]["control"] = "sc-13"
    ext_sw["sp800-53-component-definition.yaml#ok-1"]["text"] = (
        "Verified by test_sw_roundtrip."
    )
    errs_sw = census_mod.validate_census([row_sw, sa11], ext_sw, repo_root=tmp_path)
    assert any(
        "software-fallback test signers without KMS/IaC verification" in e
        for e in errs_sw
    ), errs_sw
