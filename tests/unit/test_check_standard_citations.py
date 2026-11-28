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
"""Tests for the standards-citation gate (``scripts/check_standard_citations.py``).

POAM-2026-247: every rule, extractor anchoring, the reference-table schema, and
the line-number-free monotonic ratchet.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest

from scripts import check_standard_citations as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLES_DIR = REPO_ROOT / "compliance" / "standards"


@pytest.fixture(scope="module")
def tables() -> dict[str, gate.Table]:
    loaded, errors = gate.load_tables(TABLES_DIR)
    assert errors == []
    return loaded


@pytest.fixture(scope="module")
def families(tables: dict[str, gate.Table]) -> frozenset[str]:
    return frozenset(r for r in tables[gate.STD_853].rows if len(r) == 2)


def _scan_line(
    text: str, tables: dict[str, gate.Table], families: frozenset[str]
) -> list[gate.Violation]:
    return list(gate.scan_text_lines("docs/x.md", [(1, text)], tables, families))


def _classes(violations: list[gate.Violation]) -> list[tuple[str, str, str]]:
    return [(v.standard, v.cited, v.vclass) for v in violations]


# --- table schema -------------------------------------------------------------


def test_every_committed_table_declares_its_source() -> None:
    paths = sorted(TABLES_DIR.glob("*.json"))
    assert len(paths) >= 10
    for path in paths:
        doc = json.loads(path.read_text(encoding="utf-8"))
        for key in ("source_url", "version", "retrieved", "source_quality"):
            assert isinstance(doc.get(key), str) and doc[key], (
                f"{path.name} lacks {key}"
            )
        assert doc["source_quality"] in {"primary", "secondary", "knowledge-unverified"}
        assert gate.validate_table_doc(doc, path.name) == []
        for row in doc["rows"]:
            assert row["status"] in {"active", "withdrawn"}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.pop("source_quality"),
        lambda d: d.update(source_quality="blog"),
        lambda d: d.update(retrieved="last week"),
        lambda d: d.update(source_url="http://insecure.example"),
        lambda d: d["rows"].append(dict(d["rows"][0])),
        lambda d: d["rows"][0].update(status="retired"),
    ],
    ids=[
        "missing-quality",
        "bad-quality",
        "bad-date",
        "http-url",
        "duplicate-id",
        "bad-status",
    ],
)
def test_table_schema_rejects_malformed_tables(mutation) -> None:
    doc = json.loads((TABLES_DIR / "nist_ai_600_1.json").read_text(encoding="utf-8"))
    mutation(doc)
    assert gate.validate_table_doc(doc, "t.json") != []


def test_secondary_table_must_cite_secondary_sources() -> None:
    doc = json.loads(
        (TABLES_DIR / "iso_iec_42001_2023.json").read_text(encoding="utf-8")
    )
    assert doc["source_quality"] == "secondary"
    doc.pop("secondary_sources")
    assert any("secondary_sources" in e for e in gate.validate_table_doc(doc, "t.json"))


def test_sp800_53_table_is_derived_from_the_nist_catalog(
    tables: dict[str, gate.Table],
) -> None:
    doc = json.loads(
        (TABLES_DIR / "nist_sp_800_53_r5.json").read_text(encoding="utf-8")
    )
    assert doc["source_quality"] == "primary"
    assert len(doc["source_sha256"]) == 64
    assert "17 U.S.C. 105" in doc["license"]
    rows = tables[gate.STD_853].rows
    assert rows["SA-12"].status == "withdrawn" and rows["SA-12"].replaced_by == ("SR",)
    assert rows["SI-8(1)"].status == "withdrawn"
    assert rows["SC-4"].title == "Information in Shared System Resources"


def test_six_primary_tables_record_source_sha256() -> None:
    expected_primary = {
        "dora_2022_2554.json",
        "eu_ai_act_2024_1689.json",
        "gdpr_2016_679.json",
        "nist_ai_600_1.json",
        "nist_ai_rmf_1_0.json",
        "nist_sp_800_53_r5.json",
    }
    actual_primary = set()
    for path in sorted(TABLES_DIR.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc["source_quality"] == "primary":
            actual_primary.add(path.name)
            sha = doc.get("source_sha256", "")
            assert isinstance(sha, str) and len(sha) == 64, path.name
            assert isinstance(doc.get("license"), str) and doc["license"], path.name
    assert actual_primary == expected_primary


# --- rule 1: existence --------------------------------------------------------


def test_nonexistent_subsection_is_flagged(tables, families) -> None:
    got = _classes(
        _scan_line("Per NIST AI 600-1 §2.5.4 the operator decides.", tables, families)
    )
    assert got == [(gate.STD_AI600, "2.5.4", gate.NONEXISTENT)]


def test_nonexistent_article_point_is_flagged(tables, families) -> None:
    got = _classes(
        _scan_line("DORA Art. 12(1)(d) continuity testing", tables, families)
    )
    assert (gate.STD_DORA, "12(1)(d)", gate.NONEXISTENT) in got


def test_withdrawn_control_is_flagged_with_successor(tables, families) -> None:
    violations = _scan_line("NIST SP 800-53 SA-12 supply chain", tables, families)
    assert _classes(violations) == [(gate.STD_853, "SA-12", gate.WITHDRAWN)]
    assert "SR" in violations[0].message


def test_withdrawn_enhancement_in_profile_with_ids(tables, families) -> None:
    lines = [(1, "      with-ids:"), (2, "        - si-8.1"), (3, "        - si-8.2")]
    got = _classes(
        list(
            gate.scan_text_lines(
                "compliance/oscal/sp800053-profile.yaml",
                lines,
                tables,
                families,
                oscal=True,
            )
        )
    )
    assert got == [(gate.STD_853, "SI-8(1)", gate.WITHDRAWN)]


def test_existing_ids_pass(tables, families) -> None:
    text = "NIST AI 600-1 §2.8 Information Integrity; ISO/IEC 42001 A.6.2.8; EU AI Act Art. 72; NIST SP 800-53 AC-2(1)"
    assert _scan_line(text, tables, families) == []


# --- rule 2: attached title / meaning -----------------------------------------


@pytest.mark.parametrize(
    ("text", "cited"),
    [
        ("NIST AI 600-1 §2.7 Information Integrity", "2.7"),
        ("AI 600-1 §2.3 prompt injection / data poisoning controls", "2.3"),
        ("ISO 42001 A.5.3 — Logging and Monitoring", "A.5.3"),
        ("EU AI Act Art. 61 post-market monitoring", "61"),
        ("MAS FEAT Principle 2 (Ethics)", "2"),
        ("MAS TRM §4.2 (Data Residency)", "4.2"),
    ],
)
def test_wrong_title_is_flagged(text: str, cited: str, tables, families) -> None:
    got = _classes(_scan_line(text, tables, families))
    assert [(c, k) for _, c, k in got] == [(cited, gate.WRONG_TITLE)]


@pytest.mark.parametrize(
    "text",
    [
        "NIST AI 600-1 §2.8 Information Integrity",
        "NIST AI 600-1 §2.9 (prompt injection)",
        "ISO/IEC 42001 A.6.2.8 — AI system recording of event logs",
        "EU AI Act Art. 14 (Human oversight)",
        "NIST SP 800-53 CA-2 Security Assessments",
        "NIST AI 600-1 §2.8 is the relevant risk",
    ],
)
def test_matching_or_prose_titles_pass(text: str, tables, families) -> None:
    assert _scan_line(text, tables, families) == []


# --- rule 3: exact titles in structured slots ---------------------------------


def _mapping(descriptions: dict[str, str]) -> str:
    return json.dumps(
        {"_framework_id": "ISO42001", "control_descriptions": descriptions}, indent=2
    )


def test_framework_mapping_title_must_be_exact(tables, families) -> None:
    text = _mapping({"A.5.2": "Social impact — AI system impact on society"})
    got = list(
        gate.scan_framework_mapping(
            "config/oscal/framework_mappings/ISO_42001.json",
            text,
            gate.STD_ISO,
            tables,
            families,
        )
    )
    assert _classes(got) == [(gate.STD_ISO, "A.5.2", gate.EXACT_TITLE_MISMATCH)]


def test_framework_mapping_exact_title_passes_and_case_matters(
    tables, families
) -> None:
    ok = _mapping(
        {"A.5.2": "AI system impact assessment process — elaboration allowed"}
    )
    assert (
        list(gate.scan_framework_mapping("m.json", ok, gate.STD_ISO, tables, families))
        == []
    )
    case = _mapping({"A.5.2": "AI System Impact Assessment Process"})
    got = list(
        gate.scan_framework_mapping("m.json", case, gate.STD_ISO, tables, families)
    )
    assert _classes(got) == [(gate.STD_ISO, "A.5.2", gate.EXACT_TITLE_MISMATCH)]


def test_oscal_title_field_uses_exact_prefix(tables, families) -> None:
    bad = [
        (
            1,
            '        title: "Lula Validation: ISO 42001 A.5.2 Social Impact Assessment"',
        )
    ]
    good = [
        (
            1,
            "      title: ISO/IEC 42001 A.6.2.8 AI system recording of event logs boundary",
        )
    ]
    rel = "compliance/oscal/sp800-53-component-definition.yaml"
    assert _classes(
        list(gate.scan_text_lines(rel, bad, tables, families, oscal=True))
    ) == [(gate.STD_ISO, "A.5.2", gate.EXACT_TITLE_MISMATCH)]
    assert list(gate.scan_text_lines(rel, good, tables, families, oscal=True)) == []


def test_exact_title_normalizes_unicode_dashes_and_whitespace(tables, families) -> None:
    ascii_hyphen = _mapping(
        {
            "Annex XI": (
                "Technical documentation referred to in Article 53(1), point (a) - "
                "technical documentation for providers of general-purpose AI models"
            )
        }
    )
    em_dash_with_elaboration = _mapping(
        {
            "Annex XI": (
                "Technical documentation   referred to in Article 53(1), point (a) — "
                "technical documentation for providers of general\u2011purpose AI models — "
                "CAGE model card mapping"
            )
        }
    )
    assert (
        list(
            gate.scan_framework_mapping(
                "m.json", ascii_hyphen, gate.STD_EU, tables, families
            )
        )
        == []
    )
    assert (
        list(
            gate.scan_framework_mapping(
                "m.json", em_dash_with_elaboration, gate.STD_EU, tables, families
            )
        )
        == []
    )
    rel = "compliance/oscal/sp800-53-component-definition.yaml"
    oj_typo_alias = [
        (
            1,
            "      title: EU AI Act Art. 111 AI systems already placed on the market "
            "or put into service and general-purpose AI models already placed on the marked",
        )
    ]
    assert (
        list(gate.scan_text_lines(rel, oj_typo_alias, tables, families, oscal=True))
        == []
    )


def test_map_literals_are_exact_title_slots(tables, families) -> None:
    source = textwrap.dedent(
        """
        NIST_MAP: dict[str, str] = {"A.5.3": "AU-12", "A.5.2": "GOVERN 1.1", "SC-4": "AC-6"}
        EU_MAP: dict[str, str] = {"A.5.2": "Art. 9 (Risk management system)", "A.6.2": "Art. 9 (Risk Management System)"}
        MAS_MAP: dict[str, str] = {"A.9.2": "MAS TRM §4.2 (Data Residency)"}
        """
    )
    got = _classes(
        list(gate.scan_map_literals(gate.ISO_CONTROL_REL, source, tables, families))
    )
    assert (gate.STD_853, "GOVERN 1.1", gate.NONEXISTENT) in got
    assert (gate.STD_853, "SC-4", gate.ID_COLLISION) in got
    assert got.count((gate.STD_EU, "9", gate.EXACT_TITLE_MISMATCH)) == 1
    assert (gate.STD_TRM, "4.2", gate.EXACT_TITLE_MISMATCH) in got
    assert all(c != "AU-12" for _, c, _ in got)


# --- rule 4: internal identifier collisions -----------------------------------


def test_internal_constraint_in_nist_context_collides(tables, families) -> None:
    got = _classes(
        _scan_line(
            "NIST SC-4 maps to CAGE custom System Constraint SC-4", tables, families
        )
    )
    assert got == [(gate.STD_853, "SC-4", gate.ID_COLLISION)]


@pytest.mark.parametrize(
    "text",
    [
        "NIST SC-4 maps to CAGE-SC-4 (fiscal limits)",
        "System Constraint SC-4 bounds fiscal exposure",
        "FED-SR-26-2-3 is cited next to NIST SP 800-53 SI-7",
    ],
)
def test_prefixed_or_non_nist_internal_ids_pass(text: str, tables, families) -> None:
    assert _scan_line(text, tables, families) == []


@pytest.mark.parametrize(
    ("text", "iid"),
    [
        ("### CA-04 MEDIUM — notes cross-reference NIST controls", "CA-04"),
        ("SR-26-2-3 sits beside NIST SP 800-53 SI-7", "SR-26-2-3"),
        ("See CP-3 in BREAKING_CHANGES for the NIST SP 800-53 mapping", "CP-3"),
    ],
)
def test_other_internal_shapes_collide(text: str, iid: str, tables, families) -> None:
    assert (gate.STD_853, iid, gate.ID_COLLISION) in _classes(
        _scan_line(text, tables, families)
    )


# --- extractor anchoring ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "See section 2.7 of the paper and §2.7 above.",
        "Version 2.7 of the chart; A.5.2 of the appendix.",
        "AI 600-1 2.7 is cited without a section sign.",
    ],
)
def test_unanchored_numbers_are_ignored(text: str, families) -> None:
    assert [
        c
        for c in gate.extract_line(text, families)
        if c.standard == gate.STD_AI600 or c.standard == gate.STD_ISO
    ] == []


def test_anchor_chains_and_stops_at_table_cells(families) -> None:
    cits = gate.extract_line(
        "ISO 42001 A.5.2, A.5.3 and A.9.2 | §4.7 Human-AI Config", families
    )
    assert [(c.standard, c.cited) for c in cits] == [
        (gate.STD_ISO, "A.5.2"),
        (gate.STD_ISO, "A.5.3"),
        (gate.STD_ISO, "A.9.2"),
    ]


def test_nearest_anchor_owns_article_numbers(families) -> None:
    cits = gate.extract_line("EU AI Act Art. 14 and GDPR Art. 22(3)", families)
    assert [(c.standard, c.cited) for c in cits] == [
        (gate.STD_EU, "14"),
        (gate.STD_GDPR, "22(3)"),
    ]


def test_docstrings_only_in_python(tables, families) -> None:
    source = '"""Module — AI 600-1 §2.5.1 control."""\nX = "AI 600-1 §2.5.1"  # AI 600-1 §2.5.1\n'
    lines = gate.docstring_lines(source)
    assert lines == [(1, "Module — AI 600-1 §2.5.1 control.")]


# --- ratchet ------------------------------------------------------------------


def _mini_repo(tmp_path: Path, body: str) -> Path:
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.md").write_text(body, encoding="utf-8")
    return root


def _run(root: Path, tables_dir: Path, *extra: str) -> int:
    return gate.main(
        [
            "--root",
            str(root),
            "--tables-dir",
            str(tables_dir),
            "--baseline",
            str(root / "baseline.json"),
            *extra,
        ]
    )


REASON = "seed baseline for the ratchet unit test fixture"
BAD_A = "NIST AI 600-1 §2.5.1 oversight\n"
BAD_B = "NIST AI 600-1 §2.5.2 oversight\n"


def test_ratchet_rejects_new_identity_even_when_total_does_not_rise(
    tmp_path: Path,
) -> None:
    root = _mini_repo(tmp_path, "intro\n" + BAD_A)
    assert _run(root, TABLES_DIR, "--init-baseline", "--reason", REASON) == 0
    assert _run(root, TABLES_DIR) == 0
    (root / "docs" / "a.md").write_text("intro\n" + BAD_B, encoding="utf-8")
    assert _run(root, TABLES_DIR) == 1


def test_ratchet_fingerprint_is_stable_under_line_moves(tmp_path: Path) -> None:
    root = _mini_repo(tmp_path, "intro\n" + BAD_A + "tail\n")
    assert _run(root, TABLES_DIR, "--init-baseline", "--reason", REASON) == 0
    (root / "docs" / "a.md").write_text(
        "\n\n\nnew heading\n" + "tail\n" + "  " + BAD_A.replace(" ", "  "),
        encoding="utf-8",
    )
    assert _run(root, TABLES_DIR) == 0


def test_ratchet_counts_duplicates_per_identity(tmp_path: Path) -> None:
    root = _mini_repo(tmp_path, BAD_A)
    assert _run(root, TABLES_DIR, "--init-baseline", "--reason", REASON) == 0
    (root / "docs" / "a.md").write_text(BAD_A + BAD_A, encoding="utf-8")
    assert _run(root, TABLES_DIR) == 1


def test_update_baseline_only_lowers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _mini_repo(tmp_path, BAD_A + BAD_B)
    assert _run(root, TABLES_DIR, "--init-baseline", "--reason", REASON) == 0
    (root / "docs" / "a.md").write_text(BAD_A, encoding="utf-8")
    capsys.readouterr()
    assert _run(root, TABLES_DIR) == 1
    assert "--update-baseline" in capsys.readouterr().err
    assert _run(root, TABLES_DIR, "--update-baseline") == 0
    assert _run(root, TABLES_DIR) == 0
    state, err = gate.read_baseline(root / "baseline.json")
    assert err is None and state is not None and state.total == 1
    (root / "docs" / "a.md").write_text(BAD_A + BAD_B, encoding="utf-8")
    assert _run(root, TABLES_DIR, "--update-baseline") == 1
    state, _ = gate.read_baseline(root / "baseline.json")
    assert state is not None and state.total == 1


def test_recompute_requires_changed_fingerprint_and_reason(tmp_path: Path) -> None:
    root = _mini_repo(tmp_path, BAD_A)
    tables_copy = tmp_path / "tables"
    shutil.copytree(TABLES_DIR, tables_copy)
    assert _run(root, tables_copy, "--init-baseline", "--reason", REASON) == 0
    assert _run(root, tables_copy, "--recompute-baseline", "--reason", REASON) == 1
    path = tables_copy / "nist_ai_600_1.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["rows"][0].setdefault("aliases", []).append("Opening")
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _run(root, tables_copy) == 1
    assert _run(root, tables_copy, "--recompute-baseline", "--reason", "too short") == 1
    assert _run(root, tables_copy, "--recompute-baseline", "--reason", REASON) == 0
    assert _run(root, tables_copy) == 0
    state, err = gate.read_baseline(root / "baseline.json")
    assert err is None and state is not None
    assert [h["event"] for h in state.history] == ["initial_baseline", "recompute"]


def test_history_rejects_update_that_raises_the_baseline(tmp_path: Path) -> None:
    root = _mini_repo(tmp_path, BAD_A)
    assert _run(root, TABLES_DIR, "--init-baseline", "--reason", REASON) == 0
    path = root / "baseline.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    sha = doc["detector_sha256"]
    doc["history"].append(
        {
            "event": "update",
            "detector_sha256": sha,
            "before_detector_sha256": sha,
            "before_baseline": 1,
            "after_baseline": 2,
            "reason": "raise",
        }
    )
    path.write_text(json.dumps(doc), encoding="utf-8")
    _, err = gate.read_baseline(path)
    assert err is not None and "raised baseline" in err


def test_detector_fingerprint_ignores_comments_but_not_logic(tmp_path: Path) -> None:
    script = Path(gate.__file__)
    base = gate.compute_detector_fingerprint(script, TABLES_DIR)
    copy = tmp_path / "copy.py"
    source = script.read_text(encoding="utf-8")
    copy.write_text(
        source.replace("# --- title matching", "# --- title matching (reworded)"),
        encoding="utf-8",
    )
    assert gate.compute_detector_fingerprint(copy, TABLES_DIR) == base
    copy.write_text(
        source.replace("ZONE_MAX: Final[int] = 160", "ZONE_MAX: Final[int] = 161"),
        encoding="utf-8",
    )
    assert gate.compute_detector_fingerprint(copy, TABLES_DIR) != base


def test_committed_baseline_is_valid_and_repo_has_no_new_violations() -> None:
    state, err = gate.read_baseline(REPO_ROOT / gate.BASELINE_REL)
    assert err is None and state is not None
    assert state.history[0]["event"] == "initial_baseline"
    assert gate.main([]) == 0
