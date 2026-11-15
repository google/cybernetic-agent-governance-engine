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
# Closure regression guard for: POAM-2026-027, POAM-2026-176

"""Contract, bypass-closure, and mutation-killing tests for scripts/check_poam_lula_divergence.py.

Covers:
- Live repository four-check audit pass (100+ closed rows, 100+ detail sections,
  12 active Lula v0.16.0 manifests, 0 waivers)
- Legacy waiver retirement (no NON_TESTABLE_CONTROLS, CODE_EVIDENCE_FINDINGS,
  CONTROL_ALIASES, or control-ID stem matching)
- Duplicate ### POAM-YYYY-NNN header detection, Open/Closed overlap rejection,
  and backtick-pipe row parsing (POAM-2026-027, POAM-2026-176)
- All 6 hardened Check 2 / Check 3 / Check 1 bypass closures:
  1. Bypass 1: EVIDENCE_STORE_REGISTRY consulted (incl. opa_decision_logs and gmp_monarch)
  2. Bypass 2: Bare Valkey (DB 0) and ClickHouse infra_events rejected for custody
  3. Bypass 3: ### POAM-... detail sections parsed and audited for parity + Check 1/2/3
  4. Bypass 4: Reopened open rows lacking "Closes on" fail [Check 1: Reopened Schema]
     and are never silently skipped by Check 2 / Check 3
  5. Bypass 5: Clause-scoped _TELEMETRY_QUALIFIER_RE and retention qualifiers
  6. Bypass 6: .github/workflows/*.yml + Observed still requires finding-ID binding
- Hermetic PR-CI pytest marker requirement (live_external alone rejected)
- Non-implemented HOLDS census row path verification (Deliverable 2)
- CE-M1..CE-M6 mutation-killing checks across regional POA&Ms, Lula, and OSCAL census
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import shutil
import sys

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

_SPEC = importlib.util.spec_from_file_location(
    "check_poam_lula_divergence",
    _REPO_ROOT / "scripts" / "check_poam_lula_divergence.py",
)
assert _SPEC is not None and _SPEC.loader is not None
drift = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = drift
_SPEC.loader.exec_module(drift)

_CENSUS_SPEC = importlib.util.spec_from_file_location(
    "check_oscal_claim_census",
    _REPO_ROOT / "scripts" / "check_oscal_claim_census.py",
)
assert _CENSUS_SPEC is not None and _CENSUS_SPEC.loader is not None
census_mod = importlib.util.module_from_spec(_CENSUS_SPEC)
sys.modules[_CENSUS_SPEC.name] = census_mod
_CENSUS_SPEC.loader.exec_module(census_mod)


@pytest.fixture()
def synthetic_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """Construct a fast, self-contained valid repository passing all 4 PR-9 checks."""
    repo = tmp_path / "repo"
    (repo / "docs" / "compliance" / "cross-region").mkdir(parents=True)
    (repo / "docs" / "compliance" / "universal").mkdir(parents=True)
    (repo / "docs" / "compliance" / "us_fed").mkdir(parents=True)
    (repo / "docs" / "compliance" / "eu_ecb").mkdir(parents=True)
    (repo / "docs" / "compliance" / "apac_mas").mkdir(parents=True)
    (repo / "docs" / "operations").mkdir(parents=True)
    (repo / "compliance" / "lula").mkdir(parents=True)
    (repo / "compliance" / "oscal").mkdir(parents=True)
    (repo / "scripts").mkdir(parents=True)
    (repo / "tests" / "unit").mkdir(parents=True)
    (repo / "infra" / "targets" / "gcp-gke").mkdir(parents=True)
    (repo / "deployment" / "k8s").mkdir(parents=True)
    (repo / "config").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)

    shutil.copy2(
        _REPO_ROOT / "scripts" / "check_oscal_claim_census.py",
        repo / "scripts" / "check_oscal_claim_census.py",
    )

    # CI workflow referencing scripts/check_sample_gate.py
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [pull_request]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: uv run python scripts/check_sample_gate.py\n",
        encoding="utf-8",
    )
    (repo / "scripts" / "check_sample_gate.py").write_text(
        "# Gate guard for POAM-2026-002\nprint('ok')\n",
        encoding="utf-8",
    )

    # Runnable pytest file binding POAM-2026-001, ISO-001, AI600-004, EU-AI-001, MAS-655-001
    (repo / "tests" / "unit" / "test_bound_guard.py").write_text(
        "import pytest\n"
        "# Closure regression guard for: POAM-2026-001, ISO-001, AI600-004, EU-AI-001, MAS-655-001\n"
        "pytestmark = [pytest.mark.unit, pytest.mark.local]\n\n"
        "def test_enforces_guard() -> None:\n"
        "    assert True\n",
        encoding="utf-8",
    )

    # Config / deployment / prose decoys (never sufficient on their own)
    (repo / "infra" / "targets" / "gcp-gke" / "main.tf").write_text(
        "# POAM-2026-999\n", encoding="utf-8"
    )
    (repo / "infra" / "targets" / "gcp-gke" / "staging.tfvars").write_text(
        'env = "staging"\n', encoding="utf-8"
    )
    (repo / "deployment" / "k8s" / "opa.yaml").write_text(
        "# POAM-2026-999\n", encoding="utf-8"
    )
    (repo / "config" / "governance_thresholds.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (repo / "docs" / "operations" / "KEY_ROTATION.md").write_text(
        "# POAM-2026-999\n", encoding="utf-8"
    )

    # Active Lula v0.16.0 manifest + Stub Lula manifest
    (repo / "compliance" / "lula" / "README.md").write_text(
        "| File | Status |\n|---|---|\n"
        "| `lula-validation-sc4.yaml` | \u2705 Active |\n"
        "| `lula-validation-ac2.yaml` | \U0001f536 Stub |\n",
        encoding="utf-8",
    )
    (repo / "compliance" / "lula" / "lula-validation-sc4.yaml").write_text(
        "component-definition:\n"
        "  uuid: 11111111-1111-4111-8111-111111111111\n"
        "  metadata:\n"
        "    title: SC4\n"
        "    version: 1.0.0\n"
        "    oscal-version: 1.1.2\n"
        "  components:\n"
        "    - uuid: 22222222-2222-4222-8222-222222222222\n"
        "      type: software\n"
        "      title: CAGE\n"
        "      description: CAGE\n"
        "      control-implementations:\n"
        "        - uuid: 33333333-3333-4333-8333-333333333333\n"
        "          source: https://example.org\n"
        "          description: SC4\n"
        "          implemented-requirements:\n"
        "            - uuid: 44444444-4444-4444-8444-444444444444\n"
        "              control-id: sc4\n"
        "              description: SC4\n"
        "              links:\n"
        "                - href: '#55555555-5555-4555-8555-555555555555'\n"
        "                  rel: lula\n"
        "  back-matter:\n"
        "    resources:\n"
        "      - uuid: 55555555-5555-4555-8555-555555555555\n"
        "        description: |\n"
        "          domain:\n"
        "            type: kubernetes\n"
        "          provider:\n"
        "            type: opa\n"
        "            opa-spec:\n"
        "              rego: |\n"
        "                package validate\n"
        "                validate { input.ready == true }\n",
        encoding="utf-8",
    )
    (repo / "compliance" / "lula" / "lula-validation-ac2.yaml").write_text(
        "# POAM-2026-999\n# TODO: STUB\ndefault validate = true\n",
        encoding="utf-8",
    )

    # Primary docs/POAM.md (1 open row, 2 closed rows, plus matching detail sections)
    (repo / "docs" / "POAM.md").write_text(
        "# POA&M\n\n"
        "## Open Findings\n\n"
        "### US Federal Region (US_FED)\n\n"
        "| ID | Control | Description | Severity | Target Date |\n"
        "|---|---|---|---|---|\n"
        "| POAM-2026-084 | AU-9 / AU-11 | Live custody verification open. Closes on verified chain in the persistent >=2555-day locked WORM domain (`POAM-2026-197`), never the 1-day staging WORM bucket | High | 2026-11-30 |\n\n"
        "## Closed Findings\n\n"
        "| ID | Control | Description | Closed |\n"
        "|---|---|---|---|\n"
        "| POAM-2026-001 | SC-4 | Guarded by `tests/unit/test_bound_guard.py` | 2026-11-05 |\n"
        "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n\n"
        "### POAM-2026-084: Custody Verification\n\n"
        "**Control:** AU-9 / AU-11\n"
        "**Severity:** High\n"
        "**Status:** Open\n\n"
        "Live custody verification open. Closes on verified chain in the persistent >=2555-day locked WORM domain (`POAM-2026-197`), never the 1-day staging WORM bucket.\n\n"
        "### POAM-2026-001: Guarded SC-4\n\n"
        "**Control:** SC-4\n"
        "**Severity:** High\n"
        "**Status:** Closed (2026-11-05)\n\n"
        "Verified by `tests/unit/test_bound_guard.py`.\n",
        encoding="utf-8",
    )

    # 4 Regional POA&M trackers (each: 1 open, 1 closed -> raw totals: 8 = 4 open, 0 in_progress, 4 closed)
    reg_hdr = (
        "| POA&M ID | Control ID | Weakness Description | Risk Level | Status | Target Closure | Milestone |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    (repo / "docs" / "compliance" / "universal" / "POAM_ISO42001.md").write_text(
        reg_hdr
        + "| `ISO-001` | A.8.4 | Enforced (`tests/unit/test_bound_guard.py`) | Medium | **Closed** | 2026-11-05 | Verified |\n"
        + "| `ISO-002` | A.9.3 | Pending validation | Low | **Open** | 2026-12-31 | Add test |\n",
        encoding="utf-8",
    )
    (repo / "docs" / "compliance" / "us_fed" / "POAM_US_FED.md").write_text(
        reg_hdr
        + "| `AI600-004` | NIST AI 600-1 | Enforced (`tests/unit/test_bound_guard.py`) | Medium | **Closed** | 2026-11-05 | Verified |\n"
        + "| `POAM-001` | AC-2 | Pending active Lula check | Medium | **Open** | 2026-12-31 | Activate Lula |\n",
        encoding="utf-8",
    )
    (repo / "docs" / "compliance" / "eu_ecb" / "POAM_EU_ECB.md").write_text(
        reg_hdr
        + "| `EU-AI-001` | EU AI Act Art. 9 | Enforced (`tests/unit/test_bound_guard.py`) | High | **Closed** | 2026-11-05 | Verified |\n"
        + "| `EU-AI-002` | EU AI Act Art. 12 | Audit record-keeping gap | High | **Open** | 2026-12-31 | Verify persistent >=2555-day locked WORM (`POAM-2026-197`) |\n",
        encoding="utf-8",
    )
    (repo / "docs" / "compliance" / "apac_mas" / "POAM_APAC_MAS.md").write_text(
        reg_hdr
        + "| `MAS-655-001` | MAS TRM S9 | Enforced (`tests/unit/test_bound_guard.py`) | Medium | **Closed** | 2026-11-05 | Verified |\n"
        + "| `MAS-655-002` | MAS Notice 655 | Audit retention gap | High | **Open** | 2026-12-31 | Verify persistent >=2555-day locked WORM (`POAM-2026-197`) |\n",
        encoding="utf-8",
    )

    (repo / "docs" / "compliance" / "cross-region" / "POAM_INDEX.md").write_text(
        "# POA&M Master Index\n\n"
        "## File Registry\n\n"
        "| File | Region Scope | Primary Framework | Entries | Open | In Progress | Closed |\n"
        "|---|---|---|---|---|---|---|\n"
        "| [`compliance/universal/POAM_ISO42001.md`](../universal/POAM_ISO42001.md) | ALL | ISO 42001 | 2 | 1 | 0 | 1 |\n"
        "| [`compliance/us_fed/POAM_US_FED.md`](../us_fed/POAM_US_FED.md) | US_FED | NIST SP 800-53 | 2 | 1 | 0 | 1 |\n"
        "| [`compliance/eu_ecb/POAM_EU_ECB.md`](../eu_ecb/POAM_EU_ECB.md) | EU_ECB | EU AI Act | 2 | 1 | 0 | 1 |\n"
        "| [`compliance/apac_mas/POAM_APAC_MAS.md`](../apac_mas/POAM_APAC_MAS.md) | APAC_MAS | MAS FEAT | 2 | 1 | 0 | 1 |\n"
        "| **Raw Row Sum** | | | **8** | **4** | **0** | **4** |\n"
        "| **Deduplicated Total** | | | **8** | **4** | **0** | **4** |\n",
        encoding="utf-8",
    )

    # Minimal structured OSCAL file with 1 implemented claim + SA11-SYSTEMIC rollup + rendered register
    desc = "CBF safety barrier enforced in tests/unit/test_bound_guard.py."
    desc_sha = hashlib.sha256(" ".join(desc.split()).encode("utf-8")).hexdigest()
    (repo / "compliance" / "oscal" / "component-definition.yaml").write_text(
        "component-definition:\n"
        "  uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n"
        "  metadata:\n"
        "    title: Synthetic Component Definition\n"
        "    version: 1.0.0\n"
        "    oscal-version: 1.1.2\n"
        "  components:\n"
        "    - uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\n"
        "      type: software\n"
        "      title: CAGE Gateway\n"
        "      description: Gateway\n"
        "      control-implementations:\n"
        "        - uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc\n"
        "          source: https://example.org/iso\n"
        "          description: ISO\n"
        "          implemented-requirements:\n"
        "            - uuid: req-impl-0001\n"
        "              control-id: SC-4\n"
        f"              description: {desc}\n"
        "              props:\n"
        "                - name: implementation-status\n"
        "                  value: implemented\n",
        encoding="utf-8",
    )
    census_rows = [
        {
            "id": "component-definition.yaml#req-impl-0001",
            "slice": "ring2_cd",
            "control": "sc-4",
            "component": "CAGE Gateway",
            "status_written": "implemented",
            "status_extracted": "implemented",
            "description_sha256": desc_sha,
            "claim": desc,
            "evidence_named": ["tests/unit/test_bound_guard.py"],
            "paths_missing": [],
            "custody": {"grade": "PLANE", "note": "Gateway kernel enforcement."},
            "read_back": {
                "grade": "OBSERVES",
                "check": "tests/unit/test_bound_guard.py",
                "runs_in": "ci:ci.yml",
            },
            "lifetime": {"grade": "REPO", "note": "Code and tests in git."},
            "w_binding": {"value": False, "object": "none"},
            "verdict": "HOLDS",
            "disposition": "holds",
            "failing_axes": [],
            "refs": [],
            "cites": ["tests/unit/test_bound_guard.py:L1-L6"],
            "notes": "Synthetic valid implemented claim.",
            "read_back_to_hold": "Holds.",
        },
        {
            "id": "SA11-SYSTEMIC",
            "slice": "ring1_euapac",
            "control": "sa-11",
            "component": "STPA Compiler",
            "status_written": "partially-implemented",
            "status_extracted": "partially-implemented",
            "description_sha256": hashlib.sha256(b"").hexdigest(),
            "claim": "Synthetic STPA rollup.",
            "evidence_named": ["scripts/check_sample_gate.py"],
            "paths_missing": [],
            "custody": {"grade": "CONFIG", "note": "Compiler output."},
            "read_back": {
                "grade": "OBSERVES",
                "check": "scripts/check_sample_gate.py",
                "runs_in": "ci:ci.yml",
            },
            "lifetime": {"grade": "REPO", "note": "Git tracked."},
            "w_binding": {"value": False, "object": "none"},
            "verdict": "HOLDS",
            "disposition": "holds",
            "failing_axes": [],
            "refs": [],
            "cites": ["scripts/check_sample_gate.py:L1-L2"],
            "notes": "Synthetic rollup.",
            "read_back_to_hold": "Holds.",
        },
    ]
    (repo / "compliance" / "oscal" / "evidence_claim_census.jsonl").write_text(
        "\n".join(json.dumps(r) for r in census_rows) + "\n",
        encoding="utf-8",
    )
    (repo / "docs" / "compliance" / "OSCAL_EVIDENCE_CLAIM_REGISTER.md").write_text(
        census_mod.render_register_markdown(census_rows),
        encoding="utf-8",
    )

    errs, stats = drift.audit_poam_and_oscal(repo)
    assert errs == [], f"Fixture baseline must be clean, got: {errs}"
    assert stats["poam_closed_rows"] == 6
    assert stats["poam_detail_sections"] == 2
    assert stats["oscal_implemented_claims"] == 1
    return repo


# ---------------------------------------------------------------------------
# Live repository & legacy-waiver retirement guards
# ---------------------------------------------------------------------------


def test_live_repository_passes_all_four_checks(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = drift.main(["--root", str(_REPO_ROOT)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert (
        "0 uncovered closures, 0 detail-section/reopened divergences, "
        "0 lifetime/custody violations, and 0 OSCAL census divergences"
    ) in out

    errs, stats = drift.audit_poam_and_oscal(_REPO_ROOT)
    assert errs == []
    assert stats["poam_closed_rows"] >= 130 and stats["poam_total_rows"] >= 220
    assert stats["poam_open_or_in_progress_rows"] >= 90
    assert stats["poam_detail_sections"] >= 100
    assert stats["active_lula_manifests"] == 12


def test_zero_legacy_waiver_lists_or_control_stem_matching_remain() -> None:
    for removed in (
        "NON_TESTABLE_CONTROLS",
        "CODE_EVIDENCE_FINDINGS",
        "CONTROL_ALIASES",
        "get_lula_file_stems",
        "find_matching_lula_stems",
    ):
        assert not hasattr(drift, removed), (
            f"Legacy waiver/helper {removed} must remain deleted"
        )


def test_split_md_row_preserves_inline_code_pipes() -> None:
    """Regression guard for POAM-2026-027 / POAM-2026-087: inline code `|` must not split columns."""
    row = "| POAM-2026-087 | AC-3 | Enforces `allow | deny` union in `tests/t.py` | 2026-10-01 |"
    cols = drift.split_md_row(row)
    assert cols == [
        "POAM-2026-087",
        "AC-3",
        "Enforces `allow | deny` union in `tests/t.py`",
        "2026-10-01",
    ]


def test_no_duplicate_poam_headers_at_head_and_duplicate_or_overlap_fails(
    synthetic_repo: pathlib.Path,
) -> None:
    """Regression guard for POAM-2026-176: duplicate headers and Open/Closed overlaps fail."""
    live_poam = (_REPO_ROOT / "docs" / "POAM.md").read_text(encoding="utf-8")
    assert drift.find_duplicate_poam_headers(live_poam) == []

    poam_file = synthetic_repo / "docs" / "POAM.md"
    orig = poam_file.read_text(encoding="utf-8")
    poam_file.write_text(
        orig.replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-084 | AU-9 | Duplicate open+closed (`tests/unit/test_bound_guard.py`) | 2026-11-05 |",
        )
        + "\n### POAM-2026-084: Duplicate Detail Header\n\n**Status:** Open\n",
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "Duplicate ### POAM headers" in e and "POAM-2026-084" in e for e in errs
    ), errs
    assert any(
        "appears in both Open Findings" in e and "and Closed Findings" in e
        for e in errs
    ), errs


# ---------------------------------------------------------------------------
# Six Hardened Check 2 / Check 3 / Check 1 Bypass Closure Regression Tests
# ---------------------------------------------------------------------------


def test_bypass1_evidence_store_registry_gmp_monarch_and_opa_decision_logs(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 1: EVIDENCE_STORE_REGISTRY classifies gmp_monarch and opa_decision_logs and is enforced."""
    gmp = drift.EVIDENCE_STORE_REGISTRY["gmp_monarch"]
    assert gmp.custody == "GOV_WRITABLE"
    assert gmp.plane == "PLANE"
    assert gmp.lifetime == "24m"
    assert gmp.retention_days == 730
    assert gmp.locked is False

    opa_logs = drift.EVIDENCE_STORE_REGISTRY["opa_decision_logs"]
    assert opa_logs.custody == "GOV_WRITABLE"
    assert opa_logs.retention_days == 0
    assert opa_logs.locked is False

    # 1a. gmp_monarch claimed for non-repudiable AU-10 decision custody MUST fail Check 3:
    poam = synthetic_repo / "docs" / "POAM.md"
    orig_poam = poam.read_text(encoding="utf-8")
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-501 | AU-10 | Non-repudiation open. Closes on Google Managed Prometheus (`gmp_monarch`) counters proving decision custody | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_au10, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-501" in e and "[Check 3: Custody]" in e and "gmp_monarch" in e
        for e in errs_au10
    ), errs_au10

    # 1b. gmp_monarch explicitly scoped as operational AU-12 / SI-4 PodMonitoring telemetry passes Check 3:
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-502 | AU-12 / SI-4 | Metrics scrape open. Closes on Google Managed Prometheus PodMonitoring scrape health (operational telemetry only, not non-repudiable decision custody) | Moderate | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_au12_ok, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert errs_au12_ok == [], errs_au12_ok

    # 1c. Unqualified OPA decision_logs cited on AU-12 fails Check 2 (0-day pod-ephemeral) and Check 3 (GOV_WRITABLE):
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-503 | AU-12 | Policy audit open. Closes on exporting OPA decision_logs from the sidecar | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_opa, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-503" in e and "[Check 2: Lifetime]" in e and "opa_decision_logs" in e
        for e in errs_opa
    ), errs_opa
    assert any(
        "POAM-2026-503" in e and "[Check 3: Custody]" in e and "opa_decision_logs" in e
        for e in errs_opa
    ), errs_opa


def test_bypass2_bare_valkey_and_clickhouse_infra_events_rejected_for_custody(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 2: Bare Valkey (DB 0) and ClickHouse infra_events fail tamper-evident custody claims."""
    poam = synthetic_repo / "docs" / "POAM.md"
    orig_poam = poam.read_text(encoding="utf-8")

    # 2a. Bare Valkey tamper-evident custody claim on a non-AU control (e.g., SC-28) still fails Check 3:
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-511 | SC-28 | State custody open. Closes on tamper-evident custody chain in Valkey | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_valkey, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-511" in e and "[Check 3: Custody]" in e and "valkey_app" in e
        for e in errs_valkey
    ), errs_valkey

    # 2b. ClickHouse infra_events tamper-evident custody claim fails Check 3:
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-512 | SC-28 | Event custody open. Closes on immutable audit trail in ClickHouse `infra_events` | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_ch, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-512" in e and "[Check 3: Custody]" in e and "infra_events" in e
        for e in errs_ch
    ), errs_ch

    # 2c. Valkey explicitly scoped in the same clause to Redis DB 1 cage:evidence:stream + WORM EVIDENCE_ARCHIVE_BUCKET passes:
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-513 | AU-9 | Stream custody open. Closes on tamper-evident custody chain via Valkey Redis DB 1 `cage:evidence:stream` archived to `EVIDENCE_ARCHIVE_BUCKET` | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs_ok, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert errs_ok == [], errs_ok


def test_bypass3_poam_detail_sections_audited_for_parity_and_evidence(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 3: ### POAM-... detail sections are audited for status parity and Check 1/2/3."""
    poam = synthetic_repo / "docs" / "POAM.md"
    orig_poam = poam.read_text(encoding="utf-8")

    # 3a. Detail section status diverges from summary table (summary=closed, detail=open):
    poam.write_text(
        orig_poam.replace(
            "### POAM-2026-001: Guarded SC-4\n\n**Control:** SC-4\n**Severity:** High\n**Status:** Closed (2026-11-05)",
            "### POAM-2026-001: Guarded SC-4\n\n**Control:** SC-4\n**Severity:** High\n**Status:** Open",
        ),
        encoding="utf-8",
    )
    errs_div, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-001" in e and "[Check 1: Detail Parity]" in e and "diverges" in e
        for e in errs_div
    ), errs_div

    # 3b. Closed detail section lacking runnable evidence AND planting GOV_WRITABLE custody claim fails:
    poam.write_text(
        orig_poam.replace(
            "### POAM-2026-001: Guarded SC-4\n\n**Control:** SC-4\n**Severity:** High\n**Status:** Closed (2026-11-05)\n\nVerified by `tests/unit/test_bound_guard.py`.",
            "### POAM-2026-001: Guarded SC-4\n\n**Control:** AU-12\n**Severity:** High\n**Status:** Closed (2026-11-05)\n\nClosed via Langfuse compliance audit records with no runnable citation.",
        ),
        encoding="utf-8",
    )
    errs_det, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-001" in e and "[Check 1: Read-Back]" in e and "detail section" in e
        for e in errs_det
    ), errs_det
    assert any(
        "POAM-2026-001" in e and "[Check 3: Custody]" in e and "langfuse_app" in e
        for e in errs_det
    ), errs_det


def test_bypass4_reopened_open_rows_without_closes_on_fail_and_are_not_skipped(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 4: Reopened open rows lacking 'Closes on' fail [Check 1: Reopened Schema] and still run Check 2/3."""
    poam = synthetic_repo / "docs" / "POAM.md"
    orig_poam = poam.read_text(encoding="utf-8")

    # Plant a Reopened open AU-12 row with NO 'Closes on' and a bad Langfuse reference:
    poam.write_text(
        orig_poam.replace(
            "## Closed Findings",
            "| POAM-2026-540 | AU-12 | Reopened 2026-11-06: audit spans exported to Langfuse | High | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-540" in e and "[Check 1: Reopened Schema]" in e for e in errs
    ), errs
    assert any(
        "POAM-2026-540" in e and "[Check 3: Custody]" in e and "langfuse_app" in e
        for e in errs
    ), errs


def test_bypass5_clause_scoped_telemetry_and_retention_qualifiers(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 5: A qualifier in sentence 1 cannot whitewash an unqualified store claim in sentence 2."""
    eu = synthetic_repo / "docs" / "compliance" / "eu_ecb" / "POAM_EU_ECB.md"
    orig_eu = eu.read_text(encoding="utf-8")

    # Sentence 1 qualifies Langfuse as operational telemetry; Sentence 2 uses Langfuse unqualified for Art. 12:
    eu.write_text(
        orig_eu.replace(
            "Verify persistent >=2555-day locked WORM (`POAM-2026-197`)",
            "Langfuse is operational telemetry only. Verify compliance spans in Langfuse for Art. 12 closure",
        ),
        encoding="utf-8",
    )
    errs_custody, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "EU-AI-002" in e and "[Check 3: Custody]" in e and "langfuse_app" in e
        for e in errs_custody
    ), errs_custody
    eu.write_text(orig_eu, encoding="utf-8")

    # Sentence 1 cites unqualified 'in the WORM bucket'; Sentence 2 mentions >=2555-day locked WORM separately:
    poam = synthetic_repo / "docs" / "POAM.md"
    orig_poam = poam.read_text(encoding="utf-8")
    poam.write_text(
        orig_poam.replace(
            "Closes on verified chain in the persistent >=2555-day locked WORM domain (`POAM-2026-197`), never the 1-day staging WORM bucket",
            "Closes on verifying records in the WORM bucket. Persistent >=2555-day locked WORM is tracked under POAM-2026-197",
        ),
        encoding="utf-8",
    )
    errs_lifetime, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-084" in e and "[Check 2: Lifetime]" in e for e in errs_lifetime
    ), errs_lifetime


def test_bypass6_workflow_plus_observed_requires_finding_id_binding(
    synthetic_repo: pathlib.Path,
) -> None:
    """Bypass 6: .github/workflows/*.yml + Observed fails without explicit finding-ID binding."""
    (synthetic_repo / ".github" / "workflows" / "bound.yml").write_text(
        "# Closure regression guard for: POAM-2026-303\n"
        "name: bound\non: [push]\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    poam = synthetic_repo / "docs" / "POAM.md"
    poam.write_text(
        poam.read_text(encoding="utf-8").replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-302 | SA-11 | Unbound workflow (`.github/workflows/ci.yml`) Observed 2026-11-05: run 98765 -> green | 2026-11-05 |\n"
            "| POAM-2026-303 | SA-11 | Bound workflow (`.github/workflows/bound.yml`) Observed 2026-11-05: run 98765 -> green | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("POAM-2026-302" in e and "[Check 1: Read-Back]" in e for e in errs), errs
    assert not any("POAM-2026-303" in e for e in errs), errs


def test_live_external_only_pytest_rejected_without_pr_ci_marker(
    synthetic_repo: pathlib.Path,
) -> None:
    """POAM-2026-104 class: @pytest.mark.live_external alone cannot guard a closed finding in PR CI."""
    (synthetic_repo / "tests" / "unit" / "test_live_only.py").write_text(
        "import pytest\n# Closure regression guard for: POAM-2026-404\n"
        "pytestmark = [pytest.mark.live_external]\n\n"
        "def test_live_wire() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    poam = synthetic_repo / "docs" / "POAM.md"
    orig = poam.read_text(encoding="utf-8")
    poam.write_text(
        orig.replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-404 | SC-8 | Live-only (`tests/unit/test_live_only.py`) | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs_live_only, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "POAM-2026-404" in e and "[Check 1: Read-Back]" in e and "live_external" in e
        for e in errs_live_only
    ), errs_live_only

    # Pairing with a hermetic [pytest.mark.unit, pytest.mark.local] test binding POAM-2026-404 passes:
    (synthetic_repo / "tests" / "unit" / "test_hermetic_vectors.py").write_text(
        "import pytest\n# Closure regression guard for: POAM-2026-404\n"
        "pytestmark = [pytest.mark.unit, pytest.mark.local]\n\n"
        "def test_vectors() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    poam.write_text(
        orig.replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-404 | SC-8 | Paired (`tests/unit/test_hermetic_vectors.py`, `tests/unit/test_live_only.py`) | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs_paired, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert not any("POAM-2026-404" in e for e in errs_paired), errs_paired


def test_non_implemented_holds_census_row_with_missing_path_fails_check4(
    synthetic_repo: pathlib.Path,
) -> None:
    """Deliverable 2: non-implemented HOLDS census rows have read_back.check & evidence_named verified."""
    census_file = (
        synthetic_repo / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    )
    rows = [
        json.loads(line)
        for line in census_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows[1]["status_extracted"] == "partially-implemented"
    assert rows[1]["verdict"] == "HOLDS"
    rows[1]["read_back"]["check"] = "scripts/check_missing_on_disk.py"
    census_file.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    (
        synthetic_repo / "docs" / "compliance" / "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
    ).write_text(
        census_mod.render_register_markdown(rows),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "SA11-SYSTEMIC" in e
        and "[Check 4: HOLDS Path]" in e
        and "scripts/check_missing_on_disk.py" in e
        for e in errs
    ), errs


# ---------------------------------------------------------------------------
# CE-M1: Jurisdictional POA&M scope (all 4 regional files + POAM_INDEX.md)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel_path", "planted_row"),
    [
        (
            "docs/compliance/universal/POAM_ISO42001.md",
            "| `ISO-999` | A.8.4 | Planted unbacked regional closure | High | **Closed** | 2026-11-05 | Done |\n",
        ),
        (
            "docs/compliance/us_fed/POAM_US_FED.md",
            "| `AI600-999` | NIST AI 600-1 | Planted unbacked regional closure | High | **Closed** | 2026-11-05 | Done |\n",
        ),
        (
            "docs/compliance/eu_ecb/POAM_EU_ECB.md",
            "| `EU-AI-999` | EU AI Act Art. 9 | Planted unbacked regional closure | High | **Closed** | 2026-11-05 | Done |\n",
        ),
        (
            "docs/compliance/apac_mas/POAM_APAC_MAS.md",
            "| `MAS-655-999` | MAS TRM | Planted unbacked regional closure | High | **Closed** | 2026-11-05 | Done |\n",
        ),
    ],
)
def test_ce_m1_regional_unbacked_closure_and_index_drift_fail(
    synthetic_repo: pathlib.Path, rel_path: str, planted_row: str
) -> None:
    target = synthetic_repo / rel_path
    target.write_text(
        target.read_text(encoding="utf-8") + planted_row, encoding="utf-8"
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("[Check 1: Read-Back]" in e and rel_path in e for e in errs), errs
    assert any("[Check 1: Index Parity]" in e for e in errs), errs


def test_ce_m1_poam_index_deduplicated_count_mismatch_fails(
    synthetic_repo: pathlib.Path,
) -> None:
    idx = synthetic_repo / "docs" / "compliance" / "cross-region" / "POAM_INDEX.md"
    idx.write_text(
        idx.read_text(encoding="utf-8").replace(
            "| **Deduplicated Total** | | | **8** | **4** | **0** | **4** |",
            "| **Deduplicated Total** | | | **8** | **2** | **0** | **6** |",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "[Check 1: Index Parity]" in e and "Deduplicated Total" in e for e in errs
    ), errs


# ---------------------------------------------------------------------------
# CE-M2: Control-name fallback retired, exact finding-ID binding, marker & Lula
# ---------------------------------------------------------------------------


def test_ce_m2_control_name_match_alone_fails_even_with_active_sc4_lula(
    synthetic_repo: pathlib.Path,
) -> None:
    poam = synthetic_repo / "docs" / "POAM.md"
    poam.write_text(
        poam.read_text(encoding="utf-8").replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-777 | SC-4 | Closed relying on control name SC-4 without citing evidence | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("POAM-2026-777" in e and "[Check 1: Read-Back]" in e for e in errs), errs


def test_ce_m2_exact_id_word_boundary_marker_contract_and_stub_lula(
    synthetic_repo: pathlib.Path,
) -> None:
    # 1. Test naming POAM-2026-100 must NOT satisfy POAM-2026-10 (word boundary).
    (synthetic_repo / "tests" / "unit" / "test_prefix_trap.py").write_text(
        "import pytest\n# Guard for POAM-2026-100\npytestmark = [pytest.mark.unit]\n"
        "def test_ok():\n    assert True\n",
        encoding="utf-8",
    )
    # 2. Test naming POAM-2026-200 but lacking pytest.mark.* must fail.
    (synthetic_repo / "tests" / "unit" / "test_unmarked.py").write_text(
        "# Guard for POAM-2026-200\ndef test_unmarked():\n    assert True\n",
        encoding="utf-8",
    )
    poam = synthetic_repo / "docs" / "POAM.md"
    base = poam.read_text(encoding="utf-8")
    poam.write_text(
        base.replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            "| POAM-2026-010 | SC-4 | Prefix collision trap (`tests/unit/test_bound_guard.py`) | 2026-11-05 |\n"
            "| POAM-2026-10 | SC-4 | Substring prefix trap (`tests/unit/test_prefix_trap.py`) | 2026-11-05 |\n"
            "| POAM-2026-200 | SC-4 | Missing marker (`tests/unit/test_unmarked.py`) | 2026-11-05 |\n"
            "| POAM-2026-999 | AC-2 | Stub Lula (`compliance/lula/lula-validation-ac2.yaml`) | 2026-11-05 |\n"
            "| POAM-2026-301 | SA-11 | Bare workflow (`.github/workflows/ci.yml`) | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    for bad_id in (
        "POAM-2026-010",
        "POAM-2026-10",
        "POAM-2026-200",
        "POAM-2026-999",
        "POAM-2026-301",
    ):
        assert any(bad_id in e and "[Check 1: Read-Back]" in e for e in errs), (
            bad_id,
            errs,
        )


# ---------------------------------------------------------------------------
# CE-M3: Config, manifest, tfvars, and prose paths never count as evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "non_runnable_citation",
    [
        "infra/targets/gcp-gke/main.tf",
        "infra/targets/gcp-gke/staging.tfvars",
        "deployment/k8s/opa.yaml",
        "config/governance_thresholds.json",
        "docs/operations/KEY_ROTATION.md",
    ],
)
def test_ce_m3_config_manifest_and_prose_only_citations_fail(
    synthetic_repo: pathlib.Path, non_runnable_citation: str
) -> None:
    poam = synthetic_repo / "docs" / "POAM.md"
    poam.write_text(
        poam.read_text(encoding="utf-8").replace(
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |",
            "| POAM-2026-002 | CM-3 | Guarded by `scripts/check_sample_gate.py` | 2026-11-05 |\n"
            f"| POAM-2026-999 | CM-6 | Closed citing only `{non_runnable_citation}` | 2026-11-05 |",
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("POAM-2026-999" in e and "[Check 1: Read-Back]" in e for e in errs), errs


# ---------------------------------------------------------------------------
# CE-M4: Check 2 lifetime on open criteria, closed rows, and OSCAL claims
# ---------------------------------------------------------------------------


def test_ce_m4_lifetime_rejects_short_lived_stores_on_open_and_closed_rows_and_oscal(
    synthetic_repo: pathlib.Path,
) -> None:
    poam = synthetic_repo / "docs" / "POAM.md"
    poam.write_text(
        poam.read_text(encoding="utf-8")
        .replace(
            "Closes on verified chain in the persistent >=2555-day locked WORM domain (`POAM-2026-197`), never the 1-day staging WORM bucket",
            "Closes on verifying signed records in the 1-day staging WORM bucket (retention = 86400)",
        )
        .replace(
            "| POAM-2026-001 | SC-4 | Guarded by `tests/unit/test_bound_guard.py` | 2026-11-05 |",
            "| POAM-2026-001 | AU-11 | Verified via `gcloud logging read` on `_Required` (`tests/unit/test_bound_guard.py`) | 2026-11-05 |",
        )
        .replace(
            "## Closed Findings",
            "| POAM-2026-085 | AU-12 | Audit check. Closes on `gcloud logging read` from `_Default` | Moderate | 2026-12-31 |\n\n## Closed Findings",
        ),
        encoding="utf-8",
    )
    census_file = (
        synthetic_repo / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    )
    rows = [
        json.loads(line)
        for line in census_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows[0]["lifetime"] = {"grade": "SHORTER", "note": "1-day bucket"}
    census_file.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    (
        synthetic_repo / "docs" / "compliance" / "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
    ).write_text(
        census_mod.render_register_markdown(rows),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("POAM-2026-084" in e and "[Check 2: Lifetime]" in e for e in errs), errs
    assert any("POAM-2026-085" in e and "[Check 2: Lifetime]" in e for e in errs), errs
    assert any("POAM-2026-001" in e and "[Check 2: Lifetime]" in e for e in errs), errs
    assert any(
        "OSCAL component-definition.yaml#req-impl-0001" in e
        and "[Check 2: Lifetime]" in e
        for e in errs
    ), errs


# ---------------------------------------------------------------------------
# CE-M5: Check 3 custody rejects GOV_WRITABLE stores for audit controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_custody_claim",
    [
        "Audit records persisted to Langfuse backend",
        "Langfuse satisfies authoritative audit durability",
        "`/v1/infra/events` provides authoritative audit trail",
        "application Valkey satisfies audit durability",
        "Verify spans in Langfuse for AU-12 closure",
    ],
)
def test_ce_m5_gov_writable_stores_rejected_on_open_and_closed_audit_rows(
    synthetic_repo: pathlib.Path, bad_custody_claim: str
) -> None:
    eu = synthetic_repo / "docs" / "compliance" / "eu_ecb" / "POAM_EU_ECB.md"
    eu.write_text(
        eu.read_text(encoding="utf-8").replace(
            "Verify persistent >=2555-day locked WORM (`POAM-2026-197`)",
            bad_custody_claim,
        ),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("EU-AI-002" in e and "[Check 3: Custody]" in e for e in errs), errs


def test_ce_m5_oscal_implemented_gov_writable_rejected_while_telemetry_qualifier_passes(
    synthetic_repo: pathlib.Path,
) -> None:
    eu = synthetic_repo / "docs" / "compliance" / "eu_ecb" / "POAM_EU_ECB.md"
    eu.write_text(
        eu.read_text(encoding="utf-8").replace(
            "Verify persistent >=2555-day locked WORM (`POAM-2026-197`)",
            "Langfuse is operational telemetry only - authoritative records use EvidenceStream -> persistent locked WORM (`POAM-2026-197`)",
        ),
        encoding="utf-8",
    )
    errs_clean, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert errs_clean == [], errs_clean

    census_file = (
        synthetic_repo / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    )
    rows = [
        json.loads(line)
        for line in census_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows[0]["custody"] = {"grade": "GOV_WRITABLE", "note": "Shared Langfuse project"}
    census_file.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    (
        synthetic_repo / "docs" / "compliance" / "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
    ).write_text(
        census_mod.render_register_markdown(rows),
        encoding="utf-8",
    )
    errs, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "OSCAL component-definition.yaml#req-impl-0001" in e
        and "[Check 3: Custody]" in e
        for e in errs
    ), errs


# ---------------------------------------------------------------------------
# CE-M6: Check 4 OSCAL census description_sha256, verdict, & rendered parity
# ---------------------------------------------------------------------------


def test_ce_m6_oscal_description_sha_drift_weaker_verdict_and_register_drift_fail(
    synthetic_repo: pathlib.Path,
) -> None:
    cd = synthetic_repo / "compliance" / "oscal" / "component-definition.yaml"
    orig_cd = cd.read_text(encoding="utf-8")
    cd.write_text(
        orig_cd.replace("safety barrier", "mutated narrative"), encoding="utf-8"
    )
    errs_sha, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "[Check 4: Census]" in e and "description_sha256" in e for e in errs_sha
    ), errs_sha
    cd.write_text(orig_cd, encoding="utf-8")

    reg = synthetic_repo / "docs" / "compliance" / "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
    orig_reg = reg.read_text(encoding="utf-8")
    reg.write_text(orig_reg + "\n<!-- stale edit -->\n", encoding="utf-8")
    errs_reg, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any("[Check 4: Census]" in e and "out of sync" in e for e in errs_reg), (
        errs_reg
    )

    census_file = (
        synthetic_repo / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    )
    rows = [
        json.loads(line)
        for line in census_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows[0]["verdict"] = "WEAKER"
    rows[0]["disposition"] = "restate"
    rows[0]["failing_axes"] = ["custody"]
    census_file.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    reg.write_text(census_mod.render_register_markdown(rows), encoding="utf-8")
    errs_verdict, _ = drift.audit_poam_and_oscal(synthetic_repo)
    assert any(
        "[Check 4: Census]" in e and "failing verdict 'WEAKER'" in e
        for e in errs_verdict
    ), errs_verdict
