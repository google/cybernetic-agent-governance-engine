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

"""Unit tests for scripts/check_lula_stub_count.py and GDPR Art. 22 posture (PR-J)."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest
import yaml

from scripts import check_lula_stub_count as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LULA_DIR = REPO_ROOT / "compliance" / "lula"

EXPECTED_AI600_STUBS = frozenset(
    {
        "lula-validation-ai600-cbrn.yaml",
        "lula-validation-ai600-confabulation.yaml",
        "lula-validation-ai600-data-privacy.yaml",
        "lula-validation-ai600-human-ai-config.yaml",
        "lula-validation-ai600-prompt-injection.yaml",
    }
)


def _make_oscal_manifest(
    *,
    title: str = "CAGE Validation — Synthetic Control",
    remarks: str = "Auto-converted from standalone lula validation format.\nRegion: US_FED.",
    ctrl_desc: str = "Control implementation for synthetic check.",
    req_desc: str = "Automated lula validation for synthetic check.",
    props: list[dict[str, str]] | None = None,
    embedded_yaml: str | None = None,
) -> str:
    if embedded_yaml is None:
        embedded_yaml = textwrap.dedent(
            """\
            domain:
              type: kubernetes
              kubernetes-spec:
                resources:
                  - name: gateway_deploy
                    resource-rule:
                      group: apps
                      version: v1
                      resource: deployments
                      namespaces:
                        - governance-stack
            provider:
              type: opa
              opa-spec:
                rego: |
                  package lula
                  import future.keywords.if
                  validate if {
                    count(input.gateway_deploy) > 0
                    input.gateway_deploy[0].metadata.name == "gateway"
                    input.gateway_deploy[0].spec.replicas >= 1
                  }
            """
        )
    doc = {
        "component-definition": {
            "uuid": "11111111-2222-4333-8444-555555555555",
            "metadata": {
                "title": title,
                "last-modified": "2026-07-01T00:00:00Z",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "remarks": remarks,
                **({"props": props} if props is not None else {}),
            },
            "components": [
                {
                    "uuid": "22222222-3333-4444-8555-666666666666",
                    "type": "software",
                    "title": "CAGE",
                    "description": "Synthetic component.",
                    "control-implementations": [
                        {
                            "uuid": "33333333-4444-4555-8666-777777777777",
                            "source": "https://example.org/spec",
                            "description": ctrl_desc,
                            "implemented-requirements": [
                                {
                                    "uuid": "44444444-5555-4666-8777-888888888888",
                                    "control-id": "syn-1",
                                    "description": req_desc,
                                }
                            ],
                        }
                    ],
                }
            ],
            "back-matter": {
                "resources": [
                    {
                        "uuid": "55555555-6666-4777-8888-999999999999",
                        "title": "Lula Validation",
                        "description": embedded_yaml,
                    }
                ]
            },
        }
    }
    return yaml.safe_dump(doc, sort_keys=False)


class TestLiveRepositoryStubGate:
    """Verify live repository scan, exact stub classification, and POAM linkage."""

    def test_live_repo_gate_passes_with_exact_5_ai600_stubs(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = gate.main([])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "Scanned 33 manifest(s)" in out
        assert "extracted 33 Rego policy body/bodies" in out
        assert "Stubs found: 5" in out
        assert "Baseline: 5  Current: 5" in out

    def test_live_corpus_extracts_33_domains_and_33_rego_bodies(self) -> None:
        files = sorted(LULA_DIR.glob("lula-validation-*.yaml"))
        assert len(files) == 33

        results = [gate.classify_manifest(f) for f in files]
        assert sum(r.rego_body_count for r in results) == 33
        assert sum(r.domain_count for r in results) == 33
        assert all(not r.structural_errors for r in results)

        stub_names = {r.name for r in results if r.is_stub}
        assert stub_names == EXPECTED_AI600_STUBS

        non_stub_names = {r.name for r in results if not r.is_stub}
        assert len(non_stub_names) == 28
        assert "lula-validation-eu-fria.yaml" in non_stub_names
        assert "lula-validation-cm6.yaml" in non_stub_names
        assert "lula-validation-gdpr-art22.yaml" in non_stub_names

    def test_live_baseline_file_is_five_and_all_stubs_resolve_poam_ids(self) -> None:
        assert gate._read_baseline(LULA_DIR / ".stub-baseline") == 5

        poam_files = [REPO_ROOT / rel for rel in gate._DEFAULT_RELATIVE_POAM_FILES]
        poam_refs = gate._load_poam_references(poam_files)
        results = gate.check_poam_coverage(
            [
                gate.classify_manifest(f)
                for f in sorted(LULA_DIR.glob("lula-validation-*.yaml"))
            ],
            poam_refs,
        )
        stubs = {r.name: r for r in results if r.is_stub}
        assert set(stubs) == EXPECTED_AI600_STUBS
        for name, res in stubs.items():
            assert res.has_poam is True, f"{name} missing POAM linkage"
            assert len(res.poam_ids) >= 1

        assert "AI600-001" in stubs["lula-validation-ai600-confabulation.yaml"].poam_ids
        assert "AI600-002" in stubs["lula-validation-ai600-data-privacy.yaml"].poam_ids
        assert (
            "AI600-003" in stubs["lula-validation-ai600-prompt-injection.yaml"].poam_ids
        )
        assert (
            "AI600-005" in stubs["lula-validation-ai600-human-ai-config.yaml"].poam_ids
        )
        cbrn_ids = set(stubs["lula-validation-ai600-cbrn.yaml"].poam_ids)
        assert {"POAM-2026-025", "AI600-007"} <= cbrn_ids

    def test_lula_readme_manifest_count_and_us_fed_posture_counts(self) -> None:
        readme = (LULA_DIR / "README.md").read_text(encoding="utf-8")
        unique_names = set(re.findall(r"lula-validation-[a-z0-9_-]*\.yaml", readme))
        disk_names = {p.name for p in LULA_DIR.glob("lula-validation-*.yaml")}
        assert unique_names == disk_names
        assert "**4 Active (US_FED scope):**" in readme
        assert "**9 Stub (US_FED scope):**" in readme
        assert "compliance/lula/.stub-baseline" in readme


class TestNonVacuousCorpusFloor:
    """Verify vacuous corpora or unextractable OSCAL payloads fail closed."""

    def test_empty_directory_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = gate.main(["--lula-dir", str(tmp_path)])
        assert rc == 1
        assert "no lula-validation-*.yaml files found" in capsys.readouterr().err

    def test_assessment_results_yaml_is_ignored_by_manifest_glob(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "assessment-results.yaml").write_text(
            "assessment-results:\n  results: []\n", encoding="utf-8"
        )
        # With only assessment-results.yaml present, 0 lula-validation-*.yaml files exist
        assert gate.main(["--lula-dir", str(tmp_path)]) == 1

    def test_manifest_count_below_floor_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "lula-validation-one.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        (tmp_path / ".stub-baseline").write_text("0\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text("# POAM\n", encoding="utf-8")

        # Passes with custom floor=1, fails with floor=2 or live floor=30
        assert (
            gate.main(
                [
                    "--lula-dir",
                    str(tmp_path),
                    "--poam-files",
                    str(poam),
                    "--min-manifests",
                    "1",
                    "--min-rego-bodies",
                    "1",
                ]
            )
            == 0
        )
        capsys.readouterr()

        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam),
                "--min-manifests",
                "30",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "below required floor 30" in err

    def test_rego_body_count_below_floor_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "lula-validation-one.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        (tmp_path / ".stub-baseline").write_text("0\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text("# POAM\n", encoding="utf-8")

        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam),
                "--min-manifests",
                "1",
                "--min-rego-bodies",
                "2",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "Total extracted Rego bodies 1 is below required floor 2" in err

    def test_vacuous_oscal_manifest_without_rego_or_domain_fails_even_with_high_baseline_and_poam(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Valid active manifest #1 so total_rego_bodies >= 1 if floor=1, plus vacuous #2
        (tmp_path / "lula-validation-good.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        (tmp_path / "lula-validation-vacuous.yaml").write_text(
            _make_oscal_manifest(embedded_yaml="not_lula_schema: true\n"),
            encoding="utf-8",
        )
        (tmp_path / ".stub-baseline").write_text("10\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text(
            "### POAM-2026-999\nCovers `lula-validation-vacuous.yaml`.\n",
            encoding="utf-8",
        )

        res = gate.classify_manifest(tmp_path / "lula-validation-vacuous.yaml")
        assert res.rego_body_count == 0
        assert res.domain_count == 0
        assert len(res.structural_errors) >= 2

        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam),
                "--min-manifests",
                "1",
                "--min-rego-bodies",
                "1",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "failed non-vacuous OSCAL/Lula extraction" in err

    def test_corrupt_embedded_back_matter_yaml_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "lula-validation-corrupt.yaml").write_text(
            _make_oscal_manifest(embedded_yaml="domain: [unterminated\n"),
            encoding="utf-8",
        )
        (tmp_path / ".stub-baseline").write_text("5\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text(
            "| POAM-2026-999 | ctrl | `lula-validation-corrupt.yaml` |\n",
            encoding="utf-8",
        )

        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam),
                "--min-manifests",
                "1",
                "--min-rego-bodies",
                "0",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "YAML error" in err


class TestStubClassificationRules:
    """Verify Notes: false-positive exclusion vs. structured stub detection."""

    def test_notes_prose_mentioning_stub_or_placeholder_is_not_false_positive(
        self, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "lula-validation-notes-safe.yaml"
        manifest.write_text(
            _make_oscal_manifest(
                remarks=(
                    "Auto-converted from standalone lula validation format.\n"
                    "Region: EU_ECB. Posture: eu-ai-act.\n"
                    "Notes: Asserts non-stub value and avoids deprecated Rego stub "
                    "confusion or placeholder TODO wording in explanatory prose."
                )
            ),
            encoding="utf-8",
        )
        res = gate.classify_manifest(manifest)
        assert res.is_stub is False
        assert res.stub_reasons == []
        assert res.rego_body_count == 1
        assert res.domain_count == 1

    @pytest.mark.parametrize(
        ("kwargs", "expected_substring"),
        [
            (
                {
                    "remarks": (
                        "Phase-0 stub for AI 600-1 controls. Always passes until "
                        "Phase 2 real assertions replace stub."
                    )
                },
                "STUB",
            ),
            (
                {
                    "remarks": (
                        "Auto-converted.\nNotes: This manifest always passes in cluster."
                    )
                },
                "always passes",
            ),
            (
                {"props": [{"name": "validation-mode", "value": "placeholder"}]},
                "placeholder",
            ),
            (
                {"req_desc": "TODO: wire live cluster endpoint"},
                "TODO",
            ),
            (
                {
                    "embedded_yaml": textwrap.dedent(
                        """\
                        domain:
                          type: kubernetes
                          kubernetes-spec:
                            resources:
                              - name: gw
                                resource-rule:
                                  group: apps
                                  version: v1
                                  resource: deployments
                                  namespaces: [governance-stack]
                        provider:
                          type: opa
                          opa-spec:
                            rego: |
                              package lula
                              default allow = true
                              allow = true
                              x := 1
                              y := 2
                        """
                    )
                },
                "default allow = true",
            ),
            (
                {
                    "embedded_yaml": textwrap.dedent(
                        """\
                        domain:
                          type: kubernetes
                          kubernetes-spec:
                            resources:
                              - name: gw
                                resource-rule:
                                  group: apps
                                  version: v1
                                  resource: deployments
                                  namespaces: [governance-stack]
                        provider:
                          type: opa
                          opa-spec:
                            rego: |
                              package lula
                              validate := true
                        """
                    )
                },
                "meaningful rule line",
            ),
            (
                {
                    "embedded_yaml": textwrap.dedent(
                        """\
                        domain:
                          type: kubernetes
                          kubernetes-spec:
                            resources: []
                        provider:
                          type: opa
                          opa-spec:
                            rego: |
                              package lula
                              import future.keywords.if
                              validate if {
                                1 == 1
                                2 == 2
                                3 == 3
                              }
                        """
                    )
                },
                "empty or absent",
            ),
        ],
    )
    def test_structured_markers_and_rego_defects_classify_as_stub(
        self,
        tmp_path: Path,
        kwargs: dict[str, object],
        expected_substring: str,
    ) -> None:
        manifest = tmp_path / "lula-validation-planted.yaml"
        manifest.write_text(_make_oscal_manifest(**kwargs), encoding="utf-8")  # type: ignore[arg-type]
        res = gate.classify_manifest(manifest)
        assert res.is_stub is True
        assert any(expected_substring in r for r in res.stub_reasons), res.stub_reasons

    def test_standalone_top_level_domain_provider_format_supported(
        self, tmp_path: Path
    ) -> None:
        standalone = tmp_path / "lula-validation-standalone.yaml"
        standalone.write_text(
            textwrap.dedent(
                """\
                metadata:
                  name: standalone-valid
                domain:
                  type: api
                  api-spec:
                    requests:
                      - name: health
                        url: http://localhost:8080/healthz
                provider:
                  type: opa
                  opa-spec:
                    rego: |
                      package lula
                      import future.keywords.if
                      validate if {
                        count(input.health) > 0
                        input.health.ok == true
                      }
                """
            ),
            encoding="utf-8",
        )
        res = gate.classify_manifest(standalone)
        assert res.is_stub is False
        assert res.rego_body_count == 1
        assert res.domain_count == 1
        assert not res.structural_errors


class TestDownwardOnlyBaselineRatchet:
    """Verify downward-only .stub-baseline enforcement in normal and --update-baseline modes."""

    def _setup_corpus(
        self,
        tmp_path: Path,
        *,
        num_stubs: int,
        baseline: int | None,
        with_poam: bool = True,
    ) -> tuple[Path, Path]:
        (tmp_path / "lula-validation-active.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        poam_lines = ["# POAM\n"]
        for i in range(num_stubs):
            fname = f"lula-validation-stub-{i}.yaml"
            (tmp_path / fname).write_text(
                _make_oscal_manifest(remarks="Phase-0 stub. Always passes."),
                encoding="utf-8",
            )
            if with_poam:
                poam_lines.append(
                    f"| AI600-00{i + 1} | ctrl | Stub `{fname}` pending Phase 2 |\n"
                )

        baseline_file = tmp_path / ".stub-baseline"
        if baseline is not None:
            baseline_file.write_text(f"{baseline}\n", encoding="utf-8")

        poam_file = tmp_path / "POAM.md"
        poam_file.write_text("".join(poam_lines), encoding="utf-8")
        return baseline_file, poam_file

    def test_normal_mode_fails_when_stub_count_exceeds_baseline(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _, poam_file = self._setup_corpus(tmp_path, num_stubs=2, baseline=1)
        rc = gate.main(["--lula-dir", str(tmp_path), "--poam-files", str(poam_file)])
        err = capsys.readouterr().err
        assert rc == 1
        assert "EXCEEDED downward-only baseline: 2 > baseline 1" in err

    def test_normal_mode_fails_when_baseline_missing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _, poam_file = self._setup_corpus(tmp_path, num_stubs=0, baseline=None)
        rc = gate.main(["--lula-dir", str(tmp_path), "--poam-files", str(poam_file)])
        err = capsys.readouterr().err
        assert rc == 1
        assert "Baseline file missing or invalid" in err

    def test_update_baseline_refuses_upward_ratchet_and_preserves_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        baseline_file, poam_file = self._setup_corpus(tmp_path, num_stubs=3, baseline=2)
        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam_file),
                "--update-baseline",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert (
            "Refusing --update-baseline: current stub count 3 > existing baseline 2"
            in err
        )
        assert baseline_file.read_text(encoding="utf-8") == "2\n"

    def test_update_baseline_ratchets_downward_when_stubs_hardened(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        baseline_file, poam_file = self._setup_corpus(tmp_path, num_stubs=1, baseline=3)
        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam_file),
                "--update-baseline",
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "Baseline ratcheted" in out
        assert baseline_file.read_text(encoding="utf-8") == "1\n"

    def test_update_baseline_refuses_when_stub_lacks_poam(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        baseline_file, poam_file = self._setup_corpus(
            tmp_path, num_stubs=1, baseline=2, with_poam=False
        )
        rc = gate.main(
            [
                "--lula-dir",
                str(tmp_path),
                "--poam-files",
                str(poam_file),
                "--update-baseline",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "without POAM entry" in err
        assert baseline_file.read_text(encoding="utf-8") == "2\n"


class TestPoamReferenceLoader:
    """Verify heading-bounded ### sections and Markdown table row POAM extraction."""

    def test_heading_section_does_not_bleed_into_subsequent_h2_summary_table(
        self, tmp_path: Path
    ) -> None:
        poam_doc = tmp_path / "POAM.md"
        poam_doc.write_text(
            textwrap.dedent(
                """\
                ### POAM-2026-101: Specific Stub Entry
                Tracks `lula-validation-alpha.yaml`.

                ## Unrelated Trailing Inventory Section
                Mentions `lula-validation-beta.yaml` only in an informational inventory.
                """
            ),
            encoding="utf-8",
        )
        refs = gate._load_poam_references(poam_doc)
        assert refs.get("lula-validation-alpha.yaml") == ["POAM-2026-101"]
        assert "lula-validation-beta.yaml" not in refs

    def test_markdown_table_rows_extract_regional_and_central_ids(
        self, tmp_path: Path
    ) -> None:
        poam_doc = tmp_path / "POAM_REGIONAL.md"
        poam_doc.write_text(
            textwrap.dedent(
                """\
                | ID | Control | Description |
                |---|---|---|
                | AI600-005 | §2.5 | Tracks `lula-validation-ai600-human-ai-config.yaml` |
                | **EU-006** | GDPR Art. 22 | Tracks `lula-validation-gdpr-art22.yaml` |
                """
            ),
            encoding="utf-8",
        )
        refs = gate._load_poam_references([poam_doc])
        assert refs["lula-validation-ai600-human-ai-config.yaml"] == ["AI600-005"]
        assert refs["lula-validation-gdpr-art22.yaml"] == ["EU-006"]


class TestCiWorkflowWiring:
    """Verify check_lula_stub_count.py is enforced in ci.yml lint & lula-ai600-validation."""

    def test_ci_workflow_runs_lula_stub_gate_in_lint_and_lula_ai600_jobs(self) -> None:
        ci_doc = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        jobs = ci_doc["jobs"]

        lint_runs = "\n".join(
            str(step.get("run", "")) for step in jobs["lint"]["steps"]
        )
        assert "scripts/check_lula_stub_count.py" in lint_runs

        ai600_runs = "\n".join(
            str(step.get("run", "")) for step in jobs["lula-ai600-validation"]["steps"]
        )
        assert "scripts/check_lula_stub_count.py" in ai600_runs


class TestGdprArt22Posture:
    """Verify GDPR Art. 22 re-point onto REQUIRE_APPROVAL and honest planned marking."""

    def test_eu_ecb_ssp_repoints_gdpr_art22_to_require_approval_and_marks_contest_planned(
        self,
    ) -> None:
        ssp_path = (
            REPO_ROOT / "compliance" / "oscal" / "system-security-plan-eu-ecb.yaml"
        )
        raw = ssp_path.read_text(encoding="utf-8")
        assert "hitl_escalator" not in raw.lower()
        assert "hitl escalator" not in raw.lower()
        assert "implemented via contest mechanism" not in raw.lower()

        doc = yaml.safe_load(raw)
        ssp = doc["system-security-plan"]

        comp = next(
            c
            for c in ssp["system-implementation"]["components"]
            if c["uuid"] == "eu-ecb-comp-0002-4000-8000-000000000002"
        )
        comp_desc = comp["description"]
        assert "REQUIRE_APPROVAL" in comp_desc
        assert "src/cage_finance/tiers/consensus_tier.py" in comp_desc
        assert "[0.70, 0.95)" in comp_desc
        assert "src/gateway/governance/governor/stages/confidence.py" in comp_desc
        assert "[0.70, 0.97)" in comp_desc
        assert "src/cage_finance/tiers/trade_confidence_tier.py" in comp_desc
        assert "DeferQueue.approve()" in comp_desc
        assert "DeferQueue.consume_approval()" in comp_desc
        assert "SymbolicGovernor.revalidate_post_hitl()" in comp_desc
        assert "planned" in comp_desc.lower()

        req = next(
            r
            for r in ssp["control-implementation"]["implemented-requirements"]
            if r["control-id"] == "gdpr-art22"
        )
        assert req["uuid"] == "eu-ecb-req-0002-4000-8000-000000000002"
        props = {p["name"]: p["value"] for p in req["props"]}
        assert props["implementation-status"] == "partially-implemented"
        assert props["system-triggered-oversight-status"] == "implemented"
        assert props["subject-initiated-contest-status"] == "planned"
        assert props["compliance-bridge-art22-endpoint-status"] == "planned"
        assert "REQUIRE_APPROVAL" in req["description"]
        assert "EU-006" in req["description"]

        assert len(req["by-components"]) == 2
        by_comp_impl = req["by-components"][0]
        assert by_comp_impl["implementation-status"]["state"] == "implemented"
        assert "REQUIRE_APPROVAL" in by_comp_impl["description"]
        by_comp_planned = req["by-components"][1]
        assert by_comp_planned["implementation-status"]["state"] == "planned"
        assert "lula-validation-gdpr-art22.yaml" in by_comp_planned["description"]

    def test_gdpr_art22_and_human_ai_config_lula_manifests_drop_dead_hitl_escalator(
        self,
    ) -> None:
        gdpr_raw = (LULA_DIR / "lula-validation-gdpr-art22.yaml").read_text(
            encoding="utf-8"
        )
        assert "hitl_escalator" not in gdpr_raw.lower()
        assert "hitl escalator" not in gdpr_raw.lower()
        assert "REQUIRE_APPROVAL" in gdpr_raw
        assert "EU-006" in gdpr_raw
        assert "[0.70, 0.95)" in gdpr_raw
        assert "[0.70, 0.97)" in gdpr_raw

        human_raw = (LULA_DIR / "lula-validation-ai600-human-ai-config.yaml").read_text(
            encoding="utf-8"
        )
        assert "hitl_escalator" not in human_raw.lower()
        assert "hitl escalator" not in human_raw.lower()
        assert "AI600-005" in human_raw
        assert "AI600-004" not in human_raw

    def test_poam_eu_ecb_and_gdpr_dpia_track_eu006_and_live_thresholds(self) -> None:
        poam_eu = (
            REPO_ROOT / "docs" / "compliance" / "eu_ecb" / "POAM_EU_ECB.md"
        ).read_text(encoding="utf-8")
        assert "| **Total Items** | 6" in poam_eu
        assert "| **Moderate**    | 3" in poam_eu
        assert "| **Open**        | 1" in poam_eu
        assert "| **In Progress** | 5" in poam_eu
        assert "| EU-006 |" in poam_eu
        assert "lula-validation-gdpr-art22.yaml" in poam_eu

        eu_rows = re.findall(r"^\|\s*(EU-\d{3})\s*\|", poam_eu, flags=re.MULTILINE)
        assert eu_rows == ["EU-001", "EU-002", "EU-003", "EU-004", "EU-005", "EU-006"]

        dpia = (
            REPO_ROOT / "docs" / "compliance" / "eu_ecb" / "GDPR_DPIA.md"
        ).read_text(encoding="utf-8")
        assert "> €10,000" not in dpia
        assert "REQUIRE_APPROVAL" in dpia
        assert "7,500" in dpia
        assert "[0.70, 0.97)" in dpia
        assert "EU-006" in dpia


class TestNothingSkippedSilently:
    """Entries the manifest glob would miss fail the gate instead of dropping out."""

    @staticmethod
    def _valid_corpus(lula_dir: Path) -> Path:
        (lula_dir / "lula-validation-one.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        (lula_dir / ".stub-baseline").write_text("0\n", encoding="utf-8")
        poam = lula_dir / "POAM.md"
        poam.write_text("# POAM\n", encoding="utf-8")
        return poam

    @staticmethod
    def _run(lula_dir: Path, poam: Path) -> int:
        return gate.main(["--lula-dir", str(lula_dir), "--poam-files", str(poam)])

    def test_valid_corpus_passes(self, tmp_path: Path) -> None:
        poam = self._valid_corpus(tmp_path)
        assert self._run(tmp_path, poam) == 0

    @pytest.mark.parametrize(
        "name",
        [
            "lula-ai600-misnamed.yaml",
            "lula-validation-wrong-suffix.yml",
            "lula-validation-oscal.json",
        ],
    )
    def test_content_file_outside_the_manifest_glob_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
    ) -> None:
        poam = self._valid_corpus(tmp_path)
        (tmp_path / name).write_text(_make_oscal_manifest(), encoding="utf-8")
        assert self._run(tmp_path, poam) == 1
        err = capsys.readouterr().err
        assert "Unrecognized entries" in err
        assert name in err

    def test_undeclared_subdirectory_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        poam = self._valid_corpus(tmp_path)
        nested = tmp_path / "ai600"
        nested.mkdir()
        (nested / "lula-validation-nested.yaml").write_text(
            _make_oscal_manifest(), encoding="utf-8"
        )
        assert self._run(tmp_path, poam) == 1
        assert "ai600/" in capsys.readouterr().err

    def test_declared_entries_are_listed_as_not_scanned(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        poam = self._valid_corpus(tmp_path)
        (tmp_path / "assessment-results.yaml").write_text(
            "assessment-results: {}\n", encoding="utf-8"
        )
        (tmp_path / "drafts").mkdir()
        (tmp_path / "schemas").mkdir()
        assert self._run(tmp_path, poam) == 0
        assert (
            "Not scanned (declared non-manifest entries): "
            "assessment-results.yaml, drafts/, schemas/" in capsys.readouterr().out
        )

    def test_live_repository_has_no_unrecognized_entries(self) -> None:
        assert gate.unrecognized_entries(LULA_DIR) == []
        assert gate.declared_entries(LULA_DIR) == [
            "assessment-results.yaml",
            "drafts/",
            "schemas/",
        ]


class TestLulaSspStatusParity:
    """Bidirectional # cage-status <-> SSP implementation-status parity."""

    EXPECTED_PLANNED = frozenset(
        {
            "lula-validation-gdpr-art22.yaml",
            "lula-validation-ra5.yaml",
        }
    )
    EXPECTED_NOT_APPLICABLE = frozenset(
        {
            "lula-validation-dora-art10.yaml",
            "lula-validation-eu-ai-act-art9.yaml",
            "lula-validation-mas-feat.yaml",
            "lula-validation-mas-notice655.yaml",
            "lula-validation-mas-trm-s6.yaml",
        }
    )

    @staticmethod
    def _write_ssp(
        path: Path,
        requirements: list[tuple[str, str, str]],
    ) -> Path:
        doc = {
            "system-security-plan": {
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "control-implementation": {
                    "description": "Synthetic SSP",
                    "implemented-requirements": [
                        {
                            "uuid": f"00000000-0000-4000-8000-{idx:012d}",
                            "control-id": cid,
                            "description": desc,
                            "props": [
                                {"name": "implementation-status", "value": status}
                            ],
                        }
                        for idx, (cid, status, desc) in enumerate(requirements, start=1)
                    ],
                },
            }
        }
        path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        return path

    @staticmethod
    def _write_manifest(
        path: Path,
        *,
        control_id: str = "syn-1",
        planned: bool = False,
        not_applicable: bool = False,
        region: str = "US_FED",
    ) -> Path:
        body = _make_oscal_manifest(remarks=f"Region: {region}.")
        body = body.replace("control-id: syn-1", f"control-id: {control_id}", 1)
        header = f"# {path.name}\n"
        if planned:
            header += "# cage-status: planned\n"
        if not_applicable:
            header += "# cage-status: not-applicable\n"
        path.write_text(header + body, encoding="utf-8")
        return path

    def test_live_repository_has_2_planned_5_not_applicable_and_26_active_with_zero_parity_errors(
        self,
    ) -> None:
        yaml_files = sorted(LULA_DIR.glob("lula-validation-*.yaml"))
        assert len(yaml_files) == 33
        actual_planned = {
            p.name
            for p in yaml_files
            if gate.has_planned_header(p.read_text(encoding="utf-8"))
        }
        actual_not_applicable = {
            p.name
            for p in yaml_files
            if gate.has_not_applicable_header(p.read_text(encoding="utf-8"))
        }
        assert actual_planned == self.EXPECTED_PLANNED
        assert actual_not_applicable == self.EXPECTED_NOT_APPLICABLE
        ssp_files = [
            REPO_ROOT / "compliance/oscal/system-security-plan.yaml",
            REPO_ROOT / "compliance/oscal/system-security-plan-eu-ecb.yaml",
            REPO_ROOT / "compliance/oscal/system-security-plan-apac-mas.yaml",
        ]
        errors, non_active_count, active_count = gate.check_lula_ssp_status_parity(
            yaml_files, ssp_files
        )
        assert errors == []
        assert non_active_count == 7
        assert active_count == 26

    def test_ssp_not_applicable_with_lula_missing_not_applicable_header_fails_closed(
        self, tmp_path: Path
    ) -> None:
        m = self._write_manifest(
            tmp_path / "lula-validation-syn1.yaml",
            control_id="syn-1",
            planned=True,
        )
        ssp = self._write_ssp(
            tmp_path / "system-security-plan.yaml",
            [("syn-1", "not-applicable", "Adopter-operated institutional control.")],
        )
        errors, _, _ = gate.check_lula_ssp_status_parity([m], [ssp])
        assert any(
            "has '# cage-status: planned'" in e and "not-applicable" in e
            for e in errors
        )

    def test_lula_planned_header_with_ssp_implemented_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lula_dir = tmp_path / "lula"
        lula_dir.mkdir()
        self._write_manifest(
            lula_dir / "lula-validation-syn1.yaml", control_id="syn-1", planned=True
        )
        (lula_dir / ".stub-baseline").write_text("0\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text("# POAM\n", encoding="utf-8")
        ssp = self._write_ssp(
            tmp_path / "system-security-plan.yaml",
            [("syn-1", "implemented", "Implemented control.")],
        )

        rc = gate.main(
            [
                "--lula-dir",
                str(lula_dir),
                "--poam-files",
                str(poam),
                "--ssp-files",
                str(ssp),
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "Lula<->SSP status drift" in err
        assert "has '# cage-status: planned'" in err

    def test_ssp_planned_with_lula_missing_planned_header_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lula_dir = tmp_path / "lula"
        lula_dir.mkdir()
        self._write_manifest(
            lula_dir / "lula-validation-syn1.yaml", control_id="syn-1", planned=False
        )
        (lula_dir / ".stub-baseline").write_text("0\n", encoding="utf-8")
        poam = tmp_path / "POAM.md"
        poam.write_text("# POAM\n", encoding="utf-8")
        ssp = self._write_ssp(
            tmp_path / "system-security-plan.yaml",
            [("syn-1", "planned", "Planned control.")],
        )

        rc = gate.main(
            [
                "--lula-dir",
                str(lula_dir),
                "--poam-files",
                str(poam),
                "--ssp-files",
                str(ssp),
            ]
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "Lula<->SSP status drift" in err
        assert "lacks '# cage-status: planned'" in err

    def test_unresolvable_control_id_fails_closed(self, tmp_path: Path) -> None:
        m = self._write_manifest(
            tmp_path / "lula-validation-orphan.yaml",
            control_id="unknown-99",
            planned=False,
        )
        ssp = self._write_ssp(
            tmp_path / "system-security-plan.yaml",
            [("syn-1", "implemented", "Implemented control.")],
        )
        errors, _, _ = gate.check_lula_ssp_status_parity([m], [ssp])
        assert any("unresolved control-id" in e and "unknown-99" in e for e in errors)

    def test_ssp_dangling_lula_manifest_reference_fails_closed(
        self, tmp_path: Path
    ) -> None:
        m = self._write_manifest(
            tmp_path / "lula-validation-syn1.yaml", control_id="syn-1", planned=False
        )
        ssp = self._write_ssp(
            tmp_path / "system-security-plan.yaml",
            [
                ("syn-1", "implemented", "Backed by lula-validation-syn1.yaml."),
                ("syn-2", "planned", "Backed by lula-validation-ghost.yaml."),
            ],
        )
        errors, _, _ = gate.check_lula_ssp_status_parity([m], [ssp])
        assert any(
            "dangling reference" in e and "lula-validation-ghost.yaml" in e
            for e in errors
        )

    def test_nist_enhancement_resolves_to_parent_control_and_catches_drift(
        self, tmp_path: Path
    ) -> None:
        m = self._write_manifest(
            tmp_path / "lula-validation-au12.yaml",
            control_id="au-12.1",
            planned=False,
        )
        ssp_ok = self._write_ssp(
            tmp_path / "ssp-ok.yaml",
            [("au-12", "implemented", "AU-12 audit generation.")],
        )
        ok_errors, planned, active = gate.check_lula_ssp_status_parity([m], [ssp_ok])
        assert ok_errors == []
        assert (planned, active) == (0, 1)

        ssp_drift = self._write_ssp(
            tmp_path / "ssp-drift.yaml",
            [("au-12", "planned", "AU-12 planned.")],
        )
        drift_errors, _, _ = gate.check_lula_ssp_status_parity([m], [ssp_drift])
        assert any("Lula<->SSP status drift" in e for e in drift_errors)

    def test_missing_ssp_files_fails_closed(self, tmp_path: Path) -> None:
        m = self._write_manifest(
            tmp_path / "lula-validation-syn1.yaml", control_id="syn-1", planned=False
        )
        errors, _, _ = gate.check_lula_ssp_status_parity(
            [m], [tmp_path / "does-not-exist.yaml"]
        )
        assert any("No OSCAL SSP files found" in e for e in errors)
