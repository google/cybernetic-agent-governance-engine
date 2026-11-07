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

"""Unit tests for Gate G9 documentation reference and line-anchor checks."""

import subprocess
from pathlib import Path

import pytest

import scripts.check_doc_references as g9
from scripts.check_doc_references import (
    audit_markdown_file,
    main,
    verify_file_path,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO = Path(__file__).resolve().parents[1]


def _write_sample_target(tmp_path: Path, lines: int = 10) -> Path:
    target = tmp_path / "sample.py"
    target.write_text(
        "\n".join(f"# line {i}" for i in range(1, lines + 1)) + "\n",
        encoding="utf-8",
    )
    return target


def test_verify_file_path_valid_line_anchor_passes(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L1-L10")
    assert valid is True
    assert reason == ""


def test_verify_file_path_anchor_past_eof_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L99999")
    assert valid is False
    assert "exceeds file length" in reason

    doc = tmp_path / "doc.md"
    doc.write_text("See [sample](sample.py#L99999).\n", encoding="utf-8")
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert issues[0].reference_type == "Markdown Link"
    assert "exceeds file length" in issues[0].reason


def test_verify_file_path_inverted_line_anchor_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=20)
    valid, reason = verify_file_path(tmp_path, "sample.py#L10-L5")
    assert valid is False
    assert "inverted range" in reason

    doc = tmp_path / "doc.md"
    doc.write_text("See [sample](sample.py#L10-L5).\n", encoding="utf-8")
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert "inverted range" in issues[0].reason


def test_verify_file_path_zero_start_line_anchor_fails(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L0-L5")
    assert valid is False
    assert "< 1" in reason


def test_main_nonexistent_path_fails_closed() -> None:
    exit_code = main(["--path", "nonexistent_doc_scope_12345"])
    assert exit_code == 1


def test_main_explicit_markdown_file_outside_doc_roots(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    valid_doc = tmp_path / "external_plan.md"
    valid_doc.write_text("See [sample](sample.py#L1-L10).\n", encoding="utf-8")
    assert main(["--path", str(valid_doc)]) == 0

    broken_doc = tmp_path / "broken_plan.md"
    broken_doc.write_text("See [sample](sample.py#L99999).\n", encoding="utf-8")
    assert main(["--path", str(broken_doc)]) == 1


# ---------------------------------------------------------------------------
# Revision-pinned paths: `<sha>:<path>` / `<sha>^:<path>`
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    """Run git in a throwaway fixture repository (synthetic identity, no signing)."""
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=g9-fixture",
            "-c",
            "user.email=g9-fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture()
def history_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    """Two commits on main: `src/gone.py` is added, then deleted by the returned commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "src").mkdir()
    (repo / "src" / "gone.py").write_text("GONE = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add")
    _git(repo, "rm", "-q", "src/gone.py")
    (repo / "kept.md").write_text("kept\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "delete")
    monkeypatch.setattr(g9, "REPO_ROOT", repo)
    g9._history_unavailable.cache_clear()
    return repo, _git(repo, "rev-parse", "HEAD")


def _audit(repo: Path, text: str) -> list[g9.Issue]:
    doc = repo / "doc.md"
    doc.write_text(text + "\n", encoding="utf-8")
    return audit_markdown_file(doc)


def test_pinned_path_resolves_before_the_deleting_commit(
    history_repo: tuple[Path, str],
) -> None:
    repo, deleting = history_repo
    assert _audit(repo, f"`{deleting[:8]}^:src/gone.py` was removed.") == []


def test_pinned_path_absent_at_the_pinned_revision_fails(
    history_repo: tuple[Path, str],
) -> None:
    repo, deleting = history_repo
    issues = _audit(repo, f"`{deleting[:8]}:src/gone.py`")
    assert [i.reference_type for i in issues] == ["Pinned Path"]
    assert "does not exist at" in issues[0].reason


def test_pinned_unknown_commit_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    issues = _audit(repo, "`deadbeef^:src/gone.py`")
    assert len(issues) == 1
    assert "is not a commit" in issues[0].reason


def test_pinned_commit_off_the_mainline_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "side.py").write_text("SIDE = 1\n", encoding="utf-8")
    _git(repo, "add", "side.py")
    _git(repo, "commit", "-q", "-m", "side")
    side = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    issues = _audit(repo, f"`{side[:8]}:side.py`")
    assert len(issues) == 1
    assert "not an ancestor of HEAD" in issues[0].reason


def test_pinned_path_fails_closed_in_a_shallow_clone(
    history_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, deleting = history_repo
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow))
    monkeypatch.setattr(g9, "REPO_ROOT", shallow)
    g9._history_unavailable.cache_clear()
    issues = _audit(shallow, f"`{deleting[:8]}^:src/gone.py`")
    assert len(issues) == 1
    assert "shallow clone" in issues[0].reason


def test_unpinned_removed_path_still_fails(history_repo: tuple[Path, str]) -> None:
    repo, _ = history_repo
    issues = _audit(repo, "`src/gone.py` was removed.")
    assert [i.reference_type for i in issues] == ["File Path"]


# ---------------------------------------------------------------------------
# Terraform paths and link labels
# ---------------------------------------------------------------------------


def test_terraform_paths_are_checked(tmp_path: Path) -> None:
    (tmp_path / "infra" / "mod").mkdir(parents=True)
    (tmp_path / "infra" / "mod" / "main.tf").write_text("# tf\n", encoding="utf-8")
    doc = tmp_path / "doc.md"
    doc.write_text(
        "`infra/mod/main.tf` and `infra/no_such_g9/main.tf`\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert [i.target for i in issues] == ["infra/no_such_g9/main.tf"]


def test_local_link_label_is_display_text(tmp_path: Path) -> None:
    """The target of a local link is the reference; a short label is not re-checked."""
    (tmp_path / "infra" / "modules" / "app").mkdir(parents=True)
    (tmp_path / "infra" / "modules" / "app" / "main.tf").write_text(
        "# tf\n", encoding="utf-8"
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "[`app/main.tf`](infra/modules/app/main.tf)\n"
        "[`app/main.tf`](infra/modules/no_such_g9/main.tf)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in issues] == [(2, "Markdown Link")]


def test_external_link_label_is_still_checked(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "[`src/no_such_module_g9.py`](https://example.com/x)\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert [i.reference_type for i in issues] == ["File Path"]


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


def test_gate_scope_has_one_copy() -> None:
    """CI gate G9 and `make docs-check` pass no --path, so DOC_SCOPE is the only scope."""
    for config in (REPO / ".github" / "workflows" / "ci.yml", REPO / "Makefile"):
        calls = [
            line
            for line in config.read_text(encoding="utf-8").splitlines()
            if "uv run" in line and "check_doc_references.py" in line
        ]
        assert calls, f"{config.name} no longer runs the gate"
        for line in calls:
            assert "--path" not in line, f"{config.name} narrows the scope: {line}"
            assert not line.rstrip().endswith("\\"), f"{config.name}: {line}"
    assert "docs/POAM.md" in g9.DOC_SCOPE


# ---------------------------------------------------------------------------
# Terraform / HCL symbol, index, and module output validation
# ---------------------------------------------------------------------------


@pytest.fixture()
def tf_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fixture repo with a target .tf file and a child module."""
    target_dir = tmp_path / "infra" / "targets" / "gcp-gke"
    mod_dir = tmp_path / "infra" / "modules" / "vpc_network"
    target_dir.mkdir(parents=True)
    mod_dir.mkdir(parents=True)

    (target_dir / "main.tf").write_text(
        'resource "google_kms_key_ring" "signing" {\n'
        '  name = "signing"\n'
        "}\n"
        'resource "google_container_analysis_note" "build_attestor_note" {\n'
        "  count = var.enable_binauthz ? 1 : 0\n"
        "}\n"
        'resource "terraform_data" "control_plane_access_guard" {}\n'
        'data "google_kms_crypto_key_version" "binauthz_attestor" {}\n'
        'module "vpc_network" {\n'
        "  count  = 1\n"
        '  source = "../../modules/vpc_network"\n'
        "}\n"
        'variable "network" {\n'
        '  default = "default"\n'
        "}\n"
        "locals {\n"
        "  any_compliance_active = true\n"
        "}\n",
        encoding="utf-8",
    )
    (mod_dir / "outputs.tf").write_text(
        'output "subnetwork_name" {\n  value = "cage-subnet"\n}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    g9._get_terraform_index.cache_clear()
    return tmp_path


def test_terraform_symbol_valid_declarations_pass(tf_repo: Path) -> None:
    doc = tf_repo / "doc.md"
    doc.write_text(
        "Valid: `google_kms_key_ring.signing`, "
        '`resource "terraform_data" "control_plane_access_guard"`, '
        "`google_container_analysis_note.build_attestor_note[0]`, "
        "`data.google_kms_crypto_key_version.binauthz_attestor`, "
        "`module.vpc_network[0].subnetwork_name`, "
        "`var.network`, `local.any_compliance_active`.\n",
        encoding="utf-8",
    )
    assert audit_markdown_file(doc) == []


def test_terraform_symbol_nonexistent_or_wrong_block_type_fails(tf_repo: Path) -> None:
    doc = tf_repo / "doc.md"
    doc.write_text(
        "Missing key: `google_kms_crypto_key.valkey`\n"
        'Wrong name: `resource "google_memorystore_instance" "valkey"`\n'
        'Wrong block kind: `check "control_plane_access_guard"`\n',
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [i.reference_type for i in issues] == [
        "Terraform Symbol",
        "Terraform Symbol",
        "Terraform Symbol",
    ]
    assert "google_kms_crypto_key.valkey" in issues[0].target
    assert 'resource "google_memorystore_instance" "valkey"' in issues[1].target
    assert 'check "control_plane_access_guard"' in issues[2].target


def test_terraform_symbol_index_without_count_or_for_each_fails(tf_repo: Path) -> None:
    doc = tf_repo / "doc.md"
    doc.write_text(
        "Unindexed resource: `google_kms_key_ring.signing[0]`\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert issues[0].reference_type == "Terraform Symbol"
    assert "has no count/for_each" in issues[0].reason


def test_terraform_symbol_nonexistent_module_output_fails(tf_repo: Path) -> None:
    doc = tf_repo / "doc.md"
    doc.write_text(
        "Bad output: `module.vpc_network[0].gke_subnet_name`\n", encoding="utf-8"
    )
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert issues[0].reference_type == "Terraform Symbol"
    assert "gke_subnet_name" in issues[0].reason


# ---------------------------------------------------------------------------
# Inline `:line_spec` anchors, prose line refs, YAML UUID spans, & Python symbols
# ---------------------------------------------------------------------------


def test_inline_colon_line_anchor_valid_and_out_of_bounds(tmp_path: Path) -> None:
    _write_sample_target(tmp_path, lines=10)
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid `sample.py:5` and `sample.py:2-8`, invalid `sample.py:99` and `sample.py:8-3`.\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.reference_type, i.target) for i in issues] == [
        ("File Path", "sample.py:99"),
        ("File Path", "sample.py:8-3"),
    ]


def test_prose_line_reference_bounds_blank_and_clause_tokens(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "ALPHA_TOKEN = 1\n"
        "def first_fn():\n"
        "\n"
        "    return ALPHA_TOKEN\n"
        "def beta_handler():\n"
        "    return 2\n",
        encoding="utf-8",
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid: `beta_handler` in [`sample.py`](sample.py) line 5.\n"
        "Out of bounds: [`sample.py`](sample.py) line 50.\n"
        "Blank line: [`sample.py`](sample.py) line 3.\n"
        "Wrong token line: `beta_handler` in [`sample.py`](sample.py) line 1.\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (2, "Line Reference"),
        (3, "Line Reference"),
        (4, "Line Reference"),
    ]
    assert "exceeds file length" in issues[0].reason
    assert "is blank" in issues[1].reason
    assert "beta_handler" in issues[2].reason


def test_prose_line_reference_yaml_uuid_span_validation(tmp_path: Path) -> None:
    yaml_file = tmp_path / "component-definition.yaml"
    yaml_file.write_text(
        "implemented-requirements:\n"
        "  - uuid: 423a5590-5440-411f-a3fd-81a950236704\n"
        "    control-id: cm-2\n"
        "    description: >\n"
        "      Baseline configuration.\n"
        "  - uuid: d29a087a-3209-4429-8a58-019f029f1215\n"
        "    control-id: sc-7\n",
        encoding="utf-8",
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid span: `423a5590-5440-411f-a3fd-81a950236704` in [`component-definition.yaml`](component-definition.yaml) (`lines 2\u20135`).\n"
        "Drifted span: `423a5590-5440-411f-a3fd-81a950236704` in [`component-definition.yaml`](component-definition.yaml) (`lines 2\u20137`).\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert issues[0].reference_type == "Line Reference"
    assert "spans lines 2-5, not 2-7" in issues[0].reason


def test_contextual_python_symbol_in_and_paren_patterns(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "EXISTING_CONST = ('a', 'b')\ndef test_existing_func():\n    pass\n",
        encoding="utf-8",
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid: `EXISTING_CONST` in [`sample.py`](sample.py) and [`sample.py`](sample.py) (`test_existing_func`).\n"
        "Invalid in: `REQUIRED_MAIN_CHECKS` in [`sample.py`](sample.py).\n"
        "Invalid paren: [`sample.py`](sample.py) (`test_nonexistent_func`).\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type, i.target) for i in issues] == [
        (2, "Python Symbol", "sample.py::REQUIRED_MAIN_CHECKS"),
        (3, "Python Symbol", "sample.py::test_nonexistent_func"),
    ]


# ---------------------------------------------------------------------------
# Historical assertion evidence check (POAM-2026-169 instance 9)
# ---------------------------------------------------------------------------


def test_historical_assertion_rejects_f3c88e95_poam_174_false_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All three verbatim false historical claims from f3c88e95:docs/POAM.md must fail."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True)
    poam = docs_dir / "POAM.md"
    poam.write_text(
        "| POAM-2026-174 | SC-7 | Verified unfired on `<PROJECT_ID>` (`2026-11-01`: `authorizedNetworksConfig.enabled=true` with 1 CIDR, `databaseEncryption.state=ENCRYPTED`) | Medium | 2026-11-30 |\n"
        "**Status:** Open — verified unfired on `<PROJECT_ID>` (`2026-11-01`)\n"
        "**Live posture (`2026-11-01`, `<PROJECT_ID>`):** `gcloud container clusters describe cage-staging --region=us-central1` returned `authorizedNetworksConfig: {cidrBlocks: [{cidrBlock: <DEPLOYER_IP>/32, displayName: Temporary Deploy Access}], enabled: true}` and `databaseEncryption: {keyName: .../cryptoKeys/gke-etcd-key, state: ENCRYPTED}`. The cluster was applied via `deploy_all.sh --target gcp-gke --env staging`, which sets both variables on every run; the latch has therefore unfired on `<PROJECT_ID>`.\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(poam)
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (1, "Historical Claim"),
        (2, "Historical Claim"),
        (3, "Historical Claim"),
    ]
    for issue in issues:
        assert "Deployment/cluster historical assertion" in issue.reason


def test_historical_assertion_deployment_claim_rejects_git_log_or_commit_sha_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Citing git log or a commit SHA on a deployment/cluster claim still fails without state-serial or audit-log evidence."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True)
    doc = docs_dir / "POAM.md"
    doc.write_text(
        # Deployment claim with only commit SHA + git log -> must STILL fail:
        "On `<PROJECT_ID>`, `cage-staging` was applied via `deploy_all.sh` (`git log`, `f3c88e95`).\n"
        # Deployment claim with state-serial evidence -> passes:
        "On `<PROJECT_ID>`, the latch fired in `default.tfstate.pre-migration-backup` (`serial: 689`).\n"
        # Deployment claim with Cloud Audit Log / UpdateCluster evidence -> passes:
        "On `<PROJECT_ID>`, `cage-staging` has never had a second node pool (`UpdateCluster` in Cloud Audit Logs).\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (1, "Historical Claim"),
    ]
    assert (
        "Deployment/cluster historical assertion requires audit-log or Terraform state-serial"
        in issues[0].reason
    )


def test_historical_assertion_rejects_unverified_never_always_and_no_evidence_of(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unverified 'has never', 'has always', 'never fired', and 'no evidence of' claims in docs/ fail."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True)
    doc = docs_dir / "audit.md"
    doc.write_text(
        "The workflow had never run on main.\n"
        "The branch rule has always required two approvals.\n"
        "There is no evidence of any bypass on main.\n"
        "The latch never fired during staging runs.\n"
        # Verified counterparts with repo/CI/audit evidence pass:
        "The workflow had never run (`total_count: 0`, `run 41362761903`).\n"
        "The branch rule has always required two approvals (`rulesets/26377312/history`).\n"
        "There is no evidence of any bypass in `git log`.\n"
        "The latch never fired in `serial: 42` of `.tfstate`.\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type, i.target) for i in issues] == [
        (1, "Historical Claim", "had never run"),
        (2, "Historical Claim", "has always required"),
        (3, "Historical Claim", "no evidence of"),
        (4, "Historical Claim", "never fired"),
    ]


def test_historical_assertion_normative_never_and_headings_are_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normative 'never <verb>' rules and markdown headings are not false-positived as historical assertions."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True)
    doc = docs_dir / "rules.md"
    doc.write_text(
        "# Why the latch had never fired in local tests\n"
        "A point-in-time snapshot proves only current state and never how the resource reached that state.\n"
        "Never use local Docker daemon for GKE images.\n",
        encoding="utf-8",
    )
    assert audit_markdown_file(doc) == []


def _seed_version_hygiene_repo(
    root: Path,
    *,
    pyproject_version: str = "4.0.0",
    breaking_body: str = (
        "# CAGE Breaking Changes\n\n"
        "# v3.x\n\n## v3.0.1\n\n"
        "# v4.x\n\n## v4.0.0\n\n"
        "# Unreleased (v5.x)\n\n## Unreleased (next major) — Item\n"
    ),
) -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "cage"\nversion = "{pyproject_version}"\n',
        encoding="utf-8",
    )
    docs_dir = root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "BREAKING_CHANGES.md").write_text(breaking_body, encoding="utf-8")


def test_version_hygiene_live_repo_passes() -> None:
    assert g9.audit_version_hygiene(REPO) == []


def test_version_hygiene_happy_path_with_partner_and_lula_schema(
    tmp_path: Path,
) -> None:
    _seed_version_hygiene_repo(tmp_path)
    partner_spec = tmp_path / "docs" / "partners" / "provider_01" / "spec_v02.md"
    partner_spec.parent.mkdir(parents=True, exist_ok=True)
    partner_spec.write_text("# Partner v0.2 spec\n", encoding="utf-8")

    lula_schema = (
        tmp_path
        / "compliance"
        / "lula"
        / "schemas"
        / "lula_v0160_validation.schema.json"
    )
    lula_schema.parent.mkdir(parents=True, exist_ok=True)
    lula_schema.write_text("{}\n", encoding="utf-8")

    verifier = tmp_path / "scripts" / "verify_lula_assessment_results.py"
    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text('"""Lula v0.16.0 verifier."""\n', encoding="utf-8")

    assert g9.audit_version_hygiene(tmp_path) == []


def test_version_hygiene_rejects_stale_versioned_doc_filenames(tmp_path: Path) -> None:
    _seed_version_hygiene_repo(tmp_path)
    (tmp_path / "docs" / "BREAKING_CHANGES_v3.md").write_text(
        "# Old\n", encoding="utf-8"
    )
    (tmp_path / "MIGRATION_v4.md").write_text("# Migration\n", encoding="utf-8")
    oscal_dir = tmp_path / "compliance" / "oscal"
    oscal_dir.mkdir(parents=True)
    (oscal_dir / "ssp_v3.yaml").write_text("ssp: {}\n", encoding="utf-8")

    issues = g9.audit_version_hygiene(tmp_path)
    assert sorted(i.target for i in issues) == [
        "MIGRATION_v4.md",
        "compliance/oscal/ssp_v3.yaml",
        "docs/BREAKING_CHANGES_v3.md",
    ]


def test_version_hygiene_rejects_major_version_drift_in_breaking_changes(
    tmp_path: Path,
) -> None:
    # Bumping pyproject.toml to 5.0.0 without promoting # Unreleased (v5.x) -> # v5.x
    # and advancing # Unreleased (v6.x) must fail closed on both counts.
    _seed_version_hygiene_repo(tmp_path, pyproject_version="5.0.0")
    issues = g9.audit_version_hygiene(tmp_path)
    assert [(i.reference_type, i.target) for i in issues] == [
        ("Version Hygiene", "# v5.x"),
        ("Version Hygiene", "# Unreleased (v5.x)"),
    ]


def test_version_hygiene_rejects_lula_schema_version_drift(tmp_path: Path) -> None:
    _seed_version_hygiene_repo(tmp_path)
    lula_schema = (
        tmp_path
        / "compliance"
        / "lula"
        / "schemas"
        / "lula_v0170_validation.schema.json"
    )
    lula_schema.parent.mkdir(parents=True, exist_ok=True)
    lula_schema.write_text("{}\n", encoding="utf-8")
    verifier = tmp_path / "scripts" / "verify_lula_assessment_results.py"
    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text('"""Lula v0.16.0 verifier."""\n', encoding="utf-8")

    issues = g9.audit_version_hygiene(tmp_path)
    assert len(issues) == 1
    assert (
        issues[0].target == "compliance/lula/schemas/lula_v0170_validation.schema.json"
    )
    assert "Lula v0.17.0" in issues[0].reason
