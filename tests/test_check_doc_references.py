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


def test_verify_file_path_valid_line_anchor_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L1-L10")
    assert valid is True
    assert reason == ""


def test_verify_file_path_anchor_past_eof_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
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


def test_verify_file_path_inverted_line_anchor_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
    _write_sample_target(tmp_path, lines=20)
    valid, reason = verify_file_path(tmp_path, "sample.py#L10-L5")
    assert valid is False
    assert "inverted range" in reason

    doc = tmp_path / "doc.md"
    doc.write_text("See [sample](sample.py#L10-L5).\n", encoding="utf-8")
    issues = audit_markdown_file(doc)
    assert len(issues) == 1
    assert "inverted range" in issues[0].reason


def test_verify_file_path_zero_start_line_anchor_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
    _write_sample_target(tmp_path, lines=10)
    valid, reason = verify_file_path(tmp_path, "sample.py#L0-L5")
    assert valid is False
    assert "< 1" in reason


def test_main_nonexistent_path_fails_closed() -> None:
    exit_code = main(["--path", "nonexistent_doc_scope_12345"])
    assert exit_code == 1


def test_main_explicit_markdown_file_outside_doc_roots(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("def handle() -> None:\n    return None\n", encoding="utf-8")
    valid_doc = tmp_path / "external_plan.md"
    valid_doc.write_text("See [sample](sample.py#handle).\n", encoding="utf-8")
    assert main(["--path", str(valid_doc)]) == 0

    broken_doc = tmp_path / "broken_plan.md"
    broken_doc.write_text("See [sample](sample.py#no_such_symbol).\n", encoding="utf-8")
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
    (repo / "src" / "gone.py").write_text(
        "GONE = 1\nRETIRED_FLAG = True\n\ndef legacy_refusal() -> bool:\n    return RETIRED_FLAG\n",
        encoding="utf-8",
    )
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


def test_inline_colon_line_anchor_valid_and_out_of_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
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


def test_prose_line_reference_bounds_blank_and_clause_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
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


def test_prose_line_reference_yaml_uuid_span_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
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


# ---------------------------------------------------------------------------
# PR-9 / CE-1 / F-64 (CE-M7): Compliance scope, OSCAL/Lula YAML, Ring 3 census
# ---------------------------------------------------------------------------


def test_doc_scope_includes_all_six_poam_and_oscal_register_docs() -> None:
    expected = {
        "docs/POAM.md",
        "docs/BREAKING_CHANGES.md",
        "docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md",
        "docs/compliance/cross-region/POAM_INDEX.md",
        "docs/compliance/us_fed/POAM_US_FED.md",
        "docs/compliance/universal/POAM_ISO42001.md",
        "docs/compliance/eu_ecb/POAM_EU_ECB.md",
        "docs/compliance/apac_mas/POAM_APAC_MAS.md",
    }
    assert expected <= set(g9.DOC_SCOPE)


def test_oscal_and_lula_yaml_rejects_duplicate_mapping_keys(tmp_path: Path) -> None:
    oscal_dir = tmp_path / "compliance" / "oscal"
    lula_dir = tmp_path / "compliance" / "lula"
    oscal_dir.mkdir(parents=True)
    lula_dir.mkdir(parents=True)

    (oscal_dir / "sp800-53-component-definition.yaml").write_text(
        "component-definition:\n"
        "  uuid: 11111111-1111-4111-8111-111111111111\n"
        "  components:\n"
        "    - uuid: a\n"
        "  components:\n"
        "    - uuid: b\n",
        encoding="utf-8",
    )
    (lula_dir / "lula-validation-dup.yaml").write_text(
        "component-definition:\n"
        "  uuid: 22222222-2222-4222-8222-222222222222\n"
        "  back-matter:\n"
        "    resources:\n"
        "      - uuid: 33333333-3333-4333-8333-333333333333\n"
        "        description: |\n"
        "          domain:\n"
        "            type: kubernetes\n"
        "          provider:\n"
        "            type: opa\n"
        "          provider:\n"
        "            type: opa\n",
        encoding="utf-8",
    )

    issues = g9.audit_oscal_and_lula_yaml(tmp_path)
    by_type = [(i.source_file.name, i.reference_type) for i in issues]
    assert ("sp800-53-component-definition.yaml", "YAML Duplicate Key") in by_type
    assert ("lula-validation-dup.yaml", "YAML Duplicate Key") in by_type


def test_oscal_yaml_rejects_dangling_fragment_local_href_and_docs_proof_packages_paths(
    tmp_path: Path,
) -> None:
    """OSCAL YAML hrefs and narrative paths cover docs/, proof/, and packages/, with no waiver."""
    oscal_dir = tmp_path / "compliance" / "oscal"
    src_dir = tmp_path / "src" / "gateway"
    docs_dir = tmp_path / "docs"
    proof_dir = tmp_path / "proof"
    pkg_dir = tmp_path / "packages" / "cage-client"
    for d in (oscal_dir, src_dir, docs_dir, proof_dir, pkg_dir):
        d.mkdir(parents=True)
    (src_dir / "real.py").write_text("x = 1\n", encoding="utf-8")
    (docs_dir / "existing_guide.md").write_text("# guide\n", encoding="utf-8")
    (proof_dir / "real_proof.py").write_text("x = 1\n", encoding="utf-8")
    (pkg_dir / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    # Both were KNOWN_DOCUMENTED_GAPS entries; the waiver is deleted (POAM-2026-224).
    assert not hasattr(g9, "KNOWN_DOCUMENTED_GAPS")
    waived_gap_path = "compliance/oscal/sp80053-profile.yaml"
    waived_narrative = "scripts/generate_sar.py"

    (oscal_dir / "eu-ai-act-profile.yaml").write_text(
        "profile:\n"
        "  uuid: 44444444-4444-4444-8444-444444444444\n"
        "  imports:\n"
        f"    - href: {waived_gap_path}\n"
        "    - href: '#missing-uuid-999'\n"
        "    - href: '#present-uuid-001'\n"
        "  metadata:\n"
        "    remarks: >-\n"
        "      Valid src/gateway/real.py, docs/existing_guide.md, proof/real_proof.py, packages/cage-client/pyproject.toml "
        f"vs missing {waived_narrative}, docs/missing_doc.md, proof/missing_proof.py, packages/cage-client/missing.py.\n"
        "  back-matter:\n"
        "    resources:\n"
        "      - uuid: present-uuid-001\n"
        "        rlinks:\n"
        "          - href: https://example.org/spec\n",
        encoding="utf-8",
    )

    issues = g9.audit_oscal_and_lula_yaml(tmp_path)
    got = {(i.reference_type, i.target) for i in issues}
    assert ("OSCAL Href Path", waived_gap_path) in got
    assert ("OSCAL Href Fragment", "#missing-uuid-999") in got
    assert ("OSCAL File Path", waived_narrative) in got
    assert ("OSCAL File Path", "docs/missing_doc.md") in got
    assert ("OSCAL File Path", "proof/missing_proof.py") in got
    assert ("OSCAL File Path", "packages/cage-client/missing.py") in got
    assert not any(
        good in i.target
        for i in issues
        for good in (
            "real.py",
            "existing_guide.md",
            "real_proof.py",
            "pyproject.toml",
            "present-uuid-001",
        )
    )


def test_census_non_implemented_holds_read_back_paths_are_verified(
    tmp_path: Path,
) -> None:
    """Non-implemented HOLDS rows in evidence_claim_census.jsonl must have read_back.check paths verified."""
    import json

    import scripts.check_oscal_claim_census as census_mod

    oscal_dir = tmp_path / "compliance" / "oscal"
    oscal_dir.mkdir(parents=True)
    (tmp_path / "proof").mkdir()
    (tmp_path / "proof" / "real_inv.py").write_text("x = 1\n", encoding="utf-8")

    row_ok = {
        "id": "sp800-53-component-definition.yaml#ok-partial-001",
        "verdict": "HOLDS",
        "disposition": "holds",
        "status_extracted": "partial",
        "custody": {"grade": "PLANE"},
        "lifetime": {"grade": "OUTLIVES"},
        "read_back": {
            "grade": "OBSERVES",
            "check": "proof/real_inv.py#x",
        },
        "cites": ["proof/real_inv.py#x"],
        "evidence_named": ["proof/real_inv.py"],
        "description_sha256": "a" * 64,
    }
    row_bad = {
        "id": "sp800-53-component-definition.yaml#bad-partial-002",
        "verdict": "HOLDS",
        "disposition": "holds",
        "status_extracted": "partial",
        "custody": {"grade": "PLANE"},
        "lifetime": {"grade": "OUTLIVES"},
        "read_back": {
            "grade": "OBSERVES",
            "check": "docs/nonexistent_runbook.md and packages/cage-conformance/missing.py",
        },
        "cites": [],
        "evidence_named": ["proof/missing_oracle.py"],
        "description_sha256": "b" * 64,
    }
    census_file = oscal_dir / "evidence_claim_census.jsonl"
    census_file.write_text(
        json.dumps(row_ok) + "\n" + json.dumps(row_bad) + "\n",
        encoding="utf-8",
    )

    g9_issues = g9.audit_oscal_and_lula_yaml(tmp_path)
    g9_targets = {
        i.target for i in g9_issues if i.reference_type == "Census HOLDS Path"
    }
    assert g9_targets == {
        "docs/nonexistent_runbook.md",
        "packages/cage-conformance/missing.py",
        "proof/missing_oracle.py",
    }

    extracted = {
        row_ok["id"]: {"description_sha256": "a" * 64, "status": "partial"},
        row_bad["id"]: {"description_sha256": "b" * 64, "status": "partial"},
    }
    c_errs = census_mod.validate_census(
        [
            row_ok,
            row_bad,
            {
                "id": "SA11-SYSTEMIC",
                "verdict": "NOT_IN_FORCE",
                "disposition": "restate",
                "custody": {"grade": "n/a"},
                "read_back": {"grade": "NONE", "check": "none"},
                "lifetime": {"grade": "n/a"},
                "cites": [],
                "description_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        ],
        extracted,
        tmp_path,
    )
    assert any("docs/nonexistent_runbook.md" in e for e in c_errs)
    assert any("packages/cage-conformance/missing.py" in e for e in c_errs)
    assert any("proof/missing_oracle.py" in e for e in c_errs)


def test_ring3_census_claim_ids_and_summary_tables_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oscal_dir = tmp_path / "compliance" / "oscal"
    oscal_dir.mkdir(parents=True)
    (oscal_dir / "evidence_claim_census.jsonl").write_text(
        '{"id": "component-definition.yaml#good-001", "verdict": "HOLDS"}\n'
        '{"id": "system-security-plan.yaml#weak-002", "verdict": "WEAKER"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    g9._load_census_index.cache_clear()

    sec = tmp_path / "SECURITY.md"
    sec.write_text(
        "## Hardening\n\n"
        "### Implemented Controls Summary\n\n"
        "| Control | Census Claim ID | Notes |\n"
        "|---|---|---|\n"
        "| Valid row | `component-definition.yaml#good-001` | Enforced |\n"
        "| Uncited row | -- | Enforced without census ID |\n"
        "| Unknown ID | `component-definition.yaml#ghost-999` | Bad ID |\n"
        "| Unqualified weak | `system-security-plan.yaml#weak-002` | Claims full coverage |\n"
        "| Qualified weak | `system-security-plan.yaml#weak-002` | Gap tracked under POAM-2026-195 (open) |\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(sec)
    got = [(i.line_number, i.reference_type, i.target) for i in issues]
    assert got == [
        (
            8,
            "Uncited Control Claim",
            "| Uncited row | -- | Enforced without census ID |",
        ),
        (9, "Census Claim ID", "component-definition.yaml#ghost-999"),
        (10, "Census Claim ID", "system-security-plan.yaml#weak-002"),
    ]


# ---------------------------------------------------------------------------
# POAM-2026-224: retracted records and branch-name examples
# ---------------------------------------------------------------------------

NOTICE = (
    "> **RETRACTED 2026-11-15** \u2014 Withdrawn in full under `POAM-2026-224`. "
    "Nothing below is a current claim.\n"
)


@pytest.fixture()
def retracted_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fixture repo: docs/POAM.md with a POAM-2026-224 row, and the retracted archive."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "POAM.md").write_text(
        "| ID | Control | Description | Severity | Target Date |\n"
        "|----|---------|-------------|----------|-------------|\n"
        "| POAM-2026-224 | CA-2 | Waiver deleted | Moderate | 2026-12-31 |\n",
        encoding="utf-8",
    )
    (tmp_path / "compliance" / "archive" / "retracted").mkdir(parents=True)
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    return tmp_path


def _retracted(repo: Path, text: str) -> list[g9.Issue]:
    doc = repo / "compliance" / "archive" / "retracted" / "SAR.md"
    doc.write_text(text, encoding="utf-8")
    return audit_markdown_file(doc)


def test_retracted_record_with_notice_and_poam_row_skips_its_body(
    retracted_repo: Path,
) -> None:
    body = "\n# Old report\n\n| Related SAP | `docs/no_such_plan_g9.md` |\n"
    assert _retracted(retracted_repo, "\n" + NOTICE + body) == []


def test_retracted_record_without_notice_is_reported_and_checked(
    retracted_repo: Path,
) -> None:
    issues = _retracted(retracted_repo, "# Old report\n\n`docs/no_such_plan_g9.md`\n")
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (1, "Retraction Notice"),
        (3, "File Path"),
    ]
    assert (
        "lacks a dated retraction notice naming an existing POAM item"
        in issues[0].reason
    )


def test_retracted_record_naming_a_poam_without_a_row_is_reported(
    retracted_repo: Path,
) -> None:
    notice = NOTICE.replace("POAM-2026-224", "POAM-2026-999")
    issues = _retracted(retracted_repo, notice + "\n`docs/no_such_plan_g9.md`\n")
    assert [(i.reference_type, i.target) for i in issues] == [
        ("Retraction Notice", "POAM-2026-999"),
        ("File Path", "docs/no_such_plan_g9.md"),
    ]
    assert "has no table row in docs/POAM.md" in issues[0].reason


@pytest.mark.parametrize(
    "opening",
    [
        "# Old report\n\n" + NOTICE,  # the notice is not the first non-empty line
        NOTICE.replace("2026-11-15", "2026-11"),  # undated
        NOTICE.replace("2026-11-15", "2026-13-45"),  # not a calendar date
        NOTICE.replace("`POAM-2026-224`", "the POAM"),  # names no POAM item
    ],
)
def test_retracted_record_with_a_malformed_notice_is_reported(
    retracted_repo: Path, opening: str
) -> None:
    issues = _retracted(retracted_repo, opening + "\nBody.\n")
    assert [i.reference_type for i in issues] == ["Retraction Notice"]


def test_retraction_notice_outside_the_archive_excludes_nothing(
    retracted_repo: Path,
) -> None:
    doc = retracted_repo / "docs" / "report.md"
    doc.write_text(NOTICE + "\n`docs/no_such_plan_g9.md`\n", encoding="utf-8")
    assert [i.reference_type for i in audit_markdown_file(doc)] == ["File Path"]


def test_retracted_records_are_discovered_through_doc_scope(
    retracted_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert any(
        g9.RETRACTED_ARCHIVE == entry or g9.RETRACTED_ARCHIVE.startswith(entry + "/")
        for entry in g9.DOC_SCOPE
    )
    doc = retracted_repo / "compliance" / "archive" / "retracted" / "SAR.md"
    doc.write_text("# Old report\n", encoding="utf-8")
    monkeypatch.setattr(g9, "DOC_SCOPE", ("compliance",))
    assert doc.resolve() in g9.find_markdown_files()


BRANCH_TABLE = "| Purpose | Pattern | Example |\n|---|---|---|\n"


def test_branch_table_examples_are_verified_as_branch_names(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        BRANCH_TABLE
        + "| Documentation | `docs/<short-description>` | `docs/stpa-control-diagram` |\n"
        "| Hotfix on release | `hotfix/<version>-<description>` | `hotfix/2.0.1-redis-timeout` |\n"
        "| Release candidate | `rc-v<semver>` | `rc-v2.1.0` |\n",
        encoding="utf-8",
    )
    assert audit_markdown_file(doc) == []


@pytest.mark.parametrize(
    ("example", "reason"),
    [
        ("docs/STPA-control-diagram", "does not match pattern"),
        ("docs/" + "a" * 31, "<short-description> part is 31 characters"),
        ("fix/stpa-control-diagram", "does not match pattern"),
    ],
)
def test_branch_table_example_mismatch_is_reported(
    tmp_path: Path, example: str, reason: str
) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        BRANCH_TABLE
        + f"| Documentation | `docs/<short-description>` | `{example}` |\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type, i.target) for i in issues] == [
        (3, "Branch Example", example)
    ]
    assert reason in issues[0].reason


def test_docs_path_outside_a_branch_table_is_still_checked(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "See `docs/nonexistent-thing` for details.\n"
        "| Area | Document | Example |\n|---|---|---|\n"
        "| Docs | `main` | `docs/nonexistent-thing` |\n"
        "| Plan | `docs/<area>/plan.md` | `docs/nonexistent-thing/plan.md` |\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (1, "File Path"),
        (4, "File Path"),
        (5, "File Path"),
    ]


def test_markdown_link_rejects_subtree_alias_and_repo_root_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Markdown links resolve strictly relative to doc parent (or leading / against REPO_ROOT)."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    (tmp_path / "docs" / "compliance" / "us_fed").mkdir(parents=True)
    (tmp_path / "docs" / "POAM.md").write_text("# POAM\n", encoding="utf-8")
    (tmp_path / "src" / "integrations" / "actuator_01").mkdir(parents=True)

    nested_doc = tmp_path / "docs" / "compliance" / "us_fed" / "POAM_US_FED.md"
    nested_doc.write_text(
        "Broken 404 link: [POAM](../../docs/POAM.md)\n"
        "Valid link: [POAM](../../POAM.md)\n",
        encoding="utf-8",
    )
    nested_issues = audit_markdown_file(nested_doc)
    assert [(i.line_number, i.reference_type, i.target) for i in nested_issues] == [
        (1, "Markdown Link", "../../docs/POAM.md")
    ]

    docs_doc = tmp_path / "docs" / "POAM_TEST.md"
    docs_doc.write_text(
        "Broken subtree alias link: [act](actuator_01/)\n", encoding="utf-8"
    )
    docs_issues = audit_markdown_file(docs_doc)
    assert [(i.line_number, i.reference_type, i.target) for i in docs_issues] == [
        (1, "Markdown Link", "actuator_01/")
    ]


def test_inline_code_path_rejects_parent_traversal_and_subtree_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inline backtick paths must not skip ../.. or guess arbitrary src/ subdirectories."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    (tmp_path / "docs" / "compliance" / "us_fed").mkdir(parents=True)
    (tmp_path / "docs" / "POAM.md").write_text("# POAM\n", encoding="utf-8")
    (tmp_path / "src" / "gateway" / "governance" / "governor").mkdir(parents=True)
    (
        tmp_path / "src" / "gateway" / "governance" / "governor" / "pipeline.py"
    ).write_text("X = 1\n", encoding="utf-8")

    doc = tmp_path / "docs" / "compliance" / "us_fed" / "note.md"
    doc.write_text(
        "Bad traversal: `../../docs/POAM.md`\n"
        "Bad abbreviated path: `governor/pipeline.py`\n"
        "Good canonical path: `src/gateway/governance/governor/pipeline.py`\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type, i.target) for i in issues] == [
        (1, "File Path", "../../docs/POAM.md"),
        (2, "File Path", "governor/pipeline.py"),
    ]


def test_python_symbol_check_rejects_string_literal_spoofing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Arbitrary lowercase/CamelCase string literals must not satisfy Python symbol checks."""
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    g9._get_python_file_symbols.cache_clear()
    mod = tmp_path / "mod.py"
    mod.write_text(
        'SPOOF = "nonexistent_helper"\n'
        'CODE = "FTRA_ERROR"\n'
        "def real_helper() -> None:\n"
        "    return None\n",
        encoding="utf-8",
    )
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Spoofed fn: `nonexistent_helper()` in [`mod.py`](mod.py)\n"
        "Real fn: `real_helper()` in [`mod.py`](mod.py)\n"
        "Upper constant: `FTRA_ERROR` in [`mod.py`](mod.py)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type, i.target) for i in issues] == [
        (1, "Python Symbol", "mod.py::nonexistent_helper")
    ]


# ---------------------------------------------------------------------------
# Two-Tier Structural Symbol Anchors & Strict Unpinned Line-Number Rejection
# ---------------------------------------------------------------------------


def test_tier1_python_structural_anchors_and_ambiguous_leaf_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", True)
    g9._extract_structural_symbols_cached.cache_clear()

    py_file = tmp_path / "engine.py"
    py_file.write_text(
        "MAX_RETRIES: int = 3\n"
        'SPOOF = "ghost_fn"\n'
        "async def run_pipeline() -> None:\n"
        "    return None\n"
        "class Alpha:\n"
        "    KIND = 'alpha'\n"
        "    def execute(self) -> int:\n"
        "        return 1\n"
        "class Beta:\n"
        "    def execute(self) -> int:\n"
        "        return 2\n"
        "    def unique_method(self) -> int:\n"
        "        return 3\n",
        encoding="utf-8",
    )

    stats = g9.AnchorStats()
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid const: [MAX_RETRIES](engine.py#MAX_RETRIES)\n"
        "Valid async fn: [run_pipeline](engine.py#run_pipeline)\n"
        "Valid class attr: [Alpha.KIND](engine.py#Alpha.KIND)\n"
        "Valid qualified method: `engine.py::Alpha.execute`\n"
        "Valid unique leaf method: [unique_method](engine.py#unique_method)\n"
        "Ambiguous leaf method: [execute](engine.py#execute)\n"
        "Spoofed string literal: [ghost_fn](engine.py#ghost_fn)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc, anchor_stats=stats)
    assert [(i.line_number, i.reference_type) for i in issues] == [
        (6, "Markdown Link"),
        (7, "Markdown Link"),
    ]
    assert "Ambiguous unqualified symbol 'execute'" in issues[0].reason
    assert "Symbol anchor 'ghost_fn' not found" in issues[1].reason
    assert stats.tier1_structural == 5
    assert stats.tier2_scoped_subtoken == 0


def test_tier1_polyglot_grammars_rego_hcl_yaml_json_toml_sh_docker_sql_ts_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", True)
    g9._extract_structural_symbols_cached.cache_clear()

    (tmp_path / "policy.rego").write_text(
        'package cage.authz\ndefault allow := false\ndeny_reason[msg] {\n  msg := "no"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "main.tf").write_text(
        'resource "google_kms_key_ring" "signing" {\n  name = "ring"\n}\n'
        'variable "project_id" {\n  type = string\n}\n'
        "locals {\n  enforced_mode = true\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "suite.tftest.hcl").write_text(
        'run "rejects_public_endpoint" {\n  command = plan\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "monitors.yaml").write_text(
        "apiVersion: monitoring.googleapis.com/v1\n"
        "kind: PodMonitoring\n"
        "metadata:\n"
        "  name: gateway-metrics\n"
        "spec:\n"
        "  endpoints:\n"
        "    - port: metrics\n"
        "---\n"
        "implemented-requirements:\n"
        "  - uuid: 423a5590-5440-411f-a3fd-81a950236704\n"
        "    control-id: cm-2\n",
        encoding="utf-8",
    )
    (tmp_path / "schema.json").write_text(
        '{"$defs": {"Decision": {"type": "object"}}, "properties": {"verdict": {"type": "string"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "config.toml").write_text(
        '[tool.bandit]\nskips = ["B101"]\n',
        encoding="utf-8",
    )
    (tmp_path / "gate.sh").write_text(
        "#!/usr/bin/env bash\nreadonly GATE_TIMEOUT=30\nrun_gate() {\n  echo ok\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim AS builder\nARG APP_USER=cage\nENV PORT=8080\n",
        encoding="utf-8",
    )
    (tmp_path / "init.sql").write_text(
        "CREATE TABLE IF NOT EXISTS audit_ledger (id TEXT PRIMARY KEY);\n"
        "CREATE INDEX idx_audit_ts ON audit_ledger (id);\n",
        encoding="utf-8",
    )
    (tmp_path / "client.ts").write_text(
        "export interface Envelope { id: string; }\n"
        "export async function sendEnvelope(): Promise<void> {}\n",
        encoding="utf-8",
    )
    (tmp_path / "target.md").write_text(
        "# Architecture Overview\n\n"
        "## Duplicate Heading\n\n"
        "## Duplicate Heading\n\n"
        "| ID | Control |\n|---|---|\n| POAM-2026-233 | AU-10 |\n",
        encoding="utf-8",
    )

    stats = g9.AnchorStats()
    doc = tmp_path / "index.md"
    doc.write_text(
        "[rego allow](policy.rego#allow) and [rego rule](policy.rego#deny_reason)\n"
        "[tf res](main.tf#google_kms_key_ring.signing) and [tf local](main.tf#local.enforced_mode)\n"
        "[tftest](suite.tftest.hcl#run.rejects_public_endpoint)\n"
        "[k8s](monitors.yaml#PodMonitoring/gateway-metrics) and [oscal](monitors.yaml#uuid:423a5590-5440-411f-a3fd-81a950236704)\n"
        "[json](schema.json#properties.verdict) and [defs](schema.json#$defs.Decision)\n"
        "[toml](config.toml#tool.bandit.skips)\n"
        "[sh fn](gate.sh#run_gate)\n"
        "[docker stage](Dockerfile#stage:builder) and [docker env](Dockerfile#PORT)\n"
        "[sql tbl](init.sql#audit_ledger) and [sql idx](init.sql#idx_audit_ts)\n"
        "[ts iface](client.ts#Envelope) and [ts fn](client.ts#sendEnvelope)\n"
        "[md slug](target.md#duplicate-heading-1) and [md row](target.md#POAM-2026-233)\n"
        "[bad sh var](gate.sh#GATE_TIMEOUT)\n"
        "[bad rego](policy.rego#missing_rule)\n"
        "[bad md](target.md#missing-heading)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc, anchor_stats=stats)
    assert [(i.line_number, i.target) for i in issues] == [
        (12, "gate.sh#GATE_TIMEOUT"),
        (13, "policy.rego#missing_rule"),
        (14, "target.md#missing-heading"),
    ]
    assert stats.tier1_structural == 19


def test_tier2_scoped_subtoken_strips_comments_and_enforces_span_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", True)
    g9._extract_structural_symbols_cached.cache_clear()

    (tmp_path / "guard.py").write_text(
        "def verify_seal(token: str) -> bool:\n"
        "    # SPOOFED_IN_COMMENT should never satisfy Tier 2\n"
        "    if not token:\n"
        "        raise ValueError('SEAL_MISSING')\n"
        "    return True\n\n"
        "def other_fn() -> str:\n"
        "    return 'ONLY_IN_OTHER_FN'\n",
        encoding="utf-8",
    )
    (tmp_path / "handler.ts").write_text(
        "export function checkHeader(hdr: string): boolean {\n"
        "  // COMMENT_ONLY_TOKEN\n"
        "  /* BLOCK_COMMENT_TOKEN */\n"
        "  return hdr === 'l5d-client-id';\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "ledger.sql").write_text(
        "CREATE TABLE ledger_entries (\n"
        "  -- SQL_COMMENT_SPOOF\n"
        "  entry_hash TEXT NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )

    stats = g9.AnchorStats()
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Valid link subtoken: [seal](guard.py#verify_seal:SEAL_MISSING)\n"
        "Valid code subtoken: `guard.py::verify_seal#SEAL_MISSING`\n"
        "Valid ts subtoken: [ts](handler.ts#checkHeader:l5d-client-id)\n"
        "Valid sql subtoken: [sql](ledger.sql#ledger_entries:entry_hash)\n"
        "Py comment spoof: [spoof1](guard.py#verify_seal:SPOOFED_IN_COMMENT)\n"
        "Wrong span spoof: [spoof2](guard.py#verify_seal:ONLY_IN_OTHER_FN)\n"
        "TS line comment spoof: [spoof3](handler.ts#checkHeader:COMMENT_ONLY_TOKEN)\n"
        "TS block comment spoof: [spoof4](handler.ts#checkHeader:BLOCK_COMMENT_TOKEN)\n"
        "SQL comment spoof: [spoof5](ledger.sql#ledger_entries:SQL_COMMENT_SPOOF)\n"
        "Too short subtoken: [short](guard.py#verify_seal:x)\n",
        encoding="utf-8",
    )
    issues = audit_markdown_file(doc, anchor_stats=stats)
    assert [i.line_number for i in issues] == [5, 6, 7, 8, 9, 10]
    for issue in issues[:5]:
        assert "not found in non-comment body" in issue.reason
    assert ">= 2 characters" in issues[5].reason
    assert stats.tier1_structural == 0
    assert stats.tier2_scoped_subtoken == 4


def test_strict_mode_rejects_all_unpinned_line_citations_and_allows_sha_pinned(
    history_repo: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, deleting = history_repo
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", True)
    g9._extract_structural_symbols_cached.cache_clear()

    live = repo / "kept.py"
    live.write_text("def check_ok() -> bool:\n    return True\n", encoding="utf-8")

    oscal_dir = repo / "compliance" / "oscal"
    oscal_dir.mkdir(parents=True)
    (oscal_dir / "profile.yaml").write_text(
        "profile:\n"
        "  uuid: 55555555-5555-4555-8555-555555555555\n"
        "  metadata:\n"
        "    remarks: >-\n"
        "      Bad unpinned src/missing_no_wait.py is separate; check kept.py is root, so use docs/ref.md:1.\n",
        encoding="utf-8",
    )
    (repo / "docs").mkdir()
    (repo / "docs" / "ref.md").write_text("# Heading\n", encoding="utf-8")

    doc = repo / "doc.md"
    doc.write_text(
        f"Allowed pinned colon: `{deleting[:8]}^:src/gone.py:2` set `RETIRED_FLAG` and prose at `{deleting[:8]}^:src/gone.py` (line 2, `RETIRED_FLAG`).\n"
        "Allowed structural: [check_ok](kept.py#check_ok) on port :8080, STPA Loss L1 (L1), g2-standard-8 (L4), 24m, v1.2.3.\n"
        "Forbidden hash line: [kept](kept.py#L1-L2)\n"
        "Forbidden colon line: `kept.py:1`\n"
        "Forbidden prose word: see [kept](kept.py) at line 2.\n"
        "Forbidden prose L-span: see [kept](kept.py) (L1-L2).\n",
        encoding="utf-8",
    )
    md_issues = audit_markdown_file(doc)
    assert [(i.line_number, i.reference_type) for i in md_issues] == [
        (3, "Markdown Link"),
        (4, "File Path"),
        (5, "Unpinned Line Number"),
        (6, "Unpinned Line Number"),
    ]

    oscal_issues = g9.audit_oscal_and_lula_yaml(repo)
    assert any(
        i.reference_type == "OSCAL File Path" and i.target == "docs/ref.md:1"
        for i in oscal_issues
    )


# --- TLA+ structural anchors -------------------------------------------------

_TLA_SPEC = (
    "---- MODULE Spec ----\n"  # 1
    "VARIABLES seal, nonce \\* governed state\n"  # 2
    "\n"  # 3
    "\\* Ghost == not a header: line comment\n"  # 4
    "Init == seal = 0\n"  # 5
    "\n"  # 6
    "Next(x) ==\n"  # 7
    "    /\\ seal' = x  \\* consumes nonce\n"  # 8
    "\n"  # 9
    "(*\n"  # 10
    "Phantom == commented out\n"  # 11
    "*)\n"  # 12
    "THEOREM Safety == Init => Next(1)\n"  # 13
    "====\n"  # 14
)


def test_tla_extractor_spans_operators_theorems_and_declarations() -> None:
    spans = {
        (s.name, s.kind): (s.start_line, s.end_line)
        for s in g9._extract_tla_symbols(_TLA_SPEC)
    }
    # Each span runs to the line before the next header (trailing comments
    # included; they are stripped before any subtoken check).
    assert spans == {
        ("seal", "tla_decl"): (2, 4),
        ("nonce", "tla_decl"): (2, 4),
        ("Init", "tla_op"): (5, 5),
        ("Next", "tla_op"): (7, 12),
        ("Safety", "tla_theorem"): (13, 13),
    }


def test_tla_anchor_resolves_definitions_and_refuses_commented_names(
    tmp_path: Path,
) -> None:
    spec = tmp_path / "Spec.tla"
    spec.write_text(_TLA_SPEC, encoding="utf-8")
    g9._extract_structural_symbols_cached.cache_clear()

    assert g9.resolve_symbol_anchor(spec, "Next")[0]
    assert g9.resolve_symbol_anchor(spec, "Safety")[0]
    assert g9.resolve_symbol_anchor(spec, "Next:seal")[0]
    # A line comment, a block comment, and a subtoken only present in a
    # `\*` comment must not satisfy an anchor.
    assert not g9.resolve_symbol_anchor(spec, "Ghost")[0]
    assert not g9.resolve_symbol_anchor(spec, "Phantom")[0]
    assert not g9.resolve_symbol_anchor(spec, "Next:nonce")[0]


# --- Pinned-blob line and symbol verification (strict mode) ----------------


@pytest.fixture
def strict_pins(
    history_repo: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", True)
    g9._extract_structural_symbols_cached.cache_clear()
    repo, deleting = history_repo
    return repo, deleting[:8]


@pytest.mark.parametrize(
    ("clause", "reference_type", "reason"),
    [
        (
            "`{p}^:src/gone.py:9` set `RETIRED_FLAG`",
            "Pinned Line",
            "exceeds the pinned blob (5 lines)",
        ),
        (
            "`{p}^:src/gone.py:3` defines `legacy_refusal`",
            "Pinned Line",
            "is a blank line",
        ),
        (
            "`{p}^:src/gone.py:1` defines `legacy_refusal`",
            "Pinned Line",
            "does not contain the clause's identifier",
        ),
        ("`{p}^:src/gone.py:2` was removed", "Pinned Line", "names no identifier"),
        (
            "`{p}^:src/gone.py` (line 9, `RETIRED_FLAG`)",
            "Pinned Line",
            "exceeds the pinned blob",
        ),
        ("`{p}^:src/gone.py#missing_fn` was removed", "Pinned Symbol", "missing_fn"),
    ],
)
def test_strict_pin_refuses_lines_and_symbols_the_blob_does_not_hold(
    strict_pins: tuple[Path, str], clause: str, reference_type: str, reason: str
) -> None:
    repo, pin = strict_pins
    issues = _audit(repo, clause.format(p=pin))
    assert [i.reference_type for i in issues] == [reference_type]
    assert reason in issues[0].reason


@pytest.mark.parametrize(
    "clause",
    [
        "`{p}^:src/gone.py:2` set `RETIRED_FLAG`",
        "`{p}^:src/gone.py:5` returns `RETIRED_FLAG`",
        "`{p}^:src/gone.py` (line 4, `legacy_refusal`)",
        "`{p}^:src/gone.py#legacy_refusal` was removed",
    ],
)
def test_strict_pin_accepts_lines_and_symbols_the_blob_holds(
    strict_pins: tuple[Path, str], clause: str
) -> None:
    repo, pin = strict_pins
    assert _audit(repo, clause.format(p=pin)) == []


def test_pin_clause_break_stops_line_governance(strict_pins: tuple[Path, str]) -> None:
    # The bad span sits in the next clause, so it is not checked against this pin.
    repo, pin = strict_pins
    issues = _audit(
        repo, f"`{pin}^:src/gone.py:2` set `RETIRED_FLAG`; unrelated (line 99)"
    )
    assert [
        i.reference_type for i in issues if i.reference_type.startswith("Pinned")
    ] == []


def test_non_strict_mode_checks_pin_existence_only(
    history_repo: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g9, "STRICT_SYMBOL_ANCHORS", False)
    repo, deleting = history_repo
    assert _audit(repo, f"`{deleting[:8]}^:src/gone.py:9` was removed") == []


# --- Pin clause tokens: paths and the pinned filename are not identifiers ---


@pytest.mark.parametrize(
    "named",
    [
        "`src/retired_flag.py`",  # a path, not an identifier
        "`retired_flag.py`",  # a concrete filename
        "`gone`",  # part of the pinned filename itself
    ],
)
def test_pin_clause_tokens_ignore_paths_and_the_pinned_filename(
    strict_pins: tuple[Path, str], named: str
) -> None:
    # Line 2 really holds RETIRED_FLAG, but a clause that only *names a path*
    # whose stem happens to match is not agreement evidence and must be refused.
    repo, pin = strict_pins
    issues = _audit(repo, f"`{pin}^:src/gone.py:2` see {named}")
    pinned = [i for i in issues if i.reference_type.startswith("Pinned")]
    assert [i.reference_type for i in pinned] == ["Pinned Line"]
    assert "names no identifier" in pinned[0].reason


def test_pin_clause_tokens_keep_backticked_identifiers() -> None:
    line = "`abc1234^:src/gone.py:2` sets `RETIRED_FLAG` via `src/x.py`"
    assert g9._pin_clause_tokens(line, 0, len(line), "src/gone.py") == {"retired_flag"}


# --- Pin clause window: code spans are paired on the whole line -------------

_LONG_SPAN = "a" * 200  # longer than PIN_GOVERNANCE_WINDOW


def test_pin_clause_tokens_drop_spans_straddling_the_window() -> None:
    line = "x `straddle_head` sets `RETIRED_FLAG` then `straddle_tail` y"
    start = line.index("straddle_head") + 3  # cut inside the leading span
    end = line.index("straddle_tail") + 3  # cut inside the trailing span
    assert g9._pin_clause_tokens(line, start, end, "src/gone.py") == {"retired_flag"}


@pytest.mark.parametrize(
    "prefix",
    [
        # Odd parity: the clause window starts inside this code span, so
        # pairing backticks on the slice would invert every pair and read the
        # prose between spans as identifiers while dropping RETIRED_FLAG.
        f"see `{_LONG_SPAN}` ",
        # Even-parity control: the long run is prose, not a code span.
        f"see `x` {_LONG_SPAN} ",
    ],
    ids=["odd-parity", "even-parity-control"],
)
def test_pin_clause_window_parity_does_not_flip_code_spans(
    strict_pins: tuple[Path, str], prefix: str
) -> None:
    repo, pin = strict_pins
    issues = _audit(repo, f"{prefix}`{pin}^:src/gone.py:2` sets `RETIRED_FLAG`")
    assert [
        i.reference_type for i in issues if i.reference_type.startswith("Pinned")
    ] == []
