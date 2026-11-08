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

"""Meta-check regression suite ensuring every CI and Makefile gate actually enforces.

Covers all 19 workflows in ``.github/workflows/*.yml`` (18 gate workflows + 1 release
workflow ``publish-client-sdk.yml``) plus ``Makefile`` and ``scripts/staging_lifecycle.sh``:

1. Complete workflow inventory & classification (fails if a new workflow is added
   without being registered).
2. Universal structural anti-masking checks across all gate workflows:
   - No ``continue-on-error: true`` (or matrix ``continue_on_error: true``)
   - No Trivy ``exit-code: "0"`` (both ``aquasecurity/trivy-action`` and CLI ``trivy image``)
   - No ``|| true`` (outside teardown/diagnostic commands), ``|| echo``, ``sys.exit(0)``
     inside ``WARNING`` blocks, or unconditional ``exit 0``
   - No job gated on unset ``vars.CAGE_DEPLOYMENT_REGION`` or ``if: always()`` on
     downstream test jobs
3. Adversarial planted-defect checks for every gate script and inline workflow gate
   so that no gate can silently degrade into a no-op.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import tomllib
import yaml

from scripts import (
    check_ai600_lula_manifests,
    check_doc_references,
    check_domain_literals,
    check_import_boundaries,
    check_k8s_terraform_parity,
    check_locked_yanks,
    check_locust_baseline,
    check_oscal_claim_census,
    check_poam_lula_divergence,
    check_producer_consumer_keys,
    check_project_id_hygiene,
    check_stpa_freshness,
    check_telemetry_literals,
    check_vendor_brands,
    generate_agent_state_schema,
    verify_langfuse_posture,
)
from src.gateway.governance.stpa_compiler import generate_opa, load_control_structures

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
GITLEAKS_TOML_PATH = REPO_ROOT / ".gitleaks.toml"
STAGING_LIFECYCLE_PATH = REPO_ROOT / "scripts" / "staging_lifecycle.sh"

# Complete classification of all 19 workflows in .github/workflows/
NON_GATE_WORKFLOWS: frozenset[str] = frozenset(
    {
        "publish-client-sdk.yml",  # Tag/manual release workflow building & pushing cage-client wheel/GHCR package
    }
)

GATE_WORKFLOWS: frozenset[str] = frozenset(
    {
        "apac-mas-compliance.yml",
        "ci-integration.yml",
        "ci-partner-integration.yml",
        "ci.yml",
        "dependency-review.yml",
        "eu-ecb-compliance.yml",
        "license_guard.yml",
        "locust-nightly.yml",
        "lula-validate.yml",
        "lula2-pr-compliance.yml",
        "poam-drift.yml",
        "policy_compile.yml",
        "regional-posture.yml",
        # Live repository rules vs .github/branch-protection-rules.md;
        # planted-defect tests in tests/test_check_repo_rules.py.
        "repo-rules.yml",
        "sbom.yml",
        "security-scan.yml",
        "test-hermetic.yml",
        "tlc-model-check.yml",
    }
)

# Teardown / diagnostic commands allowed to use `|| true` in cleanup blocks
ALLOWED_TEARDOWN_OR_DIAGNOSTIC_PATTERNS = (
    re.compile(r"\bkind\s+delete\s+cluster\b"),
    re.compile(r"\bdocker\s+compose\s+(?:down|ps|logs)\b"),
    re.compile(r"\bkubectl\s+logs\b"),
)


def _iter_workflows() -> list[tuple[Path, dict[str, Any]]]:
    workflows: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict), f"{path.name} did not parse as a YAML mapping"
        workflows.append((path, data))
    assert workflows, "No workflow files found in .github/workflows/"
    return workflows


def _extract_heredoc_python(step_run: str) -> str:
    """Extract inline Python heredoc body (`python3 - <<'EOF' ... EOF`) from a workflow step."""
    m = re.search(
        r"python3?\s+-\s*<<['\"]?(\w+)['\"]?\n(.*?)\n\s*\1\b",
        step_run,
        re.DOTALL,
    )
    assert m is not None, f"Could not extract Python heredoc from:\n{step_run}"
    return m.group(2)


# ---------------------------------------------------------------------------
# 1. Complete Workflow Inventory & Classification
# ---------------------------------------------------------------------------


def test_workflow_inventory_is_complete_and_classified() -> None:
    """Every file in .github/workflows/*.yml must be explicitly classified as a gate or non-gate workflow."""
    on_disk = {p.name for p in WORKFLOWS_DIR.glob("*.yml")}
    classified = GATE_WORKFLOWS | NON_GATE_WORKFLOWS
    assert not (GATE_WORKFLOWS & NON_GATE_WORKFLOWS), (
        "Workflow cannot be in both GATE_WORKFLOWS and NON_GATE_WORKFLOWS"
    )
    unclassified = sorted(on_disk - classified)
    missing = sorted(classified - on_disk)
    assert not unclassified, (
        f"Unclassified workflow(s) in .github/workflows/: {unclassified}. "
        "Register new workflows in GATE_WORKFLOWS and add adversarial gate tests."
    )
    assert not missing, f"Classified workflow(s) missing from disk: {missing}"
    assert len(on_disk) == 19, f"Expected 19 workflows, found {len(on_disk)}"

    # Verify publish-client-sdk.yml is genuinely a release workflow, not a disguised test gate
    pub_data = yaml.safe_load(
        (WORKFLOWS_DIR / "publish-client-sdk.yml").read_text(encoding="utf-8")
    )
    triggers = pub_data.get("on") or pub_data.get(True) or {}
    assert "pull_request" not in triggers, (
        "publish-client-sdk.yml must not trigger on pull_request"
    )


# ---------------------------------------------------------------------------
# 2. Universal Structural Anti-Masking Checks Across All Workflows
# ---------------------------------------------------------------------------


def test_no_workflow_uses_continue_on_error_true() -> None:
    """No job, step, or matrix entry in .github/workflows/*.yml may set continue-on-error: true."""
    violations: list[str] = []
    for path, data in _iter_workflows():
        jobs = data.get("jobs", {}) or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if job.get("continue-on-error") is True:
                violations.append(
                    f"{path.name}:job:{job_id} sets continue-on-error: true"
                )

            strategy = job.get("strategy", {}) or {}
            matrix = strategy.get("matrix", {}) or {}
            if isinstance(matrix, dict):
                for entry in matrix.get("include", []) or []:
                    if (
                        isinstance(entry, dict)
                        and entry.get("continue_on_error") is True
                    ):
                        violations.append(
                            f"{path.name}:job:{job_id}:matrix.include({entry.get('region')}) "
                            "sets continue_on_error: true"
                        )

            for idx, step in enumerate(job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                step_name = step.get("name", f"step[{idx}]")
                if step.get("continue-on-error") is True:
                    violations.append(
                        f"{path.name}:job:{job_id}:step:{step_name!r} sets continue-on-error: true"
                    )

    assert not violations, (
        "Found non-enforcing `continue-on-error: true` in GitHub workflows:\n"
        + "\n".join(violations)
    )


def test_no_trivy_step_uses_exit_code_zero() -> None:
    """Every vulnerability scan with Trivy (action or CLI) must fail on findings (exit-code 1)."""
    violations: list[str] = []
    for path, data in _iter_workflows():
        jobs = data.get("jobs", {}) or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for idx, step in enumerate(job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                step_name = step.get("name", f"step[{idx}]")
                uses = str(step.get("uses", ""))
                if "aquasecurity/trivy-action" in uses:
                    with_cfg = step.get("with", {}) or {}
                    fmt = str(with_cfg.get("format", ""))
                    exit_code = with_cfg.get("exit-code")
                    if str(exit_code) == "0":
                        violations.append(
                            f"{path.name}:job:{job_id}:step:{step_name!r} sets exit-code: {exit_code!r}"
                        )
                    if fmt != "cyclonedx" and str(exit_code) != "1":
                        violations.append(
                            f"{path.name}:job:{job_id}:step:{step_name!r} must explicitly set exit-code: '1' (got {exit_code!r})"
                        )
                run_script = step.get("run")
                if (
                    isinstance(run_script, str)
                    and "trivy image" in run_script
                    and "--severity" in run_script
                ):
                    if "--exit-code 1" not in run_script:
                        violations.append(
                            f"{path.name}:job:{job_id}:step:{step_name!r} runs `trivy image --severity` without `--exit-code 1`"
                        )

    assert not violations, (
        "Found non-enforcing Trivy configuration in GitHub workflows:\n"
        + "\n".join(violations)
    )


def test_no_gate_step_swallows_errors_with_or_true_or_exit_zero() -> None:
    """No gate step in .github/workflows/*.yml may swallow failures via `|| true`, `|| echo`, `exit 0`, or `sys.exit(0)`."""
    violations: list[str] = []
    or_true_re = re.compile(r"\|\|\s*true\b")
    or_echo_re = re.compile(r"\|\|\s*echo\b")
    exit_zero_re = re.compile(r"^\s*exit\s+0\s*$", re.MULTILINE)
    sys_exit_zero_re = re.compile(r"\bsys\.exit\(\s*0\s*\)")

    for path, data in _iter_workflows():
        jobs = data.get("jobs", {}) or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for idx, step in enumerate(job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                run_script = step.get("run")
                if not isinstance(run_script, str):
                    continue
                step_name = step.get("name", f"step[{idx}]")
                for line in run_script.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if or_true_re.search(line):
                        if not any(
                            pat.search(line)
                            for pat in ALLOWED_TEARDOWN_OR_DIAGNOSTIC_PATTERNS
                        ):
                            violations.append(
                                f"{path.name}:job:{job_id}:step:{step_name!r} uses `|| true`: {stripped}"
                            )
                    if or_echo_re.search(line):
                        violations.append(
                            f"{path.name}:job:{job_id}:step:{step_name!r} swallows failure with `|| echo`: {stripped}"
                        )
                if exit_zero_re.search(run_script):
                    violations.append(
                        f"{path.name}:job:{job_id}:step:{step_name!r} contains unconditional `exit 0`"
                    )
                if sys_exit_zero_re.search(run_script):
                    violations.append(
                        f"{path.name}:job:{job_id}:step:{step_name!r} contains `sys.exit(0)` early-exit mask"
                    )

    assert not violations, (
        "Found error-swallowing patterns in GitHub workflows:\n" + "\n".join(violations)
    )


def test_no_gate_job_is_gated_on_unset_vars_or_if_always() -> None:
    """No gate job may be gated on `vars.CAGE_DEPLOYMENT_REGION` or use `if: always()` without failing on upstream error."""
    violations: list[str] = []
    for path, data in _iter_workflows():
        raw_text = path.read_text(encoding="utf-8")
        for line in raw_text.splitlines():
            if (
                not line.strip().startswith("#")
                and "vars.CAGE_DEPLOYMENT_REGION" in line
            ):
                violations.append(
                    f"{path.name} references unset `vars.CAGE_DEPLOYMENT_REGION`: {line.strip()}"
                )
        jobs = data.get("jobs", {}) or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_if = str(job.get("if", ""))
            if "always()" in job_if:
                # Only summary jobs that explicitly check needs.*.result and `exit 1` may use `if: always()`
                steps_run = "\n".join(
                    str(s.get("run", ""))
                    for s in (job.get("steps", []) or [])
                    if isinstance(s, dict)
                )
                if "exit 1" not in steps_run:
                    violations.append(
                        f"{path.name}:job:{job_id} uses job-level `if: {job_if}` without failing on upstream error"
                    )

    assert not violations, "\n".join(violations)


def test_every_bandit_invocation_in_ci_and_makefile_has_full_scope_and_config() -> None:
    """Every `bandit` command across workflows and Makefile must pass `-c pyproject.toml -ll -ii` and scan `src/` + `scripts/`."""
    violations: list[str] = []
    bandit_cmd_re = re.compile(r"\bbandit\s+-r\b[^\n]*")

    sources: list[tuple[str, str]] = [
        (MAKEFILE_PATH.name, MAKEFILE_PATH.read_text(encoding="utf-8"))
    ]
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        sources.append((path.name, path.read_text(encoding="utf-8")))

    found_count = 0
    for name, content in sources:
        for match in bandit_cmd_re.finditer(content):
            found_count += 1
            cmd = match.group(0)
            for required_token in (
                "src/",
                "scripts/",
                "-c pyproject.toml",
                "-ll",
                "-ii",
            ):
                if required_token not in cmd:
                    violations.append(
                        f"{name}: bandit invocation missing `{required_token}`: {cmd.strip()}"
                    )

    assert found_count >= 3, (
        f"Expected at least 3 bandit invocations across CI and Makefile, found {found_count}"
    )
    assert not violations, "\n".join(violations)


def test_every_opa_fmt_invocation_uses_fail_flag() -> None:
    """Every `opa fmt` invocation in workflows must use `--fail` and never `--diff || true`."""
    violations: list[str] = []
    opa_fmt_re = re.compile(r"\bopa\s+fmt\b[^\n]*")
    found_count = 0

    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        content = path.read_text(encoding="utf-8")
        for match in opa_fmt_re.finditer(content):
            found_count += 1
            cmd = match.group(0)
            if "--fail" not in cmd:
                violations.append(
                    f"{path.name}: `opa fmt` without `--fail`: {cmd.strip()}"
                )

    assert found_count >= 1, (
        "Expected at least one `opa fmt` invocation in .github/workflows/"
    )
    assert not violations, "\n".join(violations)


def test_makefile_gate_targets_do_not_use_or_true() -> None:
    """Makefile gate targets (`lint`, `security`, `docs-check`, `poam-drift-check`, `check-agent-state-schema`) must not use `|| true`."""
    makefile_text = MAKEFILE_PATH.read_text(encoding="utf-8")
    for target in (
        "lint",
        "security",
        "docs-check",
        "poam-drift-check",
        "check-agent-state-schema",
    ):
        m = re.search(
            rf"^{target}:[^\n]*\n((?:\t[^\n]*\n)+)", makefile_text, re.MULTILINE
        )
        assert m is not None, f"Target `{target}:` not found in Makefile"
        recipe = m.group(1)
        assert "|| true" not in recipe, (
            f"Makefile target `{target}` must not use `|| true`:\n{recipe}"
        )


def test_every_workflow_pytest_target_path_exists() -> None:
    """Every explicit test path passed to pytest across all workflows must exist on disk."""
    pytest_path_re = re.compile(
        r"\bpytest\b[^\n]*?\b((?:tests|compliance)/[A-Za-z0-9_./*${}-]+)"
    )
    missing: list[str] = []
    harness_script = REPO_ROOT / "scripts" / "partner_harness.py"
    if harness_script.is_file():
        import importlib.util

        spec = importlib.util.spec_from_file_location("partner_harness", harness_script)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for partner, rel_target in mod.PARTNER_TARGETS.items():
            if not (REPO_ROOT / rel_target).exists():
                missing.append(
                    f"partner_harness.py: {partner} target {rel_target!r} does not exist"
                )
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        content = path.read_text(encoding="utf-8")
        for match in pytest_path_re.finditer(content):
            raw_target = match.group(1)
            if "${" in raw_target:
                continue
            if "*" in raw_target:
                matches = list(REPO_ROOT.glob(raw_target))
                if not matches:
                    missing.append(f"{path.name}: glob {raw_target!r} matched 0 files")
            else:
                target_path = REPO_ROOT / raw_target
                if not target_path.exists():
                    missing.append(f"{path.name}: path {raw_target!r} does not exist")
    assert not missing, "\n".join(missing)


# ---------------------------------------------------------------------------
# 3. Adversarial Planted-Defect Tests for Every Gate
# ---------------------------------------------------------------------------


def test_gate_squash_merge_guard_rejects_two_parent_commit() -> None:
    """ci.yml:squash-merge-guard must fail when git cat-file -p HEAD has > 1 parent line."""
    ci_data = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    step_run = ci_data["jobs"]["squash-merge-guard"]["steps"][1]["run"]
    assert 'grep -c "^parent "' in step_run
    assert '[ "$parents" -gt 1 ]' in step_run
    assert "exit 1" in step_run

    # Planted 2-parent merge commit header vs 1-parent squash commit header
    merge_commit_obj = (
        "tree 0000000\nparent 1111111\nparent 2222222\nauthor A\n\nMerge PR\n"
    )
    single_parent_obj = "tree 0000000\nparent 1111111\nauthor A\n\nfeat(ci): squash\n"
    assert (
        sum(1 for ln in merge_commit_obj.splitlines() if ln.startswith("parent ")) > 1
    )
    assert (
        sum(1 for ln in single_parent_obj.splitlines() if ln.startswith("parent ")) == 1
    )


def test_gate_branch_name_validator_rejects_invalid_branches() -> None:
    """ci.yml:branch-name-validator regex must reject malformed branch names and accept valid ones."""
    ci_data = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    step_run = ci_data["jobs"]["branch-name-validator"]["steps"][0]["run"]
    m = re.search(r"PATTERN='([^']+)'", step_run)
    assert m is not None, "Could not find PATTERN in branch-name-validator"
    pattern = re.compile(m.group(1))

    # Planted invalid branch names must be rejected
    for invalid in (
        "main",
        "feature/new-thing",
        "bugfix/issue-1",
        "feat/UPPERCASE",
        "fix/underscore_name",
        "fix/trailing-hyphen-",
        "feat/-leading-hyphen",
        "feat/this-description-is-over-thirty-chars",
        "random-branch",
    ):
        assert not pattern.search(invalid), (
            f"Branch validator erroneously accepted {invalid!r}"
        )

    # Valid branch names must be accepted
    for valid in (
        "feat/redis-rate-limiter",
        "fix/ci-gate-enforcement",
        "docs/readiness-poam-items",
        "chore/bump-joserfc",
        "hotfix/2.0.1-redis-timeout",
        "dependabot/pip/joserfc-1.7.7",
    ):
        assert pattern.search(valid), f"Branch validator erroneously rejected {valid!r}"


def test_gate_license_header_check_catches_unlicensed_file(tmp_path: Path) -> None:
    """ci.yml:license-check must fail when a source file lacks the Apache 2.0 header."""
    ci_data = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    step_run = ci_data["jobs"]["license-check"]["steps"][1]["run"]
    assert "Apache License" in step_run and "Copyright 2026" in step_run

    planted = tmp_path / "src" / "unlicensed.py"
    planted.parent.mkdir(parents=True)
    planted.write_text("def foo() -> int:\n    return 42\n", encoding="utf-8")

    proc = subprocess.run(
        ["bash", "-c", step_run],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1, (
        f"Expected license-check to fail on planted file, got {proc.returncode}"
    )
    assert "Missing Apache 2.0 license header" in proc.stdout


def test_gate_marker_contract_rejects_unmarked_test() -> None:
    """ci.yml:marker-contract-check (via tests/conftest.py) must raise UsageError on an unmarked test item."""
    from tests import conftest as tests_conftest

    class _FakeUnmarkedItem:
        nodeid = "tests/test_planted_unmarked.py::test_missing_marker"
        name = "test_missing_marker"
        keywords: dict[str, Any] = {}

    with pytest.raises(pytest.UsageError, match="carry no selection marker"):
        tests_conftest._assert_selection_markers([_FakeUnmarkedItem()])


def test_gate_bandit_catches_planted_b310_in_scripts(tmp_path: Path) -> None:
    """Bandit SAST gate (`-c pyproject.toml -ll -ii`) must fail on a planted B310 urlopen defect."""
    planted = tmp_path / "planted_b310.py"
    planted.write_text(
        "import urllib.request\n"
        "def fetch(url: str) -> bytes:\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-c",
            str(REPO_ROOT / "pyproject.toml"),
            "-ll",
            "-ii",
            str(planted),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, (
        "Bandit failed to flag planted B310 defect with `-c pyproject.toml -ll -ii`"
    )
    assert "B310" in proc.stdout


def test_gate_g3_import_boundaries_catches_planted_upward_and_sdk_imports(
    tmp_path: Path,
) -> None:
    """Gate G3 (`scripts/check_import_boundaries.py`) must flag Layer 1 -> Layer 2/eval_harness/vendor SDK imports."""
    planted = tmp_path / "src" / "gateway" / "gateway_planted.py"
    planted.parent.mkdir(parents=True)
    planted.write_text(
        "from src.cage_finance.plugin import FinancePlugin\n"
        "from src.eval_harness.harness import FoundationModelEvalHarness\n"
        "from google.cloud import kms\n",
        encoding="utf-8",
    )
    violations = check_import_boundaries.check_file_boundaries(planted, verbose=False)
    categories = {v.rule_violated for v in violations}
    assert any("Layer 2" in c or "cage_" in c for c in categories), categories
    assert any("Offline" in c or "eval_harness" in c for c in categories), categories
    assert any("vendor SDK" in c or "google.cloud" in c for c in categories), categories


def test_gate_g6_domain_literals_catches_planted_literal_and_syntax_error(
    tmp_path: Path,
) -> None:
    """Gate G6 (`scripts/check_domain_literals.py`) must flag domain literals and fail closed on SyntaxError."""
    planted_literal = tmp_path / "kernel_planted.py"
    planted_literal.write_text("ACTION = 'execute_trade'\n", encoding="utf-8")
    assert check_domain_literals.check_file(planted_literal) == [(1, "execute_trade")]

    planted_syntax = tmp_path / "broken_syntax.py"
    planted_syntax.write_text("def broken(:\n", encoding="utf-8")
    syntax_violations = check_domain_literals.check_file(planted_syntax)
    assert syntax_violations and "unparseable" in syntax_violations[0][1]


def test_gate_g7_telemetry_literals_catches_planted_literal_and_syntax_error(
    tmp_path: Path,
) -> None:
    """Gate G7 (`scripts/check_telemetry_literals.py`) must flag raw `langfuse.*` literals and fail closed on SyntaxError."""
    planted_literal = tmp_path / "telemetry_planted.py"
    planted_literal.write_text(
        "SPAN_ATTR = 'langfuse.observation.type'\n", encoding="utf-8"
    )
    assert check_telemetry_literals.check_file(planted_literal) == [
        (1, "langfuse.observation.type")
    ]

    planted_syntax = tmp_path / "broken_syntax.py"
    planted_syntax.write_text("def broken(:\n", encoding="utf-8")
    syntax_violations = check_telemetry_literals.check_file(planted_syntax)
    assert syntax_violations and "unparseable" in syntax_violations[0][1]


def test_gate_g8_vendor_brands_catches_planted_brand_empty_list_and_syntax_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate G8 (`scripts/check_vendor_brands.py`) must flag vendor brands, fail on SyntaxError, and refuse an empty brand list."""
    assert check_vendor_brands.FORBIDDEN_VENDOR_BRANDS, (
        "FORBIDDEN_VENDOR_BRANDS must not be empty"
    )

    planted_brand = tmp_path / "vendor_planted.py"
    planted_brand.write_text("TRACER = 'langsmith'\n", encoding="utf-8")
    assert check_vendor_brands.check_file(planted_brand) == [(1, "langsmith")]

    planted_syntax = tmp_path / "broken_syntax.py"
    planted_syntax.write_text("def broken(:\n", encoding="utf-8")
    syntax_violations = check_vendor_brands.check_file(planted_syntax)
    assert syntax_violations and "unparseable" in syntax_violations[0][1]

    monkeypatch.setattr(check_vendor_brands, "FORBIDDEN_VENDOR_BRANDS", set())
    monkeypatch.setattr(sys, "argv", ["check_vendor_brands.py"])
    assert check_vendor_brands.main() == 1


def test_gate_project_id_hygiene_catches_planted_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`scripts/check_project_id_hygiene.py` must return 1 when a tracked file contains a prohibited project ID."""
    planted = tmp_path / "leaked_config.yaml"
    prohibited = check_project_id_hygiene.PROHIBITED_IDENTIFIERS[0]
    planted.write_text(f"project_id: {prohibited}\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        check_project_id_hygiene, "get_tracked_files", lambda: ["leaked_config.yaml"]
    )
    monkeypatch.setattr(sys, "argv", ["check_project_id_hygiene.py"])
    assert check_project_id_hygiene.main() == 1


def test_gate_g9_doc_references_catches_planted_dangling_path(tmp_path: Path) -> None:
    """Gate G9 (`scripts/check_doc_references.py`) must flag a planted reference to a non-existent file."""
    doc_file = tmp_path / "README.md"
    doc_file.write_text(
        "See `src/gateway/nonexistent_planted_file_xyz.py` for details.\n",
        encoding="utf-8",
    )
    findings = check_doc_references.audit_markdown_file(doc_file)
    assert findings, "Gate G9 failed to flag planted dangling file reference"


def test_gate_agent_state_schema_catches_planted_drift(tmp_path: Path) -> None:
    """`scripts/generate_agent_state_schema.py --check` must return False when committed schema drifts."""
    current = generate_agent_state_schema.generate_schema()
    drifted_path = tmp_path / "agent_state_schema.json"
    drifted = dict(current)
    drifted["title"] = "DriftedAgentState"
    drifted_path.write_text(json.dumps(drifted, indent=2) + "\n", encoding="utf-8")

    assert generate_agent_state_schema.check_schema(current, drifted_path) is False
    assert (
        generate_agent_state_schema.check_schema(
            current, generate_agent_state_schema.SCHEMA_OUTPUT_PATH
        )
        is True
    )


def test_gate_stpa_compiler_emits_opa_fmt_compliant_rego_and_catches_drift() -> None:
    """`generate_opa()` must emit tab-indented Rego without consecutive blank lines, and `content_digest` must detect drift."""
    files = sorted((REPO_ROOT / "config" / "stpa").rglob("*.yaml"))
    cs = load_control_structures(files)
    compiled = generate_opa(cs)
    assert not (REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego").exists(), (
        "generated_stpa_policy.rego must not be emitted on disk by default (F-102)"
    )
    assert "\n\n\n" not in compiled, (
        "generate_opa() must not emit consecutive blank lines"
    )
    assert "\tinput.action ==" in compiled, (
        "generate_opa() must use tab indentation for opa fmt compliance"
    )
    assert check_stpa_freshness.content_digest(
        compiled
    ) != check_stpa_freshness.content_digest(compiled + "\ndefault allow := true\n")


def test_gate_nemo_freshness_catches_planted_configmap_drift(tmp_path: Path) -> None:
    """`ci.yml:nemo-freshness-check` script must pass on current repo and exit 1 when actions.py drifts."""
    ci_data = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    step_run = ci_data["jobs"]["nemo-freshness-check"]["steps"][2]["run"]
    script = _extract_heredoc_python(step_run)

    # Passes on real repo
    clean_proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert clean_proc.returncode == 0, clean_proc.stdout + clean_proc.stderr

    # Fails on planted drift
    configmap_dir = tmp_path / "infra" / "modules" / "nemo_guardrails"
    configmap_dir.mkdir(parents=True)
    (tmp_path / "config" / "rails").mkdir(parents=True)
    (configmap_dir / "nemo-rails-configmap.yaml").write_text(
        "data:\n  actions.py: |\n    x = 1\n",
        encoding="utf-8",
    )
    (tmp_path / "config" / "rails" / "actions.py").write_text(
        "x = 2\n", encoding="utf-8"
    )
    drift_proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert drift_proc.returncode == 1
    assert "stale relative to config/rails/actions.py" in drift_proc.stdout


def test_gate_langfuse_posture_catches_missing_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`scripts/verify_langfuse_posture.py` must fail closed when any required env var is unset."""
    for var in verify_langfuse_posture.BASE_REQUIRED_VARS:
        monkeypatch.setenv(var, "mock-value")
    assert verify_langfuse_posture.check_env_vars("development") is True

    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    assert verify_langfuse_posture.check_env_vars("development") is False


def test_gate_langfuse_live_check_runs_both_halves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live Langfuse check needs both project IDs and fails on a breach in either half.

    Before #636 it skipped the compliance half, and passed, whenever
    ``LANGFUSE_COMPLIANCE_PROJECT_ID`` was unset.
    """
    for var in verify_langfuse_posture.BASE_REQUIRED_VARS:
        monkeypatch.setenv(var, "mock-value")
    monkeypatch.setenv("LANGFUSE_HOST", "https://core.invalid")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_HOST", "https://compliance.invalid")
    monkeypatch.delenv("LANGFUSE_PROJECT_ID", raising=False)
    monkeypatch.delenv("LANGFUSE_COMPLIANCE_PROJECT_ID", raising=False)
    assert verify_langfuse_posture.check_env_vars("development", live=True) is False

    reachable = {
        "https://core.invalid": ["core-project"],
        "https://compliance.invalid": ["compliance-project"],
    }
    monkeypatch.setattr(
        verify_langfuse_posture,
        "query_langfuse_projects",
        lambda host, _public_key, _secret_key: reachable[host],
    )
    monkeypatch.setenv("LANGFUSE_PROJECT_ID", "core-project")
    # Planted: no compliance project ID, so the compliance half cannot run.
    assert verify_langfuse_posture.verify_live_isolation() is False

    monkeypatch.setenv("LANGFUSE_COMPLIANCE_PROJECT_ID", "compliance-project")
    assert verify_langfuse_posture.check_env_vars("development", live=True) is True
    assert verify_langfuse_posture.verify_live_isolation() is True

    # Planted: the compliance keys also reach the core project.
    reachable["https://compliance.invalid"] = ["compliance-project", "core-project"]
    assert verify_langfuse_posture.verify_live_isolation() is False

    # Planted: the core keys also reach the compliance project.
    reachable["https://compliance.invalid"] = ["compliance-project"]
    reachable["https://core.invalid"] = ["core-project", "compliance-project"]
    assert verify_langfuse_posture.verify_live_isolation() is False


def test_gate_lula_manifests_and_readme_count_catches_planted_defect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`scripts/check_ai600_lula_manifests.py` and README count check must pass on repo and fail on planted defects."""
    assert check_ai600_lula_manifests.main() == 0

    # Planted manifest missing `component-definition`
    lula_dir = tmp_path / "compliance" / "lula"
    lula_dir.mkdir(parents=True)
    (lula_dir / "lula-validation-ai600-planted.yaml").write_text(
        "invalid_top_key: {}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert check_ai600_lula_manifests.main() == 1

    # Verify disk count vs README unique reference count on real repo
    disk_files = sorted(
        (REPO_ROOT / "compliance" / "lula").glob("lula-validation-*.yaml")
    )
    readme_text = (REPO_ROOT / "compliance" / "lula" / "README.md").read_text(
        encoding="utf-8"
    )
    readme_refs = set(re.findall(r"lula-validation-[a-z0-9_-]*\.yaml", readme_text))
    assert len(disk_files) == len(readme_refs), (
        f"Manifest count mismatch: {len(disk_files)} on disk vs {len(readme_refs)} in README.md"
    )


def test_gate_poam_lula_divergence_catches_planted_uncovered_finding() -> None:
    """`scripts/check_poam_lula_divergence.py` must flag a closed POAM finding that has no matching Lula file."""
    planted_poam = (
        "## Closed Findings\n\n"
        "| ID | Control | Description | Closed |\n"
        "|---|---|---|---|\n"
        "| POAM-2026-999 | ZZ-99 | Planted uncovered finding | 2026-10-30 |\n"
    )
    findings = check_poam_lula_divergence.parse_closed_findings(planted_poam)
    assert len(findings) == 1
    lula_stems = check_poam_lula_divergence.get_lula_file_stems(
        REPO_ROOT / "compliance" / "lula"
    )
    controls = check_poam_lula_divergence.split_controls(findings[0]["control"])
    assert (
        check_poam_lula_divergence.find_matching_lula_stems(controls, lula_stems) == []
    )


def test_gate_cbrn_keyword_check_enforces_threshold_invariants() -> None:
    """`ci.yml:cbrn-keyword-check` invariants must hold on `config/governance_thresholds.json`."""
    cfg = json.loads(
        (REPO_ROOT / "config" / "governance_thresholds.json").read_text(
            encoding="utf-8"
        )
    )
    assert "tier1_keywords_cbrn" in cfg
    assert len(cfg["tier1_keywords_cbrn"]) >= 10
    assert cfg.get("tier1_keywords_cbrn_enabled") is True
    assert (REPO_ROOT / "docs" / "governance" / "AGENTIC_SCOPE_STATEMENT.md").is_file()


def test_gate_locked_yanks_catches_planted_yanked_release(tmp_path: Path) -> None:
    """`scripts/check_locked_yanks.py` must return 1 when a locked package version is yanked on PyPI."""
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(
        'version = 1\n\n[[package]]\nname = "planted-pkg"\nversion = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    rc = check_locked_yanks.main(
        argv=[str(lock_file)],
        fetch=lambda _rel: {"info": {"yanked": True, "yanked_reason": "CVE planted"}},
        sleep=lambda _s: None,
    )
    assert rc == 1


def test_gate_gitleaks_scans_full_history_and_catches_planted_secret_patterns() -> None:
    """`security-scan.yml` must scan full git history, and `.gitleaks.toml` custom rules must catch planted secrets."""
    sec_scan = (WORKFLOWS_DIR / "security-scan.yml").read_text(encoding="utf-8")
    assert "HEAD~1..HEAD" not in sec_scan, (
        "security-scan.yml must scan full commit history, not `--log-opts HEAD~1..HEAD`"
    )
    assert "gitleaks detect" in sec_scan
    assert "--exit-code 1" in sec_scan

    cfg = tomllib.loads(GITLEAKS_TOML_PATH.read_text(encoding="utf-8"))
    rules = {r["id"]: re.compile(r["regex"]) for r in cfg.get("rules", [])}
    assert len(rules) >= 5, "Expected at least 5 custom rules in .gitleaks.toml"

    # Build synthetic secret strings dynamically so no literal secret is stored in source
    planted_samples = {
        "cage-langfuse-key": "sk-lf-" + "a1b2c3d4e5f6g7h8i9j0k1",
        "cage-huggingface-token": "hf_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "cage-google-credential": "GOOG" + "1234567890abcdefghij1234",
        "cage-aws-access-key-id": "AKIA" + "1234567890ABCDEF",
        "cage-private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    }
    for rule_id, sample in planted_samples.items():
        assert rule_id in rules, f"Missing rule {rule_id} in .gitleaks.toml"
        assert rules[rule_id].search(sample), (
            f"Rule {rule_id} failed to match planted secret pattern"
        )

    allowlist = cfg.get("allowlist", {})
    for pat in allowlist.get("paths", []):
        compiled = re.compile(pat)
        assert not compiled.search("infra/targets/gcp-gke/main.tf"), (
            f".gitleaks.toml path allowlist {pat!r} must not exclude active infra/ files"
        )
    for pat in allowlist.get("regexes", []):
        re.compile(pat)


def test_gate_license_guard_rejects_planted_gpl_dependency() -> None:
    """`license_guard.yml` forbidden license regex must flag GPL, AGPL, and LGPL packages and allow dual-licensed MIT/Apache/BSD."""
    lg_data = yaml.safe_load(
        (WORKFLOWS_DIR / "license_guard.yml").read_text(encoding="utf-8")
    )
    step_run = lg_data["jobs"]["license-check"]["steps"][5]["run"]
    m = re.search(r"grep -iE '([^']+)'", step_run)
    m_allow = re.search(r"grep -viE '([^']+)'", step_run)
    assert m is not None
    assert m_allow is not None
    forbidden_re = re.compile(m.group(1), re.IGNORECASE)
    permissive_dual_re = re.compile(m_allow.group(1), re.IGNORECASE)

    def _is_flagged(line: str) -> bool:
        return bool(forbidden_re.search(line)) and not bool(
            permissive_dual_re.search(line)
        )

    for forbidden in (
        '{"Name": "bad", "License": "GPLv3"}',
        '{"Name": "bad", "License": "GPL-3.0-only"}',
        '{"Name": "bad", "License": "GNU Affero General Public License v3 (AGPL-3.0)"}',
        '{"Name": "bad", "License": "LGPL-2.1"}',
    ):
        assert _is_flagged(forbidden), f"license_guard.yml failed to flag {forbidden}"

    assert not _is_flagged('{"Name": "ok", "License": "Apache-2.0"}')
    assert not _is_flagged('{"Name": "ok", "License": "MIT"}')
    assert not _is_flagged(
        '{"Name": "forbiddenfruit", "License": "GNU General Public License v3 or later (GPLv3+); MIT License"}'
    )


def test_gate_apac_mas_and_eu_ecb_compliance_workflows_catch_planted_defects(
    tmp_path: Path,
) -> None:
    """All 4 inline Python gates in `apac-mas-compliance.yml` and `eu-ecb-compliance.yml` must pass on repo and fail on planted defects."""
    for wf_name, _region_prefix, dev_tfvars_name, enable_flag, baseline_name in (
        (
            "apac-mas-compliance.yml",
            "asia-",
            "apac-dev.tfvars",
            "enforce_in_dev",
            "APAC_MAS_BASELINE.json",
        ),
        (
            "eu-ecb-compliance.yml",
            "europe-",
            "eu-dev.tfvars",
            "enforce_in_dev",
            "EU_ECB_BASELINE.json",
        ),
    ):
        wf_data = yaml.safe_load((WORKFLOWS_DIR / wf_name).read_text(encoding="utf-8"))
        job = next(iter(wf_data["jobs"].values()))
        py_steps = [
            (s["name"], _extract_heredoc_python(s["run"]))
            for s in job["steps"]
            if isinstance(s, dict) and "python3 - <<" in str(s.get("run", ""))
        ]
        assert len(py_steps) == 4, (
            f"Expected 4 Python gate steps in {wf_name}, found {len(py_steps)}"
        )

        # 1. Every step must pass (exit 0) against the real repository
        for step_name, script in py_steps:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, (
                f"{wf_name} step {step_name!r} failed on clean repo:\n{proc.stdout}\n{proc.stderr}"
            )

        # 2. Every step must fail (exit 1) when its guarded files/invariants are missing in tmp_path
        sandbox = tmp_path / wf_name.replace(".yml", "")
        sandbox.mkdir(parents=True)
        for step_name, script in py_steps:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                cwd=sandbox,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode != 0, (
                f"{wf_name} step {step_name!r} silently exited 0 when files were missing!"
            )

        # 3. Planted dev.tfvars with enforce_in_dev or enable_audit_logging set to false must fail step 3
        dev_tfvars = sandbox / "infra" / "targets" / "gcp-gke" / dev_tfvars_name
        dev_tfvars.parent.mkdir(parents=True, exist_ok=True)
        for bad_tfvars in (
            f"{enable_flag} = false\nenable_audit_logging = true\n",
            f"{enable_flag} = true\nenable_audit_logging = false\n",
        ):
            dev_tfvars.write_text(bad_tfvars, encoding="utf-8")
            proc_step3 = subprocess.run(
                [sys.executable, "-c", py_steps[2][1]],
                cwd=sandbox,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc_step3.returncode != 0, (
                f"{wf_name} step 3 ({py_steps[2][0]!r}) exited 0 on {bad_tfvars!r}!"
            )

        # 4. Planted baseline threshold file without SR 26-2 sentinel must fail step 4
        thresh_dir = sandbox / "config" / "thresholds"
        thresh_dir.mkdir(parents=True, exist_ok=True)
        (thresh_dir / baseline_name).write_text(
            '{"thresholds": {}}\n', encoding="utf-8"
        )
        proc_step4 = subprocess.run(
            [sys.executable, "-c", py_steps[3][1]],
            cwd=sandbox,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_step4.returncode != 0, (
            f"{wf_name} step 4 ({py_steps[3][0]!r}) exited 0 when SR 26-2 sentinel was missing!"
        )


def test_gate_locust_baseline_catches_planted_p95_regression(tmp_path: Path) -> None:
    """`scripts/check_locust_baseline.py` must return 1 when Aggregated p95 exceeds ceiling."""
    csv_path = tmp_path / "locust_stats.csv"
    csv_path.write_text(
        "Type,Name,Request Count,95%\n,Aggregated,100,2500\n",
        encoding="utf-8",
    )
    assert (
        check_locust_baseline.main(
            ["--stats-csv", str(csv_path), "--p95-baseline-ms", "2000"]
        )
        == 1
    )
    assert (
        check_locust_baseline.main(
            ["--stats-csv", str(csv_path), "--p95-baseline-ms", "3000"]
        )
        == 0
    )


def test_gate_hermetic_environment_script_catches_planted_ml_package() -> None:
    """`test-hermetic.yml` environment verification script must exit non-zero if an ML package is present."""
    herm_data = yaml.safe_load(
        (WORKFLOWS_DIR / "test-hermetic.yml").read_text(encoding="utf-8")
    )
    step_run = herm_data["jobs"]["hermetic-test"]["steps"][4]["run"]
    script = _extract_heredoc_python(step_run)

    # Execute the hermetic check in a subprocess where `torch` is mocked as installed via find_spec
    wrapper = (
        "import importlib.util, os, sys\n"
        "os.environ['UV_PROJECT_ENVIRONMENT'] = sys.prefix\n"
        "_orig = importlib.util.find_spec\n"
        "importlib.util.find_spec = lambda name: object() if name == 'torch' else _orig(name)\n"
        + script
    )
    proc = subprocess.run(
        [sys.executable, "-c", wrapper],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "ML packages installed in hermetic mode" in proc.stderr


def test_retired_compliance_matrix_folded_into_staging_lifecycle_gate_w(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`compliance-matrix.yml` and `run_matrix_tests.sh` are retired into `staging_lifecycle.sh` Phases 3-5."""
    assert not (WORKFLOWS_DIR / "compliance-matrix.yml").exists(), (
        "compliance-matrix.yml stub was retired into scripts/staging_lifecycle.sh"
    )
    assert not (REPO_ROOT / "scripts" / "run_matrix_tests.sh").exists(), (
        "scripts/run_matrix_tests.sh was retired into scripts/staging_lifecycle.sh"
    )

    # Every Lula manifest targets a live-cluster domain (kubernetes or api), evaluated in Gate W Phase 3.
    domain_type = re.compile(r"domain:\s*\n\s*type:\s*([A-Za-z0-9_-]+)")
    manifests = sorted(
        (REPO_ROOT / "compliance" / "lula").glob("lula-validation-*.yaml")
    )
    assert len(manifests) >= 30, f"found only {len(manifests)} Lula manifests"
    for manifest in manifests:
        types = set(domain_type.findall(manifest.read_text(encoding="utf-8")))
        assert types and types <= {"kubernetes", "api"}, (manifest.name, types)

    # No workflow may run verify_langfuse_posture.py in --dry-run mode.
    for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
        wf_text = workflow.read_text(encoding="utf-8")
        assert "verify_langfuse_posture.py --dry-run" not in wf_text, workflow.name

    script_text = STAGING_LIFECYCLE_PATH.read_text(encoding="utf-8")
    assert "tests/core" not in script_text
    assert (
        "src/governed_financial_advisor/governance/policy/trade_governance.rego"
        not in script_text
    )
    assert 'verify_langfuse_posture.py" --posture staging' in script_text
    assert "--dry-run" not in script_text
    assert 'test_data_residency.py" --run-integration' in script_text
    assert "plan -detailed-exitcode" in script_text
    assert "--from=cronjob/lula-audit" in script_text
    assert "/v1/evidence/verify?require_citable=true" in script_text
    assert "prometheus.googleapis.com/cage_" in script_text

    # --posture staging must enforce PROD_EXTRA_VARS (LANGFUSE_COMPLIANCE_PROJECT_ID).
    for var in verify_langfuse_posture.BASE_REQUIRED_VARS:
        monkeypatch.setenv(var, f"val-{var}")
    for var in verify_langfuse_posture.LIVE_EXTRA_VARS:
        monkeypatch.setenv(var, f"val-{var}")
    monkeypatch.delenv("LANGFUSE_COMPLIANCE_PROJECT_ID", raising=False)
    assert verify_langfuse_posture.check_env_vars("staging", live=True) is False
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_PROJECT_ID", "proj-compliance-01")
    assert verify_langfuse_posture.check_env_vars("staging", live=True) is True


def test_gate_tlc_model_check_rejects_unpinned_tlc_verdicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tlc-model-check (`scripts/verify_tla.py`) must fail on any TLC verdict no pin covers.

    TLC reports `SP4_FenceEpochMonotonic`, declared under PROPERTIES, as an
    action property, not an invariant. Until 2026-11-02 the runner read only
    invariant violations: with SP-4 planted false, TLC v1.7.4 printed 768
    `Action property` errors on DistributedCBF.cfg and the runner printed OK on
    all 8 cfgs. Under -continue TLC also exits 0 and prints its no-error line
    after reporting violations, so neither can stand in for its Error lines.
    The runner must also fail a cfg whose declared checks differ from its pin.
    """
    # The verdict lines below are recorded from TLC v1.7.4, the
    # TLA_TOOLS_VERSION pinned in tlc-model-check.yml. This test never runs
    # TLC, so a jar bump cannot fail it even if real TLC words its verdicts
    # differently. Whoever bumps the jar re-derives these strings from the new
    # tla2tools.jar's tlc2/output/MP.class and pushes a planted violation
    # through real TLC (POAM-2026-090 detail). verify_tla.py reads only
    # "Error: " lines, so a verdict printed without that prefix would pass the
    # gate silently, and no committed cfg produces an action-property
    # violation that would expose it.
    from proof.distributed_cbf_model import EXPECTED_STATE_COUNTS
    from proof.tla_pins import TLC_PINS, CfgChecks
    from scripts import verify_tla

    trace = "Error: The behavior up to this point is:\nState 1: <Initial predicate>\n"
    completed = "Model checking completed. No error has been found.\n"

    def tlc_output(states: int, violated: frozenset[str]) -> str:
        errors = "".join(
            f"Error: Invariant {inv} is violated.\n{trace}" for inv in sorted(violated)
        )
        return (
            f"{errors}{completed}{3 * states} states generated, "
            f"{states} distinct states found, 0 states left on queue.\n"
        )

    recorded = {
        name: tlc_output(
            states,
            frozenset(
                inv
                for inv, holds in (
                    ("SP1_NoDoubleSpend", sp1),
                    ("SP2_NoOvercommit", sp2),
                )
                if not holds
            ),
        )
        for (name, n), (states, sp1, sp2) in EXPECTED_STATE_COUNTS.items()
        if n == 2
    }
    recorded |= {
        name: tlc_output(pin.distinct_states, pin.violated)
        for name, pin in TLC_PINS.items()
    }
    outputs = dict(recorded)

    def fake_run_tlc(
        java: str, jar: str, cfg: Path, spec: Path
    ) -> tuple[int, set[str], str]:
        out = outputs[cfg.stem]
        states = int(verify_tla._DISTINCT.findall(out)[-1])
        return states, set(verify_tla._VIOLATED.findall(out)), out

    monkeypatch.setattr(verify_tla, "_tools", lambda: ("java", "tla2tools.jar"))
    monkeypatch.setattr(verify_tla, "run_tlc", fake_run_tlc)
    assert verify_tla.main() == 0, "the recorded results must pass as pinned"

    sp4 = f"Error: Action property SP4_FenceEpochMonotonic is violated.\n{trace}"
    plants = {
        "SP-4 violated, shipped cfg": ("DistributedCBF", sp4),
        "SP-4 violated, negative control": ("DistributedCBF_nosync", sp4),
        "liveness violated": (
            "FtraBoundary",
            "Error: Temporal properties were violated.\n",
        ),
        "deadlock": ("LangGraphHarness", "Error: Deadlock reached.\n"),
    }
    for label, (cfg, error) in plants.items():
        outputs.clear()
        outputs.update(recorded, **{cfg: error + recorded[cfg]})
        assert verify_tla.main() == 1, f"tlc-model-check passed a planted {label}"

    outputs.clear()
    outputs.update(recorded)
    outputs["FtraBoundary_nonetpol"] = recorded["FtraBoundary_nonetpol"].replace(
        completed, ""
    )
    assert verify_tla.main() == 1, (
        "tlc-model-check passed a search that never completed"
    )

    # A cfg that drops a pinned invariant: every TLC output is clean and pinned,
    # and the state counts are unchanged.
    outputs.clear()
    outputs.update(recorded)
    pin = verify_tla.DECLARED_CHECKS["DistributedCBF"]
    monkeypatch.setitem(
        verify_tla.DECLARED_CHECKS,
        "DistributedCBF",
        CfgChecks(pin.invariants | {"SP3_NotDeclared"}, pin.properties),
    )
    assert verify_tla.main() == 1, (
        "tlc-model-check passed a cfg missing a pinned invariant"
    )


def test_gate_producer_consumer_keys_rejects_unproduced_keys_and_events(
    tmp_path: Path,
) -> None:
    """Gate 11 (check_producer_consumer_keys.py) must run in ci.yml lint and catch drift."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    lint_steps = ci_yaml["jobs"]["lint"]["steps"]
    assert any(
        "scripts/check_producer_consumer_keys.py" in step.get("run", "")
        for step in lint_steps
    ), "ci.yml lint job must run scripts/check_producer_consumer_keys.py"

    # Live repo passes with floors active
    assert check_producer_consumer_keys.main(["--repo-root", str(REPO_ROOT)]) == 0, (
        "Live repository must pass Gate 11 with zero baseline waivers"
    )

    # Planted unproduced event_type + payload key must fail closed (exit 1)
    producer = tmp_path / "src" / "gateway" / "governance" / "governor" / "verdicts.py"
    producer.parent.mkdir(parents=True, exist_ok=True)
    producer.write_text(
        "def emit(sink):\n"
        "    sink.ingest_sync({'type': 'GOVERNANCE_REFUSAL', 'violated_rule': 'r1'}, "
        "event_type='GOVERNANCE_REFUSAL')\n",
        encoding="utf-8",
    )
    consumer = tmp_path / "proof" / "stream_invariants.py"
    consumer.parent.mkdir(parents=True, exist_ok=True)
    consumer.write_text(
        "def check_stream(records):\n"
        "    for r in records:\n"
        "        event_type = r['event_type']\n"
        "        payload = r['payload']\n"
        "        if event_type == 'UNPRODUCED_GHOST_EVENT':\n"
        "            pass\n"
        "        if event_type == 'GOVERNANCE_REFUSAL':\n"
        "            _ = payload.get('ghost_key')\n",
        encoding="utf-8",
    )
    assert (
        check_producer_consumer_keys.main(["--repo-root", str(tmp_path), "--no-floors"])
        == 1
    ), "Gate 11 failed to reject planted unproduced event_type and payload key"


def test_gate_doc_version_hygiene_rejects_stale_filename_and_major_drift(
    tmp_path: Path,
) -> None:
    """Gate G9 audit_version_hygiene must catch version-suffixed living docs and major-version drift."""
    assert check_doc_references.audit_version_hygiene(REPO_ROOT) == [], (
        "Live repository failed Gate G9 version hygiene"
    )

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "cage"\nversion = "5.0.0"\n',
        encoding="utf-8",
    )
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "BREAKING_CHANGES.md").write_text(
        "# CAGE Breaking Changes\n\n# v4.x\n\n# Unreleased (v5.x)\n",
        encoding="utf-8",
    )
    (docs_dir / "BREAKING_CHANGES_v4.md").write_text("# Stale\n", encoding="utf-8")

    issues = check_doc_references.audit_version_hygiene(tmp_path)
    targets = {issue.target for issue in issues}
    assert "# v5.x" in targets
    assert "# Unreleased (v5.x)" in targets
    assert "docs/BREAKING_CHANGES_v4.md" in targets


def test_gate_oscal_claim_census_rejects_drifted_hash_and_stale_register(
    tmp_path: Path,
) -> None:
    """check_oscal_claim_census.py must run in ci.yml lint + poam-drift.yml and reject drift."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    lint_steps = ci_yaml["jobs"]["lint"]["steps"]
    assert any(
        "scripts/check_oscal_claim_census.py --verify-rendered docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md"
        in step.get("run", "")
        for step in lint_steps
    ), "ci.yml lint job must run scripts/check_oscal_claim_census.py --verify-rendered"

    poam_yaml = yaml.safe_load(
        (WORKFLOWS_DIR / "poam-drift.yml").read_text(encoding="utf-8")
    )
    poam_steps = poam_yaml["jobs"]["poam-drift"]["steps"]
    assert any(
        "scripts/check_oscal_claim_census.py --verify-rendered docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md"
        in step.get("run", "")
        for step in poam_steps
    ), "poam-drift.yml must run scripts/check_oscal_claim_census.py --verify-rendered"

    assert (
        check_oscal_claim_census.main(
            ["--verify-rendered", str(check_oscal_claim_census.DEFAULT_REGISTER_PATH)]
        )
        == 0
    ), "Live repository failed OSCAL claim census or rendered register parity"

    stale_reg = tmp_path / "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
    stale_reg.write_text("# Stale Register\n", encoding="utf-8")
    assert check_oscal_claim_census.main(["--verify-rendered", str(stale_reg)]) == 1, (
        "OSCAL census gate failed to reject a stale rendered register"
    )

    drifted_census = tmp_path / "evidence_claim_census.jsonl"
    rows = check_oscal_claim_census.load_census()
    rows[0]["description_sha256"] = "0" * 64
    drifted_census.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    assert check_oscal_claim_census.main(["--census", str(drifted_census)]) == 1, (
        "OSCAL census gate failed to reject planted description_sha256 drift"
    )


def test_gate_k8s_terraform_parity_catches_shadow_manifests_and_orphan_selectors(
    tmp_path: Path,
) -> None:
    """check_k8s_terraform_parity.py must run in ci.yml lint and reject shadow manifests + orphan selectors."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    lint_steps = ci_yaml["jobs"]["lint"]["steps"]
    assert any(
        "scripts/check_k8s_terraform_parity.py" in step.get("run", "")
        for step in lint_steps
    ), "ci.yml lint job must run scripts/check_k8s_terraform_parity.py"

    assert check_k8s_terraform_parity.main([]) == 0, (
        "Live repository failed Kubernetes/Terraform selector parity gate"
    )

    # 1. Shadow deployment/k8s/ directory must fail with ShadowManifestError
    shadow_repo = tmp_path / "shadow_repo"
    (shadow_repo / "deployment" / "k8s").mkdir(parents=True)
    (shadow_repo / "deployment" / "k8s" / "shadow.yaml").write_text(
        "kind: Deployment\n", encoding="utf-8"
    )
    (shadow_repo / "infra").mkdir(parents=True)
    with pytest.raises(check_k8s_terraform_parity.ShadowManifestError):
        check_k8s_terraform_parity.verify_k8s_terraform_parity(
            shadow_repo, enforce_floors=False
        )
    assert (
        check_k8s_terraform_parity.main(
            ["--repo-root", str(shadow_repo), "--no-floors"]
        )
        == 1
    )

    # 2. Valid synthetic infra/ passes with --no-floors, but fails corpus-floor check without --no-floors
    synth_repo = tmp_path / "synth_repo"
    mod_dir = synth_repo / "infra" / "modules" / "gateway"
    mod_dir.mkdir(parents=True)
    base_tf = """
resource "kubernetes_deployment" "gateway" {
  metadata { name = "gateway" }
  spec {
    template {
      metadata {
        labels = {
          app  = "gateway"
          role = "governance-gateway"
        }
      }
    }
  }
}

resource "kubernetes_service" "gateway" {
  metadata { name = "gateway" }
  spec {
    selector = {
      app = "gateway"
    }
  }
}
"""
    (mod_dir / "main.tf").write_text(base_tf, encoding="utf-8")
    assert (
        check_k8s_terraform_parity.main(["--repo-root", str(synth_repo), "--no-floors"])
        == 0
    )
    with pytest.raises(
        check_k8s_terraform_parity.OrphanSelectorError, match="Corpus floor check"
    ):
        check_k8s_terraform_parity.verify_k8s_terraform_parity(
            synth_repo, enforce_floors=True
        )

    # 3. Planted orphan NetworkPolicy spec.pod_selector must raise OrphanSelectorError
    target_dir = synth_repo / "infra" / "targets" / "gcp-gke"
    target_dir.mkdir(parents=True)
    netpol_path = target_dir / "network_policy.tf"
    netpol_path.write_text(
        """
resource "kubernetes_network_policy_v1" "orphan_spec" {
  metadata { name = "orphan-spec" }
  spec {
    pod_selector {
      match_labels = {
        role = "sovereign-agent"
      }
    }
  }
}
""",
        encoding="utf-8",
    )
    with pytest.raises(
        check_k8s_terraform_parity.OrphanSelectorError, match="sovereign-agent"
    ):
        check_k8s_terraform_parity.verify_k8s_terraform_parity(
            synth_repo, enforce_floors=False
        )

    # 4. Planted orphan NetworkPolicy egress.to.pod_selector peer must raise OrphanSelectorError
    netpol_path.write_text(
        """
resource "kubernetes_network_policy_v1" "orphan_peer" {
  metadata { name = "orphan-peer" }
  spec {
    pod_selector {
      match_labels = {
        app = "gateway"
      }
    }
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "vllm-service"
          }
        }
      }
    }
  }
}
""",
        encoding="utf-8",
    )
    with pytest.raises(
        check_k8s_terraform_parity.OrphanSelectorError, match="vllm-service"
    ):
        check_k8s_terraform_parity.verify_k8s_terraform_parity(
            synth_repo, enforce_floors=False
        )
    netpol_path.unlink()

    # 5. Planted orphan Helm PodMonitoring selector must raise OrphanSelectorError
    chart_dir = mod_dir / "metrics-monitors" / "templates"
    chart_dir.mkdir(parents=True)
    (mod_dir / "metrics-monitors" / "Chart.yaml").write_text(
        "apiVersion: v2\nname: metrics-monitors\nversion: 0.1.0\n",
        encoding="utf-8",
    )
    (chart_dir / "monitors.yaml").write_text(
        """
apiVersion: monitoring.googleapis.com/v1
kind: PodMonitoring
metadata:
  name: ghost-metrics
spec:
  selector:
    matchLabels:
      app: ghost-workload
""",
        encoding="utf-8",
    )
    with pytest.raises(
        check_k8s_terraform_parity.OrphanSelectorError, match="ghost-workload"
    ):
        check_k8s_terraform_parity.verify_k8s_terraform_parity(
            synth_repo, enforce_floors=False
        )


def test_setup_git_hooks_precommit_matches_ci_deterministic_gates() -> None:
    """scripts/setup_git_hooks.sh must run ruff, mypy, and every deterministic gate script in ci.yml."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    hooks_installer = (REPO_ROOT / "scripts" / "setup_git_hooks.sh").read_text(
        encoding="utf-8"
    )

    deterministic_jobs = (
        "lint",
        "agent-state-schema-check",
        "stpa-freshness-check",
        "lula-ai600-validation",
    )
    script_re = re.compile(r"\bscripts/[A-Za-z0-9_]+\.py\b")
    ci_scripts: set[str] = set()
    for job_name in deterministic_jobs:
        job = ci_yaml["jobs"].get(job_name)
        assert isinstance(job, dict), f"Missing job {job_name!r} in ci.yml"
        for step in job.get("steps", []) or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                ci_scripts.update(script_re.findall(step["run"]))

    assert len(ci_scripts) >= 21, (
        f"Expected at least 21 deterministic scripts in ci.yml, found {len(ci_scripts)}: {sorted(ci_scripts)}"
    )
    missing_scripts = sorted(s for s in ci_scripts if s not in hooks_installer)
    assert not missing_scripts, (
        "scripts/setup_git_hooks.sh pre-commit hook is missing deterministic ci.yml gate script(s): "
        f"{missing_scripts}"
    )

    for required_token in (
        '"${repo_ruff}" check .',
        '"${repo_ruff}" format --check .',
        '"${repo_mypy}" src/',
        "--verify-rendered docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md",
        "generate_agent_state_schema.py --check",
        "Apache License",
        "selection_markers",
        "nemo-rails-configmap.yaml",
        "lula-validation-",
    ):
        assert required_token in hooks_installer, (
            f"scripts/setup_git_hooks.sh missing required pre-commit token: {required_token!r}"
        )
