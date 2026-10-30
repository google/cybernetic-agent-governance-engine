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
workflow ``publish-client-sdk.yml``) plus ``Makefile`` and ``scripts/run_matrix_tests.sh``:

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
    check_locked_yanks,
    check_locust_baseline,
    check_poam_lula_divergence,
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
MATRIX_SCRIPT_PATH = REPO_ROOT / "scripts" / "run_matrix_tests.sh"

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
        "compliance-matrix.yml",
        "dependency-review.yml",
        "eu-ecb-compliance.yml",
        "license_guard.yml",
        "locust-nightly.yml",
        "lula-validate.yml",
        "lula2-pr-compliance.yml",
        "poam-drift.yml",
        "policy_compile.yml",
        "regional-posture.yml",
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
    """`generate_opa()` must match `config/opa/generated_stpa_policy.rego` with tabs, and `content_digest` must detect drift."""
    files = sorted((REPO_ROOT / "config" / "stpa").rglob("*.yaml"))
    cs = load_control_structures(files)
    compiled = generate_opa(cs)
    on_disk = (REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego").read_text(
        encoding="utf-8"
    )
    assert check_stpa_freshness.content_digest(
        compiled
    ) == check_stpa_freshness.content_digest(on_disk), (
        "generate_opa() output drifted from config/opa/generated_stpa_policy.rego"
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
    (tmp_path / "deployment" / "k8s").mkdir(parents=True)
    (tmp_path / "config" / "rails").mkdir(parents=True)
    (tmp_path / "deployment" / "k8s" / "nemo-rails-configmap.yaml").write_text(
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
            "enable_apac_mas_compliance",
            "APAC_MAS_BASELINE.json",
        ),
        (
            "eu-ecb-compliance.yml",
            "europe-",
            "eu-dev.tfvars",
            "enable_eu_ecb_compliance",
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

        # 3. Planted dev.tfvars with flag set to false must fail step 3
        dev_tfvars = sandbox / "infra" / "targets" / "gcp-gke" / dev_tfvars_name
        dev_tfvars.parent.mkdir(parents=True, exist_ok=True)
        dev_tfvars.write_text(f"{enable_flag} = false\n", encoding="utf-8")
        proc_step3 = subprocess.run(
            [sys.executable, "-c", py_steps[2][1]],
            cwd=sandbox,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_step3.returncode != 0, (
            f"{wf_name} step 3 ({py_steps[2][0]!r}) exited 0 when {enable_flag} = false!"
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


def test_gate_compliance_matrix_script_has_valid_paths_and_no_silent_skips() -> None:
    """`scripts/run_matrix_tests.sh` must reference existing Rego/test paths and fail closed on missing test files."""
    script_text = MATRIX_SCRIPT_PATH.read_text(encoding="utf-8")
    assert "tests/core" not in script_text, (
        "scripts/run_matrix_tests.sh must not reference non-existent tests/core/"
    )
    assert (
        "src/governed_financial_advisor/governance/policy/trade_governance.rego"
        not in script_text
    ), "scripts/run_matrix_tests.sh must use canonical src/cage_finance/opa/ path"
    assert (REPO_ROOT / "tests" / "test_symbolic_governor.py").is_file()
    assert (REPO_ROOT / "tests" / "infrastructure" / "test_data_residency.py").is_file()
    assert (REPO_ROOT / "src" / "cage_finance" / "opa").is_dir()
    assert 'warn "Gate 0.1 SKIPPED' not in script_text
    assert 'warn "Gate 1.2 SKIPPED' not in script_text
