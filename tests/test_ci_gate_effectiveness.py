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

"""Meta-check regression suite ensuring CI and Makefile gates actually enforce.

Verifies that no CI workflow in ``.github/workflows/*.yml`` or gate target in
``Makefile`` silently reports green when a check fails via:
- ``continue-on-error: true`` (or matrix ``continue_on_error: true``)
- Trivy ``exit-code: "0"``
- ``|| true`` or ``|| echo`` in gate steps (only ``if: always()`` / ``if: failure()``
  teardown or diagnostic log-dump steps may ignore teardown errors)
- Unconditional ``exit 0`` after error detection in gate scripts
- ``bandit`` invocations missing ``-c pyproject.toml``, ``-ll``, ``-ii``, ``src/``, or ``scripts/``
- ``opa fmt`` invocations without ``--fail``
- ``gitleaks detect`` narrowed to ``--log-opts "HEAD~1..HEAD"`` instead of full history
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import tomllib
import yaml

from scripts.check_stpa_freshness import content_digest
from src.gateway.governance.stpa_compiler import generate_opa, load_control_structures

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
GITLEAKS_TOML_PATH = REPO_ROOT / ".gitleaks.toml"

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
    """Every vulnerability scan with aquasecurity/trivy-action must fail on findings (exit-code: '1')."""
    violations: list[str] = []
    for path, data in _iter_workflows():
        jobs = data.get("jobs", {}) or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for idx, step in enumerate(job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                if "aquasecurity/trivy-action" not in uses:
                    continue
                with_cfg = step.get("with", {}) or {}
                step_name = step.get("name", f"step[{idx}]")
                # CycloneDX SBOM generation steps have format: "cyclonedx"; vulnerability scans have severity or sarif/table format
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

    assert not violations, (
        "Found non-enforcing Trivy configuration in GitHub workflows:\n"
        + "\n".join(violations)
    )


def test_no_gate_step_swallows_errors_with_or_true_or_exit_zero() -> None:
    """No gate step in .github/workflows/*.yml may swallow failures via `|| true`, `|| echo`, or `exit 0`."""
    violations: list[str] = []
    or_true_re = re.compile(r"\|\|\s*true\b")
    or_echo_re = re.compile(r"\|\|\s*echo\b")
    exit_zero_re = re.compile(r"^\s*exit\s+0\s*$", re.MULTILINE)

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

    assert not violations, (
        "Found error-swallowing shell patterns in GitHub workflows:\n"
        + "\n".join(violations)
    )


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


def test_gitleaks_scans_full_history_and_config_is_valid() -> None:
    """security-scan.yml must not restrict gitleaks to HEAD~1..HEAD, and .gitleaks.toml must be valid TOML."""
    sec_scan = (WORKFLOWS_DIR / "security-scan.yml").read_text(encoding="utf-8")
    assert "HEAD~1..HEAD" not in sec_scan, (
        "security-scan.yml must scan full commit history, not `--log-opts HEAD~1..HEAD`"
    )
    assert "gitleaks detect" in sec_scan
    assert "--exit-code 1" in sec_scan

    cfg = tomllib.loads(GITLEAKS_TOML_PATH.read_text(encoding="utf-8"))
    rules = cfg.get("rules", [])
    assert len(rules) >= 5, "Expected custom rules in .gitleaks.toml"
    for rule in rules:
        re.compile(rule["regex"])

    allowlist = cfg.get("allowlist", {})
    for pat in allowlist.get("paths", []):
        re.compile(pat)
    for pat in allowlist.get("regexes", []):
        re.compile(pat)


def test_makefile_gate_targets_do_not_use_or_true() -> None:
    """Makefile gate targets (`lint`, `security`, `docs-check`, `poam-drift-check`) must not use `|| true`."""
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


def test_stpa_compiler_emits_opa_fmt_compliant_rego() -> None:
    """generate_opa() output must match config/opa/generated_stpa_policy.rego with tabs and single blank lines."""
    files = sorted((REPO_ROOT / "config" / "stpa").rglob("*.yaml"))
    cs = load_control_structures(files)
    compiled = generate_opa(cs)
    on_disk = (REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego").read_text(
        encoding="utf-8"
    )
    assert content_digest(compiled) == content_digest(on_disk), (
        "generate_opa() output drifted from config/opa/generated_stpa_policy.rego"
    )
    # Canonical opa fmt uses tab indentation inside rule bodies and no double blank lines
    assert "\n\n\n" not in compiled, (
        "generate_opa() must not emit consecutive blank lines"
    )
    assert "\tinput.action ==" in compiled, (
        "generate_opa() must use tab indentation for opa fmt compliance"
    )
