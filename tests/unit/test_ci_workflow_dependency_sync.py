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

"""CI workflow dependency-sync & non-vacuous SBOM regression suite (POAM-2026-221).

Prevents recurrence of vacuous GitHub Actions gates caused by running repository
Python gates or Python SBOM generators inside unsynced runner environments that
only `pip install` a hand-listed subset of packages.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.generate_sbom import (
    expected_uv_lock_component_floor,
    generate_python_sbom,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
SCRIPT_CALL_RE = re.compile(r"\bscripts/([A-Za-z0-9_]+\.py)\b")

# Pure-stdlib scripts explicitly allowed to run before/without `uv sync`
# (mechanically verified below to import zero third-party packages).
STDLIB_ONLY_WORKFLOW_SCRIPTS = frozenset(
    {
        "check_advisory_traces.py",
        "check_client_sdk_sync.py",
        "check_conformance_sync.py",
        "check_locked_yanks.py",
        "check_repo_rules.py",
        "partner_harness.py",
        # Runs in jobs that can mint a signing identity, which therefore
        # install nothing (POAM-2026-115).
        "review_bypass_attestation.py",
    }
)


def _job_has_uv_sync(job: dict[str, object]) -> bool:
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        run_cmd = str(step.get("run", ""))
        if "uv sync" in run_cmd:
            return True
    return False


def test_stdlib_allowlisted_workflow_scripts_import_only_stdlib() -> None:
    """Every script in STDLIB_ONLY_WORKFLOW_SCRIPTS must have zero third-party imports."""
    stdlib_names = sys.stdlib_module_names
    for script_name in sorted(STDLIB_ONLY_WORKFLOW_SCRIPTS):
        path = REPO_ROOT / "scripts" / script_name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in stdlib_names, (
                        f"{script_name} imports non-stdlib module {top!r}; "
                        "either keep it stdlib-only or require `uv sync` in its workflow job"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                top = node.module.split(".")[0]
                assert top in stdlib_names, (
                    f"{script_name} imports non-stdlib module {top!r}; "
                    "either keep it stdlib-only or require `uv sync` in its workflow job"
                )


def test_every_workflow_job_running_repo_scripts_syncs_uv_environment() -> None:
    """Any GitHub Actions job invoking `scripts/*.py` (except verified stdlib-only scripts) must run `uv sync`."""
    violations: list[str] = []
    for wf_path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            invoked_scripts: set[str] = set()
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("run"), str):
                    invoked_scripts.update(SCRIPT_CALL_RE.findall(step["run"]))
            non_stdlib_scripts = invoked_scripts - STDLIB_ONLY_WORKFLOW_SCRIPTS
            if non_stdlib_scripts and not _job_has_uv_sync(job):
                violations.append(
                    f"{wf_path.name}::{job_id} invokes {sorted(non_stdlib_scripts)} without `uv sync`"
                )

    assert not violations, (
        "GitHub Actions jobs invoking repository Python scripts without `uv sync`:\n  "
        + "\n  ".join(violations)
    )


def test_stpa_freshness_workflow_enforces_red_before_green_canary() -> None:
    """`ci.yml::stpa-freshness-check` must sync uv and verify planted STPA + OSCAL drift fails before checking clean HEAD."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    stpa_job = ci_yaml["jobs"]["stpa-freshness-check"]
    assert _job_has_uv_sync(stpa_job), "ci.yml::stpa-freshness-check must run `uv sync`"
    runs = "\n".join(
        str(s.get("run", "")) for s in stpa_job["steps"] if isinstance(s, dict)
    )
    assert "generated_stpa_rails.co" in runs
    assert "system-security-plan.yaml" in runs


def test_python_sbom_workflow_jobs_sync_uv_and_assert_uv_lock_floor() -> None:
    """Both `ci.yml::sbom-generate` and `security-scan.yml::sbom-generation` must sync locked deps and enforce uv.lock floor."""
    ci_yaml = yaml.safe_load((WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8"))
    sbom_job = ci_yaml["jobs"]["sbom-generate"]
    assert _job_has_uv_sync(sbom_job), "ci.yml::sbom-generate must run `uv sync`"
    ci_runs = "\n".join(
        str(s.get("run", "")) for s in sbom_job["steps"] if isinstance(s, dict)
    )
    assert "expected_uv_lock_component_floor" in ci_runs, (
        "ci.yml::sbom-generate must assert component count against expected_uv_lock_component_floor()"
    )
    assert "len(comps) >= floor" in ci_runs

    sec_yaml = yaml.safe_load(
        (WORKFLOWS_DIR / "security-scan.yml").read_text(encoding="utf-8")
    )
    sec_sbom_job = sec_yaml["jobs"]["sbom-generation"]
    assert _job_has_uv_sync(sec_sbom_job), (
        "security-scan.yml::sbom-generation must run `uv sync`"
    )


def test_generate_python_sbom_rejects_empty_and_partial_environments(
    tmp_path: Path,
) -> None:
    """`generate_python_sbom` fails closed on both empty (1-pkg) and partial/half-rendered (150-pkg) SBOMs against `uv.lock`."""
    floor = expected_uv_lock_component_floor()
    assert floor >= 250, f"Expected uv.lock floor >= 250, got {floor}"

    for bad_count in (1, 150, floor - 1):
        partial_cdx = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"name": f"pkg-{idx}", "version": "1.0.0"}
                    for idx in range(bad_count)
                ],
            }
        )
        bad_proc = subprocess.CompletedProcess(
            args=["python", "-m", "cyclonedx_py", "environment"],
            returncode=0,
            stdout=partial_cdx,
            stderr="",
        )
        with (
            patch("scripts.generate_sbom.subprocess.run", return_value=bad_proc),
            pytest.raises(
                RuntimeError, match="Vacuous or partial Python SBOM rejected"
            ),
        ):
            generate_python_sbom(tmp_path, dry_run=True)

    populated_cdx = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"name": f"pkg-{idx}", "version": "1.0.0"} for idx in range(floor)
            ],
        }
    )
    populated_proc = subprocess.CompletedProcess(
        args=["python", "-m", "cyclonedx_py", "environment"],
        returncode=0,
        stdout=populated_cdx,
        stderr="",
    )
    with patch("scripts.generate_sbom.subprocess.run", return_value=populated_proc):
        sbom = generate_python_sbom(tmp_path, dry_run=True)
    assert len(sbom["components"]) == floor


def test_generate_summary_report_supports_cyclonedx_16_tools_object(
    tmp_path: Path,
) -> None:
    """`generate_summary_report` handles CycloneDX 1.6 `metadata.tools = {'components': [...]}` without `KeyError: 0`."""
    from scripts.generate_sbom import generate_summary_report

    cdx_16 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {"name": "cybernetic-agent-governance-engine"},
            "tools": {
                "components": [
                    {"type": "application", "name": "cyclonedx-py", "version": "7.2.1"}
                ]
            },
            "timestamp": "2026-11-15T23:27:41Z",
        },
        "components": [{"name": "fastapi", "version": "0.115.0", "type": "library"}],
    }
    summary = generate_summary_report(
        sbom=cdx_16,
        vulnerabilities=[],
        license_violations=[],
        output_dir=tmp_path,
        sbom_filename="python-deps-2026-11-15.cdx.json",
        dry_run=False,
    )
    rendered = summary.read_text(encoding="utf-8")
    assert "| **Tool** | cyclonedx-py |" in rendered
    assert "| **Format** | CycloneDX 1.6 |" in rendered


# Regression coverage binding: POAM-2026-221
