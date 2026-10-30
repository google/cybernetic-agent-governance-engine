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

"""The partner over-the-wire harness, checked on every pull request.

The harness (``.github/workflows/ci-partner-integration.yml``) runs only on
dispatch and weekly, so nothing else would notice it drifting from the live
tests. It drifted for six weeks: #218 moved the live tests and the harness
kept calling the old paths, its secrets never reached its test step, two
partners were missing, and the flag it passed left every partner test skipped,
so an ``all`` run would have reported success without testing anything.

These tests pin the workflow to ``scripts/partner_harness.py`` and to the live
tests themselves, and check the two mechanisms that make a run able to fail:
the ``--run-partner-integration`` flag semantics and the ``require_live`` plugin.
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
import yaml

from scripts import partner_harness as harness
from tests.fixtures.selection_flags import live_external_enabled

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci-partner-integration.yml"
_PARTNER_MARK = "pytest.mark.partner_integration"
_NON_SECRET_ENV = {
    "PARTNER",
    "LANGSMITH_TRACING",
    "LANGCHAIN_TRACING_V2",
    "KMS_GOVERNANCE_KEY",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _workflow() -> dict[str, Any]:
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _on_block(doc: dict[str, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) parses a bare `on:` key as boolean True.
    return doc["on"] if "on" in doc else doc[True]


def _live_steps() -> dict[str, dict[str, Any]]:
    steps = _workflow()["jobs"]["live"]["steps"]
    return {step["name"]: step for step in steps}


def _partner_test_files() -> list[Path]:
    """Every test module that carries the partner_integration marker."""
    found = []
    for path in sorted((_REPO_ROOT / "tests").rglob("test_*.py")):
        if path.resolve() == Path(__file__).resolve():
            continue
        if _PARTNER_MARK in path.read_text(encoding="utf-8"):
            found.append(path)
    return found


def _files_under(target: str) -> list[Path]:
    root = _REPO_ROOT / target
    return [p for p in _partner_test_files() if p == root or root in p.parents]


def _gate(partner: str, key: str) -> str:
    return f"${{{{ matrix.partner == '{partner}' && secrets.{key} || '' }}}}"


# ── --run-partner-integration enables partner tests ───────────────────────────


@pytest.mark.parametrize(
    ("keywords", "live_external", "partner_integration", "enabled"),
    [
        ({"live_external", "partner_integration"}, False, True, True),
        ({"live_external"}, False, True, False),
        ({"live_external", "partner_integration"}, True, False, True),
        ({"live_external"}, True, False, True),
        ({"live_external", "partner_integration"}, False, False, False),
    ],
)
def test_live_external_flag_semantics(
    keywords: set[str], live_external: bool, partner_integration: bool, enabled: bool
) -> None:
    """The partner flag enables partner tests, and no other live_external test."""
    assert (
        live_external_enabled(
            keywords,
            run_live_external=live_external,
            run_partner_integration=partner_integration,
        )
        is enabled
    )


def test_every_partner_live_test_also_carries_live_external() -> None:
    """The case the flag rule exists for. If this stops holding, revisit it."""
    for path in _partner_test_files():
        assert "pytest.mark.live_external" in path.read_text(encoding="utf-8"), path


# ── require_live: a skip fails the run ────────────────────────────────────────


def _run_pytest(
    tmp_path: Path, body: str, *, plugin: bool = True
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "test_case.py").write_text(
        f"import pytest\n\n{body}\n", encoding="utf-8"
    )
    args = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "test_case.py",
    ]
    if plugin:
        args[3:3] = ["-p", "tests.fixtures.require_live"]
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        args,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


_PASS = "def test_ok():\n    pass\n"
_SKIP = "def test_skip():\n    pytest.skip('API key not configured')\n"


@pytest.mark.parametrize(
    ("name", "body", "returncode"),
    [
        ("all pass", _PASS, 0),
        ("skip in the test", _PASS + _SKIP, 1),
        ("skip at collection", "@pytest.mark.skip(reason='no flag')\n" + _PASS, 1),
        (
            "xfail",
            "@pytest.mark.xfail(reason='known')\ndef test_x():\n    assert False\n",
            1,
        ),
        ("failure", "def test_bad():\n    assert False\n", 1),
        ("nothing collected", "X = 1\n", 5),
    ],
)
def test_require_live_outcomes(
    tmp_path: Path, name: str, body: str, returncode: int
) -> None:
    result = _run_pytest(tmp_path, body)
    assert result.returncode == returncode, f"{name}:\n{result.stdout}\n{result.stderr}"


def test_require_live_names_what_did_not_run(tmp_path: Path) -> None:
    result = _run_pytest(tmp_path, _PASS + _SKIP)
    assert "NOT RUN test_case.py::test_skip: API key not configured" in result.stdout
    assert "1 passed, 1 not run" in result.stdout


def test_without_require_live_a_skip_passes(tmp_path: Path) -> None:
    """The control: plain pytest reports this run as a success."""
    assert _run_pytest(tmp_path, _SKIP, plugin=False).returncode == 0


# ── scripts/partner_harness.py ────────────────────────────────────────────────


def test_matrix_selection() -> None:
    assert harness.matrix("all") == list(harness.PARTNER_TARGETS)
    assert harness.matrix("") == list(harness.PARTNER_TARGETS)
    assert harness.matrix("provider_07") == ["provider_07"]
    with pytest.raises(ValueError, match="unknown partner"):
        harness.matrix("provider_04")


@pytest.mark.parametrize(
    ("argv", "returncode", "stdout"),
    [
        (["matrix", "all"], 0, json.dumps(list(harness.PARTNER_TARGETS)) + "\n"),
        (["matrix", "actuator_01"], 0, '["actuator_01"]\n'),
        (["target", "provider_08"], 0, "tests/integrations/provider_08\n"),
        (["target", "all"], 2, ""),
        (["matrix", '"]; echo'], 2, ""),
        (["matrix"], 2, ""),
    ],
)
def test_cli(
    argv: list[str], returncode: int, stdout: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert harness.main(argv) == returncode
    assert capsys.readouterr().out == stdout


def test_partner_tables_agree() -> None:
    assert set(harness.PARTNER_SECRETS) == set(harness.PARTNER_TARGETS)
    secrets = [name for names in harness.PARTNER_SECRETS.values() for name in names]
    assert len(secrets) == len(set(secrets)), "a secret is listed for two partners"
    assert not set(secrets) & set(harness.UNSUPPLIED)


# ── The workflow matches the harness module and the live tests ────────────────


def test_dispatch_choices_are_the_partner_list() -> None:
    inputs = _on_block(_workflow())["workflow_dispatch"]["inputs"]
    assert inputs["partner_filter"]["options"] == ["all", *harness.PARTNER_TARGETS]


def test_runs_weekly() -> None:
    assert _on_block(_workflow())["schedule"], (
        "a live check that runs only on request decays"
    )


def test_every_target_exists_and_selects_partner_tests() -> None:
    for partner, target in harness.PARTNER_TARGETS.items():
        assert (_REPO_ROOT / target).exists(), f"{partner}: {target} does not exist"
        assert _files_under(target), (
            f"{partner}: no partner_integration tests under {target}"
        )


def test_every_partner_live_test_belongs_to_a_partner() -> None:
    """A new partner's live tests cannot be left out of the harness."""
    covered = {
        p for target in harness.PARTNER_TARGETS.values() for p in _files_under(target)
    }
    missing = [
        str(p.relative_to(_REPO_ROOT))
        for p in _partner_test_files()
        if p not in covered
    ]
    assert not missing, (
        f"partner_integration tests outside every harness target: {missing}"
    )


def test_secrets_reach_only_their_own_partner() -> None:
    env = _live_steps()["Run live tests"]["env"]
    expected = {
        key: _gate(partner, key)
        for partner, keys in harness.PARTNER_SECRETS.items()
        for key in keys
    }
    assert {k: v for k, v in env.items() if k not in _NON_SECRET_ENV} == expected
    assert env["PARTNER"] == "${{ matrix.partner }}"


def test_actuator_01_files_are_staged_from_their_secrets() -> None:
    step = _live_steps()["Stage actuator_01 mTLS material"]
    assert step["if"] == "matrix.partner == 'actuator_01'"
    assert step["env"] == {k: f"${{{{ secrets.{k} }}}}" for k in harness.STAGED_FILES}
    for secret, path_var in harness.STAGED_FILES.items():
        assert re.search(rf"stage {secret} {path_var} \S+", step["run"]), secret


def test_actuator_01_wif_and_kms_signing() -> None:
    """actuator_01 authenticates via WIF and signs via Cloud KMS (no secret key PEM)."""
    live_job = _workflow()["jobs"]["live"]
    assert live_job["permissions"] == {"contents": "read", "id-token": "write"}

    wif_var = harness.ACTUATOR_01_GCP_AUTH["workload_identity_provider"]
    sa_var = harness.ACTUATOR_01_GCP_AUTH["service_account"]
    kms_var = harness.ACTUATOR_01_GCP_AUTH["kms_governance_key"]

    auth_step = _live_steps()["Authenticate to GCP for actuator_01 KMS signing"]
    assert auth_step["if"] == (
        f"matrix.partner == 'actuator_01' && vars.{wif_var} != ''"
    )
    assert auth_step["uses"].startswith("google-github-actions/auth@")
    assert re.search(r"@[0-9a-f]{40}$", auth_step["uses"])
    assert auth_step["with"] == {
        "workload_identity_provider": f"${{{{ vars.{wif_var} }}}}",
        "service_account": f"${{{{ vars.{sa_var} }}}}",
    }

    env = _live_steps()["Run live tests"]["env"]
    assert env["KMS_GOVERNANCE_KEY"] == (
        f"${{{{ matrix.partner == 'actuator_01' && vars.{kms_var} || '' }}}}"
    )


def test_no_other_step_sees_a_secret() -> None:
    allowed = {"Run live tests", "Stage actuator_01 mTLS material"}
    for job_name, job in _workflow()["jobs"].items():
        for step in job["steps"]:
            if step.get("name") in allowed and job_name == "live":
                continue
            assert "secrets." not in json.dumps(step), f"{job_name}/{step.get('name')}"


def test_live_tests_read_only_what_the_harness_supplies() -> None:
    """Every partner variable a live test reads is supplied, or listed as not supplied.

    actuator_01's test once read file paths while the workflow passed
    differently named PEM secrets, so it could only skip.
    """
    staged = set(harness.STAGED_FILES.values())
    for partner, target in harness.PARTNER_TARGETS.items():
        supplied = (
            set(harness.PARTNER_SECRETS[partner]) | staged | set(harness.UNSUPPLIED)
        )
        prefix = partner.upper() + "_"
        for path in _files_under(target):
            read = set(
                re.findall(rf'"({prefix}[A-Z0-9_]+)"', path.read_text(encoding="utf-8"))
            )
            unknown = sorted(read - supplied)
            assert not unknown, f"{path.relative_to(_REPO_ROOT)} reads {unknown}"


def test_the_run_can_fail() -> None:
    run = _live_steps()["Run live tests"]["run"]
    for required in (
        "scripts/partner_harness.py target",
        "-m partner_integration",
        "--run-partner-integration",
        "-p tests.fixtures.require_live",
    ):
        assert required in run, required
    select = _workflow()["jobs"]["select"]["steps"][-1]["run"]
    assert "scripts/partner_harness.py matrix" in select


def test_verdict_requires_every_partner_job() -> None:
    verdict = _workflow()["jobs"]["verdict"]
    assert verdict["needs"] == "live"
    assert verdict["if"] == "always()"
    (step,) = verdict["steps"]
    assert step["env"] == {"LIVE_RESULT": "${{ needs.live.result }}"}
    assert '"$LIVE_RESULT" != "success"' in step["run"]
