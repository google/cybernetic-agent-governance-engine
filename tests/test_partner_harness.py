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
tests themselves, check the ``--run-partner-integration`` flag semantics and the
``require_live`` plugin, and enforce Decision D2: the weekly Monday schedule runs
``PROVISIONED_PARTNERS`` failing closed while explicitly disclosing every
unprovisioned partner as ``NOT RUN`` with its blocker in both stdout and
``$GITHUB_STEP_SUMMARY``.
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
    "PROVIDER_01_GCP_ID_TOKEN",
}
_MINT_STEP = "Mint provider_01 Cloud Run ID token"
_UNPROVISIONED_EXPECTED = ("provider_02", "provider_03", "provider_07", "actuator_01")


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


def _assert_provisioned_disclosure_complete(text: str) -> None:
    """Contract validator for ``provisioned`` scope disclosure output."""
    assert "Partner Harness Scope: 3 of 7 partners selected (mode: provisioned)" in text
    assert "SELECTED (3 of 7): provider_01, provider_05, provider_08" in text
    assert (
        "NOT RUN (4 of 7): provider_02, provider_03, provider_07, actuator_01" in text
    )
    assert "7 of 7 partners selected" not in text
    for partner in harness.PROVISIONED_PARTNERS:
        assert f"| `{partner}` | SELECTED |" in text
    for partner, reason in harness.UNPROVISIONED_PARTNER_REASONS.items():
        assert f"| `{partner}` | NOT RUN |" in text
        assert reason in text


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
    assert harness.matrix("") == ["provider_01", "provider_05", "provider_08"]
    assert harness.matrix("provisioned") == [
        "provider_01",
        "provider_05",
        "provider_08",
    ]
    assert harness.matrix("") == harness.matrix("provisioned")
    assert harness.matrix("all") == list(harness.PARTNER_TARGETS)
    assert len(harness.matrix("all")) == 7
    assert harness.matrix("provider_07") == ["provider_07"]
    with pytest.raises(ValueError, match="unknown partner"):
        harness.matrix("provider_04")


def test_provisioned_and_unprovisioned_partition_partner_targets() -> None:
    """PROVISIONED_PARTNERS and UNPROVISIONED_PARTNER_REASONS must partition PARTNER_TARGETS."""
    assert harness.PROVISIONED_PARTNERS == ("provider_01", "provider_05", "provider_08")
    assert tuple(harness.UNPROVISIONED_PARTNER_REASONS) == _UNPROVISIONED_EXPECTED
    assert len(harness.PROVISIONED_PARTNERS) == len(set(harness.PROVISIONED_PARTNERS))
    assert set(harness.PROVISIONED_PARTNERS) | set(
        harness.UNPROVISIONED_PARTNER_REASONS
    ) == set(harness.PARTNER_TARGETS)
    assert (
        set(harness.PROVISIONED_PARTNERS) & set(harness.UNPROVISIONED_PARTNER_REASONS)
        == set()
    )
    for partner, reason in harness.UNPROVISIONED_PARTNER_REASONS.items():
        assert reason.strip(), f"empty unprovisioned reason for {partner}"
    harness.validate_partner_partition()


def test_partition_validation_rejects_planted_defects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding/removing/overlapping a partner without updating both sets must fail closed."""
    # Planted defect M1: new partner added to PARTNER_TARGETS without updating partition
    monkeypatch.setitem(
        harness.PARTNER_TARGETS, "provider_09", "tests/integrations/provider_09"
    )
    with pytest.raises(RuntimeError, match="must partition PARTNER_TARGETS"):
        harness.matrix("provisioned")
    monkeypatch.undo()

    # Planted defect M2: partner listed in both PROVISIONED_PARTNERS and UNPROVISIONED_PARTNER_REASONS
    monkeypatch.setattr(
        harness,
        "PROVISIONED_PARTNERS",
        ("provider_01", "provider_02", "provider_05", "provider_08"),
    )
    with pytest.raises(RuntimeError, match="both PROVISIONED_PARTNERS and"):
        harness.disclosure("provisioned")
    monkeypatch.undo()

    # Planted defect M3: unprovisioned partner dropped from UNPROVISIONED_PARTNER_REASONS
    shrunk_reasons = {
        k: v
        for k, v in harness.UNPROVISIONED_PARTNER_REASONS.items()
        if k != "actuator_01"
    }
    monkeypatch.setattr(harness, "UNPROVISIONED_PARTNER_REASONS", shrunk_reasons)
    with pytest.raises(RuntimeError, match="must partition PARTNER_TARGETS"):
        harness.disclosure("provisioned")
    monkeypatch.undo()

    # Planted defect M4: duplicate entry in PROVISIONED_PARTNERS
    monkeypatch.setattr(
        harness,
        "PROVISIONED_PARTNERS",
        ("provider_01", "provider_01", "provider_05", "provider_08"),
    )
    with pytest.raises(RuntimeError, match="duplicate entries"):
        harness.validate_partner_partition()
    monkeypatch.undo()

    # Planted defect M5: blank blocker reason for an unprovisioned partner
    monkeypatch.setitem(harness.UNPROVISIONED_PARTNER_REASONS, "provider_03", "   ")
    with pytest.raises(RuntimeError, match="blank reason"):
        harness.disclosure("provisioned")


def test_disclosure_provisioned_names_counts_and_every_unprovisioned_blocker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Provisioned/schedule disclosure explicitly reports 3 of 7 run and 4 of 7 NOT RUN."""
    rendered = harness.disclosure("provisioned")
    assert harness.disclosure("") == rendered
    _assert_provisioned_disclosure_complete(rendered)

    assert harness.main(["disclosure", "provisioned"]) == 0
    assert capsys.readouterr().out == rendered + "\n"

    all_rendered = harness.disclosure("all")
    assert "Partner Harness Scope: 7 of 7 partners selected (mode: all)" in all_rendered
    assert "NOT RUN (0 of 7): none" in all_rendered

    single_rendered = harness.disclosure("provider_01")
    assert (
        "Partner Harness Scope: 1 of 7 partners selected (mode: provider_01)"
        in single_rendered
    )
    assert (
        "NOT RUN (6 of 7): provider_02, provider_03, provider_05, "
        "provider_07, provider_08, actuator_01" in single_rendered
    )


@pytest.mark.parametrize("omitted_partner", _UNPROVISIONED_EXPECTED)
def test_disclosure_contract_fails_when_any_unprovisioned_partner_is_omitted(
    omitted_partner: str,
) -> None:
    """Mutating disclosure to drop any unprovisioned partner or its reason fails the check."""
    valid = harness.disclosure("provisioned")
    without_row = "\n".join(
        line
        for line in valid.splitlines()
        if not line.startswith(f"| `{omitted_partner}` |")
    )
    with pytest.raises(AssertionError):
        _assert_provisioned_disclosure_complete(without_row)

    reason = harness.UNPROVISIONED_PARTNER_REASONS[omitted_partner]
    without_reason = valid.replace(reason, "omitted")
    with pytest.raises(AssertionError):
        _assert_provisioned_disclosure_complete(without_reason)


@pytest.mark.parametrize(
    ("argv", "returncode", "stdout"),
    [
        (["matrix", "all"], 0, json.dumps(list(harness.PARTNER_TARGETS)) + "\n"),
        (
            ["matrix", "provisioned"],
            0,
            json.dumps(list(harness.PROVISIONED_PARTNERS)) + "\n",
        ),
        (["matrix", ""], 0, json.dumps(list(harness.PROVISIONED_PARTNERS)) + "\n"),
        (["matrix", "actuator_01"], 0, '["actuator_01"]\n'),
        (["target", "provider_08"], 0, "tests/integrations/provider_08\n"),
        (["target", "all"], 2, ""),
        (["target", "provisioned"], 2, ""),
        (
            ["verdict", "provisioned"],
            0,
            "PASSED: 3 of 7 partners verified over the wire; 4 of 7 NOT RUN (unprovisioned)\n",
        ),
        (
            ["verdict", ""],
            0,
            "PASSED: 3 of 7 partners verified over the wire; 4 of 7 NOT RUN (unprovisioned)\n",
        ),
        (
            ["verdict", "all"],
            0,
            "PASSED: 7 of 7 partners verified over the wire; 0 of 7 NOT RUN\n",
        ),
        (
            ["verdict", "provider_01"],
            0,
            "PASSED: 1 of 7 partners (provider_01) verified over the wire; "
            "6 of 7 NOT RUN (excluded from selection)\n",
        ),
        (["disclosure", "provider_04"], 2, ""),
        (["verdict", "provider_04"], 2, ""),
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
    assert not set(secrets) & set(harness.MINTED)
    assert not set(harness.MINTED) & set(harness.UNSUPPLIED)


# ── The workflow matches the harness module and the live tests ────────────────


def test_dispatch_choices_are_the_partner_list() -> None:
    inputs = _on_block(_workflow())["workflow_dispatch"]["inputs"]
    assert inputs["partner_filter"]["default"] == "provisioned"
    assert inputs["partner_filter"]["options"] == [
        "provisioned",
        "all",
        *harness.PARTNER_TARGETS,
    ]


def test_runs_weekly() -> None:
    assert _on_block(_workflow())["schedule"], (
        "a live check that runs only on request decays"
    )


def test_each_partner_selection_has_its_own_concurrency_group() -> None:
    """A newer run supersedes a pending one in its group, whatever cancel-in-progress
    says, so a shared group let one partner's dispatch cancel another's queued run."""
    concurrency = _workflow()["concurrency"]
    assert concurrency["cancel-in-progress"] is False, "never cancel a running check"
    group = concurrency["group"]
    assert (
        "inputs.partner_filter || 'provisioned'" in group and "github.ref" in group
    ), group


def test_no_run_step_interpolates_github_inputs_directly() -> None:
    """zizmor template-injection hygiene: pass inputs via step env:, never inside run:."""
    for job_name, job in _workflow()["jobs"].items():
        for step in job["steps"]:
            run_script = step.get("run", "")
            assert "inputs." not in run_script, (
                f"{job_name}/{step.get('name')} interpolates inputs.* in run:"
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


def test_provider_01_id_token_is_minted_not_stored() -> None:
    """FlowSignal's Cloud Run ID token is minted per run via WIF, never stored.

    The token's audience is the endpoint the tests call, so the mint step reads
    that one secret and nothing else. It writes no credentials file and exports
    no environment: the job's only GCP credential is the ID token itself.
    """
    auth = harness.PROVIDER_01_GCP_AUTH
    assert set(auth) == {"workload_identity_provider", "delegates", "service_account"}
    assert "PROVIDER_01_ENDPOINT" in harness.PARTNER_SECRETS["provider_01"]

    step = _live_steps()[_MINT_STEP]
    assert step["id"] == "provider_01_id_token"
    assert step["if"] == (
        f"matrix.partner == 'provider_01' && vars.{auth['workload_identity_provider']} != ''"
    )
    assert step["uses"].startswith("google-github-actions/auth@")
    assert re.search(r"@[0-9a-f]{40}$", step["uses"])
    assert step["with"] == {
        **{key: f"${{{{ vars.{var} }}}}" for key, var in auth.items()},
        "token_format": "id_token",
        "id_token_audience": "${{ secrets.PROVIDER_01_ENDPOINT }}",
        "id_token_include_email": True,
        "create_credentials_file": False,
        "export_environment_variables": False,
    }

    env = _live_steps()["Run live tests"]["env"]
    assert set(harness.MINTED) == {"PROVIDER_01_GCP_ID_TOKEN"}
    assert env["PROVIDER_01_GCP_ID_TOKEN"] == (
        "${{ steps.provider_01_id_token.outputs.id_token }}"
    )


def test_no_other_step_sees_a_secret() -> None:
    allowed = {"Run live tests", "Stage actuator_01 mTLS material", _MINT_STEP}
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
    finding_code_suffixes = ("_ALLOW", "_REFUSE", "_UNSUITABLE", "_ESCALATE")
    staged = set(harness.STAGED_FILES.values())
    for partner, target in harness.PARTNER_TARGETS.items():
        supplied = (
            set(harness.PARTNER_SECRETS[partner])
            | staged
            | set(harness.MINTED)
            | set(harness.UNSUPPLIED)
        )
        prefix = partner.upper() + "_"
        for path in _files_under(target):
            read = {
                token
                for token in re.findall(
                    rf'"({prefix}[A-Z0-9_]+)"', path.read_text(encoding="utf-8")
                )
                if not token.endswith(finding_code_suffixes)
            }
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
    select_step = _workflow()["jobs"]["select"]["steps"][-1]
    assert select_step["env"] == {"SELECTION": "${{ inputs.partner_filter }}"}
    select = select_step["run"]
    assert 'scripts/partner_harness.py matrix "${SELECTION:-provisioned}"' in select
    assert 'scripts/partner_harness.py disclosure "${SELECTION:-provisioned}"' in select
    assert '>> "$GITHUB_STEP_SUMMARY"' in select


def test_verdict_requires_every_partner_job() -> None:
    verdict = _workflow()["jobs"]["verdict"]
    assert verdict["needs"] == "live"
    assert verdict["if"] == "always()"
    checkout_step, gate_step = verdict["steps"]
    assert checkout_step["uses"].startswith("actions/checkout@")
    assert re.search(r"@[0-9a-f]{40}$", checkout_step["uses"])
    assert checkout_step["with"] == {"persist-credentials": False}
    assert gate_step["env"] == {
        "LIVE_RESULT": "${{ needs.live.result }}",
        "SELECTION": "${{ inputs.partner_filter }}",
    }
    assert (
        'scripts/partner_harness.py disclosure "${SELECTION:-provisioned}"'
        in gate_step["run"]
    )
    assert (
        'scripts/partner_harness.py verdict "${SELECTION:-provisioned}"'
        in gate_step["run"]
    )
    assert '>> "$GITHUB_STEP_SUMMARY"' in gate_step["run"]
    assert '"$LIVE_RESULT" != "success"' in gate_step["run"]
    assert "exit 1" in gate_step["run"]


def test_select_and_verdict_shell_scripts_execute_end_to_end(tmp_path: Path) -> None:
    """Execute the actual workflow shell scripts for schedule pass and fail-closed verdict."""
    doc = _workflow()
    select_script = doc["jobs"]["select"]["steps"][-1]["run"]
    verdict_script = doc["jobs"]["verdict"]["steps"][-1]["run"]

    gh_output = tmp_path / "github_output.txt"
    select_summary = tmp_path / "select_summary.md"
    select_proc = subprocess.run(  # noqa: S603 - fixed bash -eo pipefail invocation
        ["bash", "-eo", "pipefail", "-c", select_script],
        cwd=_REPO_ROOT,
        env={
            **os.environ,
            "SELECTION": "",
            "GITHUB_OUTPUT": str(gh_output),
            "GITHUB_STEP_SUMMARY": str(select_summary),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert select_proc.returncode == 0, select_proc.stderr
    assert (
        gh_output.read_text(encoding="utf-8").strip()
        == 'partners=["provider_01", "provider_05", "provider_08"]'
    )
    _assert_provisioned_disclosure_complete(select_proc.stdout)
    _assert_provisioned_disclosure_complete(select_summary.read_text(encoding="utf-8"))

    # Verdict when all 3 provisioned partners succeed: passes and prints explicit 3 of 7 / 4 of 7
    pass_summary = tmp_path / "verdict_pass_summary.md"
    pass_proc = subprocess.run(  # noqa: S603 - fixed bash -eo pipefail invocation
        ["bash", "-eo", "pipefail", "-c", verdict_script],
        cwd=_REPO_ROOT,
        env={
            **os.environ,
            "SELECTION": "",
            "LIVE_RESULT": "success",
            "GITHUB_STEP_SUMMARY": str(pass_summary),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert pass_proc.returncode == 0, pass_proc.stderr
    expected_pass = (
        "PASSED: 3 of 7 partners verified over the wire; 4 of 7 NOT RUN (unprovisioned)"
    )
    assert expected_pass in pass_proc.stdout
    _assert_provisioned_disclosure_complete(pass_proc.stdout)
    pass_summary_text = pass_summary.read_text(encoding="utf-8")
    _assert_provisioned_disclosure_complete(pass_summary_text)
    assert expected_pass in pass_summary_text

    # Verdict when any selected partner fails or skips: still writes disclosure, exits 1
    fail_summary = tmp_path / "verdict_fail_summary.md"
    fail_proc = subprocess.run(  # noqa: S603 - fixed bash -eo pipefail invocation
        ["bash", "-eo", "pipefail", "-c", verdict_script],
        cwd=_REPO_ROOT,
        env={
            **os.environ,
            "SELECTION": "",
            "LIVE_RESULT": "failure",
            "GITHUB_STEP_SUMMARY": str(fail_summary),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert fail_proc.returncode == 1
    assert (
        "At least one partner job did not pass (result: failure)." in fail_proc.stderr
    )
    _assert_provisioned_disclosure_complete(fail_proc.stdout)
    _assert_provisioned_disclosure_complete(fail_summary.read_text(encoding="utf-8"))
    assert expected_pass not in fail_proc.stdout
