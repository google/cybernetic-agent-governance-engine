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

"""No ``.env`` file may reach a hermetic test session.

The rule, its reasons and the live-run exemption are in
``tests/fixtures/dotenv_guard.py``. These tests pin the search, the refusal,
its wiring into ``tests/conftest.py``, and the two places that could undo it:
a conftest that loads ``.env`` again, and a CI job that runs pytest after it
creates one.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
import yaml

from tests.fixtures.dotenv_guard import (
    LIVE_RUN_OPTIONS,
    reachable_dotenv_files,
    refusal,
    search_starts,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]
_LOADS_DOTENV = re.compile(
    r"\b(load_dotenv|dotenv_values|find_dotenv)\b"
    r"|^\s*(from|import)\s+dotenv\b"
    r"|[\"']\.env[\"']",
    re.MULTILINE,
)


def _under(found: list[Path], root: Path) -> list[Path]:
    # Directories above tmp_path are outside the test's control.
    return [path for path in found if root in path.parents]


def test_finds_a_dotenv_file_in_a_parent_directory(tmp_path: Path) -> None:
    start = tmp_path / "a" / "b" / "c"
    start.mkdir(parents=True)
    (tmp_path / "a" / ".env").write_text("X=1\n", encoding="utf-8")

    assert _under(reachable_dotenv_files([start]), tmp_path) == [
        tmp_path / "a" / ".env"
    ]


def test_reports_each_file_once_and_ignores_directories(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    (tmp_path / "one" / ".env").mkdir(parents=True)
    (tmp_path / "two").mkdir()

    found = reachable_dotenv_files([tmp_path / "one", tmp_path / "two"])

    assert _under(found, tmp_path) == [tmp_path / ".env"]


def test_searches_from_tests_the_working_directory_and_installed_packages() -> None:
    starts = search_starts()

    # From tests/fixtures the search passes the repository root, and from
    # site-packages it follows litellm's own load_dotenv() call.
    assert _REPO in starts[0].parents
    assert Path.cwd() in starts
    assert Path(sysconfig.get_paths()["purelib"]).resolve() in starts


def test_a_hermetic_session_is_refused_and_told_which_file(tmp_path: Path) -> None:
    reason = refusal([tmp_path / ".env"], live_run=False)

    assert reason is not None
    assert str(tmp_path / ".env") in reason


def test_a_live_run_is_exempt(tmp_path: Path) -> None:
    assert refusal([tmp_path / ".env"], live_run=True) is None


def test_nothing_to_refuse_without_a_file() -> None:
    assert refusal([], live_run=False) is None


def test_live_run_options_are_registered_options() -> None:
    conftest = (_REPO / "tests" / "conftest.py").read_text(encoding="utf-8")
    for option in LIVE_RUN_OPTIONS:
        assert f'"{option}"' in conftest, option


def _collect_only(cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(Path(__file__).resolve()),
            "--collect-only",
            "-q",
            "-n",
            "0",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_conftest_refuses_a_session_a_dotenv_file_can_reach(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("CAGE_SEAL_STRICT_MODE=false\n", encoding="utf-8")

    result = _collect_only(tmp_path)

    assert result.returncode == pytest.ExitCode.USAGE_ERROR, (
        result.stdout + result.stderr
    )
    assert "Refusing to start a hermetic test session" in result.stderr
    assert str(tmp_path / ".env") in result.stderr


def test_conftest_starts_a_session_no_dotenv_file_can_reach(tmp_path: Path) -> None:
    result = _collect_only(tmp_path)

    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


def test_no_conftest_loads_a_dotenv_file() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "*conftest.py"],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert tracked, "git ls-files found no conftest.py"
    offenders = [
        path
        for path in tracked
        if _LOADS_DOTENV.search((_REPO / path).read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_the_quickstart_job_runs_pytest_before_it_creates_dotenv() -> None:
    workflow = yaml.safe_load(
        (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    runs = [
        step.get("run", "") for step in workflow["jobs"]["quickstart-smoke"]["steps"]
    ]
    creates = next(i for i, run in enumerate(runs) if "cp .env.example .env" in run)
    pytest_steps = [i for i, run in enumerate(runs) if "pytest" in run]

    assert pytest_steps, "quickstart-smoke no longer runs pytest"
    assert all(i < creates for i in pytest_steps), (pytest_steps, creates)
