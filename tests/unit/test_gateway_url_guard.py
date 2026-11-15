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

"""Contract tests for the hermetic ``GATEWAY_URL`` guard.

Pins ``tests/fixtures/gateway_url_guard.py`` and its wiring in
``tests/conftest.py``:

* ``GATEWAY_URL`` is unset across unmarked and region-marked (``us_fed``,
  ``eu_ecb``, ``apac_mas``, ``each_region``) hermetic tests.
* Starting a hermetic pytest session with ``GATEWAY_URL`` exported fails closed
  with ``pytest.ExitCode.USAGE_ERROR``.
* Live-flagged sessions remain exempt.
* A hermetic test that mutates ``os.environ["GATEWAY_URL"]`` without
  ``monkeypatch`` fails closed at teardown and is cleaned up before the next
  test runs.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fixtures.dotenv_guard import LIVE_RUN_OPTIONS
from tests.fixtures.gateway_url_guard import (
    GATEWAY_URL_ENV_VAR,
    is_live_session,
    refusal,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _fake_config(*enabled_options: str) -> SimpleNamespace:
    enabled = set(enabled_options)
    return SimpleNamespace(
        getoption=lambda opt, default=False: True if opt in enabled else default
    )


def test_is_live_session_matches_every_live_run_option() -> None:
    assert is_live_session(_fake_config()) is False  # type: ignore[arg-type]
    assert is_live_session(_fake_config("--run-chaos")) is False  # type: ignore[arg-type]
    for opt in LIVE_RUN_OPTIONS:
        assert is_live_session(_fake_config(opt)) is True, opt  # type: ignore[arg-type]


def test_refusal_allows_unset_gateway_url_in_hermetic_session() -> None:
    assert refusal(None, live_run=False) is None


@pytest.mark.parametrize(
    "exported", ["http://localhost:8080", "https://gw.example", ""]
)
def test_refusal_rejects_set_gateway_url_in_hermetic_session(exported: str) -> None:
    reason = refusal(exported, live_run=False)
    assert reason is not None
    assert f"GATEWAY_URL={exported!r}" in reason
    assert "env -u GATEWAY_URL" in reason


def test_refusal_exempts_live_session() -> None:
    assert refusal("http://localhost:8080", live_run=True) is None


def test_unmarked_hermetic_test_has_gateway_url_unset() -> None:
    assert GATEWAY_URL_ENV_VAR not in os.environ


@pytest.mark.us_fed
def test_us_fed_hermetic_test_has_gateway_url_unset() -> None:
    assert GATEWAY_URL_ENV_VAR not in os.environ


@pytest.mark.eu_ecb
def test_eu_ecb_hermetic_test_has_gateway_url_unset() -> None:
    assert GATEWAY_URL_ENV_VAR not in os.environ


@pytest.mark.apac_mas
def test_apac_mas_hermetic_test_has_gateway_url_unset() -> None:
    assert GATEWAY_URL_ENV_VAR not in os.environ


def test_each_region_hermetic_test_has_gateway_url_unset(each_region: str) -> None:
    assert each_region in {"US_FED", "EU_ECB", "APAC_MAS"}
    assert GATEWAY_URL_ENV_VAR not in os.environ


def test_monkeypatch_setenv_gateway_url_cleans_up_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(GATEWAY_URL_ENV_VAR, "http://example.test:8080")
    assert os.environ[GATEWAY_URL_ENV_VAR] == "http://example.test:8080"


def _run_subsession(
    args: list[str], *, cwd: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PYTEST_") and k != GATEWAY_URL_ENV_VAR
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *args,
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


def test_conftest_refuses_hermetic_session_when_gateway_url_exported(
    tmp_path: Path,
) -> None:
    result = _run_subsession(
        [str(Path(__file__).resolve()), "--collect-only"],
        cwd=tmp_path,
        extra_env={GATEWAY_URL_ENV_VAR: "http://localhost:8080"},
    )
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, (
        result.stdout + result.stderr
    )
    assert "Refusing to start a hermetic test session" in result.stderr
    assert "GATEWAY_URL='http://localhost:8080'" in result.stderr


def test_conftest_starts_hermetic_session_when_gateway_url_unset(
    tmp_path: Path,
) -> None:
    result = _run_subsession(
        [str(Path(__file__).resolve()), "--collect-only"],
        cwd=tmp_path,
    )
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


def test_probe_leaks_gateway_url_when_enabled() -> None:
    if os.environ.get("_CAGE_TEST_PROBE_LEAK_GATEWAY_URL") == "1":
        os.environ[GATEWAY_URL_ENV_VAR] = "http://leaked.invalid:8080"


def test_probe_followup_sees_gateway_url_unset() -> None:
    assert GATEWAY_URL_ENV_VAR not in os.environ


def test_conftest_fails_test_that_leaks_gateway_url_and_isolates_next_test(
    tmp_path: Path,
) -> None:
    this_file = str(Path(__file__).resolve())
    result = _run_subsession(
        [
            f"{this_file}::test_probe_leaks_gateway_url_when_enabled",
            f"{this_file}::test_probe_followup_sees_gateway_url_unset",
        ],
        cwd=tmp_path,
        extra_env={"_CAGE_TEST_PROBE_LEAK_GATEWAY_URL": "1"},
    )
    combined = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, combined
    assert "leaked GATEWAY_URL='http://leaked.invalid:8080' into os.environ" in combined
    assert "2 passed" in combined
    assert "1 error" in combined
