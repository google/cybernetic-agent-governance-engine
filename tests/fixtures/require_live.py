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

"""Pytest plugin: a live run passes only if every selected test ran and passed.

Load it with ``-p tests.fixtures.require_live``. Without it, pytest reports a
run in which every test skipped as a success, and a live test skips whenever it
cannot reach its partner: missing credentials, a missing flag, a moved file.
The partner harness (``.github/workflows/ci-partner-integration.yml``) loads it,
so a skip fails the job there. A skipped test verified nothing.

An expected failure (``xfail``) counts as not run, for the same reason. A run
that selects nothing needs no help: pytest already exits 5.
"""

from __future__ import annotations

import pytest


class RequireLive:
    """Counts passes and records every test that did not run."""

    def __init__(self) -> None:
        self.passed = 0
        self.not_run: list[tuple[str, str]] = []

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped:
            self.not_run.append((report.nodeid, _skip_reason(report)))
        elif report.when == "call" and report.passed:
            self.passed += 1

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        if exitstatus == pytest.ExitCode.OK and self.not_run:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter) -> None:  # noqa: ANN001
        terminalreporter.section("require-live")
        for nodeid, reason in self.not_run:
            terminalreporter.line(f"NOT RUN {nodeid}: {reason}")
        verdict = "FAILED: every selected test must run" if self.not_run else "ok"
        terminalreporter.line(
            f"{self.passed} passed, {len(self.not_run)} not run ({verdict})"
        )


def _skip_reason(report: pytest.TestReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2]).removeprefix("Skipped: ")
    if hasattr(report, "wasxfail"):
        return f"xfail: {report.wasxfail}"
    return str(longrepr)


def pytest_configure(config: pytest.Config) -> None:
    # Under xdist only the controller sees every report.
    if not hasattr(config, "workerinput"):
        config.pluginmanager.register(RequireLive(), "require-live")
