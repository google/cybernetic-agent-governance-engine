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

"""Contract tests for the hermetic ``gcloud`` subprocess guard (Issue #949).

Pins ``tests/fixtures/gcloud_guard.py`` and ``guard_hermetic_gcloud`` in
``tests/conftest.py``:

* Direct ``subprocess`` execution of ``gcloud`` in an unmarked hermetic test
  fails closed immediately with :class:`HermeticGcloudError`.
* Indirect execution via ``bash`` — even when the test creates a ``tmp_path``
  ``gcloud`` stub and prepends it to ``PATH`` without opting in — is blocked
  by the guard shim (allowance is explicit, never inferred from ``PATH``).
* Calling ``scripts.verify_audit_corroboration.trusted_deployers()`` without
  ``CAGE_CALLER_PRINCIPAL`` fails closed immediately rather than shelling out to
  host ``gcloud config get-value account``.
* Tests carrying ``@pytest.mark.allow_hermetic_gcloud`` execute their own
  stubbed ``gcloud`` cleanly, while direct calls targeting host ``gcloud``
  directories remain blocked.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import verify_audit_corroboration as live_corroborator
from tests.fixtures.gcloud_guard import (
    ALLOW_HERMETIC_GCLOUD_MARKER,
    HermeticGcloudError,
    guard_subprocess_env,
    is_gcloud_command,
    targets_host_gcloud_dir,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_is_gcloud_command_detects_direct_and_shell_invocations() -> None:
    assert is_gcloud_command(["gcloud", "config", "get-value", "account"]) is True
    assert is_gcloud_command(["/usr/bin/gcloud", "auth", "print-access-token"]) is True
    assert is_gcloud_command(["bash", "-c", "echo hi"]) is False
    assert (
        is_gcloud_command("echo ok && CLOUDSDK_CORE_PROJECT=p gcloud info", shell=True)
        is True
    )
    assert is_gcloud_command("echo gcloud", shell=True) is False


def test_targets_host_gcloud_dir_identifies_explicit_host_paths() -> None:
    assert (
        targets_host_gcloud_dir(["/usr/bin/gcloud", "info"], None, ("/usr/bin",))
        is True
    )
    assert targets_host_gcloud_dir(["gcloud", "info"], None, ("/usr/bin",)) is False
    assert (
        targets_host_gcloud_dir(["/tmp/stub/bin/gcloud", "info"], None, ("/usr/bin",))
        is False
    )


def test_guard_subprocess_env_positions_blocker_per_opt_in(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    stub = tmp_path / "stub"

    blocked_env = guard_subprocess_env(
        {"PATH": f"{stub}{os.pathsep}/usr/bin"},
        blocker_dir=blocker,
        opted_in=False,
        host_gcloud_dirs=("/usr/bin",),
    )
    assert blocked_env["PATH"].split(os.pathsep) == [
        str(blocker),
        str(stub),
        "/usr/bin",
    ]

    opted_env = guard_subprocess_env(
        {"PATH": f"{stub}{os.pathsep}/usr/bin"},
        blocker_dir=blocker,
        opted_in=True,
        host_gcloud_dirs=("/usr/bin",),
    )
    assert opted_env["PATH"].split(os.pathsep) == [
        str(stub),
        str(blocker),
        "/usr/bin",
    ]


def test_guard_blocks_direct_gcloud_invocation_by_default() -> None:
    with pytest.raises(HermeticGcloudError, match=ALLOW_HERMETIC_GCLOUD_MARKER):
        subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            check=False,
            timeout=5,
        )


def test_guard_blocks_trusted_deployers_fallback_without_caller_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CAGE_CALLER_PRINCIPAL", raising=False)
    monkeypatch.setattr(
        live_corroborator.shutil,
        "which",
        lambda cmd: "/usr/bin/gcloud" if cmd == "gcloud" else None,
    )
    with pytest.raises(HermeticGcloudError, match="CAGE_CALLER_PRINCIPAL"):
        live_corroborator.trusted_deployers("cage-staging-proj", "staging", ())


def test_probe_unopted_tmp_stub_blocked_when_enabled(tmp_path: Path) -> None:
    if os.environ.get("_CAGE_TEST_PROBE_UNOPTED_GCLOUD") != "1":
        return
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "gcloud"
    stub.write_text("#!/usr/bin/env sh\necho STUB_BYPASSED\nexit 0\n", encoding="utf-8")
    stub.chmod(stat.S_IRWXU)
    env = {
        **os.environ,
        "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        ["bash", "-c", "gcloud info || true"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "STUB_BYPASSED" not in proc.stdout


def test_guard_blocks_path_shadowing_tmp_stub_without_explicit_opt_in() -> None:
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    child_env["_CAGE_TEST_PROBE_UNOPTED_GCLOUD"] = "1"
    repo_root = Path(__file__).resolve().parents[2]
    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            f"{Path(__file__).resolve()}::test_probe_unopted_tmp_stub_blocked_when_enabled",
            "-q",
            "-n",
            "0",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
        ],
        cwd=str(repo_root),
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    combined = res.stdout + res.stderr
    assert res.returncode == pytest.ExitCode.TESTS_FAILED, combined
    assert "invoked blocked gcloud" in combined


@pytest.mark.allow_hermetic_gcloud
def test_explicit_opt_in_permits_test_local_gcloud_stub(tmp_path: Path) -> None:
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "gcloud"
    stub.write_text("#!/usr/bin/env sh\necho STUB_OK\nexit 0\n", encoding="utf-8")
    stub.chmod(stat.S_IRWXU)

    env = {
        **os.environ,
        "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    }
    proc = subprocess.run(
        ["bash", "-c", "gcloud info"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "STUB_OK"
