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

"""Static and hermetic guards for the GKE load test (one gateway replica, no HPA).

The gateway keeps pod-local state, so ``scripts/run_gke_load_test.sh`` must
never autoscale it. The script refuses production contexts, removes leftover
HPAs, refuses to run while another autoscaler targets the gateway, pins one
replica, fails if the deployment changed during the run, and restores the
original count on every exit. The hermetic tests run the real script against
stub ``kubectl``, ``locust`` and ``sleep`` executables that record each call.
"""

from __future__ import annotations

import os
import re
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "run_gke_load_test.sh"
CONTEXT = "gke_test-project_us-central1-a_cage-dev"
PINNED = f"--context {CONTEXT} -n governance-stack "

_KUBECTL_STUB = """#!/usr/bin/env bash
echo "$*" >> "${STUB_LOG}"
case "$*" in
  "config current-context")
    if [[ -z "${STUB_CONTEXT}" ]]; then exit 1; fi
    echo "${STUB_CONTEXT}" ;;
  *" get hpa "*)
    printf '%b' "${STUB_HPA_TARGETS:-}" ;;
  *" get deployment/gateway "*)
    reads_file="${STUB_LOG}.reads"
    reads=$(( $(cat "${reads_file}" 2>/dev/null || echo 0) + 1 ))
    echo "${reads}" > "${reads_file}"
    IFS='|' read -r -a answers <<< "${STUB_DEPLOYMENT_READS}"
    printf '%s' "${answers[$((reads - 1))]:-}" ;;
  *" rollout status "*)
    exit "${STUB_ROLLOUT_RC:-0}" ;;
  *" scale "*"--replicas=${STUB_FAIL_SCALE_TO:-none}")
    exit 1 ;;
esac
exit 0
"""

_LOCUST_STUB = """#!/usr/bin/env bash
prefix=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--csv" ]]; then prefix="$2"; shift; fi
  shift
done
if [[ -n "${STUB_LOCUST_AVG_MS:-}" && -n "${prefix}" ]]; then
  {
    echo "Type,Name,Request Count,Failure Count,Median Response Time,Average Response Time,Min Response Time,Max Response Time,Average Content Size,Requests/s,Failures/s,50%,66%,75%,80%,90%,95%,98%,99%,99.9%,99.99%,100%"
    echo "GET,/health,100,0,10,${STUB_LOCUST_AVG_MS},5,40,20,50.0,0.0,10,11,12,13,15,18,20,25,30,35,40"
  } > "${prefix}_stats.csv"
fi
exit 0
"""

_SLEEP_STUB = """#!/usr/bin/env bash
if [[ -n "${STUB_REAL_SLEEP:-}" ]]; then exec /bin/sleep "${STUB_REAL_SLEEP}"; fi
exit 0
"""


def _executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _environment(tmp_path: Path, **stub: str) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _executable(bin_dir / "kubectl", _KUBECTL_STUB)
    _executable(bin_dir / "locust", _LOCUST_STUB)
    _executable(bin_dir / "sleep", _SLEEP_STUB)
    log = tmp_path / "kubectl.log"
    log.touch()
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("LOAD_TEST_", "STUB_"))
    }
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "TMPDIR": str(tmp_path),
            "NAMESPACE": "governance-stack",
            "STUB_LOG": str(log),
            "STUB_CONTEXT": CONTEXT,
            "STUB_DEPLOYMENT_READS": "2|1/7|1/7",
            "STUB_LOCUST_AVG_MS": "12.5",
        }
    )
    env.update(stub)
    return env, log


def _calls(log: Path) -> list[str]:
    """kubectl calls with the pinned ``--context``/``-n`` prefix stripped.

    Fails if any call after the context lookup is not pinned to it.
    """
    calls = log.read_text(encoding="utf-8").splitlines()
    unpinned = [
        call
        for call in calls
        if call != "config current-context" and not call.startswith(PINNED)
    ]
    assert unpinned == [], f"kubectl calls not pinned to {CONTEXT}: {unpinned}"
    return [call.removeprefix(PINNED) for call in calls]


def _run(
    tmp_path: Path, **stub: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the load test against stubs; return the result and kubectl calls."""
    env, log = _environment(tmp_path, **stub)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return result, _calls(log)


def _scales(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("scale ")]


_PIN = "scale deployment/gateway --replicas=1"
_RESTORE = "scale deployment/gateway --replicas=2"


def test_script_never_applies_manifests_and_the_hpa_manifest_is_gone() -> None:
    code_lines = [
        line.strip()
        for line in SCRIPT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert not any(re.search(r"\bapply\b", line) for line in code_lines)
    assert any(
        "delete hpa gateway-hpa" in line and "--ignore-not-found" in line
        for line in code_lines
    )
    assert not (REPO_ROOT / "deployment" / "k8s" / "gateway-hpa.yaml").exists()


def test_refuses_a_production_context_before_touching_the_cluster(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path, STUB_CONTEXT="gke_test-project_us-central1_cage-prod"
    )

    assert result.returncode == 1
    assert "looks like production" in result.stderr
    assert calls == ["config current-context"]


def test_refuses_when_the_context_cannot_be_read(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, STUB_CONTEXT="")

    assert result.returncode == 1
    assert "Unable to determine the current kubectl context" in result.stderr
    assert calls == ["config current-context"]


def test_refuses_while_another_autoscaler_targets_the_gateway(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, STUB_HPA_TARGETS="Deployment   gateway\n")

    assert result.returncode == 1
    assert "autoscaler still targets deployment/gateway" in result.stderr
    assert "delete hpa gateway-hpa --ignore-not-found" in calls
    assert _scales(calls) == []


def test_refuses_an_unreadable_replica_count(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, STUB_DEPLOYMENT_READS="not-a-number")

    assert result.returncode == 1
    assert "Could not read the gateway replica count" in result.stderr
    assert _scales(calls) == []


def test_pins_one_replica_measures_and_restores_the_original_count(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "PASS: Average latency is within limits" in result.stdout
    assert _scales(calls) == [_PIN, _RESTORE]
    delete = calls.index("delete hpa gateway-hpa --ignore-not-found")
    rollout = calls.index("rollout status deployment/gateway --timeout=300s")
    assert delete < calls.index(_PIN) < rollout


@pytest.mark.parametrize(
    ("final_state", "case"),
    [("3/8", "rescaled"), ("1/9", "scaled and scaled back")],
)
def test_fails_when_the_deployment_changes_during_the_run(
    tmp_path: Path, final_state: str, case: str
) -> None:
    result, calls = _run(tmp_path, STUB_DEPLOYMENT_READS=f"2|1/7|{final_state}")

    assert result.returncode == 1, case
    assert "changed during the run" in result.stderr
    assert _scales(calls)[-1] == _RESTORE


def test_failed_rollout_still_restores(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, STUB_ROLLOUT_RC="1")

    assert result.returncode == 1
    assert _scales(calls) == [_PIN, _RESTORE]


def test_failed_restore_fails_an_otherwise_passing_run(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, STUB_FAIL_SCALE_TO="2")

    assert result.returncode == 1
    assert "Could not restore deployment/gateway" in result.stderr
    assert _scales(calls) == [_PIN, _RESTORE]


@pytest.mark.parametrize(
    ("latency", "message"),
    [
        ("", "Locust stats CSV not found"),
        ("250", "FAIL: Average latency exceeded threshold"),
    ],
)
def test_fails_without_a_passing_measurement(
    tmp_path: Path, latency: str, message: str
) -> None:
    result, calls = _run(tmp_path, STUB_LOCUST_AVG_MS=latency)

    assert result.returncode == 1
    assert message in result.stdout + result.stderr
    assert _scales(calls)[-1] == _RESTORE


def test_termination_during_the_run_restores_the_original_count(
    tmp_path: Path,
) -> None:
    env, log = _environment(tmp_path, STUB_REAL_SLEEP="0.2")
    process = subprocess.Popen(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while "rollout status" not in log.read_text(encoding="utf-8"):
            assert process.poll() is None, "script exited before pinning"
            assert time.monotonic() < deadline, "script never pinned the gateway"
            time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    assert returncode == 143
    assert _scales(_calls(log)) == [_PIN, _RESTORE]
