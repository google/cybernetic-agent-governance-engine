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
replica, fails if the deployment changed during the run or if Locust produced
no valid ``GET /health`` measurement, and restores the original count on every
exit. The hermetic tests run the real script against stub ``kubectl``,
``locust`` and ``sleep`` executables that record each call.
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

# Header of the stats CSV that ``locust --csv <prefix>`` writes.
_STATS_HEADER = (
    "Type,Name,Request Count,Failure Count,Median Response Time,"
    "Average Response Time,Min Response Time,Max Response Time,"
    "Average Content Size,Requests/s,Failures/s,50%,66%,75%,80%,90%,95%,"
    "98%,99%,99.9%,99.99%,100%"
)

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
  *" scale "*"--replicas=${STUB_SLOW_SCALE_TO:-none}")
    /bin/sleep 2
    echo done > "${STUB_LOG}.slow-scale" ;;
esac
exit 0
"""

# Accepts only the Locust options the script uses. Like Locust's argparse
# parser, it rejects anything else (such as an option only a locustfile
# could register) with exit status 2, so the passing run below proves the
# script passes no option Locust does not define.
_LOCUST_STUB = """#!/usr/bin/env bash
prefix=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--host|--users|--spawn-rate|--run-time) shift ;;
    --csv) prefix="$2"; shift ;;
    --headless|--only-summary) ;;
    *) echo "locust: error: unrecognized arguments: $1" >&2; exit 2 ;;
  esac
  shift
done
echo "stub locust: started"
if [[ -n "${STUB_LOCUST_STARTUP_ERROR:-}" ]]; then
  echo "${STUB_LOCUST_STARTUP_ERROR}" >&2
  exit 2
fi
if [[ -n "${STUB_LOCUST_AVG_MS:-}" && -n "${prefix}" ]]; then
  {
    echo "__STATS_HEADER__"
    echo "POST,POST /governance/validate-action,500,0,30,35,10,90,40,8.0,0.0,30,32,34,36,40,45,50,60,80,90,95"
    echo "GET,${STUB_LOCUST_HEALTH_NAME:-GET /health},${STUB_LOCUST_HEALTH_REQUESTS:-100},${STUB_LOCUST_HEALTH_FAILURES:-0},10,${STUB_LOCUST_AVG_MS},5,40,20,1.5,0.0,10,11,12,13,15,18,20,25,30,35,40"
    echo ",Aggregated,600,0,25,31,5,90,37,9.5,0.0,25,28,30,32,38,43,48,58,78,88,95"
  } > "${prefix}_stats.csv"
fi
exit "${STUB_LOCUST_RC:-0}"
""".replace("__STATS_HEADER__", _STATS_HEADER)

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


def _wait_for(log: Path, text: str, process: subprocess.Popen[bytes]) -> None:
    """Block until ``text`` appears in the kubectl log; fail if the script exits."""
    deadline = time.monotonic() + 30
    while text not in log.read_text(encoding="utf-8"):
        assert process.poll() is None, f"script exited before {text!r}"
        assert time.monotonic() < deadline, f"script never reached {text!r}"
        time.sleep(0.05)


_PIN = "scale deployment/gateway --replicas=1"
_RESTORE = "scale deployment/gateway --request-timeout=30s --replicas=2"


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
    # D2 restores deployment/k8s/gateway-hpa.yaml with custom External+Pods metrics,
    # while scripts/run_gke_load_test.sh still never applies it and deletes any active HPA.


def test_stub_locust_rejects_options_locust_does_not_define(tmp_path: Path) -> None:
    env, _ = _environment(tmp_path)

    result = subprocess.run(
        [str(tmp_path / "bin" / "locust"), "--headless", "--agent-endpoint", "/health"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 2
    assert "unrecognized arguments: --agent-endpoint" in result.stderr


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
    # Report and Locust output land in this run's own directory.
    (run_dir,) = tmp_path.glob("cage-load-test.*")
    assert (run_dir / "locust_report_stats.csv").is_file()
    locust_log = (run_dir / "locust_run.log").read_text(encoding="utf-8")
    assert "stub locust: started" in locust_log
    assert "stub locust" not in result.stdout


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


def test_locust_startup_error_fails_the_run_and_shows_the_locust_log(
    tmp_path: Path,
) -> None:
    error = "locust: error: unrecognized arguments: --agent-endpoint"

    result, calls = _run(tmp_path, STUB_LOCUST_STARTUP_ERROR=error)

    assert result.returncode == 1
    assert "Locust exited with status 2; nothing was measured" in result.stderr
    assert error in result.stderr
    assert _scales(calls)[-1] == _RESTORE


def test_a_stale_report_cannot_stand_in_for_a_missing_one(tmp_path: Path) -> None:
    # A passing report where the script used to write it, left by an earlier run.
    (tmp_path / "locust_report_stats.csv").write_text(
        f"{_STATS_HEADER}\n"
        "GET,GET /health,100,0,10,12.5,5,40,20,1.5,0.0,10,11,12,13,15,18,20,25,30,35,40\n",
        encoding="utf-8",
    )

    result, calls = _run(tmp_path, STUB_LOCUST_AVG_MS="")

    assert result.returncode == 1
    assert "Locust stats CSV not found" in result.stderr
    assert "stub locust: started" in result.stderr
    assert _scales(calls)[-1] == _RESTORE


@pytest.mark.parametrize(
    ("stub", "message"),
    [
        pytest.param(
            {"STUB_LOCUST_HEALTH_NAME": "GET /status"},
            "Could not find a /health row",
            id="no-health-row",
        ),
        pytest.param(
            {"STUB_LOCUST_HEALTH_REQUESTS": "n/a"},
            "Could not parse the /health request counts",
            id="unparsable-counts",
        ),
        pytest.param(
            {"STUB_LOCUST_HEALTH_REQUESTS": "0"},
            "No /health request was recorded",
            id="no-health-requests",
        ),
        pytest.param(
            {"STUB_LOCUST_HEALTH_FAILURES": "3", "STUB_LOCUST_RC": "1"},
            "3 of 100 /health requests failed",
            id="health-failures",
        ),
        pytest.param(
            {"STUB_LOCUST_AVG_MS": "N/A"},
            "Could not parse the average /health latency",
            id="unparsable-average",
        ),
        pytest.param(
            {"STUB_LOCUST_AVG_MS": "250"},
            "FAIL: Average latency exceeded threshold",
            id="too-slow",
        ),
    ],
)
def test_fails_without_a_valid_passing_measurement(
    tmp_path: Path, stub: dict[str, str], message: str
) -> None:
    result, calls = _run(tmp_path, **stub)

    assert result.returncode == 1
    assert message in result.stderr
    assert _scales(calls)[-1] == _RESTORE


def test_failed_requests_elsewhere_warn_without_failing_the_gate(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, STUB_LOCUST_RC="1")

    assert result.returncode == 0, result.stderr
    assert "Locust reported failed requests (exit status 1)" in result.stdout
    assert "PASS: Average latency is within limits" in result.stdout
    assert _scales(calls) == [_PIN, _RESTORE]


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
        _wait_for(log, "rollout status", process)
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    assert returncode == 143
    assert _scales(_calls(log)) == [_PIN, _RESTORE]


def test_a_second_interrupt_cannot_abort_the_restore(tmp_path: Path) -> None:
    env, log = _environment(tmp_path, STUB_REAL_SLEEP="0.2", STUB_SLOW_SCALE_TO="2")
    # In its own session, so the Ctrl-C below reaches the script's whole
    # process group, the restoring kubectl included, as it would from a
    # terminal.
    process = subprocess.Popen(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_for(log, "rollout status", process)
        process.send_signal(signal.SIGTERM)
        _wait_for(log, _RESTORE, process)
        os.killpg(process.pid, signal.SIGINT)
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)

    assert returncode == 143
    restored = tmp_path / "kubectl.log.slow-scale"
    assert restored.read_text(encoding="utf-8").strip() == "done"
    assert _scales(_calls(log)) == [_PIN, _RESTORE]


def test_closed_stdout_restores_the_original_count(tmp_path: Path) -> None:
    # Nothing but a closed stdout: the script's next write raises SIGPIPE.
    # Before SIGPIPE was trapped, bash died of it (returncode -13) without
    # running cleanup, and the gateway stayed pinned.
    env, log = _environment(tmp_path, STUB_REAL_SLEEP="0.2")
    process = subprocess.Popen(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for(log, "rollout status", process)
        assert process.stdout is not None
        process.stdout.close()
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    assert returncode == 141
    assert _scales(_calls(log)) == [_PIN, _RESTORE]


def test_closed_stdout_pipe_still_restores_the_original_count(
    tmp_path: Path,
) -> None:
    # `run_gke_load_test.sh | tee` interrupted: the pipe closes and SIGTERM
    # arrives. Which one bash handles first depends on whether the script
    # writes before the signal lands, so 141 and 143 are both correct. The
    # restore must happen either way. Under load the write used to win, and
    # the script died of SIGPIPE before cleanup.
    env, log = _environment(tmp_path, STUB_REAL_SLEEP="0.2")
    process = subprocess.Popen(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for(log, "rollout status", process)
        assert process.stdout is not None
        process.stdout.close()
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    assert returncode in (141, 143)
    assert _scales(_calls(log)) == [_PIN, _RESTORE]


def test_hangup_restores_the_original_count(tmp_path: Path) -> None:
    # A closed terminal sends SIGHUP.
    env, log = _environment(tmp_path, STUB_REAL_SLEEP="0.2")
    process = subprocess.Popen(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for(log, "rollout status", process)
        process.send_signal(signal.SIGHUP)
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    assert returncode == 129
    assert _scales(_calls(log)) == [_PIN, _RESTORE]
