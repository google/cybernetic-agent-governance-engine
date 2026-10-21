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
never autoscale it: it refuses production contexts, removes leftover HPAs,
refuses to run while another autoscaler targets the gateway, pins one
replica, checks the pin held, and restores the original count on exit. The
hermetic tests run the real script against stub ``kubectl``, ``locust`` and
``sleep`` executables that record every call.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "run_gke_load_test.sh"

_KUBECTL_STUB = """#!/usr/bin/env bash
echo "$*" >> "${STUB_LOG}"
case "$*" in
  "config current-context")
    echo "${STUB_CONTEXT}" ;;
  "get hpa"*)
    printf '%b' "${STUB_HPA_TARGETS:-}" ;;
  "get deployment/gateway"*)
    reads_file="${STUB_LOG}.replica-reads"
    reads=$(( $(cat "${reads_file}" 2>/dev/null || echo 0) + 1 ))
    echo "${reads}" > "${reads_file}"
    if [[ "${reads}" -eq 1 ]]; then
      printf '%s' "${STUB_ORIGINAL_REPLICAS}"
    else
      printf '%s' "${STUB_FINAL_REPLICAS}"
    fi ;;
esac
exit 0
"""


def _executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _run(
    tmp_path: Path,
    *,
    context: str = "gke_test-project_us-central1-a_cage-dev",
    hpa_targets: str = "",
    original_replicas: str = "2",
    final_replicas: str = "1",
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the load test against stubs; return the result and kubectl calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _executable(bin_dir / "kubectl", _KUBECTL_STUB)
    _executable(bin_dir / "locust", "#!/usr/bin/env bash\nexit 0\n")
    _executable(bin_dir / "sleep", "#!/usr/bin/env bash\nexit 0\n")
    log = tmp_path / "kubectl.log"
    log.touch()

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "TMPDIR": str(tmp_path),
            "NAMESPACE": "governance-stack",
            "STUB_LOG": str(log),
            "STUB_CONTEXT": context,
            "STUB_HPA_TARGETS": hpa_targets,
            "STUB_ORIGINAL_REPLICAS": original_replicas,
            "STUB_FINAL_REPLICAS": final_replicas,
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def _scales(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("scale ")]


def test_script_never_applies_manifests_and_the_hpa_manifest_is_gone() -> None:
    code_lines = [
        line.strip()
        for line in SCRIPT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert not any("kubectl apply" in line for line in code_lines)
    assert any(
        "kubectl delete hpa gateway-hpa" in line and "--ignore-not-found" in line
        for line in code_lines
    )
    assert not (REPO_ROOT / "deployment" / "k8s" / "gateway-hpa.yaml").exists()


def test_refuses_a_production_context_before_touching_the_cluster(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, context="gke_test-project_us-central1_cage-prod")

    assert result.returncode == 1
    assert "looks like production" in result.stderr
    assert calls == ["config current-context"]


def test_refuses_while_another_autoscaler_targets_the_gateway(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, hpa_targets="Deployment   gateway\n")

    assert result.returncode == 1
    assert "autoscaler still targets deployment/gateway" in result.stderr
    assert any(call.startswith("delete hpa gateway-hpa") for call in calls)
    assert _scales(calls) == []


def test_pins_one_replica_and_restores_the_original_count(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, original_replicas="2", final_replicas="1")

    assert result.returncode == 0, result.stderr
    assert _scales(calls) == [
        "scale deployment/gateway --replicas=1 -n governance-stack",
        "scale deployment/gateway --replicas=2 -n governance-stack",
    ]
    delete = calls.index(
        "delete hpa gateway-hpa -n governance-stack --ignore-not-found"
    )
    pin = calls.index("scale deployment/gateway --replicas=1 -n governance-stack")
    rollout = calls.index(
        "rollout status deployment/gateway -n governance-stack --timeout=300s"
    )
    assert delete < pin < rollout


def test_fails_when_the_replica_count_changes_mid_run_and_still_restores(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, original_replicas="2", final_replicas="3")

    assert result.returncode == 1
    assert "rescaled to 3 during the run" in result.stderr
    assert (
        _scales(calls)[-1]
        == "scale deployment/gateway --replicas=2 -n governance-stack"
    )
