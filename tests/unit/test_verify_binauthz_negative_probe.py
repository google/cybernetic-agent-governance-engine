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

"""Unit tests for ``scripts/verify_binauthz_negative_probe.py``."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import scripts.verify_binauthz_negative_probe as binauthz_probe

pytestmark = [pytest.mark.unit, pytest.mark.local]

_WHITELISTED_PREFIXES = (
    "gcr.io/gke-release/",
    "gcr.io/config-management-release/",
    "k8s.gcr.io/",
    "gke.gcr.io/",
    "quay.io/jetstack/",
    "cr.l5d.io/",
    "ghcr.io/linkerd/",
)


def test_unattested_pod_manifest_satisfies_restricted_pss_and_non_whitelisted_image() -> (
    None
):
    manifest = binauthz_probe.build_unattested_pod_manifest()
    assert manifest["kind"] == "Pod"
    assert manifest["metadata"]["namespace"] == "default"
    assert manifest["metadata"]["annotations"]["linkerd.io/inject"] == "disabled"
    pod_sc = manifest["spec"]["securityContext"]
    assert pod_sc["runAsNonRoot"] is True
    assert pod_sc["runAsUser"] == 1000
    assert pod_sc["seccompProfile"]["type"] == "RuntimeDefault"

    container = manifest["spec"]["containers"][0]
    image = str(container["image"])
    assert "@sha256:" in image
    assert not any(image.startswith(prefix) for prefix in _WHITELISTED_PREFIXES)
    ctr_sc = container["securityContext"]
    assert ctr_sc["allowPrivilegeEscalation"] is False
    assert ctr_sc["readOnlyRootFilesystem"] is True
    assert ctr_sc["runAsNonRoot"] is True
    assert ctr_sc["capabilities"]["drop"] == ["ALL"]
    assert ctr_sc["seccompProfile"]["type"] == "RuntimeDefault"


def test_unattested_pod_manifest_refuses_meshed_governance_stack_namespace() -> None:
    with pytest.raises(ValueError, match="cage-mesh-proxy-required"):
        binauthz_probe.build_unattested_pod_manifest(namespace="governance-stack")


def test_negative_probe_passes_on_imagepolicywebhook_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def _fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(args))
        if "apply" in args:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr=(
                    'Error from server (Forbidden): error when creating "STDIN": '
                    'admission webhook "imagepolicywebhook.image-policy.k8s.io" denied '
                    "the request: Image cgr.dev/chainguard/wolfi-base@sha256:... denied "
                    "by projects/demo/attestors/cage-build-attestor-staging: No attestations found"
                ),
            )
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(binauthz_probe.subprocess, "run", _fake_run)
    out = tmp_path / "probe.json"
    rc = binauthz_probe.main(["--output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["passed"] is True
    assert doc["namespace"] == "default"
    assert doc["pod_admitted"] is False
    assert doc["webhook_verified"] is True
    assert len(calls) == 2


def test_negative_probe_fails_closed_and_cleans_up_when_pod_is_admitted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def _fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(args))
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="pod/cage-binauthz-unattested-probe created\n",
            stderr="",
        )

    monkeypatch.setattr(binauthz_probe.subprocess, "run", _fake_run)
    out = tmp_path / "probe-admitted.json"
    rc = binauthz_probe.main(["--namespace", "default", "--output", str(out)])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["passed"] is False
    assert doc["pod_admitted"] is True
    assert len(calls) == 3
    assert "delete" in calls[-1]


@pytest.mark.parametrize(
    "stderr_msg",
    [
        'Error from server (Forbidden): pods "cage-binauthz-unattested-probe" is forbidden: violates PodSecurity "restricted:latest"',
        'The pods "cage-binauthz-unattested-probe" is invalid: ValidatingAdmissionPolicy "cage-mesh-proxy-required" with binding "cage-mesh-proxy-required" denied request: pods in this namespace must run the Linkerd proxy',
        "The connection to the server 10.0.0.2:443 was refused",
    ],
)
def test_negative_probe_fails_closed_when_rejection_is_not_binauthz(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stderr_msg: str
) -> None:
    def _fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        if "apply" in args:
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr=stderr_msg
            )
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(binauthz_probe.subprocess, "run", _fake_run)
    out = tmp_path / "probe-wrong-err.json"
    rc = binauthz_probe.main(["--namespace", "custom-ns", "--output", str(out)])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["passed"] is False
    assert doc["pod_admitted"] is False
    assert doc["webhook_verified"] is False
