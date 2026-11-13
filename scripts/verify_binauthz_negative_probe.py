#!/usr/bin/env python3
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

"""Negative supply-chain admission probe for GKE Binary Authorization (Gate W).

Submits a Pod manifest that satisfies Kubernetes ``restricted`` Pod Security
Standards (`runAsNonRoot`, `runAsUser=1000`, `readOnlyRootFilesystem`, dropped
`ALL` capabilities, `RuntimeDefault` seccomp) and pins a valid `@sha256:` image
digest outside `google_binary_authorization_policy.cluster_policy`'s system
registry whitelist (`cgr.dev/chainguard/wolfi-base@sha256:...`) that carries
**zero** `cage-build-attestor` Grafeas attestations.

Pass criteria (fail-closed):
  1. `kubectl apply` MUST return a non-zero exit code (if admitted, the probe
     deletes the pod immediately and exits `1`).
  2. Rejection output MUST come from Binary Authorization admission enforcement
     (`imagepolicywebhook.image-policy.k8s.io` / attestation refusal), never
     from `PodSecurity`, RBAC, or API transport errors.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_UNATTESTED_IMAGE = (
    "cgr.dev/chainguard/wolfi-base@"
    "sha256:f15fea2f49cb14dceaea491fcbde0d35e0c190126a744ac05a9838440d47d994"
)
DEFAULT_PROBE_NAMESPACE = "default"
DEFAULT_POD_NAME = "cage-binauthz-unattested-probe"

_BINAUTHZ_MARKERS: tuple[str, ...] = (
    "imagepolicywebhook.image-policy.k8s.io",
    "binaryauthorization",
    "attestation",
    "attestor",
)


def build_unattested_pod_manifest(
    *,
    namespace: str = DEFAULT_PROBE_NAMESPACE,
    pod_name: str = DEFAULT_POD_NAME,
    image: str = DEFAULT_UNATTESTED_IMAGE,
) -> dict[str, Any]:
    """Build a restricted-PSS-compliant Pod manifest using an unattested digest.

    Targets a non-meshed namespace (``default`` by default) because
    ``ValidatingAdmissionPolicy/cage-mesh-proxy-required`` (MI-3) binds
    ``governance-stack`` and denies ``linkerd.io/inject=disabled`` pods in-process
    before ``imagepolicywebhook.image-policy.k8s.io`` is reached, whereas
    ``google_binary_authorization_policy.cluster_policy`` enforces
    ``REQUIRE_ATTESTATION`` / ``ENFORCED_BLOCK_AND_AUDIT_LOG`` cluster-wide.
    """
    if namespace == "governance-stack":
        raise ValueError(
            "Binary Authorization negative probe must target a non-meshed namespace "
            "(e.g. 'default'), not 'governance-stack': ValidatingAdmissionPolicy/"
            "cage-mesh-proxy-required denies linkerd.io/inject=disabled pods before "
            "Binary Authorization admission runs."
        )
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": pod_name,
                "app.kubernetes.io/part-of": "cybernetic-governance-engine",
            },
            "annotations": {
                "linkerd.io/inject": "disabled",
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "unattested-probe",
                    "image": image,
                    "command": ["/bin/false"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "16Mi"},
                        "limits": {"cpu": "50m", "memory": "32Mi"},
                    },
                }
            ],
        },
    }


def run_negative_probe(
    *,
    namespace: str = DEFAULT_PROBE_NAMESPACE,
    pod_name: str = DEFAULT_POD_NAME,
    image: str = DEFAULT_UNATTESTED_IMAGE,
    kubectl_bin: str | None = None,
) -> dict[str, Any]:
    """Execute the negative Binary Authorization admission probe and return structured evidence."""
    resolved_kubectl = kubectl_bin or shutil.which("kubectl") or "kubectl"
    manifest_json = json.dumps(
        build_unattested_pod_manifest(
            namespace=namespace, pod_name=pod_name, image=image
        ),
        sort_keys=True,
    )

    subprocess.run(
        [
            resolved_kubectl,
            "delete",
            f"pod/{pod_name}",
            "-n",
            namespace,
            "--ignore-not-found",
            "--wait=false",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    apply_proc = subprocess.run(
        [resolved_kubectl, "apply", "-n", namespace, "-f", "-"],
        input=manifest_json,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    combined = "\n".join(
        part.strip()
        for part in (apply_proc.stderr or "", apply_proc.stdout or "")
        if part.strip()
    )
    combined_lower = combined.lower()

    if apply_proc.returncode == 0:
        subprocess.run(
            [
                resolved_kubectl,
                "delete",
                f"pod/{pod_name}",
                "-n",
                namespace,
                "--ignore-not-found",
                "--wait=false",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "checked_at_utc": datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "passed": False,
            "pod_admitted": True,
            "webhook_verified": False,
            "namespace": namespace,
            "pod_name": pod_name,
            "probe_image": image,
            "failure_reason": "Unattested pod was admitted instead of rejected by Binary Authorization",
            "rejection_excerpt": combined[:500],
        }

    non_binauthz_policy_blocked = (
        "podsecurity" in combined_lower
        or "cage-mesh-proxy-required" in combined_lower
        or "must run the linkerd proxy" in combined_lower
    )
    webhook_matched = not non_binauthz_policy_blocked and any(
        marker in combined_lower for marker in _BINAUTHZ_MARKERS
    )
    passed = bool(webhook_matched)
    return {
        "checked_at_utc": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "passed": passed,
        "pod_admitted": False,
        "webhook_verified": webhook_matched,
        "namespace": namespace,
        "pod_name": pod_name,
        "probe_image": image,
        "failure_reason": (
            ""
            if passed
            else "kubectl apply failed, but rejection did not originate from Binary Authorization webhook"
        ),
        "rejection_excerpt": combined[:500],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify GKE Binary Authorization rejects a deliberately unattested pod."
    )
    parser.add_argument(
        "--namespace",
        default=DEFAULT_PROBE_NAMESPACE,
        help="Non-meshed Kubernetes namespace for probe admission (default: default).",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_UNATTESTED_IMAGE,
        help="Digest-pinned non-whitelisted unattested container image.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write JSON probe summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    result = run_negative_probe(namespace=args.namespace, image=args.image)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    if not result["passed"]:
        sys.stderr.write(
            f"❌ Binary Authorization negative probe FAILED: {result['failure_reason']} "
            f"(excerpt={result['rejection_excerpt']!r})\n"
        )
        return 1
    sys.stdout.write(
        f"✅ Binary Authorization negative probe passed: unattested image rejected "
        f"({result['rejection_excerpt'][:160]})\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
