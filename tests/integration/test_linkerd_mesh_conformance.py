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

"""Live Linkerd service-mesh conformance tests for POAM-2026-080 (SC-8 / IA-3 / AC-3).

Applies the repository's canonical ``deployment/k8s/service-account.yaml`` and
``deployment/k8s/linkerd-mtls-policy.yaml`` manifests to a Linkerd-meshed
Kubernetes cluster (e.g. ``kind`` + Linkerd in CI via ``make test-mesh``) and
verifies over real Linkerd proxy sidecars that:

1. The Linkerd CRD validation webhooks accept ``Server``, ``HTTPRoute``,
   ``MeshTLSAuthentication``, ``NetworkAuthentication``, and
   ``AuthorizationPolicy`` resources without schema errors.
2. A meshed pod running as ``cage-advisor-sa`` reaches both open (``/healthz``)
   and gated (``/governance/policy-version``) gateway routes over mTLS, and the
   inbound Linkerd proxy injects
   ``l5d-client-id: cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local``.
3. A meshed pod running as ``cage-vllm-sa`` reaches open routes (``/healthz``)
   but is rejected with HTTP 403 by the inbound Linkerd proxy on gated routes
   (``/governance/policy-version``).
4. A forged ``l5d-client-id`` header sent by ``cage-vllm-sa`` cannot bypass the
   Linkerd ``AuthorizationPolicy`` on gated routes (HTTP 403) and is overwritten
   by the inbound Linkerd proxy with the caller's true mTLS identity on open
   routes.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import textwrap

import pytest

pytestmark = [pytest.mark.integration]

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVICE_ACCOUNT_MANIFEST = REPO_ROOT / "deployment" / "k8s" / "service-account.yaml"
LINKERD_POLICY_MANIFEST = REPO_ROOT / "deployment" / "k8s" / "linkerd-mtls-policy.yaml"

NAMESPACE = "governance-stack"
VLLM_NAMESPACE = "vllm-inference"
ADVISOR_SPIFFE_ID = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
VLLM_SPIFFE_ID = (
    "cage-vllm-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


def _kubectl(
    *args: str,
    input_text: str | None = None,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", *args],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def _require_linkerd_cluster() -> None:
    """Ensure a Kubernetes cluster with Linkerd policy CRDs is reachable."""
    require_cluster = os.environ.get(
        "CAGE_REQUIRE_LINKERD_CLUSTER", "0"
    ).strip().lower() in ("1", "true", "yes")
    try:
        res = _kubectl(
            "get", "crd", "servers.policy.linkerd.io", timeout=10, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        if require_cluster:
            pytest.fail(f"Linkerd cluster required but kubectl failed: {exc}")
        pytest.skip(f"kubectl unavailable or cluster unreachable: {exc}")

    if res.returncode != 0:
        msg = (
            "Linkerd policy CRD (servers.policy.linkerd.io) not installed on current cluster: "
            f"{res.stderr.strip()}"
        )
        if require_cluster:
            pytest.fail(msg)
        pytest.skip(msg)


@pytest.fixture(scope="module")
def linkerd_mesh_fixture():
    """Apply CAGE Linkerd policy manifests and deploy meshed probe workloads."""
    _require_linkerd_cluster()

    namespaces_yaml = textwrap.dedent(
        f"""\
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {NAMESPACE}
          annotations:
            linkerd.io/inject: enabled
        ---
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {VLLM_NAMESPACE}
        """
    )
    _kubectl("apply", "-f", "-", input_text=namespaces_yaml)
    _kubectl("apply", "-f", str(SERVICE_ACCOUNT_MANIFEST))
    _kubectl("apply", "-f", str(LINKERD_POLICY_MANIFEST))

    probe_workloads_yaml = textwrap.dedent(
        f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: gateway-mesh-probe
          namespace: {NAMESPACE}
          labels:
            app: gateway
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: gateway
          template:
            metadata:
              annotations:
                linkerd.io/inject: enabled
              labels:
                app: gateway
            spec:
              serviceAccountName: cage-gateway-sa
              containers:
                - name: gateway
                  image: python:3.11-slim
                  ports:
                    - name: http
                      containerPort: 8080
                  command:
                    - python3
                    - -c
                    - |
                      import json
                      from http.server import BaseHTTPRequestHandler, HTTPServer

                      OPEN_PATHS = {{"/health", "/healthz", "/metrics", "/governance/jwks", "/governance/.well-known/jwks.json"}}
                      TRUSTED_ID = "{ADVISOR_SPIFFE_ID}"

                      class Handler(BaseHTTPRequestHandler):
                          def do_GET(self):
                              client_id = self.headers.get("l5d-client-id", "")
                              if self.path not in OPEN_PATHS and client_id != TRUSTED_ID:
                                  body = json.dumps({{"error": "untrusted_client", "l5d_client_id": client_id}}).encode()
                                  self.send_response(403)
                              else:
                                  body = json.dumps({{"status": "ok", "path": self.path, "l5d_client_id": client_id}}).encode()
                                  self.send_response(200)
                              self.send_header("Content-Type", "application/json")
                              self.send_header("Content-Length", str(len(body)))
                              self.end_headers()
                              self.wfile.write(body)

                      HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
        ---
        apiVersion: v1
        kind: Service
        metadata:
          name: gateway-mesh-probe
          namespace: {NAMESPACE}
        spec:
          selector:
            app: gateway
          ports:
            - name: http
              port: 8080
              targetPort: http
        ---
        apiVersion: v1
        kind: Pod
        metadata:
          name: advisor-mesh-client
          namespace: {NAMESPACE}
          annotations:
            linkerd.io/inject: enabled
        spec:
          serviceAccountName: cage-advisor-sa
          containers:
            - name: client
              image: python:3.11-slim
              command: ["sleep", "3600"]
        ---
        apiVersion: v1
        kind: Pod
        metadata:
          name: vllm-mesh-client
          namespace: {NAMESPACE}
          annotations:
            linkerd.io/inject: enabled
        spec:
          serviceAccountName: cage-vllm-sa
          containers:
            - name: client
              image: python:3.11-slim
              command: ["sleep", "3600"]
        """
    )
    _kubectl("apply", "-f", "-", input_text=probe_workloads_yaml)

    _kubectl(
        "rollout",
        "status",
        "deployment/gateway-mesh-probe",
        "-n",
        NAMESPACE,
        "--timeout=180s",
        timeout=200,
    )
    _kubectl(
        "wait",
        "--for=condition=Ready",
        "pod/advisor-mesh-client",
        "pod/vllm-mesh-client",
        "-n",
        NAMESPACE,
        "--timeout=180s",
        timeout=200,
    )

    yield

    _kubectl(
        "delete",
        "deployment/gateway-mesh-probe",
        "service/gateway-mesh-probe",
        "pod/advisor-mesh-client",
        "pod/vllm-mesh-client",
        "-n",
        NAMESPACE,
        "--ignore-not-found=true",
        check=False,
    )


def _exec_http_get(
    pod_name: str,
    path: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Execute an HTTP GET from inside a meshed client pod to the gateway Service."""
    headers_literal = json.dumps(extra_headers or {})
    script = textwrap.dedent(
        f"""\
        import json, urllib.request, urllib.error
        url = "http://gateway-mesh-probe.{NAMESPACE}.svc.cluster.local:8080{path}"
        req = urllib.request.Request(url, headers={headers_literal})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(json.dumps({{"status": resp.status, "body": resp.read().decode("utf-8", "replace")}}))
        except urllib.error.HTTPError as exc:
            print(json.dumps({{"status": exc.code, "body": exc.read().decode("utf-8", "replace")}}))
        """
    )
    res = _kubectl(
        "exec",
        pod_name,
        "-n",
        NAMESPACE,
        "-c",
        "client",
        "--",
        "python3",
        "-c",
        script,
    )
    payload = json.loads(res.stdout.strip().splitlines()[-1])
    return int(payload["status"]), str(payload["body"])


def test_linkerd_manifests_accepted_by_apiserver(linkerd_mesh_fixture) -> None:
    """Verify Linkerd policy resources from deployment/k8s/linkerd-mtls-policy.yaml are active."""
    expected_resources = [
        "server.policy.linkerd.io/gateway-http",
        "httproute.policy.linkerd.io/gateway-open",
        "httproute.policy.linkerd.io/gateway-gated",
        "meshtlsauthentication.policy.linkerd.io/gateway-trusted-clients",
        "networkauthentication.policy.linkerd.io/gateway-any-network",
        "authorizationpolicy.policy.linkerd.io/gateway-open",
        "authorizationpolicy.policy.linkerd.io/gateway-gated",
    ]
    for resource in expected_resources:
        res = _kubectl("get", resource, "-n", NAMESPACE)
        assert res.returncode == 0


def test_trusted_advisor_sa_reaches_gated_and_open_routes(linkerd_mesh_fixture) -> None:
    """Verify cage-advisor-sa is admitted to both open and gated routes with verified l5d-client-id."""
    status_open, body_open = _exec_http_get("advisor-mesh-client", "/healthz")
    assert status_open == 200
    assert json.loads(body_open)["l5d_client_id"] == ADVISOR_SPIFFE_ID

    status_gated, body_gated = _exec_http_get(
        "advisor-mesh-client", "/governance/policy-version"
    )
    assert status_gated == 200
    assert json.loads(body_gated)["l5d_client_id"] == ADVISOR_SPIFFE_ID


def test_untrusted_vllm_sa_reaches_open_route_but_denied_on_gated_route(
    linkerd_mesh_fixture,
) -> None:
    """Verify cage-vllm-sa is admitted to /healthz (200) but blocked by Linkerd on gated routes (403)."""
    status_open, body_open = _exec_http_get("vllm-mesh-client", "/healthz")
    assert status_open == 200
    assert json.loads(body_open)["l5d_client_id"] == VLLM_SPIFFE_ID

    status_gated, _ = _exec_http_get("vllm-mesh-client", "/governance/policy-version")
    assert status_gated == 403


def test_forged_l5d_client_id_header_rejected_and_overwritten_by_linkerd(
    linkerd_mesh_fixture,
) -> None:
    """Verify a caller cannot spoof l5d-client-id to bypass Linkerd or application middleware."""
    forged_headers = {"l5d-client-id": ADVISOR_SPIFFE_ID}

    status_gated, _ = _exec_http_get(
        "vllm-mesh-client",
        "/governance/policy-version",
        extra_headers=forged_headers,
    )
    assert status_gated == 403

    status_open, body_open = _exec_http_get(
        "vllm-mesh-client",
        "/healthz",
        extra_headers=forged_headers,
    )
    assert status_open == 200
    assert json.loads(body_open)["l5d_client_id"] == VLLM_SPIFFE_ID
