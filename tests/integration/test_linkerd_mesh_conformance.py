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

"""Live Linkerd service-mesh conformance tests for POAM-2026-080 & POAM-2026-167 (F-106).

Renders and applies the repository's canonical Helm chart
(``infra/modules/gateway/mesh-policy``) to a Linkerd-meshed Kubernetes cluster
(e.g. ``kind`` + Linkerd in CI via ``make test-mesh``), deploys the built Wolfi
gateway container image (``src/gateway/Dockerfile``) booting the real
``src.gateway.server.hybrid_server:root_app`` application with an in-pod OPA
sidecar, and verifies over real Linkerd proxy sidecars that:

1. The Linkerd CRD validation webhooks accept the Helm-rendered ``Server``,
   ``HTTPRoute``, ``MeshTLSAuthentication``, ``NetworkAuthentication``, and
   ``AuthorizationPolicy`` resources without schema errors.
2. A meshed pod running as ``cage-advisor-sa`` reaches both open (``/healthz``)
   and gated (``/governance/policy-version``) routes on ``hybrid_server:root_app``
   over mTLS, passing both Linkerd's ``AuthorizationPolicy`` and
   ``WorkloadIdentityMiddleware`` (``is_pod_local_connection`` non-loopback
   pod-IP ``peer == server``).
3. A meshed pod running as ``cage-vllm-sa`` reaches open routes (``/healthz``)
   but is rejected with HTTP 403 by the inbound Linkerd proxy on gated routes
   (``/governance/policy-version``).
4. A forged ``l5d-client-id`` header sent by ``cage-vllm-sa`` cannot bypass the
   Linkerd ``AuthorizationPolicy`` on gated routes (HTTP 403), and even when the
   mesh ``MeshTLSAuthentication`` is widened to let ``cage-vllm-sa`` through the
   proxy, the inbound Linkerd proxy overwrites the forged header with
   ``cage-vllm-sa``'s mTLS identity so ``WorkloadIdentityMiddleware`` on
   ``hybrid_server:root_app`` rejects it with HTTP 403
   (``INGRESS_IDENTITY_REFUSED``).
5. A ``kubectl port-forward`` loopback connection (``127.0.0.1``) sending a
   forged ``l5d-client-id`` header is rejected with HTTP 403 by
   ``WorkloadIdentityMiddleware`` on ``hybrid_server:root_app`` and logs
   ``INGRESS_IDENTITY_NOT_FROM_PROXY`` (``is_pod_local_connection`` refuses
   loopback peers; POAM-2026-167, F-38, F-39, F-106).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import textwrap
import time
import urllib.error
import urllib.request

import pytest
import yaml

pytestmark = [pytest.mark.integration]

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MESH_POLICY_CHART_DIR = REPO_ROOT / "infra" / "modules" / "gateway" / "mesh-policy"
FINANCE_REGO_PATH = REPO_ROOT / "src" / "cage_finance" / "opa" / "trade_governance.rego"

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


def render_mesh_policy_chart(
    namespace: str = NAMESPACE,
    trusted_identities: list[str] | None = None,
) -> str:
    """Render ``infra/modules/gateway/mesh-policy`` for the given namespace and identities."""
    identities = (
        [ADVISOR_SPIFFE_ID] if trusted_identities is None else list(trusted_identities)
    )
    if shutil.which("helm") is not None:
        set_args: list[str] = []
        for idx, identity in enumerate(identities):
            set_args.extend(["--set-string", f"trustedIdentities[{idx}]={identity}"])
        res = subprocess.run(
            [
                "helm",
                "template",
                "mesh-policy",
                str(MESH_POLICY_CHART_DIR),
                "--namespace",
                namespace,
                *set_args,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return res.stdout

    values = yaml.safe_load((MESH_POLICY_CHART_DIR / "values.yaml").read_text())
    open_paths = list(values["openExactPaths"])
    open_matches = "\n".join(
        f"        - path:\n            type: Exact\n            value: {json.dumps(p)}"
        for p in open_paths
    )
    docs = [
        textwrap.dedent(
            f"""\
            apiVersion: policy.linkerd.io/v1beta3
            kind: Server
            metadata:
              name: gateway-http
              namespace: {namespace}
            spec:
              podSelector:
                matchLabels:
                  app: gateway
              port: http
            """
        ),
        (
            "apiVersion: policy.linkerd.io/v1beta3\n"
            "kind: HTTPRoute\n"
            "metadata:\n"
            "  name: gateway-open\n"
            f"  namespace: {namespace}\n"
            "spec:\n"
            "  parentRefs:\n"
            "    - group: policy.linkerd.io\n"
            "      kind: Server\n"
            "      name: gateway-http\n"
            "  rules:\n"
            "    - matches:\n"
            f"{open_matches}\n"
        ),
        textwrap.dedent(
            f"""\
            apiVersion: policy.linkerd.io/v1beta3
            kind: HTTPRoute
            metadata:
              name: gateway-gated
              namespace: {namespace}
            spec:
              parentRefs:
                - group: policy.linkerd.io
                  kind: Server
                  name: gateway-http
              rules:
                - matches:
                    - path:
                        type: PathPrefix
                        value: /
            ---
            apiVersion: policy.linkerd.io/v1alpha1
            kind: NetworkAuthentication
            metadata:
              name: gateway-any-network
              namespace: {namespace}
            spec:
              networks:
                - cidr: 0.0.0.0/0
                - cidr: ::/0
            ---
            apiVersion: policy.linkerd.io/v1alpha1
            kind: AuthorizationPolicy
            metadata:
              name: gateway-open
              namespace: {namespace}
            spec:
              targetRef:
                group: policy.linkerd.io
                kind: HTTPRoute
                name: gateway-open
              requiredAuthenticationRefs:
                - group: policy.linkerd.io
                  kind: NetworkAuthentication
                  name: gateway-any-network
            """
        ),
    ]
    if identities:
        id_lines = "\n".join(f"    - {json.dumps(i)}" for i in identities)
        docs.append(
            f"apiVersion: policy.linkerd.io/v1alpha1\n"
            f"kind: MeshTLSAuthentication\n"
            f"metadata:\n"
            f"  name: gateway-trusted-clients\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  identities:\n"
            f"{id_lines}\n"
            f"---\n"
            f"apiVersion: policy.linkerd.io/v1alpha1\n"
            f"kind: AuthorizationPolicy\n"
            f"metadata:\n"
            f"  name: gateway-gated\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  targetRef:\n"
            f"    group: policy.linkerd.io\n"
            f"    kind: HTTPRoute\n"
            f"    name: gateway-gated\n"
            f"  requiredAuthenticationRefs:\n"
            f"    - group: policy.linkerd.io\n"
            f"      kind: MeshTLSAuthentication\n"
            f"      name: gateway-trusted-clients\n"
        )
    return "\n---\n".join(docs)


def _resolve_gateway_image() -> str:
    """Resolve the built Wolfi gateway image (src/gateway/Dockerfile) for F-106."""
    configured = os.environ.get("CAGE_GATEWAY_IMAGE", "").strip()
    if configured:
        return configured
    gw_img_res = _kubectl(
        "get",
        "deployment/gateway",
        "-n",
        NAMESPACE,
        "-o",
        "jsonpath={.spec.template.spec.containers[0].image}",
        check=False,
    )
    if gw_img_res.returncode == 0 and gw_img_res.stdout.strip():
        return gw_img_res.stdout.strip()
    raise RuntimeError(
        "Set CAGE_GATEWAY_IMAGE to the built src/gateway/Dockerfile image "
        "(or run against a cluster with deployment/gateway in governance-stack) "
        "before running Linkerd mesh conformance (POAM-2026-167 / F-106)."
    )


def _require_linkerd_cluster() -> None:
    """Ensure a Kubernetes cluster with Linkerd policy CRDs is reachable."""
    require_cluster = os.environ.get(
        "CAGE_REQUIRE_LINKERD_CLUSTER", "0"
    ).strip().lower() in ("1", "true", "yes")

    if shutil.which("kubectl") is None:
        if require_cluster:
            pytest.fail(
                "kubectl binary not found while CAGE_REQUIRE_LINKERD_CLUSTER=1."
            )
        pytest.skip("kubectl not installed; skipping live Linkerd conformance suite.")

    crd_check = _kubectl(
        "get",
        "crd",
        "servers.policy.linkerd.io",
        "authorizationpolicies.policy.linkerd.io",
        "meshtlsauthentications.policy.linkerd.io",
        check=False,
    )
    if crd_check.returncode != 0:
        if require_cluster:
            pytest.fail(
                f"Linkerd policy CRDs missing in target cluster:\n{crd_check.stderr}"
            )
        pytest.skip(
            "Linkerd policy CRDs not installed in current kubectl context; "
            "run in CI (kind + Linkerd) or GKE staging with Linkerd installed."
        )


@pytest.fixture(scope="module")
def linkerd_mesh_fixture():
    """Apply CAGE Linkerd policy chart and deploy the Wolfi gateway image booting hybrid_server:root_app."""
    _require_linkerd_cluster()
    gateway_image = _resolve_gateway_image()
    opa_image = os.environ.get(
        "CAGE_OPA_IMAGE", "openpolicyagent/opa:0.70.0-static"
    ).strip()

    for ns in (NAMESPACE, VLLM_NAMESPACE):
        if _kubectl("get", "namespace", ns, check=False).returncode != 0:
            ns_yaml = textwrap.dedent(
                f"""\
                apiVersion: v1
                kind: Namespace
                metadata:
                  name: {ns}
                  annotations:
                    linkerd.io/inject: enabled
                """
            )
            _kubectl("apply", "-f", "-", input_text=ns_yaml)

    # Create probe ServiceAccounts when absent (e.g. bare kind in CI). On live
    # GKE clusters, Terraform manages KSA Workload Identity annotations and
    # Linkerd policy resources via infra/targets/gcp-gke/iam.tf and
    # infra/modules/gateway/mesh-policy.
    for sa_name in ("cage-gateway-sa", "cage-advisor-sa", "cage-vllm-sa"):
        if _kubectl("get", "sa", sa_name, "-n", NAMESPACE, check=False).returncode != 0:
            sa_yaml = textwrap.dedent(
                f"""\
                apiVersion: v1
                kind: ServiceAccount
                metadata:
                  name: {sa_name}
                  namespace: {NAMESPACE}
                """
            )
            _kubectl("apply", "-f", "-", input_text=sa_yaml)

    rendered_policy = render_mesh_policy_chart(
        namespace=NAMESPACE,
        trusted_identities=[ADVISOR_SPIFFE_ID],
    )
    _kubectl("apply", "-f", "-", input_text=rendered_policy)

    opa_configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "gateway-mesh-probe-opa-policy",
            "namespace": NAMESPACE,
        },
        "data": {
            "trade_governance.rego": FINANCE_REGO_PATH.read_text(encoding="utf-8"),
        },
    }
    _kubectl("apply", "-f", "-", input_text=yaml.safe_dump(opa_configmap))

    probe_workloads_yaml = textwrap.dedent(
        f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: gateway-mesh-probe
          namespace: {NAMESPACE}
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: gateway
              probe: linkerd-mesh-conformance
          template:
            metadata:
              labels:
                app: gateway
                probe: linkerd-mesh-conformance
              annotations:
                linkerd.io/inject: enabled
                config.linkerd.io/skip-outbound-ports: "8181"
            spec:
              serviceAccountName: cage-gateway-sa
              securityContext:
                runAsNonRoot: true
                runAsUser: 1000
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: opa
                  image: {opa_image}
                  imagePullPolicy: IfNotPresent
                  args:
                    - "run"
                    - "--server"
                    - "--log-level=error"
                    - "--addr=127.0.0.1:8181"
                    - "--ignore=.*"
                    - "/policies"
                  securityContext:
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop:
                        - ALL
                    privileged: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    runAsUser: 1000
                    seccompProfile:
                      type: RuntimeDefault
                  volumeMounts:
                    - name: opa-policy
                      mountPath: /policies
                      readOnly: true
                - name: gateway
                  image: {gateway_image}
                  imagePullPolicy: IfNotPresent
                  command:
                    - uvicorn
                    - src.gateway.server.hybrid_server:root_app
                    - --host
                    - 0.0.0.0
                    - --port
                    - "8080"
                    - --loop
                    - uvloop
                    - --http
                    - httptools
                    - --no-proxy-headers
                  env:
                    - name: PORT
                      value: "8080"
                    - name: SERVICE_NAME
                      value: "hybrid-gateway"
                    - name: CAGE_ENV
                      value: "development"
                    - name: CAGE_ALLOW_DEV_LOOPBACK_IDENTITY
                      value: "false"
                    - name: CAGE_METRICS_PORT
                      value: "0"
                    - name: CAGE_DOMAIN
                      value: "finance"
                    - name: CAGE_DEPLOYMENT_REGION
                      value: "US_FED"
                    - name: CAGE_INFERENCE_BACKEND
                      value: "none"
                    - name: CAGE_TELEMETRY_PROVIDER
                      value: "noop"
                    - name: OTEL_TRACES_EXPORTER
                      value: "none"
                    - name: CAGE_KMS_PROVIDER
                      value: "ed25519"
                    - name: EVIDENCE_STREAM_ENABLED
                      value: "false"
                    - name: EVIDENCE_CHAIN_BLOCKING
                      value: "false"
                    - name: USE_MOCK_BROKER
                      value: "true"
                    - name: OPA_URL
                      value: "http://127.0.0.1:8181"
                    - name: CAGE_TRUSTED_CLIENT_IDENTITIES
                      value: "{ADVISOR_SPIFFE_ID}"
                    - name: TMPDIR
                      value: "/tmp"
                  ports:
                    - name: http
                      containerPort: 8080
                  readinessProbe:
                    httpGet:
                      path: /healthz
                      port: http
                    initialDelaySeconds: 2
                    periodSeconds: 2
                    failureThreshold: 45
                  securityContext:
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop:
                        - ALL
                    privileged: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    runAsUser: 1000
                    seccompProfile:
                      type: RuntimeDefault
                  volumeMounts:
                    - name: tmp
                      mountPath: /tmp
              volumes:
                - name: opa-policy
                  configMap:
                    name: gateway-mesh-probe-opa-policy
                - name: tmp
                  emptyDir:
                    medium: Memory
        ---
        apiVersion: v1
        kind: Service
        metadata:
          name: gateway-mesh-probe
          namespace: {NAMESPACE}
        spec:
          selector:
            app: gateway
            probe: linkerd-mesh-conformance
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
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: client
              image: {gateway_image}
              imagePullPolicy: IfNotPresent
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
                privileged: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                runAsUser: 1000
                seccompProfile:
                  type: RuntimeDefault
              command: ["python", "-c", "import time; time.sleep(3600)"]
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
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: client
              image: {gateway_image}
              imagePullPolicy: IfNotPresent
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
                privileged: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                runAsUser: 1000
                seccompProfile:
                  type: RuntimeDefault
              command: ["python", "-c", "import time; time.sleep(3600)"]
        """
    )
    try:
        _kubectl("apply", "-f", "-", input_text=probe_workloads_yaml)

        rollout_res = _kubectl(
            "rollout",
            "status",
            "deployment/gateway-mesh-probe",
            "-n",
            NAMESPACE,
            "--timeout=180s",
            timeout=200,
            check=False,
        )
        if rollout_res.returncode != 0:
            desc = _kubectl(
                "describe",
                "pods",
                "-l",
                "probe=linkerd-mesh-conformance",
                "-n",
                NAMESPACE,
                check=False,
            )
            logs = _kubectl(
                "logs",
                "-l",
                "probe=linkerd-mesh-conformance",
                "-n",
                NAMESPACE,
                "--all-containers=true",
                "--tail=200",
                check=False,
            )
            pytest.fail(
                "gateway-mesh-probe rollout failed:\n"
                f"STDOUT:\n{rollout_res.stdout}\nSTDERR:\n{rollout_res.stderr}\n"
                f"DESCRIBE:\n{desc.stdout}\nLOGS:\n{logs.stdout}\n{logs.stderr}"
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
    finally:
        _kubectl(
            "delete",
            "deployment/gateway-mesh-probe",
            "service/gateway-mesh-probe",
            "configmap/gateway-mesh-probe-opa-policy",
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
        "python",
        "-c",
        script,
    )
    payload = json.loads(res.stdout.strip().splitlines()[-1])
    return int(payload["status"]), str(payload["body"])


def test_linkerd_manifests_accepted_by_apiserver(linkerd_mesh_fixture) -> None:
    """Verify Linkerd policy resources rendered from infra/modules/gateway/mesh-policy are active."""
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


def test_companion_mesh_charts_accepted_by_linkerd_webhook(
    linkerd_mesh_fixture,
) -> None:
    """Verify compliance-bridge and workload-mesh-policy Helm charts pass linkerd-policy-validator webhook."""
    if shutil.which("helm") is None:
        pytest.skip("helm binary not installed; skipping companion chart render check.")
    suffix = f"{NAMESPACE}.serviceaccount.identity.linkerd.cluster.local"
    cb_chart = REPO_ROOT / "infra" / "modules" / "compliance_bridge" / "mesh-policy"
    cb_rendered = subprocess.run(
        [
            "helm",
            "template",
            "compliance-bridge-mesh-policy",
            str(cb_chart),
            "--namespace",
            NAMESPACE,
            "--set-string",
            f"trustedIdentities[0]=cage-gateway-sa.{suffix}",
            "--set-string",
            f"auditorIdentity=cage-lula-auditor-sa.{suffix}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    _kubectl("apply", "--dry-run=server", "-f", "-", input_text=cb_rendered)

    wl_chart = (
        REPO_ROOT / "infra" / "targets" / "gcp-gke" / "charts" / "workload-mesh-policy"
    )
    wl_rendered = subprocess.run(
        [
            "helm",
            "template",
            "workload-mesh-policy",
            str(wl_chart),
            "--namespace",
            NAMESPACE,
            "--set-string",
            f"identities.gatewayGrpcClients[0]={ADVISOR_SPIFFE_ID}",
            "--set-string",
            f"identities.modelBackendClients[0]=cage-gateway-sa.{suffix}",
            "--set-string",
            f"identities.clickhouseHttpClients[0]=cage-compliance-bridge-sa.{suffix}",
            "--set-string",
            f"identities.clickhouseTcpClients[0]=langfuse-sa.{suffix}",
            "--set-string",
            f"identities.clickhouseInterserverClients[0]=cage-clickhouse-sa.{suffix}",
            "--set-string",
            f"identities.clickhouseKeeperClients[0]=cage-clickhouse-sa.{suffix}",
            "--set-string",
            f"identities.clickhouseKeeperRaftClients[0]=cage-clickhouse-keeper-sa.{suffix}",
            "--set-string",
            f"identities.langfuseWebClients[0]=cage-gateway-sa.{suffix}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    _kubectl("apply", "--dry-run=server", "-f", "-", input_text=wl_rendered)


def test_trusted_advisor_sa_reaches_gated_and_open_routes(linkerd_mesh_fixture) -> None:
    """Verify cage-advisor-sa is admitted to both open and gated routes on hybrid_server:root_app."""
    status_open, body_open = _exec_http_get("advisor-mesh-client", "/healthz")
    assert status_open == 200
    assert json.loads(body_open)["status"] == "healthy"

    status_gated, body_gated = _exec_http_get(
        "advisor-mesh-client", "/governance/policy-version"
    )
    assert status_gated == 200
    gated_payload = json.loads(body_gated)
    assert gated_payload.get("active_hash")
    assert gated_payload.get("thresholds_digest")


def test_untrusted_vllm_sa_reaches_open_route_but_denied_on_gated_route(
    linkerd_mesh_fixture,
) -> None:
    """Verify cage-vllm-sa is admitted to /healthz (200) but blocked by Linkerd on gated routes (403)."""
    status_open, body_open = _exec_http_get("vllm-mesh-client", "/healthz")
    assert status_open == 200
    assert json.loads(body_open)["status"] == "healthy"

    status_gated, _ = _exec_http_get("vllm-mesh-client", "/governance/policy-version")
    assert status_gated == 403


def test_forged_l5d_client_id_header_rejected_and_overwritten_by_linkerd(
    linkerd_mesh_fixture,
) -> None:
    """Verify forged l5d-client-id cannot bypass Linkerd or WorkloadIdentityMiddleware on hybrid_server:root_app."""
    forged_headers = {"l5d-client-id": ADVISOR_SPIFFE_ID}

    status_gated, _ = _exec_http_get(
        "vllm-mesh-client",
        "/governance/policy-version",
        extra_headers=forged_headers,
    )
    assert status_gated == 403

    # Temporarily admit cage-vllm-sa at the Linkerd proxy layer while keeping
    # CAGE_TRUSTED_CLIENT_IDENTITIES restricted to ADVISOR_SPIFFE_ID in
    # hybrid_server:root_app: proves Linkerd overwrites the forged header with
    # VLLM_SPIFFE_ID and WorkloadIdentityMiddleware enforces defense-in-depth.
    widened_policy = render_mesh_policy_chart(
        namespace=NAMESPACE,
        trusted_identities=[ADVISOR_SPIFFE_ID, VLLM_SPIFFE_ID],
    )
    strict_policy = render_mesh_policy_chart(
        namespace=NAMESPACE,
        trusted_identities=[ADVISOR_SPIFFE_ID],
    )
    try:
        _kubectl("apply", "-f", "-", input_text=widened_policy)
        overwritten_verified = False
        for _ in range(15):
            status_mw, body_mw = _exec_http_get(
                "vllm-mesh-client",
                "/governance/policy-version",
                extra_headers=forged_headers,
            )
            assert status_mw == 403
            if "caller workload identity is not authorized" in body_mw:
                overwritten_verified = True
                break
            time.sleep(0.5)
        assert overwritten_verified, (
            "Expected Linkerd inbound proxy to overwrite forged l5d-client-id "
            "and reach WorkloadIdentityMiddleware 403 JSON response."
        )
        gw_logs = _kubectl(
            "logs",
            "deployment/gateway-mesh-probe",
            "-n",
            NAMESPACE,
            "-c",
            "gateway",
            "--tail=100",
        ).stdout
        assert "INGRESS_IDENTITY_REFUSED" in gw_logs
        assert VLLM_SPIFFE_ID in gw_logs
    finally:
        _kubectl("apply", "-f", "-", input_text=strict_policy)


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_port_forward_loopback_forged_l5d_client_id_rejected_by_middleware(
    linkerd_mesh_fixture,
) -> None:
    """Verify kubectl port-forward (loopback peer) sending forged l5d-client-id is rejected with 403 (POAM-2026-167 / F-106)."""
    local_port = _free_local_port()
    pf_proc = subprocess.Popen(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "port-forward",
            "deployment/gateway-mesh-probe",
            f"{local_port}:8080",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        health_url = f"http://127.0.0.1:{local_port}/healthz"
        assert health_url.startswith(("http://", "https://"))
        ready = False
        for _ in range(30):
            if pf_proc.poll() is not None:
                _, stderr = pf_proc.communicate(timeout=5)
                pytest.fail(f"kubectl port-forward exited early: {stderr}")
            try:
                req = urllib.request.Request(health_url)
                with urllib.request.urlopen(req, timeout=2) as resp:  # nosec B310
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)
        assert ready, "kubectl port-forward tunnel did not become ready on /healthz"

        gated_url = f"http://127.0.0.1:{local_port}/governance/policy-version"
        assert gated_url.startswith(("http://", "https://"))
        forged_req = urllib.request.Request(
            gated_url,
            headers={"l5d-client-id": ADVISOR_SPIFFE_ID},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(forged_req, timeout=5)  # nosec B310
        assert exc_info.value.code == 403
        err_body = exc_info.value.read().decode("utf-8", errors="replace")
        assert "Forbidden" in err_body

        gw_logs = _kubectl(
            "logs",
            "deployment/gateway-mesh-probe",
            "-n",
            NAMESPACE,
            "-c",
            "gateway",
            "--tail=100",
        ).stdout
        assert "INGRESS_IDENTITY_NOT_FROM_PROXY" in gw_logs
    finally:
        pf_proc.terminate()
        try:
            pf_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pf_proc.kill()
