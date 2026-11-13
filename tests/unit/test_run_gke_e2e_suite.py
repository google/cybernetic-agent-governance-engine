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

"""Unit tests for `scripts/run_gke_e2e_suite.py`."""

from __future__ import annotations

import asyncio
import json
import stat
from pathlib import Path

import pytest
import yaml

from src.compliance_bridge.oidc_verifier import OidcVerifier, parse_jwks_payload
from tests.e2e.run_gke_e2e_suite import (
    build_webauthn_binding_payload,
    generate_ephemeral_operator_keypair,
    mint_operator_oidc_tokens,
    render_e2e_job_manifest,
    validate_http_url,
    write_private_key_secure,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_ephemeral_keypair_and_minted_tokens_verify_against_bridge_oidc_verifier(
    tmp_path: Path,
) -> None:
    priv_pem, jwks_json = generate_ephemeral_operator_keypair(kid="cage-e2e-op-1")
    assert "PRIVATE KEY" not in jwks_json
    parsed_doc = json.loads(jwks_json)
    assert len(parsed_doc["keys"]) == 1
    assert "d" not in parsed_doc["keys"][0]
    assert "k" not in parsed_doc["keys"][0]

    key_file = tmp_path / "op_key.pem"
    write_private_key_secure(key_file, priv_pem)
    mode = stat.S_IMODE(key_file.stat().st_mode)
    assert mode == 0o600

    keys_by_kid = parse_jwks_payload(jwks_json)
    assert "cage-e2e-op-1" in keys_by_kid

    tok1, tok2 = mint_operator_oidc_tokens(
        key_file.read_bytes(),
        identities=("risk-1@example.com", "risk-2@example.com"),
        issuer="https://idp.cage.example",
        audience="cage-compliance-bridge",
        kid="cage-e2e-op-1",
    )
    assert tok1 != tok2

    verifier = OidcVerifier(
        issuer="https://idp.cage.example",
        audience="cage-compliance-bridge",
        jwks_cache=keys_by_kid,
    )
    ok1, claims1, err1 = asyncio.run(verifier.verify_token(tok1))
    ok2, claims2, err2 = asyncio.run(verifier.verify_token(tok2))
    assert ok1 is True, err1
    assert ok2 is True, err2
    assert claims1["sub"] == "risk-1@example.com"
    assert claims2["sub"] == "risk-2@example.com"


def test_render_e2e_job_manifest_satisfies_wolfi_pss_and_network_policy() -> None:
    rendered = render_e2e_job_manifest(
        job_name="cage-verify-trade-e2e-a",
        namespace="governance-stack",
        workload_image="us-central1-docker.pkg.dev/proj/cage-images/advisor@sha256:abc",
        phase="phase_a",
        model_name="Qwen/Qwen2.5-1.5B-Instruct",
        require_inference_proxy=True,
        deferred_ids={"s2_single_use": "def-1"},
        configmap_name="cage-verify-trade-e2e-a-runner",
    )
    assert "${" not in rendered
    doc = yaml.safe_load(rendered)
    assert doc["kind"] == "Job"
    tmpl = doc["spec"]["template"]
    assert tmpl["metadata"]["labels"]["app"] == "governed-financial-advisor"
    assert tmpl["metadata"]["annotations"]["linkerd.io/inject"] == "enabled"
    spec = tmpl["spec"]
    assert spec["serviceAccountName"] == "cage-advisor-sa"
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["securityContext"]["runAsUser"] == 1000
    container = spec["containers"][0]
    assert container["command"] == ["/app/.venv/bin/python", "/e2e/in_mesh_runner.py"]
    assert "readinessProbe" in container


def test_webauthn_binding_and_url_scheme_validation() -> None:
    body = build_webauthn_binding_payload("def-123", 0)
    assert len(body["challenge_binding"]) == 64
    assert body["client_data_json"]
    assert validate_http_url("http://localhost:3002/") == "http://localhost:3002"
    with pytest.raises(ValueError, match="http:// or https://"):
        validate_http_url("file:///etc/passwd")


def test_standalone_sys_path_resolves_cage_conformance() -> None:
    import sys

    from cage_conformance.runner import HttpResponse

    from tests.e2e import run_gke_e2e_suite

    assert str(run_gke_e2e_suite._CONFORMANCE_SRC) in sys.path
    resp = HttpResponse(status_code=200, headers={}, body=b"{}")
    assert resp.status_code == 200


def test_wait_for_seeded_metrics_polls_v1_metrics_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import inspect

    import httpx

    from tests.e2e import run_gke_e2e_suite

    sig = inspect.signature(run_gke_e2e_suite._wait_for_seeded_metrics)
    assert sig.parameters["timeout_seconds"].default == 120

    seen_urls: list[str] = []
    call_counts: dict[str, int] = {}

    class _FakeResponse:
        def __init__(self, status_code: int, payload: dict[str, object]) -> None:
            self.status_code = status_code
            self._payload = payload

        def json(self) -> dict[str, object]:
            return self._payload

    class _FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def get(self, url: str) -> _FakeResponse:
            seen_urls.append(url)
            call_counts[url] = call_counts.get(url, 0) + 1
            if call_counts[url] == 1:
                return _FakeResponse(
                    200,
                    {
                        "total_traces": 0,
                        "safety_rate": 1.0,
                        "startup_grace_active": False,
                    },
                )
            return _FakeResponse(
                200,
                {"total_traces": 2, "safety_rate": 1.0, "startup_grace_active": False},
            )

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setattr(run_gke_e2e_suite.time, "sleep", lambda _s: None)

    ready = run_gke_e2e_suite._wait_for_seeded_metrics(
        "http://localhost:3002/",
        ["A.5.2", "A.5.3", "A.9.2"],
    )
    assert set(ready) == {"A.5.2", "A.5.3", "A.9.2"}
    assert all("/api/v1/compliance/metrics/" not in u for u in seen_urls)
    assert set(seen_urls) == {
        "http://localhost:3002/v1/metrics/A.5.2",
        "http://localhost:3002/v1/metrics/A.5.3",
        "http://localhost:3002/v1/metrics/A.9.2",
    }


def test_render_e2e_job_manifest_propagates_require_advisor_sdk_and_runner_parses() -> (
    None
):
    import ast

    from tests.e2e import run_gke_e2e_suite

    ast.parse(run_gke_e2e_suite._IN_MESH_RUNNER_SOURCE)
    assert "_exercise_advisor_sdk_in_mesh" in run_gke_e2e_suite._IN_MESH_RUNNER_SOURCE
    assert "GatewayClient" in run_gke_e2e_suite._IN_MESH_RUNNER_SOURCE
    assert "safety_check_node" in run_gke_e2e_suite._IN_MESH_RUNNER_SOURCE
    assert "RoutingSealVerificationError" in run_gke_e2e_suite._IN_MESH_RUNNER_SOURCE

    rendered_true = render_e2e_job_manifest(
        job_name="cage-verify-trade-e2e-a",
        namespace="governance-stack",
        workload_image="us-central1-docker.pkg.dev/proj/cage-images/advisor@sha256:abc",
        phase="phase_a",
        model_name="Qwen/Qwen2.5-1.5B-Instruct",
        require_inference_proxy=True,
        require_advisor_sdk=True,
        deferred_ids={},
        configmap_name="cage-verify-trade-e2e-a-runner",
    )
    assert "${" not in rendered_true
    doc_true = yaml.safe_load(rendered_true)
    env_map = {
        item["name"]: item["value"]
        for item in doc_true["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env_map["CAGE_E2E_REQUIRE_ADVISOR_SDK"] == "true"

    rendered_false = render_e2e_job_manifest(
        job_name="cage-verify-trade-e2e-a",
        namespace="governance-stack",
        workload_image="us-central1-docker.pkg.dev/proj/cage-images/gateway@sha256:def",
        phase="phase_a",
        model_name="Qwen/Qwen2.5-1.5B-Instruct",
        require_inference_proxy=False,
        deferred_ids={},
        configmap_name="cage-verify-trade-e2e-a-runner",
    )
    doc_false = yaml.safe_load(rendered_false)
    env_map_false = {
        item["name"]: item["value"]
        for item in doc_false["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env_map_false["CAGE_E2E_REQUIRE_ADVISOR_SDK"] == "false"
