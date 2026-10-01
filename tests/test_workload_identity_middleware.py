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

"""POAM-2026-080: gateway ingress is deny-by-default on mesh workload identity."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.testclient import TestClient

from src.gateway.server.workload_identity import (
    CLIENT_IDENTITY_HEADER,
    OPEN_EXACT_PATHS,
    TRUSTED_IDENTITIES_ENV,
    IdentityPolicy,
    WorkloadIdentityMiddleware,
    extract_client_identity,
    is_open_path,
    load_identity_policy,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

ADVISOR = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
OTHER = "cage-vllm-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
GATED = [
    "/mcp/sse",
    "/mcp/messages/",
    "/tools/execute",
    "/governance/check",
    "/governance/validate-action",
    "/governance/policy-version",
    "/inference/v1/chat/completions",
    "/v1/pause/tok",
    "/v1/pause/tok/resume",
    "/unknown",
]


async def _ok(request):
    return PlainTextResponse("ok")


async def _ws(websocket):
    await websocket.accept()
    await websocket.send_text("ok")
    await websocket.close()


def _client(policy: IdentityPolicy) -> TestClient:
    inner = Starlette(
        routes=[
            Route("/{path:path}", _ok, methods=["GET", "POST"]),
            WebSocketRoute("/ws", _ws),
        ]
    )
    return TestClient(WorkloadIdentityMiddleware(inner, policy))


ENFORCED = IdentityPolicy(trusted=frozenset({ADVISOR}))


@pytest.mark.parametrize("path", GATED)
def test_gated_path_without_identity_is_refused(path: str) -> None:
    resp = _client(ENFORCED).post(path)
    assert resp.status_code == 403
    assert "workload identity" in resp.json()["detail"]


@pytest.mark.parametrize("path", GATED)
def test_gated_path_with_untrusted_identity_is_refused(path: str) -> None:
    resp = _client(ENFORCED).post(path, headers={CLIENT_IDENTITY_HEADER: OTHER})
    assert resp.status_code == 403


@pytest.mark.parametrize("path", GATED)
def test_gated_path_with_trusted_identity_is_admitted(path: str) -> None:
    resp = _client(ENFORCED).post(path, headers={CLIENT_IDENTITY_HEADER: ADVISOR})
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "value",
    [
        "",
        "spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
        ADVISOR.upper(),
        f" {ADVISOR}",
        f"{ADVISOR},{OTHER}",
    ],
)
def test_near_miss_identities_are_refused(value: str) -> None:
    resp = _client(ENFORCED).post(
        "/tools/execute", headers={CLIENT_IDENTITY_HEADER: value}
    )
    assert resp.status_code == 403


def test_duplicate_identity_headers_are_refused() -> None:
    client = _client(ENFORCED)
    resp = client.post(
        "/tools/execute",
        headers=[(CLIENT_IDENTITY_HEADER, ADVISOR), (CLIENT_IDENTITY_HEADER, ADVISOR)],
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("path", sorted(OPEN_EXACT_PATHS))
def test_open_paths_need_no_identity(path: str) -> None:
    assert _client(ENFORCED).get(path).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "//health",
        "/health/",
        "/./health",
        "/governance/../mcp",
        "/governance/a/../../mcp",
        "/governance//jwks",
        "/governance/jwks/..",
        "health",
    ],
)
def test_non_canonical_variants_of_open_paths_are_gated(path: str) -> None:
    assert not is_open_path(path)


def test_websocket_without_identity_is_closed() -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as exc:
        with _client(ENFORCED).websocket_connect("/ws") as ws:
            ws.receive_text()
    assert exc.value.code == 1008


def test_empty_or_malformed_identity_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one trusted identity"):
        IdentityPolicy(trusted=frozenset())
    with pytest.raises(ValueError, match="not Linkerd workload identities"):
        IdentityPolicy(
            trusted=frozenset(
                {"spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa"}
            )
        )


def test_extract_client_identity_validates_single_linkerd_header() -> None:
    scope = {"headers": [(b"l5d-client-id", ADVISOR.encode("latin-1"))]}
    assert extract_client_identity(scope) == ADVISOR

    with pytest.raises(ValueError, match="l5d-client-id"):
        extract_client_identity({"headers": []})

    with pytest.raises(ValueError, match="l5d-client-id"):
        extract_client_identity(
            {
                "headers": [
                    (b"l5d-client-id", ADVISOR.encode("latin-1")),
                    (b"l5d-client-id", ADVISOR.encode("latin-1")),
                ]
            }
        )

    with pytest.raises(ValueError, match="l5d-client-id"):
        extract_client_identity(
            {
                "headers": [
                    (
                        b"l5d-client-id",
                        b"spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
                    )
                ]
            }
        )


# --- load_identity_policy ---------------------------------------------------


@pytest.mark.parametrize(
    "posture",
    ["dev", "test", "ci", "local", "staging", "production", "something-else"],
)
def test_without_identities_refuses_to_start_in_every_posture(
    monkeypatch, posture
) -> None:
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.delenv(TRUSTED_IDENTITIES_ENV, raising=False)
    with pytest.raises(RuntimeError, match=TRUSTED_IDENTITIES_ENV):
        load_identity_policy()


@pytest.mark.parametrize("posture", ["dev", "test", "ci", "production"])
def test_configured_identities_are_enforced_in_every_posture(
    monkeypatch, posture
) -> None:
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv(TRUSTED_IDENTITIES_ENV, f" {ADVISOR} , ,")
    assert load_identity_policy() == IdentityPolicy(trusted=frozenset({ADVISOR}))


@pytest.mark.parametrize(
    "bad",
    [
        "spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
        "cage-advisor-sa",
        "CAGE-ADVISOR-SA.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    ],
)
def test_malformed_identity_refuses_to_start(monkeypatch, bad) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.setenv(TRUSTED_IDENTITIES_ENV, f"{ADVISOR},{bad}")
    with pytest.raises(RuntimeError, match="not Linkerd workload identities"):
        load_identity_policy()


# --- wiring on the real gateway ---------------------------------------------


def test_gateway_root_app_installs_the_middleware_outermost() -> None:
    from src.gateway.server.hybrid_server import root_app

    assert root_app.user_middleware[0].cls is WorkloadIdentityMiddleware


def _route_paths(routes, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for route in routes:
        if isinstance(route, Mount):
            out |= _route_paths(route.routes, prefix + route.path)
        elif hasattr(route, "path"):
            out.add(prefix + route.path)
    return out


def test_every_open_path_is_a_real_gateway_route() -> None:
    """A stale open-list entry would silently widen the unauthenticated surface."""
    from src.gateway.server.hybrid_server import root_app

    routes = _route_paths(root_app.routes)
    missing = sorted(p for p in OPEN_EXACT_PATHS - {"/metrics"} if p not in routes)
    assert missing == []
    # The PAUSE routes are gone with the verdict; nothing under /v1/pause may exist.
    assert not any(r.startswith("/v1/pause") for r in routes)


def test_real_gateway_refuses_unidentified_calls_to_governed_routes() -> None:
    from src.gateway.server.hybrid_server import root_app

    client = TestClient(root_app)
    for path in (
        "/tools/execute",
        "/governance/validate-action",
        "/governance/check",
    ):
        assert client.post(path, json={}).status_code == 403, path
    assert client.get("/mcp/sse").status_code == 403
