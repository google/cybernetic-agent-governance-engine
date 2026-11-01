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

import logging

import httpx
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
    _serving,
    current_client_identity,
    extract_client_identity,
    is_open_path,
    is_pod_local_connection,
    is_workload_identity,
    load_identity_policy,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

ADVISOR = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
OTHER = "cage-vllm-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
GATED = [
    "/mcp/",
    "/mcp/sse",
    "/mcp/messages/",
    "/tools/execute",
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


#: The Linkerd inbound proxy connects to the container from inside the pod.
#: Loopback stands in for that here; the pod-IP form is tested separately.
PROXY_PEER = ("127.0.0.1", 50000)
#: Another pod reaching the container directly, as it can when the pod runs
#: without its proxy.
OTHER_POD = ("10.112.3.7", 51000)
#: The gateway pod's own address: the peer of every request its proxy forwards.
POD_IP = "10.112.0.43"


def _client(
    policy: IdentityPolicy,
    peer: tuple[str, int] = PROXY_PEER,
    base_url: str = "http://testserver",
) -> TestClient:
    inner = Starlette(
        routes=[
            Route("/{path:path}", _ok, methods=["GET", "POST"]),
            WebSocketRoute("/ws", _ws),
        ]
    )
    return TestClient(
        WorkloadIdentityMiddleware(inner, policy), client=peer, base_url=base_url
    )


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
    scope = {
        "headers": [(b"l5d-client-id", ADVISOR.encode("latin-1"))],
        "client": PROXY_PEER,
    }
    assert extract_client_identity(scope) == ADVISOR

    with pytest.raises(ValueError, match="l5d-client-id"):
        extract_client_identity({"headers": [], "client": PROXY_PEER})

    with pytest.raises(ValueError, match="l5d-client-id"):
        extract_client_identity(
            {
                "headers": [
                    (b"l5d-client-id", ADVISOR.encode("latin-1")),
                    (b"l5d-client-id", ADVISOR.encode("latin-1")),
                ],
                "client": PROXY_PEER,
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
                ],
                "client": PROXY_PEER,
            }
        )


# ---------------------------------------------------------------------------
# Where the header came from (POAM-2026-167). Only the pod's own Linkerd proxy
# writes l5d-client-id, so the header counts only on a connection from inside
# the pod. A pod running without its proxy can be reached directly, and there a
# caller can send any identity it likes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", GATED)
def test_trusted_identity_from_another_pod_is_refused(path: str) -> None:
    resp = _client(ENFORCED, peer=OTHER_POD).post(
        path, headers={CLIENT_IDENTITY_HEADER: ADVISOR}
    )
    assert resp.status_code == 403


def test_request_from_another_pod_without_identity_is_refused() -> None:
    assert _client(ENFORCED, peer=OTHER_POD).post("/tools/execute").status_code == 403


def test_proxy_connection_from_the_pods_own_address_is_admitted() -> None:
    # The Linkerd proxy connects to the container from the pod's own IP: on
    # staging, the gateway's access log shows its own address as the peer of
    # every proxied request.
    client = _client(ENFORCED, peer=(POD_IP, 40000), base_url=f"http://{POD_IP}:8080")
    resp = client.post("/tools/execute", headers={CLIENT_IDENTITY_HEADER: ADVISOR})
    assert resp.status_code == 200


def test_identity_from_another_pod_is_logged_as_not_from_the_proxy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(
        logging.WARNING, logger="src.gateway.server.workload_identity"
    ):
        _client(ENFORCED, peer=OTHER_POD).post(
            "/tools/execute", headers={CLIENT_IDENTITY_HEADER: ADVISOR}
        )
    assert any(
        "INGRESS_IDENTITY_NOT_FROM_PROXY" in r.getMessage()
        and OTHER_POD[0] in r.getMessage()
        and ADVISOR in r.getMessage()
        for r in caplog.records
    )


def test_open_paths_answer_any_peer() -> None:
    resp = _client(ENFORCED, peer=OTHER_POD).get(
        "/health", headers={CLIENT_IDENTITY_HEADER: ADVISOR}
    )
    assert resp.status_code == 200


def test_websocket_identity_from_another_pod_is_closed() -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as exc:
        with _client(ENFORCED, peer=OTHER_POD).websocket_connect(
            "/ws", headers={CLIENT_IDENTITY_HEADER: ADVISOR}
        ) as ws:
            ws.receive_text()
    assert exc.value.code == 1008


async def test_a_header_from_another_pod_never_becomes_the_caller() -> None:
    seen: list[str | None] = []
    app = WorkloadIdentityMiddleware(_recording(seen), ENFORCED)

    status = await _status(
        app, "/tools/execute", ADVISOR, client=OTHER_POD, server=(POD_IP, 8080)
    )

    assert status == 403
    assert seen == []


def test_extract_client_identity_refuses_a_header_from_another_pod() -> None:
    scope = {
        "headers": [(b"l5d-client-id", ADVISOR.encode("latin-1"))],
        "client": OTHER_POD,
        "server": (POD_IP, 8080),
    }
    with pytest.raises(ValueError, match=r"10\.112\.3\.7, not through the pod's"):
        extract_client_identity(scope)


@pytest.mark.parametrize(
    ("client", "server", "expected"),
    [
        (("127.0.0.1", 1), None, True),
        (("127.8.9.10", 1), None, True),  # all of 127.0.0.0/8 is loopback
        (("::1", 1), None, True),
        (("::ffff:127.0.0.1", 1), None, True),  # IPv4-mapped loopback
        ((POD_IP, 1), (POD_IP, 8080), True),  # the proxy, from the pod's own IP
        ((POD_IP, 1), [POD_IP, 8080], True),  # servers may pass lists
        ((f"::ffff:{POD_IP}", 1), (POD_IP, 8080), True),
        (OTHER_POD, (POD_IP, 8080), False),  # another pod
        (("10.112.0.1", 1), (POD_IP, 8080), False),  # any other peer
        ((POD_IP, 1), None, False),  # no local address to compare with
        ((POD_IP, 1), ("testserver", 80), False),
        (("testclient", 50000), ("testserver", 80), False),  # TestClient default
        (None, (POD_IP, 8080), False),
        ("127.0.0.1", None, False),  # not a (host, port) pair
        ((), None, False),
    ],
)
def test_is_pod_local_connection(
    client: object, server: object, expected: bool
) -> None:
    assert is_pod_local_connection({"client": client, "server": server}) is expected


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
        "/mcp/",
        "/tools/execute",
        "/governance/validate-action",
    ):
        assert client.post(path, json={}).status_code == 403, path
    assert client.get("/mcp/").status_code == 403


# ---------------------------------------------------------------------------
# current_client_identity(): the verified caller, for its own request only
# (GHSA-w39v-5v7h-fxg9: the finance plugin binds trader_role from it)
# ---------------------------------------------------------------------------


def _recording(seen: list[str | None]):  # type: ignore[no-untyped-def]
    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        seen.append(current_client_identity())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    return app


async def _status(  # type: ignore[no-untyped-def]
    app,
    path: str,
    identity: str | None = None,
    client: tuple[str, int] | None = PROXY_PEER,
    server: tuple[str, int] | None = None,
) -> int:
    headers = (
        []
        if identity is None
        else [(CLIENT_IDENTITY_HEADER.encode(), identity.encode())]
    )
    sent: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
        "client": client,
        "server": server,
    }
    await app(scope, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


async def test_a_trusted_request_runs_as_its_verified_identity() -> None:
    seen: list[str | None] = []
    app = WorkloadIdentityMiddleware(_recording(seen), ENFORCED)

    assert await _status(app, "/tools/execute", ADVISOR) == 200

    assert seen == [ADVISOR]
    assert current_client_identity() is None  # reset once the request is served


async def test_an_open_path_never_runs_as_a_caller() -> None:
    seen: list[str | None] = []
    app = WorkloadIdentityMiddleware(_recording(seen), ENFORCED)

    with _serving(OTHER):  # even nested inside another verified request
        assert await _status(app, "/health", ADVISOR) == 200
        assert current_client_identity() == OTHER

    assert seen == [None]


@pytest.mark.parametrize("identity", [None, OTHER], ids=["none", "untrusted"])
async def test_a_refused_request_never_runs(identity: str | None) -> None:
    seen: list[str | None] = []
    app = WorkloadIdentityMiddleware(_recording(seen), ENFORCED)

    assert await _status(app, "/tools/execute", identity) == 403

    assert seen == []


def test_there_is_no_identity_outside_a_request() -> None:
    assert current_client_identity() is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ADVISOR, True),
        (ADVISOR.upper(), False),
        ("spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa", False),
        ("", False),
        (None, False),
    ],
)
def test_is_workload_identity(value: object, expected: bool) -> None:
    assert is_workload_identity(value) is expected


class _MeshProxy(httpx.AsyncBaseTransport):
    """Stands in for the Linkerd inbound proxy: sets ``l5d-client-id``."""

    def __init__(self, app) -> None:  # type: ignore[no-untyped-def]
        self._inner = httpx.ASGITransport(app=app)
        self.identity = ADVISOR

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.headers[CLIENT_IDENTITY_HEADER] = self.identity
        return await self._inner.handle_async_request(request)


async def test_an_mcp_tool_call_runs_as_the_identity_of_its_own_request() -> None:
    # Stateless MCP (as the gateway runs it) serves each call in the context of
    # the HTTP request that carried it, so a tool sees that caller's identity
    # and never the identity of an earlier request on the same client session.
    from mcp.server.fastmcp import FastMCP
    from mcp.server.transport_security import TransportSecuritySettings

    from src.gateway.infrastructure.mcp_client import GatewayMCPClient

    server = FastMCP(
        "identity-propagation",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(allowed_hosts=["gateway:*"]),
    )

    @server.tool()
    async def whoami() -> str:
        return str(current_client_identity())

    proxy = _MeshProxy(
        WorkloadIdentityMiddleware(
            Starlette(routes=[Mount("/mcp", app=server.streamable_http_app())]),
            IdentityPolicy(trusted=frozenset({ADVISOR, OTHER})),
        )
    )
    client = GatewayMCPClient("http://gateway:8080/mcp/", http_transport=proxy)
    seen: list[str] = []
    async with server.session_manager.run():
        try:
            for identity in (ADVISOR, OTHER, ADVISOR):
                proxy.identity = identity
                seen.append(await client.call_tool("whoami", {}))
        finally:
            await client.close()

    assert seen == [ADVISOR, OTHER, ADVISOR]


def test_the_gateway_mcp_server_is_stateless() -> None:
    # The propagation above holds only for stateless serving: a stateful
    # session would run every call in the context of the request that opened it.
    from src.gateway.server.mcp_tool_server import mcp

    assert mcp.settings.stateless_http is True
