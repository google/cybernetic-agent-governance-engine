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

"""Gateway ingress authentication by mesh workload identity (POAM-2026-080).

Every request to the gateway must come from a trusted workload identity,
except for a short list of open paths (health, metrics, public keys). This
is deny by default: a path that is not explicitly open requires
an identity, so a new route is protected the moment it is added.

Where the identity comes from
-----------------------------
The Linkerd inbound proxy terminates mTLS in front of the gateway container.
On every inbound HTTP request it either **sets** ``l5d-client-id`` to the
client identity it verified from the peer certificate, or **removes** the
header when the connection carried no verified identity. A caller therefore
cannot forge the header through the proxy.

A caller that reaches the container without passing through the proxy can
send any ``l5d-client-id`` it likes. That is the position of every caller of a
pod running without its proxy, for example one admitted while the proxy
injector was down (POAM-2026-167). So the header is believed only on a
connection from the pod's own non-loopback IP address
(:func:`is_pod_local_connection`): the Linkerd inbound proxy connects to the
container from the pod's own IP address (``peer == server`` and
``not peer.is_loopback``). Loopback peers (``127.0.0.1``, ``::1``,
``::ffff:127.0.0.1``) are never treated as the mesh proxy — even when
``scope["server"]`` is also loopback — because ``kubectl port-forward``
(kubelet loopback stream) and unproxied pod-local processes connect from
loopback (POAM-2026-167, F-38, F-39). A request that carries the header from
loopback or any external peer is refused.

This depends on ``scope["client"]`` being the TCP peer, so the servers run
with uvicorn's proxy-header handling off (``proxy_headers=False``). With it
on, a peer that uvicorn trusts could set the client address through
``X-Forwarded-For``.

Architectural determination ``D-167-1``: Because CAGE relies on Linkerd's
proxy-injected ``l5d-client-id`` header rather than terminating mTLS in-process,
header authenticity holds only when all three invariants hold together:
(1) mandatory ``linkerd.io/inject: enabled`` and ``all-authenticated`` inbound
policy with ``proxy-init`` netfilter redirect active; (2) non-loopback pod-IP
peer equality (:func:`is_pod_local_connection`); and (3) no untrusted in-pod
co-tenant or interactive ``pods/exec`` / ``pods/portforward`` access in
enforcing namespaces.

Dev-only Compose loopback channel (``LT-1``)
--------------------------------------------
For local Docker Compose development without a Linkerd sidecar, scripts running
inside the gateway container (``scripts/compose_gateway_call.sh``) connect over
loopback. Accepting ``l5d-client-id`` over loopback requires a dual condition
(:func:`is_dev_loopback_identity_allowed`): (1) a non-enforcing dev posture
(``not is_enforcing(os.environ)`` and ``CAGE_ENV`` in ``{"dev", "development"}``),
**and** (2) explicit opt-in ``CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true``. This
channel is unconditionally refused whenever ``is_enforcing(os.environ)`` is True.

The identity is Linkerd's DNS-style name, not a ``spiffe://`` URI::

    <service-account>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>

This check is the application half of a two-layer control. The mesh half is
the gateway ``Server`` / ``HTTPRoute`` / ``AuthorizationPolicy`` set, which
refuses unauthorized connections before they reach the container. If that
policy is deleted, this middleware still refuses identities it does not
trust. If the pod runs without a proxy, there is no mesh half at all, and
this middleware refuses every request on a gated path: one without the header
for lacking it, one with the header because it did not come through a proxy.

Always enforced
---------------
Trusted identities come from ``CAGE_TRUSTED_CLIENT_IDENTITIES`` (comma
separated). The variable is required in every environment — there is no
development or test off-switch — and startup fails closed if it is unset,
empty, or contains a malformed identity.

Who is calling
--------------
While the middleware serves a request it admitted, the verified identity is
available to everything that runs for that request through
:func:`current_client_identity`. Governance reads it when an action's params
must describe the caller rather than the caller's claims (for example a
domain role bound to a workload identity), so the identity is never taken
from a request body or a tool argument. Open paths, refused requests and code
running outside a request see ``None``. The MCP tool server runs stateless
(one MCP server run per HTTP request), so a tool call sees the identity of
the request that carried it.

This module is domain-agnostic kernel code (Layer 1).
"""

from __future__ import annotations

import contextvars
import ipaddress
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.env_posture import (
    DeploymentPosture,
    is_enforcing,
    resolve_posture,
)
from src.gateway.governance.governor.metrics import (
    GovernorMetrics,
    governor_metrics,
    track_gated_request,
    was_request_refused,
)

logger = logging.getLogger(__name__)

CLIENT_IDENTITY_HEADER = "l5d-client-id"
TRUSTED_IDENTITIES_ENV = "CAGE_TRUSTED_CLIENT_IDENTITIES"
ALLOW_DEV_LOOPBACK_IDENTITY_ENV = "CAGE_ALLOW_DEV_LOOPBACK_IDENTITY"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Paths that need no caller identity. Everything else is refused unless the
#: caller presents a trusted identity. Only exact paths can be open: there is
#: no prefix form, so no route family is ever open by accident. Keep in sync
#: with the gateway's open HTTPRoute (infra/modules/gateway/mesh-policy); a
#: test enforces that.
OPEN_EXACT_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/governance/jwks",
        "/governance/.well-known/jwks.json",
    }
)

_LINKERD_IDENTITY = re.compile(
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?"  # service account
    r"\.[a-z0-9]([-a-z0-9]*[a-z0-9])?"  # namespace
    r"\.serviceaccount\.identity\.linkerd\."
    r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"  # trust domain
)

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

#: The caller identity :class:`WorkloadIdentityMiddleware` verified for the
#: request being served. Only the middleware sets it (:func:`_serving`).
_VERIFIED_CLIENT_IDENTITY: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cage_verified_client_identity", default=None
)


def current_client_identity() -> str | None:
    """Return the verified workload identity of the request being served.

    :class:`WorkloadIdentityMiddleware` sets it, for the duration of the
    downstream call, once the request's single ``l5d-client-id`` is trusted.
    It is ``None`` on open paths and outside a request (a background task,
    an in-process call): an identity is never inferred, so a caller that
    needs one must treat ``None`` as unauthenticated.
    """
    return _VERIFIED_CLIENT_IDENTITY.get()


@contextmanager
def _serving(identity: str | None) -> Iterator[None]:
    """Make ``identity`` the verified caller for the enclosed downstream call."""
    token = _VERIFIED_CLIENT_IDENTITY.set(identity)
    try:
        yield
    finally:
        _VERIFIED_CLIENT_IDENTITY.reset(token)


def is_workload_identity(value: object) -> bool:
    """True if ``value`` is a Linkerd workload identity (``l5d-client-id`` form)."""
    return isinstance(value, str) and _LINKERD_IDENTITY.match(value) is not None


@dataclass(frozen=True)
class IdentityPolicy:
    """Which caller identities the gateway admits. Always enforced."""

    trusted: frozenset[str]

    def __post_init__(self) -> None:
        if not self.trusted:
            raise ValueError("IdentityPolicy requires at least one trusted identity.")
        malformed = sorted(i for i in self.trusted if not _LINKERD_IDENTITY.match(i))
        if malformed:
            raise ValueError(
                f"IdentityPolicy contains values that are not Linkerd workload "
                f"identities: {malformed}."
            )


def is_open_path(path: str) -> bool:
    """True if ``path`` needs no caller identity.

    Only canonical paths can be open: a path with an empty, ``.`` or ``..``
    segment is never open, so ``//health`` or ``/governance/../mcp`` falls
    through to the identity check instead of matching by accident.
    """
    segments = path.split("/")[1:]
    if not path.startswith("/") or any(s in ("", ".", "..") for s in segments[:-1]):
        return False
    if segments and segments[-1] in (".", ".."):
        return False
    return path in OPEN_EXACT_PATHS


def is_dev_loopback_identity_allowed(
    env: Mapping[str, str] | None = None,
) -> bool:
    """True only when the dual-condition dev loopback channel (LT-1) is active.

    Requires BOTH:
    1. A non-enforcing dev posture (``not is_enforcing(source)`` and
       ``CAGE_ENV`` in ``{"dev", "development"}``), AND
    2. Explicit opt-in ``CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true``.

    Unconditionally returns ``False`` whenever ``is_enforcing(source)`` is True.
    """
    source = os.environ if env is None else env
    if is_enforcing(source) or resolve_posture(source) is not DeploymentPosture.DEV:
        return False
    if source.get("CAGE_ENV", "").strip().lower() not in {"dev", "development"}:
        return False
    return source.get(ALLOW_DEV_LOOPBACK_IDENTITY_ENV, "").strip().lower() in _TRUTHY


def load_identity_policy() -> IdentityPolicy:
    """Build the policy from the environment. Always fails closed when unset.

    Raises:
        RuntimeError: no identity is configured, a configured identity is
            not a Linkerd workload identity, or the LT-1 dev loopback opt-in is
            set outside a non-enforcing dev posture.
    """
    dev_loopback_flag = (
        os.environ.get(ALLOW_DEV_LOOPBACK_IDENTITY_ENV, "").strip().lower() in _TRUTHY
    )
    if dev_loopback_flag and not is_dev_loopback_identity_allowed(os.environ):
        raise RuntimeError(
            f"{ALLOW_DEV_LOOPBACK_IDENTITY_ENV}=true is forbidden when is_enforcing() is True "
            "or CAGE_ENV is not 'dev'/'development' (POAM-2026-167 / LT-1)."
        )
    raw = os.environ.get(TRUSTED_IDENTITIES_ENV, "")
    identities = frozenset(part.strip() for part in raw.split(",") if part.strip())
    malformed = sorted(i for i in identities if not _LINKERD_IDENTITY.match(i))
    if malformed:
        raise RuntimeError(
            f"{TRUSTED_IDENTITIES_ENV} contains values that are not Linkerd workload "
            f"identities: {malformed}. Use '<sa>.<namespace>.serviceaccount.identity."
            "linkerd.<trust-domain>' (the l5d-client-id format), not a spiffe:// URI."
        )
    if not identities:
        raise RuntimeError(
            f"{TRUSTED_IDENTITIES_ENV} must list the workload identities allowed to call "
            "the gateway (POAM-2026-080). There is no permissive bypass."
        )
    return IdentityPolicy(trusted=identities)


def _client_identities(scope: Mapping[str, Any]) -> list[str]:
    name = CLIENT_IDENTITY_HEADER.encode()
    return [
        v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == name
    ]


def _address(
    endpoint: object,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address of an ASGI ``(host, port)`` pair, or ``None``."""
    if not isinstance(endpoint, (tuple, list)) or not endpoint:
        return None
    try:
        address = ipaddress.ip_address(str(endpoint[0]))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def is_pod_local_connection(scope: Mapping[str, Any]) -> bool:
    """True if the request's TCP peer is the pod's own non-loopback IP address.

    The Linkerd inbound proxy connects to the container from the pod's own IP,
    so ``scope["client"]`` and ``scope["server"]`` share the same non-loopback
    IP address. ``scope["client"]`` must be the TCP peer, which is why the
    servers run with uvicorn's proxy-header handling off (``proxy_headers=False``).

    Loopback peers (``127.0.0.1``, ``::1``, ``::ffff:127.0.0.1``) are never
    treated as the Linkerd proxy — even when ``scope["server"]`` is also
    loopback — because ``kubectl port-forward`` (kubelet loopback stream) and
    unproxied pod-local processes connect from loopback (POAM-2026-167, F-38,
    F-39, D-167-1).
    """
    peer = _address(scope.get("client"))
    if peer is None or peer.is_loopback or peer.is_unspecified:
        return False
    server = _address(scope.get("server"))
    if server is None or server.is_loopback or server.is_unspecified:
        return False
    return peer == server


def _is_trusted_identity_source(
    scope: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
) -> bool:
    """True if ``l5d-client-id`` came from the pod-local proxy or the LT-1 dev loopback channel."""
    if is_pod_local_connection(scope):
        return True
    if not is_dev_loopback_identity_allowed(env):
        return False
    peer = _address(scope.get("client"))
    return peer is not None and peer.is_loopback


def _peer(scope: Mapping[str, Any]) -> str:
    client = scope.get("client")
    if isinstance(client, (tuple, list)) and client:
        return str(client[0])
    return "<none>"


def extract_client_identity(scope: Mapping[str, Any]) -> str:
    """Return the verified Linkerd client identity from an ASGI ``scope``.

    Raises:
        ValueError: if the request does not carry exactly one valid
            ``l5d-client-id`` header, or the header did not arrive on a
            connection from the pod's Linkerd proxy (:func:`is_pod_local_connection`)
            or the dual-condition LT-1 dev loopback channel.
    """
    presented = _client_identities(scope)
    if len(presented) != 1 or not _LINKERD_IDENTITY.match(presented[0]):
        raise ValueError(
            f"Request must carry exactly one valid {CLIENT_IDENTITY_HEADER} header "
            f"(got {len(presented)})."
        )
    if not _is_trusted_identity_source(scope):
        raise ValueError(
            f"{CLIENT_IDENTITY_HEADER} arrived from {_peer(scope)}, not through "
            "the pod's Linkerd proxy."
        )
    return presented[0]


class WorkloadIdentityMiddleware:
    """ASGI middleware: refuse any non-open request without a trusted identity."""

    def __init__(
        self,
        app: ASGIApp,
        policy: IdentityPolicy,
        *,
        metrics: GovernorMetrics | None = None,
    ) -> None:
        self.app = app
        self.policy = policy
        self._metrics = metrics

    def _resolve_metrics(self) -> GovernorMetrics:
        return self._metrics if self._metrics is not None else governor_metrics()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if is_open_path(path):
            # An open path never runs as an authenticated caller and is excluded
            # from gated request counters so kubelet probes cannot dilute a
            # sustained refusal outage.
            with _serving(None):
                await self.app(scope, receive, send)
            return
        metrics = self._resolve_metrics()
        presented = _client_identities(scope)
        if presented and not _is_trusted_identity_source(scope):
            # Through the proxy, the header is the identity the proxy verified.
            # From any other peer, it is whatever the caller chose to send, so
            # it is logged with repr().
            logger.warning(
                "INGRESS_IDENTITY_NOT_FROM_PROXY path=%s peer=%s claimed=%r",
                path,
                _peer(scope),
                presented[0] if len(presented) == 1 else f"<{len(presented)} headers>",
            )
            metrics.gated_request_completed(blocked=True)
            await _refuse(scope, send)
            return
        # Exactly one header, and it must be trusted. Several headers mean
        # something other than the proxy wrote one of them.
        if len(presented) == 1 and presented[0] in self.policy.trusted:
            is_ws = scope["type"] == "websocket"
            http_status: int | None = None
            ws_accepted = False
            ws_policy_closed = False

            async def _tracked_send(message: dict[str, Any]) -> None:
                nonlocal http_status, ws_accepted, ws_policy_closed
                msg_type = message.get("type")
                if msg_type == "http.response.start":
                    http_status = int(message.get("status", 500))
                elif msg_type == "websocket.accept":
                    ws_accepted = True
                elif msg_type == "websocket.close" and not ws_accepted:
                    ws_policy_closed = True
                await send(message)

            completed_cleanly = False
            with _serving(presented[0]), track_gated_request():
                try:
                    await self.app(scope, receive, _tracked_send)
                    completed_cleanly = True
                finally:
                    if is_ws:
                        blocked = (
                            not completed_cleanly
                            or ws_policy_closed
                            or not ws_accepted
                            or was_request_refused()
                        )
                    else:
                        blocked = (
                            not completed_cleanly
                            or http_status is None
                            or http_status >= 400
                            or was_request_refused()
                        )
                    metrics.gated_request_completed(blocked=blocked)
            return
        logger.warning(
            "INGRESS_IDENTITY_REFUSED path=%s identity=%s",
            path,
            presented[0] if len(presented) == 1 else f"<{len(presented)} headers>",
        )
        metrics.gated_request_completed(blocked=True)
        await _refuse(scope, send)


async def _refuse(scope: Scope, send: Send) -> None:
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": 1008})
        return
    body = json.dumps(
        {
            "detail": "Forbidden: caller workload identity is not authorized for this route."
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
