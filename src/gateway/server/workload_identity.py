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

The identity is Linkerd's DNS-style name, not a ``spiffe://`` URI::

    <service-account>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>

This check is the application half of a two-layer control. The mesh half is
the gateway ``Server`` / ``HTTPRoute`` / ``AuthorizationPolicy`` set, which
refuses unauthorized connections before they reach the container. If that
policy is deleted, or the pod runs without a proxy, this middleware still
refuses the request: no proxy means no header, and no header means 403.

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
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

CLIENT_IDENTITY_HEADER = "l5d-client-id"
TRUSTED_IDENTITIES_ENV = "CAGE_TRUSTED_CLIENT_IDENTITIES"
TRUSTED_GEAP_PRINCIPALS_ENV = "CAGE_TRUSTED_GEAP_AGENT_PRINCIPALS"

#: Paths that need no caller identity. Everything else is refused unless the
#: caller presents a trusted identity. Only exact paths can be open: there is
#: no prefix form, so no route family is ever open by accident. Keep in sync
#: with the gateway's open HTTPRoute (deployment/k8s/linkerd-mtls-policy.yaml
#: and infra/modules/gateway/mesh-policy); a test enforces that.
OPEN_EXACT_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/metrics",
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

_GEAP_AGENT_PRINCIPAL = re.compile(
    r"^(?:principal://)?agents\.global\.org-[a-z0-9-]+(?:\.system\.id\.goog)?/[a-zA-Z0-9._/-]+$"
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
    trusted_geap_principals: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.trusted:
            raise ValueError("IdentityPolicy requires at least one trusted identity.")
        malformed = sorted(i for i in self.trusted if not _LINKERD_IDENTITY.match(i))
        if malformed:
            raise ValueError(
                f"IdentityPolicy contains values that are not Linkerd workload "
                f"identities: {malformed}."
            )
        malformed_geap = sorted(
            p
            for p in self.trusted_geap_principals
            if not _GEAP_AGENT_PRINCIPAL.match(p)
        )
        if malformed_geap:
            raise ValueError(
                f"IdentityPolicy contains values that are not GEAP agent "
                f"principals: {malformed_geap}."
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


def load_identity_policy() -> IdentityPolicy:
    """Build the policy from the environment. Always fails closed when unset.

    Raises:
        RuntimeError: no identity is configured, or a configured identity is
            not a Linkerd workload identity.
    """
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
    raw_geap = os.environ.get(TRUSTED_GEAP_PRINCIPALS_ENV, "")
    geap_principals = frozenset(
        part.strip() for part in raw_geap.split(",") if part.strip()
    )
    malformed_geap = sorted(
        p for p in geap_principals if not _GEAP_AGENT_PRINCIPAL.match(p)
    )
    if malformed_geap:
        raise RuntimeError(
            f"{TRUSTED_GEAP_PRINCIPALS_ENV} contains values that are not GEAP agent "
            f"principals: {malformed_geap}. Expected 'principal://agents.global.org-<id>/<agent>'."
        )
    return IdentityPolicy(trusted=identities, trusted_geap_principals=geap_principals)


def _client_identities(scope: Mapping[str, Any]) -> list[str]:
    name = CLIENT_IDENTITY_HEADER.encode()
    return [
        v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == name
    ]


def extract_client_identity(scope: Mapping[str, Any]) -> str:
    """Return the verified Linkerd client identity from an ASGI ``scope``.

    Raises:
        ValueError: if the request does not carry exactly one valid
            ``l5d-client-id`` header.
    """
    presented = _client_identities(scope)
    if len(presented) != 1 or not _LINKERD_IDENTITY.match(presented[0]):
        raise ValueError(
            f"Request must carry exactly one valid {CLIENT_IDENTITY_HEADER} header "
            f"(got {len(presented)})."
        )
    return presented[0]


class WorkloadIdentityMiddleware:
    """ASGI middleware: refuse any non-open request without a trusted identity."""

    def __init__(self, app: ASGIApp, policy: IdentityPolicy) -> None:
        self.app = app
        self.policy = policy

    async def _verify_geap_id2_principal(self, scope: Mapping[str, Any]) -> bool:
        """Verify GEAP ID-2 OIDC Bearer JWT when trusted_geap_principals is configured."""
        if not self.policy.trusted_geap_principals:
            return True
        auth_headers = [
            v.decode("latin-1")
            for k, v in scope.get("headers", [])
            if k.lower() == b"authorization"
        ]
        if not auth_headers:
            return False
        if len(auth_headers) != 1 or not auth_headers[0].startswith("Bearer "):
            return False
        token = auth_headers[0][len("Bearer ") :].strip()
        if not token:
            return False
        from src.gateway.governance.ingress.agw_adapter import get_agw_adapter

        valid, claims = await get_agw_adapter().validate_oidc_token(token)
        if not valid:
            return False
        sub = str(claims.get("sub", ""))
        return sub in self.policy.trusted_geap_principals

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if is_open_path(path):
            # An open path never runs as an authenticated caller.
            with _serving(None):
                await self.app(scope, receive, send)
            return
        presented = _client_identities(scope)
        # Exactly one header, and it must be trusted. Several headers mean
        # something other than the proxy wrote one of them.
        if (
            len(presented) == 1
            and presented[0] in self.policy.trusted
            and await self._verify_geap_id2_principal(scope)
        ):
            with _serving(presented[0]):
                await self.app(scope, receive, send)
            return
        logger.warning(
            "INGRESS_IDENTITY_REFUSED path=%s identity=%s",
            path,
            presented[0] if len(presented) == 1 else f"<{len(presented)} headers>",
        )
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
